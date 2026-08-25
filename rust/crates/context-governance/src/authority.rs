//! Production Context Governance authority.
//!
//! Mutations enter as bounded domain commands, are normalized to Canonical Action IR, and are
//! handed to the durable orchestrator. The only database mutation boundary is the typed executor;
//! it requires the exact PEP, ledger, fence, resource-version, and authorization-evidence facts
//! forwarded by Tool Proxy. Tenant RLS is selected inside every transaction. Domain mutation and
//! an immutable Evidence outbox record commit atomically, while idempotent external effects and
//! Evidence delivery remain recoverable across process failure.

use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector, RiskContext,
    RiskLevel, SchemaVersion, StepId, TaskId, TenantId, ToolId, ToolRef, ToolVersion,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const CONTEXT_COMMAND_SCHEMA: &str = "agenttrust.context-command.v1";
pub const CONTEXT_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.context-execution-request.v1";
pub const CONTEXT_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.context-action-receipt.v1";
pub const CONTEXT_MUTATION_RESULT_SCHEMA: &str = "agenttrust.context-mutation-result.v1";
pub const CONTEXT_RETRIEVAL_REQUEST_SCHEMA: &str = "agenttrust.context-retrieval-request.v1";
pub const CONTEXT_RETRIEVAL_RESULT_SCHEMA: &str = "agenttrust.context-retrieval-result.v1";
pub const CONTEXT_LIFECYCLE_EVIDENCE_SCHEMA: &str = "agenttrust.context-lifecycle-evidence.v1";
pub const CONTEXT_READINESS_SCHEMA: &str = "agenttrust.context-readiness.v1";
pub const AUTHORITATIVE_CONTEXT_PAGE_SCHEMA: &str = "agenttrust.authoritative-context-page.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContextAuthorityError {
    #[error("CONTEXT_AUTHORITY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("CONTEXT_AUTHORITY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("CONTEXT_AUTHORITY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("CONTEXT_AUTHORITY_STATE_CONFLICT")]
    StateConflict,
    #[error("CONTEXT_AUTHORITY_NOT_FOUND")]
    NotFound,
    #[error("CONTEXT_AUTHORITY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("CONTEXT_AUTHORITY_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("CONTEXT_AUTHORITY_SUPPLY_CHAIN_DENIED")]
    SupplyChainDenied,
    #[error("CONTEXT_AUTHORITY_LEGAL_HOLD_BLOCKED")]
    LegalHoldBlocked,
    #[error("CONTEXT_AUTHORITY_POISONING_DETECTED")]
    PoisoningDetected,
    #[error("CONTEXT_AUTHORITY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextOperation {
    WriteMemory,
    DeleteMemory,
    PublishPrompt,
    ActivatePrompt,
    RollbackPrompt,
    RegisterKnowledgeSource,
    PublishKnowledgeSnapshot,
    DeleteKnowledgeSnapshot,
    QuarantineResource,
    ReleaseQuarantine,
}

impl ContextOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WriteMemory => "WRITE_MEMORY",
            Self::DeleteMemory => "DELETE_MEMORY",
            Self::PublishPrompt => "PUBLISH_PROMPT",
            Self::ActivatePrompt => "ACTIVATE_PROMPT",
            Self::RollbackPrompt => "ROLLBACK_PROMPT",
            Self::RegisterKnowledgeSource => "REGISTER_KNOWLEDGE_SOURCE",
            Self::PublishKnowledgeSnapshot => "PUBLISH_KNOWLEDGE_SNAPSHOT",
            Self::DeleteKnowledgeSnapshot => "DELETE_KNOWLEDGE_SNAPSHOT",
            Self::QuarantineResource => "QUARANTINE_RESOURCE",
            Self::ReleaseQuarantine => "RELEASE_QUARANTINE",
        }
    }

    fn risk(self) -> RiskLevel {
        match self {
            Self::WriteMemory | Self::RegisterKnowledgeSource => RiskLevel::High,
            Self::PublishPrompt
            | Self::ActivatePrompt
            | Self::RollbackPrompt
            | Self::PublishKnowledgeSnapshot
            | Self::DeleteMemory
            | Self::DeleteKnowledgeSnapshot
            | Self::QuarantineResource
            | Self::ReleaseQuarantine => RiskLevel::Critical,
        }
    }

    pub(crate) fn external_effects(self) -> bool {
        matches!(
            self,
            Self::WriteMemory
                | Self::DeleteMemory
                | Self::PublishPrompt
                | Self::PublishKnowledgeSnapshot
                | Self::DeleteKnowledgeSnapshot
                | Self::QuarantineResource
                | Self::ReleaseQuarantine
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub task_id: Uuid,
    pub resource: String,
    pub operation: ContextOperation,
    pub expected_resource_version: u64,
    pub requested_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextExecutorRequest {
    pub schema_version: String,
    pub command: ContextCommandRequest,
    pub actor_subject: String,
    pub actor_kind: String,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContextExecutionBinding {
    pub tenant_id: TenantId,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub resource_version: u64,
    pub idempotency_key: String,
    pub trace_id: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContextActionReceipt {
    pub schema_version: String,
    pub action_id: String,
    pub task_id: String,
    pub accepted: bool,
    pub execution_pending: bool,
    pub ingress_digest: String,
    pub ledger_evidence_ref: String,
    pub ledger_evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub resource: String,
    pub operation: ContextOperation,
    pub resource_version: u64,
    pub state: String,
    pub result_digest: String,
    pub evidence_outbox_ref: String,
    pub quarantine: bool,
    pub legal_hold_blocked: bool,
    pub safe_receipts: Vec<AdapterReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterReceipt {
    pub adapter: String,
    pub operation: String,
    pub resource: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub receipt_digest: String,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContextEffectReceipt {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub idempotency_key: String,
    pub operation: ContextOperation,
    pub resource: String,
    pub object_ref: Option<String>,
    pub index_ref: Option<String>,
    pub quarantine: bool,
    pub legal_hold_blocked: bool,
    pub poisoning_findings: BTreeSet<String>,
    pub receipts: Vec<AdapterReceipt>,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDeliveryReceipt {
    pub schema_version: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub payload_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContextRetrievalRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub retrieval_id: Uuid,
    pub subject: String,
    pub query: String,
    pub maximum_classification: DataClassification,
    pub jurisdiction: String,
    pub maximum_results: u16,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetrievalAuthorizationBinding {
    pub tenant_id: TenantId,
    pub client_subject: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub policy_evidence_ref: String,
    pub policy_evidence_digest: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VectorSearchHit {
    pub resource: String,
    pub score_millionths: u32,
    pub content_digest: String,
    pub provenance_digest: String,
    pub object_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextRetrievalResult {
    pub schema_version: String,
    pub retrieval_id: Uuid,
    pub authorization_decision_id: Uuid,
    pub authorized_candidate_count: usize,
    pub hits: Vec<VectorSearchHit>,
    pub retrieval_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetrievalDecision {
    pub decision_id: Uuid,
    pub authorized_resources: BTreeSet<String>,
    pub request_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeContextResource {
    pub resource: String,
    pub resource_version: u64,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub fence_digest: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeContextPage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub authoritative: bool,
    pub items: Vec<AuthoritativeContextResource>,
    pub next_after: Option<String>,
    pub data_digest: String,
}

#[derive(Debug, Clone)]
pub struct ContextAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
}

impl ContextAuthorityConfig {
    pub fn validate(&self) -> Result<(), ContextAuthorityError> {
        if canonical_uuid(&self.service_agent_id.0)
            && identifier(&self.organization_id, 256)
            && identifier(&self.agent_version, 128)
            && identifier(&self.region, 128)
            && identifier(&self.tool_id.0, 256)
            && identifier(&self.tool_version.0, 128)
            && identifier(&self.credential_profile, 128)
            && identifier(&self.service_subject, 256)
        {
            Ok(())
        } else {
            Err(ContextAuthorityError::ConfigurationInvalid)
        }
    }
}

#[async_trait]
pub trait ContextOrchestratorPort: Send + Sync {
    async fn ready(&self) -> bool;

    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<ContextActionReceipt, ContextAuthorityError>;
}

#[async_trait]
pub trait ContextRuntimePort: Send + Sync {
    async fn ready(&self) -> bool;

    async fn execute_effects(
        &self,
        binding: &ContextExecutionBinding,
        request: &ContextExecutorRequest,
    ) -> Result<Option<ContextEffectReceipt>, ContextAuthorityError>;

    async fn search(
        &self,
        binding: &RetrievalAuthorizationBinding,
        request: &ContextRetrievalRequest,
        decision: &RetrievalDecision,
    ) -> Result<Vec<VectorSearchHit>, ContextAuthorityError>;

    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<EvidenceDeliveryReceipt, ContextAuthorityError>;
}

#[derive(Clone)]
pub struct ContextIngressAuthority {
    store: PostgresContextAuthorityStore,
    orchestrator: Arc<dyn ContextOrchestratorPort>,
    config: ContextAuthorityConfig,
}

impl ContextIngressAuthority {
    pub fn new(
        store: PostgresContextAuthorityStore,
        orchestrator: Arc<dyn ContextOrchestratorPort>,
        config: ContextAuthorityConfig,
    ) -> Result<Self, ContextAuthorityError> {
        config.validate()?;
        Ok(Self {
            store,
            orchestrator,
            config,
        })
    }

    pub async fn submit(
        &self,
        tenant: TenantId,
        actor_subject: String,
        request: ContextCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<ContextActionReceipt, ContextAuthorityError> {
        validate_command(
            &tenant,
            &actor_subject,
            &request,
            request_digest,
            idempotency_key,
        )?;
        let current = self
            .store
            .current_resource_version(&tenant, &request.resource)
            .await?;
        if current != request.expected_resource_version {
            return Err(ContextAuthorityError::StateConflict);
        }
        let executor = ContextExecutorRequest {
            schema_version: CONTEXT_EXECUTOR_REQUEST_SCHEMA.into(),
            command: request.clone(),
            actor_subject: actor_subject.clone(),
            actor_kind: "WORKLOAD".into(),
            approval_ids: BTreeSet::new(),
        };
        let envelope = canonical_context_action(&executor, &self.config, idempotency_key)?;
        let prepared = self
            .store
            .prepare_ingress(
                &tenant,
                &actor_subject,
                &request,
                request_digest,
                idempotency_key,
                envelope,
            )
            .await?;
        if let Some(receipt) = prepared.receipt {
            return Ok(receipt);
        }
        let receipt = self
            .orchestrator
            .submit(&tenant, &prepared.envelope)
            .await?;
        self.store
            .complete_ingress(&tenant, idempotency_key, &receipt)
            .await
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.orchestrator.ready().await
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativeContextPage, ContextAuthorityError> {
        self.store.authoritative_page(tenant, after, limit).await
    }
}

#[derive(Clone)]
pub struct ContextExecutor {
    store: PostgresContextAuthorityStore,
    runtime: Arc<dyn ContextRuntimePort>,
    execution_lease_seconds: i64,
}

impl ContextExecutor {
    pub fn new(
        store: PostgresContextAuthorityStore,
        runtime: Arc<dyn ContextRuntimePort>,
        execution_lease_seconds: i64,
    ) -> Result<Self, ContextAuthorityError> {
        if !(15..=300).contains(&execution_lease_seconds) {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            runtime,
            execution_lease_seconds,
        })
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.runtime.ready().await
    }

    pub async fn execute(
        &self,
        binding: ContextExecutionBinding,
        request: ContextExecutorRequest,
    ) -> Result<ContextMutationResult, ContextAuthorityError> {
        validate_execution(&binding, &request)?;
        match self
            .store
            .claim_execution(&binding, &request, self.execution_lease_seconds)
            .await?
        {
            ExecutionClaim::Completed(result) => Ok(result),
            ExecutionClaim::EvidencePending(pending) => {
                self.deliver_and_finalize(&binding.tenant_id, pending).await
            }
            ExecutionClaim::Claimed(claim) => {
                let effect = self.runtime.execute_effects(&binding, &request).await?;
                validate_effect(&binding, &request, effect.as_ref())?;
                let pending = self
                    .store
                    .commit_mutation(&binding, &request, claim, effect)
                    .await?;
                self.deliver_and_finalize(&binding.tenant_id, pending).await
            }
        }
    }

    async fn deliver_and_finalize(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
    ) -> Result<ContextMutationResult, ContextAuthorityError> {
        let receipt = self
            .runtime
            .publish_evidence(
                tenant,
                pending.event_id,
                &pending.idempotency_key,
                &pending.payload,
                &pending.payload_digest,
            )
            .await?;
        validate_evidence_receipt(&pending, &receipt)?;
        self.store.finalize_evidence(tenant, pending, receipt).await
    }

    pub async fn recover_pending_evidence(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<Vec<ContextMutationResult>, ContextAuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(ContextAuthorityError::RequestInvalid);
        }
        let pending = self.store.pending_evidence(tenant, limit).await?;
        let mut results = Vec::new();
        for item in pending {
            results.push(self.deliver_and_finalize(tenant, item).await?);
        }
        Ok(results)
    }
}

#[derive(Clone)]
pub struct RetrievalAuthorizer {
    store: PostgresContextAuthorityStore,
    runtime: Arc<dyn ContextRuntimePort>,
}

impl RetrievalAuthorizer {
    pub fn new(store: PostgresContextAuthorityStore, runtime: Arc<dyn ContextRuntimePort>) -> Self {
        Self { store, runtime }
    }

    pub async fn retrieve(
        &self,
        binding: RetrievalAuthorizationBinding,
        request: ContextRetrievalRequest,
    ) -> Result<ContextRetrievalResult, ContextAuthorityError> {
        validate_retrieval(&binding, &request)?;
        // This database authorization and immutable decision insert deliberately happens before
        // the vector port is reachable. The vector request receives only the allowlisted resource
        // identifiers, never a tenant-wide metadata filter that an adapter could accidentally omit.
        let decision = self.store.authorize_retrieval(&binding, &request).await?;
        let mut hits = if decision.authorized_resources.is_empty() {
            Vec::new()
        } else {
            self.runtime.search(&binding, &request, &decision).await?
        };
        if hits.len() > usize::from(request.maximum_results)
            || hits.iter().any(|hit| {
                !decision.authorized_resources.contains(&hit.resource)
                    || !digest(&hit.content_digest)
                    || !digest(&hit.provenance_digest)
                    || !object_reference(&hit.object_ref)
                    || hit.score_millionths > 1_000_000
            })
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        hits.sort_by(|left, right| {
            right
                .score_millionths
                .cmp(&left.score_millionths)
                .then(left.resource.cmp(&right.resource))
        });
        let retrieval_digest = canonical_digest(&json!({
            "retrieval_id": request.retrieval_id,
            "decision_id": decision.decision_id,
            "hits": hits,
        }))?;
        Ok(ContextRetrievalResult {
            schema_version: CONTEXT_RETRIEVAL_RESULT_SCHEMA.into(),
            retrieval_id: request.retrieval_id,
            authorization_decision_id: decision.decision_id,
            authorized_candidate_count: decision.authorized_resources.len(),
            hits,
            retrieval_digest,
        })
    }
}

#[derive(Clone)]
pub struct PostgresContextAuthorityStore {
    pool: PgPool,
}

impl PostgresContextAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM context_action_ingress WHERE false UNION ALL SELECT 1 LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .is_ok()
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, ContextAuthorityError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(parse_tenant(tenant)?.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }

    pub async fn current_resource_version(
        &self,
        tenant: &TenantId,
        resource: &str,
    ) -> Result<u64, ContextAuthorityError> {
        if !resource_identifier(resource) {
            return Err(ContextAuthorityError::RequestInvalid);
        }
        let mut tx = self.begin_tenant(tenant).await?;
        let value = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM context_resource_versions \
             WHERE tenant_id=$1 AND resource=$2",
        )
        .bind(parse_tenant(tenant)?)
        .bind(resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        u64::try_from(value).map_err(|_| ContextAuthorityError::DependencyUnavailable)
    }
}

#[derive(Debug)]
struct PreparedIngress {
    envelope: InboundEnvelope,
    receipt: Option<ContextActionReceipt>,
}

#[derive(Debug)]
enum ExecutionClaim {
    Completed(ContextMutationResult),
    EvidencePending(PendingEvidence),
    Claimed(Uuid),
}

#[derive(Debug, Clone)]
struct PendingEvidence {
    event_id: Uuid,
    idempotency_key: String,
    payload: Value,
    payload_digest: String,
    result: ContextMutationResult,
}

impl PostgresContextAuthorityStore {
    #[allow(clippy::too_many_arguments)]
    async fn prepare_ingress(
        &self,
        tenant: &TenantId,
        actor_subject: &str,
        request: &ContextCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        envelope: InboundEnvelope,
    ) -> Result<PreparedIngress, ContextAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let envelope_value =
            serde_json::to_value(&envelope).map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let admitted_hash = action_hash(&action)
            .map_err(|_| ContextAuthorityError::RequestInvalid)?
            .0;
        let mut tx = self.begin_tenant(tenant).await?;
        let inserted = sqlx::query(
            "INSERT INTO context_action_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,action_hash,resource,\
              operation,actor_subject,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED') \
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(request.command_id)
        .bind(request.task_id)
        .bind(&admitted_hash)
        .bind(&request.resource)
        .bind(request.operation.as_str())
        .bind(actor_subject)
        .bind(&envelope_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::IdempotencyConflict)?
        .rows_affected()
            == 1;
        let row = sqlx::query(
            "SELECT request_digest,action_id,task_id,action_hash,resource,operation,actor_subject,\
                    envelope,state,receipt FROM context_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .ok_or(ContextAuthorityError::IdempotencyConflict)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command_id
            || row.get::<Uuid, _>("task_id") != request.task_id
            || row.get::<String, _>("resource") != request.resource
            || row.get::<String, _>("operation") != request.operation.as_str()
            || row.get::<String, _>("actor_subject") != actor_subject
            || !matches!(
                row.get::<String, _>("state").as_str(),
                "PREPARED" | "ACCEPTED"
            )
        {
            return Err(ContextAuthorityError::IdempotencyConflict);
        }
        let stored_envelope_value = row.get::<Value, _>("envelope");
        let stored_envelope: InboundEnvelope =
            serde_json::from_value(stored_envelope_value.clone())
                .map_err(|_| ContextAuthorityError::IdempotencyConflict)?;
        let stored_action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&stored_envelope.payload)
                .map_err(|_| ContextAuthorityError::IdempotencyConflict)?;
        let stored_hash = action_hash(&stored_action)
            .map_err(|_| ContextAuthorityError::IdempotencyConflict)?
            .0;
        let expected_executor = ContextExecutorRequest {
            schema_version: CONTEXT_EXECUTOR_REQUEST_SCHEMA.into(),
            command: request.clone(),
            actor_subject: actor_subject.into(),
            actor_kind: "WORKLOAD".into(),
            approval_ids: BTreeSet::new(),
        };
        let expected_executor_value = serde_json::to_value(expected_executor)
            .map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let expected_state_version = request.expected_resource_version.to_string();
        if row.get::<String, _>("action_hash") != stored_hash
            || stored_envelope.schema_version != GATEWAY_SCHEMA_VERSION
            || stored_envelope.content_type != "application/json"
            || stored_envelope.idempotency_key.as_deref() != Some(idempotency_key)
            || stored_envelope.tenant_context.tenant_id.0.as_str() != tenant.0.as_str()
            || stored_envelope.identity_context.tenant_id.0.as_str() != tenant.0.as_str()
            || stored_envelope.identity_context.owner_subject != actor_subject
            || stored_envelope.payload_hash != sha256(&stored_envelope.payload)
            || stored_action.action_id.0 != request.command_id.to_string()
            || stored_action.task_id.0 != request.task_id.to_string()
            || stored_action.current_state_version.as_deref()
                != Some(expected_state_version.as_str())
            || Value::Object(stored_action.payload.data.clone()) != expected_executor_value
            || inserted && (stored_hash != admitted_hash || stored_envelope_value != envelope_value)
        {
            return Err(ContextAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("receipt")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        Ok(PreparedIngress {
            envelope: stored_envelope,
            receipt,
        })
    }

    async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &ContextActionReceipt,
    ) -> Result<ContextActionReceipt, ContextAuthorityError> {
        if receipt.schema_version != CONTEXT_ACTION_RECEIPT_SCHEMA
            || !receipt.accepted
            || !receipt.execution_pending
            || !canonical_uuid(&receipt.action_id)
            || !canonical_uuid(&receipt.task_id)
            || !digest(&receipt.ingress_digest)
            || !evidence_reference(&receipt.ledger_evidence_ref)
            || !digest(&receipt.ledger_evidence_digest)
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let receipt_value = serde_json::to_value(receipt)
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,state,receipt FROM context_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("action_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("receipt") {
            if existing != receipt_value || row.get::<String, _>("state") != "ACCEPTED" {
                return Err(ContextAuthorityError::IdempotencyConflict);
            }
        } else {
            let updated = sqlx::query(
                "UPDATE context_action_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&receipt_value)
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(ContextAuthorityError::OutcomeUnknown);
            }
        }
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }

    async fn claim_execution(
        &self,
        binding: &ContextExecutionBinding,
        request: &ContextExecutorRequest,
        lease_seconds: i64,
    ) -> Result<ExecutionClaim, ContextAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(request)?;
        let request_value =
            serde_json::to_value(request).map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let expected_version = i64::try_from(binding.resource_version)
            .map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let claim = Uuid::new_v4();
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let ingress = sqlx::query(
            "SELECT state,actor_subject,envelope,action_hash FROM context_action_ingress \
             WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .ok_or(ContextAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("actor_subject") != request.actor_subject
            || ingress.get::<String, _>("action_hash") != binding.action_hash
        {
            return Err(ContextAuthorityError::PrincipalDenied);
        }
        let envelope: InboundEnvelope = serde_json::from_value(ingress.get("envelope"))
            .map_err(|_| ContextAuthorityError::PrincipalDenied)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| ContextAuthorityError::PrincipalDenied)?;
        let admitted_hash =
            action_hash(&action).map_err(|_| ContextAuthorityError::PrincipalDenied)?;
        let expected_action_version = request.command.expected_resource_version.to_string();
        if admitted_hash.0 != binding.action_hash
            || action.action_id.0 != request.command.command_id.to_string()
            || action.task_id.0 != request.command.task_id.to_string()
            || action.current_state_version.as_deref() != Some(expected_action_version.as_str())
            || Value::Object(action.payload.data.clone()) != request_value
        {
            return Err(ContextAuthorityError::PrincipalDenied);
        }

        sqlx::query(
            "INSERT INTO context_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,action_hash,\
              ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,resource,\
              resource_version,trace_id,policy_decision_id,policy_decision_digest,\
              authorization_evidence_ref,authorization_evidence_digest,request,state,\
              execution_owner,execution_lease_until) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,\
                     'PREPARED',$19,now()+make_interval(secs=>$20)) \
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(&request_digest)
        .bind(request.command.command_id)
        .bind(request.command.task_id)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(binding.ledger_event_id)
        .bind(&binding.ledger_event_digest)
        .bind(&binding.fence_digest)
        .bind(&request.command.resource)
        .bind(expected_version)
        .bind(&binding.trace_id)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(&request_value)
        .bind(claim)
        .bind(lease_seconds as f64)
        .execute(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::IdempotencyConflict)?;
        let row = sqlx::query(
            "SELECT request_digest,action_id,task_id,action_hash,ledger_execution_id,ledger_event_id,\
                    ledger_event_digest,fence_digest,resource,resource_version,trace_id,\
                    policy_decision_id,policy_decision_digest,authorization_evidence_ref,\
                    authorization_evidence_digest,request,state,safe_result,execution_owner,\
                    execution_lease_until,evidence_request \
             FROM context_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .ok_or(ContextAuthorityError::StateConflict)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command.command_id
            || row.get::<Uuid, _>("task_id") != request.command.task_id
            || row.get::<String, _>("action_hash") != binding.action_hash
            || row.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
            || row.get::<Uuid, _>("ledger_event_id") != binding.ledger_event_id
            || row.get::<String, _>("ledger_event_digest") != binding.ledger_event_digest
            || row.get::<String, _>("fence_digest") != binding.fence_digest
            || row.get::<String, _>("resource") != request.command.resource
            || row.get::<i64, _>("resource_version") != expected_version
            || row.get::<String, _>("trace_id") != binding.trace_id
            || row.get::<String, _>("policy_decision_id") != binding.policy_decision_id
            || row.get::<String, _>("policy_decision_digest") != binding.policy_decision_digest
            || row.get::<String, _>("authorization_evidence_ref")
                != binding.authorization_evidence_ref
            || row.get::<String, _>("authorization_evidence_digest")
                != binding.authorization_evidence_digest
            || row.get::<Value, _>("request") != request_value
        {
            return Err(ContextAuthorityError::IdempotencyConflict);
        }
        let state: String = row.get("state");
        if state == "SUCCEEDED" {
            let result = parse_result(row.get::<Option<Value>, _>("safe_result"))?;
            tx.commit()
                .await
                .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            return Ok(ExecutionClaim::Completed(result));
        }
        if state == "MUTATED_PENDING_EVIDENCE" {
            let pending = pending_from_row(
                &mut tx,
                tenant,
                &binding.idempotency_key,
                row.get::<Option<Value>, _>("safe_result"),
            )
            .await?;
            tx.commit()
                .await
                .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            return Ok(ExecutionClaim::EvidencePending(pending));
        }
        if !matches!(state.as_str(), "PREPARED" | "SIDE_EFFECTS_PENDING") {
            return Err(ContextAuthorityError::OutcomeUnknown);
        }
        let owner: Uuid = row.get("execution_owner");
        if owner != claim {
            let lease_until: DateTime<Utc> = row.get("execution_lease_until");
            if lease_until > Utc::now() {
                return Err(ContextAuthorityError::OutcomeUnknown);
            }
            let claimed = sqlx::query(
                "UPDATE context_authority_executions SET execution_owner=$3,\
                 execution_lease_until=now()+make_interval(secs=>$4),\
                 state='SIDE_EFFECTS_PENDING',updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 \
                   AND state IN ('PREPARED','SIDE_EFFECTS_PENDING') AND execution_lease_until<=now()",
            )
            .bind(tenant)
            .bind(&binding.idempotency_key)
            .bind(claim)
            .bind(lease_seconds as f64)
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            if claimed.rows_affected() != 1 {
                return Err(ContextAuthorityError::OutcomeUnknown);
            }
        } else if state == "PREPARED" {
            let updated = sqlx::query(
                "UPDATE context_authority_executions SET state='SIDE_EFFECTS_PENDING',updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED' \
                   AND execution_owner=$3",
            )
            .bind(tenant)
            .bind(&binding.idempotency_key)
            .bind(claim)
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(ContextAuthorityError::OutcomeUnknown);
            }
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM context_resource_versions \
             WHERE tenant_id=$1 AND resource=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current != expected_version
            || request.command.expected_resource_version != binding.resource_version
        {
            return Err(ContextAuthorityError::StateConflict);
        }
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        Ok(ExecutionClaim::Claimed(claim))
    }

    async fn commit_mutation(
        &self,
        binding: &ContextExecutionBinding,
        request: &ContextExecutorRequest,
        claim: Uuid,
        effect: Option<ContextEffectReceipt>,
    ) -> Result<PendingEvidence, ContextAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let current = i64::try_from(binding.resource_version)
            .map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let next = current
            .checked_add(1)
            .ok_or(ContextAuthorityError::StateConflict)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let execution = sqlx::query(
            "SELECT state,execution_owner,execution_lease_until FROM context_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        if execution.get::<String, _>("state") != "SIDE_EFFECTS_PENDING"
            || execution.get::<Uuid, _>("execution_owner") != claim
            || execution.get::<DateTime<Utc>, _>("execution_lease_until") <= Utc::now()
        {
            return Err(ContextAuthorityError::OutcomeUnknown);
        }
        let observed = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM context_resource_versions \
             WHERE tenant_id=$1 AND resource=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if observed != current {
            return Err(ContextAuthorityError::StateConflict);
        }
        let (quarantine, legal_hold_blocked) =
            apply_domain_mutation(&mut tx, tenant, binding, request, effect.as_ref(), next).await?;
        if current == 0 {
            sqlx::query(
                "INSERT INTO context_resource_versions \
                 (tenant_id,resource,resource_version,action_hash,ledger_execution_id,fence_digest) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(tenant)
            .bind(&request.command.resource)
            .bind(next)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
        } else {
            let updated = sqlx::query(
                "UPDATE context_resource_versions SET resource_version=$3,action_hash=$4,\
                 ledger_execution_id=$5,fence_digest=$6,updated_at=now() \
                 WHERE tenant_id=$1 AND resource=$2 AND resource_version=$7",
            )
            .bind(tenant)
            .bind(&request.command.resource)
            .bind(next)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .bind(current)
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            if updated.rows_affected() != 1 {
                return Err(ContextAuthorityError::StateConflict);
            }
        }
        let safe_receipts = effect
            .as_ref()
            .map(|value| value.receipts.clone())
            .unwrap_or_default();
        let result_material = json!({
            "command_id": request.command.command_id,
            "resource": request.command.resource,
            "operation": request.command.operation,
            "resource_version": next,
            "quarantine": quarantine,
            "legal_hold_blocked": legal_hold_blocked,
            "safe_receipts": safe_receipts,
        });
        let result_digest = canonical_digest(&result_material)?;
        let event_id = Uuid::new_v4();
        let result = ContextMutationResult {
            schema_version: CONTEXT_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            resource: request.command.resource.clone(),
            operation: request.command.operation,
            resource_version: u64::try_from(next)
                .map_err(|_| ContextAuthorityError::StateConflict)?,
            state: "SUCCEEDED".into(),
            result_digest,
            evidence_outbox_ref: format!("context-outbox://{tenant}/{event_id}"),
            quarantine,
            legal_hold_blocked,
            safe_receipts,
        };
        let payload = json!({
            "schema_version": CONTEXT_LIFECYCLE_EVIDENCE_SCHEMA,
            "event_id": event_id,
            "tenant_id": tenant,
            "action_id": request.command.command_id,
            "task_id": request.command.task_id,
            "operation": request.command.operation,
            "resource": request.command.resource,
            "resource_version": next,
            "actor_subject": request.actor_subject,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "ledger_event_id": binding.ledger_event_id,
            "ledger_event_digest": binding.ledger_event_digest,
            "fence_digest": binding.fence_digest,
            "policy_decision_id": binding.policy_decision_id,
            "policy_decision_digest": binding.policy_decision_digest,
            "authorization_evidence_ref": binding.authorization_evidence_ref,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "trace_id": binding.trace_id,
            "result_digest": result.result_digest,
            "quarantine": quarantine,
            "legal_hold_blocked": legal_hold_blocked,
            "effect_receipt_digest": effect.as_ref().map(|value| value.receipt_digest.clone()),
            "occurred_at": Utc::now(),
        });
        let payload_digest = canonical_digest(&payload)?;
        sqlx::query(
            "INSERT INTO context_evidence_outbox \
             (tenant_id,event_id,idempotency_key,action_id,execution_id,payload,payload_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(&binding.idempotency_key)
        .bind(request.command.command_id)
        .bind(binding.ledger_execution_id)
        .bind(&payload)
        .bind(&payload_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        let result_value =
            serde_json::to_value(&result).map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        let external_receipts = effect
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        let updated = sqlx::query(
            "UPDATE context_authority_executions SET state='MUTATED_PENDING_EVIDENCE',\
             external_receipts=$3,safe_result=$4,evidence_request=$5,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='SIDE_EFFECTS_PENDING' \
               AND execution_owner=$6",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(external_receipts)
        .bind(&result_value)
        .bind(&payload)
        .bind(claim)
        .execute(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        if updated.rows_affected() != 1 {
            return Err(ContextAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        Ok(PendingEvidence {
            event_id,
            idempotency_key: binding.idempotency_key.clone(),
            payload,
            payload_digest,
            result,
        })
    }

    async fn finalize_evidence(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
        receipt: EvidenceDeliveryReceipt,
    ) -> Result<ContextMutationResult, ContextAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let outbox = sqlx::query(
            "SELECT payload,payload_digest,delivered_at FROM context_evidence_outbox \
             WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(pending.event_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        if outbox.get::<Value, _>("payload") != pending.payload
            || outbox.get::<String, _>("payload_digest") != pending.payload_digest
        {
            return Err(ContextAuthorityError::OutcomeUnknown);
        }
        if outbox
            .get::<Option<DateTime<Utc>>, _>("delivered_at")
            .is_none()
        {
            let updated = sqlx::query(
                "UPDATE context_evidence_outbox SET delivered_at=now() \
                 WHERE tenant_id=$1 AND event_id=$2 AND delivered_at IS NULL",
            )
            .bind(tenant_uuid)
            .bind(pending.event_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(ContextAuthorityError::OutcomeUnknown);
            }
        }
        let receipt_value =
            serde_json::to_value(&receipt).map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        let updated = sqlx::query(
            "UPDATE context_authority_executions SET state='SUCCEEDED',evidence_ref=$3,\
             evidence_digest=$4,evidence_receipt=$5,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 \
               AND state='MUTATED_PENDING_EVIDENCE'",
        )
        .bind(tenant_uuid)
        .bind(&pending.idempotency_key)
        .bind(&receipt.evidence_ref)
        .bind(&receipt.evidence_digest)
        .bind(receipt_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        if updated.rows_affected() != 1 {
            let state = sqlx::query_scalar::<_, String>(
                "SELECT state FROM context_authority_executions \
                 WHERE tenant_id=$1 AND idempotency_key=$2",
            )
            .bind(tenant_uuid)
            .bind(&pending.idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            if state.as_deref() != Some("SUCCEEDED") {
                return Err(ContextAuthorityError::OutcomeUnknown);
            }
        }
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        Ok(pending.result)
    }

    async fn pending_evidence(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<Vec<PendingEvidence>, ContextAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT e.idempotency_key,e.safe_result,o.event_id,o.payload,o.payload_digest \
             FROM context_authority_executions e \
             JOIN context_evidence_outbox o ON o.tenant_id=e.tenant_id \
               AND o.idempotency_key=e.idempotency_key \
             WHERE e.tenant_id=$1 AND e.state='MUTATED_PENDING_EVIDENCE' \
               AND o.delivered_at IS NULL ORDER BY o.created_at LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let mut pending = Vec::new();
        for row in rows {
            pending.push(PendingEvidence {
                event_id: row.get("event_id"),
                idempotency_key: row.get("idempotency_key"),
                payload: row.get("payload"),
                payload_digest: row.get("payload_digest"),
                result: parse_result(row.get::<Option<Value>, _>("safe_result"))?,
            });
        }
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        Ok(pending)
    }

    async fn authorize_retrieval(
        &self,
        binding: &RetrievalAuthorizationBinding,
        request: &ContextRetrievalRequest,
    ) -> Result<RetrievalDecision, ContextAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let classification = classification_rank(request.maximum_classification);
        let request_digest = canonical_digest(request)?;
        let query_digest = sha256(request.query.as_bytes());
        let decision_id = Uuid::new_v4();
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let rows = sqlx::query(
            "SELECT resource FROM (\
               SELECT 'memory:' || m.memory_id::text AS resource,m.classification,m.jurisdiction,\
                      m.trust_level,m.owner_subject,m.visibility,m.expires_at,\
                      m.status,false AS source_quarantined \
                 FROM governed_memory_entries m WHERE m.tenant_id=$1 \
               UNION ALL \
               SELECT 'knowledge-snapshot:' || k.snapshot_id AS resource,k.classification,k.jurisdiction,\
                      s.trust_level,s.owner_subject,s.allowed_subjects,k.expires_at,\
                      CASE WHEN k.tombstoned THEN 'TOMBSTONED' ELSE 'ACTIVE' END AS status,\
                      (s.quarantined OR k.quarantined) AS source_quarantined \
                 FROM knowledge_snapshots k JOIN context_knowledge_sources s \
                   ON s.tenant_id=k.tenant_id AND s.source_id=k.source_id \
                WHERE k.tenant_id=$1\
             ) authorized \
             WHERE status='ACTIVE' AND NOT source_quarantined AND expires_at>now() \
               AND CASE classification \
                    WHEN 'PUBLIC' THEN 0 WHEN 'INTERNAL' THEN 1 \
                    WHEN 'CONFIDENTIAL' THEN 2 WHEN 'RESTRICTED' THEN 3 \
                    WHEN 'REGULATED' THEN 4 ELSE 99 END <= $2 \
               AND jurisdiction=$4 \
               AND trust_level IN ('VERIFIED','AUTHORITATIVE') \
               AND (owner_subject=$3 OR visibility ? $3) \
             ORDER BY resource LIMIT 10000",
        )
        .bind(tenant)
        .bind(classification)
        .bind(&request.subject)
        .bind(&request.jurisdiction)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let authorized_resources = rows
            .into_iter()
            .map(|row| row.get::<String, _>("resource"))
            .collect::<BTreeSet<_>>();
        let resources_value = serde_json::to_value(&authorized_resources)
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "INSERT INTO context_retrieval_decisions \
             (tenant_id,decision_id,retrieval_id,request_digest,subject,query_digest,authorized_resources,\
              policy_decision_id,policy_digest,policy_evidence_ref,policy_evidence_digest,trace_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING",
        )
        .bind(tenant)
        .bind(decision_id)
        .bind(request.retrieval_id)
        .bind(&request_digest)
        .bind(&request.subject)
        .bind(&query_digest)
        .bind(resources_value)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.policy_evidence_ref)
        .bind(&binding.policy_evidence_digest)
        .bind(&binding.trace_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let stored = sqlx::query(
            "SELECT decision_id,request_digest,subject,query_digest,authorized_resources,\
                    policy_decision_id,policy_digest,policy_evidence_ref,policy_evidence_digest,trace_id \
             FROM context_retrieval_decisions WHERE tenant_id=$1 AND retrieval_id=$2",
        )
        .bind(tenant)
        .bind(request.retrieval_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
        .ok_or(ContextAuthorityError::OutcomeUnknown)?;
        if stored.get::<String, _>("request_digest") != request_digest
            || stored.get::<String, _>("subject") != request.subject
            || stored.get::<String, _>("query_digest") != query_digest
            || stored.get::<String, _>("policy_decision_id") != binding.policy_decision_id
            || stored.get::<String, _>("policy_digest") != binding.policy_decision_digest
            || stored.get::<String, _>("policy_evidence_ref") != binding.policy_evidence_ref
            || stored.get::<String, _>("policy_evidence_digest") != binding.policy_evidence_digest
            || stored.get::<String, _>("trace_id") != binding.trace_id
        {
            return Err(ContextAuthorityError::IdempotencyConflict);
        }
        let stored_resources = serde_json::from_value::<BTreeSet<String>>(
            stored.get::<Value, _>("authorized_resources"),
        )
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let stored_decision_id = stored.get::<Uuid, _>("decision_id");
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        Ok(RetrievalDecision {
            decision_id: stored_decision_id,
            authorized_resources: stored_resources,
            request_digest,
        })
    }

    async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativeContextPage, ContextAuthorityError> {
        if !(1..=200).contains(&limit) || after.is_some_and(|value| !resource_identifier(value)) {
            return Err(ContextAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT resource,resource_version,action_hash,ledger_execution_id,fence_digest,updated_at \
             FROM context_resource_versions WHERE tenant_id=$1 \
               AND ($2::text IS NULL OR resource>$2) ORDER BY resource LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let items = rows
            .iter()
            .take(limit as usize)
            .map(|row| {
                let resource_version = u64::try_from(row.get::<i64, _>("resource_version"))
                    .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
                Ok(AuthoritativeContextResource {
                    resource: row.get("resource"),
                    resource_version,
                    action_hash: row.get("action_hash"),
                    ledger_execution_id: row.get("ledger_execution_id"),
                    fence_digest: row.get("fence_digest"),
                    updated_at: row.get("updated_at"),
                })
            })
            .collect::<Result<Vec<_>, ContextAuthorityError>>()?;
        let next_after = (rows.len() > limit as usize)
            .then(|| items.last().map(|item| item.resource.clone()))
            .flatten();
        tx.commit()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let data_digest = canonical_digest(&json!({
            "schema_version": AUTHORITATIVE_CONTEXT_PAGE_SCHEMA,
            "tenant_id": tenant,
            "authoritative": true,
            "items": &items,
            "next_after": &next_after,
        }))?;
        Ok(AuthoritativeContextPage {
            schema_version: AUTHORITATIVE_CONTEXT_PAGE_SCHEMA.into(),
            tenant_id: tenant.clone(),
            authoritative: true,
            items,
            next_after,
            data_digest,
        })
    }
}

async fn pending_from_row(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    idempotency_key: &str,
    safe_result: Option<Value>,
) -> Result<PendingEvidence, ContextAuthorityError> {
    let row = sqlx::query(
        "SELECT event_id,payload,payload_digest FROM context_evidence_outbox \
         WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(tenant)
    .bind(idempotency_key)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
    Ok(PendingEvidence {
        event_id: row.get("event_id"),
        idempotency_key: idempotency_key.into(),
        payload: row.get("payload"),
        payload_digest: row.get("payload_digest"),
        result: parse_result(safe_result)?,
    })
}

fn parse_result(value: Option<Value>) -> Result<ContextMutationResult, ContextAuthorityError> {
    value
        .ok_or(ContextAuthorityError::OutcomeUnknown)
        .and_then(|value| {
            serde_json::from_value(value).map_err(|_| ContextAuthorityError::OutcomeUnknown)
        })
}

async fn apply_domain_mutation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    binding: &ContextExecutionBinding,
    request: &ContextExecutorRequest,
    effect: Option<&ContextEffectReceipt>,
    next_version: i64,
) -> Result<(bool, bool), ContextAuthorityError> {
    let payload = request
        .command
        .payload
        .as_object()
        .ok_or(ContextAuthorityError::RequestInvalid)?;
    let effect_quarantine = effect.is_some_and(|value| value.quarantine);
    let resulting_quarantine = match request.command.operation {
        ContextOperation::QuarantineResource => true,
        ContextOperation::ReleaseQuarantine => false,
        _ => effect_quarantine,
    };
    let legal_hold_blocked = effect.is_some_and(|value| value.legal_hold_blocked);
    match request.command.operation {
        ContextOperation::WriteMemory => {
            let memory_id = uuid_field_value(payload, "memory_id")?;
            let owner = string_field_value(payload, "owner_subject")?;
            let visibility = payload
                .get("visibility")
                .cloned()
                .ok_or(ContextAuthorityError::RequestInvalid)?;
            let provenance = payload
                .get("provenance")
                .cloned()
                .ok_or(ContextAuthorityError::RequestInvalid)?;
            let object_ref = effect
                .and_then(|value| value.object_ref.as_deref())
                .ok_or(ContextAuthorityError::DependencyUnavailable)?;
            let status = if effect_quarantine {
                "QUARANTINED"
            } else {
                "ACTIVE"
            };
            let quarantine_digest = if effect_quarantine {
                effect
                    .map(|value| canonical_digest(&value.poisoning_findings))
                    .transpose()?
                    .unwrap_or_else(|| "0".repeat(64))
            } else {
                "0".repeat(64)
            };
            sqlx::query(
                "INSERT INTO governed_memory_entries \
                 (tenant_id,memory_id,subject_id,owner_subject,action_digest,policy_digest,\
                  content_digest,object_ref,status,expires_at,requested_by,purpose,classification,\
                  jurisdiction,visibility,trust_level,provenance,policy_version,ledger_execution_id,\
                  fence_digest,resource_version,quarantine_reason_digest,updated_at) \
                 VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,now())",
            )
            .bind(tenant)
            .bind(memory_id)
            .bind(owner)
            .bind(&binding.action_hash)
            .bind(&binding.policy_decision_digest)
            .bind(string_field_value(payload, "content_digest")?)
            .bind(object_ref)
            .bind(status)
            .bind(time_field_value(payload, "expires_at")?)
            .bind(&request.actor_subject)
            .bind(string_field_value(payload, "purpose")?)
            .bind(string_field_value(payload, "classification")?)
            .bind(string_field_value(payload, "jurisdiction")?)
            .bind(visibility)
            .bind(string_field_value(payload, "trust_level")?)
            .bind(provenance)
            .bind(string_field_value(payload, "policy_version")?)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .bind(next_version)
            .bind(quarantine_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            if effect_quarantine {
                insert_quarantine(tx, tenant, "MEMORY", &memory_id.to_string(), effect).await?;
            }
        }
        ContextOperation::DeleteMemory => {
            let memory_id = uuid_field_value(payload, "memory_id")?;
            let row = sqlx::query(
                "SELECT content_digest,object_ref,owner_subject,status FROM governed_memory_entries \
                 WHERE tenant_id=$1 AND memory_id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(memory_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
            .ok_or(ContextAuthorityError::NotFound)?;
            if row.get::<String, _>("owner_subject") != request.actor_subject
                && !request
                    .approval_ids
                    .iter()
                    .any(|value| value.starts_with("privacy:"))
            {
                return Err(ContextAuthorityError::PrincipalDenied);
            }
            if row.get::<String, _>("content_digest")
                != string_field_value(payload, "content_digest")?
                || row.get::<String, _>("object_ref") != string_field_value(payload, "object_ref")?
            {
                return Err(ContextAuthorityError::StateConflict);
            }
            if row.get::<String, _>("status") == "TOMBSTONED" {
                return Err(ContextAuthorityError::StateConflict);
            }
            let new_status = if legal_hold_blocked {
                "HELD"
            } else {
                "TOMBSTONED"
            };
            sqlx::query(
                "UPDATE governed_memory_entries SET status=$3,resource_version=$4,\
                 ledger_execution_id=$5,fence_digest=$6,updated_at=now() \
                 WHERE tenant_id=$1 AND memory_id=$2",
            )
            .bind(tenant)
            .bind(memory_id)
            .bind(new_status)
            .bind(next_version)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            let deletion_receipt =
                serde_json::to_value(effect).map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
            sqlx::query(
                "INSERT INTO context_deletion_tombstones \
                 (tenant_id,tombstone_id,resource_type,resource_id,content_digest,deleted_by,\
                  object_purged,index_purged,cache_purged,legal_hold_blocked,deletion_receipt) \
                 VALUES ($1,$2,'MEMORY',$3,$4,$5,$6,$6,$6,$7,$8)",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(memory_id.to_string())
            .bind(row.get::<String, _>("content_digest"))
            .bind(&request.actor_subject)
            .bind(!legal_hold_blocked)
            .bind(legal_hold_blocked)
            .bind(deletion_receipt)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        }
        ContextOperation::PublishPrompt => {
            let prompt_id = string_field_value(payload, "prompt_id")?;
            let version = string_field_value(payload, "version")?;
            let object_ref = effect
                .and_then(|value| value.object_ref.as_deref())
                .ok_or(ContextAuthorityError::DependencyUnavailable)?;
            let status = if effect_quarantine {
                "QUARANTINED"
            } else {
                "STAGED"
            };
            sqlx::query(
                "INSERT INTO prompt_versions \
                 (tenant_id,prompt_id,version,content_digest,provenance_digest,signature,status,\
                  artifact_digest,supply_chain_receipt,approved_by,trust_level,rollout_percent,\
                  resource_version,object_ref,updated_at) \
                 VALUES ($1,$2,$3,$4,$5,decode($6,'base64'),$7,$8,$9,$10,$11,$12,$13,$14,now())",
            )
            .bind(tenant)
            .bind(prompt_id)
            .bind(version)
            .bind(string_field_value(payload, "content_digest")?)
            .bind(string_field_value(payload, "provenance_digest")?)
            .bind(string_field_value(payload, "signature")?)
            .bind(status)
            .bind(string_field_value(payload, "artifact_digest")?)
            .bind(
                payload
                    .get("supply_chain_receipt")
                    .cloned()
                    .ok_or(ContextAuthorityError::RequestInvalid)?,
            )
            .bind(
                payload
                    .get("approved_by")
                    .cloned()
                    .ok_or(ContextAuthorityError::RequestInvalid)?,
            )
            .bind(string_field_value(payload, "trust_level")?)
            .bind(i64_field_value(payload, "rollout_percent")?)
            .bind(next_version)
            .bind(object_ref)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            if effect_quarantine {
                insert_quarantine(tx, tenant, "PROMPT", prompt_id, effect).await?;
            }
        }
        ContextOperation::ActivatePrompt | ContextOperation::RollbackPrompt => {
            let prompt_id = string_field_value(payload, "prompt_id")?;
            let target_version = string_field_value(payload, "target_version")?;
            let target = sqlx::query_scalar::<_, String>(
                "SELECT status FROM prompt_versions WHERE tenant_id=$1 AND prompt_id=$2 \
                 AND version=$3 FOR UPDATE",
            )
            .bind(tenant)
            .bind(prompt_id)
            .bind(target_version)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
            .ok_or(ContextAuthorityError::NotFound)?;
            if !matches!(target.as_str(), "STAGED" | "RETIRED" | "ACTIVE") {
                return Err(ContextAuthorityError::StateConflict);
            }
            sqlx::query(
                "UPDATE prompt_versions SET status='RETIRED',updated_at=now() \
                 WHERE tenant_id=$1 AND prompt_id=$2 AND status='ACTIVE' AND version<>$3",
            )
            .bind(tenant)
            .bind(prompt_id)
            .bind(target_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            let updated = sqlx::query(
                "UPDATE prompt_versions SET status='ACTIVE',rollout_percent=$4,activated_at=now(),\
                 resource_version=$5,updated_at=now() WHERE tenant_id=$1 AND prompt_id=$2 \
                 AND version=$3 AND status IN ('STAGED','RETIRED','ACTIVE')",
            )
            .bind(tenant)
            .bind(prompt_id)
            .bind(target_version)
            .bind(i64_field_value(payload, "rollout_percent")?)
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            if updated.rows_affected() != 1 {
                return Err(ContextAuthorityError::StateConflict);
            }
        }
        ContextOperation::RegisterKnowledgeSource => {
            let provenance = payload
                .get("provenance")
                .cloned()
                .ok_or(ContextAuthorityError::RequestInvalid)?;
            sqlx::query(
                "INSERT INTO context_knowledge_sources \
                 (tenant_id,source_id,owner_subject,trust_level,allowed_subjects,classification,\
                  jurisdiction,provenance,resource_version) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(tenant)
            .bind(string_field_value(payload, "source_id")?)
            .bind(string_field_value(payload, "owner_subject")?)
            .bind(string_field_value(payload, "trust_level")?)
            .bind(
                payload
                    .get("allowed_subjects")
                    .cloned()
                    .ok_or(ContextAuthorityError::RequestInvalid)?,
            )
            .bind(string_field_value(payload, "classification")?)
            .bind(string_field_value(payload, "jurisdiction")?)
            .bind(provenance)
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
        }
        ContextOperation::PublishKnowledgeSnapshot => {
            let source_id = string_field_value(payload, "source_id")?;
            let source = sqlx::query(
                "SELECT trust_level,classification,jurisdiction,quarantined \
                 FROM context_knowledge_sources WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(source_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
            .ok_or(ContextAuthorityError::NotFound)?;
            if source.get::<bool, _>("quarantined")
                || !matches!(
                    source.get::<String, _>("trust_level").as_str(),
                    "VERIFIED" | "AUTHORITATIVE"
                )
                || source.get::<String, _>("classification")
                    != string_field_value(payload, "classification")?
                || source.get::<String, _>("jurisdiction")
                    != string_field_value(payload, "jurisdiction")?
            {
                return Err(ContextAuthorityError::StateConflict);
            }
            let object_ref = effect
                .and_then(|value| value.object_ref.as_deref())
                .ok_or(ContextAuthorityError::DependencyUnavailable)?;
            let index_ref = effect.and_then(|value| value.index_ref.as_deref());
            sqlx::query(
                "INSERT INTO knowledge_snapshots \
                 (tenant_id,source_id,snapshot_id,snapshot_digest,trust_level,object_ref,expires_at,\
                  source_version,content_digest,artifact_digest,supply_chain_receipt,classification,\
                  jurisdiction,quarantined,resource_version,created_at,updated_at,index_ref,tombstoned) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$4,$9,$10,$11,$12,$13,$14,now(),now(),$15,false)",
            )
            .bind(tenant)
            .bind(source_id)
            .bind(string_field_value(payload, "snapshot_id")?)
            .bind(string_field_value(payload, "content_digest")?)
            .bind(source.get::<String, _>("trust_level"))
            .bind(object_ref)
            .bind(time_field_value(payload, "expires_at")?)
            .bind(string_field_value(payload, "source_version")?)
            .bind(string_field_value(payload, "artifact_digest")?)
            .bind(
                payload
                    .get("supply_chain_receipt")
                    .cloned()
                    .ok_or(ContextAuthorityError::RequestInvalid)?,
            )
            .bind(string_field_value(payload, "classification")?)
            .bind(string_field_value(payload, "jurisdiction")?)
            .bind(effect_quarantine)
            .bind(next_version)
            .bind(index_ref)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            if effect_quarantine {
                insert_quarantine(
                    tx,
                    tenant,
                    "KNOWLEDGE_SNAPSHOT",
                    string_field_value(payload, "snapshot_id")?,
                    effect,
                )
                .await?;
            }
        }
        ContextOperation::DeleteKnowledgeSnapshot => {
            let snapshot_id = string_field_value(payload, "snapshot_id")?;
            let row = sqlx::query(
                "SELECT k.content_digest,k.object_ref,k.index_ref,k.tombstoned,s.owner_subject \
                 FROM knowledge_snapshots k JOIN context_knowledge_sources s \
                   ON s.tenant_id=k.tenant_id AND s.source_id=k.source_id \
                 WHERE k.tenant_id=$1 AND k.snapshot_id=$2 FOR UPDATE OF k,s",
            )
            .bind(tenant)
            .bind(snapshot_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?
            .ok_or(ContextAuthorityError::NotFound)?;
            if row.get::<bool, _>("tombstoned") {
                return Err(ContextAuthorityError::StateConflict);
            }
            if row.get::<String, _>("owner_subject") != request.actor_subject
                && !request
                    .approval_ids
                    .iter()
                    .any(|value| value.starts_with("privacy:"))
            {
                return Err(ContextAuthorityError::PrincipalDenied);
            }
            if row.get::<String, _>("content_digest")
                != string_field_value(payload, "content_digest")?
                || row.get::<String, _>("object_ref") != string_field_value(payload, "object_ref")?
                || row.get::<Option<String>, _>("index_ref").as_deref()
                    != string_field(payload, "index_ref")
            {
                return Err(ContextAuthorityError::StateConflict);
            }
            sqlx::query(
                "UPDATE knowledge_snapshots SET tombstoned=$3,quarantined=true,\
                 resource_version=$4,updated_at=now() WHERE tenant_id=$1 AND snapshot_id=$2",
            )
            .bind(tenant)
            .bind(snapshot_id)
            .bind(!legal_hold_blocked)
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            sqlx::query(
                "INSERT INTO context_deletion_tombstones \
                 (tenant_id,tombstone_id,resource_type,resource_id,content_digest,deleted_by,\
                  object_purged,index_purged,cache_purged,legal_hold_blocked,deletion_receipt) \
                 VALUES ($1,$2,'KNOWLEDGE_SNAPSHOT',$3,$4,$5,$6,$6,$6,$7,$8)",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(snapshot_id)
            .bind(row.get::<String, _>("content_digest"))
            .bind(&request.actor_subject)
            .bind(!legal_hold_blocked)
            .bind(legal_hold_blocked)
            .bind(serde_json::to_value(effect).map_err(|_| ContextAuthorityError::OutcomeUnknown)?)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
        }
        ContextOperation::QuarantineResource => {
            let resource_type = string_field_value(payload, "resource_type")?;
            let resource_id = string_field_value(payload, "resource_id")?;
            let quarantine_id = uuid_field_value(payload, "quarantine_id")?;
            sqlx::query(
                "INSERT INTO context_quarantine_records \
                 (tenant_id,quarantine_id,resource_type,resource_id,reason_codes,detector_digest) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(tenant)
            .bind(quarantine_id)
            .bind(resource_type)
            .bind(resource_id)
            .bind(
                payload
                    .get("reason_codes")
                    .cloned()
                    .ok_or(ContextAuthorityError::RequestInvalid)?,
            )
            .bind(string_field_value(payload, "detector_digest")?)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            set_resource_quarantine(tx, tenant, resource_type, resource_id, true, next_version)
                .await?;
        }
        ContextOperation::ReleaseQuarantine => {
            let resource_type = string_field_value(payload, "resource_type")?;
            let resource_id = string_field_value(payload, "resource_id")?;
            let quarantine_id = uuid_field_value(payload, "quarantine_id")?;
            let updated = sqlx::query(
                "UPDATE context_quarantine_records SET released_by=$4,\
                 remediation_evidence_ref=$5,remediation_evidence_digest=$6,released_at=now() \
                 WHERE tenant_id=$1 AND quarantine_id=$2 AND resource_id=$3 \
                   AND released_at IS NULL",
            )
            .bind(tenant)
            .bind(quarantine_id)
            .bind(resource_id)
            .bind(&request.actor_subject)
            .bind(string_field_value(payload, "remediation_evidence_ref")?)
            .bind(string_field_value(payload, "remediation_evidence_digest")?)
            .execute(&mut **tx)
            .await
            .map_err(|_| ContextAuthorityError::StateConflict)?;
            if updated.rows_affected() != 1 {
                return Err(ContextAuthorityError::StateConflict);
            }
            set_resource_quarantine(tx, tenant, resource_type, resource_id, false, next_version)
                .await?;
        }
    }
    Ok((resulting_quarantine, legal_hold_blocked))
}

async fn insert_quarantine(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    resource_type: &str,
    resource_id: &str,
    effect: Option<&ContextEffectReceipt>,
) -> Result<(), ContextAuthorityError> {
    let receipt = effect.ok_or(ContextAuthorityError::DependencyUnavailable)?;
    let reason_codes = serde_json::to_value(&receipt.poisoning_findings)
        .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
    let detector_digest = canonical_digest(&receipt.poisoning_findings)?;
    sqlx::query(
        "INSERT INTO context_quarantine_records \
         (tenant_id,quarantine_id,resource_type,resource_id,reason_codes,detector_digest) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(resource_type)
    .bind(resource_id)
    .bind(reason_codes)
    .bind(detector_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| ContextAuthorityError::OutcomeUnknown)?;
    Ok(())
}

async fn set_resource_quarantine(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    resource_type: &str,
    resource_id: &str,
    quarantined: bool,
    resource_version: i64,
) -> Result<(), ContextAuthorityError> {
    let affected = match resource_type {
        "MEMORY" => {
            let memory_id = Uuid::parse_str(resource_id)
                .map_err(|_| ContextAuthorityError::RequestInvalid)?;
            sqlx::query(
                "UPDATE governed_memory_entries SET status=$3,resource_version=$4,updated_at=now() \
                 WHERE tenant_id=$1 AND memory_id=$2 AND status<>'TOMBSTONED'",
            )
            .bind(tenant)
            .bind(memory_id)
            .bind(if quarantined { "QUARANTINED" } else { "ACTIVE" })
            .bind(resource_version)
            .execute(&mut **tx)
            .await
        }
        "PROMPT" => sqlx::query(
            "UPDATE prompt_versions SET status=$3,resource_version=$4,updated_at=now() \
             WHERE tenant_id=$1 AND prompt_id=$2 AND status<>'REVOKED'",
        )
        .bind(tenant)
        .bind(resource_id)
        .bind(if quarantined { "QUARANTINED" } else { "STAGED" })
        .bind(resource_version)
        .execute(&mut **tx)
        .await,
        "KNOWLEDGE_SOURCE" => sqlx::query(
            "UPDATE context_knowledge_sources SET quarantined=$3,resource_version=$4,updated_at=now() \
             WHERE tenant_id=$1 AND source_id=$2",
        )
        .bind(tenant)
        .bind(resource_id)
        .bind(quarantined)
        .bind(resource_version)
        .execute(&mut **tx)
        .await,
        "KNOWLEDGE_SNAPSHOT" => sqlx::query(
            "UPDATE knowledge_snapshots SET quarantined=$3,resource_version=$4,updated_at=now() \
             WHERE tenant_id=$1 AND snapshot_id=$2 AND NOT tombstoned",
        )
        .bind(tenant)
        .bind(resource_id)
        .bind(quarantined)
        .bind(resource_version)
        .execute(&mut **tx)
        .await,
        _ => return Err(ContextAuthorityError::RequestInvalid),
    }
    .map_err(|_| ContextAuthorityError::StateConflict)?;
    if affected.rows_affected() == 0 {
        return Err(ContextAuthorityError::NotFound);
    }
    Ok(())
}

fn validate_command(
    tenant: &TenantId,
    actor_subject: &str,
    request: &ContextCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), ContextAuthorityError> {
    if request.schema_version != CONTEXT_COMMAND_SCHEMA
        || request.tenant_id.to_string() != tenant.0
        || request.command_id.is_nil()
        || request.task_id.is_nil()
        || !identifier(actor_subject, 256)
        || !resource_identifier(&request.resource)
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || request.requested_at > Utc::now() + Duration::minutes(1)
        || request.requested_at < Utc::now() - Duration::hours(24)
        || serde_json::to_vec(&request.payload).map_or(true, |bytes| bytes.len() > 1_048_576)
        || !payload_shape(request, actor_subject)
    {
        return Err(ContextAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn validate_execution(
    binding: &ContextExecutionBinding,
    request: &ContextExecutorRequest,
) -> Result<(), ContextAuthorityError> {
    if request.schema_version != CONTEXT_EXECUTOR_REQUEST_SCHEMA
        || request.command.tenant_id.to_string() != binding.tenant_id.0
        || request.command.expected_resource_version != binding.resource_version
        || request.actor_kind != "WORKLOAD"
        || !identifier(&request.actor_subject, 256)
        || !digest(&binding.action_hash)
        || binding.ledger_execution_id.is_nil()
        || binding.ledger_event_id.is_nil()
        || !digest(&binding.ledger_event_digest)
        || !digest(&binding.fence_digest)
        || !valid_idempotency_key(&binding.idempotency_key)
        || !identifier(&binding.trace_id, 256)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !evidence_reference(&binding.authorization_evidence_ref)
        || !digest(&binding.authorization_evidence_digest)
        || !payload_shape(&request.command, &request.actor_subject)
    {
        return Err(ContextAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn validate_retrieval(
    binding: &RetrievalAuthorizationBinding,
    request: &ContextRetrievalRequest,
) -> Result<(), ContextAuthorityError> {
    if request.schema_version != CONTEXT_RETRIEVAL_REQUEST_SCHEMA
        || request.tenant_id.to_string() != binding.tenant_id.0
        || request.retrieval_id.is_nil()
        || request.subject != binding.client_subject
        || !identifier(&request.subject, 256)
        || request.query.trim().is_empty()
        || request.query.len() > 16_384
        || request.query.contains('\0')
        || !identifier(&request.jurisdiction, 64)
        || !(1..=100).contains(&request.maximum_results)
        || request.requested_at > Utc::now() + Duration::minutes(1)
        || request.requested_at < Utc::now() - Duration::minutes(10)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !evidence_reference(&binding.policy_evidence_ref)
        || !digest(&binding.policy_evidence_digest)
        || !identifier(&binding.trace_id, 256)
    {
        return Err(ContextAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn payload_shape(request: &ContextCommandRequest, actor: &str) -> bool {
    let Some(payload) = request.payload.as_object() else {
        return false;
    };
    let resource_matches = |prefix: &str, id: &str| request.resource == format!("{prefix}:{id}");
    match request.operation {
        ContextOperation::WriteMemory => {
            exact_keys(
                payload,
                &[
                    "memory_id",
                    "owner_subject",
                    "purpose",
                    "classification",
                    "jurisdiction",
                    "visibility",
                    "trust_level",
                    "provenance",
                    "content_digest",
                    "staging_object_ref",
                    "policy_version",
                    "expires_at",
                ],
            ) && uuid_field(payload, "memory_id")
                && string_field(payload, "owner_subject") == Some(actor)
                && identifier_field(payload, "purpose", 128)
                && classification_field(payload, "classification")
                && identifier_field(payload, "jurisdiction", 64)
                && string_array(payload, "visibility", 1, 256, |value| {
                    identifier(value, 256)
                })
                && trust_field(payload, "trust_level")
                && provenance_field(payload, "provenance")
                && digest_field(payload, "content_digest")
                && object_reference_field(payload, "staging_object_ref")
                && version_field(payload, "policy_version")
                && future_time_field(payload, "expires_at", Duration::days(366))
                && string_field(payload, "memory_id")
                    .is_some_and(|value| resource_matches("memory", value))
                && request.expected_resource_version == 0
        }
        ContextOperation::DeleteMemory => {
            exact_keys(
                payload,
                &[
                    "memory_id",
                    "content_digest",
                    "object_ref",
                    "legal_hold_id",
                    "reason_code",
                ],
            ) && uuid_field(payload, "memory_id")
                && digest_field(payload, "content_digest")
                && object_reference_field(payload, "object_ref")
                && identifier_field(payload, "legal_hold_id", 256)
                && identifier_field(payload, "reason_code", 128)
                && string_field(payload, "memory_id")
                    .is_some_and(|value| resource_matches("memory", value))
                && request.expected_resource_version > 0
        }
        ContextOperation::PublishPrompt => {
            exact_keys(
                payload,
                &[
                    "prompt_id",
                    "version",
                    "content_digest",
                    "provenance_digest",
                    "artifact_digest",
                    "signature",
                    "supply_chain_receipt",
                    "approved_by",
                    "trust_level",
                    "rollout_percent",
                    "staging_object_ref",
                ],
            ) && identifier_field(payload, "prompt_id", 256)
                && semver_field(payload, "version")
                && digest_field(payload, "content_digest")
                && digest_field(payload, "provenance_digest")
                && digest_field(payload, "artifact_digest")
                && base64_field(payload, "signature", 32, 512)
                && supply_chain_receipt(payload.get("supply_chain_receipt"))
                && string_array(payload, "approved_by", 2, 32, |value| {
                    identifier(value, 256)
                })
                && matches!(
                    string_field(payload, "trust_level"),
                    Some("VERIFIED" | "AUTHORITATIVE")
                )
                && percentage_field(payload, "rollout_percent")
                && object_reference_field(payload, "staging_object_ref")
                && string_field(payload, "prompt_id")
                    .is_some_and(|value| resource_matches("prompt", value))
        }
        ContextOperation::ActivatePrompt | ContextOperation::RollbackPrompt => {
            exact_keys(
                payload,
                &[
                    "prompt_id",
                    "target_version",
                    "rollout_percent",
                    "reason_code",
                ],
            ) && identifier_field(payload, "prompt_id", 256)
                && semver_field(payload, "target_version")
                && percentage_field(payload, "rollout_percent")
                && identifier_field(payload, "reason_code", 128)
                && string_field(payload, "prompt_id")
                    .is_some_and(|value| resource_matches("prompt", value))
        }
        ContextOperation::RegisterKnowledgeSource => {
            exact_keys(
                payload,
                &[
                    "source_id",
                    "owner_subject",
                    "trust_level",
                    "allowed_subjects",
                    "classification",
                    "jurisdiction",
                    "provenance",
                ],
            ) && identifier_field(payload, "source_id", 256)
                && string_field(payload, "owner_subject") == Some(actor)
                && trust_field(payload, "trust_level")
                && string_array(payload, "allowed_subjects", 1, 1024, |value| {
                    identifier(value, 256)
                })
                && classification_field(payload, "classification")
                && identifier_field(payload, "jurisdiction", 64)
                && provenance_field(payload, "provenance")
                && string_field(payload, "source_id")
                    .is_some_and(|value| resource_matches("knowledge-source", value))
                && request.expected_resource_version == 0
        }
        ContextOperation::PublishKnowledgeSnapshot => {
            exact_keys(
                payload,
                &[
                    "source_id",
                    "snapshot_id",
                    "source_version",
                    "content_digest",
                    "artifact_digest",
                    "supply_chain_receipt",
                    "classification",
                    "jurisdiction",
                    "staging_object_ref",
                    "expires_at",
                ],
            ) && identifier_field(payload, "source_id", 256)
                && identifier_field(payload, "snapshot_id", 256)
                && semver_field(payload, "source_version")
                && digest_field(payload, "content_digest")
                && digest_field(payload, "artifact_digest")
                && supply_chain_receipt(payload.get("supply_chain_receipt"))
                && classification_field(payload, "classification")
                && identifier_field(payload, "jurisdiction", 64)
                && object_reference_field(payload, "staging_object_ref")
                && future_time_field(payload, "expires_at", Duration::days(366))
                && string_field(payload, "snapshot_id")
                    .is_some_and(|value| resource_matches("knowledge-snapshot", value))
                && request.expected_resource_version == 0
        }
        ContextOperation::DeleteKnowledgeSnapshot => {
            exact_keys(
                payload,
                &[
                    "snapshot_id",
                    "content_digest",
                    "object_ref",
                    "index_ref",
                    "legal_hold_id",
                    "reason_code",
                ],
            ) && identifier_field(payload, "snapshot_id", 256)
                && digest_field(payload, "content_digest")
                && object_reference_field(payload, "object_ref")
                && index_reference_field(payload, "index_ref")
                && identifier_field(payload, "legal_hold_id", 256)
                && identifier_field(payload, "reason_code", 128)
                && string_field(payload, "snapshot_id")
                    .is_some_and(|value| resource_matches("knowledge-snapshot", value))
                && request.expected_resource_version > 0
        }
        ContextOperation::QuarantineResource => {
            exact_keys(
                payload,
                &[
                    "quarantine_id",
                    "resource_type",
                    "resource_id",
                    "reason_codes",
                    "detector_digest",
                    "object_ref",
                    "index_ref",
                ],
            ) && uuid_field(payload, "quarantine_id")
                && resource_type_field(payload, "resource_type")
                && identifier_field(payload, "resource_id", 512)
                && string_array(payload, "reason_codes", 1, 64, |value| {
                    identifier(value, 128)
                })
                && digest_field(payload, "detector_digest")
                && object_reference_field(payload, "object_ref")
                && optional_index_reference_field(payload, "index_ref")
                && resource_from_type(payload).as_deref() == Some(request.resource.as_str())
                && request.expected_resource_version > 0
        }
        ContextOperation::ReleaseQuarantine => {
            exact_keys(
                payload,
                &[
                    "quarantine_id",
                    "resource_type",
                    "resource_id",
                    "content_digest",
                    "object_ref",
                    "remediation_evidence_ref",
                    "remediation_evidence_digest",
                ],
            ) && uuid_field(payload, "quarantine_id")
                && resource_type_field(payload, "resource_type")
                && identifier_field(payload, "resource_id", 512)
                && digest_field(payload, "content_digest")
                && object_reference_field(payload, "object_ref")
                && evidence_reference_field(payload, "remediation_evidence_ref")
                && digest_field(payload, "remediation_evidence_digest")
                && resource_from_type(payload).as_deref() == Some(request.resource.as_str())
                && request.expected_resource_version > 0
        }
    }
}

fn canonical_context_action(
    request: &ContextExecutorRequest,
    config: &ContextAuthorityConfig,
    idempotency_key: &str,
) -> Result<InboundEnvelope, ContextAuthorityError> {
    let now = Utc::now();
    let command = &request.command;
    let tenant = TenantId(command.tenant_id.to_string());
    let data = serde_json::to_value(request)
        .map_err(|_| ContextAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(ContextAuthorityError::RequestInvalid)?;
    let plan_hash = canonical_digest(&json!({
        "operation": command.operation,
        "resource": command.resource,
        "expected_resource_version": command.expected_resource_version,
        "payload": command.payload,
    }))?;
    let mut extensions = BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    extensions.insert(
        "x-required-control-path".into(),
        Value::String("CANONICAL_ACTION_IR->PEP->LEDGER->EVIDENCE".into()),
    );
    extensions.insert(
        "x-retrieval-order-invariant".into(),
        Value::String("AUTHORIZATION_BEFORE_SIMILARITY".into()),
    );
    let operation = command.operation.as_str().to_ascii_lowercase();
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(command.command_id.to_string()),
        task_id: TaskId(command.task_id.to_string()),
        step_id: StepId::new(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "context-governance-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: request.actor_subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-context-governance".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: format!("workload-identity://{}", request.actor_subject),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: canonical_digest(command)?,
            operation: operation.clone(),
            justification_code: "CONTEXT_PROVENANCE_GOVERNANCE".into(),
            safe_summary: Some(format!(
                "{} {}",
                command.operation.as_str(),
                command.resource
            )),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "context.governance.mutation.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator: format!("context-governance/{}", command.resource),
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: false,
        },
        current_state_version: Some(command.expected_resource_version.to_string()),
        risk: RiskContext {
            declared_risk: command.operation.risk(),
            trajectory_risk_ref: None,
            scope_delta: 1,
            automation_allowed: false,
        },
        data: DataContext {
            classification: payload_classification(&command.payload),
            jurisdiction: payload_jurisdiction(&command.payload)
                .unwrap_or_else(|| config.region.clone()),
            export_constraints: vec![
                "TENANT_BOUND".into(),
                "PROVENANCE_REQUIRED".into(),
                "NO_PRIVATE_REASONING".into(),
            ],
        },
        expected_outcome: ExpectedOutcome {
            metric: "context_resource_version_advanced_with_evidence".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "context-governance/".into(),
            operations: vec![operation],
        }],
        requested_at: command.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("context.governance.mutation.v1", "1");
    let action =
        normalize(draft, &normalization).map_err(|_| ContextAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| ContextAuthorityError::RequestInvalid)?;
    let payload = serde_json::to_vec(&action).map_err(|_| ContextAuthorityError::RequestInvalid)?;
    Ok(InboundEnvelope {
        request_id: Uuid::new_v4().to_string(),
        trace_context: TraceContext {
            trace_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
            invalid_input_replaced: false,
        },
        identity_context: IdentityContext {
            subject: config.service_subject.clone(),
            tenant_id: tenant.clone(),
            agent_instance_id: config.service_agent_id.clone(),
            owner_subject: request.actor_subject.clone(),
            trust_level: "attested".into(),
        },
        tenant_context: TenantContext {
            tenant_id: tenant,
            quota_profile: "context-governance-authority".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: Some(idempotency_key.into()),
        received_at: now,
        payload_hash: sha256(&payload),
        payload,
    })
}

fn validate_effect(
    binding: &ContextExecutionBinding,
    request: &ContextExecutorRequest,
    receipt: Option<&ContextEffectReceipt>,
) -> Result<(), ContextAuthorityError> {
    if request.command.operation.external_effects() != receipt.is_some() {
        return Err(ContextAuthorityError::DependencyUnavailable);
    }
    let Some(receipt) = receipt else {
        return Ok(());
    };
    let mut unsigned = receipt.clone();
    unsigned.receipt_digest.clear();
    if receipt.schema_version != "agenttrust.context-effect-receipt.v1"
        || receipt.tenant_id != request.command.tenant_id
        || receipt.action_hash != binding.action_hash
        || receipt.ledger_execution_id != binding.ledger_execution_id
        || receipt.idempotency_key != binding.idempotency_key
        || receipt.operation != request.command.operation
        || receipt.resource != request.command.resource
        || receipt.receipts.is_empty()
        || receipt.receipts.len() > 16
        || canonical_digest(&unsigned)? != receipt.receipt_digest
        || receipt.receipts.iter().any(|item| {
            item.idempotency_key != binding.idempotency_key
                || item.resource != request.command.resource
                || !identifier(&item.adapter, 128)
                || !identifier(&item.operation, 128)
                || !digest(&item.request_digest)
                || !digest(&item.receipt_digest)
                || !adapter_reference(&item.reference)
        })
    {
        return Err(ContextAuthorityError::DependencyUnavailable);
    }
    let adapters = receipt
        .receipts
        .iter()
        .map(|value| value.adapter.as_str())
        .collect::<BTreeSet<_>>();
    let mut required = match request.command.operation {
        ContextOperation::WriteMemory => BTreeSet::from(["POISONING", "OBJECT_STORE"]),
        ContextOperation::DeleteMemory | ContextOperation::DeleteKnowledgeSnapshot => {
            if receipt.legal_hold_blocked {
                BTreeSet::from(["LEGAL_HOLD"])
            } else {
                BTreeSet::from(["LEGAL_HOLD", "OBJECT_STORE", "VECTOR_INDEX", "CACHE"])
            }
        }
        ContextOperation::PublishPrompt => {
            BTreeSet::from(["SUPPLY_CHAIN", "POISONING", "OBJECT_STORE"])
        }
        ContextOperation::PublishKnowledgeSnapshot => {
            BTreeSet::from(["SUPPLY_CHAIN", "POISONING", "OBJECT_STORE"])
        }
        ContextOperation::QuarantineResource => BTreeSet::from(["VECTOR_INDEX", "CACHE"]),
        ContextOperation::ReleaseQuarantine => {
            BTreeSet::from(["POISONING", "VECTOR_INDEX", "CACHE"])
        }
        ContextOperation::ActivatePrompt
        | ContextOperation::RollbackPrompt
        | ContextOperation::RegisterKnowledgeSource => BTreeSet::new(),
    };
    if !receipt.quarantine
        && matches!(
            request.command.operation,
            ContextOperation::WriteMemory | ContextOperation::PublishKnowledgeSnapshot
        )
    {
        required.insert("VECTOR_INDEX");
    }
    if !required.is_subset(&adapters)
        || receipt.quarantine != !receipt.poisoning_findings.is_empty()
        || receipt.quarantine && receipt.index_ref.is_some()
        || !receipt.quarantine
            && matches!(
                request.command.operation,
                ContextOperation::WriteMemory | ContextOperation::PublishKnowledgeSnapshot
            )
            && receipt
                .index_ref
                .as_deref()
                .is_none_or(|value| !index_reference(value))
        || matches!(
            request.command.operation,
            ContextOperation::WriteMemory
                | ContextOperation::PublishPrompt
                | ContextOperation::PublishKnowledgeSnapshot
        ) && receipt
            .object_ref
            .as_deref()
            .is_none_or(|value| !object_reference(value))
    {
        return Err(ContextAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn validate_evidence_receipt(
    pending: &PendingEvidence,
    receipt: &EvidenceDeliveryReceipt,
) -> Result<(), ContextAuthorityError> {
    if receipt.schema_version != "agenttrust.context-evidence-delivery-receipt.v1"
        || receipt.idempotency_key != pending.idempotency_key
        || !evidence_reference(&receipt.evidence_ref)
        || !digest(&receipt.evidence_digest)
        || receipt.payload_digest != pending.payload_digest
    {
        return Err(ContextAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn supply_chain_receipt(value: Option<&Value>) -> bool {
    let Some(value) = value.and_then(Value::as_object) else {
        return false;
    };
    exact_keys(
        value,
        &[
            "schema_version",
            "artifact_digest",
            "manifest_digest",
            "signer_key_id",
            "signature",
            "verified_at",
            "expires_at",
        ],
    ) && string_field(value, "schema_version") == Some("agenttrust.supply-chain-receipt.v1")
        && digest_field(value, "artifact_digest")
        && digest_field(value, "manifest_digest")
        && identifier_field(value, "signer_key_id", 128)
        && base64_field(value, "signature", 32, 512)
        && time_field(value, "verified_at").is_some()
        && future_time_field(value, "expires_at", Duration::days(30))
}

fn provenance_field(value: &Map<String, Value>, field: &str) -> bool {
    let Some(value) = value.get(field).and_then(Value::as_object) else {
        return false;
    };
    exact_keys(
        value,
        &[
            "schema_version",
            "source_type",
            "source_id",
            "source_version",
            "source_digest",
            "imported_by",
            "imported_at",
        ],
    ) && string_field(value, "schema_version") == Some("agenttrust.provenance.v1")
        && identifier_field(value, "source_type", 128)
        && identifier_field(value, "source_id", 512)
        && version_field(value, "source_version")
        && digest_field(value, "source_digest")
        && identifier_field(value, "imported_by", 256)
        && time_field(value, "imported_at").is_some()
}

fn resource_from_type(payload: &Map<String, Value>) -> Option<String> {
    let kind = string_field(payload, "resource_type")?;
    let id = string_field(payload, "resource_id")?;
    let prefix = match kind {
        "MEMORY" => "memory",
        "PROMPT" => "prompt",
        "KNOWLEDGE_SOURCE" => "knowledge-source",
        "KNOWLEDGE_SNAPSHOT" => "knowledge-snapshot",
        _ => return None,
    };
    Some(format!("{prefix}:{id}"))
}

fn payload_classification(value: &Value) -> DataClassification {
    match value
        .as_object()
        .and_then(|value| string_field(value, "classification"))
    {
        Some("PUBLIC") => DataClassification::Public,
        Some("INTERNAL") => DataClassification::Internal,
        Some("CONFIDENTIAL") => DataClassification::Confidential,
        Some("RESTRICTED") => DataClassification::Restricted,
        Some("REGULATED") => DataClassification::Regulated,
        _ => DataClassification::Restricted,
    }
}

fn payload_jurisdiction(value: &Value) -> Option<String> {
    value
        .as_object()
        .and_then(|value| string_field(value, "jurisdiction"))
        .map(str::to_string)
}

fn classification_rank(value: DataClassification) -> i32 {
    match value {
        DataClassification::Public => 0,
        DataClassification::Internal => 1,
        DataClassification::Confidential => 2,
        DataClassification::Restricted => 3,
        DataClassification::Regulated => 4,
    }
}

fn exact_keys(value: &Map<String, Value>, keys: &[&str]) -> bool {
    value.len() == keys.len() && keys.iter().all(|key| value.contains_key(*key))
}

fn string_field<'a>(value: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn string_field_value<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, ContextAuthorityError> {
    string_field(value, field).ok_or(ContextAuthorityError::RequestInvalid)
}

fn uuid_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(canonical_uuid)
}

fn uuid_field_value(
    value: &Map<String, Value>,
    field: &str,
) -> Result<Uuid, ContextAuthorityError> {
    Uuid::parse_str(string_field_value(value, field)?)
        .map_err(|_| ContextAuthorityError::RequestInvalid)
}

fn i64_field_value(value: &Map<String, Value>, field: &str) -> Result<i64, ContextAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(ContextAuthorityError::RequestInvalid)
}

fn time_field(value: &Map<String, Value>, field: &str) -> Option<DateTime<Utc>> {
    string_field(value, field)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn time_field_value(
    value: &Map<String, Value>,
    field: &str,
) -> Result<DateTime<Utc>, ContextAuthorityError> {
    time_field(value, field).ok_or(ContextAuthorityError::RequestInvalid)
}

fn future_time_field(value: &Map<String, Value>, field: &str, maximum: Duration) -> bool {
    time_field(value, field)
        .is_some_and(|value| value > Utc::now() && value <= Utc::now() + maximum)
}

fn identifier_field(value: &Map<String, Value>, field: &str, maximum: usize) -> bool {
    string_field(value, field).is_some_and(|value| identifier(value, maximum))
}

fn digest_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(digest)
}

fn classification_field(value: &Map<String, Value>, field: &str) -> bool {
    matches!(
        string_field(value, field),
        Some("PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "REGULATED")
    )
}

fn trust_field(value: &Map<String, Value>, field: &str) -> bool {
    matches!(
        string_field(value, field),
        Some("UNTRUSTED" | "IMPORTED" | "VERIFIED" | "AUTHORITATIVE")
    )
}

fn resource_type_field(value: &Map<String, Value>, field: &str) -> bool {
    matches!(
        string_field(value, field),
        Some("MEMORY" | "PROMPT" | "KNOWLEDGE_SOURCE" | "KNOWLEDGE_SNAPSHOT")
    )
}

fn semver_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(|value| {
        let parts = value.split('.').collect::<Vec<_>>();
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn version_field(value: &Map<String, Value>, field: &str) -> bool {
    identifier_field(value, field, 128)
}

fn percentage_field(value: &Map<String, Value>, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_u64)
        .is_some_and(|value| value <= 100)
}

fn base64_field(value: &Map<String, Value>, field: &str, minimum: usize, maximum: usize) -> bool {
    string_field(value, field).is_some_and(|value| {
        (minimum..=maximum).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
            })
    })
}

fn string_array(
    value: &Map<String, Value>,
    field: &str,
    minimum: usize,
    maximum: usize,
    validator: impl Fn(&str) -> bool,
) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            (minimum..=maximum).contains(&items.len())
                && items
                    .iter()
                    .all(|item| item.as_str().is_some_and(|value| validator(value)))
                && items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == items.len()
        })
}

fn object_reference_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(object_reference)
}

fn index_reference_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(index_reference)
}

fn optional_index_reference_field(value: &Map<String, Value>, field: &str) -> bool {
    value
        .get(field)
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(index_reference))
}

fn evidence_reference_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(evidence_reference)
}

pub(crate) fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

pub(crate) fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

pub(crate) fn resource_identifier(value: &str) -> bool {
    (1..=1024).contains(&value.len())
        && value.contains(':')
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(crate) fn object_reference(value: &str) -> bool {
    (value.starts_with("object://") || value.starts_with("s3://") || value.starts_with("gs://"))
        && value.len() <= 2048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

pub(crate) fn index_reference(value: &str) -> bool {
    value.starts_with("vector://")
        && value.len() <= 2048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

pub(crate) fn evidence_reference(value: &str) -> bool {
    (value.starts_with("evidence://") || value.starts_with("urn:agenttrust:evidence:"))
        && value.len() <= 2048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

fn adapter_reference(value: &str) -> bool {
    (value.starts_with("adapter-receipt://")
        || value.starts_with("object://")
        || value.starts_with("vector://")
        || value.starts_with("evidence://"))
        && value.len() <= 2048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

fn parse_tenant(value: &TenantId) -> Result<Uuid, ContextAuthorityError> {
    Uuid::parse_str(&value.0)
        .ok()
        .filter(|parsed| parsed.to_string() == value.0)
        .ok_or(ContextAuthorityError::PrincipalDenied)
}

pub(crate) fn canonical_digest<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, ContextAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| ContextAuthorityError::RequestInvalid)
}

pub(crate) fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}
