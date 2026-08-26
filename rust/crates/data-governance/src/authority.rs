//! Durable production authority for data-governance mutations.
//!
//! Public callers can only submit bounded metadata commands. Ingress normalizes each command to
//! Canonical Action IR and delegates authorization/scheduling to the durable orchestrator. The
//! executor accepts only an exact PEP, ledger, fence, resource-version, and Evidence binding.
//! Domain state and an immutable Evidence outbox event commit in the same tenant-RLS transaction.
//! Raw prompts, artifacts, credentials, DLP samples, and transformed content are never persisted.

use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION, ActionId, AgentIdentity, AgentInstanceId,
    AuthorityEvidenceSourceKind, CONTRACT_SCHEMA_VERSION, DataClassification, DataContext,
    DataPolicyRequest, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector,
    RiskContext, RiskLevel, SchemaVersion, SignedAuthorityEvidenceReceipt, StepId, TaskId,
    TenantId, ToolId, ToolRef, ToolVersion,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const DATA_COMMAND_SCHEMA: &str = "agenttrust.data-governance-command.v1";
pub const DATA_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.data-governance-execution-request.v1";
pub const DATA_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.data-governance-action-receipt.v1";
pub const DATA_MUTATION_RESULT_SCHEMA: &str = "agenttrust.data-governance-mutation-result.v1";
pub const DATA_EVIDENCE_SCHEMA: &str = "agenttrust.data-governance-evidence.v1";
pub const DATA_READINESS_SCHEMA: &str = "agenttrust.data-governance-readiness.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DataAuthorityError {
    #[error("DATA_AUTHORITY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("DATA_AUTHORITY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("DATA_AUTHORITY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("DATA_AUTHORITY_STATE_CONFLICT")]
    StateConflict,
    #[error("DATA_AUTHORITY_NOT_FOUND")]
    NotFound,
    #[error("DATA_AUTHORITY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("DATA_AUTHORITY_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("DATA_AUTHORITY_DLP_DENIED")]
    DlpDenied,
    #[error("DATA_AUTHORITY_CROSS_DOMAIN_REPLAYED")]
    CrossDomainReplayed,
    #[error("DATA_AUTHORITY_LEGAL_HOLD_BLOCKED")]
    LegalHoldBlocked,
    #[error("DATA_AUTHORITY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataOperation {
    RegisterLabel,
    RecordPolicyDecision,
    RecordDlpScan,
    RecordTransformReceipt,
    IssueCrossDomainGrant,
    ConsumeCrossDomainGrant,
    ResolveRetention,
    PlaceLegalHold,
    ReleaseLegalHold,
    AuthorizeExport,
    CompleteExport,
}

impl DataOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterLabel => "REGISTER_LABEL",
            Self::RecordPolicyDecision => "RECORD_POLICY_DECISION",
            Self::RecordDlpScan => "RECORD_DLP_SCAN",
            Self::RecordTransformReceipt => "RECORD_TRANSFORM_RECEIPT",
            Self::IssueCrossDomainGrant => "ISSUE_CROSS_DOMAIN_GRANT",
            Self::ConsumeCrossDomainGrant => "CONSUME_CROSS_DOMAIN_GRANT",
            Self::ResolveRetention => "RESOLVE_RETENTION",
            Self::PlaceLegalHold => "PLACE_LEGAL_HOLD",
            Self::ReleaseLegalHold => "RELEASE_LEGAL_HOLD",
            Self::AuthorizeExport => "AUTHORIZE_EXPORT",
            Self::CompleteExport => "COMPLETE_EXPORT",
        }
    }

    fn risk(self) -> RiskLevel {
        match self {
            Self::RegisterLabel
            | Self::RecordPolicyDecision
            | Self::RecordDlpScan
            | Self::RecordTransformReceipt
            | Self::ResolveRetention => RiskLevel::High,
            Self::IssueCrossDomainGrant
            | Self::ConsumeCrossDomainGrant
            | Self::PlaceLegalHold
            | Self::ReleaseLegalHold
            | Self::AuthorizeExport
            | Self::CompleteExport => RiskLevel::Critical,
        }
    }

    pub(crate) fn requires_external_effect(self) -> bool {
        matches!(
            self,
            Self::RecordDlpScan
                | Self::ResolveRetention
                | Self::PlaceLegalHold
                | Self::ReleaseLegalHold
                | Self::AuthorizeExport
                | Self::CompleteExport
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub task_id: Uuid,
    pub resource: String,
    pub operation: DataOperation,
    pub expected_resource_version: u64,
    pub requested_at: DateTime<Utc>,
    /// Operation-specific metadata. Raw content fields are rejected by `validate_payload`.
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataExecutorRequest {
    pub schema_version: String,
    pub command: DataCommandRequest,
    pub actor_subject: String,
    pub actor_kind: String,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataExecutionBinding {
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
pub struct DataActionReceipt {
    pub schema_version: String,
    pub action_id: String,
    pub task_id: String,
    pub accepted: bool,
    pub execution_pending: bool,
    pub ingress_digest: String,
    pub ledger_evidence_ref: String,
    pub ledger_evidence_digest: String,
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
pub struct DataEffectReceipt {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub idempotency_key: String,
    pub operation: DataOperation,
    pub resource: String,
    pub receipts: Vec<AdapterReceipt>,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub operation: DataOperation,
    pub resource: String,
    pub resource_version: u64,
    pub state: String,
    pub result_digest: String,
    pub evidence_outbox_ref: String,
    pub evidence_ref: Option<String>,
    pub evidence_digest: Option<String>,
    pub safe_receipts: Vec<AdapterReceipt>,
}

#[derive(Debug, Clone)]
pub struct ArtifactDurablePreflight {
    pub authorization_id: Uuid,
    pub object_ref: String,
    pub object_digest: String,
    pub label: Value,
    pub label_digest: String,
    pub policy_request: Value,
    pub policy_request_digest: String,
    pub decision_id: Uuid,
    pub decision: Value,
    pub decision_digest: String,
    pub required_transformations: BTreeSet<String>,
    pub dlp_scan_id: Uuid,
    pub dlp_receipt_digest: String,
    pub transform_id: Option<Uuid>,
    pub transform_receipt_digest: Option<String>,
    pub cross_domain_grant_id: Option<Uuid>,
    pub cross_domain_approval_id: Option<Uuid>,
    pub source_jurisdiction: String,
    pub target_jurisdiction: String,
    pub classification: DataClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeDataResource {
    pub resource: String,
    pub resource_version: u64,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub fence_digest: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeDataPage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub authoritative: bool,
    pub items: Vec<AuthoritativeDataResource>,
    pub next_after: Option<String>,
    pub data_digest: String,
}

#[derive(Debug, Clone)]
pub struct DataAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
}

impl DataAuthorityConfig {
    pub fn validate(&self) -> Result<(), DataAuthorityError> {
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
            Err(DataAuthorityError::ConfigurationInvalid)
        }
    }
}

#[async_trait]
pub trait DataOrchestratorPort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<DataActionReceipt, DataAuthorityError>;
}

#[async_trait]
pub trait DataRuntimePort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn execute_effects(
        &self,
        binding: &DataExecutionBinding,
        request: &DataExecutorRequest,
    ) -> Result<Option<DataEffectReceipt>, DataAuthorityError>;
    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<SignedAuthorityEvidenceReceipt, DataAuthorityError>;
}

#[derive(Clone)]
pub struct DataIngressAuthority {
    store: PostgresDataAuthorityStore,
    orchestrator: Arc<dyn DataOrchestratorPort>,
    config: DataAuthorityConfig,
}

impl DataIngressAuthority {
    pub fn new(
        store: PostgresDataAuthorityStore,
        orchestrator: Arc<dyn DataOrchestratorPort>,
        config: DataAuthorityConfig,
    ) -> Result<Self, DataAuthorityError> {
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
        request: DataCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<DataActionReceipt, DataAuthorityError> {
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
            return Err(DataAuthorityError::StateConflict);
        }
        let executor = DataExecutorRequest {
            schema_version: DATA_EXECUTOR_REQUEST_SCHEMA.into(),
            command: request.clone(),
            actor_subject: actor_subject.clone(),
            actor_kind: "WORKLOAD".into(),
            approval_ids: BTreeSet::new(),
        };
        let envelope = canonical_data_action(&executor, &self.config, idempotency_key)?;
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
    ) -> Result<AuthoritativeDataPage, DataAuthorityError> {
        self.store.authoritative_page(tenant, after, limit).await
    }

    /// Read a completed mutation by its canonical command/action identifier. Pending rows never
    /// expose a proposal as durable Evidence; callers retry until the final result is available.
    pub async fn completed_mutation(
        &self,
        tenant: &TenantId,
        command_id: Uuid,
    ) -> Result<DataMutationResult, DataAuthorityError> {
        self.store.completed_mutation(tenant, command_id).await
    }
}

#[derive(Clone)]
pub struct DataExecutor {
    store: PostgresDataAuthorityStore,
    runtime: Arc<dyn DataRuntimePort>,
    execution_lease_seconds: i64,
}

impl DataExecutor {
    pub fn new(
        store: PostgresDataAuthorityStore,
        runtime: Arc<dyn DataRuntimePort>,
        execution_lease_seconds: i64,
    ) -> Result<Self, DataAuthorityError> {
        if !(15..=300).contains(&execution_lease_seconds) {
            return Err(DataAuthorityError::ConfigurationInvalid);
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
        binding: DataExecutionBinding,
        request: DataExecutorRequest,
    ) -> Result<DataMutationResult, DataAuthorityError> {
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
                if matches!(
                    request.command.operation,
                    DataOperation::AuthorizeExport | DataOperation::CompleteExport
                ) {
                    self.store
                        .verify_external_effect_preconditions(&binding.tenant_id, &request)
                        .await?;
                }
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
    ) -> Result<DataMutationResult, DataAuthorityError> {
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
    ) -> Result<Vec<DataMutationResult>, DataAuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(DataAuthorityError::RequestInvalid);
        }
        let mut results = Vec::new();
        for pending in self.store.pending_evidence(tenant, limit).await? {
            results.push(self.deliver_and_finalize(tenant, pending).await?);
        }
        Ok(results)
    }
}

#[derive(Clone)]
pub struct PostgresDataAuthorityStore {
    pool: PgPool,
}

impl PostgresDataAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok_and(|value| value == 1)
    }

    /// Reject invalid durable export commands before any object/WORM or Enterprise DLP effect.
    /// The mutation transaction repeats every check after the effect to close the race window.
    pub async fn verify_external_effect_preconditions(
        &self,
        tenant: &TenantId,
        request: &DataExecutorRequest,
    ) -> Result<(), DataAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let payload = payload_object(&request.command.payload)?;
        let mut tx = self.begin_tenant(tenant).await?;
        match request.command.operation {
            DataOperation::AuthorizeExport => {
                verify_authorize_export_prerequisites(&mut tx, tenant_uuid, payload).await?;
            }
            DataOperation::CompleteExport => {
                let permitted = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS (SELECT 1 FROM data_export_intents \
                     WHERE tenant_id=$1 AND export_id=$2::uuid AND object_digest=$3 \
                       AND state='AUTHORIZED' AND expires_at>now())",
                )
                .bind(tenant_uuid)
                .bind(text(payload, "export_id")?)
                .bind(text(payload, "object_digest")?)
                .fetch_one(&mut *tx)
                .await
                .map_err(dependency)?;
                if !permitted {
                    return Err(DataAuthorityError::StateConflict);
                }
            }
            _ => {}
        }
        tx.commit().await.map_err(dependency)?;
        Ok(())
    }

    /// Verify that an ephemeral Artifact authorization is backed by the exact tenant-RLS durable
    /// label, policy decision, DLP summary, required transform, and cross-domain grant. This is a
    /// read-only preflight; export state still changes only through the governed mutation executor.
    pub async fn verify_artifact_preflight(
        &self,
        tenant: &TenantId,
        binding: &ArtifactDurablePreflight,
    ) -> Result<(), DataAuthorityError> {
        if !canonical_uuid(&binding.authorization_id.to_string())
            || !object_reference(&binding.object_ref)
            || !digest(&binding.object_digest)
            || !digest(&binding.label_digest)
            || canonical_digest(&binding.label)? != binding.label_digest
            || !digest(&binding.policy_request_digest)
            || canonical_digest(&binding.policy_request)? != binding.policy_request_digest
            || !canonical_uuid(&binding.decision_id.to_string())
            || !digest(&binding.decision_digest)
            || canonical_digest(&binding.decision)? != binding.decision_digest
            || !canonical_uuid(&binding.dlp_scan_id.to_string())
            || !digest(&binding.dlp_receipt_digest)
            || binding.transform_id.is_some() != binding.transform_receipt_digest.is_some()
            || binding
                .transform_receipt_digest
                .as_deref()
                .is_some_and(|value| !digest(value))
            || binding.cross_domain_grant_id.is_some() != binding.cross_domain_approval_id.is_some()
            || !jurisdiction(&binding.source_jurisdiction)
            || !jurisdiction(&binding.target_jurisdiction)
            || binding.required_transformations.len() > 32
            || binding
                .required_transformations
                .iter()
                .any(|value| !identifier(value, 256))
        {
            return Err(DataAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let label = sqlx::query(
            "SELECT object_ref,object_digest,label FROM governed_data_labels \
             WHERE tenant_id=$1 AND label_digest=$2",
        )
        .bind(tenant_uuid)
        .bind(&binding.label_digest)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .ok_or(DataAuthorityError::DlpDenied)?;
        if label.get::<String, _>("object_ref") != binding.object_ref
            || label.get::<String, _>("object_digest") != binding.object_digest
            || label.get::<Value, _>("label") != binding.label
        {
            return Err(DataAuthorityError::DlpDenied);
        }

        let decision = sqlx::query(
            "SELECT request_digest,request,decision,decision_digest,allowed,shadow \
             FROM data_policy_decision_records WHERE tenant_id=$1 AND decision_id=$2",
        )
        .bind(tenant_uuid)
        .bind(binding.decision_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .ok_or(DataAuthorityError::DlpDenied)?;
        if decision.get::<String, _>("request_digest") != binding.policy_request_digest
            || decision.get::<Value, _>("request") != binding.policy_request
            || decision.get::<Value, _>("decision") != binding.decision
            || decision.get::<String, _>("decision_digest") != binding.decision_digest
            || !decision.get::<bool, _>("allowed")
            || decision.get::<bool, _>("shadow")
        {
            return Err(DataAuthorityError::DlpDenied);
        }

        let scan = sqlx::query(
            "SELECT content_digest,engine_receipt_digest,high_risk,blocking \
             FROM data_dlp_scan_summaries \
             WHERE tenant_id=$1 AND scan_id=$2",
        )
        .bind(tenant_uuid)
        .bind(binding.dlp_scan_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .ok_or(DataAuthorityError::DlpDenied)?;
        if scan.get::<String, _>("content_digest") != binding.object_digest
            || scan.get::<String, _>("engine_receipt_digest") != binding.dlp_receipt_digest
            || scan.get::<bool, _>("high_risk")
                != (binding.classification >= DataClassification::Confidential)
            || scan.get::<bool, _>("blocking")
        {
            return Err(DataAuthorityError::DlpDenied);
        }

        match (
            binding.transform_id,
            binding.transform_receipt_digest.as_deref(),
        ) {
            (None, None) if binding.required_transformations.is_empty() => {}
            (Some(transform_id), Some(transform_digest))
                if !binding.required_transformations.is_empty() =>
            {
                let transform = sqlx::query(
                    "SELECT output_digest,transformations,transform_receipt_digest \
                     FROM data_transform_receipts WHERE tenant_id=$1 AND transform_id=$2",
                )
                .bind(tenant_uuid)
                .bind(transform_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(dependency)?
                .ok_or(DataAuthorityError::DlpDenied)?;
                let transformations = transform
                    .get::<Value, _>("transformations")
                    .as_array()
                    .cloned()
                    .ok_or(DataAuthorityError::DependencyUnavailable)?
                    .into_iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect::<Option<BTreeSet<_>>>()
                    .ok_or(DataAuthorityError::DependencyUnavailable)?;
                if transform.get::<String, _>("output_digest") != binding.object_digest
                    || transform.get::<String, _>("transform_receipt_digest") != transform_digest
                    || !binding.required_transformations.is_subset(&transformations)
                {
                    return Err(DataAuthorityError::DlpDenied);
                }
            }
            _ => return Err(DataAuthorityError::DlpDenied),
        }

        match (
            binding.cross_domain_grant_id,
            binding.cross_domain_approval_id,
        ) {
            (None, None) => {}
            (Some(grant_id), Some(approval_id)) => {
                let grant = sqlx::query(
                    "SELECT source_jurisdiction,target_jurisdiction,object_digest,classification,\
                            approval_id,expires_at>now() AS valid,single_use,consumed_at,consumption_id \
                     FROM data_cross_domain_grants WHERE tenant_id=$1 AND grant_id=$2",
                )
                .bind(tenant_uuid)
                .bind(grant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(dependency)?
                .ok_or(DataAuthorityError::DlpDenied)?;
                let consumed_for_authorization = match (
                    grant.get::<Option<DateTime<Utc>>, _>("consumed_at"),
                    grant.get::<Option<Uuid>, _>("consumption_id"),
                ) {
                    (None, None) => true,
                    (Some(_), Some(consumption_id)) => sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS (SELECT 1 FROM data_cross_domain_consumptions \
                         WHERE tenant_id=$1 AND consumption_id=$2 AND grant_id=$3 \
                           AND export_intent_id=$4 AND object_digest=$5)",
                    )
                    .bind(tenant_uuid)
                    .bind(consumption_id)
                    .bind(grant_id)
                    .bind(binding.authorization_id)
                    .bind(&binding.object_digest)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(dependency)?,
                    _ => false,
                };
                if grant.get::<String, _>("source_jurisdiction") != binding.source_jurisdiction
                    || grant.get::<String, _>("target_jurisdiction") != binding.target_jurisdiction
                    || grant.get::<String, _>("object_digest") != binding.object_digest
                    || grant.get::<String, _>("classification")
                        != classification_name(binding.classification)
                    || grant.get::<Uuid, _>("approval_id") != approval_id
                    || !grant.get::<bool, _>("valid")
                    || !grant.get::<bool, _>("single_use")
                    || !consumed_for_authorization
                {
                    return Err(DataAuthorityError::DlpDenied);
                }
            }
            _ => return Err(DataAuthorityError::DlpDenied),
        }
        tx.commit().await.map_err(dependency)?;
        Ok(())
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, DataAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(dependency)?;
        let selected =
            sqlx::query_scalar::<_, String>("SELECT set_config('app.tenant_id',$1,true)")
                .bind(tenant_uuid.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(dependency)?;
        if selected != tenant_uuid.to_string() {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        Ok(tx)
    }

    async fn current_resource_version(
        &self,
        tenant: &TenantId,
        resource: &str,
    ) -> Result<u64, DataAuthorityError> {
        if !resource_reference(resource) {
            return Err(DataAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let value = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM data_resource_versions \
             WHERE tenant_id=$1 AND resource=$2",
        )
        .bind(tenant_uuid)
        .bind(resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .unwrap_or(0);
        tx.commit().await.map_err(dependency)?;
        u64::try_from(value).map_err(|_| DataAuthorityError::DependencyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_ingress(
        &self,
        tenant: &TenantId,
        actor_subject: &str,
        request: &DataCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        envelope: InboundEnvelope,
    ) -> Result<PreparedIngress, DataAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let envelope_value =
            serde_json::to_value(&envelope).map_err(|_| DataAuthorityError::RequestInvalid)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| DataAuthorityError::RequestInvalid)?;
        let admitted_hash = action_hash(&action)
            .map_err(|_| DataAuthorityError::RequestInvalid)?
            .0;
        let mut tx = self.begin_tenant(tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{tenant_uuid}:{idempotency_key}"))
            .execute(&mut *tx)
            .await
            .map_err(dependency)?;
        let inserted = sqlx::query(
            "INSERT INTO data_authority_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,action_hash,resource,\
              operation,actor_subject,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED') ON CONFLICT DO NOTHING",
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
        .map_err(|_| DataAuthorityError::IdempotencyConflict)?
        .rows_affected()
            == 1;
        let row = sqlx::query(
            "SELECT request_digest,action_id,task_id,action_hash,resource,operation,actor_subject,\
                    envelope,state,receipt FROM data_authority_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .ok_or(DataAuthorityError::IdempotencyConflict)?;
        let stored_envelope_value = row.get::<Value, _>("envelope");
        let stored_envelope: InboundEnvelope =
            serde_json::from_value(stored_envelope_value.clone())
                .map_err(|_| DataAuthorityError::IdempotencyConflict)?;
        let stored_action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&stored_envelope.payload)
                .map_err(|_| DataAuthorityError::IdempotencyConflict)?;
        let stored_hash = action_hash(&stored_action)
            .map_err(|_| DataAuthorityError::IdempotencyConflict)?
            .0;
        let expected_executor = DataExecutorRequest {
            schema_version: DATA_EXECUTOR_REQUEST_SCHEMA.into(),
            command: request.clone(),
            actor_subject: actor_subject.into(),
            actor_kind: "WORKLOAD".into(),
            approval_ids: BTreeSet::new(),
        };
        let expected_payload = serde_json::to_value(expected_executor)
            .map_err(|_| DataAuthorityError::RequestInvalid)?;
        let expected_state_version = request.expected_resource_version.to_string();
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command_id
            || row.get::<Uuid, _>("task_id") != request.task_id
            || row.get::<String, _>("action_hash") != stored_hash
            || row.get::<String, _>("resource") != request.resource
            || row.get::<String, _>("operation") != request.operation.as_str()
            || row.get::<String, _>("actor_subject") != actor_subject
            || !matches!(
                row.get::<String, _>("state").as_str(),
                "PREPARED" | "ACCEPTED"
            )
            || stored_envelope.schema_version != GATEWAY_SCHEMA_VERSION
            || stored_envelope.idempotency_key.as_deref() != Some(idempotency_key)
            || stored_envelope.payload_hash != sha256(&stored_envelope.payload)
            || stored_action.action_id.0 != request.command_id.to_string()
            || stored_action.task_id.0 != request.task_id.to_string()
            || stored_action.current_state_version.as_deref()
                != Some(expected_state_version.as_str())
            || Value::Object(stored_action.payload.data.clone()) != expected_payload
            || inserted && (stored_hash != admitted_hash || stored_envelope_value != envelope_value)
        {
            return Err(DataAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("receipt")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        tx.commit().await.map_err(dependency)?;
        Ok(PreparedIngress {
            envelope: stored_envelope,
            receipt,
        })
    }

    async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &DataActionReceipt,
    ) -> Result<DataActionReceipt, DataAuthorityError> {
        validate_action_receipt(receipt)?;
        let tenant_uuid = parse_tenant(tenant)?;
        let receipt_value =
            serde_json::to_value(receipt).map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,state,receipt FROM data_authority_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DataAuthorityError::OutcomeUnknown)?
        .ok_or(DataAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("action_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("receipt") {
            if existing != receipt_value || row.get::<String, _>("state") != "ACCEPTED" {
                return Err(DataAuthorityError::IdempotencyConflict);
            }
        } else {
            let updated = sqlx::query(
                "UPDATE data_authority_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&receipt_value)
            .execute(&mut *tx)
            .await
            .map_err(|_| DataAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(DataAuthorityError::OutcomeUnknown);
            }
        }
        tx.commit()
            .await
            .map_err(|_| DataAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }

    async fn claim_execution(
        &self,
        binding: &DataExecutionBinding,
        request: &DataExecutorRequest,
        lease_seconds: i64,
    ) -> Result<ExecutionClaim, DataAuthorityError> {
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(request)?;
        let request_value =
            serde_json::to_value(request).map_err(|_| DataAuthorityError::RequestInvalid)?;
        let resource_version = i64::try_from(binding.resource_version)
            .map_err(|_| DataAuthorityError::RequestInvalid)?;
        let owner = Uuid::new_v4();
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{tenant_uuid}:{}", binding.ledger_execution_id))
            .execute(&mut *tx)
            .await
            .map_err(dependency)?;
        let ingress = sqlx::query(
            "SELECT state,actor_subject,envelope,action_hash FROM data_authority_ingress \
             WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .ok_or(DataAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("actor_subject") != request.actor_subject
            || ingress.get::<String, _>("action_hash") != binding.action_hash
        {
            return Err(DataAuthorityError::PrincipalDenied);
        }
        let envelope: InboundEnvelope = serde_json::from_value(ingress.get("envelope"))
            .map_err(|_| DataAuthorityError::PrincipalDenied)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| DataAuthorityError::PrincipalDenied)?;
        let admitted = action_hash(&action).map_err(|_| DataAuthorityError::PrincipalDenied)?;
        if admitted.0 != binding.action_hash
            || action.action_id.0 != request.command.command_id.to_string()
            || action.task_id.0 != request.command.task_id.to_string()
            || Value::Object(action.payload.data.clone()) != request_value
        {
            return Err(DataAuthorityError::PrincipalDenied);
        }
        sqlx::query(
            "INSERT INTO data_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,action_hash,\
              ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,resource,\
              resource_version,trace_id,policy_decision_id,policy_decision_digest,\
              authorization_evidence_ref,authorization_evidence_digest,request,state,\
              execution_owner,execution_lease_until) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,\
                     'EXECUTING',$19,now()+make_interval(secs=>$20)) ON CONFLICT DO NOTHING",
        )
        .bind(tenant_uuid)
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
        .bind(resource_version)
        .bind(&binding.trace_id)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(&request_value)
        .bind(owner)
        .bind(lease_seconds as f64)
        .execute(&mut *tx)
        .await
        .map_err(dependency)?;
        let row = sqlx::query(
            "SELECT request_digest,action_hash,ledger_execution_id,ledger_event_id,\
                    ledger_event_digest,fence_digest,resource,resource_version,trace_id,\
                    policy_decision_id,policy_decision_digest,authorization_evidence_ref,\
                    authorization_evidence_digest,request,state,execution_owner,\
                    execution_lease_until < now() AS lease_expired,result,evidence_event_id \
             FROM data_authority_executions WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(dependency)?;
        validate_execution_row(
            &row,
            binding,
            request,
            &request_digest,
            &request_value,
            resource_version,
        )?;
        let state = row.get::<String, _>("state");
        let claim_owner = row.get::<Uuid, _>("execution_owner");
        let result = if state == "COMPLETED" {
            let value = row
                .get::<Option<Value>, _>("result")
                .ok_or(DataAuthorityError::DependencyUnavailable)?;
            ExecutionClaim::Completed(
                serde_json::from_value(value)
                    .map_err(|_| DataAuthorityError::DependencyUnavailable)?,
            )
        } else if state == "MUTATED_PENDING_EVIDENCE" {
            let event_id = row
                .get::<Option<Uuid>, _>("evidence_event_id")
                .ok_or(DataAuthorityError::DependencyUnavailable)?;
            ExecutionClaim::EvidencePending(load_pending(&mut tx, tenant_uuid, event_id).await?)
        } else if state == "EXECUTING" && claim_owner == owner {
            ExecutionClaim::Claimed(ExecutionLease { owner })
        } else if state == "EXECUTING" && row.get::<bool, _>("lease_expired") {
            let renewed = sqlx::query(
                "UPDATE data_authority_executions SET execution_owner=$3,\
                 execution_lease_until=now()+make_interval(secs=>$4),updated_at=now() \
                 WHERE tenant_id=$1 AND action_id=$2 AND state='EXECUTING' \
                   AND execution_lease_until < now()",
            )
            .bind(tenant_uuid)
            .bind(request.command.command_id)
            .bind(owner)
            .bind(lease_seconds as f64)
            .execute(&mut *tx)
            .await
            .map_err(dependency)?;
            if renewed.rows_affected() != 1 {
                return Err(DataAuthorityError::OutcomeUnknown);
            }
            ExecutionClaim::Claimed(ExecutionLease { owner })
        } else {
            return Err(DataAuthorityError::OutcomeUnknown);
        };
        tx.commit().await.map_err(dependency)?;
        Ok(result)
    }

    async fn commit_mutation(
        &self,
        binding: &DataExecutionBinding,
        request: &DataExecutorRequest,
        lease: ExecutionLease,
        effect: Option<DataEffectReceipt>,
    ) -> Result<PendingEvidence, DataAuthorityError> {
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let expected = i64::try_from(request.command.expected_resource_version)
            .map_err(|_| DataAuthorityError::RequestInvalid)?;
        let next = expected
            .checked_add(1)
            .ok_or(DataAuthorityError::StateConflict)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let execution = sqlx::query(
            "SELECT state,execution_owner,execution_lease_until > now() AS lease_valid \
             FROM data_authority_executions WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(dependency)?;
        if execution.get::<String, _>("state") != "EXECUTING"
            || execution.get::<Uuid, _>("execution_owner") != lease.owner
            || !execution.get::<bool, _>("lease_valid")
        {
            return Err(DataAuthorityError::OutcomeUnknown);
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM data_resource_versions \
             WHERE tenant_id=$1 AND resource=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.command.resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .unwrap_or(0);
        if current != expected
            || binding.resource_version != request.command.expected_resource_version
        {
            return Err(DataAuthorityError::StateConflict);
        }
        apply_domain_mutation(&mut tx, binding, request, effect.as_ref()).await?;
        let advanced = sqlx::query(
            "INSERT INTO data_resource_versions \
             (tenant_id,resource,resource_version,action_hash,ledger_execution_id,fence_digest) \
             VALUES ($1,$2,$3,$4,$5,$6) \
             ON CONFLICT (tenant_id,resource) DO UPDATE SET \
               resource_version=EXCLUDED.resource_version,action_hash=EXCLUDED.action_hash,\
               ledger_execution_id=EXCLUDED.ledger_execution_id,fence_digest=EXCLUDED.fence_digest,\
               updated_at=now() WHERE data_resource_versions.resource_version=$7",
        )
        .bind(tenant_uuid)
        .bind(&request.command.resource)
        .bind(next)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .bind(expected)
        .execute(&mut *tx)
        .await
        .map_err(|_| DataAuthorityError::StateConflict)?;
        if advanced.rows_affected() != 1 {
            return Err(DataAuthorityError::StateConflict);
        }

        let safe_receipts = effect.map(|value| value.receipts).unwrap_or_default();
        let result_digest = canonical_digest(&json!({
            "command_id": request.command.command_id,
            "operation": request.command.operation,
            "resource": request.command.resource,
            "resource_version": next,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "safe_receipts": safe_receipts,
        }))?;
        let event_id = Uuid::new_v4();
        let evidence_ref = format!("evidence-outbox://data-governance/{event_id}");
        let result = DataMutationResult {
            schema_version: DATA_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            operation: request.command.operation,
            resource: request.command.resource.clone(),
            resource_version: u64::try_from(next)
                .map_err(|_| DataAuthorityError::DependencyUnavailable)?,
            state: "MUTATED_PENDING_EVIDENCE".into(),
            result_digest,
            evidence_outbox_ref: evidence_ref,
            evidence_ref: None,
            evidence_digest: None,
            safe_receipts,
        };
        let evidence_time = Utc::now();
        let payload = json!({
            "schema_version": DATA_EVIDENCE_SCHEMA,
            "event_id": event_id,
            "tenant_id": tenant_uuid,
            "task_id": request.command.task_id,
            "command_id": request.command.command_id,
            "operation": request.command.operation,
            "resource": request.command.resource,
            "resource_version": next,
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
            "safe_receipts": result.safe_receipts,
            "event_occurred_at": evidence_time,
            "delivery_requested_at": evidence_time,
        });
        let payload_digest = canonical_digest(&payload)?;
        let evidence_idempotency_key = format!("data-governance-evidence-{event_id}");
        let result_value =
            serde_json::to_value(&result).map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "INSERT INTO data_evidence_outbox \
             (tenant_id,event_id,action_id,idempotency_key,payload,payload_digest,state) \
             VALUES ($1,$2,$3,$4,$5,$6,'PENDING')",
        )
        .bind(tenant_uuid)
        .bind(event_id)
        .bind(request.command.command_id)
        .bind(&evidence_idempotency_key)
        .bind(&payload)
        .bind(&payload_digest)
        .execute(&mut *tx)
        .await
        .map_err(dependency)?;
        let updated = sqlx::query(
            "UPDATE data_authority_executions SET state='MUTATED_PENDING_EVIDENCE',result=$4,\
             evidence_event_id=$5,execution_lease_until=NULL,updated_at=now() \
             WHERE tenant_id=$1 AND action_id=$2 AND execution_owner=$3 AND state='EXECUTING'",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .bind(lease.owner)
        .bind(&result_value)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(dependency)?;
        if updated.rows_affected() != 1 {
            return Err(DataAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| DataAuthorityError::OutcomeUnknown)?;
        Ok(PendingEvidence {
            event_id,
            idempotency_key: evidence_idempotency_key,
            payload,
            payload_digest,
            result,
        })
    }

    async fn finalize_evidence(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
        receipt: SignedAuthorityEvidenceReceipt,
    ) -> Result<DataMutationResult, DataAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let receipt_value = serde_json::to_value(&receipt)
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let outbox = sqlx::query(
            "SELECT o.state,o.payload,o.payload_digest,o.delivery_receipt,\
                    e.state AS execution_state,e.result \
             FROM data_evidence_outbox o JOIN data_authority_executions e \
               ON e.tenant_id=o.tenant_id AND e.evidence_event_id=o.event_id \
             WHERE o.tenant_id=$1 AND o.event_id=$2 FOR UPDATE OF o,e",
        )
        .bind(tenant_uuid)
        .bind(pending.event_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(dependency)?;
        if outbox.get::<String, _>("payload_digest") != pending.payload_digest
            || outbox.get::<Value, _>("payload") != pending.payload
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        let state = outbox.get::<String, _>("state");
        if state == "DELIVERED" {
            if outbox.get::<Option<Value>, _>("delivery_receipt") != Some(receipt_value)
                || outbox.get::<String, _>("execution_state") != "COMPLETED"
            {
                return Err(DataAuthorityError::IdempotencyConflict);
            }
            let result: DataMutationResult =
                serde_json::from_value(outbox.get::<Value, _>("result"))
                    .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
            if result.command_id != pending.result.command_id
                || result.result_digest != pending.result.result_digest
                || result.state != "COMPLETED"
                || result.evidence_ref.as_deref() != Some(receipt.evidence_ref.as_str())
                || result.evidence_digest.as_deref() != Some(receipt.evidence_digest.as_str())
            {
                return Err(DataAuthorityError::IdempotencyConflict);
            }
            tx.commit().await.map_err(dependency)?;
            return Ok(result);
        } else if state == "PENDING" {
            if outbox.get::<String, _>("execution_state") != "MUTATED_PENDING_EVIDENCE"
                || outbox.get::<Value, _>("result")
                    != serde_json::to_value(&pending.result)
                        .map_err(|_| DataAuthorityError::DependencyUnavailable)?
            {
                return Err(DataAuthorityError::StateConflict);
            }
            let delivered = sqlx::query(
                "UPDATE data_evidence_outbox SET state='DELIVERED',delivery_receipt=$3,\
                 delivered_at=now() WHERE tenant_id=$1 AND event_id=$2 AND state='PENDING'",
            )
            .bind(tenant_uuid)
            .bind(pending.event_id)
            .bind(&receipt_value)
            .execute(&mut *tx)
            .await
            .map_err(dependency)?;
            if delivered.rows_affected() != 1 {
                return Err(DataAuthorityError::OutcomeUnknown);
            }
        } else {
            return Err(DataAuthorityError::StateConflict);
        }
        let mut completed = pending.result;
        completed.state = "COMPLETED".into();
        completed.evidence_ref = Some(receipt.evidence_ref.clone());
        completed.evidence_digest = Some(receipt.evidence_digest.clone());
        let completed_value = serde_json::to_value(&completed)
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        let finalized = sqlx::query(
            "UPDATE data_authority_executions SET state='COMPLETED',result=$4,completed_at=now(),\
             updated_at=now() WHERE tenant_id=$1 AND action_id=$2 AND evidence_event_id=$3 \
             AND state='MUTATED_PENDING_EVIDENCE'",
        )
        .bind(tenant_uuid)
        .bind(completed.command_id)
        .bind(pending.event_id)
        .bind(&completed_value)
        .execute(&mut *tx)
        .await
        .map_err(dependency)?;
        if finalized.rows_affected() != 1 {
            return Err(DataAuthorityError::OutcomeUnknown);
        }
        tx.commit().await.map_err(dependency)?;
        Ok(completed)
    }

    async fn pending_evidence(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<Vec<PendingEvidence>, DataAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT event_id FROM data_evidence_outbox WHERE tenant_id=$1 AND state='PENDING' \
             ORDER BY created_at,event_id LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(dependency)?;
        let mut pending = Vec::with_capacity(ids.len());
        for event_id in ids {
            pending.push(load_pending(&mut tx, tenant_uuid, event_id).await?);
        }
        tx.commit().await.map_err(dependency)?;
        Ok(pending)
    }

    async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativeDataPage, DataAuthorityError> {
        if !(1..=500).contains(&limit) || after.is_some_and(|value| !resource_reference(value)) {
            return Err(DataAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT resource,resource_version,action_hash,ledger_execution_id,fence_digest,updated_at \
             FROM data_resource_versions WHERE tenant_id=$1 AND resource>$2 ORDER BY resource LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(after.unwrap_or(""))
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(dependency)?;
        tx.commit().await.map_err(dependency)?;
        let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
        let limit = usize::try_from(limit).map_err(|_| DataAuthorityError::RequestInvalid)?;
        let mut items = Vec::new();
        for row in rows.into_iter().take(limit) {
            items.push(AuthoritativeDataResource {
                resource: row.get("resource"),
                resource_version: u64::try_from(row.get::<i64, _>("resource_version"))
                    .map_err(|_| DataAuthorityError::DependencyUnavailable)?,
                action_hash: row.get("action_hash"),
                ledger_execution_id: row.get("ledger_execution_id"),
                fence_digest: row.get("fence_digest"),
                updated_at: row.get("updated_at"),
            });
        }
        let next_after = has_more
            .then(|| items.last().map(|item| item.resource.clone()))
            .flatten();
        let mut page = AuthoritativeDataPage {
            schema_version: "agenttrust.authoritative-data-page.v1".into(),
            tenant_id: tenant.clone(),
            authoritative: true,
            items,
            next_after,
            data_digest: String::new(),
        };
        let mut material =
            serde_json::to_value(&page).map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        material
            .as_object_mut()
            .ok_or(DataAuthorityError::DependencyUnavailable)?
            .remove("data_digest");
        page.data_digest = canonical_digest(&material)?;
        Ok(page)
    }

    async fn completed_mutation(
        &self,
        tenant: &TenantId,
        command_id: Uuid,
    ) -> Result<DataMutationResult, DataAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT state,result FROM data_authority_executions \
             WHERE tenant_id=$1 AND action_id=$2",
        )
        .bind(tenant_uuid)
        .bind(command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dependency)?
        .ok_or(DataAuthorityError::NotFound)?;
        let state = row.get::<String, _>("state");
        if state != "COMPLETED" {
            return Err(DataAuthorityError::OutcomeUnknown);
        }
        let result: DataMutationResult = row
            .get::<Option<Value>, _>("result")
            .ok_or(DataAuthorityError::DependencyUnavailable)
            .and_then(|value| {
                serde_json::from_value(value).map_err(|_| DataAuthorityError::DependencyUnavailable)
            })?;
        if result.schema_version != DATA_MUTATION_RESULT_SCHEMA
            || result.command_id != command_id
            || result.state != "COMPLETED"
            || !digest(&result.result_digest)
            || !evidence_reference(
                result
                    .evidence_ref
                    .as_deref()
                    .ok_or(DataAuthorityError::DependencyUnavailable)?,
            )
            || !digest(
                result
                    .evidence_digest
                    .as_deref()
                    .ok_or(DataAuthorityError::DependencyUnavailable)?,
            )
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        tx.commit().await.map_err(dependency)?;
        Ok(result)
    }
}

struct PreparedIngress {
    envelope: InboundEnvelope,
    receipt: Option<DataActionReceipt>,
}

enum ExecutionClaim {
    Claimed(ExecutionLease),
    EvidencePending(PendingEvidence),
    Completed(DataMutationResult),
}

struct ExecutionLease {
    owner: Uuid,
}

struct PendingEvidence {
    event_id: Uuid,
    idempotency_key: String,
    payload: Value,
    payload_digest: String,
    result: DataMutationResult,
}

async fn apply_domain_mutation(
    tx: &mut Transaction<'_, Postgres>,
    binding: &DataExecutionBinding,
    request: &DataExecutorRequest,
    effect: Option<&DataEffectReceipt>,
) -> Result<(), DataAuthorityError> {
    let tenant = parse_tenant(&binding.tenant_id)?;
    let payload = payload_object(&request.command.payload)?;
    let effect_value = effect
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
    match request.command.operation {
        DataOperation::RegisterLabel => {
            sqlx::query(
                "INSERT INTO governed_data_labels \
                 (tenant_id,object_ref,object_version,object_digest,label,label_digest,classification,confidence,\
                  source_evidence_ref,source_evidence_digest,action_hash,ledger_execution_id) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            )
            .bind(tenant)
            .bind(text(payload, "object_ref")?)
            .bind(text(payload, "object_version")?)
            .bind(text(payload, "object_digest")?)
            .bind(value(payload, "label")?)
            .bind(text(payload, "label_digest")?)
            .bind(nested_text(payload, "label", "classification")?)
            .bind(nested_text(payload, "label", "confidence")?)
            .bind(text(payload, "source_evidence_ref")?)
            .bind(text(payload, "source_evidence_digest")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::RecordPolicyDecision => {
            let policy_request: DataPolicyRequest =
                serde_json::from_value(value(payload, "request")?.clone())
                    .map_err(|_| DataAuthorityError::RequestInvalid)?;
            if policy_request.tenant_id != binding.tenant_id {
                return Err(DataAuthorityError::PrincipalDenied);
            }
            sqlx::query(
                "INSERT INTO data_policy_decision_records \
                 (tenant_id,decision_id,request_digest,request,decision,decision_digest,policy_version,\
                  allowed,shadow,evaluated_at,action_hash,ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11,$12)",
            )
            .bind(tenant)
            .bind(text(payload, "decision_id")?)
            .bind(text(payload, "request_digest")?)
            .bind(value(payload, "request")?)
            .bind(value(payload, "decision")?)
            .bind(text(payload, "decision_digest")?)
            .bind(nested_text(payload, "decision", "policy_version")?)
            .bind(nested_bool(payload, "decision", "allowed")?)
            .bind(boolean(payload, "shadow")?)
            .bind(text(payload, "evaluated_at")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::RecordDlpScan => {
            sqlx::query(
                "INSERT INTO data_dlp_scan_summaries \
                 (tenant_id,scan_id,content_digest,size_bytes,finding_counts,findings_digest,\
                  engine_revision,engine_receipt_ref,engine_receipt_digest,high_risk,\
                  blocking,action_hash,ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(tenant)
            .bind(text(payload, "scan_id")?)
            .bind(text(payload, "content_digest")?)
            .bind(integer(payload, "size_bytes")?)
            .bind(value(payload, "finding_counts")?)
            .bind(text(payload, "findings_digest")?)
            .bind(text(payload, "engine_revision")?)
            .bind(text(payload, "engine_receipt_ref")?)
            .bind(text(payload, "engine_receipt_digest")?)
            .bind(boolean(payload, "high_risk")?)
            .bind(boolean(payload, "blocking")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::RecordTransformReceipt => {
            let scan_id = parse_uuid(text(payload, "dlp_scan_id")?)?;
            let verified = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM data_dlp_scan_summaries \
                 WHERE tenant_id=$1 AND scan_id=$2 AND content_digest=$3 \
                   AND engine_receipt_digest=$4 AND NOT blocking)",
            )
            .bind(tenant)
            .bind(scan_id)
            .bind(text(payload, "input_digest")?)
            .bind(text(payload, "dlp_receipt_digest")?)
            .fetch_one(&mut **tx)
            .await
            .map_err(dependency)?;
            if !verified {
                return Err(DataAuthorityError::DlpDenied);
            }
            sqlx::query(
                "INSERT INTO data_transform_receipts \
                 (tenant_id,transform_id,input_digest,output_digest,transformations,reversible,\
                  key_reference_digest,dlp_scan_id,dlp_receipt_digest,transform_receipt_digest,\
                  action_hash,ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8::uuid,$9,$10,$11,$12)",
            )
            .bind(tenant)
            .bind(text(payload, "transform_id")?)
            .bind(text(payload, "input_digest")?)
            .bind(text(payload, "output_digest")?)
            .bind(value(payload, "transformations")?)
            .bind(boolean(payload, "reversible")?)
            .bind(optional_text(payload, "key_reference_digest")?)
            .bind(scan_id)
            .bind(text(payload, "dlp_receipt_digest")?)
            .bind(text(payload, "transform_receipt_digest")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::IssueCrossDomainGrant => {
            sqlx::query(
                "INSERT INTO data_cross_domain_grants \
                 (tenant_id,grant_id,source_zone,target_zone,source_jurisdiction,target_jurisdiction,\
                  object_digest,classification,approval_id,approval_evidence_ref,\
                  approval_evidence_digest,expires_at,single_use,action_hash,ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9::uuid,$10,$11,$12::timestamptz,$13,$14,$15)",
            )
            .bind(tenant)
            .bind(text(payload, "grant_id")?)
            .bind(text(payload, "source_zone")?)
            .bind(text(payload, "target_zone")?)
            .bind(text(payload, "source_jurisdiction")?)
            .bind(text(payload, "target_jurisdiction")?)
            .bind(text(payload, "object_digest")?)
            .bind(text(payload, "classification")?)
            .bind(text(payload, "approval_id")?)
            .bind(text(payload, "approval_evidence_ref")?)
            .bind(text(payload, "approval_evidence_digest")?)
            .bind(text(payload, "expires_at")?)
            .bind(boolean(payload, "single_use")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::ConsumeCrossDomainGrant => {
            let grant_id = parse_uuid(text(payload, "grant_id")?)?;
            let row = sqlx::query(
                "SELECT source_zone,target_zone,object_digest,expires_at>now() AS valid,\
                        consumed_at IS NULL AS unused,single_use \
                 FROM data_cross_domain_grants WHERE tenant_id=$1 AND grant_id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(grant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(dependency)?
            .ok_or(DataAuthorityError::NotFound)?;
            if row.get::<String, _>("source_zone") != text(payload, "source_zone")?
                || row.get::<String, _>("target_zone") != text(payload, "target_zone")?
                || row.get::<String, _>("object_digest") != text(payload, "object_digest")?
                || !row.get::<bool, _>("valid")
                || !row.get::<bool, _>("unused")
                || !row.get::<bool, _>("single_use")
            {
                return Err(DataAuthorityError::CrossDomainReplayed);
            }
            let consumption_id = Uuid::new_v4();
            let consumed = sqlx::query(
                "UPDATE data_cross_domain_grants SET consumed_at=now(),consumption_id=$3 \
                 WHERE tenant_id=$1 AND grant_id=$2 AND consumed_at IS NULL",
            )
            .bind(tenant)
            .bind(grant_id)
            .bind(consumption_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::CrossDomainReplayed)?;
            if consumed.rows_affected() != 1 {
                return Err(DataAuthorityError::CrossDomainReplayed);
            }
            sqlx::query(
                "INSERT INTO data_cross_domain_consumptions \
                 (tenant_id,consumption_id,grant_id,export_intent_id,object_digest,\
                  action_hash,ledger_execution_id) VALUES ($1,$2,$3,$4::uuid,$5,$6,$7)",
            )
            .bind(tenant)
            .bind(consumption_id)
            .bind(grant_id)
            .bind(text(payload, "export_intent_id")?)
            .bind(text(payload, "object_digest")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::CrossDomainReplayed)?;
        }
        DataOperation::ResolveRetention => {
            let object_ref = text(payload, "object_ref")?;
            lock_domain_object(tx, tenant, object_ref).await?;
            if text(payload, "action")? != "RETAIN" {
                let held = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS (SELECT 1 FROM data_legal_holds \
                     WHERE tenant_id=$1 AND object_ref=$2 AND state='ACTIVE')",
                )
                .bind(tenant)
                .bind(object_ref)
                .fetch_one(&mut **tx)
                .await
                .map_err(dependency)?;
                if held {
                    return Err(DataAuthorityError::LegalHoldBlocked);
                }
            }
            sqlx::query(
                "INSERT INTO data_retention_records \
                 (tenant_id,retention_id,object_ref,retention_label,retention_action,retain_until,\
                  policy_version,legal_hold_checked_at,resolver_receipt_ref,resolver_receipt_digest,\
                  adapter_receipt,action_hash,ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5,$6::timestamptz,$7,$8::timestamptz,$9,$10,$11,$12,$13)",
            )
            .bind(tenant)
            .bind(text(payload, "retention_id")?)
            .bind(object_ref)
            .bind(text(payload, "retention_label")?)
            .bind(text(payload, "action")?)
            .bind(text(payload, "retain_until")?)
            .bind(text(payload, "policy_version")?)
            .bind(text(payload, "legal_hold_checked_at")?)
            .bind(text(payload, "resolver_receipt_ref")?)
            .bind(text(payload, "resolver_receipt_digest")?)
            .bind(effect_value)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::PlaceLegalHold => {
            lock_domain_object(tx, tenant, text(payload, "object_ref")?).await?;
            sqlx::query(
                "INSERT INTO data_legal_holds \
                 (tenant_id,hold_id,object_ref,reason_digest,approval_id,approval_evidence_ref,\
                  approval_evidence_digest,effective_at,state,adapter_receipt,action_hash,\
                  ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5::uuid,$6,$7,$8::timestamptz,'ACTIVE',$9,$10,$11)",
            )
            .bind(tenant)
            .bind(text(payload, "hold_id")?)
            .bind(text(payload, "object_ref")?)
            .bind(text(payload, "reason_digest")?)
            .bind(text(payload, "approval_id")?)
            .bind(text(payload, "approval_evidence_ref")?)
            .bind(text(payload, "approval_evidence_digest")?)
            .bind(text(payload, "effective_at")?)
            .bind(effect_value)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::ReleaseLegalHold => {
            lock_domain_object(tx, tenant, text(payload, "object_ref")?).await?;
            let updated = sqlx::query(
                "UPDATE data_legal_holds SET state='RELEASED',released_at=$4::timestamptz,\
                 release_approval_id=$5::uuid,release_evidence_ref=$6,release_evidence_digest=$7,\
                 release_adapter_receipt=$8,release_action_hash=$9,release_ledger_execution_id=$10 \
                 WHERE tenant_id=$1 AND hold_id=$2::uuid AND object_ref=$3 AND state='ACTIVE'",
            )
            .bind(tenant)
            .bind(text(payload, "hold_id")?)
            .bind(text(payload, "object_ref")?)
            .bind(text(payload, "released_at")?)
            .bind(text(payload, "release_approval_id")?)
            .bind(text(payload, "release_evidence_ref")?)
            .bind(text(payload, "release_evidence_digest")?)
            .bind(effect_value)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(dependency)?;
            if updated.rows_affected() != 1 {
                return Err(DataAuthorityError::LegalHoldBlocked);
            }
        }
        DataOperation::AuthorizeExport => {
            let export_id = verify_authorize_export_prerequisites(tx, tenant, payload).await?;
            let decision_id = parse_uuid(text(payload, "decision_id")?)?;
            let scan_id = parse_uuid(text(payload, "dlp_scan_id")?)?;
            sqlx::query(
                "INSERT INTO data_export_intents \
                 (tenant_id,export_id,object_ref,object_digest,label_digest,decision_id,dlp_scan_id,\
                  dlp_receipt_digest,transform_id,transform_receipt_digest,grant_id,\
                  object_authorization_ref,object_authorization_digest,destination_kind,\
                  destination_digest,expires_at,redirects_allowed,state,adapter_receipt,action_hash,\
                  ledger_execution_id) \
                 VALUES ($1,$2::uuid,$3,$4,$5,$6::uuid,$7::uuid,$8,$9::uuid,$10,$11::uuid,$12,$13,\
                         $14,$15,$16::timestamptz,$17,'AUTHORIZED',$18,$19,$20)",
            )
            .bind(tenant)
            .bind(export_id)
            .bind(text(payload, "object_ref")?)
            .bind(text(payload, "object_digest")?)
            .bind(text(payload, "label_digest")?)
            .bind(decision_id)
            .bind(scan_id)
            .bind(text(payload, "dlp_receipt_digest")?)
            .bind(optional_text(payload, "transform_id")?)
            .bind(optional_text(payload, "transform_receipt_digest")?)
            .bind(optional_text(payload, "grant_id")?)
            .bind(text(payload, "object_authorization_ref")?)
            .bind(text(payload, "object_authorization_digest")?)
            .bind(text(payload, "destination_kind")?)
            .bind(text(payload, "destination_digest")?)
            .bind(text(payload, "expires_at")?)
            .bind(boolean(payload, "redirects_allowed")?)
            .bind(effect_value)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| DataAuthorityError::StateConflict)?;
        }
        DataOperation::CompleteExport => {
            let updated = sqlx::query(
                "UPDATE data_export_intents SET state='COMPLETED',artifact_ref=$4,artifact_digest=$5,\
                 watermark_digest=$6,signature_digest=$7,worm_receipt_ref=$8,worm_receipt_digest=$9,\
                 completion_adapter_receipt=$10,completed_at=$11::timestamptz,\
                 completion_action_hash=$12,completion_ledger_execution_id=$13 \
                 WHERE tenant_id=$1 AND export_id=$2::uuid AND object_digest=$3 \
                   AND state='AUTHORIZED' AND expires_at>now()",
            )
            .bind(tenant)
            .bind(text(payload, "export_id")?)
            .bind(text(payload, "object_digest")?)
            .bind(text(payload, "artifact_ref")?)
            .bind(text(payload, "artifact_digest")?)
            .bind(text(payload, "watermark_digest")?)
            .bind(text(payload, "signature_digest")?)
            .bind(text(payload, "worm_receipt_ref")?)
            .bind(text(payload, "worm_receipt_digest")?)
            .bind(effect_value)
            .bind(text(payload, "completed_at")?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .execute(&mut **tx)
            .await
            .map_err(dependency)?;
            if updated.rows_affected() != 1 {
                return Err(DataAuthorityError::StateConflict);
            }
        }
    }
    Ok(())
}

async fn verify_authorize_export_prerequisites(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    payload: &serde_json::Map<String, Value>,
) -> Result<Uuid, DataAuthorityError> {
    let export_id = parse_uuid(text(payload, "export_id")?)?;
    let decision_id = parse_uuid(text(payload, "decision_id")?)?;
    let scan_id = parse_uuid(text(payload, "dlp_scan_id")?)?;
    let prerequisites = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (\
           SELECT 1 FROM data_policy_decision_records d \
           JOIN data_dlp_scan_summaries s ON s.tenant_id=d.tenant_id \
           JOIN governed_data_labels l ON l.tenant_id=d.tenant_id \
           LEFT JOIN data_transform_receipts t \
             ON t.tenant_id=d.tenant_id AND t.transform_id=$11::uuid \
           LEFT JOIN data_cross_domain_grants g \
             ON g.tenant_id=d.tenant_id AND g.grant_id=$13::uuid \
           WHERE d.tenant_id=$1 AND d.decision_id=$2 AND d.allowed AND NOT d.shadow \
             AND d.decision_digest=$3 AND d.request_digest=$4 \
             AND d.request->>'destination_kind'=$5 \
             AND s.scan_id=$6 AND NOT s.blocking AND s.content_digest=$7 \
             AND s.engine_receipt_digest=$8 \
             AND s.high_risk=(l.classification IN ('CONFIDENTIAL','RESTRICTED','REGULATED')) \
             AND l.label_digest=$9 AND l.object_ref=$10 AND l.object_digest=$7 \
             AND d.request->>'classification'=l.classification \
             AND ((jsonb_array_length(d.decision->'required_transformations')=0 \
                    AND $11::text IS NULL AND $12::text IS NULL) \
               OR (jsonb_array_length(d.decision->'required_transformations')>0 \
                    AND $11::text IS NOT NULL AND $12::text IS NOT NULL \
                    AND t.output_digest=$7 AND t.transform_receipt_digest=$12 \
                    AND t.dlp_scan_id=s.scan_id \
                    AND t.dlp_receipt_digest=s.engine_receipt_digest \
                    AND t.transformations @> d.decision->'required_transformations')) \
             AND (($13::text IS NULL \
                    AND d.request->>'cross_domain_approval_id' IS NULL) \
               OR ($13::text IS NOT NULL \
                    AND d.request->>'cross_domain_approval_id'=g.approval_id::text \
                    AND g.object_digest=$7 AND g.classification=l.classification \
                    AND g.source_jurisdiction=d.request->>'source_jurisdiction' \
                    AND g.target_jurisdiction=d.request->>'destination_jurisdiction' \
                    AND g.single_use AND g.expires_at>now())))",
    )
    .bind(tenant)
    .bind(decision_id)
    .bind(text(payload, "decision_digest")?)
    .bind(text(payload, "policy_request_digest")?)
    .bind(text(payload, "destination_kind")?)
    .bind(scan_id)
    .bind(text(payload, "object_digest")?)
    .bind(text(payload, "dlp_receipt_digest")?)
    .bind(text(payload, "label_digest")?)
    .bind(text(payload, "object_ref")?)
    .bind(optional_text(payload, "transform_id")?)
    .bind(optional_text(payload, "transform_receipt_digest")?)
    .bind(optional_text(payload, "grant_id")?)
    .fetch_one(&mut **tx)
    .await
    .map_err(dependency)?;
    if !prerequisites {
        return Err(DataAuthorityError::DlpDenied);
    }
    if let Some(grant) = optional_text(payload, "grant_id")? {
        let grant_id = parse_uuid(grant)?;
        let consumed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
               SELECT 1 FROM data_cross_domain_consumptions c \
               JOIN data_cross_domain_grants g \
                 ON g.tenant_id=c.tenant_id AND g.grant_id=c.grant_id \
               WHERE c.tenant_id=$1 AND c.grant_id=$2 AND c.export_intent_id=$3 \
                 AND c.object_digest=$4 AND g.consumption_id=c.consumption_id \
                 AND g.consumed_at IS NOT NULL AND g.expires_at>now())",
        )
        .bind(tenant)
        .bind(grant_id)
        .bind(export_id)
        .bind(text(payload, "object_digest")?)
        .fetch_one(&mut **tx)
        .await
        .map_err(dependency)?;
        if !consumed {
            return Err(DataAuthorityError::CrossDomainReplayed);
        }
    }
    Ok(export_id)
}

async fn load_pending(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    event_id: Uuid,
) -> Result<PendingEvidence, DataAuthorityError> {
    let row = sqlx::query(
        "SELECT o.idempotency_key,o.payload,o.payload_digest,e.result \
         FROM data_evidence_outbox o JOIN data_authority_executions e \
           ON e.tenant_id=o.tenant_id AND e.evidence_event_id=o.event_id \
         WHERE o.tenant_id=$1 AND o.event_id=$2 AND o.state='PENDING'",
    )
    .bind(tenant)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(dependency)?
    .ok_or(DataAuthorityError::NotFound)?;
    let result = serde_json::from_value(row.get::<Value, _>("result"))
        .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
    Ok(PendingEvidence {
        event_id,
        idempotency_key: row.get("idempotency_key"),
        payload: row.get("payload"),
        payload_digest: row.get("payload_digest"),
        result,
    })
}

fn canonical_data_action(
    request: &DataExecutorRequest,
    config: &DataAuthorityConfig,
    idempotency_key: &str,
) -> Result<InboundEnvelope, DataAuthorityError> {
    let now = Utc::now();
    let command = &request.command;
    let tenant = TenantId(command.tenant_id.to_string());
    let data = serde_json::to_value(request)
        .map_err(|_| DataAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(DataAuthorityError::RequestInvalid)?;
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
        "x-raw-content-persistence".into(),
        Value::String("PROHIBITED".into()),
    );
    let operation = command.operation.as_str().to_ascii_lowercase();
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(command.command_id.to_string()),
        task_id: TaskId(command.task_id.to_string()),
        step_id: StepId::new(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "data-governance-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: request.actor_subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-data-governance".into(),
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
            justification_code: "DATA_FLOW_GOVERNANCE".into(),
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
            type_id: "data.governance.mutation.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator: format!("data-governance/{}", command.resource),
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
                "DLP_REQUIRED".into(),
                "NO_RAW_CONTENT_PERSISTENCE".into(),
            ],
        },
        expected_outcome: ExpectedOutcome {
            metric: "data_resource_version_advanced_with_evidence".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "data-governance/".into(),
            operations: vec![operation],
        }],
        requested_at: command.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("data.governance.mutation.v1", "1");
    let action =
        normalize(draft, &normalization).map_err(|_| DataAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| DataAuthorityError::RequestInvalid)?;
    let payload = serde_json::to_vec(&action).map_err(|_| DataAuthorityError::RequestInvalid)?;
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
            quota_profile: "data-governance-authority".into(),
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

fn validate_command(
    tenant: &TenantId,
    actor: &str,
    request: &DataCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), DataAuthorityError> {
    validate_command_shape(tenant, actor, request, request_digest, idempotency_key)?;
    let now = Utc::now();
    // Durable callers must replay the byte-identical command and original timestamp after a long
    // partition. Idempotency, admitted Canonical Action, PEP/ledger/fence bindings, and the stored
    // request are checked exactly; only future skew is invalid here.
    if request.requested_at > now + Duration::minutes(1) {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_command_shape(
    tenant: &TenantId,
    actor: &str,
    request: &DataCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), DataAuthorityError> {
    let tenant_uuid = parse_tenant(tenant)?;
    if request.schema_version != DATA_COMMAND_SCHEMA
        || request.tenant_id != tenant_uuid
        || !identifier(actor, 256)
        || !resource_reference(&request.resource)
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || !validate_payload(request.operation, &request.payload)
        || !validate_resource_binding(request.operation, &request.resource, &request.payload)
    {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(())
}

async fn lock_domain_object(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    object_ref: &str,
) -> Result<(), DataAuthorityError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("data-governance:{tenant}:{object_ref}"))
        .execute(&mut **tx)
        .await
        .map_err(dependency)?;
    Ok(())
}

fn validate_resource_binding(operation: DataOperation, resource: &str, payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let (prefix, key) = match operation {
        DataOperation::RegisterLabel => ("labels", "label_digest"),
        DataOperation::RecordPolicyDecision => ("policy-decisions", "decision_id"),
        DataOperation::RecordDlpScan => ("dlp-scans", "scan_id"),
        DataOperation::RecordTransformReceipt => ("transforms", "transform_id"),
        DataOperation::IssueCrossDomainGrant | DataOperation::ConsumeCrossDomainGrant => {
            ("cross-domain-grants", "grant_id")
        }
        DataOperation::ResolveRetention => ("retention", "retention_id"),
        DataOperation::PlaceLegalHold | DataOperation::ReleaseLegalHold => {
            ("legal-holds", "hold_id")
        }
        DataOperation::AuthorizeExport | DataOperation::CompleteExport => {
            ("export-intents", "export_id")
        }
    };
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|identity| resource == format!("{prefix}/{identity}"))
}

fn validate_execution(
    binding: &DataExecutionBinding,
    request: &DataExecutorRequest,
) -> Result<(), DataAuthorityError> {
    validate_command_shape(
        &binding.tenant_id,
        &request.actor_subject,
        &request.command,
        &"a".repeat(64),
        &binding.idempotency_key,
    )?;
    if request.schema_version != DATA_EXECUTOR_REQUEST_SCHEMA
        || request.actor_kind != "WORKLOAD"
        || binding.tenant_id.0 != request.command.tenant_id.to_string()
        || binding.resource_version != request.command.expected_resource_version
        || !digest(&binding.action_hash)
        || !digest(&binding.ledger_event_digest)
        || !digest(&binding.fence_digest)
        || !identifier(&binding.trace_id, 256)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !evidence_reference(&binding.authorization_evidence_ref)
        || !digest(&binding.authorization_evidence_digest)
        // Approval identities are bound through the PEP decision/Evidence headers and, for grant
        // or legal-hold operations, the exact payload references. The admitted Canonical Action
        // carries an empty set and the executor must not append unadmitted fields later.
        || !request.approval_ids.is_empty()
    {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_effect(
    binding: &DataExecutionBinding,
    request: &DataExecutorRequest,
    receipt: Option<&DataEffectReceipt>,
) -> Result<(), DataAuthorityError> {
    if request.command.operation.requires_external_effect() != receipt.is_some() {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    let Some(receipt) = receipt else {
        return Ok(());
    };
    let mut unsigned = receipt.clone();
    unsigned.receipt_digest.clear();
    if receipt.schema_version != "agenttrust.data-governance-effect-receipt.v1"
        || receipt.tenant_id != request.command.tenant_id
        || receipt.action_hash != binding.action_hash
        || receipt.ledger_execution_id != binding.ledger_execution_id
        || receipt.idempotency_key != binding.idempotency_key
        || receipt.operation != request.command.operation
        || receipt.resource != request.command.resource
        || receipt.receipts.is_empty()
        || receipt.receipts.len() > 8
        || canonical_digest(&unsigned)? != receipt.receipt_digest
        || receipt.receipts.iter().any(|item| {
            !matches!(
                item.adapter.as_str(),
                "ENTERPRISE_DLP" | "OBJECT_WORM" | "LEGAL_HOLD"
            ) || !identifier(&item.operation, 128)
                || item.resource != request.command.resource
                || item.idempotency_key != binding.idempotency_key
                || !digest(&item.request_digest)
                || !digest(&item.receipt_digest)
                || !adapter_reference(&item.reference)
        })
    {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    for item in &receipt.receipts {
        let mut unsigned_item = item.clone();
        unsigned_item.receipt_digest.clear();
        if canonical_digest(&unsigned_item)? != item.receipt_digest {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
    }
    let actual = receipt
        .receipts
        .iter()
        .map(|item| (item.adapter.as_str(), item.operation.as_str()))
        .collect::<BTreeSet<_>>();
    let required = match request.command.operation {
        DataOperation::RecordDlpScan => BTreeSet::from([("ENTERPRISE_DLP", "VERIFY_DLP_RECEIPT")]),
        DataOperation::ResolveRetention => BTreeSet::from([("LEGAL_HOLD", "RESOLVE_RETENTION")]),
        DataOperation::PlaceLegalHold => BTreeSet::from([("LEGAL_HOLD", "PLACE")]),
        DataOperation::ReleaseLegalHold => BTreeSet::from([("LEGAL_HOLD", "RELEASE")]),
        DataOperation::AuthorizeExport => BTreeSet::from([
            ("ENTERPRISE_DLP", "AUTHORIZE_EXPORT"),
            ("OBJECT_WORM", "AUTHORIZE_EXPORT"),
        ]),
        DataOperation::CompleteExport => BTreeSet::from([("OBJECT_WORM", "COMPLETE_EXPORT")]),
        _ => BTreeSet::new(),
    };
    if actual != required || receipt.receipts.len() != required.len() {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    let payload = payload_object(&request.command.payload)?;
    if request.command.operation == DataOperation::ResolveRetention {
        let receipt = receipt
            .receipts
            .first()
            .ok_or(DataAuthorityError::DependencyUnavailable)?;
        if receipt.reference != text(payload, "resolver_receipt_ref")?
            || receipt.receipt_digest != text(payload, "resolver_receipt_digest")?
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
    }
    if request.command.operation == DataOperation::CompleteExport {
        let receipt = receipt
            .receipts
            .first()
            .ok_or(DataAuthorityError::DependencyUnavailable)?;
        if receipt.reference != text(payload, "worm_receipt_ref")?
            || receipt.receipt_digest != text(payload, "worm_receipt_digest")?
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
    }
    Ok(())
}

fn validate_evidence_receipt(
    pending: &PendingEvidence,
    receipt: &SignedAuthorityEvidenceReceipt,
) -> Result<(), DataAuthorityError> {
    let payload = pending
        .payload
        .as_object()
        .ok_or(DataAuthorityError::DependencyUnavailable)?;
    let tenant_id = payload
        .get("tenant_id")
        .and_then(Value::as_str)
        .ok_or(DataAuthorityError::DependencyUnavailable)?;
    let task_id = payload
        .get("task_id")
        .and_then(Value::as_str)
        .ok_or(DataAuthorityError::DependencyUnavailable)?;
    let event_occurred_at: DateTime<Utc> = serde_json::from_value(
        payload
            .get("event_occurred_at")
            .cloned()
            .ok_or(DataAuthorityError::DependencyUnavailable)?,
    )
    .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
    let delivery_requested_at: DateTime<Utc> = serde_json::from_value(
        payload
            .get("delivery_requested_at")
            .cloned()
            .ok_or(DataAuthorityError::DependencyUnavailable)?,
    )
    .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
    if receipt.schema_version != AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION
        || receipt.authority_event_id != pending.event_id.to_string()
        || receipt.payload_digest != pending.payload_digest
        || receipt.idempotency_key.0 != pending.idempotency_key
        || receipt.tenant_id.0 != tenant_id
        || receipt.task_id.0 != task_id
        || receipt.source_kind != AuthorityEvidenceSourceKind::GovernedAction
        || receipt.event.event_id != receipt.authority_event_id
        || receipt.event.draft.tenant_id != receipt.tenant_id
        || receipt.event.draft.task_id != receipt.task_id
        || receipt.event.draft.payload_hash != pending.payload_digest
        || receipt.event.draft.occurred_at != event_occurred_at
        || receipt.persisted_at < event_occurred_at
        || delivery_requested_at < event_occurred_at
        || !digest(&receipt.request_digest)
        || !evidence_reference(&receipt.evidence_ref)
        || !digest(&receipt.evidence_digest)
    {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn validate_action_receipt(receipt: &DataActionReceipt) -> Result<(), DataAuthorityError> {
    if receipt.schema_version != DATA_ACTION_RECEIPT_SCHEMA
        || !receipt.accepted
        || !receipt.execution_pending
        || !canonical_uuid(&receipt.action_id)
        || !canonical_uuid(&receipt.task_id)
        || !digest(&receipt.ingress_digest)
        || !evidence_reference(&receipt.ledger_evidence_ref)
        || !digest(&receipt.ledger_evidence_digest)
    {
        Err(DataAuthorityError::DependencyUnavailable)
    } else {
        Ok(())
    }
}

fn validate_execution_row(
    row: &sqlx::postgres::PgRow,
    binding: &DataExecutionBinding,
    request: &DataExecutorRequest,
    request_digest: &str,
    request_value: &Value,
    resource_version: i64,
) -> Result<(), DataAuthorityError> {
    if row.get::<String, _>("request_digest") != request_digest
        || row.get::<String, _>("action_hash") != binding.action_hash
        || row.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
        || row.get::<Uuid, _>("ledger_event_id") != binding.ledger_event_id
        || row.get::<String, _>("ledger_event_digest") != binding.ledger_event_digest
        || row.get::<String, _>("fence_digest") != binding.fence_digest
        || row.get::<String, _>("resource") != request.command.resource
        || row.get::<i64, _>("resource_version") != resource_version
        || row.get::<String, _>("trace_id") != binding.trace_id
        || row.get::<String, _>("policy_decision_id") != binding.policy_decision_id
        || row.get::<String, _>("policy_decision_digest") != binding.policy_decision_digest
        || row.get::<String, _>("authorization_evidence_ref") != binding.authorization_evidence_ref
        || row.get::<String, _>("authorization_evidence_digest")
            != binding.authorization_evidence_digest
        || row.get::<Value, _>("request") != *request_value
    {
        Err(DataAuthorityError::IdempotencyConflict)
    } else {
        Ok(())
    }
}

fn validate_payload(operation: DataOperation, payload: &Value) -> bool {
    let Ok(object) = payload_object(payload) else {
        return false;
    };
    if serde_json::to_vec(payload).map_or(true, |raw| raw.len() > 131_072)
        || contains_forbidden_content_key(payload, 0)
    {
        return false;
    }
    match operation {
        DataOperation::RegisterLabel => {
            exact_keys(
                object,
                &[
                    "object_ref",
                    "object_version",
                    "object_digest",
                    "label",
                    "label_digest",
                    "source_evidence_ref",
                    "source_evidence_digest",
                ],
            ) && object_reference_field(object, "object_ref")
                && identifier_field(object, "object_version", 256)
                && digest_field(object, "object_digest")
                && digest_field(object, "label_digest")
                && evidence_reference_field(object, "source_evidence_ref")
                && digest_field(object, "source_evidence_digest")
                && valid_label_value(object.get("label"))
                && canonical_digest(object.get("label").unwrap_or(&Value::Null)).is_ok_and(
                    |digest| {
                        object.get("label_digest").and_then(Value::as_str) == Some(digest.as_str())
                    },
                )
        }
        DataOperation::RecordPolicyDecision => {
            exact_keys(
                object,
                &[
                    "decision_id",
                    "request_digest",
                    "request",
                    "decision",
                    "decision_digest",
                    "shadow",
                    "evaluated_at",
                ],
            ) && uuid_field(object, "decision_id")
                && digest_field(object, "request_digest")
                && valid_policy_request(object.get("request"))
                && valid_policy_decision(object.get("decision"))
                && digest_field(object, "decision_digest")
                && boolean_field(object, "shadow")
                && recent_timestamp_field(object, "evaluated_at", 10)
                && canonical_digest(object.get("decision").unwrap_or(&Value::Null)).is_ok_and(
                    |digest| {
                        object.get("decision_digest").and_then(Value::as_str)
                            == Some(digest.as_str())
                    },
                )
                && canonical_digest(object.get("request").unwrap_or(&Value::Null)).is_ok_and(
                    |digest| {
                        object.get("request_digest").and_then(Value::as_str)
                            == Some(digest.as_str())
                    },
                )
        }
        DataOperation::RecordDlpScan => {
            exact_keys(
                object,
                &[
                    "scan_id",
                    "content_digest",
                    "size_bytes",
                    "finding_counts",
                    "findings_digest",
                    "engine_revision",
                    "engine_receipt_ref",
                    "engine_receipt_digest",
                    "high_risk",
                    "blocking",
                ],
            ) && uuid_field(object, "scan_id")
                && digest_field(object, "content_digest")
                && bounded_integer_field(object, "size_bytes", 1, 8_388_608)
                && valid_finding_counts(object.get("finding_counts"))
                && digest_field(object, "findings_digest")
                && identifier_field(object, "engine_revision", 256)
                && adapter_reference_field(object, "engine_receipt_ref")
                && digest_field(object, "engine_receipt_digest")
                && boolean_field(object, "high_risk")
                && boolean_field(object, "blocking")
        }
        DataOperation::RecordTransformReceipt => {
            exact_keys(
                object,
                &[
                    "transform_id",
                    "input_digest",
                    "output_digest",
                    "transformations",
                    "reversible",
                    "key_reference_digest",
                    "dlp_scan_id",
                    "dlp_receipt_digest",
                    "transform_receipt_digest",
                ],
            ) && uuid_field(object, "transform_id")
                && digest_field(object, "input_digest")
                && digest_field(object, "output_digest")
                && string_array_field(object, "transformations", 1, 16)
                && boolean_field(object, "reversible")
                && optional_digest_field(object, "key_reference_digest")
                && uuid_field(object, "dlp_scan_id")
                && digest_field(object, "dlp_receipt_digest")
                && digest_field(object, "transform_receipt_digest")
                && ((object.get("reversible").and_then(Value::as_bool) == Some(true))
                    == object
                        .get("key_reference_digest")
                        .and_then(Value::as_str)
                        .is_some_and(digest))
                && embedded_digest_matches(object, "transform_receipt_digest")
        }
        DataOperation::IssueCrossDomainGrant => {
            exact_keys(
                object,
                &[
                    "grant_id",
                    "source_zone",
                    "target_zone",
                    "source_jurisdiction",
                    "target_jurisdiction",
                    "object_digest",
                    "classification",
                    "approval_id",
                    "approval_evidence_ref",
                    "approval_evidence_digest",
                    "expires_at",
                    "single_use",
                ],
            ) && uuid_field(object, "grant_id")
                && identifier_field(object, "source_zone", 128)
                && identifier_field(object, "target_zone", 128)
                && object.get("source_zone") != object.get("target_zone")
                && jurisdiction_field(object, "source_jurisdiction")
                && jurisdiction_field(object, "target_jurisdiction")
                && digest_field(object, "object_digest")
                && classification_field(object, "classification")
                && uuid_field(object, "approval_id")
                && evidence_reference_field(object, "approval_evidence_ref")
                && digest_field(object, "approval_evidence_digest")
                && future_timestamp_field(object, "expires_at", 24 * 3600)
                && object.get("single_use").and_then(Value::as_bool) == Some(true)
        }
        DataOperation::ConsumeCrossDomainGrant => {
            exact_keys(
                object,
                &[
                    "grant_id",
                    "object_digest",
                    "source_zone",
                    "target_zone",
                    "export_intent_id",
                ],
            ) && uuid_field(object, "grant_id")
                && digest_field(object, "object_digest")
                && identifier_field(object, "source_zone", 128)
                && identifier_field(object, "target_zone", 128)
                && object.get("source_zone") != object.get("target_zone")
                && uuid_field(object, "export_intent_id")
        }
        DataOperation::ResolveRetention => {
            exact_keys(
                object,
                &[
                    "retention_id",
                    "object_ref",
                    "retention_label",
                    "action",
                    "retain_until",
                    "policy_version",
                    "legal_hold_checked_at",
                    "resolver_receipt_ref",
                    "resolver_receipt_digest",
                ],
            ) && uuid_field(object, "retention_id")
                && object_reference_field(object, "object_ref")
                && identifier_field(object, "retention_label", 128)
                && object
                    .get("action")
                    .and_then(Value::as_str)
                    .is_some_and(|value| matches!(value, "DELETE" | "ARCHIVE" | "RETAIN"))
                && future_timestamp_field(object, "retain_until", 20 * 365 * 24 * 3600)
                && identifier_field(object, "policy_version", 256)
                && recent_timestamp_field(object, "legal_hold_checked_at", 10)
                && adapter_reference_field(object, "resolver_receipt_ref")
                && digest_field(object, "resolver_receipt_digest")
        }
        DataOperation::PlaceLegalHold => {
            exact_keys(
                object,
                &[
                    "hold_id",
                    "object_ref",
                    "reason_digest",
                    "approval_id",
                    "approval_evidence_ref",
                    "approval_evidence_digest",
                    "effective_at",
                ],
            ) && uuid_field(object, "hold_id")
                && object_reference_field(object, "object_ref")
                && digest_field(object, "reason_digest")
                && uuid_field(object, "approval_id")
                && evidence_reference_field(object, "approval_evidence_ref")
                && digest_field(object, "approval_evidence_digest")
                && recent_timestamp_field(object, "effective_at", 10)
        }
        DataOperation::ReleaseLegalHold => {
            exact_keys(
                object,
                &[
                    "hold_id",
                    "object_ref",
                    "released_at",
                    "release_approval_id",
                    "release_evidence_ref",
                    "release_evidence_digest",
                ],
            ) && uuid_field(object, "hold_id")
                && object_reference_field(object, "object_ref")
                && recent_timestamp_field(object, "released_at", 10)
                && uuid_field(object, "release_approval_id")
                && evidence_reference_field(object, "release_evidence_ref")
                && digest_field(object, "release_evidence_digest")
        }
        DataOperation::AuthorizeExport => {
            exact_keys(
                object,
                &[
                    "export_id",
                    "object_ref",
                    "object_digest",
                    "label_digest",
                    "decision_id",
                    "decision_digest",
                    "policy_request_digest",
                    "dlp_scan_id",
                    "dlp_receipt_digest",
                    "transform_id",
                    "transform_receipt_digest",
                    "grant_id",
                    "object_authorization_ref",
                    "object_authorization_digest",
                    "destination_kind",
                    "destination_digest",
                    "expires_at",
                    "redirects_allowed",
                ],
            ) && uuid_field(object, "export_id")
                && object_reference_field(object, "object_ref")
                && digest_field(object, "object_digest")
                && digest_field(object, "label_digest")
                && uuid_field(object, "decision_id")
                && digest_field(object, "decision_digest")
                && digest_field(object, "policy_request_digest")
                && uuid_field(object, "dlp_scan_id")
                && digest_field(object, "dlp_receipt_digest")
                && optional_uuid_field(object, "transform_id")
                && optional_digest_field(object, "transform_receipt_digest")
                && (object.get("transform_id").and_then(Value::as_str).is_some()
                    == object
                        .get("transform_receipt_digest")
                        .and_then(Value::as_str)
                        .is_some())
                && optional_uuid_field(object, "grant_id")
                && object
                    .get("object_authorization_ref")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.starts_with("object://") && adapter_reference(value))
                && digest_field(object, "object_authorization_digest")
                && identifier_field(object, "destination_kind", 2048)
                && digest_field(object, "destination_digest")
                && future_timestamp_field(object, "expires_at", 3600)
                && object.get("redirects_allowed").and_then(Value::as_bool) == Some(false)
        }
        DataOperation::CompleteExport => {
            exact_keys(
                object,
                &[
                    "export_id",
                    "object_digest",
                    "artifact_ref",
                    "artifact_digest",
                    "watermark_digest",
                    "signature_digest",
                    "worm_receipt_ref",
                    "worm_receipt_digest",
                    "completed_at",
                ],
            ) && uuid_field(object, "export_id")
                && digest_field(object, "object_digest")
                && artifact_reference_field(object, "artifact_ref")
                && digest_field(object, "artifact_digest")
                && digest_field(object, "watermark_digest")
                && digest_field(object, "signature_digest")
                && adapter_reference_field(object, "worm_receipt_ref")
                && digest_field(object, "worm_receipt_digest")
                && recent_timestamp_field(object, "completed_at", 10)
        }
    }
}

fn valid_label_value(value: Option<&Value>) -> bool {
    let Some(object) = value.and_then(Value::as_object) else {
        return false;
    };
    exact_keys(
        object,
        &[
            "schema_version",
            "classification",
            "domain_tags",
            "jurisdictions",
            "contains_secret",
            "contains_personal_data",
            "export_restricted",
            "retention_label",
            "confidence",
            "lineage",
        ],
    ) && object.get("schema_version").and_then(Value::as_str) == Some(crate::DATA_SCHEMA_VERSION)
        && classification_field(object, "classification")
        && string_array_field(object, "domain_tags", 0, 64)
        && string_array_field(object, "jurisdictions", 1, 32)
        && boolean_field(object, "contains_secret")
        && boolean_field(object, "contains_personal_data")
        && boolean_field(object, "export_restricted")
        && identifier_field(object, "retention_label", 128)
        && object
            .get("confidence")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                matches!(
                    value,
                    "UNKNOWN" | "INFERRED" | "DETERMINISTIC" | "HUMAN_VERIFIED"
                )
            })
        && (object.get("confidence").and_then(Value::as_str) != Some("UNKNOWN")
            || object
                .get("classification")
                .and_then(Value::as_str)
                .is_some_and(|value| matches!(value, "RESTRICTED" | "REGULATED")))
        && (!object
            .get("contains_secret")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || (object
                .get("classification")
                .and_then(Value::as_str)
                .is_some_and(|value| matches!(value, "RESTRICTED" | "REGULATED"))
                && object.get("export_restricted").and_then(Value::as_bool) == Some(true)))
        && (!object
            .get("contains_personal_data")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || (object.get("classification").and_then(Value::as_str) == Some("REGULATED")
                && object.get("export_restricted").and_then(Value::as_bool) == Some(true)))
        && object
            .get("lineage")
            .and_then(Value::as_object)
            .is_some_and(|lineage| {
                exact_keys(
                    lineage,
                    &["source_id", "source_hash", "transformation_hashes"],
                ) && identifier_field(lineage, "source_id", 512)
                    && digest_field(lineage, "source_hash")
                    && digest_array_field(lineage, "transformation_hashes", 0, 1024)
            })
}

fn valid_policy_decision(value: Option<&Value>) -> bool {
    let Some(object) = value.and_then(Value::as_object) else {
        return false;
    };
    exact_keys(
        object,
        &[
            "schema_version",
            "allowed",
            "policy_version",
            "reason_codes",
            "required_transformations",
            "maximum_retention_seconds",
        ],
    ) && object.get("schema_version").and_then(Value::as_str) == Some(crate::DATA_SCHEMA_VERSION)
        && boolean_field(object, "allowed")
        && identifier_field(object, "policy_version", 256)
        && string_array_field(object, "reason_codes", 1, 32)
        && string_array_field(object, "required_transformations", 0, 32)
        && bounded_integer_field(object, "maximum_retention_seconds", 0, 20 * 365 * 24 * 3600)
}

fn valid_policy_request(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Ok(request) = serde_json::from_value::<DataPolicyRequest>(value.clone()) else {
        return false;
    };
    request.schema_version.0 == CONTRACT_SCHEMA_VERSION
        && canonical_uuid(&request.tenant_id.0)
        && jurisdiction(&request.source_jurisdiction)
        && jurisdiction(&request.destination_jurisdiction)
        && identifier(&request.destination_kind, 2048)
        && !request.deployment_profile.is_empty()
        && request.deployment_profile.len() <= 128
        && request
            .deployment_profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && request
            .cross_domain_approval_id
            .as_ref()
            .is_none_or(|approval| canonical_uuid(&approval.0))
}

fn valid_finding_counts(value: Option<&Value>) -> bool {
    let Some(object) = value.and_then(Value::as_object) else {
        return false;
    };
    object.len() <= 16
        && object.iter().all(|(key, value)| {
            matches!(
                key.as_str(),
                "SECRET"
                    | "PERSONAL_DATA"
                    | "INDUSTRIAL_SENSITIVE"
                    | "ENCODED_PAYLOAD"
                    | "COMPRESSED_PAYLOAD"
                    | "UNKNOWN"
            ) && value.as_u64().is_some_and(|count| count <= 1_000_000)
        })
}

fn payload_object(payload: &Value) -> Result<&serde_json::Map<String, Value>, DataAuthorityError> {
    payload
        .as_object()
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn embedded_digest_matches(object: &serde_json::Map<String, Value>, digest_key: &str) -> bool {
    let Some(expected) = object.get(digest_key).and_then(Value::as_str) else {
        return false;
    };
    let mut material = object.clone();
    material.remove(digest_key);
    canonical_digest(&Value::Object(material)).is_ok_and(|actual| actual == expected)
}

fn contains_forbidden_content_key(value: &Value, depth: usize) -> bool {
    if depth > 32 {
        return true;
    }
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "raw"
                    | "raw_content"
                    | "content"
                    | "content_base64"
                    | "prompt"
                    | "sanitized_prompt"
                    | "sample"
                    | "secret"
                    | "password"
                    | "token"
                    | "api_key"
                    | "authorization"
                    | "credential"
                    | "private_key"
            ) || contains_forbidden_content_key(value, depth + 1)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_forbidden_content_key(value, depth + 1)),
        _ => false,
    }
}

fn value<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a Value, DataAuthorityError> {
    object.get(key).ok_or(DataAuthorityError::RequestInvalid)
}

fn text<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, DataAuthorityError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn optional_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, DataAuthorityError> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(DataAuthorityError::RequestInvalid),
    }
}

fn boolean(object: &serde_json::Map<String, Value>, key: &str) -> Result<bool, DataAuthorityError> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn integer(object: &serde_json::Map<String, Value>, key: &str) -> Result<i64, DataAuthorityError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn nested_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    parent: &str,
    key: &str,
) -> Result<&'a str, DataAuthorityError> {
    object
        .get(parent)
        .and_then(Value::as_object)
        .and_then(|nested| nested.get(key))
        .and_then(Value::as_str)
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn nested_bool(
    object: &serde_json::Map<String, Value>,
    parent: &str,
    key: &str,
) -> Result<bool, DataAuthorityError> {
    object
        .get(parent)
        .and_then(Value::as_object)
        .and_then(|nested| nested.get(key))
        .and_then(Value::as_bool)
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn identifier_field(object: &serde_json::Map<String, Value>, key: &str, max: usize) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| identifier(value, max))
}

fn digest_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object.get(key).and_then(Value::as_str).is_some_and(digest)
}

fn optional_digest_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(digest))
}

fn uuid_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(canonical_uuid)
}

fn optional_uuid_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(canonical_uuid))
}

fn boolean_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object.get(key).is_some_and(Value::is_boolean)
}

fn classification_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| {
            matches!(
                value,
                "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "REGULATED"
            )
        })
}

fn jurisdiction_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(jurisdiction)
}

fn jurisdiction(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn bounded_integer_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    minimum: u64,
    maximum: u64,
) -> bool {
    object
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|value| (minimum..=maximum).contains(&value))
}

fn string_array_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> bool {
    object
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            (minimum..=maximum).contains(&values.len())
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|text| identifier(text, 256)))
                && values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == values.len()
        })
}

fn digest_array_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> bool {
    object
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            (minimum..=maximum).contains(&values.len())
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(digest))
                && values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == values.len()
        })
}

fn object_reference_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(object_reference)
}

fn evidence_reference_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(evidence_reference)
}

fn adapter_reference_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(adapter_reference)
}

fn artifact_reference_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| {
            (value.starts_with("artifact://") || value.starts_with("object://"))
                && identifier(value, 2048)
        })
}

fn recent_timestamp_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    tolerance_minutes: i64,
) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|value| {
            let value = value.with_timezone(&Utc);
            value >= Utc::now() - Duration::minutes(tolerance_minutes)
                && value <= Utc::now() + Duration::minutes(1)
        })
}

fn future_timestamp_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    maximum_seconds: u64,
) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|value| {
            let value = value.with_timezone(&Utc);
            let Ok(maximum_seconds) = i64::try_from(maximum_seconds) else {
                return false;
            };
            value > Utc::now() && value <= Utc::now() + Duration::seconds(maximum_seconds)
        })
}

fn payload_classification(payload: &Value) -> DataClassification {
    let classification = payload
        .as_object()
        .and_then(|object| object.get("classification"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .as_object()
                .and_then(|object| object.get("label"))
                .and_then(Value::as_object)
                .and_then(|label| label.get("classification"))
                .and_then(Value::as_str)
        });
    match classification {
        Some("PUBLIC") => DataClassification::Public,
        Some("INTERNAL") => DataClassification::Internal,
        Some("CONFIDENTIAL") => DataClassification::Confidential,
        Some("REGULATED") => DataClassification::Regulated,
        _ => DataClassification::Restricted,
    }
}

fn classification_name(classification: DataClassification) -> &'static str {
    match classification {
        DataClassification::Public => "PUBLIC",
        DataClassification::Internal => "INTERNAL",
        DataClassification::Confidential => "CONFIDENTIAL",
        DataClassification::Restricted => "RESTRICTED",
        DataClassification::Regulated => "REGULATED",
    }
}

fn payload_jurisdiction(payload: &Value) -> Option<String> {
    payload
        .as_object()
        .and_then(|object| object.get("source_jurisdiction"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            payload
                .as_object()
                .and_then(|object| object.get("label"))
                .and_then(Value::as_object)
                .and_then(|label| label.get("jurisdictions"))
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

pub(crate) fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

pub(crate) fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn evidence_reference(value: &str) -> bool {
    value.starts_with("evidence://") && identifier(value, 2048)
}

pub(crate) fn adapter_reference(value: &str) -> bool {
    (value.starts_with("dlp://")
        || value.starts_with("object://")
        || value.starts_with("worm://")
        || value.starts_with("legal-hold://")
        || value.starts_with("evidence://"))
        && identifier(value, 2048)
}

fn object_reference(value: &str) -> bool {
    (value.starts_with("artifact://")
        || value.starts_with("object://")
        || value.starts_with("dataset://")
        || value.starts_with("trace://")
        || value.starts_with("field://"))
        && identifier(value, 2048)
}

fn resource_reference(value: &str) -> bool {
    !value.starts_with('/')
        && !value.contains("..")
        && !value.contains("//")
        && identifier(value, 1024)
}

pub(crate) fn valid_idempotency_key(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_tenant(tenant: &TenantId) -> Result<Uuid, DataAuthorityError> {
    parse_uuid(&tenant.0)
}

fn parse_uuid(value: &str) -> Result<Uuid, DataAuthorityError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(DataAuthorityError::RequestInvalid)
}

pub(crate) fn canonical_digest<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, DataAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| DataAuthorityError::RequestInvalid)
}

pub(crate) fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn dependency(_: sqlx::Error) -> DataAuthorityError {
    DataAuthorityError::DependencyUnavailable
}
