//! Authoritative production execution composition.
//!
//! The service deliberately composes domain contracts owned by action-ir, registry,
//! policy-pep, transaction-ledger, tool-proxy, and evidence-evaluator. It does not
//! duplicate any of their policy, fencing, connector, or evidence-chain semantics.

use agent_trust_action_ir::{
    CanonicalAction, NormalizationContext, ParseLimits, RuntimeContext, TrajectoryRiskSnapshot,
    hash as canonical_action_hash, normalize, parse_draft, to_policy_input,
};
use agent_trust_contracts::{
    APPROVAL_CONSUMPTION_REQUEST_SCHEMA_VERSION, ActionHash, ApprovalConsumptionRequest,
    ApprovalGrantReceipt, ArtifactRef, Decision, ENTERPRISE_APPROVAL_GRANT_SCHEMA_VERSION,
    EVIDENCE_EVENT_SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION, EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE,
    EXECUTION_AUTHORIZATION_SCHEMA_VERSION, EXECUTION_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    EXECUTION_EVIDENCE_REQUEST_SCHEMA_VERSION, EffectClass, EnforcementStage,
    EnterpriseApprovalGrant, EvidenceEventDraft, EvidenceEventType, ExecutionAuthorization,
    ExecutionEvidenceRequest as SharedExecutionEvidenceRequest, ExecutionStatus, IdempotencyKey,
    MinimalApprovalGrant, Obligation, PEP_EXECUTION_AUTHORIZATION_KEY_USAGE,
    PEP_PRE_APPROVAL_KEY_USAGE, PepFinalAuthorizationRequest, PepPreApprovalEnvelope,
    PepPreApprovalRequest, PepPreExecutionAuthorization, ResourceVersion, SignedEvidenceEvent,
    SignedExecutionEvidenceReceipt, SignedPreApprovalOutcome, TaskId, TenantId, ToolRef,
    WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE, WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION,
    WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE,
    WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION,
};
use agent_trust_evidence_evaluator::EvidenceError;
use agent_trust_gateway::{GATEWAY_SCHEMA_VERSION, InboundEnvelope, IngressProtocol};
use agent_trust_identity::CredentialHandle;
use agent_trust_policy_pep::{POLICY_SCHEMA_VERSION, policy_input_hash};
use agent_trust_registry::{
    REGISTRY_SCHEMA_VERSION, ResolvedToolSnapshot, ToolManifest, ToolVersionStatus,
    canonical_manifest_hash, canonical_schema_pair_hash, resolved_snapshot_from_active_manifest,
    validate_schema_instance,
};
use agent_trust_tool_proxy::{AuthorizedToolRequest, PROXY_SCHEMA_VERSION, SanitizedToolResult};
use agent_trust_transaction_ledger::{
    CompensationPlan, ExecutionFence, ExecutionIntent, ExecutionLedger, ExecutionRecord,
    LEDGER_SCHEMA_VERSION, LedgerError,
};
use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

pub const EXECUTION_REQUEST_SCHEMA: &str = "agenttrust.execution-request.v1";
pub const EXECUTION_OUTCOME_SCHEMA: &str = "agenttrust.execution-outcome.v1";
pub const EXECUTION_READINESS_SCHEMA: &str = "agenttrust.execution-readiness.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionMaterializationRef {
    pub schema_version: String,
    pub tenant_id: String,
    pub action_id: String,
    pub payload_hash: String,
    pub store: String,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub schema_version: String,
    pub tenant_id: String,
    pub task_id: String,
    pub action_id: String,
    pub ingress_digest: String,
    pub idempotency_key: String,
    pub action_materialization: ActionMaterializationRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOutcome {
    pub schema_version: String,
    pub tenant_id: String,
    pub task_id: String,
    pub action_id: String,
    pub ingress_digest: String,
    pub idempotency_key: String,
    pub ledger_execution_id: String,
    pub fence_digest: String,
    pub status: ExecutionStatus,
    pub outcome_digest: String,
    pub evidence_refs: Vec<String>,
    pub action_materialization: ActionMaterializationRef,
}

#[derive(Debug, Clone)]
pub struct MaterializedAction {
    pub action: CanonicalAction,
    pub action_hash: ActionHash,
    pub owner_subject: String,
    pub trace_id: String,
}

pub type PreApprovalRequest = PepPreApprovalRequest<CanonicalAction, ResolvedToolSnapshot>;
pub type FinalAuthorizationRequest = PepFinalAuthorizationRequest<
    CanonicalAction,
    ResolvedToolSnapshot,
    agent_trust_action_ir::PolicyInput,
>;
pub type PreExecutionAuthorization =
    PepPreExecutionAuthorization<ResolvedToolSnapshot, CredentialHandle>;
pub type PreApprovalOutcome = PepPreApprovalEnvelope<CompensationPlan>;

/// The approval transport is pinned to the shared `agenttrust.approval-grant-request.v1`
/// and `agenttrust.approval-grant-receipt.v1` wire contracts.  The values are
/// imported from `contracts` below rather than re-declared in this client.
pub type ApprovalGrantRequest = ApprovalConsumptionRequest;

pub type ExecutionEvidenceRequest = SharedExecutionEvidenceRequest<SanitizedToolResult>;

pub type ExecutionEvidenceReceipt = SignedExecutionEvidenceReceipt;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[async_trait]
pub trait CanonicalActionMaterializer: Send + Sync {
    async fn materialize(
        &self,
        request: &ExecutionRequest,
    ) -> Result<MaterializedAction, ExecutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait ActiveToolRegistryPort: Send + Sync {
    async fn resolve(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, ExecutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait PreExecutionPepPort: Send + Sync {
    async fn preapprove(
        &self,
        request: &PreApprovalRequest,
    ) -> Result<PreApprovalOutcome, ExecutionError>;
    async fn authorize(
        &self,
        request: &FinalAuthorizationRequest,
    ) -> Result<PreExecutionAuthorization, ExecutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait ApprovalGrantPort: Send + Sync {
    async fn consume(
        &self,
        request: &ApprovalGrantRequest,
    ) -> Result<ApprovalGrantReceipt, ExecutionError>;
    fn verify_receipt(
        &self,
        request: &ApprovalGrantRequest,
        receipt: &ApprovalGrantReceipt,
    ) -> Result<MinimalApprovalGrant, ExecutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait ProductionToolProxyPort: Send + Sync {
    async fn execute(
        &self,
        request: AuthorizedToolRequest,
        idempotency_key: &str,
        fence_digest: &str,
    ) -> Result<SanitizedToolResult, ExecutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait ExecutionEvidencePort: Send + Sync {
    async fn append(
        &self,
        request: &ExecutionEvidenceRequest,
    ) -> Result<ExecutionEvidenceReceipt, ExecutionError>;
    fn verify_receipt(&self, receipt: &ExecutionEvidenceReceipt) -> Result<(), ExecutionError>;
    async fn ready(&self) -> bool;
}

#[derive(Clone)]
pub struct PostgresActionMaterializer {
    pool: PgPool,
}

impl PostgresActionMaterializer {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanonicalActionMaterializer for PostgresActionMaterializer {
    async fn materialize(
        &self,
        request: &ExecutionRequest,
    ) -> Result<MaterializedAction, ExecutionError> {
        validate_request(request)?;
        let tenant =
            Uuid::parse_str(&request.tenant_id).map_err(|_| ExecutionError::RequestInvalid)?;
        let action =
            Uuid::parse_str(&request.action_id).map_err(|_| ExecutionError::RequestInvalid)?;
        let mut transaction = self.pool.begin().await.map_err(dependency)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(dependency)?;
        let row = sqlx::query(
            "SELECT tenant_id,action_id,task_id,owner_subject,payload_hash,envelope \
             FROM orchestrator_ingress_actions WHERE tenant_id=$1 AND action_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(action)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(dependency)?
        .ok_or(ExecutionError::MaterializationInvalid)?;
        let row_tenant: Uuid = row.try_get("tenant_id").map_err(materialization)?;
        let row_action: Uuid = row.try_get("action_id").map_err(materialization)?;
        let row_task: Uuid = row.try_get("task_id").map_err(materialization)?;
        let owner_subject: String = row.try_get("owner_subject").map_err(materialization)?;
        let payload_hash: String = row.try_get("payload_hash").map_err(materialization)?;
        let envelope: Value = row.try_get("envelope").map_err(materialization)?;

        let envelope_object = envelope
            .as_object()
            .ok_or(ExecutionError::MaterializationInvalid)?;
        let typed_envelope: InboundEnvelope =
            serde_json::from_value(envelope.clone()).map_err(materialization)?;
        let expected_envelope_keys = [
            "request_id",
            "trace_context",
            "identity_context",
            "tenant_context",
            "protocol",
            "content_type",
            "schema_version",
            "idempotency_key",
            "received_at",
            "payload",
            "payload_hash",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        if envelope_object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected_envelope_keys
            || row_tenant != tenant
            || row_action != action
            || row_task.to_string() != request.task_id
            || payload_hash != request.action_materialization.payload_hash
            || typed_envelope.schema_version != GATEWAY_SCHEMA_VERSION
            || typed_envelope.protocol != IngressProtocol::Http
            || typed_envelope.content_type.split(';').next().map(str::trim)
                != Some("application/json")
            || typed_envelope
                .idempotency_key
                .as_deref()
                .is_none_or(str::is_empty)
            || typed_envelope.payload_hash != payload_hash
            || typed_envelope.identity_context.tenant_id.0 != request.tenant_id
            || typed_envelope.tenant_context.tenant_id.0 != request.tenant_id
            || typed_envelope.identity_context.owner_subject != owner_subject
            || owner_subject.is_empty()
        {
            return Err(ExecutionError::MaterializationInvalid);
        }
        if hex_digest(&python_compact_sorted_json_bytes(&envelope)?) != request.ingress_digest {
            return Err(ExecutionError::MaterializationInvalid);
        }
        let payload = typed_envelope.payload;
        if payload.len() > ParseLimits::default().max_body_bytes
            || hex_digest(&payload) != payload_hash
        {
            return Err(ExecutionError::MaterializationInvalid);
        }
        let draft = parse_draft(&payload, &ParseLimits::default())?;
        let canonical = normalize(draft, &NormalizationContext::default())?;
        if canonical.agent.tenant_id.0 != request.tenant_id
            || canonical.resource.tenant_id.0 != request.tenant_id
            || canonical.environment.tenant_id.0 != request.tenant_id
            || canonical.action_id.0 != request.action_id
            || canonical.task_id.0 != request.task_id
            || canonical.agent.owner_subject != owner_subject
            || !canonical
                .environment
                .deployment
                .eq_ignore_ascii_case("production")
            || canonical.environment.simulation
            || !canonical
                .agent
                .deployment_environment
                .eq_ignore_ascii_case("production")
        {
            return Err(ExecutionError::MaterializationInvalid);
        }
        let trace_id = typed_envelope.trace_context.trace_id;
        if trace_id.is_empty() || trace_id.len() > 256 {
            return Err(ExecutionError::MaterializationInvalid);
        }
        transaction.commit().await.map_err(dependency)?;
        Ok(MaterializedAction {
            action_hash: canonical_action_hash(&canonical)?,
            action: canonical,
            owner_subject,
            trace_id,
        })
    }

    async fn ready(&self) -> bool {
        tokio::time::timeout(
            Duration::from_millis(400),
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        )
        .await
        .ok()
        .and_then(Result::ok)
            == Some(1)
    }
}

#[derive(Clone)]
pub struct PostgresActiveToolRegistry {
    pool: PgPool,
}

impl PostgresActiveToolRegistry {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ActiveToolRegistryPort for PostgresActiveToolRegistry {
    async fn resolve(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, ExecutionError> {
        tool.validate_exact()
            .map_err(|_| ExecutionError::AuthorizationDenied)?;
        let tenant_uuid = Uuid::parse_str(&tenant.0).map_err(|_| ExecutionError::RequestInvalid)?;
        let mut transaction = self.pool.begin().await.map_err(dependency)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(dependency)?;
        let row = sqlx::query(
            "SELECT manifest,manifest_hash,COALESCE(schema_hash,'') AS schema_hash \
             FROM tool_versions WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status='ACTIVE' FOR SHARE",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(dependency)?
        .ok_or(ExecutionError::AuthorizationDenied)?;
        let mut manifest: ToolManifest = serde_json::from_value(
            row.try_get("manifest")
                .map_err(|_| ExecutionError::DependencyResponseInvalid)?,
        )
        .map_err(|_| ExecutionError::DependencyResponseInvalid)?;
        manifest.status = ToolVersionStatus::Active;
        let stored_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| ExecutionError::DependencyResponseInvalid)?;
        let stored_schema_hash: String = row
            .try_get("schema_hash")
            .map_err(|_| ExecutionError::DependencyResponseInvalid)?;
        if canonical_manifest_hash(&manifest)? != stored_hash
            || (!stored_schema_hash.is_empty()
                && canonical_schema_pair_hash(&manifest)? != stored_schema_hash)
        {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        let compensation_target_active = if let Some(binding) = &manifest.compensation {
            if binding.tool == manifest.tool_ref() {
                true
            } else {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM tool_versions WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status='ACTIVE')",
                )
                .bind(tenant_uuid)
                .bind(&binding.tool.tool_id.0)
                .bind(&binding.tool.tool_version.0)
                .fetch_one(&mut *transaction)
                .await
                .map_err(dependency)?
            }
        } else {
            true
        };
        transaction.commit().await.map_err(dependency)?;
        let snapshot =
            resolved_snapshot_from_active_manifest(tenant, &manifest, compensation_target_active)?;
        if snapshot.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        Ok(snapshot)
    }

    async fn ready(&self) -> bool {
        tokio::time::timeout(
            Duration::from_millis(400),
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        )
        .await
        .ok()
        .and_then(Result::ok)
            == Some(1)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PepKeyDocument {
    schema_version: String,
    keys: Vec<PepKeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PepKeyEntry {
    key_id: String,
    issuer: String,
    algorithm: String,
    public_key_base64: String,
    #[serde(default)]
    key_usages: BTreeSet<String>,
}

type AuthorizationKey = (String, VerifyingKey, BTreeSet<String>);

#[derive(Clone)]
pub struct PepAuthorizationKeyring {
    keys: Arc<BTreeMap<String, AuthorizationKey>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyDocument {
    schema_version: String,
    keys: Vec<EvidenceKeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyEntry {
    key_id: String,
    issuer: String,
    algorithm: String,
    public_key_base64: String,
    key_usages: BTreeSet<String>,
}

#[derive(Clone)]
pub struct ApprovalGrantKeyring {
    keys: Arc<BTreeMap<String, (String, VerifyingKey)>>,
}

impl ApprovalGrantKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ExecutionError> {
        // Approval and PEP key documents intentionally share the same strict wire shape.
        let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ExecutionError::Configuration);
        }
        let document: PepKeyDocument =
            serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
        if document.schema_version != "agenttrust.approval-verification-keys.v1"
            || document.keys.is_empty()
        {
            return Err(ExecutionError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw_key = STANDARD
                .decode(entry.public_key_base64)
                .map_err(|_| ExecutionError::Configuration)?;
            let key: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| ExecutionError::Configuration)?;
            if entry.key_id.is_empty()
                || entry.issuer.is_empty()
                || entry.algorithm != "Ed25519"
                || keys
                    .insert(
                        entry.key_id,
                        (
                            entry.issuer,
                            VerifyingKey::from_bytes(&key)
                                .map_err(|_| ExecutionError::Configuration)?,
                        ),
                    )
                    .is_some()
            {
                return Err(ExecutionError::Configuration);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn verify(&self, grant: &EnterpriseApprovalGrant) -> Result<(), ExecutionError> {
        use ed25519_dalek::{Signature, Verifier};
        let (issuer, key) = self
            .keys
            .get(&grant.key_id)
            .ok_or(ExecutionError::AuthorizationDenied)?;
        if issuer != &grant.issuer
            || grant.schema_version.0 != ENTERPRISE_APPROVAL_GRANT_SCHEMA_VERSION
            || grant.maximum_uses != 1
            || grant.approver_subjects.is_empty()
            || Utc::now() < grant.issued_at
            || Utc::now() >= grant.expires_at
        {
            return Err(ExecutionError::AuthorizationDenied);
        }
        let mut unsigned = grant.clone();
        unsigned.signature.clear();
        let raw = URL_SAFE_NO_PAD
            .decode(&grant.signature)
            .map_err(|_| ExecutionError::AuthorizationDenied)?;
        let signature =
            Signature::from_slice(&raw).map_err(|_| ExecutionError::AuthorizationDenied)?;
        key.verify(
            &serde_jcs::to_vec(&unsigned).map_err(|_| ExecutionError::AuthorizationDenied)?,
            &signature,
        )
        .map_err(|_| ExecutionError::AuthorizationDenied)
    }
}

#[derive(Clone)]
pub struct EvidenceEventKeyring {
    keys: Arc<BTreeMap<String, AuthorizationKey>>,
}

impl EvidenceEventKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ExecutionError> {
        let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ExecutionError::Configuration);
        }
        let document: EvidenceKeyDocument =
            serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
        if document.schema_version != "agenttrust.evidence-verification-keys.v1"
            || document.keys.is_empty()
        {
            return Err(ExecutionError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw_key = STANDARD
                .decode(entry.public_key_base64)
                .map_err(|_| ExecutionError::Configuration)?;
            let key: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| ExecutionError::Configuration)?;
            if entry.key_id.is_empty()
                || entry.issuer.is_empty()
                || entry.algorithm != "Ed25519"
                || !entry
                    .key_usages
                    .contains(EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE)
                || keys
                    .insert(
                        entry.key_id,
                        (
                            entry.issuer,
                            VerifyingKey::from_bytes(&key)
                                .map_err(|_| ExecutionError::Configuration)?,
                            entry.key_usages,
                        ),
                    )
                    .is_some()
            {
                return Err(ExecutionError::Configuration);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn verify_event(&self, event: &SignedEvidenceEvent) -> Result<(), ExecutionError> {
        use ed25519_dalek::{Signature, Verifier};
        let (_, key, _) = self
            .keys
            .get(&event.key_id)
            .ok_or(ExecutionError::EvidenceInvalid)?;
        let mut unsigned = event.clone();
        unsigned.event_hash.clear();
        unsigned.signature.clear();
        let expected_hash =
            hex_digest(&serde_jcs::to_vec(&unsigned).map_err(|_| ExecutionError::EvidenceInvalid)?);
        if expected_hash != event.event_hash {
            return Err(ExecutionError::EvidenceInvalid);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&event.signature)
            .map_err(|_| ExecutionError::EvidenceInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ExecutionError::EvidenceInvalid)?;
        key.verify(event.event_hash.as_bytes(), &signature)
            .map_err(|_| ExecutionError::EvidenceInvalid)
    }

    fn verify_receipt(&self, receipt: &ExecutionEvidenceReceipt) -> Result<(), ExecutionError> {
        let (issuer, key, usages) = self
            .keys
            .get(&receipt.key_id)
            .ok_or(ExecutionError::EvidenceInvalid)?;
        if issuer != &receipt.issuer || !usages.contains(EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE) {
            return Err(ExecutionError::EvidenceInvalid);
        }
        receipt
            .verify(key, Utc::now())
            .map_err(|_| ExecutionError::EvidenceInvalid)?;
        self.verify_event(&receipt.event)
    }
}

impl PepAuthorizationKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ExecutionError> {
        let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ExecutionError::Configuration);
        }
        let document: PepKeyDocument =
            serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
        if document.schema_version != "agenttrust.pep-verification-keys.v1"
            || document.keys.is_empty()
        {
            return Err(ExecutionError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw_key = STANDARD
                .decode(entry.public_key_base64)
                .map_err(|_| ExecutionError::Configuration)?;
            let key: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| ExecutionError::Configuration)?;
            if entry.key_id.is_empty()
                || entry.issuer.is_empty()
                || entry.algorithm != "Ed25519"
                || !entry.key_usages.contains(PEP_PRE_APPROVAL_KEY_USAGE)
                || !entry
                    .key_usages
                    .contains(PEP_EXECUTION_AUTHORIZATION_KEY_USAGE)
                || keys
                    .insert(
                        entry.key_id,
                        (
                            entry.issuer,
                            VerifyingKey::from_bytes(&key)
                                .map_err(|_| ExecutionError::Configuration)?,
                            entry.key_usages,
                        ),
                    )
                    .is_some()
            {
                return Err(ExecutionError::Configuration);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn verify_authorization(
        &self,
        authorization: &ExecutionAuthorization,
    ) -> Result<(), ExecutionError> {
        let (issuer, key, usages) = self
            .keys
            .get(&authorization.key_id)
            .ok_or(ExecutionError::DependencyResponseInvalid)?;
        if issuer != &authorization.issuer
            || !usages.contains(PEP_EXECUTION_AUTHORIZATION_KEY_USAGE)
        {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        authorization
            .verify(key, Utc::now())
            .map_err(|_| ExecutionError::DependencyResponseInvalid)
    }

    fn verify_preapproval(&self, outcome: &SignedPreApprovalOutcome) -> Result<(), ExecutionError> {
        let (issuer, key, usages) = self
            .keys
            .get(&outcome.key_id)
            .ok_or(ExecutionError::DependencyResponseInvalid)?;
        if issuer != &outcome.issuer || !usages.contains(PEP_PRE_APPROVAL_KEY_USAGE) {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        outcome
            .verify(key, Utc::now())
            .map_err(|_| ExecutionError::DependencyResponseInvalid)
    }
}

#[derive(Clone)]
pub struct HttpExecutionPort {
    client: reqwest::Client,
    base_url: url::Url,
    token: Arc<str>,
    readiness_schema: Arc<str>,
    evidence_keys: Option<EvidenceEventKeyring>,
}

impl HttpExecutionPort {
    // The constructor keeps the endpoint, credential material, readiness contract, and
    // service-specific verification keyrings explicit so production callers cannot silently
    // inherit insecure defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: &str,
        token: String,
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
        readiness_schema: String,
        evidence_keys: Option<EvidenceEventKeyring>,
    ) -> Result<Self, ExecutionError> {
        let base_url = url::Url::parse(endpoint).map_err(|_| ExecutionError::Configuration)?;
        if base_url.scheme() != "https"
            || base_url.host_str().is_none()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
            || token.is_empty()
            || readiness_schema.is_empty()
        {
            return Err(ExecutionError::Configuration);
        }
        let ca = std::fs::read(ca_file).map_err(|_| ExecutionError::Configuration)?;
        let mut identity =
            std::fs::read(certificate_file).map_err(|_| ExecutionError::Configuration)?;
        if !identity.ends_with(b"\n") {
            identity.push(b'\n');
        }
        identity
            .extend(std::fs::read(private_key_file).map_err(|_| ExecutionError::Configuration)?);
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(20))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca).map_err(|_| ExecutionError::Configuration)?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|_| ExecutionError::Configuration)?,
            )
            .build()
            .map_err(|_| ExecutionError::Configuration)?;
        Ok(Self {
            client,
            base_url,
            token: token.into(),
            readiness_schema: readiness_schema.into(),
            evidence_keys,
        })
    }

    async fn post<T: Serialize + ?Sized, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
        tenant_id: &str,
        idempotency_key: &str,
        fence_digest: Option<&str>,
    ) -> Result<R, ExecutionError> {
        if Uuid::parse_str(tenant_id).is_err() {
            return Err(ExecutionError::Configuration);
        }
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| ExecutionError::Configuration)?;
        let mut request = self
            .client
            .post(url)
            .bearer_auth(self.token.as_ref())
            .header("Accept", "application/json")
            .header("X-AgentTrust-Tenant-Id", tenant_id)
            .header("Idempotency-Key", idempotency_key)
            .json(body);
        if let Some(fence) = fence_digest {
            request = request.header("X-AgentTrust-Fence-Digest", fence);
        }
        let mut response = request.send().await.map_err(dependency)?;
        if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::FORBIDDEN
                | reqwest::StatusCode::CONFLICT
                | reqwest::StatusCode::UNPROCESSABLE_ENTITY
        ) {
            return Err(ExecutionError::AuthorizationDenied);
        }
        if !response.status().is_success() {
            return Err(ExecutionError::DependencyUnavailable);
        }
        if !json_content_type(response.headers()) {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(dependency)? {
            if bytes.len().saturating_add(chunk.len()) > 1_048_576 {
                return Err(ExecutionError::DependencyResponseInvalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        serde_json::from_slice(&bytes).map_err(|_| ExecutionError::DependencyResponseInvalid)
    }

    async fn probe_ready(&self) -> bool {
        let Ok(url) = self.base_url.join("ready") else {
            return false;
        };
        let Ok(Ok(mut response)) = tokio::time::timeout(
            Duration::from_millis(600),
            self.client.get(url).bearer_auth(self.token.as_ref()).send(),
        )
        .await
        else {
            return false;
        };
        if !response.status().is_success() || !json_content_type(response.headers()) {
            return false;
        }
        if response
            .content_length()
            .is_some_and(|length| length > 65_536)
        {
            return false;
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(value) => value,
                Err(_) => return false,
            };
            let Some(chunk) = chunk else { break };
            if bytes.len().saturating_add(chunk.len()) > 65_536 {
                return false;
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return false;
        }
        serde_json::from_slice::<DependencyReadiness>(&bytes).is_ok_and(|value| {
            value.ready && value.schema_version == self.readiness_schema.as_ref()
        })
    }
}

/// PEP uses distinct credentials for pre-approval and final authorization. Keeping the two
/// transports separate prevents a leaked pre-approval token from being replayed at the route
/// that issues execution credentials and signed authorizations.
#[derive(Clone)]
pub struct HttpPepExecutionPort {
    preapproval: HttpExecutionPort,
    authorization: HttpExecutionPort,
    keys: PepAuthorizationKeyring,
}

impl HttpPepExecutionPort {
    pub fn new(
        preapproval: HttpExecutionPort,
        authorization: HttpExecutionPort,
        keys: PepAuthorizationKeyring,
    ) -> Result<Self, ExecutionError> {
        if preapproval.base_url != authorization.base_url
            || preapproval.readiness_schema != authorization.readiness_schema
            || preapproval.token.as_ref() == authorization.token.as_ref()
            || preapproval.evidence_keys.is_some()
            || authorization.evidence_keys.is_some()
        {
            return Err(ExecutionError::Configuration);
        }
        Ok(Self {
            preapproval,
            authorization,
            keys,
        })
    }
}

#[derive(Clone)]
pub struct HttpApprovalGrantPort {
    http: HttpExecutionPort,
    keys: ApprovalGrantKeyring,
}

impl HttpApprovalGrantPort {
    pub fn new(http: HttpExecutionPort, keys: ApprovalGrantKeyring) -> Self {
        Self { http, keys }
    }
}

#[async_trait]
impl ApprovalGrantPort for HttpApprovalGrantPort {
    async fn consume(
        &self,
        request: &ApprovalGrantRequest,
    ) -> Result<ApprovalGrantReceipt, ExecutionError> {
        // The approval service owns atomic single-use consumption and must return
        // the same receipt for this action-bound idempotency key on retry.
        self.http
            .post(
                "/v1/approvals/grants/consume",
                request,
                &request.tenant_id,
                &request.action_hash,
                None,
            )
            .await
    }
    fn verify_receipt(
        &self,
        request: &ApprovalGrantRequest,
        receipt: &ApprovalGrantReceipt,
    ) -> Result<MinimalApprovalGrant, ExecutionError> {
        let grant = &receipt.grant;
        self.keys.verify(grant)?;
        if receipt.schema_version != agent_trust_contracts::APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION
            || receipt.remaining_uses != 0
            || receipt.consumption_ref.is_empty()
            || receipt.consumption_ref.len() > 2_048
            || receipt.consumed_at < grant.issued_at
            || receipt.consumed_at >= grant.expires_at
            || receipt.consumed_at > Utc::now() + chrono::Duration::minutes(5)
            || grant.tenant_id.0 != request.tenant_id
            || grant.task_id.0 != request.task_id
            || grant.step_id.0 != request.step_id
            || grant.action_hash.0 != request.action_hash
            || grant.plan_hash != request.plan_hash
            || grant.parameter_hash != request.parameter_hash
            || grant.resource != request.resource
            || grant.resource_version.0 != request.resource_version
            || grant.policy_version.0 != request.policy_version
            || grant.environment != request.environment
            || request.maximum_risk > grant.maximum_risk
        {
            return Err(ExecutionError::AuthorizationDenied);
        }
        Ok(grant.to_minimal_grant())
    }
    async fn ready(&self) -> bool {
        self.http.probe_ready().await
    }
}

#[async_trait]
impl PreExecutionPepPort for HttpPepExecutionPort {
    async fn preapprove(
        &self,
        request: &PreApprovalRequest,
    ) -> Result<PreApprovalOutcome, ExecutionError> {
        let response: PreApprovalOutcome = self
            .preapproval
            .post(
                "/v1/authorize/pre-approval",
                request,
                &request.action.agent.tenant_id.0,
                &request.idempotency_key,
                None,
            )
            .await?;
        self.keys.verify_preapproval(&response.signed_outcome)?;
        Ok(response)
    }

    async fn authorize(
        &self,
        request: &FinalAuthorizationRequest,
    ) -> Result<PreExecutionAuthorization, ExecutionError> {
        let response: PreExecutionAuthorization = self
            .authorization
            .post(
                "/v1/authorize/execution",
                request,
                &request.action.agent.tenant_id.0,
                &request.idempotency_key,
                Some(&request.fence_digest),
            )
            .await?;
        self.keys.verify_authorization(&response.authorization)?;
        Ok(response)
    }
    async fn ready(&self) -> bool {
        let (preapproval, authorization) = tokio::join!(
            self.preapproval.probe_ready(),
            self.authorization.probe_ready(),
        );
        preapproval && authorization
    }
}

#[async_trait]
impl ProductionToolProxyPort for HttpExecutionPort {
    async fn execute(
        &self,
        request: AuthorizedToolRequest,
        idempotency_key: &str,
        fence_digest: &str,
    ) -> Result<SanitizedToolResult, ExecutionError> {
        if request.idempotency_key.0 != idempotency_key || request.fence_digest != fence_digest {
            return Err(ExecutionError::AuthorizationDenied);
        }
        self.post(
            "/v1/tools/execute",
            &request,
            &request.tenant_id.0,
            idempotency_key,
            Some(fence_digest),
        )
        .await
    }
    async fn ready(&self) -> bool {
        self.probe_ready().await
    }
}

#[async_trait]
impl ExecutionEvidencePort for HttpExecutionPort {
    async fn append(
        &self,
        request: &ExecutionEvidenceRequest,
    ) -> Result<ExecutionEvidenceReceipt, ExecutionError> {
        self.post(
            "/v1/evidence/executions",
            request,
            &request.tenant_id.0,
            &request.idempotency_key.0,
            Some(&request.fence_digest),
        )
        .await
    }
    fn verify_receipt(&self, receipt: &ExecutionEvidenceReceipt) -> Result<(), ExecutionError> {
        self.evidence_keys
            .as_ref()
            .ok_or(ExecutionError::Configuration)?
            .verify_receipt(receipt)
    }
    async fn ready(&self) -> bool {
        self.probe_ready().await
    }
}

pub struct ExecutionCoordinator<M, R, A, P, T, E, L>
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    materializer: Arc<M>,
    registry: Arc<R>,
    approvals: Arc<A>,
    pep: Arc<P>,
    tool_proxy: Arc<T>,
    evidence: Arc<E>,
    ledger: Arc<L>,
    source_service: String,
}

impl<M, R, A, P, T, E, L> ExecutionCoordinator<M, R, A, P, T, E, L>
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        materializer: Arc<M>,
        registry: Arc<R>,
        approvals: Arc<A>,
        pep: Arc<P>,
        tool_proxy: Arc<T>,
        evidence: Arc<E>,
        ledger: Arc<L>,
        source_service: String,
    ) -> Result<Self, ExecutionError> {
        if source_service.is_empty()
            || source_service.len() > 256
            || !(source_service.starts_with("DNS:") || source_service.starts_with("URI:"))
            || source_service.bytes().any(|byte| byte <= 32 || byte > 126)
        {
            return Err(ExecutionError::Configuration);
        }
        Ok(Self {
            materializer,
            registry,
            approvals,
            pep,
            tool_proxy,
            evidence,
            ledger,
            source_service,
        })
    }

    pub async fn execute(
        &self,
        request: ExecutionRequest,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        validate_request(&request)?;
        let materialized = self.materializer.materialize(&request).await?;
        let tenant = TenantId::parse(request.tenant_id.clone())
            .map_err(|_| ExecutionError::RequestInvalid)?;
        let tool = self
            .registry
            .resolve(&tenant, &materialized.action.tool)
            .await?;
        validate_schema_instance(
            &tool.input_schema,
            &Value::Object(materialized.action.payload.data.clone()),
            false,
        )?;
        let preapproval_request = PreApprovalRequest {
            schema_version: "agenttrust.pre-approval-request.v1".into(),
            action: materialized.action.clone(),
            action_hash: materialized.action_hash.clone(),
            tool: tool.clone(),
            idempotency_key: request.idempotency_key.clone(),
            requested_at: Utc::now(),
        };
        let preapproval = self.pep.preapprove(&preapproval_request).await?;
        validate_preapproval(&preapproval, &preapproval_request, &materialized, &tool)?;
        let signed_preapproval = &preapproval.signed_outcome;
        let (approval, approval_consumption_ref, approval_receipt_digest) =
            if !signed_preapproval.approval_required {
                (None, None, None)
            } else {
                let plan_hash = materialized
                    .action
                    .extensions
                    .get("x-plan-hash")
                    .and_then(Value::as_str)
                    .filter(|value| is_digest(value))
                    .ok_or(ExecutionError::AuthorizationDenied)?
                    .to_owned();
                let parameter_hash = hex_digest(
                    &serde_jcs::to_vec(materialized.action.arguments()).map_err(materialization)?,
                );
                let approval_request = ApprovalGrantRequest {
                    schema_version: APPROVAL_CONSUMPTION_REQUEST_SCHEMA_VERSION.into(),
                    tenant_id: tenant.0.clone(),
                    task_id: materialized.action.task_id.0.clone(),
                    step_id: materialized.action.step_id.0.clone(),
                    action_hash: materialized.action_hash.0.clone(),
                    plan_hash,
                    parameter_hash,
                    resource: materialized.action.resource.locator.clone(),
                    resource_version: materialized
                        .action
                        .current_state_version
                        .clone()
                        .ok_or(ExecutionError::AuthorizationDenied)?,
                    policy_version: signed_preapproval.decision.policy_version.0.clone(),
                    environment: materialized.action.environment.deployment.clone(),
                    maximum_risk: std::cmp::max(
                        std::cmp::max(materialized.action.risk.declared_risk, tool.risk_level),
                        signed_preapproval.decision.risk_summary,
                    ),
                };
                let receipt = self.approvals.consume(&approval_request).await?;
                let grant = self.approvals.verify_receipt(&approval_request, &receipt)?;
                let receipt_digest = canonical_request_digest(&receipt)?;
                (
                    Some(grant),
                    Some(receipt.consumption_ref),
                    Some(receipt_digest),
                )
            };
        let compensation_plan = preapproval.compensation_plan.clone();
        let compensation_valid = compensation_plan.as_ref().is_some_and(|plan| {
            plan.forward_action_hash == materialized.action_hash && !plan.steps.is_empty()
        });
        if (tool.effect_class == EffectClass::Compensatable && !compensation_valid)
            || (tool.effect_class != EffectClass::Compensatable && compensation_plan.is_some())
        {
            return Err(ExecutionError::AuthorizationDenied);
        }
        let intent = ExecutionIntent {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId::parse(request.task_id.clone())
                .map_err(|_| ExecutionError::RequestInvalid)?,
            step_id: materialized.action.step_id.clone(),
            action_hash: materialized.action_hash.clone(),
            idempotency_key: IdempotencyKey(request.idempotency_key.clone()),
            tool: materialized.action.tool.clone(),
            effect_class: tool.effect_class,
            resource_version: materialized
                .action
                .current_state_version
                .clone()
                .map(ResourceVersion),
            canonical_arguments_hash: hex_digest(
                &serde_jcs::to_vec(materialized.action.arguments()).map_err(materialization)?,
            ),
            compensation_plan,
            requested_at: materialized.action.requested_at,
        };
        let reservation = self.ledger.reserve(intent).await?;
        let fence_digest = fence_digest(&reservation.fence)?;
        if reservation.existing {
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            // RUNNING/UNKNOWN may have performed the side effect; terminal records are immutable.
            // None of them may be automatically replayed.
            if record.status != ExecutionStatus::Prepared {
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
        }
        let authorization_time = Utc::now();
        if authorization_time < signed_preapproval.issued_at
            || authorization_time >= signed_preapproval.expires_at
            || signed_preapproval
                .fact_snapshot
                .validate_integrity(authorization_time)
                .is_err()
            || signed_preapproval.fact_snapshot.require_verified().is_err()
        {
            self.ledger
                .mark_failed(
                    &reservation.fence,
                    "EXECUTION_AUTHORITATIVE_FACTS_EXPIRED".into(),
                )
                .await?;
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            return self
                .outcome_from_record(&request, &record, &fence_digest)
                .await;
        }
        let fact_snapshot = &signed_preapproval.fact_snapshot;
        let policy_input = to_policy_input(
            &materialized.action,
            &tool.policy_snapshot(),
            &RuntimeContext {
                identity_subject: fact_snapshot
                    .identity_subject
                    .clone()
                    .ok_or(ExecutionError::AuthorizationDenied)?,
                prior_approvals: approval
                    .iter()
                    .map(|grant| grant.approval_id.0.clone())
                    .collect(),
                budget_remaining_microunits: fact_snapshot
                    .budget_remaining_microunits
                    .ok_or(ExecutionError::AuthorizationDenied)?,
            },
            &TrajectoryRiskSnapshot {
                version: fact_snapshot
                    .trajectory_risk_version
                    .clone()
                    .ok_or(ExecutionError::AuthorizationDenied)?,
                accumulated_resources: fact_snapshot
                    .accumulated_resources
                    .clone()
                    .ok_or(ExecutionError::AuthorizationDenied)?,
                anomaly_score_millionths: fact_snapshot
                    .anomaly_score_millionths
                    .ok_or(ExecutionError::AuthorizationDenied)?,
            },
        )?;
        // Bind the final authorization to the durable RESERVED ledger event.  This
        // fact is captured before the PEP call and is subsequently carried in the
        // signed authorization all the way to the tool target.  A later RUNNING
        // transition must not silently replace the fact authorized by the PEP.
        let ledger_event = self
            .ledger
            .status_event_fact(&tenant, &reservation.execution_id)
            .await?;
        let final_request = FinalAuthorizationRequest {
            schema_version: "agenttrust.final-authorization-request.v1".into(),
            stage: EnforcementStage::PreExecution,
            action: materialized.action.clone(),
            action_hash: materialized.action_hash.clone(),
            tool: tool.clone(),
            policy_input,
            preapproval: signed_preapproval.clone(),
            approval: approval.clone(),
            approval_consumption_ref: approval_consumption_ref.clone(),
            approval_receipt_digest: approval_receipt_digest.clone(),
            ledger_execution_id: reservation.execution_id.clone(),
            ledger_event_id: ledger_event.event_id.clone(),
            ledger_event_digest: ledger_event.event_digest.clone(),
            fence_digest: fence_digest.clone(),
            idempotency_key: request.idempotency_key.clone(),
            requested_at: Utc::now(),
        };
        let authorized = match self.pep.authorize(&final_request).await {
            Ok(value) => value,
            Err(ExecutionError::AuthorizationDenied) => {
                self.ledger
                    .mark_failed(&reservation.fence, "EXECUTION_AUTHORIZATION_DENIED".into())
                    .await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
            Err(ExecutionError::DependencyResponseInvalid) => {
                self.ledger
                    .mark_failed(
                        &reservation.fence,
                        "EXECUTION_AUTHORIZATION_RESPONSE_INVALID".into(),
                    )
                    .await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
            Err(error) => return Err(error),
        };
        if validate_authorization(&authorized, &final_request, &materialized, &tool).is_err() {
            self.ledger
                .mark_failed(
                    &reservation.fence,
                    "EXECUTION_AUTHORIZATION_RESPONSE_INVALID".into(),
                )
                .await?;
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            return self
                .outcome_from_record(&request, &record, &fence_digest)
                .await;
        }
        let authorization_id = authorized.authorization.authorization_id.clone();
        let authorization_digest = canonical_request_digest(&authorized.authorization)?;
        let expected_credential_id = authorized.authorization.workload_credential_id.clone();
        let expected_credential_audience = authorized
            .authorization
            .workload_credential_audience
            .clone();
        let expected_credential_revocation_epoch = authorized
            .authorization
            .workload_credential_revocation_epoch;
        let expected_credential_claims_digest = authorized
            .authorization
            .workload_credential_claims_digest
            .clone();
        let expected_credential_consumption_key = format!("credential-consume:{authorization_id}");
        let authorized_resource_version = ResourceVersion(
            materialized
                .action
                .current_state_version
                .clone()
                .or_else(|| {
                    materialized
                        .action
                        .resource
                        .version
                        .as_ref()
                        .map(|version| version.0.clone())
                })
                .unwrap_or_else(|| "unversioned-read".into()),
        );
        if let Err(error) = self.ledger.mark_started(&reservation.fence, None).await {
            if matches!(
                error,
                LedgerError::StaleFence | LedgerError::TransitionInvalid
            ) {
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
            return Err(error.into());
        }
        let result = match self
            .tool_proxy
            .execute(
                AuthorizedToolRequest {
                    authorization: authorized.authorization,
                    tool: authorized.tool,
                    tenant_id: tenant.clone(),
                    ledger_execution_id: reservation.execution_id.clone(),
                    ledger_event_id: ledger_event.event_id,
                    ledger_event_digest: ledger_event.event_digest,
                    fence_digest: fence_digest.clone(),
                    idempotency_key: IdempotencyKey(request.idempotency_key.clone()),
                    workload_credential: authorized.workload_credential,
                    credential_binding_receipt: authorized.credential_binding_receipt,
                    operation: materialized.action.intent.operation.clone(),
                    resource: materialized.action.resource.locator.clone(),
                    resource_version: authorized_resource_version,
                    target_profile: authorized.target_profile,
                    environment: materialized.action.environment.deployment.clone(),
                    arguments: materialized.action.payload.data.clone(),
                    trace_id: materialized.trace_id.clone(),
                },
                &request.idempotency_key,
                &fence_digest,
            )
            .await
        {
            Ok(result) => result,
            Err(ExecutionError::AuthorizationDenied) => {
                self.ledger
                    .mark_failed(&reservation.fence, "EXECUTION_TOOL_REJECTED".into())
                    .await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
            Err(_) => {
                self.ledger
                    .mark_unknown(&reservation.fence, "EXECUTION_OUTCOME_UNKNOWN".into())
                    .await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
        };
        if result.schema_version != PROXY_SCHEMA_VERSION
            || !is_digest(&result.result_hash)
            || hex_digest(&serde_jcs::to_vec(&result.value).map_err(materialization)?)
                != result.result_hash
            || result.credential_consumption_receipt.schema_version
                != WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION
            || result.credential_consumption_receipt.key_usage
                != WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE
            || result.credential_consumption_receipt.idempotency_key.0
                != expected_credential_consumption_key
            || result.credential_consumption_receipt.credential_id != expected_credential_id
            || result.credential_consumption_receipt.tenant_id != tenant
            || result.credential_consumption_receipt.action_hash != materialized.action_hash
            || result.credential_consumption_receipt.audience != expected_credential_audience
            || result.credential_consumption_receipt.revocation_epoch
                != expected_credential_revocation_epoch
            || result.credential_consumption_receipt.claims_digest
                != expected_credential_claims_digest
            || Uuid::parse_str(&result.credential_consumption_receipt.consumption_id).is_err()
            || !is_digest(&result.credential_consumption_receipt.scope_digest)
            || result.credential_consumption_receipt.remaining_uses != 0
            || result.credential_consumption_receipt.issuer.is_empty()
            || result.credential_consumption_receipt.key_id.is_empty()
            || result.credential_consumption_receipt.signature.is_empty()
        {
            self.ledger
                .mark_unknown(&reservation.fence, "EXECUTION_TOOL_RESULT_INVALID".into())
                .await?;
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            return self
                .outcome_from_record(&request, &record, &fence_digest)
                .await;
        }
        let result_digest = result.result_hash.clone();
        let evidence_request = ExecutionEvidenceRequest {
            schema_version: EXECUTION_EVIDENCE_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: materialized.action.task_id.clone(),
            step_id: materialized.action.step_id.clone(),
            execution_id: reservation.execution_id.clone(),
            fence_digest: fence_digest.clone(),
            action_hash: materialized.action_hash.clone(),
            authorization_id,
            authorization_digest,
            idempotency_key: IdempotencyKey(request.idempotency_key.clone()),
            result: result.clone(),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                task_id: materialized.action.task_id.clone(),
                event_type: EvidenceEventType::ToolExecuted,
                actor_subject: materialized.owner_subject,
                source_service: self.source_service.clone(),
                trace_id: materialized.trace_id,
                span_id: reservation.execution_id.0.clone(),
                payload_hash: result_digest.clone(),
                safe_summary: format!("tool execution {}", reservation.execution_id.0),
                artifact_refs: result
                    .artifact_ref
                    .iter()
                    .cloned()
                    .map(ArtifactRef)
                    .collect(),
                occurred_at: Utc::now(),
            },
        };
        let evidence = self.evidence.append(&evidence_request).await;
        let evidence = match evidence {
            Ok(value) => value,
            Err(_) => {
                self.ledger
                    .mark_unknown(&reservation.fence, "EXECUTION_EVIDENCE_UNKNOWN".into())
                    .await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self
                    .outcome_from_record(&request, &record, &fence_digest)
                    .await;
            }
        };
        if validate_evidence(&evidence, &evidence_request).is_err()
            || self.evidence.verify_receipt(&evidence).is_err()
        {
            self.ledger
                .mark_unknown(&reservation.fence, "EXECUTION_EVIDENCE_INVALID".into())
                .await?;
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            return self
                .outcome_from_record(&request, &record, &fence_digest)
                .await;
        }
        self.ledger
            .mark_succeeded(&reservation.fence, result_digest, evidence.evidence_ref)
            .await?;
        let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
        self.outcome_from_record(&request, &record, &fence_digest)
            .await
    }

    async fn outcome_from_record(
        &self,
        request: &ExecutionRequest,
        record: &ExecutionRecord,
        fence_digest: &str,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        let ledger_ref = self
            .ledger
            .status_event_ref(&record.intent.tenant_id, &record.execution_id)
            .await?;
        outcome_from_record(request, record, fence_digest, ledger_ref)
    }

    pub async fn ready(&self) -> bool {
        tokio::time::timeout(Duration::from_millis(1_800), async {
            let (materializer, registry, approvals, ledger, pep, tool, evidence) = tokio::join!(
                self.materializer.ready(),
                self.registry.ready(),
                self.approvals.ready(),
                self.ledger.ready(),
                self.pep.ready(),
                self.tool_proxy.ready(),
                self.evidence.ready(),
            );
            materializer && registry && approvals && ledger && pep && tool && evidence
        })
        .await
        .unwrap_or(false)
    }
}

pub fn validate_request(request: &ExecutionRequest) -> Result<(), ExecutionError> {
    if request.schema_version != EXECUTION_REQUEST_SCHEMA
        || Uuid::parse_str(&request.tenant_id).is_err()
        || Uuid::parse_str(&request.task_id).is_err()
        || Uuid::parse_str(&request.action_id).is_err()
        || !is_digest(&request.ingress_digest)
        || request.idempotency_key.is_empty()
        || request.idempotency_key.len() > 128
        || !request
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        || request.action_materialization.schema_version
            != "agenttrust.action-materialization-ref.v1"
        || request.action_materialization.tenant_id != request.tenant_id
        || request.action_materialization.action_id != request.action_id
        || !is_digest(&request.action_materialization.payload_hash)
        || request.action_materialization.store != "ORCHESTRATOR_INGRESS_POSTGRESQL"
        || request.action_materialization.uri
            != format!(
                "orchestrator-ingress://{}/{}",
                request.tenant_id, request.action_id
            )
    {
        return Err(ExecutionError::RequestInvalid);
    }
    Ok(())
}

fn validate_preapproval(
    value: &PreApprovalOutcome,
    request: &PreApprovalRequest,
    materialized: &MaterializedAction,
    tool: &ResolvedToolSnapshot,
) -> Result<(), ExecutionError> {
    let signed = &value.signed_outcome;
    if matches!(
        signed.decision.decision,
        Decision::Deny | Decision::Pause | Decision::Kill
    ) {
        return Err(ExecutionError::AuthorizationDenied);
    }
    let approval_required = tool.approval_profile != "none"
        || signed.decision.decision == Decision::RequireApproval
        || signed
            .decision
            .obligations
            .iter()
            .any(|obligation| matches!(obligation, Obligation::RequireApproval { .. }));
    signed
        .fact_snapshot
        .require_verified()
        .map_err(|_| ExecutionError::AuthorizationDenied)?;
    let facts = &signed.fact_snapshot;
    let expected_resource_version = materialized
        .action
        .current_state_version
        .as_deref()
        .or_else(|| {
            materialized
                .action
                .resource
                .version
                .as_ref()
                .map(|value| value.0.as_str())
        })
        .unwrap_or("unversioned-read");
    let preapproval_input = to_policy_input(
        &materialized.action,
        &tool.policy_snapshot(),
        &RuntimeContext {
            identity_subject: facts
                .identity_subject
                .clone()
                .ok_or(ExecutionError::AuthorizationDenied)?,
            prior_approvals: vec![],
            budget_remaining_microunits: facts
                .budget_remaining_microunits
                .ok_or(ExecutionError::AuthorizationDenied)?,
        },
        &TrajectoryRiskSnapshot {
            version: facts
                .trajectory_risk_version
                .clone()
                .ok_or(ExecutionError::AuthorizationDenied)?,
            accumulated_resources: facts
                .accumulated_resources
                .clone()
                .ok_or(ExecutionError::AuthorizationDenied)?,
            anomaly_score_millionths: facts
                .anomaly_score_millionths
                .ok_or(ExecutionError::AuthorizationDenied)?,
        },
    )?;
    let expected_input_hash = policy_input_hash(&preapproval_input)
        .map_err(|_| ExecutionError::DependencyResponseInvalid)?;
    let expected_plan_digest = value
        .compensation_plan
        .as_ref()
        .map(canonical_request_digest)
        .transpose()?;
    let now = Utc::now();
    if value.schema_version != agent_trust_contracts::PEP_PRE_APPROVAL_ENVELOPE_SCHEMA_VERSION
        || request.schema_version != "agenttrust.pre-approval-request.v1"
        || signed.stage != EnforcementStage::PreApproval
        || signed.tenant_id != materialized.action.environment.tenant_id
        || signed.task_id != materialized.action.task_id
        || signed.step_id != materialized.action.step_id
        || signed.action_hash != request.action_hash
        || signed.tool_id != tool.tool_id
        || signed.tool_version != tool.tool_version
        || signed.tool_snapshot_hash != tool.snapshot_hash
        || signed.idempotency_key.0 != request.idempotency_key
        || signed.request_digest != canonical_request_digest(request)?
        || signed.fact_snapshot_digest != facts.snapshot_digest
        || signed.execution_plan_digest != expected_plan_digest
        || signed.approval_required != approval_required
        || signed.decision.schema_version.0 != POLICY_SCHEMA_VERSION
        || signed.schema_version.0 != agent_trust_contracts::PRE_APPROVAL_OUTCOME_SCHEMA_VERSION
        || signed.key_usage != PEP_PRE_APPROVAL_KEY_USAGE
        || signed.signature.is_empty()
        || signed.decision.input_hash != expected_input_hash
        || signed.decision.decision != Decision::Allow
            && signed.decision.decision != Decision::RequireApproval
        || signed.decision.decision_id.is_empty()
        || signed.decision.policy_version.0.is_empty()
        || !is_digest(&signed.decision.policy_bundle_hash)
        || facts.identity_subject.as_deref() != Some(&materialized.owner_subject)
        || facts
            .resource_state_version
            .as_ref()
            .map(|value| value.0.as_str())
            != Some(expected_resource_version)
        || materialized
            .action
            .environment
            .deployment
            .eq_ignore_ascii_case("production")
            && facts.identity_uses_dev_verifier != Some(false)
        || now < signed.decision.evaluated_at
        || now >= signed.decision.expires_at
    {
        return Err(ExecutionError::DependencyResponseInvalid);
    }
    Ok(())
}

fn validate_authorization(
    value: &PreExecutionAuthorization,
    request: &FinalAuthorizationRequest,
    materialized: &MaterializedAction,
    tool: &ResolvedToolSnapshot,
) -> Result<(), ExecutionError> {
    let expected_resource_version = materialized
        .action
        .current_state_version
        .as_deref()
        .or_else(|| {
            materialized
                .action
                .resource
                .version
                .as_ref()
                .map(|version| version.0.as_str())
        })
        .unwrap_or("unversioned-read");
    let expected_approval_ids = request
        .approval
        .iter()
        .map(|grant| grant.approval_id.clone())
        .collect::<Vec<_>>();
    let expected_policy_input_hash = policy_input_hash(&request.policy_input)
        .map_err(|_| ExecutionError::AuthorizationDenied)?;
    let authorization = &value.authorization;
    let credential = &value.credential_binding_receipt;
    let credential_claims = &credential.claims;
    if value.schema_version != "agenttrust.pre-execution-authorization.v1"
        || authorization.schema_version.0 != EXECUTION_AUTHORIZATION_SCHEMA_VERSION
        || authorization.key_usage != PEP_EXECUTION_AUTHORIZATION_KEY_USAGE
        || authorization.tenant_id != materialized.action.environment.tenant_id
        || authorization.task_id != materialized.action.task_id
        || authorization.step_id != materialized.action.step_id
        || authorization.agent_instance_id != materialized.action.agent.agent_instance_id
        || authorization.action_hash != materialized.action_hash
        || authorization.tool_id != tool.tool_id
        || authorization.tool_version != tool.tool_version
        || authorization.tool_snapshot_hash != tool.snapshot_hash
        || authorization.implementation_digest != tool.implementation.digest
        || authorization.executor_profile != tool.executor_profile
        || authorization.operation != materialized.action.intent.operation
        || authorization.resource != materialized.action.resource.locator
        || authorization.canonical_arguments_hash
            != hex_digest(
                &serde_jcs::to_vec(materialized.action.arguments()).map_err(materialization)?,
            )
        || authorization.target_profile != value.target_profile
        || authorization.environment != materialized.action.environment.deployment
        || authorization.idempotency_key.0 != request.idempotency_key
        || authorization.ledger_execution_id != request.ledger_execution_id
        || authorization.ledger_event_id != request.ledger_event_id
        || authorization.ledger_event_digest != request.ledger_event_digest
        || authorization.fence_digest != request.fence_digest
        || authorization.policy_version != request.preapproval.decision.policy_version
        || authorization.policy_bundle_hash != request.preapproval.decision.policy_bundle_hash
        || authorization.policy_input_hash != expected_policy_input_hash
        || authorization.preapproval_digest != canonical_request_digest(&request.preapproval)?
        || authorization.approval_ids != expected_approval_ids
        || authorization.approval_consumption_ref != request.approval_consumption_ref
        || authorization.approval_receipt_digest != request.approval_receipt_digest
        || authorization.resource_version.0 != expected_resource_version
        || authorization.sandbox_profile.is_empty()
        || authorization.network_profile != tool.network_profile_ref
        || authorization.credential_profile != tool.credential_profile
        || !is_digest(&authorization.workload_credential_claims_digest)
        || authorization.workload_credential_audience != "tool-proxy"
        || credential.schema_version != WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION
        || credential.key_usage != WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE
        || credential.signature.is_empty()
        || credential.credential_handle_sha256 != hex_digest(value.workload_credential.0.as_bytes())
        || credential.claims_digest != authorization.workload_credential_claims_digest
        || credential_claims.credential_id != authorization.workload_credential_id
        || credential_claims.tenant_id != authorization.tenant_id
        || credential_claims.agent_instance_id != authorization.agent_instance_id
        || credential_claims.task_id != authorization.task_id
        || credential_claims.step_id != authorization.step_id
        || credential_claims.action_hash != authorization.action_hash
        || credential_claims.policy_decision_id != authorization.policy_decision_id
        || credential_claims.tool_id != authorization.tool_id
        || credential_claims.credential_profile != authorization.credential_profile
        || credential_claims.operation != authorization.operation
        || credential_claims.resource != authorization.resource
        || credential_claims.target_profile != authorization.target_profile
        || credential_claims.audience != authorization.workload_credential_audience
        || credential_claims.revocation_epoch != authorization.workload_credential_revocation_epoch
        || credential_claims.expires_at < authorization.expires_at
        || credential_claims.max_uses != 1
        || authorization.max_execution_ms == 0
        || authorization.max_execution_ms > tool.limits.timeout_ms
        || authorization.max_result_bytes == 0
        || authorization.max_result_bytes > tool.limits.max_result_bytes
        || !authorization.single_use
        || value.tool != *tool
        || value.approval != request.approval
        || value.workload_credential.0.is_empty()
        || value.target_profile.is_empty()
    {
        return Err(ExecutionError::AuthorizationDenied);
    }
    Ok(())
}

fn validate_evidence(
    value: &ExecutionEvidenceReceipt,
    request: &ExecutionEvidenceRequest,
) -> Result<(), ExecutionError> {
    if value.schema_version != EXECUTION_EVIDENCE_RECEIPT_SCHEMA_VERSION
        || value.key_usage != EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE
        || value.tenant_id != request.tenant_id
        || value.task_id != request.task_id
        || value.step_id != request.step_id
        || value.execution_id != request.execution_id
        || value.action_hash != request.action_hash
        || value.authorization_id != request.authorization_id
        || value.authorization_digest != request.authorization_digest
        || value.fence_digest != request.fence_digest
        || value.idempotency_key != request.idempotency_key
        || value.request_digest != canonical_request_digest(request)?
        || value.result_hash != request.result.result_hash
        || value.chain_head != value.event.event_hash
        || value.evidence_ref != value.expected_evidence_ref()
        || value.evidence_ref.len() > 2_048
        || value.event.schema_version != EVIDENCE_SCHEMA_VERSION
        || Uuid::parse_str(&value.event.event_id).is_err()
        || value.event.sequence == 0
        || !is_digest(&value.event.previous_hash)
        || value.event.draft != request.event
        || !is_digest(&value.event.event_hash)
        || value.event.signature.is_empty()
    {
        return Err(ExecutionError::EvidenceInvalid);
    }
    Ok(())
}

fn outcome_from_record(
    request: &ExecutionRequest,
    record: &ExecutionRecord,
    fence_digest: &str,
    ledger_ref: String,
) -> Result<ExecutionOutcome, ExecutionError> {
    // Every status exposes the exact durable outbox event ID. Signed evidence is additional.
    let mut evidence_refs = vec![ledger_ref];
    if let Some(reference) = &record.evidence_ref
        && !evidence_refs.contains(reference)
    {
        evidence_refs.push(reference.clone());
    }
    let material = serde_json::json!({
        "execution_id": record.execution_id.0,
        "status": record.status,
        "result_ref": record.result_ref,
        "evidence_refs": evidence_refs,
        "last_error_code": record.last_error_code,
        "fence_digest": fence_digest,
    });
    Ok(ExecutionOutcome {
        schema_version: EXECUTION_OUTCOME_SCHEMA.into(),
        tenant_id: request.tenant_id.clone(),
        task_id: request.task_id.clone(),
        action_id: request.action_id.clone(),
        ingress_digest: request.ingress_digest.clone(),
        idempotency_key: request.idempotency_key.clone(),
        ledger_execution_id: record.execution_id.0.clone(),
        fence_digest: fence_digest.into(),
        status: record.status,
        outcome_digest: hex_digest(&serde_jcs::to_vec(&material).map_err(materialization)?),
        evidence_refs,
        action_materialization: request.action_materialization.clone(),
    })
}

fn fence_digest(fence: &ExecutionFence) -> Result<String, ExecutionError> {
    Ok(hex_digest(
        &serde_jcs::to_vec(fence).map_err(materialization)?,
    ))
}

pub fn python_compact_sorted_json_bytes(value: &Value) -> Result<Vec<u8>, ExecutionError> {
    // Python orchestrator uses sort_keys=True,separators=(",",":"),ensure_ascii=False.
    // PostgreSQL jsonb discards object order, so all maps must be sorted recursively here.
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).map_err(materialization)
}

fn json_content_type(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("application/json")
            })
        })
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical_request_digest<T: Serialize>(value: &T) -> Result<String, ExecutionError> {
    Ok(hex_digest(
        &serde_jcs::to_vec(value).map_err(materialization)?,
    ))
}
fn dependency<T>(_: T) -> ExecutionError {
    ExecutionError::DependencyUnavailable
}
fn materialization<T>(_: T) -> ExecutionError {
    ExecutionError::MaterializationInvalid
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("EXECUTION_CONFIGURATION_INVALID")]
    Configuration,
    #[error("EXECUTION_REQUEST_INVALID")]
    RequestInvalid,
    #[error("EXECUTION_MATERIALIZATION_INVALID")]
    MaterializationInvalid,
    #[error("EXECUTION_AUTHORIZATION_DENIED")]
    AuthorizationDenied,
    #[error("EXECUTION_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("EXECUTION_DEPENDENCY_RESPONSE_INVALID")]
    DependencyResponseInvalid,
    #[error("EXECUTION_EVIDENCE_INVALID")]
    EvidenceInvalid,
    #[error(transparent)]
    ActionIr(#[from] agent_trust_action_ir::ActionIrError),
    #[error(transparent)]
    Registry(#[from] agent_trust_registry::RegistryError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_language_digest_preserves_unicode_and_sorts_recursively() {
        let value = serde_json::json!({"中文":"值","a":{"z":2,"b":1}});
        assert_eq!(
            python_compact_sorted_json_bytes(&value)
                .unwrap_or_else(|error| panic!("canonical json: {error}")),
            "{\"a\":{\"b\":1,\"z\":2},\"中文\":\"值\"}".as_bytes()
        );
    }

    #[test]
    fn request_materialization_reference_is_exact() {
        let tenant = Uuid::new_v4().to_string();
        let action = Uuid::new_v4().to_string();
        let request = ExecutionRequest {
            schema_version: EXECUTION_REQUEST_SCHEMA.into(),
            tenant_id: tenant.clone(),
            task_id: Uuid::new_v4().to_string(),
            action_id: action.clone(),
            ingress_digest: "a".repeat(64),
            idempotency_key: "execute:valid".into(),
            action_materialization: ActionMaterializationRef {
                schema_version: "agenttrust.action-materialization-ref.v1".into(),
                tenant_id: tenant.clone(),
                action_id: action.clone(),
                payload_hash: "b".repeat(64),
                store: "ORCHESTRATOR_INGRESS_POSTGRESQL".into(),
                uri: format!("orchestrator-ingress://{tenant}/{action}"),
            },
        };
        assert!(validate_request(&request).is_ok());
        let mut changed = request;
        changed.action_materialization.uri.push_str("/shadow");
        assert!(validate_request(&changed).is_err());
    }
}
