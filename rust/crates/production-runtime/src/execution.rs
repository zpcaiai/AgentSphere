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
    ActionHash, ArtifactRef, Decision, EffectClass, ExecutionAuthorization, ExecutionStatus,
    IdempotencyKey, MinimalApprovalGrant, Obligation, PolicyDecision, ResourceVersion, TaskId,
    TenantId, ToolRef,
};
use agent_trust_enterprise_approval::{APPROVAL_SCHEMA_VERSION, EnterpriseApprovalGrant};
use agent_trust_evidence_evaluator::{
    EVIDENCE_SCHEMA_VERSION, EvidenceError, EvidenceEventDraft, EvidenceEventType,
    SignedEvidenceEvent,
};
use agent_trust_gateway::{GATEWAY_SCHEMA_VERSION, InboundEnvelope, IngressProtocol};
use agent_trust_identity::CredentialHandle;
use agent_trust_policy_pep::{EnforcementStage, POLICY_SCHEMA_VERSION, policy_input_hash};
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
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
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

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreExecutionRequest {
    pub schema_version: &'static str,
    pub stage: EnforcementStage,
    pub action: CanonicalAction,
    pub action_hash: ActionHash,
    pub tool: ResolvedToolSnapshot,
    pub policy_input: agent_trust_action_ir::PolicyInput,
    pub approval: Option<MinimalApprovalGrant>,
    pub idempotency_key: String,
    pub identity_uses_dev_verifier: bool,
    pub resource_state_fresh: bool,
    pub requested_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreExecutionAuthorization {
    pub schema_version: String,
    pub authorization: ExecutionAuthorization,
    pub tool: ResolvedToolSnapshot,
    pub workload_credential: CredentialHandle,
    pub target_profile: String,
    #[serde(default)]
    pub approval: Option<MinimalApprovalGrant>,
    #[serde(default)]
    pub compensation_plan: Option<CompensationPlan>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreApprovalOutcome {
    pub schema_version: String,
    pub action_hash: ActionHash,
    pub tool_snapshot_hash: String,
    pub approval_required: bool,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantRequest {
    pub schema_version: &'static str,
    pub tenant_id: String,
    pub task_id: String,
    pub step_id: String,
    pub action_hash: String,
    pub plan_hash: String,
    pub parameter_hash: String,
    pub resource: String,
    pub resource_version: String,
    pub policy_version: String,
    pub environment: String,
    pub maximum_risk: agent_trust_contracts::RiskLevel,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantReceipt {
    pub schema_version: String,
    pub grant: EnterpriseApprovalGrant,
    pub consumed_at: chrono::DateTime<Utc>,
    pub remaining_uses: u32,
    pub consumption_ref: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidenceRequest {
    pub schema_version: &'static str,
    pub execution_id: String,
    pub fence_digest: String,
    pub action_hash: String,
    pub result: SanitizedToolResult,
    pub event: EvidenceEventDraft,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidenceReceipt {
    pub schema_version: String,
    pub evidence_ref: String,
    pub event: SignedEvidenceEvent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[async_trait]
pub trait CanonicalActionMaterializer: Send + Sync {
    async fn materialize(&self, request: &ExecutionRequest)
        -> Result<MaterializedAction, ExecutionError>;
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
        request: &PreExecutionRequest,
    ) -> Result<PreApprovalOutcome, ExecutionError>;
    async fn authorize(
        &self,
        request: &PreExecutionRequest,
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
        let tenant = Uuid::parse_str(&request.tenant_id).map_err(|_| ExecutionError::RequestInvalid)?;
        let action = Uuid::parse_str(&request.action_id).map_err(|_| ExecutionError::RequestInvalid)?;
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

        let envelope_object = envelope.as_object().ok_or(ExecutionError::MaterializationInvalid)?;
        let typed_envelope: InboundEnvelope = serde_json::from_value(envelope.clone()).map_err(materialization)?;
        let expected_envelope_keys = [
            "request_id", "trace_context", "identity_context", "tenant_context", "protocol",
            "content_type", "schema_version", "idempotency_key", "received_at", "payload", "payload_hash",
        ].into_iter().collect::<std::collections::BTreeSet<_>>();
        if envelope_object.keys().map(String::as_str).collect::<std::collections::BTreeSet<_>>() != expected_envelope_keys
            || row_tenant != tenant
            || row_action != action
            || row_task.to_string() != request.task_id
            || payload_hash != request.action_materialization.payload_hash
            || typed_envelope.schema_version != GATEWAY_SCHEMA_VERSION
            || typed_envelope.protocol != IngressProtocol::Http
            || typed_envelope.content_type.split(';').next().map(str::trim) != Some("application/json")
            || typed_envelope.idempotency_key.as_deref().is_none_or(str::is_empty)
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
        if payload.len() > ParseLimits::default().max_body_bytes || hex_digest(&payload) != payload_hash {
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
            || !canonical.environment.deployment.eq_ignore_ascii_case("production")
            || canonical.environment.simulation
            || !canonical.agent.deployment_environment.eq_ignore_ascii_case("production")
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
        tokio::time::timeout(Duration::from_millis(400), sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool))
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
        tool.validate_exact().map_err(|_| ExecutionError::AuthorizationDenied)?;
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
            row.try_get("manifest").map_err(|_| ExecutionError::DependencyResponseInvalid)?,
        )
        .map_err(|_| ExecutionError::DependencyResponseInvalid)?;
        manifest.status = ToolVersionStatus::Active;
        let stored_hash: String = row.try_get("manifest_hash").map_err(|_| ExecutionError::DependencyResponseInvalid)?;
        let stored_schema_hash: String = row.try_get("schema_hash").map_err(|_| ExecutionError::DependencyResponseInvalid)?;
        if canonical_manifest_hash(&manifest)? != stored_hash
            || (!stored_schema_hash.is_empty() && canonical_schema_pair_hash(&manifest)? != stored_schema_hash)
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
        let snapshot = resolved_snapshot_from_active_manifest(
            tenant,
            &manifest,
            compensation_target_active,
        )?;
        if snapshot.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(ExecutionError::DependencyResponseInvalid);
        }
        Ok(snapshot)
    }

    async fn ready(&self) -> bool {
        tokio::time::timeout(Duration::from_millis(400), sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool))
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
}

#[derive(Clone)]
pub struct PepAuthorizationKeyring {
    keys: Arc<BTreeMap<String, (String, VerifyingKey)>>,
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
    algorithm: String,
    public_key_base64: String,
}

#[derive(Clone)]
pub struct ApprovalGrantKeyring {
    keys: Arc<BTreeMap<String, (String, VerifyingKey)>>,
}

impl ApprovalGrantKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ExecutionError> {
        // Approval and PEP key documents intentionally share the same strict wire shape.
        let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
        if raw.is_empty() || raw.len() > 1_048_576 { return Err(ExecutionError::Configuration); }
        let document: PepKeyDocument = serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
        if document.schema_version != "agenttrust.approval-verification-keys.v1" || document.keys.is_empty() {
            return Err(ExecutionError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw_key = STANDARD.decode(entry.public_key_base64).map_err(|_| ExecutionError::Configuration)?;
            let key: [u8; 32] = raw_key.try_into().map_err(|_| ExecutionError::Configuration)?;
            if entry.key_id.is_empty() || entry.issuer.is_empty() || entry.algorithm != "Ed25519"
                || keys.insert(entry.key_id, (entry.issuer, VerifyingKey::from_bytes(&key).map_err(|_| ExecutionError::Configuration)?)).is_some()
            { return Err(ExecutionError::Configuration); }
        }
        Ok(Self { keys: Arc::new(keys) })
    }

    fn verify(&self, grant: &EnterpriseApprovalGrant) -> Result<(), ExecutionError> {
        use ed25519_dalek::{Signature, Verifier};
        let (issuer, key) = self.keys.get(&grant.key_id).ok_or(ExecutionError::AuthorizationDenied)?;
        if issuer != &grant.issuer || grant.schema_version.0 != APPROVAL_SCHEMA_VERSION
            || grant.maximum_uses != 1 || grant.approver_subjects.is_empty()
            || Utc::now() < grant.issued_at || Utc::now() >= grant.expires_at
        { return Err(ExecutionError::AuthorizationDenied); }
        let mut unsigned = grant.clone(); unsigned.signature.clear();
        let raw = URL_SAFE_NO_PAD.decode(&grant.signature).map_err(|_| ExecutionError::AuthorizationDenied)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ExecutionError::AuthorizationDenied)?;
        key.verify(&serde_jcs::to_vec(&unsigned).map_err(|_| ExecutionError::AuthorizationDenied)?, &signature)
            .map_err(|_| ExecutionError::AuthorizationDenied)
    }
}

#[derive(Clone)]
pub struct EvidenceEventKeyring {
    keys: Arc<BTreeMap<String, VerifyingKey>>,
}

impl EvidenceEventKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ExecutionError> {
        let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ExecutionError::Configuration);
        }
        let document: EvidenceKeyDocument = serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
        if document.schema_version != "agenttrust.evidence-verification-keys.v1" || document.keys.is_empty() {
            return Err(ExecutionError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw_key = STANDARD.decode(entry.public_key_base64).map_err(|_| ExecutionError::Configuration)?;
            let key: [u8; 32] = raw_key.try_into().map_err(|_| ExecutionError::Configuration)?;
            if entry.key_id.is_empty() || entry.algorithm != "Ed25519"
                || keys.insert(entry.key_id, VerifyingKey::from_bytes(&key).map_err(|_| ExecutionError::Configuration)?).is_some()
            {
                return Err(ExecutionError::Configuration);
            }
        }
        Ok(Self { keys: Arc::new(keys) })
    }

    fn verify(&self, event: &SignedEvidenceEvent) -> Result<(), ExecutionError> {
        use ed25519_dalek::{Signature, Verifier};
        let key = self.keys.get(&event.key_id).ok_or(ExecutionError::EvidenceInvalid)?;
        let mut unsigned = event.clone();
        unsigned.event_hash.clear();
        unsigned.signature.clear();
        let expected_hash = hex_digest(&serde_jcs::to_vec(&unsigned).map_err(|_| ExecutionError::EvidenceInvalid)?);
        if expected_hash != event.event_hash {
            return Err(ExecutionError::EvidenceInvalid);
        }
        let raw = URL_SAFE_NO_PAD.decode(&event.signature).map_err(|_| ExecutionError::EvidenceInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ExecutionError::EvidenceInvalid)?;
        key.verify(event.event_hash.as_bytes(), &signature).map_err(|_| ExecutionError::EvidenceInvalid)
    }
}

impl PepAuthorizationKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ExecutionError> {
        let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ExecutionError::Configuration);
        }
        let document: PepKeyDocument = serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
        if document.schema_version != "agenttrust.pep-verification-keys.v1" || document.keys.is_empty() {
            return Err(ExecutionError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw_key = STANDARD.decode(entry.public_key_base64).map_err(|_| ExecutionError::Configuration)?;
            let key: [u8; 32] = raw_key.try_into().map_err(|_| ExecutionError::Configuration)?;
            if entry.key_id.is_empty() || entry.issuer.is_empty() || entry.algorithm != "Ed25519"
                || keys.insert(entry.key_id, (entry.issuer, VerifyingKey::from_bytes(&key).map_err(|_| ExecutionError::Configuration)?)).is_some()
            {
                return Err(ExecutionError::Configuration);
            }
        }
        Ok(Self { keys: Arc::new(keys) })
    }

    fn verify(&self, authorization: &ExecutionAuthorization) -> Result<(), ExecutionError> {
        let (issuer, key) = self.keys.get(&authorization.key_id).ok_or(ExecutionError::AuthorizationDenied)?;
        if issuer != &authorization.issuer {
            return Err(ExecutionError::AuthorizationDenied);
        }
        authorization.verify(key, Utc::now()).map_err(|_| ExecutionError::AuthorizationDenied)
    }
}

#[derive(Clone)]
pub struct HttpExecutionPort {
    client: reqwest::Client,
    base_url: url::Url,
    token: Arc<str>,
    readiness_schema: Arc<str>,
    pep_keys: Option<PepAuthorizationKeyring>,
    evidence_keys: Option<EvidenceEventKeyring>,
}

impl HttpExecutionPort {
    pub fn new(
        endpoint: &str,
        token: String,
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
        readiness_schema: String,
        pep_keys: Option<PepAuthorizationKeyring>,
        evidence_keys: Option<EvidenceEventKeyring>,
    ) -> Result<Self, ExecutionError> {
        let base_url = url::Url::parse(endpoint).map_err(|_| ExecutionError::Configuration)?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() || base_url.query().is_some()
            || base_url.fragment().is_some() || base_url.path() != "/" || token.is_empty()
            || readiness_schema.is_empty()
        {
            return Err(ExecutionError::Configuration);
        }
        let ca = std::fs::read(ca_file).map_err(|_| ExecutionError::Configuration)?;
        let mut identity = std::fs::read(certificate_file).map_err(|_| ExecutionError::Configuration)?;
        if !identity.ends_with(b"\n") {
            identity.push(b'\n');
        }
        identity.extend(std::fs::read(private_key_file).map_err(|_| ExecutionError::Configuration)?);
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(20))
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(|_| ExecutionError::Configuration)?)
            .identity(reqwest::Identity::from_pem(&identity).map_err(|_| ExecutionError::Configuration)?)
            .build()
            .map_err(|_| ExecutionError::Configuration)?;
        Ok(Self { client, base_url, token: token.into(), readiness_schema: readiness_schema.into(), pep_keys, evidence_keys })
    }

    async fn post<T: Serialize + ?Sized, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: &str,
        fence_digest: Option<&str>,
    ) -> Result<R, ExecutionError> {
        let url = self.base_url.join(path.trim_start_matches('/')).map_err(|_| ExecutionError::Configuration)?;
        let mut request = self.client.post(url)
            .bearer_auth(self.token.as_ref())
            .header("Accept", "application/json")
            .header("Idempotency-Key", idempotency_key)
            .json(body);
        if let Some(fence) = fence_digest {
            request = request.header("X-AgentTrust-Fence-Digest", fence);
        }
        let mut response = request.send().await.map_err(dependency)?;
        if matches!(response.status(), reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::CONFLICT | reqwest::StatusCode::UNPROCESSABLE_ENTITY) {
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
        let Ok(url) = self.base_url.join("ready") else { return false };
        let Ok(Ok(response)) = tokio::time::timeout(
            Duration::from_millis(600),
            self.client.get(url).bearer_auth(self.token.as_ref()).send(),
        ).await else { return false };
        if !response.status().is_success() || !json_content_type(response.headers()) {
            return false;
        }
        let Ok(bytes) = response.bytes().await else { return false };
        if bytes.is_empty() || bytes.len() > 65_536 {
            return false;
        }
        serde_json::from_slice::<DependencyReadiness>(&bytes)
            .is_ok_and(|value| value.ready && value.schema_version == self.readiness_schema.as_ref())
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
        if receipt.schema_version != "agenttrust.approval-grant-receipt.v1"
            || receipt.remaining_uses != 0
            || receipt.consumption_ref.is_empty()
            || receipt.consumption_ref.len() > 2_048
            || receipt.consumed_at < grant.issued_at
            || receipt.consumed_at >= grant.expires_at
            || receipt.consumed_at > Utc::now() + chrono::Duration::minutes(5)
            || grant.tenant_id.0 != request.tenant_id || grant.task_id.0 != request.task_id
            || grant.step_id.0 != request.step_id || grant.action_hash.0 != request.action_hash
            || grant.plan_hash != request.plan_hash
            || grant.parameter_hash != request.parameter_hash
            || grant.resource != request.resource || grant.resource_version.0 != request.resource_version
            || grant.policy_version.0 != request.policy_version
            || grant.environment != request.environment
            || request.maximum_risk > grant.maximum_risk
        { return Err(ExecutionError::AuthorizationDenied); }
        Ok(grant.to_minimal_grant())
    }
    async fn ready(&self) -> bool { self.http.probe_ready().await }
}

#[async_trait]
impl PreExecutionPepPort for HttpExecutionPort {
    async fn preapprove(
        &self,
        request: &PreExecutionRequest,
    ) -> Result<PreApprovalOutcome, ExecutionError> {
        self.post(
            "/v1/authorize/pre-approval",
            request,
            &request.idempotency_key,
            None,
        )
        .await
    }

    async fn authorize(&self, request: &PreExecutionRequest) -> Result<PreExecutionAuthorization, ExecutionError> {
        let response: PreExecutionAuthorization = self.post("/v1/authorize/execution", request, &request.idempotency_key, None).await?;
        self.pep_keys.as_ref().ok_or(ExecutionError::Configuration)?.verify(&response.authorization)?;
        Ok(response)
    }
    async fn ready(&self) -> bool { self.probe_ready().await }
}

#[async_trait]
impl ProductionToolProxyPort for HttpExecutionPort {
    async fn execute(&self, request: AuthorizedToolRequest, idempotency_key: &str, fence_digest: &str) -> Result<SanitizedToolResult, ExecutionError> {
        self.post("/v1/tools/execute", &request, idempotency_key, Some(fence_digest)).await
    }
    async fn ready(&self) -> bool { self.probe_ready().await }
}

#[async_trait]
impl ExecutionEvidencePort for HttpExecutionPort {
    async fn append(&self, request: &ExecutionEvidenceRequest) -> Result<ExecutionEvidenceReceipt, ExecutionError> {
        self.post("/v1/evidence/executions", request, &request.execution_id, Some(&request.fence_digest)).await
    }
    fn verify_receipt(&self, receipt: &ExecutionEvidenceReceipt) -> Result<(), ExecutionError> {
        self.evidence_keys.as_ref().ok_or(ExecutionError::Configuration)?.verify(&receipt.event)
    }
    async fn ready(&self) -> bool { self.probe_ready().await }
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
    pub fn new(materializer: Arc<M>, registry: Arc<R>, approvals: Arc<A>, pep: Arc<P>, tool_proxy: Arc<T>, evidence: Arc<E>, ledger: Arc<L>) -> Self {
        Self { materializer, registry, approvals, pep, tool_proxy, evidence, ledger }
    }

    pub async fn execute(&self, request: ExecutionRequest) -> Result<ExecutionOutcome, ExecutionError> {
        validate_request(&request)?;
        let materialized = self.materializer.materialize(&request).await?;
        let tenant = TenantId::parse(request.tenant_id.clone()).map_err(|_| ExecutionError::RequestInvalid)?;
        let tool = self.registry.resolve(&tenant, &materialized.action.tool).await?;
        validate_schema_instance(
            &tool.input_schema,
            &Value::Object(materialized.action.payload.data.clone()),
            false,
        )?;
        let build_policy_input = |prior_approvals: Vec<String>| {
            to_policy_input(
                &materialized.action,
                &tool.policy_snapshot(),
                &RuntimeContext {
                    identity_subject: materialized.owner_subject.clone(),
                    prior_approvals,
                    budget_remaining_microunits: 0,
                },
                &TrajectoryRiskSnapshot {
                    version: materialized
                        .action
                        .risk
                        .trajectory_risk_ref
                        .clone()
                        .unwrap_or_else(|| "none".into()),
                    accumulated_resources: vec![materialized.action.resource.locator.clone()],
                    anomaly_score_millionths: 0,
                },
            )
        };
        let preapproval_request = PreExecutionRequest {
            schema_version: "agenttrust.pre-execution-request.v1",
            stage: EnforcementStage::PreApproval,
            action: materialized.action.clone(),
            action_hash: materialized.action_hash.clone(),
            tool: tool.clone(),
            policy_input: build_policy_input(Vec::new())?,
            approval: None,
            idempotency_key: request.idempotency_key.clone(),
            identity_uses_dev_verifier: false,
            resource_state_fresh: true,
            requested_at: Utc::now(),
        };
        let preapproval = self.pep.preapprove(&preapproval_request).await?;
        validate_preapproval(&preapproval, &preapproval_request, &tool)?;
        let approval = if !preapproval.approval_required {
            None
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
                &serde_jcs::to_vec(materialized.action.arguments())
                    .map_err(materialization)?,
            );
            let approval_request = ApprovalGrantRequest {
                schema_version: "agenttrust.approval-grant-request.v1",
                tenant_id: tenant.0.clone(), task_id: materialized.action.task_id.0.clone(),
                step_id: materialized.action.step_id.0.clone(), action_hash: materialized.action_hash.0.clone(),
                plan_hash,
                parameter_hash,
                resource: materialized.action.resource.locator.clone(),
                resource_version: materialized.action.current_state_version.clone().ok_or(ExecutionError::AuthorizationDenied)?,
                policy_version: preapproval.decision.policy_version.0.clone(),
                environment: materialized.action.environment.deployment.clone(),
                maximum_risk: std::cmp::max(
                    std::cmp::max(materialized.action.risk.declared_risk, tool.risk_level),
                    preapproval.decision.risk_summary,
                ),
            };
            let receipt = self.approvals.consume(&approval_request).await?;
            Some(self.approvals.verify_receipt(&approval_request, &receipt)?)
        };
        let policy_input = build_policy_input(
            approval
                .iter()
                .map(|grant| grant.approval_id.0.clone())
                .collect(),
        )?;
        let authorized = self.pep.authorize(&PreExecutionRequest {
            schema_version: "agenttrust.pre-execution-request.v1",
            stage: EnforcementStage::PreExecution,
            action: materialized.action.clone(),
            action_hash: materialized.action_hash.clone(),
            tool: tool.clone(),
            policy_input,
            approval: approval.clone(),
            idempotency_key: request.idempotency_key.clone(),
            identity_uses_dev_verifier: false,
            resource_state_fresh: true,
            requested_at: Utc::now(),
        }).await?;
        validate_authorization(&authorized, &materialized, &tool)?;
        if authorized.approval != approval {
            return Err(ExecutionError::AuthorizationDenied);
        }
        let expected_approval_ids = approval.iter().map(|grant| grant.approval_id.clone()).collect::<Vec<_>>();
        if authorized.authorization.approval_ids != expected_approval_ids {
            return Err(ExecutionError::AuthorizationDenied);
        }
        let compensation_plan = authorized.compensation_plan.clone();
        let compensation_valid = compensation_plan.as_ref().is_some_and(|plan| {
            plan.forward_action_hash == materialized.action_hash && !plan.steps.is_empty()
        });
        if (tool.effect_class == EffectClass::Compensatable && !compensation_valid)
            || (tool.effect_class != EffectClass::Compensatable && compensation_plan.is_some()) {
            return Err(ExecutionError::AuthorizationDenied);
        }
        let intent = ExecutionIntent {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId::parse(request.task_id.clone()).map_err(|_| ExecutionError::RequestInvalid)?,
            step_id: materialized.action.step_id.clone(),
            action_hash: materialized.action_hash.clone(),
            idempotency_key: IdempotencyKey(request.idempotency_key.clone()),
            tool: materialized.action.tool.clone(),
            effect_class: tool.effect_class,
            resource_version: materialized.action.current_state_version.clone().map(ResourceVersion),
            canonical_arguments_hash: hex_digest(&serde_jcs::to_vec(materialized.action.arguments()).map_err(materialization)?),
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
                return self.outcome_from_record(&request, &record, &fence_digest).await;
            }
        }
        if let Err(error) = self.ledger.mark_started(&reservation.fence, None).await {
            if matches!(error, LedgerError::StaleFence | LedgerError::TransitionInvalid) {
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self.outcome_from_record(&request, &record, &fence_digest).await;
            }
            return Err(error.into());
        }
        let result = match self.tool_proxy.execute(AuthorizedToolRequest {
            authorization: authorized.authorization,
            tool: authorized.tool,
            tenant_id: tenant.clone(),
            workload_credential: authorized.workload_credential,
            operation: materialized.action.intent.operation.clone(),
            resource: materialized.action.resource.locator.clone(),
            target_profile: authorized.target_profile,
            arguments: materialized.action.payload.data.clone(),
            trace_id: materialized.trace_id.clone(),
        }, &request.idempotency_key, &fence_digest).await {
            Ok(result) => result,
            Err(ExecutionError::AuthorizationDenied | ExecutionError::DependencyResponseInvalid) => {
                self.ledger.mark_failed(&reservation.fence, "EXECUTION_TOOL_REJECTED".into()).await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self.outcome_from_record(&request, &record, &fence_digest).await;
            }
            Err(_) => {
                self.ledger.mark_unknown(&reservation.fence, "EXECUTION_OUTCOME_UNKNOWN".into()).await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self.outcome_from_record(&request, &record, &fence_digest).await;
            }
        };
        if result.schema_version != PROXY_SCHEMA_VERSION
            || !is_digest(&result.result_hash)
            || hex_digest(&serde_jcs::to_vec(&result.value).map_err(materialization)?) != result.result_hash
        {
            self.ledger.mark_unknown(&reservation.fence, "EXECUTION_TOOL_RESULT_INVALID".into()).await?;
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            return self.outcome_from_record(&request, &record, &fence_digest).await;
        }
        let result_digest = result.result_hash.clone();
        let evidence = self.evidence.append(&ExecutionEvidenceRequest {
            schema_version: "agenttrust.execution-evidence-request.v1",
            execution_id: reservation.execution_id.0.clone(),
            fence_digest: fence_digest.clone(),
            action_hash: materialized.action_hash.0.clone(),
            result: result.clone(),
            event: EvidenceEventDraft {
                tenant_id: tenant.clone(),
                task_id: materialized.action.task_id.clone(),
                event_type: EvidenceEventType::ToolExecuted,
                actor_subject: materialized.owner_subject,
                source_service: "agenttrust-execution-service".into(),
                trace_id: materialized.trace_id,
                span_id: reservation.execution_id.0.clone(),
                payload_hash: result_digest.clone(),
                safe_summary: format!("tool execution {}", reservation.execution_id.0),
                artifact_refs: result.artifact_ref.iter().cloned().map(ArtifactRef).collect(),
                occurred_at: Utc::now(),
            },
        }).await;
        let evidence = match evidence {
            Ok(value) => value,
            Err(_) => {
                self.ledger.mark_unknown(&reservation.fence, "EXECUTION_EVIDENCE_UNKNOWN".into()).await?;
                let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
                return self.outcome_from_record(&request, &record, &fence_digest).await;
            }
        };
        if validate_evidence(&evidence, &tenant, &materialized.action.task_id, &result_digest).is_err()
            || self.evidence.verify_receipt(&evidence).is_err()
        {
            self.ledger.mark_unknown(&reservation.fence, "EXECUTION_EVIDENCE_INVALID".into()).await?;
            let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
            return self.outcome_from_record(&request, &record, &fence_digest).await;
        }
        self.ledger.mark_succeeded(&reservation.fence, result_digest, evidence.evidence_ref).await?;
        let record = self.ledger.get(&tenant, &reservation.execution_id).await?;
        self.outcome_from_record(&request, &record, &fence_digest).await
    }

    async fn outcome_from_record(
        &self,
        request: &ExecutionRequest,
        record: &ExecutionRecord,
        fence_digest: &str,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        let ledger_ref = self.ledger.status_event_ref(&record.intent.tenant_id, &record.execution_id).await?;
        outcome_from_record(request, record, fence_digest, ledger_ref)
    }

    pub async fn ready(&self) -> bool {
        tokio::time::timeout(Duration::from_millis(1_800), async {
            let (materializer, registry, approvals, ledger, pep, tool, evidence) = tokio::join!(
                self.materializer.ready(), self.registry.ready(), self.approvals.ready(),
                self.ledger.ready(), self.pep.ready(), self.tool_proxy.ready(), self.evidence.ready(),
            );
            materializer && registry && approvals && ledger && pep && tool && evidence
        }).await.unwrap_or(false)
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
        || !request.idempotency_key.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        || request.action_materialization.schema_version != "agenttrust.action-materialization-ref.v1"
        || request.action_materialization.tenant_id != request.tenant_id
        || request.action_materialization.action_id != request.action_id
        || !is_digest(&request.action_materialization.payload_hash)
        || request.action_materialization.store != "ORCHESTRATOR_INGRESS_POSTGRESQL"
        || request.action_materialization.uri != format!("orchestrator-ingress://{}/{}", request.tenant_id, request.action_id)
    {
        return Err(ExecutionError::RequestInvalid);
    }
    Ok(())
}

fn validate_preapproval(
    value: &PreApprovalOutcome,
    request: &PreExecutionRequest,
    tool: &ResolvedToolSnapshot,
) -> Result<(), ExecutionError> {
    if matches!(
        value.decision.decision,
        Decision::Deny | Decision::Pause | Decision::Kill
    ) {
        return Err(ExecutionError::AuthorizationDenied);
    }
    let approval_required = tool.approval_profile != "none"
        || value.decision.decision == Decision::RequireApproval
        || value
            .decision
            .obligations
            .iter()
            .any(|obligation| matches!(obligation, Obligation::RequireApproval { .. }));
    let expected_input_hash =
        policy_input_hash(&request.policy_input).map_err(|_| ExecutionError::DependencyResponseInvalid)?;
    let now = Utc::now();
    if request.stage != EnforcementStage::PreApproval
        || request.approval.is_some()
        || value.schema_version != "agenttrust.pre-approval-outcome.v1"
        || value.action_hash != request.action_hash
        || value.tool_snapshot_hash != tool.snapshot_hash
        || value.approval_required != approval_required
        || value.decision.schema_version.0 != POLICY_SCHEMA_VERSION
        || value.decision.input_hash != expected_input_hash
        || value.decision.decision != Decision::Allow
            && value.decision.decision != Decision::RequireApproval
        || value.decision.decision_id.is_empty()
        || value.decision.policy_version.0.is_empty()
        || value.decision.policy_bundle_hash.is_empty()
        || now < value.decision.evaluated_at
        || now >= value.decision.expires_at
    {
        return Err(ExecutionError::DependencyResponseInvalid);
    }
    Ok(())
}

fn validate_authorization(value: &PreExecutionAuthorization, materialized: &MaterializedAction, tool: &ResolvedToolSnapshot) -> Result<(), ExecutionError> {
    let expected_resource_version = materialized.action.current_state_version.as_deref().unwrap_or("unversioned-read");
    if value.schema_version != "agenttrust.pre-execution-authorization.v1"
        || value.authorization.schema_version.0 != POLICY_SCHEMA_VERSION
        || value.authorization.action_hash != materialized.action_hash
        || value.authorization.tool_snapshot_hash != tool.snapshot_hash
        || value.authorization.resource_version.0 != expected_resource_version
        || value.authorization.sandbox_profile.is_empty()
        || value.authorization.network_profile != tool.network_profile_ref
        || value.authorization.credential_profile != tool.credential_profile
        || value.authorization.max_execution_ms == 0
        || value.authorization.max_execution_ms > tool.limits.timeout_ms
        || value.authorization.max_result_bytes == 0
        || value.authorization.max_result_bytes > tool.limits.max_result_bytes
        || !value.authorization.single_use
        || value.tool != *tool
        || value.workload_credential.0.is_empty()
        || value.target_profile.is_empty()
    {
        return Err(ExecutionError::AuthorizationDenied);
    }
    Ok(())
}

fn validate_evidence(value: &ExecutionEvidenceReceipt, tenant: &TenantId, task: &TaskId, result_digest: &str) -> Result<(), ExecutionError> {
    if value.schema_version != "agenttrust.execution-evidence-receipt.v1"
        || value.evidence_ref.is_empty()
        || value.evidence_ref.len() > 2_048
        || value.event.schema_version != EVIDENCE_SCHEMA_VERSION
        || Uuid::parse_str(&value.event.event_id).is_err()
        || value.event.sequence == 0
        || !is_digest(&value.event.previous_hash)
        || value.event.draft.tenant_id != *tenant
        || value.event.draft.task_id != *task
        || value.event.draft.event_type != EvidenceEventType::ToolExecuted
        || value.event.draft.source_service != "agenttrust-execution-service"
        || value.event.draft.payload_hash != result_digest
        || !is_digest(&value.event.event_hash)
        || value.event.signature.is_empty()
    {
        return Err(ExecutionError::EvidenceInvalid);
    }
    Ok(())
}

fn outcome_from_record(request: &ExecutionRequest, record: &ExecutionRecord, fence_digest: &str, ledger_ref: String) -> Result<ExecutionOutcome, ExecutionError> {
    // Every status exposes the exact durable outbox event ID. Signed evidence is additional.
    let mut evidence_refs = vec![ledger_ref];
    if let Some(reference) = &record.evidence_ref {
        if !evidence_refs.contains(reference) {
            evidence_refs.push(reference.clone());
        }
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
    Ok(hex_digest(&serde_jcs::to_vec(fence).map_err(materialization)?))
}

pub fn python_compact_sorted_json_bytes(value: &Value) -> Result<Vec<u8>, ExecutionError> {
    // Python orchestrator uses sort_keys=True,separators=(",",":"),ensure_ascii=False.
    // PostgreSQL jsonb discards object order, so all maps must be sorted recursively here.
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(map.iter().map(|(key, value)| (key.clone(), sort(value))).collect()),
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).map_err(materialization)
}

fn json_content_type(headers: &reqwest::header::HeaderMap) -> bool {
    headers.get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next().is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json")))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn dependency<T>(_: T) -> ExecutionError { ExecutionError::DependencyUnavailable }
fn materialization<T>(_: T) -> ExecutionError { ExecutionError::MaterializationInvalid }

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
            schema_version: EXECUTION_REQUEST_SCHEMA.into(), tenant_id: tenant.clone(),
            task_id: Uuid::new_v4().to_string(), action_id: action.clone(), ingress_digest: "a".repeat(64),
            idempotency_key: "execute:valid".into(), action_materialization: ActionMaterializationRef {
                schema_version: "agenttrust.action-materialization-ref.v1".into(), tenant_id: tenant.clone(),
                action_id: action.clone(), payload_hash: "b".repeat(64), store: "ORCHESTRATOR_INGRESS_POSTGRESQL".into(),
                uri: format!("orchestrator-ingress://{tenant}/{action}"),
            },
        };
        assert!(validate_request(&request).is_ok());
        let mut changed = request;
        changed.action_materialization.uri.push_str("/shadow");
        assert!(validate_request(&changed).is_err());
    }
}
