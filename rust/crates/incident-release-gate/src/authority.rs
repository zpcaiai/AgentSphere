//! Production incident, replay, and release-gate authority.
//!
//! Public commands are never database mutations. They are normalized to Canonical Action IR and
//! admitted by the durable orchestrator. Only the runtime executor scope can apply a mutation,
//! and it must present the PEP decision, transaction-ledger execution, fence, resource version,
//! and authorization-evidence bindings. Every successful mutation appends a local immutable
//! evidence event and a durable Evidence-authority outbox entry in the same transaction.

use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector, RiskContext,
    RiskLevel, SchemaVersion, StepId, TaskId, TenantId, ToolId, ToolRef, ToolVersion,
    VerifiedHumanPrincipal,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const INCIDENT_COMMAND_SCHEMA: &str = "agenttrust.incident-command.v1";
pub const INCIDENT_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.incident-executor-request.v1";
pub const INCIDENT_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.incident-action-receipt.v1";
pub const INCIDENT_MUTATION_RESULT_SCHEMA: &str = "agenttrust.incident-mutation-result.v1";
pub const INCIDENT_AUTHORITY_READINESS_SCHEMA: &str = "agenttrust.incident-release-readiness.v1";
pub const AUTHORITATIVE_INCIDENT_PAGE_SCHEMA: &str = "agenttrust.authoritative-incident-page.v1";
pub const RELEASE_GATE_ENGINE_RECEIPT_SCHEMA: &str = "agenttrust.release-gate-engine-receipt.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IncidentAuthorityError {
    #[error("INCIDENT_AUTHORITY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("INCIDENT_AUTHORITY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("INCIDENT_AUTHORITY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("INCIDENT_AUTHORITY_STATE_CONFLICT")]
    StateConflict,
    #[error("INCIDENT_AUTHORITY_NOT_FOUND")]
    NotFound,
    #[error("INCIDENT_AUTHORITY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("INCIDENT_AUTHORITY_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("INCIDENT_AUTHORITY_EVIDENCE_MISSING")]
    EvidenceMissing,
    #[error("INCIDENT_AUTHORITY_REPLAY_BOUNDARY_VIOLATION")]
    ReplayBoundaryViolation,
    #[error("INCIDENT_AUTHORITY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentAuthorityOperation {
    Detect,
    Triage,
    Contain,
    Investigate,
    PreserveEvidence,
    PlanReplay,
    CompleteReplay,
    PublishRootCause,
    BeginRemediation,
    TriggerRecertification,
    EvaluateRelease,
    StartCanary,
    RecordCanary,
    RollbackRelease,
    Close,
}

impl IncidentAuthorityOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detect => "DETECT",
            Self::Triage => "TRIAGE",
            Self::Contain => "CONTAIN",
            Self::Investigate => "INVESTIGATE",
            Self::PreserveEvidence => "PRESERVE_EVIDENCE",
            Self::PlanReplay => "PLAN_REPLAY",
            Self::CompleteReplay => "COMPLETE_REPLAY",
            Self::PublishRootCause => "PUBLISH_ROOT_CAUSE",
            Self::BeginRemediation => "BEGIN_REMEDIATION",
            Self::TriggerRecertification => "TRIGGER_RECERTIFICATION",
            Self::EvaluateRelease => "EVALUATE_RELEASE",
            Self::StartCanary => "START_CANARY",
            Self::RecordCanary => "RECORD_CANARY",
            Self::RollbackRelease => "ROLLBACK_RELEASE",
            Self::Close => "CLOSE",
        }
    }

    fn required_role(self) -> &'static str {
        match self {
            Self::Detect => "incident-detector",
            Self::Triage
            | Self::Investigate
            | Self::PreserveEvidence
            | Self::PlanReplay
            | Self::CompleteReplay => "incident-responder",
            Self::Contain
            | Self::PublishRootCause
            | Self::BeginRemediation
            | Self::TriggerRecertification
            | Self::Close => "incident-commander",
            Self::EvaluateRelease
            | Self::StartCanary
            | Self::RecordCanary
            | Self::RollbackRelease => "release-manager",
        }
    }

    fn risk(self) -> RiskLevel {
        match self {
            Self::Detect
            | Self::Triage
            | Self::Investigate
            | Self::PreserveEvidence
            | Self::PlanReplay => RiskLevel::High,
            Self::Contain
            | Self::CompleteReplay
            | Self::PublishRootCause
            | Self::BeginRemediation
            | Self::TriggerRecertification
            | Self::EvaluateRelease
            | Self::StartCanary
            | Self::RecordCanary
            | Self::RollbackRelease
            | Self::Close => RiskLevel::Critical,
        }
    }

    fn is_release(self) -> bool {
        matches!(
            self,
            Self::EvaluateRelease | Self::StartCanary | Self::RecordCanary | Self::RollbackRelease
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IncidentCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub resource_id: String,
    pub task_id: Uuid,
    pub operation: IncidentAuthorityOperation,
    pub expected_resource_version: u64,
    pub requested_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IncidentExecutorRequest {
    pub schema_version: String,
    pub command: IncidentCommandRequest,
    pub actor_subject: String,
    pub actor_kind: String,
    pub principal_assertion_digest: Option<String>,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentExecutionBinding {
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
pub struct IncidentActionReceipt {
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
pub struct IncidentMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub resource_id: String,
    pub operation: IncidentAuthorityOperation,
    pub resource_version: u64,
    pub state: String,
    pub result_digest: String,
    pub evidence_outbox_ref: String,
    pub effect_receipt: Option<Value>,
    pub release_receipt: Option<ReleaseGateEngineReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGateEngineReceipt {
    pub schema_version: String,
    pub certificate_id: Uuid,
    pub tenant_id: Uuid,
    pub release_digest: String,
    pub gate_id: String,
    pub gate_version: String,
    pub definition_digest: String,
    pub evidence_digests: BTreeMap<String, String>,
    pub rollback_artifact_digest: String,
    pub canary_plan_digest: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub engine_certificate_only: bool,
    pub production_closure: bool,
    pub key_id: String,
    pub signature: String,
}

impl ReleaseGateEngineReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, IncidentAuthorityError> {
        let mut value = self.clone();
        value.signature.clear();
        serde_jcs::to_vec(&value).map_err(|_| IncidentAuthorityError::RequestInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectReceipt {
    pub schema_version: String,
    pub operation: IncidentAuthorityOperation,
    pub resource_id: String,
    pub idempotency_key: String,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub effect_count: u32,
    pub production_access_detected: bool,
    pub input_digest: String,
    pub result_digest: String,
    pub difference_digest: String,
    pub evidence_refs: BTreeSet<String>,
    pub evidence_digests: BTreeSet<String>,
}

#[async_trait]
pub trait IncidentEffectPort: Send + Sync {
    async fn ready(&self) -> bool;

    async fn execute(
        &self,
        binding: &IncidentExecutionBinding,
        request: &IncidentExecutorRequest,
    ) -> Result<Option<ExternalEffectReceipt>, IncidentAuthorityError>;
}

#[derive(Debug, Clone)]
pub struct IncidentAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
}

impl IncidentAuthorityConfig {
    pub fn validate(&self) -> Result<(), IncidentAuthorityError> {
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
            Err(IncidentAuthorityError::ConfigurationInvalid)
        }
    }
}

#[derive(Debug, Clone)]
struct AuthorityPrincipal {
    tenant_id: TenantId,
    subject: String,
    roles: BTreeSet<String>,
    approval_ids: BTreeSet<String>,
    assertion_jti: Option<Uuid>,
    assertion_digest: Option<String>,
    assertion_expires_at: Option<DateTime<Utc>>,
    auth_context_ref: String,
    actor_kind: String,
}

impl AuthorityPrincipal {
    fn human(value: &VerifiedHumanPrincipal) -> Result<Self, IncidentAuthorityError> {
        Ok(Self {
            tenant_id: value.tenant_id.clone(),
            subject: value.subject.clone(),
            roles: value.roles.clone(),
            approval_ids: value.approval_ids.clone(),
            assertion_jti: Some(
                Uuid::parse_str(&value.jti).map_err(|_| IncidentAuthorityError::PrincipalDenied)?,
            ),
            assertion_digest: Some(value.assertion_digest.clone()),
            assertion_expires_at: Some(value.expires_at),
            auth_context_ref: format!("human-assertion://{}", value.jti),
            actor_kind: "HUMAN".into(),
        })
    }

    fn detector(tenant: TenantId, subject: String) -> Result<Self, IncidentAuthorityError> {
        if !identifier(&subject, 256) {
            return Err(IncidentAuthorityError::PrincipalDenied);
        }
        Ok(Self {
            tenant_id: tenant,
            subject: subject.clone(),
            roles: BTreeSet::from(["incident-detector".into()]),
            approval_ids: BTreeSet::new(),
            assertion_jti: None,
            assertion_digest: None,
            assertion_expires_at: None,
            auth_context_ref: format!("workload-identity://{subject}"),
            actor_kind: "WORKLOAD".into(),
        })
    }
}

#[async_trait]
pub trait IncidentOrchestratorPort: Send + Sync {
    async fn ready(&self) -> bool;

    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<IncidentActionReceipt, IncidentAuthorityError>;
}

#[derive(Clone)]
pub struct IncidentIngressAuthority {
    store: PostgresIncidentAuthorityStore,
    orchestrator: Arc<dyn IncidentOrchestratorPort>,
    config: IncidentAuthorityConfig,
}

impl IncidentIngressAuthority {
    pub fn new(
        store: PostgresIncidentAuthorityStore,
        orchestrator: Arc<dyn IncidentOrchestratorPort>,
        config: IncidentAuthorityConfig,
    ) -> Result<Self, IncidentAuthorityError> {
        config.validate()?;
        Ok(Self {
            store,
            orchestrator,
            config,
        })
    }

    pub async fn submit_human(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: IncidentCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<IncidentActionReceipt, IncidentAuthorityError> {
        if request.operation == IncidentAuthorityOperation::Detect {
            return Err(IncidentAuthorityError::PrincipalDenied);
        }
        self.submit(
            AuthorityPrincipal::human(principal)?,
            request,
            request_digest,
            idempotency_key,
        )
        .await
    }

    pub async fn submit_detection(
        &self,
        tenant: TenantId,
        detector_subject: String,
        request: IncidentCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<IncidentActionReceipt, IncidentAuthorityError> {
        if request.operation != IncidentAuthorityOperation::Detect {
            return Err(IncidentAuthorityError::PrincipalDenied);
        }
        self.submit(
            AuthorityPrincipal::detector(tenant, detector_subject)?,
            request,
            request_digest,
            idempotency_key,
        )
        .await
    }

    async fn submit(
        &self,
        principal: AuthorityPrincipal,
        request: IncidentCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<IncidentActionReceipt, IncidentAuthorityError> {
        validate_command(&principal, &request, request_digest, idempotency_key)?;
        let current = self
            .store
            .current_resource_version(&principal.tenant_id, &request.resource_id)
            .await?;
        if current != request.expected_resource_version {
            return Err(IncidentAuthorityError::StateConflict);
        }
        let envelope = canonical_incident_action(&principal, &request, &self.config)?;
        let prepared = self
            .store
            .prepare_ingress(
                &principal,
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
            .submit(&principal.tenant_id, &prepared.envelope)
            .await?;
        self.store
            .complete_ingress(&principal.tenant_id, idempotency_key, &receipt)
            .await
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.orchestrator.ready().await
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<AuthoritativeIncidentPage, IncidentAuthorityError> {
        self.store.authoritative_page(tenant, after, limit).await
    }

    pub async fn authoritative_detail(
        &self,
        tenant: &TenantId,
        incident_id: Uuid,
    ) -> Result<AuthoritativeIncident, IncidentAuthorityError> {
        self.store.authoritative_detail(tenant, incident_id).await
    }
}

#[derive(Debug, Clone)]
struct PreparedIngress {
    envelope: InboundEnvelope,
    receipt: Option<IncidentActionReceipt>,
}

fn validate_command(
    principal: &AuthorityPrincipal,
    request: &IncidentCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), IncidentAuthorityError> {
    if request.schema_version != INCIDENT_COMMAND_SCHEMA
        || request.tenant_id.to_string() != principal.tenant_id.0
        || request.command_id.is_nil()
        || request.task_id.is_nil()
        || request.operation.is_release() && !release_resource_identifier(&request.resource_id)
        || !request.operation.is_release() && !incident_resource_identifier(&request.resource_id)
        || !principal.roles.contains(request.operation.required_role())
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || request.payload.as_object().is_none()
        || serde_json::to_vec(&request.payload).map_or(true, |value| value.len() > 1_048_576)
        || request.requested_at > Utc::now() + Duration::minutes(1)
        || request.requested_at < Utc::now() - Duration::hours(24)
        || !payload_shape(request, &principal.approval_ids)
    {
        return Err(IncidentAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn payload_shape(request: &IncidentCommandRequest, approvals: &BTreeSet<String>) -> bool {
    let payload = match request.payload.as_object() {
        Some(value) => value,
        None => return false,
    };
    match request.operation {
        IncidentAuthorityOperation::Detect => {
            exact_keys(
                payload,
                &[
                    "incident_id",
                    "detection_id",
                    "severity",
                    "owner",
                    "scope",
                    "safe_summary",
                    "evidence_refs",
                    "auto_contain",
                ],
            ) && uuid_field(payload, "incident_id")
                && identifier_field(payload, "detection_id", 256)
                && matches!(
                    string_field(payload, "severity"),
                    Some("P0" | "P1" | "P2" | "P3")
                )
                && identifier_field(payload, "owner", 256)
                && string_array(payload, "scope", 1, 256, resource_identifier)
                && string_array(payload, "evidence_refs", 1, 256, evidence_reference)
                && safe_summary(payload)
                && payload.get("auto_contain").and_then(Value::as_bool) == Some(true)
                && request.expected_resource_version == 0
        }
        IncidentAuthorityOperation::Triage => {
            exact_keys(payload, &["owner", "severity", "reason_code"])
                && identifier_field(payload, "owner", 256)
                && matches!(
                    string_field(payload, "severity"),
                    Some("P0" | "P1" | "P2" | "P3")
                )
                && identifier_field(payload, "reason_code", 128)
        }
        IncidentAuthorityOperation::Contain => {
            exact_keys(payload, &["reason_code", "targets", "break_glass"])
                && identifier_field(payload, "reason_code", 128)
                && containment_targets(payload.get("targets"))
                && approval_or_break_glass(approvals, payload.get("break_glass"))
        }
        IncidentAuthorityOperation::Investigate | IncidentAuthorityOperation::BeginRemediation => {
            exact_keys(payload, &["reason_code"]) && identifier_field(payload, "reason_code", 128)
        }
        IncidentAuthorityOperation::PreserveEvidence => {
            exact_keys(
                payload,
                &[
                    "chain_head_digest",
                    "snapshot_digest",
                    "process_digest",
                    "network_digest",
                    "configuration_digest",
                    "version_digest",
                    "legal_hold_id",
                ],
            ) && [
                "chain_head_digest",
                "snapshot_digest",
                "process_digest",
                "network_digest",
                "configuration_digest",
                "version_digest",
            ]
            .iter()
            .all(|name| digest_field(payload, name))
                && identifier_field(payload, "legal_hold_id", 256)
        }
        IncidentAuthorityOperation::PlanReplay => replay_plan_shape(payload, approvals),
        IncidentAuthorityOperation::CompleteReplay => replay_result_shape(payload, approvals),
        IncidentAuthorityOperation::PublishRootCause => root_cause_shape(payload),
        IncidentAuthorityOperation::TriggerRecertification => {
            exact_keys(
                payload,
                &["root_cause_digest", "release_digest", "campaigns"],
            ) && digest_field(payload, "root_cause_digest")
                && digest_field(payload, "release_digest")
                && string_array(payload, "campaigns", 1, 64, |value| identifier(value, 128))
                && !approvals.is_empty()
        }
        IncidentAuthorityOperation::EvaluateRelease => release_gate_shape(payload, approvals),
        IncidentAuthorityOperation::StartCanary => {
            exact_keys(
                payload,
                &[
                    "certificate_id",
                    "release_digest",
                    "canary_plan_digest",
                    "percentage",
                ],
            ) && uuid_field(payload, "certificate_id")
                && digest_field(payload, "release_digest")
                && digest_field(payload, "canary_plan_digest")
                && payload
                    .get("percentage")
                    .and_then(Value::as_u64)
                    .is_some_and(|value| (1..=10).contains(&value))
                && approvals.len() >= 2
        }
        IncidentAuthorityOperation::RecordCanary => {
            exact_keys(
                payload,
                &[
                    "certificate_id",
                    "release_digest",
                    "metrics_digest",
                    "passed",
                    "rollback_required",
                ],
            ) && uuid_field(payload, "certificate_id")
                && digest_field(payload, "release_digest")
                && digest_field(payload, "metrics_digest")
                && payload.get("passed").and_then(Value::as_bool).is_some()
                && payload
                    .get("rollback_required")
                    .and_then(Value::as_bool)
                    .is_some()
                && (payload.get("passed").and_then(Value::as_bool) == Some(true)
                    || payload.get("rollback_required").and_then(Value::as_bool) == Some(true))
                && approvals.len() >= 2
        }
        IncidentAuthorityOperation::RollbackRelease => {
            exact_keys(
                payload,
                &["release_digest", "target_release_digest", "reason_digest"],
            ) && digest_field(payload, "release_digest")
                && digest_field(payload, "target_release_digest")
                && digest_field(payload, "reason_digest")
                && approvals.len() >= 2
        }
        IncidentAuthorityOperation::Close => {
            exact_keys(
                payload,
                &[
                    "root_cause_digest",
                    "recertification_evidence_ref",
                    "recertification_evidence_digest",
                ],
            ) && digest_field(payload, "root_cause_digest")
                && evidence_reference_field(payload, "recertification_evidence_ref")
                && digest_field(payload, "recertification_evidence_digest")
                && !approvals.is_empty()
        }
    }
}

fn canonical_incident_action(
    principal: &AuthorityPrincipal,
    request: &IncidentCommandRequest,
    config: &IncidentAuthorityConfig,
) -> Result<InboundEnvelope, IncidentAuthorityError> {
    let now = Utc::now();
    let task_id = TaskId(request.task_id.to_string());
    let tenant = principal.tenant_id.clone();
    let executor = IncidentExecutorRequest {
        schema_version: INCIDENT_EXECUTOR_REQUEST_SCHEMA.into(),
        command: request.clone(),
        actor_subject: principal.subject.clone(),
        actor_kind: principal.actor_kind.clone(),
        principal_assertion_digest: principal.assertion_digest.clone(),
        approval_ids: principal.approval_ids.clone(),
    };
    let data = serde_json::to_value(&executor)
        .map_err(|_| IncidentAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(IncidentAuthorityError::RequestInvalid)?;
    let plan_hash = canonical_digest(&json!({
        "operation": request.operation,
        "resource_id": request.resource_id,
        "resource_version": request.expected_resource_version,
        "payload": request.payload,
    }))?;
    let mut extensions = BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    if let Some(assertion_digest) = &principal.assertion_digest {
        extensions.insert(
            "x-human-principal-assertion-digest".into(),
            Value::String(assertion_digest.clone()),
        );
    }
    extensions.insert(
        "x-required-control-path".into(),
        Value::String("CANONICAL_ACTION_IR->PEP->LEDGER->EVIDENCE".into()),
    );
    let operation = request.operation.as_str().to_ascii_lowercase();
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(request.command_id.to_string()),
        task_id: task_id.clone(),
        step_id: StepId::new(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "incident-release-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: principal.subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-incident-release-engine".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: principal.auth_context_ref.clone(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: canonical_digest(request)?,
            operation: operation.clone(),
            justification_code: "INCIDENT_RELEASE_GOVERNANCE".into(),
            safe_summary: Some(format!(
                "{} {}",
                request.operation.as_str(),
                request.resource_id
            )),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "incident.release.mutation.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator: format!("incident-release/{}", request.resource_id),
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: matches!(
                request.operation,
                IncidentAuthorityOperation::PlanReplay | IncidentAuthorityOperation::CompleteReplay
            ) && string_field(
                request
                    .payload
                    .as_object()
                    .ok_or(IncidentAuthorityError::RequestInvalid)?,
                "mode",
            ) != Some("LIVE"),
        },
        current_state_version: Some(request.expected_resource_version.to_string()),
        risk: RiskContext {
            declared_risk: request.operation.risk(),
            trajectory_risk_ref: None,
            scope_delta: 1,
            automation_allowed: request.operation == IncidentAuthorityOperation::Detect,
        },
        data: DataContext {
            classification: DataClassification::Restricted,
            jurisdiction: config.region.clone(),
            export_constraints: vec!["TENANT_BOUND".into(), "INCIDENT_LEGAL_HOLD".into()],
        },
        expected_outcome: ExpectedOutcome {
            metric: "incident_release_state_persisted".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "incident-release/".into(),
            operations: vec![operation],
        }],
        requested_at: request.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("incident.release.mutation.v1", "1");
    let action =
        normalize(draft, &normalization).map_err(|_| IncidentAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| IncidentAuthorityError::RequestInvalid)?;
    let payload =
        serde_json::to_vec(&action).map_err(|_| IncidentAuthorityError::RequestInvalid)?;
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
            owner_subject: principal.subject.clone(),
            trust_level: "attested".into(),
        },
        tenant_context: TenantContext {
            tenant_id: tenant,
            quota_profile: "incident-release-authority".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: None,
        received_at: now,
        payload_hash: sha256(&payload),
        payload,
    })
}

#[derive(Clone)]
pub struct PostgresIncidentAuthorityStore {
    pool: PgPool,
}

impl PostgresIncidentAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM incident_action_ingress WHERE false UNION ALL SELECT 1 LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .is_ok()
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, IncidentAuthorityError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(parse_tenant(tenant)?.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }

    pub async fn current_resource_version(
        &self,
        tenant: &TenantId,
        resource_id: &str,
    ) -> Result<u64, IncidentAuthorityError> {
        let mut tx = self.begin_tenant(tenant).await?;
        let version = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM incident_resource_versions \
             WHERE tenant_id=$1 AND resource_id=$2",
        )
        .bind(parse_tenant(tenant)?)
        .bind(resource_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        u64::try_from(version).map_err(|_| IncidentAuthorityError::DependencyUnavailable)
    }

    async fn prepare_ingress(
        &self,
        principal: &AuthorityPrincipal,
        request: &IncidentCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        mut envelope: InboundEnvelope,
    ) -> Result<PreparedIngress, IncidentAuthorityError> {
        envelope.idempotency_key = Some(idempotency_key.to_string());
        let tenant = request.tenant_id;
        let envelope_value =
            serde_json::to_value(&envelope).map_err(|_| IncidentAuthorityError::RequestInvalid)?;
        let mut tx = self.begin_tenant(&principal.tenant_id).await?;
        if let (Some(jti), Some(assertion_digest), Some(expires_at)) = (
            principal.assertion_jti,
            principal.assertion_digest.as_deref(),
            principal.assertion_expires_at,
        ) {
            sqlx::query(
                "INSERT INTO incident_principal_assertion_replay \
                 (tenant_id,jti,assertion_digest,request_digest,expires_at) \
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,jti) DO NOTHING",
            )
            .bind(tenant)
            .bind(jti)
            .bind(assertion_digest)
            .bind(request_digest)
            .bind(expires_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
            let replay = sqlx::query(
                "SELECT assertion_digest,request_digest,expires_at \
                 FROM incident_principal_assertion_replay \
                 WHERE tenant_id=$1 AND jti=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(jti)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
            if replay.get::<String, _>("assertion_digest") != assertion_digest
                || replay.get::<String, _>("request_digest") != request_digest
                || replay.get::<DateTime<Utc>, _>("expires_at") != expires_at
            {
                return Err(IncidentAuthorityError::IdempotencyConflict);
            }
        }
        sqlx::query(
            "INSERT INTO incident_action_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,resource_id,operation,\
              principal_subject,principal_kind,principal_assertion_digest,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PREPARED') \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(request.command_id)
        .bind(request.task_id)
        .bind(&request.resource_id)
        .bind(request.operation.as_str())
        .bind(&principal.subject)
        .bind(&principal.actor_kind)
        .bind(principal.assertion_digest.as_deref())
        .bind(&envelope_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        let row = sqlx::query(
            "SELECT request_digest,action_id,task_id,resource_id,operation,principal_subject,\
                    principal_kind,principal_assertion_digest,envelope,receipt \
             FROM incident_action_ingress WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command_id
            || row.get::<Uuid, _>("task_id") != request.task_id
            || row.get::<String, _>("resource_id") != request.resource_id
            || row.get::<String, _>("operation") != request.operation.as_str()
            || row.get::<String, _>("principal_subject") != principal.subject
            || row.get::<String, _>("principal_kind") != principal.actor_kind
            || row.get::<Option<String>, _>("principal_assertion_digest")
                != principal.assertion_digest
            || row.get::<Value, _>("envelope") != envelope_value
        {
            return Err(IncidentAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("receipt")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        Ok(PreparedIngress { envelope, receipt })
    }

    async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &IncidentActionReceipt,
    ) -> Result<IncidentActionReceipt, IncidentAuthorityError> {
        if receipt.schema_version != INCIDENT_ACTION_RECEIPT_SCHEMA
            || !receipt.accepted
            || !receipt.execution_pending
            || !canonical_uuid(&receipt.action_id)
            || !canonical_uuid(&receipt.task_id)
            || !digest(&receipt.ingress_digest)
            || !evidence_reference(&receipt.ledger_evidence_ref)
            || !digest(&receipt.ledger_evidence_digest)
        {
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let value = serde_json::to_value(receipt)
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,state,receipt FROM incident_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("action_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("receipt") {
            if existing != value {
                return Err(IncidentAuthorityError::IdempotencyConflict);
            }
        } else {
            let updated = sqlx::query(
                "UPDATE incident_action_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(IncidentAuthorityError::OutcomeUnknown);
            }
        }
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<AuthoritativeIncidentPage, IncidentAuthorityError> {
        if !(1..=200).contains(&limit) {
            return Err(IncidentAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT incident_id,correlation_key,severity,status,task_id,owner,safe_summary,scope,\
                    evidence_refs,legal_hold_id,resource_version,created_at,updated_at \
             FROM incidents WHERE tenant_id=$1 AND ($2::uuid IS NULL OR incident_id>$2) \
             ORDER BY incident_id LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        let mut items = Vec::new();
        for row in rows.iter().take(limit as usize) {
            let incident_id: Uuid = row.get("incident_id");
            let timeline = sqlx::query(
                "SELECT event_id,sequence,event_type,from_status,to_status,actor_subject,\
                        reason_code,payload_digest,action_hash,ledger_execution_id,fence_digest,\
                        policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,occurred_at \
                 FROM incident_timeline WHERE tenant_id=$1 AND incident_id=$2 ORDER BY sequence",
            )
            .bind(tenant_uuid)
            .bind(incident_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
            .into_iter()
            .map(|entry| AuthoritativeTimelineEntry {
                event_id: entry.get("event_id"),
                sequence: entry.get("sequence"),
                event_type: entry.get("event_type"),
                from_status: entry.get("from_status"),
                to_status: entry.get("to_status"),
                actor_subject: entry.get("actor_subject"),
                reason_code: entry.get("reason_code"),
                payload_digest: entry.get("payload_digest"),
                action_hash: entry.get("action_hash"),
                ledger_execution_id: entry.get("ledger_execution_id"),
                fence_digest: entry.get("fence_digest"),
                policy_decision_digest: entry.get("policy_decision_digest"),
                authorization_evidence_ref: entry.get("authorization_evidence_ref"),
                authorization_evidence_digest: entry.get("authorization_evidence_digest"),
                occurred_at: entry.get("occurred_at"),
            })
            .collect();
            items.push(AuthoritativeIncident {
                incident_id,
                correlation_key: row.get("correlation_key"),
                severity: row.get("severity"),
                status: row.get("status"),
                task_id: row.get("task_id"),
                owner: row.get("owner"),
                safe_summary: row.get("safe_summary"),
                scope: row.get("scope"),
                evidence_refs: row.get("evidence_refs"),
                legal_hold_id: row.get("legal_hold_id"),
                resource_version: row.get("resource_version"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                timeline,
            });
        }
        let next_after_incident_id = (rows.len() > limit as usize)
            .then(|| items.last().map(|item| item.incident_id))
            .flatten();
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        Ok(AuthoritativeIncidentPage {
            schema_version: AUTHORITATIVE_INCIDENT_PAGE_SCHEMA.into(),
            tenant_id: tenant.clone(),
            items,
            next_after_incident_id,
        })
    }

    pub async fn authoritative_detail(
        &self,
        tenant: &TenantId,
        incident_id: Uuid,
    ) -> Result<AuthoritativeIncident, IncidentAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT incident_id,correlation_key,severity,status,task_id,owner,safe_summary,scope,\
                    evidence_refs,legal_hold_id,resource_version,created_at,updated_at \
             FROM incidents WHERE tenant_id=$1 AND incident_id=$2",
        )
        .bind(tenant_uuid)
        .bind(incident_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
        .ok_or(IncidentAuthorityError::NotFound)?;
        let timeline = sqlx::query(
            "SELECT event_id,sequence,event_type,from_status,to_status,actor_subject,\
                    reason_code,payload_digest,action_hash,ledger_execution_id,fence_digest,\
                    policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,occurred_at \
             FROM incident_timeline WHERE tenant_id=$1 AND incident_id=$2 ORDER BY sequence",
        )
        .bind(tenant_uuid)
        .bind(incident_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
        .into_iter()
        .map(|entry| AuthoritativeTimelineEntry {
            event_id: entry.get("event_id"),
            sequence: entry.get("sequence"),
            event_type: entry.get("event_type"),
            from_status: entry.get("from_status"),
            to_status: entry.get("to_status"),
            actor_subject: entry.get("actor_subject"),
            reason_code: entry.get("reason_code"),
            payload_digest: entry.get("payload_digest"),
            action_hash: entry.get("action_hash"),
            ledger_execution_id: entry.get("ledger_execution_id"),
            fence_digest: entry.get("fence_digest"),
            policy_decision_digest: entry.get("policy_decision_digest"),
            authorization_evidence_ref: entry.get("authorization_evidence_ref"),
            authorization_evidence_digest: entry.get("authorization_evidence_digest"),
            occurred_at: entry.get("occurred_at"),
        })
        .collect();
        let item = AuthoritativeIncident {
            incident_id,
            correlation_key: row.get("correlation_key"),
            severity: row.get("severity"),
            status: row.get("status"),
            task_id: row.get("task_id"),
            owner: row.get("owner"),
            safe_summary: row.get("safe_summary"),
            scope: row.get("scope"),
            evidence_refs: row.get("evidence_refs"),
            legal_hold_id: row.get("legal_hold_id"),
            resource_version: row.get("resource_version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            timeline,
        };
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        Ok(item)
    }
}

fn validate_execution(
    binding: &IncidentExecutionBinding,
    request: &IncidentExecutorRequest,
) -> Result<(), IncidentAuthorityError> {
    if request.schema_version != INCIDENT_EXECUTOR_REQUEST_SCHEMA
        || request.command.tenant_id.to_string() != binding.tenant_id.0
        || request.command.expected_resource_version != binding.resource_version
        || !matches!(request.actor_kind.as_str(), "HUMAN" | "WORKLOAD")
        || !identifier(&request.actor_subject, 256)
        || request.actor_kind == "HUMAN"
            && request
                .principal_assertion_digest
                .as_deref()
                .is_none_or(|value| !digest(value))
        || request.actor_kind == "WORKLOAD" && request.principal_assertion_digest.is_some()
        || !digest(&binding.action_hash)
        || !digest(&binding.fence_digest)
        || binding.ledger_execution_id.is_nil()
        || binding.ledger_event_id.is_nil()
        || !digest(&binding.ledger_event_digest)
        || !valid_idempotency_key(&binding.idempotency_key)
        || !identifier(&binding.trace_id, 256)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !evidence_reference(&binding.authorization_evidence_ref)
        || !digest(&binding.authorization_evidence_digest)
        || !payload_shape(&request.command, &request.approval_ids)
        || request.command.operation == IncidentAuthorityOperation::Detect
            && request.actor_kind != "WORKLOAD"
        || request.command.operation != IncidentAuthorityOperation::Detect
            && request.actor_kind != "HUMAN"
    {
        return Err(IncidentAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn validate_effect(
    request: &IncidentExecutorRequest,
    binding: &IncidentExecutionBinding,
    receipt: Option<&ExternalEffectReceipt>,
) -> Result<(), IncidentAuthorityError> {
    let needs_effect = matches!(
        request.command.operation,
        IncidentAuthorityOperation::Detect
            | IncidentAuthorityOperation::Contain
            | IncidentAuthorityOperation::CompleteReplay
    );
    if needs_effect != receipt.is_some() {
        return Err(IncidentAuthorityError::DependencyUnavailable);
    }
    let Some(receipt) = receipt else {
        return Ok(());
    };
    if receipt.operation != request.command.operation
        || receipt.resource_id != request.command.resource_id
        || receipt.idempotency_key != binding.idempotency_key
        || receipt.action_hash != binding.action_hash
        || receipt.ledger_execution_id != binding.ledger_execution_id
        || receipt.ledger_event_id != binding.ledger_event_id
        || receipt.ledger_event_digest != binding.ledger_event_digest
        || receipt.fence_digest != binding.fence_digest
        || receipt.policy_decision_digest != binding.policy_decision_digest
        || receipt.authorization_evidence_ref != binding.authorization_evidence_ref
        || receipt.authorization_evidence_digest != binding.authorization_evidence_digest
        || !digest(&receipt.input_digest)
        || !digest(&receipt.result_digest)
        || !digest(&receipt.difference_digest)
        || receipt.evidence_refs.is_empty()
        || receipt.evidence_refs.len() > 256
        || receipt
            .evidence_refs
            .iter()
            .any(|value| !evidence_reference(value))
        || receipt.evidence_digests.len() != receipt.evidence_refs.len()
        || receipt.evidence_digests.iter().any(|value| !digest(value))
    {
        return Err(IncidentAuthorityError::DependencyUnavailable);
    }
    match request.command.operation {
        IncidentAuthorityOperation::Detect | IncidentAuthorityOperation::Contain => {
            if receipt.schema_version != "agenttrust.containment-effect-receipt.v1"
                || receipt.effect_count < 4
                || receipt.production_access_detected
            {
                return Err(IncidentAuthorityError::DependencyUnavailable);
            }
        }
        IncidentAuthorityOperation::CompleteReplay => {
            if receipt.schema_version != "agenttrust.replay-effect-receipt.v1" {
                return Err(IncidentAuthorityError::ReplayBoundaryViolation);
            }
            let mode = request
                .command
                .payload
                .get("mode")
                .and_then(Value::as_str)
                .ok_or(IncidentAuthorityError::ReplayBoundaryViolation)?;
            if mode == "LOGICAL"
                && (receipt.effect_count != 0 || receipt.production_access_detected)
                || mode == "SANDBOX" && receipt.production_access_detected
            {
                return Err(IncidentAuthorityError::ReplayBoundaryViolation);
            }
        }
        _ => return Err(IncidentAuthorityError::RequestInvalid),
    }
    Ok(())
}

fn replay_plan_shape(payload: &Map<String, Value>, approvals: &BTreeSet<String>) -> bool {
    if !exact_keys(
        payload,
        &[
            "replay_id",
            "mode",
            "input_digest",
            "source_snapshot_digest",
            "expected_result_digest",
            "resource_refs",
            "credential_profile",
            "fresh_lease_id",
            "fresh_lease_digest",
            "authorization_lease_expires_at",
        ],
    ) || !uuid_field(payload, "replay_id")
        || !digest_field(payload, "input_digest")
        || !digest_field(payload, "source_snapshot_digest")
        || !digest_field(payload, "expected_result_digest")
    {
        return false;
    }
    match string_field(payload, "mode") {
        Some("LOGICAL") => {
            payload.get("credential_profile") == Some(&Value::Null)
                && payload.get("fresh_lease_id") == Some(&Value::Null)
                && payload.get("fresh_lease_digest") == Some(&Value::Null)
                && payload.get("authorization_lease_expires_at") == Some(&Value::Null)
                && payload
                    .get("resource_refs")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        }
        Some("SANDBOX") => {
            string_field(payload, "credential_profile") == Some("test-only")
                && string_array(payload, "resource_refs", 1, 256, |value| {
                    value.starts_with("sandbox://") && resource_identifier(value)
                })
                && payload.get("fresh_lease_id") == Some(&Value::Null)
                && payload.get("fresh_lease_digest") == Some(&Value::Null)
                && payload.get("authorization_lease_expires_at") == Some(&Value::Null)
        }
        Some("LIVE") => {
            string_field(payload, "credential_profile")
                .is_some_and(|value| value != "test-only" && identifier(value, 128))
                && optional_uuid_field(payload, "fresh_lease_id")
                    .ok()
                    .flatten()
                    .is_some()
                && string_field(payload, "fresh_lease_digest").is_some_and(digest)
                && parse_time_field(payload, "authorization_lease_expires_at").is_ok_and(|value| {
                    value > Utc::now() && value <= Utc::now() + Duration::hours(1)
                })
                && string_array(payload, "resource_refs", 1, 256, resource_identifier)
                && approvals.len() >= 2
        }
        _ => false,
    }
}

fn replay_result_shape(payload: &Map<String, Value>, approvals: &BTreeSet<String>) -> bool {
    exact_keys(payload, &["replay_id", "mode", "plan_digest"])
        && uuid_field(payload, "replay_id")
        && digest_field(payload, "plan_digest")
        && matches!(
            string_field(payload, "mode"),
            Some("LOGICAL" | "SANDBOX" | "LIVE")
        )
        && (string_field(payload, "mode") != Some("LIVE") || approvals.len() >= 2)
}

fn containment_targets(value: Option<&Value>) -> bool {
    let Some(value) = value.and_then(Value::as_object) else {
        return false;
    };
    exact_keys(
        value,
        &[
            "kill_task",
            "revoke_credentials",
            "isolate_integrations",
            "freeze_artifacts",
        ],
    ) && value.get("kill_task").and_then(Value::as_bool) == Some(true)
        && value.get("revoke_credentials").and_then(Value::as_bool) == Some(true)
        && value.get("freeze_artifacts").and_then(Value::as_bool) == Some(true)
        && string_array(value, "isolate_integrations", 1, 256, resource_identifier)
}

fn approval_or_break_glass(approvals: &BTreeSet<String>, value: Option<&Value>) -> bool {
    if !approvals.is_empty() {
        return value == Some(&Value::Null);
    }
    let Some(value) = value.and_then(Value::as_object) else {
        return false;
    };
    if !exact_keys(
        value,
        &[
            "break_glass_id",
            "expires_at",
            "review_due_at",
            "compensating_controls",
            "reason_digest",
        ],
    ) || !uuid_field(value, "break_glass_id")
        || !digest_field(value, "reason_digest")
        || !string_array(value, "compensating_controls", 1, 32, |item| {
            identifier(item, 128)
        })
    {
        return false;
    }
    let now = Utc::now();
    let Ok(expires_at) = parse_time_field(value, "expires_at") else {
        return false;
    };
    let Ok(review_due_at) = parse_time_field(value, "review_due_at") else {
        return false;
    };
    expires_at > now
        && expires_at <= now + Duration::minutes(15)
        && review_due_at >= expires_at
        && review_due_at <= now + Duration::hours(24)
}

fn root_cause_shape(payload: &Map<String, Value>) -> bool {
    if !exact_keys(
        payload,
        &["report_id", "report_digest", "findings", "remediations"],
    ) || !uuid_field(payload, "report_id")
        || !digest_field(payload, "report_digest")
    {
        return false;
    }
    let Some(findings) = payload.get("findings").and_then(Value::as_array) else {
        return false;
    };
    let Some(remediations) = payload.get("remediations").and_then(Value::as_array) else {
        return false;
    };
    if findings.is_empty()
        || findings.len() > 256
        || remediations.is_empty()
        || remediations.len() > 512
    {
        return false;
    }
    let mut finding_ids = BTreeSet::new();
    for finding in findings {
        let Some(value) = finding.as_object() else {
            return false;
        };
        if !exact_keys(
            value,
            &[
                "finding_id",
                "category",
                "trigger",
                "system_defect",
                "detection_gap",
                "recovery_gap",
                "evidence_refs",
            ],
        ) || !identifier_field(value, "finding_id", 128)
            || !matches!(
                string_field(value, "category"),
                Some("TRIGGER" | "SYSTEM_DEFECT" | "DETECTION_GAP" | "RECOVERY_PROBLEM")
            )
            || ["trigger", "system_defect", "detection_gap", "recovery_gap"]
                .iter()
                .any(|name| !identifier_field(value, name, 512))
            || !string_array(value, "evidence_refs", 1, 256, evidence_reference)
            || !finding_ids.insert(
                required_string(value, "finding_id")
                    .unwrap_or("")
                    .to_string(),
            )
        {
            return false;
        }
    }
    let mut covered = BTreeSet::new();
    for remediation in remediations {
        let Some(value) = remediation.as_object() else {
            return false;
        };
        if !exact_keys(
            value,
            &[
                "remediation_id",
                "finding_id",
                "policy_ref",
                "test_ref",
                "owner",
                "due_at",
            ],
        ) || !identifier_field(value, "remediation_id", 128)
            || !identifier_field(value, "finding_id", 128)
            || !resource_identifier(required_string(value, "policy_ref").unwrap_or(""))
            || !resource_identifier(required_string(value, "test_ref").unwrap_or(""))
            || !identifier_field(value, "owner", 256)
            || parse_time_field(value, "due_at").is_err()
        {
            return false;
        }
        covered.insert(
            required_string(value, "finding_id")
                .unwrap_or("")
                .to_string(),
        );
    }
    finding_ids.is_subset(&covered)
        && canonical_digest(&json!({"findings": findings, "remediations": remediations}))
            .is_ok_and(|value| string_field(payload, "report_digest") == Some(value.as_str()))
}

fn release_gate_shape(payload: &Map<String, Value>, approvals: &BTreeSet<String>) -> bool {
    if approvals.len() < 2
        || !exact_keys(
            payload,
            &[
                "release_digest",
                "definition",
                "evidence",
                "rollback_artifact_digest",
                "canary_plan_digest",
                "valid_until",
            ],
        )
        || !digest_field(payload, "release_digest")
        || !digest_field(payload, "rollback_artifact_digest")
        || !digest_field(payload, "canary_plan_digest")
    {
        return false;
    }
    let Some(definition) = payload.get("definition").and_then(Value::as_object) else {
        return false;
    };
    if !exact_keys(
        definition,
        &[
            "gate_id",
            "version",
            "definition_digest",
            "required_controls",
            "maximum_evidence_age_seconds",
        ],
    ) || !identifier_field(definition, "gate_id", 128)
        || !identifier_field(definition, "version", 64)
        || !digest_field(definition, "definition_digest")
        || !string_array(definition, "required_controls", 10, 128, |value| {
            identifier(value, 128)
        })
    {
        return false;
    }
    let maximum_age = match definition
        .get("maximum_evidence_age_seconds")
        .and_then(Value::as_u64)
    {
        Some(value) if (60..=2_592_000).contains(&value) => value,
        _ => return false,
    };
    let required = definition
        .get("required_controls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let baseline = BTreeSet::from([
        "CONTRACT",
        "IDENTITY",
        "POLICY",
        "SANDBOX",
        "IDEMPOTENCY",
        "ROLLBACK",
        "TRACE",
        "THREAT",
        "COMPLIANCE",
        "DOMAIN_EVALUATOR",
    ]);
    let definition_material = json!({
        "gate_id": definition.get("gate_id"),
        "version": definition.get("version"),
        "required_controls": definition.get("required_controls"),
        "maximum_evidence_age_seconds": maximum_age,
    });
    if !baseline.is_subset(&required)
        || canonical_digest(&definition_material).ok().as_deref()
            != string_field(definition, "definition_digest")
    {
        return false;
    }
    let Some(evidence) = payload.get("evidence").and_then(Value::as_array) else {
        return false;
    };
    if evidence.len() != required.len() {
        return false;
    }
    let release_digest = string_field(payload, "release_digest").unwrap_or("");
    let now = Utc::now();
    let mut observed = BTreeSet::new();
    for item in evidence {
        let Some(value) = item.as_object() else {
            return false;
        };
        if !exact_keys(
            value,
            &[
                "control_id",
                "evidence_ref",
                "evidence_digest",
                "release_digest",
                "passed",
                "collected_at",
            ],
        ) || !identifier_field(value, "control_id", 128)
            || !evidence_reference_field(value, "evidence_ref")
            || !digest_field(value, "evidence_digest")
            || string_field(value, "release_digest") != Some(release_digest)
            || value.get("passed").and_then(Value::as_bool) != Some(true)
        {
            return false;
        }
        let collected = match parse_time_field(value, "collected_at") {
            Ok(value) => value,
            Err(_) => return false,
        };
        if collected > now
            || now.signed_duration_since(collected).num_seconds() as u64 > maximum_age
            || !observed.insert(string_field(value, "control_id").unwrap_or(""))
        {
            return false;
        }
    }
    observed == required
        && parse_time_field(payload, "valid_until")
            .is_ok_and(|value| value > now && value <= now + Duration::days(7))
}

fn require_state(actual: Option<&str>, allowed: &[&str]) -> Result<(), IncidentAuthorityError> {
    if actual.is_some_and(|value| allowed.contains(&value)) {
        Ok(())
    } else {
        Err(IncidentAuthorityError::StateConflict)
    }
}

fn exact_keys(value: &Map<String, Value>, keys: &[&str]) -> bool {
    value.len() == keys.len() && keys.iter().all(|key| value.contains_key(*key))
}

fn safe_summary(value: &Map<String, Value>) -> bool {
    value
        .get("safe_summary")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            !value.is_empty() && value.len() <= 512 && !value.contains(['\0', '\r', '\n'])
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
                    .all(|item| item.as_str().is_some_and(&validator))
                && items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == items.len()
        })
}

fn uuid_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(canonical_uuid)
}

fn parse_uuid_field(
    value: &Map<String, Value>,
    field: &str,
) -> Result<Uuid, IncidentAuthorityError> {
    Uuid::parse_str(required_string(value, field)?)
        .map_err(|_| IncidentAuthorityError::RequestInvalid)
}

fn optional_uuid_field(
    value: &Map<String, Value>,
    field: &str,
) -> Result<Option<Uuid>, IncidentAuthorityError> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Uuid::parse_str(value)
            .map(Some)
            .map_err(|_| IncidentAuthorityError::RequestInvalid),
        _ => Err(IncidentAuthorityError::RequestInvalid),
    }
}

fn digest_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(digest)
}

fn evidence_reference_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(evidence_reference)
}

fn identifier_field(value: &Map<String, Value>, field: &str, maximum: usize) -> bool {
    string_field(value, field).is_some_and(|value| identifier(value, maximum))
}

fn string_field<'a>(value: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn required_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, IncidentAuthorityError> {
    string_field(value, field).ok_or(IncidentAuthorityError::RequestInvalid)
}

fn parse_time_field(
    value: &Map<String, Value>,
    field: &str,
) -> Result<DateTime<Utc>, IncidentAuthorityError> {
    required_string(value, field)?
        .parse()
        .map_err(|_| IncidentAuthorityError::RequestInvalid)
}

fn canonical_digest(value: &impl Serialize) -> Result<String, IncidentAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| IncidentAuthorityError::RequestInvalid)
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn parse_tenant(value: &TenantId) -> Result<Uuid, IncidentAuthorityError> {
    Uuid::parse_str(&value.0).map_err(|_| IncidentAuthorityError::RequestInvalid)
}

fn incident_uuid(value: &str) -> Result<Uuid, IncidentAuthorityError> {
    value
        .strip_prefix("incident:")
        .ok_or(IncidentAuthorityError::RequestInvalid)
        .and_then(|value| {
            Uuid::parse_str(value).map_err(|_| IncidentAuthorityError::RequestInvalid)
        })
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn resource_identifier(value: &str) -> bool {
    identifier(value, 1_024) && !value.contains("..")
}

fn incident_resource_identifier(value: &str) -> bool {
    value.strip_prefix("incident:").is_some_and(canonical_uuid)
}

fn release_resource_identifier(value: &str) -> bool {
    value
        .strip_prefix("release:")
        .is_some_and(|suffix| identifier(suffix, 1_016) && !suffix.contains(".."))
}

fn evidence_reference(value: &str) -> bool {
    (value.starts_with("evidence://") || value.starts_with("urn:agenttrust:evidence:"))
        && value.len() <= 2_048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

#[cfg(test)]
mod production_authority_tests {
    use super::*;

    #[test]
    fn logical_replay_cannot_carry_credentials_or_live_resources() {
        let payload = json!({
            "replay_id": Uuid::new_v4(),
            "mode": "LOGICAL",
            "input_digest": "a".repeat(64),
            "source_snapshot_digest": "b".repeat(64),
            "expected_result_digest": "c".repeat(64),
            "resource_refs": [],
            "credential_profile": null,
            "fresh_lease_id": null,
            "fresh_lease_digest": null,
            "authorization_lease_expires_at": null
        });
        assert!(replay_plan_shape(
            payload
                .as_object()
                .unwrap_or_else(|| panic!("payload object")),
            &BTreeSet::new()
        ));
        let mut unsafe_payload = payload;
        unsafe_payload["credential_profile"] = Value::String("production".into());
        assert!(!replay_plan_shape(
            unsafe_payload
                .as_object()
                .unwrap_or_else(|| panic!("payload object")),
            &BTreeSet::new()
        ));
    }

    #[test]
    fn release_gate_requires_complete_baseline_and_two_approvals() {
        let now = Utc::now();
        let controls = [
            "CONTRACT",
            "IDENTITY",
            "POLICY",
            "SANDBOX",
            "IDEMPOTENCY",
            "ROLLBACK",
            "TRACE",
            "THREAT",
            "COMPLIANCE",
            "DOMAIN_EVALUATOR",
        ];
        let evidence = controls
            .iter()
            .map(|control| {
                json!({
                    "control_id": control,
                    "evidence_ref": format!("evidence://tenant/task/{control}"),
                    "evidence_digest": "e".repeat(64),
                    "release_digest": "a".repeat(64),
                    "passed": true,
                    "collected_at": now
                })
            })
            .collect::<Vec<_>>();
        let payload = json!({
            "release_digest": "a".repeat(64),
            "definition": {
                "gate_id": "production-engine",
                "version": "1.0.0",
                "definition_digest": "d".repeat(64),
                "required_controls": controls,
                "maximum_evidence_age_seconds": 3600
            },
            "evidence": evidence,
            "rollback_artifact_digest": "b".repeat(64),
            "canary_plan_digest": "c".repeat(64),
            "valid_until": now + Duration::hours(1)
        });
        let approvals = BTreeSet::from(["approval:one".into(), "approval:two".into()]);
        assert!(release_gate_shape(
            payload
                .as_object()
                .unwrap_or_else(|| panic!("payload object")),
            &approvals
        ));
        assert!(!release_gate_shape(
            payload
                .as_object()
                .unwrap_or_else(|| panic!("payload object")),
            &BTreeSet::from(["approval:one".into()])
        ));
    }

    #[test]
    fn containment_requires_approval_or_bounded_break_glass() {
        assert!(!approval_or_break_glass(
            &BTreeSet::new(),
            Some(&Value::Null)
        ));
        assert!(approval_or_break_glass(
            &BTreeSet::from(["approval:one".into()]),
            Some(&Value::Null)
        ));
    }
}

async fn apply_operation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &IncidentExecutorRequest,
    binding: &IncidentExecutionBinding,
    effect: Option<&ExternalEffectReceipt>,
    release_receipt: Option<ReleaseGateEngineReceipt>,
    next_version: i64,
) -> Result<(String, Option<ReleaseGateEngineReceipt>), IncidentAuthorityError> {
    let command = &request.command;
    if command.operation.is_release() {
        let state =
            apply_release_operation(tx, tenant, request, binding, release_receipt.as_ref()).await?;
        return Ok((state, release_receipt));
    }
    let incident_id = incident_uuid(&command.resource_id)?;
    let payload = command
        .payload
        .as_object()
        .ok_or(IncidentAuthorityError::RequestInvalid)?;
    let from_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM incidents WHERE tenant_id=$1 AND incident_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(incident_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
    let (state, reason_code): (String, String) = match command.operation {
        IncidentAuthorityOperation::Detect => {
            if from_status.is_some()
                || required_string(payload, "incident_id")? != incident_id.to_string()
            {
                return Err(IncidentAuthorityError::StateConflict);
            }
            sqlx::query(
                "INSERT INTO incidents \
                 (tenant_id,incident_id,correlation_key,severity,status,task_id,owner,safe_summary,\
                  scope,evidence_refs,legal_hold_id,resource_version) \
                 VALUES ($1,$2,$3,$4,'CONTAINED',$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(tenant)
            .bind(incident_id)
            .bind(required_string(payload, "detection_id")?)
            .bind(required_string(payload, "severity")?)
            .bind(command.task_id)
            .bind(required_string(payload, "owner")?)
            .bind(required_string(payload, "safe_summary")?)
            .bind(
                payload
                    .get("scope")
                    .cloned()
                    .ok_or(IncidentAuthorityError::RequestInvalid)?,
            )
            .bind(
                payload
                    .get("evidence_refs")
                    .cloned()
                    .ok_or(IncidentAuthorityError::RequestInvalid)?,
            )
            .bind(format!("incident-legal-hold:{incident_id}"))
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            let receipt = effect.ok_or(IncidentAuthorityError::DependencyUnavailable)?;
            let targets = json!({
                "kill_task": true,
                "revoke_credentials": true,
                "isolate_integrations": payload.get("scope").cloned().unwrap_or(Value::Array(vec![])),
                "freeze_artifacts": true
            });
            sqlx::query(
                "INSERT INTO containment_actions \
                 (tenant_id,containment_id,incident_id,action_id,idempotency_key,targets,approval_ids,\
                  break_glass,effect_receipt,effect_receipt_digest,action_hash,ledger_execution_id,\
                  fence_digest,policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,completed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,'[]'::jsonb,'null'::jsonb,$7,$8,$9,$10,$11,$12,$13,$14,now())",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(incident_id)
            .bind(command.command_id)
            .bind(&binding.idempotency_key)
            .bind(targets)
            .bind(serde_json::to_value(receipt).map_err(|_| IncidentAuthorityError::RequestInvalid)?)
            .bind(canonical_digest(receipt)?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .bind(&binding.policy_decision_digest)
            .bind(&binding.authorization_evidence_ref)
            .bind(&binding.authorization_evidence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            (
                "CONTAINED".into(),
                "ANOMALY_DETECTED_AND_AUTOMATICALLY_CONTAINED".into(),
            )
        }
        IncidentAuthorityOperation::Triage => {
            require_state(from_status.as_deref(), &["DETECTED"])?;
            update_incident(
                tx,
                tenant,
                incident_id,
                "TRIAGED",
                Some(required_string(payload, "owner")?),
                Some(required_string(payload, "severity")?),
                next_version,
            )
            .await?;
            (
                "TRIAGED".into(),
                required_string(payload, "reason_code")?.into(),
            )
        }
        IncidentAuthorityOperation::Contain => {
            require_state(from_status.as_deref(), &["DETECTED", "TRIAGED"])?;
            let receipt = effect.ok_or(IncidentAuthorityError::DependencyUnavailable)?;
            sqlx::query(
                "INSERT INTO containment_actions \
                 (tenant_id,containment_id,incident_id,action_id,idempotency_key,targets,approval_ids,\
                  break_glass,effect_receipt,effect_receipt_digest,action_hash,ledger_execution_id,\
                  fence_digest,policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,completed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,now())",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(incident_id)
            .bind(command.command_id)
            .bind(&binding.idempotency_key)
            .bind(payload.get("targets").cloned().unwrap_or(Value::Null))
            .bind(serde_json::to_value(&request.approval_ids).map_err(|_| IncidentAuthorityError::RequestInvalid)?)
            .bind(payload.get("break_glass").cloned().unwrap_or(Value::Null))
            .bind(serde_json::to_value(receipt).map_err(|_| IncidentAuthorityError::RequestInvalid)?)
            .bind(canonical_digest(receipt)?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .bind(&binding.policy_decision_digest)
            .bind(&binding.authorization_evidence_ref)
            .bind(&binding.authorization_evidence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            update_incident(
                tx,
                tenant,
                incident_id,
                "CONTAINED",
                None,
                None,
                next_version,
            )
            .await?;
            (
                "CONTAINED".into(),
                required_string(payload, "reason_code")?.into(),
            )
        }
        IncidentAuthorityOperation::Investigate => {
            require_state(from_status.as_deref(), &["CONTAINED"])?;
            update_incident(
                tx,
                tenant,
                incident_id,
                "INVESTIGATING",
                None,
                None,
                next_version,
            )
            .await?;
            (
                "INVESTIGATING".into(),
                required_string(payload, "reason_code")?.into(),
            )
        }
        IncidentAuthorityOperation::PreserveEvidence => {
            require_state(
                from_status.as_deref(),
                &["CONTAINED", "INVESTIGATING", "REMEDIATING", "RECERTIFYING"],
            )?;
            sqlx::query(
                "INSERT INTO incident_evidence_preservations \
                 (tenant_id,preservation_id,incident_id,chain_head_digest,snapshot_digest,\
                  process_digest,network_digest,configuration_digest,version_digest,legal_hold_id,\
                  preserved_by,action_hash,ledger_execution_id,fence_digest,created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now())",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(incident_id)
            .bind(required_string(payload, "chain_head_digest")?)
            .bind(required_string(payload, "snapshot_digest")?)
            .bind(required_string(payload, "process_digest")?)
            .bind(required_string(payload, "network_digest")?)
            .bind(required_string(payload, "configuration_digest")?)
            .bind(required_string(payload, "version_digest")?)
            .bind(required_string(payload, "legal_hold_id")?)
            .bind(&request.actor_subject)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            (
                from_status.clone().unwrap_or_else(|| "UNKNOWN".into()),
                "EVIDENCE_PRESERVED".into(),
            )
        }
        IncidentAuthorityOperation::PlanReplay => {
            require_state(from_status.as_deref(), &["INVESTIGATING", "REMEDIATING"])?;
            let plan_digest = canonical_digest(&command.payload)?;
            sqlx::query(
                "INSERT INTO replay_plans \
                 (tenant_id,replay_id,incident_id,mode,input_digest,source_snapshot_digest,\
                  expected_result_digest,plan_digest,resource_refs,credential_profile,\
                  fresh_lease_id,fresh_lease_digest,approval_ids,created_by,created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now())",
            )
            .bind(tenant)
            .bind(parse_uuid_field(payload, "replay_id")?)
            .bind(incident_id)
            .bind(required_string(payload, "mode")?)
            .bind(required_string(payload, "input_digest")?)
            .bind(required_string(payload, "source_snapshot_digest")?)
            .bind(required_string(payload, "expected_result_digest")?)
            .bind(&plan_digest)
            .bind(
                payload
                    .get("resource_refs")
                    .cloned()
                    .unwrap_or(Value::Array(vec![])),
            )
            .bind(payload.get("credential_profile").and_then(Value::as_str))
            .bind(optional_uuid_field(payload, "fresh_lease_id")?)
            .bind(payload.get("fresh_lease_digest").and_then(Value::as_str))
            .bind(
                serde_json::to_value(&request.approval_ids)
                    .map_err(|_| IncidentAuthorityError::RequestInvalid)?,
            )
            .bind(&request.actor_subject)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            (
                from_status.clone().unwrap_or_else(|| "UNKNOWN".into()),
                "REPLAY_PLANNED".into(),
            )
        }
        IncidentAuthorityOperation::CompleteReplay => {
            require_state(
                from_status.as_deref(),
                &["INVESTIGATING", "REMEDIATING", "RECERTIFYING"],
            )?;
            let receipt = effect.ok_or(IncidentAuthorityError::DependencyUnavailable)?;
            let replay_id = parse_uuid_field(payload, "replay_id")?;
            let plan = sqlx::query(
                "SELECT mode,plan_digest,input_digest FROM replay_plans \
                 WHERE tenant_id=$1 AND replay_id=$2 AND incident_id=$3",
            )
            .bind(tenant)
            .bind(replay_id)
            .bind(incident_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
            .ok_or(IncidentAuthorityError::NotFound)?;
            if plan.get::<String, _>("mode") != required_string(payload, "mode")?
                || plan.get::<String, _>("plan_digest") != required_string(payload, "plan_digest")?
                || plan.get::<String, _>("input_digest") != receipt.input_digest
            {
                return Err(IncidentAuthorityError::ReplayBoundaryViolation);
            }
            sqlx::query(
                "INSERT INTO replay_runs \
                 (tenant_id,replay_id,incident_id,mode,input_digest,result_digest,difference_digest,\
                  effect_count,production_access_detected,effect_receipt,evidence_ref,created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())",
            )
            .bind(tenant)
            .bind(replay_id)
            .bind(incident_id)
            .bind(required_string(payload, "mode")?)
            .bind(&receipt.input_digest)
            .bind(&receipt.result_digest)
            .bind(&receipt.difference_digest)
            .bind(i64::from(receipt.effect_count))
            .bind(receipt.production_access_detected)
            .bind(serde_json::to_value(receipt).map_err(|_| IncidentAuthorityError::RequestInvalid)?)
            .bind(receipt.evidence_refs.iter().next())
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            (
                from_status.clone().unwrap_or_else(|| "UNKNOWN".into()),
                "REPLAY_COMPLETED".into(),
            )
        }
        IncidentAuthorityOperation::PublishRootCause => {
            require_state(from_status.as_deref(), &["INVESTIGATING"])?;
            let report_digest = required_string(payload, "report_digest")?;
            sqlx::query(
                "INSERT INTO root_cause_reports \
                 (tenant_id,report_id,incident_id,report_digest,findings,remediations,published_by,\
                  action_hash,ledger_execution_id,fence_digest,published_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())",
            )
            .bind(tenant)
            .bind(parse_uuid_field(payload, "report_id")?)
            .bind(incident_id)
            .bind(report_digest)
            .bind(payload.get("findings").cloned().unwrap_or(Value::Null))
            .bind(payload.get("remediations").cloned().unwrap_or(Value::Null))
            .bind(&request.actor_subject)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            update_incident(
                tx,
                tenant,
                incident_id,
                "REMEDIATING",
                None,
                None,
                next_version,
            )
            .await?;
            ("REMEDIATING".into(), "ROOT_CAUSE_PUBLISHED".into())
        }
        IncidentAuthorityOperation::BeginRemediation => {
            require_state(from_status.as_deref(), &["INVESTIGATING", "REMEDIATING"])?;
            update_incident(
                tx,
                tenant,
                incident_id,
                "REMEDIATING",
                None,
                None,
                next_version,
            )
            .await?;
            (
                "REMEDIATING".into(),
                required_string(payload, "reason_code")?.into(),
            )
        }
        IncidentAuthorityOperation::TriggerRecertification => {
            require_state(from_status.as_deref(), &["REMEDIATING"])?;
            sqlx::query(
                "INSERT INTO incident_recertifications \
                 (tenant_id,recertification_id,incident_id,root_cause_digest,release_digest,\
                  campaigns,approval_ids,requested_by,action_hash,ledger_execution_id,fence_digest,\
                  state,requested_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'REQUESTED',now())",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(incident_id)
            .bind(required_string(payload, "root_cause_digest")?)
            .bind(required_string(payload, "release_digest")?)
            .bind(payload.get("campaigns").cloned().unwrap_or(Value::Null))
            .bind(serde_json::to_value(&request.approval_ids).map_err(|_| IncidentAuthorityError::RequestInvalid)?)
            .bind(&request.actor_subject)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            update_incident(
                tx,
                tenant,
                incident_id,
                "RECERTIFYING",
                None,
                None,
                next_version,
            )
            .await?;
            ("RECERTIFYING".into(), "RECERTIFICATION_REQUESTED".into())
        }
        IncidentAuthorityOperation::Close => {
            require_state(from_status.as_deref(), &["RECERTIFYING"])?;
            let matching = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM root_cause_reports WHERE tenant_id=$1 AND incident_id=$2 \
                 AND report_digest=$3",
            )
            .bind(tenant)
            .bind(incident_id)
            .bind(required_string(payload, "root_cause_digest")?)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
            if matching != 1 {
                return Err(IncidentAuthorityError::EvidenceMissing);
            }
            update_incident(tx, tenant, incident_id, "CLOSED", None, None, next_version).await?;
            ("CLOSED".into(), "RECERTIFICATION_PASSED".into())
        }
        _ => return Err(IncidentAuthorityError::RequestInvalid),
    };
    if matches!(
        command.operation,
        IncidentAuthorityOperation::PreserveEvidence
            | IncidentAuthorityOperation::PlanReplay
            | IncidentAuthorityOperation::CompleteReplay
    ) {
        update_incident(tx, tenant, incident_id, &state, None, None, next_version).await?;
    }
    append_timeline(
        tx,
        tenant,
        incident_id,
        request,
        binding,
        from_status.as_deref(),
        &state,
        &reason_code,
    )
    .await?;
    Ok((state, None))
}

async fn apply_release_operation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &IncidentExecutorRequest,
    binding: &IncidentExecutionBinding,
    receipt: Option<&ReleaseGateEngineReceipt>,
) -> Result<String, IncidentAuthorityError> {
    let payload = request
        .command
        .payload
        .as_object()
        .ok_or(IncidentAuthorityError::RequestInvalid)?;
    match request.command.operation {
        IncidentAuthorityOperation::EvaluateRelease => {
            let receipt = receipt.ok_or(IncidentAuthorityError::OutcomeUnknown)?;
            let open_critical = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM incidents WHERE tenant_id=$1 AND severity IN ('P0','P1') \
                 AND status<>'CLOSED'",
            )
            .bind(tenant)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
            if open_critical != 0 {
                return Err(IncidentAuthorityError::EvidenceMissing);
            }
            let evidence_digest = canonical_digest(
                payload
                    .get("evidence")
                    .ok_or(IncidentAuthorityError::EvidenceMissing)?,
            )?;
            sqlx::query(
                "INSERT INTO release_gate_runs \
                 (tenant_id,gate_run_id,release_id,release_digest,gate_id,gate_version,\
                  definition_digest,evidence_digest,rollback_artifact_digest,canary_plan_digest,\
                  approval_ids,state,action_hash,ledger_execution_id,fence_digest,\
                  policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,evaluated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'GATE_PASSED',$12,$13,$14,$15,$16,$17,now())",
            )
            .bind(tenant)
            .bind(Uuid::new_v4())
            .bind(&request.command.resource_id)
            .bind(&receipt.release_digest)
            .bind(&receipt.gate_id)
            .bind(&receipt.gate_version)
            .bind(&receipt.definition_digest)
            .bind(evidence_digest)
            .bind(&receipt.rollback_artifact_digest)
            .bind(&receipt.canary_plan_digest)
            .bind(serde_json::to_value(&request.approval_ids).map_err(|_| IncidentAuthorityError::RequestInvalid)?)
            .bind(&binding.action_hash)
            .bind(binding.ledger_execution_id)
            .bind(&binding.fence_digest)
            .bind(&binding.policy_decision_digest)
            .bind(&binding.authorization_evidence_ref)
            .bind(&binding.authorization_evidence_digest)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            sqlx::query(
                "INSERT INTO release_gate_certificates \
                 (tenant_id,certificate_id,release_id,receipt,receipt_digest,key_id,valid_from,\
                  valid_until,engine_certificate_only,production_closure,issued_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,false,now())",
            )
            .bind(tenant)
            .bind(receipt.certificate_id)
            .bind(&request.command.resource_id)
            .bind(
                serde_json::to_value(receipt)
                    .map_err(|_| IncidentAuthorityError::RequestInvalid)?,
            )
            .bind(canonical_digest(receipt)?)
            .bind(&receipt.key_id)
            .bind(receipt.valid_from)
            .bind(receipt.valid_until)
            .execute(&mut **tx)
            .await
            .map_err(|_| IncidentAuthorityError::StateConflict)?;
            Ok("GATE_PASSED".into())
        }
        IncidentAuthorityOperation::StartCanary => {
            require_release_certificate_binding(
                tx,
                tenant,
                &request.command.resource_id,
                payload,
                true,
            )
            .await?;
            update_release_state(
                tx,
                tenant,
                &request.command.resource_id,
                "GATE_PASSED",
                "CANARY_RUNNING",
            )
            .await?;
            append_canary_event(tx, tenant, request, binding, "CANARY_STARTED").await?;
            Ok("CANARY_RUNNING".into())
        }
        IncidentAuthorityOperation::RecordCanary => {
            require_release_certificate_binding(
                tx,
                tenant,
                &request.command.resource_id,
                payload,
                false,
            )
            .await?;
            let passed = payload.get("passed").and_then(Value::as_bool) == Some(true);
            let state = if passed {
                "CANARY_PASSED"
            } else {
                "ROLLBACK_REQUIRED"
            };
            update_release_state(
                tx,
                tenant,
                &request.command.resource_id,
                "CANARY_RUNNING",
                state,
            )
            .await?;
            append_canary_event(tx, tenant, request, binding, state).await?;
            Ok(state.into())
        }
        IncidentAuthorityOperation::RollbackRelease => {
            require_release_digest_binding(tx, tenant, &request.command.resource_id, payload)
                .await?;
            update_release_state_any(
                tx,
                tenant,
                &request.command.resource_id,
                &[
                    "GATE_PASSED",
                    "CANARY_RUNNING",
                    "CANARY_PASSED",
                    "ROLLBACK_REQUIRED",
                ],
                "ROLLED_BACK",
            )
            .await?;
            append_canary_event(tx, tenant, request, binding, "ROLLED_BACK").await?;
            Ok("ROLLED_BACK".into())
        }
        _ => Err(IncidentAuthorityError::RequestInvalid),
    }
}

async fn require_release_certificate_binding(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    release_id: &str,
    payload: &Map<String, Value>,
    require_canary_plan: bool,
) -> Result<(), IncidentAuthorityError> {
    let row = sqlx::query(
        "SELECT r.release_digest,r.canary_plan_digest,c.certificate_id \
         FROM release_gate_runs r JOIN release_gate_certificates c \
           ON c.tenant_id=r.tenant_id AND c.release_id=r.release_id \
         WHERE r.tenant_id=$1 AND r.release_id=$2",
    )
    .bind(tenant)
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
    .ok_or(IncidentAuthorityError::EvidenceMissing)?;
    if row.get::<String, _>("release_digest") != required_string(payload, "release_digest")?
        || row.get::<Uuid, _>("certificate_id") != parse_uuid_field(payload, "certificate_id")?
        || require_canary_plan
            && row.get::<String, _>("canary_plan_digest")
                != required_string(payload, "canary_plan_digest")?
    {
        return Err(IncidentAuthorityError::EvidenceMissing);
    }
    Ok(())
}

async fn require_release_digest_binding(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    release_id: &str,
    payload: &Map<String, Value>,
) -> Result<(), IncidentAuthorityError> {
    let release_digest = sqlx::query_scalar::<_, String>(
        "SELECT release_digest FROM release_gate_runs WHERE tenant_id=$1 AND release_id=$2",
    )
    .bind(tenant)
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
    .ok_or(IncidentAuthorityError::EvidenceMissing)?;
    if release_digest != required_string(payload, "release_digest")? {
        return Err(IncidentAuthorityError::EvidenceMissing);
    }
    Ok(())
}

async fn update_incident(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    incident_id: Uuid,
    status: &str,
    owner: Option<&str>,
    severity: Option<&str>,
    resource_version: i64,
) -> Result<(), IncidentAuthorityError> {
    let updated = sqlx::query(
        "UPDATE incidents SET status=$3,owner=COALESCE($4,owner),severity=COALESCE($5,severity),\
         resource_version=$6,updated_at=now() WHERE tenant_id=$1 AND incident_id=$2",
    )
    .bind(tenant)
    .bind(incident_id)
    .bind(status)
    .bind(owner)
    .bind(severity)
    .bind(resource_version)
    .execute(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::StateConflict)?;
    if updated.rows_affected() != 1 {
        return Err(IncidentAuthorityError::StateConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_timeline(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    incident_id: Uuid,
    request: &IncidentExecutorRequest,
    binding: &IncidentExecutionBinding,
    from_status: Option<&str>,
    to_status: &str,
    reason_code: &str,
) -> Result<(), IncidentAuthorityError> {
    let sequence = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(max(sequence),0)+1 FROM incident_timeline \
         WHERE tenant_id=$1 AND incident_id=$2",
    )
    .bind(tenant)
    .bind(incident_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
    sqlx::query(
        "INSERT INTO incident_timeline \
         (tenant_id,incident_id,event_id,sequence,event_type,from_status,to_status,actor_subject,\
          reason_code,payload_digest,action_hash,ledger_execution_id,fence_digest,\
          policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,occurred_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,now())",
    )
    .bind(tenant)
    .bind(incident_id)
    .bind(Uuid::new_v4())
    .bind(sequence)
    .bind(request.command.operation.as_str())
    .bind(from_status)
    .bind(to_status)
    .bind(&request.actor_subject)
    .bind(reason_code)
    .bind(canonical_digest(&request.command.payload)?)
    .bind(&binding.action_hash)
    .bind(binding.ledger_execution_id)
    .bind(&binding.fence_digest)
    .bind(&binding.policy_decision_digest)
    .bind(&binding.authorization_evidence_ref)
    .bind(&binding.authorization_evidence_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::StateConflict)?;
    Ok(())
}

async fn update_release_state(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    release_id: &str,
    from: &str,
    to: &str,
) -> Result<(), IncidentAuthorityError> {
    let updated = sqlx::query(
        "UPDATE release_gate_runs SET state=$4,updated_at=now() \
         WHERE tenant_id=$1 AND release_id=$2 AND state=$3",
    )
    .bind(tenant)
    .bind(release_id)
    .bind(from)
    .bind(to)
    .execute(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::StateConflict)?;
    if updated.rows_affected() != 1 {
        return Err(IncidentAuthorityError::StateConflict);
    }
    Ok(())
}

async fn update_release_state_any(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    release_id: &str,
    from: &[&str],
    to: &str,
) -> Result<(), IncidentAuthorityError> {
    let updated = sqlx::query(
        "UPDATE release_gate_runs SET state=$4,updated_at=now() \
         WHERE tenant_id=$1 AND release_id=$2 AND state=ANY($3)",
    )
    .bind(tenant)
    .bind(release_id)
    .bind(from)
    .bind(to)
    .execute(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::StateConflict)?;
    if updated.rows_affected() != 1 {
        return Err(IncidentAuthorityError::StateConflict);
    }
    Ok(())
}

async fn append_canary_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &IncidentExecutorRequest,
    binding: &IncidentExecutionBinding,
    event_type: &str,
) -> Result<(), IncidentAuthorityError> {
    sqlx::query(
        "INSERT INTO release_canary_events \
         (tenant_id,event_id,release_id,event_type,payload,payload_digest,actor_subject,\
          approval_ids,action_hash,ledger_execution_id,fence_digest,occurred_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(&request.command.resource_id)
    .bind(event_type)
    .bind(&request.command.payload)
    .bind(canonical_digest(&request.command.payload)?)
    .bind(&request.actor_subject)
    .bind(
        serde_json::to_value(&request.approval_ids)
            .map_err(|_| IncidentAuthorityError::RequestInvalid)?,
    )
    .bind(&binding.action_hash)
    .bind(binding.ledger_execution_id)
    .bind(&binding.fence_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| IncidentAuthorityError::StateConflict)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeTimelineEntry {
    pub event_id: Uuid,
    pub sequence: i64,
    pub event_type: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub actor_subject: String,
    pub reason_code: String,
    pub payload_digest: String,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub fence_digest: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeIncident {
    pub incident_id: Uuid,
    pub correlation_key: String,
    pub severity: String,
    pub status: String,
    pub task_id: Uuid,
    pub owner: String,
    pub safe_summary: String,
    pub scope: Value,
    pub evidence_refs: Value,
    pub legal_hold_id: String,
    pub resource_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub timeline: Vec<AuthoritativeTimelineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeIncidentPage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub items: Vec<AuthoritativeIncident>,
    pub next_after_incident_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct IncidentExecutor {
    store: PostgresIncidentAuthorityStore,
    effects: Arc<dyn IncidentEffectPort>,
    release_key_id: String,
    release_signing_key: Arc<SigningKey>,
    execution_lease_seconds: i64,
}

impl IncidentExecutor {
    pub fn new(
        store: PostgresIncidentAuthorityStore,
        effects: Arc<dyn IncidentEffectPort>,
        release_key_id: String,
        release_signing_key: SigningKey,
        execution_lease_seconds: i64,
    ) -> Result<Self, IncidentAuthorityError> {
        if !identifier(&release_key_id, 128) || !(15..=300).contains(&execution_lease_seconds) {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            effects,
            release_key_id,
            release_signing_key: Arc::new(release_signing_key),
            execution_lease_seconds,
        })
    }

    pub async fn execute(
        &self,
        binding: IncidentExecutionBinding,
        request: IncidentExecutorRequest,
    ) -> Result<IncidentMutationResult, IncidentAuthorityError> {
        validate_execution(&binding, &request)?;
        let claim = match self
            .store
            .claim_execution(&binding, &request, self.execution_lease_seconds)
            .await?
        {
            ExecutionClaim::Completed(result) => return Ok(*result),
            ExecutionClaim::Claimed(claim) => claim,
        };
        let effect = self.effects.execute(&binding, &request).await?;
        validate_effect(&request, &binding, effect.as_ref())?;
        let release_receipt =
            if request.command.operation == IncidentAuthorityOperation::EvaluateRelease {
                Some(self.issue_release_receipt(&request)?)
            } else {
                None
            };
        self.store
            .finalize_execution(&binding, &request, &claim, effect, release_receipt)
            .await
    }

    pub async fn ready(&self) -> bool {
        self.effects.ready().await
    }

    fn issue_release_receipt(
        &self,
        request: &IncidentExecutorRequest,
    ) -> Result<ReleaseGateEngineReceipt, IncidentAuthorityError> {
        let payload = request
            .command
            .payload
            .as_object()
            .ok_or(IncidentAuthorityError::RequestInvalid)?;
        let definition = payload
            .get("definition")
            .and_then(Value::as_object)
            .ok_or(IncidentAuthorityError::RequestInvalid)?;
        let evidence = payload
            .get("evidence")
            .and_then(Value::as_array)
            .ok_or(IncidentAuthorityError::EvidenceMissing)?;
        let mut evidence_digests = BTreeMap::new();
        for item in evidence {
            let item = item
                .as_object()
                .ok_or(IncidentAuthorityError::EvidenceMissing)?;
            let control_id =
                string_field(item, "control_id").ok_or(IncidentAuthorityError::EvidenceMissing)?;
            let evidence_digest = string_field(item, "evidence_digest")
                .ok_or(IncidentAuthorityError::EvidenceMissing)?;
            evidence_digests.insert(control_id.into(), evidence_digest.into());
        }
        let valid_from = Utc::now();
        let valid_until = parse_time_field(payload, "valid_until")?;
        if valid_until <= valid_from || valid_until > valid_from + Duration::days(7) {
            return Err(IncidentAuthorityError::RequestInvalid);
        }
        let mut receipt = ReleaseGateEngineReceipt {
            schema_version: RELEASE_GATE_ENGINE_RECEIPT_SCHEMA.into(),
            certificate_id: Uuid::new_v4(),
            tenant_id: request.command.tenant_id,
            release_digest: required_string(payload, "release_digest")?.into(),
            gate_id: required_string(definition, "gate_id")?.into(),
            gate_version: required_string(definition, "version")?.into(),
            definition_digest: required_string(definition, "definition_digest")?.into(),
            evidence_digests,
            rollback_artifact_digest: required_string(payload, "rollback_artifact_digest")?.into(),
            canary_plan_digest: required_string(payload, "canary_plan_digest")?.into(),
            valid_from,
            valid_until,
            engine_certificate_only: true,
            production_closure: false,
            key_id: self.release_key_id.clone(),
            signature: String::new(),
        };
        receipt.signature = URL_SAFE_NO_PAD.encode(
            self.release_signing_key
                .sign(&receipt.signing_bytes()?)
                .to_bytes(),
        );
        Ok(receipt)
    }
}

#[derive(Debug)]
enum ExecutionClaim {
    Completed(Box<IncidentMutationResult>),
    Claimed(Uuid),
}

impl PostgresIncidentAuthorityStore {
    async fn claim_execution(
        &self,
        binding: &IncidentExecutionBinding,
        request: &IncidentExecutorRequest,
        lease_seconds: i64,
    ) -> Result<ExecutionClaim, IncidentAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(request)?;
        let request_value =
            serde_json::to_value(request).map_err(|_| IncidentAuthorityError::RequestInvalid)?;
        let expected_version = i64::try_from(binding.resource_version)
            .map_err(|_| IncidentAuthorityError::RequestInvalid)?;
        let claim = Uuid::new_v4();
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let ingress = sqlx::query(
            "SELECT state,principal_subject,principal_kind,principal_assertion_digest,envelope \
             FROM incident_action_ingress WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
        .ok_or(IncidentAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("principal_subject") != request.actor_subject
            || ingress.get::<String, _>("principal_kind") != request.actor_kind
            || ingress.get::<Option<String>, _>("principal_assertion_digest")
                != request.principal_assertion_digest
        {
            return Err(IncidentAuthorityError::PrincipalDenied);
        }
        let envelope: InboundEnvelope = serde_json::from_value(ingress.get("envelope"))
            .map_err(|_| IncidentAuthorityError::PrincipalDenied)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| IncidentAuthorityError::PrincipalDenied)?;
        let admitted_hash =
            action_hash(&action).map_err(|_| IncidentAuthorityError::PrincipalDenied)?;
        let expected_action_version = request.command.expected_resource_version.to_string();
        if admitted_hash.0 != binding.action_hash
            || action.action_id.0 != request.command.command_id.to_string()
            || action.task_id.0 != request.command.task_id.to_string()
            || action.current_state_version.as_deref() != Some(expected_action_version.as_str())
            // The admitted Canonical Action contains the complete executor request. Checking only
            // identifiers would let a runtime substitute operation, payload, approvals, or actor
            // claims while replaying a valid admitted action hash.
            || Value::Object(action.payload.data.clone()) != request_value
        {
            return Err(IncidentAuthorityError::PrincipalDenied);
        }
        sqlx::query(
            "INSERT INTO incident_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,action_hash,\
              ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,resource_id,resource_version,trace_id,\
              policy_decision_id,policy_decision_digest,authorization_evidence_ref,\
              authorization_evidence_digest,request,state,execution_owner,execution_lease_until) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'EXECUTING',$19,\
                     now()+make_interval(secs=>$20)) \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
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
        .bind(&request.command.resource_id)
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
        .map_err(|_| IncidentAuthorityError::IdempotencyConflict)?;
        let row = sqlx::query(
            "SELECT request_digest,action_id,task_id,action_hash,ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,\
                    resource_id,resource_version,trace_id,policy_decision_id,policy_decision_digest,\
                    authorization_evidence_ref,authorization_evidence_digest,request,state,\
                    safe_result,execution_owner,execution_lease_until \
             FROM incident_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command.command_id
            || row.get::<Uuid, _>("task_id") != request.command.task_id
            || row.get::<String, _>("action_hash") != binding.action_hash
            || row.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
            || row.get::<Uuid, _>("ledger_event_id") != binding.ledger_event_id
            || row.get::<String, _>("ledger_event_digest") != binding.ledger_event_digest
            || row.get::<String, _>("fence_digest") != binding.fence_digest
            || row.get::<String, _>("resource_id") != request.command.resource_id
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
            return Err(IncidentAuthorityError::IdempotencyConflict);
        }
        let state: String = row.get("state");
        if state == "SUCCEEDED" {
            let result = row
                .get::<Option<Value>, _>("safe_result")
                .ok_or(IncidentAuthorityError::OutcomeUnknown)
                .and_then(|value| {
                    serde_json::from_value(value)
                        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)
                })?;
            tx.commit()
                .await
                .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
            return Ok(ExecutionClaim::Completed(Box::new(result)));
        }
        if state != "EXECUTING" {
            return Err(IncidentAuthorityError::OutcomeUnknown);
        }
        let owner: Uuid = row.get("execution_owner");
        if owner != claim {
            let lease_until: DateTime<Utc> = row.get("execution_lease_until");
            if lease_until > Utc::now() {
                return Err(IncidentAuthorityError::OutcomeUnknown);
            }
            let claimed = sqlx::query(
                "UPDATE incident_authority_executions SET execution_owner=$3,\
                 execution_lease_until=now()+make_interval(secs=>$4),updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING' \
                   AND execution_lease_until<=now()",
            )
            .bind(tenant)
            .bind(&binding.idempotency_key)
            .bind(claim)
            .bind(lease_seconds as f64)
            .execute(&mut *tx)
            .await
            .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
            if claimed.rows_affected() != 1 {
                return Err(IncidentAuthorityError::OutcomeUnknown);
            }
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM incident_resource_versions \
             WHERE tenant_id=$1 AND resource_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.resource_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current != expected_version
            || request.command.expected_resource_version != binding.resource_version
        {
            return Err(IncidentAuthorityError::StateConflict);
        }
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        Ok(ExecutionClaim::Claimed(claim))
    }

    async fn finalize_execution(
        &self,
        binding: &IncidentExecutionBinding,
        request: &IncidentExecutorRequest,
        claim: &Uuid,
        effect: Option<ExternalEffectReceipt>,
        release_receipt: Option<ReleaseGateEngineReceipt>,
    ) -> Result<IncidentMutationResult, IncidentAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let expected = i64::try_from(binding.resource_version)
            .map_err(|_| IncidentAuthorityError::RequestInvalid)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let execution = sqlx::query(
            "SELECT state,execution_owner,execution_lease_until FROM incident_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        if execution.get::<String, _>("state") != "EXECUTING"
            || execution.get::<Uuid, _>("execution_owner") != *claim
            || execution.get::<DateTime<Utc>, _>("execution_lease_until") <= Utc::now()
        {
            return Err(IncidentAuthorityError::OutcomeUnknown);
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM incident_resource_versions \
             WHERE tenant_id=$1 AND resource_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.resource_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current != expected {
            return Err(IncidentAuthorityError::StateConflict);
        }
        let next = current
            .checked_add(1)
            .ok_or(IncidentAuthorityError::StateConflict)?;
        let (state, release_receipt) = apply_operation(
            &mut tx,
            tenant,
            request,
            binding,
            effect.as_ref(),
            release_receipt,
            next,
        )
        .await?;
        sqlx::query(
            "INSERT INTO incident_resource_versions \
             (tenant_id,resource_id,resource_version,action_hash,ledger_execution_id,fence_digest) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,resource_id) DO UPDATE SET \
             resource_version=EXCLUDED.resource_version,action_hash=EXCLUDED.action_hash,\
             ledger_execution_id=EXCLUDED.ledger_execution_id,fence_digest=EXCLUDED.fence_digest,\
             updated_at=now()",
        )
        .bind(tenant)
        .bind(&request.command.resource_id)
        .bind(next)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        let event_id = Uuid::new_v4();
        let recorded_at = Utc::now();
        let event_payload = json!({
            "schema_version": "agenttrust.incident-release-evidence.v1",
            "event_id": event_id,
            "tenant_id": tenant,
            "task_id": request.command.task_id,
            "resource_id": request.command.resource_id,
            "command_id": request.command.command_id,
            "operation": request.command.operation,
            "actor_subject": request.actor_subject,
            "actor_kind": request.actor_kind,
            "principal_assertion_digest": request.principal_assertion_digest,
            "approval_ids": request.approval_ids,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "ledger_event_id": binding.ledger_event_id,
            "ledger_event_digest": binding.ledger_event_digest,
            "fence_digest": binding.fence_digest,
            "policy_decision_id": binding.policy_decision_id,
            "policy_decision_digest": binding.policy_decision_digest,
            "authorization_evidence_ref": binding.authorization_evidence_ref,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "resource_version": next,
            "state": state,
            "effect_receipt": effect,
            "release_receipt": release_receipt,
            "trace_id": binding.trace_id,
            "recorded_at": recorded_at,
        });
        let event_digest = canonical_digest(&event_payload)?;
        let evidence_outbox_ref =
            format!("outbox://incident-evidence/{tenant}/{event_id}/sha256:{event_digest}");
        sqlx::query(
            "INSERT INTO incident_evidence_events \
             (tenant_id,event_id,task_id,resource_id,event_type,actor_subject,payload,payload_digest,\
              evidence_outbox_ref,action_hash,ledger_execution_id,fence_digest,\
              policy_decision_digest,authorization_evidence_ref) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(request.command.task_id)
        .bind(&request.command.resource_id)
        .bind(request.command.operation.as_str())
        .bind(&request.actor_subject)
        .bind(&event_payload)
        .bind(&event_digest)
        .bind(&evidence_outbox_ref)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .execute(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        sqlx::query(
            "INSERT INTO incident_evidence_outbox \
             (tenant_id,event_id,task_id,event_type,idempotency_key,payload,payload_digest) \
             VALUES ($1,$2,$3,'INCIDENT_RELEASE_EVIDENCE',$4,$5,$6)",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(request.command.task_id)
        .bind(format!("incident-evidence:{event_id}"))
        .bind(&event_payload)
        .bind(&event_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        let result_digest = canonical_digest(&json!({
            "state": state,
            "effect": effect,
            "release": release_receipt,
            "resource_version": next,
            "event_digest": event_digest,
        }))?;
        let result = IncidentMutationResult {
            schema_version: INCIDENT_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            resource_id: request.command.resource_id.clone(),
            operation: request.command.operation,
            resource_version: u64::try_from(next)
                .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?,
            state,
            result_digest,
            evidence_outbox_ref,
            effect_receipt: effect
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?,
            release_receipt,
        };
        let result_value =
            serde_json::to_value(&result).map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        let result_digest = canonical_digest(&result)?;
        let updated = sqlx::query(
            "UPDATE incident_authority_executions SET state='SUCCEEDED',safe_result=$4,\
             safe_result_digest=$5,execution_lease_until=NULL,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND execution_owner=$3 \
               AND state='EXECUTING'",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(claim)
        .bind(&result_value)
        .bind(&result_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        if updated.rows_affected() != 1 {
            return Err(IncidentAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| IncidentAuthorityError::OutcomeUnknown)?;
        Ok(result)
    }
}
