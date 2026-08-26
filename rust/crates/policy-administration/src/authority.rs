//! Production Policy Administration authority and fenced lifecycle executor.
//!
//! Human-authenticated commands are first normalized to Canonical Action IR and submitted to the
//! durable orchestrator.  The database mutation endpoint is a separate runtime-only scope and
//! accepts the ledger execution, action hash, resource version and fence binding produced after
//! PEP authorization.  No HTTP administration request writes policy state directly.

use crate::principal::VerifiedHumanPrincipal;
use crate::{
    ImpactReport, POLICY_ADMIN_SCHEMA_VERSION, PolicyBundle, PolicyCompiler, PolicySource,
    SimulationEngine, StaticAnalyzer,
};
use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent,
    PEP_POLICY_ACTIVATION_ACK_KEY_USAGE, POLICY_ACTIVATION_REQUEST_SCHEMA_VERSION,
    PepPolicyActivationAcknowledgement, PolicyActivationRequest, PolicyEnvironment,
    ResourceSelector, RiskContext, RiskLevel, SchemaVersion, SignedPolicyBundle, StepId, TaskId,
    TenantId, ToolId, ToolRef, ToolVersion,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const POLICY_COMMAND_SCHEMA: &str = "agenttrust.policy-command.v1";
pub const POLICY_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.policy-executor-request.v1";
pub const POLICY_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.policy-action-receipt.v1";
pub const POLICY_MUTATION_RESULT_SCHEMA: &str = "agenttrust.policy-mutation-result.v1";
pub const POLICY_AUTHORITY_READINESS_SCHEMA: &str = "agenttrust.policy-admin-readiness.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyAuthorityError {
    #[error("POLICY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("POLICY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("POLICY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("POLICY_STATE_CONFLICT")]
    StateConflict,
    #[error("POLICY_REVIEW_SEPARATION_REQUIRED")]
    ReviewSeparationRequired,
    #[error("POLICY_VALIDATION_BLOCKED")]
    ValidationBlocked,
    #[error("POLICY_NOT_FOUND")]
    NotFound,
    #[error("POLICY_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("POLICY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("POLICY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyOperation {
    CreateDraft,
    Validate,
    Simulate,
    ShadowEvaluate,
    ImpactAnalyze,
    Approve,
    Sign,
    Promote,
    Rollback,
    Deprecate,
    CreateException,
    RevokeException,
}

impl PolicyOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreateDraft => "CREATE_DRAFT",
            Self::Validate => "VALIDATE",
            Self::Simulate => "SIMULATE",
            Self::ShadowEvaluate => "SHADOW_EVALUATE",
            Self::ImpactAnalyze => "IMPACT_ANALYZE",
            Self::Approve => "APPROVE",
            Self::Sign => "SIGN",
            Self::Promote => "PROMOTE",
            Self::Rollback => "ROLLBACK",
            Self::Deprecate => "DEPRECATE",
            Self::CreateException => "CREATE_EXCEPTION",
            Self::RevokeException => "REVOKE_EXCEPTION",
        }
    }

    fn required_role(self) -> &'static str {
        match self {
            Self::CreateDraft
            | Self::Validate
            | Self::Simulate
            | Self::ShadowEvaluate
            | Self::ImpactAnalyze => "policy-author",
            Self::Approve => "policy-reviewer",
            Self::Sign
            | Self::Promote
            | Self::Rollback
            | Self::Deprecate
            | Self::CreateException
            | Self::RevokeException => "policy-admin",
        }
    }

    fn risk(self) -> RiskLevel {
        match self {
            Self::CreateDraft
            | Self::Validate
            | Self::Simulate
            | Self::ShadowEvaluate
            | Self::ImpactAnalyze => RiskLevel::Medium,
            Self::Approve | Self::Sign => RiskLevel::High,
            Self::Promote
            | Self::Rollback
            | Self::Deprecate
            | Self::CreateException
            | Self::RevokeException => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub policy_id: String,
    pub operation: PolicyOperation,
    pub expected_resource_version: u64,
    pub payload: Value,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionReceipt {
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
pub struct PolicyExecutorRequest {
    pub schema_version: String,
    pub command: PolicyCommandRequest,
    pub principal_subject: String,
    pub principal_assertion_digest: String,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyExecutionBinding {
    pub tenant_id: TenantId,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub fence_digest: String,
    pub resource_version: u64,
    pub idempotency_key: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub policy_id: String,
    pub operation: PolicyOperation,
    pub resource_version: u64,
    pub state: String,
    pub artifact_digest: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePolicy {
    pub policy_id: String,
    pub revision: i64,
    pub lifecycle_state: String,
    pub source_digest: String,
    pub author_subject: String,
    pub active_bundle_digest: Option<String>,
    pub active_environment: Option<String>,
    pub resource_version: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePolicyPage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub items: Vec<AuthoritativePolicy>,
    pub next_after_policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePolicyArtifactPage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub policy_id: String,
    pub artifact_type: String,
    pub items: Vec<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyArtifactType {
    Sources,
    Analyses,
    Reviews,
    Simulations,
    ImpactReports,
    Promotions,
    Exceptions,
}

impl PolicyArtifactType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sources => "SOURCES",
            Self::Analyses => "ANALYSES",
            Self::Reviews => "REVIEWS",
            Self::Simulations => "SIMULATIONS",
            Self::ImpactReports => "IMPACT_REPORTS",
            Self::Promotions => "PROMOTIONS",
            Self::Exceptions => "EXCEPTIONS",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
}

impl PolicyAuthorityConfig {
    pub fn validate(&self) -> Result<(), PolicyAuthorityError> {
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
            Err(PolicyAuthorityError::ConfigurationInvalid)
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedPolicyIngress {
    pub envelope: InboundEnvelope,
    pub receipt: Option<PolicyActionReceipt>,
}

#[async_trait]
pub trait PolicyOrchestratorPort: Send + Sync {
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<PolicyActionReceipt, PolicyAuthorityError>;
}

#[async_trait]
pub trait PolicyActivationPort: Send + Sync {
    async fn ready(&self) -> bool;

    async fn activate(
        &self,
        request: &PolicyActivationRequest,
    ) -> Result<PepPolicyActivationAcknowledgement, PolicyAuthorityError>;
}

#[derive(Clone)]
pub struct HttpPepPolicyActivationClient {
    client: reqwest::Client,
    endpoint: url::Url,
    readiness_endpoint: url::Url,
    token_file: std::path::PathBuf,
    verifying_key: VerifyingKey,
}

impl HttpPepPolicyActivationClient {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: std::path::PathBuf,
        verifying_key: VerifyingKey,
    ) -> Result<Self, PolicyAuthorityError> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/v1/policies/activations"
            || !token_file.is_absolute()
        {
            return Err(PolicyAuthorityError::ConfigurationInvalid);
        }
        activation_token(&token_file)?;
        let mut readiness_endpoint = endpoint.clone();
        readiness_endpoint.set_path("/ready");
        Ok(Self {
            client,
            endpoint,
            readiness_endpoint,
            token_file,
            verifying_key,
        })
    }
}

#[async_trait]
impl PolicyActivationPort for HttpPepPolicyActivationClient {
    async fn ready(&self) -> bool {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.client.get(self.readiness_endpoint.clone()).send(),
        )
        .await;
        let Ok(Ok(response)) = response else {
            return false;
        };
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return false;
        }
        bounded_http_body(response, 65_536)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_some_and(|value| {
                value.get("schema_version").and_then(Value::as_str)
                    == Some("agenttrust.pep-readiness.v1")
                    && value.get("ready").and_then(Value::as_bool) == Some(true)
            })
    }

    async fn activate(
        &self,
        request: &PolicyActivationRequest,
    ) -> Result<PepPolicyActivationAcknowledgement, PolicyAuthorityError> {
        if self.endpoint.path() != "/v1/policies/activations" {
            return Err(PolicyAuthorityError::ConfigurationInvalid);
        }
        request
            .validate()
            .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(activation_token(&self.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &request.tenant_id.0)
            .header("X-AgentTrust-Scope", "pep:policy-activate")
            .header("Idempotency-Key", &request.idempotency_key)
            .json(request)
            .send()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 131_072)
        {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let bytes = bounded_http_body(response, 131_072).await?;
        if bytes.is_empty() {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let acknowledgement: PepPolicyActivationAcknowledgement =
            serde_json::from_slice(&bytes).map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        acknowledgement
            .verify(&self.verifying_key)
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if acknowledgement.key_usage != PEP_POLICY_ACTIVATION_ACK_KEY_USAGE
            || acknowledgement.activation_id != request.activation_id
            || acknowledgement.idempotency_key != request.idempotency_key
            || acknowledgement.tenant_id != request.tenant_id
            || acknowledgement.policy_id != request.policy_id
            || acknowledgement.environment != request.environment
            || acknowledgement.sequence != request.sequence
            || acknowledgement.bundle_digest != request.bundle.bundle_digest
            || !acknowledgement.active
        {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        Ok(acknowledgement)
    }
}

async fn bounded_http_body(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PolicyAuthorityError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Clone)]
pub struct PolicyIngressAuthority {
    store: PostgresPolicyAuthorityStore,
    orchestrator: Arc<dyn PolicyOrchestratorPort>,
    config: PolicyAuthorityConfig,
}

impl PolicyIngressAuthority {
    pub fn new(
        store: PostgresPolicyAuthorityStore,
        orchestrator: Arc<dyn PolicyOrchestratorPort>,
        config: PolicyAuthorityConfig,
    ) -> Result<Self, PolicyAuthorityError> {
        config.validate()?;
        Ok(Self {
            store,
            orchestrator,
            config,
        })
    }

    pub async fn submit(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: PolicyCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<PolicyActionReceipt, PolicyAuthorityError> {
        validate_command(principal, &request, request_digest, idempotency_key)?;
        let tenant = TenantId(request.tenant_id.to_string());
        let actual_version = self
            .store
            .current_resource_version(&tenant, &request.policy_id)
            .await?;
        if actual_version != request.expected_resource_version {
            return Err(PolicyAuthorityError::StateConflict);
        }
        let envelope = canonical_policy_action(principal, &request, &self.config)?;
        let prepared = self
            .store
            .prepare_ingress(
                principal,
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
        self.store.ready().await
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativePolicyPage, PolicyAuthorityError> {
        self.store.authoritative_page(tenant, after, limit).await
    }

    pub async fn authoritative_artifacts(
        &self,
        tenant: &TenantId,
        policy_id: &str,
        artifact_type: PolicyArtifactType,
        limit: i64,
    ) -> Result<AuthoritativePolicyArtifactPage, PolicyAuthorityError> {
        self.store
            .authoritative_artifacts(tenant, policy_id, artifact_type, limit)
            .await
    }

    pub async fn expire_due_exceptions(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<u64, PolicyAuthorityError> {
        self.store.expire_due_exceptions(tenant, limit).await
    }
}

fn validate_command(
    principal: &VerifiedHumanPrincipal,
    request: &PolicyCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), PolicyAuthorityError> {
    if request.schema_version != POLICY_COMMAND_SCHEMA
        || request.tenant_id.to_string() != principal.tenant_id.0
        || request.command_id.is_nil()
        || !identifier(&request.policy_id, 256)
        || !principal.roles.contains(request.operation.required_role())
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || request.payload.as_object().is_none()
        || serde_json::to_vec(&request.payload).map_or(true, |value| value.len() > 1_048_576)
        || request.requested_at > Utc::now() + Duration::minutes(5)
        || request.requested_at < Utc::now() - Duration::hours(24)
        || !command_payload_shape(request)
    {
        return Err(PolicyAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn command_payload_shape(request: &PolicyCommandRequest) -> bool {
    let payload = match request.payload.as_object() {
        Some(value) => value,
        None => return false,
    };
    match request.operation {
        PolicyOperation::CreateDraft => payload.len() == 1 && payload.get("source").is_some(),
        PolicyOperation::Validate => payload.is_empty(),
        PolicyOperation::Simulate | PolicyOperation::ShadowEvaluate => {
            payload.len() == 2
                && payload
                    .get("baseline_bundle_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("actions")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty() && items.len() <= 10_000)
        }
        PolicyOperation::Approve => {
            payload.len() == 2
                && payload.get("decision").and_then(Value::as_str) == Some("APPROVE")
                && payload
                    .get("review_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
        }
        PolicyOperation::Sign => payload.is_empty(),
        PolicyOperation::Promote => {
            payload.len() == 3
                && payload
                    .get("bundle_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("impact_report_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("environment")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        matches!(value, "DEV" | "STAGING" | "CANARY" | "PRODUCTION")
                    })
        }
        PolicyOperation::Rollback => {
            payload.len() == 3
                && payload
                    .get("target_bundle_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("reason_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("environment")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        matches!(value, "DEV" | "STAGING" | "CANARY" | "PRODUCTION")
                    })
        }
        PolicyOperation::Deprecate => {
            payload.len() == 2
                && payload
                    .get("bundle_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("reason_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
        }
        PolicyOperation::ImpactAnalyze => {
            payload.len() == 1
                && payload
                    .get("simulation_id")
                    .and_then(Value::as_str)
                    .is_some_and(canonical_uuid)
        }
        PolicyOperation::CreateException => {
            payload.len() == 7
                && payload
                    .get("exception_id")
                    .and_then(Value::as_str)
                    .is_some_and(canonical_uuid)
                && payload
                    .get("owner_subject")
                    .and_then(Value::as_str)
                    .is_some_and(|value| identifier(value, 256))
                && payload
                    .get("scope")
                    .and_then(Value::as_array)
                    .is_some_and(|values| !values.is_empty() && values.len() <= 128)
                && payload
                    .get("reason_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && payload
                    .get("compensating_controls")
                    .and_then(Value::as_array)
                    .is_some_and(|values| !values.is_empty() && values.len() <= 64)
                && payload
                    .get("approval_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|values| (2..=64).contains(&values.len()))
                && payload
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .is_some()
        }
        PolicyOperation::RevokeException => {
            payload.len() == 2
                && payload
                    .get("exception_id")
                    .and_then(Value::as_str)
                    .is_some_and(canonical_uuid)
                && payload
                    .get("reason_digest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
        }
    }
}

fn canonical_policy_action(
    principal: &VerifiedHumanPrincipal,
    request: &PolicyCommandRequest,
    config: &PolicyAuthorityConfig,
) -> Result<InboundEnvelope, PolicyAuthorityError> {
    let now = Utc::now();
    let tenant = TenantId(request.tenant_id.to_string());
    let task_id = TaskId::new();
    let step_id = StepId::new();
    let executor = PolicyExecutorRequest {
        schema_version: POLICY_EXECUTOR_REQUEST_SCHEMA.into(),
        command: request.clone(),
        principal_subject: principal.subject.clone(),
        principal_assertion_digest: principal.assertion_digest.clone(),
        approval_ids: principal.approval_ids.clone(),
    };
    let data = serde_json::to_value(&executor)
        .map_err(|_| PolicyAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let plan_hash = sha256(
        &serde_jcs::to_vec(&json!({
            "operation": request.operation,
            "policy_id": request.policy_id,
            "resource_version": request.expected_resource_version,
            "payload": request.payload,
        }))
        .map_err(|_| PolicyAuthorityError::RequestInvalid)?,
    );
    let mut extensions = std::collections::BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    extensions.insert(
        "x-human-principal-assertion-digest".into(),
        Value::String(principal.assertion_digest.clone()),
    );
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(request.command_id.to_string()),
        task_id: task_id.clone(),
        step_id,
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "policy-administration-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: principal.subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-policy-lifecycle".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: format!("human-assertion://{}", principal.jti),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: sha256(
                &serde_jcs::to_vec(request).map_err(|_| PolicyAuthorityError::RequestInvalid)?,
            ),
            operation: request.operation.as_str().to_ascii_lowercase(),
            justification_code: "POLICY_GOVERNANCE".into(),
            safe_summary: Some(format!(
                "{} policy {}",
                request.operation.as_str(),
                request.policy_id
            )),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "policy.lifecycle.mutation.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator: format!("policy/{}", request.policy_id),
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: false,
        },
        current_state_version: Some(request.expected_resource_version.to_string()),
        risk: RiskContext {
            declared_risk: request.operation.risk(),
            trajectory_risk_ref: None,
            scope_delta: 1,
            automation_allowed: false,
        },
        data: DataContext {
            classification: DataClassification::Confidential,
            jurisdiction: config.region.clone(),
            export_constraints: vec!["TENANT_BOUND".into(), "POLICY_SOURCE".into()],
        },
        expected_outcome: ExpectedOutcome {
            metric: "policy_lifecycle_state_persisted".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "policy/".into(),
            operations: vec![request.operation.as_str().to_ascii_lowercase()],
        }],
        requested_at: request.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("policy.lifecycle.mutation.v1", "1");
    let action =
        normalize(draft, &normalization).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    let payload = serde_json::to_vec(&action).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    let payload_hash = sha256(&payload);
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
            quota_profile: "policy-administration".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: None,
        received_at: now,
        payload,
        payload_hash,
    })
}

#[derive(Clone)]
pub struct PostgresPolicyAuthorityStore {
    pool: PgPool,
}

impl PostgresPolicyAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    pub async fn current_resource_version(
        &self,
        tenant: &TenantId,
        policy_id: &str,
    ) -> Result<u64, PolicyAuthorityError> {
        let mut tx = self.begin_tenant(tenant).await?;
        let value = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM policy_resource_versions WHERE tenant_id=$1 AND policy_id=$2",
        )
        .bind(parse_tenant(tenant)?)
        .bind(policy_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        u64::try_from(value).map_err(|_| PolicyAuthorityError::DependencyUnavailable)
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, PolicyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(tenant_uuid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_ingress(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: &PolicyCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        mut envelope: InboundEnvelope,
    ) -> Result<PreparedPolicyIngress, PolicyAuthorityError> {
        envelope.idempotency_key = Some(idempotency_key.to_string());
        let tenant = TenantId(request.tenant_id.to_string());
        let tenant_uuid = request.tenant_id;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let envelope_value =
            serde_json::to_value(&envelope).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let mut tx = self.begin_tenant(&tenant).await?;
        sqlx::query(
            "INSERT INTO policy_principal_assertion_replay \
             (tenant_id,jti,assertion_digest,request_digest,expires_at) VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (tenant_id,jti) DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(Uuid::parse_str(&principal.jti).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
        .bind(&principal.assertion_digest)
        .bind(request_digest)
        .bind(principal.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let replay = sqlx::query(
            "SELECT assertion_digest,request_digest FROM policy_principal_assertion_replay \
             WHERE tenant_id=$1 AND jti=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(Uuid::parse_str(&principal.jti).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        if replay.get::<String, _>("assertion_digest") != principal.assertion_digest
            || replay.get::<String, _>("request_digest") != request_digest
        {
            return Err(PolicyAuthorityError::IdempotencyConflict);
        }
        sqlx::query(
            "INSERT INTO policy_action_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,principal_subject,principal_assertion_digest,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PREPARED') ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(Uuid::parse_str(&action.action_id.0).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
        .bind(Uuid::parse_str(&action.task_id.0).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
        .bind(&principal.subject)
        .bind(&principal.assertion_digest)
        .bind(&envelope_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let row = sqlx::query(
            "SELECT request_digest,envelope,state,receipt FROM policy_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let stored_envelope: Value = row.get("envelope");
        if row.get::<String, _>("request_digest") != request_digest
            || stored_envelope != envelope_value
        {
            return Err(PolicyAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("receipt")
            .map(|value| serde_json::from_value(value))
            .transpose()
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        Ok(PreparedPolicyIngress { envelope, receipt })
    }

    pub async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &PolicyActionReceipt,
    ) -> Result<PolicyActionReceipt, PolicyAuthorityError> {
        if receipt.schema_version != POLICY_ACTION_RECEIPT_SCHEMA
            || !receipt.accepted
            || !receipt.execution_pending
            || !digest(&receipt.ingress_digest)
            || !digest(&receipt.ledger_evidence_digest)
            || receipt.ledger_evidence_ref.is_empty()
        {
            return Err(PolicyAuthorityError::DependencyUnavailable);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let value = serde_json::to_value(receipt)
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,state,receipt FROM policy_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("action_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(PolicyAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("receipt") {
            if existing != value {
                return Err(PolicyAuthorityError::IdempotencyConflict);
            }
        } else {
            sqlx::query(
                "UPDATE policy_action_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        }
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativePolicyPage, PolicyAuthorityError> {
        if !(1..=200).contains(&limit) || after.is_some_and(|value| !identifier(value, 256)) {
            return Err(PolicyAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT s.policy_id,s.revision,s.lifecycle_state,s.source_digest,s.author_subject,\
                    p.bundle_digest AS active_bundle_digest,p.environment AS active_environment,\
                    v.resource_version,v.updated_at \
             FROM policy_sources s \
             JOIN policy_resource_versions v ON v.tenant_id=s.tenant_id AND v.policy_id=s.policy_id \
             LEFT JOIN LATERAL (SELECT bundle_digest,environment FROM policy_promotions \
               WHERE tenant_id=s.tenant_id AND policy_id=s.policy_id AND state='ACTIVE' \
               ORDER BY sequence DESC LIMIT 1) p ON true \
             WHERE s.tenant_id=$1 AND s.revision=(SELECT max(s2.revision) FROM policy_sources s2 \
               WHERE s2.tenant_id=s.tenant_id AND s2.policy_id=s.policy_id) \
               AND ($2::text IS NULL OR s.policy_id>$2) ORDER BY s.policy_id LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let mut items = rows
            .iter()
            .take(limit as usize)
            .map(|row| AuthoritativePolicy {
                policy_id: row.get("policy_id"),
                revision: row.get("revision"),
                lifecycle_state: row.get("lifecycle_state"),
                source_digest: row.get("source_digest"),
                author_subject: row.get("author_subject"),
                active_bundle_digest: row.get("active_bundle_digest"),
                active_environment: row.get("active_environment"),
                resource_version: row.get("resource_version"),
                updated_at: row.get("updated_at"),
            })
            .collect::<Vec<_>>();
        let next_after_policy_id = (rows.len() > limit as usize)
            .then(|| items.last().map(|item| item.policy_id.clone()))
            .flatten();
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        Ok(AuthoritativePolicyPage {
            schema_version: "agenttrust.authoritative-policy-page.v1".into(),
            tenant_id: tenant.clone(),
            items: std::mem::take(&mut items),
            next_after_policy_id,
        })
    }

    pub async fn authoritative_artifacts(
        &self,
        tenant: &TenantId,
        policy_id: &str,
        artifact_type: PolicyArtifactType,
        limit: i64,
    ) -> Result<AuthoritativePolicyArtifactPage, PolicyAuthorityError> {
        if !identifier(policy_id, 256) || !(1..=100).contains(&limit) {
            return Err(PolicyAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let items = match artifact_type {
            PolicyArtifactType::Sources => sqlx::query_scalar::<_, Value>(
                "SELECT source_json FROM policy_sources WHERE tenant_id=$1 AND policy_id=$2 \
                 ORDER BY revision DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
            PolicyArtifactType::Analyses => sqlx::query_scalar::<_, Value>(
                "SELECT findings FROM policy_analysis_results WHERE tenant_id=$1 AND policy_id=$2 \
                 ORDER BY revision DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
            PolicyArtifactType::Reviews => sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object('review_id',review_id,'revision',revision,\
                 'reviewer_subject',reviewer_subject,'decision',decision,\
                 'review_digest',review_digest,'reviewed_at',reviewed_at) \
                 FROM policy_reviews WHERE tenant_id=$1 AND policy_id=$2 \
                 ORDER BY reviewed_at DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
            PolicyArtifactType::Simulations => sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object('simulation_id',simulation_id,'revision',revision,\
                 'run_kind',run_kind,'baseline_bundle_digest',baseline_bundle_digest,\
                 'candidate_source_digest',candidate_source_digest,'corpus_digest',corpus_digest,\
                 'evaluated_actions',evaluated_actions,'difference_count',difference_count,\
                 'side_effect_count',side_effect_count,'impact_report_digest',impact_report_digest,\
                 'impact_report',impact_report,'run_by',run_by,'created_at',created_at) \
                 FROM policy_simulation_runs WHERE tenant_id=$1 AND policy_id=$2 \
                 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
            PolicyArtifactType::ImpactReports => sqlx::query_scalar::<_, Value>(
                "SELECT impact_report FROM policy_impact_reports WHERE tenant_id=$1 AND policy_id=$2 \
                 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
            PolicyArtifactType::Promotions => sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object('environment',environment,'sequence',sequence,\
                 'bundle_digest',bundle_digest,'previous_bundle_digest',previous_bundle_digest,\
                 'rollback_of',rollback_of,'promoted_by',promoted_by,'state',state,\
                 'promotion_digest',promotion_digest,'promoted_at',promoted_at,\
                 'completed_at',completed_at) FROM policy_promotions \
                 WHERE tenant_id=$1 AND policy_id=$2 ORDER BY promoted_at DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
            PolicyArtifactType::Exceptions => sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object('exception_id',exception_id,'policy_id',policy_id,\
                 'scope_digest',scope_digest,'owner_subject',owner_subject,\
                 'approval_ids',approver_subjects,'reason_digest',reason_digest,\
                 'compensating_controls',compensating_controls,'issued_by',issued_by,\
                 'expires_at',expires_at,'revoked_at',revoked_at,'expired_at',expired_at,\
                 'state',CASE WHEN revoked_at IS NOT NULL THEN 'REVOKED' \
                   WHEN expired_at IS NOT NULL OR expires_at<=now() THEN 'EXPIRED' ELSE 'ACTIVE' END,\
                 'created_at',created_at) FROM policy_exceptions \
                 WHERE tenant_id=$1 AND policy_id=$2 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(tenant_uuid)
            .bind(policy_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await,
        }
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        Ok(AuthoritativePolicyArtifactPage {
            schema_version: "agenttrust.authoritative-policy-artifact-page.v1".into(),
            tenant_id: tenant.clone(),
            policy_id: policy_id.into(),
            artifact_type: artifact_type.as_str().into(),
            items,
        })
    }

    pub async fn expire_due_exceptions(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<u64, PolicyAuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(PolicyAuthorityError::ConfigurationInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT exception_id,policy_id,owner_subject,scope_digest,expires_at \
             FROM policy_exceptions WHERE tenant_id=$1 AND revoked_at IS NULL \
             AND expired_at IS NULL AND expires_at<=now() ORDER BY expires_at \
             FOR UPDATE SKIP LOCKED LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        for row in &rows {
            let exception_id: Uuid = row.get("exception_id");
            let policy_id: String = row.get("policy_id");
            sqlx::query(
                "UPDATE policy_exceptions SET expired_at=now() \
                 WHERE tenant_id=$1 AND exception_id=$2 AND expired_at IS NULL AND revoked_at IS NULL",
            )
            .bind(tenant_uuid)
            .bind(exception_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            let event_id = Uuid::new_v4();
            let payload = json!({
                "schema_version": "agenttrust.policy-lifecycle-evidence.v1",
                "event_id": event_id,
                "tenant_id": tenant_uuid,
                "policy_id": policy_id,
                "operation": "EXPIRE_EXCEPTION",
                "exception_id": exception_id,
                "principal_subject": "policy-expiry-controller",
                "owner_subject": row.get::<String, _>("owner_subject"),
                "scope_digest": row.get::<String, _>("scope_digest"),
                "scheduled_expires_at": row.get::<DateTime<Utc>, _>("expires_at"),
                "recorded_at": Utc::now(),
            });
            let payload_digest = canonical_digest(&payload)?;
            let evidence_ref = format!(
                "urn:agenttrust:policy-evidence:{}:{}:sha256:{}",
                tenant_uuid, event_id, payload_digest
            );
            sqlx::query(
                "INSERT INTO policy_evidence_events \
                 (tenant_id,event_id,policy_id,event_type,actor_subject,payload,payload_digest,evidence_ref) \
                 VALUES ($1,$2,$3,'POLICY_EXCEPTION_EXPIRED','policy-expiry-controller',$4,$5,$6)",
            )
            .bind(tenant_uuid)
            .bind(event_id)
            .bind(&policy_id)
            .bind(&payload)
            .bind(&payload_digest)
            .bind(&evidence_ref)
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            sqlx::query(
                "INSERT INTO policy_evidence_outbox \
                 (tenant_id,event_id,event_type,aggregate_id,payload,payload_digest) \
                 VALUES ($1,$2,'POLICY_LIFECYCLE_EVIDENCE',$3,$4,$5)",
            )
            .bind(tenant_uuid)
            .bind(event_id)
            .bind(&policy_id)
            .bind(&payload)
            .bind(&payload_digest)
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        }
        let count = u64::try_from(rows.len()).map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        Ok(count)
    }
}

struct PreparedPolicyActivation {
    request: PolicyActivationRequest,
    claim_owner: Uuid,
    resource_version: i64,
}

enum PolicyActivationPreparation {
    Replay(PolicyMutationResult),
    Pending(PreparedPolicyActivation),
}

#[derive(Clone)]
pub struct PolicyExecutor {
    store: PostgresPolicyAuthorityStore,
    signing_key_id: String,
    signing_key: Arc<SigningKey>,
    activation: Arc<dyn PolicyActivationPort>,
    activation_verifying_key: VerifyingKey,
}

impl PolicyExecutor {
    pub fn new(
        store: PostgresPolicyAuthorityStore,
        signing_key_id: String,
        signing_key: SigningKey,
        activation: Arc<dyn PolicyActivationPort>,
        activation_verifying_key: VerifyingKey,
    ) -> Result<Self, PolicyAuthorityError> {
        if !identifier(&signing_key_id, 128) {
            return Err(PolicyAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            signing_key_id,
            signing_key: Arc::new(signing_key),
            activation,
            activation_verifying_key,
        })
    }

    pub async fn execute(
        &self,
        binding: PolicyExecutionBinding,
        request: PolicyExecutorRequest,
    ) -> Result<PolicyMutationResult, PolicyAuthorityError> {
        if matches!(
            request.command.operation,
            PolicyOperation::Promote | PolicyOperation::Rollback
        ) {
            return self.execute_activation(binding, request).await;
        }
        validate_execution(&binding, &request)?;
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(&request)?;
        let request_value =
            serde_json::to_value(&request).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let mut tx = self.store.begin_tenant(&binding.tenant_id).await?;

        let ingress = sqlx::query(
            "SELECT state,principal_subject,principal_assertion_digest FROM policy_action_ingress \
             WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .ok_or(PolicyAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("principal_subject") != request.principal_subject
            || ingress.get::<String, _>("principal_assertion_digest")
                != request.principal_assertion_digest
        {
            return Err(PolicyAuthorityError::PrincipalDenied);
        }

        sqlx::query(
            "INSERT INTO policy_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,action_hash,ledger_execution_id,\
              fence_digest,policy_id,resource_version,trace_id,request,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PREPARED') \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(&request_digest)
        .bind(request.command.command_id)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .bind(&request.command.policy_id)
        .bind(
            i64::try_from(binding.resource_version)
                .map_err(|_| PolicyAuthorityError::RequestInvalid)?,
        )
        .bind(&binding.trace_id)
        .bind(&request_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::IdempotencyConflict)?;
        let existing = sqlx::query(
            "SELECT request_digest,action_hash,ledger_execution_id,fence_digest,policy_id,\
                    resource_version,request,state,safe_result \
             FROM policy_authority_executions WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        if existing.get::<String, _>("request_digest") != request_digest
            || existing.get::<String, _>("action_hash") != binding.action_hash
            || existing.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
            || existing.get::<String, _>("fence_digest") != binding.fence_digest
            || existing.get::<String, _>("policy_id") != request.command.policy_id
            || existing.get::<i64, _>("resource_version")
                != i64::try_from(binding.resource_version)
                    .map_err(|_| PolicyAuthorityError::RequestInvalid)?
            || existing.get::<Value, _>("request") != request_value
        {
            return Err(PolicyAuthorityError::IdempotencyConflict);
        }
        if existing.get::<String, _>("state") == "SUCCEEDED" {
            let result: PolicyMutationResult = serde_json::from_value(
                existing
                    .get::<Option<Value>, _>("safe_result")
                    .ok_or(PolicyAuthorityError::OutcomeUnknown)?,
            )
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            tx.commit()
                .await
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            return Ok(result);
        }
        if existing.get::<String, _>("state") != "PREPARED" {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        sqlx::query(
            "UPDATE policy_authority_executions SET state='EXECUTING',updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;

        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM policy_resource_versions \
             WHERE tenant_id=$1 AND policy_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.command.policy_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current
            != i64::try_from(request.command.expected_resource_version)
                .map_err(|_| PolicyAuthorityError::RequestInvalid)?
            || binding.resource_version != request.command.expected_resource_version
        {
            return Err(PolicyAuthorityError::StateConflict);
        }
        let (state, artifact_digest) = self.apply_operation(&mut tx, tenant_uuid, &request).await?;
        let next_version = current
            .checked_add(1)
            .ok_or(PolicyAuthorityError::StateConflict)?;
        sqlx::query(
            "INSERT INTO policy_resource_versions \
             (tenant_id,policy_id,resource_version,action_hash,ledger_execution_id,fence_digest) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,policy_id) DO UPDATE SET \
             resource_version=EXCLUDED.resource_version,action_hash=EXCLUDED.action_hash,\
             ledger_execution_id=EXCLUDED.ledger_execution_id,fence_digest=EXCLUDED.fence_digest,updated_at=now()",
        )
        .bind(tenant_uuid)
        .bind(&request.command.policy_id)
        .bind(next_version)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;

        let evidence_id = Uuid::new_v4();
        let evidence_payload = json!({
            "schema_version": "agenttrust.policy-lifecycle-evidence.v1",
            "event_id": evidence_id,
            "tenant_id": tenant_uuid,
            "policy_id": request.command.policy_id,
            "command_id": request.command.command_id,
            "operation": request.command.operation,
            "principal_subject": request.principal_subject,
            "principal_assertion_digest": request.principal_assertion_digest,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "fence_digest": binding.fence_digest,
            "resource_version": next_version,
            "artifact_digest": artifact_digest,
            "state": state,
            "trace_id": binding.trace_id,
            "recorded_at": Utc::now(),
        });
        let evidence_digest = canonical_digest(&evidence_payload)?;
        let evidence_ref = format!(
            "urn:agenttrust:policy-evidence:{}:{}:sha256:{}",
            tenant_uuid, evidence_id, evidence_digest
        );
        sqlx::query(
            "INSERT INTO policy_evidence_events \
             (tenant_id,event_id,policy_id,event_type,actor_subject,payload,payload_digest,evidence_ref) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(tenant_uuid)
        .bind(evidence_id)
        .bind(&request.command.policy_id)
        .bind(format!("POLICY_{}", request.command.operation.as_str()))
        .bind(&request.principal_subject)
        .bind(&evidence_payload)
        .bind(&evidence_digest)
        .bind(&evidence_ref)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        sqlx::query(
            "INSERT INTO policy_evidence_outbox \
             (tenant_id,event_id,event_type,aggregate_id,payload,payload_digest) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(tenant_uuid)
        .bind(evidence_id)
        .bind("POLICY_LIFECYCLE_EVIDENCE")
        .bind(&request.command.policy_id)
        .bind(&evidence_payload)
        .bind(&evidence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let result = PolicyMutationResult {
            schema_version: POLICY_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            policy_id: request.command.policy_id.clone(),
            operation: request.command.operation,
            resource_version: u64::try_from(next_version)
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?,
            state,
            artifact_digest,
            evidence_ref,
        };
        let result_value =
            serde_json::to_value(&result).map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let result_digest = canonical_digest(&result)?;
        sqlx::query(
            "UPDATE policy_authority_executions SET state='SUCCEEDED',safe_result=$3,\
             safe_result_digest=$4,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING'",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(&result_value)
        .bind(&result_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        Ok(result)
    }

    pub async fn ready(&self) -> bool {
        self.activation.ready().await
    }

    async fn execute_activation(
        &self,
        binding: PolicyExecutionBinding,
        request: PolicyExecutorRequest,
    ) -> Result<PolicyMutationResult, PolicyAuthorityError> {
        validate_execution(&binding, &request)?;
        let prepared = self.prepare_policy_activation(&binding, &request).await?;
        let prepared = match prepared {
            PolicyActivationPreparation::Replay(result) => return Ok(result),
            PolicyActivationPreparation::Pending(value) => value,
        };
        let acknowledgement = match self.activation.activate(&prepared.request).await {
            Ok(value) => value,
            Err(error) => {
                self.mark_policy_activation_unknown(&binding, &prepared)
                    .await?;
                return Err(error);
            }
        };
        self.complete_policy_activation(&binding, &request, prepared, acknowledgement)
            .await
    }

    async fn prepare_policy_activation(
        &self,
        binding: &PolicyExecutionBinding,
        request: &PolicyExecutorRequest,
    ) -> Result<PolicyActivationPreparation, PolicyAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(request)?;
        let request_value =
            serde_json::to_value(request).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let mut tx = self.store.begin_tenant(&binding.tenant_id).await?;
        let ingress = sqlx::query(
            "SELECT state,principal_subject,principal_assertion_digest FROM policy_action_ingress \
             WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .ok_or(PolicyAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("principal_subject") != request.principal_subject
            || ingress.get::<String, _>("principal_assertion_digest")
                != request.principal_assertion_digest
        {
            return Err(PolicyAuthorityError::PrincipalDenied);
        }
        sqlx::query(
            "INSERT INTO policy_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,action_hash,ledger_execution_id,\
              fence_digest,policy_id,resource_version,trace_id,request,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PREPARED') \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(&request_digest)
        .bind(request.command.command_id)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .bind(&request.command.policy_id)
        .bind(
            i64::try_from(binding.resource_version)
                .map_err(|_| PolicyAuthorityError::RequestInvalid)?,
        )
        .bind(&binding.trace_id)
        .bind(&request_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::IdempotencyConflict)?;
        let execution = sqlx::query(
            "SELECT request_digest,action_hash,ledger_execution_id,fence_digest,policy_id,\
                    resource_version,request,state,safe_result FROM policy_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        if execution.get::<String, _>("request_digest") != request_digest
            || execution.get::<String, _>("action_hash") != binding.action_hash
            || execution.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
            || execution.get::<String, _>("fence_digest") != binding.fence_digest
            || execution.get::<String, _>("policy_id") != request.command.policy_id
            || execution.get::<i64, _>("resource_version")
                != i64::try_from(binding.resource_version)
                    .map_err(|_| PolicyAuthorityError::RequestInvalid)?
            || execution.get::<Value, _>("request") != request_value
        {
            return Err(PolicyAuthorityError::IdempotencyConflict);
        }
        if execution.get::<String, _>("state") == "SUCCEEDED" {
            let result = serde_json::from_value(
                execution
                    .get::<Option<Value>, _>("safe_result")
                    .ok_or(PolicyAuthorityError::OutcomeUnknown)?,
            )
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            tx.commit()
                .await
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            return Ok(PolicyActivationPreparation::Replay(result));
        }
        let current_version = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM policy_resource_versions \
             WHERE tenant_id=$1 AND policy_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.policy_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current_version
            != i64::try_from(request.command.expected_resource_version)
                .map_err(|_| PolicyAuthorityError::RequestInvalid)?
            || binding.resource_version != request.command.expected_resource_version
        {
            return Err(PolicyAuthorityError::StateConflict);
        }
        let existing_intent = sqlx::query(
            "SELECT request_body,state,claim_owner,claim_expires_at>clock_timestamp() AS lease_live \
             FROM policy_activation_intents WHERE tenant_id=$1 AND activation_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        if let Some(intent) = existing_intent {
            let activation_request: PolicyActivationRequest =
                serde_json::from_value(intent.get::<Value, _>("request_body"))
                    .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            if activation_request.policy_id != request.command.policy_id
                || activation_request.tenant_id != binding.tenant_id
            {
                return Err(PolicyAuthorityError::IdempotencyConflict);
            }
            let state = intent.get::<String, _>("state");
            if state == "ACTIVE" {
                return Err(PolicyAuthorityError::OutcomeUnknown);
            }
            if state == "PENDING" && intent.get::<bool, _>("lease_live") {
                return Err(PolicyAuthorityError::OutcomeUnknown);
            }
            let claim_owner = Uuid::new_v4();
            let updated = sqlx::query(
                "UPDATE policy_activation_intents SET state='PENDING',claim_owner=$3,\
                 claim_expires_at=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND activation_id=$2 \
                   AND (state='UNKNOWN' OR claim_expires_at<=clock_timestamp())",
            )
            .bind(tenant)
            .bind(request.command.command_id)
            .bind(claim_owner)
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(PolicyAuthorityError::OutcomeUnknown);
            }
            if state == "UNKNOWN" {
                let promotion_reclaimed = sqlx::query(
                    "UPDATE policy_promotions SET state='PENDING_ACTIVATION' \
                     WHERE tenant_id=$1 AND policy_id=$2 AND environment=$3 AND sequence=$4 AND state='UNKNOWN'",
                )
                .bind(tenant)
                .bind(&activation_request.policy_id)
                .bind(activation_request.environment.as_str())
                .bind(i64::try_from(activation_request.sequence).map_err(|_| PolicyAuthorityError::OutcomeUnknown)?)
                .execute(&mut *tx)
                .await
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
                if promotion_reclaimed.rows_affected() != 1 {
                    return Err(PolicyAuthorityError::OutcomeUnknown);
                }
                let execution_reclaimed = sqlx::query(
                    "UPDATE policy_authority_executions SET state='EXECUTING',updated_at=clock_timestamp() \
                     WHERE tenant_id=$1 AND idempotency_key=$2 AND state='UNKNOWN'",
                )
                .bind(tenant)
                .bind(&binding.idempotency_key)
                .execute(&mut *tx)
                .await
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
                if execution_reclaimed.rows_affected() != 1 {
                    return Err(PolicyAuthorityError::OutcomeUnknown);
                }
            }
            tx.commit()
                .await
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            return Ok(PolicyActivationPreparation::Pending(
                PreparedPolicyActivation {
                    request: activation_request,
                    claim_owner,
                    resource_version: current_version,
                },
            ));
        }
        if execution.get::<String, _>("state") != "PREPARED" {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let rollback = request.command.operation == PolicyOperation::Rollback;
        let environment = PolicyEnvironment::from_deployment(
            request.command.payload["environment"]
                .as_str()
                .ok_or(PolicyAuthorityError::RequestInvalid)?,
        )
        .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let digest_key = if rollback {
            "target_bundle_digest"
        } else {
            "bundle_digest"
        };
        let bundle_digest = request.command.payload[digest_key]
            .as_str()
            .ok_or(PolicyAuthorityError::RequestInvalid)?;
        let bundle_row = sqlx::query(
            "SELECT revision,status,deprecated_at,bundle_json FROM policy_bundles \
             WHERE tenant_id=$1 AND policy_id=$2 AND compiled_digest=$3 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.command.policy_id)
        .bind(bundle_digest)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .ok_or(PolicyAuthorityError::NotFound)?;
        if bundle_row
            .get::<Option<DateTime<Utc>>, _>("deprecated_at")
            .is_some()
        {
            return Err(PolicyAuthorityError::StateConflict);
        }
        let bundle: SignedPolicyBundle = serde_json::from_value(bundle_row.get("bundle_json"))
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        if bundle_row.get::<String, _>("status") != "SIGNED"
            || bundle.bundle_digest != bundle_digest
            || bundle.policy_id != request.command.policy_id
            || bundle.tenant_id != binding.tenant_id
            || bundle.source_revision
                != u64::try_from(bundle_row.get::<i64, _>("revision"))
                    .map_err(|_| PolicyAuthorityError::StateConflict)?
            || bundle.key_id != self.signing_key_id
            || bundle.compiled_at > Utc::now() + Duration::seconds(30)
            || bundle.verify(&self.signing_key.verifying_key()).is_err()
        {
            return Err(PolicyAuthorityError::StateConflict);
        }
        if !rollback {
            let prerequisite = match environment {
                PolicyEnvironment::Dev => None,
                PolicyEnvironment::Staging => Some(PolicyEnvironment::Dev),
                PolicyEnvironment::Canary => Some(PolicyEnvironment::Staging),
                PolicyEnvironment::Production => Some(PolicyEnvironment::Canary),
            };
            if let Some(previous_environment) = prerequisite {
                let satisfied = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM policy_promotions WHERE tenant_id=$1 \
                     AND environment=$2 AND bundle_digest=$3 AND state='ACTIVE')",
                )
                .bind(tenant)
                .bind(previous_environment.as_str())
                .bind(bundle_digest)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
                if !satisfied {
                    return Err(PolicyAuthorityError::StateConflict);
                }
            }
            let impact_digest = request.command.payload["impact_report_digest"]
                .as_str()
                .ok_or(PolicyAuthorityError::RequestInvalid)?;
            let impact_matches = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM policy_simulation_runs WHERE tenant_id=$1 AND policy_id=$2 \
                 AND revision=$3 AND impact_report_digest=$4 AND side_effect_count=0)",
            )
            .bind(tenant)
            .bind(&request.command.policy_id)
            .bind(bundle_row.get::<i64, _>("revision"))
            .bind(impact_digest)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
            if !impact_matches {
                return Err(PolicyAuthorityError::StateConflict);
            }
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "POLICY_ACTIVATION:{}:{}",
                tenant,
                environment.as_str()
            ))
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let current = sqlx::query(
            "SELECT policy_id,sequence,bundle_digest FROM policy_promotions WHERE tenant_id=$1 \
             AND environment=$2 AND state='ACTIVE' ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
        )
        .bind(tenant)
        .bind(environment.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        if rollback
            && current
                .as_ref()
                .is_none_or(|row| row.get::<String, _>("policy_id") != request.command.policy_id)
        {
            return Err(PolicyAuthorityError::StateConflict);
        }
        let sequence = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(max(sequence),0)+1 FROM policy_promotions \
             WHERE tenant_id=$1 AND environment=$2",
        )
        .bind(tenant)
        .bind(environment.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
        let previous_bundle_digest = current
            .as_ref()
            .map(|row| row.get::<String, _>("bundle_digest"));
        if previous_bundle_digest.as_deref() == Some(bundle_digest) {
            return Err(PolicyAuthorityError::StateConflict);
        }
        if rollback {
            let was_active = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM policy_promotions WHERE tenant_id=$1 AND policy_id=$2 \
                 AND environment=$3 AND bundle_digest=$4 AND state IN ('SUPERSEDED','ROLLED_BACK'))",
            )
            .bind(tenant)
            .bind(&request.command.policy_id)
            .bind(environment.as_str())
            .bind(bundle_digest)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
            if !was_active {
                return Err(PolicyAuthorityError::StateConflict);
            }
        }
        let activation_id = request.command.command_id;
        let activation_request = PolicyActivationRequest {
            schema_version: POLICY_ACTIVATION_REQUEST_SCHEMA_VERSION.into(),
            activation_id: activation_id.to_string(),
            idempotency_key: format!("policy-activation:{activation_id}"),
            tenant_id: binding.tenant_id.clone(),
            policy_id: request.command.policy_id.clone(),
            environment,
            sequence: u64::try_from(sequence).map_err(|_| PolicyAuthorityError::StateConflict)?,
            previous_bundle_digest: previous_bundle_digest.clone(),
            bundle,
            requested_at: Utc::now(),
        };
        activation_request
            .validate()
            .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let activation_request_value = serde_json::to_value(&activation_request)
            .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
        let activation_request_digest = canonical_digest(&activation_request)?;
        let claim_owner = Uuid::new_v4();
        let rollback_of = current.as_ref().map(|row| row.get::<i64, _>("sequence"));
        let promotion_digest = canonical_digest(&json!({
            "tenant_id": tenant,
            "policy_id": request.command.policy_id,
            "environment": environment,
            "sequence": sequence,
            "bundle_digest": bundle_digest,
            "rollback_of": rollback_of,
            "activation_id": activation_id,
        }))?;
        sqlx::query(
            "INSERT INTO policy_promotions \
             (tenant_id,policy_id,environment,sequence,bundle_digest,previous_bundle_digest,rollback_of,\
              promoted_by,state,promotion_digest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PENDING_ACTIVATION',$9)",
        )
        .bind(tenant)
        .bind(&request.command.policy_id)
        .bind(environment.as_str())
        .bind(sequence)
        .bind(bundle_digest)
        .bind(&previous_bundle_digest)
        .bind(rollback_of)
        .bind(&request.principal_subject)
        .bind(&promotion_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::StateConflict)?;
        sqlx::query(
            "INSERT INTO policy_activation_intents \
             (tenant_id,activation_id,idempotency_key,policy_id,environment,sequence,bundle_digest,\
              previous_bundle_digest,request_digest,request_body,state,claim_owner,claim_expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PENDING',$11,clock_timestamp()+interval '30 seconds')",
        )
        .bind(tenant)
        .bind(activation_id)
        .bind(&activation_request.idempotency_key)
        .bind(&request.command.policy_id)
        .bind(environment.as_str())
        .bind(sequence)
        .bind(bundle_digest)
        .bind(&previous_bundle_digest)
        .bind(&activation_request_digest)
        .bind(&activation_request_value)
        .bind(claim_owner)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::StateConflict)?;
        sqlx::query(
            "UPDATE policy_authority_executions SET state='EXECUTING',updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        Ok(PolicyActivationPreparation::Pending(
            PreparedPolicyActivation {
                request: activation_request,
                claim_owner,
                resource_version: current_version,
            },
        ))
    }

    async fn mark_policy_activation_unknown(
        &self,
        binding: &PolicyExecutionBinding,
        prepared: &PreparedPolicyActivation,
    ) -> Result<(), PolicyAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let mut tx = self.store.begin_tenant(&binding.tenant_id).await?;
        let updated = sqlx::query(
            "UPDATE policy_activation_intents SET state='UNKNOWN',updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND activation_id=$2::uuid AND state='PENDING' AND claim_owner=$3",
        )
        .bind(tenant)
        .bind(&prepared.request.activation_id)
        .bind(prepared.claim_owner)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if updated.rows_affected() != 1 {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let promotion_unknown = sqlx::query(
            "UPDATE policy_promotions SET state='UNKNOWN' WHERE tenant_id=$1 AND policy_id=$2 \
             AND environment=$3 AND sequence=$4 AND state='PENDING_ACTIVATION'",
        )
        .bind(tenant)
        .bind(&prepared.request.policy_id)
        .bind(prepared.request.environment.as_str())
        .bind(
            i64::try_from(prepared.request.sequence)
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?,
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if promotion_unknown.rows_affected() != 1 {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let execution_unknown = sqlx::query(
            "UPDATE policy_authority_executions SET state='UNKNOWN',updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING'",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if execution_unknown.rows_affected() != 1 {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)
    }

    async fn complete_policy_activation(
        &self,
        binding: &PolicyExecutionBinding,
        request: &PolicyExecutorRequest,
        prepared: PreparedPolicyActivation,
        acknowledgement: PepPolicyActivationAcknowledgement,
    ) -> Result<PolicyMutationResult, PolicyAuthorityError> {
        acknowledgement
            .verify(&self.activation_verifying_key)
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if acknowledgement.activation_id != prepared.request.activation_id
            || acknowledgement.idempotency_key != prepared.request.idempotency_key
            || acknowledgement.tenant_id != prepared.request.tenant_id
            || acknowledgement.policy_id != prepared.request.policy_id
            || acknowledgement.environment != prepared.request.environment
            || acknowledgement.sequence != prepared.request.sequence
            || acknowledgement.bundle_digest != prepared.request.bundle.bundle_digest
            || !acknowledgement.active
        {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let tenant = parse_tenant(&binding.tenant_id)?;
        let acknowledgement_digest = canonical_digest(&acknowledgement)?;
        let acknowledgement_value = serde_json::to_value(&acknowledgement)
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let mut tx = self.store.begin_tenant(&binding.tenant_id).await?;
        let intent = sqlx::query(
            "SELECT request_body,state,claim_owner FROM policy_activation_intents \
             WHERE tenant_id=$1 AND activation_id=$2::uuid FOR UPDATE",
        )
        .bind(tenant)
        .bind(&prepared.request.activation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if intent.get::<Value, _>("request_body")
            != serde_json::to_value(&prepared.request)
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?
            || intent.get::<String, _>("state") != "PENDING"
            || intent.get::<Uuid, _>("claim_owner") != prepared.claim_owner
        {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "POLICY_ACTIVATION:{}:{}",
                tenant,
                prepared.request.environment.as_str()
            ))
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let current = sqlx::query(
            "SELECT policy_id,sequence,bundle_digest FROM policy_promotions WHERE tenant_id=$1 \
             AND environment=$2 AND state='ACTIVE' ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
        )
        .bind(tenant)
        .bind(prepared.request.environment.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if current
            .as_ref()
            .map(|row| row.get::<String, _>("bundle_digest"))
            != prepared.request.previous_bundle_digest
        {
            return Err(PolicyAuthorityError::StateConflict);
        }
        if let Some(row) = current {
            let superseded = sqlx::query(
                "UPDATE policy_promotions SET state=$4 WHERE tenant_id=$1 AND policy_id=$2 \
                 AND environment=$3 AND sequence=$5 AND state='ACTIVE'",
            )
            .bind(tenant)
            .bind(row.get::<String, _>("policy_id"))
            .bind(prepared.request.environment.as_str())
            .bind(if request.command.operation == PolicyOperation::Rollback {
                "ROLLED_BACK"
            } else {
                "SUPERSEDED"
            })
            .bind(row.get::<i64, _>("sequence"))
            .execute(&mut *tx)
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
            if superseded.rows_affected() != 1 {
                return Err(PolicyAuthorityError::OutcomeUnknown);
            }
        }
        let promoted = sqlx::query(
            "UPDATE policy_promotions SET state='ACTIVE' WHERE tenant_id=$1 AND policy_id=$2 \
             AND environment=$3 AND sequence=$4 AND state='PENDING_ACTIVATION'",
        )
        .bind(tenant)
        .bind(&prepared.request.policy_id)
        .bind(prepared.request.environment.as_str())
        .bind(
            i64::try_from(prepared.request.sequence)
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?,
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if promoted.rows_affected() != 1 {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let activated = sqlx::query(
            "UPDATE policy_activation_intents SET state='ACTIVE',acknowledgement_digest=$4,\
             acknowledgement=$5,activated_at=$6,updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND activation_id=$2::uuid AND claim_owner=$3 AND state='PENDING'",
        )
        .bind(tenant)
        .bind(&prepared.request.activation_id)
        .bind(prepared.claim_owner)
        .bind(&acknowledgement_digest)
        .bind(&acknowledgement_value)
        .bind(acknowledgement.acknowledged_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if activated.rows_affected() != 1 {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        let next_version = prepared
            .resource_version
            .checked_add(1)
            .ok_or(PolicyAuthorityError::StateConflict)?;
        sqlx::query(
            "INSERT INTO policy_resource_versions \
             (tenant_id,policy_id,resource_version,action_hash,ledger_execution_id,fence_digest) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,policy_id) DO UPDATE SET \
             resource_version=EXCLUDED.resource_version,action_hash=EXCLUDED.action_hash,\
             ledger_execution_id=EXCLUDED.ledger_execution_id,fence_digest=EXCLUDED.fence_digest,updated_at=now()",
        )
        .bind(tenant)
        .bind(&request.command.policy_id)
        .bind(next_version)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let evidence_id = Uuid::new_v4();
        let evidence_payload = json!({
            "schema_version": "agenttrust.policy-lifecycle-evidence.v1",
            "event_id": evidence_id,
            "tenant_id": tenant,
            "policy_id": request.command.policy_id,
            "command_id": request.command.command_id,
            "operation": request.command.operation,
            "principal_subject": request.principal_subject,
            "principal_assertion_digest": request.principal_assertion_digest,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "fence_digest": binding.fence_digest,
            "resource_version": next_version,
            "artifact_digest": prepared.request.bundle.bundle_digest,
            "activation_id": prepared.request.activation_id,
            "activation_ack_digest": acknowledgement_digest,
            "pep_activation_evidence_ref": acknowledgement.evidence_ref,
            "pep_activation_evidence_digest": acknowledgement.evidence_digest,
            "state": "ACTIVE",
            "trace_id": binding.trace_id,
            "recorded_at": Utc::now(),
        });
        let evidence_digest = canonical_digest(&evidence_payload)?;
        let evidence_ref = format!(
            "urn:agenttrust:policy-evidence:{}:{}:sha256:{}",
            tenant, evidence_id, evidence_digest
        );
        sqlx::query(
            "INSERT INTO policy_evidence_events \
             (tenant_id,event_id,policy_id,event_type,actor_subject,payload,payload_digest,evidence_ref) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(tenant)
        .bind(evidence_id)
        .bind(&request.command.policy_id)
        .bind(format!("POLICY_{}", request.command.operation.as_str()))
        .bind(&request.principal_subject)
        .bind(&evidence_payload)
        .bind(&evidence_digest)
        .bind(&evidence_ref)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        sqlx::query(
            "INSERT INTO policy_evidence_outbox \
             (tenant_id,event_id,event_type,aggregate_id,payload,payload_digest) \
             VALUES ($1,$2,'POLICY_LIFECYCLE_EVIDENCE',$3,$4,$5)",
        )
        .bind(tenant)
        .bind(evidence_id)
        .bind(&request.command.policy_id)
        .bind(&evidence_payload)
        .bind(&evidence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let result = PolicyMutationResult {
            schema_version: POLICY_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            policy_id: request.command.policy_id.clone(),
            operation: request.command.operation,
            resource_version: u64::try_from(next_version)
                .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?,
            state: "ACTIVE".into(),
            artifact_digest: prepared.request.bundle.bundle_digest,
            evidence_ref,
        };
        let result_value =
            serde_json::to_value(&result).map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        let result_digest = canonical_digest(&result)?;
        let updated = sqlx::query(
            "UPDATE policy_authority_executions SET state='SUCCEEDED',safe_result=$3,\
             safe_result_digest=$4,updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING'",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(&result_value)
        .bind(&result_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        if updated.rows_affected() != 1 {
            return Err(PolicyAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| PolicyAuthorityError::OutcomeUnknown)?;
        Ok(result)
    }

    async fn apply_operation(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        request: &PolicyExecutorRequest,
    ) -> Result<(String, String), PolicyAuthorityError> {
        match request.command.operation {
            PolicyOperation::CreateDraft => create_draft(tx, tenant, request).await,
            PolicyOperation::Validate => validate_policy_source(tx, tenant, request).await,
            PolicyOperation::Simulate => simulate_policy(tx, tenant, request, "SIMULATION").await,
            PolicyOperation::ShadowEvaluate => simulate_policy(tx, tenant, request, "SHADOW").await,
            PolicyOperation::ImpactAnalyze => analyze_impact(tx, tenant, request).await,
            PolicyOperation::Approve => approve_policy(tx, tenant, request).await,
            PolicyOperation::Sign => {
                sign_policy(tx, tenant, request, &self.signing_key_id, &self.signing_key).await
            }
            PolicyOperation::Promote | PolicyOperation::Rollback => {
                // Promotion has its own two-transaction activation path in `execute_activation`.
                // Reaching this transaction-local dispatcher would bypass PDP convergence.
                Err(PolicyAuthorityError::ConfigurationInvalid)
            }
            PolicyOperation::Deprecate => deprecate_policy(tx, tenant, request).await,
            PolicyOperation::CreateException => create_exception(tx, tenant, request).await,
            PolicyOperation::RevokeException => revoke_exception(tx, tenant, request).await,
        }
    }
}

async fn create_draft(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    let source: PolicySource = serde_json::from_value(
        request
            .command
            .payload
            .get("source")
            .cloned()
            .ok_or(PolicyAuthorityError::RequestInvalid)?,
    )
    .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    if source.schema_version != POLICY_ADMIN_SCHEMA_VERSION
        || source.tenant_id.0 != tenant.to_string()
        || source.source_id != request.command.policy_id
        || source.author != request.principal_subject
        || source.source_digest
            != source
                .compute_digest()
                .map_err(|_| PolicyAuthorityError::RequestInvalid)?
        || source.rules.is_empty()
        || source.rules.len() > 10_000
    {
        return Err(PolicyAuthorityError::RequestInvalid);
    }
    let revision = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(max(revision),0)+1 FROM policy_sources WHERE tenant_id=$1 AND policy_id=$2",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let source_value =
        serde_json::to_value(&source).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    sqlx::query(
        "INSERT INTO policy_sources \
         (tenant_id,policy_id,revision,version,author_subject,source_digest,source_json,lifecycle_state) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'DRAFT')",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .bind(&source.version)
    .bind(&request.principal_subject)
    .bind(&source.source_digest)
    .bind(&source_value)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    Ok(("DRAFT".into(), source.source_digest))
}

async fn latest_source(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    policy_id: &str,
) -> Result<(i64, PolicySource, String), PolicyAuthorityError> {
    let row = sqlx::query(
        "SELECT revision,source_json,author_subject FROM policy_sources \
         WHERE tenant_id=$1 AND policy_id=$2 ORDER BY revision DESC LIMIT 1 FOR UPDATE",
    )
    .bind(tenant)
    .bind(policy_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
    .ok_or(PolicyAuthorityError::NotFound)?;
    let source = serde_json::from_value(row.get("source_json"))
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    Ok((row.get("revision"), source, row.get("author_subject")))
}

async fn validate_policy_source(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    let (revision, source, _) = latest_source(tx, tenant, &request.command.policy_id).await?;
    let findings = StaticAnalyzer::analyze(&source);
    let valid = !findings.iter().any(|finding| finding.blocking);
    let report = json!({
        "schema_version": "agenttrust.policy-static-analysis.v1",
        "policy_id": request.command.policy_id,
        "revision": revision,
        "source_digest": source.source_digest,
        "valid": valid,
        "findings": findings,
        "analyzed_at": Utc::now(),
    });
    let report_digest = canonical_digest(&report)?;
    sqlx::query(
        "INSERT INTO policy_analysis_results \
         (tenant_id,policy_id,revision,analysis_digest,valid,findings,analyzed_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,policy_id,revision) DO NOTHING",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .bind(&report_digest)
    .bind(valid)
    .bind(&report)
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    if valid {
        sqlx::query(
            "UPDATE policy_sources SET lifecycle_state='VALIDATED' \
             WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3 AND lifecycle_state='DRAFT'",
        )
        .bind(tenant)
        .bind(&request.command.policy_id)
        .bind(revision)
        .execute(&mut **tx)
        .await
        .map_err(|_| PolicyAuthorityError::StateConflict)?;
    }
    Ok((
        (if valid {
            "VALIDATED"
        } else {
            "VALIDATION_BLOCKED"
        })
        .into(),
        report_digest,
    ))
}

async fn simulate_policy(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
    run_kind: &str,
) -> Result<(String, String), PolicyAuthorityError> {
    let (revision, source, _) = latest_source(tx, tenant, &request.command.policy_id).await?;
    let baseline_digest = request.command.payload["baseline_bundle_digest"]
        .as_str()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let source_revision =
        u64::try_from(revision).map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let baseline = if baseline_digest == "0".repeat(64) {
        PolicyBundle {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            bundle_id: "bootstrap-deny-baseline".into(),
            tenant_id: source.tenant_id.clone(),
            policy_id: request.command.policy_id.clone(),
            source_revision,
            version: "0".into(),
            source_digest: baseline_digest.into(),
            bundle_digest: baseline_digest.into(),
            rules: source
                .rules
                .iter()
                .cloned()
                .map(|mut rule| {
                    rule.decision = agent_trust_contracts::Decision::Deny;
                    rule
                })
                .collect(),
            default_decision: agent_trust_contracts::Decision::Deny,
            review_ids: BTreeSet::new(),
            key_id: "bootstrap-deny-baseline".into(),
            signature: String::new(),
            compiled_at: Utc::now(),
        }
    } else {
        let baseline_value = sqlx::query_scalar::<_, Value>(
            "SELECT bundle_json FROM policy_bundles WHERE tenant_id=$1 AND compiled_digest=$2 AND deprecated_at IS NULL",
        )
        .bind(tenant)
        .bind(baseline_digest)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
        .ok_or(PolicyAuthorityError::NotFound)?;
        serde_json::from_value(baseline_value)
            .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
    };
    let actions = serde_json::from_value(request.command.payload["actions"].clone())
        .map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    let actions: Vec<crate::PolicyAction> = actions;
    if actions.is_empty()
        || actions.len() > 10_000
        || actions
            .iter()
            .any(|action| action.tenant_id.0 != tenant.to_string())
    {
        return Err(PolicyAuthorityError::RequestInvalid);
    }
    let candidate = PolicyBundle {
        schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
        bundle_id: format!("simulation:{}:{}", request.command.policy_id, revision),
        tenant_id: source.tenant_id.clone(),
        policy_id: request.command.policy_id.clone(),
        source_revision,
        version: source.version.clone(),
        source_digest: source.source_digest.clone(),
        bundle_digest: source.source_digest.clone(),
        rules: source.rules.clone(),
        default_decision: source.default_decision,
        review_ids: BTreeSet::new(),
        key_id: "simulation-only".into(),
        signature: String::new(),
        compiled_at: Utc::now(),
    };
    let report: ImpactReport = SimulationEngine::shadow_compare(&baseline, &candidate, &actions);
    if report.side_effect_count != 0 || report.evaluated_actions != actions.len() {
        return Err(PolicyAuthorityError::DependencyUnavailable);
    }
    let report_value =
        serde_json::to_value(&report).map_err(|_| PolicyAuthorityError::RequestInvalid)?;
    let report_digest = canonical_digest(&report)?;
    sqlx::query(
        "INSERT INTO policy_simulation_runs \
         (tenant_id,simulation_id,policy_id,revision,run_kind,baseline_bundle_digest,candidate_source_digest,\
          corpus_digest,evaluated_actions,difference_count,side_effect_count,impact_report_digest,impact_report,run_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12,$13)",
    )
    .bind(tenant)
    .bind(request.command.command_id)
    .bind(&request.command.policy_id)
    .bind(revision)
    .bind(run_kind)
    .bind(baseline_digest)
    .bind(&source.source_digest)
    .bind(sha256(&serde_jcs::to_vec(&actions).map_err(|_| PolicyAuthorityError::RequestInvalid)?))
    .bind(i64::try_from(actions.len()).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
    .bind(i64::try_from(report.differences.len()).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
    .bind(&report_digest)
    .bind(&report_value)
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    Ok((
        (if run_kind == "SHADOW" {
            "SHADOW_EVALUATED"
        } else {
            "SIMULATED"
        })
        .into(),
        report_digest,
    ))
}

async fn analyze_impact(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    let simulation_id = request.command.payload["simulation_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let row = sqlx::query(
        "SELECT revision,impact_report_digest,impact_report FROM policy_simulation_runs \
         WHERE tenant_id=$1 AND policy_id=$2 AND simulation_id=$3 AND side_effect_count=0",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(simulation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
    .ok_or(PolicyAuthorityError::NotFound)?;
    let simulation: ImpactReport = serde_json::from_value(row.get("impact_report"))
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let affected_agents = simulation
        .differences
        .iter()
        .map(|difference| difference.agent_id.clone())
        .collect::<BTreeSet<_>>();
    let affected_tools = simulation
        .differences
        .iter()
        .map(|difference| difference.tool.clone())
        .collect::<BTreeSet<_>>();
    let affected_resources = simulation
        .differences
        .iter()
        .map(|difference| difference.resource.clone())
        .collect::<BTreeSet<_>>();
    let maximum_risk = simulation
        .differences
        .iter()
        .map(|difference| difference.risk)
        .max()
        .unwrap_or(RiskLevel::Low);
    let report = json!({
        "schema_version": "agenttrust.policy-impact-report.v1",
        "impact_report_id": request.command.command_id,
        "tenant_id": tenant,
        "policy_id": request.command.policy_id,
        "revision": row.get::<i64, _>("revision"),
        "simulation_id": simulation_id,
        "simulation_digest": row.get::<String, _>("impact_report_digest"),
        "evaluated_actions": simulation.evaluated_actions,
        "difference_count": simulation.differences.len(),
        "affected_agents": affected_agents,
        "affected_tools": affected_tools,
        "affected_resources": affected_resources,
        "maximum_risk": maximum_risk,
        "generated_at": Utc::now(),
    });
    let report_digest = canonical_digest(&report)?;
    let mut sealed = report
        .as_object()
        .cloned()
        .ok_or(PolicyAuthorityError::DependencyUnavailable)?;
    sealed.insert(
        "impact_report_digest".into(),
        Value::String(report_digest.clone()),
    );
    sqlx::query(
        "INSERT INTO policy_impact_reports \
         (tenant_id,impact_report_id,policy_id,revision,simulation_id,impact_report_digest,impact_report,generated_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tenant)
    .bind(request.command.command_id)
    .bind(&request.command.policy_id)
    .bind(row.get::<i64, _>("revision"))
    .bind(simulation_id)
    .bind(&report_digest)
    .bind(Value::Object(sealed))
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    Ok(("IMPACT_ANALYZED".into(), report_digest))
}

async fn approve_policy(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    let (revision, _, author) = latest_source(tx, tenant, &request.command.policy_id).await?;
    if author == request.principal_subject {
        return Err(PolicyAuthorityError::ReviewSeparationRequired);
    }
    let review_digest = request.command.payload["review_digest"]
        .as_str()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    sqlx::query(
        "INSERT INTO policy_reviews \
         (tenant_id,policy_id,revision,review_id,reviewer_subject,decision,review_digest) \
         VALUES ($1,$2,$3,$4,$5,'APPROVE',$6)",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .bind(request.command.command_id)
    .bind(&request.principal_subject)
    .bind(review_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::ReviewSeparationRequired)?;
    let transitioned = sqlx::query(
        "UPDATE policy_sources SET lifecycle_state='REVIEW' \
         WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3 AND lifecycle_state IN ('VALIDATED','REVIEW')",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?
    .rows_affected();
    if transitioned != 1 {
        return Err(PolicyAuthorityError::ValidationBlocked);
    }
    Ok(("REVIEW".into(), review_digest.into()))
}

async fn sign_policy(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<(String, String), PolicyAuthorityError> {
    let (revision, source, author) = latest_source(tx, tenant, &request.command.policy_id).await?;
    let analysis_valid = sqlx::query_scalar::<_, bool>(
        "SELECT valid FROM policy_analysis_results WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?
    .unwrap_or(false);
    let simulated = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM policy_simulation_runs WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3 AND side_effect_count=0)",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let review_rows = sqlx::query(
        "SELECT review_id,reviewer_subject FROM policy_reviews WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3 AND decision='APPROVE'",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let reviewers = review_rows
        .iter()
        .map(|row| row.get::<String, _>("reviewer_subject"))
        .collect::<BTreeSet<_>>();
    if !analysis_valid || !simulated || reviewers.len() < 2 || reviewers.contains(&author) {
        return Err(PolicyAuthorityError::ReviewSeparationRequired);
    }
    let review_ids = review_rows
        .iter()
        .map(|row| row.get::<Uuid, _>("review_id").to_string())
        .collect::<BTreeSet<_>>();
    let compiler = PolicyCompiler::new(key_id.into(), signing_key.clone())
        .map_err(|_| PolicyAuthorityError::ConfigurationInvalid)?;
    let bundle = compiler
        .compile_revision(
            &source,
            u64::try_from(revision).map_err(|_| PolicyAuthorityError::StateConflict)?,
            review_ids,
        )
        .map_err(|_| PolicyAuthorityError::ValidationBlocked)?;
    let bundle_value =
        serde_json::to_value(&bundle).map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&bundle.signature)
        .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    let analysis = sqlx::query(
        "SELECT analysis_digest,findings FROM policy_analysis_results \
         WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    sqlx::query(
        "INSERT INTO policy_bundles \
         (tenant_id,bundle_id,version,policy_id,revision,source_digest,compiled_digest,analysis_digest,\
          static_analysis,key_id,signature,bundle_json,status,signed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'SIGNED',now())",
    )
    .bind(tenant)
    .bind(&bundle.bundle_id)
    .bind(&bundle.version)
    .bind(&request.command.policy_id)
    .bind(revision)
    .bind(&bundle.source_digest)
    .bind(&bundle.bundle_digest)
    .bind(analysis.get::<String, _>("analysis_digest"))
    .bind(analysis.get::<Value, _>("findings"))
    .bind(key_id)
    .bind(signature)
    .bind(&bundle_value)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    sqlx::query(
        "UPDATE policy_sources SET lifecycle_state='SIGNED' WHERE tenant_id=$1 AND policy_id=$2 AND revision=$3",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(revision)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    Ok(("SIGNED".into(), bundle.bundle_digest))
}

async fn deprecate_policy(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    let bundle_digest = request.command.payload["bundle_digest"]
        .as_str()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM policy_promotions WHERE tenant_id=$1 AND policy_id=$2 \
         AND bundle_digest=$3 AND state='ACTIVE')",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(bundle_digest)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::DependencyUnavailable)?;
    if active {
        return Err(PolicyAuthorityError::StateConflict);
    }
    let affected = sqlx::query(
        "UPDATE policy_bundles SET status='DEPRECATED',deprecated_at=now() \
         WHERE tenant_id=$1 AND policy_id=$2 AND compiled_digest=$3 AND deprecated_at IS NULL",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(bundle_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?
    .rows_affected();
    if affected != 1 {
        return Err(PolicyAuthorityError::NotFound);
    }
    Ok(("DEPRECATED".into(), bundle_digest.into()))
}

async fn create_exception(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    latest_source(tx, tenant, &request.command.policy_id).await?;
    let exception_id = request.command.payload["exception_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let owner = request.command.payload["owner_subject"]
        .as_str()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let expires_at = request.command.payload["expires_at"]
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let scope = string_set(&request.command.payload["scope"], 128, 2_048)?;
    let controls = string_set(&request.command.payload["compensating_controls"], 64, 256)?;
    let approvals = string_set(&request.command.payload["approval_ids"], 64, 256)?;
    if owner == request.principal_subject
        || approvals.len() < 2
        || !approvals.is_subset(&request.approval_ids)
        || expires_at <= Utc::now()
        || expires_at > Utc::now() + Duration::days(30)
    {
        return Err(PolicyAuthorityError::ReviewSeparationRequired);
    }
    let scope_digest = canonical_digest(&scope)?;
    let reason_digest = request.command.payload["reason_digest"]
        .as_str()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    sqlx::query(
        "INSERT INTO policy_exceptions \
         (tenant_id,exception_id,policy_id,scope_digest,owner_subject,approver_subjects,reason,\
          reason_digest,compensating_controls,issued_by,expires_at,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,now())",
    )
    .bind(tenant)
    .bind(exception_id)
    .bind(&request.command.policy_id)
    .bind(&scope_digest)
    .bind(owner)
    .bind(serde_json::to_value(&approvals).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
    .bind(reason_digest)
    .bind(serde_json::to_value(&controls).map_err(|_| PolicyAuthorityError::RequestInvalid)?)
    .bind(&request.principal_subject)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?;
    Ok(("EXCEPTION_ACTIVE".into(), scope_digest))
}

async fn revoke_exception(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &PolicyExecutorRequest,
) -> Result<(String, String), PolicyAuthorityError> {
    let exception_id = request.command.payload["exception_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let reason_digest = request.command.payload["reason_digest"]
        .as_str()
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let affected = sqlx::query(
        "UPDATE policy_exceptions SET revoked_at=now(),revocation_reason_digest=$4 \
         WHERE tenant_id=$1 AND policy_id=$2 AND exception_id=$3 \
         AND revoked_at IS NULL AND expired_at IS NULL AND expires_at>now()",
    )
    .bind(tenant)
    .bind(&request.command.policy_id)
    .bind(exception_id)
    .bind(reason_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| PolicyAuthorityError::StateConflict)?
    .rows_affected();
    if affected != 1 {
        return Err(PolicyAuthorityError::NotFound);
    }
    Ok(("EXCEPTION_REVOKED".into(), reason_digest.into()))
}

fn validate_execution(
    binding: &PolicyExecutionBinding,
    request: &PolicyExecutorRequest,
) -> Result<(), PolicyAuthorityError> {
    if request.schema_version != POLICY_EXECUTOR_REQUEST_SCHEMA
        || request.command.schema_version != POLICY_COMMAND_SCHEMA
        || binding.tenant_id.0 != request.command.tenant_id.to_string()
        || !identifier(&request.principal_subject, 256)
        || !digest(&request.principal_assertion_digest)
        || !digest(&binding.action_hash)
        || !digest(&binding.fence_digest)
        || !valid_idempotency_key(&binding.idempotency_key)
        || !identifier(&binding.trace_id, 256)
        || binding.resource_version != request.command.expected_resource_version
        || !command_payload_shape(&request.command)
    {
        return Err(PolicyAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn parse_tenant(tenant: &TenantId) -> Result<Uuid, PolicyAuthorityError> {
    Uuid::parse_str(&tenant.0)
        .ok()
        .filter(|value| value.to_string() == tenant.0)
        .ok_or(PolicyAuthorityError::RequestInvalid)
}

fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, PolicyAuthorityError> {
    Ok(sha256(
        &serde_jcs::to_vec(value).map_err(|_| PolicyAuthorityError::RequestInvalid)?,
    ))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn string_set(
    value: &Value,
    maximum_items: usize,
    maximum_length: usize,
) -> Result<BTreeSet<String>, PolicyAuthorityError> {
    let items = value
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= maximum_items)
        .ok_or(PolicyAuthorityError::RequestInvalid)?;
    let values = items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= maximum_length
                        && !value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
                })
                .map(str::to_owned)
                .ok_or(PolicyAuthorityError::RequestInvalid)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if values.len() != items.len() {
        return Err(PolicyAuthorityError::RequestInvalid);
    }
    Ok(values)
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn activation_token(path: &std::path::Path) -> Result<String, PolicyAuthorityError> {
    if !path.is_absolute() {
        return Err(PolicyAuthorityError::ConfigurationInvalid);
    }
    let raw =
        std::fs::read_to_string(path).map_err(|_| PolicyAuthorityError::ConfigurationInvalid)?;
    let value = raw.trim();
    if !(16..=8_192).contains(&value.len())
        || value.contains(char::is_whitespace)
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(PolicyAuthorityError::ConfigurationInvalid);
    }
    Ok(value.to_string())
}
