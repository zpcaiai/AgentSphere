//! Fail-closed policy enforcement, obligations, minimal approval, and execution grants.

use agent_trust_action_ir::{CanonicalAction, PolicyInput, hash as action_hash};
use agent_trust_contracts::{
    ActionHash, Decision, EffectClass, ExecutionAuthorization, MinimalApprovalGrant, Obligation,
    PolicyDecision, ResourceVersion, RiskLevel, SchemaVersion,
};
use agent_trust_registry::{ResolvedToolSnapshot, ToolRegistry};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};
use thiserror::Error;
use uuid::Uuid;

pub const POLICY_SCHEMA_VERSION: &str = "agenttrust.policy.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementStage {
    PreApproval,
    PreExecution,
    Continuous,
}

#[derive(Debug, Clone)]
pub struct EnforcementRequest {
    pub stage: EnforcementStage,
    pub action: CanonicalAction,
    pub action_hash: ActionHash,
    pub tool: ResolvedToolSnapshot,
    pub policy_input: PolicyInput,
    pub approval: Option<MinimalApprovalGrant>,
    pub idempotency_key: Option<String>,
    pub identity_uses_dev_verifier: bool,
    pub resource_state_fresh: bool,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReceipt {
    pub obligation_kind: String,
    pub receipt_hash: String,
    pub enforced_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EnforcementContext {
    pub action_hash: ActionHash,
    pub stage: EnforcementStage,
    pub now: DateTime<Utc>,
}

#[async_trait]
pub trait ObligationHandler: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn enforce(
        &self,
        obligation: &Obligation,
        context: &EnforcementContext,
    ) -> Result<EnforcementReceipt, PolicyError>;
}

#[async_trait]
pub trait RuntimeControlPort: Send + Sync {
    async fn pause(&self, action_hash: &ActionHash) -> Result<(), PolicyError>;
    async fn kill(&self, action_hash: &ActionHash) -> Result<(), PolicyError>;
    async fn security_alert(&self, code: &str, action_hash: &ActionHash)
    -> Result<(), PolicyError>;
}

pub struct RuntimeObligationHandler {
    runtime: Arc<dyn RuntimeControlPort>,
}
impl RuntimeObligationHandler {
    pub fn new(runtime: Arc<dyn RuntimeControlPort>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl ObligationHandler for RuntimeObligationHandler {
    fn kind(&self) -> &'static str {
        "runtime"
    }
    async fn enforce(
        &self,
        obligation: &Obligation,
        context: &EnforcementContext,
    ) -> Result<EnforcementReceipt, PolicyError> {
        let kind = match obligation {
            Obligation::PauseTask => {
                self.runtime.pause(&context.action_hash).await?;
                "PAUSE_TASK"
            }
            Obligation::KillTask => {
                self.runtime.kill(&context.action_hash).await?;
                "KILL_TASK"
            }
            Obligation::EmitSecurityAlert { code } => {
                self.runtime
                    .security_alert(code, &context.action_hash)
                    .await?;
                "EMIT_SECURITY_ALERT"
            }
            _ => return Err(PolicyError::UnknownObligation),
        };
        Ok(receipt(kind, context))
    }
}

fn receipt(kind: &str, context: &EnforcementContext) -> EnforcementReceipt {
    let receipt_hash = hex_string(
        Sha256::digest(
            format!("{}:{}:{:?}", kind, context.action_hash.0, context.stage).as_bytes(),
        )
        .as_slice(),
    );
    EnforcementReceipt {
        obligation_kind: kind.into(),
        receipt_hash,
        enforced_at: context.now,
    }
}

#[async_trait]
pub trait PolicyDecisionPointPort: Send + Sync {
    async fn evaluate(
        &self,
        input: &PolicyInput,
        stage: EnforcementStage,
    ) -> Result<PolicyDecision, PolicyError>;
}

pub struct HttpPolicyDecisionPoint {
    client: reqwest::Client,
    endpoint: String,
    timeout: std::time::Duration,
}

impl HttpPolicyDecisionPoint {
    pub fn new(
        endpoint: impl Into<String>,
        timeout: std::time::Duration,
    ) -> Result<Self, PolicyError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PolicyError::PdpUnavailable)?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            timeout,
        })
    }
}

#[derive(Serialize)]
struct PdpRequest<'a> {
    input: &'a PolicyInput,
    stage: EnforcementStage,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PdpResponse {
    result: PolicyDecision,
}

#[async_trait]
impl PolicyDecisionPointPort for HttpPolicyDecisionPoint {
    async fn evaluate(
        &self,
        input: &PolicyInput,
        stage: EnforcementStage,
    ) -> Result<PolicyDecision, PolicyError> {
        let response = self
            .client
            .post(&self.endpoint)
            .timeout(self.timeout)
            .json(&PdpRequest { input, stage })
            .send()
            .await
            .map_err(|_| PolicyError::PdpUnavailable)?;
        if !response.status().is_success() {
            return Err(PolicyError::PdpUnavailable);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| PolicyError::DecisionInvalid)?;
        if bytes.len() > 262_144 {
            return Err(PolicyError::DecisionInvalid);
        }
        serde_json::from_slice::<PdpResponse>(&bytes)
            .map(|response| response.result)
            .map_err(|_| PolicyError::DecisionInvalid)
    }
}

#[derive(Default)]
pub struct MinimalApprovalKernel {
    used: RwLock<BTreeSet<String>>,
}

impl MinimalApprovalKernel {
    pub fn verify_and_consume(
        &self,
        grant: &MinimalApprovalGrant,
        request: &EnforcementRequest,
        policy_version: &agent_trust_contracts::PolicyVersion,
    ) -> Result<(), PolicyError> {
        if request.now >= grant.expires_at
            || grant.action_hash != request.action_hash
            || grant.resource_version.0
                != request
                    .action
                    .current_state_version
                    .clone()
                    .unwrap_or_default()
            || &grant.policy_version != policy_version
            || grant.task_id != request.action.task_id
            || grant.step_id != request.action.step_id
        {
            return Err(PolicyError::ApprovalMismatch);
        }
        if grant.single_use && !self.used.write().insert(grant.approval_id.0.clone()) {
            return Err(PolicyError::ApprovalMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum EnforcementOutcome {
    PreApprovalPassed {
        decision: PolicyDecision,
        receipts: Vec<EnforcementReceipt>,
    },
    ApprovalRequired {
        decision: PolicyDecision,
    },
    ExecutionAuthorized {
        decision: PolicyDecision,
        authorization: Box<ExecutionAuthorization>,
        receipts: Vec<EnforcementReceipt>,
    },
    PauseRequired {
        decision: PolicyDecision,
        receipts: Vec<EnforcementReceipt>,
    },
    KillRequired {
        decision: PolicyDecision,
        receipts: Vec<EnforcementReceipt>,
    },
}

pub struct PolicyEnforcementPoint<R: ToolRegistry, P: PolicyDecisionPointPort> {
    registry: Arc<R>,
    pdp: Arc<P>,
    approval: Arc<MinimalApprovalKernel>,
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
    allowed_policy_bundles: BTreeSet<String>,
    runtime_handler: Option<Arc<dyn ObligationHandler>>,
}

impl<R: ToolRegistry, P: PolicyDecisionPointPort> PolicyEnforcementPoint<R, P> {
    pub fn new(
        registry: Arc<R>,
        pdp: Arc<P>,
        approval: Arc<MinimalApprovalKernel>,
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
        allowed_policy_bundles: BTreeSet<String>,
    ) -> Self {
        Self {
            registry,
            pdp,
            approval,
            issuer,
            key_id,
            signing_key,
            allowed_policy_bundles,
            runtime_handler: None,
        }
    }
    pub fn with_runtime_handler(mut self, handler: Arc<dyn ObligationHandler>) -> Self {
        self.runtime_handler = Some(handler);
        self
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub async fn enforce(
        &self,
        request: EnforcementRequest,
    ) -> Result<EnforcementOutcome, PolicyError> {
        self.local_hard_guard(&request).await?;
        let input_hash = policy_input_hash(&request.policy_input)?;
        let decision = self
            .pdp
            .evaluate(&request.policy_input, request.stage)
            .await?;
        validate_decision(
            &decision,
            &input_hash,
            request.now,
            &self.allowed_policy_bundles,
        )?;
        if matches!(decision.decision, Decision::Deny) {
            return Err(PolicyError::LocalGuardDenied);
        }

        let approval_required = decision.decision == Decision::RequireApproval
            || decision
                .obligations
                .iter()
                .any(|item| matches!(item, Obligation::RequireApproval { .. }))
            || request.tool.approval_profile != "none";
        if request.stage == EnforcementStage::PreApproval {
            if approval_required {
                return Ok(EnforcementOutcome::ApprovalRequired { decision });
            }
            let receipts = self
                .enforce_obligations(&decision.obligations, &request)
                .await?;
            return Ok(EnforcementOutcome::PreApprovalPassed { decision, receipts });
        }
        if request.stage == EnforcementStage::Continuous {
            let receipts = self
                .enforce_obligations(&decision.obligations, &request)
                .await?;
            return match decision.decision {
                Decision::Pause => Ok(EnforcementOutcome::PauseRequired { decision, receipts }),
                Decision::Kill => Ok(EnforcementOutcome::KillRequired { decision, receipts }),
                Decision::Allow => Ok(EnforcementOutcome::PreApprovalPassed { decision, receipts }),
                _ => Err(PolicyError::FailClosed),
            };
        }
        if approval_required {
            let grant = request
                .approval
                .as_ref()
                .ok_or(PolicyError::ApprovalRequired)?;
            self.approval
                .verify_and_consume(grant, &request, &decision.policy_version)?;
        }
        if decision.decision != Decision::Allow && decision.decision != Decision::RequireApproval {
            return Err(PolicyError::FailClosed);
        }
        let receipts = self
            .enforce_obligations(&decision.obligations, &request)
            .await?;
        let authorization = self.issue_execution_authorization(&request, &decision)?;
        Ok(EnforcementOutcome::ExecutionAuthorized {
            decision,
            authorization: Box::new(authorization),
            receipts,
        })
    }

    async fn local_hard_guard(&self, request: &EnforcementRequest) -> Result<(), PolicyError> {
        if action_hash(&request.action).map_err(|_| PolicyError::LocalGuardDenied)?
            != request.action_hash
        {
            return Err(PolicyError::InputHashMismatch);
        }
        if request.action.environment.tenant_id != request.action.agent.tenant_id
            || request.action.resource.tenant_id != request.action.environment.tenant_id
        {
            return Err(PolicyError::LocalGuardDenied);
        }
        if request
            .action
            .environment
            .deployment
            .eq_ignore_ascii_case("production")
            && request.identity_uses_dev_verifier
        {
            return Err(PolicyError::LocalGuardDenied);
        }
        if self
            .registry
            .is_revoked(&request.action.tool, &request.tool.implementation.digest)
            .await
            .map_err(|_| PolicyError::RegistryRevoked)?
        {
            return Err(PolicyError::RegistryRevoked);
        }
        self.registry
            .validate_arguments(&request.tool, request.action.arguments())
            .await
            .map_err(|_| PolicyError::LocalGuardDenied)?;
        let is_write = request.tool.effect_class != EffectClass::Pure;
        if is_write
            && request
                .idempotency_key
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        {
            return Err(PolicyError::LocalGuardDenied);
        }
        if request.tool.risk_level >= RiskLevel::High
            && (!request.resource_state_fresh
                || request
                    .action
                    .current_state_version
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty())
        {
            return Err(PolicyError::ResourceStateStale);
        }
        if request.tool.effect_class == EffectClass::Irreversible
            && request.tool.approval_profile == "none"
        {
            return Err(PolicyError::LocalGuardDenied);
        }
        if request
            .action
            .credential_refs
            .iter()
            .any(|reference| reference.profile == "inline")
        {
            return Err(PolicyError::LocalGuardDenied);
        }
        Ok(())
    }

    async fn enforce_obligations(
        &self,
        obligations: &[Obligation],
        request: &EnforcementRequest,
    ) -> Result<Vec<EnforcementReceipt>, PolicyError> {
        let context = EnforcementContext {
            action_hash: request.action_hash.clone(),
            stage: request.stage,
            now: request.now,
        };
        let mut receipts = Vec::new();
        for obligation in obligations {
            match obligation {
                Obligation::PauseTask
                | Obligation::KillTask
                | Obligation::EmitSecurityAlert { .. } => {
                    let handler = self
                        .runtime_handler
                        .as_ref()
                        .ok_or(PolicyError::ObligationFailed)?;
                    receipts.push(handler.enforce(obligation, &context).await?);
                }
                Obligation::RequireSimulation if !request.action.environment.simulation => {
                    return Err(PolicyError::ObligationFailed);
                }
                Obligation::RequireFreshResourceState if !request.resource_state_fresh => {
                    return Err(PolicyError::ResourceStateStale);
                }
                Obligation::RequireResourceVersion
                    if request
                        .action
                        .current_state_version
                        .as_deref()
                        .unwrap_or_default()
                        .is_empty() =>
                {
                    return Err(PolicyError::ResourceStateStale);
                }
                _ => receipts.push(receipt(obligation_name(obligation), &context)),
            }
        }
        Ok(receipts)
    }

    fn issue_execution_authorization(
        &self,
        request: &EnforcementRequest,
        decision: &PolicyDecision,
    ) -> Result<ExecutionAuthorization, PolicyError> {
        let obligations = ObligationConfig::from_obligations(&decision.obligations, &request.tool);
        let expires_at = request.now + chrono::Duration::seconds(60);
        let mut authorization = ExecutionAuthorization {
            schema_version: SchemaVersion(POLICY_SCHEMA_VERSION.into()),
            authorization_id: Uuid::new_v4().to_string(),
            action_hash: request.action_hash.clone(),
            tool_snapshot_hash: request.tool.snapshot_hash.clone(),
            policy_decision_id: decision.decision_id.clone(),
            approval_ids: request
                .approval
                .iter()
                .map(|grant| grant.approval_id.clone())
                .collect(),
            resource_version: ResourceVersion(
                request
                    .action
                    .current_state_version
                    .clone()
                    .unwrap_or_else(|| "unversioned-read".into()),
            ),
            sandbox_profile: obligations.sandbox_profile,
            network_profile: obligations.network_profile,
            credential_profile: obligations.credential_profile,
            max_execution_ms: obligations
                .max_execution_ms
                .min(request.tool.limits.timeout_ms),
            max_result_bytes: obligations
                .max_result_bytes
                .min(request.tool.limits.max_result_bytes),
            issued_at: request.now,
            expires_at,
            single_use: true,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        authorization
            .sign(&self.signing_key)
            .map_err(|_| PolicyError::ExecutionAuthInvalid)?;
        Ok(authorization)
    }
}

struct ObligationConfig {
    sandbox_profile: String,
    network_profile: String,
    credential_profile: String,
    max_execution_ms: u64,
    max_result_bytes: u64,
}
impl ObligationConfig {
    fn from_obligations(obligations: &[Obligation], tool: &ResolvedToolSnapshot) -> Self {
        let mut config = Self {
            sandbox_profile: tool.executor_profile.clone(),
            network_profile: tool.network_profile_ref.clone(),
            credential_profile: tool.credential_profile.clone(),
            max_execution_ms: tool.limits.timeout_ms,
            max_result_bytes: tool.limits.max_result_bytes,
        };
        for obligation in obligations {
            match obligation {
                Obligation::UseSandboxProfile { profile } => {
                    config.sandbox_profile = profile.clone()
                }
                Obligation::UseNetworkProfile { profile } => {
                    config.network_profile = profile.clone()
                }
                Obligation::UseCredentialProfile { profile } => {
                    config.credential_profile = profile.clone()
                }
                Obligation::MaxExecutionTime { milliseconds } => {
                    config.max_execution_ms = config.max_execution_ms.min(*milliseconds)
                }
                Obligation::MaxResultBytes { bytes } => {
                    config.max_result_bytes = config.max_result_bytes.min(*bytes)
                }
                _ => {}
            }
        }
        config
    }
}

fn obligation_name(obligation: &Obligation) -> &'static str {
    match obligation {
        Obligation::RequireApproval { .. } => "REQUIRE_APPROVAL",
        Obligation::UseSandboxProfile { .. } => "USE_SANDBOX_PROFILE",
        Obligation::UseNetworkProfile { .. } => "USE_NETWORK_PROFILE",
        Obligation::UseFilesystemProfile { .. } => "USE_FILESYSTEM_PROFILE",
        Obligation::UseCredentialProfile { .. } => "USE_CREDENTIAL_PROFILE",
        Obligation::MaxExecutionTime { .. } => "MAX_EXECUTION_TIME",
        Obligation::MaxResultBytes { .. } => "MAX_RESULT_BYTES",
        Obligation::RedactFields { .. } => "REDACT_FIELDS",
        Obligation::RequireFreshResourceState => "REQUIRE_FRESH_RESOURCE_STATE",
        Obligation::RequireResourceVersion => "REQUIRE_RESOURCE_VERSION",
        Obligation::RequireSimulation => "REQUIRE_SIMULATION",
        Obligation::PauseTask => "PAUSE_TASK",
        Obligation::KillTask => "KILL_TASK",
        Obligation::EmitSecurityAlert { .. } => "EMIT_SECURITY_ALERT",
        Obligation::SetRetryLimit { .. } => "SET_RETRY_LIMIT",
        Obligation::RequireEvaluator { .. } => "REQUIRE_EVALUATOR",
    }
}

pub fn policy_input_hash(input: &PolicyInput) -> Result<String, PolicyError> {
    Ok(hex_string(
        Sha256::digest(serde_jcs::to_vec(input).map_err(|_| PolicyError::DecisionInvalid)?)
            .as_slice(),
    ))
}

fn validate_decision(
    decision: &PolicyDecision,
    input_hash: &str,
    now: DateTime<Utc>,
    allowed_bundles: &BTreeSet<String>,
) -> Result<(), PolicyError> {
    if decision.schema_version.0 != POLICY_SCHEMA_VERSION
        || decision.input_hash != input_hash
        || now < decision.evaluated_at
        || now >= decision.expires_at
        || !allowed_bundles.contains(&decision.policy_bundle_hash)
    {
        return Err(PolicyError::DecisionInvalid);
    }
    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("POLICY_LOCAL_GUARD_DENIED")]
    LocalGuardDenied,
    #[error("POLICY_PDP_UNAVAILABLE")]
    PdpUnavailable,
    #[error("POLICY_DECISION_INVALID")]
    DecisionInvalid,
    #[error("POLICY_INPUT_HASH_MISMATCH")]
    InputHashMismatch,
    #[error("POLICY_UNKNOWN_OBLIGATION")]
    UnknownObligation,
    #[error("POLICY_OBLIGATION_FAILED")]
    ObligationFailed,
    #[error("POLICY_APPROVAL_REQUIRED")]
    ApprovalRequired,
    #[error("POLICY_APPROVAL_MISMATCH")]
    ApprovalMismatch,
    #[error("POLICY_RESOURCE_STATE_STALE")]
    ResourceStateStale,
    #[error("POLICY_REGISTRY_REVOKED")]
    RegistryRevoked,
    #[error("POLICY_EXECUTION_AUTH_INVALID")]
    ExecutionAuthInvalid,
    #[error("POLICY_FAIL_CLOSED")]
    FailClosed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_action_ir::{
        ActionDraft, NormalizationContext, RegistryPolicySnapshot, RuntimeContext,
        TrajectoryRiskSnapshot, TypedPayload, normalize, to_policy_input,
    };
    use agent_trust_contracts::*;
    use agent_trust_registry::*;
    use serde_json::{Map, Value};
    use std::collections::BTreeMap;

    struct AllowPdp;
    #[async_trait]
    impl PolicyDecisionPointPort for AllowPdp {
        async fn evaluate(
            &self,
            input: &PolicyInput,
            _: EnforcementStage,
        ) -> Result<PolicyDecision, PolicyError> {
            Ok(PolicyDecision {
                schema_version: SchemaVersion(POLICY_SCHEMA_VERSION.into()),
                decision_id: "d".into(),
                decision: Decision::Allow,
                reason_codes: vec!["ALLOW_TEST".into()],
                policy_version: PolicyVersion("p1".into()),
                policy_bundle_hash: "bundle".into(),
                input_hash: policy_input_hash(input)?,
                evaluated_at: Utc::now() - chrono::Duration::seconds(1),
                expires_at: Utc::now() + chrono::Duration::minutes(1),
                obligations: vec![],
                risk_summary: RiskLevel::Low,
            })
        }
    }
    struct DownPdp;
    #[async_trait]
    impl PolicyDecisionPointPort for DownPdp {
        async fn evaluate(
            &self,
            _: &PolicyInput,
            _: EnforcementStage,
        ) -> Result<PolicyDecision, PolicyError> {
            Err(PolicyError::PdpUnavailable)
        }
    }

    fn registry_and_request(
        effect: EffectClass,
    ) -> (Arc<InMemoryToolRegistry>, EnforcementRequest) {
        let tenant = TenantId::new();
        let registry = Arc::new(InMemoryToolRegistry::new());
        let signing = SigningKey::from_bytes(&[1u8; 32]);
        registry.add_publisher_key("k", signing.verifying_key());
        let mut manifest = ToolManifest {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            tool_id: ToolId("coding.repo-read".into()),
            tool_version: ToolVersion("1.0.0".into()),
            status: ToolVersionStatus::Draft,
            domain: "coding".into(),
            display_name: "read".into(),
            description: "read".into(),
            input_schema: serde_json::json!({"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"}},"required":["path"]}),
            output_schema: serde_json::json!({"type":"object","additionalProperties":false}),
            effect_class: effect,
            risk_level: RiskLevel::Low,
            executor_profile: "local".into(),
            credential_profile: if effect == EffectClass::Pure {
                "none".into()
            } else {
                "repo".into()
            },
            approval_profile: "none".into(),
            compensation: None,
            limits: ToolLimits {
                timeout_ms: 5000,
                max_result_bytes: 4096,
            },
            network_profile_ref: "none".into(),
            filesystem_profile_ref: "repo-ro".into(),
            implementation: ToolImplementation {
                kind: ImplementationKind::InternalService,
                digest: format!("sha256:{}", "b".repeat(64)),
                executor_id: "reader".into(),
            },
            allowed_tenants: BTreeSet::from([tenant.clone()]),
            signature: None,
        };
        if effect == EffectClass::Compensatable {
            manifest.compensation = Some(CompensationBinding {
                tool: manifest.tool_ref(),
                precondition_kind: "version".into(),
            });
        }
        let tool_ref = manifest.tool_ref();
        registry
            .create_draft(manifest)
            .unwrap_or_else(|_| panic!("draft"));
        registry
            .validate_version(&tool_ref)
            .unwrap_or_else(|_| panic!("validate"));
        registry
            .sign_version(&tool_ref, "publisher".into(), "k".into(), &signing)
            .unwrap_or_else(|_| panic!("sign"));
        registry
            .activate(&tool_ref)
            .unwrap_or_else(|_| panic!("activate"));
        let snapshot = futures::executor::block_on(registry.resolve_exact(&tenant, &tool_ref))
            .unwrap_or_else(|_| panic!("snapshot"));
        let draft = ActionDraft {
            schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
            action_id: ActionId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            agent: AgentIdentity {
                schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
                agent_type: "coding".into(),
                agent_instance_id: AgentInstanceId::new(),
                organization_id: "org".into(),
                tenant_id: tenant.clone(),
                owner_subject: "user".into(),
                model_provider: "test".into(),
                model_id: "m".into(),
                agent_version: "1".into(),
                deployment_environment: "dev".into(),
                trust_level: "verified".into(),
                auth_context_ref: "auth".into(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
            intent: Intent {
                goal_hash: "g".into(),
                operation: if effect == EffectClass::Pure {
                    "read".into()
                } else {
                    "write".into()
                },
                justification_code: "USER".into(),
                safe_summary: None,
            },
            tool: tool_ref,
            payload: TypedPayload {
                type_id: "coding.command.v1".into(),
                schema_version: "1".into(),
                data: Map::from_iter([("path".into(), Value::String("src".into()))]),
            },
            resource: ResourceSelector {
                scheme: "repo".into(),
                tenant_id: tenant.clone(),
                locator: "repo:a".into(),
                version: Some(ResourceVersion("v1".into())),
            },
            environment: ExecutionEnvironment {
                tenant_id: tenant,
                deployment: "dev".into(),
                region: "local".into(),
                zone: None,
                simulation: false,
            },
            current_state_version: if effect == EffectClass::Pure {
                None
            } else {
                Some("v1".into())
            },
            risk: RiskContext {
                declared_risk: RiskLevel::Low,
                trajectory_risk_ref: None,
                scope_delta: 0,
                automation_allowed: true,
            },
            data: DataContext {
                classification: DataClassification::Internal,
                jurisdiction: "CN".into(),
                export_constraints: vec![],
            },
            expected_outcome: ExpectedOutcome {
                metric: "ok".into(),
                operator: "eq".into(),
                target: Value::Bool(true),
            },
            credential_refs: vec![],
            requested_at: Utc::now(),
            extensions: BTreeMap::new(),
        };
        let action =
            normalize(draft, &NormalizationContext::default()).unwrap_or_else(|_| panic!("action"));
        let action_hash = action_hash(&action).unwrap_or_else(|_| panic!("hash"));
        let policy_snapshot = RegistryPolicySnapshot {
            snapshot_hash: snapshot.snapshot_hash.clone(),
            tool_id: snapshot.tool_id.0.clone(),
            tool_version: snapshot.tool_version.0.clone(),
            risk: snapshot.risk_level,
            effect: snapshot.effect_class,
            implementation_digest: snapshot.implementation.digest.clone(),
        };
        let input = to_policy_input(
            &action,
            &policy_snapshot,
            &RuntimeContext {
                identity_subject: "user".into(),
                prior_approvals: vec![],
                budget_remaining_microunits: 1,
            },
            &TrajectoryRiskSnapshot {
                version: "1".into(),
                accumulated_resources: vec![],
                anomaly_score_millionths: 0,
            },
        )
        .unwrap_or_else(|_| panic!("input"));
        (
            registry,
            EnforcementRequest {
                stage: EnforcementStage::PreExecution,
                action,
                action_hash,
                tool: snapshot,
                policy_input: input,
                approval: None,
                idempotency_key: if effect == EffectClass::Pure {
                    None
                } else {
                    Some("key".into())
                },
                identity_uses_dev_verifier: false,
                resource_state_fresh: true,
                now: Utc::now(),
            },
        )
    }

    #[tokio::test]
    async fn allow_still_requires_local_guards_and_signed_authorization() {
        let (registry, request) = registry_and_request(EffectClass::Pure);
        let pep = PolicyEnforcementPoint::new(
            registry,
            Arc::new(AllowPdp),
            Arc::new(MinimalApprovalKernel::default()),
            "pep".into(),
            "key".into(),
            SigningKey::from_bytes(&[2u8; 32]),
            BTreeSet::from(["bundle".into()]),
        );
        let result = pep
            .enforce(request)
            .await
            .unwrap_or_else(|_| panic!("enforce"));
        match result {
            EnforcementOutcome::ExecutionAuthorized { authorization, .. } => assert!(
                authorization
                    .verify(&pep.verifying_key(), Utc::now())
                    .is_ok()
            ),
            _ => panic!("not authorized"),
        }
    }

    #[tokio::test]
    async fn pdp_unavailable_fails_closed() {
        let (registry, request) = registry_and_request(EffectClass::Pure);
        let pep = PolicyEnforcementPoint::new(
            registry,
            Arc::new(DownPdp),
            Arc::new(MinimalApprovalKernel::default()),
            "pep".into(),
            "key".into(),
            SigningKey::from_bytes(&[2u8; 32]),
            BTreeSet::from(["bundle".into()]),
        );
        assert!(matches!(
            pep.enforce(request).await,
            Err(PolicyError::PdpUnavailable)
        ));
    }

    #[tokio::test]
    async fn write_without_idempotency_is_denied_before_pdp() {
        let (registry, mut request) = registry_and_request(EffectClass::Compensatable);
        request.idempotency_key = None;
        let pep = PolicyEnforcementPoint::new(
            registry,
            Arc::new(AllowPdp),
            Arc::new(MinimalApprovalKernel::default()),
            "pep".into(),
            "key".into(),
            SigningKey::from_bytes(&[2u8; 32]),
            BTreeSet::from(["bundle".into()]),
        );
        assert!(matches!(
            pep.enforce(request).await,
            Err(PolicyError::LocalGuardDenied)
        ));
    }
}
