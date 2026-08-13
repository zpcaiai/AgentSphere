//! Authoritative cross-service contracts for the Agent Trust control plane.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const CONTRACT_SCHEMA_VERSION: &str = "agenttrust.contracts.v1";

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                Uuid::parse_str(&value).map_err(|_| ContractError::InvalidId(stringify!($name)))?;
                Ok(Self(value))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

id_type!(TaskId);
id_type!(StepId);
id_type!(ActionId);
id_type!(AgentInstanceId);
id_type!(TenantId);
id_type!(ApprovalId);
id_type!(ExecutionId);
id_type!(TraceId);
id_type!(GoalId);
id_type!(PlanId);
id_type!(LeaseId);

macro_rules! string_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);
    };
}

string_type!(ToolId);
string_type!(ToolVersion);
string_type!(CapabilityId);
string_type!(PolicyVersion);
string_type!(ArtifactRef);
string_type!(SchemaVersion);
string_type!(ResourceVersion);
string_type!(IdempotencyKey);
string_type!(ActionHash);
string_type!(DigestValue);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskStatus {
    Created,
    Planned,
    PolicyChecked,
    ApprovalPending,
    Approved,
    Running,
    PauseRequested,
    Paused,
    CancelRequested,
    Cancelling,
    KillRequested,
    Killed,
    Verifying,
    Completed,
    Denied,
    Failed,
    EvaluationFailed,
    Compensating,
    RolledBack,
    NeedsHuman,
    ManualRecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    Prepared,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Killed,
    Compensating,
    Compensated,
    CompensationFailed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectClass {
    Pure,
    Idempotent,
    Compensatable,
    Irreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
    Pause,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    Regulated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataPolicyRequest {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub classification: DataClassification,
    pub source_jurisdiction: String,
    pub destination_jurisdiction: String,
    pub destination_kind: String,
    pub deployment_profile: String,
    pub contains_secret: bool,
    pub cross_domain_approval_id: Option<ApprovalId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataPolicyDecision {
    pub schema_version: SchemaVersion,
    pub allowed: bool,
    pub policy_version: PolicyVersion,
    pub reason_codes: Vec<String>,
    pub required_transformations: Vec<String>,
    pub maximum_retention_seconds: u64,
}

pub trait DataPolicyPort: Send + Sync {
    fn evaluate(&self, request: &DataPolicyRequest) -> Result<DataPolicyDecision, ContractError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluationStatus {
    Pass,
    Fail,
    NeedsHuman,
    RolledBack,
    ManualRecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub schema_version: SchemaVersion,
    pub agent_type: String,
    pub agent_instance_id: AgentInstanceId,
    pub organization_id: String,
    pub tenant_id: TenantId,
    pub owner_subject: String,
    pub model_provider: String,
    pub model_id: String,
    pub agent_version: String,
    pub deployment_environment: String,
    pub trust_level: String,
    pub auth_context_ref: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ToolRef {
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
}

impl ToolRef {
    pub fn validate_exact(&self) -> Result<(), ContractError> {
        if self.tool_version.0.is_empty()
            || self.tool_version.0.eq_ignore_ascii_case("latest")
            || self.tool_version.0.contains('*')
        {
            return Err(ContractError::VersionRequired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub goal_hash: String,
    pub operation: String,
    pub justification_code: String,
    pub safe_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelector {
    pub scheme: String,
    pub tenant_id: TenantId,
    pub locator: String,
    pub version: Option<ResourceVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvironment {
    pub tenant_id: TenantId,
    pub deployment: String,
    pub region: String,
    pub zone: Option<String>,
    pub simulation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RiskContext {
    pub declared_risk: RiskLevel,
    pub trajectory_risk_ref: Option<String>,
    pub scope_delta: u32,
    pub automation_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataContext {
    pub classification: DataClassification,
    pub jurisdiction: String,
    pub export_constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOutcome {
    pub metric: String,
    pub operator: String,
    pub target: Value,
}

pub type StrictJsonObject = Map<String, Value>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedGoal {
    pub schema_version: SchemaVersion,
    pub goal_id: GoalId,
    pub normalized_goal: String,
    pub goal_hash: String,
    pub constraints: BTreeMap<String, String>,
    pub approved_by: String,
    pub signed_at: DateTime<Utc>,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub step_id: StepId,
    pub sequence: u32,
    pub intent: String,
    pub dependencies: Vec<StepId>,
    pub tool: Option<ToolRef>,
    pub resource_scope: Vec<String>,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanManifest {
    pub schema_version: SchemaVersion,
    pub plan_id: PlanId,
    pub goal_hash: String,
    pub plan_hash: String,
    pub steps: Vec<PlanStep>,
    pub max_scope: Vec<String>,
    pub risk_budget: RiskLevel,
    pub cost_budget_microunits: u64,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationEnvelope {
    pub schema_version: SchemaVersion,
    pub parent_agent: AgentInstanceId,
    pub child_agent: AgentInstanceId,
    pub delegated_tools: BTreeSet<ToolRef>,
    pub delegated_resources: BTreeSet<String>,
    pub budget_ceiling_microunits: u64,
    pub expiry: DateTime<Utc>,
}

impl DelegationEnvelope {
    pub fn is_within(&self, parent: &AuthorizationLease) -> bool {
        self.delegated_tools.is_subset(&parent.allowed_tools)
            && self
                .delegated_resources
                .is_subset(&parent.allowed_resources)
            && self.expiry <= parent.valid_until
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLease {
    pub schema_version: SchemaVersion,
    pub lease_id: LeaseId,
    pub task_id: TaskId,
    pub goal_hash: String,
    pub plan_hash: String,
    pub policy_snapshot: String,
    pub allowed_tools: BTreeSet<ToolRef>,
    pub allowed_resources: BTreeSet<String>,
    pub revocation_epoch: u64,
    pub valid_until: DateTime<Utc>,
}

pub struct AuthorizationLeaseVerifier;

impl AuthorizationLeaseVerifier {
    pub fn verify(
        lease: &AuthorizationLease,
        goal_hash: &str,
        plan_hash: &str,
        tool: &ToolRef,
        resource: &str,
        minimum_revocation_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        if lease.schema_version.0 != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::UnknownVersion);
        }
        if lease.goal_hash != goal_hash || lease.plan_hash != plan_hash {
            return Err(ContractError::HashMismatch);
        }
        if now >= lease.valid_until {
            return Err(ContractError::Expired);
        }
        if lease.revocation_epoch < minimum_revocation_epoch {
            return Err(ContractError::Revoked);
        }
        if !lease.allowed_tools.contains(tool) || !lease.allowed_resources.contains(resource) {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum Obligation {
    RequireApproval { dual: bool },
    UseSandboxProfile { profile: String },
    UseNetworkProfile { profile: String },
    UseFilesystemProfile { profile: String },
    UseCredentialProfile { profile: String },
    MaxExecutionTime { milliseconds: u64 },
    MaxResultBytes { bytes: u64 },
    RedactFields { fields: Vec<String> },
    RequireFreshResourceState,
    RequireResourceVersion,
    RequireSimulation,
    PauseTask,
    KillTask,
    EmitSecurityAlert { code: String },
    SetRetryLimit { count: u32 },
    RequireEvaluator { evaluator: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub schema_version: SchemaVersion,
    pub decision_id: String,
    pub decision: Decision,
    pub reason_codes: Vec<String>,
    pub policy_version: PolicyVersion,
    pub policy_bundle_hash: String,
    pub input_hash: String,
    pub evaluated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub obligations: Vec<Obligation>,
    pub risk_summary: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MinimalApprovalGrant {
    pub schema_version: SchemaVersion,
    pub approval_id: ApprovalId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub resource_version: ResourceVersion,
    pub policy_version: PolicyVersion,
    pub approver_subject: String,
    pub approver_roles: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub single_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorization {
    pub schema_version: SchemaVersion,
    pub authorization_id: String,
    pub action_hash: ActionHash,
    pub tool_snapshot_hash: String,
    pub policy_decision_id: String,
    pub approval_ids: Vec<ApprovalId>,
    pub resource_version: ResourceVersion,
    pub sandbox_profile: String,
    pub network_profile: String,
    pub credential_profile: String,
    pub max_execution_ms: u64,
    pub max_result_bytes: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub single_use: bool,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl ExecutionAuthorization {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ContractError> {
        if now < self.issued_at || now >= self.expires_at {
            return Err(ContractError::Expired);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let sig = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &sig)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub schema_version: SchemaVersion,
    pub status: EvaluationStatus,
    pub score_millionths: u32,
    pub hard_gate_results: BTreeMap<String, bool>,
    pub findings: Vec<String>,
    pub evidence_refs: Vec<ArtifactRef>,
    pub evaluator_id: String,
    pub evaluator_version: String,
    pub evaluated_at: DateTime<Utc>,
}

pub struct StateTransitionGuard;

impl StateTransitionGuard {
    pub fn allows(
        from: TaskStatus,
        to: TaskStatus,
        evaluation: Option<&EvaluationResult>,
        has_side_effects: bool,
        compensation_verified: bool,
    ) -> bool {
        use TaskStatus::*;
        match (from, to) {
            (Created, Planned)
            | (Planned, PolicyChecked)
            | (PolicyChecked, ApprovalPending)
            | (PolicyChecked, Approved)
            | (ApprovalPending, Approved)
            | (Approved, Running)
            | (Running, Verifying)
            | (Running, PauseRequested)
            | (PauseRequested, Paused)
            | (Paused, Running)
            | (Running, CancelRequested)
            | (CancelRequested, Cancelling)
            | (Running, KillRequested)
            | (Paused, KillRequested)
            | (KillRequested, Killed)
            | (_, Denied)
            | (_, NeedsHuman)
            | (_, ManualRecoveryRequired) => true,
            (Verifying, Completed) => evaluation.is_some_and(|e| {
                e.status == EvaluationStatus::Pass
                    && e.hard_gate_results.values().all(|passed| *passed)
            }),
            (Running, Failed) => !has_side_effects,
            (Running, Compensating) | (Failed, Compensating) => has_side_effects,
            (Compensating, RolledBack) => compensation_verified,
            _ => false,
        }
    }
}

pub fn canonical_hash<T: Serialize>(value: &T) -> Result<String, ContractError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| ContractError::Canonicalization)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn normalized_goal_hash(
    goal: &str,
    constraints: &BTreeMap<String, String>,
) -> Result<String, ContractError> {
    canonical_hash(&(goal.trim(), constraints))
}

pub fn plan_hash(plan: &PlanManifest) -> Result<String, ContractError> {
    let mut copy = plan.clone();
    copy.plan_hash.clear();
    canonical_hash(&copy)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("CONTRACT_INVALID_ID")]
    InvalidId(&'static str),
    #[error("CONTRACT_UNKNOWN_VERSION")]
    UnknownVersion,
    #[error("CONTRACT_VERSION_REQUIRED")]
    VersionRequired,
    #[error("CONTRACT_HASH_MISMATCH")]
    HashMismatch,
    #[error("CONTRACT_EXPIRED")]
    Expired,
    #[error("CONTRACT_REVOKED")]
    Revoked,
    #[error("CONTRACT_SCOPE_EXCEEDED")]
    ScopeExceeded,
    #[error("CONTRACT_CANONICALIZATION_FAILED")]
    Canonicalization,
    #[error("CONTRACT_SIGNATURE_FORMAT_INVALID")]
    SignatureInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goal_and_plan_changes_invalidate_hashes() {
        let mut constraints = BTreeMap::from([("repo".to_string(), "alpha".to_string())]);
        let first = normalized_goal_hash("run tests", &constraints).unwrap_or_default();
        constraints.insert("branch".into(), "task/x".into());
        let second = normalized_goal_hash("run tests", &constraints).unwrap_or_default();
        assert_ne!(first, second);
    }

    #[test]
    fn delegation_cannot_exceed_parent() {
        let tool = ToolRef {
            tool_id: ToolId("coding.run-tests".into()),
            tool_version: ToolVersion("1.0.0".into()),
        };
        let parent = AuthorizationLease {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            lease_id: LeaseId::new(),
            task_id: TaskId::new(),
            goal_hash: "g".into(),
            plan_hash: "p".into(),
            policy_snapshot: "s".into(),
            allowed_tools: BTreeSet::from([tool]),
            allowed_resources: BTreeSet::from(["repo:a".into()]),
            revocation_epoch: 1,
            valid_until: Utc::now() + chrono::Duration::minutes(5),
        };
        let child = DelegationEnvelope {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            parent_agent: AgentInstanceId::new(),
            child_agent: AgentInstanceId::new(),
            delegated_tools: BTreeSet::new(),
            delegated_resources: BTreeSet::from(["repo:b".into()]),
            budget_ceiling_microunits: 1,
            expiry: Utc::now() + chrono::Duration::minutes(1),
        };
        assert!(!child.is_within(&parent));
    }

    #[test]
    fn task_completion_requires_passing_evaluator() {
        assert!(!StateTransitionGuard::allows(
            TaskStatus::Verifying,
            TaskStatus::Completed,
            None,
            false,
            false
        ));
    }

    #[test]
    fn execution_authorization_signature_is_bound() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut auth = ExecutionAuthorization {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            authorization_id: "a".into(),
            action_hash: ActionHash("hash".into()),
            tool_snapshot_hash: "tool".into(),
            policy_decision_id: "decision".into(),
            approval_ids: vec![],
            resource_version: ResourceVersion("1".into()),
            sandbox_profile: "default".into(),
            network_profile: "none".into(),
            credential_profile: "none".into(),
            max_execution_ms: 1000,
            max_result_bytes: 1024,
            issued_at: Utc::now() - chrono::Duration::seconds(1),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            single_use: true,
            issuer: "pep".into(),
            key_id: "test".into(),
            signature: String::new(),
        };
        assert!(auth.sign(&signing).is_ok());
        assert!(auth.verify(&signing.verifying_key(), Utc::now()).is_ok());
        auth.max_execution_ms = 2000;
        assert_eq!(
            auth.verify(&signing.verifying_key(), Utc::now()),
            Err(ContractError::SignatureInvalid)
        );
    }
}
