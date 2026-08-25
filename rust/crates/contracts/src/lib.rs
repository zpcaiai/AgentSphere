//! Authoritative cross-service contracts for the Agent Trust control plane.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub const CONTRACT_SCHEMA_VERSION: &str = "agenttrust.contracts.v1";
pub const AUTHORITATIVE_FACT_SNAPSHOT_SCHEMA_VERSION: &str =
    "agenttrust.authoritative-fact-snapshot.v1";
pub const PRE_APPROVAL_OUTCOME_SCHEMA_VERSION: &str = "agenttrust.pre-approval-outcome.v1";
pub const EXECUTION_AUTHORIZATION_SCHEMA_VERSION: &str = "agenttrust.execution-authorization.v2";
pub const PEP_PRE_APPROVAL_KEY_USAGE: &str = "PEP_PRE_APPROVAL";
pub const PEP_EXECUTION_AUTHORIZATION_KEY_USAGE: &str = "PEP_EXECUTION_AUTHORIZATION";
pub const SIGNED_POLICY_BUNDLE_SCHEMA_VERSION: &str = "agenttrust.signed-policy-bundle.v1";
pub const POLICY_ACTIVATION_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.policy-activation-request.v1";
pub const PDP_POLICY_ACTIVATION_ACK_SCHEMA_VERSION: &str =
    "agenttrust.pdp-policy-activation-ack.v1";
pub const PEP_POLICY_ACTIVATION_ACK_SCHEMA_VERSION: &str =
    "agenttrust.pep-policy-activation-ack.v1";
pub const PDP_POLICY_ACTIVATION_ACK_KEY_USAGE: &str = "PDP_POLICY_ACTIVATION_ACK";
pub const PEP_POLICY_ACTIVATION_ACK_KEY_USAGE: &str = "PEP_POLICY_ACTIVATION_ACK";
pub const AUTHORITATIVE_FACT_ENVELOPE_SCHEMA_VERSION: &str =
    "agenttrust.authoritative-fact-envelope.v1";
pub const AUTHORITATIVE_FACT_KEY_USAGE: &str = "AUTHORITATIVE_FACT";
pub const PEP_PRE_APPROVAL_REQUEST_SCHEMA_VERSION: &str = "agenttrust.pre-approval-request.v1";
pub const PEP_PRE_APPROVAL_ENVELOPE_SCHEMA_VERSION: &str = "agenttrust.pre-approval-envelope.v1";
pub const PEP_FINAL_AUTHORIZATION_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.final-authorization-request.v1";
pub const PEP_PRE_EXECUTION_AUTHORIZATION_SCHEMA_VERSION: &str =
    "agenttrust.pre-execution-authorization.v1";
pub const WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.credential-binding-request.v1";
pub const WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION: &str =
    "agenttrust.workload-credential-claims.v1";
pub const WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION: &str =
    "agenttrust.credential-binding-receipt.v1";
pub const WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE: &str = "WORKLOAD_CREDENTIAL_BINDING";
pub const WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.credential-consumption-request.v1";
pub const WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION: &str =
    "agenttrust.credential-consumption-receipt.v1";
pub const WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE: &str = "WORKLOAD_CREDENTIAL_CONSUMPTION";
pub const ENTERPRISE_APPROVAL_GRANT_SCHEMA_VERSION: &str = "agenttrust.enterprise-approval.v1";
pub const APPROVAL_CONSUMPTION_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.approval-grant-request.v1";
pub const APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION: &str = "agenttrust.approval-grant-receipt.v1";
pub const SIGNED_APPROVAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION: &str =
    "agenttrust.approval-consumption.v1";
pub const EVIDENCE_EVENT_SCHEMA_VERSION: &str = "agenttrust.evidence.v1";
pub const AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.authority-evidence-event-request.v1";
pub const AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION: &str =
    "agenttrust.signed-authority-evidence-receipt.v1";
pub const AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE: &str = "AUTHORITY_EVIDENCE_RECEIPT";
pub const EXECUTION_EVIDENCE_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.execution-evidence-request.v1";
pub const EXECUTION_EVIDENCE_RECEIPT_SCHEMA_VERSION: &str =
    "agenttrust.execution-evidence-receipt.v1";
pub const EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE: &str = "EVIDENCE_EXECUTION_RECEIPT";
pub const HUMAN_PRINCIPAL_ASSERTION_SCHEMA_VERSION: &str =
    "agenttrust.signed-human-principal-assertion.v1";
pub const HUMAN_PRINCIPAL_REQUEST_BINDING_SCHEMA_VERSION: &str =
    "agenttrust.human-principal-request-binding.v1";
pub const HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE: &str = "HUMAN_PRINCIPAL_ASSERTION";
pub const HUMAN_PRINCIPAL_KEYRING_SCHEMA_VERSION: &str = "agenttrust.human-principal-keyring.v1";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementStage {
    PreApproval,
    PreExecution,
    Continuous,
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

/// Canonical deployment scope for an activated policy snapshot.  The value is deliberately
/// closed so an unknown deployment can never fall back to a development bundle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyEnvironment {
    Dev,
    Staging,
    Canary,
    Production,
}

impl PolicyEnvironment {
    pub fn from_deployment(value: &str) -> Result<Self, ContractError> {
        match value {
            "DEV" | "dev" => Ok(Self::Dev),
            "STAGING" | "staging" => Ok(Self::Staging),
            "CANARY" | "canary" => Ok(Self::Canary),
            "PRODUCTION" | "production" => Ok(Self::Production),
            _ => Err(ContractError::ScopeExceeded),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "DEV",
            Self::Staging => "STAGING",
            Self::Canary => "CANARY",
            Self::Production => "PRODUCTION",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyRule {
    pub rule_id: String,
    pub subject_pattern: String,
    pub tool_pattern: String,
    pub resource_pattern: String,
    pub decision: Decision,
    pub maximum_risk: RiskLevel,
    pub reason_code: String,
}

/// Immutable, tenant and policy-bound policy artifact.  `policy_id` and `source_revision` are
/// covered by the signature so the same artifact cannot be rebound to another policy lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub tenant_id: TenantId,
    pub policy_id: String,
    pub source_revision: u64,
    pub version: String,
    pub source_digest: String,
    pub bundle_digest: String,
    pub rules: Vec<SignedPolicyRule>,
    pub default_decision: Decision,
    pub review_ids: BTreeSet<String>,
    pub key_id: String,
    pub signature: String,
    pub compiled_at: DateTime<Utc>,
}

impl SignedPolicyBundle {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.bundle_digest.clear();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn compute_digest(&self) -> Result<String, ContractError> {
        Ok(hex::encode(Sha256::digest(self.signing_bytes()?)))
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.validate_unsigned()?;
        self.bundle_digest = self.compute_digest()?;
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(self.bundle_digest.as_bytes()).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ContractError> {
        self.validate_unsigned()?;
        if self.bundle_digest != self.compute_digest()? || !is_lower_hex_digest(&self.bundle_digest)
        {
            return Err(ContractError::SignatureInvalid);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(self.bundle_digest.as_bytes(), &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }

    fn validate_unsigned(&self) -> Result<(), ContractError> {
        let unique_rules = self
            .rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        if self.schema_version != SIGNED_POLICY_BUNDLE_SCHEMA_VERSION
            || Uuid::parse_str(&self.bundle_id).is_err()
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || !bounded_nonempty(&self.policy_id, 256)
            || self.source_revision == 0
            || !bounded_nonempty(&self.version, 128)
            || !is_lower_hex_digest(&self.source_digest)
            || self.rules.is_empty()
            || self.rules.len() > 10_000
            || unique_rules.len() != self.rules.len()
            || self.rules.iter().any(|rule| {
                !bounded_nonempty(&rule.rule_id, 256)
                    || !bounded_nonempty(&rule.subject_pattern, 1_024)
                    || !bounded_nonempty(&rule.tool_pattern, 1_024)
                    || !bounded_nonempty(&rule.resource_pattern, 2_048)
                    || rule.reason_code.len() < 3
                    || rule.reason_code.len() > 128
                    || !rule
                        .reason_code
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_uppercase())
                    || !rule.reason_code.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
            || self.default_decision == Decision::Allow
            || !(2..=64).contains(&self.review_ids.len())
            || self
                .review_ids
                .iter()
                .any(|value| !bounded_nonempty(value, 256))
            || !valid_contract_identifier(&self.key_id, 128)
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivationRequest {
    pub schema_version: String,
    pub activation_id: String,
    pub idempotency_key: String,
    pub tenant_id: TenantId,
    pub policy_id: String,
    pub environment: PolicyEnvironment,
    pub sequence: u64,
    pub previous_bundle_digest: Option<String>,
    pub bundle: SignedPolicyBundle,
    pub requested_at: DateTime<Utc>,
}

impl PolicyActivationRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != POLICY_ACTIVATION_REQUEST_SCHEMA_VERSION
            || Uuid::parse_str(&self.activation_id).is_err()
            || !valid_idempotency_key(&self.idempotency_key)
            || self.idempotency_key.len() < 16
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || self.policy_id != self.bundle.policy_id
            || self.tenant_id != self.bundle.tenant_id
            || self.sequence == 0
            || self
                .previous_bundle_digest
                .as_deref()
                .is_some_and(|value| !is_lower_hex_digest(value))
            || !is_lower_hex_digest(&self.bundle.bundle_digest)
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PdpPolicyActivationAcknowledgement {
    pub schema_version: String,
    pub activation_id: String,
    pub idempotency_key: String,
    pub tenant_id: TenantId,
    pub policy_id: String,
    pub environment: PolicyEnvironment,
    pub sequence: u64,
    pub bundle_digest: String,
    pub active: bool,
    pub snapshot_digest: String,
    pub activated_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl PdpPolicyActivationAcknowledgement {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ContractError> {
        if self.schema_version != PDP_POLICY_ACTIVATION_ACK_SCHEMA_VERSION
            || self.key_usage != PDP_POLICY_ACTIVATION_ACK_KEY_USAGE
            || Uuid::parse_str(&self.activation_id).is_err()
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || !valid_idempotency_key(&self.idempotency_key)
            || !bounded_nonempty(&self.policy_id, 256)
            || self.sequence == 0
            || !self.active
            || !is_lower_hex_digest(&self.bundle_digest)
            || !is_lower_hex_digest(&self.snapshot_digest)
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 128)
        {
            return Err(ContractError::ScopeExceeded);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepPolicyActivationAcknowledgement {
    pub schema_version: String,
    pub activation_id: String,
    pub idempotency_key: String,
    pub tenant_id: TenantId,
    pub policy_id: String,
    pub environment: PolicyEnvironment,
    pub sequence: u64,
    pub bundle_digest: String,
    pub active: bool,
    pub pdp_ack_digest: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub acknowledged_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl PepPolicyActivationAcknowledgement {
    pub fn compute_evidence_digest(&self) -> Result<String, ContractError> {
        let evidence = serde_json::json!({
            "schema_version": "agenttrust.pep-policy-activation-evidence.v1",
            "activation_id": self.activation_id,
            "tenant_id": self.tenant_id,
            "policy_id": self.policy_id,
            "environment": self.environment,
            "sequence": self.sequence,
            "bundle_digest": self.bundle_digest,
            "pdp_ack_digest": self.pdp_ack_digest,
            "recorded_at": self.acknowledged_at,
        });
        let bytes = serde_jcs::to_vec(&evidence).map_err(|_| ContractError::Canonicalization)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn bind_evidence(&mut self) -> Result<(), ContractError> {
        self.evidence_ref.clear();
        self.evidence_digest = self.compute_evidence_digest()?;
        self.evidence_ref = format!(
            "urn:agenttrust:pep-policy-activation:{}:{}:sha256:{}",
            self.tenant_id.0, self.activation_id, self.evidence_digest
        );
        self.signature.clear();
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ContractError> {
        if self.schema_version != PEP_POLICY_ACTIVATION_ACK_SCHEMA_VERSION
            || self.key_usage != PEP_POLICY_ACTIVATION_ACK_KEY_USAGE
            || Uuid::parse_str(&self.activation_id).is_err()
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || !valid_idempotency_key(&self.idempotency_key)
            || !bounded_nonempty(&self.policy_id, 256)
            || self.sequence == 0
            || !self.active
            || !is_lower_hex_digest(&self.bundle_digest)
            || !is_lower_hex_digest(&self.pdp_ack_digest)
            || !is_lower_hex_digest(&self.evidence_digest)
            || self.compute_evidence_digest()? != self.evidence_digest
            || self.evidence_ref
                != format!(
                    "urn:agenttrust:pep-policy-activation:{}:{}:sha256:{}",
                    self.tenant_id.0, self.activation_id, self.evidence_digest
                )
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 128)
        {
            return Err(ContractError::ScopeExceeded);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
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

/// Enterprise approval authority wire types live in contracts so the PEP and execution
/// service never depend on the approval service implementation crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseApprovalGrant {
    pub schema_version: SchemaVersion,
    pub grant_id: ApprovalId,
    pub case_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub plan_hash: String,
    pub parameter_hash: String,
    pub resource: String,
    pub resource_version: ResourceVersion,
    pub policy_version: PolicyVersion,
    pub environment: String,
    pub maximum_risk: RiskLevel,
    pub approver_subjects: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub maximum_uses: u32,
    pub break_glass: bool,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl EnterpriseApprovalGrant {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn to_minimal_grant(&self) -> MinimalApprovalGrant {
        MinimalApprovalGrant {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            approval_id: self.grant_id.clone(),
            task_id: self.task_id.clone(),
            step_id: self.step_id.clone(),
            action_hash: self.action_hash.clone(),
            resource_version: self.resource_version.clone(),
            policy_version: self.policy_version.clone(),
            approver_subject: self.approver_subjects.join(","),
            approver_roles: vec!["enterprise-approved".into()],
            expires_at: self.expires_at,
            single_use: self.maximum_uses == 1,
        }
    }

    pub fn verify_signature(
        &self,
        issuer: &str,
        key_id: &str,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        if self.schema_version.0 != ENTERPRISE_APPROVAL_GRANT_SCHEMA_VERSION
            || self.issuer != issuer
            || self.key_id != key_id
            || !canonical_uuid(&self.grant_id.0)
            || !canonical_uuid(&self.case_id)
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.step_id.0)
            || !is_lower_hex_digest(&self.action_hash.0)
            || !is_lower_hex_digest(&self.plan_hash)
            || !is_lower_hex_digest(&self.parameter_hash)
            || !bounded_nonempty(&self.resource, 2_048)
            || !bounded_nonempty(&self.resource_version.0, 256)
            || !bounded_nonempty(&self.policy_version.0, 256)
            || !bounded_nonempty(&self.environment, 128)
            || self.approver_subjects.is_empty()
            || self.approver_subjects.len() > 64
            || self
                .approver_subjects
                .iter()
                .any(|subject| !bounded_nonempty(subject, 256))
            || self.maximum_uses == 0
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::Duration::days(7)
            || now < self.issued_at
            || now >= self.expires_at
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 128)
        {
            return Err(ContractError::ScopeExceeded);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConsumptionRequest {
    pub schema_version: String,
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
    pub maximum_risk: RiskLevel,
}

impl ApprovalConsumptionRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != APPROVAL_CONSUMPTION_REQUEST_SCHEMA_VERSION
            || !canonical_uuid(&self.tenant_id)
            || !canonical_uuid(&self.task_id)
            || !canonical_uuid(&self.step_id)
            || !is_lower_hex_digest(&self.action_hash)
            || !is_lower_hex_digest(&self.plan_hash)
            || !is_lower_hex_digest(&self.parameter_hash)
            || !bounded_nonempty(&self.resource, 2_048)
            || !bounded_nonempty(&self.resource_version, 256)
            || !bounded_nonempty(&self.policy_version, 256)
            || !bounded_nonempty(&self.environment, 128)
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantReceipt {
    pub schema_version: String,
    pub grant: EnterpriseApprovalGrant,
    pub consumed_at: DateTime<Utc>,
    pub remaining_uses: u32,
    pub consumption_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalConsumptionReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub tenant_id: String,
    pub grant_id: String,
    pub case_id: String,
    pub request: ApprovalConsumptionRequest,
    pub grant: EnterpriseApprovalGrant,
    pub request_digest: String,
    pub grant_digest: String,
    pub idempotency_key_digest: String,
    pub consumed_by: String,
    pub client_identity: String,
    pub consumed_at: DateTime<Utc>,
    pub remaining_uses: u32,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl SignedApprovalConsumptionReceipt {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn verify(
        &self,
        issuer: &str,
        key_id: &str,
        key: &VerifyingKey,
    ) -> Result<(), ContractError> {
        self.request.validate()?;
        if self.schema_version != SIGNED_APPROVAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION
            || self.issuer != issuer
            || self.key_id != key_id
            || self.remaining_uses != 0
            || !canonical_uuid(&self.receipt_id)
            || !canonical_uuid(&self.tenant_id)
            || !canonical_uuid(&self.grant_id)
            || !canonical_uuid(&self.case_id)
            || !is_lower_hex_digest(&self.request_digest)
            || !is_lower_hex_digest(&self.grant_digest)
            || !is_lower_hex_digest(&self.idempotency_key_digest)
            || !approval_identifier(&self.consumed_by, 256)
            || !service_client_identity(&self.client_identity)
            || canonical_hash(&self.request)? != self.request_digest
            || canonical_hash(&self.grant)? != self.grant_digest
            || self.tenant_id != self.request.tenant_id
            || self.tenant_id != self.grant.tenant_id.0
            || self.grant_id != self.grant.grant_id.0
            || self.case_id != self.grant.case_id
            || self.consumed_at < self.grant.issued_at
            || self.consumed_at >= self.grant.expires_at
            || !approval_consumption_matches(&self.request, &self.grant)
        {
            return Err(ContractError::ScopeExceeded);
        }
        self.grant
            .verify_signature(issuer, key_id, key, self.consumed_at)?;
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalRequestBinding<'a, T: Serialize + ?Sized> {
    schema_version: &'static str,
    method: &'a str,
    path: &'a str,
    tenant_id: &'a TenantId,
    client_identity: &'a str,
    service_subject: &'a str,
    scope: &'a str,
    idempotency_key: &'a str,
    body: &'a T,
}

#[allow(clippy::too_many_arguments)]
pub fn human_principal_request_digest<T: Serialize + ?Sized>(
    method: &str,
    path: &str,
    tenant_id: &TenantId,
    client_identity: &str,
    service_subject: &str,
    scope: &str,
    idempotency_key: &str,
    body: &T,
) -> Result<String, ContractError> {
    if !matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
        || !safe_request_path(path)
        || !canonical_uuid(&tenant_id.0)
        || !service_client_identity(client_identity)
        || !human_identifier(service_subject, 256)
        || !human_scope(scope)
        || !valid_idempotency_key(idempotency_key)
    {
        return Err(ContractError::ScopeExceeded);
    }
    canonical_hash(&HumanPrincipalRequestBinding {
        schema_version: HUMAN_PRINCIPAL_REQUEST_BINDING_SCHEMA_VERSION,
        method,
        path,
        tenant_id,
        client_identity,
        service_subject,
        scope,
        idempotency_key,
        body,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedHumanPrincipalAssertion {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub subject: String,
    pub roles: BTreeSet<String>,
    pub project_ids: BTreeSet<String>,
    pub approval_ids: BTreeSet<String>,
    pub owned_resources: BTreeSet<String>,
    pub strong_auth: bool,
    pub authentication_time: DateTime<Utc>,
    pub authentication_context: String,
    pub issuer: String,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jti: String,
    pub request_digest: String,
    pub client_identity: String,
    pub service_subject: String,
    pub scope: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl SignedHumanPrincipalAssertion {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn assertion_digest(&self) -> Result<String, ContractError> {
        canonical_hash(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        key: &VerifyingKey,
        expected_tenant: &TenantId,
        expected_client_identity: &str,
        expected_service_subject: &str,
        expected_scope: &str,
        expected_request_digest: &str,
        expected_issuer: &str,
        expected_audience: &str,
        require_strong_auth: bool,
        maximum_authentication_age_seconds: i64,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        let unique_roles = self.roles.len() <= 64;
        let unique_projects = self.project_ids.len() <= 1_024;
        let unique_approvals = self.approval_ids.len() <= 1_024;
        let unique_resources = self.owned_resources.len() <= 1_024;
        if self.schema_version != HUMAN_PRINCIPAL_ASSERTION_SCHEMA_VERSION
            || self.key_usage != HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE
            || &self.tenant_id != expected_tenant
            || self.client_identity != expected_client_identity
            || self.service_subject != expected_service_subject
            || self.scope != expected_scope
            || self.request_digest != expected_request_digest
            || self.issuer != expected_issuer
            || self.audience != expected_audience
            || require_strong_auth && !self.strong_auth
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.jti)
            || !human_identifier(&self.subject, 256)
            || self.roles.is_empty()
            || !unique_roles
            || !unique_projects
            || !unique_approvals
            || !unique_resources
            || self.roles.iter().any(|value| !human_identifier(value, 256))
            || self
                .project_ids
                .iter()
                .any(|value| !human_identifier(value, 256))
            || self
                .approval_ids
                .iter()
                .any(|value| !human_identifier(value, 256))
            || self
                .owned_resources
                .iter()
                .any(|value| !safe_human_resource(value))
            || !human_identifier(&self.authentication_context, 256)
            || !human_identifier(&self.issuer, 256)
            || !human_identifier(&self.service_subject, 256)
            || !human_identifier(&self.key_id, 128)
            || !bounded_nonempty(&self.audience, 256)
            || !service_client_identity(&self.client_identity)
            || !human_scope(&self.scope)
            || !is_lower_hex_digest(&self.request_digest)
            || maximum_authentication_age_seconds <= 0
            || maximum_authentication_age_seconds > 86_400
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::Duration::minutes(5)
            || self.issued_at > now + chrono::Duration::seconds(30)
            || now >= self.expires_at
            || self.authentication_time > self.issued_at + chrono::Duration::seconds(30)
            || self.authentication_time
                < self.issued_at - chrono::Duration::seconds(maximum_authentication_age_seconds)
        {
            return Err(ContractError::ScopeExceeded);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HumanPrincipalVerificationKeyStatus {
    Active,
    VerifyOnly,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalVerificationKeyDocument {
    issuer: String,
    key_id: String,
    algorithm: String,
    usage: String,
    status: HumanPrincipalVerificationKeyStatus,
    public_key: String,
    tenant_ids: Vec<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalKeyringDocument {
    schema_version: String,
    audience: String,
    keys: Vec<HumanPrincipalVerificationKeyDocument>,
}

#[derive(Clone)]
struct HumanPrincipalVerificationKey {
    key: VerifyingKey,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Strict parser and verifier for the shared human-principal keyring contract.
///
/// Services keep file ownership, permission and rotation policy at their boundary. This type owns
/// only the dependency-low JSON/key/signature rules so an authority never needs to depend on a
/// different authority implementation merely to verify the common contract.
#[derive(Clone)]
pub struct HumanPrincipalKeyring {
    audience: String,
    keys: BTreeMap<(String, String), HumanPrincipalVerificationKey>,
}

impl HumanPrincipalKeyring {
    pub fn from_json(
        raw: &[u8],
        expected_audience: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, ContractError> {
        if raw.is_empty()
            || raw.len() > 1_048_576
            || !bounded_nonempty(expected_audience, 256)
            || expected_audience.contains(['\0', '\r', '\n'])
        {
            return Err(ContractError::ScopeExceeded);
        }
        let document: HumanPrincipalKeyringDocument =
            serde_json::from_slice(raw).map_err(|_| ContractError::ScopeExceeded)?;
        if document.schema_version != HUMAN_PRINCIPAL_KEYRING_SCHEMA_VERSION
            || document.audience != expected_audience
            || document.keys.is_empty()
            || document.keys.len() > 128
        {
            return Err(ContractError::ScopeExceeded);
        }
        let mut keys = BTreeMap::new();
        let mut active_key_is_usable = false;
        for document in document.keys {
            let tenant_ids = document.tenant_ids.iter().cloned().collect::<BTreeSet<_>>();
            if !human_identifier(&document.issuer, 256)
                || !human_identifier(&document.key_id, 128)
                || document.algorithm != "Ed25519"
                || document.usage != HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE
                || document.public_key.len() != 43
                || !document
                    .public_key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || document.tenant_ids.is_empty()
                || document.tenant_ids.len() > 1_024
                || tenant_ids.len() != document.tenant_ids.len()
                || tenant_ids.iter().any(|tenant| !canonical_uuid(tenant))
                || document.not_before >= document.expires_at
            {
                return Err(ContractError::ScopeExceeded);
            }
            let raw_key = URL_SAFE_NO_PAD
                .decode(document.public_key)
                .map_err(|_| ContractError::ScopeExceeded)?;
            let bytes: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| ContractError::ScopeExceeded)?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ContractError::ScopeExceeded)?;
            active_key_is_usable |= document.status == HumanPrincipalVerificationKeyStatus::Active
                && now >= document.not_before
                && now < document.expires_at;
            if keys
                .insert(
                    (document.issuer, document.key_id),
                    HumanPrincipalVerificationKey {
                        key,
                        tenant_ids,
                        not_before: document.not_before,
                        expires_at: document.expires_at,
                    },
                )
                .is_some()
            {
                return Err(ContractError::ScopeExceeded);
            }
        }
        if !active_key_is_usable {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(Self {
            audience: document.audience,
            keys,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_encoded(
        &self,
        encoded: &str,
        expected_tenant: &TenantId,
        expected_client_identity: &str,
        expected_service_subject: &str,
        expected_scope: &str,
        expected_request_digest: &str,
        require_strong_auth: bool,
        maximum_authentication_age_seconds: i64,
        now: DateTime<Utc>,
    ) -> Result<VerifiedHumanPrincipal, ContractError> {
        if encoded.is_empty()
            || encoded.len() > 87_384
            || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ContractError::SignatureInvalid);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ContractError::SignatureInvalid)?;
        if raw.is_empty() || raw.len() > 65_536 {
            return Err(ContractError::SignatureInvalid);
        }
        let assertion: SignedHumanPrincipalAssertion =
            serde_json::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        let key = self
            .keys
            .get(&(assertion.issuer.clone(), assertion.key_id.clone()))
            .ok_or(ContractError::SignatureInvalid)?;
        if !key.tenant_ids.contains(&expected_tenant.0)
            || now < key.not_before
            || now >= key.expires_at
            || assertion.issued_at < key.not_before
            || assertion.expires_at > key.expires_at
        {
            return Err(ContractError::ScopeExceeded);
        }
        assertion.verify(
            &key.key,
            expected_tenant,
            expected_client_identity,
            expected_service_subject,
            expected_scope,
            expected_request_digest,
            &assertion.issuer,
            &self.audience,
            require_strong_auth,
            maximum_authentication_age_seconds,
            now,
        )?;
        let assertion_digest = assertion.assertion_digest()?;
        Ok(VerifiedHumanPrincipal {
            tenant_id: assertion.tenant_id,
            subject: assertion.subject,
            roles: assertion.roles,
            project_ids: assertion.project_ids,
            approval_ids: assertion.approval_ids,
            owned_resources: assertion.owned_resources,
            strong_auth: assertion.strong_auth,
            authentication_time: assertion.authentication_time,
            authentication_context: assertion.authentication_context,
            client_identity: assertion.client_identity,
            service_subject: assertion.service_subject,
            scope: assertion.scope,
            jti: assertion.jti,
            assertion_digest,
            expires_at: assertion.expires_at,
        })
    }
}

/// Claims safe to pass beyond the authority ingress after signature and request verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHumanPrincipal {
    pub tenant_id: TenantId,
    pub subject: String,
    pub roles: BTreeSet<String>,
    pub project_ids: BTreeSet<String>,
    pub approval_ids: BTreeSet<String>,
    pub owned_resources: BTreeSet<String>,
    pub strong_auth: bool,
    pub authentication_time: DateTime<Utc>,
    pub authentication_context: String,
    pub client_identity: String,
    pub service_subject: String,
    pub scope: String,
    pub jti: String,
    pub assertion_digest: String,
    pub expires_at: DateTime<Utc>,
}

fn safe_request_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 2_048
        && !value.contains(['\0', '\r', '\n', '?', '#', '\\'])
        && !value.split('/').any(|segment| segment == "..")
}

fn human_identifier(value: &str, maximum: usize) -> bool {
    bounded_nonempty(value, maximum)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn human_scope(value: &str) -> bool {
    bounded_nonempty(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn safe_human_resource(value: &str) -> bool {
    bounded_nonempty(value, 2_048) && !value.contains(['\0', '\r', '\n'])
}

fn approval_consumption_matches(
    request: &ApprovalConsumptionRequest,
    grant: &EnterpriseApprovalGrant,
) -> bool {
    request.tenant_id == grant.tenant_id.0
        && request.task_id == grant.task_id.0
        && request.step_id == grant.step_id.0
        && request.action_hash == grant.action_hash.0
        && request.plan_hash == grant.plan_hash
        && request.parameter_hash == grant.parameter_hash
        && request.resource == grant.resource
        && request.resource_version == grant.resource_version.0
        && request.policy_version == grant.policy_version.0
        && request.environment == grant.environment
        && request.maximum_risk <= grant.maximum_risk
        && grant.maximum_uses == 1
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn approval_identifier(value: &str, maximum: usize) -> bool {
    bounded_nonempty(value, maximum)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn service_client_identity(value: &str) -> bool {
    value.len() <= 512
        && (value.starts_with("DNS:") || value.starts_with("URI:"))
        && value.split_once(':').is_some_and(|(_, identity)| {
            !identity.is_empty() && identity.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthoritativeFactKind {
    Identity,
    ResourceState,
    Budget,
    TrajectoryRisk,
    Registry,
    Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthoritativeFactStatus {
    Verified,
    Unknown,
    Stale,
    Error,
}

/// Signed response returned by each independently operated authoritative fact source.
/// The opaque payload is decoded into a kind-specific, deny-unknown-fields DTO by the PEP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthoritativeFactEnvelope {
    pub schema_version: SchemaVersion,
    pub kind: AuthoritativeFactKind,
    pub status: AuthoritativeFactStatus,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub authority_uri: String,
    pub version: String,
    pub payload: Value,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub digest: String,
    pub signature: String,
}

impl SignedAuthoritativeFactEnvelope {
    fn canonical_digest(&self) -> Result<String, ContractError> {
        let mut unsigned = self.clone();
        unsigned.digest.clear();
        unsigned.signature.clear();
        canonical_hash(&unsigned)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.digest = self.canonical_digest()?;
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        expected_kind: AuthoritativeFactKind,
        expected_tenant: &TenantId,
        expected_action_hash: &ActionHash,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        if self.schema_version.0 != AUTHORITATIVE_FACT_ENVELOPE_SCHEMA_VERSION
            || self.kind != expected_kind
            || self.status != AuthoritativeFactStatus::Verified
            || &self.tenant_id != expected_tenant
            || &self.action_hash != expected_action_hash
            || !self.authority_uri.starts_with("https://")
            || !bounded_nonempty(&self.authority_uri, 2_048)
            || !bounded_nonempty(&self.version, 256)
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 256)
            || self.key_usage != AUTHORITATIVE_FACT_KEY_USAGE
            || !self.payload.is_object()
            || !is_lower_hex_digest(&self.digest)
            || self.digest != self.canonical_digest()?
            || self.observed_at > now
            || now >= self.valid_until
            || self.valid_until - self.observed_at > chrono::Duration::minutes(5)
        {
            return Err(ContractError::FactUnavailable);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeFactRef {
    pub kind: AuthoritativeFactKind,
    pub status: AuthoritativeFactStatus,
    pub uri: String,
    pub digest: String,
    pub version: String,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// A PEP-owned snapshot of dynamic facts. Unknown values are represented as `None` and
/// must never be replaced by an allowing default. The containing pre-approval outcome
/// signs the snapshot and its canonical digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeFactSnapshot {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub identity_subject: Option<String>,
    pub identity_uses_dev_verifier: Option<bool>,
    pub identity_revocation_epoch: Option<u64>,
    pub resource_state_version: Option<ResourceVersion>,
    pub resource_state_fresh: Option<bool>,
    pub budget_remaining_microunits: Option<u64>,
    pub trajectory_risk_version: Option<String>,
    pub accumulated_resources: Option<Vec<String>>,
    pub anomaly_score_millionths: Option<u32>,
    pub fact_refs: Vec<AuthoritativeFactRef>,
    pub captured_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub snapshot_digest: String,
}

impl AuthoritativeFactSnapshot {
    pub fn canonical_digest(&self) -> Result<String, ContractError> {
        let mut unsigned = self.clone();
        unsigned.snapshot_digest.clear();
        canonical_hash(&unsigned)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.snapshot_digest = self.canonical_digest()?;
        Ok(())
    }

    pub fn validate_integrity(&self, now: DateTime<Utc>) -> Result<(), ContractError> {
        if self.schema_version.0 != AUTHORITATIVE_FACT_SNAPSHOT_SCHEMA_VERSION
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || !is_lower_hex_digest(&self.action_hash.0)
            || !is_lower_hex_digest(&self.snapshot_digest)
            || self.snapshot_digest != self.canonical_digest()?
            || now < self.captured_at
            || now >= self.expires_at
            || self.fact_refs.is_empty()
            || self.fact_refs.len() > 64
            || self
                .identity_subject
                .as_deref()
                .is_some_and(|subject| !bounded_nonempty(subject, 512))
            || self
                .resource_state_version
                .as_ref()
                .is_some_and(|version| !bounded_nonempty(&version.0, 256))
            || self
                .trajectory_risk_version
                .as_deref()
                .is_some_and(|version| !bounded_nonempty(version, 256))
            || self
                .accumulated_resources
                .as_ref()
                .is_some_and(|resources| {
                    resources.len() > 4_096
                        || resources
                            .iter()
                            .any(|resource| !bounded_nonempty(resource, 2_048))
                })
            || self
                .anomaly_score_millionths
                .is_some_and(|score| score > 1_000_000)
        {
            return Err(ContractError::HashMismatch);
        }
        let mut kinds = BTreeSet::new();
        for fact in &self.fact_refs {
            if !kinds.insert(fact.kind)
                || fact.uri.is_empty()
                || fact.uri.len() > 2_048
                || !is_lower_hex_digest(&fact.digest)
                || fact.version.is_empty()
                || fact.version.len() > 256
                || fact.observed_at > self.captured_at
                || fact.valid_until < self.expires_at
            {
                return Err(ContractError::HashMismatch);
            }
        }
        Ok(())
    }

    pub fn require_verified(&self) -> Result<(), ContractError> {
        let required = BTreeSet::from([
            AuthoritativeFactKind::Identity,
            AuthoritativeFactKind::ResourceState,
            AuthoritativeFactKind::Budget,
            AuthoritativeFactKind::TrajectoryRisk,
            AuthoritativeFactKind::Registry,
            AuthoritativeFactKind::Environment,
        ]);
        let verified = self
            .fact_refs
            .iter()
            .filter(|fact| fact.status == AuthoritativeFactStatus::Verified)
            .map(|fact| fact.kind)
            .collect::<BTreeSet<_>>();
        if !required.is_subset(&verified)
            || self.identity_subject.as_deref().is_none_or(str::is_empty)
            || self.identity_uses_dev_verifier.is_none()
            || self.identity_revocation_epoch.is_none()
            || self
                .resource_state_version
                .as_ref()
                .is_none_or(|version| version.0.is_empty())
            || self.resource_state_fresh.is_none()
            || self.budget_remaining_microunits.is_none()
            || self
                .trajectory_risk_version
                .as_deref()
                .is_none_or(str::is_empty)
            || self.accumulated_resources.is_none()
            || self.anomaly_score_millionths.is_none()
        {
            return Err(ContractError::FactUnavailable);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedPreApprovalOutcome {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub tool_snapshot_hash: String,
    pub stage: EnforcementStage,
    pub idempotency_key: IdempotencyKey,
    pub request_digest: String,
    pub fact_snapshot: AuthoritativeFactSnapshot,
    pub fact_snapshot_digest: String,
    pub execution_plan_digest: Option<String>,
    pub approval_required: bool,
    pub decision: PolicyDecision,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl SignedPreApprovalOutcome {
    fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.fact_snapshot.seal()?;
        self.fact_snapshot_digest = self.fact_snapshot.snapshot_digest.clone();
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ContractError> {
        if self.schema_version.0 != PRE_APPROVAL_OUTCOME_SCHEMA_VERSION
            || self.stage != EnforcementStage::PreApproval
            || self.key_usage != PEP_PRE_APPROVAL_KEY_USAGE
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || Uuid::parse_str(&self.task_id.0).is_err()
            || Uuid::parse_str(&self.step_id.0).is_err()
            || !is_lower_hex_digest(&self.action_hash.0)
            || !bounded_nonempty(&self.tool_id.0, 256)
            || !bounded_nonempty(&self.tool_version.0, 256)
            || !is_lower_hex_digest(&self.tool_snapshot_hash)
            || !valid_idempotency_key(&self.idempotency_key.0)
            || !is_lower_hex_digest(&self.request_digest)
            || !is_lower_hex_digest(&self.decision.policy_bundle_hash)
            || !is_lower_hex_digest(&self.decision.input_hash)
            || self
                .execution_plan_digest
                .as_deref()
                .is_some_and(|digest| !is_lower_hex_digest(digest))
            || self.fact_snapshot_digest != self.fact_snapshot.snapshot_digest
            || self.fact_snapshot.tenant_id != self.tenant_id
            || self.fact_snapshot.action_hash != self.action_hash
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 256)
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::Duration::minutes(5)
            || now < self.issued_at
            || now >= self.expires_at
            || self.decision.evaluated_at > self.issued_at
            || self.decision.evaluated_at >= self.decision.expires_at
            || self.expires_at > self.decision.expires_at
            || (self.decision.decision == Decision::RequireApproval && !self.approval_required)
            || (self
                .decision
                .obligations
                .iter()
                .any(|obligation| matches!(obligation, Obligation::RequireApproval { .. }))
                && !self.approval_required)
        {
            return Err(ContractError::ScopeExceeded);
        }
        self.fact_snapshot.validate_integrity(now)?;
        if matches!(
            self.decision.decision,
            Decision::Allow | Decision::RequireApproval
        ) {
            self.fact_snapshot.require_verified()?;
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

/// Shared, dependency-acyclic PEP wire envelopes. Concrete action, registry, policy-input,
/// compensation and credential types are supplied by the consuming crates as type parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PepPreApprovalRequest<A, T> {
    pub schema_version: String,
    pub action: A,
    pub action_hash: ActionHash,
    pub tool: T,
    pub idempotency_key: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PepPreApprovalEnvelope<C> {
    pub schema_version: String,
    pub signed_outcome: SignedPreApprovalOutcome,
    #[serde(default)]
    pub compensation_plan: Option<C>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PepFinalAuthorizationRequest<A, T, P> {
    pub schema_version: String,
    pub stage: EnforcementStage,
    pub action: A,
    pub action_hash: ActionHash,
    pub tool: T,
    pub policy_input: P,
    pub preapproval: SignedPreApprovalOutcome,
    pub approval: Option<MinimalApprovalGrant>,
    pub approval_consumption_ref: Option<String>,
    pub approval_receipt_digest: Option<String>,
    pub ledger_execution_id: ExecutionId,
    pub ledger_event_id: String,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub idempotency_key: String,
    pub requested_at: DateTime<Utc>,
}

/// Dependency-acyclic evidence wire shared by execution, evidence authority and offline tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceEventType {
    TaskCreated,
    PlanGenerated,
    PolicyEvaluated,
    ApprovalDecision,
    ApprovalReviewPrepared,
    CredentialIssued,
    ToolPrepared,
    ToolExecuted,
    Compensation,
    Evaluation,
    SecurityAlert,
    StateTransition,
    AuditQuery,
    AuditExport,
    LegalHold,
    RetentionDeletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventDraft {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub event_type: EvidenceEventType,
    pub actor_subject: String,
    pub source_service: String,
    pub trace_id: String,
    pub span_id: String,
    pub payload_hash: String,
    pub safe_summary: String,
    pub artifact_refs: Vec<ArtifactRef>,
    pub occurred_at: DateTime<Utc>,
}

impl EvidenceEventDraft {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != EVIDENCE_EVENT_SCHEMA_VERSION
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !bounded_nonempty(&self.actor_subject, 512)
            || !bounded_nonempty(&self.source_service, 256)
            || !bounded_nonempty(&self.trace_id, 256)
            || !bounded_nonempty(&self.span_id, 256)
            || !is_lower_hex_digest(&self.payload_hash)
            || self.safe_summary.len() > 512
            || self.artifact_refs.len() > 256
            || self
                .artifact_refs
                .iter()
                .any(|artifact| !bounded_nonempty(&artifact.0, 2_048))
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceEvent {
    pub schema_version: String,
    pub event_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event_hash: String,
    pub key_id: String,
    pub signature: String,
    pub draft: EvidenceEventDraft,
}

impl SignedEvidenceEvent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.event_hash.clear();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn expected_hash(&self) -> Result<String, ContractError> {
        Ok(hex::encode(Sha256::digest(self.signing_bytes()?)))
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ContractError> {
        self.draft.validate()?;
        if self.schema_version != EVIDENCE_EVENT_SCHEMA_VERSION
            || !canonical_uuid(&self.event_id)
            || self.sequence == 0
            || !is_lower_hex_digest(&self.previous_hash)
            || !is_lower_hex_digest(&self.event_hash)
            || self.event_hash != self.expected_hash()?
            || !bounded_nonempty(&self.key_id, 128)
        {
            return Err(ContractError::HashMismatch);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(self.event_hash.as_bytes(), &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

/// Describes whether an authority event is the result of a governed action or an
/// authenticated observation. Governed actions must carry the final PEP and
/// ledger binding; authenticated observations must not pretend to have one.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityEvidenceSourceKind {
    GovernedAction,
    AuthenticatedEvent,
}

/// Common final-authorization binding recorded by every production authority.
/// The Evidence Authority verifies the ledger fields against the authoritative
/// PEP persistence record before signing the evidence receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvidenceControlBinding {
    pub action_hash: ActionHash,
    pub ledger_execution_id: ExecutionId,
    pub ledger_event_id: String,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
}

impl AuthorityEvidenceControlBinding {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !is_lower_hex_digest(&self.action_hash.0)
            || !canonical_uuid(&self.ledger_execution_id.0)
            || !canonical_uuid(&self.ledger_event_id)
            || !is_lower_hex_digest(&self.ledger_event_digest)
            || !is_lower_hex_digest(&self.fence_digest)
            || !bounded_nonempty(&self.policy_decision_id, 256)
            || !is_lower_hex_digest(&self.policy_decision_digest)
            || !bounded_nonempty(&self.authorization_evidence_ref, 2_048)
            || !is_lower_hex_digest(&self.authorization_evidence_digest)
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

/// Dependency-acyclic wire used by state-owning production authorities. This is
/// intentionally separate from lifecycle evidence, whose task-state version is
/// checked against the durable orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvidenceEventRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub authority_event_id: String,
    pub idempotency_key: IdempotencyKey,
    pub source_kind: AuthorityEvidenceSourceKind,
    pub control_binding: Option<AuthorityEvidenceControlBinding>,
    pub event: EvidenceEventDraft,
    pub requested_at: DateTime<Utc>,
}

impl AuthorityEvidenceEventRequest {
    pub fn request_digest(&self) -> Result<String, ContractError> {
        self.event.validate()?;
        let binding_shape_valid = matches!(
            (&self.source_kind, &self.control_binding),
            (AuthorityEvidenceSourceKind::GovernedAction, Some(_))
                | (AuthorityEvidenceSourceKind::AuthenticatedEvent, None)
        );
        if self.schema_version != AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.authority_event_id)
            || !valid_idempotency_key(&self.idempotency_key.0)
            || self.event.tenant_id != self.tenant_id
            || self.event.task_id != self.task_id
            || !binding_shape_valid
            || matches!(
                &self.event.event_type,
                EvidenceEventType::TaskCreated
                    | EvidenceEventType::PlanGenerated
                    | EvidenceEventType::ToolExecuted
            )
            || self.requested_at > Utc::now() + chrono::Duration::minutes(1)
            || self.event.occurred_at > self.requested_at + chrono::Duration::minutes(1)
        {
            return Err(ContractError::ScopeExceeded);
        }
        if let Some(binding) = &self.control_binding {
            binding.validate()?;
        }
        canonical_hash(self)
    }
}

/// Signed, independently verifiable receipt for a state-owning authority event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityEvidenceReceipt {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub authority_event_id: String,
    pub idempotency_key: IdempotencyKey,
    pub source_kind: AuthorityEvidenceSourceKind,
    pub request_digest: String,
    pub payload_digest: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub event: SignedEvidenceEvent,
    pub persisted_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl SignedAuthorityEvidenceReceipt {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.evidence_digest.clear();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn expected_digest(&self) -> Result<String, ContractError> {
        Ok(hex::encode(Sha256::digest(self.signing_bytes()?)))
    }

    pub fn expected_evidence_ref(&self) -> String {
        format!(
            "evidence://authority-event/{}/{}/{}/{}",
            self.tenant_id.0, self.task_id.0, self.authority_event_id, self.event.event_hash
        )
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.evidence_digest = self.expected_digest()?;
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(self.evidence_digest.as_bytes()).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ContractError> {
        self.event.verify(key)?;
        if self.schema_version != AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION
            || self.key_usage != AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.authority_event_id)
            || !valid_idempotency_key(&self.idempotency_key.0)
            || !is_lower_hex_digest(&self.request_digest)
            || !is_lower_hex_digest(&self.payload_digest)
            || self.event.event_id != self.authority_event_id
            || self.event.draft.tenant_id != self.tenant_id
            || self.event.draft.task_id != self.task_id
            || self.event.draft.payload_hash != self.payload_digest
            || self.evidence_ref != self.expected_evidence_ref()
            || self.evidence_digest != self.expected_digest()?
            || self.persisted_at < self.event.draft.occurred_at
            || self.persisted_at > now
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 128)
            || self.key_id != self.event.key_id
        {
            return Err(ContractError::HashMismatch);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(self.evidence_digest.as_bytes(), &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

pub const APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION: &str =
    "agenttrust.approval-review-evidence-binding.v1";
pub const APPROVAL_REVIEW_MATERIAL_SCHEMA_VERSION: &str =
    "agenttrust.approval-review-material.v1";
pub const APPROVAL_REVIEW_EVIDENCE_ISSUE_SCHEMA_VERSION: &str =
    "agenttrust.approval-review-evidence-issue.v2";
pub const APPROVAL_REVIEW_MAX_EVIDENCE_LIFETIME_SECONDS: i64 = 900;
pub const APPROVAL_REVIEW_MAX_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodingApprovalReviewDetails {
    pub diff_artifact_ref: String,
    pub command_summary: String,
    pub network_scope: String,
    pub rollback_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndustrialApprovalReviewDetails {
    pub current_value: String,
    pub target_value: String,
    pub allowed_range: String,
    pub interlock_summary: String,
    pub physical_impact: String,
}

/// Safe, domain-discriminated facts prepared independently of the approval service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "domain",
    content = "details",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ApprovalReviewContext {
    Coding(CodingApprovalReviewDetails),
    Industrial(IndustrialApprovalReviewDetails),
}

impl ApprovalReviewContext {
    pub fn valid(&self) -> bool {
        match self {
            Self::Coding(details) => {
                approval_review_artifact_ref(&details.diff_artifact_ref)
                    && approval_review_text(&details.command_summary, 2_048)
                    && approval_review_text(&details.network_scope, 1_024)
                    && approval_review_text(&details.rollback_summary, 2_048)
            }
            Self::Industrial(details) => {
                approval_review_text(&details.current_value, 512)
                    && approval_review_text(&details.target_value, 512)
                    && approval_review_text(&details.allowed_range, 512)
                    && approval_review_text(&details.interlock_summary, 2_048)
                    && approval_review_text(&details.physical_impact, 2_048)
            }
        }
    }

    pub fn industrial(&self) -> bool {
        matches!(self, Self::Industrial(_))
    }
}

/// Complete immutable review package bound by the Evidence Authority payload digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReviewMaterial {
    pub schema_version: String,
    pub tenant_id: String,
    pub task_id: String,
    pub canonical_action_hash: String,
    pub resource: String,
    pub resource_version: String,
    pub policy_version: String,
    pub environment: String,
    pub risk: RiskLevel,
    pub review_context: ApprovalReviewContext,
    pub risk_package_ref: String,
    pub risk_package_digest: String,
    pub state_snapshot_ref: String,
    pub state_snapshot_digest: String,
}

impl ApprovalReviewMaterial {
    pub fn validate(&self) -> Result<(), ContractError> {
        let industrial_resource = approval_review_resource_is_industrial(
            &self.resource,
            &self.environment,
        );
        if self.schema_version != APPROVAL_REVIEW_MATERIAL_SCHEMA_VERSION
            || !canonical_uuid(&self.tenant_id)
            || !canonical_uuid(&self.task_id)
            || !is_lower_hex_digest(&self.canonical_action_hash)
            || !approval_review_bounded(&self.resource, 2_048)
            || !approval_review_bounded(&self.resource_version, 2_048)
            || !approval_review_bounded(&self.policy_version, 2_048)
            || !approval_review_bounded(&self.environment, 2_048)
            || !self.review_context.valid()
            || industrial_resource != self.review_context.industrial()
            || !approval_review_evidence_ref(&self.risk_package_ref)
            || !is_lower_hex_digest(&self.risk_package_digest)
            || !approval_review_evidence_ref(&self.state_snapshot_ref)
            || !is_lower_hex_digest(&self.state_snapshot_digest)
            || self.risk_package_ref == self.state_snapshot_ref
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }

    pub fn payload_digest(&self) -> Result<String, ContractError> {
        self.validate()?;
        canonical_hash(self)
    }

    pub fn artifact_refs(&self) -> Vec<ArtifactRef> {
        match &self.review_context {
            ApprovalReviewContext::Coding(details) => vec![
                ArtifactRef(details.diff_artifact_ref.clone()),
                ArtifactRef(self.risk_package_ref.clone()),
                ArtifactRef(self.state_snapshot_ref.clone()),
            ],
            ApprovalReviewContext::Industrial(_) => vec![
                ArtifactRef(self.risk_package_ref.clone()),
                ArtifactRef(self.state_snapshot_ref.clone()),
            ],
        }
    }

    pub fn safe_summary(&self) -> &'static str {
        match &self.review_context {
            ApprovalReviewContext::Coding(_) => "Approval coding review facts prepared",
            ApprovalReviewContext::Industrial(_) => "Approval industrial review facts prepared",
        }
    }
}

/// Producer input for an independent risk/snapshot authority. No signing material is accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReviewEvidenceIssueRequest {
    pub schema_version: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub actor_subject: String,
    pub source_service: String,
    pub trace_id: String,
    pub material: ApprovalReviewMaterial,
    pub requested_at: DateTime<Utc>,
}

impl ApprovalReviewEvidenceIssueRequest {
    pub fn to_authority_event(
        &self,
        expected_source_service: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthorityEvidenceEventRequest, ContractError> {
        if self.schema_version != APPROVAL_REVIEW_EVIDENCE_ISSUE_SCHEMA_VERSION
            || !canonical_uuid(&self.request_id)
            || !valid_idempotency_key(&self.idempotency_key)
            || !approval_review_identifier(&self.actor_subject, 512)
            || !approval_review_source_identity(&self.source_service)
            || self.source_service != expected_source_service
            || !approval_review_identifier(&self.trace_id, 256)
            || approval_review_secret_marker(&self.actor_subject)
            || approval_review_secret_marker(&self.source_service)
            || approval_review_secret_marker(&self.trace_id)
            || self.requested_at
                > now + chrono::Duration::seconds(APPROVAL_REVIEW_MAX_CLOCK_SKEW_SECONDS)
            || self.requested_at
                < now - chrono::Duration::seconds(APPROVAL_REVIEW_MAX_EVIDENCE_LIFETIME_SECONDS)
        {
            return Err(ContractError::ScopeExceeded);
        }
        let payload_hash = self.material.payload_digest()?;
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: TenantId(self.material.tenant_id.clone()),
            task_id: TaskId(self.material.task_id.clone()),
            authority_event_id: self.request_id.clone(),
            idempotency_key: IdempotencyKey(self.idempotency_key.clone()),
            source_kind: AuthorityEvidenceSourceKind::AuthenticatedEvent,
            control_binding: None,
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: TenantId(self.material.tenant_id.clone()),
                task_id: TaskId(self.material.task_id.clone()),
                event_type: EvidenceEventType::ApprovalReviewPrepared,
                actor_subject: self.actor_subject.clone(),
                source_service: self.source_service.clone(),
                trace_id: self.trace_id.clone(),
                span_id: self.request_id.clone(),
                payload_hash,
                safe_summary: self.material.safe_summary().into(),
                artifact_refs: self.material.artifact_refs(),
                occurred_at: self.requested_at,
            },
            requested_at: self.requested_at,
        };
        request.request_digest()?;
        Ok(request)
    }
}

/// Complete producer result persisted by Approval so request_digest can always be recomputed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReviewEvidence {
    pub schema_version: String,
    pub material: ApprovalReviewMaterial,
    pub authority_request: AuthorityEvidenceEventRequest,
    pub receipt: SignedAuthorityEvidenceReceipt,
}

impl ApprovalReviewEvidence {
    pub fn evidence_refs(&self) -> Vec<String> {
        vec![
            self.material.risk_package_ref.clone(),
            self.material.state_snapshot_ref.clone(),
            self.receipt.evidence_ref.clone(),
        ]
    }
}

fn approval_review_resource_is_industrial(resource: &str, environment: &str) -> bool {
    let resource = resource.to_ascii_lowercase();
    [
        "opcua:",
        "opc.tcp:",
        "mqtt:",
        "modbus:",
        "plc:",
        "scada:",
        "plant/",
        "urn:agenttrust:industrial:",
    ]
    .iter()
    .any(|prefix| resource.starts_with(prefix))
        || matches!(environment, "industrial" | "physical-production")
}

fn approval_review_evidence_ref(value: &str) -> bool {
    let suffix = value
        .strip_prefix("evidence://")
        .or_else(|| value.strip_prefix("urn:agenttrust:evidence:"))
        .or_else(|| value.strip_prefix("urn:agenttrust:ledger-evidence:"));
    suffix.is_some_and(|suffix| {
        !suffix.is_empty()
            && value.len() <= 2_048
            && !approval_review_secret_marker(value)
            && !value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
            && !value.contains(['?', '#'])
    })
}

fn approval_review_artifact_ref(value: &str) -> bool {
    value
        .strip_prefix("artifact://sha256/")
        .is_some_and(is_lower_hex_digest)
}

fn approval_review_source_identity(value: &str) -> bool {
    value
        .strip_prefix("DNS:")
        .or_else(|| value.strip_prefix("URI:"))
        .is_some_and(|identity| {
            !identity.is_empty() && approval_review_identifier(value, 256)
        })
}

fn approval_review_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn approval_review_bounded(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && !approval_review_secret_marker(value)
}

fn approval_review_text(value: &str, maximum: usize) -> bool {
    approval_review_bounded(value, maximum)
        && !value
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
            })
            .any(|fragment| {
                fragment.len() >= 32
                    && fragment.bytes().any(|byte| byte.is_ascii_alphabetic())
                    && fragment.bytes().any(|byte| byte.is_ascii_digit())
            })
}

fn approval_review_secret_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "password",
        "passwd",
        "client_secret",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "private key",
        "-----begin",
        "cookie:",
        "set-cookie",
        "credential://",
        "vault-kv://",
        "secret://",
        "token=",
        "token:",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidenceRequest<R> {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub execution_id: ExecutionId,
    pub fence_digest: String,
    pub action_hash: ActionHash,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub idempotency_key: IdempotencyKey,
    pub result: R,
    pub event: EvidenceEventDraft,
}

impl<R: Serialize> ExecutionEvidenceRequest<R> {
    pub fn request_digest(&self) -> Result<String, ContractError> {
        if self.schema_version != EXECUTION_EVIDENCE_REQUEST_SCHEMA_VERSION
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.step_id.0)
            || !canonical_uuid(&self.execution_id.0)
            || !canonical_uuid(&self.authorization_id)
            || !is_lower_hex_digest(&self.fence_digest)
            || !is_lower_hex_digest(&self.action_hash.0)
            || !is_lower_hex_digest(&self.authorization_digest)
            || !valid_idempotency_key(&self.idempotency_key.0)
            || self.event.tenant_id != self.tenant_id
            || self.event.task_id != self.task_id
        {
            return Err(ContractError::ScopeExceeded);
        }
        self.event.validate()?;
        canonical_hash(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionEvidenceReceipt {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub execution_id: ExecutionId,
    pub action_hash: ActionHash,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub fence_digest: String,
    pub idempotency_key: IdempotencyKey,
    pub request_digest: String,
    pub result_hash: String,
    pub chain_head: String,
    pub evidence_ref: String,
    pub event: SignedEvidenceEvent,
    pub persisted_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl SignedExecutionEvidenceReceipt {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn expected_evidence_ref(&self) -> String {
        format!(
            "evidence://{}/{}/{}/{}",
            self.tenant_id.0, self.task_id.0, self.event.sequence, self.event.event_hash
        )
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ContractError> {
        self.event.verify(key)?;
        if self.schema_version != EXECUTION_EVIDENCE_RECEIPT_SCHEMA_VERSION
            || self.key_usage != EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.step_id.0)
            || !canonical_uuid(&self.execution_id.0)
            || !canonical_uuid(&self.authorization_id)
            || !is_lower_hex_digest(&self.action_hash.0)
            || !is_lower_hex_digest(&self.authorization_digest)
            || !is_lower_hex_digest(&self.fence_digest)
            || !is_lower_hex_digest(&self.request_digest)
            || !is_lower_hex_digest(&self.result_hash)
            || self.chain_head != self.event.event_hash
            || self.evidence_ref != self.expected_evidence_ref()
            || !valid_idempotency_key(&self.idempotency_key.0)
            || self.event.draft.tenant_id != self.tenant_id
            || self.event.draft.task_id != self.task_id
            || self.event.draft.span_id != self.execution_id.0
            || self.event.draft.payload_hash != self.result_hash
            || self.persisted_at < self.event.draft.occurred_at
            || self.persisted_at > now
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 128)
        {
            return Err(ContractError::HashMismatch);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCredentialBindingRequest {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub tenant_id: TenantId,
    pub agent_instance_id: AgentInstanceId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub policy_decision_id: String,
    pub tool_id: ToolId,
    pub credential_profile: String,
    pub operation: String,
    pub resource: String,
    pub target_profile: String,
    pub audience: String,
    pub revocation_epoch: u64,
    pub ttl_seconds: u64,
    pub max_uses: u32,
}

impl WorkloadCredentialBindingRequest {
    /// Shared fail-closed validation used by the PEP, credential authority and consumers.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION
            || !valid_idempotency_key(&self.idempotency_key.0)
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.agent_instance_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.step_id.0)
            || !is_lower_hex_digest(&self.action_hash.0)
            || !bounded_nonempty(&self.policy_decision_id, 256)
            || !bounded_nonempty(&self.tool_id.0, 256)
            || !bounded_nonempty(&self.credential_profile, 256)
            || !bounded_nonempty(&self.operation, 256)
            || !bounded_nonempty(&self.resource, 2_048)
            || !bounded_nonempty(&self.target_profile, 256)
            || self.audience != "tool-proxy"
            || self.ttl_seconds == 0
            || self.ttl_seconds > 300
            || self.max_uses != 1
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCredentialClaims {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub credential_id: String,
    pub tenant_id: TenantId,
    pub agent_instance_id: AgentInstanceId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub policy_decision_id: String,
    pub tool_id: ToolId,
    pub credential_profile: String,
    pub operation: String,
    pub resource: String,
    pub target_profile: String,
    pub audience: String,
    pub revocation_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkloadCredentialBindingReceipt {
    pub schema_version: String,
    pub credential_handle_sha256: String,
    pub claims: WorkloadCredentialClaims,
    pub claims_digest: String,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl fmt::Debug for SignedWorkloadCredentialBindingReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedWorkloadCredentialBindingReceipt")
            .field("schema_version", &self.schema_version)
            .field("credential_handle_sha256", &self.credential_handle_sha256)
            .field("claims", &self.claims)
            .field("claims_digest", &self.claims_digest)
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .field("key_usage", &self.key_usage)
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl SignedWorkloadCredentialBindingReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ContractError> {
        self.claims_digest = canonical_hash(&self.claims)?;
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        request: &WorkloadCredentialBindingRequest,
        credential_handle: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        request.validate()?;
        self.verify_intrinsic(key, credential_handle, now)?;
        if self.claims.idempotency_key != request.idempotency_key
            || self.claims.tenant_id != request.tenant_id
            || self.claims.agent_instance_id != request.agent_instance_id
            || self.claims.task_id != request.task_id
            || self.claims.step_id != request.step_id
            || self.claims.action_hash != request.action_hash
            || self.claims.policy_decision_id != request.policy_decision_id
            || self.claims.tool_id != request.tool_id
            || self.claims.credential_profile != request.credential_profile
            || self.claims.operation != request.operation
            || self.claims.resource != request.resource
            || self.claims.target_profile != request.target_profile
            || self.claims.audience != request.audience
            || self.claims.revocation_epoch != request.revocation_epoch
            || self.claims.max_uses != request.max_uses
            || self.claims.expires_at - self.claims.issued_at
                > chrono::Duration::seconds(request.ttl_seconds as i64)
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }

    /// Verifies a receipt without requiring the original issuance request. Consumers use this
    /// before sending an atomic consumption request to the credential authority.
    pub fn verify_intrinsic(
        &self,
        key: &VerifyingKey,
        credential_handle: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        let claims = &self.claims;
        let lifetime = claims.expires_at - claims.issued_at;
        if self.schema_version != WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION
            || claims.schema_version != WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION
            || self.key_usage != WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE
            || !bounded_nonempty(credential_handle, 2_048)
            || !is_lower_hex_digest(&self.credential_handle_sha256)
            || self.credential_handle_sha256
                != hex::encode(Sha256::digest(credential_handle.as_bytes()))
            || !valid_idempotency_key(&claims.idempotency_key.0)
            || !canonical_uuid(&claims.credential_id)
            || !canonical_uuid(&claims.tenant_id.0)
            || !canonical_uuid(&claims.agent_instance_id.0)
            || !canonical_uuid(&claims.task_id.0)
            || !canonical_uuid(&claims.step_id.0)
            || !is_lower_hex_digest(&claims.action_hash.0)
            || !bounded_nonempty(&claims.policy_decision_id, 256)
            || !bounded_nonempty(&claims.tool_id.0, 256)
            || !bounded_nonempty(&claims.credential_profile, 256)
            || !bounded_nonempty(&claims.operation, 256)
            || !bounded_nonempty(&claims.resource, 2_048)
            || !bounded_nonempty(&claims.target_profile, 256)
            || claims.audience != "tool-proxy"
            || claims.max_uses != 1
            || claims.issued_at > now
            || claims.expires_at <= now
            || lifetime <= chrono::Duration::zero()
            || lifetime > chrono::Duration::minutes(5)
            || self.claims_digest != canonical_hash(claims)?
            || !is_lower_hex_digest(&self.claims_digest)
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 256)
        {
            return Err(ContractError::ScopeExceeded);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

/// A raw workload credential is transported only in this outer, non-persistable envelope.
/// The signed receipt contains a handle digest and non-secret claims, never the bearer itself.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCredentialIssuance<W> {
    pub workload_credential: W,
    pub binding_receipt: SignedWorkloadCredentialBindingReceipt,
}

impl<W> fmt::Debug for WorkloadCredentialIssuance<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadCredentialIssuance")
            .field("workload_credential", &"<redacted>")
            .field("binding_receipt", &self.binding_receipt)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCredentialConsumptionRequest {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub credential_handle: String,
    pub binding_receipt: SignedWorkloadCredentialBindingReceipt,
    pub tenant_id: TenantId,
    pub agent_instance_id: AgentInstanceId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub policy_decision_id: String,
    pub tool_id: ToolId,
    pub credential_profile: String,
    pub operation: String,
    pub resource: String,
    pub target_profile: String,
    pub audience: String,
    pub revocation_epoch: u64,
    pub claims_digest: String,
}

impl fmt::Debug for WorkloadCredentialConsumptionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadCredentialConsumptionRequest")
            .field("schema_version", &self.schema_version)
            .field("idempotency_key", &self.idempotency_key)
            .field("credential_handle", &"<redacted>")
            .field("binding_receipt", &self.binding_receipt)
            .field("tenant_id", &self.tenant_id)
            .field("agent_instance_id", &self.agent_instance_id)
            .field("task_id", &self.task_id)
            .field("step_id", &self.step_id)
            .field("action_hash", &self.action_hash)
            .field("policy_decision_id", &self.policy_decision_id)
            .field("tool_id", &self.tool_id)
            .field("credential_profile", &self.credential_profile)
            .field("operation", &self.operation)
            .field("resource", &self.resource)
            .field("target_profile", &self.target_profile)
            .field("audience", &self.audience)
            .field("revocation_epoch", &self.revocation_epoch)
            .field("claims_digest", &self.claims_digest)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WorkloadCredentialConsumptionScope<'a> {
    tenant_id: &'a TenantId,
    agent_instance_id: &'a AgentInstanceId,
    task_id: &'a TaskId,
    step_id: &'a StepId,
    action_hash: &'a ActionHash,
    policy_decision_id: &'a str,
    tool_id: &'a ToolId,
    credential_profile: &'a str,
    operation: &'a str,
    resource: &'a str,
    target_profile: &'a str,
    audience: &'a str,
    revocation_epoch: u64,
    claims_digest: &'a str,
}

impl WorkloadCredentialConsumptionRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        let claims = &self.binding_receipt.claims;
        if self.schema_version != WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION
            || !valid_idempotency_key(&self.idempotency_key.0)
            || !bounded_nonempty(&self.credential_handle, 2_048)
            || self.binding_receipt.schema_version
                != WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION
            || self.binding_receipt.key_usage != WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE
            || claims.schema_version != WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION
            || !valid_idempotency_key(&claims.idempotency_key.0)
            || !canonical_uuid(&claims.credential_id)
            || self.binding_receipt.credential_handle_sha256
                != hex::encode(Sha256::digest(self.credential_handle.as_bytes()))
            || !canonical_uuid(&self.tenant_id.0)
            || !canonical_uuid(&self.agent_instance_id.0)
            || !canonical_uuid(&self.task_id.0)
            || !canonical_uuid(&self.step_id.0)
            || !is_lower_hex_digest(&self.action_hash.0)
            || !bounded_nonempty(&self.policy_decision_id, 256)
            || !bounded_nonempty(&self.tool_id.0, 256)
            || !bounded_nonempty(&self.credential_profile, 256)
            || !bounded_nonempty(&self.operation, 256)
            || !bounded_nonempty(&self.resource, 2_048)
            || !bounded_nonempty(&self.target_profile, 256)
            || self.audience != "tool-proxy"
            || !is_lower_hex_digest(&self.claims_digest)
            || self.claims_digest != self.binding_receipt.claims_digest
            || self.binding_receipt.claims_digest != canonical_hash(claims)?
            || claims.tenant_id != self.tenant_id
            || claims.agent_instance_id != self.agent_instance_id
            || claims.task_id != self.task_id
            || claims.step_id != self.step_id
            || claims.action_hash != self.action_hash
            || claims.policy_decision_id != self.policy_decision_id
            || claims.tool_id != self.tool_id
            || claims.credential_profile != self.credential_profile
            || claims.operation != self.operation
            || claims.resource != self.resource
            || claims.target_profile != self.target_profile
            || claims.audience != self.audience
            || claims.revocation_epoch != self.revocation_epoch
            || claims.max_uses != 1
        {
            return Err(ContractError::ScopeExceeded);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Result<String, ContractError> {
        self.validate()?;
        canonical_hash(&WorkloadCredentialConsumptionScope {
            tenant_id: &self.tenant_id,
            agent_instance_id: &self.agent_instance_id,
            task_id: &self.task_id,
            step_id: &self.step_id,
            action_hash: &self.action_hash,
            policy_decision_id: &self.policy_decision_id,
            tool_id: &self.tool_id,
            credential_profile: &self.credential_profile,
            operation: &self.operation,
            resource: &self.resource,
            target_profile: &self.target_profile,
            audience: &self.audience,
            revocation_epoch: self.revocation_epoch,
            claims_digest: &self.claims_digest,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkloadCredentialConsumptionReceipt {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub consumption_id: String,
    pub credential_id: String,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub audience: String,
    pub revocation_epoch: u64,
    pub claims_digest: String,
    pub scope_digest: String,
    pub consumed_at: DateTime<Utc>,
    pub remaining_uses: u32,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl fmt::Debug for SignedWorkloadCredentialConsumptionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedWorkloadCredentialConsumptionReceipt")
            .field("schema_version", &self.schema_version)
            .field("idempotency_key", &self.idempotency_key)
            .field("consumption_id", &self.consumption_id)
            .field("credential_id", &self.credential_id)
            .field("tenant_id", &self.tenant_id)
            .field("action_hash", &self.action_hash)
            .field("audience", &self.audience)
            .field("revocation_epoch", &self.revocation_epoch)
            .field("claims_digest", &self.claims_digest)
            .field("scope_digest", &self.scope_digest)
            .field("consumed_at", &self.consumed_at)
            .field("remaining_uses", &self.remaining_uses)
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .field("key_usage", &self.key_usage)
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl SignedWorkloadCredentialConsumptionReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ContractError::Canonicalization)
    }

    pub fn sign(
        &mut self,
        key: &SigningKey,
        request: &WorkloadCredentialConsumptionRequest,
    ) -> Result<(), ContractError> {
        request.validate()?;
        self.scope_digest = request.scope_digest()?;
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        request: &WorkloadCredentialConsumptionRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ContractError> {
        request.validate()?;
        if self.schema_version != WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION
            || self.idempotency_key != request.idempotency_key
            || !canonical_uuid(&self.consumption_id)
            || self.credential_id != request.binding_receipt.claims.credential_id
            || self.tenant_id != request.tenant_id
            || self.action_hash != request.action_hash
            || self.audience != request.audience
            || self.revocation_epoch != request.revocation_epoch
            || self.claims_digest != request.claims_digest
            || self.scope_digest != request.scope_digest()?
            || self.consumed_at > now
            || self.remaining_uses != 0
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 256)
            || self.key_usage != WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE
        {
            return Err(ContractError::ScopeExceeded);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ContractError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ContractError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ContractError::SignatureInvalid)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PepPreExecutionAuthorization<T, W> {
    pub schema_version: String,
    pub authorization: ExecutionAuthorization,
    pub tool: T,
    pub workload_credential: W,
    pub credential_binding_receipt: SignedWorkloadCredentialBindingReceipt,
    pub target_profile: String,
    #[serde(default)]
    pub approval: Option<MinimalApprovalGrant>,
}

impl<T: fmt::Debug, W> fmt::Debug for PepPreExecutionAuthorization<T, W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PepPreExecutionAuthorization")
            .field("schema_version", &self.schema_version)
            .field("authorization", &self.authorization)
            .field("tool", &self.tool)
            .field("workload_credential", &"<redacted>")
            .field("credential_binding_receipt", &"<redacted>")
            .field("target_profile", &self.target_profile)
            .field("approval", &self.approval)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorization {
    pub schema_version: SchemaVersion,
    pub authorization_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub agent_instance_id: AgentInstanceId,
    pub action_hash: ActionHash,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub tool_snapshot_hash: String,
    pub implementation_digest: String,
    pub executor_profile: String,
    pub operation: String,
    pub resource: String,
    pub canonical_arguments_hash: String,
    pub target_profile: String,
    pub environment: String,
    pub idempotency_key: IdempotencyKey,
    pub ledger_execution_id: ExecutionId,
    pub ledger_event_id: String,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub policy_version: PolicyVersion,
    pub policy_bundle_hash: String,
    pub policy_input_hash: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub preapproval_digest: String,
    pub approval_ids: Vec<ApprovalId>,
    pub approval_consumption_ref: Option<String>,
    pub approval_receipt_digest: Option<String>,
    pub resource_version: ResourceVersion,
    pub sandbox_profile: String,
    pub network_profile: String,
    pub credential_profile: String,
    pub workload_credential_id: String,
    pub workload_credential_claims_digest: String,
    pub workload_credential_audience: String,
    pub workload_credential_revocation_epoch: u64,
    pub max_execution_ms: u64,
    pub max_result_bytes: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub single_use: bool,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl ExecutionAuthorization {
    pub fn compute_evidence_digest(&self) -> Result<String, ContractError> {
        let mut evidence = self.clone();
        evidence.authorization_evidence_ref.clear();
        evidence.authorization_evidence_digest.clear();
        evidence.signature.clear();
        let bytes = serde_jcs::to_vec(&evidence).map_err(|_| ContractError::Canonicalization)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn bind_evidence(&mut self) -> Result<(), ContractError> {
        self.authorization_evidence_ref.clear();
        self.authorization_evidence_digest.clear();
        self.signature.clear();
        self.authorization_evidence_digest = self.compute_evidence_digest()?;
        self.authorization_evidence_ref = format!(
            "urn:agenttrust:pep-authorization:{}:{}:sha256:{}",
            self.tenant_id.0, self.authorization_id, self.authorization_evidence_digest
        );
        Ok(())
    }

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
        let approval_binding_present =
            self.approval_consumption_ref.is_some() && self.approval_receipt_digest.is_some();
        let unique_approval_ids = self.approval_ids.iter().collect::<BTreeSet<_>>();
        if self.schema_version.0 != EXECUTION_AUTHORIZATION_SCHEMA_VERSION
            || self.key_usage != PEP_EXECUTION_AUTHORIZATION_KEY_USAGE
            || Uuid::parse_str(&self.authorization_id).is_err()
            || Uuid::parse_str(&self.tenant_id.0).is_err()
            || Uuid::parse_str(&self.task_id.0).is_err()
            || Uuid::parse_str(&self.step_id.0).is_err()
            || Uuid::parse_str(&self.agent_instance_id.0).is_err()
            || Uuid::parse_str(&self.ledger_execution_id.0).is_err()
            || Uuid::parse_str(&self.ledger_event_id).is_err()
            || !is_lower_hex_digest(&self.ledger_event_digest)
            || !is_lower_hex_digest(&self.action_hash.0)
            || !is_lower_hex_digest(&self.tool_snapshot_hash)
            || !is_lower_hex_digest(&self.canonical_arguments_hash)
            || !is_lower_hex_digest(&self.fence_digest)
            || !is_lower_hex_digest(&self.policy_bundle_hash)
            || !is_lower_hex_digest(&self.policy_input_hash)
            || !is_lower_hex_digest(&self.preapproval_digest)
            || self
                .approval_receipt_digest
                .as_deref()
                .is_some_and(|digest| !is_lower_hex_digest(digest))
            || self.approval_ids.len() > 64
            || unique_approval_ids.len() != self.approval_ids.len()
            || self
                .approval_ids
                .iter()
                .any(|approval_id| Uuid::parse_str(&approval_id.0).is_err())
            || approval_binding_present != !self.approval_ids.is_empty()
            || self.approval_consumption_ref.is_some() != self.approval_receipt_digest.is_some()
            || self
                .approval_consumption_ref
                .as_deref()
                .is_some_and(|reference| !bounded_nonempty(reference, 2_048))
            || !bounded_nonempty(&self.tool_id.0, 256)
            || !bounded_nonempty(&self.tool_version.0, 256)
            || !valid_implementation_digest(&self.implementation_digest)
            || !bounded_nonempty(&self.executor_profile, 256)
            || !bounded_nonempty(&self.operation, 256)
            || !bounded_nonempty(&self.resource, 2_048)
            || !bounded_nonempty(&self.target_profile, 256)
            || !bounded_nonempty(&self.environment, 128)
            || !valid_idempotency_key(&self.idempotency_key.0)
            || !bounded_nonempty(&self.policy_decision_id, 256)
            || !is_lower_hex_digest(&self.policy_decision_digest)
            || !bounded_nonempty(&self.policy_version.0, 256)
            || !is_lower_hex_digest(&self.authorization_evidence_digest)
            || self.authorization_evidence_ref
                != format!(
                    "urn:agenttrust:pep-authorization:{}:{}:sha256:{}",
                    self.tenant_id.0, self.authorization_id, self.authorization_evidence_digest
                )
            || self.compute_evidence_digest()? != self.authorization_evidence_digest
            || !bounded_nonempty(&self.resource_version.0, 256)
            || !bounded_nonempty(&self.sandbox_profile, 256)
            || !bounded_nonempty(&self.network_profile, 256)
            || !bounded_nonempty(&self.credential_profile, 256)
            || Uuid::parse_str(&self.workload_credential_id).is_err()
            || !is_lower_hex_digest(&self.workload_credential_claims_digest)
            || self.workload_credential_audience != "tool-proxy"
            || self.max_execution_ms == 0
            || self.max_execution_ms > 86_400_000
            || self.max_result_bytes == 0
            || self.max_result_bytes > 1_073_741_824
            || !self.single_use
            || !bounded_nonempty(&self.issuer, 256)
            || !bounded_nonempty(&self.key_id, 256)
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::Duration::minutes(5)
        {
            return Err(ContractError::ScopeExceeded);
        }
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

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_nonempty(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

fn valid_idempotency_key(value: &str) -> bool {
    bounded_nonempty(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_contract_identifier(value: &str, maximum: usize) -> bool {
    bounded_nonempty(value, maximum)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_implementation_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(is_lower_hex_digest)
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
    #[error("CONTRACT_AUTHORITATIVE_FACT_UNAVAILABLE")]
    FactUnavailable,
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
        let now = Utc::now();
        let mut auth = ExecutionAuthorization {
            schema_version: SchemaVersion(EXECUTION_AUTHORIZATION_SCHEMA_VERSION.into()),
            authorization_id: Uuid::new_v4().to_string(),
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            agent_instance_id: AgentInstanceId::new(),
            action_hash: ActionHash("a".repeat(64)),
            tool_id: ToolId("coding.run-tests".into()),
            tool_version: ToolVersion("1.0.0".into()),
            tool_snapshot_hash: "b".repeat(64),
            implementation_digest: format!("sha256:{}", "c".repeat(64)),
            executor_profile: "sandbox".into(),
            operation: "execute".into(),
            resource: "repo:alpha".into(),
            canonical_arguments_hash: "d".repeat(64),
            target_profile: "repo-primary".into(),
            environment: "production".into(),
            idempotency_key: IdempotencyKey("execution-1".into()),
            ledger_execution_id: ExecutionId::new(),
            ledger_event_id: Uuid::new_v4().to_string(),
            ledger_event_digest: "3".repeat(64),
            fence_digest: "e".repeat(64),
            policy_decision_id: "decision".into(),
            policy_decision_digest: "4".repeat(64),
            policy_version: PolicyVersion("policy-1".into()),
            policy_bundle_hash: "f".repeat(64),
            policy_input_hash: "0".repeat(64),
            authorization_evidence_ref: String::new(),
            authorization_evidence_digest: String::new(),
            preapproval_digest: "1".repeat(64),
            approval_ids: vec![],
            approval_consumption_ref: None,
            approval_receipt_digest: None,
            resource_version: ResourceVersion("1".into()),
            sandbox_profile: "default".into(),
            network_profile: "none".into(),
            credential_profile: "none".into(),
            workload_credential_id: Uuid::new_v4().to_string(),
            workload_credential_claims_digest: "2".repeat(64),
            workload_credential_audience: "tool-proxy".into(),
            workload_credential_revocation_epoch: 0,
            max_execution_ms: 1000,
            max_result_bytes: 1024,
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            single_use: true,
            issuer: "pep".into(),
            key_id: "test".into(),
            key_usage: PEP_EXECUTION_AUTHORIZATION_KEY_USAGE.into(),
            signature: String::new(),
        };
        assert!(auth.bind_evidence().is_ok());
        assert!(auth.sign(&signing).is_ok());
        assert!(auth.verify(&signing.verifying_key(), now).is_ok());
        let signed = auth.clone();
        auth.fence_digest = "3".repeat(64);
        assert_eq!(
            auth.verify(&signing.verifying_key(), now),
            Err(ContractError::SignatureInvalid)
        );
        let mut duplicate_approval = signed.clone();
        let approval_id = ApprovalId::new();
        duplicate_approval.approval_ids = vec![approval_id.clone(), approval_id];
        duplicate_approval.approval_consumption_ref = Some("approval://consume/1".into());
        duplicate_approval.approval_receipt_digest = Some("4".repeat(64));
        duplicate_approval
            .sign(&signing)
            .unwrap_or_else(|_| panic!("sign"));
        assert_eq!(
            duplicate_approval.verify(&signing.verifying_key(), now),
            Err(ContractError::ScopeExceeded)
        );
        let mut wrong_audience = signed.clone();
        wrong_audience.workload_credential_audience = "another-consumer".into();
        wrong_audience
            .sign(&signing)
            .unwrap_or_else(|_| panic!("sign"));
        assert_eq!(
            wrong_audience.verify(&signing.verifying_key(), now),
            Err(ContractError::ScopeExceeded)
        );
        let mut changed_epoch = signed.clone();
        changed_epoch.workload_credential_revocation_epoch += 1;
        assert_eq!(
            changed_epoch.verify(&signing.verifying_key(), now),
            Err(ContractError::SignatureInvalid)
        );
        let mut oversized = signed;
        oversized.operation = "x".repeat(257);
        oversized.sign(&signing).unwrap_or_else(|_| panic!("sign"));
        assert_eq!(
            oversized.verify(&signing.verifying_key(), now),
            Err(ContractError::ScopeExceeded)
        );
    }

    #[test]
    fn signed_preapproval_rejects_unknown_authoritative_fact() {
        let now = Utc::now();
        let tenant = TenantId::new();
        let action_hash = ActionHash("a".repeat(64));
        let fact_refs = [
            AuthoritativeFactKind::Identity,
            AuthoritativeFactKind::ResourceState,
            AuthoritativeFactKind::Budget,
            AuthoritativeFactKind::TrajectoryRisk,
            AuthoritativeFactKind::Registry,
            AuthoritativeFactKind::Environment,
        ]
        .into_iter()
        .map(|kind| AuthoritativeFactRef {
            kind,
            status: AuthoritativeFactStatus::Verified,
            uri: format!("authority://facts/{kind:?}"),
            digest: "b".repeat(64),
            version: "1".into(),
            observed_at: now - chrono::Duration::seconds(2),
            valid_until: now + chrono::Duration::minutes(2),
        })
        .collect();
        let facts = AuthoritativeFactSnapshot {
            schema_version: SchemaVersion(AUTHORITATIVE_FACT_SNAPSHOT_SCHEMA_VERSION.into()),
            tenant_id: tenant.clone(),
            action_hash: action_hash.clone(),
            identity_subject: Some("user:1".into()),
            identity_uses_dev_verifier: Some(false),
            identity_revocation_epoch: Some(7),
            resource_state_version: Some(ResourceVersion("v1".into())),
            resource_state_fresh: Some(true),
            budget_remaining_microunits: Some(1_000),
            trajectory_risk_version: Some("risk-1".into()),
            accumulated_resources: Some(vec!["repo:alpha".into()]),
            anomaly_score_millionths: Some(0),
            fact_refs,
            captured_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            snapshot_digest: String::new(),
        };
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let mut outcome = SignedPreApprovalOutcome {
            schema_version: SchemaVersion(PRE_APPROVAL_OUTCOME_SCHEMA_VERSION.into()),
            tenant_id: tenant,
            task_id: TaskId::new(),
            step_id: StepId::new(),
            action_hash,
            tool_id: ToolId("coding.run-tests".into()),
            tool_version: ToolVersion("1.0.0".into()),
            tool_snapshot_hash: "c".repeat(64),
            stage: EnforcementStage::PreApproval,
            idempotency_key: IdempotencyKey("execution-1".into()),
            request_digest: "d".repeat(64),
            fact_snapshot: facts,
            fact_snapshot_digest: String::new(),
            execution_plan_digest: None,
            approval_required: false,
            decision: PolicyDecision {
                schema_version: SchemaVersion("agenttrust.policy.v1".into()),
                decision_id: "decision".into(),
                decision: Decision::Allow,
                reason_codes: vec!["ALLOW".into()],
                policy_version: PolicyVersion("policy-1".into()),
                policy_bundle_hash: "e".repeat(64),
                input_hash: "f".repeat(64),
                evaluated_at: now - chrono::Duration::seconds(2),
                expires_at: now + chrono::Duration::minutes(2),
                obligations: vec![],
                risk_summary: RiskLevel::Low,
            },
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            issuer: "pep".into(),
            key_id: "pep-key".into(),
            key_usage: PEP_PRE_APPROVAL_KEY_USAGE.into(),
            signature: String::new(),
        };
        outcome.sign(&signing).unwrap_or_else(|_| panic!("sign"));
        assert!(outcome.verify(&signing.verifying_key(), now).is_ok());
        outcome.fact_snapshot.fact_refs[0].status = AuthoritativeFactStatus::Unknown;
        assert_eq!(
            outcome.fact_snapshot.require_verified(),
            Err(ContractError::FactUnavailable)
        );
    }

    #[test]
    fn approval_review_prepared_event_token_is_cross_contract_stable() {
        assert_eq!(
            serde_json::to_string(&EvidenceEventType::ApprovalReviewPrepared)
                .unwrap_or_else(|_| panic!("event token")),
            "\"APPROVAL_REVIEW_PREPARED\""
        );
        assert_eq!(
            serde_json::from_str::<EvidenceEventType>("\"APPROVAL_REVIEW_PREPARED\"")
                .unwrap_or_else(|_| panic!("event token")),
            EvidenceEventType::ApprovalReviewPrepared
        );
    }

    #[test]
    fn authority_evidence_requires_real_control_binding_and_supports_durable_replay() {
        let now = Utc::now();
        let occurred_at = now - chrono::Duration::hours(2);
        let tenant = TenantId::new();
        let task = TaskId::new();
        let authority_event_id = Uuid::new_v4().to_string();
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            authority_event_id: authority_event_id.clone(),
            idempotency_key: IdempotencyKey("runtime-anomaly:evidence:one".into()),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(AuthorityEvidenceControlBinding {
                action_hash: ActionHash("a".repeat(64)),
                ledger_execution_id: ExecutionId::new(),
                ledger_event_id: Uuid::new_v4().to_string(),
                ledger_event_digest: "b".repeat(64),
                fence_digest: "c".repeat(64),
                policy_decision_id: "decision-1".into(),
                policy_decision_digest: "d".repeat(64),
                authorization_evidence_ref: "urn:agenttrust:pep-authorization:test".into(),
                authorization_evidence_digest: "e".repeat(64),
            }),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                task_id: task.clone(),
                event_type: EvidenceEventType::StateTransition,
                actor_subject: "runtime-anomaly-authority".into(),
                source_service: "URI:spiffe://agenttrust/runtime-anomaly".into(),
                trace_id: Uuid::new_v4().to_string(),
                span_id: authority_event_id.clone(),
                payload_hash: "f".repeat(64),
                safe_summary: "Governed anomaly response persisted".into(),
                artifact_refs: Vec::new(),
                occurred_at,
            },
            requested_at: occurred_at,
        };
        let request_digest = request
            .request_digest()
            .unwrap_or_else(|_| panic!("durable request"));
        let mut missing_binding = request.clone();
        missing_binding.control_binding = None;
        assert_eq!(
            missing_binding.request_digest(),
            Err(ContractError::ScopeExceeded)
        );

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let mut event = SignedEvidenceEvent {
            schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
            event_id: authority_event_id.clone(),
            sequence: 1,
            previous_hash: "0".repeat(64),
            event_hash: String::new(),
            key_id: "evidence-key-1".into(),
            signature: String::new(),
            draft: request.event.clone(),
        };
        event.event_hash = event.expected_hash().unwrap_or_else(|_| panic!("event hash"));
        event.signature = URL_SAFE_NO_PAD.encode(
            signing
                .sign(event.event_hash.as_bytes())
                .to_bytes(),
        );
        let mut receipt = SignedAuthorityEvidenceReceipt {
            schema_version: AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION.into(),
            tenant_id: tenant,
            task_id: task,
            authority_event_id,
            idempotency_key: request.idempotency_key,
            source_kind: request.source_kind,
            request_digest,
            payload_digest: request.event.payload_hash,
            evidence_ref: String::new(),
            evidence_digest: String::new(),
            event,
            persisted_at: now - chrono::Duration::hours(1),
            issuer: "evidence-authority".into(),
            key_id: "evidence-key-1".into(),
            key_usage: AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE.into(),
            signature: String::new(),
        };
        receipt.evidence_ref = receipt.expected_evidence_ref();
        assert!(receipt.sign(&signing).is_ok());
        assert!(receipt.verify(&signing.verifying_key(), now).is_ok());
        receipt.payload_digest = "0".repeat(64);
        assert_eq!(
            receipt.verify(&signing.verifying_key(), now),
            Err(ContractError::HashMismatch)
        );
    }

    #[test]
    fn workload_credential_binding_is_exact_and_debug_is_redacted() {
        let now = Utc::now();
        let request = WorkloadCredentialBindingRequest {
            schema_version: WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION.into(),
            idempotency_key: IdempotencyKey("pep-credential:one".into()),
            tenant_id: TenantId::new(),
            agent_instance_id: AgentInstanceId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            action_hash: ActionHash("a".repeat(64)),
            policy_decision_id: "decision-1".into(),
            tool_id: ToolId("http.call".into()),
            credential_profile: "target-api".into(),
            operation: "post".into(),
            resource: "api:orders".into(),
            target_profile: "orders-prod".into(),
            audience: "tool-proxy".into(),
            revocation_epoch: 9,
            ttl_seconds: 60,
            max_uses: 1,
        };
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let secret_handle = "opaque-super-secret-handle";
        let mut receipt = SignedWorkloadCredentialBindingReceipt {
            schema_version: WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION.into(),
            credential_handle_sha256: hex::encode(Sha256::digest(secret_handle.as_bytes())),
            claims: WorkloadCredentialClaims {
                schema_version: WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION.into(),
                idempotency_key: request.idempotency_key.clone(),
                credential_id: Uuid::new_v4().to_string(),
                tenant_id: request.tenant_id.clone(),
                agent_instance_id: request.agent_instance_id.clone(),
                task_id: request.task_id.clone(),
                step_id: request.step_id.clone(),
                action_hash: request.action_hash.clone(),
                policy_decision_id: request.policy_decision_id.clone(),
                tool_id: request.tool_id.clone(),
                credential_profile: request.credential_profile.clone(),
                operation: request.operation.clone(),
                resource: request.resource.clone(),
                target_profile: request.target_profile.clone(),
                audience: request.audience.clone(),
                revocation_epoch: request.revocation_epoch,
                issued_at: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::seconds(30),
                max_uses: request.max_uses,
            },
            claims_digest: String::new(),
            issuer: "credential-authority".into(),
            key_id: "credential-key-1".into(),
            key_usage: WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE.into(),
            signature: String::new(),
        };
        assert!(request.validate().is_ok());
        assert!(receipt.sign(&signing).is_ok());
        assert!(
            receipt
                .verify(&signing.verifying_key(), &request, secret_handle, now)
                .is_ok()
        );
        let signature = receipt.signature.clone();
        let receipt_debug = format!("{receipt:?}");
        assert!(!receipt_debug.contains(secret_handle));
        assert!(!receipt_debug.contains(&signature));
        let issuance = WorkloadCredentialIssuance {
            workload_credential: secret_handle.to_string(),
            binding_receipt: receipt.clone(),
        };
        assert!(!format!("{issuance:?}").contains(secret_handle));

        let authorization = sample_execution_authorization(now);
        let envelope = PepPreExecutionAuthorization {
            schema_version: PEP_PRE_EXECUTION_AUTHORIZATION_SCHEMA_VERSION.into(),
            authorization,
            tool: (),
            workload_credential: secret_handle.to_string(),
            credential_binding_receipt: receipt.clone(),
            target_profile: request.target_profile.clone(),
            approval: None,
        };
        assert!(!format!("{envelope:?}").contains(secret_handle));

        let consumption_request = WorkloadCredentialConsumptionRequest {
            schema_version: WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION.into(),
            idempotency_key: IdempotencyKey("consume:execution-1".into()),
            credential_handle: secret_handle.into(),
            binding_receipt: receipt.clone(),
            tenant_id: request.tenant_id.clone(),
            agent_instance_id: request.agent_instance_id.clone(),
            task_id: request.task_id.clone(),
            step_id: request.step_id.clone(),
            action_hash: request.action_hash.clone(),
            policy_decision_id: request.policy_decision_id.clone(),
            tool_id: request.tool_id.clone(),
            credential_profile: request.credential_profile.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            target_profile: request.target_profile.clone(),
            audience: request.audience.clone(),
            revocation_epoch: request.revocation_epoch,
            claims_digest: receipt.claims_digest.clone(),
        };
        assert!(consumption_request.validate().is_ok());
        assert!(!format!("{consumption_request:?}").contains(secret_handle));
        let mut consumption_receipt = SignedWorkloadCredentialConsumptionReceipt {
            schema_version: WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION.into(),
            idempotency_key: consumption_request.idempotency_key.clone(),
            consumption_id: Uuid::new_v4().to_string(),
            credential_id: receipt.claims.credential_id.clone(),
            tenant_id: request.tenant_id.clone(),
            action_hash: request.action_hash.clone(),
            audience: request.audience.clone(),
            revocation_epoch: request.revocation_epoch,
            claims_digest: receipt.claims_digest.clone(),
            scope_digest: String::new(),
            consumed_at: now,
            remaining_uses: 0,
            issuer: "credential-authority".into(),
            key_id: "credential-key-1".into(),
            key_usage: WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE.into(),
            signature: String::new(),
        };
        assert!(
            consumption_receipt
                .sign(&signing, &consumption_request)
                .is_ok()
        );
        assert!(
            consumption_receipt
                .verify(&signing.verifying_key(), &consumption_request, now)
                .is_ok()
        );
        let consumption_signature = consumption_receipt.signature.clone();
        assert!(!format!("{consumption_receipt:?}").contains(&consumption_signature));

        receipt.claims.audience = "wrong-audience".into();
        assert_eq!(
            receipt.verify(&signing.verifying_key(), &request, secret_handle, now),
            Err(ContractError::ScopeExceeded)
        );
    }

    #[test]
    fn human_principal_assertion_is_request_bound_and_fail_closed() {
        let now = Utc::now();
        let tenant = TenantId::new();
        let body = serde_json::json!({
            "schema_version": "agenttrust.enterprise-mutation.v1",
            "operation": "UPDATE_QUOTA",
            "project_id": "project-7",
            "approval_ids": ["approval-1", "approval-2"]
        });
        let request_digest = human_principal_request_digest(
            "POST",
            "/v1/enterprise/actions",
            &tenant,
            "URI:spiffe://agenttrust/enterprise-bff",
            "enterprise-bff",
            "enterprise:mutate",
            "mutation:01900000-0000-7000-8000-000000000008",
            &body,
        )
        .unwrap_or_else(|_| panic!("request digest"));
        let signing = SigningKey::from_bytes(&[91u8; 32]);
        let mut assertion = SignedHumanPrincipalAssertion {
            schema_version: HUMAN_PRINCIPAL_ASSERTION_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            subject: "human@example.test".into(),
            roles: BTreeSet::from(["quota-manager".into(), "tenant-admin".into()]),
            project_ids: BTreeSet::from(["project-7".into()]),
            approval_ids: BTreeSet::from(["approval-1".into(), "approval-2".into()]),
            owned_resources: BTreeSet::from(["tenant:current".into()]),
            strong_auth: true,
            authentication_time: now - chrono::Duration::seconds(5),
            authentication_context: "urn:agenttrust:acr:mfa".into(),
            issuer: "enterprise-idp".into(),
            audience: "agenttrust-governance".into(),
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(4),
            jti: Uuid::new_v4().to_string(),
            request_digest: request_digest.clone(),
            client_identity: "URI:spiffe://agenttrust/enterprise-bff".into(),
            service_subject: "enterprise-bff".into(),
            scope: "enterprise:mutate".into(),
            key_id: "human-assertion-key-1".into(),
            key_usage: HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE.into(),
            signature: String::new(),
        };
        assertion.signature = URL_SAFE_NO_PAD.encode(
            signing
                .sign(
                    &assertion
                        .signing_bytes()
                        .unwrap_or_else(|_| panic!("signing bytes")),
                )
                .to_bytes(),
        );
        assert!(
            assertion
                .verify(
                    &signing.verifying_key(),
                    &tenant,
                    "URI:spiffe://agenttrust/enterprise-bff",
                    "enterprise-bff",
                    "enterprise:mutate",
                    &request_digest,
                    "enterprise-idp",
                    "agenttrust-governance",
                    true,
                    900,
                    now,
                )
                .is_ok()
        );

        let keyring_bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": HUMAN_PRINCIPAL_KEYRING_SCHEMA_VERSION,
            "audience": "agenttrust-governance",
            "keys": [{
                "issuer": "enterprise-idp",
                "key_id": "human-assertion-key-1",
                "algorithm": "Ed25519",
                "usage": HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE,
                "status": "ACTIVE",
                "public_key": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                "tenant_ids": [tenant.0.clone()],
                "not_before": now - chrono::Duration::hours(1),
                "expires_at": now + chrono::Duration::hours(1)
            }]
        }))
        .unwrap_or_else(|_| panic!("keyring JSON"));
        let keyring =
            HumanPrincipalKeyring::from_json(&keyring_bytes, "agenttrust-governance", now)
                .unwrap_or_else(|_| panic!("keyring"));
        let encoded_assertion = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&assertion).unwrap_or_else(|_| panic!("assertion JSON")));
        let verified = keyring
            .verify_encoded(
                &encoded_assertion,
                &tenant,
                "URI:spiffe://agenttrust/enterprise-bff",
                "enterprise-bff",
                "enterprise:mutate",
                &request_digest,
                true,
                900,
                now,
            )
            .unwrap_or_else(|_| panic!("verified principal"));
        assert_eq!(verified.subject, "human@example.test");
        assert_eq!(
            verified.assertion_digest,
            assertion.assertion_digest().unwrap_or_default()
        );

        assertion.approval_ids.insert("approval-untrusted".into());
        assert_eq!(
            assertion.verify(
                &signing.verifying_key(),
                &tenant,
                "URI:spiffe://agenttrust/enterprise-bff",
                "enterprise-bff",
                "enterprise:mutate",
                &request_digest,
                "enterprise-idp",
                "agenttrust-governance",
                true,
                900,
                now,
            ),
            Err(ContractError::SignatureInvalid)
        );
    }

    fn sample_execution_authorization(now: DateTime<Utc>) -> ExecutionAuthorization {
        let mut authorization = ExecutionAuthorization {
            schema_version: SchemaVersion(EXECUTION_AUTHORIZATION_SCHEMA_VERSION.into()),
            authorization_id: Uuid::new_v4().to_string(),
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            agent_instance_id: AgentInstanceId::new(),
            action_hash: ActionHash("a".repeat(64)),
            tool_id: ToolId("http.call".into()),
            tool_version: ToolVersion("1.0.0".into()),
            tool_snapshot_hash: "b".repeat(64),
            implementation_digest: format!("sha256:{}", "c".repeat(64)),
            executor_profile: "http".into(),
            operation: "post".into(),
            resource: "api:orders".into(),
            canonical_arguments_hash: "d".repeat(64),
            target_profile: "orders-prod".into(),
            environment: "production".into(),
            idempotency_key: IdempotencyKey("execution-1".into()),
            ledger_execution_id: ExecutionId::new(),
            ledger_event_id: Uuid::new_v4().to_string(),
            ledger_event_digest: "3".repeat(64),
            fence_digest: "e".repeat(64),
            policy_decision_id: "decision-1".into(),
            policy_decision_digest: "4".repeat(64),
            policy_version: PolicyVersion("policy-1".into()),
            policy_bundle_hash: "f".repeat(64),
            policy_input_hash: "0".repeat(64),
            authorization_evidence_ref: String::new(),
            authorization_evidence_digest: String::new(),
            preapproval_digest: "1".repeat(64),
            approval_ids: vec![],
            approval_consumption_ref: None,
            approval_receipt_digest: None,
            resource_version: ResourceVersion("v1".into()),
            sandbox_profile: "default".into(),
            network_profile: "api".into(),
            credential_profile: "target-api".into(),
            workload_credential_id: Uuid::new_v4().to_string(),
            workload_credential_claims_digest: "2".repeat(64),
            workload_credential_audience: "tool-proxy".into(),
            workload_credential_revocation_epoch: 0,
            max_execution_ms: 1_000,
            max_result_bytes: 4_096,
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::seconds(30),
            single_use: true,
            issuer: "pep".into(),
            key_id: "pep-key-1".into(),
            key_usage: PEP_EXECUTION_AUTHORIZATION_KEY_USAGE.into(),
            signature: String::new(),
        };
        authorization
            .bind_evidence()
            .unwrap_or_else(|error| panic!("bind evidence: {error}"));
        authorization
    }
}
