// GENERATED from schemas/contract-model.json; source_sha256=90e36f317a4dedf3f38397c419c3975ca2d14dda60664af823301cb68633d097; run ./scripts/generate-contracts.sh

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus { Created, Planned, PolicyChecked, ApprovalPending, Approved, Running, PauseRequested, Paused, CancelRequested, Cancelling, KillRequested, Killed, Verifying, Completed, Denied, Failed, EvaluationFailed, Compensating, RolledBack, NeedsHuman, ManualRecoveryRequired }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus { Prepared, Running, Succeeded, Failed, TimedOut, Cancelled, Killed, Compensating, Compensated, CompensationFailed, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel { Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectClass { Pure, Idempotent, Compensatable, Irreversible }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision { Allow, Deny, RequireApproval, Pause, Kill }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification { Public, Internal, Confidential, Restricted, Regulated }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationStatus { Pass, Fail, NeedsHuman, RolledBack, ManualRecoveryRequired }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRef {
    pub tool_id: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub step_id: String,
    pub sequence: u32,
    pub intent: String,
    pub dependencies: Vec<String>,
    pub tool: Option<ToolRef>,
    pub resource_scope: Vec<String>,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGoal {
    pub schema_version: String,
    pub goal_id: String,
    pub normalized_goal: String,
    pub goal_hash: String,
    pub constraints: std::collections::BTreeMap<String, String>,
    pub approved_by: String,
    pub signed_at: String,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanManifest {
    pub schema_version: String,
    pub plan_id: String,
    pub goal_hash: String,
    pub plan_hash: String,
    pub steps: Vec<PlanStep>,
    pub max_scope: Vec<String>,
    pub risk_budget: RiskLevel,
    pub cost_budget_microunits: u64,
    pub valid_until: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationEnvelope {
    pub schema_version: String,
    pub parent_agent: String,
    pub child_agent: String,
    pub delegated_tools: Vec<ToolRef>,
    pub delegated_resources: Vec<String>,
    pub budget_ceiling_microunits: u64,
    pub expiry: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationLease {
    pub schema_version: String,
    pub lease_id: String,
    pub task_id: String,
    pub goal_hash: String,
    pub plan_hash: String,
    pub policy_snapshot: String,
    pub allowed_tools: Vec<ToolRef>,
    pub allowed_resources: Vec<String>,
    pub revocation_epoch: u64,
    pub valid_until: String,
}
