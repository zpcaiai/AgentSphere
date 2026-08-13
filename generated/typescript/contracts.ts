// GENERATED from schemas/contract-model.json; source_sha256=90e36f317a4dedf3f38397c419c3975ca2d14dda60664af823301cb68633d097; run ./scripts/generate-contracts.sh

export type TaskStatus = "CREATED" | "PLANNED" | "POLICY_CHECKED" | "APPROVAL_PENDING" | "APPROVED" | "RUNNING" | "PAUSE_REQUESTED" | "PAUSED" | "CANCEL_REQUESTED" | "CANCELLING" | "KILL_REQUESTED" | "KILLED" | "VERIFYING" | "COMPLETED" | "DENIED" | "FAILED" | "EVALUATION_FAILED" | "COMPENSATING" | "ROLLED_BACK" | "NEEDS_HUMAN" | "MANUAL_RECOVERY_REQUIRED";

export type ExecutionStatus = "PREPARED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "TIMED_OUT" | "CANCELLED" | "KILLED" | "COMPENSATING" | "COMPENSATED" | "COMPENSATION_FAILED" | "UNKNOWN";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type EffectClass = "PURE" | "IDEMPOTENT" | "COMPENSATABLE" | "IRREVERSIBLE";

export type Decision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "PAUSE" | "KILL";

export type DataClassification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "REGULATED";

export type EvaluationStatus = "PASS" | "FAIL" | "NEEDS_HUMAN" | "ROLLED_BACK" | "MANUAL_RECOVERY_REQUIRED";

export interface ToolRef {
  readonly tool_id: string;
  readonly tool_version: string;
}

export interface PlanStep {
  readonly step_id: string;
  readonly sequence: number;
  readonly intent: string;
  readonly dependencies: Array<string>;
  readonly tool: ToolRef | null;
  readonly resource_scope: Array<string>;
  readonly risk: RiskLevel;
}

export interface SignedGoal {
  readonly schema_version: string;
  readonly goal_id: string;
  readonly normalized_goal: string;
  readonly goal_hash: string;
  readonly constraints: Readonly<Record<string, string>>;
  readonly approved_by: string;
  readonly signed_at: string;
  readonly signer_key_id: string;
  readonly signature: string;
}

export interface PlanManifest {
  readonly schema_version: string;
  readonly plan_id: string;
  readonly goal_hash: string;
  readonly plan_hash: string;
  readonly steps: Array<PlanStep>;
  readonly max_scope: Array<string>;
  readonly risk_budget: RiskLevel;
  readonly cost_budget_microunits: number;
  readonly valid_until: string;
}

export interface DelegationEnvelope {
  readonly schema_version: string;
  readonly parent_agent: string;
  readonly child_agent: string;
  readonly delegated_tools: Array<ToolRef>;
  readonly delegated_resources: Array<string>;
  readonly budget_ceiling_microunits: number;
  readonly expiry: string;
}

export interface AuthorizationLease {
  readonly schema_version: string;
  readonly lease_id: string;
  readonly task_id: string;
  readonly goal_hash: string;
  readonly plan_hash: string;
  readonly policy_snapshot: string;
  readonly allowed_tools: Array<ToolRef>;
  readonly allowed_resources: Array<string>;
  readonly revocation_epoch: number;
  readonly valid_until: string;
}
