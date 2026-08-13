// GENERATED from schemas/contract-model.json; source_sha256=90e36f317a4dedf3f38397c419c3975ca2d14dda60664af823301cb68633d097; run ./scripts/generate-contracts.sh

package com.agenttrust.v1;

public final class Contracts {
  private Contracts() {}
  public enum TaskStatus { CREATED, PLANNED, POLICY_CHECKED, APPROVAL_PENDING, APPROVED, RUNNING, PAUSE_REQUESTED, PAUSED, CANCEL_REQUESTED, CANCELLING, KILL_REQUESTED, KILLED, VERIFYING, COMPLETED, DENIED, FAILED, EVALUATION_FAILED, COMPENSATING, ROLLED_BACK, NEEDS_HUMAN, MANUAL_RECOVERY_REQUIRED }
  public enum ExecutionStatus { PREPARED, RUNNING, SUCCEEDED, FAILED, TIMED_OUT, CANCELLED, KILLED, COMPENSATING, COMPENSATED, COMPENSATION_FAILED, UNKNOWN }
  public enum RiskLevel { LOW, MEDIUM, HIGH, CRITICAL }
  public enum EffectClass { PURE, IDEMPOTENT, COMPENSATABLE, IRREVERSIBLE }
  public enum Decision { ALLOW, DENY, REQUIRE_APPROVAL, PAUSE, KILL }
  public enum DataClassification { PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, REGULATED }
  public enum EvaluationStatus { PASS, FAIL, NEEDS_HUMAN, ROLLED_BACK, MANUAL_RECOVERY_REQUIRED }
  public record ToolRef(String tool_id, String tool_version) {}
  public record PlanStep(String step_id, int sequence, String intent, java.util.List<String> dependencies, java.util.Optional<ToolRef> tool, java.util.List<String> resource_scope, RiskLevel risk) {}
  public record SignedGoal(String schema_version, String goal_id, String normalized_goal, String goal_hash, java.util.Map<String, String> constraints, String approved_by, String signed_at, String signer_key_id, String signature) {}
  public record PlanManifest(String schema_version, String plan_id, String goal_hash, String plan_hash, java.util.List<PlanStep> steps, java.util.List<String> max_scope, RiskLevel risk_budget, long cost_budget_microunits, String valid_until) {}
  public record DelegationEnvelope(String schema_version, String parent_agent, String child_agent, java.util.List<ToolRef> delegated_tools, java.util.List<String> delegated_resources, long budget_ceiling_microunits, String expiry) {}
  public record AuthorizationLease(String schema_version, String lease_id, String task_id, String goal_hash, String plan_hash, String policy_snapshot, java.util.List<ToolRef> allowed_tools, java.util.List<String> allowed_resources, long revocation_epoch, String valid_until) {}
}
