import type {
  Decision,
  PlanManifest,
  RiskLevel,
  SignedGoal,
  ToolRef,
} from "../../generated/typescript/contracts";

const tool: ToolRef = { tool_id: "coding.test", tool_version: "1.0.0" };
const risk: RiskLevel = "LOW";
const decision: Decision = "REQUIRE_APPROVAL";
const goal: SignedGoal = {
  schema_version: "agenttrust.contracts.v1",
  goal_id: "goal-1",
  normalized_goal: "run tests",
  goal_hash: "a".repeat(64),
  constraints: { network: "none" },
  approved_by: "user:1",
  signed_at: "2026-08-05T10:00:00Z",
  signer_key_id: "key-1",
  signature: "signature",
};
const plan: PlanManifest = {
  schema_version: "agenttrust.contracts.v1",
  plan_id: "plan-1",
  goal_hash: goal.goal_hash,
  plan_hash: "b".repeat(64),
  steps: [{
    step_id: "step-1",
    sequence: 1,
    intent: "run tests",
    dependencies: [],
    tool,
    resource_scope: ["repo:example"],
    risk,
  }],
  max_scope: ["repo:example"],
  risk_budget: risk,
  cost_budget_microunits: 100,
  valid_until: "2026-08-05T11:00:00Z",
};

if (plan.steps[0]?.tool?.tool_id !== "coding.test" || decision !== "REQUIRE_APPROVAL") {
  throw new Error("generated TypeScript contracts are inconsistent");
}
