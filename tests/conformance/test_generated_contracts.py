from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "generated" / "python"))

import contracts  # noqa: E402


class GeneratedContractsTest(unittest.TestCase):
    def test_enum_wire_values_are_stable(self) -> None:
        self.assertEqual(contracts.RiskLevel.CRITICAL.value, "CRITICAL")
        self.assertEqual(contracts.Decision.REQUIRE_APPROVAL.value, "REQUIRE_APPROVAL")
        self.assertEqual(contracts.ExecutionStatus.UNKNOWN.value, "UNKNOWN")

    def test_signed_goal_contains_scope_constraints(self) -> None:
        goal = contracts.SignedGoal(
            schema_version="agenttrust.contracts.v1",
            goal_id="goal-1",
            normalized_goal="run tests",
            goal_hash="a" * 64,
            constraints={"network": "none"},
            approved_by="user:1",
            signed_at="2026-08-05T10:00:00Z",
            signer_key_id="key-1",
            signature="signature",
        )
        self.assertEqual(goal.constraints, {"network": "none"})

    def test_plan_and_lease_use_typed_tool_references(self) -> None:
        tool = contracts.ToolRef("coding.test", "1.0.0")
        step = contracts.PlanStep(
            step_id="step-1",
            sequence=1,
            intent="test repository",
            dependencies=[],
            tool=tool,
            resource_scope=["repo:example"],
            risk=contracts.RiskLevel.LOW,
        )
        plan = contracts.PlanManifest(
            schema_version="agenttrust.contracts.v1",
            plan_id="plan-1",
            goal_hash="a" * 64,
            plan_hash="b" * 64,
            steps=[step],
            max_scope=["repo:example"],
            risk_budget=contracts.RiskLevel.LOW,
            cost_budget_microunits=100,
            valid_until="2026-08-05T11:00:00Z",
        )
        self.assertEqual(plan.steps[0].tool, tool)


if __name__ == "__main__":
    unittest.main()
