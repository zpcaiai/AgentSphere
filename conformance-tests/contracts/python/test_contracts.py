import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "generated/python"))
from contracts import RiskLevel, SignedGoal, TaskStatus  # noqa: E402


class ContractTests(unittest.TestCase):
    def test_enum_fails_closed_on_unknown(self):
        with self.assertRaises(ValueError):
            RiskLevel("UNKNOWN")

    def test_generated_record_is_immutable(self):
        goal = SignedGoal("v1", "g", "goal", "hash", "user", "2026-01-01T00:00:00Z", "kid", "sig")
        with self.assertRaises((AttributeError, TypeError)):
            goal.goal_hash = "changed"

    def test_task_completed_is_distinct(self):
        self.assertNotEqual(TaskStatus.COMPLETED, TaskStatus.RUNNING)


if __name__ == "__main__":
    unittest.main()

