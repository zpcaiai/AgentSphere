import unittest

from python.energy_planner import ConstraintEnvelope, EnergyPlanner, ForecastPoint


class EnergyPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.constraints = ConstraintEnvelope(-10, 10, 2, 0.2, 0.8, 0.5, 100, 0.25)

    def test_candidate_obeys_power_and_ramp_and_is_shadow_only(self) -> None:
        plan = EnergyPlanner().propose(
            [ForecastPoint(5, 9, 0.9), ForecastPoint(10, 0, 0.9)], self.constraints
        )
        self.assertEqual(plan.setpoints_kw, (2.0, 0.0))
        self.assertTrue(plan.requires_shadow_validation)
        self.assertIsNone(plan.fallback_reason)

    def test_ood_uses_deterministic_safe_fallback(self) -> None:
        plan = EnergyPlanner().propose([ForecastPoint(100, 0, 0.2)], self.constraints)
        self.assertEqual(plan.setpoints_kw, (0.0,))
        self.assertEqual(plan.fallback_reason, "FORECAST_OOD")


if __name__ == "__main__":
    unittest.main()
