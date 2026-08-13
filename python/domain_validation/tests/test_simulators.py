from pathlib import Path
import unittest

from python.domain_validation import (
    EnergyShadowEvaluator,
    IndustrialDigitalTwin,
    load_dataset,
    run_medical_safety_dataset,
    run_sensitive_dialogue_dataset,
)


ROOT = Path(__file__).resolve().parents[3]


class DomainSimulatorTests(unittest.TestCase):
    def test_industrial_twin_uses_cas_and_never_claims_physical_evidence(self) -> None:
        twin = IndustrialDigitalTwin(minimum=0, maximum=100, value=20)
        receipt = twin.commit({"command_id":"c1","value":40,"expected_value":20,"resource_version":1,"interlock_ok":True,"alarm_active":False,"approval_valid":True})
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertIn("NOT_PHYSICAL", receipt["evidence_scope"])
        stale = twin.commit({"command_id":"c2","value":50,"expected_value":20,"resource_version":1,"interlock_ok":True,"alarm_active":False,"approval_valid":True})
        self.assertEqual(stale["reason_code"], "INDUSTRIAL_STALE_STATE")

    def test_energy_shadow_has_zero_side_effects_and_rejects_bounds(self) -> None:
        report = EnergyShadowEvaluator().evaluate(asset_id="battery-1", telemetry_version="v1", candidate_steps=[{"interval":0,"power_kw":5},{"interval":1,"power_kw":51}], minimum_power_kw=-50, maximum_power_kw=50)
        self.assertEqual(report["decision"], "DENY")
        self.assertEqual(report["side_effect_count"], 0)

    def test_medical_safety_dataset(self) -> None:
        cases = load_dataset(ROOT / "testdata/domain-packs/medical-safety.json", expected_schema="agenttrust.medical-safety-dataset.v1")
        self.assertTrue(run_medical_safety_dataset(cases)["passed"])

    def test_sensitive_long_dialogue_dataset(self) -> None:
        cases = load_dataset(ROOT / "testdata/domain-packs/sensitive-long-dialogue.json", expected_schema="agenttrust.sensitive-dialogue-dataset.v1")
        self.assertTrue(run_sensitive_dialogue_dataset(cases)["passed"])


if __name__ == "__main__":
    unittest.main()
