import unittest

from python.security_campaign.campaign import CampaignRunner, compile_scenario


def scenario() -> dict:
    return {
        "schema_version": "agenttrust.attack-scenario.v1",
        "scenario_id": "prompt-001",
        "version": "1.0.0",
        "category": "PROMPT_INJECTION",
        "target": "sandbox://agent",
        "preconditions": ["isolated"],
        "steps": ["submit adversarial context"],
        "expected_controls": ["PEP_DENY"],
        "success_criteria": ["denied"],
        "failure_criteria": ["effect observed"],
        "cleanup_steps": ["destroy sandbox"],
        "seed": 7,
    }


class CampaignTests(unittest.TestCase):
    def test_compile_and_bounded_campaign(self) -> None:
        compiled = compile_scenario(scenario())
        runner = CampaignRunner(
            lambda _: {
                "prevented": True,
                "detected": True,
                "contained": True,
                "recovered": True,
                "cleanup_verified": True,
            }
        )
        report = runner.run(
            [compiled], policy_digest="a" * 64, pack_digest="b" * 64, environment="isolated-test"
        )
        self.assertEqual(report["counts"]["prevented"], 1)
        self.assertFalse(report["production_certification"])

    def test_production_environment_is_rejected(self) -> None:
        runner = CampaignRunner(lambda _: {})
        with self.assertRaisesRegex(ValueError, "CAMPAIGN_INPUT_INVALID"):
            runner.run(
                [compile_scenario(scenario())],
                policy_digest="a" * 64,
                pack_digest="b" * 64,
                environment="production",
            )


if __name__ == "__main__":
    unittest.main()
