from pathlib import Path
import tempfile
import unittest

from python.security_campaign.api import CampaignRepository, CampaignWorker
from python.security_campaign.tests.test_campaign import scenario


class CampaignApiTests(unittest.TestCase):
    def test_persistent_campaign_idempotency_and_worker(self):
        with tempfile.TemporaryDirectory() as raw:
            repository = CampaignRepository(Path(raw) / "campaigns.sqlite3")
            repository.register_scenario(scenario())
            first = repository.create_campaign(scenario_ids=["prompt-001"], policy_digest="a" * 64,
                pack_digest="b" * 64, environment="isolated-test", idempotency_key="idempotency-key-0001")
            second = repository.create_campaign(scenario_ids=["prompt-001"], policy_digest="a" * 64,
                pack_digest="b" * 64, environment="isolated-test", idempotency_key="idempotency-key-0001")
            self.assertEqual(first, second)
            worker = CampaignWorker(repository, lambda _: {"prevented":True,"detected":True,
                "contained":True,"recovered":True,"cleanup_verified":True})
            self.assertTrue(worker.run_once())
            state = repository.get(first)
            self.assertEqual(state["status"], "COMPLETED")
            self.assertFalse(state["report"]["production_certification"])

    def test_idempotency_payload_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            repository = CampaignRepository(Path(raw) / "campaigns.sqlite3")
            repository.register_scenario(scenario())
            repository.create_campaign(scenario_ids=["prompt-001"], policy_digest="a" * 64,
                pack_digest="b" * 64, environment="sandbox", idempotency_key="idempotency-key-0002")
            with self.assertRaisesRegex(ValueError, "CAMPAIGN_IDEMPOTENCY_CONFLICT"):
                repository.create_campaign(scenario_ids=["prompt-001"], policy_digest="c" * 64,
                    pack_digest="b" * 64, environment="sandbox", idempotency_key="idempotency-key-0002")


if __name__ == "__main__":
    unittest.main()
