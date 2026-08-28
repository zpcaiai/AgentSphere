from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]


class ProductionDeploymentOrchestrationContractTests(unittest.TestCase):
    def test_workflow_uses_blue_green_materializer_and_external_broker(self) -> None:
        workflow = (ROOT / ".github/workflows/production-release.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/materialize-production-blue-green-stack.py", workflow)
        self.assertIn("scripts/execute-production-deployment.py", workflow)
        self.assertIn("scripts/acquire-github-oidc-token.py", workflow)
        self.assertIn("AGENT_TRUST_DEPLOYMENT_CUTOVER_BROKER_CONFIG_FILE", workflow)
        self.assertIn("AGENT_TRUST_DEPLOYMENT_ENVIRONMENT_REFERENCE", workflow)
        self.assertRegex(workflow, r"signed WRITER_FENCE")
        self.assertRegex(workflow, r"signed CUTOVER")
        self.assertRegex(workflow, r"signed UNFREEZE")

    def test_manifest_contains_orchestration_runtime_and_receipt_schema(self) -> None:
        manifest = (ROOT / "config/production-runtime/release-code-manifest.txt").read_text(encoding="utf-8").splitlines()
        for path in (
            "python/production_gates/blue_green_stack.py",
            "python/production_gates/deployment_cutover_broker.py",
            "python/production_gates/production_deployment.py",
            "scripts/execute-production-deployment.py",
            "schemas/release/production-deployment-receipt.schema.json",
        ):
            self.assertIn(path, manifest)
        self.assertEqual(manifest, sorted(set(manifest)))


if __name__ == "__main__":
    unittest.main()
