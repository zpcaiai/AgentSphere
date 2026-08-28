from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_CONTRACTS = {
    "candidate_environment_variable_names": "release-candidate.yml",
    "evidence_environment_variable_names": "production-evidence-intake.yml",
    "assurance_environment_variable_names": "production-assurance.yml",
    "production_environment_variable_names": "production-release.yml",
}


class ReleaseGovernanceContractTests(unittest.TestCase):
    def test_terraform_environment_variables_exactly_match_workflows(self) -> None:
        terraform = (
            ROOT
            / "infra/terraform/github-release-governance/environment_variables.tf"
        ).read_text(encoding="utf-8")
        for local_name, workflow_name in WORKFLOW_CONTRACTS.items():
            with self.subTest(workflow=workflow_name):
                block = re.search(
                    rf"\b{re.escape(local_name)}\s*=\s*toset\(\[(.*?)\]\)",
                    terraform,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(block)
                declared = set(
                    re.findall(r'"(AGENT_TRUST_[A-Z0-9_]+)"', block.group(1))
                )
                workflow = (ROOT / ".github/workflows" / workflow_name).read_text(
                    encoding="utf-8"
                )
                consumed = set(re.findall(r"\bvars\.([A-Z][A-Z0-9_]+)", workflow))
                self.assertEqual(declared, consumed)

    def test_each_protected_environment_is_managed_fail_closed(self) -> None:
        variables = (
            ROOT / "infra/terraform/github-release-governance/variables.tf"
        ).read_text(encoding="utf-8")
        environment_variables = (
            ROOT
            / "infra/terraform/github-release-governance/environment_variables.tf"
        ).read_text(encoding="utf-8")
        environments = (
            ROOT / "infra/terraform/github-release-governance/main.tf"
        ).read_text(encoding="utf-8")
        for short_name in ("candidate", "evidence", "assurance", "production"):
            with self.subTest(environment=short_name):
                self.assertIn(
                    f'resource "github_actions_environment_variable" "{short_name}"',
                    environment_variables,
                )
                self.assertIn(
                    f'variable "{short_name}_environment_variables"', variables
                )
        for local_name in WORKFLOW_CONTRACTS:
            self.assertIn(
                f"local.{local_name}",
                environments,
            )
        self.assertEqual(environments.count("prevent_self_review = true"), 4)
        self.assertEqual(environments.count("can_admins_bypass   = false"), 4)


if __name__ == "__main__":
    unittest.main()
