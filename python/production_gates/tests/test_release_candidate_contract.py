from pathlib import Path
import unittest


ROOT = Path(__file__).parents[3]


class ReleaseCandidateContractTests(unittest.TestCase):
    def test_candidate_supply_chain_uses_protected_dedicated_runners(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        runner = (
            "runs-on: [self-hosted, linux, production-candidate, "
            "actions-runner-2-327-1]"
        )

        self.assertEqual(workflow.count(runner), 3)
        self.assertNotIn("runs-on: ubuntu-24.04", workflow)
        self.assertEqual(workflow.count("environment: production-candidate"), 3)
        self.assertIn("cancel-in-progress: false", workflow)

    def test_candidate_verifies_immutable_source_and_runner_tools(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        for variable in (
            "AGENT_TRUST_GH_BINARY",
            "AGENT_TRUST_GH_SHA256",
            "AGENT_TRUST_GIT_BINARY",
            "AGENT_TRUST_GIT_SHA256",
            "AGENT_TRUST_DOCKER_BINARY",
            "AGENT_TRUST_DOCKER_SHA256",
            "AGENT_TRUST_PYTHON_BINARY",
            "AGENT_TRUST_PYTHON_SHA256",
            "AGENT_TRUST_GIT_VERIFICATION_CONFIG_FILE",
            "AGENT_TRUST_CODEOWNERS_SHA256",
        ):
            self.assertIn(variable, workflow)
        self.assertIn(
            "EXPECTED_DISPATCH_REF: refs/heads/${{ github.event.repository.default_branch }}",
            workflow,
        )
        self.assertIn('test "$GITHUB_REF_PROTECTED" = true', workflow)
        self.assertIn('test "$commit_sha" = "$GITHUB_SHA"', workflow)
        self.assertIn('--docker-binary "$AGENT_TRUST_DOCKER_BINARY"', workflow)
        self.assertIn("unix:///var/run/docker.sock", workflow)
        self.assertNotIn("docker/setup-buildx-action", workflow)
        self.assertNotIn("sha256sum", workflow)


if __name__ == "__main__":
    unittest.main()
