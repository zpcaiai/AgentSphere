from pathlib import Path
import unittest

from python.durable_worker.worker import (
    AuthoritativeTransitionActivities,
    TaskCommand,
    TransitionHttpClient,
    load_production_config,
    validate_command,
)


class DurableWorkerTests(unittest.TestCase):
    def test_command_and_production_config(self) -> None:
        validate_command(TaskCommand(
            "agenttrust.orchestrator-command.v1", "cmd:1", "tenant:1", "task:1", "PAUSE", 2, "a" * 64
        ))
        root = Path(__file__).resolve().parents[3]
        config = load_production_config(root / "config/orchestrator/worker.production.json")
        self.assertEqual(config["workflow_engine"], "TEMPORAL")

    def test_unknown_command_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ORCHESTRATOR_COMMAND_INVALID"):
            validate_command(TaskCommand(
                "agenttrust.orchestrator-command.v1", "cmd:1", "tenant:1", "task:1", "SKIP_AUTH", 0, "a" * 64
            ))

    def test_production_transition_client_requires_https_and_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "TRANSITION_CLIENT_CONFIG_INVALID"):
            TransitionHttpClient("http://localhost/transition", "token")
        with self.assertRaisesRegex(ValueError, "TRANSITION_CLIENT_CONFIG_INVALID"):
            TransitionHttpClient("https://control.example/transition", "")

    def test_activity_boundary_is_concrete(self) -> None:
        class Client:
            async def apply(self, initial, command):
                return {**initial, "command_id": command.command_id}

        activity = AuthoritativeTransitionActivities(Client())
        self.assertIsNotNone(activity)


if __name__ == "__main__":
    unittest.main()
