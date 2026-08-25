import asyncio
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone
import unittest
import uuid
from urllib import request as urllib_request

from python.durable_worker.worker import (
    AuthoritativeTransitionActivities,
    AuthoritativeExecutionActivities,
    _TaskWorkflowCore,
    StepWorkflow,
    TaskCommand,
    TaskWorkflow,
    TransitionRejected,
    _no_redirect_handler,
    _secure_file,
    command_fingerprint,
    command_payload_digest,
    execution_followup_command,
    execution_reference,
    TransitionHttpClient,
    load_production_config,
    validate_command,
)

try:
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker
    _TEMPORAL_TESTING_AVAILABLE = True
except ImportError:
    WorkflowEnvironment = Worker = None
    _TEMPORAL_TESTING_AVAILABLE = False


class DurableWorkerTests(unittest.TestCase):
    def test_command_and_production_config(self) -> None:
        validate_command(TaskCommand(
            "agenttrust.orchestrator-command.v1", "cmd:1", "request:1", "tenant:1", "task:1", "PAUSE", 2,
            command_payload_digest("PAUSE"), "user:1", datetime.now(timezone.utc).isoformat()
        ))
        root = Path(__file__).resolve().parents[3]
        config = load_production_config(root / "config/orchestrator/worker.production.json")
        self.assertEqual(config["workflow_engine"], "TEMPORAL")

    def test_unknown_command_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ORCHESTRATOR_COMMAND_INVALID"):
            validate_command(TaskCommand(
                "agenttrust.orchestrator-command.v1", "cmd:1", "request:1", "tenant:1", "task:1", "SKIP_AUTH", 0,
                "a" * 64, "user:1", datetime.now(timezone.utc).isoformat()
            ))

    def test_production_transition_client_requires_https_and_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "TRANSITION_CLIENT_CONFIG_INVALID"):
            TransitionHttpClient("http://localhost/transition", "token")
        with self.assertRaisesRegex(ValueError, "TRANSITION_CLIENT_CONFIG_INVALID"):
            TransitionHttpClient("https://control.example/transition", "")

    def test_http_clients_do_not_follow_redirects(self) -> None:
        request = urllib_request.Request("https://control.example/v1/transitions/apply")
        self.assertIsNone(
            _no_redirect_handler().redirect_request(
                request,
                None,
                307,
                "Temporary Redirect",
                {},
                "https://untrusted.example/v1/transitions/apply",
            )
        )

    def test_activity_boundary_is_concrete(self) -> None:
        class Client:
            async def apply(self, initial, command):
                return {**initial, "command_id": command.command_id}

        activity = AuthoritativeTransitionActivities(Client())
        self.assertIsNotNone(activity)

    def test_execution_reference_is_stable_and_contains_no_action_payload(self) -> None:
        state = {
            "tenant_id": "tenant:1", "task_id": "task:1", "action_id": "action:1",
            "ingress_digest": "a" * 64, "payload": {"secret": "must-not-cross"},
            "action_materialization": {
                "schema_version": "agenttrust.action-materialization-ref.v1",
                "tenant_id": "tenant:1", "action_id": "action:1",
                "payload_hash": "b" * 64, "store": "ORCHESTRATOR_INGRESS_POSTGRESQL",
                "uri": "orchestrator-ingress://tenant:1/action:1",
            },
        }
        first = execution_reference(state)
        self.assertEqual(first, execution_reference(state))
        self.assertNotIn("payload", first)
        self.assertTrue(first["idempotency_key"].startswith("execute:"))

    def test_execution_terminal_statuses_map_to_authoritative_followups(self) -> None:
        self.assertEqual(execution_followup_command("SUCCEEDED"), "VERIFY")
        self.assertEqual(execution_followup_command("KILLED"), "KILL")
        self.assertEqual(execution_followup_command("COMPENSATED"), "NEEDS_HUMAN")
        self.assertIsNone(execution_followup_command("COMPENSATING"))


class DurableWorkflowQueueTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_signal_is_idempotent_and_conflict_is_rejected(self) -> None:
        workflow = _TaskWorkflowCore()
        value = {
            "schema_version": "agenttrust.orchestrator-command.v1",
            "command_id": "cmd:1",
            "request_idempotency_key": "request:1",
            "tenant_id": "tenant:1",
            "task_id": "task:1",
            "command_type": "PAUSE",
            "expected_state_version": 2,
            "payload_digest": command_payload_digest("PAUSE"),
            "requested_by": "user:1",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        await workflow.command(value)
        await workflow.command(value)
        self.assertEqual(len(workflow._commands), 1)
        with self.assertRaisesRegex(RuntimeError, "IDEMPOTENCY_CONFLICT"):
            await workflow.command({
                **value,
                "command_type": "KILL",
                "payload_digest": command_payload_digest("KILL"),
            })

    async def test_denied_command_is_recorded_without_terminating_later_control(self) -> None:
        class DeniedClient:
            async def apply(self, initial, command):
                raise TransitionRejected("ORCHESTRATOR_AUTHORITATIVE_FACT_DENIED")

        value = {
            "schema_version": "agenttrust.orchestrator-command.v1",
            "command_id": "pause:denied",
            "request_idempotency_key": "request:denied",
            "tenant_id": "tenant:1",
            "task_id": "task:1",
            "command_type": "PAUSE",
            "expected_state_version": 2,
            "payload_digest": command_payload_digest("PAUSE"),
            "requested_by": "user:1",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        activity = AuthoritativeTransitionActivities(DeniedClient())
        outcome = await activity.apply_authoritative_transition({}, value)
        self.assertFalse(outcome["accepted"])
        workflow = _TaskWorkflowCore()
        command = TaskCommand(**value)
        workflow.record_rejection(
            command, outcome["error_code"], datetime.now(timezone.utc)
        )
        await workflow.command({
            **value,
            "command_id": "kill:later",
            "request_idempotency_key": "request:later",
            "command_type": "KILL",
            "payload_digest": command_payload_digest("KILL"),
        })
        self.assertFalse(workflow._terminal)
        self.assertEqual(len(workflow._commands), 1)
        self.assertEqual(
            workflow.state_view({"status": "RUNNING"})["command_rejections"][0]["error_code"],
            "ORCHESTRATOR_AUTHORITATIVE_FACT_DENIED",
        )

    async def test_future_rejection_capacity_reserves_emergency_kill(self) -> None:
        workflow = _TaskWorkflowCore()
        now = datetime.now(timezone.utc).isoformat()
        for index in range(1023):
            command_type = "CHECKPOINT"
            await workflow.command({
                "schema_version": "agenttrust.orchestrator-command.v1",
                "command_id": f"checkpoint:{index}",
                "request_idempotency_key": f"checkpoint:{index}",
                "tenant_id": "tenant:1", "task_id": "task:1",
                "command_type": command_type, "expected_state_version": index,
                "payload_digest": command_payload_digest(command_type),
                "requested_by": "user:1", "requested_at": now,
            })
        with self.assertRaisesRegex(RuntimeError, "REJECTION_HISTORY_SATURATED"):
            await workflow.command({
                "schema_version": "agenttrust.orchestrator-command.v1",
                "command_id": "pause:overflow", "request_idempotency_key": "pause:overflow",
                "tenant_id": "tenant:1", "task_id": "task:1", "command_type": "PAUSE",
                "expected_state_version": 0, "payload_digest": command_payload_digest("PAUSE"),
                "requested_by": "user:1", "requested_at": now,
            })
        await workflow.command({
            "schema_version": "agenttrust.orchestrator-command.v1",
            "command_id": "kill:reserved", "request_idempotency_key": "kill:reserved",
            "tenant_id": "tenant:1", "task_id": "task:1", "command_type": "KILL",
            "expected_state_version": 0, "payload_digest": command_payload_digest("KILL"),
            "requested_by": "user:1", "requested_at": now,
        })
        self.assertEqual(workflow._commands[0].command_id, "kill:reserved")


@unittest.skipUnless(os.name == "posix", "POSIX permission contract")
class SecureFileTests(unittest.TestCase):
    def test_private_file_accepts_csi_group_read_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "secret"
            private.write_text("secret", encoding="utf-8")
            private.chmod(0o440)
            self.assertTrue(_secure_file(private, private=True))
            link = Path(directory) / "link"
            link.symlink_to(private)
            self.assertFalse(_secure_file(link, private=True))


@unittest.skipUnless(_TEMPORAL_TESTING_AVAILABLE, "Temporal SDK testing runtime is unavailable")
class TemporalWorkflowE2ETests(unittest.IsolatedAsyncioTestCase):
    async def test_denied_command_does_not_terminate_real_temporal_workflow(self) -> None:
        class ControlledTransitionClient:
            async def apply(self, initial, command):
                if command.command_type == "PAUSE":
                    raise TransitionRejected("ORCHESTRATOR_AUTHORITATIVE_FACT_DENIED")
                target = {"START": "RUNNING", "KILL": "KILLED"}[command.command_type]
                fingerprint = command_fingerprint(command)
                cursor = initial["recovery_cursor"] + 1
                return {
                    **initial,
                    "status": target,
                    "recovery_cursor": cursor,
                    "terminal": target == "KILLED",
                    "evidence_refs": [*initial.get("evidence_refs", []), f"evidence:{cursor}"],
                    "processed_commands": [*initial.get("processed_commands", []), command.command_id],
                    "processed_command_fingerprints": {
                        **initial.get("processed_command_fingerprints", {}),
                        command.command_id: fingerprint,
                    },
                    "processed_idempotency_keys": {
                        **initial.get("processed_idempotency_keys", {}),
                        command.request_idempotency_key: fingerprint,
                    },
                    "events": [
                        *initial.get("events", []),
                        {
                            "event_id": f"transition:{cursor}",
                            "command_id": command.command_id,
                            "from": initial["status"],
                            "to": target,
                            "recovery_cursor": cursor,
                            "evidence_digest": "a" * 64,
                        },
                    ],
                }

        class RunningExecutionClient:
            async def execute(self, reference):
                return {
                    **reference,
                    "schema_version": "agenttrust.execution-outcome.v1",
                    "ledger_execution_id": "execution:test",
                    "fence_digest": "b" * 64,
                    "status": "RUNNING",
                    "outcome_digest": "c" * 64,
                    "evidence_refs": ["evidence:running"],
                }

        task_id = str(uuid.uuid4())
        tenant_id = str(uuid.uuid4())
        initial_action_id = str(uuid.uuid4())
        initial = {
            "schema_version": "agenttrust.orchestrator-state.v1",
            "tenant_id": tenant_id,
            "task_id": task_id,
            "action_id": initial_action_id,
            "status": "CREATED",
            "recovery_cursor": 0,
            "terminal": False,
            "evidence_refs": [],
            "ingress_digest": "a" * 64,
            "has_side_effects": True,
            "action_materialization": {
                "schema_version": "agenttrust.action-materialization-ref.v1",
                "tenant_id": tenant_id, "action_id": initial_action_id,
                "payload_hash": "b" * 64, "store": "ORCHESTRATOR_INGRESS_POSTGRESQL",
                "uri": f"orchestrator-ingress://{tenant_id}/{initial_action_id}",
            },
            "processed_commands": [],
            "processed_command_fingerprints": {},
            "processed_idempotency_keys": {},
            "events": [],
        }

        def command(kind: str, cursor: int) -> dict:
            command_id = f"{kind.lower()}:{cursor}"
            return {
                "schema_version": "agenttrust.orchestrator-command.v1",
                "command_id": command_id,
                "request_idempotency_key": command_id,
                "tenant_id": tenant_id,
                "task_id": task_id,
                "command_type": kind,
                "expected_state_version": cursor,
                "payload_digest": command_payload_digest(kind),
                "requested_by": "integration:test",
                "requested_at": datetime.now(timezone.utc).isoformat(),
            }

        environment = await WorkflowEnvironment.start_time_skipping()
        async with environment:
            activities = AuthoritativeTransitionActivities(ControlledTransitionClient())
            execution_activities = AuthoritativeExecutionActivities(RunningExecutionClient())
            async with Worker(
                environment.client,
                task_queue="durable-orchestrator-e2e",
                workflows=[TaskWorkflow, StepWorkflow],
                activities=[
                    activities.apply_authoritative_transition,
                    execution_activities.execute_authoritative_action,
                ],
            ):
                handle = await environment.client.start_workflow(
                    TaskWorkflow.run,
                    initial,
                    id=task_id,
                    task_queue="durable-orchestrator-e2e",
                    start_signal="command",
                    start_signal_args=[command("START", 0)],
                )

                async def wait_for(predicate):
                    for _ in range(200):
                        state = await handle.query("state")
                        if predicate(state):
                            return state
                        await asyncio.sleep(0.01)
                    self.fail("Temporal workflow state did not reach the expected condition")

                running = await wait_for(lambda state: state["recovery_cursor"] == 1)
                self.assertEqual(running["status"], "RUNNING")
                await handle.signal("command", command("PAUSE", 1))
                rejected = await wait_for(lambda state: bool(state["command_rejections"]))
                self.assertEqual(rejected["status"], "RUNNING")
                self.assertEqual(rejected["recovery_cursor"], 1)
                self.assertEqual(
                    rejected["command_rejections"][0]["error_code"],
                    "ORCHESTRATOR_AUTHORITATIVE_FACT_DENIED",
                )
                await handle.signal("command", command("KILL", 1))
                result = await handle.result()
                self.assertEqual(result["status"], "KILLED")
                self.assertTrue(result["terminal"])
                self.assertEqual(result["recovery_cursor"], 2)


if __name__ == "__main__":
    unittest.main()
