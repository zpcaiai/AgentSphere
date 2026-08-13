"""Durable workflow adapter. Security decisions stay in PEP/Rust activities."""

from __future__ import annotations

import argparse
import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
import json
import os
from pathlib import Path
import ssl
from typing import Any, Mapping, Protocol, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request

try:  # Optional locally; mandatory in the production profile.
    from temporalio import activity as _activity
    from temporalio.common import RetryPolicy as _RetryPolicy
    from temporalio import workflow as _workflow
except ImportError:  # pragma: no cover - exercised only when Temporal SDK is installed.
    _activity = None
    _RetryPolicy = None
    _workflow = None


@dataclass(frozen=True)
class TaskCommand:
    schema_version: str
    command_id: str
    tenant_id: str
    task_id: str
    command_type: str
    expected_state_version: int
    payload_digest: str


def validate_command(command: TaskCommand) -> None:
    if (
        command.schema_version != "agenttrust.orchestrator-command.v1"
        or not command.command_id
        or not command.tenant_id
        or not command.task_id
        or command.command_type not in {"START", "PAUSE", "RESUME", "CANCEL", "KILL", "CHECKPOINT"}
        or command.expected_state_version < 0
        or len(command.payload_digest) != 64
        or any(character not in "0123456789abcdef" for character in command.payload_digest)
    ):
        raise ValueError("ORCHESTRATOR_COMMAND_INVALID")


class _TaskWorkflowCore:
    """Deterministic queueing only; transition activity owns authorization and persistence."""

    def __init__(self) -> None:
        self._commands: deque[TaskCommand] = deque(maxlen=1024)
        self._terminal = False

    async def command(self, value: Mapping[str, Any]) -> None:
        command = TaskCommand(**value)
        validate_command(command)
        if len(self._commands) == self._commands.maxlen:
            raise RuntimeError("ORCHESTRATOR_COMMAND_QUEUE_FULL")
        self._commands.append(command)


class TransitionClient(Protocol):
    async def apply(self, initial: Mapping[str, Any], command: TaskCommand) -> Mapping[str, Any]: ...


class TransitionHttpClient:
    """mTLS-capable client for the authoritative Rust transition service."""

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        ca_file: Path | None = None,
        certificate_file: Path | None = None,
        private_key_file: Path | None = None,
        timeout_seconds: float = 10.0,
        maximum_response_bytes: int = 1_048_576,
    ) -> None:
        if (
            not endpoint.startswith("https://")
            or not bearer_token
            or timeout_seconds <= 0
            or not 1024 <= maximum_response_bytes <= 8_388_608
            or (certificate_file is None) != (private_key_file is None)
        ):
            raise ValueError("TRANSITION_CLIENT_CONFIG_INVALID")
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        if certificate_file and private_key_file:
            context.load_cert_chain(str(certificate_file), str(private_key_file))
        self._endpoint = endpoint.rstrip("/")
        self._token = bearer_token
        self._context = context
        self._timeout = timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes

    async def apply(self, initial: Mapping[str, Any], command: TaskCommand) -> Mapping[str, Any]:
        return await asyncio.to_thread(self._apply_sync, initial, command)

    def _apply_sync(self, initial: Mapping[str, Any], command: TaskCommand) -> Mapping[str, Any]:
        validate_command(command)
        body = json.dumps(
            {"schema_version": "agenttrust.transition-request.v1", "current": initial, "command": command.__dict__},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        req = urllib_request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Idempotency-Key": command.command_id,
            },
        )
        try:
            with urllib_request.urlopen(req, timeout=self._timeout, context=self._context) as response:
                raw = response.read(self._maximum_response_bytes + 1)
        except urllib_error.HTTPError as exc:
            if exc.code == 403:
                raise PermissionError("ORCHESTRATOR_TRANSITION_DENIED") from exc
            if exc.code == 409:
                raise RuntimeError("ORCHESTRATOR_TRANSITION_CONFLICT") from exc
            raise ConnectionError("ORCHESTRATOR_TRANSITION_UNAVAILABLE") from exc
        except (urllib_error.URLError, TimeoutError) as exc:
            raise ConnectionError("ORCHESTRATOR_TRANSITION_UNAVAILABLE") from exc
        if len(raw) > self._maximum_response_bytes:
            raise ValueError("ORCHESTRATOR_TRANSITION_RESPONSE_TOO_LARGE")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("ORCHESTRATOR_TRANSITION_RESPONSE_INVALID") from exc
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != "agenttrust.orchestrator-state.v1"
            or value.get("tenant_id") != command.tenant_id
            or value.get("task_id") != command.task_id
            or not isinstance(value.get("recovery_cursor"), int)
            or value["recovery_cursor"] <= command.expected_state_version
            or not isinstance(value.get("terminal"), bool)
            or not isinstance(value.get("evidence_refs"), list)
            or not value["evidence_refs"]
        ):
            raise ValueError("ORCHESTRATOR_TRANSITION_RESPONSE_INVALID")
        return value


class AuthoritativeTransitionActivities:
    def __init__(self, client: TransitionClient) -> None:
        self._client = client

    async def apply_authoritative_transition(
        self, initial: Mapping[str, Any], command: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        value = TaskCommand(**command)
        validate_command(value)
        return await self._client.apply(initial, value)


if _workflow is not None:  # pragma: no cover - requires external Temporal service for evidence.

    AuthoritativeTransitionActivities.apply_authoritative_transition = _activity.defn(
        name="apply_authoritative_transition"
    )(AuthoritativeTransitionActivities.apply_authoritative_transition)

    @_workflow.defn(name="AgentTrustStepWorkflow")
    class StepWorkflow:
        @_workflow.run
        async def run(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
            return await _workflow.execute_activity_method(
                AuthoritativeTransitionActivities.apply_authoritative_transition,
                args=[value["initial"], value["command"]],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=_RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=5,
                    non_retryable_error_types=["PermissionError", "ValueError"],
                ),
            )

    @_workflow.defn(name="AgentTrustTaskWorkflow")
    class TaskWorkflow(_TaskWorkflowCore):
        @_workflow.run
        async def run(self, initial: Mapping[str, Any]) -> Mapping[str, Any]:
            self._current = dict(initial)
            while not self._terminal:
                await _workflow.wait_condition(lambda: bool(self._commands))
                command = self._commands.popleft()
                result = await _workflow.execute_child_workflow(
                    StepWorkflow.run,
                    {"initial": initial, "command": command.__dict__},
                    id=f"{command.task_id}:{command.command_id}",
                )
                self._terminal = bool(result.get("terminal", False))
                initial = result
                self._current = dict(result)
            return initial

        @_workflow.signal(name="command")
        async def command(self, value: Mapping[str, Any]) -> None:
            await super().command(value)

        @_workflow.query(name="state")
        def state(self) -> Mapping[str, Any]:
            return dict(self._current)

else:

    class StepWorkflow:
        """Import-safe local type; production bootstrap refuses a missing SDK."""

    class TaskWorkflow(_TaskWorkflowCore):
        """Import-safe local type; production bootstrap refuses a missing SDK."""


def load_production_config(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        value.get("profile") != "production"
        or value.get("fail_closed") is not True
        or value.get("workflow_engine") != "TEMPORAL"
        or value.get("state_store") != "POSTGRESQL"
        or value.get("dev_in_memory_store") is not False
    ):
        raise ValueError("ORCHESTRATOR_PRODUCTION_CONFIG_INVALID")
    return value


async def run_temporal_worker(
    address: str,
    namespace: str,
    task_queue: str,
    transition_client: TransitionClient,
) -> None:
    if _workflow is None:
        raise RuntimeError("TEMPORAL_SDK_REQUIRED")
    if not address or not namespace or not task_queue:
        raise ValueError("TEMPORAL_WORKER_CONFIG_INVALID")
    from temporalio.client import Client
    from temporalio.worker import Worker

    client = await Client.connect(address, namespace=namespace)
    activities = AuthoritativeTransitionActivities(transition_client)
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[TaskWorkflow, StepWorkflow],
        activities=[activities.apply_authoritative_transition],
        max_concurrent_activities=100,
        max_concurrent_workflow_tasks=1000,
    )
    await worker.run()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-durable-worker")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--temporal-address", default=os.environ.get("AGENT_TRUST_TEMPORAL_ADDRESS", ""))
    parser.add_argument("--namespace", default=os.environ.get("AGENT_TRUST_TEMPORAL_NAMESPACE", ""))
    parser.add_argument("--task-queue", default=os.environ.get("AGENT_TRUST_TEMPORAL_TASK_QUEUE", ""))
    parser.add_argument("--transition-endpoint", default=os.environ.get("AGENT_TRUST_TRANSITION_ENDPOINT", ""))
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--certificate-file", type=Path)
    parser.add_argument("--private-key-file", type=Path)
    args = parser.parse_args(argv)
    load_production_config(args.config)
    client = TransitionHttpClient(
        args.transition_endpoint,
        os.environ.get("AGENT_TRUST_TRANSITION_TOKEN", ""),
        ca_file=args.ca_file,
        certificate_file=args.certificate_file,
        private_key_file=args.private_key_file,
    )
    asyncio.run(run_temporal_worker(args.temporal_address, args.namespace, args.task_queue, client))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
