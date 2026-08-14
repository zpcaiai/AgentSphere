"""Durable workflow adapter. Security decisions stay in PEP/Rust activities."""

from __future__ import annotations

import argparse
import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat
from typing import Any, Mapping, Protocol, Sequence
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

try:  # Optional locally; mandatory in the production profile.
    from temporalio import activity as _activity
    from temporalio.common import RetryPolicy as _RetryPolicy
    from temporalio.exceptions import ApplicationError as _ApplicationError
    from temporalio import workflow as _workflow
except ImportError:  # pragma: no cover - exercised only when Temporal SDK is installed.
    _activity = None
    _RetryPolicy = None
    _ApplicationError = None
    _workflow = None


@dataclass(frozen=True)
class TaskCommand:
    schema_version: str
    command_id: str
    request_idempotency_key: str
    tenant_id: str
    task_id: str
    command_type: str
    expected_state_version: int
    payload_digest: str
    requested_by: str
    requested_at: str


def validate_command(command: TaskCommand, *, now: datetime | None = None) -> None:
    if (
        command.schema_version != "agenttrust.orchestrator-command.v1"
        or not command.command_id
        or not command.request_idempotency_key
        or len(command.command_id) > 256
        or len(command.request_idempotency_key) > 256
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
               for character in command.command_id)
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
               for character in command.request_idempotency_key)
        or not command.tenant_id
        or not command.task_id
        or command.command_type not in {
            "START", "PAUSE", "RESUME", "CANCEL", "KILL", "CHECKPOINT", "VERIFY",
            "COMPLETE", "NEEDS_HUMAN",
        }
        or command.expected_state_version < 0
        or len(command.payload_digest) != 64
        or any(character not in "0123456789abcdef" for character in command.payload_digest)
        or command.payload_digest != command_payload_digest(command.command_type)
        or not command.requested_by
        or len(command.requested_by) > 512
    ):
        raise ValueError("ORCHESTRATOR_COMMAND_INVALID")
    try:
        requested_at = datetime.fromisoformat(command.requested_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("ORCHESTRATOR_COMMAND_INVALID") from exc
    current_time = now or datetime.now(timezone.utc)
    if requested_at.tzinfo is None or requested_at > current_time + timedelta(minutes=5):
        raise ValueError("ORCHESTRATOR_COMMAND_INVALID")


class _TaskWorkflowCore:
    """Deterministic queueing only; transition activity owns authorization and persistence."""

    def __init__(self) -> None:
        self._commands: deque[TaskCommand] = deque(maxlen=1024)
        self._queued_commands: dict[str, TaskCommand] = {}
        self._queued_idempotency_keys: dict[str, str] = {}
        self._rejected_command_fingerprints: dict[str, str] = {}
        self._rejected_idempotency_keys: dict[str, str] = {}
        self._command_rejections: deque[dict[str, Any]] = deque(maxlen=1024)
        self._terminal = False

    async def command(self, value: Mapping[str, Any], *, now: datetime | None = None) -> None:
        command = TaskCommand(**value)
        validate_command(command, now=now)
        fingerprint = command_fingerprint(command)
        existing = self._queued_commands.get(command.command_id)
        if existing is not None:
            if command_fingerprint(existing) != fingerprint:
                raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
            return
        existing = self._queued_idempotency_keys.get(command.request_idempotency_key)
        if existing is not None:
            if existing != fingerprint:
                raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
            return
        existing = self._rejected_command_fingerprints.get(command.command_id)
        if existing is not None:
            if existing != fingerprint:
                raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
            raise RuntimeError("ORCHESTRATOR_COMMAND_PREVIOUSLY_REJECTED")
        existing = self._rejected_idempotency_keys.get(command.request_idempotency_key)
        if existing is not None:
            if existing != fingerprint:
                raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
            raise RuntimeError("ORCHESTRATOR_COMMAND_PREVIOUSLY_REJECTED")
        # Every queued command can still become a durable rejection. Bound that future state,
        # not only the already-rejected maps, and reserve the final slot for emergency KILL.
        rejection_capacity = (
            len(self._rejected_command_fingerprints) + len(self._queued_commands)
        )
        if rejection_capacity >= 1023:
            if command.command_type != "KILL" or rejection_capacity >= 1024:
                raise RuntimeError("ORCHESTRATOR_REJECTION_HISTORY_SATURATED")
        if len(self._commands) == self._commands.maxlen:
            if command.command_type != "KILL":
                raise RuntimeError("ORCHESTRATOR_COMMAND_QUEUE_FULL")
            # Emergency containment must remain admissible under command pressure. Evict the
            # oldest non-KILL command with an explicit durable rejection, then prioritize KILL.
            evicted = next(
                (candidate for candidate in self._commands if candidate.command_type != "KILL"),
                None,
            )
            if evicted is None:
                raise RuntimeError("ORCHESTRATOR_COMMAND_QUEUE_FULL")
            self._commands.remove(evicted)
            self._queued_commands.pop(evicted.command_id, None)
            self._queued_idempotency_keys.pop(evicted.request_idempotency_key, None)
            self.record_rejection(
                evicted,
                "ORCHESTRATOR_COMMAND_PREEMPTED_BY_KILL",
                now or datetime.now(timezone.utc),
            )
            self._commands.appendleft(command)
            self._queued_commands[command.command_id] = command
            self._queued_idempotency_keys[command.request_idempotency_key] = fingerprint
            return
        if command.command_type == "KILL":
            self._commands.appendleft(command)
        else:
            self._commands.append(command)
        self._queued_commands[command.command_id] = command
        self._queued_idempotency_keys[command.request_idempotency_key] = fingerprint

    def record_rejection(
        self, command: TaskCommand, error_code: str, rejected_at: datetime
    ) -> None:
        if not error_code.startswith("ORCHESTRATOR_") or len(error_code) > 128:
            error_code = "ORCHESTRATOR_TRANSITION_REJECTED"
        fingerprint = command_fingerprint(command)
        existing_command = self._rejected_command_fingerprints.get(command.command_id)
        existing_request = self._rejected_idempotency_keys.get(
            command.request_idempotency_key
        )
        if any(
            existing is not None and existing != fingerprint
            for existing in (existing_command, existing_request)
        ):
            raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
        if (
            existing_command is None
            and len(self._rejected_command_fingerprints) >= 1024
        ):
            raise RuntimeError("ORCHESTRATOR_REJECTION_HISTORY_INVARIANT_BROKEN")
        if (
            existing_request is None
            and len(self._rejected_idempotency_keys) >= 1024
        ):
            raise RuntimeError("ORCHESTRATOR_REJECTION_HISTORY_INVARIANT_BROKEN")
        self._rejected_command_fingerprints[command.command_id] = fingerprint
        self._rejected_idempotency_keys[command.request_idempotency_key] = fingerprint
        self._command_rejections.append({
            "schema_version": "agenttrust.command-rejection.v1",
            "event_id": hashlib.sha256(
                f"{command.task_id}:{command.command_id}:{error_code}".encode()
            ).hexdigest(),
            "command_id": command.command_id,
            "request_idempotency_key": command.request_idempotency_key,
            "command_type": command.command_type,
            "expected_state_version": command.expected_state_version,
            "error_code": error_code,
            "rejected_at": rejected_at.isoformat(),
        })

    def reject_queued_after_terminal(self, rejected_at: datetime) -> None:
        while self._commands:
            command = self._commands.popleft()
            self._queued_commands.pop(command.command_id, None)
            self._queued_idempotency_keys.pop(command.request_idempotency_key, None)
            self.record_rejection(
                command, "ORCHESTRATOR_TASK_TERMINATED", rejected_at
            )

    def state_view(self, current: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            **current,
            "queued_command_count": len(self._commands),
            "queued_command_ids": [command.command_id for command in self._commands],
            "command_rejections": list(self._command_rejections),
            "rejected_command_fingerprints": dict(self._rejected_command_fingerprints),
            "rejected_idempotency_keys": dict(self._rejected_idempotency_keys),
        }


def command_fingerprint(command: TaskCommand) -> str:
    canonical = {
        "command_id": command.command_id,
        "command_type": command.command_type,
        "expected_state_version": str(command.expected_state_version),
        "payload_digest": command.payload_digest,
        "request_idempotency_key": command.request_idempotency_key,
        "requested_by": command.requested_by,
        "schema_version": command.schema_version,
        "task_id": command.task_id,
        "tenant_id": command.tenant_id,
    }
    return hashlib.sha256(
        json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def command_payload_digest(command_type: str) -> str:
    payload = json.dumps(
        {"command_type": command_type}, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _safe_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ORCHESTRATOR_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def execution_reference(state: Mapping[str, Any]) -> Mapping[str, Any]:
    required = ("tenant_id", "task_id", "action_id", "ingress_digest")
    if any(not isinstance(state.get(field), str) or not state[field] for field in required):
        raise ValueError("ORCHESTRATOR_EXECUTION_REFERENCE_INVALID")
    if not _digest(state["ingress_digest"]):
        raise ValueError("ORCHESTRATOR_EXECUTION_REFERENCE_INVALID")
    materialization = state.get("action_materialization")
    if (
        not isinstance(materialization, dict)
        or materialization.get("schema_version") != "agenttrust.action-materialization-ref.v1"
        or materialization.get("tenant_id") != state["tenant_id"]
        or materialization.get("action_id") != state["action_id"]
        or materialization.get("store") != "ORCHESTRATOR_INGRESS_POSTGRESQL"
        or materialization.get("uri")
            != f"orchestrator-ingress://{state['tenant_id']}/{state['action_id']}"
        or not _digest(materialization.get("payload_hash"))
    ):
        raise ValueError("ORCHESTRATOR_EXECUTION_REFERENCE_INVALID")
    seed = ":".join(str(state[field]) for field in required)
    return {
        "schema_version": "agenttrust.execution-request.v1",
        **{field: state[field] for field in required},
        "idempotency_key": f"execute:{hashlib.sha256(seed.encode()).hexdigest()}",
        "action_materialization": dict(materialization),
    }


def execution_followup_command(status: str) -> str | None:
    if status in {"PREPARED", "RUNNING", "COMPENSATING"}:
        return None
    if status == "SUCCEEDED":
        return "VERIFY"
    if status == "KILLED":
        # A provider-reported kill is not authoritative containment. Route it through KILL so
        # the Rust transition independently requires supervisor acknowledgement and revocation.
        return "KILL"
    if status in {
        "FAILED",
        "TIMED_OUT",
        "CANCELLED",
        "COMPENSATED",
        "COMPENSATION_FAILED",
        "UNKNOWN",
    }:
        return "NEEDS_HUMAN"
    raise ValueError("ORCHESTRATOR_EXECUTION_RESPONSE_INVALID")


class TransitionClient(Protocol):
    async def apply(self, initial: Mapping[str, Any], command: TaskCommand) -> Mapping[str, Any]: ...
    async def ready(self) -> bool: ...


class ExecutionClient(Protocol):
    async def execute(self, reference: Mapping[str, Any]) -> Mapping[str, Any]: ...
    async def ready(self) -> bool: ...


class TransitionRejected(RuntimeError):
    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


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
        parsed = urllib_parse.urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/transitions/apply"
            or not bearer_token
            or timeout_seconds <= 0
            or not 1024 <= maximum_response_bytes <= 8_388_608
            or ca_file is None
            or certificate_file is None
            or private_key_file is None
        or not _secure_file(ca_file, private=False)
        or not _secure_file(certificate_file, private=False)
        or not _secure_file(private_key_file, private=True)
        ):
            raise ValueError("TRANSITION_CLIENT_CONFIG_INVALID")
        context = ssl.create_default_context(cafile=str(ca_file))
        context.load_cert_chain(str(certificate_file), str(private_key_file))
        self._endpoint = endpoint.rstrip("/")
        self._token = bearer_token
        self._opener = urllib_request.build_opener(
            urllib_request.HTTPSHandler(context=context), _NoRedirectHandler()
        )
        self._timeout = timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes

    async def apply(self, initial: Mapping[str, Any], command: TaskCommand) -> Mapping[str, Any]:
        return await asyncio.to_thread(self._apply_sync, initial, command)

    async def ready(self) -> bool:
        return await asyncio.to_thread(self._ready_sync)

    def _ready_sync(self) -> bool:
        parsed = urllib_parse.urlsplit(self._endpoint)
        endpoint = urllib_parse.urlunsplit((parsed.scheme, parsed.netloc, "/ready", "", ""))
        request = urllib_request.Request(endpoint, headers={
            "Accept": "application/json", "Authorization": f"Bearer {self._token}",
        })
        try:
            with self._opener.open(request, timeout=min(self._timeout, 1.0)) as response:
                return _readiness_response(
                    response, "agenttrust.transition-readiness.v1"
                )
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, ValueError):
            return False

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
            with self._opener.open(req, timeout=self._timeout) as response:
                if response.headers.get_content_type() != "application/json":
                    raise ValueError("ORCHESTRATOR_TRANSITION_RESPONSE_INVALID")
                raw = response.read(self._maximum_response_bytes + 1)
        except urllib_error.HTTPError as exc:
            if exc.code in {400, 403, 409, 429}:
                raise TransitionRejected(_http_error_code(exc)) from exc
            raise ConnectionError("ORCHESTRATOR_TRANSITION_UNAVAILABLE") from exc
        except (urllib_error.URLError, TimeoutError) as exc:
            raise ConnectionError("ORCHESTRATOR_TRANSITION_UNAVAILABLE") from exc
        except KeyError as exc:
            raise ValueError("ORCHESTRATOR_TRANSITION_RESPONSE_INVALID") from exc
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
            or value.get("action_id") != initial.get("action_id")
            or value.get("ingress_digest") != initial.get("ingress_digest")
            or value.get("action_materialization") != initial.get("action_materialization")
            or value.get("has_side_effects") != initial.get("has_side_effects")
            or not isinstance(value.get("recovery_cursor"), int)
            or value["recovery_cursor"] != command.expected_state_version + 1
            or not isinstance(value.get("terminal"), bool)
            or not isinstance(value.get("evidence_refs"), list)
            or not value["evidence_refs"]
            or not isinstance(value.get("processed_command_fingerprints"), dict)
            or not isinstance(value.get("processed_idempotency_keys"), dict)
            or command.command_id not in value.get("processed_commands", [])
            or value["processed_command_fingerprints"].get(command.command_id)
                != command_fingerprint(command)
            or value["processed_idempotency_keys"].get(command.request_idempotency_key)
                != command_fingerprint(command)
        ):
            raise ValueError("ORCHESTRATOR_TRANSITION_RESPONSE_INVALID")
        return value


class ExecutionHttpClient:
    """mTLS execution port; canonical Action bytes never enter Temporal history."""

    _STATUSES = {
        "PREPARED", "RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "KILLED",
        "COMPENSATING", "COMPENSATED", "COMPENSATION_FAILED", "UNKNOWN",
    }

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        ca_file: Path,
        certificate_file: Path,
        private_key_file: Path,
        timeout_seconds: float = 30.0,
    ) -> None:
        parsed = urllib_parse.urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/executions/execute"
            or not bearer_token
            or timeout_seconds <= 0
        or not _secure_file(ca_file, private=False)
        or not _secure_file(certificate_file, private=False)
        or not _secure_file(private_key_file, private=True)
        ):
            raise ValueError("EXECUTION_CLIENT_CONFIG_INVALID")
        context = ssl.create_default_context(cafile=str(ca_file))
        context.load_cert_chain(str(certificate_file), str(private_key_file))
        self._endpoint = endpoint
        self._token = bearer_token
        self._timeout = timeout_seconds
        self._opener = urllib_request.build_opener(
            urllib_request.HTTPSHandler(context=context), _NoRedirectHandler()
        )

    async def execute(self, reference: Mapping[str, Any]) -> Mapping[str, Any]:
        return await asyncio.to_thread(self._execute_sync, reference)

    async def ready(self) -> bool:
        return await asyncio.to_thread(self._ready_sync)

    def _ready_sync(self) -> bool:
        parsed = urllib_parse.urlsplit(self._endpoint)
        endpoint = urllib_parse.urlunsplit((parsed.scheme, parsed.netloc, "/ready", "", ""))
        request = urllib_request.Request(endpoint, headers={
            "Accept": "application/json", "Authorization": f"Bearer {self._token}",
        })
        try:
            with self._opener.open(request, timeout=min(self._timeout, 1.0)) as response:
                return _readiness_response(
                    response, "agenttrust.execution-readiness.v1"
                )
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, ValueError):
            return False

    def _execute_sync(self, reference: Mapping[str, Any]) -> Mapping[str, Any]:
        body = json.dumps(reference, sort_keys=True, separators=(",", ":")).encode()
        request = urllib_request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Idempotency-Key": str(reference["idempotency_key"]),
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.headers.get_content_type() != "application/json":
                    raise ValueError("ORCHESTRATOR_EXECUTION_RESPONSE_INVALID")
                raw = response.read(1_048_577)
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError) as error:
            raise ConnectionError("ORCHESTRATOR_EXECUTION_UNAVAILABLE") from error
        if len(raw) > 1_048_576:
            raise ValueError("ORCHESTRATOR_EXECUTION_RESPONSE_INVALID")
        try:
            outcome = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("ORCHESTRATOR_EXECUTION_RESPONSE_INVALID") from error
        expected = {
            "schema_version", "tenant_id", "task_id", "action_id", "ingress_digest",
            "idempotency_key", "ledger_execution_id", "fence_digest", "status",
            "outcome_digest", "evidence_refs", "action_materialization",
        }
        if (
            not isinstance(outcome, dict)
            or set(outcome) != expected
            or outcome.get("schema_version") != "agenttrust.execution-outcome.v1"
            or any(outcome.get(field) != reference.get(field) for field in (
                "tenant_id", "task_id", "action_id", "ingress_digest", "idempotency_key"
            ))
            or outcome.get("action_materialization") != reference.get("action_materialization")
            or outcome.get("status") not in self._STATUSES
            or not _safe_token(outcome.get("ledger_execution_id"))
            or not _digest(outcome.get("fence_digest"))
            or not _digest(outcome.get("outcome_digest"))
            or not isinstance(outcome.get("evidence_refs"), list)
            or not outcome["evidence_refs"]
            or len(outcome["evidence_refs"]) > 1024
            or any(not isinstance(value, str) or not value or len(value) > 2048
                   for value in outcome["evidence_refs"])
        ):
            raise ValueError("ORCHESTRATOR_EXECUTION_RESPONSE_INVALID")
        return outcome


class _NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _readiness_response(response: Any, expected_schema: str) -> bool:
    if (
        response.status != 200
        or response.headers.get_content_type() != "application/json"
    ):
        return False
    raw = response.read(65_537)
    if not raw or len(raw) > 65_536:
        return False
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(value, dict)
        and set(value) == {"schema_version", "ready"}
        and value.get("schema_version") == expected_schema
        and value.get("ready") is True
    )


def _http_error_code(error: urllib_error.HTTPError) -> str:
    try:
        raw = error.read(65_537)
        if len(raw) > 65_536:
            return "ORCHESTRATOR_TRANSITION_REJECTED"
        value = json.loads(raw)
        code = value.get("error") if isinstance(value, dict) else None
        if (
            isinstance(code, str)
            and code.startswith("ORCHESTRATOR_")
            and len(code) <= 128
            and all(character.isupper() or character.isdigit() or character == "_" for character in code)
        ):
            return code
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "ORCHESTRATOR_TRANSITION_REJECTED"


class AuthoritativeTransitionActivities:
    def __init__(self, client: TransitionClient) -> None:
        self._client = client

    async def apply_authoritative_transition(
        self, initial: Mapping[str, Any], command: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        value = TaskCommand(**command)
        validate_command(value)
        try:
            state = await self._client.apply(initial, value)
        except TransitionRejected as error:
            return {"accepted": False, "error_code": error.error_code}
        except ConnectionError as error:
            if _ApplicationError is None:
                raise
            # Preserve retry classification across Temporal serialization. The SDK retry policy
            # now keys on this stable type instead of an implementation-language exception name.
            raise _ApplicationError(
                "ORCHESTRATOR_TRANSITION_UNAVAILABLE",
                type="ORCHESTRATOR_TRANSITION_UNAVAILABLE",
            ) from error
        return {"accepted": True, "state": state}


class AuthoritativeExecutionActivities:
    def __init__(self, client: ExecutionClient) -> None:
        self._client = client

    async def execute_authoritative_action(
        self, reference: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if _activity is not None:
            _activity.heartbeat("execution-dispatch-or-poll")
        try:
            outcome = await self._client.execute(reference)
        except ConnectionError as error:
            if _ApplicationError is None:
                raise
            raise _ApplicationError(
                "ORCHESTRATOR_EXECUTION_UNAVAILABLE",
                type="ORCHESTRATOR_EXECUTION_UNAVAILABLE",
            ) from error
        except (TypeError, ValueError) as error:
            if _ApplicationError is None:
                raise
            raise _ApplicationError(
                "ORCHESTRATOR_EXECUTION_RESPONSE_INVALID",
                type="ORCHESTRATOR_EXECUTION_RESPONSE_INVALID",
                non_retryable=True,
            ) from error
        if _activity is not None:
            _activity.heartbeat(str(outcome.get("status", "UNKNOWN")))
        return outcome


if _workflow is not None:  # pragma: no cover - requires external Temporal service for evidence.

    AuthoritativeTransitionActivities.apply_authoritative_transition = _activity.defn(
        name="apply_authoritative_transition"
    )(AuthoritativeTransitionActivities.apply_authoritative_transition)
    AuthoritativeExecutionActivities.execute_authoritative_action = _activity.defn(
        name="execute_authoritative_action"
    )(AuthoritativeExecutionActivities.execute_authoritative_action)

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
                ),
            )

    @_workflow.defn(name="AgentTrustTaskWorkflow")
    class TaskWorkflow(_TaskWorkflowCore):
        @_workflow.run
        async def run(self, initial: Mapping[str, Any]) -> Mapping[str, Any]:
            self._current = dict(initial)
            self._execution_active = False
            self._execution_observation = None
            while not self._terminal:
                if not self._commands and self._execution_active:
                    try:
                        outcome = await _workflow.execute_activity_method(
                            AuthoritativeExecutionActivities.execute_authoritative_action,
                            execution_reference(self._current),
                            start_to_close_timeout=timedelta(seconds=5),
                            heartbeat_timeout=timedelta(seconds=3),
                            retry_policy=_RetryPolicy(
                                initial_interval=timedelta(milliseconds=250),
                                maximum_interval=timedelta(seconds=1),
                                maximum_attempts=2,
                            ),
                        )
                    except Exception:
                        # Dependency exhaustion is not an authoritative UNKNOWN outcome. Keep
                        # the task controllable and retry a short poll after yielding to signals.
                        await _workflow.sleep(timedelta(seconds=1))
                        continue
                    self._execution_observation = dict(outcome)
                    execution_status = outcome.get("status")
                    followup = execution_followup_command(str(execution_status))
                    if followup is None:
                        await _workflow.sleep(timedelta(seconds=1))
                        continue
                    self._execution_active = False
                    await self._enqueue_internal(followup)
                    continue
                if not self._commands:
                    await _workflow.wait_condition(
                        lambda: bool(self._commands) or self._execution_active
                    )
                    continue
                command = self._commands.popleft()
                self._queued_commands.pop(command.command_id, None)
                self._queued_idempotency_keys.pop(command.request_idempotency_key, None)
                if command.command_id in self._current.get("processed_commands", []):
                    expected = self._current.get("processed_command_fingerprints", {}).get(
                        command.command_id
                    )
                    if expected != command_fingerprint(command):
                        raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
                    continue
                expected = self._current.get("processed_idempotency_keys", {}).get(
                    command.request_idempotency_key
                )
                if expected is not None:
                    if expected != command_fingerprint(command):
                        raise RuntimeError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")
                    continue
                try:
                    outcome = await _workflow.execute_child_workflow(
                        StepWorkflow.run,
                        {"initial": initial, "command": command.__dict__},
                        id=f"agenttrust-step:{command.tenant_id}:{command.task_id}:{command.command_id}",
                    )
                except Exception:
                    # The child retries dependency failures before surfacing them. Exhaustion is
                    # an attempt outcome, not a task lifecycle outcome: preserve authoritative
                    # state and keep accepting emergency or later commands.
                    self.record_rejection(
                        command,
                        "ORCHESTRATOR_TRANSITION_DEPENDENCY_EXHAUSTED",
                        _workflow.now(),
                    )
                    continue
                if not outcome.get("accepted"):
                    self.record_rejection(
                        command,
                        str(outcome.get("error_code", "ORCHESTRATOR_TRANSITION_REJECTED")),
                        _workflow.now(),
                    )
                    continue
                result = outcome.get("state")
                if not isinstance(result, dict):
                    raise RuntimeError("ORCHESTRATOR_TRANSITION_RESPONSE_INVALID")
                self._terminal = bool(result.get("terminal", False))
                initial = result
                self._current = dict(result)
                if self._terminal:
                    self.reject_queued_after_terminal(_workflow.now())
                if command.command_type in {"START", "RESUME"} and result.get("status") == "RUNNING":
                    self._execution_active = True
                if command.command_type in {"PAUSE", "CANCEL", "KILL", "NEEDS_HUMAN"}:
                    self._execution_active = False
                if command.command_type == "VERIFY" and result.get("status") == "VERIFYING":
                    await self._enqueue_internal("COMPLETE")
            return initial

        async def _enqueue_internal(self, command_type: str) -> None:
            command_id = f"system:{command_type.lower()}:{self._current['action_id']}"
            await super().command({
                "schema_version": "agenttrust.orchestrator-command.v1",
                "command_id": command_id,
                "request_idempotency_key": command_id,
                "tenant_id": self._current["tenant_id"],
                "task_id": self._current["task_id"],
                "command_type": command_type,
                "expected_state_version": self._current["recovery_cursor"],
                "payload_digest": command_payload_digest(command_type),
                "requested_by": "service:durable-worker",
                "requested_at": _workflow.now().isoformat(),
            }, now=_workflow.now())

        @_workflow.signal(name="command")
        async def command(self, value: Mapping[str, Any]) -> None:
            parsed: TaskCommand | None = None
            safe_value = value if isinstance(value, Mapping) else {}
            try:
                parsed = TaskCommand(**value)
                validate_command(parsed, now=_workflow.now())
                await super().command(value, now=_workflow.now())
            except (TypeError, ValueError, RuntimeError) as error:
                # A Temporal signal cannot return an acknowledgement. Persist queue-pressure
                # rejection so an accepted transport signal is never silently discarded and the
                # caller can observe the outcome through task events/query.
                code = str(error)
                if parsed is not None and code == "ORCHESTRATOR_COMMAND_QUEUE_FULL":
                    self.record_rejection(parsed, code, _workflow.now())
                else:
                    self._command_rejections.append({
                        "schema_version": "agenttrust.command-rejection.v1",
                        "event_id": hashlib.sha256(
                            f"{safe_value.get('task_id', 'invalid')}:{safe_value.get('command_id', 'invalid')}:{code}".encode()
                        ).hexdigest(),
                        "command_id": str(safe_value.get("command_id", "invalid"))[:256],
                        "request_idempotency_key": str(
                            safe_value.get("request_idempotency_key", "invalid")
                        )[:256],
                        "command_type": str(safe_value.get("command_type", "INVALID"))[:64],
                        "expected_state_version": safe_value.get("expected_state_version"),
                        "error_code": code if code.startswith("ORCHESTRATOR_") else "ORCHESTRATOR_COMMAND_INVALID",
                        "rejected_at": _workflow.now().isoformat(),
                    })
                return

        @_workflow.update(name="command_update")
        async def command_update(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
            try:
                await super().command(value, now=_workflow.now())
            except (TypeError, ValueError, RuntimeError) as error:
                code = str(error)
                return {
                    "accepted": False,
                    "error_code": code if code.startswith("ORCHESTRATOR_")
                    else "ORCHESTRATOR_COMMAND_INVALID",
                }
            return {"accepted": True, "command_id": value["command_id"]}

        @_workflow.query(name="state")
        def state(self) -> Mapping[str, Any]:
            return {
                **self.state_view(self._current),
                "execution_observation": self._execution_observation,
            }

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
    execution_client: ExecutionClient,
    temporal_tls: Any,
    management_listen: str,
    management_port: int,
) -> None:
    if _workflow is None:
        raise RuntimeError("TEMPORAL_SDK_REQUIRED")
    if not address or not namespace or not task_queue:
        raise ValueError("TEMPORAL_WORKER_CONFIG_INVALID")
    from temporalio.client import Client
    from temporalio.worker import Worker

    client = await Client.connect(address, namespace=namespace, tls=temporal_tls)
    activities = AuthoritativeTransitionActivities(transition_client)
    execution_activities = AuthoritativeExecutionActivities(execution_client)
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[TaskWorkflow, StepWorkflow],
        activities=[
            activities.apply_authoritative_transition,
            execution_activities.execute_authoritative_action,
        ],
        max_concurrent_activities=100,
        max_concurrent_workflow_tasks=1000,
    )
    if not management_listen or not 1 <= management_port <= 65535:
        raise ValueError("TEMPORAL_WORKER_MANAGEMENT_CONFIG_INVALID")
    from aiohttp import web
    async def ready(_: Any) -> Any:
        try:
            from temporalio.api.workflowservice.v1 import GetSystemInfoRequest
            temporal_ready, transition_ready, execution_ready = await asyncio.wait_for(
                asyncio.gather(
                    client.workflow_service.get_system_info(GetSystemInfoRequest()),
                    transition_client.ready(),
                    execution_client.ready(),
                ),
                timeout=1.5,
            )
            ready_value = bool(temporal_ready) and transition_ready and execution_ready
        except Exception:
            ready_value = False
        return web.json_response(
            {"schema_version": "agenttrust.worker-readiness.v1", "ready": ready_value},
            status=200 if ready_value else 503,
        )
    management_app = web.Application(client_max_size=1024)
    management_app.router.add_get("/ready", ready)
    runner = web.AppRunner(management_app)
    await runner.setup()
    await web.TCPSite(runner, management_listen, management_port).start()
    try:
        await worker.run()
    finally:
        await runner.cleanup()


def load_temporal_tls(
    ca_file: Path,
    certificate_file: Path,
    private_key_file: Path,
    server_name: str,
) -> Any:
    if (
        not server_name
        or not _secure_file(ca_file, private=False)
        or not _secure_file(certificate_file, private=False)
        or not _secure_file(private_key_file, private=True)
    ):
        raise ValueError("TEMPORAL_TLS_CONFIG_INVALID")
    ca = ca_file.read_bytes()
    certificate = certificate_file.read_bytes()
    private_key = private_key_file.read_bytes()
    if not ca or not certificate or not private_key:
        raise ValueError("TEMPORAL_TLS_CONFIG_INVALID")
    try:
        from temporalio.client import TLSConfig
    except ImportError as exc:
        raise RuntimeError("TEMPORAL_SDK_REQUIRED") from exc
    return TLSConfig(
        server_root_ca_cert=ca,
        client_cert=certificate,
        client_private_key=private_key,
        domain=server_name,
    )


def read_required_secret_file(environment_name: str) -> str:
    raw_path = os.environ.get(environment_name, "")
    if not raw_path:
        raise ValueError("ORCHESTRATOR_SECRET_FILE_REQUIRED")
    path = Path(raw_path)
    if (
        not _secure_file(path, private=True)
        or path.stat().st_size > 65_536
    ):
        raise ValueError("ORCHESTRATOR_SECRET_FILE_REQUIRED")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\n" in value:
        raise ValueError("ORCHESTRATOR_SECRET_FILE_INVALID")
    return value


def _secure_file(path: Path, *, private: bool) -> bool:
    """Accept regular non-symlink files and CSI's root:fsGroup 0440 private mount."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions & 0o007 or permissions & 0o022:
        return False
    if private:
        if permissions & ~0o440:
            return False
        owner_can_read = bool(permissions & 0o400) and metadata.st_uid == os.geteuid()
        group_can_read = bool(permissions & 0o040) and metadata.st_gid == os.getegid()
        if not owner_can_read and not group_can_read:
            return False
        if permissions & 0o004:
            return False
        if permissions & 0o070 not in {0, 0o040}:
            return False
        if permissions & 0o040 and metadata.st_gid != os.getegid():
            return False
    return 0 < metadata.st_size <= 1_048_576


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-durable-worker")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--temporal-address", default=os.environ.get("AGENT_TRUST_TEMPORAL_ADDRESS", ""))
    parser.add_argument("--namespace", default=os.environ.get("AGENT_TRUST_TEMPORAL_NAMESPACE", ""))
    parser.add_argument("--task-queue", default=os.environ.get("AGENT_TRUST_TEMPORAL_TASK_QUEUE", ""))
    parser.add_argument("--transition-endpoint", default=os.environ.get("AGENT_TRUST_TRANSITION_ENDPOINT", ""))
    parser.add_argument(
        "--ca-file", type=Path, default=os.environ.get("AGENT_TRUST_TRANSITION_CA_FILE")
    )
    parser.add_argument(
        "--certificate-file",
        type=Path,
        default=os.environ.get("AGENT_TRUST_TRANSITION_CERTIFICATE_FILE"),
    )
    parser.add_argument(
        "--private-key-file",
        type=Path,
        default=os.environ.get("AGENT_TRUST_TRANSITION_PRIVATE_KEY_FILE"),
    )
    parser.add_argument(
        "--temporal-ca-file",
        type=Path,
        default=os.environ.get("AGENT_TRUST_TEMPORAL_CA_FILE"),
    )
    parser.add_argument(
        "--temporal-certificate-file",
        type=Path,
        default=os.environ.get("AGENT_TRUST_TEMPORAL_CERTIFICATE_FILE"),
    )
    parser.add_argument(
        "--temporal-private-key-file",
        type=Path,
        default=os.environ.get("AGENT_TRUST_TEMPORAL_PRIVATE_KEY_FILE"),
    )
    parser.add_argument(
        "--temporal-server-name",
        default=os.environ.get("AGENT_TRUST_TEMPORAL_SERVER_NAME", ""),
    )
    parser.add_argument("--management-listen", default="127.0.0.1")
    parser.add_argument("--management-port", type=int, default=9092)
    args = parser.parse_args(argv)
    load_production_config(args.config)
    client = TransitionHttpClient(
        args.transition_endpoint,
        read_required_secret_file("AGENT_TRUST_TRANSITION_TOKEN_FILE"),
        ca_file=args.ca_file,
        certificate_file=args.certificate_file,
        private_key_file=args.private_key_file,
    )
    execution_client = ExecutionHttpClient(
        os.environ.get("AGENT_TRUST_EXECUTION_ENDPOINT", ""),
        read_required_secret_file("AGENT_TRUST_EXECUTION_TOKEN_FILE"),
        ca_file=Path(os.environ.get("AGENT_TRUST_EXECUTION_CA_FILE", "")),
        certificate_file=Path(
            os.environ.get("AGENT_TRUST_EXECUTION_CERTIFICATE_FILE", "")
        ),
        private_key_file=Path(
            os.environ.get("AGENT_TRUST_EXECUTION_PRIVATE_KEY_FILE", "")
        ),
        timeout_seconds=3.0,
    )
    if not all((args.temporal_ca_file, args.temporal_certificate_file, args.temporal_private_key_file)):
        raise ValueError("TEMPORAL_TLS_CONFIG_INVALID")
    temporal_tls = load_temporal_tls(
        args.temporal_ca_file,
        args.temporal_certificate_file,
        args.temporal_private_key_file,
        args.temporal_server_name,
    )
    asyncio.run(
        run_temporal_worker(
            args.temporal_address,
            args.namespace,
            args.task_queue,
            client,
            execution_client,
            temporal_tls,
            args.management_listen,
            args.management_port,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
