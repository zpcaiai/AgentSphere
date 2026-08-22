"""Production ingress API backed by PostgreSQL and multi-zone Temporal.

The API performs durable admission/idempotency and starts or signals workflows. Security
decisions and authoritative state transitions remain in the Rust transition service.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Mapping, Protocol, Sequence
import unicodedata
from urllib import parse as urllib_parse
import uuid

from python.durable_worker.worker import (
    TaskCommand,
    _secure_file,
    command_fingerprint,
    load_temporal_tls,
)


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_ORCHESTRATOR_BINDING_SCHEMA = "agenttrust.orchestrator-token-bindings.v1"
_ORCHESTRATOR_SCOPES = frozenset({
    "orchestrator:runtime",
    "orchestrator:read",
    "orchestrator:command",
    "orchestrator:transitions",
})


class OrchestratorApiError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.status = status


@dataclass(frozen=True)
class ActionRecord:
    tenant_id: str
    action_id: str
    task_id: str
    owner_subject: str
    status: str
    payload_hash: str
    idempotency_key: str


@dataclass(frozen=True)
class OrchestratorTokenBinding:
    client_identity: str
    tenant_id: str
    subject: str
    scope: str
    token_sha256: str


class OrchestratorTokenAuthorizer:
    """Exact mTLS SAN, tenant, route-scope and opaque-token binding authority."""

    def __init__(
        self,
        bindings: Sequence[OrchestratorTokenBinding],
        runtime_identities: frozenset[str],
        bff_identities: frozenset[str],
    ) -> None:
        if not bindings or not runtime_identities or not bff_identities:
            raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID")
        allowed = runtime_identities | bff_identities
        security_tuples: set[tuple[str, str, str]] = set()
        exact: set[OrchestratorTokenBinding] = set()
        for binding in bindings:
            try:
                tenant = str(uuid.UUID(binding.tenant_id))
            except ValueError as error:
                raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID") from error
            runtime_scope = binding.scope == "orchestrator:runtime"
            if (
                binding.client_identity not in allowed
                or tenant != binding.tenant_id
                or binding.scope not in _ORCHESTRATOR_SCOPES
                or runtime_scope != (binding.client_identity in runtime_identities)
                or binding.client_identity in runtime_identities
                    and binding.client_identity in bff_identities
                or not _safe_subject(binding.subject)
                or not _DIGEST.fullmatch(binding.token_sha256)
                or (binding.client_identity, tenant, binding.token_sha256)
                    in security_tuples
                or binding in exact
            ):
                raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID")
            security_tuples.add((binding.client_identity, tenant, binding.token_sha256))
            exact.add(binding)
        if any(not any(item.client_identity == identity for item in exact) for identity in allowed):
            raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID")
        self._bindings = frozenset(exact)

    @classmethod
    def from_file(
        cls,
        path: Path,
        runtime_identities: str,
        bff_identities: str,
    ) -> "OrchestratorTokenAuthorizer":
        if not _secure_file(path, private=True) or path.stat().st_size > 1_048_576:
            raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID")
        try:
            document = json.loads(path.read_text(encoding="utf-8"),
                                  object_pairs_hook=_reject_duplicate_pairs)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID") from error
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "bindings"}
            or document.get("schema_version") != _ORCHESTRATOR_BINDING_SCHEMA
            or not isinstance(document.get("bindings"), list)
            or not 1 <= len(document["bindings"]) <= 100_000
        ):
            raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID")
        bindings: list[OrchestratorTokenBinding] = []
        fields = {"client_identity", "tenant_id", "subject", "scope", "token_sha256"}
        for item in document["bindings"]:
            if (
                not isinstance(item, dict)
                or set(item) != fields
                or any(not isinstance(item[field], str) for field in fields)
            ):
                raise ValueError("ORCHESTRATOR_TOKEN_BINDINGS_INVALID")
            bindings.append(OrchestratorTokenBinding(**item))
        return cls(bindings, _parse_identity_allowlist(runtime_identities),
                   _parse_identity_allowlist(bff_identities))

    def authorize(
        self,
        peer_identity: str,
        tenant_id: str,
        scope: str,
        authorization: str | None,
    ) -> str:
        try:
            tenant = str(uuid.UUID(tenant_id))
        except ValueError as error:
            raise OrchestratorApiError("ORCHESTRATOR_UNAUTHENTICATED", 401) from error
        token = authorization[len("Bearer "):] if authorization and authorization.startswith(
            "Bearer "
        ) else ""
        if (
            tenant != tenant_id
            or scope not in _ORCHESTRATOR_SCOPES
            or not token
            or len(token) > 8_192
            or any(not character.isascii() or ord(character) < 33 or ord(character) > 126
                   for character in token)
        ):
            raise OrchestratorApiError("ORCHESTRATOR_UNAUTHENTICATED", 401)
        supplied = hashlib.sha256(token.encode("utf-8")).hexdigest()
        matches = [binding for binding in self._bindings if (
            binding.client_identity == peer_identity
            and binding.tenant_id == tenant
            and binding.scope == scope
            and hmac.compare_digest(binding.token_sha256, supplied)
        )]
        if len(matches) != 1:
            raise OrchestratorApiError("ORCHESTRATOR_UNAUTHENTICATED", 401)
        return matches[0].subject


class ActionStore(Protocol):
    async def admit(self, record: ActionRecord, envelope: Mapping[str, Any]) -> tuple[ActionRecord, bool]: ...
    async def mark_workflow_started(self, tenant_id: str, action_id: str) -> None: ...
    async def mark_start_requested(self, tenant_id: str, action_id: str) -> None: ...
    async def get(self, tenant_id: str, action_id: str) -> ActionRecord | None: ...
    async def get_task(self, tenant_id: str, task_id: str) -> ActionRecord | None: ...
    async def append_event(
        self, tenant_id: str, task_id: str, event: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...
    async def events(self, tenant_id: str, task_id: str, limit: int) -> list[Mapping[str, Any]]: ...
    async def event_for_command(
        self, tenant_id: str, task_id: str, command_id: str
    ) -> Mapping[str, Any] | None: ...
    async def list_tasks(
        self, tenant_id: str, owner: str, limit: int
    ) -> list[ActionRecord]: ...
    async def ready(self) -> bool: ...


class TemporalPort(Protocol):
    async def start(
        self, task_id: str, initial: Mapping[str, Any], start_command: Mapping[str, Any]
    ) -> bool: ...
    async def signal(self, task_id: str, command: Mapping[str, Any]) -> None: ...
    async def signal_exact(self, task_id: str, command: Mapping[str, Any]) -> None: ...
    async def update_exact(
        self, task_id: str, command: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...
    async def state(self, task_id: str) -> Mapping[str, Any]: ...
    async def ready(self) -> bool: ...


class OrchestratorApi:
    def __init__(
        self, store: ActionStore, temporal: TemporalPort,
        agui_signing_key: Any = None, dependency_probes: Sequence[Any] = (),
    ) -> None:
        self._store = store
        self._temporal = temporal
        self._agui_signing_key = agui_signing_key
        self._dependency_probes = tuple(dependency_probes)

    async def ready(self) -> Mapping[str, Any]:
        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    self._store.ready(),
                    self._temporal.ready(),
                    *(probe.ready() for probe in self._dependency_probes),
                    return_exceptions=True,
                ),
                timeout=1.5,
            )
            ready = bool(results) and all(result is True for result in results)
        except (TimeoutError, asyncio.TimeoutError):
            ready = False
        if not ready:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_READY", 503)
        return {
            "schema_version": "agenttrust.orchestrator-readiness.v1",
            "ready": True,
        }

    async def submit(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        identity = envelope.get("identity_context")
        tenant = envelope.get("tenant_context")
        trace = envelope.get("trace_context")
        idempotency_key = envelope.get("idempotency_key")
        payload_hash = envelope.get("payload_hash")
        payload_items = envelope.get("payload")
        envelope_keys = {
            "request_id", "trace_context", "identity_context", "tenant_context", "protocol",
            "content_type", "schema_version", "idempotency_key", "received_at", "payload",
            "payload_hash",
        }
        if (
            set(envelope) != envelope_keys
            or envelope.get("schema_version") != "agenttrust.gateway.v1"
            # `IngressProtocol` is serialized by the Rust gateway with
            # `SCREAMING_SNAKE_CASE`; the wire value is therefore `HTTP`.
            or envelope.get("protocol") != "HTTP"
            or str(envelope.get("content_type", "")).split(";", 1)[0].strip() != "application/json"
            or not _valid_gateway_context(identity, tenant, trace)
            or not isinstance(envelope.get("request_id"), str)
            or len(envelope["request_id"]) > 128
            or not _TOKEN.fullmatch(envelope["request_id"])
            or not isinstance(idempotency_key, str)
            or len(idempotency_key) > 128
            or not _TOKEN.fullmatch(idempotency_key)
            or not isinstance(payload_hash, str) or not _DIGEST.fullmatch(payload_hash)
            or not isinstance(payload_items, list)
            or any(type(item) is not int or not 0 <= item <= 255 for item in payload_items)
            or not _valid_gateway_timestamp(envelope.get("received_at"))
        ):
            raise OrchestratorApiError("ORCHESTRATOR_INGRESS_INVALID")
        _validate_scope(str(tenant["tenant_id"]), str(identity["owner_subject"]))
        try:
            payload = bytes(payload_items)
        except (TypeError, ValueError) as exc:
            raise OrchestratorApiError("ORCHESTRATOR_INGRESS_INVALID") from exc
        if len(payload) > 1_048_576 or hashlib.sha256(payload).hexdigest() != payload_hash:
            raise OrchestratorApiError("ORCHESTRATOR_PAYLOAD_HASH_MISMATCH")
        action = _parse_bound_action(payload, identity, tenant)
        # Cross-language compact JSON digest: recursive key order with UTF-8 code points kept
        # verbatim.  Rust materialization reconstructs the same bytes from PostgreSQL jsonb.
        canonical = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        record = ActionRecord(
            str(tenant["tenant_id"]), str(action["action_id"]), str(action["task_id"]),
            str(identity["owner_subject"]), "PENDING_WORKFLOW", payload_hash, idempotency_key,
        )
        admitted, created = await self._store.admit(record, envelope)
        command = _command(
            admitted,
            "START",
            admitted.owner_subject,
            command_id=f"start:{admitted.action_id}",
        )
        workflow_started = False
        if created or admitted.status == "PENDING_WORKFLOW":
            initial_state = {
                "schema_version": "agenttrust.orchestrator-state.v1",
                "tenant_id": admitted.tenant_id, "task_id": admitted.task_id,
                "action_id": admitted.action_id, "status": "CREATED",
                "recovery_cursor": 0, "terminal": False, "evidence_refs": [],
                "ingress_digest": hashlib.sha256(canonical).hexdigest(),
                "has_side_effects": _action_has_side_effects(action),
                "action_materialization": {
                    "schema_version": "agenttrust.action-materialization-ref.v1",
                    "tenant_id": admitted.tenant_id,
                    "action_id": admitted.action_id,
                    "payload_hash": admitted.payload_hash,
                    "store": "ORCHESTRATOR_INGRESS_POSTGRESQL",
                    "uri": f"orchestrator-ingress://{admitted.tenant_id}/{admitted.action_id}",
                },
                "execution": None,
                "processed_commands": [], "processed_command_fingerprints": {},
                "processed_idempotency_keys": {}, "events": [],
            }
            workflow_started = await self._temporal.start(
                _workflow_id(admitted), initial_state, command
            )
            if not workflow_started:
                existing = await self._temporal.state(_workflow_id(admitted))
                if any(existing.get(field) != initial_state.get(field) for field in (
                    "tenant_id", "task_id", "action_id", "ingress_digest",
                    "action_materialization", "has_side_effects",
                )):
                    raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_ID_CONFLICT", 409)
            await self._store.mark_workflow_started(admitted.tenant_id, admitted.action_id)
        if created or admitted.status in {"PENDING_WORKFLOW", "CREATED"}:
            if not workflow_started:
                outcome = await self._temporal.update_exact(_workflow_id(admitted), command)
                if outcome.get("accepted") is not True:
                    code = str(outcome.get("error_code", "ORCHESTRATOR_COMMAND_REJECTED"))
                    raise OrchestratorApiError(
                        code, 429 if code.endswith("QUEUE_FULL") else 409
                    )
            await self._store.append_event(admitted.tenant_id, admitted.task_id, command)
            await self._store.mark_start_requested(admitted.tenant_id, admitted.action_id)
        durable_start = await self._store.event_for_command(
            admitted.tenant_id, admitted.task_id, str(command["command_id"])
        )
        if durable_start is None:
            raise OrchestratorApiError("ORCHESTRATOR_EVENT_PERSISTENCE_FAILED", 503)
        acceptance_evidence = await self._store.append_event(
            admitted.tenant_id, admitted.task_id, durable_start
        )
        event_ref = acceptance_evidence.get("event_ref")
        event_digest = acceptance_evidence.get("event_digest")
        if (
            acceptance_evidence.get("schema_version")
            != "agenttrust.command-acceptance-evidence.v1"
            or not isinstance(event_ref, str)
            or not _valid_event_ref(event_ref, admitted.tenant_id, admitted.task_id)
            or not isinstance(event_digest, str)
            or not _DIGEST.fullmatch(event_digest)
        ):
            raise OrchestratorApiError("ORCHESTRATOR_EVENT_EVIDENCE_INVALID", 503)
        return {
            "schema_version": "agenttrust.action-acceptance.v1",
            "action_id": admitted.action_id,
            "task_id": admitted.task_id,
            "accepted": True,
            "start_requested": True,
            # Durable acceptance is not process execution success or task completion.
            "execution_pending": True,
            "ingress_digest": hashlib.sha256(canonical).hexdigest(),
            "evidence_ref": event_ref,
            "evidence_digest": event_digest,
        }

    async def query(self, tenant_id: str, owner: str, action_id: str) -> Mapping[str, Any]:
        _validate_scope(tenant_id, owner, action_id)
        record = await self._store.get(tenant_id, action_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        state = await self._bound_state(record)
        status = state.get("status")
        if not isinstance(status, str) or not status:
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        return {
            "action_id": record.action_id,
            "task_id": record.task_id,
            "status": status,
            "owner_subject": record.owner_subject,
            "tenant_id": record.tenant_id,
            "recovery_cursor": state.get("recovery_cursor"),
            "terminal": state.get("terminal"),
            "evidence_refs": state.get("evidence_refs", []),
        }

    async def control(
        self,
        tenant_id: str,
        owner: str,
        action_id: str,
        command_type: str,
        command_id: str | None = None,
    ) -> Mapping[str, Any]:
        _validate_scope(tenant_id, owner, action_id)
        record = await self._store.get(tenant_id, action_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        if command_type not in {
            "START", "PAUSE", "RESUME", "CANCEL", "KILL", "CHECKPOINT", "VERIFY", "COMPLETE"
        } or (command_id is not None and not _TOKEN.fullmatch(command_id)):
            raise OrchestratorApiError("ORCHESTRATOR_COMMAND_INVALID")
        state = await self._bound_state(record)
        recovery_cursor = state.get("recovery_cursor")
        if not isinstance(recovery_cursor, int) or recovery_cursor < 0:
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        # Legacy action-control callers do not supply an idempotency key. Derive one from
        # the immutable action and operation so an HTTP retry cannot execute containment
        # (or any other transition) twice after the recovery cursor advances.
        resolved_command_id = command_id or f"{command_type.lower()}:{record.action_id}"
        durable_event = await self._store.event_for_command(
            tenant_id, record.task_id, resolved_command_id
        )
        if durable_event is not None:
            expected_binding = {
                "schema_version": "agenttrust.orchestrator-command.v1",
                "command_id": resolved_command_id,
                "request_idempotency_key": resolved_command_id,
                "command_type": command_type,
                "tenant_id": tenant_id,
                "task_id": record.task_id,
                "requested_by": owner,
            }
            if any(durable_event.get(key) != value for key, value in expected_binding.items()):
                raise OrchestratorApiError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT", 409)
            evidence = await self._store.append_event(
                tenant_id, record.task_id, durable_event
            )
            return _command_receipt(
                resolved_command_id, tenant_id, record.task_id, evidence
            )
        processed = state.get("processed_command_fingerprints", {})
        rejected = state.get("rejected_command_fingerprints", {})
        if not isinstance(processed, dict) or not isinstance(rejected, dict):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        if resolved_command_id in rejected:
            raise OrchestratorApiError("ORCHESTRATOR_COMMAND_PREVIOUSLY_REJECTED", 409)
        if resolved_command_id in processed:
            # Heal the only cross-system crash window: Temporal may durably apply the
            # command immediately before PostgreSQL stores its acceptance event. The
            # authoritative transition cursor proves the original expected version and
            # the processed fingerprint proves every immutable command field. If either
            # proof is unavailable (for example after history compaction), fail closed.
            transitions = state.get("events")
            candidates = [
                event for event in transitions if isinstance(event, dict)
                and event.get("command_id") == resolved_command_id
            ] if isinstance(transitions, list) else []
            transition_cursor = (
                candidates[0].get("recovery_cursor") if len(candidates) == 1 else None
            )
            if not isinstance(transition_cursor, int) or transition_cursor < 1:
                raise OrchestratorApiError(
                    "ORCHESTRATOR_COMMAND_ACCEPTANCE_EVIDENCE_MISSING", 503
                )
            recovered = _command(
                record,
                command_type,
                owner,
                command_id=resolved_command_id,
                expected_state_version=transition_cursor - 1,
            )
            try:
                recovered_fingerprint = command_fingerprint(TaskCommand(**recovered))
            except (TypeError, ValueError) as exc:
                raise OrchestratorApiError(
                    "ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503
                ) from exc
            if recovered_fingerprint != processed[resolved_command_id]:
                raise OrchestratorApiError(
                    "ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT", 409
                )
            evidence = await self._store.append_event(
                tenant_id, record.task_id, recovered
            )
            return _command_receipt(
                resolved_command_id, tenant_id, record.task_id, evidence
            )
        command = _command(
            record,
            command_type,
            owner,
            command_id=resolved_command_id,
            expected_state_version=recovery_cursor,
        )
        outcome = await self._temporal.update_exact(_workflow_id(record), command)
        if outcome.get("accepted") is not True:
            code = str(outcome.get("error_code", "ORCHESTRATOR_COMMAND_REJECTED"))
            raise OrchestratorApiError(code, 429 if code.endswith("QUEUE_FULL") else 409)
        evidence = await self._store.append_event(tenant_id, record.task_id, command)
        return _command_receipt(
            command["command_id"], tenant_id, record.task_id, evidence
        )

    async def list_tasks(self, tenant_id: str, owner: str, limit: int) -> Mapping[str, Any]:
        _validate_scope(tenant_id, owner)
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise OrchestratorApiError("ORCHESTRATOR_QUERY_INVALID")
        records = await self._store.list_tasks(tenant_id, owner, limit)
        states = await asyncio.gather(
            *(self._bound_state(record) for record in records)
        )
        tasks: list[Mapping[str, Any]] = []
        for record, state in zip(records, states, strict=True):
            tasks.append({
                "action_id": record.action_id,
                "task_id": record.task_id,
                "status": state.get("status"),
                "recovery_cursor": state.get("recovery_cursor"),
                "terminal": state.get("terminal"),
            })
        return {"tasks": tasks}

    async def authoritative_tasks(
        self, tenant_id: str, owner: str, resource: str, limit: int
    ) -> Mapping[str, Any]:
        """Tenant- and principal-bound task inventory for the enterprise BFF.

        This surface is a view over Temporal's authoritative workflow state and the durable
        ingress index. It never derives a completion claim from the ingress row alone.
        """
        if (
            not isinstance(resource, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,99}", resource)
        ):
            raise OrchestratorApiError("ORCHESTRATOR_QUERY_INVALID")
        listed = await self.list_tasks(tenant_id, owner, limit)
        items = [
            {
                "schema_version": "agenttrust.task-view.v1",
                "action_id": task["action_id"],
                "task_id": task["task_id"],
                "status": task["status"],
                "recovery_cursor": task["recovery_cursor"],
                "terminal": task["terminal"],
            }
            for task in listed["tasks"]
        ]
        page: dict[str, Any] = {
            "schema_version": "agenttrust.authoritative-task-page.v1",
            "authoritative": True,
            "tenant_id": tenant_id,
            "resource": resource,
            "items": items,
            "next_cursor": None,
        }
        page["data_digest"] = hashlib.sha256(
            json.dumps(
                page, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        return page

    async def task_events(
        self, tenant_id: str, owner: str, task_id: str, limit: int
    ) -> Mapping[str, Any]:
        _validate_scope(tenant_id, owner, task_id)
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise OrchestratorApiError("ORCHESTRATOR_QUERY_INVALID")
        record = await self._store.get_task(tenant_id, task_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        state = await self._bound_state(record)
        authoritative = state.get("events", [])
        rejections = state.get("command_rejections", [])
        if not isinstance(authoritative, list) or not isinstance(rejections, list):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        submitted = await self._store.events(tenant_id, task_id, limit)
        return {"events": (submitted + authoritative + rejections)[-limit:]}

    async def task_transitions(
        self, tenant_id: str, owner: str, task_id: str, limit: int
    ) -> Mapping[str, Any]:
        """Return only authoritative state-machine transitions for signed UI recovery.

        Submission and rejection audit entries intentionally never share this response.  A large
        rejection history therefore cannot evict the current transition and make a BFF sign a
        stale CREATED snapshot for a running or terminal task.
        """
        _validate_scope(tenant_id, owner, task_id)
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise OrchestratorApiError("ORCHESTRATOR_QUERY_INVALID")
        record = await self._store.get_task(tenant_id, task_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        state = await self._bound_state(record)
        transitions = _validated_authoritative_transitions(state)
        current_cursor = state["recovery_cursor"]
        latest = transitions[-1] if transitions else None
        return {
            "schema_version": "agenttrust.authoritative-task-transitions.v1",
            "tenant_id": tenant_id,
            "task_id": task_id,
            "status": state["status"],
            "recovery_cursor": current_cursor,
            "terminal": state["terminal"],
            "evidence_digest": latest["evidence_digest"] if latest else None,
            "occurred_at": latest["occurred_at"] if latest else None,
            "transitions": transitions[-limit:],
        }

    async def bff_command(
        self,
        tenant_id: str,
        actor: str,
        task_id: str,
        command: Mapping[str, Any],
        idempotency_key: str | None,
    ) -> Mapping[str, Any]:
        _validate_scope(tenant_id, actor, task_id)
        record = await self._store.get_task(tenant_id, task_id)
        if record is None or record.owner_subject != actor:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        command_id = command.get("command_id")
        command_type = command.get("command_type")
        expected_version = command.get("expected_state_version")
        payload_digest = command.get("payload_digest")
        if (
            command.get("schema_version") != "agenttrust.orchestrator-command.v1"
            or not isinstance(command_id, str) or not _TOKEN.fullmatch(command_id)
            or not isinstance(idempotency_key, str) or not _TOKEN.fullmatch(idempotency_key)
            or command_type not in {"START", "PAUSE", "RESUME", "CANCEL", "KILL", "CHECKPOINT", "VERIFY", "COMPLETE"}
            or not isinstance(expected_version, int) or expected_version < 0
            or not isinstance(payload_digest, str) or not _DIGEST.fullmatch(payload_digest)
            or payload_digest != _command_payload_digest(command_type)
        ):
            raise OrchestratorApiError("ORCHESTRATOR_COMMAND_INVALID")
        versioned = {**command, "tenant_id": tenant_id, "task_id": task_id,
                     "request_idempotency_key": idempotency_key,
                     "requested_by": actor, "requested_at": datetime.now(timezone.utc).isoformat()}
        try:
            fingerprint = command_fingerprint(TaskCommand(**versioned))
        except (TypeError, ValueError) as exc:
            raise OrchestratorApiError("ORCHESTRATOR_COMMAND_INVALID") from exc
        state = await self._bound_state(record)
        by_command = state.get("processed_command_fingerprints", {})
        by_request = state.get("processed_idempotency_keys", {})
        rejected_by_command = state.get("rejected_command_fingerprints", {})
        rejected_by_request = state.get("rejected_idempotency_keys", {})
        if (
            not isinstance(by_command, dict)
            or not isinstance(by_request, dict)
            or not isinstance(rejected_by_command, dict)
            or not isinstance(rejected_by_request, dict)
        ):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        accepted_existing = [value for value in (
            by_command.get(command_id), by_request.get(idempotency_key),
        ) if value is not None]
        rejected_existing = [value for value in (
            rejected_by_command.get(command_id), rejected_by_request.get(idempotency_key),
        ) if value is not None]
        if accepted_existing or rejected_existing:
            if any(
                value != fingerprint
                for value in (*accepted_existing, *rejected_existing)
            ):
                raise OrchestratorApiError("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT", 409)
            if rejected_existing:
                raise OrchestratorApiError(
                    "ORCHESTRATOR_COMMAND_PREVIOUSLY_REJECTED", 409
                )
            receipt = await self._store.append_event(
                tenant_id, task_id, versioned
            )
            return _command_receipt(command_id, tenant_id, task_id, receipt)
        if state.get("recovery_cursor") != expected_version:
            raise OrchestratorApiError("ORCHESTRATOR_CONCURRENT_COMMAND", 409)
        outcome = await self._temporal.update_exact(_workflow_id(record), versioned)
        if outcome.get("accepted") is not True:
            code = str(outcome.get("error_code", "ORCHESTRATOR_COMMAND_REJECTED"))
            raise OrchestratorApiError(code, 429 if code.endswith("QUEUE_FULL") else 409)
        receipt = await self._store.append_event(tenant_id, task_id, versioned)
        return _command_receipt(command_id, tenant_id, task_id, receipt)

    async def agui_events(
        self, tenant_id: str, actor: str, task_id: str, resume_token: str | None, limit: int
    ) -> Mapping[str, Any]:
        _validate_scope(tenant_id, actor, task_id)
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise OrchestratorApiError("ORCHESTRATOR_QUERY_INVALID")
        record = await self._store.get_task(tenant_id, task_id)
        if record is None or record.owner_subject != actor:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        try:
            cursor = int(resume_token) if resume_token else 0
        except (TypeError, ValueError) as exc:
            raise OrchestratorApiError("ORCHESTRATOR_RESUME_TOKEN_INVALID") from exc
        if cursor < 0:
            raise OrchestratorApiError("ORCHESTRATOR_RESUME_TOKEN_INVALID")
        state = await self._bound_state(record)
        source = _validated_authoritative_transitions(state)
        current_cursor = state["recovery_cursor"]
        if cursor > current_cursor:
            raise OrchestratorApiError("ORCHESTRATOR_RESUME_TOKEN_AHEAD", 409)
        selected = [event for event in source if isinstance(event, dict)
                    and isinstance(event.get("recovery_cursor"), int)
                    and event["recovery_cursor"] > cursor][:limit]
        if self._agui_signing_key is None:
            raise OrchestratorApiError("ORCHESTRATOR_AGUI_SIGNING_UNAVAILABLE", 503)
        events = [
            _agui_event(tenant_id, task_id, event, self._agui_signing_key)
            for event in selected
        ]
        next_cursor = str(selected[-1]["recovery_cursor"] if selected else cursor)
        safe_snapshot_required = current_cursor > cursor and (
            not selected or selected[0]["recovery_cursor"] != cursor + 1
        )
        return {"events": events, "next_resume_token": next_cursor,
                "safe_snapshot_required": safe_snapshot_required}

    async def stream_snapshot(self, tenant_id: str, owner: str, task_id: str) -> Mapping[str, Any]:
        record = await self._store.get_task(tenant_id, task_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        snapshot = await self.task_events(tenant_id, owner, task_id, 1000)
        events = snapshot["events"]
        safe = [json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events]
        return {"events": safe}

    async def _bound_state(self, record: ActionRecord) -> Mapping[str, Any]:
        state = await self._temporal.state(_workflow_id(record))
        materialization = state.get("action_materialization")
        if (
            state.get("tenant_id") != record.tenant_id
            or state.get("task_id") != record.task_id
            or state.get("action_id") != record.action_id
            or not isinstance(materialization, dict)
            or materialization.get("tenant_id") != record.tenant_id
            or materialization.get("action_id") != record.action_id
            or materialization.get("payload_hash") != record.payload_hash
        ):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_SCOPE_MISMATCH", 409)
        return state


class PostgresActionStore:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def admit(self, record: ActionRecord, envelope: Mapping[str, Any]) -> tuple[ActionRecord, bool]:
        async with self._pool.acquire() as connection:
            async with connection.transaction(isolation="serializable"):
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", record.tenant_id)
                existing = await connection.fetchrow(
                    "SELECT * FROM orchestrator_ingress_actions WHERE tenant_id=$1::uuid AND idempotency_key=$2 FOR UPDATE",
                    record.tenant_id, record.idempotency_key)
                if existing:
                    persisted_envelope = _database_json_object(existing["envelope"])
                    if (
                        existing["payload_hash"] != record.payload_hash
                        or not hmac.compare_digest(
                            _canonical_json_digest(persisted_envelope),
                            _canonical_json_digest(envelope),
                        )
                    ):
                        raise OrchestratorApiError("ORCHESTRATOR_IDEMPOTENCY_CONFLICT", 409)
                    return _record(existing), False
                await connection.execute(
                    """INSERT INTO orchestrator_ingress_actions
                    (tenant_id,action_id,task_id,owner_subject,status,payload_hash,idempotency_key,envelope)
                    VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8::jsonb)""",
                    record.tenant_id, record.action_id, record.task_id, record.owner_subject,
                    record.status, record.payload_hash, record.idempotency_key, json.dumps(envelope))
                return record, True

    async def mark_workflow_started(self, tenant_id: str, action_id: str) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                result = await connection.execute(
                    """UPDATE orchestrator_ingress_actions SET status='CREATED',updated_at=now()
                    WHERE tenant_id=$1::uuid AND action_id=$2::uuid AND status IN ('PENDING_WORKFLOW','CREATED')""",
                    tenant_id, action_id)
                if result != "UPDATE 1":
                    raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_START_CONFLICT", 409)

    async def mark_start_requested(self, tenant_id: str, action_id: str) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                result = await connection.execute(
                    """UPDATE orchestrator_ingress_actions SET status='START_REQUESTED',updated_at=now()
                    WHERE tenant_id=$1::uuid AND action_id=$2::uuid
                    AND status IN ('CREATED','START_REQUESTED')""",
                    tenant_id, action_id)
                if result != "UPDATE 1":
                    raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_START_CONFLICT", 409)

    async def get(self, tenant_id: str, action_id: str) -> ActionRecord | None:
        return await self._lookup(tenant_id, "action_id", action_id)

    async def get_task(self, tenant_id: str, task_id: str) -> ActionRecord | None:
        return await self._lookup(tenant_id, "task_id", task_id)

    async def _lookup(self, tenant_id: str, column: str, value: str) -> ActionRecord | None:
        if column not in {"action_id", "task_id"}:
            raise OrchestratorApiError("ORCHESTRATOR_QUERY_INVALID")
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                row = await connection.fetchrow(
                    f"SELECT * FROM orchestrator_ingress_actions WHERE tenant_id=$1::uuid AND {column}=$2::uuid",
                    tenant_id, value)
                return _record(row) if row else None

    async def append_event(
        self, tenant_id: str, task_id: str, event: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                command_id = event.get("command_id")
                if not isinstance(command_id, str) or not _TOKEN.fullmatch(command_id):
                    raise OrchestratorApiError("ORCHESTRATOR_EVENT_INVALID")
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", command_id
                )
                existing = await connection.fetchrow(
                    "SELECT sequence,event FROM orchestrator_stream_events "
                    "WHERE tenant_id=$1::uuid AND task_id=$2::uuid "
                    "AND event->>'command_id'=$3 ORDER BY sequence LIMIT 1",
                    tenant_id, task_id, command_id,
                )
                if existing is None:
                    existing = await connection.fetchrow(
                        "INSERT INTO orchestrator_stream_events(tenant_id,task_id,event) "
                        "VALUES ($1::uuid,$2::uuid,$3::jsonb) RETURNING sequence,event",
                        tenant_id, task_id,
                        json.dumps(event, ensure_ascii=False, separators=(",", ":")),
                    )
                if existing is None:
                    raise OrchestratorApiError("ORCHESTRATOR_EVENT_PERSISTENCE_FAILED", 503)
                persisted = _database_json_object(existing["event"])
                try:
                    persisted_fingerprint = command_fingerprint(TaskCommand(**persisted))
                    supplied_fingerprint = command_fingerprint(TaskCommand(**event))
                except (TypeError, ValueError) as exc:
                    raise OrchestratorApiError("ORCHESTRATOR_EVENT_INVALID") from exc
                if persisted_fingerprint != supplied_fingerprint:
                    raise OrchestratorApiError(
                        "ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT", 409
                    )
                sequence = int(existing["sequence"])
                digest = hashlib.sha256(
                    json.dumps(
                        persisted, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest()
                return {
                    "schema_version": "agenttrust.command-acceptance-evidence.v1",
                    "event_ref": (
                        f"orchestrator-event://{tenant_id}/{task_id}/{sequence}"
                    ),
                    "event_digest": digest,
                }

    async def events(self, tenant_id: str, task_id: str, limit: int) -> list[Mapping[str, Any]]:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                rows = await connection.fetch("SELECT event FROM orchestrator_stream_events WHERE tenant_id=$1::uuid AND task_id=$2::uuid ORDER BY sequence DESC LIMIT $3",
                                              tenant_id, task_id, limit)
                return [
                    _database_json_object(row["event"])
                    for row in reversed(rows)
                ]

    async def event_for_command(
        self, tenant_id: str, task_id: str, command_id: str
    ) -> Mapping[str, Any] | None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                row = await connection.fetchrow(
                    "SELECT event FROM orchestrator_stream_events "
                    "WHERE tenant_id=$1::uuid AND task_id=$2::uuid "
                    "AND event->>'command_id'=$3 ORDER BY sequence LIMIT 1",
                    tenant_id, task_id, command_id,
                )
                return _database_json_object(row["event"]) if row else None

    async def list_tasks(
        self, tenant_id: str, owner: str, limit: int
    ) -> list[ActionRecord]:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                rows = await connection.fetch(
                    """SELECT * FROM orchestrator_ingress_actions
                    WHERE tenant_id=$1::uuid AND owner_subject=$2
                    ORDER BY updated_at DESC,action_id DESC LIMIT $3""",
                    tenant_id, owner, limit)
                return [_record(row) for row in rows]

    async def ready(self) -> bool:
        try:
            return await self._pool.fetchval("SELECT 1") == 1
        except Exception:
            return False


class TemporalClientPort:
    def __init__(self, client: Any, task_queue: str) -> None:
        self._client, self._task_queue = client, task_queue
    async def start(
        self, task_id: str, initial: Mapping[str, Any], start_command: Mapping[str, Any]
    ) -> bool:
        from python.durable_worker.worker import TaskWorkflow
        try:
            await self._client.start_workflow(TaskWorkflow.run, initial, id=task_id,
                                              task_queue=self._task_queue,
                                              start_signal="command",
                                              start_signal_args=[dict(start_command)])
            return True
        except Exception as error:
            from temporalio.client import WorkflowAlreadyStartedError
            if not isinstance(error, WorkflowAlreadyStartedError):
                raise OrchestratorApiError("ORCHESTRATOR_TEMPORAL_UNAVAILABLE", 503) from error
            return False
    async def signal(self, task_id: str, command: Mapping[str, Any]) -> None:
        try:
            handle = self._client.get_workflow_handle(task_id)
            state = await self.state(task_id)
            if not isinstance(state, dict) or not isinstance(state.get("recovery_cursor"), int):
                raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
            versioned = {**command, "expected_state_version": state["recovery_cursor"]}
            await handle.signal("command", versioned)
        except OrchestratorApiError:
            raise
        except Exception as error:
            raise OrchestratorApiError("ORCHESTRATOR_TEMPORAL_UNAVAILABLE", 503) from error
    async def signal_exact(self, task_id: str, command: Mapping[str, Any]) -> None:
        try:
            await self._client.get_workflow_handle(task_id).signal("command", dict(command))
        except Exception as error:
            raise OrchestratorApiError("ORCHESTRATOR_TEMPORAL_UNAVAILABLE", 503) from error
    async def update_exact(
        self, task_id: str, command: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        try:
            outcome = await self._client.get_workflow_handle(task_id).execute_update(
                "command_update", dict(command)
            )
        except Exception as error:
            raise OrchestratorApiError("ORCHESTRATOR_TEMPORAL_UNAVAILABLE", 503) from error
        if not isinstance(outcome, dict) or not isinstance(outcome.get("accepted"), bool):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        return outcome
    async def state(self, task_id: str) -> Mapping[str, Any]:
        try:
            value = await self._client.get_workflow_handle(task_id).query("state")
        except Exception as error:
            raise OrchestratorApiError("ORCHESTRATOR_TEMPORAL_UNAVAILABLE", 503) from error
        if not isinstance(value, dict):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        return value
    async def ready(self) -> bool:
        try:
            from temporalio.api.workflowservice.v1 import GetSystemInfoRequest
            await asyncio.wait_for(
                self._client.workflow_service.get_system_info(GetSystemInfoRequest()),
                timeout=1.5,
            )
            return True
        except Exception:
            return False


def _record(row: Mapping[str, Any]) -> ActionRecord:
    return ActionRecord(*(str(row[key]) for key in (
        "tenant_id", "action_id", "task_id", "owner_subject", "status", "payload_hash", "idempotency_key")))


def _workflow_id(record: ActionRecord) -> str:
    # Tenant is part of the Temporal identity; task UUIDs are only tenant-unique in PostgreSQL.
    return f"agenttrust:{record.tenant_id}:{record.task_id}"


def _validate_scope(tenant_id: str, owner: str, resource_id: str | None = None) -> None:
    try:
        tenant = uuid.UUID(tenant_id)
        resource = uuid.UUID(resource_id) if resource_id is not None else None
    except (AttributeError, TypeError, ValueError) as exc:
        raise OrchestratorApiError("ORCHESTRATOR_REQUEST_INVALID") from exc
    if (
        tenant.int == 0
        or (resource is not None and resource.int == 0)
        or not isinstance(owner, str)
        or not _safe_subject(owner)
    ):
        raise OrchestratorApiError("ORCHESTRATOR_REQUEST_INVALID")


def _valid_gateway_context(
    identity: Any, tenant: Any, trace: Any,
) -> bool:
    if (
        not isinstance(identity, dict)
        or set(identity) != {
            "subject", "tenant_id", "agent_instance_id", "owner_subject", "trust_level",
        }
        or not isinstance(tenant, dict)
        or set(tenant) != {"tenant_id", "quota_profile"}
        or not isinstance(trace, dict)
        or set(trace) != {"trace_id", "parent_span_id", "invalid_input_replaced"}
        or tenant.get("tenant_id") != identity.get("tenant_id")
    ):
        return False
    if (
        not isinstance(identity.get("subject"), str)
        or not _safe_subject(identity["subject"])
        or not isinstance(identity.get("owner_subject"), str)
        or not _safe_subject(identity["owner_subject"])
        or not isinstance(identity.get("trust_level"), str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identity["trust_level"])
            is None
    ):
        return False
    if (
        not isinstance(identity.get("tenant_id"), str)
        or not isinstance(identity.get("agent_instance_id"), str)
    ):
        return False
    try:
        tenant_id = uuid.UUID(str(identity.get("tenant_id")))
        agent_id = uuid.UUID(str(identity.get("agent_instance_id")))
    except (AttributeError, TypeError, ValueError):
        return False
    quota_profile = tenant.get("quota_profile")
    trace_id = trace.get("trace_id")
    parent_span_id = trace.get("parent_span_id")
    return (
        tenant_id.int != 0
        and agent_id.int != 0
        and str(tenant_id) == identity["tenant_id"].lower()
        and str(agent_id) == identity["agent_instance_id"].lower()
        and isinstance(quota_profile, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", quota_profile) is not None
        and isinstance(trace_id, str)
        and re.fullmatch(r"[0-9A-Fa-f]{32}", trace_id) is not None
        and (
            parent_span_id is None
            or isinstance(parent_span_id, str)
            and re.fullmatch(r"[0-9A-Fa-f]{16}", parent_span_id) is not None
        )
        and type(trace.get("invalid_input_replaced")) is bool
    )


def _valid_gateway_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        received_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return received_at.tzinfo is not None and received_at <= datetime.now(timezone.utc) + timedelta(minutes=5)


def _command(
    record: ActionRecord,
    command_type: str,
    requested_by: str,
    *,
    command_id: str | None = None,
    request_idempotency_key: str | None = None,
    expected_state_version: int = 0,
) -> dict[str, Any]:
    resolved_command_id = command_id or str(uuid.uuid4())
    return {
        "schema_version": "agenttrust.orchestrator-command.v1",
        "command_id": resolved_command_id,
        "request_idempotency_key": request_idempotency_key or resolved_command_id,
        "tenant_id": record.tenant_id,
        "task_id": record.task_id,
        "command_type": command_type,
        "expected_state_version": expected_state_version,
        "payload_digest": _command_payload_digest(command_type),
        "requested_by": requested_by,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }


def _command_payload_digest(command_type: str) -> str:
    payload = json.dumps(
        {"command_type": command_type}, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()


_TASK_STATUSES = {
    "CREATED", "PLANNED", "POLICY_CHECKED", "APPROVAL_PENDING", "APPROVED",
    "RUNNING", "PAUSE_REQUESTED", "PAUSED", "CANCEL_REQUESTED", "CANCELLING",
    "KILL_REQUESTED", "KILLED", "VERIFYING", "COMPLETED", "DENIED", "FAILED",
    "EVALUATION_FAILED", "COMPENSATING", "ROLLED_BACK", "NEEDS_HUMAN",
    "MANUAL_RECOVERY_REQUIRED",
}


def _validated_authoritative_transitions(
    state: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    source = state.get("events")
    cursor = state.get("recovery_cursor")
    status = state.get("status")
    terminal = state.get("terminal")
    if (
        not isinstance(source, list)
        or len(source) > 1024
        or not isinstance(cursor, int)
        or not 0 <= cursor <= 1_000_000
        or status not in _TASK_STATUSES
        or not isinstance(terminal, bool)
    ):
        raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
    validated: list[Mapping[str, Any]] = []
    previous = -1
    for event in source:
        if not isinstance(event, dict):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        recovery_cursor = event.get("recovery_cursor")
        occurred_at = event.get("occurred_at")
        try:
            parsed_time = datetime.fromisoformat(str(occurred_at).replace("Z", "+00:00"))
        except ValueError as exc:
            raise OrchestratorApiError(
                "ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503
            ) from exc
        if (
            event.get("schema_version") != "agenttrust.orchestrator-state.v1"
            or not isinstance(recovery_cursor, int)
            or recovery_cursor <= previous
            or recovery_cursor < 1
            or recovery_cursor > cursor
            or not isinstance(event.get("event_id"), str)
            or not _TOKEN.fullmatch(event["event_id"])
            or not isinstance(event.get("command_id"), str)
            or not _TOKEN.fullmatch(event["command_id"])
            or event.get("from") not in _TASK_STATUSES
            or event.get("to") not in _TASK_STATUSES
            or not isinstance(event.get("evidence_digest"), str)
            or not _DIGEST.fullmatch(event["evidence_digest"])
            or parsed_time.tzinfo is None
        ):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        previous = recovery_cursor
        validated.append(event)
    if cursor == 0:
        if validated or status != "CREATED":
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
    elif not validated or validated[-1]["recovery_cursor"] != cursor:
        raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
    if validated and validated[-1]["to"] != status:
        raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
    expected_terminal = status in {"COMPLETED", "KILLED", "FAILED", "ROLLED_BACK", "DENIED"}
    if terminal is not expected_terminal:
        raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
    return validated


def _agui_event(
    tenant_id: str, task_id: str, event: Mapping[str, Any], signing_key: Any
) -> Mapping[str, Any]:
    recovery_cursor = event["recovery_cursor"]
    unsigned = {
        "schema_version": "agenttrust.a2a-agui.v1",
        "event_id": str(event.get("event_id", f"transition:{task_id}:{recovery_cursor}")),
        "tenant_id": tenant_id,
        "task_id": task_id,
        "sequence": recovery_cursor,
        "trace_id": str(event.get("command_id", "orchestrator")),
        "kind": "EXECUTION_STATUS",
        "safe_payload": {
            "from": event.get("from"), "to": event.get("to"),
            "evidence_digest": event.get("evidence_digest"),
        },
        "occurred_at": event.get("occurred_at"),
        "backend_signature": "",
    }
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    signature = signing_key.sign(encoded)
    return {**unsigned, "backend_signature": base64.urlsafe_b64encode(signature).decode().rstrip("=")}


def load_agui_signing_key(path: Path) -> Any:
    if not _secure_file(path, private=True) or not 64 <= path.stat().st_size <= 65_536:
        raise ValueError("ORCHESTRATOR_AGUI_SIGNING_KEY_INVALID")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ImportError, TypeError, ValueError) as exc:
        raise ValueError("ORCHESTRATOR_AGUI_SIGNING_KEY_INVALID") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("ORCHESTRATOR_AGUI_SIGNING_KEY_INVALID")
    return key


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("ORCHESTRATOR_ACTION_IR_DUPLICATE_KEY")
        value[key] = item
    return value


def _strict_json_loads(value: str) -> Any:
    """Decode an HTTP JSON body while rejecting ambiguous duplicate object keys."""
    return json.loads(value, object_pairs_hook=_reject_duplicate_pairs)


def _command_receipt(
    command_id: str,
    tenant_id: str,
    task_id: str,
    evidence: Mapping[str, Any],
) -> Mapping[str, Any]:
    expected = {"schema_version", "event_ref", "event_digest"}
    event_ref = evidence.get("event_ref")
    event_digest = evidence.get("event_digest")
    if (
        set(evidence) != expected
        or evidence.get("schema_version")
            != "agenttrust.command-acceptance-evidence.v1"
        or not isinstance(event_ref, str)
        or not _valid_event_ref(event_ref, tenant_id, task_id)
        or not isinstance(event_digest, str)
        or not _DIGEST.fullmatch(event_digest)
    ):
        raise OrchestratorApiError("ORCHESTRATOR_EVENT_EVIDENCE_INVALID", 503)
    return {
        "schema_version": "agenttrust.command-receipt.v1",
        "accepted": True,
        "command_id": command_id,
        "evidence_ref": event_ref,
        "evidence_digest": event_digest,
        # Temporal accepted the durable command. It has not asserted execution success.
        "execution_pending": True,
    }


def _canonical_json_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _database_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value, object_pairs_hook=_reject_duplicate_pairs)
        except (json.JSONDecodeError, ValueError) as exc:
            raise OrchestratorApiError(
                "ORCHESTRATOR_DATABASE_VALUE_INVALID", 503
            ) from exc
        if isinstance(decoded, dict):
            return decoded
    raise OrchestratorApiError("ORCHESTRATOR_DATABASE_VALUE_INVALID", 503)


def _valid_event_ref(event_ref: str, tenant_id: str, task_id: str) -> bool:
    return re.fullmatch(
        rf"orchestrator-event://{re.escape(tenant_id)}/{re.escape(task_id)}/[1-9][0-9]*",
        event_ref,
    ) is not None


def _parse_bound_action(
    payload: bytes, identity: Mapping[str, Any], tenant: Mapping[str, Any]
) -> Mapping[str, Any]:
    try:
        action = json.loads(payload, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID") from exc
    required = {
        "schema_version", "action_id", "task_id", "step_id", "agent", "intent",
        "tool", "payload", "resource", "environment", "risk", "data",
        "expected_outcome", "credential_refs", "requested_at", "extensions",
    }
    allowed = required | {"current_state_version"}
    if not isinstance(action, dict) or set(action) - allowed or not required <= set(action):
        raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID")
    agent = action.get("agent")
    resource = action.get("resource")
    environment = action.get("environment")
    if (
        action.get("schema_version") != "agenttrust.action.v1"
        or not isinstance(agent, dict)
        or not isinstance(resource, dict)
        or not isinstance(environment, dict)
        or str(agent.get("tenant_id")) != str(tenant.get("tenant_id"))
        or str(resource.get("tenant_id")) != str(tenant.get("tenant_id"))
        or str(environment.get("tenant_id")) != str(tenant.get("tenant_id"))
        or str(agent.get("agent_instance_id")) != str(identity.get("agent_instance_id"))
        or str(agent.get("owner_subject")) != str(identity.get("owner_subject"))
        or str(agent.get("trust_level")) != str(identity.get("trust_level"))
        or str(environment.get("deployment")).lower() != "production"
        or environment.get("simulation") is not False
        or str(agent.get("deployment_environment")).lower() != "production"
    ):
        raise OrchestratorApiError("ORCHESTRATOR_ACTION_IDENTITY_MISMATCH", 403)
    for field in ("action_id", "task_id", "step_id"):
        try:
            parsed = uuid.UUID(str(action.get(field)))
        except (TypeError, ValueError) as exc:
            raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID") from exc
        if parsed.int == 0 or str(parsed) != str(action[field]).lower():
            raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID")
    try:
        requested_at = datetime.fromisoformat(str(action["requested_at"]).replace("Z", "+00:00"))
        agent_issued_at = datetime.fromisoformat(str(agent["issued_at"]).replace("Z", "+00:00"))
        agent_expires_at = datetime.fromisoformat(str(agent["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID") from exc
    now = datetime.now(timezone.utc)
    if (
        requested_at.tzinfo is None
        or agent_issued_at.tzinfo is None
        or agent_expires_at.tzinfo is None
        or requested_at > now + timedelta(minutes=5)
        or agent_issued_at > now + timedelta(minutes=5)
        or agent_expires_at <= now
    ):
        raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID")
    extensions = action.get("extensions")
    if not isinstance(extensions, dict) or len(extensions) > 32:
        raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID")
    if _action_has_side_effects(action):
        plan_hash = extensions.get("x-plan-hash")
        state_version = action.get("current_state_version")
        if (
            not isinstance(plan_hash, str)
            or not _DIGEST.fullmatch(plan_hash)
            or not isinstance(state_version, str)
            or not state_version
            or len(state_version) > 128
            or any(unicodedata.category(character).startswith("C") for character in state_version)
        ):
            raise OrchestratorApiError("ORCHESTRATOR_ACTION_IR_INVALID")
    return action


def _action_has_side_effects(action: Mapping[str, Any]) -> bool:
    operation = action.get("intent", {}).get("operation")
    return not isinstance(operation, str) or operation.lower() not in {
        "read", "get", "list", "search", "inspect",
    }


def _safe_subject(value: str) -> bool:
    return bool(
        value
        and len(value) <= 256
        and value[0].isalnum()
        and all(character.isascii() and (character.isalnum() or character in "._:@/-")
                for character in value)
    )


def _parse_identity_allowlist(value: str) -> frozenset[str]:
    identities = frozenset(item.strip() for item in value.split(",") if item.strip())
    if (
        not identities
        or any(
            len(identity) > 512
            or not identity.startswith(("DNS:", "URI:"))
            or not identity.split(":", 1)[1]
            or any(not character.isascii() or not character.isprintable()
                   for character in identity)
            for identity in identities
        )
    ):
        raise ValueError("ORCHESTRATOR_CLIENT_IDENTITIES_INVALID")
    return identities


def _peer_identity(
    peer_certificate: Mapping[str, Any] | None, expected: str
) -> str | None:
    if not isinstance(peer_certificate, Mapping):
        return None
    try:
        expected_identities = _parse_identity_allowlist(expected)
    except ValueError:
        return None
    certificate_identities: list[str] = []
    for entry in peer_certificate.get("subjectAltName", ()):
        if not isinstance(entry, tuple) or len(entry) != 2 or entry[0] not in {"DNS", "URI"}:
            continue
        identity = f"{entry[0]}:{entry[1]}"
        if len(identity) > 512 or not identity.split(":", 1)[1]:
            return None
        certificate_identities.append(identity)
    if len(certificate_identities) != 1 or certificate_identities[0] not in expected_identities:
        return None
    return certificate_identities[0]


def _peer_identity_matches(peer_certificate: Mapping[str, Any] | None, expected: str) -> bool:
    return _peer_identity(peer_certificate, expected) is not None


def _authenticate_request(
    authorizer: OrchestratorTokenAuthorizer,
    request: Any,
    trusted_client_identity: str,
    tenant_id: str,
    scope: str,
) -> str:
    transport = request.transport
    ssl_object = transport.get_extra_info("ssl_object") if transport is not None else None
    peer_certificate = ssl_object.getpeercert() if ssl_object is not None else None
    identity = _peer_identity(peer_certificate, trusted_client_identity)
    if identity is None:
        raise OrchestratorApiError("ORCHESTRATOR_SERVICE_IDENTITY_UNTRUSTED", 401)
    return authorizer.authorize(
        identity, tenant_id, scope, _single_request_header(request, "Authorization")
    )


def _single_request_header(request: Any, name: str) -> str | None:
    values = request.headers.getall(name, [])
    if len(values) != 1 or not isinstance(values[0], str):
        return None
    return values[0]


def _request_tenant(request: Any) -> str:
    tenant = _single_request_header(request, "X-AgentTrust-Tenant-Id")
    legacy = _single_request_header(request, "X-Tenant-Id")
    try:
        canonical = str(uuid.UUID(tenant or ""))
    except ValueError as error:
        raise OrchestratorApiError("ORCHESTRATOR_SCOPE_MISMATCH", 403) from error
    if canonical != tenant or legacy is not None and not hmac.compare_digest(legacy, tenant):
        raise OrchestratorApiError("ORCHESTRATOR_SCOPE_MISMATCH", 403)
    return canonical


def _body_tenant(body: Mapping[str, Any]) -> str | None:
    candidates: list[Any] = [body.get("tenant_id")]
    for field in ("tenant_context", "identity_context"):
        nested = body.get(field)
        if isinstance(nested, Mapping):
            candidates.append(nested.get("tenant_id"))
    values = [value for value in candidates if value is not None]
    if not values or any(not isinstance(value, str) for value in values):
        return None
    if any(not hmac.compare_digest(values[0], value) for value in values[1:]):
        return None
    return values[0]


def create_app(
    api: OrchestratorApi,
    trusted_runtime_client_identities: str,
    trusted_bff_client_identities: str,
    authorizer: OrchestratorTokenAuthorizer,
) -> Any:
    from aiohttp import web

    async def json_call(
        request: Any,
        operation: Any,
        trusted_identities: str = trusted_runtime_client_identities,
        scope: str = "orchestrator:runtime",
        require_body_tenant: bool = True,
    ) -> Any:
        try:
            tenant_id = _request_tenant(request)
            body = await request.json(loads=_strict_json_loads)
            if not isinstance(body, Mapping) or (
                require_body_tenant and _body_tenant(body) != tenant_id
            ):
                raise OrchestratorApiError("ORCHESTRATOR_SCOPE_MISMATCH", 403)
            _authenticate_request(authorizer, request, trusted_identities, tenant_id, scope)
            return web.json_response(await operation(body, tenant_id))
        except OrchestratorApiError as error:
            return web.json_response({"error": str(error)}, status=error.status)
        except (json.JSONDecodeError, ValueError, TypeError, KeyError):
            return web.json_response({"error": "ORCHESTRATOR_REQUEST_INVALID"}, status=400)
        except Exception:
            return web.json_response({"error": "ORCHESTRATOR_DEPENDENCY_UNAVAILABLE"}, status=503)
    app = web.Application(client_max_size=1_048_576)
    async def ready(_: Any) -> Any:
        try:
            return web.json_response(await api.ready())
        except OrchestratorApiError as error:
            return web.json_response({"ready": False, "error": str(error)}, status=error.status)
    async def bff_command(request: Any) -> Any:
        return await json_call(
            request,
            lambda body, tenant: api.bff_command(
                tenant,
                _single_request_header(request, "X-Actor-Subject") or "",
                request.match_info["task_id"],
                body,
                _single_request_header(request, "Idempotency-Key"),
            ),
            trusted_bff_client_identities,
            "orchestrator:command",
            False,
        )
    async def agui(request: Any) -> Any:
        try:
            tenant_id = _request_tenant(request)
            _authenticate_request(authorizer, request, trusted_bff_client_identities, tenant_id,
                                  "orchestrator:transitions")
            return web.json_response(await api.agui_events(
                tenant_id,
                _single_request_header(request, "X-Actor-Subject") or "",
                request.match_info["task_id"],
                request.query.get("resume_token"),
                int(request.query.get("limit", "100")),
            ))
        except OrchestratorApiError as error:
            return web.json_response({"error": str(error)}, status=error.status)
        except (TypeError, ValueError):
            return web.json_response({"error": "ORCHESTRATOR_REQUEST_INVALID"}, status=400)
        except Exception:
            return web.json_response({"error": "ORCHESTRATOR_DEPENDENCY_UNAVAILABLE"}, status=503)
    async def bff_events(request: Any) -> Any:
        async def bound_events(body: Mapping[str, Any], tenant_id: str) -> Mapping[str, Any]:
            actor = _single_request_header(request, "X-Actor-Subject") or ""
            if body.get("tenant_id") != tenant_id or body.get("owner") != actor:
                raise OrchestratorApiError("ORCHESTRATOR_SCOPE_MISMATCH", 403)
            return await api.task_events(
                tenant_id, actor, body["task_id"], body.get("limit", 1000)
            )
        return await json_call(request, bound_events, trusted_bff_client_identities,
                               "orchestrator:transitions")
    async def bff_transitions(request: Any) -> Any:
        async def bound_transitions(body: Mapping[str, Any], tenant_id: str) -> Mapping[str, Any]:
            actor = _single_request_header(request, "X-Actor-Subject") or ""
            if body.get("tenant_id") != tenant_id or body.get("owner") != actor:
                raise OrchestratorApiError("ORCHESTRATOR_SCOPE_MISMATCH", 403)
            return await api.task_transitions(
                tenant_id, actor, body["task_id"], body.get("limit", 1000)
            )
        return await json_call(request, bound_transitions, trusted_bff_client_identities,
                               "orchestrator:transitions")
    async def authoritative_tasks(request: Any) -> Any:
        try:
            tenant_id = _request_tenant(request)
            _authenticate_request(authorizer, request, trusted_bff_client_identities, tenant_id,
                                  "orchestrator:read")
            return web.json_response(await api.authoritative_tasks(
                tenant_id,
                _single_request_header(request, "X-Actor-Subject") or "",
                request.query.get("resource", ""),
                int(request.query.get("limit", "100")),
            ))
        except OrchestratorApiError as error:
            return web.json_response({"error": str(error)}, status=error.status)
        except (TypeError, ValueError):
            return web.json_response({"error": "ORCHESTRATOR_REQUEST_INVALID"}, status=400)
        except Exception:
            return web.json_response({"error": "ORCHESTRATOR_DEPENDENCY_UNAVAILABLE"}, status=503)
    app.router.add_get("/ready", ready)
    app.router.add_get("/v1/authoritative/tasks", authoritative_tasks)
    app.router.add_post(
        "/v1/actions", lambda request: json_call(request, lambda body, _: api.submit(body))
    )
    app.router.add_post("/v1/tasks/{task_id}/commands", bff_command)
    app.router.add_get("/v1/tasks/{task_id}/agui/events", agui)
    app.router.add_post(
        "/v1/actions/query",
        lambda request: json_call(
            request, lambda body, _: api.query(body["tenant_id"], body["owner"],
                                               body["action_id"])
        ),
    )
    for operation, command_type in (
        ("start", "START"), ("pause", "PAUSE"), ("resume", "RESUME"),
        ("cancel", "CANCEL"), ("kill", "KILL"), ("checkpoint", "CHECKPOINT"),
        ("verify", "VERIFY"), ("complete", "COMPLETE"),
    ):
        async def control(request: Any, kind: str = command_type) -> Any:
            return await json_call(
                request,
                lambda body, _: api.control(
                    body["tenant_id"], body["owner"], body["action_id"], kind,
                    body.get("command_id"),
                ),
            )
        app.router.add_post(f"/v1/actions/{operation}", control)
    app.router.add_post(
        "/v1/tasks/list",
        lambda request: json_call(
            request,
            lambda body, _: api.list_tasks(body["tenant_id"], body["owner"],
                                           body.get("limit", 100)),
        ),
    )
    app.router.add_post("/v1/tasks/events", bff_events)
    app.router.add_post("/v1/tasks/transitions", bff_transitions)
    app.router.add_post(
        "/v1/tasks/stream-snapshot",
        lambda request: json_call(
            request, lambda body, _: api.stream_snapshot(body["tenant_id"], body["owner"],
                                                         body["task_id"])
        ),
    )
    return app


async def run(
    address: str,
    port: int,
    database_url: str,
    database_password: str,
    temporal_address: str,
    namespace: str,
    task_queue: str,
    temporal_tls: Any,
    token_authorizer: OrchestratorTokenAuthorizer,
    agui_signing_key: Any,
    server_tls: ssl.SSLContext,
    trusted_runtime_client_identities: str,
    trusted_bff_client_identities: str,
    expected_database_role: str,
    dependency_probes: Sequence[Any],
) -> None:
    import asyncpg
    from aiohttp import web
    from temporalio.client import Client
    _validate_database_url(database_url, expected_database_role)
    if (
        not temporal_address
        or not namespace
        or not task_queue
        or not trusted_runtime_client_identities
        or not trusted_bff_client_identities
        or not expected_database_role
        or not 1 <= port <= 65535
    ):
        raise ValueError("ORCHESTRATOR_API_CONFIG_INVALID")
    if not database_password or len(database_password) > 65_536:
        raise ValueError("ORCHESTRATOR_API_CONFIG_INVALID")
    pool = await asyncpg.create_pool(
        database_url, password=database_password, min_size=2, max_size=20, command_timeout=10
    )
    role = await pool.fetchrow(
        "SELECT current_user AS role_name, rolsuper, rolbypassrls, "
        "current_setting('search_path') AS search_path, "
        "current_schemas(true)::text AS resolved_schemas "
        "FROM pg_roles WHERE rolname=current_user"
    )
    if (
        role is None
        or str(role["role_name"]) != expected_database_role
        or role["rolsuper"] is not False
        or role["rolbypassrls"] is not False
        or role["search_path"] != "pg_catalog, public"
        or role["resolved_schemas"] != "{pg_catalog,public}"
    ):
        await pool.close()
        raise ValueError("ORCHESTRATOR_DATABASE_ROLE_UNSAFE")
    temporal = await Client.connect(temporal_address, namespace=namespace, tls=temporal_tls)
    runner = web.AppRunner(create_app(
        OrchestratorApi(
            PostgresActionStore(pool), TemporalClientPort(temporal, task_queue),
            agui_signing_key, dependency_probes,
        ),
        trusted_runtime_client_identities,
        trusted_bff_client_identities,
        token_authorizer,
    ))
    await runner.setup()
    await web.TCPSite(runner, address, port, ssl_context=server_tls).start()
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
        await pool.close()


def _validate_database_url(database_url: str, expected_role: str) -> Path:
    parsed_database = urllib_parse.urlsplit(database_url)
    try:
        database_options = urllib_parse.parse_qs(
            parsed_database.query, keep_blank_values=True, strict_parsing=True
        )
    except ValueError as error:
        raise ValueError("ORCHESTRATOR_API_CONFIG_INVALID") from error
    normalized_database_options: dict[str, list[str]] = {}
    for key, values in database_options.items():
        normalized = key.lower()
        if (
            normalized in normalized_database_options
            or len(values) != 1
            or values[0] == ""
        ):
            raise ValueError("ORCHESTRATOR_API_CONFIG_INVALID")
        normalized_database_options[normalized] = values
    ssl_root_certificates = normalized_database_options.get("sslrootcert", [])
    ssl_root_certificate = (
        Path(ssl_root_certificates[0]) if len(ssl_root_certificates) == 1 else Path("")
    )
    forbidden_database_tls_options = {
        key for key in normalized_database_options
        if key.startswith("ssl") and key not in {"sslmode", "sslrootcert"}
    }
    if (
        parsed_database.scheme not in {"postgres", "postgresql"}
        or not parsed_database.hostname
        or not parsed_database.username
        or parsed_database.username != expected_role
        or parsed_database.password is not None
        or parsed_database.path in {"", "/"}
        or "/" in parsed_database.path.strip("/")
        or bool(parsed_database.fragment)
        or set(normalized_database_options) != {"sslmode", "sslrootcert", "options"}
        or normalized_database_options.get("sslmode") != ["verify-full"]
        or normalized_database_options.get("options") != ["-csearch_path=pg_catalog,public"]
        or len(ssl_root_certificates) != 1
        or not ssl_root_certificate.is_absolute()
        or not _secure_file(ssl_root_certificate, private=False)
        or forbidden_database_tls_options
    ):
        raise ValueError("ORCHESTRATOR_API_CONFIG_INVALID")
    return ssl_root_certificate


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-orchestrator-api")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args(argv)
    database_url = _read_required_secret_file("AGENT_TRUST_DATABASE_URL_FILE")
    database_password = _read_required_secret_file(
        "AGENT_TRUST_ORCHESTRATOR_DATABASE_PASSWORD_FILE"
    )
    temporal_paths = tuple(
        Path(os.environ.get(name, ""))
        for name in (
            "AGENT_TRUST_TEMPORAL_CA_FILE",
            "AGENT_TRUST_TEMPORAL_CERTIFICATE_FILE",
            "AGENT_TRUST_TEMPORAL_PRIVATE_KEY_FILE",
        )
    )
    temporal_tls = load_temporal_tls(
        *temporal_paths,
        os.environ.get("AGENT_TRUST_TEMPORAL_SERVER_NAME", ""),
    )
    server_tls = load_orchestrator_server_tls(
        Path(os.environ.get("AGENT_TRUST_ORCHESTRATOR_TLS_CA_FILE", "")),
        Path(os.environ.get("AGENT_TRUST_ORCHESTRATOR_TLS_CERTIFICATE_FILE", "")),
        Path(os.environ.get("AGENT_TRUST_ORCHESTRATOR_TLS_PRIVATE_KEY_FILE", "")),
    )
    from python.durable_worker.worker import ExecutionHttpClient, TransitionHttpClient
    transition_probe = TransitionHttpClient(
        os.environ.get("AGENT_TRUST_TRANSITION_ENDPOINT", ""),
        _read_required_secret_file("AGENT_TRUST_TRANSITION_TOKEN_FILE"),
        ca_file=Path(os.environ.get("AGENT_TRUST_TRANSITION_CA_FILE", "")),
        certificate_file=Path(
            os.environ.get("AGENT_TRUST_TRANSITION_CERTIFICATE_FILE", "")
        ),
        private_key_file=Path(
            os.environ.get("AGENT_TRUST_TRANSITION_PRIVATE_KEY_FILE", "")
        ),
        timeout_seconds=3.0,
    )
    execution_probe = ExecutionHttpClient(
        os.environ.get("AGENT_TRUST_EXECUTION_ENDPOINT", ""),
        _read_required_secret_file("AGENT_TRUST_EXECUTION_TOKEN_FILE"),
        ca_file=Path(os.environ.get("AGENT_TRUST_EXECUTION_CA_FILE", "")),
        certificate_file=Path(
            os.environ.get("AGENT_TRUST_EXECUTION_CERTIFICATE_FILE", "")
        ),
        private_key_file=Path(
            os.environ.get("AGENT_TRUST_EXECUTION_PRIVATE_KEY_FILE", "")
        ),
        timeout_seconds=3.0,
    )
    runtime_identities = os.environ.get(
        "AGENT_TRUST_ORCHESTRATOR_RUNTIME_CLIENT_IDENTITIES", ""
    )
    bff_identities = os.environ.get(
        "AGENT_TRUST_ORCHESTRATOR_BFF_CLIENT_IDENTITIES", ""
    )
    token_authorizer = OrchestratorTokenAuthorizer.from_file(
        Path(os.environ.get("AGENT_TRUST_ORCHESTRATOR_TOKEN_BINDINGS_FILE", "")),
        runtime_identities,
        bff_identities,
    )
    asyncio.run(run(
        args.listen,
        args.port,
        database_url,
        database_password,
        os.environ.get("AGENT_TRUST_TEMPORAL_ADDRESS", ""),
        os.environ.get("AGENT_TRUST_TEMPORAL_NAMESPACE", ""),
        os.environ.get("AGENT_TRUST_TEMPORAL_TASK_QUEUE", ""),
        temporal_tls,
        token_authorizer,
        load_agui_signing_key(Path(os.environ.get("AGENT_TRUST_AGUI_SIGNING_KEY_FILE", ""))),
        server_tls,
        runtime_identities,
        bff_identities,
        os.environ.get("AGENT_TRUST_ORCHESTRATOR_DATABASE_EXPECTED_ROLE", ""),
        (transition_probe, execution_probe),
    ))
    return 0


def _read_required_secret_file(environment_name: str) -> str:
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


def load_orchestrator_server_tls(
    ca_file: Path, certificate_file: Path, private_key_file: Path
) -> ssl.SSLContext:
    if (
        not _secure_file(ca_file, private=False)
        or not _secure_file(certificate_file, private=False)
        or not _secure_file(private_key_file, private=True)
    ):
        raise ValueError("ORCHESTRATOR_SERVER_TLS_CONFIG_INVALID")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(ca_file))
        context.load_cert_chain(str(certificate_file), str(private_key_file))
        # Readiness remains probeable without a client certificate; every non-readiness route
        # performs an exact SAN match after this TLS layer validates any presented chain.
        context.verify_mode = ssl.CERT_OPTIONAL
    except (OSError, ssl.SSLError) as exc:
        raise ValueError("ORCHESTRATOR_SERVER_TLS_CONFIG_INVALID") from exc
    return context


if __name__ == "__main__":
    raise SystemExit(main())
