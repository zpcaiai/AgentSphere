from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timedelta, timezone
import unittest

from python.durable_worker.orchestrator_api import (
    ActionRecord, OrchestratorApi, OrchestratorApiError, OrchestratorTokenAuthorizer,
    OrchestratorTokenBinding, _command_payload_digest, _command_receipt,
    _database_json_object,
    _peer_identity_matches, _strict_json_loads, _validate_database_url,
)


class Store:
    def __init__(self) -> None:
        self.actions: dict[tuple[str, str], ActionRecord] = {}
        self.idempotency: dict[tuple[str, str], ActionRecord] = {}
        self.envelopes: dict[tuple[str, str], dict] = {}
        self.stream: list[dict] = []
    async def admit(self, record, envelope):
        key = (record.tenant_id, record.idempotency_key)
        existing = self.idempotency.get(key)
        if existing:
            if existing.payload_hash != record.payload_hash or self.envelopes[key] != envelope:
                raise OrchestratorApiError("ORCHESTRATOR_IDEMPOTENCY_CONFLICT", 409)
            return existing, False
        self.idempotency[key] = record
        self.envelopes[key] = json.loads(json.dumps(envelope))
        self.actions[(record.tenant_id, record.action_id)] = record
        return record, True
    async def mark_workflow_started(self, tenant_id, action_id):
        record = self.actions[(tenant_id, action_id)]
        started = ActionRecord(record.tenant_id, record.action_id, record.task_id,
                               record.owner_subject, "CREATED", record.payload_hash, record.idempotency_key)
        self.actions[(tenant_id, action_id)] = started
        self.idempotency[(tenant_id, record.idempotency_key)] = started
    async def mark_start_requested(self, tenant_id, action_id):
        record = self.actions[(tenant_id, action_id)]
        started = ActionRecord(record.tenant_id, record.action_id, record.task_id,
                               record.owner_subject, "START_REQUESTED", record.payload_hash,
                               record.idempotency_key)
        self.actions[(tenant_id, action_id)] = started
        self.idempotency[(tenant_id, record.idempotency_key)] = started
    async def get(self, tenant_id, action_id):
        return self.actions.get((tenant_id, action_id))
    async def get_task(self, tenant_id, task_id):
        return next((value for value in self.actions.values()
                     if value.tenant_id == tenant_id and value.task_id == task_id), None)
    async def append_event(self, tenant_id, task_id, event):
        if not any(item.get("command_id") == event.get("command_id") for item in self.stream):
            self.stream.append(dict(event))
        persisted = next(
            item for item in self.stream
            if item.get("command_id") == event.get("command_id")
        )
        digest = hashlib.sha256(json.dumps(
            persisted, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        return {
            "schema_version": "agenttrust.command-acceptance-evidence.v1",
            "event_ref": f"orchestrator-event://{tenant_id}/{task_id}/1",
            "event_digest": digest,
        }
    async def events(self, tenant_id, task_id, limit):
        return self.stream[-limit:]
    async def event_for_command(self, tenant_id, task_id, command_id):
        return next((item for item in self.stream if item.get("command_id") == command_id), None)
    async def list_tasks(self, tenant_id, owner, limit):
        return [value for value in self.actions.values()
                if value.tenant_id == tenant_id and value.owner_subject == owner][:limit]
    async def ready(self): return True


class Temporal:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.signals: list[dict] = []
        self.cursor = 0
        self.initial_by_workflow: dict[str, dict] = {}
        self.processed: dict[str, str] = {}
        self.rejected: dict[str, str] = {}
        self.events: list[dict] = []
    async def start(self, task_id, initial, start_command):
        self.started.append(task_id)
        self.initial_by_workflow[task_id] = dict(initial)
        self.signals.append(dict(start_command))
        return True
    async def signal(self, task_id, command): self.signals.append(dict(command))
    async def signal_exact(self, task_id, command): self.signals.append(dict(command))
    async def update_exact(self, task_id, command):
        self.signals.append(dict(command))
        return {"accepted": True, "command_id": command["command_id"]}
    async def state(self, task_id): return {
        **self.initial_by_workflow[task_id],
        "status": "RUNNING", "recovery_cursor": self.cursor,
        "processed_command_fingerprints": self.processed,
        "processed_idempotency_keys": {},
        "rejected_command_fingerprints": self.rejected,
        "rejected_idempotency_keys": {},
        "events": list(self.events),
    }
    async def ready(self): return True


class OrchestratorApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.store, self.temporal = Store(), Temporal()
        class SigningKey:
            def sign(self, value):
                return hashlib.sha512(value).digest()
        self.api = OrchestratorApi(self.store, self.temporal, SigningKey())
        tenant_id = "00000000-0000-4000-8000-000000000001"
        agent_id = "00000000-0000-4000-8000-000000000004"
        now = datetime.now(timezone.utc)
        action = {
            "schema_version": "agenttrust.action.v1",
            "action_id": "00000000-0000-4000-8000-000000000002",
            "task_id": "00000000-0000-4000-8000-000000000003",
            "step_id": "00000000-0000-4000-8000-000000000005",
            "agent": {
                "schema_version": "agenttrust.contracts.v1", "agent_type": "test",
                "agent_instance_id": agent_id, "organization_id": "org:1",
                "tenant_id": tenant_id, "owner_subject": "user:1",
                "model_provider": "test", "model_id": "test", "agent_version": "1.0.0",
                "deployment_environment": "production", "trust_level": "verified",
                "auth_context_ref": "auth:1", "issued_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
            },
            "intent": {"goal_hash": "a" * 64, "operation": "read",
                       "justification_code": "TEST", "safe_summary": "test"},
            "tool": {"tool_id": "test", "tool_version": "1.0.0"},
            "payload": {"type_id": "coding.command.v1", "schema_version": "1", "data": {}},
            "resource": {"scheme": "repo", "tenant_id": tenant_id,
                         "locator": "repo/test", "version": "1"},
            "environment": {"tenant_id": tenant_id, "deployment": "production",
                            "region": "test", "zone": "test-a", "simulation": False},
            "current_state_version": "1",
            "risk": {"declared_risk": "LOW", "trajectory_risk_ref": None,
                     "scope_delta": 0, "automation_allowed": True},
            "data": {"classification": "INTERNAL", "jurisdiction": "US",
                     "export_constraints": []},
            "expected_outcome": {"metric": "read", "operator": "eq", "target": True},
            "credential_refs": [],
            "requested_at": now.isoformat(),
            "extensions": {},
        }
        payload = json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
        self.envelope = {
            "request_id": "request-1",
            "trace_context": {"trace_id": "0" * 32, "parent_span_id": None,
                              "invalid_input_replaced": False},
            "identity_context": {"subject": "agent:test", "tenant_id": tenant_id,
                                 "owner_subject": "user:1",
                                 "agent_instance_id": agent_id, "trust_level": "verified"},
            "tenant_context": {"tenant_id": tenant_id, "quota_profile": "default"},
            "protocol": "HTTP", "content_type": "application/json",
            "schema_version": "agenttrust.gateway.v1", "received_at": now.isoformat(),
            "idempotency_key": "request-1", "payload": list(payload),
            "payload_hash": hashlib.sha256(payload).hexdigest(),
        }

    async def test_admission_is_idempotent_and_starts_one_workflow(self) -> None:
        first = await self.api.submit(self.envelope)
        second = await self.api.submit(self.envelope)
        self.assertEqual(first, second)
        self.assertEqual(first["action_id"], "00000000-0000-4000-8000-000000000002")
        self.assertEqual(first["task_id"], "00000000-0000-4000-8000-000000000003")
        self.assertEqual(first["schema_version"], "agenttrust.action-acceptance.v1")
        self.assertTrue(first["execution_pending"])
        self.assertRegex(first["ingress_digest"], r"^[a-f0-9]{64}$")
        self.assertRegex(first["evidence_digest"], r"^[a-f0-9]{64}$")
        self.assertTrue(first["evidence_ref"].startswith("orchestrator-event://"))
        self.assertEqual(len(self.temporal.started), 1)
        self.assertEqual(len(self.temporal.signals), 1)
        self.assertEqual(self.temporal.signals[0]["command_type"], "START")
        self.assertEqual(
            self.temporal.started[0],
            "agenttrust:00000000-0000-4000-8000-000000000001:"
            "00000000-0000-4000-8000-000000000003",
        )

    async def test_idempotency_key_is_bound_to_the_complete_ingress_envelope(self) -> None:
        await self.api.submit(self.envelope)
        replay = json.loads(json.dumps(self.envelope))
        replay["request_id"] = "request-rebound"
        with self.assertRaisesRegex(OrchestratorApiError, "IDEMPOTENCY_CONFLICT"):
            await self.api.submit(replay)

    def test_database_json_and_command_evidence_are_scope_bound(self) -> None:
        self.assertEqual(_database_json_object('{"safe":true}'), {"safe": True})
        tenant = self.envelope["tenant_context"]["tenant_id"]
        task = "00000000-0000-4000-8000-000000000003"
        evidence = {
            "schema_version": "agenttrust.command-acceptance-evidence.v1",
            "event_ref": f"orchestrator-event://{tenant}/{task}/1",
            "event_digest": "a" * 64,
        }
        self.assertTrue(_command_receipt("command:1", tenant, task, evidence)["accepted"])
        with self.assertRaisesRegex(OrchestratorApiError, "EVENT_EVIDENCE_INVALID"):
            _command_receipt(
                "command:1",
                tenant,
                task,
                {**evidence, "event_ref": f"orchestrator-event://{tenant}/{task}/1/extra"},
            )

    async def test_temporal_workflow_identity_is_tenant_scoped(self) -> None:
        await self.api.submit(self.envelope)
        second = json.loads(json.dumps(self.envelope))
        second_tenant = "00000000-0000-4000-8000-000000000099"
        second_action = "00000000-0000-4000-8000-000000000098"
        second["request_id"] = "request-tenant-2"
        second["idempotency_key"] = "request-tenant-2"
        second["identity_context"]["tenant_id"] = second_tenant
        second["tenant_context"]["tenant_id"] = second_tenant
        action = json.loads(bytes(second["payload"]))
        action["action_id"] = second_action
        action["agent"]["tenant_id"] = second_tenant
        action["resource"]["tenant_id"] = second_tenant
        action["environment"]["tenant_id"] = second_tenant
        payload = json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
        second["payload"] = list(payload)
        second["payload_hash"] = hashlib.sha256(payload).hexdigest()
        await self.api.submit(second)
        self.assertNotEqual(self.temporal.started[0], self.temporal.started[1])
        self.assertTrue(self.temporal.started[1].startswith(f"agenttrust:{second_tenant}:"))

    async def test_owner_is_enforced_for_query_and_control(self) -> None:
        receipt = await self.api.submit(self.envelope)
        with self.assertRaisesRegex(OrchestratorApiError, "NOT_FOUND"):
            await self.api.query(self.envelope["tenant_context"]["tenant_id"], "user:2", receipt["action_id"])
        await self.api.control(self.envelope["tenant_context"]["tenant_id"], "user:1",
                               receipt["action_id"], "KILL")
        self.assertEqual(self.temporal.signals[-1]["command_type"], "KILL")

    async def test_pause_resume_listing_and_events_are_coherent(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        self.temporal.cursor = 1
        pause = await self.api.control(
            tenant, "user:1", receipt["action_id"], "PAUSE", "pause:1"
        )
        self.assertEqual(pause["command_id"], "pause:1")
        self.assertEqual(pause["schema_version"], "agenttrust.command-receipt.v1")
        self.assertTrue(pause["execution_pending"])
        self.assertTrue(pause["evidence_ref"].startswith("orchestrator-event://"))
        self.assertEqual(self.temporal.signals[-1]["expected_state_version"], 1)
        self.temporal.cursor = 2
        await self.api.control(tenant, "user:1", receipt["action_id"], "RESUME", "resume:1")
        self.assertEqual(self.temporal.signals[-1]["expected_state_version"], 2)
        listing = await self.api.list_tasks(tenant, "user:1", 10)
        self.assertEqual(listing["tasks"][0]["task_id"], receipt["task_id"])
        page = await self.api.authoritative_tasks(tenant, "user:1", "overview", 10)
        self.assertEqual(page["schema_version"], "agenttrust.authoritative-task-page.v1")
        self.assertTrue(page["authoritative"])
        self.assertEqual(page["tenant_id"], tenant)
        self.assertEqual(page["items"][0]["task_id"], receipt["task_id"])
        digest_material = dict(page)
        supplied_digest = digest_material.pop("data_digest")
        self.assertEqual(
            supplied_digest,
            hashlib.sha256(json.dumps(
                digest_material, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest(),
        )
        events = await self.api.task_events(tenant, "user:1", receipt["task_id"], 10)
        self.assertEqual([event["command_type"] for event in events["events"]],
                         ["START", "PAUSE", "RESUME"])

    async def test_legacy_control_uses_safe_cursor_and_deterministic_retry_key(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        self.temporal.cursor = 3
        first = await self.api.control(tenant, "user:1", receipt["action_id"], "KILL")
        command_id = f"kill:{receipt['action_id']}"
        self.assertEqual(first["command_id"], command_id)
        self.assertEqual(first["schema_version"], "agenttrust.command-receipt.v1")
        self.assertRegex(first["evidence_digest"], r"^[a-f0-9]{64}$")
        self.assertEqual(self.temporal.signals[-1]["expected_state_version"], 3)
        self.temporal.processed[command_id] = "authoritative-fingerprint"
        self.temporal.cursor = 4
        before_retry = len(self.temporal.signals)
        retry = await self.api.control(tenant, "user:1", receipt["action_id"], "KILL")
        self.assertEqual(retry, first)
        self.assertEqual(len(self.temporal.signals), before_retry)

    async def test_legacy_control_rejected_or_ambiguous_id_fails_closed(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        rejected_id = f"pause:{receipt['action_id']}"
        self.temporal.rejected[rejected_id] = "rejected-fingerprint"
        with self.assertRaisesRegex(OrchestratorApiError, "PREVIOUSLY_REJECTED"):
            await self.api.control(tenant, "user:1", receipt["action_id"], "PAUSE")
        self.temporal.rejected.clear()
        self.temporal.processed["caller:key"] = "processed-fingerprint"
        with self.assertRaisesRegex(
            OrchestratorApiError, "COMMAND_ACCEPTANCE_EVIDENCE_MISSING"
        ):
            await self.api.control(
                tenant, "user:1", receipt["action_id"], "PAUSE", "caller:key"
            )

    async def test_legacy_control_heals_temporal_to_postgres_crash_window(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        command_id = f"kill:{receipt['action_id']}"
        self.temporal.cursor = 4
        recovered = {
            "schema_version": "agenttrust.orchestrator-command.v1",
            "command_id": command_id,
            "request_idempotency_key": command_id,
            "tenant_id": tenant,
            "task_id": receipt["task_id"],
            "command_type": "KILL",
            "expected_state_version": 3,
            "payload_digest": _command_payload_digest("KILL"),
            "requested_by": "user:1",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        from python.durable_worker.worker import TaskCommand, command_fingerprint
        self.temporal.processed[command_id] = command_fingerprint(TaskCommand(**recovered))
        self.temporal.events = [{
            "schema_version": "agenttrust.orchestrator-state.v1",
            "event_id": "event:kill",
            "command_id": command_id,
            "from": "RUNNING",
            "to": "KILLED",
            "recovery_cursor": 4,
            "evidence_digest": "a" * 64,
            "occurred_at": "2026-08-14T00:00:00+00:00",
        }]
        self.store.stream.clear()
        before = len(self.temporal.signals)
        result = await self.api.control(
            tenant, "user:1", receipt["action_id"], "KILL"
        )
        self.assertEqual(result["schema_version"], "agenttrust.command-receipt.v1")
        self.assertEqual(len(self.temporal.signals), before)
        self.assertEqual(self.store.stream[0]["expected_state_version"], 3)

    async def test_payload_hash_and_tenant_mismatch_fail_closed(self) -> None:
        invalid = {**self.envelope, "payload_hash": "0" * 64}
        with self.assertRaisesRegex(OrchestratorApiError, "PAYLOAD_HASH_MISMATCH"):
            await self.api.submit(invalid)
        invalid = {**self.envelope, "tenant_context": {"tenant_id": "other"}}
        with self.assertRaisesRegex(OrchestratorApiError, "INGRESS_INVALID"):
            await self.api.submit(invalid)
        arbitrary = b'{"tool":"read"}'
        invalid = {
            **self.envelope,
            "idempotency_key": "arbitrary",
            "payload": list(arbitrary),
            "payload_hash": hashlib.sha256(arbitrary).hexdigest(),
        }
        with self.assertRaisesRegex(OrchestratorApiError, "ACTION_IR_INVALID"):
            await self.api.submit(invalid)

    async def test_side_effecting_action_requires_plan_and_state_bindings(self) -> None:
        side_effect = json.loads(json.dumps(self.envelope))
        action = json.loads(bytes(side_effect["payload"]))
        action["intent"]["operation"] = "write"
        action.pop("current_state_version")
        action["extensions"] = {"x-plan-hash": "b" * 64}
        payload = json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
        side_effect["payload"] = list(payload)
        side_effect["payload_hash"] = hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(OrchestratorApiError, "ACTION_IR_INVALID"):
            await self.api.submit(side_effect)

        action["current_state_version"] = "1"
        action["extensions"] = {}
        payload = json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
        side_effect["payload"] = list(payload)
        side_effect["payload_hash"] = hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(OrchestratorApiError, "ACTION_IR_INVALID"):
            await self.api.submit(side_effect)

        action["extensions"] = {"x-plan-hash": "b" * 64}
        payload = json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
        side_effect["payload"] = list(payload)
        side_effect["payload_hash"] = hashlib.sha256(payload).hexdigest()
        accepted = await self.api.submit(side_effect)
        self.assertTrue(accepted["accepted"])

    async def test_gateway_context_and_byte_payload_are_exact(self) -> None:
        unknown_identity = json.loads(json.dumps(self.envelope))
        unknown_identity["identity_context"]["caller_claim"] = "untrusted"
        with self.assertRaisesRegex(OrchestratorApiError, "INGRESS_INVALID"):
            await self.api.submit(unknown_identity)
        missing_subject = json.loads(json.dumps(self.envelope))
        del missing_subject["identity_context"]["subject"]
        with self.assertRaisesRegex(OrchestratorApiError, "INGRESS_INVALID"):
            await self.api.submit(missing_subject)
        boolean_byte = json.loads(json.dumps(self.envelope))
        boolean_byte["payload"][0] = True
        with self.assertRaisesRegex(OrchestratorApiError, "INGRESS_INVALID"):
            await self.api.submit(boolean_byte)
        unsafe_owner = json.loads(json.dumps(self.envelope))
        unsafe_owner["identity_context"]["owner_subject"] = "user:1\nforged"
        with self.assertRaisesRegex(OrchestratorApiError, "INGRESS_INVALID"):
            await self.api.submit(unsafe_owner)

    async def test_ingress_digest_uses_cross_language_utf8_canonical_json(self) -> None:
        localized = json.loads(json.dumps(self.envelope))
        action = json.loads(bytes(localized["payload"]).decode())
        action["intent"]["safe_summary"] = "生产执行闭环"
        payload = json.dumps(
            action, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        localized["payload"] = list(payload)
        localized["payload_hash"] = hashlib.sha256(payload).hexdigest()
        await self.api.submit(localized)
        workflow_id = self.temporal.started[-1]
        expected = hashlib.sha256(json.dumps(
            localized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest()
        self.assertEqual(
            self.temporal.initial_by_workflow[workflow_id]["ingress_digest"], expected
        )

    async def test_action_identity_is_bound_to_gateway_identity(self) -> None:
        invalid = {
            **self.envelope,
            "idempotency_key": "wrong-agent",
            "identity_context": {
                **self.envelope["identity_context"],
                "agent_instance_id": "00000000-0000-4000-8000-000000000099",
            },
        }
        with self.assertRaisesRegex(OrchestratorApiError, "ACTION_IDENTITY_MISMATCH"):
            await self.api.submit(invalid)

    async def test_bff_route_derives_scope_and_validates_version_and_digest(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        command = {
            "schema_version": "agenttrust.orchestrator-command.v1",
            "command_id": "pause:command",
            "command_type": "PAUSE",
            "expected_state_version": 0,
            "payload_digest": _command_payload_digest("PAUSE"),
        }
        self.temporal.cursor = 0
        result = await self.api.bff_command(
            tenant, "user:1", receipt["task_id"], command, "pause:command"
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["schema_version"], "agenttrust.command-receipt.v1")
        self.assertTrue(result["execution_pending"])
        self.assertTrue(result["evidence_ref"].startswith("orchestrator-event://"))
        self.assertRegex(result["evidence_digest"], r"^[a-f0-9]{64}$")
        self.assertEqual(self.temporal.signals[-1]["tenant_id"], tenant)
        self.assertEqual(self.temporal.signals[-1]["requested_by"], "user:1")
        self.assertEqual(
            self.temporal.signals[-1]["request_idempotency_key"], "pause:command"
        )
        retry = await self.api.bff_command(
            tenant, "user:1", receipt["task_id"], command, "pause:command"
        )
        self.assertEqual(retry["evidence_ref"], result["evidence_ref"])
        self.assertEqual(retry["evidence_digest"], result["evidence_digest"])
        with self.assertRaisesRegex(OrchestratorApiError, "COMMAND_INVALID"):
            await self.api.bff_command(
                tenant, "user:1", receipt["task_id"],
                {**command, "payload_digest": "invalid"}, "pause:command"
            )
        with self.assertRaisesRegex(OrchestratorApiError, "NOT_FOUND"):
            await self.api.bff_command(
                tenant, "operator:1", receipt["task_id"], command, "another:key"
            )

    async def test_service_auth_and_agui_resume_fail_closed(self) -> None:
        tenant = self.envelope["tenant_context"]["tenant_id"]
        authorizer = OrchestratorTokenAuthorizer([
            OrchestratorTokenBinding(
                "URI:spiffe://agenttrust/runtime", tenant, "runtime", "orchestrator:runtime",
                hashlib.sha256(b"service-token").hexdigest(),
            ),
            OrchestratorTokenBinding(
                "URI:spiffe://agenttrust/control-api", tenant, "bff", "orchestrator:read",
                hashlib.sha256(b"read-token").hexdigest(),
            ),
        ], frozenset({"URI:spiffe://agenttrust/runtime"}),
           frozenset({"URI:spiffe://agenttrust/control-api"}))
        with self.assertRaisesRegex(OrchestratorApiError, "UNAUTHENTICATED"):
            authorizer.authorize("URI:spiffe://agenttrust/runtime", tenant,
                                 "orchestrator:runtime", None)
        self.assertEqual("runtime", authorizer.authorize(
            "URI:spiffe://agenttrust/runtime", tenant, "orchestrator:runtime",
            "Bearer service-token"))
        with self.assertRaisesRegex(ValueError, "TOKEN_BINDINGS_INVALID"):
            OrchestratorTokenAuthorizer([
                OrchestratorTokenBinding(
                    "URI:spiffe://agenttrust/runtime", tenant, "runtime",
                    "orchestrator:runtime", hashlib.sha256(b"runtime-unique").hexdigest(),
                ),
                OrchestratorTokenBinding(
                    "URI:spiffe://agenttrust/control-api", tenant, "bff",
                    "orchestrator:read", hashlib.sha256(b"reused").hexdigest(),
                ),
                OrchestratorTokenBinding(
                    "URI:spiffe://agenttrust/control-api", tenant, "bff",
                    "orchestrator:command", hashlib.sha256(b"reused").hexdigest(),
                ),
            ], frozenset({"URI:spiffe://agenttrust/runtime"}),
               frozenset({"URI:spiffe://agenttrust/control-api"}))
        receipt = await self.api.submit(self.envelope)
        self.temporal.state = lambda task_id: _async_value({
            **self.temporal.initial_by_workflow[task_id],
            "status": "RUNNING", "recovery_cursor": 1, "terminal": False,
            "events": [{"schema_version": "agenttrust.orchestrator-state.v1",
                        "event_id": "event:1", "command_id": "start:1", "from": "CREATED",
                        "to": "RUNNING", "recovery_cursor": 1,
                        "evidence_digest": "a" * 64,
                        "occurred_at": "2026-08-13T00:00:00+00:00"}],
        })
        result = await self.api.agui_events(tenant, "user:1", receipt["task_id"], None, 100)
        self.assertEqual(result["events"][0]["sequence"], 1)
        self.assertEqual(result["events"][0]["tenant_id"], tenant)
        self.assertEqual(result["events"][0]["occurred_at"], "2026-08-13T00:00:00+00:00")
        self.assertGreaterEqual(len(result["events"][0]["backend_signature"]), 16)
        with self.assertRaisesRegex(OrchestratorApiError, "RESUME_TOKEN_AHEAD"):
            await self.api.agui_events(tenant, "user:1", receipt["task_id"], "2", 100)

    async def test_agui_reports_compacted_cursor_gap(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        self.temporal.state = lambda task_id: _async_value({
            **self.temporal.initial_by_workflow[task_id],
            "status": "RUNNING", "recovery_cursor": 7, "terminal": False,
            "events": [{"schema_version": "agenttrust.orchestrator-state.v1",
                        "event_id": "event:7", "command_id": "checkpoint:7",
                        "from": "RUNNING", "to": "RUNNING", "recovery_cursor": 7,
                        "evidence_digest": "a" * 64,
                        "occurred_at": "2026-08-13T00:00:00+00:00"}],
        })
        result = await self.api.agui_events(tenant, "user:1", receipt["task_id"], "2", 100)
        self.assertTrue(result["safe_snapshot_required"])

    async def test_authoritative_transitions_cannot_be_evicted_by_rejection_audit(self) -> None:
        receipt = await self.api.submit(self.envelope)
        tenant = self.envelope["tenant_context"]["tenant_id"]
        transition = {
            "schema_version": "agenttrust.orchestrator-state.v1",
            "event_id": "event:completed", "command_id": "complete:1",
            "from": "VERIFYING", "to": "COMPLETED", "recovery_cursor": 1,
            "evidence_digest": "b" * 64,
            "occurred_at": "2026-08-13T00:00:00+00:00",
        }
        self.temporal.state = lambda task_id: _async_value({
            **self.temporal.initial_by_workflow[task_id],
            "status": "COMPLETED", "recovery_cursor": 1, "terminal": True,
            "events": [transition],
            "command_rejections": [
                {"command_id": f"rejected:{index}"} for index in range(1024)
            ],
        })
        result = await self.api.task_transitions(
            tenant, "user:1", receipt["task_id"], 1000
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["recovery_cursor"], 1)
        self.assertEqual(result["transitions"], [transition])
        self.assertEqual(result["evidence_digest"], "b" * 64)

    def test_trusted_proxy_identity_is_exact_san_match(self) -> None:
        certificate = {"subjectAltName": (("URI", "spiffe://agenttrust/control-api"),)}
        self.assertTrue(_peer_identity_matches(
            certificate, "URI:spiffe://agenttrust/control-api"
        ))
        self.assertTrue(_peer_identity_matches(
            certificate,
            "URI:spiffe://agenttrust/runtime, URI:spiffe://agenttrust/control-api",
        ))
        self.assertFalse(_peer_identity_matches(
            certificate, "URI:spiffe://agenttrust/control"
        ))
        self.assertFalse(_peer_identity_matches(
            {"subjectAltName": (
                ("DNS", "enterprise-control-api.agenttrust.svc"),
                ("URI", "spiffe://agenttrust/control-api"),
            )},
            "DNS:enterprise-control-api.agenttrust.svc,URI:spiffe://agenttrust/control-api",
        ))

    def test_http_json_body_rejects_duplicate_control_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "DUPLICATE_KEY"):
            _strict_json_loads(
                '{"command_id":"safe","command_type":"PAUSE",'
                '"command_type":"KILL"}'
            )

    @unittest.skipUnless(os.name == "posix", "POSIX permission contract")
    def test_database_url_rejects_case_folded_tls_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "database-ca.pem"
            ca.write_text("certificate", encoding="utf-8")
            ca.chmod(0o440)
            valid = (
                "postgresql://orchestrator_app@database.example/agenttrust?sslmode=verify-full"
                f"&sslrootcert={ca}&options=-csearch_path%3Dpg_catalog%2Cpublic"
            )
            self.assertEqual(_validate_database_url(valid, "orchestrator_app"), ca)
            with self.assertRaisesRegex(ValueError, "API_CONFIG_INVALID"):
                _validate_database_url(f"{valid}&SSLMode=disable", "orchestrator_app")
            with self.assertRaisesRegex(ValueError, "API_CONFIG_INVALID"):
                _validate_database_url(f"{valid}&sslhostnameverifier=allow_all",
                                       "orchestrator_app")
            with self.assertRaisesRegex(ValueError, "API_CONFIG_INVALID"):
                _validate_database_url(valid.replace(
                    "-csearch_path%3Dpg_catalog%2Cpublic", "-csearch_path%3Dpublic"
                ), "orchestrator_app")
            with self.assertRaisesRegex(ValueError, "API_CONFIG_INVALID"):
                _validate_database_url(f"{valid}&OPTIONS=-csearch_path%3Devil%2Cpublic",
                                       "orchestrator_app")
            with self.assertRaisesRegex(ValueError, "API_CONFIG_INVALID"):
                _validate_database_url(valid.replace("orchestrator_app@",
                    "orchestrator_app:embedded@"), "orchestrator_app")


async def _async_value(value):
    return value


if __name__ == "__main__":
    unittest.main()
