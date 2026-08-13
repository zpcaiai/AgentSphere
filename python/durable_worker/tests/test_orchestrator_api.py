from __future__ import annotations

import hashlib
import unittest

from python.durable_worker.orchestrator_api import ActionRecord, OrchestratorApi, OrchestratorApiError


class Store:
    def __init__(self) -> None:
        self.actions: dict[tuple[str, str], ActionRecord] = {}
        self.idempotency: dict[tuple[str, str], ActionRecord] = {}
        self.stream: list[dict] = []
    async def admit(self, record, envelope):
        key = (record.tenant_id, record.idempotency_key)
        existing = self.idempotency.get(key)
        if existing:
            if existing.payload_hash != record.payload_hash:
                raise OrchestratorApiError("ORCHESTRATOR_IDEMPOTENCY_CONFLICT", 409)
            return existing, False
        self.idempotency[key] = record
        self.actions[(record.tenant_id, record.action_id)] = record
        return record, True
    async def mark_workflow_started(self, tenant_id, action_id):
        record = self.actions[(tenant_id, action_id)]
        started = ActionRecord(record.tenant_id, record.action_id, record.task_id,
                               record.owner_subject, "CREATED", record.payload_hash, record.idempotency_key)
        self.actions[(tenant_id, action_id)] = started
        self.idempotency[(tenant_id, record.idempotency_key)] = started
    async def get(self, tenant_id, action_id):
        return self.actions.get((tenant_id, action_id))
    async def get_task(self, tenant_id, task_id):
        return next((value for value in self.actions.values()
                     if value.tenant_id == tenant_id and value.task_id == task_id), None)
    async def append_event(self, tenant_id, task_id, event):
        self.stream.append(dict(event))
    async def events(self, tenant_id, task_id, limit):
        return self.stream[-limit:]
    async def ready(self): return True


class Temporal:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.signals: list[dict] = []
    async def start(self, task_id, initial): self.started.append(task_id)
    async def signal(self, task_id, command): self.signals.append(dict(command))
    async def state(self, task_id): return {"status": "RUNNING", "recovery_cursor": 0}
    async def ready(self): return True


class OrchestratorApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.store, self.temporal = Store(), Temporal()
        self.api = OrchestratorApi(self.store, self.temporal)
        payload = b'{"tool":"read"}'
        self.envelope = {
            "identity_context": {"tenant_id": "00000000-0000-4000-8000-000000000001",
                                 "owner_subject": "user:1"},
            "tenant_context": {"tenant_id": "00000000-0000-4000-8000-000000000001"},
            "idempotency_key": "request-1", "payload": list(payload),
            "payload_hash": hashlib.sha256(payload).hexdigest(),
        }

    async def test_admission_is_idempotent_and_starts_one_workflow(self) -> None:
        first = await self.api.submit(self.envelope)
        second = await self.api.submit(self.envelope)
        self.assertEqual(first, second)
        self.assertEqual(len(self.temporal.started), 1)

    async def test_owner_is_enforced_for_query_and_control(self) -> None:
        receipt = await self.api.submit(self.envelope)
        with self.assertRaisesRegex(OrchestratorApiError, "NOT_FOUND"):
            await self.api.query(self.envelope["tenant_context"]["tenant_id"], "user:2", receipt["action_id"])
        await self.api.control(self.envelope["tenant_context"]["tenant_id"], "user:1",
                               receipt["action_id"], "KILL")
        self.assertEqual(self.temporal.signals[0]["command_type"], "KILL")

    async def test_payload_hash_and_tenant_mismatch_fail_closed(self) -> None:
        invalid = {**self.envelope, "payload_hash": "0" * 64}
        with self.assertRaisesRegex(OrchestratorApiError, "PAYLOAD_HASH_MISMATCH"):
            await self.api.submit(invalid)
        invalid = {**self.envelope, "tenant_context": {"tenant_id": "other"}}
        with self.assertRaisesRegex(OrchestratorApiError, "INGRESS_INVALID"):
            await self.api.submit(invalid)


if __name__ == "__main__":
    unittest.main()
