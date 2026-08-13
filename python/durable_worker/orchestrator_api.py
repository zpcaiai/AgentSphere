"""Production ingress API backed by PostgreSQL and multi-zone Temporal.

The API performs durable admission/idempotency and starts or signals workflows. Security
decisions and authoritative state transitions remain in the Rust transition service.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Protocol, Sequence
import uuid


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


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


class ActionStore(Protocol):
    async def admit(self, record: ActionRecord, envelope: Mapping[str, Any]) -> tuple[ActionRecord, bool]: ...
    async def mark_workflow_started(self, tenant_id: str, action_id: str) -> None: ...
    async def get(self, tenant_id: str, action_id: str) -> ActionRecord | None: ...
    async def get_task(self, tenant_id: str, task_id: str) -> ActionRecord | None: ...
    async def append_event(self, tenant_id: str, task_id: str, event: Mapping[str, Any]) -> None: ...
    async def events(self, tenant_id: str, task_id: str, limit: int) -> list[Mapping[str, Any]]: ...
    async def ready(self) -> bool: ...


class TemporalPort(Protocol):
    async def start(self, task_id: str, initial: Mapping[str, Any]) -> None: ...
    async def signal(self, task_id: str, command: Mapping[str, Any]) -> None: ...
    async def state(self, task_id: str) -> Mapping[str, Any]: ...
    async def ready(self) -> bool: ...


class OrchestratorApi:
    def __init__(self, store: ActionStore, temporal: TemporalPort) -> None:
        self._store = store
        self._temporal = temporal

    async def ready(self) -> Mapping[str, Any]:
        ready = await self._store.ready() and await self._temporal.ready()
        if not ready:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_READY", 503)
        return {"ready": True}

    async def submit(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        identity = envelope.get("identity_context")
        tenant = envelope.get("tenant_context")
        idempotency_key = envelope.get("idempotency_key")
        payload_hash = envelope.get("payload_hash")
        if (
            not isinstance(identity, dict) or not isinstance(tenant, dict)
            or not isinstance(idempotency_key, str) or not _TOKEN.fullmatch(idempotency_key)
            or not isinstance(payload_hash, str) or not _DIGEST.fullmatch(payload_hash)
            or tenant.get("tenant_id") != identity.get("tenant_id")
            or not isinstance(identity.get("owner_subject"), str) or not identity["owner_subject"]
        ):
            raise OrchestratorApiError("ORCHESTRATOR_INGRESS_INVALID")
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(bytes(envelope.get("payload", []))).hexdigest() != payload_hash:
            raise OrchestratorApiError("ORCHESTRATOR_PAYLOAD_HASH_MISMATCH")
        record = ActionRecord(
            str(tenant["tenant_id"]), str(uuid.uuid4()), str(uuid.uuid4()),
            str(identity["owner_subject"]), "PENDING_WORKFLOW", payload_hash, idempotency_key,
        )
        admitted, created = await self._store.admit(record, envelope)
        if created or admitted.status == "PENDING_WORKFLOW":
            await self._temporal.start(admitted.task_id, {
                "schema_version": "agenttrust.orchestrator-state.v1",
                "tenant_id": admitted.tenant_id, "task_id": admitted.task_id,
                "action_id": admitted.action_id, "status": "CREATED",
                "recovery_cursor": 0, "terminal": False, "evidence_refs": [],
                "ingress_digest": hashlib.sha256(canonical).hexdigest(),
            })
            await self._store.mark_workflow_started(admitted.tenant_id, admitted.action_id)
        return {"action_id": admitted.action_id, "task_id": admitted.task_id, "accepted": True}

    async def query(self, tenant_id: str, owner: str, action_id: str) -> Mapping[str, Any]:
        record = await self._store.get(tenant_id, action_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        state = await self._temporal.state(record.task_id)
        status = state.get("status")
        if not isinstance(status, str) or not status:
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        return {"action_id": record.action_id, "task_id": record.task_id, "status": record.status,
                "owner_subject": record.owner_subject, "tenant_id": record.tenant_id} | {"status": status}

    async def control(self, tenant_id: str, owner: str, action_id: str, command_type: str) -> Mapping[str, Any]:
        record = await self._store.get(tenant_id, action_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        if command_type not in {"CANCEL", "KILL"}:
            raise OrchestratorApiError("ORCHESTRATOR_COMMAND_INVALID")
        command = {"schema_version": "agenttrust.orchestrator-command.v1",
                   "command_id": str(uuid.uuid4()), "tenant_id": tenant_id,
                   "task_id": record.task_id, "command_type": command_type,
                   "expected_state_version": 0, "payload_digest": "0" * 64}
        await self._temporal.signal(record.task_id, command)
        await self._store.append_event(tenant_id, record.task_id, command)
        return {"accepted": True}

    async def stream_snapshot(self, tenant_id: str, owner: str, task_id: str) -> Mapping[str, Any]:
        record = await self._store.get_task(tenant_id, task_id)
        if record is None or record.owner_subject != owner:
            raise OrchestratorApiError("ORCHESTRATOR_NOT_FOUND", 404)
        events = await self._store.events(tenant_id, task_id, 1000)
        safe = [json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events]
        return {"events": safe}


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
                    if existing["payload_hash"] != record.payload_hash:
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

    async def append_event(self, tenant_id: str, task_id: str, event: Mapping[str, Any]) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                await connection.execute("INSERT INTO orchestrator_stream_events(tenant_id,task_id,event) VALUES($1::uuid,$2::uuid,$3::jsonb)",
                                         tenant_id, task_id, json.dumps(event))

    async def events(self, tenant_id: str, task_id: str, limit: int) -> list[Mapping[str, Any]]:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id',$1,true)", tenant_id)
                rows = await connection.fetch("SELECT event FROM orchestrator_stream_events WHERE tenant_id=$1::uuid AND task_id=$2::uuid ORDER BY sequence DESC LIMIT $3",
                                              tenant_id, task_id, limit)
                return [dict(row["event"]) for row in reversed(rows)]

    async def ready(self) -> bool:
        try:
            return await self._pool.fetchval("SELECT 1") == 1
        except Exception:
            return False


class TemporalClientPort:
    def __init__(self, client: Any, task_queue: str) -> None:
        self._client, self._task_queue = client, task_queue
    async def start(self, task_id: str, initial: Mapping[str, Any]) -> None:
        from python.durable_worker.worker import TaskWorkflow
        try:
            await self._client.start_workflow(TaskWorkflow.run, initial, id=task_id,
                                              task_queue=self._task_queue)
        except Exception as error:
            from temporalio.client import WorkflowAlreadyStartedError
            if not isinstance(error, WorkflowAlreadyStartedError):
                raise
    async def signal(self, task_id: str, command: Mapping[str, Any]) -> None:
        handle = self._client.get_workflow_handle(task_id)
        state = await self.state(task_id)
        if not isinstance(state, dict) or not isinstance(state.get("recovery_cursor"), int):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        versioned = {**command, "expected_state_version": state["recovery_cursor"]}
        await handle.signal("command", versioned)
    async def state(self, task_id: str) -> Mapping[str, Any]:
        value = await self._client.get_workflow_handle(task_id).query("state")
        if not isinstance(value, dict):
            raise OrchestratorApiError("ORCHESTRATOR_WORKFLOW_STATE_INVALID", 503)
        return value
    async def ready(self) -> bool:
        try:
            from temporalio.api.workflowservice.v1 import GetSystemInfoRequest
            await self._client.workflow_service.get_system_info(GetSystemInfoRequest())
            return True
        except Exception:
            return False


def _record(row: Mapping[str, Any]) -> ActionRecord:
    return ActionRecord(*(str(row[key]) for key in (
        "tenant_id", "action_id", "task_id", "owner_subject", "status", "payload_hash", "idempotency_key")))


def create_app(api: OrchestratorApi) -> Any:
    from aiohttp import web
    async def json_call(request: Any, operation: Any) -> Any:
        try:
            body = await request.json(loads=json.loads)
            return web.json_response(await operation(body))
        except OrchestratorApiError as error:
            return web.json_response({"error": str(error)}, status=error.status)
        except (json.JSONDecodeError, ValueError, TypeError):
            return web.json_response({"error": "ORCHESTRATOR_REQUEST_INVALID"}, status=400)
    app = web.Application(client_max_size=1_048_576)
    async def ready(_: Any) -> Any:
        try:
            return web.json_response(await api.ready())
        except OrchestratorApiError as error:
            return web.json_response({"ready": False, "error": str(error)}, status=error.status)
    app.router.add_get("/ready", ready)
    app.router.add_post("/v1/actions", lambda request: json_call(request, api.submit))
    app.router.add_post("/v1/actions/query", lambda request: json_call(request, lambda b: api.query(b["tenant_id"], b["owner"], b["action_id"])))
    app.router.add_post("/v1/actions/cancel", lambda request: json_call(request, lambda b: api.control(b["tenant_id"], b["owner"], b["action_id"], "CANCEL")))
    app.router.add_post("/v1/actions/kill", lambda request: json_call(request, lambda b: api.control(b["tenant_id"], b["owner"], b["action_id"], "KILL")))
    app.router.add_post("/v1/tasks/stream-snapshot", lambda request: json_call(request, lambda b: api.stream_snapshot(b["tenant_id"], b["owner"], b["task_id"])))
    return app


async def run(address: str, port: int, database_url: str, temporal_address: str,
              namespace: str, task_queue: str) -> None:
    import asyncpg
    from aiohttp import web
    from temporalio.client import Client
    if not database_url.startswith("postgresql") or not temporal_address or not namespace or not task_queue:
        raise ValueError("ORCHESTRATOR_API_CONFIG_INVALID")
    pool = await asyncpg.create_pool(database_url, min_size=2, max_size=20, command_timeout=10)
    temporal = await Client.connect(temporal_address, namespace=namespace)
    runner = web.AppRunner(create_app(OrchestratorApi(PostgresActionStore(pool), TemporalClientPort(temporal, task_queue))))
    await runner.setup()
    await web.TCPSite(runner, address, port).start()
    await asyncio.Event().wait()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-orchestrator-api")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args(argv)
    asyncio.run(run(args.listen, args.port, os.environ.get("AGENT_TRUST_DATABASE_URL", ""),
                    os.environ.get("AGENT_TRUST_TEMPORAL_ADDRESS", ""),
                    os.environ.get("AGENT_TRUST_TEMPORAL_NAMESPACE", ""),
                    os.environ.get("AGENT_TRUST_TEMPORAL_TASK_QUEUE", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
