"""Persistent Campaign API and isolated-executor worker."""

from __future__ import annotations

import argparse
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import ssl
import threading
from typing import Any, Callable, Mapping, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request
import uuid

from .campaign import CampaignRunner, CompiledScenario, compile_scenario


class CampaignRepository:
    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("CAMPAIGN_DATABASE_PATH_INVALID")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS scenarios(
                  scenario_id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                CREATE TABLE IF NOT EXISTS campaigns(
                  campaign_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
                  scenario_ids TEXT NOT NULL, policy_digest TEXT NOT NULL, pack_digest TEXT NOT NULL,
                  environment TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
                  report TEXT, safe_error_code TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            """)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def register_scenario(self, value: Mapping[str, Any]) -> CompiledScenario:
        scenario = compile_scenario(value)
        payload = json.dumps(scenario.source, sort_keys=True, separators=(",", ":"))
        with self._lock, self._connect() as connection:
            existing = connection.execute("SELECT digest FROM scenarios WHERE scenario_id=?", (scenario.scenario_id,)).fetchone()
            if existing and existing[0] != scenario.digest:
                raise ValueError("CAMPAIGN_SCENARIO_CONFLICT")
            connection.execute("INSERT OR IGNORE INTO scenarios(scenario_id,digest,payload) VALUES(?,?,?)",
                (scenario.scenario_id, scenario.digest, payload))
        return scenario

    def create_campaign(self, *, scenario_ids: Sequence[str], policy_digest: str, pack_digest: str,
                        environment: str, idempotency_key: str) -> str:
        if (not scenario_ids or len(scenario_ids) > 1000 or len(set(scenario_ids)) != len(scenario_ids)
            or len(idempotency_key) < 16 or len(idempotency_key) > 128
            or not all(len(value) == 64 and all(c in "0123456789abcdef" for c in value)
                       for value in (policy_digest, pack_digest))
            or environment not in {"isolated-test", "sandbox"}):
            raise ValueError("CAMPAIGN_REQUEST_INVALID")
        with self._lock, self._connect() as connection:
            found = {row[0] for row in connection.execute(
                f"SELECT scenario_id FROM scenarios WHERE scenario_id IN ({','.join('?' for _ in scenario_ids)})", tuple(scenario_ids))}
            if found != set(scenario_ids):
                raise ValueError("CAMPAIGN_SCENARIO_NOT_FOUND")
            existing = connection.execute("SELECT campaign_id,scenario_ids,policy_digest,pack_digest,environment FROM campaigns WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            encoded_ids = json.dumps(list(scenario_ids), separators=(",", ":"))
            if existing:
                if tuple(existing[1:]) == (encoded_ids, policy_digest, pack_digest, environment):
                    return str(existing[0])
                raise ValueError("CAMPAIGN_IDEMPOTENCY_CONFLICT")
            campaign_id = str(uuid.uuid4())
            connection.execute("INSERT INTO campaigns(campaign_id,idempotency_key,scenario_ids,policy_digest,pack_digest,environment,status) VALUES(?,?,?,?,?,?,?)",
                (campaign_id, idempotency_key, encoded_ids, policy_digest, pack_digest, environment, "QUEUED"))
            return campaign_id

    def claim_next(self) -> tuple[str, list[CompiledScenario], str, str, str] | None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT campaign_id,scenario_ids,policy_digest,pack_digest,environment FROM campaigns WHERE status='QUEUED' ORDER BY created_at LIMIT 1").fetchone()
            if row is None:
                connection.commit()
                return None
            updated = connection.execute("UPDATE campaigns SET status='RUNNING',updated_at=CURRENT_TIMESTAMP WHERE campaign_id=? AND status='QUEUED'", (row[0],)).rowcount
            if updated != 1:
                connection.rollback()
                return None
            scenarios = []
            for scenario_id in json.loads(row[1]):
                payload = connection.execute("SELECT payload FROM scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
                if payload is None:
                    connection.rollback()
                    raise RuntimeError("CAMPAIGN_SCENARIO_DISAPPEARED")
                scenarios.append(compile_scenario(json.loads(payload[0])))
            connection.commit()
            return str(row[0]), scenarios, str(row[2]), str(row[3]), str(row[4])

    def complete(self, campaign_id: str, report: Mapping[str, Any]) -> None:
        encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
        with self._lock, self._connect() as connection:
            if connection.execute("UPDATE campaigns SET status='COMPLETED',report=?,updated_at=CURRENT_TIMESTAMP WHERE campaign_id=? AND status='RUNNING'", (encoded, campaign_id)).rowcount != 1:
                raise RuntimeError("CAMPAIGN_STATE_CONFLICT")

    def fail(self, campaign_id: str, code: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE campaigns SET status='FAILED',safe_error_code=?,updated_at=CURRENT_TIMESTAMP WHERE campaign_id=? AND status='RUNNING'", (code, campaign_id))

    def get(self, campaign_id: str) -> Mapping[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT campaign_id,status,report,safe_error_code FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if row is None:
            raise KeyError("CAMPAIGN_NOT_FOUND")
        return {"schema_version":"agenttrust.security-campaign-status.v1","campaign_id":row[0],
            "status":row[1],"report":json.loads(row[2]) if row[2] else None,"safe_error_code":row[3]}


class CampaignWorker:
    def __init__(self, repository: CampaignRepository,
                 executor: Callable[[CompiledScenario], Mapping[str, Any]]) -> None:
        self._repository = repository
        self._executor = executor

    def run_once(self) -> bool:
        item = self._repository.claim_next()
        if item is None:
            return False
        campaign_id, scenarios, policy, pack, environment = item
        try:
            report = CampaignRunner(self._executor).run(scenarios, policy_digest=policy,
                pack_digest=pack, environment=environment)
            self._repository.complete(campaign_id, report)
        except Exception:
            self._repository.fail(campaign_id, "CAMPAIGN_EXECUTION_FAILED")
        return True


class IsolatedExecutorClient:
    def __init__(self, endpoint: str, token: str, timeout: float = 30.0) -> None:
        if not endpoint.startswith("https://") or not token or timeout <= 0:
            raise ValueError("CAMPAIGN_EXECUTOR_CONFIG_INVALID")
        self._endpoint, self._token, self._timeout = endpoint, token, timeout
        self._context = ssl.create_default_context()

    def __call__(self, scenario: CompiledScenario) -> Mapping[str, Any]:
        request = urllib_request.Request(self._endpoint, method="POST",
            data=json.dumps(scenario.source, sort_keys=True, separators=(",", ":")).encode(),
            headers={"Authorization":f"Bearer {self._token}","Content-Type":"application/json",
                "Idempotency-Key":scenario.digest})
        try:
            with urllib_request.urlopen(request, timeout=self._timeout, context=self._context) as response:
                raw = response.read(1_048_577)
        except (urllib_error.URLError, TimeoutError) as exc:
            raise ConnectionError("CAMPAIGN_EXECUTOR_UNAVAILABLE") from exc
        if len(raw) > 1_048_576:
            raise ValueError("CAMPAIGN_EXECUTOR_RESPONSE_TOO_LARGE")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("CAMPAIGN_EXECUTOR_RESPONSE_INVALID")
        return value


def serve(repository: CampaignRepository, token: str, host: str, port: int) -> None:
    if not token or host not in {"127.0.0.1", "::1"} or not 1 <= port <= 65535:
        raise ValueError("CAMPAIGN_API_CONFIG_INVALID")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentTrustCampaignAPI/1"

        def _authorized(self) -> bool:
            return hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}")

        def _json(self, status: HTTPStatus, value: Mapping[str, Any]) -> None:
            body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Mapping[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 2_000_000:
                raise ValueError("CAMPAIGN_BODY_SIZE_INVALID")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ValueError("CAMPAIGN_BODY_INVALID")
            return value

        def do_POST(self) -> None:
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"code":"CAMPAIGN_UNAUTHORIZED"}); return
            try:
                value = self._body()
                if self.path == "/v1/scenarios":
                    scenario = repository.register_scenario(value)
                    self._json(HTTPStatus.CREATED, {"scenario_id":scenario.scenario_id,"digest":scenario.digest}); return
                if self.path == "/v1/campaigns":
                    campaign_id = repository.create_campaign(scenario_ids=value["scenario_ids"],
                        policy_digest=value["policy_digest"],pack_digest=value["pack_digest"],
                        environment=value["environment"],idempotency_key=self.headers.get("Idempotency-Key", ""))
                    self._json(HTTPStatus.ACCEPTED, {"campaign_id":campaign_id,"status":"QUEUED"}); return
                self._json(HTTPStatus.NOT_FOUND, {"code":"CAMPAIGN_ROUTE_NOT_FOUND"})
            except (ValueError, KeyError, json.JSONDecodeError):
                self._json(HTTPStatus.BAD_REQUEST, {"code":"CAMPAIGN_REQUEST_INVALID"})

        def do_GET(self) -> None:
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"code":"CAMPAIGN_UNAUTHORIZED"}); return
            prefix = "/v1/campaigns/"
            try:
                if not self.path.startswith(prefix): raise KeyError
                self._json(HTTPStatus.OK, repository.get(self.path[len(prefix):]))
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"code":"CAMPAIGN_NOT_FOUND"})

        def log_message(self, format: str, *args: Any) -> None:
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-campaign-api")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8093)
    args = parser.parse_args(argv)
    token = __import__("os").environ.get("AGENT_TRUST_CAMPAIGN_API_TOKEN", "")
    serve(CampaignRepository(args.database), token, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
