#!/usr/bin/env python3
"""Statically validate the immutable production migration set and RLS closure."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
MANIFEST = MIGRATIONS / "manifest.txt"
PATH = re.compile(r"^[A-Za-z0-9._/-]+\.sql$")


def fail(code: str) -> None:
    raise RuntimeError(code)


def main() -> int:
    entries = [
        line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    discovered = {
        path.relative_to(MIGRATIONS).as_posix() for path in MIGRATIONS.rglob("*.sql")
    }
    if len(entries) != len(set(entries)) or set(entries) != discovered:
        fail("MIGRATION_MANIFEST_SET_MISMATCH")
    if any(not PATH.fullmatch(value) or ".." in value for value in entries):
        fail("MIGRATION_MANIFEST_PATH_INVALID")
    versions = [int(Path(value).name[:4]) for value in entries]
    if versions != sorted(versions):
        fail("MIGRATION_MANIFEST_ORDER_INVALID")
    if entries[-1] != "production-closure/0036_02_global_tenant_isolation.sql":
        fail("GLOBAL_TENANT_ISOLATION_NOT_LAST")
    if entries.index("transaction-ledger/0001_transaction_ledger.sql") > entries.index(
        "transaction-ledger/0003_transaction_ledger_inbox_tenant.sql"
    ):
        fail("LEDGER_TENANT_MIGRATION_ORDER_INVALID")
    if entries.index("orchestrator/0029_durable_orchestrator.sql") > entries.index(
        "orchestrator/0029_03_orchestrator_rls.sql"
    ):
        fail("ORCHESTRATOR_RLS_ORDER_INVALID")
    if entries.index("enterprise-control/0035_03_remote_action_closure.sql") > entries.index(
        "enterprise-control/0035_04_spring_session.sql"
    ):
        fail("ENTERPRISE_SESSION_MIGRATION_ORDER_INVALID")

    source = "\n".join((MIGRATIONS / value).read_text(encoding="utf-8") for value in entries)
    upper = source.upper()
    if "DISABLE ROW LEVEL SECURITY" in upper or re.search(r"DROP\s+(?:TABLE|SCHEMA)", upper):
        fail("MIGRATION_DESTRUCTIVE_OR_RLS_BYPASS")
    if not re.search(
        r"enterprise_remote_actions\s*\(.*?PRIMARY KEY \(tenant_id, action_id\).*?UNIQUE \(tenant_id, idempotency_key\)",
        source, re.DOTALL,
    ):
        fail("REMOTE_ACTION_IDEMPOTENCY_BINDING_MISSING")
    if not re.search(
        r"enterprise_approval_intents\s*\(.*?intent_digest char\(64\).*?case_id uuid NOT NULL.*?PRIMARY KEY \(tenant_id, idempotency_key\)",
        source, re.DOTALL,
    ):
        fail("APPROVAL_INTENT_IDEMPOTENCY_BINDING_MISSING")
    for required in (
        "ALTER TABLE %I FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation",
        "enterprise_remote_actions",
        "enterprise_approval_intents",
        "FOREIGN KEY (tenant_id, case_id) REFERENCES approval_cases (tenant_id, case_id)",
        "execution_attempts ADD COLUMN IF NOT EXISTS tenant_id",
        "execution_outbox ADD COLUMN IF NOT EXISTS tenant_id",
        "execution_inbox ADD COLUMN IF NOT EXISTS tenant_id",
        "FOREIGN KEY (tenant_id, execution_id)\n      REFERENCES executions (tenant_id, execution_id)",
        "FOREIGN KEY (tenant_id, forward_execution_id)\n      REFERENCES executions (tenant_id, execution_id)",
        "LEDGER_INBOX_TENANT_BACKFILL_REQUIRED",
        "orchestrator_tasks",
        "orchestrator_steps",
        "orchestrator_commands",
        "spring_session",
        "spring_session_attributes",
    ):
        if required not in source:
            fail(f"MIGRATION_REQUIRED_CLOSURE_MISSING:{required}")
    runner = (ROOT / "scripts/run-production-migrations.sh").read_text(encoding="utf-8")
    for required in (
        "SET search_path = public",
        "current_schemas(true)",
        "AGENT_TRUST_ENTERPRISE_APPLICATION_ROLE",
        "AGENT_TRUST_ORCHESTRATOR_APPLICATION_ROLE",
        "REVOKE ALL ON public.agenttrust_schema_migrations",
        "public.spring_session_attributes",
        "public.orchestrator_stream_events_sequence_seq",
        "MIGRATION_APPLICATION_ROLE_CROSS_DOMAIN_GRANT",
    ):
        if required not in runner:
            fail(f"MIGRATION_RUNNER_CLOSURE_MISSING:{required}")
    print(f"validated {len(entries)} ordered production migrations and tenant RLS closure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
