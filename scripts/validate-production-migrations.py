#!/usr/bin/env python3
"""Statically validate the immutable production migration set and RLS closure."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
MANIFEST = MIGRATIONS / "manifest.txt"
PATH = re.compile(r"^[A-Za-z0-9._/-]+\.sql$")
VERSION = re.compile(r"^\d{4}(?:_\d{2})*")


def fail(code: str) -> None:
    raise RuntimeError(code)


def migration_version(value: str) -> tuple[int, ...]:
    match = VERSION.match(Path(value).name)
    if match is None:
        fail("MIGRATION_VERSION_INVALID")
    return tuple(int(part) for part in match.group(0).split("_"))


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
    versions = [migration_version(value) for value in entries]
    if versions != sorted(versions):
        fail("MIGRATION_MANIFEST_ORDER_INVALID")
    if entries[-1] != "production-closure/0036_02_global_tenant_isolation.sql":
        fail("GLOBAL_TENANT_ISOLATION_NOT_LAST")
    if "orchestrator/0036_01_24_production_orchestrator_hardening.sql" not in entries:
        fail("ORCHESTRATOR_PRODUCTION_HARDENING_MISSING")
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
    if re.search(r"\b(?:CREATE|ALTER)\s+ROLE\b", upper):
        fail("MIGRATION_EMBEDDED_RUNTIME_ROLE_FORBIDDEN")
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
        "orchestrator_ingress_contract_check",
        "orchestrator_stream_ingress_fk",
        "orchestrator_stream_command_once_idx",
        "ORCHESTRATOR_STREAM_APPEND_ONLY",
        "spring_session",
        "spring_session_attributes",
        "enterprise_action_ingress",
        "enterprise_authority_executions",
        "agent_registry_audit_events",
        "audit_human_assertion_uses",
    ):
        if required not in source:
            fail(f"MIGRATION_REQUIRED_CLOSURE_MISSING:{required}")
    runner = (ROOT / "scripts/run-production-migrations.sh").read_text(encoding="utf-8")
    for required in (
        "SET search_path = public",
        "current_schemas(true)",
        "AGENT_TRUST_ENTERPRISE_APPLICATION_ROLE",
        "AGENT_TRUST_ENTERPRISE_AUTHORITY_APPLICATION_ROLE",
        "AGENT_TRUST_ORCHESTRATOR_APPLICATION_ROLE",
        "AGENT_TRUST_EXECUTION_APPLICATION_ROLE",
        "AGENT_TRUST_REGISTRY_APPLICATION_ROLE",
        "AGENT_TRUST_AGENT_REGISTRY_APPLICATION_ROLE",
        "AGENT_TRUST_APPROVAL_APPLICATION_ROLE",
        "AGENT_TRUST_PEP_APPLICATION_ROLE",
        "AGENT_TRUST_IDENTITY_APPLICATION_ROLE",
        "AGENT_TRUST_TOOL_PROXY_APPLICATION_ROLE",
        "AGENT_TRUST_EVIDENCE_APPLICATION_ROLE",
        "AGENT_TRUST_AUDIT_APPLICATION_ROLE",
        "REVOKE ALL ON public.agenttrust_schema_migrations",
        "REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC",
        "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC",
        "public.spring_session_attributes",
        "public.orchestrator_stream_events_sequence_seq",
        "MIGRATION_APPROVAL_EXCESS_COLUMN_UPDATE_GRANT",
        "MIGRATION_ORCHESTRATOR_EXCESS_MUTATION_GRANT",
        "MIGRATION_ORCHESTRATOR_UPDATE_GRANT_MISSING",
        "MIGRATION_IDENTITY_WRITE_ONLY_GRANTS_INVALID",
        "MIGRATION_TOOL_PROXY_WRITE_ONLY_GRANTS_INVALID",
        "MIGRATION_EVIDENCE_LEDGER_READ_GRANTS_INVALID",
        "MIGRATION_AUDIT_GRANTS_INVALID",
        "MIGRATION_AUDIT_LEGAL_HOLD_EXCESS_GRANT",
        "MIGRATION_ENTERPRISE_AUTHORITY_EXCESS_COLUMN_UPDATE_GRANT",
        "MIGRATION_AGENT_REGISTRY_GRANTS_INVALID",
        "MIGRATION_APPLICATION_ROLE_CROSS_DOMAIN_GRANT",
        "MIGRATION_APPLICATION_ROLE_EXCESS_FUNCTION_GRANT",
    ):
        if required not in runner:
            fail(f"MIGRATION_RUNNER_CLOSURE_MISSING:{required}")
    print(f"validated {len(entries)} ordered production migrations and tenant RLS closure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
