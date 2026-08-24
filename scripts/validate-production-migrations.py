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
BARE_CREATE = (
    ("TABLE", re.compile(r"^[ \t]*CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS\b)", re.IGNORECASE | re.MULTILINE)),
    ("INDEX", re.compile(r"^[ \t]*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!IF\s+NOT\s+EXISTS\b)", re.IGNORECASE | re.MULTILINE)),
    ("SEQUENCE", re.compile(r"^[ \t]*CREATE\s+SEQUENCE\s+(?!IF\s+NOT\s+EXISTS\b)", re.IGNORECASE | re.MULTILINE)),
    ("SCHEMA", re.compile(r"^[ \t]*CREATE\s+SCHEMA\s+(?!IF\s+NOT\s+EXISTS\b)", re.IGNORECASE | re.MULTILINE)),
    ("EXTENSION", re.compile(r"^[ \t]*CREATE\s+EXTENSION\s+(?!IF\s+NOT\s+EXISTS\b)", re.IGNORECASE | re.MULTILINE)),
    ("MATERIALIZED_VIEW", re.compile(r"^[ \t]*CREATE\s+MATERIALIZED\s+VIEW\s+(?!IF\s+NOT\s+EXISTS\b)", re.IGNORECASE | re.MULTILINE)),
    ("VIEW", re.compile(r"^[ \t]*CREATE\s+VIEW\b", re.IGNORECASE | re.MULTILINE)),
    ("FUNCTION", re.compile(r"^[ \t]*CREATE\s+FUNCTION\b", re.IGNORECASE | re.MULTILINE)),
    ("PROCEDURE", re.compile(r"^[ \t]*CREATE\s+PROCEDURE\b", re.IGNORECASE | re.MULTILINE)),
    ("TYPE", re.compile(r"^[ \t]*CREATE\s+TYPE\b", re.IGNORECASE | re.MULTILINE)),
)
TRIGGER = re.compile(
    r"^[ \t]*CREATE\s+TRIGGER\s+(\"?[A-Za-z_][A-Za-z0-9_$]*\"?)",
    re.IGNORECASE | re.MULTILINE,
)
POLICY = re.compile(
    r"^[ \t]*CREATE\s+POLICY\s+(\"?[A-Za-z_][A-Za-z0-9_$]*\"?)",
    re.IGNORECASE | re.MULTILINE,
)
CONSTRAINT = re.compile(
    r"\bADD\s+CONSTRAINT\s+(\"?[A-Za-z_][A-Za-z0-9_$]*\"?)",
    re.IGNORECASE,
)
DYNAMIC_CREATE = re.compile(r"['\"]CREATE\s+(TRIGGER|POLICY)\b", re.IGNORECASE)
SET_SCHEMA = re.compile(
    r"^[ \t]*ALTER\s+TABLE\s+[^;\n]+\s+SET\s+SCHEMA\b",
    re.IGNORECASE | re.MULTILINE,
)
RENAME_TABLE = re.compile(
    r"^[ \t]*ALTER\s+TABLE\s+[^;\n]+\s+RENAME\s+TO\b",
    re.IGNORECASE | re.MULTILINE,
)
INSERT = re.compile(r"^[ \t]*INSERT\s+INTO\b.*?;", re.IGNORECASE | re.MULTILINE | re.DOTALL)
TRANSACTION_CONTROL = frozenset({"BEGIN;", "COMMIT;", "ROLLBACK;"})
TRANSACTION_STATEMENT = re.compile(
    r"^(?:BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|"
    r"RELEASE\s+SAVEPOINT|PREPARE\s+TRANSACTION)(?:\s|$)",
    re.IGNORECASE,
)
DOLLAR_DELIMITER = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


def fail(code: str) -> None:
    raise RuntimeError(code)


def migration_version(value: str) -> tuple[int, ...]:
    match = VERSION.match(Path(value).name)
    if match is None:
        fail("MIGRATION_VERSION_INVALID")
    return tuple(int(part) for part in match.group(0).split("_"))


def location(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def lex_visible_sql(relative: str, source: str) -> str:
    visible: list[str] = []
    position = 0
    state = "normal"
    block_depth = 0
    dollar_delimiter = ""
    while position < len(source):
        character = source[position]
        pair = source[position:position + 2]
        if state == "single_quote":
            if character == "'":
                if source[position + 1:position + 2] == "'":
                    position += 2
                else:
                    state = "normal"
                    position += 1
            elif character == "\n":
                visible.append("\n")
                position += 1
            else:
                position += 1
            continue
        if state == "double_quote":
            if character == '"':
                if source[position + 1:position + 2] == '"':
                    position += 2
                else:
                    state = "normal"
                    position += 1
            elif character == "\n":
                visible.append("\n")
                position += 1
            else:
                position += 1
            continue
        if state == "block_comment":
            if pair == "/*":
                block_depth += 1
                position += 2
            elif pair == "*/":
                block_depth -= 1
                position += 2
                if block_depth == 0:
                    state = "normal"
            elif character == "\n":
                visible.append("\n")
                position += 1
            else:
                position += 1
            continue
        if state == "dollar_quote":
            closing_position = source.find(dollar_delimiter, position)
            if closing_position < 0:
                fail(f"MIGRATION_SQL_LEXER_INVALID:{relative}")
            visible.append("\n" * source.count("\n", position, closing_position))
            position = closing_position + len(dollar_delimiter)
            state = "normal"
            dollar_delimiter = ""
            continue

        if pair == "--":
            newline = source.find("\n", position + 2)
            if newline < 0:
                visible.append(" ")
                position = len(source)
            else:
                visible.append("\n")
                position = newline + 1
        elif pair == "/*":
            visible.append(" ")
            state = "block_comment"
            block_depth = 1
            position += 2
        elif character == "'":
            visible.append(" ")
            state = "single_quote"
            position += 1
        elif character == '"':
            visible.append(" ")
            state = "double_quote"
            position += 1
        elif character == "$":
            match = DOLLAR_DELIMITER.match(source, position)
            if match is None:
                visible.append(character)
                position += 1
            else:
                visible.append(" ")
                dollar_delimiter = match.group(0)
                state = "dollar_quote"
                position = match.end()
        else:
            visible.append(character)
            position += 1
    if state != "normal":
        fail(f"MIGRATION_SQL_LEXER_INVALID:{relative}")
    return "".join(visible)


def validate_transaction_boundary(relative: str, source: str) -> None:
    # Production migration SQL deliberately has no backslash bytes. This
    # strict rule prevents psql meta-commands even when placed after SQL or in
    # a context a line-oriented detector would misclassify.
    if "\\" in source:
        fail(f"MIGRATION_PSQL_META_COMMAND_FORBIDDEN:{relative}")

    visible_source = lex_visible_sql(relative, source)
    transaction_lines: list[tuple[int, str]] = []
    for line_number, (raw_line, visible_line) in enumerate(
        zip(source.splitlines(), visible_source.splitlines(), strict=True),
        start=1,
    ):
        visible_normalized = " ".join(visible_line.split()).upper()
        if visible_normalized in TRANSACTION_CONTROL:
            if raw_line.strip().upper() != visible_normalized:
                fail(f"MIGRATION_TRANSACTION_BOUNDARY_INVALID:{relative}")
            transaction_lines.append((line_number, visible_normalized))
    statements = [
        " ".join(statement.split()).upper()
        for statement in visible_source.split(";")
        if statement.split()
    ]
    if not statements:
        fail(f"MIGRATION_EMPTY:{relative}")
    transaction_statements = [
        statement for statement in statements if TRANSACTION_STATEMENT.match(statement)
    ]
    if not transaction_statements:
        return
    if not (
        len(transaction_lines) == 2
        and transaction_lines[0][1] == "BEGIN;"
        and transaction_lines[1][1] == "COMMIT;"
        and transaction_statements == ["BEGIN", "COMMIT"]
        and statements[0] == "BEGIN"
        and statements[-1] == "COMMIT"
    ):
        fail(f"MIGRATION_TRANSACTION_BOUNDARY_INVALID:{relative}")


def validate_idempotent_sql(relative: str, source: str) -> None:
    for kind, pattern in BARE_CREATE:
        match = pattern.search(source)
        if match is not None:
            fail(f"MIGRATION_DDL_NOT_IDEMPOTENT:{relative}:{location(source, match.start())}:{kind}")

    for kind, pattern, drop_kind, catalog_name in (
        ("TRIGGER", TRIGGER, "TRIGGER", "tgname"),
        ("POLICY", POLICY, "POLICY", "policyname"),
    ):
        for match in pattern.finditer(source):
            name = match.group(1).strip('"')
            before = source[:match.start()]
            guarded = re.search(
                rf"DROP\s+{drop_kind}\s+IF\s+EXISTS\s+{re.escape(name)}\b",
                before,
                re.IGNORECASE,
            ) or re.search(
                rf"{catalog_name}\s*=\s*'{re.escape(name)}'",
                before,
                re.IGNORECASE,
            )
            if not guarded:
                fail(f"MIGRATION_DDL_NOT_IDEMPOTENT:{relative}:{location(source, match.start())}:{kind}")

    for match in CONSTRAINT.finditer(source):
        name = match.group(1).strip('"')
        before = source[:match.start()]
        guarded = re.search(
            rf"DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+{re.escape(name)}\b",
            before,
            re.IGNORECASE,
        ) or re.search(
            rf"conname\s*=\s*'{re.escape(name)}'",
            before,
            re.IGNORECASE,
        )
        if not guarded:
            fail(f"MIGRATION_DDL_NOT_IDEMPOTENT:{relative}:{location(source, match.start())}:CONSTRAINT")

    for match in DYNAMIC_CREATE.finditer(source):
        kind = match.group(1).upper()
        before = source[max(0, match.start() - 1_500):match.start()].upper()
        guarded = f"DROP {kind}" in before
        if kind == "POLICY":
            guarded = guarded or ("PG_POLICIES" in before and "IF NOT EXISTS" in before)
        else:
            guarded = guarded or ("PG_TRIGGER" in before and "IF NOT EXISTS" in before)
        if not guarded:
            fail(f"MIGRATION_DYNAMIC_DDL_NOT_IDEMPOTENT:{relative}:{location(source, match.start())}:{kind}")

    for pattern, kind in ((SET_SCHEMA, "SET_SCHEMA"), (RENAME_TABLE, "RENAME_TABLE")):
        for match in pattern.finditer(source):
            before = source[max(0, match.start() - 1_500):match.start()].upper()
            if "TO_REGCLASS" not in before or "IS NULL" not in before:
                fail(f"MIGRATION_DDL_NOT_IDEMPOTENT:{relative}:{location(source, match.start())}:{kind}")

    for match in INSERT.finditer(source):
        statement = match.group(0).upper()
        if "ON CONFLICT" not in statement and "WHERE NOT EXISTS" not in statement:
            fail(f"MIGRATION_INSERT_NOT_IDEMPOTENT:{relative}:{location(source, match.start())}")

    if relative == "security-evaluation/0036_01_12_production_security_evaluation.sql":
        for table_name in ("attack_scenarios", "security_campaigns", "security_findings"):
            if f"FROM security_eval_legacy.{table_name}" not in source:
                fail(f"MIGRATION_SECURITY_LEGACY_SOURCE_UNSAFE:{table_name}")
    if relative == "platform-sre/0036_01_13_production_platform_sre.sql":
        if source.count("WHERE NOT EXISTS (") < 3:
            fail("MIGRATION_SRE_LEGACY_QUARANTINE_NOT_IDEMPOTENT")


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

    for relative in entries:
        migration_source = (MIGRATIONS / relative).read_text(encoding="utf-8")
        validate_transaction_boundary(relative, migration_source)
        validate_idempotent_sql(relative, migration_source)

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
        "append_atomic_migration_body",
        "MIGRATION_TRANSACTION_BOUNDARY_INVALID",
        "MIGRATION_SNAPSHOT_FAILED",
        "MIGRATION_DIGEST_INVALID",
        "AGENT_TRUST_DATABASE_PASSWORD_FILE",
        "MIGRATION_DATABASE_PASSWORD_SNAPSHOT_FAILED",
        'export PGHOST="$database_host"',
        'export PGDATABASE="$database_name"',
        'export PGPASSFILE="$pgpass_file"',
        "PGSSLMINPROTOCOLVERSION=TLSv1.3",
        "PGCHANNELBINDING=require",
        "PGGSSENCMODE=disable",
        "PGCLIENTENCODING=UTF8",
        "unset PGPASSWORD",
        "MIGRATION_PSQL_CLIENT_UNSUPPORTED",
        "FROM pg_catalog.pg_stat_ssl AS transport",
        "MIGRATION_TLS_VERSION_INVALID",
        'chmod 0400 "$migration_snapshot"',
    ):
        if required not in runner:
            fail(f"MIGRATION_RUNNER_CLOSURE_MISSING:{required}")
    if "\\i '$migration'" in runner or "ON CONFLICT (migration_path) DO NOTHING" in runner:
        fail("MIGRATION_RUNNER_NON_ATOMIC_HISTORY_WRITE")
    if 'digest_file "$migration"' in runner:
        fail("MIGRATION_RUNNER_SOURCE_DIGEST_TOCTOU")
    if runner.index("unset PGPASSWORD") > runner.index('mode="${1:---apply}"'):
        fail("MIGRATION_RUNNER_INHERITED_PASSWORD_EXPOSURE")
    print(f"validated {len(entries)} ordered production migrations and tenant RLS closure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
