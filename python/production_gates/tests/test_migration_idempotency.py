from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "validate_production_migrations",
    ROOT / "scripts/validate-production-migrations.py",
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class MigrationIdempotencyValidatorTest(unittest.TestCase):
    def assert_rejected(self, sql: str, code: str) -> None:
        with self.assertRaisesRegex(RuntimeError, code):
            VALIDATOR.validate_idempotent_sql("fixture.sql", sql)

    def test_accepts_atomic_drop_and_recreate_guards(self) -> None:
        VALIDATOR.validate_idempotent_sql(
            "fixture.sql",
            """
            BEGIN;
            CREATE TABLE IF NOT EXISTS records (tenant_id uuid, value text);
            CREATE INDEX IF NOT EXISTS records_tenant_idx ON records(tenant_id);
            ALTER TABLE records DROP CONSTRAINT IF EXISTS records_value_check;
            ALTER TABLE records ADD CONSTRAINT records_value_check CHECK (value <> '');
            DROP TRIGGER IF EXISTS records_immutable ON records;
            CREATE TRIGGER records_immutable BEFORE DELETE ON records
              FOR EACH ROW EXECUTE FUNCTION reject_change();
            DROP POLICY IF EXISTS tenant_isolation ON records;
            CREATE POLICY tenant_isolation ON records USING (true);
            INSERT INTO records(tenant_id,value)
              SELECT gen_random_uuid(),'legacy'
              WHERE NOT EXISTS (SELECT 1 FROM records WHERE value='legacy');
            COMMIT;
            """,
        )

    def test_rejects_known_second_pass_failures(self) -> None:
        fixtures = (
            ("CREATE TABLE records(id bigint);", "TABLE"),
            ("CREATE INDEX records_idx ON records(id);", "INDEX"),
            (
                "CREATE TRIGGER records_guard BEFORE DELETE ON records "
                "FOR EACH ROW EXECUTE FUNCTION reject_change();",
                "TRIGGER",
            ),
            ("CREATE POLICY tenant_isolation ON records USING (true);", "POLICY"),
            (
                "ALTER TABLE records ADD CONSTRAINT records_check CHECK (id > 0);",
                "CONSTRAINT",
            ),
            (
                "DO $$ BEGIN EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (true)',"
                "'records'); END $$;",
                "DYNAMIC_DDL_NOT_IDEMPOTENT",
            ),
            ("ALTER TABLE records SET SCHEMA legacy;", "SET_SCHEMA"),
            ("INSERT INTO records(id) VALUES (1);", "INSERT_NOT_IDEMPOTENT"),
        )
        for sql, code in fixtures:
            with self.subTest(code=code):
                self.assert_rejected(sql, code)

    def test_accepts_only_runner_wrappable_transaction_boundaries(self) -> None:
        VALIDATOR.validate_transaction_boundary(
            "fixture.sql",
            "-- standalone migration\nBEGIN;\nSELECT 1;\nCOMMIT;\n",
        )
        VALIDATOR.validate_transaction_boundary(
            "fixture.sql",
            "-- runner wraps migrations without an outer transaction\nDO $$ BEGIN NULL; END $$;\n",
        )

    def test_rejects_ambiguous_transactions_and_psql_meta_commands(self) -> None:
        fixtures = (
            ("BEGIN;\nSELECT 1;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("SELECT 1;\nCOMMIT;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("BEGIN;\nCOMMIT;\nCOMMIT;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("BEGIN TRANSACTION;\nSELECT 1;\nCOMMIT WORK;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("START TRANSACTION;\nSELECT 1;\nEND;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("BEGIN; -- hidden variant\nSELECT 1;\nCOMMIT;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("SELECT 1; ROLLBACK WORK;\n", "TRANSACTION_BOUNDARY_INVALID"),
            ("SELECT 1; ABORT;\n", "TRANSACTION_BOUNDARY_INVALID"),
            (
                "BEGIN; -- visible outer decoy\n"
                "SELECT $q$\nBEGIN;\nCOMMIT;\n$q$;\n"
                "SELECT 1;\nCOMMIT; -- visible outer decoy\n",
                "TRANSACTION_BOUNDARY_INVALID",
            ),
            ("\\i /tmp/untrusted.sql\n", "PSQL_META_COMMAND_FORBIDDEN"),
            ("SELECT 1 \\gexec\n", "PSQL_META_COMMAND_FORBIDDEN"),
            ("-- even quoted backslashes are forbidden: '\\gexec'\nSELECT 1;\n", "PSQL_META_COMMAND_FORBIDDEN"),
            ("-- comments only\n", "MIGRATION_EMPTY"),
            ("SELECT 'unterminated;\n", "SQL_LEXER_INVALID"),
        )
        for sql, code in fixtures:
            with self.subTest(code=code):
                with self.assertRaisesRegex(RuntimeError, code):
                    VALIDATOR.validate_transaction_boundary("fixture.sql", sql)

    def test_runner_renders_each_migration_and_history_row_in_one_transaction(self) -> None:
        role_variables = (
            "ENTERPRISE_APPLICATION_ROLE",
            "ENTERPRISE_AUTHORITY_APPLICATION_ROLE",
            "ORCHESTRATOR_APPLICATION_ROLE",
            "EXECUTION_APPLICATION_ROLE",
            "REGISTRY_APPLICATION_ROLE",
            "AGENT_REGISTRY_APPLICATION_ROLE",
            "POLICY_ADMIN_APPLICATION_ROLE",
            "INCIDENT_RELEASE_APPLICATION_ROLE",
            "PACK_MARKETPLACE_APPLICATION_ROLE",
            "APPROVAL_APPLICATION_ROLE",
            "PEP_APPLICATION_ROLE",
            "IDENTITY_APPLICATION_ROLE",
            "TOOL_PROXY_APPLICATION_ROLE",
            "EVIDENCE_APPLICATION_ROLE",
            "AUDIT_APPLICATION_ROLE",
            "MODEL_GATEWAY_APPLICATION_ROLE",
            "DATA_GOVERNANCE_APPLICATION_ROLE",
            "CONTEXT_GOVERNANCE_APPLICATION_ROLE",
            "RUNTIME_ANOMALY_APPLICATION_ROLE",
            "SECURITY_EVALUATION_APPLICATION_ROLE",
            "PACK_SUPPLY_CHAIN_APPLICATION_ROLE",
            "DOMAIN_RUNTIME_APPLICATION_ROLE",
            "PLATFORM_SRE_APPLICATION_ROLE",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory).resolve()
            migration_root = temporary / "migrations"
            migration_root.mkdir()
            (migration_root / "0001_first.sql").write_text(
                "BEGIN;\nCREATE TABLE IF NOT EXISTS first_record(id bigint);\nCOMMIT;\n",
                encoding="utf-8",
            )
            (migration_root / "0002_second.sql").write_text(
                "DO $$ BEGIN NULL; END $$;\n",
                encoding="utf-8",
            )
            manifest = migration_root / "manifest.txt"
            manifest.write_text("0001_first.sql\n0002_second.sql\n", encoding="utf-8")
            certificate = temporary / "database-ca.pem"
            certificate.write_text("test-only-certificate\n", encoding="ascii")
            database_url = temporary / "database-url"
            database_url.write_text(
                "postgresql://migration.test/db?sslmode=verify-full"
                f"&sslrootcert={certificate}\n",
                encoding="ascii",
            )
            capture = temporary / "rendered.sql"
            runner_tmp = temporary / "tmp"
            runner_tmp.mkdir()
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            fake_psql = fake_bin / "psql"
            fake_psql.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "[ \"$1\" = --no-psqlrc ]\n"
                "[ \"$2\" = --file ]\n"
                "cp \"$3\" \"$AGENT_TRUST_CAPTURE_SQL\"\n",
                encoding="utf-8",
            )
            fake_psql.chmod(0o700)

            environment = os.environ.copy()
            environment.update({
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "AGENT_TRUST_MIGRATIONS_ROOT": str(migration_root),
                "AGENT_TRUST_MIGRATION_MANIFEST": str(manifest),
                "AGENT_TRUST_DATABASE_URL_FILE": str(database_url),
                "AGENT_TRUST_DATABASE_CA_FILE": str(certificate),
                "AGENT_TRUST_RELEASE_ID": "git:sha1:" + "1" * 40,
                "AGENT_TRUST_CAPTURE_SQL": str(capture),
                "TMPDIR": str(runner_tmp),
            })
            environment.update({
                f"AGENT_TRUST_{variable}": f"agenttrust_test_role_{index}"
                for index, variable in enumerate(role_variables, start=1)
            })
            completed = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

            rendered = capture.read_text(encoding="utf-8")
            self.assertIn(
                "\\else\nBEGIN;\n"
                "CREATE TABLE IF NOT EXISTS first_record(id bigint);\n"
                "INSERT INTO public.agenttrust_schema_migrations",
                rendered,
            )
            self.assertIn(
                "\\else\nBEGIN;\nDO $$ BEGIN NULL; END $$;\n"
                "INSERT INTO public.agenttrust_schema_migrations",
                rendered,
            )
            self.assertEqual(rendered.count("VALUES ('0001_first.sql',"), 1)
            self.assertEqual(rendered.count("VALUES ('0002_second.sql',"), 1)
            self.assertNotIn("BEGIN;\nBEGIN;", rendered)
            self.assertNotIn("ON CONFLICT (migration_path) DO NOTHING", rendered)
            self.assertIn("BEGIN;\nDO $database_acl$", rendered)
            self.assertIn(
                "$production_authority_posture$;\nCOMMIT;\n"
                "SELECT pg_advisory_unlock",
                rendered,
            )

            unsafe_transactions = (
                "BEGIN TRANSACTION;\nSELECT 1;\nCOMMIT WORK;\n",
                "BEGIN; -- line-comment bypass\nSELECT 1;\nCOMMIT;\n",
                "SELECT 1; ROLLBACK WORK;\n",
                "SELECT 1 \\gexec\n",
                (
                    "BEGIN; -- visible outer decoy\n"
                    "SELECT $q$\nBEGIN;\nCOMMIT;\n$q$;\n"
                    "SELECT 1;\nCOMMIT; -- visible outer decoy\n"
                ),
            )
            for unsafe_sql in unsafe_transactions:
                with self.subTest(unsafe_sql=unsafe_sql):
                    (migration_root / "0001_first.sql").write_text(
                        unsafe_sql,
                        encoding="utf-8",
                    )
                    rejected = subprocess.run(
                        ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                        env=environment,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(65, rejected.returncode, rejected.stderr)
                    self.assertIn(
                        "MIGRATION_TRANSACTION_BOUNDARY_INVALID:0001_first.sql",
                        rejected.stderr,
                    )

            (migration_root / "0001_first.sql").write_text(
                "BEGIN;\nSELECT 1;\nCOMMIT;\n",
                encoding="utf-8",
            )
            fake_digest = fake_bin / "sha256sum"
            fake_digest.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
            fake_digest.chmod(0o700)
            digest_failure = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(65, digest_failure.returncode, digest_failure.stderr)
            self.assertIn("MIGRATION_DIGEST_INVALID:0001_first.sql", digest_failure.stderr)

            fake_digest.unlink()
            child_started = temporary / "psql-started"
            child_terminated = temporary / "psql-terminated"
            fake_psql.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "trap 'printf terminated > \"$AGENT_TRUST_PSQL_TERMINATED\"; exit 143' TERM\n"
                "printf '%s' \"$$\" > \"$AGENT_TRUST_PSQL_STARTED\"\n"
                "while :; do sleep 1; done\n",
                encoding="utf-8",
            )
            fake_psql.chmod(0o700)
            environment.update({
                "AGENT_TRUST_PSQL_STARTED": str(child_started),
                "AGENT_TRUST_PSQL_TERMINATED": str(child_terminated),
            })
            runner = subprocess.Popen(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(200):
                if child_started.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(child_started.exists(), "fake psql did not start")
            runner.terminate()
            stdout, stderr = runner.communicate(timeout=5)
            self.assertEqual(143, runner.returncode, f"{stdout}\n{stderr}")
            self.assertTrue(child_terminated.exists(), "TERM was not forwarded to psql")
            self.assertEqual([], list(runner_tmp.glob("agenttrust-migration*")))


if __name__ == "__main__":
    unittest.main()
