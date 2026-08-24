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

ROLE_VARIABLES = (
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
                "postgresql://migration_test@database.test/db?sslmode=verify-full"
                f"&sslrootcert={certificate}\n",
                encoding="ascii",
            )
            database_password = temporary / "database-password"
            database_password.write_text("test:password\\material\n", encoding="ascii")
            capture = temporary / "rendered.sql"
            captured_pgpass = temporary / "captured.pgpass"
            runner_tmp = temporary / "tmp"
            runner_tmp.mkdir()
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            fake_psql = fake_bin / "psql"
            valid_fake_psql = (
                "#!/bin/sh\n"
                "set -eu\n"
                "[ \"${PGPASSWORD+x}\" != x ]\n"
                "if [ \"${1:-}\" = --version ]; then\n"
                "  printf '%s\\n' 'psql (PostgreSQL) 17.5'\n"
                "  exit 0\n"
                "fi\n"
                "[ \"$#\" -eq 3 ]\n"
                "[ \"$1\" = --no-psqlrc ]\n"
                "[ \"$2\" = --file ]\n"
                "[ \"$PGHOST\" = database.test ]\n"
                "[ \"$PGPORT\" = 5432 ]\n"
                "[ \"$PGUSER\" = migration_test ]\n"
                "[ \"$PGDATABASE\" = db ]\n"
                "[ \"$PGSSLMODE\" = verify-full ]\n"
                "[ \"$PGSSLROOTCERT\" = \"$AGENT_TRUST_DATABASE_CA_FILE\" ]\n"
                "[ \"$PGSSLMINPROTOCOLVERSION\" = TLSv1.3 ]\n"
                "[ \"$PGCHANNELBINDING\" = require ]\n"
                "[ \"$PGGSSENCMODE\" = disable ]\n"
                "[ \"$PGCLIENTENCODING\" = UTF8 ]\n"
                "[ \"${PGPASSWORD+x}\" != x ]\n"
                "[ \"${PGHOSTADDR+x}\" != x ]\n"
                "[ \"${PGSERVICE+x}\" != x ]\n"
                "[ \"${PGOPTIONS+x}\" != x ]\n"
                "[ -f \"$PGPASSFILE\" ]\n"
                "pgpass_mode=$(stat -c %a \"$PGPASSFILE\" 2>/dev/null || stat -f %Lp \"$PGPASSFILE\")\n"
                "[ \"$pgpass_mode\" = 600 ]\n"
                "if env | grep -F 'postgresql://' >/dev/null; then exit 1; fi\n"
                "if env | grep -F 'test:password' >/dev/null; then exit 1; fi\n"
                "cp \"$3\" \"$AGENT_TRUST_CAPTURE_SQL\"\n"
                "cp \"$PGPASSFILE\" \"$AGENT_TRUST_CAPTURE_PGPASS\"\n"
            )
            fake_psql.write_text(valid_fake_psql, encoding="utf-8")
            fake_psql.chmod(0o700)

            environment = os.environ.copy()
            environment.update({
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "AGENT_TRUST_MIGRATIONS_ROOT": str(migration_root),
                "AGENT_TRUST_MIGRATION_MANIFEST": str(manifest),
                "AGENT_TRUST_DATABASE_URL_FILE": str(database_url),
                "AGENT_TRUST_DATABASE_PASSWORD_FILE": str(database_password),
                "AGENT_TRUST_DATABASE_CA_FILE": str(certificate),
                "AGENT_TRUST_RELEASE_ID": "git:sha1:" + "1" * 40,
                "AGENT_TRUST_CAPTURE_SQL": str(capture),
                "AGENT_TRUST_CAPTURE_PGPASS": str(captured_pgpass),
                "TMPDIR": str(runner_tmp),
                "PGPASSWORD": "untrusted-inherited-password",
                "PGHOSTADDR": "203.0.113.20",
                "PGSERVICE": "untrusted-service",
                "PGOPTIONS": "-c search_path=untrusted",
            })
            environment.update({
                f"AGENT_TRUST_{variable}": f"agenttrust_test_role_{index}"
                for index, variable in enumerate(ROLE_VARIABLES, start=1)
            })
            completed = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))

            rendered = capture.read_text(encoding="utf-8")
            self.assertIn("FROM pg_catalog.pg_stat_ssl AS transport", rendered)
            self.assertIn("MIGRATION_TLS_VERSION_INVALID", rendered)
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
            self.assertEqual(
                "database.test:5432:db:migration_test:test\\:password\\\\material\n",
                captured_pgpass.read_text(encoding="ascii"),
            )

            valid_database_url = database_url.read_text(encoding="ascii")
            for unsafe_database_url, expected_error in (
                (
                    valid_database_url.replace("migration_test@", "migration_test:embedded@"),
                    "MIGRATION_DATABASE_USER_INVALID",
                ),
                (
                    valid_database_url.rstrip("\n") + "&application_name=unsafe\n",
                    "MIGRATION_DATABASE_PARAMETERS_INVALID",
                ),
                (
                    valid_database_url.replace("database.test", "database.test:70000"),
                    "MIGRATION_DATABASE_PORT_INVALID",
                ),
                (
                    valid_database_url.replace("database.test", "-invalid.database.test"),
                    "MIGRATION_DATABASE_HOST_INVALID",
                ),
                (
                    valid_database_url.rstrip("\n") + "\n\n",
                    "MIGRATION_DATABASE_URL_FILE_INVALID",
                ),
            ):
                with self.subTest(expected_error=expected_error):
                    database_url.write_text(unsafe_database_url, encoding="ascii")
                    rejected_database = subprocess.run(
                        ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                        env=environment,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(78, rejected_database.returncode, rejected_database.stderr)
                    self.assertIn(expected_error, rejected_database.stderr)
            database_url.write_text(valid_database_url, encoding="ascii")

            for variable, source, link_name in (
                ("AGENT_TRUST_DATABASE_URL_FILE", database_url, "database-url-link"),
                (
                    "AGENT_TRUST_DATABASE_PASSWORD_FILE",
                    database_password,
                    "database-password-link",
                ),
                ("AGENT_TRUST_DATABASE_CA_FILE", certificate, "database-ca-link"),
            ):
                with self.subTest(symlink_input=variable):
                    link = temporary / link_name
                    link.symlink_to(source)
                    original_path = environment[variable]
                    environment[variable] = str(link)
                    rejected_symlink = subprocess.run(
                        ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                        env=environment,
                        capture_output=True,
                        text=True,
                    )
                    environment[variable] = original_path
                    self.assertEqual(
                        78,
                        rejected_symlink.returncode,
                        rejected_symlink.stderr,
                    )
                    self.assertIn("MIGRATION_INPUT_MISSING", rejected_symlink.stderr)
                    self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))

            fake_psql.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "[ \"${PGPASSWORD+x}\" != x ]\n"
                "if [ \"${1:-}\" = --version ]; then\n"
                "  printf '%s\\n' 'psql (PostgreSQL) 12.22'\n"
                "  exit 0\n"
                "fi\n"
                "exit 99\n",
                encoding="utf-8",
            )
            unsupported_client = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(78, unsupported_client.returncode, unsupported_client.stderr)
            self.assertIn("MIGRATION_PSQL_CLIENT_UNSUPPORTED", unsupported_client.stderr)
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))
            fake_psql.write_text(valid_fake_psql, encoding="utf-8")
            fake_psql.chmod(0o700)

            database_password.write_text("first-line\nsecond-line\n", encoding="ascii")
            rejected_password = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(78, rejected_password.returncode, rejected_password.stderr)
            self.assertIn("MIGRATION_DATABASE_PASSWORD_FILE_INVALID", rejected_password.stderr)
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))
            database_password.write_text("control\x7fbyte\n", encoding="ascii")
            rejected_control_password = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                78, rejected_control_password.returncode, rejected_control_password.stderr
            )
            self.assertIn(
                "MIGRATION_DATABASE_PASSWORD_FILE_INVALID",
                rejected_control_password.stderr,
            )
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))
            database_password.write_text("test:password\\material\n", encoding="ascii")

            environment["AGENT_TRUST_DATABASE_CONNECT_TIMEOUT_SECONDS"] = "0"
            rejected_timeout = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(78, rejected_timeout.returncode, rejected_timeout.stderr)
            self.assertIn("MIGRATION_DATABASE_CONNECT_TIMEOUT_INVALID", rejected_timeout.stderr)
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))
            environment.pop("AGENT_TRUST_DATABASE_CONNECT_TIMEOUT_SECONDS")

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
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))

            fake_digest.unlink()
            child_started = temporary / "psql-started"
            child_terminated = temporary / "psql-terminated"
            fake_psql.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "[ \"${PGPASSWORD+x}\" != x ]\n"
                "if [ \"${1:-}\" = --version ]; then\n"
                "  printf '%s\\n' 'psql (PostgreSQL) 17.5'\n"
                "  exit 0\n"
                "fi\n"
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
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))

    def test_runner_renders_complete_production_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory).resolve()
            certificate = temporary / "database-ca.pem"
            certificate.write_text("test-only-certificate\n", encoding="ascii")
            database_url = temporary / "database-url"
            database_url.write_text(
                "postgresql://migration_manifest@database.test/db?sslmode=verify-full"
                f"&sslrootcert={certificate}\n",
                encoding="ascii",
            )
            database_password = temporary / "database-password"
            database_password.write_text("manifest-password\n", encoding="ascii")
            capture = temporary / "rendered.sql"
            runner_tmp = temporary / "tmp"
            runner_tmp.mkdir()
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            fake_psql = fake_bin / "psql"
            fake_psql.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "[ \"${PGPASSWORD+x}\" != x ]\n"
                "if [ \"${1:-}\" = --version ]; then\n"
                "  printf '%s\\n' 'psql (PostgreSQL) 17.5'\n"
                "  exit 0\n"
                "fi\n"
                "[ \"$1\" = --no-psqlrc ]\n"
                "[ \"$2\" = --file ]\n"
                "cp \"$3\" \"$AGENT_TRUST_CAPTURE_SQL\"\n",
                encoding="utf-8",
            )
            fake_psql.chmod(0o700)

            migration_root = ROOT / "migrations"
            manifest = migration_root / "manifest.txt"
            environment = os.environ.copy()
            environment.update({
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "AGENT_TRUST_MIGRATIONS_ROOT": str(migration_root),
                "AGENT_TRUST_MIGRATION_MANIFEST": str(manifest),
                "AGENT_TRUST_DATABASE_URL_FILE": str(database_url),
                "AGENT_TRUST_DATABASE_PASSWORD_FILE": str(database_password),
                "AGENT_TRUST_DATABASE_CA_FILE": str(certificate),
                "AGENT_TRUST_RELEASE_ID": "git:sha1:" + "2" * 40,
                "AGENT_TRUST_CAPTURE_SQL": str(capture),
                "TMPDIR": str(runner_tmp),
            })
            environment.update({
                f"AGENT_TRUST_{variable}": f"agenttrust_manifest_role_{index}"
                for index, variable in enumerate(ROLE_VARIABLES, start=1)
            })

            completed = subprocess.run(
                ["sh", str(ROOT / "scripts/run-production-migrations.sh"), "--apply"],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

            expected_paths = [
                line
                for line in manifest.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#")
            ]
            rendered = capture.read_text(encoding="utf-8")
            self.assertEqual(len(expected_paths), rendered.count("VALUES ('"))
            for relative in expected_paths:
                self.assertEqual(
                    1,
                    rendered.count(f"VALUES ('{relative}',"),
                    f"history row missing or duplicated for {relative}",
                )
            self.assertEqual([], list(runner_tmp.glob("agenttrust-*")))


if __name__ == "__main__":
    unittest.main()
