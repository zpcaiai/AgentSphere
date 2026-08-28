from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "migrations/production-closure/0036_03_production_activation_lease.sql"
RUNNER = ROOT / "scripts/run-production-migrations.sh"
RENEWER = (
    ROOT
    / "rust/crates/production-runtime/src/bin/agenttrust-activation-lease-renewer.rs"
)


class ProductionActivationLeaseContractTests(unittest.TestCase):
    def test_global_write_guard_is_last_and_fail_closed(self) -> None:
        entries = [
            line.strip()
            for line in (ROOT / "migrations/manifest.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            entries[-2:],
            [
                "production-closure/0036_02_global_tenant_isolation.sql",
                "production-closure/0036_03_production_activation_lease.sql",
            ],
        )
        sql = MIGRATION.read_text(encoding="utf-8")
        for required in (
            "production_activation_lease",
            "production_activation_history",
            "agenttrust_enforce_production_activation",
            "agenttrust_renew_production_activation",
            "agenttrust_transition_production_activation",
            "agenttrust_production_activation_guard",
            "PRODUCTION_ACTIVATION_LEASE_NOT_ACTIVE",
            "FOR UPDATE",
            "PRODUCTION_ACTIVATION_RENEWAL_CAS_REJECTED",
            "PRODUCTION_ACTIVATION_TRANSITION_CAS_REJECTED",
            "state = 'ACTIVE'",
            "valid_until > clock_timestamp()",
            "renewed_at >= clock_timestamp() - interval '60 seconds'",
            "watcher_verified_at >= clock_timestamp() - interval '60 seconds'",
            "requested_valid_until > clock_timestamp() + interval '45 seconds'",
            "BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE",
        ):
            self.assertIn(required, sql)
        self.assertIn("'agenttrust_schema_migrations'", sql)
        self.assertIn("'production_activation_lease'", sql)
        self.assertIn("'production_activation_history'", sql)
        self.assertNotIn("DISABLE TRIGGER", sql.upper())
        self.assertNotIn("session_replication_role", sql)

    def test_only_platform_sre_can_call_lease_mutators(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        for function in (
            "agenttrust_renew_production_activation",
            "agenttrust_transition_production_activation",
        ):
            self.assertIn(f"REVOKE ALL ON FUNCTION public.{function}", sql)
            self.assertIn(f"GRANT EXECUTE ON FUNCTION public.{function}", runner)
        self.assertIn("TO $platform_sre_application_role", runner)
        self.assertIn("MIGRATION_PRODUCTION_AUTHORITY_ROLE_POSTURE_INVALID", runner)
        self.assertIn("function.oid NOT IN", runner)

    def test_renewer_cross_checks_watcher_receipt_and_short_database_lease(self) -> None:
        source = RENEWER.read_text(encoding="utf-8")
        for required in (
            "parse_strict_json",
            "ActivationGuardian",
            "WATCH_MAX_AGE_SECONDS: i64 = 30",
            "RENEW_INTERVAL_SECONDS: u64 = 10",
            "LEASE_SECONDS: i64 = 45",
            "watcher.receipt_digest.as_deref() != Some(receipt.receipt_digest.as_str())",
            "watcher.revocation_registry_sequence.map(|value| value as u64)",
            "watcher.revocation_registry_digest.as_deref()",
            "agenttrust_renew_production_activation",
            "state == \"FENCED\"",
            "state != \"ACTIVE\"",
            'route("/ready"',
            'route("/active"',
            'command != "check-active"',
            "ACTIVATION_LEASE_PROBE_NOT_ACTIVE",
            "database_write_enabled",
        ):
            self.assertIn(required, source)
        self.assertNotIn("danger_accept_invalid", source)
        dockerfile = (ROOT / "Dockerfile.production-runtime").read_text(encoding="utf-8")
        self.assertIn("--bin agenttrust-activation-lease-renewer", dockerfile)
        self.assertIn("/usr/local/bin/agenttrust-activation-lease-renewer", dockerfile)


if __name__ == "__main__":
    unittest.main()
