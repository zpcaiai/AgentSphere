from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_linux_isolation_report", ROOT / "scripts/verify-linux-isolation-report.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LinuxIsolationReportTests(unittest.TestCase):
    def fixture(self) -> tuple[dict[str, object], datetime]:
        measured = datetime(2030, 1, 1, tzinfo=timezone.utc)
        valid_until = measured + timedelta(days=7)
        report: dict[str, object] = {
            "schema_version": "agenttrust.linux-isolation-report.v1",
            "mode": "production",
            "image": "registry.example/isolation@sha256:" + "1" * 64,
            "server_kernel": "6.12.0-host",
            "runtime": "runsc",
            "runsc_binary_digest": "2" * 64,
            "runsc_version_digest": "3" * 64,
            "dedicated_host_attestation_digest": "4" * 64,
            "dedicated_host_attestation_public_key_digest": "5" * 64,
            "dedicated_host_attestation_expires_at": valid_until.isoformat(),
            "sandbox_kernel": "4.4.0-gvisor",
            "runner_name": "sandbox-runner-01",
            "runner_group": "production-isolation",
            "runner_labels": sorted(MODULE.REQUIRED_LABELS),
            "node_pool": "dedicated-gvisor-a",
            "source_repository": "example/AgentSphere",
            "source_commit": "6" * 40,
            "source_workflow_ref": "example/AgentSphere/.github/workflows/linux-isolation.yml@refs/heads/main",
            "checks": {name: True for name in MODULE.CHECKS},
            "production_evidence": True,
            "measured_at": measured.isoformat(),
            "valid_until": valid_until.isoformat(),
            "evidence_digest": "",
        }
        unsigned = dict(report)
        unsigned.pop("evidence_digest")
        report["evidence_digest"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return report, measured + timedelta(minutes=1)

    def test_exact_production_report_verifies(self) -> None:
        report, now = self.fixture()
        source_environment = {
            "GITHUB_REPOSITORY": report["source_repository"],
            "GITHUB_SHA": report["source_commit"],
            "GITHUB_WORKFLOW_REF": report["source_workflow_ref"],
            "RUNNER_NAME": report["runner_name"],
        }
        with patch.dict("os.environ", source_environment):
            self.assertEqual(MODULE.verify(report, now=now), report["evidence_digest"])

    def test_tampered_or_baseline_report_fails_closed(self) -> None:
        report, now = self.fixture()
        report["runtime"] = "runc"
        with self.assertRaisesRegex(
            MODULE.IsolationReportError, "NOT_PRODUCTION_EVIDENCE"
        ):
            MODULE.verify(report, now=now)


if __name__ == "__main__":
    unittest.main()
