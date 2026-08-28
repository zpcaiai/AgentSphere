#!/usr/bin/env python3
"""Verify a production Linux/gVisor isolation report without mutating evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


FIELDS = {
    "schema_version", "mode", "image", "server_kernel", "runtime",
    "runsc_binary_digest", "runsc_version_digest",
    "dedicated_host_attestation_digest",
    "dedicated_host_attestation_public_key_digest",
    "dedicated_host_attestation_expires_at", "sandbox_kernel", "runner_name",
    "runner_group", "runner_labels", "node_pool", "source_repository",
    "source_commit", "source_workflow_ref", "checks", "production_evidence",
    "measured_at", "valid_until", "evidence_digest",
}
CHECKS = {
    "linux_oci_engine", "cgroup_v2", "seccomp_filter", "non_root",
    "read_only_rootfs", "no_new_privileges", "capabilities_dropped",
    "network_namespace_none", "metadata_denied", "docker_socket_absent",
    "host_home_absent", "pid_limit_enforced", "memory_limit_enforced",
    "cleanup_verified", "dedicated_linux_host", "runsc_binary_digest_verified",
    "runsc_runtime_selected", "sandbox_kernel_isolated_from_host",
    "user_namespaces_available",
}
REQUIRED_LABELS = {
    "self-hosted", "linux", "gvisor", "cgroup-v2", "production-isolation",
    "actions-runner-2-327-1", "agenttrust-production-gvisor",
}
DIGEST = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class IsolationReportError(RuntimeError):
    pass


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise IsolationReportError("LINUX_ISOLATION_REPORT_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise IsolationReportError("LINUX_ISOLATION_REPORT_TIME_INVALID") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise IsolationReportError("LINUX_ISOLATION_REPORT_TIME_INVALID")
    return parsed


def verify(report: object, *, now: datetime | None = None) -> str:
    if not isinstance(report, dict) or set(report) != FIELDS:
        raise IsolationReportError("LINUX_ISOLATION_REPORT_CONTRACT_INVALID")
    checks = report.get("checks")
    labels = report.get("runner_labels")
    measured_at = _timestamp(report.get("measured_at"))
    valid_until = _timestamp(report.get("valid_until"))
    attestation_expires = _timestamp(report.get("dedicated_host_attestation_expires_at"))
    checked_at = now or datetime.now(timezone.utc)
    if (
        report.get("schema_version") != "agenttrust.linux-isolation-report.v1"
        or report.get("mode") != "production"
        or report.get("runtime") != "runsc"
        or report.get("production_evidence") is not True
        or not isinstance(report.get("image"), str)
        or not IMAGE.fullmatch(report["image"])
        or not isinstance(report.get("server_kernel"), str)
        or not report["server_kernel"]
        or not isinstance(report.get("sandbox_kernel"), str)
        or not report["sandbox_kernel"]
        or report["sandbox_kernel"] == report["server_kernel"]
        or any(not isinstance(report.get(field), str) or not DIGEST.fullmatch(report[field]) for field in (
            "runsc_binary_digest", "runsc_version_digest",
            "dedicated_host_attestation_digest",
            "dedicated_host_attestation_public_key_digest",
        ))
        or not isinstance(checks, dict)
        or set(checks) != CHECKS
        or any(value is not True for value in checks.values())
        or report.get("runner_group") != "production-isolation"
        or not isinstance(labels, list)
        or len(labels) != len(set(labels))
        or not REQUIRED_LABELS.issubset(set(labels))
        or not isinstance(report.get("runner_name"), str)
        or not report["runner_name"]
        or not isinstance(report.get("node_pool"), str)
        or report["node_pool"] == "NOT_APPLICABLE"
        or not isinstance(report.get("source_repository"), str)
        or not REPOSITORY.fullmatch(report["source_repository"])
        or not isinstance(report.get("source_commit"), str)
        or not COMMIT.fullmatch(report["source_commit"])
        or not isinstance(report.get("source_workflow_ref"), str)
        or report["source_workflow_ref"] == "NOT_APPLICABLE"
        or measured_at > checked_at
        or valid_until <= checked_at
        or valid_until != attestation_expires
        or valid_until - measured_at > timedelta(days=30)
    ):
        raise IsolationReportError("LINUX_ISOLATION_REPORT_NOT_PRODUCTION_EVIDENCE")
    expected_repository = os.environ.get("GITHUB_REPOSITORY")
    expected_commit = os.environ.get("GITHUB_SHA")
    expected_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    expected_runner = os.environ.get("RUNNER_NAME")
    if (
        expected_repository is not None and report["source_repository"] != expected_repository
        or expected_commit is not None and report["source_commit"] != expected_commit
        or expected_workflow_ref is not None and report["source_workflow_ref"] != expected_workflow_ref
        or expected_runner is not None and report["runner_name"] != expected_runner
    ):
        raise IsolationReportError("LINUX_ISOLATION_REPORT_SOURCE_MISMATCH")
    claimed = report.get("evidence_digest")
    if not isinstance(claimed, str) or not DIGEST.fullmatch(claimed):
        raise IsolationReportError("LINUX_ISOLATION_REPORT_DIGEST_INVALID")
    unsigned: dict[str, Any] = dict(report)
    unsigned.pop("evidence_digest")
    actual = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if actual != claimed:
        raise IsolationReportError("LINUX_ISOLATION_REPORT_DIGEST_INVALID")
    return claimed


def main() -> int:
    if len(sys.argv) != 2:
        raise IsolationReportError("LINUX_ISOLATION_REPORT_PATH_REQUIRED")
    path = Path(sys.argv[1])
    if path.is_symlink():
        raise IsolationReportError("LINUX_ISOLATION_REPORT_PATH_INVALID")
    metadata = path.stat()
    if not path.is_file() or metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
        raise IsolationReportError("LINUX_ISOLATION_REPORT_PATH_INVALID")
    report = json.loads(path.read_text(encoding="utf-8"))
    print(verify(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
