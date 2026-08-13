#!/usr/bin/env python3
"""Offline integrity and safety-boundary verifier for external gate baselines."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/external-gates"
EXPECTED = {
    "linux-isolation-baseline.json": ("agenttrust.linux-isolation-report.v1", None),
    "enterprise-iam-not-run.json": ("agenttrust.external-gate-report.v1", "NOT_RUN_CONFIGURATION"),
    "temporal-local-protocol.json": ("agenttrust.external-gate-report.v1", "PASS_REAL_PROTOCOL"),
    "object-store-local-s3.json": ("agenttrust.external-gate-report.v1", "PASS_REAL_PROTOCOL"),
    "model-provider-live-catalog.json": ("agenttrust.external-gate-report.v1", "PASS_REAL_PROTOCOL"),
    "model-generation-live-failed.json": ("agenttrust.external-gate-report.v1", "FAIL"),
    "postgres-single-host-failover.json": ("agenttrust.postgres-failover-report.v1", None),
    "backup-restore-local-drill.json": ("agenttrust.backup-restore-drill.v1", None),
    "gateway-local-load.json": ("agenttrust.http-load-report.v1", None),
    "kubernetes-local-recovery.json": ("agenttrust.kubernetes-recovery-drill.v1", None),
}
FORBIDDEN_KEY_PARTS = ("password", "private_key", "api_key", "access_key", "secret_key", "bearer")


def _walk(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower()
            if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
                raise RuntimeError(f"EXTERNAL_EVIDENCE_SECRET_FIELD:{key}")
            _walk(child)
    elif isinstance(value, list):
        for child in value:
            _walk(child)


def main() -> int:
    actual_names = {path.name for path in EVIDENCE.glob("*.json")}
    if actual_names != set(EXPECTED):
        raise RuntimeError("EXTERNAL_EVIDENCE_SET_MISMATCH")
    for name, (schema_version, expected_status) in EXPECTED.items():
        value = json.loads((EVIDENCE / name).read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != schema_version
            or value.get("production_evidence") is not False
        ):
            raise RuntimeError(f"EXTERNAL_EVIDENCE_BOUNDARY_INVALID:{name}")
        if expected_status is not None and value.get("status") != expected_status:
            raise RuntimeError(f"EXTERNAL_EVIDENCE_STATUS_INVALID:{name}")
        claimed = value.pop("evidence_digest", "")
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if claimed != hashlib.sha256(canonical).hexdigest():
            raise RuntimeError(f"EXTERNAL_EVIDENCE_DIGEST_MISMATCH:{name}")
        _walk(value)
    print(f"verified {len(EXPECTED)} external baseline reports; production_evidence=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
