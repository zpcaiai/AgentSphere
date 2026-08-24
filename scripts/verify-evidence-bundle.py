#!/usr/bin/env python3
"""Offline verifier for the checked-in production-closure evidence bundle."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence/production-closure/evidence-bundle-manifest.json"
PRODUCTION_CLOSURE = ROOT / "evidence/production-closure"

BATCH_STATUSES = {
    "NOT_STARTED", "IN_PROGRESS", "IMPLEMENTED", "EVIDENCE_VERIFIED", "BLOCKED",
}
REQUIRED_GATES = {
    "CONTRACT_COMPATIBILITY": False,
    "SUPPLY_CHAIN_PROVENANCE": True,
    "MULTITENANT_ISOLATION": True,
    "IDEMPOTENCY_AND_RECOVERY": True,
    "CONTINUOUS_AUTHORIZATION": True,
    "DOMAIN_CODING": True,
    "DOMAIN_INDUSTRIAL": True,
    "DOMAIN_ENERGY": True,
    "DOMAIN_MEDICAL": True,
    "DOMAIN_SENSITIVE_INTERACTION": True,
    "SECURITY_CAMPAIGN": True,
    "HA_DR_RESTORE": True,
    "UPGRADE_ROLLBACK": True,
    "CONTROL_EVIDENCE_GRAPH": True,
    "ENTERPRISE_ACCEPTANCE": True,
}
GATE_RESULTS = {
    "NOT_RUN", "NOT_RUN_RESOURCE_FREEZE", "NOT_RUN_CONFIGURATION",
    "NOT_RUN_EXTERNAL_ENVIRONMENT", "NOT_PROVIDED", "FAIL", "FAIL_EXTERNAL_GATE",
    "PASS", "PASS_SCOPE_BOUND", "EVIDENCE_VERIFIED",
}
CODE_STATUSES = {"IMPLEMENTED_AND_TESTED", "IMPLEMENTED_FAIL_CLOSED_VERIFIER"}
EXTERNAL_STATUSES = {
    "NOT_RUN_CONFIGURATION", "NOT_RUN_EXTERNAL_ENVIRONMENT", "NOT_PROVIDED",
    "FAIL_EXTERNAL_GATE",
}
HEAVY_READINESS_GATES = {
    "rust_changed_crates", "rust_workspace_current_run", "rust_clippy_current_run",
    "rustfmt", "python_full_suite", "spring_boot_java21", "vue_production_build",
    "contracts_full_conformance", "enterprise_non_bypass_rls", "global_tenant_table_rls",
    "postgresql_rust_persistence", "current_rego_run",
}
REQUIRED_BLOCKING_REASONS = {
    "BATCH_01_35_NOT_EVIDENCE_VERIFIED",
    "REAL_SUPPLY_CHAIN_GATE_NOT_RUN",
    "REAL_MULTITENANT_GATE_NOT_RUN",
    "REAL_DOMAIN_GATES_NOT_RUN",
    "REAL_SECURITY_CAMPAIGN_NOT_RUN",
    "REAL_MULTI_ZONE_HA_DR_RESTORE_NOT_RUN",
    "REPRESENTATIVE_PRODUCTION_LOAD_NOT_RUN",
    "REAL_ENTERPRISE_ACCEPTANCE_NOT_RUN",
    "IMMUTABLE_GIT_PROVENANCE_NOT_CONFIGURED",
    "CURRENT_RELEASE_HEAVY_VALIDATION_NOT_RUN_RESOURCE_FREEZE",
}
REQUIRED_DENIAL_REASONS = {
    "BATCH_STATUSES_NOT_EVIDENCE_VERIFIED",
    "REQUIRED_REAL_ENVIRONMENT_GATES_NOT_RUN",
    "BLOCKING_RESIDUAL_RISKS_OPEN",
    "IMMUTABLE_GIT_PROVENANCE_ABSENT",
    "CUSTOMER_EXPERT_INDEPENDENT_SIGNATURES_ABSENT",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MIGRATION_PATH = re.compile(r"^[A-Za-z0-9._/-]+\.sql$")


def read_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"EVIDENCE_BUNDLE_JSON_OBJECT_REQUIRED:{path.relative_to(ROOT)}")
    return value


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def require_string_set(value: object, code: str) -> set[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise RuntimeError(code)
    return set(value)


def production_migration_required_items() -> set[str]:
    manifest = ROOT / "migrations/manifest.txt"
    entries = [
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if (
        len(entries) != 66
        or len(entries) != len(set(entries))
        or any(
            not MIGRATION_PATH.fullmatch(relative)
            or Path(relative).is_absolute()
            or Path(relative).as_posix() != relative
            or ".." in Path(relative).parts
            for relative in entries
        )
    ):
        raise RuntimeError("EVIDENCE_BUNDLE_MIGRATION_MANIFEST_INVALID")
    return {f"migrations/{relative}" for relative in entries}


def verify_non_certificate_truth(manifest: dict[str, object]) -> None:
    if (
        manifest.get("offline_verification_required") is not True
        or manifest.get("production_certificate_included") is not False
    ):
        raise RuntimeError("EVIDENCE_BUNDLE_NON_CERTIFICATE_METADATA_INVALID")
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise RuntimeError("EVIDENCE_BUNDLE_RELEASE_ID_INVALID")

    batch_statuses: Counter[str] = Counter()
    for batch in range(1, 37):
        expected = f"{batch:02}"
        status = read_object(
            ROOT / f"evidence/batch-{expected}/IMPLEMENTATION_STATUS.json"
        )
        if (
            status.get("project") != "agent-trust-control-plane"
            or status.get("batch") != expected
            or status.get("commit") != release_id
            or status.get("status") not in BATCH_STATUSES
        ):
            raise RuntimeError(f"EVIDENCE_BUNDLE_BATCH_STATUS_INVALID:{expected}")
        batch_statuses[str(status["status"])] += 1

    readiness = read_object(PRODUCTION_CLOSURE / "production-readiness-report.json")
    expected_summary = {
        "IN_PROGRESS": batch_statuses["IN_PROGRESS"],
        "EVIDENCE_VERIFIED": batch_statuses["EVIDENCE_VERIFIED"],
    }
    blocking_reasons = require_string_set(
        readiness.get("blocking_reason_codes"),
        "EVIDENCE_BUNDLE_READINESS_BLOCKERS_INVALID",
    )
    local_code_gates = readiness.get("local_code_gates")
    if (
        sum(batch_statuses.values()) != 36
        or set(batch_statuses) - BATCH_STATUSES
        or readiness.get("release_id") != release_id
        or readiness.get("batch_status_summary") != expected_summary
        or readiness.get("eligible") is not False
        or readiness.get("production_closure_certificate") != "NOT_ISSUED"
        or not isinstance(local_code_gates, dict)
        or not HEAVY_READINESS_GATES.issubset(local_code_gates)
        or any(
            not isinstance(local_code_gates.get(gate), str)
            or not str(local_code_gates[gate]).startswith("NOT_RUN_RESOURCE_FREEZE")
            for gate in HEAVY_READINESS_GATES
        )
        or not REQUIRED_BLOCKING_REASONS.issubset(blocking_reasons)
    ):
        raise RuntimeError("EVIDENCE_BUNDLE_READINESS_TRUTH_MISMATCH")

    gate_results = read_object(PRODUCTION_CLOSURE / "gate-results.json")
    matrix = read_object(PRODUCTION_CLOSURE / "external-condition-matrix.json")
    denial = read_object(PRODUCTION_CLOSURE / "CERTIFICATE_NOT_ISSUED.json")
    risks = read_object(PRODUCTION_CLOSURE / "residual-risk-register.json")
    gates = gate_results.get("gates")
    if not isinstance(gates, list) or len(gates) != len(REQUIRED_GATES):
        raise RuntimeError("EVIDENCE_BUNDLE_GATE_RESULTS_INVALID")
    indexed_gates: dict[str, dict[str, object]] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            raise RuntimeError("EVIDENCE_BUNDLE_GATE_RESULTS_INVALID")
        gate_id = gate.get("gate_id")
        if (
            not isinstance(gate_id, str)
            or gate_id in indexed_gates
            or gate_id not in REQUIRED_GATES
            or gate.get("external_required") is not REQUIRED_GATES[gate_id]
            or gate.get("result") not in GATE_RESULTS
        ):
            raise RuntimeError("EVIDENCE_BUNDLE_GATE_RESULTS_INVALID")
        indexed_gates[gate_id] = gate
    if set(indexed_gates) != set(REQUIRED_GATES):
        raise RuntimeError("EVIDENCE_BUNDLE_GATE_RESULTS_INVALID")

    matrix_digest = matrix.get("matrix_digest")
    matrix_material = dict(matrix)
    matrix_material.pop("matrix_digest", None)
    conditions = matrix.get("conditions")
    condition_config = read_object(
        ROOT / "config/production-runtime/conditions.json"
    ).get("conditions")
    if not isinstance(conditions, list) or not isinstance(condition_config, list):
        raise RuntimeError("EVIDENCE_BUNDLE_EXTERNAL_MATRIX_INVALID")
    expected_condition_ids = {
        item.get("condition_id") for item in condition_config if isinstance(item, dict)
    }
    indexed_conditions: dict[str, dict[str, object]] = {}
    for condition in conditions:
        if not isinstance(condition, dict):
            raise RuntimeError("EVIDENCE_BUNDLE_EXTERNAL_MATRIX_INVALID")
        condition_id = condition.get("condition_id")
        code_paths = condition.get("code_paths")
        required_inputs = condition.get("required_external_inputs")
        if (
            not isinstance(condition_id, str)
            or condition_id in indexed_conditions
            or condition_id not in expected_condition_ids
            or condition.get("code_status") not in CODE_STATUSES
            or condition.get("external_status") not in EXTERNAL_STATUSES
            or condition.get("blocking") is not True
            or not isinstance(code_paths, list)
            or not code_paths
            or any(not isinstance(path, str) or not path for path in code_paths)
            or len(code_paths) != len(set(code_paths))
            or not isinstance(required_inputs, list)
            or not required_inputs
            or any(not isinstance(item, str) or not item for item in required_inputs)
        ):
            raise RuntimeError("EVIDENCE_BUNDLE_EXTERNAL_MATRIX_INVALID")
        indexed_conditions[condition_id] = condition
    matrix_summary = matrix.get("summary")
    if (
        set(indexed_conditions) != expected_condition_ids
        or not isinstance(matrix_digest, str)
        or not SHA256.fullmatch(matrix_digest)
        or canonical_digest(matrix_material) != matrix_digest
        or matrix.get("schema_version") != "agenttrust.external-condition-matrix.v1"
        or matrix.get("overall_status") != "IN_PROGRESS"
        or matrix_summary != {
            "condition_count": len(indexed_conditions),
            "code_gate_ready": len(indexed_conditions),
            "external_verified": 0,
        }
    ):
        raise RuntimeError("EVIDENCE_BUNDLE_EXTERNAL_MATRIX_INVALID")

    risk_entries = risks.get("risks")
    if not isinstance(risk_entries, list) or not risk_entries:
        raise RuntimeError("EVIDENCE_BUNDLE_RISK_REGISTER_INVALID")
    risk_ids: set[str] = set()
    for risk in risk_entries:
        if not isinstance(risk, dict):
            raise RuntimeError("EVIDENCE_BUNDLE_RISK_REGISTER_INVALID")
        risk_id = risk.get("risk_id")
        severity = risk.get("severity")
        status = risk.get("status")
        if (
            not isinstance(risk_id, str)
            or risk_id in risk_ids
            or severity not in {"P0", "P1", "P2", "P3"}
            or status not in {"OPEN", "CLOSED", "ACCEPTED"}
            or severity in {"P0", "P1"} and status != "OPEN"
            or not isinstance(risk.get("owner"), str)
            or not isinstance(risk.get("description"), str)
            or not risk.get("description")
        ):
            raise RuntimeError("EVIDENCE_BUNDLE_RISK_REGISTER_INVALID")
        risk_ids.add(risk_id)

    denial_reasons = require_string_set(
        denial.get("reason_codes"), "EVIDENCE_BUNDLE_DENIAL_INVALID"
    )
    readiness_matrix = readiness.get("external_condition_matrix")
    if any(
        document.get("release_id") != release_id
        for document in (gate_results, matrix, denial, risks)
    ) or (
        gate_results.get("schema_version") != "agenttrust.production-gate-results.v1"
        or gate_results.get("scope_bound") is not False
        or gate_results.get("external_condition_matrix_ref")
        != "evidence/production-closure/external-condition-matrix.json"
        or gate_results.get("eligible") is not False
        or matrix.get("production_evidence") is not False
        or matrix.get("eligible") is not False
        or matrix.get("production_closure_certificate") != "NOT_ISSUED"
        or readiness_matrix != {
            "ref": "evidence/production-closure/external-condition-matrix.json",
            "condition_count": len(indexed_conditions),
            "code_gate_ready": len(indexed_conditions),
            "external_verified": 0,
        }
        or denial.get("schema_version") != "agenttrust.production-closure-denial.v1"
        or denial.get("decision") != "NOT_ISSUED"
        or denial.get("signature") is not None
        or not REQUIRED_DENIAL_REASONS.issubset(denial_reasons)
        or risks.get("schema_version") != "agenttrust.residual-risk-register.v1"
        or risks.get("production_eligible") is not False
        or risks.get("p0_p1_waiver_allowed") is not False
    ):
        raise RuntimeError("EVIDENCE_BUNDLE_PRODUCTION_TRUTH_MISMATCH")


def main() -> int:
    manifest = read_object(MANIFEST)
    if manifest.get("schema_version") != "agenttrust.closure-evidence-bundle.v1":
        raise RuntimeError("EVIDENCE_BUNDLE_SCHEMA_UNSUPPORTED")
    verify_non_certificate_truth(manifest)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("EVIDENCE_BUNDLE_ARTIFACTS_INVALID")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        relative = artifact.get("path", "")
        expected = artifact.get("sha256", "")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        path = (ROOT / relative).resolve()
        if (
            not relative
            or relative in seen
            or not path.is_relative_to(ROOT)
            or not SHA256.fullmatch(expected)
            or not path.is_file()
        ):
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"EVIDENCE_BUNDLE_DIGEST_MISMATCH:{relative}")
        seen.add(relative)
    if not seen:
        raise RuntimeError("EVIDENCE_BUNDLE_EMPTY")
    required = {
        *(f"evidence/batch-{batch:02}/IMPLEMENTATION_STATUS.json" for batch in range(1, 37)),
        *production_migration_required_items(),
        ".github/workflows/ci.yml",
        "config/production-runtime/conditions.json",
        "requirements-ci.txt",
        "python/durable_worker/requirements.production.txt",
        "migrations/manifest.txt",
        "scripts/run-production-migrations.sh",
        "scripts/validate-production-migrations.py",
        "python/production_gates/tests/test_migration_idempotency.py",
        "evidence/verification-summary.json",
        "evidence/production-closure/production-readiness-report.json",
        "evidence/production-closure/gate-results.json",
        "evidence/production-closure/residual-risk-register.json",
        "evidence/production-closure/external-condition-matrix.json",
        "evidence/production-closure/CERTIFICATE_NOT_ISSUED.json",
        "schemas/release/external-condition-matrix.schema.json",
        "python/production_gates/git_provenance.py",
        "python/production_gates/release_binding.py",
        "scripts/render-production-stack.py",
        "schemas/release/signed-git-provenance.schema.json",
        "schemas/release/git-provenance-keyring.schema.json",
        "schemas/release/signed-release-binding.schema.json",
        "schemas/release/release-binding-keyring.schema.json",
        "deploy/kubernetes/production-stack-values.schema.json",
        "deploy/kubernetes/production-stack.yaml.tmpl",
        "python/production_gates/tests/test_git_provenance.py",
        "python/production_gates/tests/test_signed_git_provenance.py",
        "python/production_gates/tests/test_release_binding.py",
        "python/production_gates/tests/test_production_deployment.py",
        "python/production_gates/tests/test_evidence_bundle_verifier.py",
        "rust/crates/bounded-http/Cargo.toml",
        "rust/crates/bounded-http/src/lib.rs",
        "scripts/validate-rust-http-bounds.py",
        "rust/crates/enterprise-approval/src/review_evidence.rs",
        "rust/crates/enterprise-approval/src/lib.rs",
        "rust/crates/enterprise-approval/src/postgres.rs",
        "rust/crates/enterprise-approval/tests/production_contract.rs",
        "schemas/approval/review-evidence-issue.schema.json",
        "schemas/approval/review-evidence-keyring.schema.json",
        "schemas/approval/approval-case.schema.json",
        "schemas/openapi/approval-v1.yaml",
        "schemas/evidence/evaluation-request.schema.json",
        "schemas/openapi/execution-v1.yaml",
        "schemas/openapi/evidence-v1.yaml",
        "migrations/enterprise-approval/0036_01_25_approval_review_evidence_v2.sql",
        "rust/crates/domain-risk-packs/server.rs",
        "rust/crates/domain-risk-packs/tests/production_contract.rs",
        "rust/crates/pack-supply-chain/src/server.rs",
        "rust/crates/pack-supply-chain/tests/production_contract.rs",
        "rust/crates/platform-sre/src/server.rs",
        "rust/crates/platform-sre/tests/production_contract.rs",
        "rust/crates/data-governance/src/server.rs",
        "rust/crates/data-governance/tests/production_contract.rs",
        "python/production_gates/tests/test_supply_domain_contract.py",
        "scripts/verify-evidence-bundle.py",
    }
    missing = required - seen
    if missing:
        raise RuntimeError(f"EVIDENCE_BUNDLE_REQUIRED_ARTIFACT_MISSING:{sorted(missing)}")
    print(f"verified {len(seen)} closure evidence artifacts; production certificate included=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
