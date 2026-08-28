#!/usr/bin/env python3
"""Offline verifier for the checked-in production-closure evidence bundle."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from python.production_gates.release_code_manifest import (
    ReleaseCodeManifestError,
    load_release_code_manifest,
    repository_file_is_safe,
    repository_file_sha256,
)


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
    "BATCH_01_36_NOT_EVIDENCE_VERIFIED",
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
MAX_EVIDENCE_FILE_BYTES = 128 * 1024 * 1024
PRODUCTION_MIGRATION_COUNT = 70
MANIFEST_FIELDS = {
    "schema_version",
    "release_id",
    "generated_at",
    "artifacts",
    "offline_verification_required",
    "production_certificate_included",
}


def reject_duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError(f"EVIDENCE_BUNDLE_DUPLICATE_JSON_KEY:{key}")
        value[key] = item
    return value


def read_object(path: Path) -> dict[str, object]:
    if (
        path.is_symlink()
        or not path.is_file()
        or not 1 <= path.stat(follow_symlinks=False).st_size <= MAX_EVIDENCE_FILE_BYTES
    ):
        raise RuntimeError(f"EVIDENCE_BUNDLE_INPUT_INVALID:{path.relative_to(ROOT)}")
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_key
    )
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
        len(entries) != PRODUCTION_MIGRATION_COUNT
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


def release_code_manifest_required_items() -> set[str]:
    """Load the deterministic source inventory covered by this evidence bundle.

    The inventory is deliberately a plain, sorted list instead of executable
    discovery logic.  This makes the reviewed release surface reproducible in
    an offline checkout and prevents a dirty worktree from silently expanding
    the evidence scope.  Every listed file must still be present in the signed
    JSON evidence manifest and have its current bytes digest-checked below.
    """

    try:
        return set(load_release_code_manifest(ROOT))
    except ReleaseCodeManifestError:
        raise RuntimeError("EVIDENCE_BUNDLE_RELEASE_CODE_MANIFEST_INVALID") from None


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
        or not str(local_code_gates.get("postgresql_migrations", "")).startswith(
            f"PASS_STATIC_MANIFEST_{PRODUCTION_MIGRATION_COUNT}_"
        )
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
    generated_at = manifest.get("generated_at")
    try:
        parsed_generated_at = datetime.fromisoformat(
            str(generated_at).replace("Z", "+00:00")
        )
    except (ValueError, OverflowError):
        raise RuntimeError("EVIDENCE_BUNDLE_METADATA_INVALID") from None
    if (
        set(manifest) != MANIFEST_FIELDS
        or manifest.get("schema_version") != "agenttrust.closure-evidence-bundle.v1"
        or not isinstance(generated_at, str)
        or not generated_at.endswith("Z")
        or not 1 <= len(generated_at) <= 64
        or parsed_generated_at.tzinfo is None
        or parsed_generated_at.utcoffset()
        != timezone.utc.utcoffset(parsed_generated_at)
    ):
        raise RuntimeError("EVIDENCE_BUNDLE_SCHEMA_UNSUPPORTED")
    verify_non_certificate_truth(manifest)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("EVIDENCE_BUNDLE_ARTIFACTS_INVALID")
    seen: set[str] = set()
    ordered_paths: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        relative = artifact.get("path", "")
        expected = artifact.get("sha256", "")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        relative_path = Path(relative)
        source_path = ROOT / relative_path
        path = source_path.resolve()
        if (
            not relative
            or relative in seen
            or relative_path.is_absolute()
            or relative_path.as_posix() != relative
            or ".." in relative_path.parts
            or not path.is_relative_to(ROOT)
            or not SHA256.fullmatch(expected)
            or not repository_file_is_safe(
                ROOT,
                relative,
                maximum_bytes=MAX_EVIDENCE_FILE_BYTES,
            )
        ):
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        try:
            actual = repository_file_sha256(
                ROOT,
                relative,
                maximum_bytes=MAX_EVIDENCE_FILE_BYTES,
            )
        except ReleaseCodeManifestError:
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID") from None
        if actual != expected:
            raise RuntimeError(f"EVIDENCE_BUNDLE_DIGEST_MISMATCH:{relative}")
        seen.add(relative)
        ordered_paths.append(relative)
    if not seen or ordered_paths != sorted(ordered_paths):
        raise RuntimeError("EVIDENCE_BUNDLE_ARTIFACT_ORDER_INVALID")
    required = {
        *(f"evidence/batch-{batch:02}/IMPLEMENTATION_STATUS.json" for batch in range(1, 37)),
        *production_migration_required_items(),
        ".github/workflows/ci.yml",
        ".github/workflows/linux-isolation.yml",
        "docs/sandbox/production-requirements.md",
        "docs/platform/platform-sre-authority-runbook.md",
        "config/production-runtime/conditions.json",
        "requirements-ci.txt",
        "python/durable_worker/requirements.production.txt",
        "python/durable_worker/worker.py",
        "python/durable_worker/tests/test_worker.py",
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
        "python/production_gates/live_integrations.py",
        "python/production_gates/git_provenance.py",
        "python/production_gates/release_binding.py",
        "scripts/render-production-stack.py",
        "schemas/release/signed-git-provenance.schema.json",
        "schemas/release/git-provenance-keyring.schema.json",
        "schemas/release/signed-release-binding.schema.json",
        "schemas/release/release-binding-keyring.schema.json",
        "schemas/release/production-closure-certificate.schema.json",
        "schemas/release/production-closure-signing-request.schema.json",
        "schemas/release/production-closure-external-signature.schema.json",
        "schemas/release/production-closure-revocation-registry.schema.json",
        "rust/crates/production-closure/Cargo.toml",
        "rust/crates/production-closure/src/lib.rs",
        "rust/crates/production-closure/src/bin/production-closure.rs",
        "docs/release/production-closure-runbook.md",
        "docs/release/production-closure-external-signing.md",
        "python/production_gates/tests/test_production_closure_signing_contract.py",
        "deploy/kubernetes/production-stack-values.schema.json",
        "deploy/kubernetes/production-stack.yaml.tmpl",
        "schemas/platform-sre/sre-command.schema.json",
        "schemas/platform-sre/sre-external-receipt.schema.json",
        "python/production_gates/tests/test_git_provenance.py",
        "python/production_gates/tests/test_signed_git_provenance.py",
        "python/production_gates/tests/test_release_binding.py",
        "python/production_gates/tests/test_production_deployment.py",
        "python/production_gates/tests/test_evidence_bundle_verifier.py",
        "Cargo.toml",
        "Cargo.lock",
        "rust/crates/bounded-http/Cargo.toml",
        "rust/crates/bounded-http/src/lib.rs",
        "scripts/validate-rust-http-bounds.py",
        "rust/crates/enterprise-approval/Cargo.toml",
        "rust/crates/enterprise-approval/PRODUCTION.md",
        "rust/crates/enterprise-approval/src/bin/agenttrust-approval-service.rs",
        "rust/crates/enterprise-approval/src/evidence_delivery.rs",
        "rust/crates/enterprise-approval/src/review_evidence.rs",
        "rust/crates/enterprise-approval/src/lib.rs",
        "rust/crates/enterprise-approval/src/postgres.rs",
        "rust/crates/enterprise-approval/src/principal.rs",
        "rust/crates/enterprise-approval/src/server.rs",
        "rust/crates/enterprise-approval/tests/production_contract.rs",
        "rust/crates/contracts/Cargo.toml",
        "rust/crates/contracts/src/lib.rs",
        "rust/crates/evidence-evaluator/src/lib.rs",
        "rust/crates/evidence-evaluator/src/postgres.rs",
        "rust/crates/evidence-evaluator/src/server.rs",
        "rust/crates/identity/src/production.rs",
        "rust/crates/identity/src/server.rs",
        "rust/crates/model-gateway/src/adapters.rs",
        "rust/crates/model-gateway/src/server.rs",
        "rust/crates/policy-pep/Cargo.toml",
        "rust/crates/policy-pep/src/authority.rs",
        "rust/crates/policy-pep/src/governance.rs",
        "rust/crates/policy-pep/src/server.rs",
        "rust/crates/tool-proxy/src/production.rs",
        "schemas/pep/governance-authorization.schema.json",
        "schemas/approval/decision-evidence-keyring.schema.json",
        "schemas/approval/decision-evidence.schema.json",
        "schemas/approval/decision-request-binding.schema.json",
        "schemas/approval/decision-result.schema.json",
        "schemas/approval/review-evidence-issue.schema.json",
        "schemas/approval/review-evidence-keyring.schema.json",
        "schemas/approval/approval-case.schema.json",
        "schemas/openapi/approval-v1.yaml",
        "schemas/openapi/control-plane-v1.yaml",
        "schemas/evidence/evaluation-request.schema.json",
        "schemas/openapi/execution-v1.yaml",
        "schemas/openapi/evidence-v1.yaml",
        "migrations/enterprise-approval/0036_01_25_approval_review_evidence_v2.sql",
        "java/enterprise-control-api/pom.xml",
        "java/enterprise-control-api/src/main/resources/application.yml",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/AdminModels.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApiErrors.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApiSecurityErrorHandlers.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalScopeTokenProvider.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalAuthoritySignatureVerifier.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalDecisionEvidenceVerifier.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalIntegrationProperties.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalPrincipalAssertionSigner.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthenticatedPrincipalResolver.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthorityJson.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthorityReadinessConfiguration.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/CanonicalDigest.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/CapacityException.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ConflictException.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ControlDeniedException.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ControlProperties.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/ControlUnavailableException.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/DatabaseSecurityVerifier.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/EnterpriseController.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/EnterpriseRepository.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/EnterpriseService.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/GovernedAuthorityGateway.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/HumanPrincipalAssertionProperties.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/HumanPrincipalAssertionSigner.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/IamSecurityConfiguration.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/JacksonSecurityConfiguration.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/PepAuthorizationClient.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/PepScopeTokenProvider.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/PepTokenProperties.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/RequestBodyLimitFilter.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/SafeApiErrorWriter.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/SafeErrorBody.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/SecretFilePolicy.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/SecureRestClientFactory.java",
        "java/enterprise-control-api/src/main/java/com/agenttrust/control/SecurityConfiguration.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/ApprovalAuthoritySignatureVerifierTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/ApprovalControlContractTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/ApprovalDecisionEvidenceVerifierTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/ApprovalPrincipalAssertionSignerTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/ApprovalScopeTokenProviderTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/ApprovalTestProperties.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/AuthenticatedPrincipalResolverTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/AuthorityJsonTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/AuthorityReadinessConfigurationTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/CanonicalDigestTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/DatabaseSecurityVerifierTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/EnterpriseApprovalPersistenceTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/GovernedAuthorityGatewayTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/HumanPrincipalAssertionSignerTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/IncidentAuthorityGatewayTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/PackMarketplaceGatewayTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/PolicyAuthorityGatewayTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/PepScopeTokenProviderTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/RequestBodyLimitFilterTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/SafeApiErrorWriterTest.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/SafeErrorTestSupport.java",
        "java/enterprise-control-api/src/test/java/com/agenttrust/control/SecretFilePolicyTest.java",
        "scripts/validate-enterprise-api-contract.py",
        "scripts/rust_source_checks.py",
        "scripts/validate-node-supply-chain.py",
        "python/production_gates/tests/test_rust_source_checks.py",
        "python/production_gates/tests/test_node_supply_chain.py",
        "python/production_gates/tests/test_model_gateway_contract.py",
        "web/control-console/.npmrc",
        "web/control-console/package.json",
        "web/control-console/package-lock.json",
        "web/control-console/tsconfig.json",
        "web/control-console/vite.config.ts",
        "web/control-console/e2e/control-console.spec.ts",
        "web/control-console/src/App.vue",
        "web/control-console/src/api-client.ts",
        "web/control-console/src/api-client.test.ts",
        "web/control-console/src/agui-client.test.ts",
        "web/control-console/src/components/PolicyStudio.test.ts",
        "web/control-console/src/components/PolicyStudio.vue",
        "web/control-console/src/enterprise-api-types.ts",
        "web/control-console/src/generated/control-plane-v1.d.ts",
        "web/shared/agui-client.ts",
        "web/approval-console/src/ApprovalConsole.vue",
        "web/approval-console/src/approval-state.ts",
        "web/approval-console/src/approval-state.test.ts",
        "docs/enterprise/control-console-runbook.md",
        "rust/crates/domain-risk-packs/server.rs",
        "rust/crates/domain-risk-packs/tests/production_contract.rs",
        "rust/crates/pack-supply-chain/src/server.rs",
        "rust/crates/pack-supply-chain/tests/production_contract.rs",
        "rust/crates/platform-sre/src/server.rs",
        "rust/crates/platform-sre/src/authority.rs",
        "rust/crates/platform-sre/src/bin/agenttrust-platform-sre-service.rs",
        "rust/crates/platform-sre/tests/production_contract.rs",
        "rust/crates/integration-tests/tests/schema_assets.rs",
        "rust/crates/registry/src/server.rs",
        "rust/crates/data-governance/src/authority.rs",
        "rust/crates/data-governance/src/service.rs",
        "rust/crates/data-governance/src/server.rs",
        "rust/crates/data-governance/tests/production_contract.rs",
        "python/production_gates/tests/test_supply_domain_contract.py",
        "scripts/verify-evidence-bundle.py",
        *release_code_manifest_required_items(),
    }
    missing = required - seen
    if missing:
        raise RuntimeError(f"EVIDENCE_BUNDLE_REQUIRED_ARTIFACT_MISSING:{sorted(missing)}")
    print(f"verified {len(seen)} closure evidence artifacts; production certificate included=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
