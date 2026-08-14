#!/usr/bin/env python3
"""Audit production-runtime code contracts without claiming external evidence.

The static audit and the Rust integration test consume the same machine-readable
contract.  ``--run-rust-contract-tests`` additionally asks Cargo to compile every
adapter/trait assertion and execute the source/configuration contract tests.
Neither mode contacts live production services or upgrades an evidence status.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
CONDITION_MANIFEST = ROOT / "config/production-runtime/conditions.json"
ADAPTER_CONTRACT = (
    ROOT / "rust/crates/production-runtime/tests/adapter-contracts.json"
)
RUST_CONTRACT_TEST = (
    ROOT / "rust/crates/production-runtime/tests/adapter_contracts.rs"
)

EXPECTED_CONDITIONS = {
    "ENTERPRISE_IDP_JWKS",
    "WORKLOAD_MTLS_CA",
    "SECRET_BROKER_DYNAMIC_LEASES",
    "DEDICATED_LINUX_GVISOR",
    "PRODUCTION_MULTIZONE_TEMPORAL",
    "MANAGED_DATABASE_MULTI_ZONE",
    "LOCKED_RETENTION_OBJECT_STORAGE",
    "MODEL_GENERATION_STREAM_DLP_BILLING_RESIDENCY",
    "MCP_REAL_ENDPOINT",
    "A2A_REAL_ENDPOINT",
    "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
    "SUPERVISED_PHYSICAL_WRITE",
    "MULTIZONE_CONTROL_PLANE_TOPOLOGY",
    "NETWORK_STORAGE_CONTROL_PLANE_FAULTS",
    "SUSTAINED_PRODUCTION_LOAD",
    "CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE",
    "IMMUTABLE_GIT_RELEASE_PROVENANCE",
}

EXPECTED_ADAPTERS = {
    "identity": ("ProductionIdentityVerifier", "IdentityVerifierPort", "identity_jwks", "identity.jwks_endpoint"),
    "orchestrator": ("HttpOrchestratorAdapter", "OrchestratorSubmissionPort", "endpoint", "orchestrator"),
    "model": ("ProductionModelAdapter", "ModelProviderAdapter", "endpoint_prefix", "model:"),
    "secret_broker": ("SecretBrokerCredentialLifecycle", "CredentialLifecyclePort", "endpoint", "secret_broker"),
    "industrial": ("HttpIndustrialAdapter", "IndustrialAdapter", "endpoint", "industrial"),
    "backup": ("HttpBackupPort", "BackupPort", "endpoint", "backup"),
    "policy_distribution": ("HttpPolicyDistributionPort", "PolicyDistributionPort", "endpoint", "policy_distribution"),
    "containment": ("HttpContainmentPort", "ContainmentPort", "endpoint", "containment"),
    "recertification": ("HttpRecertificationPort", "RecertificationPort", "endpoint", "recertification"),
    "enterprise_integration": ("HttpEnterpriseIntegration", "IntegrationPort", "endpoint", "enterprise_integration"),
    "authority": ("HttpAuthoritativeService", "AuthoritativeServicePort", "endpoint", "authority"),
    "notification": ("HttpNotificationAdapter", "NotificationAdapter", "endpoint", "notification"),
    "evidence": ("FilesystemEvidenceSource", "EvidenceSourcePort", "evidence_files", "evidence_files"),
    "mcp": ("HttpMcpTransport", "ControlledMcpTransport", "endpoint_prefix", "mcp:"),
    "a2a": ("A2aPeerClient", None, "endpoint_prefix", "a2a:"),
    "runtime_control": ("HttpRuntimeControlPort", "RuntimeControlPort", "endpoint", "runtime_control"),
    "lifecycle": ("HttpLifecyclePropagationPort", "LifecyclePropagationPort", "endpoint", "lifecycle"),
}

EXPECTED_AUXILIARY_TRAITS = {
    "identity": {("RefreshingJwksProvider", "FederatedTrustBundleProvider")},
    "orchestrator": {("ProductionOrchestratorBinding", "OrchestratorSubmissionPort")},
    "model": {("ControlledModelTransport", "ProviderWireTransport")},
}


class AuditError(RuntimeError):
    pass


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"PRODUCTION_RUNTIME_JSON_INVALID:{path.relative_to(ROOT)}") from error
    if not isinstance(value, dict):
        raise AuditError(f"PRODUCTION_RUNTIME_JSON_NOT_OBJECT:{path.relative_to(ROOT)}")
    return value


def _rows(value: Any, code: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or not all(isinstance(row, dict) for row in value):
        raise AuditError(code)
    return value


def _safe_file(raw: Any) -> tuple[Path, str]:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise AuditError(f"PRODUCTION_RUNTIME_PATH_INVALID:{raw!r}")
    path = ROOT / raw
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AuditError(f"PRODUCTION_RUNTIME_PATH_INVALID:{raw}") from error
    if not resolved.is_relative_to(ROOT.resolve()) or not resolved.is_file():
        raise AuditError(f"PRODUCTION_RUNTIME_PATH_INVALID:{raw}")
    return resolved, raw


def _strings(value: Any, code: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise AuditError(code)
    if len(value) != len(set(value)):
        raise AuditError(f"{code}_DUPLICATE")
    return value


def _implementation_scope(source: str, anchor: str) -> str:
    start = source.find(anchor)
    if start < 0:
        raise AuditError(f"PRODUCTION_ADAPTER_SCOPE_MISSING:{anchor}")
    opening = source.find("{", start)
    if opening < 0:
        raise AuditError(f"PRODUCTION_ADAPTER_SCOPE_INVALID:{anchor}")
    depth = 0
    for offset, character in enumerate(source[opening:], opening):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
            if depth < 0:
                break
    raise AuditError(f"PRODUCTION_ADAPTER_SCOPE_INVALID:{anchor}")


def _test_declared(source: str, name: str) -> bool:
    if re.search(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\(", source, re.MULTILINE):
        return name.startswith("test_")
    match = re.search(rf"\b(?:async\s+)?fn\s+{re.escape(name)}\s*\(", source)
    if match is None:
        return False
    prefix = source[max(0, match.start() - 512) : match.start()]
    return "#[test]" in prefix or "#[tokio::test" in prefix


def _set(values: Iterable[Any], code: str) -> set[str]:
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or value in result:
            raise AuditError(code)
        result.add(value)
    return result


def _audit_condition_manifest() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    manifest = _load_object(CONDITION_MANIFEST)
    if set(manifest) != {"schema_version", "fail_closed", "conditions"}:
        raise AuditError("PRODUCTION_RUNTIME_BINDING_MANIFEST_SHAPE_INVALID")
    if (
        manifest.get("schema_version") != "agenttrust.production-runtime-condition-bindings.v1"
        or manifest.get("fail_closed") is not True
    ):
        raise AuditError("PRODUCTION_RUNTIME_BINDING_MANIFEST_INVALID")
    rows = _rows(manifest.get("conditions"), "PRODUCTION_RUNTIME_CONDITION_ROWS_INVALID")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        condition_id = row.get("condition_id")
        if not isinstance(condition_id, str) or condition_id in by_id:
            raise AuditError("PRODUCTION_RUNTIME_CONDITION_ID_INVALID")
        if row.get("external_evidence_required") is not True:
            raise AuditError(f"EXTERNAL_EVIDENCE_BOUNDARY_MISSING:{condition_id}")
        if set(row) != {"condition_id", "runtime_paths", "test_paths", "external_evidence_required"}:
            raise AuditError(f"PRODUCTION_RUNTIME_CONDITION_SHAPE_INVALID:{condition_id}")
        for field in ("runtime_paths", "test_paths"):
            for raw in _strings(
                row.get(field),
                f"PRODUCTION_RUNTIME_PATH_SET_INVALID:{condition_id}:{field}",
            ):
                _safe_file(raw)
        by_id[condition_id] = row
    if set(by_id) != EXPECTED_CONDITIONS:
        raise AuditError("PRODUCTION_RUNTIME_CONDITION_SET_INCOMPLETE")
    return manifest, by_id


def _audit_operation(adapter_id: str, source: str, operation: Mapping[str, Any]) -> None:
    expected_fields = {"scope", "method", "wire_path", "transport_call"}
    if set(operation) != expected_fields or not all(
        isinstance(operation.get(field), str) and operation[field] for field in expected_fields
    ):
        raise AuditError(f"PRODUCTION_ADAPTER_OPERATION_INVALID:{adapter_id}")
    scope = _implementation_scope(source, operation["scope"])
    method = operation["method"]
    call = operation["transport_call"]
    wire_path = operation["wire_path"]
    if call not in scope or wire_path not in scope:
        raise AuditError(f"PRODUCTION_ADAPTER_WIRE_CONTRACT_MISSING:{adapter_id}:{method}:{wire_path}")
    method_call_valid = (
        (method == "GET" and "get_bytes" in call)
        or (method == "POST" and "post_json" in call)
        or (method == "FILE_READ" and call == "read_json(")
    )
    if not method_call_valid:
        raise AuditError(f"PRODUCTION_ADAPTER_METHOD_CONTRACT_INVALID:{adapter_id}:{method}")
    if wire_path.startswith("/") and (wire_path.startswith("//") or ".." in wire_path):
        raise AuditError(f"PRODUCTION_ADAPTER_WIRE_PATH_INVALID:{adapter_id}:{wire_path}")


def _absolute_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise AuditError(code)
    return value


def _audit_endpoint(adapter_id: str, endpoint: Any, binding: Mapping[str, Any]) -> None:
    if not isinstance(endpoint, dict):
        raise AuditError(f"PRODUCTION_ADAPTER_ENDPOINT_INVALID:{adapter_id}")
    base_url = endpoint.get("base_url")
    health_path = endpoint.get("health_path")
    tls = endpoint.get("tls")
    if (
        not isinstance(base_url, str)
        or not base_url.startswith("https://")
        or not isinstance(health_path, str)
        or not health_path.startswith("/")
        or health_path.startswith("//")
        or ".." in health_path
        or not isinstance(tls, dict)
    ):
        raise AuditError(f"PRODUCTION_ADAPTER_ENDPOINT_INVALID:{adapter_id}")
    _absolute_string(tls.get("ca_bundle"), f"PRODUCTION_ADAPTER_CA_INVALID:{adapter_id}")
    if binding.get("client_identity_required") is True:
        _absolute_string(
            tls.get("client_identity_pem"),
            f"PRODUCTION_ADAPTER_CLIENT_IDENTITY_INVALID:{adapter_id}",
        )
    if binding.get("token_required") is True:
        _absolute_string(
            tls.get("bearer_token_file"),
            f"PRODUCTION_ADAPTER_TOKEN_FILE_INVALID:{adapter_id}",
        )
    timeout = tls.get("timeout_ms")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 120_000:
        raise AuditError(f"PRODUCTION_ADAPTER_TIMEOUT_INVALID:{adapter_id}")


def _audit_config_bindings(adapters: Sequence[Mapping[str, Any]]) -> None:
    config = _load_object(ROOT / "config/production-runtime.example.json")
    if (
        config.get("schema_version") != "agenttrust.production-runtime-config.v1"
        or config.get("fail_closed") is not True
    ):
        raise AuditError("PRODUCTION_RUNTIME_EXAMPLE_NOT_FAIL_CLOSED")
    endpoints = config.get("endpoints")
    if not isinstance(endpoints, dict) or not endpoints:
        raise AuditError("PRODUCTION_RUNTIME_EXAMPLE_ENDPOINTS_INVALID")
    bound_endpoints: set[str] = set()
    for adapter in adapters:
        adapter_id = adapter["family_id"]
        binding = adapter.get("config_binding")
        if not isinstance(binding, dict) or set(binding) != {
            "kind", "selector", "client_identity_required", "token_required"
        }:
            raise AuditError(f"PRODUCTION_ADAPTER_CONFIG_BINDING_INVALID:{adapter_id}")
        if not isinstance(binding.get("client_identity_required"), bool) or not isinstance(
            binding.get("token_required"), bool
        ):
            raise AuditError(f"PRODUCTION_ADAPTER_CONFIG_BINDING_INVALID:{adapter_id}")
        kind = binding.get("kind")
        selector = binding.get("selector")
        if kind == "endpoint":
            if selector not in endpoints:
                raise AuditError(f"PRODUCTION_ADAPTER_ENDPOINT_MISSING:{adapter_id}:{selector}")
            _audit_endpoint(adapter_id, endpoints[selector], binding)
            bound_endpoints.add(selector)
        elif kind == "endpoint_prefix":
            matches = {name for name in endpoints if isinstance(name, str) and name.startswith(selector)}
            if not matches:
                raise AuditError(f"PRODUCTION_ADAPTER_ENDPOINT_PREFIX_MISSING:{adapter_id}:{selector}")
            for name in matches:
                _audit_endpoint(adapter_id, endpoints[name], binding)
            bound_endpoints.update(matches)
        elif kind == "identity_jwks":
            identity = config.get("identity")
            if not isinstance(identity, dict) or identity.get("require_mtls_peer") is not True:
                raise AuditError("PRODUCTION_IDENTITY_INGRESS_BINDING_INVALID")
            jwks = identity.get("jwks_endpoint")
            tls = identity.get("jwks_tls")
            if not isinstance(jwks, str) or not jwks.startswith("https://") or not isinstance(tls, dict):
                raise AuditError("PRODUCTION_IDENTITY_JWKS_BINDING_INVALID")
            _absolute_string(tls.get("ca_bundle"), "PRODUCTION_IDENTITY_JWKS_CA_INVALID")
        elif kind == "evidence_files":
            files = config.get("evidence_files")
            if not isinstance(files, dict) or set(files) != {
                "batch_statuses", "gate_evidence", "residual_risks", "exceptions"
            }:
                raise AuditError("PRODUCTION_EVIDENCE_FILE_BINDING_INVALID")
            paths = [_absolute_string(value, "PRODUCTION_EVIDENCE_PATH_INVALID") for value in files.values()]
            if len(paths) != len(set(paths)):
                raise AuditError("PRODUCTION_EVIDENCE_PATH_DUPLICATE")
        else:
            raise AuditError(f"PRODUCTION_ADAPTER_CONFIG_BINDING_INVALID:{adapter_id}")
    if bound_endpoints != set(endpoints):
        raise AuditError("PRODUCTION_RUNTIME_ENDPOINT_NOT_BOUND_TO_ADAPTER")


def _audit_adapter_contracts() -> dict[str, Any]:
    contract = _load_object(ADAPTER_CONTRACT)
    if set(contract) != {
        "schema_version", "external_evidence_required", "adapters", "condition_tests"
    }:
        raise AuditError("PRODUCTION_ADAPTER_CONTRACT_SHAPE_INVALID")
    if (
        contract.get("schema_version") != "agenttrust.production-adapter-contracts.v1"
        or contract.get("external_evidence_required") is not True
    ):
        raise AuditError("PRODUCTION_ADAPTER_CONTRACT_INVALID")
    adapters = _rows(contract.get("adapters"), "PRODUCTION_ADAPTER_ROWS_INVALID")
    by_id: dict[str, dict[str, Any]] = {}
    for adapter in adapters:
        adapter_id = adapter.get("family_id")
        if not isinstance(adapter_id, str) or adapter_id in by_id:
            raise AuditError("PRODUCTION_ADAPTER_ID_INVALID")
        expected = EXPECTED_ADAPTERS.get(adapter_id)
        if expected is None:
            raise AuditError(f"PRODUCTION_ADAPTER_UNEXPECTED:{adapter_id}")
        binding = adapter.get("config_binding")
        actual = (
            adapter.get("adapter"),
            adapter.get("trait"),
            binding.get("kind") if isinstance(binding, dict) else None,
            binding.get("selector") if isinstance(binding, dict) else None,
        )
        if actual != expected:
            raise AuditError(f"PRODUCTION_ADAPTER_TYPE_CONTRACT_INVALID:{adapter_id}")
        allowed = {"family_id", "adapter", "trait", "source", "config_binding", "operations"}
        auxiliary = adapter.get("auxiliary_traits", [])
        if adapter_id in EXPECTED_AUXILIARY_TRAITS:
            allowed.add("auxiliary_traits")
        if not isinstance(auxiliary, list) or any(
            not isinstance(binding, dict) or set(binding) != {"adapter", "trait"}
            for binding in auxiliary
        ):
            raise AuditError(f"PRODUCTION_ADAPTER_AUXILIARY_TRAIT_INVALID:{adapter_id}")
        actual_auxiliary = {
            (binding.get("adapter"), binding.get("trait")) for binding in auxiliary
        }
        if actual_auxiliary != EXPECTED_AUXILIARY_TRAITS.get(adapter_id, set()):
            raise AuditError(f"PRODUCTION_ADAPTER_AUXILIARY_TRAIT_INCOMPLETE:{adapter_id}")
        if adapter_id == "a2a":
            allowed.add("inherent_methods")
            if adapter.get("inherent_methods") != ["agent_card", "submit", "stream_snapshot"]:
                raise AuditError("PRODUCTION_A2A_SURFACE_INCOMPLETE")
        if set(adapter) != allowed:
            raise AuditError(f"PRODUCTION_ADAPTER_SHAPE_INVALID:{adapter_id}")
        source_path, _ = _safe_file(adapter.get("source"))
        source = source_path.read_text(encoding="utf-8")
        operations = _rows(
            adapter.get("operations"),
            f"PRODUCTION_ADAPTER_OPERATION_SET_EMPTY:{adapter_id}",
        )
        for operation in operations:
            _audit_operation(adapter_id, source, operation)
        by_id[adapter_id] = adapter
    if set(by_id) != set(EXPECTED_ADAPTERS):
        raise AuditError("PRODUCTION_ADAPTER_SET_INCOMPLETE")
    _audit_config_bindings(adapters)
    return contract


def _audit_condition_test_contracts(
    contract: Mapping[str, Any], conditions: Mapping[str, Mapping[str, Any]]
) -> None:
    rows = _rows(contract.get("condition_tests"), "PRODUCTION_CONDITION_TEST_ROWS_INVALID")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if set(row) not in (
            {"condition_id", "probes"},
            {"condition_id", "probes", "runtime_symbols"},
        ):
            raise AuditError("PRODUCTION_CONDITION_TEST_SHAPE_INVALID")
        condition_id = row.get("condition_id")
        if not isinstance(condition_id, str) or condition_id in by_id or condition_id not in conditions:
            raise AuditError("PRODUCTION_CONDITION_TEST_ID_INVALID")
        condition = conditions[condition_id]
        declared_tests = set(condition["test_paths"])
        probes = _rows(row.get("probes"), f"PRODUCTION_CONDITION_PROBES_EMPTY:{condition_id}")
        for probe in probes:
            if set(probe) != {"path", "test"}:
                raise AuditError(f"PRODUCTION_CONDITION_PROBE_INVALID:{condition_id}")
            path = probe.get("path")
            name = probe.get("test")
            if path not in declared_tests or not isinstance(name, str) or not name:
                raise AuditError(f"PRODUCTION_CONDITION_PROBE_UNDECLARED:{condition_id}")
            source_path, _ = _safe_file(path)
            if not _test_declared(source_path.read_text(encoding="utf-8"), name):
                raise AuditError(f"PRODUCTION_CONDITION_TEST_MISSING:{condition_id}:{name}")
        declared_runtime = set(condition["runtime_paths"])
        for binding in row.get("runtime_symbols", []):
            if not isinstance(binding, dict) or set(binding) != {"path", "symbols"}:
                raise AuditError(f"PRODUCTION_CONDITION_RUNTIME_BINDING_INVALID:{condition_id}")
            path = binding.get("path")
            if path not in declared_runtime:
                raise AuditError(f"PRODUCTION_CONDITION_RUNTIME_PATH_UNDECLARED:{condition_id}")
            symbols = _strings(
                binding.get("symbols"),
                f"PRODUCTION_CONDITION_RUNTIME_SYMBOLS_INVALID:{condition_id}",
            )
            source_path, _ = _safe_file(path)
            source = source_path.read_text(encoding="utf-8")
            for symbol in symbols:
                if symbol not in source:
                    raise AuditError(f"PRODUCTION_CONDITION_RUNTIME_SYMBOL_MISSING:{condition_id}:{symbol}")
        by_id[condition_id] = row
    if set(by_id) != EXPECTED_CONDITIONS:
        raise AuditError("PRODUCTION_CONDITION_TEST_SET_INCOMPLETE")


def _run_rust_contract_tests(cargo: str | None) -> None:
    executable = cargo or os.environ.get("CARGO") or shutil.which("cargo")
    if not executable:
        raise AuditError("CARGO_REQUIRED_FOR_PRODUCTION_ADAPTER_CONTRACT_TESTS")
    result = subprocess.run(
        [
            executable,
            "test",
            "-p",
            "agent-trust-production-runtime",
            "--test",
            "adapter_contracts",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise AuditError("PRODUCTION_ADAPTER_RUST_CONTRACT_TESTS_FAILED")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="audit-production-runtime")
    parser.add_argument(
        "--run-rust-contract-tests",
        action="store_true",
        help="compile trait assertions and execute Rust adapter contract tests",
    )
    parser.add_argument("--cargo", help="Cargo executable used with --run-rust-contract-tests")
    args = parser.parse_args(argv)
    if args.cargo and not args.run_rust_contract_tests:
        raise AuditError("CARGO_ARGUMENT_REQUIRES_RUST_CONTRACT_TESTS")

    _, conditions = _audit_condition_manifest()
    contract = _audit_adapter_contracts()
    _audit_condition_test_contracts(contract, conditions)
    if not RUST_CONTRACT_TEST.is_file():
        raise AuditError("PRODUCTION_ADAPTER_RUST_CONTRACT_TEST_MISSING")
    if args.run_rust_contract_tests:
        _run_rust_contract_tests(args.cargo)
    suffix = " plus compiled Rust contracts" if args.run_rust_contract_tests else ""
    print(
        "verified 17 external-evidence conditions and 17 adapter families: "
        f"trait/surface, method/path, config, and local probe contracts{suffix}; "
        "live evidence remains required"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
