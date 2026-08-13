#!/usr/bin/env python3
"""Machine-check the complete set of code-level production runtime bindings."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "ENTERPRISE_IDP_JWKS", "WORKLOAD_MTLS_CA", "SECRET_BROKER_DYNAMIC_LEASES",
    "DEDICATED_LINUX_GVISOR", "PRODUCTION_MULTIZONE_TEMPORAL",
    "MANAGED_DATABASE_MULTI_ZONE", "LOCKED_RETENTION_OBJECT_STORAGE",
    "MODEL_GENERATION_STREAM_DLP_BILLING_RESIDENCY", "MCP_REAL_ENDPOINT",
    "A2A_REAL_ENDPOINT", "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
    "SUPERVISED_PHYSICAL_WRITE", "MULTIZONE_CONTROL_PLANE_TOPOLOGY",
    "NETWORK_STORAGE_CONTROL_PLANE_FAULTS", "SUSTAINED_PRODUCTION_LOAD",
    "CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE", "IMMUTABLE_GIT_RELEASE_PROVENANCE",
}


def main() -> int:
    manifest = json.loads((ROOT / "config/production-runtime/conditions.json").read_text())
    if manifest.get("schema_version") != "agenttrust.production-runtime-condition-bindings.v1" \
            or manifest.get("fail_closed") is not True:
        raise RuntimeError("PRODUCTION_RUNTIME_BINDING_MANIFEST_INVALID")
    rows = manifest.get("conditions")
    if not isinstance(rows, list) or {row.get("condition_id") for row in rows} != EXPECTED:
        raise RuntimeError("PRODUCTION_RUNTIME_CONDITION_SET_INCOMPLETE")
    for row in rows:
        if row.get("external_evidence_required") is not True:
            raise RuntimeError(f"EXTERNAL_EVIDENCE_BOUNDARY_MISSING:{row.get('condition_id')}")
        for field in ("runtime_paths", "test_paths"):
            paths = row.get(field)
            if not isinstance(paths, list) or not paths:
                raise RuntimeError(f"PRODUCTION_RUNTIME_PATH_SET_EMPTY:{row.get('condition_id')}:{field}")
            for value in paths:
                path = ROOT / value
                if not path.is_file() or not path.resolve().is_relative_to(ROOT.resolve()):
                    raise RuntimeError(f"PRODUCTION_RUNTIME_PATH_INVALID:{value}")
    source = (ROOT / "rust/crates/production-runtime/src/lib.rs").read_text()
    for adapter in (
        "ProductionIdentityVerifier", "HttpOrchestratorAdapter", "ProductionModelAdapter",
        "SecretBrokerCredentialLifecycle", "HttpIndustrialAdapter", "HttpBackupPort",
        "HttpPolicyDistributionPort", "HttpContainmentPort", "HttpRecertificationPort",
        "HttpEnterpriseIntegration", "HttpAuthoritativeService", "HttpNotificationAdapter",
        "FilesystemEvidenceSource", "HttpMcpTransport", "A2aPeerClient",
        "HttpRuntimeControlPort", "HttpLifecyclePropagationPort",
    ):
        if adapter not in source:
            raise RuntimeError(f"PRODUCTION_ADAPTER_NOT_ASSEMBLED:{adapter}")
    print("verified 17 production conditions and 17 assembled adapter families")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
