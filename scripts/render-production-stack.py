#!/usr/bin/env python3
"""Render the complete production stack from non-secret, fail-closed inputs."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python.production_gates.git_provenance import (  # noqa: E402
    canonical_json,
    signed_git_provenance_digest,
    verify_signed_git_provenance,
)
from python.production_gates.live_integrations import GateError  # noqa: E402
from python.production_gates.release_binding import (  # noqa: E402
    build_release_binding,
    signed_release_binding_digest,
    verify_signed_release_binding,
)
from python.production_gates.release_activation import (  # noqa: E402
    ActivationError,
    verify_activation_documents,
)


IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}$"
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
GIT_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
TOKEN = re.compile(r"@@[A-Z0-9_]+@@")
NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ENTERPRISE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
PATH_PREFIX = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
DATABASE_ROLE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
VAULT_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@?=&:+-]{0,511}$")
STORAGE = re.compile(r"^[1-9][0-9]*(?:Mi|Gi|Ti)$")
SPIFFE_PATH = re.compile(r"^(?:/[A-Za-z0-9._~!$&()*+;=:@%-]+)*$")

IMAGE_KEYS = {
    "runtime", "orchestrator", "transition", "execution", "registry", "agent_registry",
    "policy_admin", "incident_release", "pack_marketplace", "approval", "pep", "identity", "tool_proxy", "evidence", "audit", "enterprise",
    "enterprise_authority", "model_gateway", "data_governance", "context_governance",
    "runtime_anomaly", "security_evaluation", "pack_supply_chain", "domain_runtime",
    "platform_sre", "console", "migration", "envoy", "utility",
    "release_admission", "sandbox_worker",
}
VAULT_KEYS = {
    "address", "runtime_role", "runtime_path", "orchestrator_role",
    "orchestrator_path", "transition_role", "transition_path", "enterprise_role",
    "enterprise_path", "enterprise_authority_role", "enterprise_authority_path",
    "execution_role", "execution_path", "registry_role", "registry_path",
    "agent_registry_role", "agent_registry_path",
    "policy_admin_role", "policy_admin_path",
    "incident_release_role", "incident_release_path",
    "pack_marketplace_role", "pack_marketplace_path",
    "approval_role", "approval_path", "pep_role", "pep_path", "identity_role",
    "identity_path", "tool_proxy_role", "tool_proxy_path", "evidence_role", "evidence_path",
    "audit_role", "audit_path",
    "model_gateway_role", "model_gateway_path",
    "data_governance_role", "data_governance_path",
    "context_governance_role", "context_governance_path",
    "runtime_anomaly_role", "runtime_anomaly_path",
    "security_evaluation_role", "security_evaluation_path",
    "pack_supply_chain_role", "pack_supply_chain_path",
    "domain_runtime_role", "domain_runtime_path",
    "platform_sre_role", "platform_sre_path",
    "migration_role", "migration_path",
    "release_admission_role", "release_admission_path",
}
FACT_KEYS = {"policy", "approval", "credential", "ledger", "evaluator", "evidence", "supervisor"}
AUTHORITY_KEYS = {
    "agents", "approvals", "evidence", "incidents", "policies",
    "tools", "credentials", "packs", "trace", "compliance", "audit", "sre",
    "deployments", "models", "data", "context", "anomalies",
    "security_evaluations", "supply_chain", "domain_packs",
}
AUTHORITY_READINESS_KEYS = AUTHORITY_KEYS | {"tasks"}
AUTHORITY_READINESS_TOKENS = {
    "agents": "AGENT_REGISTRY", "tasks": "ORCHESTRATOR", "approvals": "APPROVAL",
    "evidence": "EVIDENCE", "incidents": "INCIDENT", "policies": "POLICY_ADMIN",
    "tools": "TOOL_REGISTRY", "credentials": "CREDENTIAL_SESSION",
    "packs": "PACK_MARKETPLACE", "trace": "TRACE", "compliance": "COMPLIANCE",
    "audit": "AUDIT", "sre": "SRE", "deployments": "DEPLOYMENT",
    "models": "MODEL_GATEWAY", "data": "DATA_GOVERNANCE",
    "context": "CONTEXT_GOVERNANCE", "anomalies": "RUNTIME_ANOMALY",
    "security_evaluations": "SECURITY_EVALUATION",
    "supply_chain": "PACK_SUPPLY_CHAIN", "domain_packs": "DOMAIN_RUNTIME",
}
INTERNAL_READINESS_SCHEMAS = {
    "agents": "agenttrust.agent-registry-readiness.v1",
    "tasks": "agenttrust.orchestrator-readiness.v1",
    "approvals": "agenttrust.approval-readiness.v1",
    "evidence": "agenttrust.evidence-readiness.v1",
    "tools": "agenttrust.registry-readiness.v1",
    "credentials": "agenttrust.identity-credential-readiness.v1",
    "audit": "agenttrust.audit-retention-readiness.v1",
    "policies": "agenttrust.policy-admin-readiness.v1",
    "incidents": "agenttrust.incident-release-readiness.v1",
    "packs": "agenttrust.pack-marketplace-readiness.v1",
    "models": "agenttrust.model-gateway-readiness.v1",
    "data": "agenttrust.data-governance-readiness.v1",
    "context": "agenttrust.context-readiness.v1",
    "anomalies": "agenttrust.runtime-anomaly-readiness.v1",
    "security_evaluations": "agenttrust.security-eval-readiness.v1",
    "supply_chain": "agenttrust.supply-chain-readiness.v1",
    "domain_packs": "agenttrust.domain-runtime-readiness.v1",
    "sre": "agenttrust.sre-readiness.v1",
}

PRODUCTION_AUTHORITY_SPECS = {
    "model_gateway": (8091, 9101, "agenttrust.model-gateway-readiness.v1"),
    "data_governance": (8092, 9102, "agenttrust.data-governance-readiness.v1"),
    "context_governance": (8095, 9105, "agenttrust.context-readiness.v1"),
    "runtime_anomaly": (8094, 9104, "agenttrust.runtime-anomaly-readiness.v1"),
    "security_evaluation": (8096, 9106, "agenttrust.security-eval-readiness.v1"),
    "pack_supply_chain": (8093, 9103, "agenttrust.supply-chain-readiness.v1"),
    "domain_runtime": (8094, 9104, "agenttrust.domain-runtime-readiness.v1"),
    "platform_sre": (8097, 9107, "agenttrust.sre-readiness.v1"),
}
PRODUCTION_AUTHORITY_KEYS = set(PRODUCTION_AUTHORITY_SPECS)
PRODUCTION_AUTHORITY_VALUE_KEYS = {
    "client_identities", "outbound_client_identity", "evidence_client_identity",
    "instance_id", "organization_id", "agent_version", "region", "service_subject",
    "data_port", "management_port", "readiness_schema", "execution_lease_seconds",
    "recovery_interval_seconds", "signing_key_id", "maximum_authentication_age_seconds",
    "dependencies",
}
PRODUCTION_AUTHORITY_DEPENDENCIES = {
    "model_gateway": {
        "data_policy", "dlp", "data_sanitizer", "data_artifact_authorizer",
        "data_mutation", "data_read", "artifact_store", "evidence",
    },
    "data_governance": {
        "orchestrator", "enterprise_dlp", "object_worm", "legal_hold", "evidence",
    },
    "context_governance": {
        "orchestrator", "object_store", "vector_index", "cache", "supply_chain",
        "legal_hold", "poisoning", "evidence",
    },
    "runtime_anomaly": {
        "orchestrator", "supervisor", "credential_authority", "incident_authority",
        "evidence_authority",
    },
    "security_evaluation": {"orchestrator", "isolated_runner", "evidence"},
    "pack_supply_chain": {
        "coordinator", "repository", "signer", "scanner", "sandbox", "revocation",
        "evidence",
    },
    "domain_runtime": {"executor", "evidence"},
    "platform_sre": {
        "orchestrator", "topology_probe", "backup", "recovery", "dr", "chaos", "load",
        "upgrade", "evidence",
    },
}
DEPENDENCY_READINESS_SCHEMAS = {
    "orchestrator": "agenttrust.orchestrator-readiness.v1",
    "enterprise_dlp": "agenttrust.dlp-readiness.v1",
    "object_worm": "agenttrust.object-worm-readiness.v1",
    "legal_hold": "agenttrust.legal-hold-readiness.v1",
    "evidence": "agenttrust.evidence-readiness.v1",
    "supervisor": "agenttrust.supervisor-readiness.v1",
    "credential_authority": "agenttrust.credential-authority-readiness.v1",
    "incident_authority": "agenttrust.incident-authority-readiness.v1",
    "evidence_authority": "agenttrust.evidence-readiness.v1",
    "isolated_runner": "agenttrust.isolated-security-runner-readiness.v1",
    "coordinator": "agenttrust.pack-coordinator-readiness.v1",
    "repository": "agenttrust.pack-repository-readiness.v1",
    "signer": "agenttrust.pack-signer-readiness.v1",
    "scanner": "agenttrust.scanner-readiness.v1",
    "sandbox": "agenttrust.pack-sandbox-readiness.v1",
    "revocation": "agenttrust.revocation-readiness.v1",
    "executor": "agenttrust.domain-executor-readiness.v1",
}
PRODUCTION_AUTHORITY_READINESS_DEPENDENCIES = {
    "data_governance": PRODUCTION_AUTHORITY_DEPENDENCIES["data_governance"],
    "runtime_anomaly": PRODUCTION_AUTHORITY_DEPENDENCIES["runtime_anomaly"],
    "security_evaluation": PRODUCTION_AUTHORITY_DEPENDENCIES["security_evaluation"],
    "pack_supply_chain": PRODUCTION_AUTHORITY_DEPENDENCIES["pack_supply_chain"],
    "domain_runtime": PRODUCTION_AUTHORITY_DEPENDENCIES["domain_runtime"],
}
EXECUTION_READINESS_SCHEMAS = {
    "approval": "agenttrust.approval-readiness.v1",
    "pep": "agenttrust.pep-readiness.v1",
    "tool": "agenttrust.tool-proxy-readiness.v1",
    "evidence": "agenttrust.evidence-readiness.v1",
}
RUNTIME_ENDPOINT_TOKENS = {
    "orchestrator": "orchestrator.token",
    "secret_broker": "secret-broker.token",
    "backup": "backup.token",
    "containment": "containment.token",
    "recertification": "recertification.token",
    "enterprise_integration": "integration.token",
    "authority": "authority.token",
    "notification": "notification.token",
    "industrial": "industrial.token",
    "runtime_control": "runtime-control.token",
    "lifecycle": "lifecycle.token",
    "model:primary": "model-primary.token",
    "mcp:primary": "mcp-primary.token",
    "a2a:primary": "a2a-primary.token",
}
RUNTIME_SECRET_FILES = set(RUNTIME_ENDPOINT_TOKENS.values()) | {
    "server-cert.pem", "server-key.pem", "enterprise-ca.pem", "industrial-ca.pem",
    "workload-identity.pem", "industrial-identity.pem",
}


class RenderError(RuntimeError):
    pass


def require_mapping(value: object, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RenderError(f"PRODUCTION_STACK_{name.upper()}_INVALID")
    return value


def require_text(value: object, code: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise RenderError(code)
    if pattern is not None and not pattern.fullmatch(value):
        raise RenderError(code)
    return value


def require_https(
    value: object,
    code: str,
    *,
    trailing_slash: bool = False,
    allowed_ports: set[int] | None = None,
) -> str:
    raw = require_text(value, code)
    if raw != raw.strip() or any(
        character.isspace() or character in "\"'|\\" or ord(character) < 0x20
        for character in raw
    ):
        raise RenderError(code)
    try:
        parsed = urlparse(raw)
        port = parsed.port
        host = parsed.hostname or ""
        try:
            ipaddress.ip_address(host)
            valid_host = True
        except ValueError:
            valid_host = bool(HOST.fullmatch(host))
    except ValueError as error:
        raise RenderError(code) from error
    if (
        parsed.scheme != "https" or not valid_host or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or (allowed_ports is not None and (port or 443) not in allowed_ports)
        or (trailing_slash and not parsed.path.endswith("/"))
    ):
        raise RenderError(code)
    return raw


def require_cidr(value: object, code: str) -> str:
    raw = require_text(value, code)
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as error:
        raise RenderError(code) from error
    if network.prefixlen == 0:
        raise RenderError(code)
    return raw


def require_client_identity(
    value: object,
    code: str = "PRODUCTION_STACK_ORCHESTRATOR_CLIENT_IDENTITIES_INVALID",
) -> str:
    raw = require_text(value, code)
    if raw != raw.strip() or any(
        character.isspace() or character in "\"'|\\," or ord(character) < 0x20
        for character in raw
    ):
        raise RenderError(code)
    if raw.startswith("DNS:"):
        if not HOST.fullmatch(raw[4:]):
            raise RenderError(code)
        return raw
    if not raw.startswith("URI:"):
        raise RenderError(code)
    try:
        parsed = urlparse(raw[4:])
        port = parsed.port
    except ValueError as error:
        raise RenderError(code) from error
    if (
        parsed.scheme != "spiffe" or not parsed.hostname
        or not HOST.fullmatch(parsed.hostname) or parsed.username is not None
        or parsed.password is not None or port is not None or parsed.query
        or parsed.fragment or parsed.params or not SPIFFE_PATH.fullmatch(parsed.path)
    ):
        raise RenderError(code)
    return raw


def require_client_identities(value: object, code: str) -> list[str]:
    if (
        not isinstance(value, list) or not value
        or len(value) != len(set(value))
        or any(not isinstance(identity, str) for identity in value)
    ):
        raise RenderError(code)
    for identity in value:
        require_client_identity(identity, code)
    return value


def reject_placeholders(value: object) -> None:
    if isinstance(value, str):
        if any(marker in value for marker in ("@@", "REPLACE_WITH", ".production.example")):
            raise RenderError("PRODUCTION_STACK_RUNTIME_CONFIG_HAS_PLACEHOLDER")
    elif isinstance(value, dict):
        for nested in value.values():
            reject_placeholders(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_placeholders(nested)


def validate_runtime_config(
    value: object, expected_release_id: str
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RenderError("PRODUCTION_STACK_RUNTIME_CONFIG_INVALID")
    reject_placeholders(value)
    if (
        value.get("schema_version") != "agenttrust.production-runtime-config.v1"
        or value.get("fail_closed") is not True
        or value.get("listeners") != {"data": "127.0.0.1:8080", "management": "0.0.0.0:9090"}
    ):
        raise RenderError("PRODUCTION_STACK_RUNTIME_CONFIG_INVALID")
    identity = value.get("identity")
    activation = value.get("activation_guardian")
    endpoints = value.get("endpoints")
    evidence = value.get("evidence_files")
    model_versions = value.get("model_versions")
    if (
        not isinstance(activation, dict)
        or set(activation) != {
            "release_id",
            "receipt_path",
            "max_staleness_seconds",
            "receipt_owner_uid",
            "receipt_reader_gid",
        }
        or activation.get("release_id") != expected_release_id
        or activation.get("receipt_path")
        != "/run/agenttrust/activation/receipt.json"
        or not isinstance(activation.get("max_staleness_seconds"), int)
        or isinstance(activation.get("max_staleness_seconds"), bool)
        or not 1 <= activation["max_staleness_seconds"] <= 60
        or activation.get("receipt_owner_uid") != 65531
        or activation.get("receipt_reader_gid") != 65532
    ):
        raise RenderError("PRODUCTION_STACK_ACTIVATION_GUARDIAN_INVALID")
    if not isinstance(identity, dict) or identity.get("require_mtls_peer") is not True:
        raise RenderError("PRODUCTION_STACK_RUNTIME_IDENTITY_INVALID")
    require_https(
        identity.get("issuer"),
        "PRODUCTION_STACK_RUNTIME_IDENTITY_ISSUER_INVALID",
        allowed_ports={443, 8443},
    )
    require_https(
        identity.get("jwks_endpoint"),
        "PRODUCTION_STACK_RUNTIME_IDENTITY_JWKS_INVALID",
        allowed_ports={443, 8443},
    )
    if (
        not isinstance(endpoints, dict)
        or set(endpoints) != set(RUNTIME_ENDPOINT_TOKENS)
        or not isinstance(endpoints.get("orchestrator"), dict)
        or not isinstance(model_versions, dict)
        or set(model_versions) != {"primary"}
        or not isinstance(model_versions.get("primary"), str)
        or not model_versions["primary"]
    ):
        raise RenderError("PRODUCTION_STACK_RUNTIME_ENDPOINTS_INVALID")
    orchestrator_url = str(endpoints["orchestrator"].get("base_url", "")).rstrip("/")
    if orchestrator_url != "https://agenttrust-orchestrator":
        raise RenderError("PRODUCTION_STACK_RUNTIME_ORCHESTRATOR_NOT_INTERNAL")
    expected_evidence = {
        "batch_statuses": "/var/lib/agenttrust/evidence/batch-statuses.json",
        "gate_evidence": "/var/lib/agenttrust/evidence/gate-evidence.json",
        "residual_risks": "/var/lib/agenttrust/evidence/residual-risks.json",
        "exceptions": "/var/lib/agenttrust/evidence/exceptions.json",
    }
    if evidence != expected_evidence:
        raise RenderError("PRODUCTION_STACK_EVIDENCE_PATH_CONTRACT_INVALID")

    tls_blocks: list[Mapping[str, Any]] = []
    jwks_tls = identity.get("jwks_tls")
    if isinstance(jwks_tls, dict):
        tls_blocks.append(jwks_tls)
    for name, endpoint in endpoints.items():
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("tls"), dict):
            raise RenderError("PRODUCTION_STACK_RUNTIME_ENDPOINTS_INVALID")
        require_https(
            endpoint.get("base_url"),
            "PRODUCTION_STACK_RUNTIME_ENDPOINT_URL_INVALID",
            allowed_ports={443, 8443},
        )
        expected_token = f"/etc/agenttrust/secrets/runtime/{RUNTIME_ENDPOINT_TOKENS[name]}"
        if endpoint["tls"].get("bearer_token_file") != expected_token:
            raise RenderError("PRODUCTION_STACK_RUNTIME_TOKEN_CONTRACT_INVALID")
        expected_identity = (
            "/etc/agenttrust/secrets/runtime/industrial-identity.pem"
            if name == "industrial" else "/etc/agenttrust/secrets/runtime/workload-identity.pem"
        )
        if name != "model:primary" and endpoint["tls"].get("client_identity_pem") != expected_identity:
            raise RenderError("PRODUCTION_STACK_RUNTIME_IDENTITY_CONTRACT_INVALID")
        tls_blocks.append(endpoint["tls"])
    for tls in tls_blocks:
        for key in ("ca_bundle", "client_identity_pem", "bearer_token_file"):
            path = tls.get(key)
            if path is not None and (
                not isinstance(path, str)
                or not path.startswith("/etc/agenttrust/secrets/runtime/")
                or ".." in Path(path).parts
                or Path(path).name not in RUNTIME_SECRET_FILES
            ):
                raise RenderError("PRODUCTION_STACK_RUNTIME_SECRET_PATH_INVALID")
    return value


def render(
    template: str,
    values: Mapping[str, Any],
    runtime_config: object,
    *,
    git_provenance: object,
    git_provenance_keyring: object,
    release_binding: object,
    release_binding_keyring: object,
    activation_receipt: object,
) -> str:
    top_keys = {
        "schema_version", "release_id", "release_digest", "images", "database", "temporal",
        "execution", "registry", "agent_registry", "policy_admin", "incident_release",
        "pack_marketplace", "transition", "authorities",
        "enterprise_authority", "production_authorities", "vault", "network", "evidence", "ingress",
        "transition_facts", "enterprise",
    }
    if set(values) != top_keys or values.get("schema_version") != "agenttrust.production-stack-values.v2":
        raise RenderError("PRODUCTION_STACK_VALUES_INVALID")
    release_id = require_text(values["release_id"], "PRODUCTION_STACK_RELEASE_ID_INVALID", GIT_RELEASE_ID)
    if not GIT_RELEASE_ID.fullmatch(release_id):
        raise RenderError("PRODUCTION_STACK_RELEASE_ID_INVALID")
    release_digest = require_text(values["release_digest"], "PRODUCTION_STACK_RELEASE_DIGEST_INVALID", DIGEST)
    if (
        not isinstance(activation_receipt, dict)
        or set(activation_receipt) != {
            "schema_version", "admitted", "release_id", "certificate_id",
            "scope_digest", "input_digest", "report_digest",
            "production_image_manifest_digest", "evidence_bundle_manifest_digest",
            "activation_material_digest", "revocation_registry_id",
            "revocation_registry_sequence", "revocation_registry_digest",
            "verified_at", "valid_until",
        }
        or activation_receipt.get("schema_version")
        != "agenttrust.production-release-activation-receipt.v1"
        or activation_receipt.get("admitted") is not True
        or activation_receipt.get("release_id") != release_id
        or not isinstance(activation_receipt.get("certificate_id"), str)
        or not re.fullmatch(r"pc-[0-9a-f]{24}", activation_receipt["certificate_id"])
        or not isinstance(activation_receipt.get("revocation_registry_sequence"), int)
        or isinstance(activation_receipt.get("revocation_registry_sequence"), bool)
        or activation_receipt["revocation_registry_sequence"] < 1
        or not isinstance(activation_receipt.get("revocation_registry_digest"), str)
        or not DIGEST.fullmatch(activation_receipt["revocation_registry_digest"])
        or any(
            not isinstance(activation_receipt.get(field), str)
            or not DIGEST.fullmatch(activation_receipt[field])
            for field in (
                "scope_digest", "input_digest", "report_digest",
                "production_image_manifest_digest", "evidence_bundle_manifest_digest",
                "activation_material_digest",
            )
        )
        or not isinstance(activation_receipt.get("verified_at"), str)
        or not isinstance(activation_receipt.get("valid_until"), str)
    ):
        raise RenderError("PRODUCTION_STACK_ACTIVATION_RECEIPT_INVALID")
    activation_receipt_digest = hashlib.sha256(
        canonical_json(activation_receipt)
    ).hexdigest()
    try:
        provenance_report = verify_signed_git_provenance(
            git_provenance, git_provenance_keyring
        )
        provenance_digest = signed_git_provenance_digest(git_provenance)
    except GateError as error:
        raise RenderError("PRODUCTION_STACK_GIT_PROVENANCE_INVALID") from error
    try:
        verified_release_binding = verify_signed_release_binding(
            release_binding, release_binding_keyring
        )
    except GateError as error:
        raise RenderError("PRODUCTION_STACK_RELEASE_BINDING_INVALID") from error
    checks = provenance_report["checks"]
    if (
        checks.get("release_id") != release_id
        or checks.get("release_tag_required") is not True
        or checks.get("release_tag_signature_verified") is not True
        or checks.get("remote_release_tag_verified") is not True
        or not checks.get("remote_membership_digest")
    ):
        raise RenderError("PRODUCTION_STACK_RELEASE_PROVENANCE_MISMATCH")
    try:
        expected_release_binding = build_release_binding(
            template,
            values,
            runtime_config,
            provenance_digest=provenance_digest,
            template_blob_object_id=verified_release_binding["template_blob_object_id"],
        )
    except GateError as error:
        raise RenderError("PRODUCTION_STACK_RELEASE_BINDING_INVALID") from error
    if (
        dict(verified_release_binding) != expected_release_binding
        or verified_release_binding.get("release_id") != release_id
        or verified_release_binding.get("signed_git_provenance_digest") != provenance_digest
        or release_digest != verified_release_binding.get("release_digest")
    ):
        raise RenderError("PRODUCTION_STACK_RELEASE_BINDING_MISMATCH")

    images = require_mapping(values["images"], "images", IMAGE_KEYS)
    if any(not isinstance(image, str) or not IMAGE.fullmatch(image) for image in images.values()):
        raise RenderError("PRODUCTION_STACK_IMAGE_NOT_IMMUTABLE")

    database = require_mapping(
        values["database"], "database",
        {
            "enterprise_application_role", "enterprise_authority_application_role",
            "orchestrator_application_role", "execution_application_role",
            "registry_application_role", "agent_registry_application_role", "approval_application_role",
            "policy_admin_application_role",
            "incident_release_application_role", "pack_marketplace_application_role",
            "pep_application_role", "identity_application_role", "tool_proxy_application_role",
            "evidence_application_role", "audit_application_role",
            "model_gateway_application_role", "data_governance_application_role",
            "context_governance_application_role", "runtime_anomaly_application_role",
            "security_evaluation_application_role", "pack_supply_chain_application_role",
            "domain_runtime_application_role", "platform_sre_application_role",
        },
    )
    for key, role in database.items():
        require_text(role, f"PRODUCTION_STACK_{key.upper()}_INVALID", DATABASE_ROLE)
    if len(set(database.values())) != len(database):
        raise RenderError("PRODUCTION_STACK_APPLICATION_ROLES_NOT_DISTINCT")

    production_authorities = require_mapping(
        values["production_authorities"], "production_authorities",
        PRODUCTION_AUTHORITY_KEYS,
    )
    validated_production_authorities: dict[str, dict[str, Any]] = {}
    all_authority_identities: set[str] = set()
    for service_name, service_value in production_authorities.items():
        service = require_mapping(
            service_value, f"production_authority_{service_name}",
            PRODUCTION_AUTHORITY_VALUE_KEYS,
        )
        identities = require_client_identities(
            service["client_identities"],
            f"PRODUCTION_STACK_{service_name.upper()}_CLIENT_IDENTITIES_INVALID",
        )
        outbound_identity = require_client_identity(
            service["outbound_client_identity"],
            f"PRODUCTION_STACK_{service_name.upper()}_OUTBOUND_CLIENT_IDENTITY_INVALID",
        )
        evidence_identity = require_client_identity(
            service["evidence_client_identity"],
            f"PRODUCTION_STACK_{service_name.upper()}_EVIDENCE_CLIENT_IDENTITY_INVALID",
        )
        if outbound_identity in all_authority_identities:
            raise RenderError("PRODUCTION_STACK_AUTHORITY_OUTBOUND_IDENTITIES_NOT_DISTINCT")
        all_authority_identities.add(outbound_identity)
        instance_id = require_text(
            service["instance_id"],
            f"PRODUCTION_STACK_{service_name.upper()}_INSTANCE_ID_INVALID",
        )
        try:
            if str(uuid.UUID(instance_id)) != instance_id:
                raise ValueError
        except ValueError as error:
            raise RenderError(
                f"PRODUCTION_STACK_{service_name.upper()}_INSTANCE_ID_INVALID"
            ) from error
        identifiers = {}
        for key in (
            "organization_id", "agent_version", "region", "service_subject",
            "signing_key_id",
        ):
            identifiers[key] = require_text(
                service[key],
                f"PRODUCTION_STACK_{service_name.upper()}_{key.upper()}_INVALID",
                ENTERPRISE_IDENTIFIER,
            )
        expected_data_port, expected_management_port, expected_schema = (
            PRODUCTION_AUTHORITY_SPECS[service_name]
        )
        if service["data_port"] != expected_data_port or service["management_port"] != expected_management_port:
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_PORT_INVALID")
        readiness_schema = require_text(
            service["readiness_schema"],
            f"PRODUCTION_STACK_{service_name.upper()}_READINESS_SCHEMA_INVALID",
            IDENTIFIER,
        )
        if readiness_schema != expected_schema:
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_READINESS_SCHEMA_MISMATCH")
        lease = service["execution_lease_seconds"]
        recovery = service["recovery_interval_seconds"]
        maximum_authentication_age = service["maximum_authentication_age_seconds"]
        if not isinstance(lease, int) or not 15 <= lease <= 300:
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_LEASE_INVALID")
        if not isinstance(recovery, int) or not 5 <= recovery <= 300:
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_RECOVERY_INVALID")
        if (
            not isinstance(maximum_authentication_age, int)
            or not 60 <= maximum_authentication_age <= 86_400
        ):
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_MAX_AUTH_AGE_INVALID")
        dependencies = service["dependencies"]
        if (
            not isinstance(dependencies, dict) or not dependencies
            or len(dependencies) > 32
            or any(not isinstance(key, str) or not IDENTIFIER.fullmatch(key) for key in dependencies)
        ):
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_DEPENDENCIES_INVALID")
        if set(dependencies) != PRODUCTION_AUTHORITY_DEPENDENCIES[service_name]:
            raise RenderError(f"PRODUCTION_STACK_{service_name.upper()}_DEPENDENCIES_INVALID")
        normalized_dependencies = {}
        observed_dependency_endpoints = set()
        for dependency_name, dependency in dependencies.items():
            endpoint = require_https(
                dependency,
                f"PRODUCTION_STACK_{service_name.upper()}_{dependency_name.upper()}_ENDPOINT_INVALID",
                allowed_ports={443, 8443},
            )
            parsed_endpoint = urlparse(endpoint)
            if parsed_endpoint.path not in {"", "/"}:
                raise RenderError(
                    f"PRODUCTION_STACK_{service_name.upper()}_{dependency_name.upper()}_ENDPOINT_INVALID"
                )
            normalized_endpoint = endpoint.rstrip("/")
            endpoint_identity = (parsed_endpoint.hostname.lower(), parsed_endpoint.port or 443)
            if endpoint_identity in observed_dependency_endpoints:
                raise RenderError(
                    f"PRODUCTION_STACK_{service_name.upper()}_DEPENDENCY_ENDPOINT_REUSE_DENIED"
                )
            observed_dependency_endpoints.add(endpoint_identity)
            normalized_dependencies[dependency_name] = normalized_endpoint
        validated_production_authorities[service_name] = {
            "client_identities": identities,
            "outbound_client_identity": outbound_identity,
            "evidence_client_identity": evidence_identity,
            "instance_id": instance_id,
            **identifiers,
            "data_port": expected_data_port,
            "management_port": expected_management_port,
            "readiness_schema": readiness_schema,
            "execution_lease_seconds": lease,
            "recovery_interval_seconds": recovery,
            "maximum_authentication_age_seconds": maximum_authentication_age,
            "dependencies": normalized_dependencies,
        }

    temporal = require_mapping(
        values["temporal"], "temporal", {"address", "namespace", "task_queue", "server_name"},
    )
    temporal_address = require_text(temporal["address"], "PRODUCTION_STACK_TEMPORAL_ADDRESS_INVALID")
    if not re.fullmatch(r"[A-Za-z0-9.-]+:[1-9][0-9]{0,4}", temporal_address):
        raise RenderError("PRODUCTION_STACK_TEMPORAL_ADDRESS_INVALID")
    for key in ("namespace", "task_queue", "server_name"):
        require_text(temporal[key], f"PRODUCTION_STACK_TEMPORAL_{key.upper()}_INVALID", VAULT_VALUE)

    execution = require_mapping(
        values["execution"], "execution",
        {
            "client_identities", "outbound_client_identity", "approval_readiness_schema", "pep_readiness_schema",
            "tool_readiness_schema", "evidence_readiness_schema",
        },
    )
    execution_client_identities = execution["client_identities"]
    if (
        not isinstance(execution_client_identities, list)
        or not execution_client_identities
        or len(execution_client_identities) != len(set(execution_client_identities))
        or any(not isinstance(value, str) for value in execution_client_identities)
    ):
        raise RenderError("PRODUCTION_STACK_EXECUTION_CLIENT_IDENTITIES_INVALID")
    for client_identity in execution_client_identities:
        require_client_identity(
            client_identity, "PRODUCTION_STACK_EXECUTION_CLIENT_IDENTITIES_INVALID"
        )
    execution_outbound_identity = require_client_identity(
        execution["outbound_client_identity"],
        "PRODUCTION_STACK_EXECUTION_OUTBOUND_CLIENT_IDENTITY_INVALID",
    )
    if len(execution_outbound_identity) > 256:
        raise RenderError("PRODUCTION_STACK_EXECUTION_OUTBOUND_CLIENT_IDENTITY_INVALID")
    execution_endpoints = {
        "approval": "https://agenttrust-approval/",
        "pep": "https://agenttrust-pep/",
        "tool": "https://agenttrust-tool-proxy/",
        "evidence": "https://agenttrust-evidence/",
    }
    execution_readiness_schemas = {
        dependency: require_text(
            execution[f"{dependency}_readiness_schema"],
            f"PRODUCTION_STACK_EXECUTION_{dependency.upper()}_READINESS_SCHEMA_INVALID",
            IDENTIFIER,
        )
        for dependency in ("approval", "pep", "tool", "evidence")
    }
    if execution_readiness_schemas != EXECUTION_READINESS_SCHEMAS:
        raise RenderError("PRODUCTION_STACK_EXECUTION_READINESS_SCHEMA_MISMATCH")

    registry = require_mapping(
        values["registry"], "registry",
        {"client_identities", "publisher_id", "publisher_key_id"},
    )
    registry_client_identities = registry["client_identities"]
    if (
        not isinstance(registry_client_identities, list)
        or not registry_client_identities
        or len(registry_client_identities) != len(set(registry_client_identities))
        or any(not isinstance(value, str) for value in registry_client_identities)
    ):
        raise RenderError("PRODUCTION_STACK_REGISTRY_CLIENT_IDENTITIES_INVALID")
    for client_identity in registry_client_identities:
        require_client_identity(
            client_identity, "PRODUCTION_STACK_REGISTRY_CLIENT_IDENTITIES_INVALID"
        )
    registry_publisher_id = require_text(
        registry["publisher_id"], "PRODUCTION_STACK_REGISTRY_PUBLISHER_ID_INVALID", IDENTIFIER
    )
    registry_publisher_key_id = require_text(
        registry["publisher_key_id"],
        "PRODUCTION_STACK_REGISTRY_PUBLISHER_KEY_ID_INVALID", IDENTIFIER,
    )

    agent_registry = require_mapping(
        values["agent_registry"], "agent_registry",
        {"client_identities", "lifecycle_endpoint"},
    )
    agent_registry_client_identities = require_client_identities(
        agent_registry["client_identities"],
        "PRODUCTION_STACK_AGENT_REGISTRY_CLIENT_IDENTITIES_INVALID",
    )
    agent_registry_lifecycle_endpoint = require_https(
        agent_registry["lifecycle_endpoint"],
        "PRODUCTION_STACK_AGENT_REGISTRY_LIFECYCLE_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
    )
    if urlparse(agent_registry_lifecycle_endpoint).path not in {"", "/"}:
        raise RenderError("PRODUCTION_STACK_AGENT_REGISTRY_LIFECYCLE_ENDPOINT_INVALID")
    agent_registry_lifecycle_endpoint = agent_registry_lifecycle_endpoint.rstrip("/") + "/"

    policy_admin = require_mapping(
        values["policy_admin"], "policy_admin",
        {
            "client_identities", "outbound_client_identity", "agent_instance_id",
            "organization_id", "agent_version", "region", "tool_id", "tool_version",
            "executor_credential_profile", "service_subject", "bundle_signing_key_id",
            "maximum_authentication_age_seconds",
        },
    )
    policy_admin_client_identities = require_client_identities(
        policy_admin["client_identities"],
        "PRODUCTION_STACK_POLICY_ADMIN_CLIENT_IDENTITIES_INVALID",
    )
    policy_admin_outbound_identity = require_client_identity(
        policy_admin["outbound_client_identity"],
        "PRODUCTION_STACK_POLICY_ADMIN_OUTBOUND_IDENTITY_INVALID",
    )
    policy_admin_agent_instance_id = require_text(
        policy_admin["agent_instance_id"],
        "PRODUCTION_STACK_POLICY_ADMIN_AGENT_INSTANCE_ID_INVALID",
    )
    try:
        if str(uuid.UUID(policy_admin_agent_instance_id)) != policy_admin_agent_instance_id:
            raise ValueError
    except ValueError as error:
        raise RenderError("PRODUCTION_STACK_POLICY_ADMIN_AGENT_INSTANCE_ID_INVALID") from error
    policy_admin_identifiers = {}
    for key in (
        "organization_id", "agent_version", "region", "tool_id", "tool_version",
        "executor_credential_profile", "service_subject",
    ):
        policy_admin_identifiers[key] = require_text(
            policy_admin[key],
            f"PRODUCTION_STACK_POLICY_ADMIN_{key.upper()}_INVALID",
            ENTERPRISE_IDENTIFIER,
        )
    policy_admin_identifiers["bundle_signing_key_id"] = require_text(
        policy_admin["bundle_signing_key_id"],
        "PRODUCTION_STACK_POLICY_ADMIN_BUNDLE_SIGNING_KEY_ID_INVALID",
        IDENTIFIER,
    )
    policy_admin_max_auth_age = policy_admin["maximum_authentication_age_seconds"]
    if (
        policy_admin_identifiers["executor_credential_profile"]
        != "policy-administration-executor"
    ):
        raise RenderError("PRODUCTION_STACK_POLICY_ADMIN_EXECUTOR_PROFILE_INVALID")
    if (
        not isinstance(policy_admin_max_auth_age, int)
        or not 60 <= policy_admin_max_auth_age <= 86_400
    ):
        raise RenderError("PRODUCTION_STACK_POLICY_ADMIN_MAX_AUTH_AGE_INVALID")

    incident_release = require_mapping(
        values["incident_release"], "incident_release",
        {
            "client_identities", "outbound_client_identity", "detection_client_identity",
            "agent_instance_id", "organization_id", "agent_version", "region", "tool_id",
            "tool_version", "executor_credential_profile", "service_subject",
            "release_signing_key_id", "maximum_authentication_age_seconds",
            "execution_lease_seconds", "containment_endpoint", "replay_endpoint",
        },
    )
    incident_release_client_identities = require_client_identities(
        incident_release["client_identities"],
        "PRODUCTION_STACK_INCIDENT_RELEASE_CLIENT_IDENTITIES_INVALID",
    )
    incident_release_outbound_identity = require_client_identity(
        incident_release["outbound_client_identity"],
        "PRODUCTION_STACK_INCIDENT_RELEASE_OUTBOUND_IDENTITY_INVALID",
    )
    incident_detection_identity = require_client_identity(
        incident_release["detection_client_identity"],
        "PRODUCTION_STACK_INCIDENT_RELEASE_DETECTION_IDENTITY_INVALID",
    )
    incident_release_agent_instance_id = require_text(
        incident_release["agent_instance_id"],
        "PRODUCTION_STACK_INCIDENT_RELEASE_AGENT_INSTANCE_ID_INVALID",
    )
    try:
        if str(uuid.UUID(incident_release_agent_instance_id)) != incident_release_agent_instance_id:
            raise ValueError
    except ValueError as error:
        raise RenderError(
            "PRODUCTION_STACK_INCIDENT_RELEASE_AGENT_INSTANCE_ID_INVALID"
        ) from error
    incident_release_identifiers = {}
    for key in (
        "organization_id", "agent_version", "region", "tool_id", "tool_version",
        "executor_credential_profile", "service_subject", "release_signing_key_id",
    ):
        incident_release_identifiers[key] = require_text(
            incident_release[key],
            f"PRODUCTION_STACK_INCIDENT_RELEASE_{key.upper()}_INVALID",
            ENTERPRISE_IDENTIFIER,
        )
    incident_release_max_auth_age = incident_release[
        "maximum_authentication_age_seconds"
    ]
    if (
        incident_release_identifiers["executor_credential_profile"]
        != "incident-release-executor"
    ):
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_EXECUTOR_PROFILE_INVALID")
    if (
        not isinstance(incident_release_max_auth_age, int)
        or not 60 <= incident_release_max_auth_age <= 86_400
    ):
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_MAX_AUTH_AGE_INVALID")
    incident_execution_lease_seconds = incident_release["execution_lease_seconds"]
    if (
        not isinstance(incident_execution_lease_seconds, int)
        or not 15 <= incident_execution_lease_seconds <= 300
    ):
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_EXECUTION_LEASE_INVALID")
    incident_effect_endpoints = {}
    for name in ("containment", "replay"):
        endpoint = require_https(
            incident_release[f"{name}_endpoint"],
            f"PRODUCTION_STACK_INCIDENT_RELEASE_{name.upper()}_ENDPOINT_INVALID",
            allowed_ports={443, 8443},
        )
        if urlparse(endpoint).path not in {"", "/"}:
            raise RenderError(
                f"PRODUCTION_STACK_INCIDENT_RELEASE_{name.upper()}_ENDPOINT_INVALID"
            )
        incident_effect_endpoints[name] = endpoint.rstrip("/") + "/"
    if incident_effect_endpoints["containment"] == incident_effect_endpoints["replay"]:
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_EFFECT_ENDPOINTS_NOT_DISTINCT")

    pack_marketplace = require_mapping(
        values["pack_marketplace"], "pack_marketplace",
        {
            "client_identities", "outbound_client_identity", "agent_instance_id",
            "organization_id", "agent_version", "region", "tool_id", "tool_version",
            "executor_credential_profile", "ingress_subject", "executor_subject",
            "query_subject", "release_gate_id", "maximum_authentication_age_seconds",
        },
    )
    pack_marketplace_client_identities = require_client_identities(
        pack_marketplace["client_identities"],
        "PRODUCTION_STACK_PACK_MARKETPLACE_CLIENT_IDENTITIES_INVALID",
    )
    pack_marketplace_outbound_identity = require_client_identity(
        pack_marketplace["outbound_client_identity"],
        "PRODUCTION_STACK_PACK_MARKETPLACE_OUTBOUND_IDENTITY_INVALID",
    )
    pack_marketplace_agent_instance_id = require_text(
        pack_marketplace["agent_instance_id"],
        "PRODUCTION_STACK_PACK_MARKETPLACE_AGENT_INSTANCE_ID_INVALID",
    )
    try:
        if str(uuid.UUID(pack_marketplace_agent_instance_id)) != pack_marketplace_agent_instance_id:
            raise ValueError
    except ValueError as error:
        raise RenderError(
            "PRODUCTION_STACK_PACK_MARKETPLACE_AGENT_INSTANCE_ID_INVALID"
        ) from error
    pack_marketplace_identifiers = {}
    for key in (
        "organization_id", "agent_version", "region", "tool_id", "tool_version",
        "executor_credential_profile", "ingress_subject", "executor_subject",
        "query_subject", "release_gate_id",
    ):
        pack_marketplace_identifiers[key] = require_text(
            pack_marketplace[key],
            f"PRODUCTION_STACK_PACK_MARKETPLACE_{key.upper()}_INVALID",
            ENTERPRISE_IDENTIFIER,
        )
    pack_marketplace_max_auth_age = pack_marketplace[
        "maximum_authentication_age_seconds"
    ]
    if (
        pack_marketplace_identifiers["executor_credential_profile"]
        != "pack-marketplace-executor"
    ):
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_EXECUTOR_PROFILE_INVALID")
    if (
        not isinstance(pack_marketplace_max_auth_age, int)
        or not 60 <= pack_marketplace_max_auth_age <= 86_400
    ):
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_MAX_AUTH_AGE_INVALID")

    enterprise_authority = require_mapping(
        values["enterprise_authority"], "enterprise_authority",
        {
            "client_identities", "outbound_client_identity", "agent_instance_id",
            "organization_id", "agent_version", "region", "tool_id", "tool_version",
            "executor_credential_profile", "service_subject",
            "maximum_authentication_age_seconds", "vault_kv_mount", "vault_kv_prefix",
        },
    )
    enterprise_authority_client_identities = require_client_identities(
        enterprise_authority["client_identities"],
        "PRODUCTION_STACK_ENTERPRISE_AUTHORITY_CLIENT_IDENTITIES_INVALID",
    )
    enterprise_authority_outbound_identity = require_client_identity(
        enterprise_authority["outbound_client_identity"],
        "PRODUCTION_STACK_ENTERPRISE_AUTHORITY_OUTBOUND_IDENTITY_INVALID",
    )
    enterprise_authority_agent_instance_id = require_text(
        enterprise_authority["agent_instance_id"],
        "PRODUCTION_STACK_ENTERPRISE_AUTHORITY_AGENT_INSTANCE_ID_INVALID",
    )
    try:
        if str(uuid.UUID(enterprise_authority_agent_instance_id)) != enterprise_authority_agent_instance_id:
            raise ValueError
    except ValueError as error:
        raise RenderError(
            "PRODUCTION_STACK_ENTERPRISE_AUTHORITY_AGENT_INSTANCE_ID_INVALID"
        ) from error
    enterprise_authority_identifiers = {}
    for key in (
        "organization_id", "agent_version", "region", "tool_id", "tool_version",
        "executor_credential_profile", "service_subject",
    ):
        enterprise_authority_identifiers[key] = require_text(
            enterprise_authority[key],
            f"PRODUCTION_STACK_ENTERPRISE_AUTHORITY_{key.upper()}_INVALID",
            ENTERPRISE_IDENTIFIER,
        )
    enterprise_authority_max_auth_age = enterprise_authority[
        "maximum_authentication_age_seconds"
    ]
    if (
        not isinstance(enterprise_authority_max_auth_age, int)
        or not 60 <= enterprise_authority_max_auth_age <= 86_400
    ):
        raise RenderError("PRODUCTION_STACK_ENTERPRISE_AUTHORITY_MAX_AUTH_AGE_INVALID")
    enterprise_authority_vault_mount = require_text(
        enterprise_authority["vault_kv_mount"],
        "PRODUCTION_STACK_ENTERPRISE_AUTHORITY_VAULT_KV_MOUNT_INVALID",
        IDENTIFIER,
    )
    enterprise_authority_vault_prefix = require_text(
        enterprise_authority["vault_kv_prefix"],
        "PRODUCTION_STACK_ENTERPRISE_AUTHORITY_VAULT_KV_PREFIX_INVALID",
        PATH_PREFIX,
    )
    if len(enterprise_authority_vault_prefix) > 128:
        raise RenderError("PRODUCTION_STACK_ENTERPRISE_AUTHORITY_VAULT_KV_PREFIX_INVALID")

    transition = require_mapping(values["transition"], "transition", {"client_identities"})
    transition_client_identities = transition["client_identities"]
    if (
        not isinstance(transition_client_identities, list)
        or not transition_client_identities
        or len(transition_client_identities) != len(set(transition_client_identities))
        or any(not isinstance(value, str) for value in transition_client_identities)
    ):
        raise RenderError("PRODUCTION_STACK_TRANSITION_CLIENT_IDENTITIES_INVALID")
    for client_identity in transition_client_identities:
        require_client_identity(client_identity)

    authorities = require_mapping(
        values["authorities"], "authorities",
        {"approval", "pep", "identity", "tool_proxy", "evidence", "audit"},
    )
    approval_authority = require_mapping(
        authorities["approval"], "approval_authority",
        {
            "client_identities", "evidence_source_identity", "issuer", "key_id", "principal_audience",
            "principal_issuer", "principal_key_id", "principal_signing_key_format",
            "service_subject", "assertion_ttl_seconds", "accepted_strong_auth_acrs",
            "maximum_authentication_age_seconds",
        },
    )
    pep_authority = require_mapping(
        authorities["pep"], "pep_authority",
        {
            "client_identities", "outbound_client_identity", "issuer", "key_id",
            "policy_bundle_signing_key_id", "human_assertion_audience",
            "human_assertion_max_authentication_age_seconds",
            "query_require_strong_auth",
        },
    )
    identity_authority = require_mapping(
        authorities["identity"], "identity_authority",
        {"client_identities", "issuer", "key_id", "tool_proxy_client_identity"},
    )
    tool_authority = require_mapping(
        authorities["tool_proxy"], "tool_proxy_authority", {"client_identities"},
    )
    evidence_authority = require_mapping(
        authorities["evidence"], "evidence_authority",
        {"client_identities", "issuer", "key_id", "worm_endpoint", "max_artifact_bytes"},
    )
    audit_authority = require_mapping(
        authorities["audit"], "audit_authority",
        {
            "client_identities", "issuer", "key_id", "worm_endpoint",
            "deletion_endpoint", "max_export_bytes", "max_request_bytes",
        },
    )
    authority_client_identities = {
        "approval": require_client_identities(
            approval_authority["client_identities"],
            "PRODUCTION_STACK_APPROVAL_CLIENT_IDENTITIES_INVALID",
        ),
        "pep": require_client_identities(
            pep_authority["client_identities"],
            "PRODUCTION_STACK_PEP_CLIENT_IDENTITIES_INVALID",
        ),
        "identity": require_client_identities(
            identity_authority["client_identities"],
            "PRODUCTION_STACK_IDENTITY_CLIENT_IDENTITIES_INVALID",
        ),
        "tool_proxy": require_client_identities(
            tool_authority["client_identities"],
            "PRODUCTION_STACK_TOOL_PROXY_CLIENT_IDENTITIES_INVALID",
        ),
        "evidence": require_client_identities(
            evidence_authority["client_identities"],
            "PRODUCTION_STACK_EVIDENCE_CLIENT_IDENTITIES_INVALID",
        ),
        "audit": require_client_identities(
            audit_authority["client_identities"],
            "PRODUCTION_STACK_AUDIT_CLIENT_IDENTITIES_INVALID",
        ),
    }
    for authority_name in ("approval", "pep", "tool_proxy", "evidence"):
        if execution_outbound_identity not in authority_client_identities[authority_name]:
            raise RenderError(
                f"PRODUCTION_STACK_{authority_name.upper()}_EXECUTION_IDENTITY_MISSING"
            )
    approval_evidence_source_identity = require_client_identity(
        approval_authority["evidence_source_identity"],
        "PRODUCTION_STACK_APPROVAL_EVIDENCE_SOURCE_IDENTITY_INVALID",
    )
    if approval_evidence_source_identity not in authority_client_identities["evidence"]:
        raise RenderError("PRODUCTION_STACK_APPROVAL_EVIDENCE_IDENTITY_MISSING")
    tool_proxy_identity = require_client_identity(
        identity_authority["tool_proxy_client_identity"],
        "PRODUCTION_STACK_IDENTITY_TOOL_PROXY_CLIENT_IDENTITY_INVALID",
    )
    if tool_proxy_identity not in authority_client_identities["identity"]:
        raise RenderError("PRODUCTION_STACK_IDENTITY_TOOL_PROXY_IDENTITY_MISSING")
    pep_outbound_identity = require_client_identity(
        pep_authority["outbound_client_identity"],
        "PRODUCTION_STACK_PEP_OUTBOUND_CLIENT_IDENTITY_INVALID",
    )
    if pep_outbound_identity not in authority_client_identities["approval"]:
        raise RenderError("PRODUCTION_STACK_APPROVAL_PEP_IDENTITY_MISSING")
    if pep_outbound_identity not in authority_client_identities["identity"]:
        raise RenderError("PRODUCTION_STACK_IDENTITY_PEP_IDENTITY_MISSING")
    if pep_outbound_identity not in registry_client_identities:
        raise RenderError("PRODUCTION_STACK_REGISTRY_PEP_IDENTITY_MISSING")
    authority_identifiers: dict[str, str] = {}
    for name, authority in (
        ("approval", approval_authority), ("pep", pep_authority),
        ("identity", identity_authority), ("evidence", evidence_authority),
        ("audit", audit_authority),
    ):
        authority_identifiers[f"{name}_issuer"] = require_text(
            authority["issuer"], f"PRODUCTION_STACK_{name.upper()}_ISSUER_INVALID", VAULT_VALUE,
        )
        authority_identifiers[f"{name}_key_id"] = require_text(
            authority["key_id"], f"PRODUCTION_STACK_{name.upper()}_KEY_ID_INVALID", IDENTIFIER,
        )
    approval_principal_audience = require_text(
        approval_authority["principal_audience"],
        "PRODUCTION_STACK_APPROVAL_PRINCIPAL_AUDIENCE_INVALID", VAULT_VALUE,
    )
    approval_principal_issuer = require_text(
        approval_authority["principal_issuer"],
        "PRODUCTION_STACK_APPROVAL_PRINCIPAL_ISSUER_INVALID", VAULT_VALUE,
    )
    approval_principal_key_id = require_text(
        approval_authority["principal_key_id"],
        "PRODUCTION_STACK_APPROVAL_PRINCIPAL_KEY_ID_INVALID", IDENTIFIER,
    )
    approval_principal_key_format = require_text(
        approval_authority["principal_signing_key_format"],
        "PRODUCTION_STACK_APPROVAL_PRINCIPAL_SIGNING_KEY_FORMAT_INVALID",
    )
    if approval_principal_key_format not in {"RAW_BASE64URL", "PKCS8_PEM"}:
        raise RenderError("PRODUCTION_STACK_APPROVAL_PRINCIPAL_SIGNING_KEY_FORMAT_INVALID")
    approval_service_subject = require_text(
        approval_authority["service_subject"],
        "PRODUCTION_STACK_APPROVAL_SERVICE_SUBJECT_INVALID", VAULT_VALUE,
    )
    approval_assertion_ttl = approval_authority["assertion_ttl_seconds"]
    approval_max_auth_age = approval_authority["maximum_authentication_age_seconds"]
    if not isinstance(approval_assertion_ttl, int) or not 1 <= approval_assertion_ttl <= 300:
        raise RenderError("PRODUCTION_STACK_APPROVAL_ASSERTION_TTL_INVALID")
    if not isinstance(approval_max_auth_age, int) or not 30 <= approval_max_auth_age <= 86_400:
        raise RenderError("PRODUCTION_STACK_APPROVAL_MAX_AUTH_AGE_INVALID")
    strong_auth_acrs = approval_authority["accepted_strong_auth_acrs"]
    if (
        not isinstance(strong_auth_acrs, list) or not strong_auth_acrs
        or len(strong_auth_acrs) > 64 or len(strong_auth_acrs) != len(set(strong_auth_acrs))
    ):
        raise RenderError("PRODUCTION_STACK_APPROVAL_STRONG_AUTH_ACRS_INVALID")
    for acr in strong_auth_acrs:
        require_text(acr, "PRODUCTION_STACK_APPROVAL_STRONG_AUTH_ACRS_INVALID", VAULT_VALUE)
    pep_policy_bundle_signing_key_id = require_text(
        pep_authority["policy_bundle_signing_key_id"],
        "PRODUCTION_STACK_PEP_POLICY_BUNDLE_SIGNING_KEY_ID_INVALID", IDENTIFIER,
    )
    pep_human_assertion_audience = require_text(
        pep_authority["human_assertion_audience"],
        "PRODUCTION_STACK_PEP_HUMAN_ASSERTION_AUDIENCE_INVALID", VAULT_VALUE,
    )
    pep_human_max_auth_age = pep_authority["human_assertion_max_authentication_age_seconds"]
    if not isinstance(pep_human_max_auth_age, int) or not 30 <= pep_human_max_auth_age <= 86_400:
        raise RenderError("PRODUCTION_STACK_PEP_HUMAN_ASSERTION_MAX_AUTH_AGE_INVALID")
    pep_query_require_strong_auth = pep_authority["query_require_strong_auth"]
    if not isinstance(pep_query_require_strong_auth, bool):
        raise RenderError("PRODUCTION_STACK_PEP_QUERY_STRONG_AUTH_INVALID")
    evidence_worm_endpoint = require_https(
        evidence_authority["worm_endpoint"],
        "PRODUCTION_STACK_EVIDENCE_WORM_ENDPOINT_INVALID", allowed_ports={443, 8443},
    ).rstrip("/") + "/"
    evidence_max_artifact_bytes = evidence_authority["max_artifact_bytes"]
    if (
        not isinstance(evidence_max_artifact_bytes, int)
        or not 1 <= evidence_max_artifact_bytes <= 1_073_741_824
    ):
        raise RenderError("PRODUCTION_STACK_EVIDENCE_MAX_ARTIFACT_BYTES_INVALID")
    audit_worm_endpoint = require_https(
        audit_authority["worm_endpoint"],
        "PRODUCTION_STACK_AUDIT_WORM_ENDPOINT_INVALID", allowed_ports={443, 8443},
    ).rstrip("/") + "/"
    audit_deletion_endpoint = require_https(
        audit_authority["deletion_endpoint"],
        "PRODUCTION_STACK_AUDIT_DELETION_ENDPOINT_INVALID", allowed_ports={443, 8443},
    ).rstrip("/") + "/"
    audit_max_export_bytes = audit_authority["max_export_bytes"]
    audit_max_request_bytes = audit_authority["max_request_bytes"]
    if (
        not isinstance(audit_max_export_bytes, int)
        or not 1_048_576 <= audit_max_export_bytes <= 67_108_864
        or not isinstance(audit_max_request_bytes, int)
        or not 65_536 <= audit_max_request_bytes <= 16_777_216
    ):
        raise RenderError("PRODUCTION_STACK_AUDIT_BOUNDS_INVALID")

    vault = require_mapping(values["vault"], "vault", VAULT_KEYS)
    vault_address = require_https(vault["address"], "PRODUCTION_STACK_VAULT_ADDRESS_INVALID")
    if urlparse(vault_address).path not in {"", "/"}:
        raise RenderError("PRODUCTION_STACK_VAULT_ADDRESS_INVALID")
    vault_address = vault_address.rstrip("/")
    for key in VAULT_KEYS - {"address"}:
        require_text(vault[key], f"PRODUCTION_STACK_VAULT_{key.upper()}_INVALID", VAULT_VALUE)
    vault_role_keys = sorted(key for key in VAULT_KEYS if key.endswith("_role"))
    vault_path_keys = sorted(key for key in VAULT_KEYS if key.endswith("_path"))
    if len({vault[key] for key in vault_role_keys}) != len(vault_role_keys):
        raise RenderError("PRODUCTION_STACK_VAULT_ROLES_NOT_DISTINCT")
    if len({vault[key] for key in vault_path_keys}) != len(vault_path_keys):
        raise RenderError("PRODUCTION_STACK_VAULT_PATHS_NOT_DISTINCT")

    network = require_mapping(
        values["network"], "network",
        {
            "node_cidr", "database_cidr", "temporal_cidr", "vault_cidr", "iam_cidr",
            "ingress_cidr", "external_service_egress_cidr", "tool_target_cidr",
            "evidence_storage_cidr", "dns_cidr",
        },
    )
    for key, raw in network.items():
        require_cidr(raw, f"PRODUCTION_STACK_{key.upper()}_INVALID")
    parsed_networks = {
        key: ipaddress.ip_network(raw, strict=True) for key, raw in network.items()
    }
    non_dns_networks = [
        (key, parsed_networks[key]) for key in network if key != "dns_cidr"
    ]
    for index, (left_key, left) in enumerate(non_dns_networks):
        for right_key, right in non_dns_networks[index + 1:]:
            if left.version == right.version and left.overlaps(right):
                raise RenderError(
                    f"PRODUCTION_STACK_NETWORK_CIDRS_OVERLAP:{left_key}:{right_key}"
                )
    dns_network = ipaddress.ip_network(network["dns_cidr"], strict=True)
    if dns_network.prefixlen != dns_network.max_prefixlen:
        raise RenderError("PRODUCTION_STACK_DNS_CIDR_INVALID")

    evidence = require_mapping(
        values["evidence"], "evidence",
        {"persistent_volume_name", "bundle_digest", "storage_size"},
    )
    require_text(evidence["persistent_volume_name"], "PRODUCTION_STACK_EVIDENCE_PV_INVALID", NAME)
    require_text(evidence["bundle_digest"], "PRODUCTION_STACK_EVIDENCE_DIGEST_INVALID", DIGEST)
    require_text(evidence["storage_size"], "PRODUCTION_STACK_EVIDENCE_SIZE_INVALID", STORAGE)
    if activation_receipt["evidence_bundle_manifest_digest"] != evidence["bundle_digest"]:
        raise RenderError("PRODUCTION_STACK_ACTIVATION_EVIDENCE_MISMATCH")

    ingress = require_mapping(
        values["ingress"], "ingress",
        {"class", "console_host", "control_api_host", "console_tls_secret", "control_api_tls_secret"},
    )
    for key in ingress:
        require_text(ingress[key], f"PRODUCTION_STACK_INGRESS_{key.upper()}_INVALID", NAME)
    if ingress["console_host"] == ingress["control_api_host"]:
        raise RenderError("PRODUCTION_STACK_INGRESS_HOSTS_NOT_DISTINCT")

    facts = require_mapping(values["transition_facts"], "transition_facts", FACT_KEYS)
    for key, endpoint in facts.items():
        require_https(
            endpoint,
            f"PRODUCTION_STACK_{key.upper()}_FACT_ENDPOINT_INVALID",
            trailing_slash=True,
            allowed_ports={443, 8443},
        )

    enterprise = require_mapping(
        values["enterprise"], "enterprise",
        {
            "iam_issuer", "iam_jwks_endpoint", "iam_audience",
            "iam_authorization_endpoint", "iam_token_endpoint",
            "iam_userinfo_endpoint", "pep_endpoint", "pep_readiness_schema",
            "approval_client_identity", "human_assertion",
            "orchestrator_runtime_client_identities",
            "orchestrator_bff_client_identities", "authority_endpoints",
            "authority_readiness_schemas",
        },
    )
    require_https(
        enterprise["iam_issuer"], "PRODUCTION_STACK_IAM_ISSUER_INVALID",
        allowed_ports={443, 8443},
    )
    require_https(
        enterprise["iam_jwks_endpoint"], "PRODUCTION_STACK_IAM_JWKS_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
    )
    require_text(enterprise["iam_audience"], "PRODUCTION_STACK_IAM_AUDIENCE_INVALID", IDENTIFIER)
    require_https(
        enterprise["iam_authorization_endpoint"],
        "PRODUCTION_STACK_IAM_AUTHORIZATION_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
    )
    require_https(
        enterprise["iam_token_endpoint"],
        "PRODUCTION_STACK_IAM_TOKEN_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
    )
    require_https(
        enterprise["iam_userinfo_endpoint"],
        "PRODUCTION_STACK_IAM_USERINFO_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
    )
    enterprise_pep_endpoint = require_https(
        enterprise["pep_endpoint"], "PRODUCTION_STACK_PEP_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
    )
    if enterprise_pep_endpoint.rstrip("/") != "https://agenttrust-pep":
        raise RenderError("PRODUCTION_STACK_PEP_ENDPOINT_NOT_INTERNAL")
    enterprise_pep_endpoint = "https://agenttrust-pep"
    pep_readiness_schema = require_text(
        enterprise["pep_readiness_schema"],
        "PRODUCTION_STACK_PEP_READINESS_SCHEMA_INVALID", IDENTIFIER,
    )
    if pep_readiness_schema != "agenttrust.pep-readiness.v1":
        raise RenderError("PRODUCTION_STACK_PEP_READINESS_SCHEMA_MISMATCH")
    enterprise_approval_identity = require_client_identity(
        enterprise["approval_client_identity"],
        "PRODUCTION_STACK_ENTERPRISE_APPROVAL_CLIENT_IDENTITY_INVALID",
    )
    human_assertion = require_mapping(
        enterprise["human_assertion"], "enterprise_human_assertion",
        {
            "issuer", "audience", "key_id", "signing_key_format",
            "service_subject", "assertion_ttl_seconds",
            "accepted_authentication_contexts", "maximum_authentication_age_seconds",
        },
    )
    human_assertion_issuer = require_text(
        human_assertion["issuer"],
        "PRODUCTION_STACK_HUMAN_ASSERTION_ISSUER_INVALID", VAULT_VALUE,
    )
    human_assertion_audience = require_text(
        human_assertion["audience"],
        "PRODUCTION_STACK_HUMAN_ASSERTION_AUDIENCE_INVALID", VAULT_VALUE,
    )
    human_assertion_key_id = require_text(
        human_assertion["key_id"],
        "PRODUCTION_STACK_HUMAN_ASSERTION_KEY_ID_INVALID", IDENTIFIER,
    )
    human_assertion_key_format = require_text(
        human_assertion["signing_key_format"],
        "PRODUCTION_STACK_HUMAN_ASSERTION_KEY_FORMAT_INVALID",
    )
    if human_assertion_key_format not in {"RAW_BASE64URL", "PKCS8_PEM"}:
        raise RenderError("PRODUCTION_STACK_HUMAN_ASSERTION_KEY_FORMAT_INVALID")
    human_assertion_service_subject = require_text(
        human_assertion["service_subject"],
        "PRODUCTION_STACK_HUMAN_ASSERTION_SERVICE_SUBJECT_INVALID", VAULT_VALUE,
    )
    human_assertion_ttl = human_assertion["assertion_ttl_seconds"]
    human_assertion_max_auth_age = human_assertion["maximum_authentication_age_seconds"]
    if not isinstance(human_assertion_ttl, int) or not 1 <= human_assertion_ttl <= 300:
        raise RenderError("PRODUCTION_STACK_HUMAN_ASSERTION_TTL_INVALID")
    if (
        not isinstance(human_assertion_max_auth_age, int)
        or not 30 <= human_assertion_max_auth_age <= 86_400
        or human_assertion_max_auth_age != pep_human_max_auth_age
    ):
        raise RenderError("PRODUCTION_STACK_HUMAN_ASSERTION_MAX_AUTH_AGE_INVALID")
    if human_assertion_audience != pep_human_assertion_audience:
        raise RenderError("PRODUCTION_STACK_HUMAN_ASSERTION_AUDIENCE_MISMATCH")
    human_auth_contexts = human_assertion["accepted_authentication_contexts"]
    if (
        not isinstance(human_auth_contexts, list) or not human_auth_contexts
        or len(human_auth_contexts) > 64
        or len(human_auth_contexts) != len(set(human_auth_contexts))
    ):
        raise RenderError("PRODUCTION_STACK_HUMAN_ASSERTION_AUTH_CONTEXTS_INVALID")
    for context in human_auth_contexts:
        require_text(
            context, "PRODUCTION_STACK_HUMAN_ASSERTION_AUTH_CONTEXTS_INVALID", VAULT_VALUE,
        )
    runtime_client_identities = enterprise["orchestrator_runtime_client_identities"]
    bff_client_identities = enterprise["orchestrator_bff_client_identities"]
    for client_identities in (runtime_client_identities, bff_client_identities):
        if (
            not isinstance(client_identities, list) or not client_identities
            or len(client_identities) != len(set(client_identities))
            or any(not isinstance(value, str) for value in client_identities)
        ):
            raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_CLIENT_IDENTITIES_INVALID")
        for client_identity in client_identities:
            require_client_identity(client_identity)
    if set(runtime_client_identities) & set(bff_client_identities):
        raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_CLIENT_IDENTITIES_NOT_DISTINCT")
    if enterprise_approval_identity not in bff_client_identities:
        raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_authority_outbound_identity not in bff_client_identities:
        raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_ENTERPRISE_AUTHORITY_IDENTITY_MISSING")
    if policy_admin_outbound_identity not in bff_client_identities:
        raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_POLICY_ADMIN_IDENTITY_MISSING")
    if incident_release_outbound_identity not in bff_client_identities:
        raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_INCIDENT_RELEASE_IDENTITY_MISSING")
    if pack_marketplace_outbound_identity not in bff_client_identities:
        raise RenderError("PRODUCTION_STACK_ORCHESTRATOR_PACK_MARKETPLACE_IDENTITY_MISSING")
    authority_outbound_identities = {
        enterprise_authority_outbound_identity,
        policy_admin_outbound_identity,
        incident_release_outbound_identity,
        pack_marketplace_outbound_identity,
    }
    if len(authority_outbound_identities) != 4:
        raise RenderError("PRODUCTION_STACK_AUTHORITY_OUTBOUND_IDENTITIES_NOT_DISTINCT")
    workload_identities = authority_outbound_identities | {
        execution_outbound_identity, pep_outbound_identity,
        enterprise_approval_identity, tool_proxy_identity,
        approval_evidence_source_identity,
    }
    if len(workload_identities) != 9:
        raise RenderError("PRODUCTION_STACK_WORKLOAD_IDENTITIES_NOT_DISTINCT")
    if enterprise_approval_identity not in agent_registry_client_identities:
        raise RenderError("PRODUCTION_STACK_AGENT_REGISTRY_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_approval_identity not in enterprise_authority_client_identities:
        raise RenderError("PRODUCTION_STACK_ENTERPRISE_AUTHORITY_BFF_IDENTITY_MISSING")
    if tool_proxy_identity not in enterprise_authority_client_identities:
        raise RenderError("PRODUCTION_STACK_ENTERPRISE_AUTHORITY_TOOL_PROXY_IDENTITY_MISSING")
    if set(policy_admin_client_identities) != {
        enterprise_approval_identity, tool_proxy_identity,
    }:
        raise RenderError("PRODUCTION_STACK_POLICY_ADMIN_CLIENT_IDENTITIES_NOT_EXACT")
    if set(authority_client_identities["pep"]) != {
        execution_outbound_identity, enterprise_approval_identity,
        policy_admin_outbound_identity,
    }:
        raise RenderError("PRODUCTION_STACK_PEP_CLIENT_IDENTITIES_NOT_EXACT")
    if set(incident_release_client_identities) != {
        enterprise_approval_identity, tool_proxy_identity, incident_detection_identity,
    }:
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_CLIENT_IDENTITIES_NOT_EXACT")
    if set(pack_marketplace_client_identities) != {
        enterprise_approval_identity, tool_proxy_identity,
    }:
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_CLIENT_IDENTITIES_NOT_EXACT")
    if incident_detection_identity in workload_identities:
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_DETECTION_IDENTITY_NOT_DISTINCT")
    if enterprise_authority_identifiers["service_subject"] != human_assertion_service_subject:
        raise RenderError("PRODUCTION_STACK_ENTERPRISE_AUTHORITY_SERVICE_SUBJECT_MISMATCH")
    if enterprise_authority_max_auth_age != human_assertion_max_auth_age:
        raise RenderError("PRODUCTION_STACK_ENTERPRISE_AUTHORITY_MAX_AUTH_AGE_MISMATCH")
    if policy_admin_identifiers["service_subject"] != human_assertion_service_subject:
        raise RenderError("PRODUCTION_STACK_POLICY_ADMIN_SERVICE_SUBJECT_MISMATCH")
    if policy_admin_max_auth_age != human_assertion_max_auth_age:
        raise RenderError("PRODUCTION_STACK_POLICY_ADMIN_MAX_AUTH_AGE_MISMATCH")
    if (
        pep_policy_bundle_signing_key_id
        != policy_admin_identifiers["bundle_signing_key_id"]
    ):
        raise RenderError("PRODUCTION_STACK_POLICY_BUNDLE_SIGNING_KEY_ID_MISMATCH")
    if incident_release_identifiers["service_subject"] != human_assertion_service_subject:
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_SERVICE_SUBJECT_MISMATCH")
    if incident_release_max_auth_age != human_assertion_max_auth_age:
        raise RenderError("PRODUCTION_STACK_INCIDENT_RELEASE_MAX_AUTH_AGE_MISMATCH")
    if pack_marketplace_identifiers["ingress_subject"] != human_assertion_service_subject:
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_INGRESS_SUBJECT_MISMATCH")
    if pack_marketplace_identifiers["query_subject"] != human_assertion_service_subject:
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_QUERY_SUBJECT_MISMATCH")
    if pack_marketplace_identifiers["executor_subject"] != tool_proxy_identity:
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_EXECUTOR_SUBJECT_MISMATCH")
    if pack_marketplace_max_auth_age != human_assertion_max_auth_age:
        raise RenderError("PRODUCTION_STACK_PACK_MARKETPLACE_MAX_AUTH_AGE_MISMATCH")
    if enterprise_approval_identity not in authority_client_identities["approval"]:
        raise RenderError("PRODUCTION_STACK_APPROVAL_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_approval_identity not in authority_client_identities["pep"]:
        raise RenderError("PRODUCTION_STACK_PEP_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_approval_identity not in registry_client_identities:
        raise RenderError("PRODUCTION_STACK_REGISTRY_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_approval_identity not in authority_client_identities["identity"]:
        raise RenderError("PRODUCTION_STACK_IDENTITY_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_approval_identity not in authority_client_identities["evidence"]:
        raise RenderError("PRODUCTION_STACK_EVIDENCE_ENTERPRISE_IDENTITY_MISSING")
    if enterprise_approval_identity not in authority_client_identities["audit"]:
        raise RenderError("PRODUCTION_STACK_AUDIT_ENTERPRISE_IDENTITY_MISSING")
    if tool_proxy_identity not in registry_client_identities:
        raise RenderError("PRODUCTION_STACK_REGISTRY_TOOL_PROXY_IDENTITY_MISSING")
    authorities = require_mapping(enterprise["authority_endpoints"], "authority_endpoints", AUTHORITY_KEYS)
    for key, endpoint in authorities.items():
        require_https(
            endpoint,
            f"PRODUCTION_STACK_{key.upper()}_AUTHORITY_ENDPOINT_INVALID",
            allowed_ports={443, 8443},
        )
    internal_authorities = {
        "agents": "https://agenttrust-agent-registry",
        "approvals": "https://agenttrust-approval",
        "evidence": "https://agenttrust-evidence",
        "tools": "https://agenttrust-registry",
        "credentials": "https://agenttrust-identity",
        "audit": "https://agenttrust-audit",
        "policies": "https://agenttrust-policy-admin",
        "incidents": "https://agenttrust-incident-release",
        "packs": "https://agenttrust-pack-marketplace",
        "models": "https://agenttrust-model-gateway",
        "data": "https://agenttrust-data-governance",
        "context": "https://agenttrust-context-governance",
        "anomalies": "https://agenttrust-runtime-anomaly",
        "security_evaluations": "https://agenttrust-security-evaluation",
        "supply_chain": "https://agenttrust-pack-supply-chain",
        "domain_packs": "https://agenttrust-domain-runtime",
        "sre": "https://agenttrust-platform-sre",
    }
    for name, endpoint in internal_authorities.items():
        if authorities[name].rstrip("/") != endpoint:
            raise RenderError(
                f"PRODUCTION_STACK_{name.upper()}_AUTHORITY_NOT_INTERNAL"
            )
    authority_readiness_schemas = require_mapping(
        enterprise["authority_readiness_schemas"],
        "authority_readiness_schemas", AUTHORITY_READINESS_KEYS,
    )
    for key, schema in authority_readiness_schemas.items():
        require_text(
            schema,
            f"PRODUCTION_STACK_{key.upper()}_AUTHORITY_READINESS_SCHEMA_INVALID",
            IDENTIFIER,
        )
    for key, expected_schema in INTERNAL_READINESS_SCHEMAS.items():
        if authority_readiness_schemas[key] != expected_schema:
            raise RenderError(
                f"PRODUCTION_STACK_{key.upper()}_AUTHORITY_READINESS_SCHEMA_MISMATCH"
            )

    runtime = validate_runtime_config(runtime_config, release_id)
    release_name_base = re.sub(r"[^a-z0-9-]+", "-", release_id.lower()).strip("-")[:40]
    if not release_name_base:
        raise RenderError("PRODUCTION_STACK_RELEASE_ID_INVALID")
    release_name = f"{release_name_base}-{release_digest[:8]}"
    runtime_text = json.dumps(runtime, indent=2, sort_keys=True, ensure_ascii=True)
    runtime_indented = "\n".join("    " + line for line in runtime_text.splitlines())

    replacements = {
        "RELEASE_ID": release_id, "RELEASE_NAME": release_name,
        "RELEASE_DIGEST": release_digest,
        "ACTIVATION_RECEIPT_DIGEST": activation_receipt_digest,
        "PRODUCTION_CERTIFICATE_ID": activation_receipt["certificate_id"],
        "REVOCATION_REGISTRY_SEQUENCE": activation_receipt[
            "revocation_registry_sequence"
        ],
        "REVOCATION_REGISTRY_DIGEST": activation_receipt[
            "revocation_registry_digest"
        ],
        "RUNTIME_CONFIG": runtime_indented,
        "EVIDENCE_BUNDLE_DIGEST": evidence["bundle_digest"],
        "EVIDENCE_PV_NAME": evidence["persistent_volume_name"],
        "EVIDENCE_STORAGE_SIZE": evidence["storage_size"],
        "TEMPORAL_ADDRESS": temporal_address, "TEMPORAL_NAMESPACE": temporal["namespace"],
        "TEMPORAL_TASK_QUEUE": temporal["task_queue"],
        "TEMPORAL_SERVER_NAME": temporal["server_name"],
        "EXECUTION_ENDPOINT": "https://agenttrust-execution/v1/executions/execute",
        "EXECUTION_CLIENT_IDENTITIES": ",".join(execution_client_identities),
        "EXECUTION_OUTBOUND_CLIENT_IDENTITY": execution_outbound_identity,
        "EXECUTION_APPROVAL_ENDPOINT": execution_endpoints["approval"],
        "EXECUTION_PEP_ENDPOINT": execution_endpoints["pep"],
        "EXECUTION_TOOL_ENDPOINT": execution_endpoints["tool"],
        "EXECUTION_EVIDENCE_ENDPOINT": execution_endpoints["evidence"],
        "EXECUTION_APPROVAL_READINESS_SCHEMA": execution_readiness_schemas["approval"],
        "EXECUTION_PEP_READINESS_SCHEMA": execution_readiness_schemas["pep"],
        "EXECUTION_TOOL_READINESS_SCHEMA": execution_readiness_schemas["tool"],
        "EXECUTION_EVIDENCE_READINESS_SCHEMA": execution_readiness_schemas["evidence"],
        "REGISTRY_CLIENT_IDENTITIES": ",".join(registry_client_identities),
        "REGISTRY_PUBLISHER_ID": registry_publisher_id,
        "REGISTRY_PUBLISHER_KEY_ID": registry_publisher_key_id,
        "TRANSITION_CLIENT_IDENTITIES": ",".join(transition_client_identities),
        "ENTERPRISE_APPLICATION_ROLE": database["enterprise_application_role"],
        "ENTERPRISE_AUTHORITY_APPLICATION_ROLE": database[
            "enterprise_authority_application_role"
        ],
        "ORCHESTRATOR_APPLICATION_ROLE": database["orchestrator_application_role"],
        "EXECUTION_APPLICATION_ROLE": database["execution_application_role"],
        "REGISTRY_APPLICATION_ROLE": database["registry_application_role"],
        "AGENT_REGISTRY_APPLICATION_ROLE": database["agent_registry_application_role"],
        "POLICY_ADMIN_APPLICATION_ROLE": database["policy_admin_application_role"],
        "INCIDENT_RELEASE_APPLICATION_ROLE": database[
            "incident_release_application_role"
        ],
        "PACK_MARKETPLACE_APPLICATION_ROLE": database[
            "pack_marketplace_application_role"
        ],
        "APPROVAL_APPLICATION_ROLE": database["approval_application_role"],
        "PEP_APPLICATION_ROLE": database["pep_application_role"],
        "IDENTITY_APPLICATION_ROLE": database["identity_application_role"],
        "TOOL_PROXY_APPLICATION_ROLE": database["tool_proxy_application_role"],
        "EVIDENCE_APPLICATION_ROLE": database["evidence_application_role"],
        "AUDIT_APPLICATION_ROLE": database["audit_application_role"],
        "MODEL_GATEWAY_APPLICATION_ROLE": database["model_gateway_application_role"],
        "DATA_GOVERNANCE_APPLICATION_ROLE": database["data_governance_application_role"],
        "CONTEXT_GOVERNANCE_APPLICATION_ROLE": database["context_governance_application_role"],
        "RUNTIME_ANOMALY_APPLICATION_ROLE": database["runtime_anomaly_application_role"],
        "SECURITY_EVALUATION_APPLICATION_ROLE": database["security_evaluation_application_role"],
        "PACK_SUPPLY_CHAIN_APPLICATION_ROLE": database["pack_supply_chain_application_role"],
        "DOMAIN_RUNTIME_APPLICATION_ROLE": database["domain_runtime_application_role"],
        "PLATFORM_SRE_APPLICATION_ROLE": database["platform_sre_application_role"],
        "APPROVAL_CLIENT_IDENTITIES": ",".join(authority_client_identities["approval"]),
        "APPROVAL_ISSUER": authority_identifiers["approval_issuer"],
        "APPROVAL_KEY_ID": authority_identifiers["approval_key_id"],
        "APPROVAL_PRINCIPAL_AUDIENCE": approval_principal_audience,
        "APPROVAL_PRINCIPAL_ISSUER": approval_principal_issuer,
        "APPROVAL_PRINCIPAL_KEY_ID": approval_principal_key_id,
        "APPROVAL_PRINCIPAL_KEY_FORMAT": approval_principal_key_format,
        "APPROVAL_SERVICE_SUBJECT": approval_service_subject,
        "APPROVAL_ASSERTION_TTL_SECONDS": str(approval_assertion_ttl),
        "APPROVAL_ACCEPTED_STRONG_AUTH_ACRS": ",".join(strong_auth_acrs),
        "APPROVAL_MAX_AUTH_AGE_SECONDS": str(approval_max_auth_age),
        "PEP_CLIENT_IDENTITIES": ",".join(authority_client_identities["pep"]),
        "PEP_OUTBOUND_CLIENT_IDENTITY": pep_outbound_identity,
        "PEP_ISSUER": authority_identifiers["pep_issuer"],
        "PEP_KEY_ID": authority_identifiers["pep_key_id"],
        "PEP_HUMAN_ASSERTION_AUDIENCE": pep_human_assertion_audience,
        "PEP_HUMAN_ASSERTION_MAX_AUTH_AGE_SECONDS": str(pep_human_max_auth_age),
        "PEP_QUERY_REQUIRE_STRONG_AUTH": str(pep_query_require_strong_auth).lower(),
        "IDENTITY_CLIENT_IDENTITIES": ",".join(authority_client_identities["identity"]),
        "IDENTITY_TOOL_PROXY_CLIENT_IDENTITY": tool_proxy_identity,
        "IDENTITY_ISSUER": authority_identifiers["identity_issuer"],
        "IDENTITY_KEY_ID": authority_identifiers["identity_key_id"],
        "TOOL_PROXY_CLIENT_IDENTITIES": ",".join(authority_client_identities["tool_proxy"]),
        "EVIDENCE_CLIENT_IDENTITIES": ",".join(authority_client_identities["evidence"]),
        "EVIDENCE_ISSUER": authority_identifiers["evidence_issuer"],
        "EVIDENCE_KEY_ID": authority_identifiers["evidence_key_id"],
        "EVIDENCE_WORM_ENDPOINT": evidence_worm_endpoint,
        "EVIDENCE_MAX_ARTIFACT_BYTES": str(evidence_max_artifact_bytes),
        "AUDIT_CLIENT_IDENTITIES": ",".join(authority_client_identities["audit"]),
        "AUDIT_ISSUER": authority_identifiers["audit_issuer"],
        "AUDIT_KEY_ID": authority_identifiers["audit_key_id"],
        "AUDIT_WORM_ENDPOINT": audit_worm_endpoint,
        "AUDIT_DELETION_ENDPOINT": audit_deletion_endpoint,
        "AUDIT_MAX_EXPORT_BYTES": str(audit_max_export_bytes),
        "AUDIT_MAX_REQUEST_BYTES": str(audit_max_request_bytes),
        "AGENT_REGISTRY_CLIENT_IDENTITIES": ",".join(agent_registry_client_identities),
        "AGENT_REGISTRY_LIFECYCLE_ENDPOINT": agent_registry_lifecycle_endpoint,
        "POLICY_ADMIN_CLIENT_IDENTITIES": ",".join(policy_admin_client_identities),
        "POLICY_ADMIN_AGENT_INSTANCE_ID": policy_admin_agent_instance_id,
        "POLICY_ADMIN_ORGANIZATION_ID": policy_admin_identifiers["organization_id"],
        "POLICY_ADMIN_AGENT_VERSION": policy_admin_identifiers["agent_version"],
        "POLICY_ADMIN_REGION": policy_admin_identifiers["region"],
        "POLICY_ADMIN_TOOL_ID": policy_admin_identifiers["tool_id"],
        "POLICY_ADMIN_TOOL_VERSION": policy_admin_identifiers["tool_version"],
        "POLICY_ADMIN_EXECUTOR_CREDENTIAL_PROFILE": policy_admin_identifiers[
            "executor_credential_profile"
        ],
        "POLICY_ADMIN_SERVICE_SUBJECT": policy_admin_identifiers["service_subject"],
        "POLICY_ADMIN_BUNDLE_SIGNING_KEY_ID": policy_admin_identifiers[
            "bundle_signing_key_id"
        ],
        "POLICY_ADMIN_MAX_AUTH_AGE_SECONDS": str(policy_admin_max_auth_age),
        "INCIDENT_RELEASE_CLIENT_IDENTITIES": ",".join(
            incident_release_client_identities
        ),
        "INCIDENT_RELEASE_AGENT_INSTANCE_ID": incident_release_agent_instance_id,
        "INCIDENT_RELEASE_ORGANIZATION_ID": incident_release_identifiers[
            "organization_id"
        ],
        "INCIDENT_RELEASE_AGENT_VERSION": incident_release_identifiers["agent_version"],
        "INCIDENT_RELEASE_REGION": incident_release_identifiers["region"],
        "INCIDENT_RELEASE_TOOL_ID": incident_release_identifiers["tool_id"],
        "INCIDENT_RELEASE_TOOL_VERSION": incident_release_identifiers["tool_version"],
        "INCIDENT_RELEASE_EXECUTOR_CREDENTIAL_PROFILE": incident_release_identifiers[
            "executor_credential_profile"
        ],
        "INCIDENT_RELEASE_SERVICE_SUBJECT": incident_release_identifiers[
            "service_subject"
        ],
        "INCIDENT_RELEASE_SIGNING_KEY_ID": incident_release_identifiers[
            "release_signing_key_id"
        ],
        "INCIDENT_RELEASE_MAX_AUTH_AGE_SECONDS": str(incident_release_max_auth_age),
        "INCIDENT_RELEASE_EXECUTION_LEASE_SECONDS": str(
            incident_execution_lease_seconds
        ),
        "INCIDENT_RELEASE_CONTAINMENT_ENDPOINT": incident_effect_endpoints[
            "containment"
        ],
        "INCIDENT_RELEASE_REPLAY_ENDPOINT": incident_effect_endpoints["replay"],
        "PACK_MARKETPLACE_CLIENT_IDENTITIES": ",".join(
            pack_marketplace_client_identities
        ),
        "PACK_MARKETPLACE_AGENT_INSTANCE_ID": pack_marketplace_agent_instance_id,
        "PACK_MARKETPLACE_ORGANIZATION_ID": pack_marketplace_identifiers[
            "organization_id"
        ],
        "PACK_MARKETPLACE_AGENT_VERSION": pack_marketplace_identifiers["agent_version"],
        "PACK_MARKETPLACE_REGION": pack_marketplace_identifiers["region"],
        "PACK_MARKETPLACE_TOOL_ID": pack_marketplace_identifiers["tool_id"],
        "PACK_MARKETPLACE_TOOL_VERSION": pack_marketplace_identifiers["tool_version"],
        "PACK_MARKETPLACE_EXECUTOR_CREDENTIAL_PROFILE": pack_marketplace_identifiers[
            "executor_credential_profile"
        ],
        "PACK_MARKETPLACE_INGRESS_SUBJECT": pack_marketplace_identifiers[
            "ingress_subject"
        ],
        "PACK_MARKETPLACE_EXECUTOR_SUBJECT": pack_marketplace_identifiers[
            "executor_subject"
        ],
        "PACK_MARKETPLACE_QUERY_SUBJECT": pack_marketplace_identifiers["query_subject"],
        "PACK_MARKETPLACE_RELEASE_GATE_ID": pack_marketplace_identifiers[
            "release_gate_id"
        ],
        "PACK_MARKETPLACE_MAX_AUTH_AGE_SECONDS": str(pack_marketplace_max_auth_age),
        "ENTERPRISE_AUTHORITY_ENDPOINT": "https://agenttrust-enterprise-authority",
        "ENTERPRISE_AUTHORITY_READINESS_SCHEMA": (
            "agenttrust.enterprise-authority-readiness.v1"
        ),
        "ENTERPRISE_AUTHORITY_CLIENT_IDENTITIES": ",".join(
            enterprise_authority_client_identities
        ),
        "ENTERPRISE_AUTHORITY_AGENT_INSTANCE_ID": enterprise_authority_agent_instance_id,
        "ENTERPRISE_AUTHORITY_ORGANIZATION_ID": enterprise_authority_identifiers[
            "organization_id"
        ],
        "ENTERPRISE_AUTHORITY_AGENT_VERSION": enterprise_authority_identifiers["agent_version"],
        "ENTERPRISE_AUTHORITY_REGION": enterprise_authority_identifiers["region"],
        "ENTERPRISE_AUTHORITY_TOOL_ID": enterprise_authority_identifiers["tool_id"],
        "ENTERPRISE_AUTHORITY_TOOL_VERSION": enterprise_authority_identifiers["tool_version"],
        "ENTERPRISE_AUTHORITY_EXECUTOR_CREDENTIAL_PROFILE": (
            enterprise_authority_identifiers["executor_credential_profile"]
        ),
        "ENTERPRISE_AUTHORITY_SERVICE_SUBJECT": enterprise_authority_identifiers[
            "service_subject"
        ],
        "ENTERPRISE_AUTHORITY_MAX_AUTH_AGE_SECONDS": str(
            enterprise_authority_max_auth_age
        ),
        "ENTERPRISE_AUTHORITY_VAULT_KV_MOUNT": enterprise_authority_vault_mount,
        "ENTERPRISE_AUTHORITY_VAULT_KV_PREFIX": enterprise_authority_vault_prefix,
        "VAULT_ADDRESS": vault_address,
        "NODE_CIDR": network["node_cidr"], "DATABASE_CIDR": network["database_cidr"],
        "TEMPORAL_CIDR": network["temporal_cidr"],
        "VAULT_CIDR": network["vault_cidr"],
        "IAM_CIDR": network["iam_cidr"],
        "INGRESS_CIDR": network["ingress_cidr"],
        "EXTERNAL_SERVICE_EGRESS_CIDR": network["external_service_egress_cidr"],
        "TOOL_TARGET_CIDR": network["tool_target_cidr"],
        "EVIDENCE_STORAGE_CIDR": network["evidence_storage_cidr"],
        "DNS_CIDR": network["dns_cidr"],
        "INGRESS_CLASS": ingress["class"], "CONSOLE_HOST": ingress["console_host"],
        "CONTROL_API_HOST": ingress["control_api_host"],
        "CONSOLE_TLS_SECRET": ingress["console_tls_secret"],
        "CONTROL_API_TLS_SECRET": ingress["control_api_tls_secret"],
        "IAM_ISSUER": enterprise["iam_issuer"],
        "IAM_JWKS_ENDPOINT": enterprise["iam_jwks_endpoint"],
        "IAM_AUDIENCE": enterprise["iam_audience"],
        "IAM_AUTHORIZATION_ENDPOINT": enterprise["iam_authorization_endpoint"],
        "IAM_TOKEN_ENDPOINT": enterprise["iam_token_endpoint"],
        "IAM_USERINFO_ENDPOINT": enterprise["iam_userinfo_endpoint"],
        "PEP_ENDPOINT": enterprise_pep_endpoint,
        "ENTERPRISE_PEP_READINESS_SCHEMA": pep_readiness_schema,
        "ENTERPRISE_APPROVAL_CLIENT_IDENTITY": enterprise_approval_identity,
        "HUMAN_ASSERTION_ISSUER": human_assertion_issuer,
        "HUMAN_ASSERTION_AUDIENCE": human_assertion_audience,
        "HUMAN_ASSERTION_KEY_ID": human_assertion_key_id,
        "HUMAN_ASSERTION_KEY_FORMAT": human_assertion_key_format,
        "HUMAN_ASSERTION_SERVICE_SUBJECT": human_assertion_service_subject,
        "HUMAN_ASSERTION_TTL_SECONDS": str(human_assertion_ttl),
        "HUMAN_ASSERTION_AUTH_CONTEXTS": ",".join(human_auth_contexts),
        "HUMAN_ASSERTION_MAX_AUTH_AGE_SECONDS": str(human_assertion_max_auth_age),
        "ORCHESTRATOR_RUNTIME_CLIENT_IDENTITIES": ",".join(runtime_client_identities),
        "ORCHESTRATOR_BFF_CLIENT_IDENTITIES": ",".join(bff_client_identities),
        "AGENT_REGISTRY_ENDPOINT": authorities["agents"],
        "APPROVAL_AUTHORITY_ENDPOINT": authorities["approvals"],
        "APPROVAL_EVIDENCE_SOURCE_IDENTITY": approval_evidence_source_identity,
        "EVIDENCE_AUTHORITY_ENDPOINT": authorities["evidence"],
        "INCIDENT_AUTHORITY_ENDPOINT": authorities["incidents"],
        "POLICY_ADMIN_ENDPOINT": authorities["policies"],
        "TOOL_REGISTRY_ENDPOINT": authorities["tools"],
        "CREDENTIAL_SESSION_ENDPOINT": authorities["credentials"],
        "PACK_MARKETPLACE_ENDPOINT": authorities["packs"],
        "TRACE_ENDPOINT": authorities["trace"],
        "COMPLIANCE_ENDPOINT": authorities["compliance"],
        "AUDIT_ENDPOINT": authorities["audit"],
        "SRE_ENDPOINT": authorities["sre"],
        "DEPLOYMENT_ENDPOINT": authorities["deployments"],
        "MODEL_GATEWAY_ENDPOINT": authorities["models"],
        "DATA_GOVERNANCE_ENDPOINT": authorities["data"],
        "CONTEXT_GOVERNANCE_ENDPOINT": authorities["context"],
        "RUNTIME_ANOMALY_ENDPOINT": authorities["anomalies"],
        "SECURITY_EVALUATION_ENDPOINT": authorities["security_evaluations"],
        "PACK_SUPPLY_CHAIN_ENDPOINT": authorities["supply_chain"],
        "DOMAIN_RUNTIME_ENDPOINT": authorities["domain_packs"],
        "PLATFORM_SRE_ENDPOINT": authorities["sre"],
    }
    for service_name, service in validated_production_authorities.items():
        token_prefix = service_name.upper()
        replacements.update({
            f"{token_prefix}_CLIENT_IDENTITIES": ",".join(service["client_identities"]),
            f"{token_prefix}_OUTBOUND_CLIENT_IDENTITY": service["outbound_client_identity"],
            f"{token_prefix}_EVIDENCE_CLIENT_IDENTITY": service["evidence_client_identity"],
            f"{token_prefix}_INSTANCE_ID": service["instance_id"],
            f"{token_prefix}_ORGANIZATION_ID": service["organization_id"],
            f"{token_prefix}_AGENT_VERSION": service["agent_version"],
            f"{token_prefix}_REGION": service["region"],
            f"{token_prefix}_SERVICE_SUBJECT": service["service_subject"],
            f"{token_prefix}_DATA_PORT": str(service["data_port"]),
            f"{token_prefix}_MANAGEMENT_PORT": str(service["management_port"]),
            f"{token_prefix}_READINESS_SCHEMA": service["readiness_schema"],
            f"{token_prefix}_EXECUTION_LEASE_SECONDS": str(service["execution_lease_seconds"]),
            f"{token_prefix}_RECOVERY_INTERVAL_SECONDS": str(service["recovery_interval_seconds"]),
            f"{token_prefix}_SIGNING_KEY_ID": service["signing_key_id"],
            f"{token_prefix}_MAX_AUTH_AGE_SECONDS": str(
                service["maximum_authentication_age_seconds"]
            ),
        })
        for dependency_name, endpoint in service["dependencies"].items():
            dependency_token = dependency_name.upper()
            replacements[f"{token_prefix}_{dependency_token}_ENDPOINT"] = endpoint
            readiness_schema = (
                DEPENDENCY_READINESS_SCHEMAS.get(dependency_name)
                if dependency_name in PRODUCTION_AUTHORITY_READINESS_DEPENDENCIES.get(
                    service_name, set()
                ) else None
            )
            if readiness_schema is not None:
                replacements[f"{token_prefix}_{dependency_token}_READINESS_SCHEMA"] = (
                    readiness_schema
                )
    for key, value in images.items():
        replacements[f"{key.upper()}_IMAGE"] = value
    for key, token_name in AUTHORITY_READINESS_TOKENS.items():
        replacements[f"ENTERPRISE_{token_name}_READINESS_SCHEMA"] = (
            authority_readiness_schemas[key]
        )
    for key in VAULT_KEYS - {"address"}:
        replacements[f"VAULT_{key.upper()}"] = vault[key]
    for key, endpoint in facts.items():
        replacements[f"{key.upper()}_FACT_ENDPOINT"] = endpoint

    expected_tokens = {f"@@{key}@@" for key in replacements}
    present_tokens = set(TOKEN.findall(template))
    if present_tokens != expected_tokens:
        missing = sorted(expected_tokens - present_tokens)
        unexpected = sorted(present_tokens - expected_tokens)
        raise RenderError(f"PRODUCTION_STACK_TEMPLATE_TOKEN_MISMATCH:{missing}:{unexpected}")
    result = template
    for key, value in replacements.items():
        result = result.replace(f"@@{key}@@", str(value))
    if TOKEN.search(result):
        raise RenderError("PRODUCTION_STACK_TEMPLATE_UNRESOLVED")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="render-production-stack")
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--runtime-config", type=Path, required=True)
    parser.add_argument("--git-provenance", type=Path, required=True)
    parser.add_argument("--git-provenance-keyring", type=Path, required=True)
    parser.add_argument("--release-binding", type=Path, required=True)
    parser.add_argument("--release-binding-keyring", type=Path, required=True)
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--closure-report", type=Path, required=True)
    parser.add_argument("--production-certificate", type=Path, required=True)
    parser.add_argument("--closure-public-key", type=Path, required=True)
    parser.add_argument("--revocation-registry", type=Path, required=True)
    parser.add_argument("--revocation-public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    input_paths = (
        args.template, args.values, args.runtime_config, args.git_provenance,
        args.git_provenance_keyring, args.release_binding,
        args.release_binding_keyring, args.activation, args.closure_report,
        args.production_certificate, args.closure_public_key,
        args.revocation_registry, args.revocation_public_key,
    )
    if (
        any(
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or not 1 <= path.stat().st_size <= 128 * 1024 * 1024
            for path in input_paths
        )
        or args.template.stat().st_size > 8 * 1024 * 1024
        or not args.output.is_absolute()
        or args.output.exists()
        or not args.output.parent.is_dir()
    ):
        raise RenderError("PRODUCTION_STACK_PATH_INVALID")
    try:
        values = json.loads(args.values.read_text(encoding="utf-8"))
        runtime_config = json.loads(args.runtime_config.read_text(encoding="utf-8"))
        git_provenance = json.loads(args.git_provenance.read_text(encoding="utf-8"))
        git_provenance_keyring = json.loads(
            args.git_provenance_keyring.read_text(encoding="utf-8")
        )
        release_binding = json.loads(args.release_binding.read_text(encoding="utf-8"))
        release_binding_keyring = json.loads(
            args.release_binding_keyring.read_text(encoding="utf-8")
        )
        activation = json.loads(args.activation.read_text(encoding="utf-8"))
        closure_report = json.loads(args.closure_report.read_text(encoding="utf-8"))
        production_certificate = json.loads(
            args.production_certificate.read_text(encoding="utf-8")
        )
        closure_public_key = json.loads(args.closure_public_key.read_text(encoding="utf-8"))
        revocation_registry = json.loads(args.revocation_registry.read_text(encoding="utf-8"))
        revocation_public_key = json.loads(
            args.revocation_public_key.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise RenderError("PRODUCTION_STACK_INPUT_JSON_INVALID") from error
    if not isinstance(values, dict):
        raise RenderError("PRODUCTION_STACK_VALUES_INVALID")
    try:
        activation_receipt = verify_activation_documents(
            activation=activation,
            report=closure_report,
            certificate=production_certificate,
            certificate_key=closure_public_key,
            revocation_registry=revocation_registry,
            revocation_key=revocation_public_key,
        )
    except ActivationError as error:
        raise RenderError("PRODUCTION_STACK_ACTIVATION_INVALID") from error
    if (
        not isinstance(activation, dict)
        or activation.get("release_id") != values.get("release_id")
        or activation.get("images") != values.get("images")
        or not isinstance(values.get("evidence"), dict)
        or activation.get("evidence_bundle_manifest_digest")
        != values["evidence"].get("bundle_digest")
        or not isinstance(activation.get("production_image_manifest"), dict)
        or activation["production_image_manifest"].get("manifest_digest")
        != activation_receipt.get("production_image_manifest_digest")
        or activation_receipt.get("evidence_bundle_manifest_digest")
        != values["evidence"].get("bundle_digest")
        or activation.get("signed_release_binding_digest")
        != signed_release_binding_digest(release_binding)
        or activation_receipt.get("admitted") is not True
    ):
        raise RenderError("PRODUCTION_STACK_ACTIVATION_BINDING_MISMATCH")
    rendered = render(
        args.template.read_text(encoding="utf-8"),
        values,
        runtime_config,
        git_provenance=git_provenance,
        git_provenance_keyring=git_provenance_keyring,
        release_binding=release_binding,
        release_binding_keyring=release_binding_keyring,
        activation_receipt=activation_receipt,
    )
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
