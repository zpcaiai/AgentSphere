#!/usr/bin/env python3
"""Render the complete production stack from non-secret, fail-closed inputs."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}$"
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"@@[A-Z0-9_]+@@")
NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DATABASE_ROLE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
VAULT_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@?=&:+-]{0,511}$")
STORAGE = re.compile(r"^[1-9][0-9]*(?:Mi|Gi|Ti)$")
SPIFFE_PATH = re.compile(r"^(?:/[A-Za-z0-9._~!$&()*+;=:@%-]+)*$")

IMAGE_KEYS = {
    "runtime", "orchestrator", "transition", "execution", "enterprise", "console",
    "migration", "envoy", "utility",
}
VAULT_KEYS = {
    "address", "runtime_role", "runtime_path", "orchestrator_role",
    "orchestrator_path", "transition_role", "transition_path", "enterprise_role",
    "enterprise_path", "execution_role", "execution_path", "migration_role", "migration_path",
}
FACT_KEYS = {"policy", "approval", "credential", "ledger", "evaluator", "evidence", "supervisor"}
AUTHORITY_KEYS = {
    "agents", "approvals", "evidence", "incidents", "policies",
    "tools", "credentials", "packs", "trace", "compliance", "audit", "sre",
    "deployments",
}
RUNTIME_ENDPOINT_TOKENS = {
    "orchestrator": "orchestrator.token",
    "secret_broker": "secret-broker.token",
    "backup": "backup.token",
    "policy_distribution": "policy.token",
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


def validate_runtime_config(value: object) -> Mapping[str, Any]:
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
    endpoints = value.get("endpoints")
    evidence = value.get("evidence_files")
    model_versions = value.get("model_versions")
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


def render(template: str, values: Mapping[str, Any], runtime_config: object) -> str:
    top_keys = {
        "schema_version", "release_id", "release_digest", "images", "database", "temporal",
        "execution", "transition", "vault", "network", "evidence", "ingress",
        "transition_facts", "enterprise",
    }
    if set(values) != top_keys or values.get("schema_version") != "agenttrust.production-stack-values.v1":
        raise RenderError("PRODUCTION_STACK_VALUES_INVALID")
    release_id = require_text(values["release_id"], "PRODUCTION_STACK_RELEASE_ID_INVALID", IDENTIFIER)
    if release_id == "WORKTREE-NO-GIT":
        raise RenderError("PRODUCTION_STACK_RELEASE_ID_INVALID")
    release_digest = require_text(values["release_digest"], "PRODUCTION_STACK_RELEASE_DIGEST_INVALID", DIGEST)

    images = require_mapping(values["images"], "images", IMAGE_KEYS)
    if any(not isinstance(image, str) or not IMAGE.fullmatch(image) for image in images.values()):
        raise RenderError("PRODUCTION_STACK_IMAGE_NOT_IMMUTABLE")

    database = require_mapping(
        values["database"], "database",
        {
            "enterprise_application_role", "orchestrator_application_role",
            "execution_application_role",
        },
    )
    for key, role in database.items():
        require_text(role, f"PRODUCTION_STACK_{key.upper()}_INVALID", DATABASE_ROLE)
    if len(set(database.values())) != 3:
        raise RenderError("PRODUCTION_STACK_APPLICATION_ROLES_NOT_DISTINCT")

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
            "client_identities", "approval_endpoint", "approval_readiness_schema",
            "pep_endpoint", "pep_readiness_schema",
            "tool_endpoint", "tool_readiness_schema", "evidence_endpoint",
            "evidence_readiness_schema",
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
    execution_endpoints: dict[str, str] = {}
    execution_ports: dict[str, int] = {}
    for dependency in ("approval", "pep", "tool", "evidence"):
        endpoint = require_https(
            execution[f"{dependency}_endpoint"],
            f"PRODUCTION_STACK_EXECUTION_{dependency.upper()}_ENDPOINT_INVALID",
            allowed_ports={443, 8443},
        )
        if urlparse(endpoint).path not in {"", "/"}:
            raise RenderError(
                f"PRODUCTION_STACK_EXECUTION_{dependency.upper()}_ENDPOINT_INVALID"
            )
        execution_endpoints[dependency] = endpoint.rstrip("/") + "/"
        execution_ports[dependency] = urlparse(endpoint).port or 443
    execution_readiness_schemas = {
        dependency: require_text(
            execution[f"{dependency}_readiness_schema"],
            f"PRODUCTION_STACK_EXECUTION_{dependency.upper()}_READINESS_SCHEMA_INVALID",
            IDENTIFIER,
        )
        for dependency in ("approval", "pep", "tool", "evidence")
    }

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

    vault = require_mapping(values["vault"], "vault", VAULT_KEYS)
    require_https(vault["address"], "PRODUCTION_STACK_VAULT_ADDRESS_INVALID")
    for key in VAULT_KEYS - {"address"}:
        require_text(vault[key], f"PRODUCTION_STACK_VAULT_{key.upper()}_INVALID", VAULT_VALUE)

    network = require_mapping(
        values["network"], "network",
        {
            "node_cidr", "database_cidr", "temporal_cidr", "trusted_service_cidr",
            "execution_approval_cidr", "execution_pep_cidr", "execution_tool_cidr",
            "execution_evidence_cidr", "dns_cidr",
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
            "iam_userinfo_endpoint", "pep_endpoint",
            "orchestrator_runtime_client_identities",
            "orchestrator_bff_client_identities", "authority_endpoints",
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
    require_https(
        enterprise["pep_endpoint"], "PRODUCTION_STACK_PEP_ENDPOINT_INVALID",
        allowed_ports={443, 8443},
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
    authorities = require_mapping(enterprise["authority_endpoints"], "authority_endpoints", AUTHORITY_KEYS)
    for key, endpoint in authorities.items():
        require_https(
            endpoint,
            f"PRODUCTION_STACK_{key.upper()}_AUTHORITY_ENDPOINT_INVALID",
            allowed_ports={443, 8443},
        )

    runtime = validate_runtime_config(runtime_config)
    release_name_base = re.sub(r"[^a-z0-9-]+", "-", release_id.lower()).strip("-")[:40]
    if not release_name_base:
        raise RenderError("PRODUCTION_STACK_RELEASE_ID_INVALID")
    release_name = f"{release_name_base}-{release_digest[:8]}"
    runtime_text = json.dumps(runtime, indent=2, sort_keys=True, ensure_ascii=True)
    runtime_indented = "\n".join("    " + line for line in runtime_text.splitlines())

    replacements = {
        "RELEASE_ID": release_id, "RELEASE_NAME": release_name,
        "RELEASE_DIGEST": release_digest,
        "RUNTIME_CONFIG": runtime_indented,
        "EVIDENCE_BUNDLE_DIGEST": evidence["bundle_digest"],
        "EVIDENCE_PV_NAME": evidence["persistent_volume_name"],
        "EVIDENCE_STORAGE_SIZE": evidence["storage_size"],
        "TEMPORAL_ADDRESS": temporal_address, "TEMPORAL_NAMESPACE": temporal["namespace"],
        "TEMPORAL_TASK_QUEUE": temporal["task_queue"],
        "TEMPORAL_SERVER_NAME": temporal["server_name"],
        "EXECUTION_ENDPOINT": "https://agenttrust-execution/v1/executions/execute",
        "EXECUTION_CLIENT_IDENTITIES": ",".join(execution_client_identities),
        "EXECUTION_APPROVAL_ENDPOINT": execution_endpoints["approval"],
        "EXECUTION_PEP_ENDPOINT": execution_endpoints["pep"],
        "EXECUTION_TOOL_ENDPOINT": execution_endpoints["tool"],
        "EXECUTION_EVIDENCE_ENDPOINT": execution_endpoints["evidence"],
        "EXECUTION_APPROVAL_READINESS_SCHEMA": execution_readiness_schemas["approval"],
        "EXECUTION_PEP_READINESS_SCHEMA": execution_readiness_schemas["pep"],
        "EXECUTION_TOOL_READINESS_SCHEMA": execution_readiness_schemas["tool"],
        "EXECUTION_EVIDENCE_READINESS_SCHEMA": execution_readiness_schemas["evidence"],
        "EXECUTION_APPROVAL_PORT": str(execution_ports["approval"]),
        "EXECUTION_PEP_PORT": str(execution_ports["pep"]),
        "EXECUTION_TOOL_PORT": str(execution_ports["tool"]),
        "EXECUTION_EVIDENCE_PORT": str(execution_ports["evidence"]),
        "TRANSITION_CLIENT_IDENTITIES": ",".join(transition_client_identities),
        "ENTERPRISE_APPLICATION_ROLE": database["enterprise_application_role"],
        "ORCHESTRATOR_APPLICATION_ROLE": database["orchestrator_application_role"],
        "EXECUTION_APPLICATION_ROLE": database["execution_application_role"],
        "VAULT_ADDRESS": vault["address"],
        "NODE_CIDR": network["node_cidr"], "DATABASE_CIDR": network["database_cidr"],
        "TEMPORAL_CIDR": network["temporal_cidr"],
        "TRUSTED_SERVICE_CIDR": network["trusted_service_cidr"],
        "EXECUTION_APPROVAL_CIDR": network["execution_approval_cidr"],
        "EXECUTION_PEP_CIDR": network["execution_pep_cidr"],
        "EXECUTION_TOOL_CIDR": network["execution_tool_cidr"],
        "EXECUTION_EVIDENCE_CIDR": network["execution_evidence_cidr"],
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
        "PEP_ENDPOINT": enterprise["pep_endpoint"],
        "ORCHESTRATOR_RUNTIME_CLIENT_IDENTITIES": ",".join(runtime_client_identities),
        "ORCHESTRATOR_BFF_CLIENT_IDENTITIES": ",".join(bff_client_identities),
        "AGENT_REGISTRY_ENDPOINT": authorities["agents"],
        "APPROVAL_AUTHORITY_ENDPOINT": authorities["approvals"],
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
    }
    for key, value in images.items():
        replacements[f"{key.upper()}_IMAGE"] = value
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if (
        not args.template.is_file() or not args.values.is_file() or not args.runtime_config.is_file()
        or not args.output.is_absolute() or args.output.exists()
    ):
        raise RenderError("PRODUCTION_STACK_PATH_INVALID")
    try:
        values = json.loads(args.values.read_text(encoding="utf-8"))
        runtime_config = json.loads(args.runtime_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RenderError("PRODUCTION_STACK_INPUT_JSON_INVALID") from error
    if not isinstance(values, dict):
        raise RenderError("PRODUCTION_STACK_VALUES_INVALID")
    rendered = render(args.template.read_text(encoding="utf-8"), values, runtime_config)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
