"""Fail-closed real-protocol probes for deployment-owned external services.

The probes in this module intentionally return non-production baseline evidence.
Batch 36 may consume them only together with a separately signed, scope-bound
real-environment attestation. Credentials and provider payloads are never
included in reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

from python.production_gates.live_integrations import (
    BoundedHttpClient,
    ConfigurationMissing,
    GateError,
    GateResult,
    HttpTransport,
    is_non_public_host,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ENV = re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
_SAFE_VAULT_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,510}$")
_SAFE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_SENSITIVE_MARKERS = (
    "authorization: bearer",
    "api_key=",
    "password=",
    "-----begin private key-----",
)


def _secret(name: str) -> str:
    if not _SAFE_ENV.fullmatch(name):
        raise GateError("EXTERNAL_SECRET_REFERENCE_INVALID")
    value = os.environ.get(name, "")
    if not value:
        raise ConfigurationMissing("EXTERNAL_SECRET_NOT_CONFIGURED")
    if len(value) > 16_384 or any(ord(character) < 32 for character in value):
        raise GateError("EXTERNAL_SECRET_INVALID")
    return value


def _strict_object(payload: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(code) from None
    if not isinstance(value, dict):
        raise GateError(code)
    return value


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    return next((value for key, value in headers.items() if key.lower() == lowered), None)


@dataclass(frozen=True)
class TlsPeerSnapshot:
    tls_version: str
    cipher: str
    peer_certificate_sha256: str
    peer_subject_alt_names: int


class TlsTransport(Protocol):
    def connect(
        self,
        host: str,
        port: int,
        ca_file: Path,
        client_certificate: Path,
        client_private_key: Path,
        timeout_seconds: int,
    ) -> TlsPeerSnapshot: ...


class SocketTlsTransport:
    def connect(
        self,
        host: str,
        port: int,
        ca_file: Path,
        client_certificate: Path,
        client_private_key: Path,
        timeout_seconds: int,
    ) -> TlsPeerSnapshot:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cafile=str(ca_file))
        context.load_cert_chain(certfile=str(client_certificate), keyfile=str(client_private_key))
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as raw:
                with context.wrap_socket(raw, server_hostname=host) as connection:
                    certificate = connection.getpeercert(binary_form=True)
                    decoded = connection.getpeercert()
                    cipher = connection.cipher()
                    version = connection.version()
        except (OSError, ssl.SSLError):
            raise GateError("MTLS_HANDSHAKE_FAILED") from None
        if not certificate or not version or not cipher:
            raise GateError("MTLS_PEER_INVALID")
        sans = decoded.get("subjectAltName", ()) if isinstance(decoded, dict) else ()
        return TlsPeerSnapshot(
            tls_version=version,
            cipher=cipher[0],
            peer_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
            peer_subject_alt_names=len(sans),
        )


def _private_file(path: Path, code: str) -> None:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ConfigurationMissing(code)
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise GateError("MTLS_PRIVATE_KEY_PERMISSIONS_TOO_OPEN")


def probe_mtls(
    host: str,
    port: int,
    ca_file: Path,
    client_certificate: Path,
    client_private_key: Path,
    *,
    transport: TlsTransport | None = None,
) -> GateResult:
    if (
        not host
        or is_non_public_host(host)
        or not 1 <= port <= 65535
    ):
        raise GateError("MTLS_CONFIGURATION_INVALID")
    for path, code in (
        (ca_file, "MTLS_CA_NOT_CONFIGURED"),
        (client_certificate, "MTLS_CLIENT_CERTIFICATE_NOT_CONFIGURED"),
    ):
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            raise ConfigurationMissing(code)
    _private_file(client_private_key, "MTLS_CLIENT_PRIVATE_KEY_NOT_CONFIGURED")
    snapshot = (transport or SocketTlsTransport()).connect(
        host, port, ca_file, client_certificate, client_private_key, 15
    )
    if snapshot.tls_version not in {"TLSv1.2", "TLSv1.3"} or not _SHA256.fullmatch(
        snapshot.peer_certificate_sha256
    ):
        raise GateError("MTLS_PEER_INVALID")
    return GateResult(
        gate="WORKLOAD_MTLS_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"mtls://{host}:{port}",
        checks={
            "mutual_tls_handshake": True,
            "minimum_tls_1_2": True,
            "hostname_verified": True,
            "ca_bundle_digest": hashlib.sha256(ca_file.read_bytes()).hexdigest(),
            "client_certificate_digest": hashlib.sha256(
                client_certificate.read_bytes()
            ).hexdigest(),
            "peer_certificate_digest": snapshot.peer_certificate_sha256,
            "peer_subject_alt_name_count": snapshot.peer_subject_alt_names,
            "cipher_digest": hashlib.sha256(snapshot.cipher.encode()).hexdigest(),
            "private_key_redacted": True,
        },
    )


def probe_vault_secret_broker(
    endpoint: str,
    token_environment: str,
    *,
    dynamic_lease_path: str | None = None,
    maximum_lease_seconds: int = 900,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or not 1 <= maximum_lease_seconds <= 3600
        or dynamic_lease_path is not None
        and not _SAFE_VAULT_PATH.fullmatch(dynamic_lease_path)
    ):
        raise GateError("SECRET_BROKER_CONFIGURATION_INVALID")
    token = _secret(token_environment)
    client = transport or BoundedHttpClient()
    headers = {"X-Vault-Token": token, "Accept": "application/json"}
    status, _, payload = client.request(
        "GET", endpoint.rstrip("/") + "/v1/sys/health", headers=headers
    )
    health = _strict_object(payload, "SECRET_BROKER_HEALTH_INVALID")
    if status not in {200, 429} or not health.get("initialized") or health.get("sealed") is not False:
        raise GateError("SECRET_BROKER_NOT_READY")
    status, _, payload = client.request(
        "GET", endpoint.rstrip("/") + "/v1/auth/token/lookup-self", headers=headers
    )
    lookup = _strict_object(payload, "SECRET_BROKER_TOKEN_INVALID")
    data = lookup.get("data")
    ttl = data.get("ttl") if isinstance(data, dict) else None
    policies = data.get("policies") if isinstance(data, dict) else None
    if (
        status != 200
        or not isinstance(ttl, int)
        or not 0 < ttl <= maximum_lease_seconds
        or not isinstance(policies, list)
        or not policies
        or len(policies) > 64
    ):
        raise GateError("SECRET_BROKER_TOKEN_INVALID")
    lease_issued = False
    lease_revoked = False
    lease_duration = 0
    if dynamic_lease_path is not None:
        status, _, payload = client.request(
            "POST",
            endpoint.rstrip("/") + "/v1/" + dynamic_lease_path,
            headers={**headers, "Content-Type": "application/json"},
            body=b"{}",
            maximum_bytes=1_048_576,
        )
        lease = _strict_object(payload, "SECRET_BROKER_LEASE_INVALID")
        lease_id = lease.get("lease_id")
        lease_duration = lease.get("lease_duration")
        lease_data = lease.get("data")
        if (
            status != 200
            or not isinstance(lease_id, str)
            or not lease_id
            or len(lease_id) > 1024
            or not isinstance(lease_duration, int)
            or not 0 < lease_duration <= maximum_lease_seconds
            or not isinstance(lease_data, dict)
            or not lease_data
        ):
            raise GateError("SECRET_BROKER_LEASE_INVALID")
        lease_issued = True
        status, _, _ = client.request(
            "POST",
            endpoint.rstrip("/") + "/v1/sys/leases/revoke",
            headers={**headers, "Content-Type": "application/json"},
            body=json.dumps({"lease_id": lease_id}, separators=(",", ":")).encode(),
            maximum_bytes=65_536,
        )
        if status not in {200, 204}:
            raise GateError("SECRET_BROKER_LEASE_REVOKE_FAILED")
        lease_revoked = True
    return GateResult(
        gate="SECRET_BROKER_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"vault://{parsed.hostname}",
        checks={
            "initialized": True,
            "unsealed": True,
            "authenticated_lookup": True,
            "token_ttl_within_limit": True,
            "policy_count": len(policies),
            "dynamic_lease_requested": dynamic_lease_path is not None,
            "dynamic_lease_issued": lease_issued,
            "dynamic_lease_revoked": lease_revoked,
            "dynamic_lease_duration_seconds": lease_duration,
            "credentials_redacted": True,
        },
    )


def _model_output(document: Mapping[str, Any]) -> tuple[str, int, int, str]:
    choices = document.get("choices")
    usage = document.get("usage")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise GateError("MODEL_GENERATION_RESPONSE_INVALID")
    message = choices[0].get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content or len(content.encode()) > 65_536:
        raise GateError("MODEL_GENERATION_RESPONSE_INVALID")
    if not isinstance(usage, dict):
        raise GateError("MODEL_USAGE_MISSING")
    input_tokens = usage.get("prompt_tokens")
    output_tokens = usage.get("completion_tokens")
    request_id = document.get("id")
    if (
        not isinstance(input_tokens, int)
        or input_tokens <= 0
        or not isinstance(output_tokens, int)
        or output_tokens <= 0
        or not isinstance(request_id, str)
        or not request_id
    ):
        raise GateError("MODEL_USAGE_MISSING")
    return content, input_tokens, output_tokens, request_id


def _parse_sse(payload: bytes) -> tuple[bytes, int, int, int]:
    output = bytearray()
    chunks = 0
    input_tokens = 0
    output_tokens = 0
    saw_done = False
    for raw_line in payload.splitlines():
        if not raw_line.startswith(b"data:"):
            continue
        raw = raw_line[5:].strip()
        if raw == b"[DONE]":
            saw_done = True
            continue
        document = _strict_object(raw, "MODEL_STREAM_INVALID")
        chunks += 1
        usage = document.get("usage")
        if isinstance(usage, dict):
            input_tokens = usage.get("prompt_tokens", input_tokens)
            output_tokens = usage.get("completion_tokens", output_tokens)
        choices = document.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            delta = choices[0].get("delta")
            content = delta.get("content") if isinstance(delta, dict) else None
            if isinstance(content, str):
                output.extend(content.encode())
        if len(output) > 65_536 or chunks > 10_000:
            raise GateError("MODEL_STREAM_TOO_LARGE")
    if not saw_done or chunks == 0 or not output or input_tokens <= 0 or output_tokens <= 0:
        raise GateError("MODEL_STREAM_INVALID")
    return bytes(output), chunks, input_tokens, output_tokens


def probe_model_generation_stream(
    completions_url: str,
    api_key_environment: str,
    model: str,
    declared_region: str,
    *,
    residency_attestation_digest: str | None = None,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(completions_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not _SAFE_MODEL.fullmatch(model)
        or not declared_region
        or len(declared_region) > 128
        or residency_attestation_digest is not None
        and not _SHA256.fullmatch(residency_attestation_digest)
    ):
        raise GateError("MODEL_GENERATION_CONFIGURATION_INVALID")
    key = _secret(api_key_environment)
    client = transport or BoundedHttpClient(timeout_seconds=30)
    prompt = "Reply exactly with AGENTTRUST_OK. This is a non-sensitive protocol probe."
    if any(marker in prompt.lower() for marker in _SENSITIVE_MARKERS):
        raise GateError("MODEL_DLP_PREFLIGHT_FAILED")
    common = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    non_stream_body = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": prompt}],
         "max_tokens": 16, "temperature": 0, "stream": False},
        separators=(",", ":"),
    ).encode()
    status, _, payload = client.request(
        "POST", completions_url, headers=common, body=non_stream_body, maximum_bytes=1_048_576
    )
    if status != 200:
        raise GateError("MODEL_GENERATION_FAILED")
    document = _strict_object(payload, "MODEL_GENERATION_RESPONSE_INVALID")
    output, input_tokens, output_tokens, request_id = _model_output(document)
    stream_body = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": prompt}],
         "max_tokens": 16, "temperature": 0, "stream": True,
         "stream_options": {"include_usage": True}},
        separators=(",", ":"),
    ).encode()
    status, headers, payload = client.request(
        "POST", completions_url, headers=common, body=stream_body, maximum_bytes=2_097_152
    )
    content_type = _header(headers, "content-type") or ""
    if status != 200 or "text/event-stream" not in content_type.lower():
        raise GateError("MODEL_STREAM_INVALID")
    stream_output, chunks, stream_input_tokens, stream_output_tokens = _parse_sse(payload)
    rendered = (output.encode() + stream_output).decode("utf-8", errors="replace").lower()
    if any(marker in rendered for marker in _SENSITIVE_MARKERS):
        raise GateError("MODEL_DLP_RESPONSE_FAILED")
    return GateResult(
        gate="MODEL_GENERATION_STREAM_USAGE_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"model-provider://{parsed.hostname}/{declared_region}",
        checks={
            "generation_completed": True,
            "stream_completed": True,
            "stream_chunk_count": chunks,
            "usage_metered": True,
            "total_input_tokens": input_tokens + stream_input_tokens,
            "total_output_tokens": output_tokens + stream_output_tokens,
            "request_id_digest": hashlib.sha256(request_id.encode()).hexdigest(),
            "generation_output_digest": hashlib.sha256(output.encode()).hexdigest(),
            "stream_output_digest": hashlib.sha256(stream_output).hexdigest(),
            "dlp_preflight": True,
            "dlp_response_scan": True,
            "declared_region": declared_region,
            "data_residency_attested": residency_attestation_digest is not None,
            "residency_attestation_digest": residency_attestation_digest or "NOT_PROVIDED",
            "invoice_reconciliation": False,
            "credentials_and_payloads_redacted": True,
        },
    )


def probe_mcp_http(
    endpoint: str,
    *,
    bearer_environment: str | None = None,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
        raise GateError("MCP_CONFIGURATION_INVALID")
    client = transport or BoundedHttpClient()
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if bearer_environment is not None:
        headers["Authorization"] = f"Bearer {_secret(bearer_environment)}"
    initialize = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "agenttrust-production-gate", "version": "1"}}},
        separators=(",", ":"),
    ).encode()
    status, response_headers, payload = client.request(
        "POST", endpoint, headers=headers, body=initialize, maximum_bytes=1_048_576
    )
    document = _strict_object(payload, "MCP_INITIALIZE_INVALID")
    result = document.get("result")
    if status != 200 or document.get("id") != 1 or not isinstance(result, dict):
        raise GateError("MCP_INITIALIZE_INVALID")
    protocol = result.get("protocolVersion")
    server_info = result.get("serverInfo")
    if not isinstance(protocol, str) or not isinstance(server_info, dict):
        raise GateError("MCP_INITIALIZE_INVALID")
    session = _header(response_headers, "mcp-session-id")
    list_headers = dict(headers)
    if session:
        if len(session) > 512 or any(ord(character) < 32 for character in session):
            raise GateError("MCP_SESSION_INVALID")
        list_headers["Mcp-Session-Id"] = session
    status, _, payload = client.request(
        "POST", endpoint, headers=list_headers,
        body=b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
        maximum_bytes=4_194_304,
    )
    document = _strict_object(payload, "MCP_TOOLS_INVALID")
    result = document.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if status != 200 or document.get("id") != 2 or not isinstance(tools, list) or len(tools) > 4096:
        raise GateError("MCP_TOOLS_INVALID")
    normalized: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise GateError("MCP_TOOLS_INVALID")
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise GateError("MCP_TOOLS_INVALID")
        normalized.append({"name": tool["name"], "inputSchema": schema})
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return GateResult(
        gate="MCP_HTTP_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"mcp://{parsed.hostname}",
        checks={
            "initialized": True,
            "protocol_version": protocol,
            "server_info_present": True,
            "session_negotiated": session is not None,
            "tool_count": len(tools),
            "tool_schema_digest": digest,
            "tool_call_not_executed": True,
            "credentials_redacted": True,
        },
    )


def probe_a2a_agent_card(
    card_url: str,
    *,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(card_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GateError("A2A_CONFIGURATION_INVALID")
    status, _, payload = (transport or BoundedHttpClient()).request(
        "GET", card_url, headers={"Accept": "application/json"}, maximum_bytes=1_048_576
    )
    card = _strict_object(payload, "A2A_AGENT_CARD_INVALID")
    endpoint = card.get("url")
    endpoint_parsed = urlparse(endpoint or "")
    skills = card.get("skills")
    capabilities = card.get("capabilities")
    if (
        status != 200
        or not isinstance(card.get("name"), str)
        or endpoint_parsed.scheme != "https"
        or endpoint_parsed.hostname != parsed.hostname
        or endpoint_parsed.port != parsed.port
        or endpoint_parsed.username is not None
        or endpoint_parsed.password is not None
        or endpoint_parsed.query
        or endpoint_parsed.fragment
        or not isinstance(skills, list)
        or len(skills) > 1024
        or not isinstance(capabilities, dict)
    ):
        raise GateError("A2A_AGENT_CARD_INVALID")
    skill_ids: set[str] = set()
    for skill in skills:
        skill_id = skill.get("id") if isinstance(skill, dict) else None
        if not isinstance(skill_id, str) or not skill_id or skill_id in skill_ids:
            raise GateError("A2A_AGENT_CARD_INVALID")
        skill_ids.add(skill_id)
    return GateResult(
        gate="A2A_AGENT_CARD_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"a2a://{parsed.hostname}",
        checks={
            "agent_card_received": True,
            "same_origin_task_endpoint": True,
            "skill_count": len(skills),
            "streaming_declared": capabilities.get("streaming") is True,
            "push_notifications_declared": capabilities.get("pushNotifications") is True,
            "card_digest": hashlib.sha256(payload).hexdigest(),
            "task_submission_not_executed": True,
        },
    )
