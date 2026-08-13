"""Bounded probes for external production integrations.

The probes exercise real wire protocols, never print credentials or provider
payloads, and intentionally do not turn a protocol smoke test into production
acceptance evidence. Production certification still requires a scope-bound
independent or real-environment attestation consumed by Batch 36.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
from typing import Any, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


_SAFE_ENV = re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_TEMPORAL_ADDRESS = re.compile(r"^[A-Za-z0-9.-]+:[0-9]{1,5}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# `python -m` executes this file as `__main__`. Extended probes import the
# canonical module path, so register the active module to keep exception and
# report types identical and preserve fail-closed CLI error reporting.
if __name__ == "__main__":
    sys.modules.setdefault("python.production_gates.live_integrations", sys.modules[__name__])


class GateError(RuntimeError):
    """Stable, non-secret gate failure."""


class ConfigurationMissing(GateError):
    """Required deployment-owned configuration is absent."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        del request, fp, code, msg, headers, newurl
        return None


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        maximum_bytes: int = 1_048_576,
        allow_http_local: bool = False,
    ) -> tuple[int, Mapping[str, str], bytes]: ...


class BoundedHttpClient:
    def __init__(self, timeout_seconds: int = 15) -> None:
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("GATE_HTTP_TIMEOUT_INVALID")
        self._timeout = timeout_seconds
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = build_opener(_NoRedirect(), ProxyHandler(), HTTPSHandler(context=context))
        self._local_opener = build_opener(_NoRedirect(), ProxyHandler({}), HTTPSHandler(context=context))

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        maximum_bytes: int = 1_048_576,
        allow_http_local: bool = False,
    ) -> tuple[int, Mapping[str, str], bytes]:
        parsed = urlparse(url)
        local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if (
            parsed.username is not None
            or parsed.password is not None
            or not parsed.hostname
            or parsed.scheme not in {"http", "https"}
            or parsed.scheme == "http" and not (allow_http_local and local)
            or not 1 <= maximum_bytes <= 8 * 1024 * 1024
            or method not in {"GET", "HEAD", "PUT", "POST", "DELETE"}
        ):
            raise GateError("GATE_HTTP_TARGET_DENIED")
        request = Request(url, data=body, headers=dict(headers or {}), method=method)
        try:
            opener = self._local_opener if local else self._opener
            with opener.open(request, timeout=self._timeout) as response:
                payload = response.read(maximum_bytes + 1)
                if len(payload) > maximum_bytes:
                    raise GateError("GATE_HTTP_RESPONSE_TOO_LARGE")
                return response.status, dict(response.headers.items()), payload
        except GateError:
            raise
        except HTTPError as exc:
            # Status is safe and useful. Do not include URL, headers, or response body.
            raise GateError(f"GATE_HTTP_STATUS_{exc.code}") from None
        except (URLError, TimeoutError, OSError):
            raise GateError("GATE_HTTP_UNAVAILABLE") from None


@dataclass(frozen=True)
class GateResult:
    gate: str
    status: str
    environment_reference: str
    checks: Mapping[str, Any]
    production_evidence: bool = False

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "agenttrust.external-gate-report.v1",
            "gate": self.gate,
            "status": self.status,
            "environment_reference": self.environment_reference,
            "checks": dict(self.checks),
            "production_evidence": self.production_evidence,
            "measured_at": datetime.now(timezone.utc).isoformat(),
        }
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        result["evidence_digest"] = hashlib.sha256(canonical).hexdigest()
        return result


def _json(payload: bytes, code: str) -> Any:
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(code) from None


def _secret_from_environment(name: str) -> str:
    if not _SAFE_ENV.fullmatch(name):
        raise GateError("GATE_SECRET_REFERENCE_INVALID")
    value = os.environ.get(name, "")
    if not value:
        raise ConfigurationMissing("GATE_SECRET_NOT_CONFIGURED")
    if len(value) > 16_384 or any(ord(char) < 32 for char in value):
        raise GateError("GATE_SECRET_INVALID")
    return value


def probe_oidc(
    issuer: str,
    audience: str,
    *,
    transport: HttpTransport | None = None,
) -> GateResult:
    if not issuer or not audience:
        raise ConfigurationMissing("OIDC_CONFIGURATION_NOT_CONFIGURED")
    parsed = urlparse(issuer)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise GateError("OIDC_CONFIGURATION_INVALID")
    client = transport or BoundedHttpClient()
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    status, _, payload = client.request("GET", discovery_url)
    document = _json(payload, "OIDC_DISCOVERY_INVALID")
    jwks_uri = document.get("jwks_uri") if isinstance(document, dict) else None
    jwks_parsed = urlparse(jwks_uri or "")
    if (
        status != 200
        or document.get("issuer") != issuer
        or jwks_parsed.scheme != "https"
        or jwks_parsed.hostname != parsed.hostname
        or jwks_parsed.port != parsed.port
        or jwks_parsed.username is not None
        or jwks_parsed.password is not None
    ):
        raise GateError("OIDC_DISCOVERY_INVALID")
    jwks_status, _, jwks_payload = client.request("GET", jwks_uri)
    jwks = _json(jwks_payload, "OIDC_JWKS_INVALID")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if jwks_status != 200 or not isinstance(keys, list) or not keys or len(keys) > 100:
        raise GateError("OIDC_JWKS_INVALID")
    key_ids: set[str] = set()
    algorithms: set[str] = set()
    for key in keys:
        if not isinstance(key, dict):
            raise GateError("OIDC_JWKS_INVALID")
        kid, kty, alg, use = key.get("kid"), key.get("kty"), key.get("alg"), key.get("use", "sig")
        key_ops = key.get("key_ops", ["verify"])
        algorithm_matches_key = (
            (kty, alg) == ("RSA", "RS256")
            and isinstance(key.get("n"), str)
            and isinstance(key.get("e"), str)
            or (kty, alg) == ("EC", "ES256")
            and key.get("crv") == "P-256"
            and isinstance(key.get("x"), str)
            and isinstance(key.get("y"), str)
            or (kty, alg) == ("OKP", "EdDSA")
            and key.get("crv") == "Ed25519"
            and isinstance(key.get("x"), str)
        )
        if (
            not isinstance(kid, str)
            or not kid
            or kid in key_ids
            or use != "sig"
            or not isinstance(key_ops, list)
            or "verify" not in key_ops
            or not algorithm_matches_key
        ):
            raise GateError("OIDC_JWKS_INVALID")
        key_ids.add(kid)
        algorithms.add(alg)
    return GateResult(
        gate="ENTERPRISE_IAM_OIDC_PREFLIGHT",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"oidc://{parsed.hostname}",
        checks={
            "issuer_exact": True,
            "jwks_https_same_origin": True,
            "signing_key_count": len(keys),
            "algorithm_count": len(algorithms),
            "audience_configured": True,
            "jwks_digest": hashlib.sha256(jwks_payload).hexdigest(),
        },
    )


class CommandRunner(Protocol):
    def run(self, args: Sequence[str], timeout_seconds: int) -> bytes: ...


class SubprocessRunner:
    def run(self, args: Sequence[str], timeout_seconds: int) -> bytes:
        try:
            completed = subprocess.run(
                list(args),
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                env={"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"},
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise GateError("TEMPORAL_PROTOCOL_PROBE_FAILED") from None
        if len(completed.stdout) > 2_000_000 or len(completed.stderr) > 2_000_000:
            raise GateError("TEMPORAL_PROTOCOL_OUTPUT_TOO_LARGE")
        return completed.stdout


def probe_temporal(
    temporal_binary: Path,
    address: str,
    namespace: str,
    *,
    require_production_tls: bool = False,
    binary_sha256: str | None = None,
    ca_file: Path | None = None,
    client_certificate: Path | None = None,
    client_private_key: Path | None = None,
    tls_server_name: str | None = None,
    runner: CommandRunner | None = None,
) -> GateResult:
    if (
        not temporal_binary.is_absolute()
        or not temporal_binary.is_file()
        or not _TEMPORAL_ADDRESS.fullmatch(address)
        or not _SAFE_TOKEN.fullmatch(namespace)
    ):
        raise GateError("TEMPORAL_CONFIGURATION_INVALID")
    binary_digest = hashlib.sha256(temporal_binary.read_bytes()).hexdigest()
    tls_arguments: list[str] = []
    if require_production_tls:
        host, _, raw_port = address.rpartition(":")
        if (
            host in {"localhost", "127.0.0.1", "::1"}
            or not raw_port
            or binary_sha256 is None
            or not _SHA256.fullmatch(binary_sha256)
            or binary_digest != binary_sha256
            or ca_file is None
            or client_certificate is None
            or client_private_key is None
            or tls_server_name is None
            or not _SAFE_HOST.fullmatch(tls_server_name)
        ):
            raise GateError("TEMPORAL_PRODUCTION_TLS_CONFIGURATION_INVALID")
        for path, private in (
            (ca_file, False),
            (client_certificate, False),
            (client_private_key, True),
        ):
            if not path.is_absolute() or not path.is_file() or path.is_symlink():
                raise ConfigurationMissing("TEMPORAL_MTLS_MATERIAL_NOT_CONFIGURED")
            if private and os.name == "posix" and path.stat().st_mode & 0o077:
                raise GateError("TEMPORAL_PRIVATE_KEY_PERMISSIONS_TOO_OPEN")
        tls_arguments = [
            "--tls",
            "--tls-ca-path", str(ca_file),
            "--tls-cert-path", str(client_certificate),
            "--tls-key-path", str(client_private_key),
            "--tls-server-name", tls_server_name,
        ]
    command = runner or SubprocessRunner()
    base = [
        str(temporal_binary),
        "--disable-config-file",
        "--disable-config-env",
        "--identity", "agenttrust-production-gate-probe",
        "--address", address,
        "--namespace", namespace,
        *tls_arguments,
    ]
    namespace_payload = command.run([*base, "operator", "namespace", "describe", "--output", "json"], 30)
    namespace_document = _json(namespace_payload, "TEMPORAL_NAMESPACE_RESPONSE_INVALID")
    if not isinstance(namespace_document, dict):
        raise GateError("TEMPORAL_NAMESPACE_RESPONSE_INVALID")
    workflow_id = f"agenttrust-probe-{secrets.token_hex(12)}"
    started = False
    try:
        command.run(
            [
                *base,
                "workflow", "start",
                "--workflow-id", workflow_id,
                "--task-queue", "agenttrust-production-gate-probe",
                "--type", "AgentTrustProtocolProbe",
                "--execution-timeout", "1m",
                "--input", '{"schema_version":"agenttrust.temporal-probe.v1"}',
            ],
            30,
        )
        started = True
        describe = command.run(
            [*base, "workflow", "describe", "--workflow-id", workflow_id, "--output", "json"],
            30,
        )
        description = _json(describe, "TEMPORAL_WORKFLOW_RESPONSE_INVALID")
        if not isinstance(description, dict):
            raise GateError("TEMPORAL_WORKFLOW_RESPONSE_INVALID")
    finally:
        if started:
            command.run(
                [*base, "workflow", "terminate", "--workflow-id", workflow_id,
                 "--reason", "agenttrust protocol probe cleanup"],
                30,
            )
    return GateResult(
        gate="TEMPORAL_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"temporal://{address}/{namespace}",
        checks={
            "namespace_described": True,
            "workflow_started": True,
            "workflow_described": True,
            "workflow_terminated": True,
            "production_tls_required": require_production_tls,
            "mutual_tls_configured": bool(tls_arguments),
            "binary_digest": binary_digest,
            "binary_digest_verified": binary_sha256 is not None and binary_digest == binary_sha256,
        },
    )


def _signing_key(secret_key: str, date: str, region: str) -> bytes:
    def sign(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode(), hashlib.sha256).digest()
    return sign(sign(sign(sign(("AWS4" + secret_key).encode(), date), region), "s3"), "aws4_request")


def _s3_request(
    transport: HttpTransport,
    method: str,
    endpoint: str,
    bucket: str,
    key: str | None,
    body: bytes,
    access_key: str,
    secret_key: str,
    region: str,
    *,
    allow_http_local: bool,
) -> tuple[int, bytes]:
    parsed = urlparse(endpoint)
    path = "/" + quote(bucket, safe="")
    if key is not None:
        path += "/" + quote(key, safe="/-_.~")
    url = endpoint.rstrip("/") + path
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    host = parsed.netloc
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    canonical_request = "\n".join([
        method, path, "", canonical_headers, "host;x-amz-content-sha256;x-amz-date", payload_hash,
    ])
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    signature = hmac.new(_signing_key(secret_key, date, region), string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
    )
    status, _, payload = transport.request(
        method,
        url,
        headers={
            "Authorization": authorization,
            "Host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        },
        body=body if method in {"PUT", "POST"} else None,
        maximum_bytes=1_048_576,
        allow_http_local=allow_http_local,
    )
    return status, payload


def probe_s3(
    endpoint: str,
    region: str,
    access_key_environment: str,
    secret_key_environment: str,
    *,
    allow_http_local: bool = False,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(endpoint)
    if not parsed.hostname or not _SAFE_TOKEN.fullmatch(region):
        raise GateError("S3_CONFIGURATION_INVALID")
    access_key = _secret_from_environment(access_key_environment)
    secret_key = _secret_from_environment(secret_key_environment)
    client = transport or BoundedHttpClient()
    bucket = f"agenttrust-probe-{secrets.token_hex(10)}"
    key = f"objects/{secrets.token_hex(12)}.bin"
    value = secrets.token_bytes(128)
    created_bucket = False
    created_object = False
    try:
        status, _ = _s3_request(client, "PUT", endpoint, bucket, None, b"", access_key, secret_key,
                                region, allow_http_local=allow_http_local)
        if status not in {200, 204}:
            raise GateError("S3_BUCKET_CREATE_FAILED")
        created_bucket = True
        status, _ = _s3_request(client, "PUT", endpoint, bucket, key, value, access_key, secret_key,
                                region, allow_http_local=allow_http_local)
        if status not in {200, 201, 204}:
            raise GateError("S3_OBJECT_PUT_FAILED")
        created_object = True
        status, downloaded = _s3_request(client, "GET", endpoint, bucket, key, b"", access_key,
                                         secret_key, region, allow_http_local=allow_http_local)
        if status != 200 or not hmac.compare_digest(downloaded, value):
            raise GateError("S3_OBJECT_INTEGRITY_FAILED")
        status, _ = _s3_request(client, "HEAD", endpoint, bucket, key, b"", access_key, secret_key,
                                region, allow_http_local=allow_http_local)
        if status != 200:
            raise GateError("S3_OBJECT_HEAD_FAILED")
    finally:
        if created_object:
            _s3_request(client, "DELETE", endpoint, bucket, key, b"", access_key, secret_key,
                        region, allow_http_local=allow_http_local)
        if created_bucket:
            _s3_request(client, "DELETE", endpoint, bucket, None, b"", access_key, secret_key,
                        region, allow_http_local=allow_http_local)
    return GateResult(
        gate="OBJECT_STORE_S3_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"s3://{parsed.hostname}:{parsed.port or 443}",
        checks={
            "bucket_lifecycle": True,
            "object_put_get_head_delete": True,
            "payload_integrity": True,
            "payload_digest": hashlib.sha256(value).hexdigest(),
            "credentials_redacted": True,
        },
    )


def probe_model_provider(
    models_url: str,
    api_key_environment: str,
    *,
    expected_model: str | None = None,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(models_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise GateError("MODEL_PROVIDER_CONFIGURATION_INVALID")
    key = _secret_from_environment(api_key_environment)
    client = transport or BoundedHttpClient()
    status, _, payload = client.request(
        "GET",
        models_url,
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
        maximum_bytes=4 * 1024 * 1024,
    )
    document = _json(payload, "MODEL_PROVIDER_RESPONSE_INVALID")
    data = document.get("data") if isinstance(document, dict) else None
    if status != 200 or not isinstance(data, list) or not data or len(data) > 100_000:
        raise GateError("MODEL_PROVIDER_RESPONSE_INVALID")
    model_ids = {item.get("id") for item in data if isinstance(item, dict) and isinstance(item.get("id"), str)}
    if expected_model and expected_model not in model_ids:
        raise GateError("MODEL_PROVIDER_EXPECTED_MODEL_MISSING")
    return GateResult(
        gate="MODEL_PROVIDER_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"model-provider://{parsed.hostname}",
        checks={
            "authenticated": True,
            "model_catalog_received": True,
            "model_count": len(model_ids),
            "expected_model_present": expected_model is None or expected_model in model_ids,
            "response_digest": hashlib.sha256(payload).hexdigest(),
            "credentials_redacted": True,
        },
    )


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise GateError("GATE_REPORT_PATH_INVALID")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-live-integration-gate")
    parser.add_argument("--output", type=Path, required=True)
    sub = parser.add_subparsers(dest="gate", required=True)
    oidc = sub.add_parser("oidc")
    oidc.add_argument("--issuer", required=True)
    oidc.add_argument("--audience", required=True)
    temporal = sub.add_parser("temporal")
    temporal.add_argument("--binary", type=Path, required=True)
    temporal.add_argument("--address", required=True)
    temporal.add_argument("--namespace", required=True)
    temporal.add_argument("--production-tls", action="store_true")
    temporal.add_argument("--binary-sha256")
    temporal.add_argument("--ca-file", type=Path)
    temporal.add_argument("--client-certificate", type=Path)
    temporal.add_argument("--client-private-key", type=Path)
    temporal.add_argument("--tls-server-name")
    s3 = sub.add_parser("s3")
    s3.add_argument("--endpoint", required=True)
    s3.add_argument("--region", required=True)
    s3.add_argument("--access-key-env", required=True)
    s3.add_argument("--secret-key-env", required=True)
    s3.add_argument("--allow-http-local", action="store_true")
    model = sub.add_parser("model")
    model.add_argument("--models-url", required=True)
    model.add_argument("--api-key-env", required=True)
    model.add_argument("--expected-model")
    mtls = sub.add_parser("mtls")
    mtls.add_argument("--host", required=True)
    mtls.add_argument("--port", type=int, required=True)
    mtls.add_argument("--ca-file", type=Path, required=True)
    mtls.add_argument("--client-certificate", type=Path, required=True)
    mtls.add_argument("--client-private-key", type=Path, required=True)
    vault = sub.add_parser("vault")
    vault.add_argument("--endpoint", required=True)
    vault.add_argument("--token-env", required=True)
    vault.add_argument("--dynamic-lease-path")
    vault.add_argument("--maximum-lease-seconds", type=int, default=900)
    generation = sub.add_parser("model-generation")
    generation.add_argument("--completions-url", required=True)
    generation.add_argument("--api-key-env", required=True)
    generation.add_argument("--model", required=True)
    generation.add_argument("--declared-region", required=True)
    generation.add_argument("--residency-attestation-digest")
    mcp = sub.add_parser("mcp")
    mcp.add_argument("--endpoint", required=True)
    mcp.add_argument("--bearer-env")
    a2a = sub.add_parser("a2a")
    a2a.add_argument("--card-url", required=True)
    args = parser.parse_args(argv)
    try:
        if args.gate == "oidc":
            result = probe_oidc(args.issuer, args.audience)
        elif args.gate == "temporal":
            result = probe_temporal(
                args.binary, args.address, args.namespace,
                require_production_tls=args.production_tls,
                binary_sha256=args.binary_sha256,
                ca_file=args.ca_file,
                client_certificate=args.client_certificate,
                client_private_key=args.client_private_key,
                tls_server_name=args.tls_server_name,
            )
        elif args.gate == "s3":
            result = probe_s3(args.endpoint, args.region, args.access_key_env, args.secret_key_env,
                              allow_http_local=args.allow_http_local)
        elif args.gate == "model":
            result = probe_model_provider(args.models_url, args.api_key_env,
                                          expected_model=args.expected_model)
        else:
            # Import here to avoid a module initialization cycle: the extended
            # probes reuse the bounded HTTP transport and report type above.
            from python.production_gates.external_services import (
                probe_a2a_agent_card,
                probe_mcp_http,
                probe_model_generation_stream,
                probe_mtls,
                probe_vault_secret_broker,
            )
            if args.gate == "mtls":
                result = probe_mtls(
                    args.host, args.port, args.ca_file, args.client_certificate,
                    args.client_private_key,
                )
            elif args.gate == "vault":
                result = probe_vault_secret_broker(
                    args.endpoint, args.token_env,
                    dynamic_lease_path=args.dynamic_lease_path,
                    maximum_lease_seconds=args.maximum_lease_seconds,
                )
            elif args.gate == "model-generation":
                result = probe_model_generation_stream(
                    args.completions_url, args.api_key_env, args.model,
                    args.declared_region,
                    residency_attestation_digest=args.residency_attestation_digest,
                )
            elif args.gate == "mcp":
                result = probe_mcp_http(
                    args.endpoint, bearer_environment=args.bearer_env
                )
            else:
                result = probe_a2a_agent_card(args.card_url)
        report = result.as_dict()
        exit_code = 0
    except ConfigurationMissing as exc:
        report = GateResult(args.gate.upper(), "NOT_RUN_CONFIGURATION", "unconfigured",
                            {"error_code": str(exc)}).as_dict()
        exit_code = 3
    except GateError as exc:
        report = GateResult(args.gate.upper(), "FAIL", "configured-target",
                            {"error_code": str(exc)}).as_dict()
        exit_code = 2
    _write_report(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
