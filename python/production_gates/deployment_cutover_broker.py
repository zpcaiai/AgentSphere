"""Fail-closed mTLS/OIDC client for an external deployment cutover authority.

The authority performs the requested writer fence or traffic operation.  This
client performs no local deployment action and accepts success only when the
authority returns a fresh, externally signed receipt that is bound to the
requested releases, environment, operation, predecessor, and writer fence.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from python.production_gates.deployment_cutover import (
    validate_blue_green_inventory,
    verify_signed_receipt,
)
from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


CONFIG_SCHEMA_VERSION = "agenttrust.deployment-cutover-broker-config.v1"
REQUEST_SCHEMA_VERSION = "agenttrust.deployment-cutover-broker-request.v1"
RESPONSE_SCHEMA_VERSION = "agenttrust.deployment-cutover-broker-response.v1"
OPERATIONS = {"WRITER_FENCE", "CUTOVER", "ROLLBACK", "UNFREEZE"}
ZERO_DIGEST = "0" * 64

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_ENVIRONMENT = re.compile(
    r"^environment://production/[A-Za-z0-9][A-Za-z0-9._:/-]{0,447}$"
)
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_CONFIG_FIELDS = {
    "schema_version", "endpoint", "server_name", "oidc_issuer", "oidc_audience",
    "ca_file", "client_certificate_file", "client_private_key_file", "keyring_file",
    "timeout_seconds", "maximum_response_bytes",
}
_REQUEST_FIELDS = {
    "schema_version", "request_id", "source_release_id", "target_release_id",
    "environment_reference", "operation", "expected_previous_transition_digest",
    "writer_fence_receipt_digest", "requested_at", "idempotency_key",
}
_RESPONSE_FIELDS = {
    "schema_version", "request_id", "request_digest", "source_release_id",
    "target_release_id", "environment_reference", "operation",
    "expected_previous_transition_digest", "writer_fence_receipt_digest",
    "inventory", "signed_receipt", "completed_at",
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() != timezone.utc.utcoffset(current):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_TIME_INVALID")
    return current.astimezone(timezone.utc)


def _time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise GateError(code) from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _secure_file(path: Path, *, private: bool, maximum: int) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.resolve() != path
        or not path.is_file()
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        return False
    if os.name == "posix":
        mode = metadata.st_mode & 0o777
        if private and mode & 0o077:
            return False
        if not private and mode & 0o022:
            return False
    return True


def read_json(path: Path, code: str, *, maximum: int = 16 * 1024 * 1024) -> object:
    if not _secure_file(path, private=False, maximum=maximum):
        raise GateError(code)
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError(code) from None


def validate_config(value: object) -> dict[str, Any]:
    code = "DEPLOYMENT_CUTOVER_BROKER_CONFIG_INVALID"
    config = _mapping(value, _CONFIG_FIELDS, code)
    endpoint = urlparse(str(config.get("endpoint")))
    issuer = urlparse(str(config.get("oidc_issuer")))
    timeout = config.get("timeout_seconds")
    maximum = config.get("maximum_response_bytes")
    paths = {
        name: Path(str(config.get(name)))
        for name in (
            "ca_file", "client_certificate_file", "client_private_key_file",
            "keyring_file",
        )
    }
    audience = config.get("oidc_audience")
    if (
        config.get("schema_version") != CONFIG_SCHEMA_VERSION
        or endpoint.scheme != "https"
        or endpoint.hostname is None
        or endpoint.hostname != config.get("server_name")
        or _DNS_NAME.fullmatch(str(config.get("server_name"))) is None
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
        or endpoint.path != "/v1/deployment-cutovers"
        or endpoint.port not in (None, 443, 8443)
        or issuer.scheme != "https"
        or issuer.hostname is None
        or issuer.username is not None
        or issuer.password is not None
        or issuer.query
        or issuer.fragment
        or issuer.port not in (None, 443)
        or not isinstance(audience, str)
        or not 1 <= len(audience) <= 256
        or any(character.isspace() for character in audience)
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 30
        or not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or not 4096 <= maximum <= 4 * 1024 * 1024
        or not _secure_file(paths["ca_file"], private=False, maximum=1024 * 1024)
        or not _secure_file(
            paths["client_certificate_file"], private=False, maximum=1024 * 1024
        )
        or not _secure_file(
            paths["client_private_key_file"], private=True, maximum=1024 * 1024
        )
        or not _secure_file(paths["keyring_file"], private=False, maximum=4 * 1024 * 1024)
    ):
        raise GateError(code)
    return json.loads(canonical_json(config))


def _jwt_claims(token: str, config: Mapping[str, Any], current: datetime) -> None:
    code = "DEPLOYMENT_CUTOVER_BROKER_TOKEN_INVALID"
    if not token or len(token) > 128 * 1024 or any(char.isspace() for char in token):
        raise GateError(code)
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise GateError(code)
    try:
        payload = base64.b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True
        )
        claims = json.loads(payload, object_pairs_hook=_duplicates)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(code) from None
    audience = claims.get("aud") if isinstance(claims, dict) else None
    normalized_audience = audience if isinstance(audience, list) else [audience]
    issued_at = claims.get("iat") if isinstance(claims, dict) else None
    not_before = claims.get("nbf", issued_at) if isinstance(claims, dict) else None
    expires = claims.get("exp") if isinstance(claims, dict) else None
    timestamp = current.timestamp()
    if (
        not isinstance(claims, dict)
        or claims.get("iss") != config.get("oidc_issuer")
        or normalized_audience != [config.get("oidc_audience")]
        or not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(not_before, int)
        or isinstance(not_before, bool)
        or not isinstance(expires, int)
        or isinstance(expires, bool)
        or issued_at > timestamp + 30
        or issued_at < timestamp - 900
        or not_before > timestamp + 30
        or expires <= timestamp + 30
        or expires - issued_at > 3600
    ):
        raise GateError(code)


def prepare_broker_request(
    *,
    source_release_id: str,
    target_release_id: str,
    environment_reference: str,
    operation: str,
    expected_previous_transition_digest: str,
    writer_fence_receipt_digest: str,
    requested_at: datetime | None = None,
) -> dict[str, object]:
    code = "DEPLOYMENT_CUTOVER_BROKER_REQUEST_INVALID"
    current = _now(requested_at)
    if (
        _RELEASE_ID.fullmatch(source_release_id) is None
        or _RELEASE_ID.fullmatch(target_release_id) is None
        or source_release_id == target_release_id
        or _ENVIRONMENT.fullmatch(environment_reference) is None
        or operation not in OPERATIONS
        or _DIGEST.fullmatch(expected_previous_transition_digest) is None
        or _DIGEST.fullmatch(writer_fence_receipt_digest) is None
        or (operation in {"WRITER_FENCE", "CUTOVER"})
        != (expected_previous_transition_digest == ZERO_DIGEST)
        or (operation == "WRITER_FENCE")
        != (writer_fence_receipt_digest == ZERO_DIGEST)
    ):
        raise GateError(code)
    material = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "source_release_id": source_release_id,
        "target_release_id": target_release_id,
        "environment_reference": environment_reference,
        "operation": operation,
        "expected_previous_transition_digest": expected_previous_transition_digest,
        "writer_fence_receipt_digest": writer_fence_receipt_digest,
        "requested_at": current.isoformat().replace("+00:00", "Z"),
    }
    identity = _digest(material)
    return {
        **material,
        "request_id": f"deployment-cutover-{identity[:32]}",
        "idempotency_key": identity,
    }


def validate_broker_request(
    value: object, *, now: datetime | None = None
) -> dict[str, Any]:
    code = "DEPLOYMENT_CUTOVER_BROKER_REQUEST_INVALID"
    current = _now(now)
    request = _mapping(value, _REQUEST_FIELDS, code)
    requested = _time(request.get("requested_at"), code)
    expected = prepare_broker_request(
        source_release_id=str(request.get("source_release_id")),
        target_release_id=str(request.get("target_release_id")),
        environment_reference=str(request.get("environment_reference")),
        operation=str(request.get("operation")),
        expected_previous_transition_digest=str(
            request.get("expected_previous_transition_digest")
        ),
        writer_fence_receipt_digest=str(request.get("writer_fence_receipt_digest")),
        requested_at=requested,
    )
    if request != expected or requested > current + timedelta(seconds=30) or requested < current - timedelta(minutes=15):
        raise GateError(code)
    return json.loads(canonical_json(request))


def validate_broker_response(
    value: object,
    request: object,
    keyring: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    code = "DEPLOYMENT_CUTOVER_BROKER_RESPONSE_INVALID"
    current = _now(now)
    request_value = validate_broker_request(request, now=current)
    response = _mapping(value, _RESPONSE_FIELDS, code)
    completed = _time(response.get("completed_at"), code)
    operation = str(request_value["operation"])
    receipt = verify_signed_receipt(
        response.get("signed_receipt"), keyring, expected_kind=operation, now=current
    )
    document = receipt["document"]
    shared_fields = (
        "source_release_id", "target_release_id", "environment_reference"
    )
    if (
        response.get("schema_version") != RESPONSE_SCHEMA_VERSION
        or response.get("request_id") != request_value["request_id"]
        or response.get("request_digest") != _digest(request_value)
        or any(response.get(field) != request_value[field] for field in shared_fields)
        or response.get("operation") != operation
        or response.get("expected_previous_transition_digest")
        != request_value["expected_previous_transition_digest"]
        or response.get("writer_fence_receipt_digest")
        != request_value["writer_fence_receipt_digest"]
        or any(document.get(field) != request_value[field] for field in shared_fields)
        or completed < _time(request_value["requested_at"], code)
        or completed > current + timedelta(seconds=30)
        or completed < current - timedelta(minutes=15)
    ):
        raise GateError(code)
    if operation == "WRITER_FENCE":
        if response.get("inventory") is not None:
            raise GateError(code)
    else:
        inventory = validate_blue_green_inventory(response.get("inventory"), now=current)
        if (
            document.get("previous_transition_digest")
            != request_value["expected_previous_transition_digest"]
            or document.get("writer_fence_receipt_digest")
            != request_value["writer_fence_receipt_digest"]
            or document.get("inventory_digest") != inventory.get("inventory_digest")
            or document.get("traffic_revision") != inventory.get("traffic_revision")
            or any(inventory.get(field) != request_value[field] for field in shared_fields)
        ):
            raise GateError(code)
    return json.loads(canonical_json(response))


def invoke_broker(
    request: object,
    config: object,
    oidc_token_file: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _now(now)
    config_value = validate_config(config)
    request_value = validate_broker_request(request, now=current)
    if not _secure_file(oidc_token_file, private=True, maximum=128 * 1024):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_TOKEN_INVALID")
    try:
        token = oidc_token_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_TOKEN_INVALID") from None
    _jwt_claims(token, config_value, current)
    context = ssl.create_default_context(cafile=str(config_value["ca_file"]))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(config_value["client_certificate_file"]),
        keyfile=str(config_value["client_private_key_file"]),
    )
    body = canonical_json(request_value)
    http_request = Request(
        str(config_value["endpoint"]),
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": str(request_value["idempotency_key"]),
            "X-AgentTrust-OIDC-Audience": str(config_value["oidc_audience"]),
            "User-Agent": "AgentTrust-Deployment-Cutover/1",
        },
    )
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
    try:
        with opener.open(
            http_request, timeout=int(config_value["timeout_seconds"])
        ) as http_response:
            if (
                http_response.status != 200
                or http_response.headers.get("Content-Type") != "application/json"
            ):
                raise GateError("DEPLOYMENT_CUTOVER_BROKER_RESPONSE_INVALID")
            payload = http_response.read(int(config_value["maximum_response_bytes"]) + 1)
    except GateError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_UNAVAILABLE") from None
    if not payload or len(payload) > int(config_value["maximum_response_bytes"]):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_RESPONSE_INVALID")
    try:
        response = json.loads(payload, object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_RESPONSE_INVALID") from None
    keyring = read_json(
        Path(str(config_value["keyring_file"])),
        "DEPLOYMENT_CUTOVER_BROKER_KEYRING_INVALID",
        maximum=4 * 1024 * 1024,
    )
    return validate_broker_response(response, request_value, keyring, now=current)
