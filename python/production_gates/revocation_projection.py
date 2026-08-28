"""Fail-closed client for the external revocation projection authority.

The projection authority is the only component allowed to update the live Vault
projection consumed by activation watchers.  This client does not infer a
successful write from an HTTP status: it verifies a short-lived signed head and
an exact, signed set of watcher acknowledgements before returning a receipt.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.revocation_checkpoint import (
    verify_successor,
)


CONFIG_SCHEMA_VERSION = "agenttrust.revocation-projection-broker-config.v1"
REQUEST_SCHEMA_VERSION = "agenttrust.production-revocation-projection-request.v1"
HEAD_SCHEMA_VERSION = "agenttrust.production-revocation-projection-head.v1"
ACK_SCHEMA_VERSION = "agenttrust.production-revocation-watcher-ack.v1"
RECEIPT_SCHEMA_VERSION = "agenttrust.production-revocation-projection-receipt.v1"
PUBLIC_KEY_SCHEMA_VERSION = "agenttrust.ed25519-public-key.v1"
REQUIRED_WATCHER_CLASSES = frozenset({
    "execution/fleet",
    "platform-sre/activation-lease",
    "runtime/fleet",
})

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_WATCHER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_ENVIRONMENT = re.compile(r"^environment://production/[A-Za-z0-9._:/-]{1,480}$")
_CONFIG_FIELDS = {
    "schema_version", "endpoint", "server_name", "oidc_audience",
    "environment_reference", "ca_file", "client_certificate_file",
    "client_private_key_file", "projection_public_key", "timeout_seconds",
    "maximum_response_bytes", "head_ttl_seconds", "ack_timeout_seconds",
    "required_watcher_ids",
}
_PUBLIC_KEY_FIELDS = {"schema_version", "key_id", "public_key"}
_REQUEST_FIELDS = {
    "schema_version", "request_id", "release_id", "environment_reference",
    "base_checkpoint_digest", "registry_id", "registry_key_id",
    "registry_sequence", "registry_digest", "registry",
    "required_watcher_ids", "requested_at", "idempotency_key",
}
_HEAD_FIELDS = {
    "schema_version", "projection_id", "environment_reference",
    "base_checkpoint_digest", "registry_id", "registry_key_id",
    "registry_sequence", "registry_digest", "projected_at", "expires_at",
    "projection_key_id", "signature",
}
_ACK_FIELDS = {
    "schema_version", "projection_id", "watcher_id", "registry_sequence",
    "registry_digest", "activation_receipt_digest", "acknowledged_at",
}
_RECEIPT_FIELDS = {
    "schema_version", "request_digest", "projection_id", "projection_head",
    "watcher_acks", "committed", "completed_at", "projection_key_id",
    "signature",
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() != timezone.utc.utcoffset(current):
        raise GateError("REVOCATION_PROJECTION_TIME_INVALID")
    return current.astimezone(timezone.utc)


def _decode(value: object, length: int, code: str) -> bytes:
    if not isinstance(value, str):
        raise GateError(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError):
        raise GateError(code) from None
    if (
        len(decoded) != length
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise GateError(code)
    return decoded


def _public_key(value: object) -> tuple[str, Ed25519PublicKey]:
    spec = _mapping(
        value, _PUBLIC_KEY_FIELDS, "REVOCATION_PROJECTION_PUBLIC_KEY_INVALID"
    )
    key_id = spec.get("key_id")
    if (
        spec.get("schema_version") != PUBLIC_KEY_SCHEMA_VERSION
        or not isinstance(key_id, str)
        or not _KEY_ID.fullmatch(key_id)
    ):
        raise GateError("REVOCATION_PROJECTION_PUBLIC_KEY_INVALID")
    try:
        key = Ed25519PublicKey.from_public_bytes(
            _decode(spec.get("public_key"), 32, "REVOCATION_PROJECTION_PUBLIC_KEY_INVALID")
        )
    except ValueError:
        raise GateError("REVOCATION_PROJECTION_PUBLIC_KEY_INVALID") from None
    return key_id, key


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


def _read_json(path: Path, code: str, *, maximum: int = 64 * 1024 * 1024) -> object:
    if not _secure_file(path, private=False, maximum=maximum):
        raise GateError(code)
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError(code) from None


def validate_config(value: object) -> Mapping[str, Any]:
    config = _mapping(value, _CONFIG_FIELDS, "REVOCATION_PROJECTION_CONFIG_INVALID")
    endpoint = urlparse(str(config.get("endpoint")))
    watcher_ids = config.get("required_watcher_ids")
    timeout = config.get("timeout_seconds")
    maximum = config.get("maximum_response_bytes")
    head_ttl = config.get("head_ttl_seconds")
    ack_timeout = config.get("ack_timeout_seconds")
    paths = {
        name: Path(str(config.get(name)))
        for name in ("ca_file", "client_certificate_file", "client_private_key_file")
    }
    if (
        config.get("schema_version") != CONFIG_SCHEMA_VERSION
        or endpoint.scheme != "https"
        or endpoint.hostname is None
        or endpoint.hostname != config.get("server_name")
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
        or endpoint.path != "/v1/revocation-projections"
        or endpoint.port not in (None, 443, 8443)
        or not isinstance(config.get("oidc_audience"), str)
        or not 1 <= len(str(config["oidc_audience"])) <= 256
        or any(character.isspace() for character in str(config["oidc_audience"]))
        or not isinstance(config.get("environment_reference"), str)
        or not _ENVIRONMENT.fullmatch(str(config["environment_reference"]))
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 30
        or not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or not 4096 <= maximum <= 4 * 1024 * 1024
        or not isinstance(head_ttl, int)
        or isinstance(head_ttl, bool)
        or not 30 <= head_ttl <= 300
        or not isinstance(ack_timeout, int)
        or isinstance(ack_timeout, bool)
        or not 5 <= ack_timeout <= 300
        or not isinstance(watcher_ids, list)
        or not 1 <= len(watcher_ids) <= 10_000
        or watcher_ids != sorted(watcher_ids)
        or len(watcher_ids) != len(set(watcher_ids))
        or not REQUIRED_WATCHER_CLASSES.issubset(set(watcher_ids))
        or any(not isinstance(item, str) or not _WATCHER_ID.fullmatch(item) for item in watcher_ids)
        or not _secure_file(paths["ca_file"], private=False, maximum=1024 * 1024)
        or not _secure_file(
            paths["client_certificate_file"], private=False, maximum=1024 * 1024
        )
        or not _secure_file(
            paths["client_private_key_file"], private=True, maximum=1024 * 1024
        )
    ):
        raise GateError("REVOCATION_PROJECTION_CONFIG_INVALID")
    _public_key(config.get("projection_public_key"))
    return config


def prepare_projection_request(
    registry: object,
    checkpoint: object,
    revocation_public_key: object,
    config: object,
    *,
    release_id: str,
    requested_at: datetime | None = None,
) -> dict[str, object]:
    current = _now(requested_at)
    config_value = validate_config(config)
    base, successor, registry_digest = verify_successor(
        checkpoint, registry, revocation_public_key
    )
    projection_key_id, _ = _public_key(config_value.get("projection_public_key"))
    if not _RELEASE_ID.fullmatch(release_id):
        raise GateError("REVOCATION_PROJECTION_RELEASE_INVALID")
    if successor.get("key_id") == projection_key_id:
        raise GateError("REVOCATION_PROJECTION_KEY_SEPARATION_REQUIRED")
    material: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": "",
        "release_id": release_id,
        "environment_reference": config_value["environment_reference"],
        "base_checkpoint_digest": base["checkpoint_digest"],
        "registry_id": successor["registry_id"],
        "registry_key_id": successor["key_id"],
        "registry_sequence": successor["sequence"],
        "registry_digest": registry_digest,
        "registry": dict(successor),
        "required_watcher_ids": list(config_value["required_watcher_ids"]),
        "requested_at": current.isoformat().replace("+00:00", "Z"),
        "idempotency_key": "",
    }
    request_digest = _digest(material)
    material["request_id"] = f"agenttrust-revocation-projection-{request_digest[:32]}"
    material["idempotency_key"] = _digest(material)
    return material


def _verify_signature(value: Mapping[str, Any], key: Ed25519PublicKey, code: str) -> None:
    signature = value.get("signature")
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        raise GateError(code)
    unsigned = dict(value)
    unsigned["signature"] = ""
    try:
        key.verify(_decode(signature, 64, code), canonical_json(unsigned))
    except InvalidSignature:
        raise GateError(code) from None


def validate_projection_response(
    response: object,
    request: Mapping[str, Any],
    config: object,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    current = _now(now)
    config_value = validate_config(config)
    key_id, projection_key = _public_key(config_value.get("projection_public_key"))
    receipt = _mapping(
        response, _RECEIPT_FIELDS, "REVOCATION_PROJECTION_RESPONSE_INVALID"
    )
    head = _mapping(
        receipt.get("projection_head"),
        _HEAD_FIELDS,
        "REVOCATION_PROJECTION_HEAD_INVALID",
    )
    projected_at = _parse_utc(
        head.get("projected_at"), "REVOCATION_PROJECTION_HEAD_INVALID"
    )
    expires_at = _parse_utc(
        head.get("expires_at"), "REVOCATION_PROJECTION_HEAD_INVALID"
    )
    expected_head = {
        "environment_reference": request.get("environment_reference"),
        "base_checkpoint_digest": request.get("base_checkpoint_digest"),
        "registry_id": request.get("registry_id"),
        "registry_key_id": request.get("registry_key_id"),
        "registry_sequence": request.get("registry_sequence"),
        "registry_digest": request.get("registry_digest"),
        "projection_key_id": key_id,
    }
    if (
        head.get("schema_version") != HEAD_SCHEMA_VERSION
        or not isinstance(head.get("projection_id"), str)
        or not _KEY_ID.fullmatch(str(head["projection_id"]))
        or any(head.get(field) != value for field, value in expected_head.items())
        or projected_at < _parse_utc(
            request.get("requested_at"), "REVOCATION_PROJECTION_REQUEST_INVALID"
        ) - timedelta(minutes=1)
        or projected_at > current + timedelta(minutes=1)
        or expires_at <= current
        or expires_at <= projected_at
        or expires_at - projected_at
        > timedelta(seconds=int(config_value["head_ttl_seconds"]))
    ):
        raise GateError("REVOCATION_PROJECTION_HEAD_INVALID")
    _verify_signature(head, projection_key, "REVOCATION_PROJECTION_HEAD_INVALID")

    completed_at = _parse_utc(
        receipt.get("completed_at"), "REVOCATION_PROJECTION_RESPONSE_INVALID"
    )
    acks = receipt.get("watcher_acks")
    if not isinstance(acks, list) or len(acks) > 10_000:
        raise GateError("REVOCATION_PROJECTION_ACK_INVALID")
    observed: list[str] = []
    for raw_ack in acks:
        ack = _mapping(raw_ack, _ACK_FIELDS, "REVOCATION_PROJECTION_ACK_INVALID")
        acknowledged_at = _parse_utc(
            ack.get("acknowledged_at"), "REVOCATION_PROJECTION_ACK_INVALID"
        )
        watcher_id = ack.get("watcher_id")
        if (
            ack.get("schema_version") != ACK_SCHEMA_VERSION
            or ack.get("projection_id") != head.get("projection_id")
            or not isinstance(watcher_id, str)
            or not _WATCHER_ID.fullmatch(watcher_id)
            or ack.get("registry_sequence") != request.get("registry_sequence")
            or ack.get("registry_digest") != request.get("registry_digest")
            or not isinstance(ack.get("activation_receipt_digest"), str)
            or not _DIGEST.fullmatch(str(ack["activation_receipt_digest"]))
            or acknowledged_at < projected_at
            or acknowledged_at > completed_at
            or completed_at - acknowledged_at
            > timedelta(seconds=int(config_value["ack_timeout_seconds"]))
        ):
            raise GateError("REVOCATION_PROJECTION_ACK_INVALID")
        observed.append(watcher_id)
    if observed != request.get("required_watcher_ids"):
        raise GateError("REVOCATION_PROJECTION_ACK_SET_INCOMPLETE")

    request_digest = _digest(request)
    if (
        receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION
        or receipt.get("request_digest") != request_digest
        or receipt.get("projection_id") != head.get("projection_id")
        or receipt.get("committed") is not True
        or receipt.get("projection_key_id") != key_id
        or completed_at < projected_at
        or completed_at > current + timedelta(minutes=1)
        or completed_at - projected_at
        > timedelta(seconds=int(config_value["ack_timeout_seconds"]))
    ):
        raise GateError("REVOCATION_PROJECTION_RESPONSE_INVALID")
    _verify_signature(receipt, projection_key, "REVOCATION_PROJECTION_RESPONSE_INVALID")
    return dict(receipt)


def invoke_projection_broker(
    registry: object,
    checkpoint: object,
    revocation_public_key: object,
    config: object,
    oidc_token_file: Path,
    *,
    release_id: str,
) -> dict[str, object]:
    config_value = validate_config(config)
    if not oidc_token_file.is_absolute() or not _secure_file(
        oidc_token_file, private=True, maximum=128 * 1024
    ):
        raise GateError("REVOCATION_PROJECTION_TOKEN_INVALID")
    token = oidc_token_file.read_text(encoding="utf-8").strip()
    if not token or any(character.isspace() for character in token):
        raise GateError("REVOCATION_PROJECTION_TOKEN_INVALID")
    request_value = prepare_projection_request(
        registry,
        checkpoint,
        revocation_public_key,
        config_value,
        release_id=release_id,
    )
    context = ssl.create_default_context(cafile=str(config_value["ca_file"]))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(config_value["client_certificate_file"]),
        keyfile=str(config_value["client_private_key_file"]),
    )
    request = Request(
        str(config_value["endpoint"]),
        data=canonical_json(request_value),
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": str(request_value["idempotency_key"]),
            "User-Agent": "AgentTrust-Revocation-Projection/1",
        },
    )
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=int(config_value["timeout_seconds"])) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise GateError("REVOCATION_PROJECTION_RESPONSE_INVALID")
            payload = response.read(int(config_value["maximum_response_bytes"]) + 1)
    except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError):
        raise GateError("REVOCATION_PROJECTION_UNAVAILABLE") from None
    if not payload or len(payload) > int(config_value["maximum_response_bytes"]):
        raise GateError("REVOCATION_PROJECTION_RESPONSE_INVALID")
    try:
        response_value = json.loads(payload, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError("REVOCATION_PROJECTION_RESPONSE_INVALID") from None
    return validate_projection_response(response_value, request_value, config_value)


def _write_new(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise GateError("REVOCATION_PROJECTION_OUTPUT_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="project-production-revocation")
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--revocation-public-key", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--oidc-token-file", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = invoke_projection_broker(
        _read_json(args.registry, "REVOCATION_PROJECTION_REGISTRY_INVALID"),
        _read_json(args.checkpoint, "REVOCATION_PROJECTION_CHECKPOINT_INVALID"),
        _read_json(
            args.revocation_public_key,
            "REVOCATION_PROJECTION_REVOCATION_KEY_INVALID",
            maximum=64 * 1024,
        ),
        _read_json(args.config, "REVOCATION_PROJECTION_CONFIG_INVALID"),
        args.oidc_token_file,
        release_id=args.release_id,
    )
    _write_new(args.output, receipt)
    print(json.dumps({
        "committed": True,
        "projection_id": receipt["projection_id"],
        "request_digest": receipt["request_digest"],
        "watcher_acknowledgements": len(receipt["watcher_acks"]),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
