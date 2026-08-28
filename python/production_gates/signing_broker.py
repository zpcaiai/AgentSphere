"""mTLS and workload-OIDC client for external production signing brokers.

The client never loads a signing private key. It sends an already prepared,
digest-bound Ed25519 payload to an approved external signer and converts the
strict broker response into the detached signature envelope independently
verified by the Rust production-closure finalizer.
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

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


CONFIG_SCHEMA_VERSION = "agenttrust.external-signing-broker-config.v1"
BROKER_REQUEST_SCHEMA_VERSION = "agenttrust.external-signing-broker-request.v1"
BROKER_RESPONSE_SCHEMA_VERSION = "agenttrust.external-signing-broker-response.v1"
AUDIT_RECEIPT_SCHEMA_VERSION = "agenttrust.external-signing-audit-receipt.v1"
SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION = (
    "agenttrust.signed-external-signing-audit-receipt.v1"
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_PAYLOAD = re.compile(r"^[A-Za-z0-9_-]{1,114294784}$")
_CONFIG_FIELDS = {
    "schema_version", "endpoint", "server_name", "oidc_audience", "ca_file",
    "client_certificate_file", "client_private_key_file", "timeout_seconds",
    "maximum_response_bytes",
}
_SIGNING_REQUEST_FIELDS = {
    "schema_version", "algorithm", "key_id", "signing_payload", "payload_sha256",
}
_BROKER_RESPONSE_FIELDS = {
    "schema_version", "request_id", "request_digest", "request_kind", "key_id",
    "algorithm", "payload_sha256", "signature", "signed_at", "audit_receipt_digest",
    "audit_receipt", "audit_signature",
}
_AUDIT_RECEIPT_FIELDS = {
    "schema_version", "request_id", "request_digest", "request_kind", "key_id",
    "algorithm", "payload_sha256", "document_signature_sha256", "signed_at",
}
_KINDS = {
    "certificate": (
        "agenttrust.production-closure-signing-request.v1",
        "PRODUCTION_CLOSURE_CERTIFICATE",
        "agenttrust.production-closure-external-signature.v2",
        "certificate",
    ),
    "revocation": (
        "agenttrust.production-closure-revocation-signing-request.v1",
        "PRODUCTION_CLOSURE_REVOCATION_REGISTRY",
        "agenttrust.production-closure-revocation-external-signature.v2",
        "registry",
    ),
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
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(code) from None
    if result.utcoffset() != timezone.utc.utcoffset(result):
        raise GateError(code)
    return result


def _decode_payload(value: object, code: str) -> bytes:
    if not isinstance(value, str) or not _PAYLOAD.fullmatch(value):
        raise GateError(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError):
        raise GateError(code) from None
    if (
        not decoded
        or len(decoded) > 64 * 1024 * 1024
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise GateError(code)
    return decoded


def prepare_broker_request(signing_request: object, kind: str) -> dict[str, object]:
    if kind not in _KINDS:
        raise GateError("SIGNING_BROKER_KIND_INVALID")
    schema_version, request_kind, _, embedded_field = _KINDS[kind]
    if not isinstance(signing_request, dict):
        raise GateError("SIGNING_BROKER_REQUEST_INVALID")
    expected_fields = _SIGNING_REQUEST_FIELDS | {embedded_field}
    if kind == "revocation":
        expected_fields.add("base_checkpoint_digest")
    request_value = _mapping(
        signing_request, expected_fields, "SIGNING_BROKER_REQUEST_INVALID"
    )
    payload = _decode_payload(
        request_value.get("signing_payload"), "SIGNING_BROKER_REQUEST_INVALID"
    )
    request_digest = _digest(request_value)
    key_id = request_value.get("key_id")
    payload_digest = request_value.get("payload_sha256")
    if (
        request_value.get("schema_version") != schema_version
        or request_value.get("algorithm") != "Ed25519"
        or not isinstance(key_id, str)
        or not _KEY_ID.fullmatch(key_id)
        or not isinstance(payload_digest, str)
        or payload_digest != hashlib.sha256(payload).hexdigest()
        or not isinstance(request_value.get(embedded_field), dict)
        or request_value[embedded_field].get("signature") != ""
        or (
            kind == "revocation"
            and (
                not isinstance(request_value.get("base_checkpoint_digest"), str)
                or not _DIGEST.fullmatch(str(request_value["base_checkpoint_digest"]))
            )
        )
    ):
        raise GateError("SIGNING_BROKER_REQUEST_INVALID")
    return {
        "schema_version": BROKER_REQUEST_SCHEMA_VERSION,
        "request_id": f"agenttrust-{request_kind.lower()}-{request_digest[:32]}",
        "request_digest": request_digest,
        "request_kind": request_kind,
        "key_id": key_id,
        "algorithm": "Ed25519",
        "payload_sha256": payload_digest,
        "signing_payload": request_value["signing_payload"],
        "idempotency_key": request_digest,
    }


def validate_broker_response(
    response: object,
    broker_request: Mapping[str, Any],
    *,
    kind: str,
    now: datetime | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    if kind not in _KINDS:
        raise GateError("SIGNING_BROKER_KIND_INVALID")
    _, expected_kind, output_schema, _ = _KINDS[kind]
    current_time = now or datetime.now(timezone.utc)
    if current_time.utcoffset() != timezone.utc.utcoffset(current_time):
        raise GateError("SIGNING_BROKER_TIME_INVALID")
    value = _mapping(
        response, _BROKER_RESPONSE_FIELDS, "SIGNING_BROKER_RESPONSE_INVALID"
    )
    signed_at = _parse_utc(value.get("signed_at"), "SIGNING_BROKER_RESPONSE_INVALID")
    audit_receipt = _mapping(
        value.get("audit_receipt"),
        _AUDIT_RECEIPT_FIELDS,
        "SIGNING_BROKER_RESPONSE_INVALID",
    )
    signature = value.get("signature")
    expected_audit_receipt = {
        "schema_version": AUDIT_RECEIPT_SCHEMA_VERSION,
        "request_id": broker_request.get("request_id"),
        "request_digest": broker_request.get("request_digest"),
        "request_kind": expected_kind,
        "key_id": broker_request.get("key_id"),
        "algorithm": "Ed25519",
        "payload_sha256": broker_request.get("payload_sha256"),
        "document_signature_sha256": (
            hashlib.sha256(signature.encode("ascii")).hexdigest()
            if isinstance(signature, str) and _SIGNATURE.fullmatch(signature)
            else ""
        ),
        "signed_at": value.get("signed_at"),
    }
    if (
        value.get("schema_version") != BROKER_RESPONSE_SCHEMA_VERSION
        or value.get("request_id") != broker_request.get("request_id")
        or value.get("request_digest") != broker_request.get("request_digest")
        or value.get("request_kind") != expected_kind
        or value.get("key_id") != broker_request.get("key_id")
        or value.get("algorithm") != "Ed25519"
        or value.get("payload_sha256") != broker_request.get("payload_sha256")
        or not isinstance(signature, str)
        or not _SIGNATURE.fullmatch(signature)
        or not isinstance(value.get("audit_receipt_digest"), str)
        or value.get("audit_receipt_digest") != _digest(audit_receipt)
        or audit_receipt != expected_audit_receipt
        or not isinstance(value.get("audit_signature"), str)
        or not _SIGNATURE.fullmatch(value["audit_signature"])
        or signed_at > current_time + timedelta(minutes=1)
        or signed_at < current_time - timedelta(minutes=15)
    ):
        raise GateError("SIGNING_BROKER_RESPONSE_INVALID")
    external_signature = {
        "schema_version": output_schema,
        "request_digest": broker_request["request_digest"],
        "algorithm": "Ed25519",
        "key_id": broker_request["key_id"],
        "signed_at": value["signed_at"],
        "audit_receipt_digest": value["audit_receipt_digest"],
        "signature": value["signature"],
    }
    signed_audit_receipt = {
        "schema_version": SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION,
        "receipt": dict(audit_receipt),
        "receipt_digest": value["audit_receipt_digest"],
        "algorithm": "Ed25519",
        "key_id": broker_request["key_id"],
        "signature": value["audit_signature"],
    }
    return external_signature, signed_audit_receipt


def _secure_file(path: Path, *, private: bool, maximum: int) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
        return False
    if not 1 <= metadata.st_size <= maximum:
        return False
    if os.name == "posix":
        mode = metadata.st_mode & 0o777
        if private and mode & 0o077:
            return False
        if not private and mode & 0o022:
            return False
    return True


def invoke_signing_broker(
    signing_request: object,
    config: object,
    oidc_token_file: Path,
    *,
    kind: str,
) -> tuple[dict[str, object], dict[str, object]]:
    broker_request = prepare_broker_request(signing_request, kind)
    value = _mapping(config, _CONFIG_FIELDS, "SIGNING_BROKER_CONFIG_INVALID")
    parsed = urlparse(str(value.get("endpoint")))
    server_name = value.get("server_name")
    timeout = value.get("timeout_seconds")
    maximum_response = value.get("maximum_response_bytes")
    paths = {
        field: Path(str(value.get(field)))
        for field in ("ca_file", "client_certificate_file", "client_private_key_file")
    }
    if (
        value.get("schema_version") != CONFIG_SCHEMA_VERSION
        or parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname != server_name
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/signatures/ed25519"
        or parsed.port not in (None, 443, 8443)
        or not isinstance(value.get("oidc_audience"), str)
        or not value["oidc_audience"]
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 30
        or not isinstance(maximum_response, int)
        or isinstance(maximum_response, bool)
        or not 1024 <= maximum_response <= 1024 * 1024
        or any(not path.is_absolute() for path in paths.values())
        or not _secure_file(paths["ca_file"], private=False, maximum=1024 * 1024)
        or not _secure_file(paths["client_certificate_file"], private=False, maximum=1024 * 1024)
        or not _secure_file(paths["client_private_key_file"], private=True, maximum=1024 * 1024)
        or not oidc_token_file.is_absolute()
        or not _secure_file(oidc_token_file, private=True, maximum=128 * 1024)
    ):
        raise GateError("SIGNING_BROKER_CONFIG_INVALID")
    token = oidc_token_file.read_text(encoding="utf-8").strip()
    if not token or any(character.isspace() for character in token):
        raise GateError("SIGNING_BROKER_TOKEN_INVALID")

    context = ssl.create_default_context(cafile=str(paths["ca_file"]))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(paths["client_certificate_file"]),
        keyfile=str(paths["client_private_key_file"]),
    )
    body = canonical_json(broker_request)
    request = Request(
        str(value["endpoint"]),
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": str(broker_request["idempotency_key"]),
            "User-Agent": "AgentTrust-Production-Closure/1",
        },
    )
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise GateError("SIGNING_BROKER_RESPONSE_INVALID")
            payload = response.read(maximum_response + 1)
    except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError):
        raise GateError("SIGNING_BROKER_UNAVAILABLE") from None
    if not payload or len(payload) > maximum_response:
        raise GateError("SIGNING_BROKER_RESPONSE_INVALID")
    try:
        response_value = json.loads(payload, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError("SIGNING_BROKER_RESPONSE_INVALID") from None
    return validate_broker_response(response_value, broker_request, kind=kind)


def _read_json(path: Path, code: str) -> object:
    if not path.is_absolute() or not _secure_file(path, private=False, maximum=64 * 1024 * 1024):
        raise GateError(code)
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError(code) from None


def _write_new(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or not path.parent.is_dir():
        raise GateError("SIGNING_BROKER_OUTPUT_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-external-signing-broker")
    parser.add_argument("--kind", choices=sorted(_KINDS), required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--oidc-token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-receipt-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output == args.audit_receipt_output:
        raise GateError("SIGNING_BROKER_OUTPUT_INVALID")
    external_signature, audit_receipt = invoke_signing_broker(
        _read_json(args.request, "SIGNING_BROKER_REQUEST_INVALID"),
        _read_json(args.config, "SIGNING_BROKER_CONFIG_INVALID"),
        args.oidc_token_file,
        kind=args.kind,
    )
    _write_new(args.output, external_signature)
    _write_new(args.audit_receipt_output, audit_receipt)
    print(json.dumps({
        "external_signature_verified_by_finalizer": False,
        "audit_receipt_verification_required": True,
        "key_id": external_signature["key_id"],
        "private_key_loaded": False,
        "request_digest": external_signature["request_digest"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
