"""Signed production release material binding.

The Git provenance signature authenticates an immutable commit and its published
tag.  This contract separately authenticates the exact deployment template,
non-secret values, and runtime configuration selected for that commit.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import (
    PRODUCTION_STACK_TEMPLATE_GIT_PATH,
    canonical_json,
    read_production_template_blob,
    read_protected_ed25519_private_key,
    signed_git_provenance_digest,
    verify_signed_git_provenance,
)
from python.production_gates.live_integrations import GateError


SIGNED_RELEASE_BINDING_SCHEMA_VERSION = "agenttrust.signed-release-binding.v1"
RELEASE_BINDING_SCHEMA_VERSION = "agenttrust.release-binding.v1"
RELEASE_BINDING_KEYRING_SCHEMA_VERSION = "agenttrust.release-binding-keyring.v1"
RELEASE_BINDING_KEY_USAGE = "PRODUCTION_RELEASE_BINDING"
RELEASE_BINDING_ALGORITHM = "Ed25519"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")

_BINDING_FIELDS = {
    "schema_version",
    "release_id",
    "release_digest",
    "signed_git_provenance_digest",
    "template_git_path",
    "template_blob_object_id",
    "template_digest",
    "values_without_release_digest",
    "runtime_config_digest",
}
_ENVELOPE_FIELDS = {
    "schema_version", "binding", "binding_digest", "issuer", "key_id",
    "key_usage", "algorithm", "signed_at", "signature",
}
_KEYRING_FIELDS = {"schema_version", "keys"}
_KEY_FIELDS = {
    "issuer", "key_id", "key_usage", "algorithm", "public_key", "status",
    "not_before", "not_after",
}


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _strict_mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise GateError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _decode_base64url(value: object, length: int, code: str) -> bytes:
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


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unsigned_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in sorted(_ENVELOPE_FIELDS - {"signature"})}


def _object_format_from_release_id(release_id: str) -> tuple[str, str]:
    if not _RELEASE_ID.fullmatch(release_id):
        raise GateError("RELEASE_BINDING_RELEASE_ID_INVALID")
    _, object_format, commit_object_id = release_id.split(":", 2)
    return object_format, commit_object_id


def build_release_binding(
    template: str,
    values: Mapping[str, Any],
    runtime_config: object,
    *,
    provenance_digest: str,
    template_blob_object_id: str,
) -> dict[str, Any]:
    if (
        not isinstance(template, str)
        or not isinstance(values, Mapping)
        or "release_digest" not in values
        or not isinstance(provenance_digest, str)
        or not _DIGEST.fullmatch(provenance_digest)
    ):
        raise GateError("RELEASE_BINDING_MATERIAL_INVALID")
    release_id = values.get("release_id")
    if not isinstance(release_id, str):
        raise GateError("RELEASE_BINDING_RELEASE_ID_INVALID")
    object_format, _ = _object_format_from_release_id(release_id)
    expected_object_length = 40 if object_format == "sha1" else 64
    if (
        not isinstance(template_blob_object_id, str)
        or len(template_blob_object_id) != expected_object_length
        or not _OBJECT_ID.fullmatch(template_blob_object_id)
    ):
        raise GateError("RELEASE_BINDING_TEMPLATE_BLOB_INVALID")
    unsigned_values = dict(values)
    unsigned_values.pop("release_digest")
    try:
        # Canonical round-trip makes the signed object independent of caller mutation.
        canonical_values = json.loads(canonical_json(unsigned_values))
        runtime_digest = _digest(runtime_config)
    except (UnicodeDecodeError, json.JSONDecodeError, GateError):
        raise GateError("RELEASE_BINDING_MATERIAL_INVALID") from None
    material: dict[str, Any] = {
        "schema_version": RELEASE_BINDING_SCHEMA_VERSION,
        "release_id": release_id,
        "signed_git_provenance_digest": provenance_digest,
        "template_git_path": PRODUCTION_STACK_TEMPLATE_GIT_PATH,
        "template_blob_object_id": template_blob_object_id,
        "template_digest": hashlib.sha256(template.encode("utf-8")).hexdigest(),
        "values_without_release_digest": canonical_values,
        "runtime_config_digest": runtime_digest,
    }
    material["release_digest"] = _digest(material)
    return material


def validate_release_binding(value: object) -> Mapping[str, Any]:
    binding = _strict_mapping(value, _BINDING_FIELDS, "RELEASE_BINDING_INVALID")
    release_id = binding.get("release_id")
    if not isinstance(release_id, str):
        raise GateError("RELEASE_BINDING_INVALID")
    object_format, _ = _object_format_from_release_id(release_id)
    object_id = binding.get("template_blob_object_id")
    expected_object_length = 40 if object_format == "sha1" else 64
    values = binding.get("values_without_release_digest")
    if (
        binding.get("schema_version") != RELEASE_BINDING_SCHEMA_VERSION
        or binding.get("template_git_path") != PRODUCTION_STACK_TEMPLATE_GIT_PATH
        or not isinstance(object_id, str)
        or len(object_id) != expected_object_length
        or not _OBJECT_ID.fullmatch(object_id)
        or not isinstance(binding.get("template_digest"), str)
        or not _DIGEST.fullmatch(str(binding["template_digest"]))
        or not isinstance(binding.get("signed_git_provenance_digest"), str)
        or not _DIGEST.fullmatch(str(binding["signed_git_provenance_digest"]))
        or not isinstance(binding.get("runtime_config_digest"), str)
        or not _DIGEST.fullmatch(str(binding["runtime_config_digest"]))
        or not isinstance(values, dict)
        or "release_digest" in values
        or values.get("release_id") != release_id
        or not isinstance(binding.get("release_digest"), str)
        or not _DIGEST.fullmatch(str(binding["release_digest"]))
    ):
        raise GateError("RELEASE_BINDING_INVALID")
    unsigned = {key: child for key, child in binding.items() if key != "release_digest"}
    if binding["release_digest"] != _digest(unsigned):
        raise GateError("RELEASE_BINDING_DIGEST_INVALID")
    return binding


def sign_release_binding(
    binding: Mapping[str, Any],
    private_key_file: Path,
    *,
    issuer: str,
    key_id: str,
    signed_at: datetime | None = None,
) -> dict[str, Any]:
    validated = validate_release_binding(binding)
    if not _IDENTIFIER.fullmatch(issuer) or not _KEY_ID.fullmatch(key_id):
        raise GateError("RELEASE_BINDING_SIGNER_IDENTITY_INVALID")
    signing_key = read_protected_ed25519_private_key(private_key_file)
    raw_time = signed_at or datetime.now(timezone.utc)
    if raw_time.tzinfo is None or raw_time.utcoffset() != timezone.utc.utcoffset(raw_time):
        raise GateError("RELEASE_BINDING_SIGNED_AT_INVALID")
    envelope: dict[str, Any] = {
        "schema_version": SIGNED_RELEASE_BINDING_SCHEMA_VERSION,
        "binding": dict(validated),
        "binding_digest": _digest(validated),
        "issuer": issuer,
        "key_id": key_id,
        "key_usage": RELEASE_BINDING_KEY_USAGE,
        "algorithm": RELEASE_BINDING_ALGORITHM,
        "signed_at": raw_time.astimezone(timezone.utc).isoformat(),
    }
    envelope["signature"] = _encode_base64url(
        signing_key.sign(canonical_json(_unsigned_envelope(envelope)))
    )
    return envelope


def verify_signed_release_binding(
    value: object,
    keyring_value: object,
    *,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    envelope = _strict_mapping(value, _ENVELOPE_FIELDS, "SIGNED_RELEASE_BINDING_INVALID")
    if (
        envelope.get("schema_version") != SIGNED_RELEASE_BINDING_SCHEMA_VERSION
        or envelope.get("key_usage") != RELEASE_BINDING_KEY_USAGE
        or envelope.get("algorithm") != RELEASE_BINDING_ALGORITHM
        or not isinstance(envelope.get("issuer"), str)
        or not _IDENTIFIER.fullmatch(str(envelope["issuer"]))
        or not isinstance(envelope.get("key_id"), str)
        or not _KEY_ID.fullmatch(str(envelope["key_id"]))
        or not isinstance(envelope.get("binding_digest"), str)
        or not _DIGEST.fullmatch(str(envelope["binding_digest"]))
        or not isinstance(envelope.get("signature"), str)
        or not _SIGNATURE.fullmatch(str(envelope["signature"]))
    ):
        raise GateError("SIGNED_RELEASE_BINDING_INVALID")
    binding = validate_release_binding(envelope.get("binding"))
    if envelope["binding_digest"] != _digest(binding):
        raise GateError("SIGNED_RELEASE_BINDING_DIGEST_INVALID")
    signed_at = _parse_utc(envelope.get("signed_at"), "SIGNED_RELEASE_BINDING_INVALID")
    raw_now = now or datetime.now(timezone.utc)
    if raw_now.tzinfo is None or raw_now.utcoffset() != timezone.utc.utcoffset(raw_now):
        raise GateError("SIGNED_RELEASE_BINDING_TIME_INVALID")
    current_time = raw_now.astimezone(timezone.utc)
    if signed_at > current_time:
        raise GateError("SIGNED_RELEASE_BINDING_TIME_INVALID")

    keyring = _strict_mapping(
        keyring_value, _KEYRING_FIELDS, "RELEASE_BINDING_KEYRING_INVALID"
    )
    keys = keyring.get("keys")
    if (
        keyring.get("schema_version") != RELEASE_BINDING_KEYRING_SCHEMA_VERSION
        or not isinstance(keys, list)
        or not 1 <= len(keys) <= 64
    ):
        raise GateError("RELEASE_BINDING_KEYRING_INVALID")
    matches: list[Mapping[str, Any]] = []
    identities: set[tuple[object, object, object]] = set()
    for raw_key in keys:
        key = _strict_mapping(raw_key, _KEY_FIELDS, "RELEASE_BINDING_KEYRING_INVALID")
        if (
            not isinstance(key.get("issuer"), str)
            or not _IDENTIFIER.fullmatch(str(key["issuer"]))
            or not isinstance(key.get("key_id"), str)
            or not _KEY_ID.fullmatch(str(key["key_id"]))
            or key.get("key_usage") != RELEASE_BINDING_KEY_USAGE
            or key.get("algorithm") != RELEASE_BINDING_ALGORITHM
            or key.get("status") not in {"ACTIVE", "REVOKED"}
            or not isinstance(key.get("public_key"), str)
            or not _PUBLIC_KEY.fullmatch(str(key["public_key"]))
        ):
            raise GateError("RELEASE_BINDING_KEYRING_INVALID")
        identity = (key["issuer"], key["key_id"], key["key_usage"])
        if identity in identities:
            raise GateError("RELEASE_BINDING_KEYRING_DUPLICATE")
        identities.add(identity)
        not_before = _parse_utc(key.get("not_before"), "RELEASE_BINDING_KEYRING_INVALID")
        not_after = _parse_utc(key.get("not_after"), "RELEASE_BINDING_KEYRING_INVALID")
        if not_before >= not_after:
            raise GateError("RELEASE_BINDING_KEYRING_INVALID")
        if identity == (envelope["issuer"], envelope["key_id"], envelope["key_usage"]):
            if (
                key["status"] != "ACTIVE"
                or not not_before <= signed_at <= not_after
                or not not_before <= current_time <= not_after
            ):
                raise GateError("RELEASE_BINDING_SIGNING_KEY_INACTIVE")
            matches.append(key)
    if len(matches) != 1:
        raise GateError("RELEASE_BINDING_SIGNING_KEY_NOT_TRUSTED")
    public_key = _decode_base64url(
        matches[0]["public_key"], 32, "RELEASE_BINDING_PUBLIC_KEY_INVALID"
    )
    signature = _decode_base64url(
        envelope["signature"], 64, "RELEASE_BINDING_SIGNATURE_INVALID"
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_json(_unsigned_envelope(envelope))
        )
    except (InvalidSignature, ValueError):
        raise GateError("RELEASE_BINDING_SIGNATURE_INVALID") from None
    return binding


def signed_release_binding_digest(value: object) -> str:
    envelope = _strict_mapping(value, _ENVELOPE_FIELDS, "SIGNED_RELEASE_BINDING_INVALID")
    return _digest(envelope)


def produce_signed_release_binding(
    repository: Path,
    template_path: Path,
    values: Mapping[str, Any],
    runtime_config: object,
    git_provenance: object,
    git_provenance_keyring: object,
    private_key_file: Path,
    *,
    issuer: str,
    key_id: str,
    signed_at: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    git_report = verify_signed_git_provenance(git_provenance, git_provenance_keyring)
    checks = git_report["checks"]
    if values.get("release_id") != checks.get("release_id"):
        raise GateError("RELEASE_BINDING_GIT_PROVENANCE_MISMATCH")
    expected_path = repository.resolve() / PRODUCTION_STACK_TEMPLATE_GIT_PATH
    if (
        not repository.is_absolute()
        or not template_path.is_absolute()
        or template_path.is_symlink()
        or template_path.resolve() != expected_path
        or not template_path.is_file()
    ):
        raise GateError("RELEASE_BINDING_TEMPLATE_PATH_INVALID")
    try:
        template_bytes = template_path.read_bytes()
        template = template_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise GateError("RELEASE_BINDING_TEMPLATE_INVALID") from None
    if not template_bytes or len(template_bytes) > 8_000_000:
        raise GateError("RELEASE_BINDING_TEMPLATE_INVALID")
    blob_object_id, committed_template = read_production_template_blob(
        repository,
        checks["commit_object_id"],
        checks["object_format"],
    )
    if committed_template != template_bytes:
        raise GateError("RELEASE_BINDING_TEMPLATE_NOT_FROM_COMMIT")
    binding = build_release_binding(
        template,
        values,
        runtime_config,
        provenance_digest=signed_git_provenance_digest(git_provenance),
        template_blob_object_id=blob_object_id,
    )
    envelope = sign_release_binding(
        binding,
        private_key_file,
        issuer=issuer,
        key_id=key_id,
        signed_at=signed_at,
    )
    finalized_values = json.loads(canonical_json(values))
    finalized_values["release_digest"] = binding["release_digest"]
    return envelope, finalized_values


def _read_json(path: Path, code: str) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError(code)
    try:
        if path.stat().st_size > 8_000_000:
            raise GateError(code)
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(code) from None


def _write_new(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists():
        raise GateError("RELEASE_BINDING_OUTPUT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-release-binding")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--runtime-config", type=Path, required=True)
    parser.add_argument("--git-provenance", type=Path, required=True)
    parser.add_argument("--git-provenance-keyring", type=Path, required=True)
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--finalized-values-output", type=Path, required=True)
    args = parser.parse_args(argv)
    values = _read_json(args.values, "RELEASE_BINDING_VALUES_INVALID")
    runtime_config = _read_json(args.runtime_config, "RELEASE_BINDING_RUNTIME_INVALID")
    provenance = _read_json(args.git_provenance, "RELEASE_BINDING_GIT_PROVENANCE_INVALID")
    provenance_keyring = _read_json(
        args.git_provenance_keyring, "RELEASE_BINDING_GIT_KEYRING_INVALID"
    )
    if not isinstance(values, dict):
        raise GateError("RELEASE_BINDING_VALUES_INVALID")
    envelope, finalized_values = produce_signed_release_binding(
        args.repository,
        args.template,
        values,
        runtime_config,
        provenance,
        provenance_keyring,
        args.signing_key_file,
        issuer=args.issuer,
        key_id=args.key_id,
    )
    if (
        args.output == args.finalized_values_output
        or not args.output.is_absolute()
        or not args.finalized_values_output.is_absolute()
        or args.output.exists()
        or args.finalized_values_output.exists()
    ):
        raise GateError("RELEASE_BINDING_OUTPUT_PATH_INVALID")
    _write_new(args.finalized_values_output, finalized_values)
    # Publish the authoritative signature last. A concurrent path race can leave
    # an unsigned finalized-values file, but never a signed binding without its
    # values counterpart.
    _write_new(args.output, envelope)
    print(json.dumps({
        "release_id": envelope["binding"]["release_id"],
        "release_digest": envelope["binding"]["release_digest"],
        "binding_digest": envelope["binding_digest"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
