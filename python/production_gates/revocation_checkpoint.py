"""Deployment-owned monotonic checkpoint for closure revocation registries.

The signing workflow is not authoritative for registry history.  A checkpoint
is initialized exactly once by deployment operations and every later registry
must be its direct, signed successor.  The release workflow advances the file
with a compare-and-swap after activation verification succeeds.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


SCHEMA_VERSION = "agenttrust.production-revocation-checkpoint.v1"
RECEIPT_SCHEMA_VERSION = "agenttrust.production-revocation-checkpoint-cas.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")
_CHECKPOINT_FIELDS = {
    "schema_version",
    "registry_id",
    "key_id",
    "sequence",
    "registry_digest",
    "updated_at",
    "checkpoint_digest",
}
_REGISTRY_FIELDS = {
    "schema_version",
    "registry_id",
    "sequence",
    "previous_registry_digest",
    "published_at",
    "expires_at",
    "key_id",
    "entries",
    "signature",
}
_KEY_FIELDS = {"schema_version", "key_id", "public_key"}
MAXIMUM_INPUT_BYTES = 64 * 1024 * 1024


def _duplicate_key(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GateError("REVOCATION_CHECKPOINT_DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def checkpoint_digest(value: Mapping[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("checkpoint_digest", None)
    return _digest(unsigned)


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(code) from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def validate_checkpoint(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CHECKPOINT_FIELDS:
        raise GateError("REVOCATION_CHECKPOINT_INVALID")
    sequence = value.get("sequence")
    registry_digest = value.get("registry_digest")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("registry_id"), str)
        or not _IDENTIFIER.fullmatch(str(value["registry_id"]))
        or not isinstance(value.get("key_id"), str)
        or not _IDENTIFIER.fullmatch(str(value["key_id"]))
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or (sequence == 0 and registry_digest is not None)
        or (
            sequence > 0
            and (not isinstance(registry_digest, str) or not _DIGEST.fullmatch(registry_digest))
        )
        or not isinstance(value.get("checkpoint_digest"), str)
        or value.get("checkpoint_digest") != checkpoint_digest(value)
    ):
        raise GateError("REVOCATION_CHECKPOINT_INVALID")
    _utc(value.get("updated_at"), "REVOCATION_CHECKPOINT_INVALID")
    return value


def genesis_checkpoint(
    *, registry_id: str, key_id: str, initialized_at: datetime | None = None
) -> dict[str, object]:
    now = initialized_at or datetime.now(timezone.utc)
    if (
        now.utcoffset() != timezone.utc.utcoffset(now)
        or not _IDENTIFIER.fullmatch(registry_id)
        or not _IDENTIFIER.fullmatch(key_id)
    ):
        raise GateError("REVOCATION_CHECKPOINT_GENESIS_INVALID")
    checkpoint: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "registry_id": registry_id,
        "key_id": key_id,
        "sequence": 0,
        "registry_digest": None,
        "updated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "checkpoint_digest": "",
    }
    checkpoint["checkpoint_digest"] = checkpoint_digest(checkpoint)
    return checkpoint


def _decode_public_key(value: object) -> Ed25519PublicKey:
    if not isinstance(value, str):
        raise GateError("REVOCATION_CHECKPOINT_KEY_INVALID")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError):
        raise GateError("REVOCATION_CHECKPOINT_KEY_INVALID") from None
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise GateError("REVOCATION_CHECKPOINT_KEY_INVALID")
    return Ed25519PublicKey.from_public_bytes(decoded)


def _verify_registry(registry: object, public_key: object) -> Mapping[str, Any]:
    if not isinstance(registry, Mapping) or set(registry) != _REGISTRY_FIELDS:
        raise GateError("REVOCATION_CHECKPOINT_REGISTRY_INVALID")
    if not isinstance(public_key, Mapping) or set(public_key) != _KEY_FIELDS:
        raise GateError("REVOCATION_CHECKPOINT_KEY_INVALID")
    signature = registry.get("signature")
    sequence = registry.get("sequence")
    previous = registry.get("previous_registry_digest")
    published_at = _utc(
        registry.get("published_at"), "REVOCATION_CHECKPOINT_REGISTRY_INVALID"
    )
    expires_at = _utc(
        registry.get("expires_at"), "REVOCATION_CHECKPOINT_REGISTRY_INVALID"
    )
    now = datetime.now(timezone.utc)
    entries = registry.get("entries")
    if (
        registry.get("schema_version")
        != "agenttrust.production-closure-revocation-registry.v1"
        or public_key.get("schema_version") != "agenttrust.ed25519-public-key.v1"
        or registry.get("key_id") != public_key.get("key_id")
        or not isinstance(registry.get("registry_id"), str)
        or not _IDENTIFIER.fullmatch(str(registry["registry_id"]))
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or (sequence == 1 and previous is not None)
        or (
            sequence > 1
            and (not isinstance(previous, str) or not _DIGEST.fullmatch(previous))
        )
        or not isinstance(signature, str)
        or not _SIGNATURE.fullmatch(signature)
        or not isinstance(entries, list)
        or len(entries) > 100_000
        or published_at > now
        or expires_at <= now
        or expires_at <= published_at
        or (expires_at - published_at).total_seconds() > 7 * 86400
    ):
        raise GateError("REVOCATION_CHECKPOINT_REGISTRY_INVALID")
    previous_certificate_id = ""
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {
            "certificate_id",
            "release_id",
            "reason_code",
            "evidence_digest",
            "revoked_at",
        }:
            raise GateError("REVOCATION_CHECKPOINT_REGISTRY_INVALID")
        certificate_id = entry.get("certificate_id")
        revoked_at = _utc(
            entry.get("revoked_at"), "REVOCATION_CHECKPOINT_REGISTRY_INVALID"
        )
        if (
            not isinstance(certificate_id, str)
            or not re.fullmatch(r"pc-[0-9a-f]{24}", certificate_id)
            or certificate_id <= previous_certificate_id
            or not isinstance(entry.get("release_id"), str)
            or not re.fullmatch(
                r"git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})",
                str(entry["release_id"]),
            )
            or not isinstance(entry.get("reason_code"), str)
            or not re.fullmatch(r"[A-Z0-9_]{1,128}", str(entry["reason_code"]))
            or not isinstance(entry.get("evidence_digest"), str)
            or not _DIGEST.fullmatch(str(entry["evidence_digest"]))
            or revoked_at > published_at
        ):
            raise GateError("REVOCATION_CHECKPOINT_REGISTRY_INVALID")
        previous_certificate_id = certificate_id
    unsigned = dict(registry)
    unsigned["signature"] = ""
    try:
        signature_bytes = base64.b64decode(
            signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True
        )
        if len(signature_bytes) != 64:
            raise ValueError("invalid Ed25519 signature length")
        _decode_public_key(public_key.get("public_key")).verify(
            signature_bytes, canonical_json(unsigned)
        )
    except (InvalidSignature, TypeError, ValueError):
        raise GateError("REVOCATION_CHECKPOINT_REGISTRY_SIGNATURE_INVALID") from None
    return registry


def verify_base_registry(
    checkpoint: object,
    previous_registry: object | None,
    public_key: object,
) -> Mapping[str, Any]:
    current = validate_checkpoint(checkpoint)
    if current["sequence"] == 0:
        if previous_registry is not None:
            raise GateError("REVOCATION_CHECKPOINT_GENESIS_BASE_INVALID")
        return current
    if previous_registry is None:
        raise GateError("REVOCATION_CHECKPOINT_PREVIOUS_REGISTRY_REQUIRED")
    previous = _verify_registry(previous_registry, public_key)
    if (
        previous.get("registry_id") != current.get("registry_id")
        or previous.get("key_id") != current.get("key_id")
        or previous.get("sequence") != current.get("sequence")
        or _digest(previous) != current.get("registry_digest")
    ):
        raise GateError("REVOCATION_CHECKPOINT_BASE_MISMATCH")
    return current


def verify_successor(
    checkpoint: object, registry: object, public_key: object
) -> tuple[Mapping[str, Any], Mapping[str, Any], str]:
    current = validate_checkpoint(checkpoint)
    successor = _verify_registry(registry, public_key)
    expected_previous = current.get("registry_digest") if current["sequence"] else None
    registry_digest = _digest(successor)
    if (
        successor.get("registry_id") != current.get("registry_id")
        or successor.get("key_id") != current.get("key_id")
        or successor.get("sequence") != current["sequence"] + 1
        or successor.get("previous_registry_digest") != expected_previous
    ):
        raise GateError("REVOCATION_CHECKPOINT_SUCCESSOR_INVALID")
    return current, successor, registry_digest


def next_checkpoint(
    checkpoint: object,
    registry: object,
    public_key: object,
    *,
    updated_at: datetime | None = None,
) -> dict[str, object]:
    current, successor, registry_digest = verify_successor(
        checkpoint, registry, public_key
    )
    now = updated_at or datetime.now(timezone.utc)
    if now.utcoffset() != timezone.utc.utcoffset(now):
        raise GateError("REVOCATION_CHECKPOINT_TIME_INVALID")
    if now < _utc(successor.get("published_at"), "REVOCATION_CHECKPOINT_REGISTRY_INVALID"):
        raise GateError("REVOCATION_CHECKPOINT_TIME_INVALID")
    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "registry_id": current["registry_id"],
        "key_id": current["key_id"],
        "sequence": successor["sequence"],
        "registry_digest": registry_digest,
        "updated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "checkpoint_digest": "",
    }
    value["checkpoint_digest"] = checkpoint_digest(value)
    return value


def _secure_json(path: Path, *, mutable: bool = False) -> tuple[Mapping[str, Any], bytes]:
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise GateError("REVOCATION_CHECKPOINT_PATH_INVALID")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata_value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata_value.st_mode)
            or metadata_value.st_nlink != 1
            or metadata_value.st_mode & 0o022
            or not 1 <= metadata_value.st_size <= MAXIMUM_INPUT_BYTES
            or (not mutable and os.access(path, os.W_OK))
        ):
            raise GateError("REVOCATION_CHECKPOINT_PATH_INVALID")
        raw = b""
        while len(raw) <= MAXIMUM_INPUT_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAXIMUM_INPUT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(descriptor)
    if not raw or len(raw) > MAXIMUM_INPUT_BYTES:
        raise GateError("REVOCATION_CHECKPOINT_INPUT_INVALID")
    try:
        value = json.loads(raw, object_pairs_hook=_duplicate_key)
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GateError("REVOCATION_CHECKPOINT_INPUT_INVALID") from None
    if not isinstance(value, dict):
        raise GateError("REVOCATION_CHECKPOINT_INPUT_INVALID")
    return value, raw


def read_checkpoint(path: Path, *, mutable: bool = False) -> Mapping[str, Any]:
    value, raw = _secure_json(path, mutable=mutable)
    if raw != canonical_json(value) + b"\n":
        raise GateError("REVOCATION_CHECKPOINT_NOT_CANONICAL")
    return validate_checkpoint(value)


def _write_exclusive(path: Path, value: object, mode: int) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise GateError("REVOCATION_CHECKPOINT_OUTPUT_INVALID")
    parent = path.parent.resolve(strict=True)
    if parent == Path("/") or parent.is_symlink():
        raise GateError("REVOCATION_CHECKPOINT_OUTPUT_INVALID")
    raw = canonical_json(value) + b"\n"
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GateError("REVOCATION_CHECKPOINT_OUTPUT_INVALID")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def initialize_checkpoint_file(
    path: Path,
    lock_path: Path,
    *,
    registry_id: str,
    key_id: str,
    initialized_at: datetime | None = None,
) -> Mapping[str, Any]:
    value = genesis_checkpoint(
        registry_id=registry_id, key_id=key_id, initialized_at=initialized_at
    )
    if not lock_path.is_absolute() or lock_path.exists() or lock_path.is_symlink():
        raise GateError("REVOCATION_CHECKPOINT_LOCK_INVALID")
    lock_descriptor = os.open(
        lock_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o440,
    )
    try:
        os.write(lock_descriptor, b"agenttrust-revocation-checkpoint-lock-v1\n")
        os.fsync(lock_descriptor)
    finally:
        os.close(lock_descriptor)
    try:
        _write_exclusive(path, value, 0o640)
    except BaseException:
        lock_path.unlink(missing_ok=True)
        raise
    return value


def advance_checkpoint_file(
    checkpoint_path: Path,
    lock_path: Path,
    registry: object,
    public_key: object,
    activation_receipt: object,
    *,
    expected_checkpoint_digest: str,
    updated_at: datetime | None = None,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not _DIGEST.fullmatch(expected_checkpoint_digest):
        raise GateError("REVOCATION_CHECKPOINT_EXPECTATION_INVALID")
    if not lock_path.is_absolute() or lock_path.is_symlink() or lock_path.resolve() != lock_path:
        raise GateError("REVOCATION_CHECKPOINT_LOCK_INVALID")
    lock_descriptor = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        lock_metadata = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_mode & 0o022
        ):
            raise GateError("REVOCATION_CHECKPOINT_LOCK_INVALID")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current = read_checkpoint(checkpoint_path, mutable=True)
        registry_value = _verify_registry(registry, public_key)
        registry_digest = _digest(registry_value)
        replay = current.get("checkpoint_digest") != expected_checkpoint_digest
        if replay:
            if (
                current.get("registry_id") != registry_value.get("registry_id")
                or current.get("key_id") != registry_value.get("key_id")
                or current.get("sequence") != registry_value.get("sequence")
                or current.get("registry_digest") != registry_digest
            ):
                raise GateError("REVOCATION_CHECKPOINT_CAS_CONFLICT")
            successor = dict(current)
        else:
            successor = next_checkpoint(
                current, registry_value, public_key, updated_at=updated_at
            )
        if (
            not isinstance(activation_receipt, Mapping)
            or activation_receipt.get("schema_version")
            != "agenttrust.production-release-activation-receipt.v1"
            or activation_receipt.get("admitted") is not True
            or activation_receipt.get("revocation_registry_id")
            != successor["registry_id"]
            or activation_receipt.get("revocation_registry_sequence")
            != successor["sequence"]
            or activation_receipt.get("revocation_registry_digest") != registry_digest
        ):
            raise GateError("REVOCATION_CHECKPOINT_ACTIVATION_RECEIPT_INVALID")
        if not replay:
            raw = canonical_json(successor) + b"\n"
            parent = checkpoint_path.parent.resolve(strict=True)
            temporary = parent / f".{checkpoint_path.name}.{os.getpid()}.cas"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o640,
            )
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise GateError("REVOCATION_CHECKPOINT_OUTPUT_INVALID")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary, checkpoint_path)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
            directory = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        receipt: dict[str, object] = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "registry_id": successor["registry_id"],
            "previous_sequence": int(successor["sequence"]) - 1,
            "sequence": successor["sequence"],
            "previous_checkpoint_digest": expected_checkpoint_digest,
            "checkpoint_digest": successor["checkpoint_digest"],
            "registry_digest": registry_digest,
            "advanced_at": successor["updated_at"],
        }
        receipt["receipt_digest"] = _digest(receipt)
        return successor, receipt
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
