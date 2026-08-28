"""Fail-closed intake for externally collected production qualification evidence.

The intake step does not create evidence.  It verifies that deployment-owned
trust roots accept a complete qualification package and that the package is
bound to the exact candidate image set and runtime configuration before it is
allowed to cross the CI artifact boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Mapping

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.production_evidence_bundle import PRODUCTION_IMAGE_KEYS
from python.production_gates.qualification import (
    QualificationTrustAnchors,
    compile_qualification,
    scope_digest,
)
from python.production_gates.release_activation import (
    ActivationError,
    validate_image_manifest,
)
from python.production_gates.revocation_checkpoint import verify_base_registry


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_REVOCATION_UPDATE_FIELDS = {
    "schema_version", "registry_id", "key_id", "base_checkpoint_digest",
    "valid_for_seconds", "new_entries",
}
_REVOCATION_ENTRY_FIELDS = {
    "certificate_id", "release_id", "reason_code", "evidence_digest", "revoked_at",
}
_PUBLIC_KEY_FIELDS = {"schema_version", "key_id", "public_key"}


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _validate_revocation_update(value: object, public_key: object) -> Mapping[str, Any]:
    update = _mapping(value, _REVOCATION_UPDATE_FIELDS, "EVIDENCE_INTAKE_REVOCATION_INVALID")
    key = _mapping(public_key, _PUBLIC_KEY_FIELDS, "EVIDENCE_INTAKE_REVOCATION_KEY_INVALID")
    entries = update.get("new_entries")
    if (
        update.get("schema_version")
        != "agenttrust.production-closure-revocation-update.v1"
        or not isinstance(update.get("registry_id"), str)
        or not _IDENTIFIER.fullmatch(str(update["registry_id"]))
        or update.get("key_id") != key.get("key_id")
        or not isinstance(update.get("base_checkpoint_digest"), str)
        or not _DIGEST.fullmatch(str(update["base_checkpoint_digest"]))
        or key.get("schema_version") != "agenttrust.ed25519-public-key.v1"
        or not isinstance(key.get("key_id"), str)
        or not _IDENTIFIER.fullmatch(str(key["key_id"]))
        or not isinstance(key.get("public_key"), str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", str(key["public_key"]))
        or not isinstance(update.get("valid_for_seconds"), int)
        or isinstance(update.get("valid_for_seconds"), bool)
        or not 300 <= int(update["valid_for_seconds"]) <= 604800
        or not isinstance(entries, list)
        or len(entries) > 10000
    ):
        raise GateError("EVIDENCE_INTAKE_REVOCATION_INVALID")
    identities: set[tuple[object, object]] = set()
    for raw_entry in entries:
        entry = _mapping(
            raw_entry, _REVOCATION_ENTRY_FIELDS, "EVIDENCE_INTAKE_REVOCATION_INVALID"
        )
        identity = (entry.get("certificate_id"), entry.get("release_id"))
        if (
            identity in identities
            or not isinstance(entry.get("certificate_id"), str)
            or not re.fullmatch(r"pc-[0-9a-f]{24}", str(entry["certificate_id"]))
            or not isinstance(entry.get("release_id"), str)
            or not _RELEASE_ID.fullmatch(str(entry["release_id"]))
            or not isinstance(entry.get("reason_code"), str)
            or not re.fullmatch(r"[A-Z0-9_]{1,128}", str(entry["reason_code"]))
            or not isinstance(entry.get("evidence_digest"), str)
            or not _DIGEST.fullmatch(str(entry["evidence_digest"]))
        ):
            raise GateError("EVIDENCE_INTAKE_REVOCATION_INVALID")
        _utc(entry.get("revoked_at"), "EVIDENCE_INTAKE_REVOCATION_INVALID")
        identities.add(identity)
    return update


def validate_evidence_intake(
    qualification_input: object,
    candidate_image_manifest: object,
    runtime_config: object,
    revocation_update: object,
    trust_anchors: QualificationTrustAnchors,
    revocation_public_key: object,
    *,
    revocation_checkpoint: object,
    previous_revocation_registry: object | None,
    expected_release_tag: str,
    expected_repository: str,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, object]]:
    """Return the derived ClosureInput and an intake receipt on exact agreement."""

    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None or checked_at.utcoffset() != timezone.utc.utcoffset(checked_at):
        raise GateError("EVIDENCE_INTAKE_TIME_INVALID")
    if not isinstance(qualification_input, dict):
        raise GateError("EVIDENCE_INTAKE_QUALIFICATION_INVALID")
    closure_input = compile_qualification(
        qualification_input, trust_anchors, now=checked_at
    )
    scope = closure_input.get("scope")
    release_binding = qualification_input.get("release_binding")
    binding = release_binding.get("binding") if isinstance(release_binding, dict) else None
    values = binding.get("static_values") if isinstance(binding, dict) else None
    images = values.get("images") if isinstance(values, dict) else None
    if not isinstance(scope, dict) or not isinstance(images, dict):
        raise GateError("EVIDENCE_INTAKE_RELEASE_BINDING_INVALID")
    try:
        manifest = validate_image_manifest(
            candidate_image_manifest, scope.get("release_id"), images, checked_at
        )
    except ActivationError:
        raise GateError("EVIDENCE_INTAKE_IMAGE_MANIFEST_INVALID") from None
    if (
        set(images) != PRODUCTION_IMAGE_KEYS
        or manifest.get("release_tag") != expected_release_tag
        or manifest.get("repository") != expected_repository
        or manifest.get("manifest_digest") != scope.get("build_digest")
        or binding.get("runtime_config_digest") != _digest(runtime_config)
        or scope.get("topology_digest") != _digest(runtime_config)
        or binding.get("release_id") != scope.get("release_id")
        or values.get("release_id") != scope.get("release_id")
    ):
        raise GateError("EVIDENCE_INTAKE_RELEASE_BINDING_INVALID")
    update = _validate_revocation_update(revocation_update, revocation_public_key)
    try:
        checkpoint = verify_base_registry(
            revocation_checkpoint,
            previous_revocation_registry,
            revocation_public_key,
        )
    except GateError as error:
        raise GateError("EVIDENCE_INTAKE_REVOCATION_CHECKPOINT_INVALID") from error
    previous_registry_digest = (
        _digest(previous_revocation_registry)
        if previous_revocation_registry is not None
        else None
    )
    if (
        update.get("registry_id") != checkpoint.get("registry_id")
        or update.get("key_id") != checkpoint.get("key_id")
        or update.get("base_checkpoint_digest") != checkpoint.get("checkpoint_digest")
    ):
        raise GateError("EVIDENCE_INTAKE_REVOCATION_CHECKPOINT_INVALID")
    receipt: dict[str, object] = {
        "schema_version": "agenttrust.production-evidence-intake-receipt.v1",
        "release_id": scope["release_id"],
        "scope_digest": scope_digest(scope),
        "qualification_input_digest": _digest(qualification_input),
        "closure_input_digest": _digest(closure_input),
        "production_image_manifest_digest": manifest["manifest_digest"],
        "runtime_config_digest": _digest(runtime_config),
        "revocation_update_digest": _digest(update),
        "revocation_checkpoint_digest": checkpoint["checkpoint_digest"],
        "revocation_checkpoint_sequence": checkpoint["sequence"],
        "revocation_registry_digest": checkpoint["registry_digest"],
        "previous_registry_artifact_digest": previous_registry_digest,
        "verified_at": checked_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verified": True,
    }
    receipt["receipt_digest"] = _digest(receipt)
    return closure_input, receipt
