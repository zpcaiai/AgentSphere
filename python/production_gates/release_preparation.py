"""Prepare mutually bound deployment activation documents without private keys."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.release_activation import validate_image_manifest
from python.production_gates.release_binding import signed_release_binding_digest


_CLOSURE_INPUT_FIELDS = {
    "schema_version", "scope", "batch_statuses", "gate_evidence",
    "residual_risks", "exceptions",
}
_SCOPE_FIELDS = {
    "release_id", "commit_digest", "signed_git_provenance_digest",
    "signed_release_binding_digest", "release_digest", "reviewer_keyring_digest",
    "build_digest", "policy_digest", "pack_set_digest", "prompt_set_digest",
    "model_set_digest", "topology_digest", "environment", "valid_from", "valid_until",
}
_EVIDENCE_MANIFEST_FIELDS = {
    "schema_version", "release_id", "scope_digest", "environment_reference",
    "created_at", "eligible", "production_certificate_included",
    "batch_evidence_verified", "condition_evidence_verified", "gate_evidence_verified",
    "trust_anchor_digests", "artifacts", "manifest_digest",
}


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def prepare_activation_documents(
    closure_input: object,
    image_manifest: object,
    evidence_manifest: object,
    release_binding: object,
    *,
    requested_at: datetime | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    now = requested_at or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise GateError("PRODUCTION_ACTIVATION_TIME_INVALID")
    input_value = _mapping(
        closure_input, _CLOSURE_INPUT_FIELDS, "PRODUCTION_ACTIVATION_INPUT_INVALID"
    )
    if input_value.get("schema_version") != "agenttrust.production-closure.v1":
        raise GateError("PRODUCTION_ACTIVATION_INPUT_INVALID")
    scope = _mapping(input_value.get("scope"), _SCOPE_FIELDS, "PRODUCTION_ACTIVATION_SCOPE_INVALID")
    scope_digest = _digest(scope)
    release_id = scope.get("release_id")
    if scope.get("environment") != "production":
        raise GateError("PRODUCTION_ACTIVATION_SCOPE_INVALID")
    if not isinstance(image_manifest, dict) or not isinstance(image_manifest.get("images"), dict):
        raise GateError("PRODUCTION_ACTIVATION_IMAGE_MANIFEST_INVALID")
    try:
        verified_images = validate_image_manifest(
            image_manifest, release_id, image_manifest["images"], now
        )
    except RuntimeError:
        raise GateError("PRODUCTION_ACTIVATION_IMAGE_MANIFEST_INVALID") from None
    evidence = _mapping(
        evidence_manifest,
        _EVIDENCE_MANIFEST_FIELDS,
        "PRODUCTION_ACTIVATION_EVIDENCE_MANIFEST_INVALID",
    )
    evidence_unsigned = dict(evidence)
    evidence_digest = evidence_unsigned.pop("manifest_digest", None)
    binding_digest = signed_release_binding_digest(release_binding)
    binding = release_binding.get("binding") if isinstance(release_binding, dict) else None
    if (
        evidence.get("schema_version") != "agenttrust.production-evidence-bundle.v1"
        or evidence.get("eligible") is not True
        or evidence.get("production_certificate_included") is not True
        or evidence.get("release_id") != release_id
        or evidence.get("scope_digest") != scope_digest
        or not isinstance(evidence_digest, str)
        or evidence_digest != _digest(evidence_unsigned)
        or scope.get("build_digest") != verified_images.get("manifest_digest")
        or scope.get("signed_release_binding_digest") != binding_digest
        or not isinstance(binding, dict)
        or binding.get("release_id") != release_id
        or binding.get("release_digest") != scope.get("release_digest")
    ):
        raise GateError("PRODUCTION_ACTIVATION_BINDING_INVALID")
    timestamp = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    activation: dict[str, object] = {
        "schema_version": "agenttrust.production-release-activation.v1",
        "release_id": release_id,
        "scope": dict(scope),
        "images": dict(verified_images["images"]),
        "production_image_manifest": dict(verified_images),
        "signed_release_binding_digest": binding_digest,
        "evidence_bundle_manifest_digest": evidence_digest,
        "requested_at": timestamp,
    }
    expectation: dict[str, object] = {
        "schema_version": "agenttrust.production-closure-activation-expectation.v1",
        "release_id": release_id,
        "scope_digest": scope_digest,
        "build_digest": scope["build_digest"],
        "release_digest": scope["release_digest"],
        "topology_digest": scope["topology_digest"],
    }
    return activation, expectation
