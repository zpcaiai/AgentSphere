"""Fail-closed production release activation verification.

This module is deliberately private-key-free.  It verifies that the exact
release scope, eligible closure report, Production Closure Certificate, and
current signed revocation registry all agree before a deployment renderer or
admission job may enable production traffic or writes.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.qualification import GATE_CONDITION_REQUIREMENTS


class ActivationError(RuntimeError):
    """Stable fail-closed activation error."""


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_CERTIFICATE_ID = re.compile(r"^pc-[0-9a-f]{24}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_URL = re.compile(r"^https://[^\s]+$")
PRODUCTION_IMAGE_KEYS = frozenset({
    "runtime", "orchestrator", "transition", "execution", "registry",
    "agent_registry", "policy_admin", "incident_release", "pack_marketplace",
    "approval", "pep", "identity", "tool_proxy", "evidence", "audit",
    "enterprise", "enterprise_authority", "model_gateway", "data_governance",
    "context_governance", "runtime_anomaly", "security_evaluation",
    "pack_supply_chain", "domain_runtime", "platform_sre", "console",
    "migration", "envoy", "utility", "release_admission", "sandbox_worker",
})
REQUIRED_PRODUCTION_GATES = frozenset(GATE_CONDITION_REQUIREMENTS)

_SCOPE_FIELDS = {
    "release_id",
    "commit_digest",
    "build_digest",
    "signed_git_provenance_digest",
    "signed_release_binding_digest",
    "release_digest",
    "reviewer_keyring_digest",
    "policy_digest",
    "pack_set_digest",
    "prompt_set_digest",
    "model_set_digest",
    "topology_digest",
    "environment",
    "valid_from",
    "valid_until",
}
_REPORT_FIELDS = {
    "schema_version",
    "release_id",
    "scope_digest",
    "input_digest",
    "eligible",
    "blockers",
    "verified_gate_digests",
    "evaluated_at",
    "evidence_valid_until",
    "report_digest",
}
_CERTIFICATE_FIELDS = {
    "schema_version",
    "certificate_id",
    "release_id",
    "scope_digest",
    "input_digest",
    "report_digest",
    "signed_git_provenance_digest",
    "signed_release_binding_digest",
    "release_digest",
    "reviewer_keyring_digest",
    "production_closure",
    "issued_at",
    "expires_at",
    "key_id",
    "signature",
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
_ACTIVATION_FIELDS = {
    "schema_version",
    "release_id",
    "scope",
    "images",
    "production_image_manifest",
    "signed_release_binding_digest",
    "evidence_bundle_manifest_digest",
    "requested_at",
}
_IMAGE_MANIFEST_FIELDS = {
    "schema_version", "release_id", "release_tag", "repository", "created_at",
    "images", "attestations", "manifest_digest",
}
_IMAGE_ATTESTATION_FIELDS = {
    "component", "subject_digest", "sbom_sha256",
    "provenance_attestation_url", "sbom_attestation_url",
}
_REVOCATION_FIELDS = {
    "certificate_id", "release_id", "reason_code", "evidence_digest", "revoked_at",
}


def _require_exact(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ActivationError(code)
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_json_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise ActivationError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ActivationError(code) from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ActivationError(code)
    return parsed


def _decode_base64url(value: object, length: int, code: str) -> bytes:
    if not isinstance(value, str):
        raise ActivationError(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError):
        raise ActivationError(code) from None
    encoded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != length or encoded != value:
        raise ActivationError(code)
    return decoded


def _public_key(spec: object, expected_key_id: object, code: str) -> Ed25519PublicKey:
    value = _require_exact(spec, _KEY_FIELDS, code)
    key_id = value.get("key_id")
    if (
        value.get("schema_version") != "agenttrust.ed25519-public-key.v1"
        or not isinstance(key_id, str)
        or not _KEY_ID.fullmatch(key_id)
        or key_id != expected_key_id
    ):
        raise ActivationError(code)
    try:
        return Ed25519PublicKey.from_public_bytes(
            _decode_base64url(value.get("public_key"), 32, code)
        )
    except ValueError:
        raise ActivationError(code) from None


def _verify_signature(
    document: Mapping[str, Any], key: Ed25519PublicKey, code: str
) -> None:
    unsigned = dict(document)
    signature = _decode_base64url(unsigned.get("signature"), 64, code)
    unsigned["signature"] = ""
    try:
        key.verify(signature, canonical_json(unsigned))
    except InvalidSignature:
        raise ActivationError(code) from None


def validate_image_manifest(
    value: object, release_id: object, images: object, checked_at: datetime
) -> Mapping[str, Any]:
    manifest = _require_exact(
        value, _IMAGE_MANIFEST_FIELDS, "ACTIVATION_IMAGE_MANIFEST_INVALID"
    )
    manifest_images = manifest.get("images")
    attestations = manifest.get("attestations")
    unsigned = dict(manifest)
    claimed_digest = unsigned.pop("manifest_digest", None)
    created_at = _parse_utc(
        manifest.get("created_at"), "ACTIVATION_IMAGE_MANIFEST_INVALID"
    )
    if (
        manifest.get("schema_version") != "agenttrust.production-image-manifest.v1"
        or manifest.get("release_id") != release_id
        or created_at > checked_at
        or not isinstance(manifest.get("release_tag"), str)
        or not isinstance(manifest.get("repository"), str)
        or not isinstance(manifest_images, Mapping)
        or set(manifest_images) != PRODUCTION_IMAGE_KEYS
        or manifest_images != images
        or not isinstance(attestations, Mapping)
        or set(attestations) != PRODUCTION_IMAGE_KEYS
        or not isinstance(claimed_digest, str)
        or not _DIGEST.fullmatch(claimed_digest)
        or claimed_digest != _digest(unsigned)
    ):
        raise ActivationError("ACTIVATION_IMAGE_MANIFEST_INVALID")
    for name, image in manifest_images.items():
        attestation = _require_exact(
            attestations.get(name),
            _IMAGE_ATTESTATION_FIELDS,
            "ACTIVATION_IMAGE_MANIFEST_INVALID",
        )
        subject_digest = attestation.get("subject_digest")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or not isinstance(image, str)
            or not _IMAGE.fullmatch(image)
            or not isinstance(subject_digest, str)
            or subject_digest != image.rsplit("@", 1)[1]
            or not isinstance(attestation.get("component"), str)
            or not attestation["component"]
            or not isinstance(attestation.get("sbom_sha256"), str)
            or not _DIGEST.fullmatch(attestation["sbom_sha256"])
            or not isinstance(attestation.get("provenance_attestation_url"), str)
            or not _URL.fullmatch(attestation["provenance_attestation_url"])
            or not isinstance(attestation.get("sbom_attestation_url"), str)
            or not _URL.fullmatch(attestation["sbom_attestation_url"])
        ):
            raise ActivationError("ACTIVATION_IMAGE_MANIFEST_INVALID")
    return manifest


def activation_material_digest(activation: Mapping[str, Any]) -> str:
    images = activation.get("images")
    if (
        not isinstance(images, Mapping)
        or set(images) != PRODUCTION_IMAGE_KEYS
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or not isinstance(image, str)
            or not _IMAGE.fullmatch(image)
            for name, image in images.items()
        )
    ):
        raise ActivationError("ACTIVATION_IMAGES_INVALID")
    release_binding = activation.get("signed_release_binding_digest")
    image_manifest = activation.get("production_image_manifest")
    image_manifest_digest = (
        image_manifest.get("manifest_digest") if isinstance(image_manifest, Mapping) else None
    )
    evidence_bundle = activation.get("evidence_bundle_manifest_digest")
    if (
        not isinstance(release_binding, str)
        or not _DIGEST.fullmatch(release_binding)
        or not isinstance(evidence_bundle, str)
        or not _DIGEST.fullmatch(evidence_bundle)
        or not isinstance(image_manifest_digest, str)
        or not _DIGEST.fullmatch(image_manifest_digest)
    ):
        raise ActivationError("ACTIVATION_MATERIAL_INVALID")
    return _digest(
        {
            "images": dict(sorted(images.items())),
            "production_image_manifest_digest": image_manifest_digest,
            "signed_release_binding_digest": release_binding,
            "evidence_bundle_manifest_digest": evidence_bundle,
        }
    )


def verify_activation_documents(
    *,
    activation: object,
    report: object,
    certificate: object,
    certificate_key: object,
    revocation_registry: object,
    revocation_key: object,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify all production activation inputs and return an auditable receipt."""

    checked_at = now or datetime.now(timezone.utc)
    if checked_at.utcoffset() != timezone.utc.utcoffset(checked_at):
        raise ActivationError("ACTIVATION_TIME_INVALID")

    activation_value = _require_exact(
        activation, _ACTIVATION_FIELDS, "ACTIVATION_DOCUMENT_INVALID"
    )
    scope = _require_exact(
        activation_value.get("scope"), _SCOPE_FIELDS, "ACTIVATION_SCOPE_INVALID"
    )
    report_value = _require_exact(report, _REPORT_FIELDS, "ACTIVATION_REPORT_INVALID")
    certificate_value = _require_exact(
        certificate, _CERTIFICATE_FIELDS, "ACTIVATION_CERTIFICATE_INVALID"
    )
    registry = _require_exact(
        revocation_registry, _REGISTRY_FIELDS, "ACTIVATION_REGISTRY_INVALID"
    )

    release_id = activation_value.get("release_id")
    scope_release_id = scope.get("release_id")
    if (
        activation_value.get("schema_version")
        != "agenttrust.production-release-activation.v1"
        or not isinstance(release_id, str)
        or not _RELEASE_ID.fullmatch(release_id)
        or release_id != scope_release_id
        or scope.get("environment") != "production"
    ):
        raise ActivationError("ACTIVATION_RELEASE_INVALID")
    requested_at = _parse_utc(
        activation_value.get("requested_at"), "ACTIVATION_REQUEST_TIME_INVALID"
    )
    valid_from = _parse_utc(scope.get("valid_from"), "ACTIVATION_SCOPE_TIME_INVALID")
    valid_until = _parse_utc(scope.get("valid_until"), "ACTIVATION_SCOPE_TIME_INVALID")
    if requested_at > checked_at or valid_from > checked_at or valid_until <= checked_at:
        raise ActivationError("ACTIVATION_SCOPE_TIME_INVALID")
    for field in (
        "commit_digest",
        "build_digest",
        "signed_git_provenance_digest",
        "signed_release_binding_digest",
        "release_digest",
        "reviewer_keyring_digest",
        "policy_digest",
        "pack_set_digest",
        "prompt_set_digest",
        "model_set_digest",
        "topology_digest",
    ):
        if not isinstance(scope.get(field), str) or not _DIGEST.fullmatch(scope[field]):
            raise ActivationError("ACTIVATION_SCOPE_INVALID")

    manifest = validate_image_manifest(
        activation_value.get("production_image_manifest"),
        release_id,
        activation_value.get("images"),
        checked_at,
    )
    material_digest = activation_material_digest(activation_value)
    if (
        scope.get("build_digest") != manifest.get("manifest_digest")
        or activation_value.get("signed_release_binding_digest")
        != scope.get("signed_release_binding_digest")
        or not isinstance(activation_value.get("evidence_bundle_manifest_digest"), str)
        or not _DIGEST.fullmatch(activation_value["evidence_bundle_manifest_digest"])
    ):
        raise ActivationError("ACTIVATION_BUILD_DIGEST_MISMATCH")
    scope_digest = _digest(scope)

    report_digest = report_value.get("report_digest")
    input_digest = report_value.get("input_digest")
    evidence_valid_until = _parse_utc(
        report_value.get("evidence_valid_until"), "ACTIVATION_REPORT_INVALID"
    )
    unsigned_report = dict(report_value)
    unsigned_report["report_digest"] = ""
    if (
        report_value.get("schema_version") != "agenttrust.production-closure.v1"
        or report_value.get("release_id") != release_id
        or report_value.get("scope_digest") != scope_digest
        or report_value.get("eligible") is not True
        or report_value.get("blockers") != []
        or not isinstance(input_digest, str)
        or not _DIGEST.fullmatch(input_digest)
        or evidence_valid_until <= checked_at
        or evidence_valid_until > valid_until
        or not isinstance(report_digest, str)
        or report_digest != _digest(unsigned_report)
    ):
        raise ActivationError("ACTIVATION_REPORT_INVALID")
    gate_digests = report_value.get("verified_gate_digests")
    if (
        not isinstance(gate_digests, Mapping)
        or set(gate_digests) != REQUIRED_PRODUCTION_GATES
        or any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in gate_digests.values())
    ):
        raise ActivationError("ACTIVATION_GATES_INVALID")

    certificate_key_value = _public_key(
        certificate_key,
        certificate_value.get("key_id"),
        "ACTIVATION_CERTIFICATE_KEY_INVALID",
    )
    issued_at = _parse_utc(
        certificate_value.get("issued_at"), "ACTIVATION_CERTIFICATE_TIME_INVALID"
    )
    expires_at = _parse_utc(
        certificate_value.get("expires_at"), "ACTIVATION_CERTIFICATE_TIME_INVALID"
    )
    certificate_id = certificate_value.get("certificate_id")
    if (
        certificate_value.get("schema_version") != "agenttrust.production-closure.v1"
        or certificate_value.get("production_closure") is not True
        or certificate_value.get("release_id") != release_id
        or certificate_value.get("scope_digest") != scope_digest
        or certificate_value.get("input_digest") != input_digest
        or certificate_value.get("report_digest") != report_digest
        or certificate_value.get("signed_git_provenance_digest")
        != scope.get("signed_git_provenance_digest")
        or certificate_value.get("signed_release_binding_digest")
        != scope.get("signed_release_binding_digest")
        or certificate_value.get("release_digest") != scope.get("release_digest")
        or certificate_value.get("reviewer_keyring_digest")
        != scope.get("reviewer_keyring_digest")
        or not isinstance(certificate_id, str)
        or not _CERTIFICATE_ID.fullmatch(certificate_id)
        or certificate_id != f"pc-{str(report_digest)[:24]}"
        or issued_at > checked_at
        or issued_at < _parse_utc(report_value.get("evaluated_at"), "ACTIVATION_REPORT_INVALID")
        or expires_at <= checked_at
        or expires_at != evidence_valid_until
    ):
        raise ActivationError("ACTIVATION_CERTIFICATE_INVALID")
    _verify_signature(
        certificate_value, certificate_key_value, "ACTIVATION_CERTIFICATE_SIGNATURE_INVALID"
    )

    registry_key_value = _public_key(
        revocation_key, registry.get("key_id"), "ACTIVATION_REGISTRY_KEY_INVALID"
    )
    published_at = _parse_utc(
        registry.get("published_at"), "ACTIVATION_REGISTRY_TIME_INVALID"
    )
    registry_expires_at = _parse_utc(
        registry.get("expires_at"), "ACTIVATION_REGISTRY_TIME_INVALID"
    )
    sequence = registry.get("sequence")
    previous = registry.get("previous_registry_digest")
    if (
        registry.get("schema_version")
        != "agenttrust.production-closure-revocation-registry.v1"
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or (sequence == 1 and previous is not None)
        or (sequence > 1 and (not isinstance(previous, str) or not _DIGEST.fullmatch(previous)))
        or published_at > checked_at
        or published_at < issued_at
        or registry_expires_at <= checked_at
        or (registry_expires_at - published_at).total_seconds() > 7 * 86400
    ):
        raise ActivationError("ACTIVATION_REGISTRY_INVALID")
    entries = registry.get("entries")
    if not isinstance(entries, list) or len(entries) > 100_000:
        raise ActivationError("ACTIVATION_REGISTRY_INVALID")
    previous_id = ""
    for entry in entries:
        entry = _require_exact(entry, _REVOCATION_FIELDS, "ACTIVATION_REGISTRY_INVALID")
        entry_id = entry.get("certificate_id")
        revoked_at = _parse_utc(entry.get("revoked_at"), "ACTIVATION_REGISTRY_INVALID")
        if (
            not isinstance(entry_id, str)
            or not _CERTIFICATE_ID.fullmatch(entry_id)
            or entry_id <= previous_id
            or not isinstance(entry.get("release_id"), str)
            or not _RELEASE_ID.fullmatch(entry["release_id"])
            or not isinstance(entry.get("reason_code"), str)
            or not re.fullmatch(r"[A-Z0-9_]{1,128}", entry["reason_code"])
            or not isinstance(entry.get("evidence_digest"), str)
            or not _DIGEST.fullmatch(entry["evidence_digest"])
            or revoked_at > published_at
        ):
            raise ActivationError("ACTIVATION_REGISTRY_INVALID")
        previous_id = entry_id
        if entry_id == certificate_id:
            if entry.get("release_id") != release_id:
                raise ActivationError("ACTIVATION_REGISTRY_INVALID")
            raise ActivationError("ACTIVATION_CERTIFICATE_REVOKED")
    _verify_signature(registry, registry_key_value, "ACTIVATION_REGISTRY_SIGNATURE_INVALID")

    registry_digest = _digest(registry)
    return {
        "schema_version": "agenttrust.production-release-activation-receipt.v1",
        "admitted": True,
        "release_id": release_id,
        "certificate_id": certificate_id,
        "scope_digest": scope_digest,
        "input_digest": input_digest,
        "report_digest": report_digest,
        "production_image_manifest_digest": manifest["manifest_digest"],
        "evidence_bundle_manifest_digest": activation_value[
            "evidence_bundle_manifest_digest"
        ],
        "activation_material_digest": material_digest,
        "revocation_registry_id": registry.get("registry_id"),
        "revocation_registry_sequence": sequence,
        "revocation_registry_digest": registry_digest,
        "verified_at": checked_at.isoformat().replace("+00:00", "Z"),
        "valid_until": min(expires_at, registry_expires_at).isoformat().replace(
            "+00:00", "Z"
        ),
    }


def _read_json(path: Path) -> object:
    if not path.is_absolute() or path.is_symlink():
        raise ActivationError("ACTIVATION_INPUT_PATH_INVALID")
    stat = path.stat()
    if not path.is_file() or stat.st_nlink != 1 or stat.st_size <= 0 or stat.st_size > 32 * 1024 * 1024:
        raise ActivationError("ACTIVATION_INPUT_INVALID")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_members,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise ActivationError("ACTIVATION_INPUT_INVALID") from None


def _write_new(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ActivationError("ACTIVATION_OUTPUT_INVALID")
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
    except OSError:
        raise ActivationError("ACTIVATION_OUTPUT_INVALID") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-release-activation")
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--certificate-key", type=Path, required=True)
    parser.add_argument("--revocation-registry", type=Path, required=True)
    parser.add_argument("--revocation-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = verify_activation_documents(
        activation=_read_json(args.activation),
        report=_read_json(args.report),
        certificate=_read_json(args.certificate),
        certificate_key=_read_json(args.certificate_key),
        revocation_registry=_read_json(args.revocation_registry),
        revocation_key=_read_json(args.revocation_key),
    )
    _write_new(args.output, receipt)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ActivationError as error:
        print(str(error), flush=True)
        raise SystemExit(2) from None
