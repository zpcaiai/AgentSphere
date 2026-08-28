"""Builder and offline verifier for positive production evidence bundles.

The checked-in negative baseline has a separate verifier and is intentionally
untouched.  This module accepts only a certificate-bearing, release-scoped
bundle and requires deployment-owned trust anchors outside that bundle.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.qualification import (
    GATE_CONDITION_REQUIREMENTS,
    QualificationTrustAnchors,
    compile_qualification,
    scope_digest,
)
from python.production_gates.revocation_checkpoint import validate_checkpoint


MANIFEST_SCHEMA_VERSION = "agenttrust.production-evidence-bundle.v1"
PUBLIC_KEY_SCHEMA_VERSION = "agenttrust.ed25519-public-key.v1"
REQUIRED_ARTIFACT_ROLES = frozenset({
    "qualification_input",
    "closure_input",
    "closure_report",
    "production_closure_certificate",
    "production_closure_signing_request",
    "production_closure_external_signature",
    "production_closure_signing_audit_receipt",
    "production_closure_revocation_registry",
    "production_closure_revocation_signing_request",
    "production_closure_revocation_external_signature",
    "production_closure_revocation_signing_audit_receipt",
    "production_image_manifest",
})
PRODUCTION_IMAGE_KEYS = frozenset({
    "runtime", "orchestrator", "transition", "execution", "registry",
    "agent_registry", "policy_admin", "incident_release", "pack_marketplace",
    "approval", "pep", "identity", "tool_proxy", "evidence", "audit",
    "enterprise", "enterprise_authority", "model_gateway", "data_governance",
    "context_governance", "runtime_anomaly", "security_evaluation",
    "pack_supply_chain", "domain_runtime", "platform_sre", "console",
    "migration", "envoy", "utility", "release_admission", "sandbox_worker",
})

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CERTIFICATE_ID = re.compile(r"^pc-[0-9a-f]{24}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REASON_CODE = re.compile(r"^[A-Z0-9_]{1,128}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_MANIFEST_FIELDS = {
    "schema_version", "release_id", "scope_digest", "environment_reference",
    "created_at", "eligible", "production_certificate_included",
    "batch_evidence_verified", "condition_evidence_verified", "gate_evidence_verified",
    "trust_anchor_digests", "artifacts", "manifest_digest",
}
_ARTIFACT_FIELDS = {"role", "path", "sha256", "size"}
_TRUST_ANCHORS = {
    "git_provenance_keyring", "release_binding_keyring", "reviewer_keyring",
    "worm_keyring", "closure_public_key", "revocation_public_key",
    "revocation_checkpoint",
}
_REPORT_FIELDS = {
    "schema_version", "release_id", "scope_digest", "input_digest", "eligible",
    "blockers", "verified_gate_digests", "evaluated_at", "evidence_valid_until",
    "report_digest",
}
_CERTIFICATE_FIELDS = {
    "schema_version", "certificate_id", "release_id", "scope_digest",
    "input_digest", "report_digest", "signed_git_provenance_digest",
    "signed_release_binding_digest", "release_digest", "reviewer_keyring_digest",
    "production_closure", "issued_at", "expires_at", "key_id", "signature",
}
_REGISTRY_FIELDS = {
    "schema_version", "registry_id", "sequence", "previous_registry_digest",
    "published_at", "expires_at", "key_id", "entries", "signature",
}
_REVOCATION_FIELDS = {
    "certificate_id", "release_id", "reason_code", "evidence_digest", "revoked_at",
}
_PUBLIC_KEY_FIELDS = {"schema_version", "key_id", "public_key"}
_EXTERNAL_SIGNATURE_FIELDS = {
    "schema_version", "request_digest", "algorithm", "key_id", "signed_at",
    "audit_receipt_digest", "signature",
}
_SIGNING_REQUEST_FIELDS = {
    "schema_version", "algorithm", "key_id", "signing_payload", "payload_sha256",
}
_SIGNED_AUDIT_RECEIPT_FIELDS = {
    "schema_version", "receipt", "receipt_digest", "algorithm", "key_id", "signature",
}
_AUDIT_RECEIPT_FIELDS = {
    "schema_version", "request_id", "request_digest", "request_kind", "key_id",
    "algorithm", "payload_sha256", "document_signature_sha256", "signed_at",
}
_IMAGE_MANIFEST_FIELDS = {
    "schema_version", "release_id", "release_tag", "repository", "created_at",
    "images", "attestations", "manifest_digest",
}
_IMAGE_ATTESTATION_FIELDS = {
    "component", "subject_digest", "sbom_sha256", "provenance_attestation_url",
    "sbom_attestation_url",
}
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HTTPS = re.compile(r"^https://[^\s]+$")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _load_json(payload: bytes) -> object:
    return json.loads(payload, object_pairs_hook=_reject_duplicates)


def _strict_mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _now(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None or result.utcoffset() != timezone.utc.utcoffset(result):
        raise GateError("PRODUCTION_BUNDLE_TIME_INVALID")
    return result.astimezone(timezone.utc)


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


def _decode_payload(value: object, code: str) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 114_294_784:
        raise GateError(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError):
        raise GateError(code) from None
    if (
        not 1 <= len(decoded) <= 64 * 1024 * 1024
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise GateError(code)
    return decoded


def _public_key(value: object, expected_key_id: object, code: str) -> Ed25519PublicKey:
    spec = _strict_mapping(value, _PUBLIC_KEY_FIELDS, code)
    if (
        spec.get("schema_version") != PUBLIC_KEY_SCHEMA_VERSION
        or spec.get("key_id") != expected_key_id
        or not isinstance(spec.get("key_id"), str)
        or not _KEY_ID.fullmatch(str(spec["key_id"]))
    ):
        raise GateError(code)
    try:
        return Ed25519PublicKey.from_public_bytes(_decode(spec.get("public_key"), 32, code))
    except ValueError:
        raise GateError(code) from None


def trust_anchor_digests(
    trust_anchors: QualificationTrustAnchors,
    closure_public_key: object,
    revocation_public_key: object,
    revocation_checkpoint: object,
) -> dict[str, str]:
    checkpoint = validate_checkpoint(revocation_checkpoint)
    return {
        "git_provenance_keyring": _digest(trust_anchors.git_provenance_keyring),
        "release_binding_keyring": _digest(trust_anchors.release_binding_keyring),
        "reviewer_keyring": _digest(trust_anchors.reviewer_keyring),
        "worm_keyring": _digest(trust_anchors.worm_keyring),
        "closure_public_key": _digest(closure_public_key),
        "revocation_public_key": _digest(revocation_public_key),
        "revocation_checkpoint": _digest(checkpoint),
    }


def _validate_report(
    value: object,
    closure_input: Mapping[str, Any],
    *,
    now: datetime,
) -> Mapping[str, Any]:
    report = _strict_mapping(value, _REPORT_FIELDS, "PRODUCTION_BUNDLE_REPORT_INVALID")
    material = dict(report)
    material["report_digest"] = ""
    gate_evidence = closure_input.get("gate_evidence")
    expected_gates = {
        item["gate_id"]: _digest(item)
        for item in gate_evidence
        if isinstance(item, dict) and isinstance(item.get("gate_id"), str)
    } if isinstance(gate_evidence, list) else {}
    evaluated_at = _parse_utc(report.get("evaluated_at"), "PRODUCTION_BUNDLE_REPORT_INVALID")
    evidence_expiries = [
        _parse_utc(closure_input["scope"]["valid_until"], "PRODUCTION_BUNDLE_REPORT_INVALID")
    ]
    for collection in (closure_input.get("batch_statuses"), gate_evidence):
        if not isinstance(collection, list):
            raise GateError("PRODUCTION_BUNDLE_REPORT_INVALID")
        evidence_expiries.extend(
            _parse_utc(item.get("expires_at"), "PRODUCTION_BUNDLE_REPORT_INVALID")
            for item in collection if isinstance(item, dict)
        )
    exceptions = closure_input.get("exceptions")
    if not isinstance(exceptions, list):
        raise GateError("PRODUCTION_BUNDLE_REPORT_INVALID")
    evidence_expiries.extend(
        _parse_utc(item.get("expires_at"), "PRODUCTION_BUNDLE_REPORT_INVALID")
        for item in exceptions if isinstance(item, dict)
    )
    expected_valid_until = min(evidence_expiries)
    if (
        report.get("schema_version") != "agenttrust.production-closure.v1"
        or report.get("release_id") != closure_input["scope"]["release_id"]
        or report.get("scope_digest") != scope_digest(closure_input["scope"])
        or report.get("input_digest") != _digest(closure_input)
        or report.get("eligible") is not True
        or report.get("blockers") != []
        or report.get("verified_gate_digests") != expected_gates
        or set(expected_gates) != set(GATE_CONDITION_REQUIREMENTS)
        or evaluated_at > now
        or _parse_utc(report.get("evidence_valid_until"), "PRODUCTION_BUNDLE_REPORT_INVALID")
        != expected_valid_until
        or expected_valid_until <= evaluated_at
        or report.get("report_digest") != _digest(material)
    ):
        raise GateError("PRODUCTION_BUNDLE_REPORT_INVALID")
    return report


def _validate_certificate(
    value: object,
    report: Mapping[str, Any],
    closure_input: Mapping[str, Any],
    public_key_spec: object,
    *,
    now: datetime,
) -> Mapping[str, Any]:
    certificate = _strict_mapping(
        value, _CERTIFICATE_FIELDS, "PRODUCTION_BUNDLE_CERTIFICATE_INVALID"
    )
    issued_at = _parse_utc(
        certificate.get("issued_at"), "PRODUCTION_BUNDLE_CERTIFICATE_INVALID"
    )
    expires_at = _parse_utc(
        certificate.get("expires_at"), "PRODUCTION_BUNDLE_CERTIFICATE_INVALID"
    )
    expected_id = f"pc-{str(report['report_digest'])[:24]}"
    if (
        certificate.get("schema_version") != "agenttrust.production-closure.v1"
        or certificate.get("certificate_id") != expected_id
        or not _CERTIFICATE_ID.fullmatch(str(certificate.get("certificate_id")))
        or certificate.get("release_id") != report.get("release_id")
        or certificate.get("scope_digest") != report.get("scope_digest")
        or certificate.get("input_digest") != report.get("input_digest")
        or certificate.get("report_digest") != report.get("report_digest")
        or certificate.get("signed_git_provenance_digest")
        != closure_input["scope"]["signed_git_provenance_digest"]
        or certificate.get("signed_release_binding_digest")
        != closure_input["scope"]["signed_release_binding_digest"]
        or certificate.get("release_digest") != closure_input["scope"]["release_digest"]
        or certificate.get("reviewer_keyring_digest")
        != closure_input["scope"]["reviewer_keyring_digest"]
        or certificate.get("production_closure") is not True
        or issued_at < _parse_utc(report["evaluated_at"], "PRODUCTION_BUNDLE_CERTIFICATE_INVALID")
        or issued_at > now
        or expires_at <= now
        or expires_at != _parse_utc(
            report["evidence_valid_until"], "PRODUCTION_BUNDLE_CERTIFICATE_INVALID"
        )
        or not isinstance(certificate.get("signature"), str)
        or not _SIGNATURE.fullmatch(str(certificate["signature"]))
    ):
        raise GateError("PRODUCTION_BUNDLE_CERTIFICATE_INVALID")
    key = _public_key(
        public_key_spec, certificate.get("key_id"), "PRODUCTION_BUNDLE_CERTIFICATE_KEY_INVALID"
    )
    unsigned = dict(certificate)
    unsigned["signature"] = ""
    try:
        key.verify(
            _decode(certificate["signature"], 64, "PRODUCTION_BUNDLE_CERTIFICATE_INVALID"),
            canonical_json(unsigned),
        )
    except InvalidSignature:
        raise GateError("PRODUCTION_BUNDLE_CERTIFICATE_INVALID") from None
    return certificate


def _validate_registry(
    value: object,
    certificate: Mapping[str, Any],
    public_key_spec: object,
    *,
    now: datetime,
) -> Mapping[str, Any]:
    registry = _strict_mapping(
        value, _REGISTRY_FIELDS, "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"
    )
    published_at = _parse_utc(
        registry.get("published_at"), "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"
    )
    expires_at = _parse_utc(
        registry.get("expires_at"), "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"
    )
    entries = registry.get("entries")
    if not isinstance(entries, list) or len(entries) > 100_000:
        raise GateError("PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID")
    previous_id = ""
    for raw_entry in entries:
        entry = _strict_mapping(
            raw_entry, _REVOCATION_FIELDS, "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"
        )
        revoked_at = _parse_utc(
            entry.get("revoked_at"), "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"
        )
        certificate_id = entry.get("certificate_id")
        if (
            not isinstance(certificate_id, str)
            or not _CERTIFICATE_ID.fullmatch(certificate_id)
            or certificate_id <= previous_id
            or not isinstance(entry.get("release_id"), str)
            or not re.fullmatch(
                r"git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})",
                str(entry["release_id"]),
            )
            or not isinstance(entry.get("reason_code"), str)
            or not _REASON_CODE.fullmatch(str(entry["reason_code"]))
            or not isinstance(entry.get("evidence_digest"), str)
            or not _DIGEST.fullmatch(str(entry["evidence_digest"]))
            or revoked_at > published_at
        ):
            raise GateError("PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID")
        previous_id = certificate_id
    sequence = registry.get("sequence")
    previous_digest = registry.get("previous_registry_digest")
    if (
        registry.get("schema_version")
        != "agenttrust.production-closure-revocation-registry.v1"
        or not isinstance(registry.get("registry_id"), str)
        or not _KEY_ID.fullmatch(str(registry["registry_id"]))
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or sequence == 1 and previous_digest is not None
        or sequence > 1 and (
            not isinstance(previous_digest, str) or not _DIGEST.fullmatch(previous_digest)
        )
        or published_at > now
        or published_at < _parse_utc(
            certificate["issued_at"], "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"
        )
        or expires_at <= now
        or expires_at <= published_at
        or expires_at - published_at > timedelta(days=7)
        or not isinstance(registry.get("signature"), str)
        or not _SIGNATURE.fullmatch(str(registry["signature"]))
        or any(entry["certificate_id"] == certificate["certificate_id"] for entry in entries)
    ):
        raise GateError("PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID")
    key = _public_key(
        public_key_spec, registry.get("key_id"),
        "PRODUCTION_BUNDLE_REVOCATION_KEY_INVALID",
    )
    unsigned = dict(registry)
    unsigned["signature"] = ""
    try:
        key.verify(
            _decode(registry["signature"], 64, "PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID"),
            canonical_json(unsigned),
        )
    except InvalidSignature:
        raise GateError("PRODUCTION_BUNDLE_REVOCATION_REGISTRY_INVALID") from None
    return registry


def _validate_external_signature(
    value: object,
    signed_document: Mapping[str, Any],
    signing_request_value: object,
    signed_audit_receipt_value: object,
    public_key_spec: object,
    *,
    schema_version: str,
    request_schema_version: str,
    request_kind: str,
    request_document_field: str,
    document_time_field: str,
    now: datetime,
) -> Mapping[str, Any]:
    envelope = _strict_mapping(
        value,
        _EXTERNAL_SIGNATURE_FIELDS,
        "PRODUCTION_BUNDLE_EXTERNAL_SIGNATURE_INVALID",
    )
    signed_at = _parse_utc(
        envelope.get("signed_at"), "PRODUCTION_BUNDLE_EXTERNAL_SIGNATURE_INVALID"
    )
    document_time = _parse_utc(
        signed_document.get(document_time_field),
        "PRODUCTION_BUNDLE_EXTERNAL_SIGNATURE_INVALID",
    )
    signing_request = _strict_mapping(
        signing_request_value,
        _SIGNING_REQUEST_FIELDS
        | {request_document_field}
        | ({"base_checkpoint_digest"} if request_kind.endswith("REVOCATION_REGISTRY") else set()),
        "PRODUCTION_BUNDLE_SIGNING_REQUEST_INVALID",
    )
    unsigned_document = dict(signed_document)
    unsigned_document["signature"] = ""
    payload = _decode_payload(
        signing_request.get("signing_payload"),
        "PRODUCTION_BUNDLE_SIGNING_REQUEST_INVALID",
    )
    payload_digest = signing_request.get("payload_sha256")
    if (
        signing_request.get("schema_version") != request_schema_version
        or signing_request.get("algorithm") != "Ed25519"
        or signing_request.get("key_id") != signed_document.get("key_id")
        or signing_request.get(request_document_field) != unsigned_document
        or payload != canonical_json(unsigned_document)
        or not isinstance(payload_digest, str)
        or payload_digest != hashlib.sha256(payload).hexdigest()
        or (
            request_kind.endswith("REVOCATION_REGISTRY")
            and (
                not isinstance(signing_request.get("base_checkpoint_digest"), str)
                or not _DIGEST.fullmatch(
                    str(signing_request["base_checkpoint_digest"])
                )
            )
        )
    ):
        raise GateError("PRODUCTION_BUNDLE_SIGNING_REQUEST_INVALID")
    if (
        envelope.get("schema_version") != schema_version
        or envelope.get("algorithm") != "Ed25519"
        or envelope.get("key_id") != signed_document.get("key_id")
        or envelope.get("signature") != signed_document.get("signature")
        or not isinstance(envelope.get("request_digest"), str)
        or envelope.get("request_digest") != _digest(signing_request)
        or not isinstance(envelope.get("audit_receipt_digest"), str)
        or not _DIGEST.fullmatch(str(envelope["audit_receipt_digest"]))
        # Freshness is enforced while consuming the live broker response.  A
        # durable evidence bundle must remain verifiable for the certificate
        # window and therefore cannot be tied to verifier wall-clock freshness.
        or signed_at > now
        or signed_at < document_time - timedelta(minutes=1)
        or signed_at > document_time + timedelta(minutes=15)
    ):
        raise GateError("PRODUCTION_BUNDLE_EXTERNAL_SIGNATURE_INVALID")
    signed_audit = _strict_mapping(
        signed_audit_receipt_value,
        _SIGNED_AUDIT_RECEIPT_FIELDS,
        "PRODUCTION_BUNDLE_SIGNING_AUDIT_RECEIPT_INVALID",
    )
    receipt = _strict_mapping(
        signed_audit.get("receipt"),
        _AUDIT_RECEIPT_FIELDS,
        "PRODUCTION_BUNDLE_SIGNING_AUDIT_RECEIPT_INVALID",
    )
    request_digest = str(envelope["request_digest"])
    expected_receipt = {
        "schema_version": "agenttrust.external-signing-audit-receipt.v1",
        "request_id": f"agenttrust-{request_kind.lower()}-{request_digest[:32]}",
        "request_digest": request_digest,
        "request_kind": request_kind,
        "key_id": signed_document.get("key_id"),
        "algorithm": "Ed25519",
        "payload_sha256": payload_digest,
        "document_signature_sha256": hashlib.sha256(
            str(signed_document["signature"]).encode("ascii")
        ).hexdigest(),
        "signed_at": envelope.get("signed_at"),
    }
    receipt_digest = _digest(receipt)
    if (
        receipt != expected_receipt
        or signed_audit.get("schema_version")
        != "agenttrust.signed-external-signing-audit-receipt.v1"
        or signed_audit.get("receipt_digest") != receipt_digest
        or envelope.get("audit_receipt_digest") != receipt_digest
        or signed_audit.get("algorithm") != "Ed25519"
        or signed_audit.get("key_id") != signed_document.get("key_id")
    ):
        raise GateError("PRODUCTION_BUNDLE_SIGNING_AUDIT_RECEIPT_INVALID")
    audit_key = _public_key(
        public_key_spec,
        signed_document.get("key_id"),
        "PRODUCTION_BUNDLE_SIGNING_AUDIT_RECEIPT_INVALID",
    )
    try:
        audit_key.verify(
            _decode(
                signed_audit.get("signature"),
                64,
                "PRODUCTION_BUNDLE_SIGNING_AUDIT_RECEIPT_INVALID",
            ),
            canonical_json(receipt),
        )
    except InvalidSignature:
        raise GateError("PRODUCTION_BUNDLE_SIGNING_AUDIT_RECEIPT_INVALID") from None
    return envelope


def _validate_image_manifest(
    value: object,
    closure_input: Mapping[str, Any],
    qualification_input: object,
    *,
    now: datetime,
) -> Mapping[str, Any]:
    manifest = _strict_mapping(
        value, _IMAGE_MANIFEST_FIELDS, "PRODUCTION_BUNDLE_IMAGE_MANIFEST_INVALID"
    )
    material = dict(manifest)
    claimed = material.pop("manifest_digest", None)
    images = manifest.get("images")
    attestations = manifest.get("attestations")
    if not isinstance(qualification_input, dict):
        raise GateError("PRODUCTION_BUNDLE_IMAGE_MANIFEST_INVALID")
    binding_envelope = qualification_input.get("release_binding")
    binding = binding_envelope.get("binding") if isinstance(binding_envelope, dict) else None
    values = binding.get("static_values") if isinstance(binding, dict) else None
    bound_images = values.get("images") if isinstance(values, dict) else None
    if (
        manifest.get("schema_version") != "agenttrust.production-image-manifest.v1"
        or manifest.get("release_id") != closure_input["scope"]["release_id"]
        or not isinstance(manifest.get("release_tag"), str)
        or not isinstance(manifest.get("repository"), str)
        or _parse_utc(
            manifest.get("created_at"), "PRODUCTION_BUNDLE_IMAGE_MANIFEST_INVALID"
        ) > now
        or not isinstance(claimed, str)
        or not _DIGEST.fullmatch(claimed)
        or claimed != _digest(material)
        or claimed != closure_input["scope"]["build_digest"]
        or not isinstance(images, dict)
        or set(images) != PRODUCTION_IMAGE_KEYS
        or images != bound_images
        or not isinstance(attestations, dict)
        or set(attestations) != PRODUCTION_IMAGE_KEYS
    ):
        raise GateError("PRODUCTION_BUNDLE_IMAGE_MANIFEST_INVALID")
    for component in PRODUCTION_IMAGE_KEYS:
        image = images[component]
        attestation = _strict_mapping(
            attestations[component], _IMAGE_ATTESTATION_FIELDS,
            "PRODUCTION_BUNDLE_IMAGE_MANIFEST_INVALID",
        )
        if (
            not isinstance(image, str)
            or not _IMAGE.fullmatch(image)
            or attestation.get("component") != component
            or not isinstance(attestation.get("subject_digest"), str)
            or not _OCI_DIGEST.fullmatch(str(attestation["subject_digest"]))
            or image.rsplit("@", 1)[1] != attestation["subject_digest"]
            or not isinstance(attestation.get("sbom_sha256"), str)
            or not _DIGEST.fullmatch(str(attestation["sbom_sha256"]))
            or not isinstance(attestation.get("provenance_attestation_url"), str)
            or not _HTTPS.fullmatch(str(attestation["provenance_attestation_url"]))
            or not isinstance(attestation.get("sbom_attestation_url"), str)
            or not _HTTPS.fullmatch(str(attestation["sbom_attestation_url"]))
        ):
            raise GateError("PRODUCTION_BUNDLE_IMAGE_MANIFEST_INVALID")
    return manifest


def _safe_artifact_path(root: Path, relative: object) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or len(relative) > 512
        or Path(relative).is_absolute()
        or Path(relative).as_posix() != relative
        or ".." in Path(relative).parts
    ):
        raise GateError("PRODUCTION_BUNDLE_ARTIFACT_PATH_INVALID")
    candidate = root / relative
    if candidate.is_symlink() or not candidate.is_file() or not candidate.resolve().is_relative_to(root):
        raise GateError("PRODUCTION_BUNDLE_ARTIFACT_PATH_INVALID")
    return candidate


def build_manifest(
    bundle_root: Path,
    artifact_paths: Mapping[str, Path],
    trust_anchors: QualificationTrustAnchors,
    closure_public_key: object,
    revocation_public_key: object,
    revocation_checkpoint: object,
    *,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a manifest for already-created artifacts; never overwrites files."""
    root = bundle_root.resolve()
    if not bundle_root.is_absolute() or not root.is_dir() or set(artifact_paths) != REQUIRED_ARTIFACT_ROLES:
        raise GateError("PRODUCTION_BUNDLE_LAYOUT_INVALID")
    artifacts = []
    documents: dict[str, object] = {}
    for role in sorted(REQUIRED_ARTIFACT_ROLES):
        path = artifact_paths[role]
        if not path.is_absolute() or path.is_symlink() or not path.resolve().is_relative_to(root):
            raise GateError("PRODUCTION_BUNDLE_LAYOUT_INVALID")
        relative = path.resolve().relative_to(root).as_posix()
        safe_path = _safe_artifact_path(root, relative)
        payload = safe_path.read_bytes()
        if not 1 <= len(payload) <= 64 * 1024 * 1024:
            raise GateError("PRODUCTION_BUNDLE_ARTIFACT_SIZE_INVALID")
        try:
            documents[role] = _load_json(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise GateError("PRODUCTION_BUNDLE_ARTIFACT_INVALID") from None
        artifacts.append({
            "role": role,
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        })
    closure_input = documents["closure_input"]
    if not isinstance(closure_input, dict) or not isinstance(closure_input.get("scope"), dict):
        raise GateError("PRODUCTION_BUNDLE_CLOSURE_INPUT_INVALID")
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "release_id": closure_input["scope"].get("release_id"),
        "scope_digest": scope_digest(closure_input["scope"]),
        "environment_reference": documents["qualification_input"].get("environment_reference")
        if isinstance(documents["qualification_input"], dict) else None,
        "created_at": _now(created_at).astimezone(timezone.utc)
        .isoformat().replace("+00:00", "Z"),
        "eligible": True,
        "production_certificate_included": True,
        "batch_evidence_verified": 35,
        "condition_evidence_verified": 17,
        "gate_evidence_verified": 15,
        "trust_anchor_digests": trust_anchor_digests(
            trust_anchors, closure_public_key, revocation_public_key,
            revocation_checkpoint,
        ),
        "artifacts": artifacts,
    }
    manifest["manifest_digest"] = _digest(manifest)
    return manifest


def verify_bundle(
    bundle_root: Path,
    manifest_value: object,
    trust_anchors: QualificationTrustAnchors,
    closure_public_key: object,
    revocation_public_key: object,
    revocation_checkpoint: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = _now(now)
    root = bundle_root.resolve()
    if not bundle_root.is_absolute() or not root.is_dir():
        raise GateError("PRODUCTION_BUNDLE_ROOT_INVALID")
    manifest = _strict_mapping(
        manifest_value, _MANIFEST_FIELDS, "PRODUCTION_BUNDLE_MANIFEST_INVALID"
    )
    material = dict(manifest)
    claimed_digest = material.pop("manifest_digest", None)
    if (
        manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION
        or manifest.get("eligible") is not True
        or manifest.get("production_certificate_included") is not True
        or manifest.get("batch_evidence_verified") != 35
        or manifest.get("condition_evidence_verified") != 17
        or manifest.get("gate_evidence_verified") != 15
        or manifest.get("trust_anchor_digests")
        != trust_anchor_digests(
            trust_anchors,
            closure_public_key,
            revocation_public_key,
            revocation_checkpoint,
        )
        or not isinstance(claimed_digest, str)
        or not _DIGEST.fullmatch(claimed_digest)
        or claimed_digest != _digest(material)
        or _parse_utc(manifest.get("created_at"), "PRODUCTION_BUNDLE_MANIFEST_INVALID") > current_time
    ):
        raise GateError("PRODUCTION_BUNDLE_MANIFEST_INVALID")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(REQUIRED_ARTIFACT_ROLES):
        raise GateError("PRODUCTION_BUNDLE_ARTIFACTS_INVALID")
    documents: dict[str, object] = {}
    seen_paths: set[str] = set()
    for raw_artifact in artifacts:
        artifact = _strict_mapping(
            raw_artifact, _ARTIFACT_FIELDS, "PRODUCTION_BUNDLE_ARTIFACTS_INVALID"
        )
        role = artifact.get("role")
        relative = artifact.get("path")
        expected_digest = artifact.get("sha256")
        size = artifact.get("size")
        if (
            role not in REQUIRED_ARTIFACT_ROLES
            or role in documents
            or not isinstance(relative, str)
            or relative in seen_paths
            or not isinstance(expected_digest, str)
            or not _DIGEST.fullmatch(expected_digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
        ):
            raise GateError("PRODUCTION_BUNDLE_ARTIFACTS_INVALID")
        path = _safe_artifact_path(root, relative)
        payload = path.read_bytes()
        if len(payload) != size or not 1 <= len(payload) <= 64 * 1024 * 1024:
            raise GateError("PRODUCTION_BUNDLE_ARTIFACT_SIZE_INVALID")
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            raise GateError("PRODUCTION_BUNDLE_ARTIFACT_DIGEST_MISMATCH")
        try:
            documents[str(role)] = _load_json(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise GateError("PRODUCTION_BUNDLE_ARTIFACT_INVALID") from None
        seen_paths.add(relative)
    if set(documents) != REQUIRED_ARTIFACT_ROLES:
        raise GateError("PRODUCTION_BUNDLE_ARTIFACTS_INVALID")

    compiled = compile_qualification(
        documents["qualification_input"], trust_anchors, now=current_time
    )
    if canonical_json(compiled) != canonical_json(documents["closure_input"]):
        raise GateError("PRODUCTION_BUNDLE_CLOSURE_INPUT_MISMATCH")
    report = _validate_report(documents["closure_report"], compiled, now=current_time)
    certificate = _validate_certificate(
        documents["production_closure_certificate"], report, compiled,
        closure_public_key, now=current_time,
    )
    registry = _validate_registry(
        documents["production_closure_revocation_registry"], certificate,
        revocation_public_key, now=current_time,
    )
    checkpoint = validate_checkpoint(revocation_checkpoint)
    signing_request = documents["production_closure_revocation_signing_request"]
    if not isinstance(signing_request, dict):
        raise GateError("PRODUCTION_BUNDLE_REVOCATION_CHECKPOINT_INVALID")
    sequence = checkpoint.get("sequence")
    expected_previous = checkpoint.get("registry_digest")
    if (
        signing_request.get("base_checkpoint_digest")
        != checkpoint.get("checkpoint_digest")
        or registry.get("registry_id") != checkpoint.get("registry_id")
        or registry.get("key_id") != checkpoint.get("key_id")
        or not isinstance(sequence, int)
        or registry.get("sequence") != sequence + 1
        or registry.get("previous_registry_digest") != expected_previous
    ):
        raise GateError("PRODUCTION_BUNDLE_REVOCATION_CHECKPOINT_INVALID")
    _validate_external_signature(
        documents["production_closure_external_signature"],
        certificate,
        documents["production_closure_signing_request"],
        documents["production_closure_signing_audit_receipt"],
        closure_public_key,
        schema_version="agenttrust.production-closure-external-signature.v2",
        request_schema_version="agenttrust.production-closure-signing-request.v1",
        request_kind="PRODUCTION_CLOSURE_CERTIFICATE",
        request_document_field="certificate",
        document_time_field="issued_at",
        now=current_time,
    )
    _validate_external_signature(
        documents["production_closure_revocation_external_signature"],
        registry,
        documents["production_closure_revocation_signing_request"],
        documents["production_closure_revocation_signing_audit_receipt"],
        revocation_public_key,
        schema_version=(
            "agenttrust.production-closure-revocation-external-signature.v2"
        ),
        request_schema_version=(
            "agenttrust.production-closure-revocation-signing-request.v1"
        ),
        request_kind="PRODUCTION_CLOSURE_REVOCATION_REGISTRY",
        request_document_field="registry",
        document_time_field="published_at",
        now=current_time,
    )
    _validate_image_manifest(
        documents["production_image_manifest"], compiled,
        documents["qualification_input"], now=current_time,
    )
    if (
        manifest.get("release_id") != compiled["scope"]["release_id"]
        or manifest.get("scope_digest") != scope_digest(compiled["scope"])
        or not isinstance(documents["qualification_input"], dict)
        or manifest.get("environment_reference")
        != documents["qualification_input"].get("environment_reference")
    ):
        raise GateError("PRODUCTION_BUNDLE_SCOPE_MISMATCH")
    return {
        "release_id": manifest["release_id"],
        "scope_digest": manifest["scope_digest"],
        "certificate_id": certificate["certificate_id"],
        "revocation_registry_id": registry["registry_id"],
        "revocation_registry_sequence": registry["sequence"],
        "manifest_digest": manifest["manifest_digest"],
        "verified": True,
    }


def write_new_json(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise GateError("PRODUCTION_BUNDLE_OUTPUT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
