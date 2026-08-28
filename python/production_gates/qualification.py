"""Fail-closed, release-scoped production evidence qualification compiler.

The compiler deliberately does not accept ``batch_statuses`` or ``GateEvidence``
as input.  Those are derived only after immutable records, WORM receipts,
release provenance, and qualified reviewer signatures have been verified.
Trust roots are deployment inputs and are never taken from the evidence bundle.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import (
    canonical_json,
    signed_git_provenance_digest,
    verify_signed_git_provenance,
)
from python.production_gates.live_integrations import GateError
from python.production_gates.release_binding import (
    signed_release_binding_digest,
    verify_signed_release_binding,
)


QUALIFICATION_INPUT_SCHEMA_VERSION = "agenttrust.production-qualification-input.v1"
QUALIFIED_RECORD_SCHEMA_VERSION = "agenttrust.qualified-evidence-record.v1"
SIGNED_WORM_RECEIPT_SCHEMA_VERSION = "agenttrust.signed-worm-evidence-receipt.v1"
WORM_RECEIPT_SCHEMA_VERSION = "agenttrust.worm-evidence-receipt.v1"
WORM_KEYRING_SCHEMA_VERSION = "agenttrust.worm-evidence-keyring.v1"
REVIEWER_KEYRING_SCHEMA_VERSION = "agenttrust.production-closure-reviewer-keyring.v1"
WORM_KEY_USAGE = "PRODUCTION_EVIDENCE_WORM_RECEIPT"
REVIEWER_KEY_USAGE = "PRODUCTION_ASSURANCE_REVIEW"
ALGORITHM = "Ed25519"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CLOSURE_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_ENVIRONMENT = re.compile(r"^environment://production/[A-Za-z0-9][A-Za-z0-9._:/-]{0,447}$")
_WORM_URI = re.compile(r"^s3-object-lock://[A-Za-z0-9.-]{1,253}/[^?#]{1,1024}\?versionIdDigest=[0-9a-f]{64}$")


EXTERNAL_CONDITIONS = frozenset({
    "ENTERPRISE_IDP_JWKS",
    "WORKLOAD_MTLS_CA",
    "SECRET_BROKER_DYNAMIC_LEASES",
    "DEDICATED_LINUX_GVISOR",
    "PRODUCTION_MULTIZONE_TEMPORAL",
    "MANAGED_DATABASE_MULTI_ZONE",
    "LOCKED_RETENTION_OBJECT_STORAGE",
    "MODEL_GENERATION_STREAM_DLP_BILLING_RESIDENCY",
    "MCP_REAL_ENDPOINT",
    "A2A_REAL_ENDPOINT",
    "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
    "SUPERVISED_PHYSICAL_WRITE",
    "MULTIZONE_CONTROL_PLANE_TOPOLOGY",
    "NETWORK_STORAGE_CONTROL_PLANE_FAULTS",
    "SUSTAINED_PRODUCTION_LOAD",
    "CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE",
    "IMMUTABLE_GIT_RELEASE_PROVENANCE",
})

# This mapping is an executable contract.  Every external condition is consumed
# by at least one closure gate; no caller-selectable mapping is accepted.
GATE_CONDITION_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "CONTRACT_COMPATIBILITY": (),
    "SUPPLY_CHAIN_PROVENANCE": (
        "IMMUTABLE_GIT_RELEASE_PROVENANCE",
        "LOCKED_RETENTION_OBJECT_STORAGE",
    ),
    "MULTITENANT_ISOLATION": (
        "ENTERPRISE_IDP_JWKS",
        "WORKLOAD_MTLS_CA",
        "SECRET_BROKER_DYNAMIC_LEASES",
    ),
    "IDEMPOTENCY_AND_RECOVERY": (
        "PRODUCTION_MULTIZONE_TEMPORAL",
        "MANAGED_DATABASE_MULTI_ZONE",
    ),
    "CONTINUOUS_AUTHORIZATION": (
        "ENTERPRISE_IDP_JWKS",
        "WORKLOAD_MTLS_CA",
        "SECRET_BROKER_DYNAMIC_LEASES",
    ),
    "DOMAIN_CODING": ("MCP_REAL_ENDPOINT", "A2A_REAL_ENDPOINT"),
    "DOMAIN_INDUSTRIAL": (
        "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
        "SUPERVISED_PHYSICAL_WRITE",
    ),
    "DOMAIN_ENERGY": (
        "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
        "SUPERVISED_PHYSICAL_WRITE",
    ),
    "DOMAIN_MEDICAL": ("CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE",),
    "DOMAIN_SENSITIVE_INTERACTION": ("CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE",),
    "SECURITY_CAMPAIGN": (
        "DEDICATED_LINUX_GVISOR",
        "ENTERPRISE_IDP_JWKS",
        "MODEL_GENERATION_STREAM_DLP_BILLING_RESIDENCY",
    ),
    "HA_DR_RESTORE": (
        "PRODUCTION_MULTIZONE_TEMPORAL",
        "MANAGED_DATABASE_MULTI_ZONE",
        "LOCKED_RETENTION_OBJECT_STORAGE",
        "MULTIZONE_CONTROL_PLANE_TOPOLOGY",
        "NETWORK_STORAGE_CONTROL_PLANE_FAULTS",
    ),
    "UPGRADE_ROLLBACK": (
        "MULTIZONE_CONTROL_PLANE_TOPOLOGY",
        "NETWORK_STORAGE_CONTROL_PLANE_FAULTS",
    ),
    "CONTROL_EVIDENCE_GRAPH": (
        "LOCKED_RETENTION_OBJECT_STORAGE",
        "IMMUTABLE_GIT_RELEASE_PROVENANCE",
    ),
    "ENTERPRISE_ACCEPTANCE": (
        "MODEL_GENERATION_STREAM_DLP_BILLING_RESIDENCY",
        "MCP_REAL_ENDPOINT",
        "A2A_REAL_ENDPOINT",
        "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
        "SUSTAINED_PRODUCTION_LOAD",
        "CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE",
    ),
}

EXTERNAL_ASSURANCE_ROLES: dict[str, frozenset[str]] = {
    "SUPPLY_CHAIN_PROVENANCE": frozenset({"RELEASE_ENGINEER", "INDEPENDENT_AUDITOR"}),
    "MULTITENANT_ISOLATION": frozenset({"SECURITY_ENGINEER", "INDEPENDENT_AUDITOR"}),
    "IDEMPOTENCY_AND_RECOVERY": frozenset({"SRE", "SECURITY_ENGINEER"}),
    "CONTINUOUS_AUTHORIZATION": frozenset({"SRE", "SECURITY_ENGINEER"}),
    "DOMAIN_CODING": frozenset({"CODING_DOMAIN_OWNER", "INDEPENDENT_AUDITOR"}),
    "DOMAIN_ENERGY": frozenset({"ENERGY_DOMAIN_ENGINEER", "SAFETY_ENGINEER"}),
    "SECURITY_CAMPAIGN": frozenset({"RED_TEAM_LEAD", "SECURITY_OWNER"}),
    "HA_DR_RESTORE": frozenset({"SRE", "DISASTER_RECOVERY_OWNER"}),
    "UPGRADE_ROLLBACK": frozenset({"SRE", "DISASTER_RECOVERY_OWNER"}),
    "CONTROL_EVIDENCE_GRAPH": frozenset({"COMPLIANCE_OWNER", "INDEPENDENT_AUDITOR"}),
    "ENTERPRISE_ACCEPTANCE": frozenset({"CUSTOMER_RELEASE_AUTHORITY", "INDEPENDENT_AUDITOR"}),
}

DOMAIN_ASSURANCE: dict[str, tuple[str, frozenset[str]]] = {
    "DOMAIN_INDUSTRIAL": (
        "INDUSTRIAL",
        frozenset({"SAFETY_ENGINEER", "OPERATIONS_OWNER"}),
    ),
    "DOMAIN_MEDICAL": (
        "MEDICAL",
        frozenset({"LICENSED_CLINICIAN", "PRIVACY_LEGAL_REVIEWER"}),
    ),
    "DOMAIN_SENSITIVE_INTERACTION": (
        "SENSITIVE_INTERACTION",
        frozenset({"SAFEGUARDING_LEAD", "HUMAN_SUPPORT_OWNER"}),
    ),
}
ALL_ASSURANCE_ROLES = frozenset().union(
    *EXTERNAL_ASSURANCE_ROLES.values(),
    *[roles for _, roles in DOMAIN_ASSURANCE.values()],
)

_INPUT_FIELDS = {
    "schema_version", "environment_reference", "scope", "git_provenance",
    "release_binding", "batch_records", "condition_records", "worm_receipts",
    "external_assurances", "domain_assurances", "residual_risks", "exceptions",
}
_SCOPE_FIELDS = {
    "release_id", "commit_digest", "signed_git_provenance_digest",
    "signed_release_binding_digest", "release_digest", "reviewer_keyring_digest",
    "build_digest", "policy_digest",
    "pack_set_digest", "prompt_set_digest", "model_set_digest",
    "topology_digest", "environment", "valid_from", "valid_until",
}
_RECORD_FIELDS = {
    "schema_version", "kind", "record_id", "release_id", "scope_digest",
    "environment_reference", "passed", "evidence_digests", "measured_at",
    "expires_at", "verification_policy_digest", "record_digest",
}
_RECEIPT_FIELDS = {
    "schema_version", "receipt_id", "artifact_kind", "artifact_id",
    "artifact_digest", "release_id", "scope_digest", "environment_reference",
    "object_uri", "retention_mode", "versioning_enabled", "verified_readback",
    "verification_result", "verification_policy_digest", "stored_at", "retain_until",
}
_SIGNED_RECEIPT_FIELDS = {
    "schema_version", "receipt", "receipt_digest", "issuer", "key_id",
    "key_usage", "algorithm", "signed_at", "signature",
}
_WORM_KEYRING_FIELDS = {"schema_version", "keys"}
_WORM_KEY_FIELDS = {
    "issuer", "key_id", "key_usage", "algorithm", "public_key", "status",
    "not_before", "not_after",
}
_REVIEWER_KEYRING_FIELDS = {
    "schema_version", "keyring_id", "version", "issued_at", "expires_at", "keys",
}
_REVIEWER_KEY_FIELDS = {
    "key_id", "reviewer_id", "organization", "roles", "key_usage", "algorithm",
    "public_key", "status", "not_before", "not_after", "revoked_at",
}
_EXTERNAL_ASSURANCE_FIELDS = {
    "schema_version", "attestation_id", "gate_id", "release_id", "scope_digest",
    "environment_reference", "decision", "automated", "change_ticket",
    "evidence_digests", "issued_at", "expires_at", "reviewers",
}
_DOMAIN_ASSURANCE_FIELDS = {
    "schema_version", "attestation_id", "domain", "release_id", "scope_digest",
    "environment_reference", "decision", "automated", "evidence_digests",
    "issued_at", "expires_at", "reviewers",
}
_REVIEWER_FIELDS = {"reviewer_id", "organization", "role", "key_id", "signature"}
_RISK_FIELDS = {"risk_id", "severity", "description", "owner", "acceptance"}
_EXCEPTION_FIELDS = {
    "exception_id", "gate_id", "severity", "owner", "compensating_control_digests",
    "expires_at", "approval",
}
_SIGNED_APPROVAL_FIELDS = {
    "schema_version", "artifact_kind", "artifact_digest", "release_id",
    "scope_digest", "environment_reference", "issued_at", "expires_at",
    "reviewers",
}
_RISK_ACCEPTANCE_ROLES = frozenset({"COMPLIANCE_OWNER"})
_EXCEPTION_APPROVAL_ROLES = frozenset({"COMPLIANCE_OWNER", "SECURITY_OWNER"})


@dataclass(frozen=True)
class QualificationTrustAnchors:
    git_provenance_keyring: object
    release_binding_keyring: object
    reviewer_keyring: object
    worm_keyring: object


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def scope_digest(scope: object) -> str:
    value = dict(_strict_mapping(scope, _SCOPE_FIELDS, "QUALIFICATION_SCOPE_INVALID"))
    value["valid_from"] = _utc_string(
        _parse_utc(value.get("valid_from"), "QUALIFICATION_SCOPE_INVALID")
    )
    value["valid_until"] = _utc_string(
        _parse_utc(value.get("valid_until"), "QUALIFICATION_SCOPE_INVALID")
    )
    return _digest(value)


def reviewer_keyring_digest(value: object) -> str:
    keyring = dict(_strict_mapping(
        value, _REVIEWER_KEYRING_FIELDS, "REVIEWER_KEYRING_INVALID"
    ))
    keyring["issued_at"] = _utc_string(
        _parse_utc(keyring.get("issued_at"), "REVIEWER_KEYRING_INVALID")
    )
    keyring["expires_at"] = _utc_string(
        _parse_utc(keyring.get("expires_at"), "REVIEWER_KEYRING_INVALID")
    )
    normalized_keys = []
    for raw_key in _strict_list(keyring.get("keys"), 1, 1_000, "REVIEWER_KEYRING_INVALID"):
        key = dict(_strict_mapping(raw_key, _REVIEWER_KEY_FIELDS, "REVIEWER_KEYRING_INVALID"))
        key["roles"] = sorted(key.get("roles", [])) if isinstance(key.get("roles"), list) else key.get("roles")
        key["not_before"] = _utc_string(
            _parse_utc(key.get("not_before"), "REVIEWER_KEYRING_INVALID")
        )
        key["not_after"] = _utc_string(
            _parse_utc(key.get("not_after"), "REVIEWER_KEYRING_INVALID")
        )
        if key.get("revoked_at") is not None:
            key["revoked_at"] = _utc_string(
                _parse_utc(key["revoked_at"], "REVIEWER_KEYRING_INVALID")
            )
        normalized_keys.append(key)
    keyring["keys"] = normalized_keys
    return _digest(keyring)


def qualified_record_artifact_digest(record: object) -> str:
    validated = _validate_record_shape(record)
    return _digest(validated)


def signed_worm_receipt_digest(receipt: object) -> str:
    _strict_mapping(receipt, _SIGNED_RECEIPT_FIELDS, "WORM_RECEIPT_INVALID")
    return _digest(receipt)


def _strict_mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _strict_list(value: object, minimum: int, maximum: int, code: str) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
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


def _utc_string(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _current_time(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise GateError("QUALIFICATION_TIME_INVALID")
    return value.astimezone(timezone.utc)


def _decode_base64url(value: object, expected_length: int, code: str) -> bytes:
    if not isinstance(value, str):
        raise GateError(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError):
        raise GateError(code) from None
    if (
        len(decoded) != expected_length
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise GateError(code)
    return decoded


def _digest_map(value: object, code: str, *, maximum: int = 512) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or not 1 <= len(value) <= maximum
        or any(
            not isinstance(key, str)
            or not key
            or len(key) > 256
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            for key, digest in value.items()
        )
    ):
        raise GateError(code)
    return dict(value)


def _bounded_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and all(character >= " " and character != "\x7f" for character in value)
    )


def _signer_valid_until(envelope: object, keyring: object, code: str) -> datetime:
    if not isinstance(envelope, dict) or not isinstance(keyring, dict):
        raise GateError(code)
    keys = keyring.get("keys")
    if not isinstance(keys, list):
        raise GateError(code)
    matches = [
        key for key in keys
        if isinstance(key, dict)
        and key.get("issuer") == envelope.get("issuer")
        and key.get("key_id") == envelope.get("key_id")
        and key.get("key_usage") == envelope.get("key_usage")
    ]
    if len(matches) != 1 or matches[0].get("status") != "ACTIVE":
        raise GateError(code)
    return _parse_utc(matches[0].get("not_after"), code)


def _validate_scope(
    value: object,
    environment_reference: str,
    now: datetime,
) -> tuple[Mapping[str, Any], str, datetime]:
    scope = _strict_mapping(value, _SCOPE_FIELDS, "QUALIFICATION_SCOPE_INVALID")
    digests = [
        scope.get("commit_digest"), scope.get("signed_git_provenance_digest"),
        scope.get("signed_release_binding_digest"), scope.get("release_digest"),
        scope.get("reviewer_keyring_digest"), scope.get("build_digest"),
        scope.get("policy_digest"),
        scope.get("pack_set_digest"), scope.get("prompt_set_digest"),
        scope.get("model_set_digest"), scope.get("topology_digest"),
    ]
    valid_from = _parse_utc(scope.get("valid_from"), "QUALIFICATION_SCOPE_INVALID")
    valid_until = _parse_utc(scope.get("valid_until"), "QUALIFICATION_SCOPE_INVALID")
    if (
        not isinstance(scope.get("release_id"), str)
        or not _RELEASE_ID.fullmatch(str(scope["release_id"]))
        or scope.get("release_id") == "WORKTREE-NO-GIT"
        or scope.get("environment") != "production"
        or not _ENVIRONMENT.fullmatch(environment_reference)
        or any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in digests)
        or valid_from > now
        or valid_until <= now
        or valid_until <= valid_from
        or valid_until - valid_from > timedelta(days=30)
    ):
        raise GateError("QUALIFICATION_SCOPE_INVALID")
    normalized_scope = dict(scope)
    normalized_scope["valid_from"] = _utc_string(valid_from)
    normalized_scope["valid_until"] = _utc_string(valid_until)
    return normalized_scope, _digest(normalized_scope), valid_until


def _validate_record_shape(value: object) -> Mapping[str, Any]:
    record = _strict_mapping(value, _RECORD_FIELDS, "QUALIFICATION_RECORD_INVALID")
    material = dict(record)
    claimed = material.pop("record_digest", None)
    if (
        record.get("schema_version") != QUALIFIED_RECORD_SCHEMA_VERSION
        or record.get("kind") not in {"BATCH", "EXTERNAL_CONDITION"}
        or not isinstance(record.get("record_id"), str)
        or not isinstance(record.get("release_id"), str)
        or not isinstance(record.get("scope_digest"), str)
        or not isinstance(record.get("environment_reference"), str)
        or record.get("passed") is not True
        or not isinstance(record.get("verification_policy_digest"), str)
        or not _DIGEST.fullmatch(str(record["verification_policy_digest"]))
        or not isinstance(claimed, str)
        or not _DIGEST.fullmatch(claimed)
        or _digest(material) != claimed
    ):
        raise GateError("QUALIFICATION_RECORD_INVALID")
    _digest_map(record.get("evidence_digests"), "QUALIFICATION_RECORD_INVALID")
    _parse_utc(record.get("measured_at"), "QUALIFICATION_RECORD_INVALID")
    _parse_utc(record.get("expires_at"), "QUALIFICATION_RECORD_INVALID")
    return record


def _validate_record(
    value: object,
    *,
    kind: str,
    record_id: str,
    release_id: str,
    expected_scope_digest: str,
    environment_reference: str,
    now: datetime,
) -> tuple[Mapping[str, Any], datetime, datetime]:
    record = _validate_record_shape(value)
    measured_at = _parse_utc(record["measured_at"], "QUALIFICATION_RECORD_INVALID")
    expires_at = _parse_utc(record["expires_at"], "QUALIFICATION_RECORD_INVALID")
    if (
        record.get("kind") != kind
        or record.get("record_id") != record_id
        or record.get("release_id") != release_id
        or record.get("scope_digest") != expected_scope_digest
        or record.get("environment_reference") != environment_reference
        or measured_at > now
        or expires_at <= now
        or expires_at <= measured_at
    ):
        raise GateError("QUALIFICATION_RECORD_SCOPE_INVALID")
    return record, measured_at, expires_at


def _validate_worm_keyring(value: object) -> list[Mapping[str, Any]]:
    keyring = _strict_mapping(value, _WORM_KEYRING_FIELDS, "WORM_KEYRING_INVALID")
    keys = _strict_list(keyring.get("keys"), 1, 64, "WORM_KEYRING_INVALID")
    if keyring.get("schema_version") != WORM_KEYRING_SCHEMA_VERSION:
        raise GateError("WORM_KEYRING_INVALID")
    identities: set[tuple[str, str]] = set()
    validated: list[Mapping[str, Any]] = []
    for value_key in keys:
        key = _strict_mapping(value_key, _WORM_KEY_FIELDS, "WORM_KEYRING_INVALID")
        identity = (str(key.get("issuer")), str(key.get("key_id")))
        not_before = _parse_utc(key.get("not_before"), "WORM_KEYRING_INVALID")
        not_after = _parse_utc(key.get("not_after"), "WORM_KEYRING_INVALID")
        if (
            not _IDENTIFIER.fullmatch(identity[0])
            or not _KEY_ID.fullmatch(identity[1])
            or identity in identities
            or key.get("key_usage") != WORM_KEY_USAGE
            or key.get("algorithm") != ALGORITHM
            or key.get("status") not in {"ACTIVE", "REVOKED"}
            or not isinstance(key.get("public_key"), str)
            or not _PUBLIC_KEY.fullmatch(str(key["public_key"]))
            or not_before >= not_after
        ):
            raise GateError("WORM_KEYRING_INVALID")
        identities.add(identity)
        validated.append(key)
    return validated


def _verify_worm_receipt(
    value: object,
    keyring: Sequence[Mapping[str, Any]],
    *,
    record: Mapping[str, Any],
    release_id: str,
    expected_scope_digest: str,
    environment_reference: str,
    scope_valid_until: datetime,
    now: datetime,
) -> Mapping[str, Any]:
    envelope = _strict_mapping(value, _SIGNED_RECEIPT_FIELDS, "WORM_RECEIPT_INVALID")
    receipt = _strict_mapping(envelope.get("receipt"), _RECEIPT_FIELDS, "WORM_RECEIPT_INVALID")
    stored_at = _parse_utc(receipt.get("stored_at"), "WORM_RECEIPT_INVALID")
    retain_until = _parse_utc(receipt.get("retain_until"), "WORM_RECEIPT_INVALID")
    signed_at = _parse_utc(envelope.get("signed_at"), "WORM_RECEIPT_INVALID")
    artifact_digest = qualified_record_artifact_digest(record)
    if (
        envelope.get("schema_version") != SIGNED_WORM_RECEIPT_SCHEMA_VERSION
        or receipt.get("schema_version") != WORM_RECEIPT_SCHEMA_VERSION
        or not isinstance(receipt.get("receipt_id"), str)
        or not _IDENTIFIER.fullmatch(str(receipt["receipt_id"]))
        or receipt.get("artifact_kind") != record.get("kind")
        or receipt.get("artifact_id") != record.get("record_id")
        or receipt.get("artifact_digest") != artifact_digest
        or receipt.get("release_id") != release_id
        or receipt.get("scope_digest") != expected_scope_digest
        or receipt.get("environment_reference") != environment_reference
        or not isinstance(receipt.get("object_uri"), str)
        or not _WORM_URI.fullmatch(str(receipt["object_uri"]))
        or receipt.get("retention_mode") != "COMPLIANCE"
        or receipt.get("versioning_enabled") is not True
        or receipt.get("verified_readback") is not True
        or receipt.get("verification_result") != "VERIFIED"
        or receipt.get("verification_policy_digest") != record.get("verification_policy_digest")
        or stored_at < _parse_utc(record["measured_at"], "WORM_RECEIPT_INVALID")
        or signed_at < stored_at
        or signed_at > now
        or retain_until < scope_valid_until
        or retain_until <= signed_at
        or envelope.get("receipt_digest") != _digest(receipt)
        or envelope.get("key_usage") != WORM_KEY_USAGE
        or envelope.get("algorithm") != ALGORITHM
        or not isinstance(envelope.get("issuer"), str)
        or not _IDENTIFIER.fullmatch(str(envelope["issuer"]))
        or not isinstance(envelope.get("key_id"), str)
        or not _KEY_ID.fullmatch(str(envelope["key_id"]))
        or not isinstance(envelope.get("signature"), str)
        or not _SIGNATURE.fullmatch(str(envelope["signature"]))
    ):
        raise GateError("WORM_RECEIPT_INVALID")
    matches = []
    for key in keyring:
        if key["issuer"] == envelope["issuer"] and key["key_id"] == envelope["key_id"]:
            not_before = _parse_utc(key["not_before"], "WORM_KEYRING_INVALID")
            not_after = _parse_utc(key["not_after"], "WORM_KEYRING_INVALID")
            if (
                key["status"] != "ACTIVE"
                or not not_before <= signed_at <= not_after
                or not_before > now
                or not_after < scope_valid_until
            ):
                raise GateError("WORM_RECEIPT_SIGNING_KEY_INACTIVE")
            matches.append(key)
    if len(matches) != 1:
        raise GateError("WORM_RECEIPT_SIGNING_KEY_NOT_TRUSTED")
    unsigned = {field: envelope[field] for field in sorted(_SIGNED_RECEIPT_FIELDS - {"signature"})}
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(matches[0]["public_key"], 32, "WORM_RECEIPT_SIGNATURE_INVALID")
        ).verify(
            _decode_base64url(envelope["signature"], 64, "WORM_RECEIPT_SIGNATURE_INVALID"),
            canonical_json(unsigned),
        )
    except (InvalidSignature, ValueError):
        raise GateError("WORM_RECEIPT_SIGNATURE_INVALID") from None
    return envelope


def _validate_reviewer_keyring(
    value: object,
    *,
    now: datetime,
) -> tuple[dict[str, Mapping[str, Any]], datetime]:
    keyring = _strict_mapping(value, _REVIEWER_KEYRING_FIELDS, "REVIEWER_KEYRING_INVALID")
    issued_at = _parse_utc(keyring.get("issued_at"), "REVIEWER_KEYRING_INVALID")
    expires_at = _parse_utc(keyring.get("expires_at"), "REVIEWER_KEYRING_INVALID")
    keys = _strict_list(keyring.get("keys"), 2, 1_000, "REVIEWER_KEYRING_INVALID")
    if (
        keyring.get("schema_version") != REVIEWER_KEYRING_SCHEMA_VERSION
        or not isinstance(keyring.get("keyring_id"), str)
        or not _CLOSURE_KEY_ID.fullmatch(str(keyring["keyring_id"]))
        or not isinstance(keyring.get("version"), int)
        or isinstance(keyring.get("version"), bool)
        or int(keyring["version"]) < 1
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > timedelta(days=366)
    ):
        raise GateError("REVIEWER_KEYRING_INVALID")
    result: dict[str, Mapping[str, Any]] = {}
    for raw_key in keys:
        key = _strict_mapping(raw_key, _REVIEWER_KEY_FIELDS, "REVIEWER_KEYRING_INVALID")
        not_before = _parse_utc(key.get("not_before"), "REVIEWER_KEYRING_INVALID")
        not_after = _parse_utc(key.get("not_after"), "REVIEWER_KEYRING_INVALID")
        revoked_at = key.get("revoked_at")
        if revoked_at is not None:
            _parse_utc(revoked_at, "REVIEWER_KEYRING_INVALID")
        roles = key.get("roles")
        if (
            not isinstance(key.get("key_id"), str)
            or not _CLOSURE_KEY_ID.fullmatch(str(key["key_id"]))
            or key["key_id"] in result
            or not _bounded_text(key.get("reviewer_id"), 128)
            or not _bounded_text(key.get("organization"), 256)
            or not isinstance(roles, list)
            or not 1 <= len(roles) <= 16
            or len(roles) != len(set(roles))
            or any(role not in ALL_ASSURANCE_ROLES for role in roles)
            or key.get("key_usage") != REVIEWER_KEY_USAGE
            or key.get("algorithm") != ALGORITHM
            or key.get("status") not in {"ACTIVE", "REVOKED"}
            or key.get("status") == "ACTIVE" and revoked_at is not None
            or key.get("status") == "REVOKED" and revoked_at is None
            or key.get("status") == "REVOKED" and (
                _parse_utc(revoked_at, "REVIEWER_KEYRING_INVALID") < not_before
                or _parse_utc(revoked_at, "REVIEWER_KEYRING_INVALID") > now
            )
            or not isinstance(key.get("public_key"), str)
            or not _PUBLIC_KEY.fullmatch(str(key["public_key"]))
            or not_before >= not_after
            or not_after <= issued_at
        ):
            raise GateError("REVIEWER_KEYRING_INVALID")
        result[str(key["key_id"])] = key
    return result, expires_at


def _assurance_expected_evidence(
    gate_id: str,
    records: Mapping[str, Mapping[str, Any]],
    receipts: Mapping[str, Mapping[str, Any]],
    provenance_digest: str,
    binding_digest: str,
    release_digest: str,
) -> dict[str, str]:
    expected = {
        "signed_git_provenance": provenance_digest,
        "signed_release_binding": binding_digest,
        "release": release_digest,
    }
    for condition in GATE_CONDITION_REQUIREMENTS[gate_id]:
        expected[f"condition:{condition}"] = qualified_record_artifact_digest(records[condition])
        expected[f"worm:{condition}"] = signed_worm_receipt_digest(receipts[condition])
    return expected


def _verify_assurance(
    value: object,
    *,
    gate_id: str,
    expected_domain: str | None,
    required_roles: frozenset[str],
    expected_evidence: Mapping[str, str],
    reviewer_keys: Mapping[str, Mapping[str, Any]],
    reviewer_keyring_expires_at: datetime,
    release_id: str,
    expected_scope_digest: str,
    environment_reference: str,
    scope_valid_until: datetime,
    now: datetime,
) -> tuple[Mapping[str, Any], datetime, datetime]:
    is_domain = expected_domain is not None
    fields = _DOMAIN_ASSURANCE_FIELDS if is_domain else _EXTERNAL_ASSURANCE_FIELDS
    code = "DOMAIN_ASSURANCE_INVALID" if is_domain else "EXTERNAL_ASSURANCE_INVALID"
    assurance = _strict_mapping(value, fields, code)
    issued_at = _parse_utc(assurance.get("issued_at"), code)
    expires_at = _parse_utc(assurance.get("expires_at"), code)
    reviewers = _strict_list(assurance.get("reviewers"), 2, 10 if is_domain else 12, code)
    maximum_days = 90 if is_domain else 30
    if (
        assurance.get("schema_version")
        != ("agenttrust.domain-assurance-attestation.v1" if is_domain else "agenttrust.external-gate-assurance-attestation.v1")
        or assurance.get("release_id") != release_id
        or assurance.get("scope_digest") != expected_scope_digest
        or assurance.get("environment_reference") != environment_reference
        or assurance.get("decision") != "APPROVED"
        or assurance.get("automated") is not False
        or is_domain and assurance.get("domain") != expected_domain
        or not is_domain and assurance.get("gate_id") != gate_id
        or not is_domain and (not isinstance(assurance.get("change_ticket"), str) or not assurance["change_ticket"])
        or _digest_map(assurance.get("evidence_digests"), code) != dict(expected_evidence)
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > timedelta(days=maximum_days)
    ):
        raise GateError(code)
    reviewer_ids: set[str] = set()
    key_ids: set[str] = set()
    organizations: set[str] = set()
    roles: set[str] = set()
    parsed_reviewers: list[Mapping[str, Any]] = []
    for value_reviewer in reviewers:
        reviewer = _strict_mapping(value_reviewer, _REVIEWER_FIELDS, code)
        key_id = reviewer.get("key_id")
        key = reviewer_keys.get(str(key_id))
        if (
            not _bounded_text(reviewer.get("reviewer_id"), 128)
            or not _bounded_text(reviewer.get("organization"), 256)
            or not isinstance(reviewer.get("role"), str)
            or not isinstance(key_id, str)
            or not _CLOSURE_KEY_ID.fullmatch(key_id)
            or not isinstance(reviewer.get("signature"), str)
            or not _SIGNATURE.fullmatch(str(reviewer["signature"]))
            or key is None
            or key.get("reviewer_id") != reviewer["reviewer_id"]
            or key.get("organization") != reviewer["organization"]
            or reviewer["role"] not in key.get("roles", [])
            or key.get("status") != "ACTIVE"
            or key.get("revoked_at") is not None
            or not _parse_utc(key["not_before"], code) <= issued_at
            or _parse_utc(key["not_after"], code) <= now
        ):
            raise GateError(code)
        reviewer_ids.add(str(reviewer["reviewer_id"]))
        key_ids.add(key_id)
        organizations.add(str(reviewer["organization"]))
        roles.add(str(reviewer["role"]))
        parsed_reviewers.append(reviewer)
    if (
        len(reviewer_ids) != len(reviewers)
        or len(key_ids) != len(reviewers)
        or not required_roles.issubset(roles)
        or not is_domain and len(organizations) < 2
    ):
        raise GateError(code)
    normalized_assurance = json.loads(canonical_json(assurance))
    normalized_assurance["issued_at"] = _utc_string(issued_at)
    normalized_assurance["expires_at"] = _utc_string(expires_at)
    unsigned = json.loads(canonical_json(normalized_assurance))
    for reviewer in unsigned["reviewers"]:
        reviewer["signature"] = ""
    payload = canonical_json(unsigned)
    for reviewer in parsed_reviewers:
        key = reviewer_keys[str(reviewer["key_id"])]
        try:
            Ed25519PublicKey.from_public_bytes(
                _decode_base64url(key["public_key"], 32, code)
            ).verify(_decode_base64url(reviewer["signature"], 64, code), payload)
        except (InvalidSignature, ValueError):
            raise GateError(code) from None
    effective_expiry = min(
        expires_at,
        reviewer_keyring_expires_at,
        scope_valid_until,
        *[_parse_utc(reviewer_keys[str(item["key_id"])]["not_after"], code)
          for item in parsed_reviewers],
    )
    if effective_expiry <= now:
        raise GateError(code)
    return normalized_assurance, issued_at, effective_expiry


def _verify_signed_approval(
    value: object,
    *,
    artifact_kind: str,
    artifact_digest: str,
    owner: str,
    required_roles: frozenset[str],
    reviewer_keys: Mapping[str, Mapping[str, Any]],
    release_id: str,
    expected_scope_digest: str,
    environment_reference: str,
    required_valid_until: datetime,
    now: datetime,
) -> list[str]:
    code = (
        "RISK_ACCEPTANCE_INVALID"
        if artifact_kind == "RISK"
        else "EXCEPTION_APPROVAL_INVALID"
    )
    approval = _strict_mapping(value, _SIGNED_APPROVAL_FIELDS, code)
    issued_at = _parse_utc(approval.get("issued_at"), code)
    expires_at = _parse_utc(approval.get("expires_at"), code)
    reviewers = _strict_list(
        approval.get("reviewers"), len(required_roles), len(required_roles), code
    )
    expected_schema = (
        "agenttrust.signed-risk-acceptance.v1"
        if artifact_kind == "RISK"
        else "agenttrust.signed-exception-approval.v1"
    )
    if (
        approval.get("schema_version") != expected_schema
        or approval.get("artifact_kind") != artifact_kind
        or approval.get("artifact_digest") != artifact_digest
        or approval.get("release_id") != release_id
        or approval.get("scope_digest") != expected_scope_digest
        or approval.get("environment_reference") != environment_reference
        or issued_at > now
        or expires_at < required_valid_until
        or expires_at <= issued_at
    ):
        raise GateError(code)
    normalized = json.loads(canonical_json(approval))
    normalized["issued_at"] = _utc_string(issued_at)
    normalized["expires_at"] = _utc_string(expires_at)
    unsigned = json.loads(canonical_json(normalized))
    for reviewer in unsigned["reviewers"]:
        if not isinstance(reviewer, dict) or "signature" not in reviewer:
            raise GateError(code)
        reviewer["signature"] = ""
    payload = canonical_json(unsigned)
    reviewer_ids: set[str] = set()
    key_ids: set[str] = set()
    roles: set[str] = set()
    for raw_reviewer in reviewers:
        reviewer = _strict_mapping(raw_reviewer, _REVIEWER_FIELDS, code)
        key_id = reviewer.get("key_id")
        key = reviewer_keys.get(str(key_id))
        reviewer_id = reviewer.get("reviewer_id")
        role = reviewer.get("role")
        if (
            not _bounded_text(reviewer_id, 128)
            or reviewer_id == owner
            or not _bounded_text(reviewer.get("organization"), 256)
            or not isinstance(role, str)
            or role not in required_roles
            or not isinstance(key_id, str)
            or not _CLOSURE_KEY_ID.fullmatch(key_id)
            or not isinstance(reviewer.get("signature"), str)
            or not _SIGNATURE.fullmatch(str(reviewer["signature"]))
            or key is None
            or key.get("reviewer_id") != reviewer_id
            or key.get("organization") != reviewer.get("organization")
            or role not in key.get("roles", [])
            or key.get("status") != "ACTIVE"
            or key.get("revoked_at") is not None
            or not _parse_utc(key.get("not_before"), code) <= issued_at
            or _parse_utc(key.get("not_after"), code) < expires_at
        ):
            raise GateError(code)
        try:
            Ed25519PublicKey.from_public_bytes(
                _decode_base64url(key["public_key"], 32, code)
            ).verify(_decode_base64url(reviewer["signature"], 64, code), payload)
        except (InvalidSignature, ValueError):
            raise GateError(code) from None
        reviewer_ids.add(str(reviewer_id))
        key_ids.add(key_id)
        roles.add(role)
    if (
        len(reviewer_ids) != len(reviewers)
        or len(key_ids) != len(reviewers)
        or roles != required_roles
    ):
        raise GateError(code)
    return sorted(reviewer_ids)


def _validate_risks(
    value: object,
    *,
    reviewer_keys: Mapping[str, Mapping[str, Any]],
    release_id: str,
    expected_scope_digest: str,
    environment_reference: str,
    scope_valid_until: datetime,
    now: datetime,
) -> list[dict[str, Any]]:
    risks = _strict_list(value, 0, 10_000, "QUALIFICATION_RISKS_INVALID")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_risk in risks:
        risk = _strict_mapping(raw_risk, _RISK_FIELDS, "QUALIFICATION_RISKS_INVALID")
        risk_id = risk.get("risk_id")
        if (
            not isinstance(risk_id, str)
            or not _KEY_ID.fullmatch(risk_id)
            or risk_id in seen
            or risk.get("severity") not in {"P2", "P3"}
            or not isinstance(risk.get("description"), str)
            or not risk["description"]
            or len(str(risk["description"])) > 4096
            or not isinstance(risk.get("owner"), str)
            or not risk["owner"]
            or len(str(risk["owner"])) > 256
        ):
            raise GateError("QUALIFICATION_RISKS_INVALID")
        seen.add(risk_id)
        material = {field: risk[field] for field in sorted(_RISK_FIELDS - {"acceptance"})}
        accepted_by = _verify_signed_approval(
            risk.get("acceptance"),
            artifact_kind="RISK",
            artifact_digest=_digest(material),
            owner=str(risk["owner"]),
            required_roles=_RISK_ACCEPTANCE_ROLES,
            reviewer_keys=reviewer_keys,
            release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            required_valid_until=scope_valid_until,
            now=now,
        )
        result.append({**material, "accepted_by": accepted_by[0]})
    return sorted(result, key=lambda item: item["risk_id"])


def _validate_exceptions(
    value: object,
    *,
    reviewer_keys: Mapping[str, Mapping[str, Any]],
    release_id: str,
    expected_scope_digest: str,
    environment_reference: str,
    scope_valid_until: datetime,
    now: datetime,
) -> list[dict[str, Any]]:
    exceptions = _strict_list(value, 0, 1_000, "QUALIFICATION_EXCEPTIONS_INVALID")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_exception in exceptions:
        exception = _strict_mapping(
            raw_exception, _EXCEPTION_FIELDS, "QUALIFICATION_EXCEPTIONS_INVALID"
        )
        exception_id = exception.get("exception_id")
        controls = exception.get("compensating_control_digests")
        expires_at = _parse_utc(exception.get("expires_at"), "QUALIFICATION_EXCEPTIONS_INVALID")
        if (
            not isinstance(exception_id, str)
            or not _KEY_ID.fullmatch(exception_id)
            or exception_id in seen
            or exception.get("gate_id") not in GATE_CONDITION_REQUIREMENTS
            or exception.get("severity") not in {"P2", "P3"}
            or not isinstance(exception.get("owner"), str)
            or not exception["owner"]
            or len(str(exception["owner"])) > 256
            or not isinstance(controls, list)
            or not controls
            or len(controls) != len(set(controls))
            or any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in controls)
            or expires_at <= now
        ):
            raise GateError("QUALIFICATION_EXCEPTIONS_INVALID")
        seen.add(exception_id)
        material = {
            field: exception[field]
            for field in sorted(_EXCEPTION_FIELDS - {"approval"})
        }
        approvals = _verify_signed_approval(
            exception.get("approval"),
            artifact_kind="EXCEPTION",
            artifact_digest=_digest(material),
            owner=str(exception["owner"]),
            required_roles=_EXCEPTION_APPROVAL_ROLES,
            reviewer_keys=reviewer_keys,
            release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            required_valid_until=min(expires_at, scope_valid_until),
            now=now,
        )
        normalized = dict(material)
        normalized["approved_by"] = approvals
        normalized["compensating_control_digests"] = sorted(controls)
        result.append(normalized)
    return sorted(result, key=lambda item: item["exception_id"])


def compile_qualification(
    value: object,
    trust_anchors: QualificationTrustAnchors,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify an evidence package and deterministically produce one ClosureInput."""
    current_time = _current_time(now)
    package = _strict_mapping(value, _INPUT_FIELDS, "QUALIFICATION_INPUT_INVALID")
    if package.get("schema_version") != QUALIFICATION_INPUT_SCHEMA_VERSION:
        raise GateError("QUALIFICATION_INPUT_INVALID")
    environment_reference = package.get("environment_reference")
    if not isinstance(environment_reference, str):
        raise GateError("QUALIFICATION_INPUT_INVALID")
    scope, expected_scope_digest, valid_until = _validate_scope(
        package.get("scope"), environment_reference, current_time
    )
    release_id = str(scope["release_id"])

    provenance_report = verify_signed_git_provenance(
        package.get("git_provenance"), trust_anchors.git_provenance_keyring, now=current_time
    )
    binding = verify_signed_release_binding(
        package.get("release_binding"), trust_anchors.release_binding_keyring, now=current_time
    )
    provenance_digest = signed_git_provenance_digest(package.get("git_provenance"))
    binding_digest = signed_release_binding_digest(package.get("release_binding"))
    checks = provenance_report.get("checks")
    values = binding.get("static_values")
    images = values.get("images") if isinstance(values, dict) else None
    if (
        not isinstance(checks, dict)
        or not isinstance(values, dict)
        or not isinstance(images, dict)
        or not 1 <= len(images) <= 128
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(image, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", image)
            for name, image in images.items()
        )
        or checks.get("release_id") != release_id
        or binding.get("release_id") != release_id
        or binding.get("signed_git_provenance_digest") != provenance_digest
        or scope.get("signed_git_provenance_digest") != provenance_digest
        or scope.get("signed_release_binding_digest") != binding_digest
        or scope.get("release_digest") != binding.get("release_digest")
        or scope.get("reviewer_keyring_digest")
        != reviewer_keyring_digest(trust_anchors.reviewer_keyring)
        or scope.get("commit_digest") != checks.get("commit_content_digest")
        or scope.get("topology_digest") != binding.get("runtime_config_digest")
        or _signer_valid_until(
            package.get("git_provenance"), trust_anchors.git_provenance_keyring,
            "QUALIFICATION_GIT_TRUST_EXPIRES",
        ) < valid_until
        or _signer_valid_until(
            package.get("release_binding"), trust_anchors.release_binding_keyring,
            "QUALIFICATION_RELEASE_TRUST_EXPIRES",
        ) < valid_until
    ):
        raise GateError("QUALIFICATION_RELEASE_BINDING_MISMATCH")

    worm_keys = _validate_worm_keyring(trust_anchors.worm_keyring)
    reviewer_keys, reviewer_keyring_expires_at = _validate_reviewer_keyring(
        trust_anchors.reviewer_keyring,
        now=current_time,
    )

    raw_batch_records = _strict_list(
        package.get("batch_records"), 35, 35, "QUALIFICATION_BATCH_RECORDS_INVALID"
    )
    raw_condition_records = _strict_list(
        package.get("condition_records"), 17, 17, "QUALIFICATION_CONDITION_RECORDS_INVALID"
    )
    batch_records: dict[str, Mapping[str, Any]] = {}
    condition_records: dict[str, Mapping[str, Any]] = {}
    record_times: dict[str, tuple[datetime, datetime]] = {}
    for raw_record in raw_batch_records:
        if not isinstance(raw_record, dict):
            raise GateError("QUALIFICATION_BATCH_RECORDS_INVALID")
        record_id = raw_record.get("record_id")
        if not isinstance(record_id, str) or not re.fullmatch(r"BATCH_(?:0[1-9]|[12][0-9]|3[0-5])", record_id):
            raise GateError("QUALIFICATION_BATCH_RECORDS_INVALID")
        record, measured, expires = _validate_record(
            raw_record, kind="BATCH", record_id=record_id, release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference, now=current_time,
        )
        if record_id in batch_records:
            raise GateError("QUALIFICATION_BATCH_RECORDS_INVALID")
        batch_records[record_id] = record
        record_times[record_id] = (measured, expires)
    expected_batches = {f"BATCH_{batch:02}" for batch in range(1, 36)}
    if set(batch_records) != expected_batches:
        raise GateError("QUALIFICATION_BATCH_RECORDS_INVALID")
    for raw_record in raw_condition_records:
        if not isinstance(raw_record, dict) or raw_record.get("record_id") not in EXTERNAL_CONDITIONS:
            raise GateError("QUALIFICATION_CONDITION_RECORDS_INVALID")
        record_id = str(raw_record["record_id"])
        record, measured, expires = _validate_record(
            raw_record, kind="EXTERNAL_CONDITION", record_id=record_id,
            release_id=release_id, expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference, now=current_time,
        )
        if record_id in condition_records:
            raise GateError("QUALIFICATION_CONDITION_RECORDS_INVALID")
        condition_records[record_id] = record
        record_times[record_id] = (measured, expires)
    if set(condition_records) != EXTERNAL_CONDITIONS:
        raise GateError("QUALIFICATION_CONDITION_RECORDS_INVALID")

    raw_receipts = _strict_list(
        package.get("worm_receipts"), 52, 52, "QUALIFICATION_WORM_RECEIPTS_INVALID"
    )
    records = {**batch_records, **condition_records}
    receipts: dict[str, Mapping[str, Any]] = {}
    object_uris: set[str] = set()
    receipt_ids: set[str] = set()
    for raw_receipt in raw_receipts:
        if not isinstance(raw_receipt, dict) or not isinstance(raw_receipt.get("receipt"), dict):
            raise GateError("QUALIFICATION_WORM_RECEIPTS_INVALID")
        artifact_id = raw_receipt["receipt"].get("artifact_id")
        if not isinstance(artifact_id, str) or artifact_id not in records or artifact_id in receipts:
            raise GateError("QUALIFICATION_WORM_RECEIPTS_INVALID")
        verified_receipt = _verify_worm_receipt(
            raw_receipt, worm_keys, record=records[artifact_id], release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            scope_valid_until=valid_until, now=current_time,
        )
        receipt = verified_receipt["receipt"]
        if receipt["receipt_id"] in receipt_ids or receipt["object_uri"] in object_uris:
            raise GateError("QUALIFICATION_WORM_RECEIPTS_INVALID")
        receipt_ids.add(receipt["receipt_id"])
        object_uris.add(receipt["object_uri"])
        receipts[artifact_id] = verified_receipt
    if set(receipts) != set(records):
        raise GateError("QUALIFICATION_WORM_RECEIPTS_INVALID")

    raw_external = _strict_list(
        package.get("external_assurances"), len(EXTERNAL_ASSURANCE_ROLES),
        len(EXTERNAL_ASSURANCE_ROLES), "QUALIFICATION_EXTERNAL_ASSURANCE_INVALID",
    )
    raw_domains = _strict_list(
        package.get("domain_assurances"), len(DOMAIN_ASSURANCE), len(DOMAIN_ASSURANCE),
        "QUALIFICATION_DOMAIN_ASSURANCE_INVALID",
    )
    external: dict[str, tuple[Mapping[str, Any], datetime, datetime]] = {}
    domains: dict[str, tuple[Mapping[str, Any], datetime, datetime]] = {}
    attestation_ids: set[str] = set()
    for raw_assurance in raw_external:
        if not isinstance(raw_assurance, dict) or raw_assurance.get("gate_id") not in EXTERNAL_ASSURANCE_ROLES:
            raise GateError("QUALIFICATION_EXTERNAL_ASSURANCE_INVALID")
        gate_id = str(raw_assurance["gate_id"])
        if gate_id in external:
            raise GateError("QUALIFICATION_EXTERNAL_ASSURANCE_INVALID")
        verified_assurance = _verify_assurance(
            raw_assurance, gate_id=gate_id, expected_domain=None,
            required_roles=EXTERNAL_ASSURANCE_ROLES[gate_id],
            expected_evidence=_assurance_expected_evidence(
                gate_id, condition_records, receipts, provenance_digest, binding_digest,
                str(binding["release_digest"]),
            ),
            reviewer_keys=reviewer_keys,
            reviewer_keyring_expires_at=reviewer_keyring_expires_at,
            release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            scope_valid_until=valid_until, now=current_time,
        )
        if verified_assurance[0]["attestation_id"] in attestation_ids:
            raise GateError("QUALIFICATION_ASSURANCE_DUPLICATE")
        attestation_ids.add(str(verified_assurance[0]["attestation_id"]))
        external[gate_id] = verified_assurance
    if set(external) != set(EXTERNAL_ASSURANCE_ROLES):
        raise GateError("QUALIFICATION_EXTERNAL_ASSURANCE_INVALID")
    domain_by_name = {domain: gate for gate, (domain, _) in DOMAIN_ASSURANCE.items()}
    for raw_assurance in raw_domains:
        if not isinstance(raw_assurance, dict) or raw_assurance.get("domain") not in domain_by_name:
            raise GateError("QUALIFICATION_DOMAIN_ASSURANCE_INVALID")
        gate_id = domain_by_name[str(raw_assurance["domain"])]
        if gate_id in domains:
            raise GateError("QUALIFICATION_DOMAIN_ASSURANCE_INVALID")
        expected_domain, roles = DOMAIN_ASSURANCE[gate_id]
        verified_assurance = _verify_assurance(
            raw_assurance, gate_id=gate_id, expected_domain=expected_domain,
            required_roles=roles,
            expected_evidence=_assurance_expected_evidence(
                gate_id, condition_records, receipts, provenance_digest, binding_digest,
                str(binding["release_digest"]),
            ),
            reviewer_keys=reviewer_keys,
            reviewer_keyring_expires_at=reviewer_keyring_expires_at,
            release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            scope_valid_until=valid_until, now=current_time,
        )
        if verified_assurance[0]["attestation_id"] in attestation_ids:
            raise GateError("QUALIFICATION_ASSURANCE_DUPLICATE")
        attestation_ids.add(str(verified_assurance[0]["attestation_id"]))
        domains[gate_id] = verified_assurance
    if set(domains) != set(DOMAIN_ASSURANCE):
        raise GateError("QUALIFICATION_DOMAIN_ASSURANCE_INVALID")

    batch_statuses = []
    for batch in range(1, 36):
        record_id = f"BATCH_{batch:02}"
        batch_statuses.append({
            "batch": batch,
            "status": "EVIDENCE_VERIFIED",
            "scope_digest": expected_scope_digest,
            "evidence_digest": _digest({
                "record": qualified_record_artifact_digest(batch_records[record_id]),
                "worm_receipt": signed_worm_receipt_digest(receipts[record_id]),
                "git_provenance": provenance_digest,
                "release_binding": binding_digest,
            }),
            "measured_at": _utc_string(record_times[record_id][0]),
            "expires_at": _utc_string(min(record_times[record_id][1], valid_until)),
        })

    gate_evidence: list[dict[str, Any]] = []
    for gate_id, requirements in GATE_CONDITION_REQUIREMENTS.items():
        if gate_id == "CONTRACT_COMPATIBILITY":
            measured_at = max(record_times[record_id][0] for record_id in batch_records)
            expires_at = min(record_times[record_id][1] for record_id in batch_records)
            evidence_digests = {
                f"batch:{record_id}": qualified_record_artifact_digest(batch_records[record_id])
                for record_id in sorted(batch_records)
            }
            evidence_digests["git_provenance"] = provenance_digest
            evidence_digests["release_binding"] = binding_digest
            kind = "INTEGRATION_TEST"
            source = "QUALIFIED_BATCH_EVIDENCE_SET"
            environment = None
        else:
            assurance, assurance_measured, assurance_expires = (
                domains[gate_id] if gate_id in domains else external[gate_id]
            )
            measured_at = max(
                [assurance_measured, *[record_times[record_id][0] for record_id in requirements]]
            )
            expires_at = min(
                [assurance_expires, *[record_times[record_id][1] for record_id in requirements]]
            )
            evidence_digests = _assurance_expected_evidence(
                gate_id, condition_records, receipts, provenance_digest, binding_digest,
                str(binding["release_digest"]),
            )
            evidence_digests["assurance"] = _digest(assurance)
            evidence_digests["reviewer_keyring"] = reviewer_keyring_digest(
                trust_anchors.reviewer_keyring
            )
            kind = "INDEPENDENT_ASSURANCE" if gate_id in domains else "REAL_ENVIRONMENT"
            source = (
                "DOMAIN_ASSURANCE_ATTESTATION"
                if gate_id in domains
                else "EXTERNAL_GATE_ASSURANCE_ATTESTATION"
            )
            environment = environment_reference
        expires_at = min(expires_at, valid_until)
        gate_evidence.append({
            "gate_id": gate_id,
            "scope_digest": expected_scope_digest,
            "passed": True,
            "evidence_kind": kind,
            "evidence_digests": dict(sorted(evidence_digests.items())),
            "environment_reference": environment,
            "measured_at": _utc_string(measured_at),
            "expires_at": _utc_string(expires_at),
            "source_certificate_type": source,
        })

    closure_input = {
        "schema_version": "agenttrust.production-closure.v1",
        "scope": json.loads(canonical_json(scope)),
        "batch_statuses": batch_statuses,
        "gate_evidence": gate_evidence,
        "residual_risks": _validate_risks(
            package.get("residual_risks"),
            reviewer_keys=reviewer_keys,
            release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            scope_valid_until=valid_until,
            now=current_time,
        ),
        "exceptions": _validate_exceptions(
            package.get("exceptions"),
            reviewer_keys=reviewer_keys,
            release_id=release_id,
            expected_scope_digest=expected_scope_digest,
            environment_reference=environment_reference,
            scope_valid_until=valid_until,
            now=current_time,
        ),
    }
    # A canonical round trip both detaches caller-owned objects and guarantees
    # one byte representation for a given qualified package.
    return json.loads(canonical_json(closure_input))


assert set(GATE_CONDITION_REQUIREMENTS) == {
    "CONTRACT_COMPATIBILITY", "SUPPLY_CHAIN_PROVENANCE", "MULTITENANT_ISOLATION",
    "IDEMPOTENCY_AND_RECOVERY", "CONTINUOUS_AUTHORIZATION", "DOMAIN_CODING",
    "DOMAIN_INDUSTRIAL", "DOMAIN_ENERGY", "DOMAIN_MEDICAL",
    "DOMAIN_SENSITIVE_INTERACTION", "SECURITY_CAMPAIGN", "HA_DR_RESTORE",
    "UPGRADE_ROLLBACK", "CONTROL_EVIDENCE_GRAPH", "ENTERPRISE_ACCEPTANCE",
}
assert set().union(*map(set, GATE_CONDITION_REQUIREMENTS.values())) == EXTERNAL_CONDITIONS
