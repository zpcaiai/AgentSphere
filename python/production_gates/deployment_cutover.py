"""Fail-closed production writer-fence and blue/green cutover contracts.

This module never changes a database, Kubernetes object, traffic selector, or
write fence.  It verifies externally observed facts and externally produced
Ed25519 signatures, then validates the monotonic receipt chain that an
orchestrator must require around those actions.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


WRITER_FENCE_SCHEMA_VERSION = "agenttrust.deployment-writer-fence-receipt.v1"
INVENTORY_SCHEMA_VERSION = "agenttrust.deployment-blue-green-inventory.v1"
TRANSITION_SCHEMA_VERSION = "agenttrust.deployment-transition-receipt.v1"
KEYRING_SCHEMA_VERSION = "agenttrust.deployment-cutover-keyring.v1"
SIGNING_REQUEST_SCHEMA_VERSION = "agenttrust.deployment-cutover-signing-request.v1"
SIGNING_PAYLOAD_SCHEMA_VERSION = "agenttrust.deployment-cutover-signing-payload.v1"
EXTERNAL_SIGNATURE_SCHEMA_VERSION = "agenttrust.deployment-cutover-external-signature.v1"
SIGNED_RECEIPT_SCHEMA_VERSION = "agenttrust.signed-deployment-control-receipt.v1"
KEY_USAGE = "PRODUCTION_DEPLOYMENT_CUTOVER"
ALGORITHM = "Ed25519"

DOCUMENT_ROLES = {
    "WRITER_FENCE": "SRE_RELEASE_FENCE",
    "CUTOVER": "RELEASE_CUTOVER_AUTHORITY",
    "ROLLBACK": "DISASTER_RECOVERY_OWNER",
    "UNFREEZE": "SRE_RELEASE_UNFREEZE",
}
DOCUMENT_SCHEMAS = {
    "WRITER_FENCE": WRITER_FENCE_SCHEMA_VERSION,
    "CUTOVER": TRANSITION_SCHEMA_VERSION,
    "ROLLBACK": TRANSITION_SCHEMA_VERSION,
    "UNFREEZE": TRANSITION_SCHEMA_VERSION,
}
TRANSITION_EVIDENCE_KEYS = {
    "CUTOVER": {"cutover_operation", "health_observation", "traffic_observation"},
    "ROLLBACK": {"health_observation", "rollback_operation", "traffic_observation"},
    "UNFREEZE": {"control_plane_observation", "traffic_observation", "write_unfreeze"},
}

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ENVIRONMENT = re.compile(r"^environment://production/[A-Za-z0-9][A-Za-z0-9._:/-]{0,447}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_OCI_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_WAL_LSN = re.compile(r"^[0-9A-F]{1,8}/[0-9A-F]{1,8}$")
_BASE64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_BASE64URL_64 = re.compile(r"^[A-Za-z0-9_-]{86}$")
_BASE64URL_PAYLOAD = re.compile(r"^[A-Za-z0-9_-]{32,16777216}$")

_FENCE_FIELDS = {
    "schema_version", "fence_id", "source_release_id", "target_release_id",
    "environment_reference", "fence_applied", "writes_blocked", "drain_complete",
    "inflight_action_count", "pending_outbox_count", "active_execution_lease_count",
    "database_recovery", "evidence_digests", "measured_at", "valid_until",
    "receipt_digest",
}
_DATABASE_RECOVERY_FIELDS = {
    "database_cluster_id", "checkpoint_id", "checkpoint_digest", "wal_lsn",
    "wal_segment_digest", "backup_id", "backup_manifest_digest",
    "backup_object_version_digest", "backup_verified_at", "restore_test_receipt_digest",
}
_FENCE_EVIDENCE_KEYS = {
    "backup_readback", "database_checkpoint", "inflight_query", "lease_query",
    "outbox_query", "write_fence",
}
_INVENTORY_FIELDS = {
    "schema_version", "inventory_id", "source_release_id", "target_release_id",
    "source_revision", "target_revision", "environment_reference", "traffic_revision",
    "traffic_bindings", "workloads", "observed_at", "valid_until", "inventory_digest",
}
_TRAFFIC_BINDING_FIELDS = {"service_name", "revision"}
_WORKLOAD_FIELDS = {
    "workload_name", "revision", "release_id", "image",
    "desired_replicas", "ready_replicas", "available_replicas",
}
_TRANSITION_FIELDS = {
    "schema_version", "transition_id", "transition_type", "source_release_id",
    "target_release_id", "environment_reference", "sequence",
    "previous_transition_digest", "writer_fence_receipt_digest", "inventory_digest",
    "traffic_revision", "writes_fenced", "from_state", "to_state", "evidence_digests",
    "observed_at", "valid_until", "receipt_digest",
}
_KEYRING_FIELDS = {"schema_version", "keyring_id", "version", "issued_at", "expires_at", "keys"}
_KEY_FIELDS = {
    "key_id", "signer_id", "organization", "roles", "key_usage", "algorithm",
    "public_key", "status", "not_before", "not_after", "revoked_at",
}
_SIGNING_REQUEST_FIELDS = {
    "schema_version", "document_kind", "key_id", "key_usage", "algorithm", "document",
    "document_digest", "signing_payload", "payload_sha256", "prepared_at", "request_digest",
}
_EXTERNAL_SIGNATURE_FIELDS = {
    "schema_version", "request_digest", "key_id", "algorithm", "signed_at", "signature",
}
_SIGNED_RECEIPT_FIELDS = {
    "schema_version", "document_kind", "document", "document_digest", "signer_id",
    "organization", "role", "key_id", "key_usage", "algorithm", "signed_at",
    "request_digest", "signature",
}


def _mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _list(value: object, minimum: int, maximum: int, code: str) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise GateError(code)
    return value


def _text(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GateError(code)
    return value


def _time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise GateError(code) from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed


def _now(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.utcoffset() != timezone.utc.utcoffset(current):
        raise GateError("DEPLOYMENT_CUTOVER_TIME_INVALID")
    return current


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _with_verified_digest(value: Mapping[str, Any], field: str, code: str) -> dict[str, Any]:
    claimed = value.get(field)
    material = dict(value)
    material.pop(field, None)
    if not isinstance(claimed, str) or not _DIGEST.fullmatch(claimed) or claimed != _digest(material):
        raise GateError(code)
    return json.loads(canonical_json(value))


def _digest_map(value: object, required: set[str], code: str) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != required
        or any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in value.values())
    ):
        raise GateError(code)
    return dict(sorted(value.items()))


def _decode_base64url(value: object, length: int, pattern: re.Pattern[str], code: str) -> bytes:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GateError(code)
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError):
        raise GateError(code) from None
    if len(decoded) != length or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise GateError(code)
    return decoded


def _decode_payload(value: object, code: str) -> bytes:
    if not isinstance(value, str) or _BASE64URL_PAYLOAD.fullmatch(value) is None:
        raise GateError(code)
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError):
        raise GateError(code) from None
    if not 1 <= len(decoded) <= 12 * 1024 * 1024:
        raise GateError(code)
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise GateError(code)
    return decoded


def validate_writer_fence_receipt(
    value: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate an externally observed, short-lived zero-work writer fence."""

    code = "DEPLOYMENT_WRITER_FENCE_INVALID"
    current = _now(now)
    receipt = _mapping(value, _FENCE_FIELDS, code)
    source = _text(receipt.get("source_release_id"), _RELEASE_ID, code)
    target = _text(receipt.get("target_release_id"), _RELEASE_ID, code)
    measured = _time(receipt.get("measured_at"), code)
    valid_until = _time(receipt.get("valid_until"), code)
    recovery = _mapping(receipt.get("database_recovery"), _DATABASE_RECOVERY_FIELDS, code)
    backup_verified = _time(recovery.get("backup_verified_at"), code)
    counters = (
        receipt.get("inflight_action_count"),
        receipt.get("pending_outbox_count"),
        receipt.get("active_execution_lease_count"),
    )
    if (
        receipt.get("schema_version") != WRITER_FENCE_SCHEMA_VERSION
        or _text(receipt.get("fence_id"), _UUID, code) is None
        or source == target
        or _text(receipt.get("environment_reference"), _ENVIRONMENT, code) is None
        or receipt.get("fence_applied") is not True
        or receipt.get("writes_blocked") is not True
        or receipt.get("drain_complete") is not True
        or any(not isinstance(item, int) or isinstance(item, bool) or item != 0 for item in counters)
        or measured > current + timedelta(seconds=30)
        or valid_until <= current
        or valid_until <= measured
        or valid_until - measured > timedelta(minutes=15)
        or backup_verified > measured
        or measured - backup_verified > timedelta(hours=24)
        or not all(
            isinstance(recovery.get(field), str) and _IDENTIFIER.fullmatch(recovery[field])
            for field in ("database_cluster_id", "checkpoint_id", "backup_id")
        )
        or not isinstance(recovery.get("wal_lsn"), str)
        or _WAL_LSN.fullmatch(recovery["wal_lsn"]) is None
        or any(
            not isinstance(recovery.get(field), str) or _DIGEST.fullmatch(recovery[field]) is None
            for field in (
                "checkpoint_digest", "wal_segment_digest", "backup_manifest_digest",
                "backup_object_version_digest", "restore_test_receipt_digest",
            )
        )
    ):
        raise GateError(code)
    _digest_map(receipt.get("evidence_digests"), _FENCE_EVIDENCE_KEYS, code)
    return _with_verified_digest(receipt, "receipt_digest", code)


def validate_blue_green_inventory(
    value: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Prove that one traffic revision is selected and both revisions are unambiguous."""

    code = "DEPLOYMENT_BLUE_GREEN_INVENTORY_INVALID"
    current = _now(now)
    inventory = _mapping(value, _INVENTORY_FIELDS, code)
    source_release = _text(inventory.get("source_release_id"), _RELEASE_ID, code)
    target_release = _text(inventory.get("target_release_id"), _RELEASE_ID, code)
    source_revision = _text(inventory.get("source_revision"), _IDENTIFIER, code)
    target_revision = _text(inventory.get("target_revision"), _IDENTIFIER, code)
    traffic_revision = _text(inventory.get("traffic_revision"), _IDENTIFIER, code)
    observed = _time(inventory.get("observed_at"), code)
    valid_until = _time(inventory.get("valid_until"), code)
    if (
        inventory.get("schema_version") != INVENTORY_SCHEMA_VERSION
        or _text(inventory.get("inventory_id"), _UUID, code) is None
        or _text(inventory.get("environment_reference"), _ENVIRONMENT, code) is None
        or source_release == target_release
        or source_revision == target_revision
        or traffic_revision not in {source_revision, target_revision}
        or observed > current + timedelta(seconds=30)
        or valid_until <= current
        or valid_until <= observed
        or valid_until - observed > timedelta(minutes=15)
    ):
        raise GateError(code)

    bindings = _list(inventory.get("traffic_bindings"), 1, 1_000, code)
    services: set[str] = set()
    for raw in bindings:
        binding = _mapping(raw, _TRAFFIC_BINDING_FIELDS, code)
        service = _text(binding.get("service_name"), _IDENTIFIER, code)
        revision = _text(binding.get("revision"), _IDENTIFIER, code)
        if service in services or revision != traffic_revision:
            raise GateError(code)
        services.add(service)

    workloads = _list(inventory.get("workloads"), 2, 4_000, code)
    by_workload: dict[str, dict[str, Mapping[str, Any]]] = {}
    for raw in workloads:
        workload = _mapping(raw, _WORKLOAD_FIELDS, code)
        name = _text(workload.get("workload_name"), _IDENTIFIER, code)
        revision = _text(workload.get("revision"), _IDENTIFIER, code)
        release = _text(workload.get("release_id"), _RELEASE_ID, code)
        image = workload.get("image")
        expected_release = source_release if revision == source_revision else target_release if revision == target_revision else None
        counts = (
            workload.get("desired_replicas"), workload.get("ready_replicas"),
            workload.get("available_replicas"),
        )
        if (
            expected_release is None
            or release != expected_release
            or not isinstance(image, str)
            or _OCI_DIGEST.fullmatch(image) is None
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts)
            or workload["ready_replicas"] != workload["desired_replicas"]
            or workload["available_replicas"] != workload["desired_replicas"]
            or revision == target_revision and workload["desired_replicas"] < 1
            or revision == traffic_revision and workload["desired_replicas"] < 1
        ):
            raise GateError(code)
        revisions = by_workload.setdefault(name, {})
        if revision in revisions:
            raise GateError(code)
        revisions[revision] = workload
    if any(set(revisions) != {source_revision, target_revision} for revisions in by_workload.values()):
        raise GateError(code)
    return _with_verified_digest(inventory, "inventory_digest", code)


def validate_transition_receipt(
    value: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    code = "DEPLOYMENT_TRANSITION_RECEIPT_INVALID"
    current = _now(now)
    receipt = _mapping(value, _TRANSITION_FIELDS, code)
    kind = receipt.get("transition_type")
    source = _text(receipt.get("source_release_id"), _RELEASE_ID, code)
    target = _text(receipt.get("target_release_id"), _RELEASE_ID, code)
    observed = _time(receipt.get("observed_at"), code)
    valid_until = _time(receipt.get("valid_until"), code)
    sequence = receipt.get("sequence")
    states = {
        "CUTOVER": ("DRAINED", "CUTOVER_COMMITTED", True, 1),
        "ROLLBACK": ("CUTOVER_COMMITTED", "ROLLBACK_COMMITTED", True, 2),
        "UNFREEZE": (
            {"CUTOVER_COMMITTED", "ROLLBACK_COMMITTED"},
            {"TARGET_ACTIVE", "SOURCE_ACTIVE"},
            False,
            {2, 3},
        ),
    }
    if (
        receipt.get("schema_version") != TRANSITION_SCHEMA_VERSION
        or kind not in states
        or _text(receipt.get("transition_id"), _UUID, code) is None
        or source == target
        or _text(receipt.get("environment_reference"), _ENVIRONMENT, code) is None
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 1 <= sequence <= 3
        or any(
            not isinstance(receipt.get(field), str) or _DIGEST.fullmatch(receipt[field]) is None
            for field in ("previous_transition_digest", "writer_fence_receipt_digest", "inventory_digest")
        )
        or not isinstance(receipt.get("traffic_revision"), str)
        or _IDENTIFIER.fullmatch(receipt["traffic_revision"]) is None
        or observed > current + timedelta(seconds=30)
        or valid_until <= current
        or valid_until <= observed
        or valid_until - observed > timedelta(minutes=15)
    ):
        raise GateError(code)
    expected_from, expected_to, expected_fenced, expected_sequence = states[str(kind)]
    if sequence not in (
        expected_sequence if isinstance(expected_sequence, set) else {expected_sequence}
    ):
        raise GateError(code)
    if kind == "UNFREEZE":
        expected_pair = {
            "CUTOVER_COMMITTED": ("TARGET_ACTIVE", 2),
            "ROLLBACK_COMMITTED": ("SOURCE_ACTIVE", 3),
        }.get(receipt.get("from_state"))
        if (
            expected_pair is None
            or (receipt.get("to_state"), sequence) != expected_pair
        ):
            raise GateError(code)
    elif receipt.get("from_state") != expected_from or receipt.get("to_state") != expected_to:
        raise GateError(code)
    if (kind == "CUTOVER") != (receipt.get("previous_transition_digest") == "0" * 64):
        raise GateError(code)
    if receipt.get("writes_fenced") is not expected_fenced:
        raise GateError(code)
    _digest_map(receipt.get("evidence_digests"), TRANSITION_EVIDENCE_KEYS[str(kind)], code)
    return _with_verified_digest(receipt, "receipt_digest", code)


def validate_cutover_keyring(
    value: object,
    *,
    now: datetime | None = None,
) -> dict[str, Mapping[str, Any]]:
    code = "DEPLOYMENT_CUTOVER_KEYRING_INVALID"
    current = _now(now)
    keyring = _mapping(value, _KEYRING_FIELDS, code)
    issued = _time(keyring.get("issued_at"), code)
    expires = _time(keyring.get("expires_at"), code)
    version = keyring.get("version")
    if (
        keyring.get("schema_version") != KEYRING_SCHEMA_VERSION
        or _text(keyring.get("keyring_id"), _KEY_ID, code) is None
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
        or issued > current
        or expires <= current
        or expires <= issued
        or expires - issued > timedelta(days=366)
    ):
        raise GateError(code)
    result: dict[str, Mapping[str, Any]] = {}
    signer_ids: set[str] = set()
    for raw in _list(keyring.get("keys"), 4, 1_000, code):
        key = _mapping(raw, _KEY_FIELDS, code)
        key_id = _text(key.get("key_id"), _KEY_ID, code)
        signer_id = _text(key.get("signer_id"), _KEY_ID, code)
        not_before = _time(key.get("not_before"), code)
        not_after = _time(key.get("not_after"), code)
        revoked_at = key.get("revoked_at")
        if revoked_at is not None:
            _time(revoked_at, code)
        roles = key.get("roles")
        if (
            key_id in result
            or signer_id in signer_ids
            or not isinstance(key.get("organization"), str)
            or not 1 <= len(key["organization"].encode("utf-8")) <= 256
            or not isinstance(roles, list)
            or not 1 <= len(roles) <= len(DOCUMENT_ROLES)
            or len(roles) != len(set(roles))
            or any(role not in DOCUMENT_ROLES.values() for role in roles)
            or key.get("key_usage") != KEY_USAGE
            or key.get("algorithm") != ALGORITHM
            or key.get("status") not in {"ACTIVE", "REVOKED"}
            or (key.get("status") == "ACTIVE") != (revoked_at is None)
            or not_before >= not_after
            or not_after <= current
        ):
            raise GateError(code)
        _decode_base64url(key.get("public_key"), 32, _BASE64URL_32, code)
        result[key_id] = key
        signer_ids.add(signer_id)
    if not set(DOCUMENT_ROLES.values()).issubset(
        {role for key in result.values() for role in key.get("roles", [])}
    ):
        raise GateError(code)
    return result


def _validate_document(kind: str, document: object, now: datetime) -> dict[str, Any]:
    if kind == "WRITER_FENCE":
        return validate_writer_fence_receipt(document, now=now)
    if kind in {"CUTOVER", "ROLLBACK", "UNFREEZE"}:
        value = validate_transition_receipt(document, now=now)
        if value.get("transition_type") != kind:
            raise GateError("DEPLOYMENT_SIGNING_DOCUMENT_INVALID")
        return value
    raise GateError("DEPLOYMENT_SIGNING_KIND_INVALID")


def _signing_payload(kind: str, key_id: str, document: Mapping[str, Any]) -> bytes:
    return canonical_json({
        "schema_version": SIGNING_PAYLOAD_SCHEMA_VERSION,
        "document_kind": kind,
        "document_digest": _digest(document),
        "key_id": key_id,
        "key_usage": KEY_USAGE,
        "document": document,
    })


def _document_observed_at(kind: str, document: Mapping[str, Any], code: str) -> datetime:
    field = "measured_at" if kind == "WRITER_FENCE" else "observed_at"
    return _time(document.get(field), code)


def prepare_signing_request(
    document: object,
    *,
    document_kind: str,
    key_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _now(now)
    if document_kind not in DOCUMENT_ROLES or _KEY_ID.fullmatch(key_id) is None:
        raise GateError("DEPLOYMENT_SIGNING_REQUEST_INVALID")
    normalized = _validate_document(document_kind, document, current)
    payload = _signing_payload(document_kind, key_id, normalized)
    request: dict[str, Any] = {
        "schema_version": SIGNING_REQUEST_SCHEMA_VERSION,
        "document_kind": document_kind,
        "key_id": key_id,
        "key_usage": KEY_USAGE,
        "algorithm": ALGORITHM,
        "document": normalized,
        "document_digest": _digest(normalized),
        "signing_payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "prepared_at": current.isoformat().replace("+00:00", "Z"),
    }
    # The stable request identity is the digest of the bytes the external authority signs.
    # This lets a verifier re-establish the binding from a finalized envelope without
    # trusting non-signed transport metadata such as ``prepared_at``.
    request["request_digest"] = hashlib.sha256(payload).hexdigest()
    return request


def _validate_signing_request(value: object, *, now: datetime) -> tuple[dict[str, Any], bytes]:
    code = "DEPLOYMENT_SIGNING_REQUEST_INVALID"
    request = _mapping(value, _SIGNING_REQUEST_FIELDS, code)
    kind = request.get("document_kind")
    key_id = _text(request.get("key_id"), _KEY_ID, code)
    prepared = _time(request.get("prepared_at"), code)
    normalized = _validate_document(str(kind), request.get("document"), now)
    claimed_request_digest = request.get("request_digest")
    payload = _decode_payload(request.get("signing_payload"), code)
    expected_payload = _signing_payload(str(kind), key_id, normalized)
    if (
        request.get("schema_version") != SIGNING_REQUEST_SCHEMA_VERSION
        or kind not in DOCUMENT_ROLES
        or request.get("key_usage") != KEY_USAGE
        or request.get("algorithm") != ALGORITHM
        or request.get("document_digest") != _digest(normalized)
        or payload != expected_payload
        or request.get("payload_sha256") != hashlib.sha256(payload).hexdigest()
        or prepared > now + timedelta(seconds=30)
        or prepared < now - timedelta(minutes=15)
        or claimed_request_digest != hashlib.sha256(payload).hexdigest()
    ):
        raise GateError(code)
    return json.loads(canonical_json(request)), payload


def finalize_external_signature(
    signing_request: object,
    external_signature: object,
    keyring: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _now(now)
    request, payload = _validate_signing_request(signing_request, now=current)
    code = "DEPLOYMENT_EXTERNAL_SIGNATURE_INVALID"
    signature = _mapping(external_signature, _EXTERNAL_SIGNATURE_FIELDS, code)
    signed_at = _time(signature.get("signed_at"), code)
    keys = validate_cutover_keyring(keyring, now=current)
    key = keys.get(str(request["key_id"]))
    expected_role = DOCUMENT_ROLES[str(request["document_kind"])]
    if (
        signature.get("schema_version") != EXTERNAL_SIGNATURE_SCHEMA_VERSION
        or signature.get("request_digest") != request.get("request_digest")
        or signature.get("key_id") != request.get("key_id")
        or signature.get("algorithm") != ALGORITHM
        or key is None
        or key.get("status") != "ACTIVE"
        or key.get("revoked_at") is not None
        or expected_role not in key.get("roles", [])
        or not _time(key.get("not_before"), code) <= signed_at <= current + timedelta(seconds=30)
        or _time(key.get("not_after"), code) <= current
        or signed_at < _time(request.get("prepared_at"), code)
        or signed_at < _document_observed_at(
            str(request["document_kind"]), request["document"], code
        )
        or signed_at > _time(request["document"]["valid_until"], code)
    ):
        raise GateError(code)
    signature_bytes = _decode_base64url(signature.get("signature"), 64, _BASE64URL_64, code)
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(key.get("public_key"), 32, _BASE64URL_32, code)
        ).verify(signature_bytes, payload)
    except (InvalidSignature, ValueError):
        raise GateError(code) from None
    return {
        "schema_version": SIGNED_RECEIPT_SCHEMA_VERSION,
        "document_kind": request["document_kind"],
        "document": request["document"],
        "document_digest": request["document_digest"],
        "signer_id": key["signer_id"],
        "organization": key["organization"],
        "role": expected_role,
        "key_id": key["key_id"],
        "key_usage": KEY_USAGE,
        "algorithm": ALGORITHM,
        "signed_at": signature["signed_at"],
        "request_digest": request["request_digest"],
        "signature": signature["signature"],
    }


def verify_signed_receipt(
    value: object,
    keyring: object,
    *,
    expected_kind: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _now(now)
    code = "DEPLOYMENT_SIGNED_RECEIPT_INVALID"
    envelope = _mapping(value, _SIGNED_RECEIPT_FIELDS, code)
    kind = envelope.get("document_kind")
    if expected_kind is not None and kind != expected_kind:
        raise GateError(code)
    document = _validate_document(str(kind), envelope.get("document"), current)
    keys = validate_cutover_keyring(keyring, now=current)
    key = keys.get(str(envelope.get("key_id")))
    signed_at = _time(envelope.get("signed_at"), code)
    if (
        envelope.get("schema_version") != SIGNED_RECEIPT_SCHEMA_VERSION
        or kind not in DOCUMENT_ROLES
        or envelope.get("document_digest") != _digest(document)
        or envelope.get("key_usage") != KEY_USAGE
        or envelope.get("algorithm") != ALGORITHM
        or envelope.get("role") != DOCUMENT_ROLES[str(kind)]
        or key is None
        or envelope.get("signer_id") != key.get("signer_id")
        or envelope.get("organization") != key.get("organization")
        or envelope.get("role") not in key.get("roles", [])
        or key.get("status") != "ACTIVE"
        or key.get("revoked_at") is not None
        or not _time(key.get("not_before"), code) <= signed_at
        or _time(key.get("not_after"), code) <= current
        or signed_at > current + timedelta(seconds=30)
        or signed_at < _document_observed_at(str(kind), document, code)
        or signed_at > _time(document.get("valid_until"), code)
        or envelope.get("request_digest") != hashlib.sha256(
            _signing_payload(str(kind), str(key["key_id"]), document)
        ).hexdigest()
    ):
        raise GateError(code)
    payload = _signing_payload(str(kind), str(key["key_id"]), document)
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(key.get("public_key"), 32, _BASE64URL_32, code)
        ).verify(
            _decode_base64url(envelope.get("signature"), 64, _BASE64URL_64, code),
            payload,
        )
    except (InvalidSignature, ValueError):
        raise GateError(code) from None
    return json.loads(canonical_json(envelope))


def verify_transition_chain(
    writer_fence: object,
    inventories: Sequence[object],
    transitions: Sequence[object],
    keyring: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify CUTOVER -> [ROLLBACK] -> UNFREEZE with strict SoD and digest chaining."""

    current = _now(now)
    code = "DEPLOYMENT_TRANSITION_CHAIN_INVALID"
    fence_envelope = verify_signed_receipt(
        writer_fence, keyring, expected_kind="WRITER_FENCE", now=current
    )
    fence = fence_envelope["document"]
    inventory_by_digest: dict[str, dict[str, Any]] = {}
    inventory_ids: set[str] = set()
    for raw in inventories:
        inventory = validate_blue_green_inventory(raw, now=current)
        digest = str(inventory["inventory_digest"])
        inventory_id = str(inventory["inventory_id"])
        if digest in inventory_by_digest or inventory_id in inventory_ids:
            raise GateError(code)
        inventory_by_digest[digest] = inventory
        inventory_ids.add(inventory_id)
    if not inventory_by_digest or not 2 <= len(transitions) <= 3:
        raise GateError(code)

    verified: list[dict[str, Any]] = []
    signer_ids = {str(fence_envelope["signer_id"])}
    transition_ids: set[str] = set()
    used_inventory_digests: set[str] = set()
    previous_digest = "0" * 64
    state = "DRAINED"
    expected_sequence = 1
    last_event_at = _time(fence_envelope["signed_at"], code)
    for raw in transitions:
        envelope = verify_signed_receipt(raw, keyring, now=current)
        receipt = envelope["document"]
        kind = str(envelope["document_kind"])
        inventory = inventory_by_digest.get(str(receipt["inventory_digest"]))
        if (
            kind == "WRITER_FENCE"
            or envelope["signer_id"] in signer_ids
            or receipt["transition_id"] in transition_ids
            or receipt["sequence"] != expected_sequence
            or receipt["previous_transition_digest"] != previous_digest
            or receipt["writer_fence_receipt_digest"] != fence["receipt_digest"]
            or receipt["source_release_id"] != fence["source_release_id"]
            or receipt["target_release_id"] != fence["target_release_id"]
            or receipt["environment_reference"] != fence["environment_reference"]
            or receipt["from_state"] != state
            or inventory is None
            or inventory["source_release_id"] != fence["source_release_id"]
            or inventory["target_release_id"] != fence["target_release_id"]
            or inventory["environment_reference"] != fence["environment_reference"]
            or receipt["traffic_revision"] != inventory["traffic_revision"]
            or _time(inventory["observed_at"], code) <= last_event_at
            or _time(inventory["observed_at"], code) > _time(receipt["observed_at"], code)
            or _time(receipt["observed_at"], code) <= last_event_at
            or _time(envelope["signed_at"], code) <= last_event_at
        ):
            raise GateError(code)
        source_revision = inventory["source_revision"]
        target_revision = inventory["target_revision"]
        if kind == "CUTOVER":
            if expected_sequence != 1 or state != "DRAINED" or receipt["traffic_revision"] != target_revision:
                raise GateError(code)
        elif kind == "ROLLBACK":
            if expected_sequence != 2 or state != "CUTOVER_COMMITTED" or receipt["traffic_revision"] != source_revision:
                raise GateError(code)
        elif kind == "UNFREEZE":
            expected_active = (
                "TARGET_ACTIVE" if state == "CUTOVER_COMMITTED"
                else "SOURCE_ACTIVE" if state == "ROLLBACK_COMMITTED"
                else None
            )
            expected_revision = target_revision if expected_active == "TARGET_ACTIVE" else source_revision
            if expected_active is None or receipt["to_state"] != expected_active or receipt["traffic_revision"] != expected_revision:
                raise GateError(code)
        else:
            raise GateError(code)
        signer_ids.add(str(envelope["signer_id"]))
        transition_ids.add(str(receipt["transition_id"]))
        used_inventory_digests.add(str(receipt["inventory_digest"]))
        verified.append(envelope)
        previous_digest = str(receipt["receipt_digest"])
        state = str(receipt["to_state"])
        last_event_at = _time(envelope["signed_at"], code)
        expected_sequence += 1
    if (
        state not in {"SOURCE_ACTIVE", "TARGET_ACTIVE"}
        or verified[-1]["document_kind"] != "UNFREEZE"
        or used_inventory_digests != set(inventory_by_digest)
    ):
        raise GateError(code)
    return {
        "schema_version": "agenttrust.deployment-cutover-chain-verification.v1",
        "verified": True,
        "external_actions_executed_by_this_module": False,
        "source_release_id": fence["source_release_id"],
        "target_release_id": fence["target_release_id"],
        "environment_reference": fence["environment_reference"],
        "writer_fence_receipt_digest": fence["receipt_digest"],
        "transition_count": len(verified),
        "final_state": state,
        "final_transition_digest": previous_digest,
        "signer_ids": sorted(signer_ids),
    }
