from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.deployment_cutover import (
    ALGORITHM,
    EXTERNAL_SIGNATURE_SCHEMA_VERSION,
    KEY_USAGE,
    finalize_external_signature,
    prepare_signing_request,
    validate_blue_green_inventory,
    validate_cutover_keyring,
    validate_transition_receipt,
    validate_writer_fence_receipt,
    verify_signed_receipt,
    verify_transition_chain,
)
from python.production_gates.deployment_cutover_broker import (
    prepare_broker_request,
    validate_broker_response,
)
from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


NOW = datetime(2026, 8, 28, 7, 0, tzinfo=timezone.utc)
SOURCE = "git:sha256:" + "1" * 64
TARGET = "git:sha256:" + "2" * 64
ENVIRONMENT = "environment://production/cn-east/control-plane"
SOURCE_REVISION = "revision-source-11111111"
TARGET_REVISION = "revision-target-22222222"
ZERO_DIGEST = "0" * 64


def _utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _digested(value: dict[str, object], field: str) -> dict[str, object]:
    result = copy.deepcopy(value)
    result[field] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


class DeploymentCutoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_keys = {
            "fence-key": Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))),
            "cutover-key": Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65))),
            "rollback-key": Ed25519PrivateKey.from_private_bytes(bytes(range(65, 97))),
            "unfreeze-key": Ed25519PrivateKey.from_private_bytes(bytes(range(97, 129))),
        }
        roles = {
            "fence-key": "SRE_RELEASE_FENCE",
            "cutover-key": "RELEASE_CUTOVER_AUTHORITY",
            "rollback-key": "DISASTER_RECOVERY_OWNER",
            "unfreeze-key": "SRE_RELEASE_UNFREEZE",
        }
        self.keyring = {
            "schema_version": "agenttrust.deployment-cutover-keyring.v1",
            "keyring_id": "cutover-keyring:production",
            "version": 1,
            "issued_at": _utc(NOW - timedelta(days=1)),
            "expires_at": _utc(NOW + timedelta(days=30)),
            "keys": [
                {
                    "key_id": key_id,
                    "signer_id": f"signer:{index}",
                    "organization": "AgentTrust Operations",
                    "roles": [roles[key_id]],
                    "key_usage": KEY_USAGE,
                    "algorithm": ALGORITHM,
                    "public_key": _b64(private.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )),
                    "status": "ACTIVE",
                    "not_before": _utc(NOW - timedelta(days=1)),
                    "not_after": _utc(NOW + timedelta(days=30)),
                    "revoked_at": None,
                }
                for index, (key_id, private) in enumerate(self.private_keys.items(), 1)
            ],
        }

    def fence(self) -> dict[str, object]:
        return _digested({
            "schema_version": "agenttrust.deployment-writer-fence-receipt.v1",
            "fence_id": "11111111-1111-4111-8111-111111111111",
            "source_release_id": SOURCE,
            "target_release_id": TARGET,
            "environment_reference": ENVIRONMENT,
            "fence_applied": True,
            "writes_blocked": True,
            "drain_complete": True,
            "inflight_action_count": 0,
            "pending_outbox_count": 0,
            "active_execution_lease_count": 0,
            "database_recovery": {
                "database_cluster_id": "postgres-primary",
                "checkpoint_id": "checkpoint-20260828-1",
                "checkpoint_digest": "3" * 64,
                "wal_lsn": "16/B374D848",
                "wal_segment_digest": "4" * 64,
                "backup_id": "backup-20260828-1",
                "backup_manifest_digest": "5" * 64,
                "backup_object_version_digest": "6" * 64,
                "backup_verified_at": _utc(NOW - timedelta(hours=1)),
                "restore_test_receipt_digest": "7" * 64,
            },
            "evidence_digests": {
                "backup_readback": "8" * 64,
                "database_checkpoint": "9" * 64,
                "inflight_query": "a" * 64,
                "lease_query": "b" * 64,
                "outbox_query": "c" * 64,
                "write_fence": "d" * 64,
            },
            "measured_at": _utc(NOW - timedelta(minutes=1)),
            "valid_until": _utc(NOW + timedelta(minutes=10)),
        }, "receipt_digest")

    def inventory(
        self,
        traffic_revision: str,
        *,
        observed_seconds_ago: int,
        inventory_id_seed: int,
    ) -> dict[str, object]:
        return _digested({
            "schema_version": "agenttrust.deployment-blue-green-inventory.v1",
            "inventory_id": (
                f"{inventory_id_seed:08x}-2222-4222-8222-222222222222"
            ),
            "source_release_id": SOURCE,
            "target_release_id": TARGET,
            "source_revision": SOURCE_REVISION,
            "target_revision": TARGET_REVISION,
            "environment_reference": ENVIRONMENT,
            "traffic_revision": traffic_revision,
            "traffic_bindings": [
                {"service_name": "agenttrust-control", "revision": traffic_revision},
                {"service_name": "agenttrust-runtime", "revision": traffic_revision},
            ],
            "workloads": [
                {
                    "workload_name": name,
                    "revision": revision,
                    "release_id": release,
                    "image": f"ghcr.io/example/{name}@sha256:{digest * 64}",
                    "desired_replicas": 3,
                    "ready_replicas": 3,
                    "available_replicas": 3,
                }
                for name in ("control", "runtime")
                for revision, release, digest in (
                    (SOURCE_REVISION, SOURCE, "1"),
                    (TARGET_REVISION, TARGET, "2"),
                )
            ],
            "observed_at": _utc(NOW - timedelta(seconds=observed_seconds_ago)),
            "valid_until": _utc(NOW + timedelta(minutes=10)),
        }, "inventory_digest")

    def transition(
        self,
        kind: str,
        sequence: int,
        previous: str,
        fence_digest: str,
        inventory: dict[str, object],
        from_state: str,
        to_state: str,
        *,
        observed_seconds_ago: int,
    ) -> dict[str, object]:
        evidence_keys = {
            "CUTOVER": ["cutover_operation", "health_observation", "traffic_observation"],
            "ROLLBACK": ["health_observation", "rollback_operation", "traffic_observation"],
            "UNFREEZE": ["control_plane_observation", "traffic_observation", "write_unfreeze"],
        }[kind]
        return _digested({
            "schema_version": "agenttrust.deployment-transition-receipt.v1",
            "transition_id": f"{sequence + 3:08x}-4444-4444-8444-444444444444",
            "transition_type": kind,
            "source_release_id": SOURCE,
            "target_release_id": TARGET,
            "environment_reference": ENVIRONMENT,
            "sequence": sequence,
            "previous_transition_digest": previous,
            "writer_fence_receipt_digest": fence_digest,
            "inventory_digest": inventory["inventory_digest"],
            "traffic_revision": inventory["traffic_revision"],
            "writes_fenced": kind != "UNFREEZE",
            "from_state": from_state,
            "to_state": to_state,
            "evidence_digests": {
                name: format(index + 10, "x")[-1] * 64
                for index, name in enumerate(evidence_keys)
            },
            "observed_at": _utc(NOW - timedelta(seconds=observed_seconds_ago)),
            "valid_until": _utc(NOW + timedelta(minutes=10)),
        }, "receipt_digest")

    def sign(
        self,
        document: dict[str, object],
        kind: str,
        key_id: str,
        *,
        signed_seconds_ago: int = 0,
    ) -> dict[str, object]:
        signed_at = NOW - timedelta(seconds=signed_seconds_ago)
        request = prepare_signing_request(
            document, document_kind=kind, key_id=key_id, now=signed_at
        )
        payload = base64.urlsafe_b64decode(request["signing_payload"] + "==")
        external = {
            "schema_version": EXTERNAL_SIGNATURE_SCHEMA_VERSION,
            "request_digest": request["request_digest"],
            "key_id": key_id,
            "algorithm": ALGORITHM,
            "signed_at": _utc(signed_at),
            "signature": _b64(self.private_keys[key_id].sign(payload)),
        }
        return finalize_external_signature(
            request, external, self.keyring, now=signed_at
        )

    def test_fence_requires_zero_work_and_fresh_recovery_evidence(self) -> None:
        self.assertEqual(
            self.fence(), validate_writer_fence_receipt(self.fence(), now=NOW)
        )
        for mutation in ("inflight", "backup", "expiry"):
            invalid = self.fence()
            if mutation == "inflight":
                invalid["inflight_action_count"] = 1
            elif mutation == "backup":
                invalid["database_recovery"]["backup_verified_at"] = _utc(
                    NOW - timedelta(hours=25)
                )
            else:
                invalid["valid_until"] = _utc(NOW)
            invalid.pop("receipt_digest")
            invalid = _digested(invalid, "receipt_digest")
            with self.assertRaises(GateError):
                validate_writer_fence_receipt(invalid, now=NOW)

    def test_external_signature_is_role_and_payload_bound(self) -> None:
        signed = self.sign(self.fence(), "WRITER_FENCE", "fence-key")
        self.assertEqual(
            signed,
            verify_signed_receipt(signed, self.keyring, expected_kind="WRITER_FENCE", now=NOW),
        )
        wrong_role_request = prepare_signing_request(
            self.fence(), document_kind="WRITER_FENCE", key_id="cutover-key", now=NOW
        )
        payload = base64.urlsafe_b64decode(wrong_role_request["signing_payload"] + "==")
        wrong_role_signature = {
            "schema_version": EXTERNAL_SIGNATURE_SCHEMA_VERSION,
            "request_digest": wrong_role_request["request_digest"],
            "key_id": "cutover-key",
            "algorithm": ALGORITHM,
            "signed_at": _utc(NOW),
            "signature": _b64(self.private_keys["cutover-key"].sign(payload)),
        }
        with self.assertRaises(GateError):
            finalize_external_signature(
                wrong_role_request, wrong_role_signature, self.keyring, now=NOW
            )
        tampered = copy.deepcopy(signed)
        tampered["document"]["database_recovery"]["wal_lsn"] = "16/B374D849"
        with self.assertRaises(GateError):
            verify_signed_receipt(tampered, self.keyring, now=NOW)

    def test_inventory_rejects_mixed_traffic_and_revision_holes(self) -> None:
        target = self.inventory(
            TARGET_REVISION, observed_seconds_ago=30, inventory_id_seed=1
        )
        self.assertEqual(target, validate_blue_green_inventory(target, now=NOW))
        mixed = copy.deepcopy(target)
        mixed["traffic_bindings"][1]["revision"] = SOURCE_REVISION
        mixed.pop("inventory_digest")
        mixed = _digested(mixed, "inventory_digest")
        with self.assertRaises(GateError):
            validate_blue_green_inventory(mixed, now=NOW)
        missing = copy.deepcopy(target)
        missing["workloads"].pop()
        missing.pop("inventory_digest")
        missing = _digested(missing, "inventory_digest")
        with self.assertRaises(GateError):
            validate_blue_green_inventory(missing, now=NOW)
        inactive_source = self.inventory(
            SOURCE_REVISION, observed_seconds_ago=20, inventory_id_seed=2
        )
        for workload in inactive_source["workloads"]:
            if workload["revision"] == SOURCE_REVISION:
                workload["desired_replicas"] = 0
                workload["ready_replicas"] = 0
                workload["available_replicas"] = 0
        inactive_source.pop("inventory_digest")
        inactive_source = _digested(inactive_source, "inventory_digest")
        with self.assertRaises(GateError):
            validate_blue_green_inventory(inactive_source, now=NOW)

    def test_transition_receipt_rejects_non_monotonic_standalone_state(self) -> None:
        fence = self.fence()
        inventory = self.inventory(
            TARGET_REVISION, observed_seconds_ago=50, inventory_id_seed=1
        )
        invalid_sequence = self.transition(
            "CUTOVER", 2, ZERO_DIGEST, fence["receipt_digest"], inventory,
            "DRAINED", "CUTOVER_COMMITTED", observed_seconds_ago=40,
        )
        with self.assertRaises(GateError):
            validate_transition_receipt(invalid_sequence, now=NOW)

        invalid_unfreeze = self.transition(
            "UNFREEZE", 2, "e" * 64, fence["receipt_digest"], inventory,
            "CUTOVER_COMMITTED", "SOURCE_ACTIVE", observed_seconds_ago=40,
        )
        with self.assertRaises(GateError):
            validate_transition_receipt(invalid_unfreeze, now=NOW)

    def test_cutover_then_unfreeze_is_a_monotonic_sod_chain(self) -> None:
        fence = self.fence()
        cutover_inventory = self.inventory(
            TARGET_REVISION, observed_seconds_ago=50, inventory_id_seed=1
        )
        unfreeze_inventory = self.inventory(
            TARGET_REVISION, observed_seconds_ago=30, inventory_id_seed=2
        )
        cutover = self.transition(
            "CUTOVER", 1, ZERO_DIGEST, fence["receipt_digest"], cutover_inventory,
            "DRAINED", "CUTOVER_COMMITTED",
            observed_seconds_ago=40,
        )
        unfreeze = self.transition(
            "UNFREEZE", 2, cutover["receipt_digest"], fence["receipt_digest"],
            unfreeze_inventory,
            "CUTOVER_COMMITTED", "TARGET_ACTIVE",
            observed_seconds_ago=20,
        )
        result = verify_transition_chain(
            self.sign(
                fence, "WRITER_FENCE", "fence-key", signed_seconds_ago=55
            ),
            [cutover_inventory, unfreeze_inventory],
            [
                self.sign(
                    cutover, "CUTOVER", "cutover-key", signed_seconds_ago=35
                ),
                self.sign(
                    unfreeze, "UNFREEZE", "unfreeze-key", signed_seconds_ago=15
                ),
            ],
            self.keyring,
            now=NOW,
        )
        self.assertEqual("TARGET_ACTIVE", result["final_state"])
        self.assertFalse(result["external_actions_executed_by_this_module"])

    def test_cutover_rollback_unfreeze_chain_returns_source_active(self) -> None:
        fence = self.fence()
        target = self.inventory(
            TARGET_REVISION, observed_seconds_ago=50, inventory_id_seed=1
        )
        source_rollback = self.inventory(
            SOURCE_REVISION, observed_seconds_ago=30, inventory_id_seed=2
        )
        source_unfreeze = self.inventory(
            SOURCE_REVISION, observed_seconds_ago=15, inventory_id_seed=3
        )
        cutover = self.transition(
            "CUTOVER", 1, ZERO_DIGEST, fence["receipt_digest"], target,
            "DRAINED", "CUTOVER_COMMITTED",
            observed_seconds_ago=40,
        )
        rollback = self.transition(
            "ROLLBACK", 2, cutover["receipt_digest"], fence["receipt_digest"],
            source_rollback,
            "CUTOVER_COMMITTED", "ROLLBACK_COMMITTED",
            observed_seconds_ago=25,
        )
        unfreeze = self.transition(
            "UNFREEZE", 3, rollback["receipt_digest"], fence["receipt_digest"],
            source_unfreeze,
            "ROLLBACK_COMMITTED", "SOURCE_ACTIVE",
            observed_seconds_ago=10,
        )
        result = verify_transition_chain(
            self.sign(
                fence, "WRITER_FENCE", "fence-key", signed_seconds_ago=55
            ),
            [target, source_rollback, source_unfreeze],
            [
                self.sign(
                    cutover, "CUTOVER", "cutover-key", signed_seconds_ago=35
                ),
                self.sign(
                    rollback, "ROLLBACK", "rollback-key", signed_seconds_ago=20
                ),
                self.sign(
                    unfreeze, "UNFREEZE", "unfreeze-key", signed_seconds_ago=5
                ),
            ],
            self.keyring,
            now=NOW,
        )
        self.assertEqual("SOURCE_ACTIVE", result["final_state"])

    def test_chain_rejects_replay_sequence_and_signer_reuse(self) -> None:
        fence = self.fence()
        cutover_inventory = self.inventory(
            TARGET_REVISION, observed_seconds_ago=50, inventory_id_seed=1
        )
        unfreeze_inventory = self.inventory(
            TARGET_REVISION, observed_seconds_ago=30, inventory_id_seed=2
        )
        cutover = self.transition(
            "CUTOVER", 1, ZERO_DIGEST, fence["receipt_digest"], cutover_inventory,
            "DRAINED", "CUTOVER_COMMITTED",
            observed_seconds_ago=40,
        )
        unfreeze = self.transition(
            "UNFREEZE", 2, ZERO_DIGEST, fence["receipt_digest"], unfreeze_inventory,
            "CUTOVER_COMMITTED", "TARGET_ACTIVE",
            observed_seconds_ago=20,
        )
        with self.assertRaises(GateError):
            verify_transition_chain(
                self.sign(
                    fence, "WRITER_FENCE", "fence-key", signed_seconds_ago=55
                ),
                [cutover_inventory, unfreeze_inventory],
                [
                    self.sign(
                        cutover, "CUTOVER", "cutover-key", signed_seconds_ago=35
                    ),
                    self.sign(
                        unfreeze,
                        "UNFREEZE",
                        "unfreeze-key",
                        signed_seconds_ago=15,
                    ),
                ],
                self.keyring,
                now=NOW,
            )

        reused = copy.deepcopy(self.keyring)
        unfreeze_key = next(key for key in reused["keys"] if key["key_id"] == "unfreeze-key")
        cutover_key = next(key for key in reused["keys"] if key["key_id"] == "cutover-key")
        unfreeze_key["signer_id"] = cutover_key["signer_id"]
        with self.assertRaises(GateError):
            validate_cutover_keyring(reused, now=NOW)

    def test_broker_response_is_request_and_signed_receipt_bound(self) -> None:
        request = prepare_broker_request(
            source_release_id=SOURCE,
            target_release_id=TARGET,
            environment_reference=ENVIRONMENT,
            operation="WRITER_FENCE",
            expected_previous_transition_digest=ZERO_DIGEST,
            writer_fence_receipt_digest=ZERO_DIGEST,
            requested_at=NOW,
        )
        response = {
            "schema_version": "agenttrust.deployment-cutover-broker-response.v1",
            "request_id": request["request_id"],
            "request_digest": hashlib.sha256(canonical_json(request)).hexdigest(),
            "source_release_id": SOURCE,
            "target_release_id": TARGET,
            "environment_reference": ENVIRONMENT,
            "operation": "WRITER_FENCE",
            "expected_previous_transition_digest": ZERO_DIGEST,
            "writer_fence_receipt_digest": ZERO_DIGEST,
            "inventory": None,
            "signed_receipt": self.sign(
                self.fence(), "WRITER_FENCE", "fence-key"
            ),
            "completed_at": _utc(NOW),
        }
        self.assertEqual(
            response,
            validate_broker_response(response, request, self.keyring, now=NOW),
        )
        response["target_release_id"] = SOURCE
        with self.assertRaises(GateError):
            validate_broker_response(response, request, self.keyring, now=NOW)

        fence = self.fence()
        inventory = self.inventory(
            TARGET_REVISION, observed_seconds_ago=30, inventory_id_seed=9
        )
        cutover = self.transition(
            "CUTOVER", 1, ZERO_DIGEST, fence["receipt_digest"], inventory,
            "DRAINED", "CUTOVER_COMMITTED", observed_seconds_ago=20,
        )
        cutover_request = prepare_broker_request(
            source_release_id=SOURCE,
            target_release_id=TARGET,
            environment_reference=ENVIRONMENT,
            operation="CUTOVER",
            expected_previous_transition_digest=ZERO_DIGEST,
            writer_fence_receipt_digest=fence["receipt_digest"],
            requested_at=NOW,
        )
        cutover_response = {
            "schema_version": "agenttrust.deployment-cutover-broker-response.v1",
            "request_id": cutover_request["request_id"],
            "request_digest": hashlib.sha256(
                canonical_json(cutover_request)
            ).hexdigest(),
            "source_release_id": SOURCE,
            "target_release_id": TARGET,
            "environment_reference": ENVIRONMENT,
            "operation": "CUTOVER",
            "expected_previous_transition_digest": ZERO_DIGEST,
            "writer_fence_receipt_digest": fence["receipt_digest"],
            "inventory": inventory,
            "signed_receipt": self.sign(cutover, "CUTOVER", "cutover-key"),
            "completed_at": _utc(NOW),
        }
        self.assertEqual(
            cutover_response,
            validate_broker_response(
                cutover_response, cutover_request, self.keyring, now=NOW
            ),
        )

    def test_public_schemas_parse_and_cover_every_document(self) -> None:
        root = Path(__file__).resolve().parents[3]
        names = {
            "deployment-writer-fence-receipt.schema.json",
            "deployment-blue-green-inventory.schema.json",
            "deployment-transition-receipt.schema.json",
            "deployment-cutover-keyring.schema.json",
            "deployment-cutover-signing-request.schema.json",
            "deployment-cutover-external-signature.schema.json",
            "signed-deployment-control-receipt.schema.json",
            "deployment-cutover-chain-verification.schema.json",
            "deployment-cutover-broker-config.schema.json",
            "deployment-cutover-broker-request.schema.json",
            "deployment-cutover-broker-response.schema.json",
            "production-deployment-receipt.schema.json",
        }
        for name in names:
            value = json.loads((root / "schemas/release" / name).read_text(encoding="utf-8"))
            self.assertEqual("object", value["type"])
            self.assertFalse(value["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
