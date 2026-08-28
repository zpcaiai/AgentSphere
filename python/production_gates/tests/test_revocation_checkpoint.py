from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import runpy
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.revocation_checkpoint import (
    advance_checkpoint_file,
    genesis_checkpoint,
    initialize_checkpoint_file,
    next_checkpoint,
    read_checkpoint,
    verify_base_registry,
    verify_successor,
)


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class ProductionRevocationCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.private_key = Ed25519PrivateKey.generate()
        self.key = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": "revocation-key-1",
            "public_key": encoded(
                self.private_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ),
        }

    def registry(
        self, sequence: int, previous: str | None, *, published_offset: int = -30
    ) -> dict[str, object]:
        published = self.now + timedelta(seconds=published_offset)
        value: dict[str, object] = {
            "schema_version": "agenttrust.production-closure-revocation-registry.v1",
            "registry_id": "production-revocations",
            "sequence": sequence,
            "previous_registry_digest": previous,
            "published_at": published.isoformat().replace("+00:00", "Z"),
            "expires_at": (self.now + timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z"),
            "key_id": "revocation-key-1",
            "entries": [],
            "signature": "",
        }
        value["signature"] = encoded(self.private_key.sign(canonical_json(value)))
        return value

    def test_genesis_accepts_only_sequence_one(self) -> None:
        checkpoint = genesis_checkpoint(
            registry_id="production-revocations",
            key_id="revocation-key-1",
            initialized_at=self.now - timedelta(minutes=2),
        )
        verify_base_registry(checkpoint, None, self.key)
        first = self.registry(1, None)
        _, _, digest = verify_successor(checkpoint, first, self.key)
        current = next_checkpoint(
            checkpoint, first, self.key, updated_at=self.now
        )
        self.assertEqual(current["registry_digest"], digest)
        with self.assertRaisesRegex(GateError, "SUCCESSOR_INVALID"):
            verify_successor(current, first, self.key)
        with self.assertRaisesRegex(GateError, "PREVIOUS_REGISTRY_REQUIRED"):
            verify_base_registry(current, None, self.key)
        verify_base_registry(current, first, self.key)

    def test_signature_and_previous_digest_tampering_fail(self) -> None:
        checkpoint = genesis_checkpoint(
            registry_id="production-revocations",
            key_id="revocation-key-1",
            initialized_at=self.now - timedelta(minutes=2),
        )
        tampered = self.registry(1, None)
        tampered["signature"] = "A" * 86
        with self.assertRaisesRegex(GateError, "SIGNATURE_INVALID"):
            verify_successor(checkpoint, tampered, self.key)
        wrong_chain = self.registry(2, "a" * 64)
        with self.assertRaisesRegex(GateError, "SUCCESSOR_INVALID"):
            verify_successor(checkpoint, wrong_chain, self.key)

    def test_file_checkpoint_advances_once_with_activation_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            checkpoint_path = directory / "checkpoint.json"
            lock_path = directory / "checkpoint.lock"
            initial = initialize_checkpoint_file(
                checkpoint_path,
                lock_path,
                registry_id="production-revocations",
                key_id="revocation-key-1",
                initialized_at=self.now - timedelta(minutes=2),
            )
            registry = self.registry(1, None)
            _, _, registry_digest = verify_successor(initial, registry, self.key)
            activation = {
                "schema_version": "agenttrust.production-release-activation-receipt.v1",
                "admitted": True,
                "revocation_registry_id": "production-revocations",
                "revocation_registry_sequence": 1,
                "revocation_registry_digest": registry_digest,
            }
            successor, receipt = advance_checkpoint_file(
                checkpoint_path,
                lock_path,
                registry,
                self.key,
                activation,
                expected_checkpoint_digest=str(initial["checkpoint_digest"]),
                updated_at=self.now,
            )
            self.assertEqual(read_checkpoint(checkpoint_path, mutable=True), successor)
            self.assertEqual(receipt["previous_sequence"], 0)
            replayed, replay_receipt = advance_checkpoint_file(
                checkpoint_path,
                lock_path,
                registry,
                self.key,
                activation,
                expected_checkpoint_digest=str(initial["checkpoint_digest"]),
                updated_at=self.now,
            )
            self.assertEqual(replayed, successor)
            self.assertEqual(replay_receipt, receipt)

    def test_evidence_intake_stages_checkpoint_as_canonical_json(self) -> None:
        root = Path(__file__).resolve().parents[3]
        intake_cli = runpy.run_path(str(root / "scripts/intake-production-evidence.py"))
        checkpoint = genesis_checkpoint(
            registry_id="production-revocations",
            key_id="revocation-key-1",
            initialized_at=self.now,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            intake_cli["_write_new"](
                directory, "revocation-checkpoint.json", checkpoint
            )
            path = directory / "revocation-checkpoint.json"
            self.assertEqual(path.read_bytes(), canonical_json(checkpoint) + b"\n")
            self.assertEqual(read_checkpoint(path, mutable=True), checkpoint)


if __name__ == "__main__":
    unittest.main()
