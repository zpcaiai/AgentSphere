from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.evidence_intake import validate_evidence_intake
from python.production_gates.live_integrations import GateError
from python.production_gates.qualification import scope_digest
from python.production_gates.revocation_checkpoint import genesis_checkpoint
from python.production_gates.tests.qualification_fixtures import (
    QualificationFixture,
    public_key,
)


class ProductionEvidenceIntakeTests(unittest.TestCase):
    def test_exact_candidate_and_runtime_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            runtime = {
                "environment": "production",
                "topology": ["zone-a", "zone-b", "zone-c"],
            }
            revocation_key = Ed25519PrivateKey.generate()
            key_spec = {
                "schema_version": "agenttrust.ed25519-public-key.v1",
                "key_id": "revocation-key-1",
                "public_key": public_key(revocation_key),
            }
            update = {
                "schema_version": "agenttrust.production-closure-revocation-update.v1",
                "registry_id": "production-revocations",
                "key_id": "revocation-key-1",
                "base_checkpoint_digest": "",
                "valid_for_seconds": 3600,
                "new_entries": [],
            }
            checkpoint = genesis_checkpoint(
                registry_id="production-revocations",
                key_id="revocation-key-1",
                initialized_at=fixture.now,
            )
            update["base_checkpoint_digest"] = checkpoint["checkpoint_digest"]
            closure_input, receipt = validate_evidence_intake(
                fixture.package,
                fixture.image_manifest,
                runtime,
                update,
                fixture.anchors,
                key_spec,
                revocation_checkpoint=checkpoint,
                previous_revocation_registry=None,
                expected_release_tag="v9.0.0",
                expected_repository="agentsphere/control-plane",
                now=fixture.now,
            )
            self.assertEqual(
                scope_digest(closure_input["scope"]), scope_digest(fixture.scope)
            )
            self.assertTrue(receipt["verified"])
            self.assertEqual(
                receipt["production_image_manifest_digest"], fixture.scope["build_digest"]
            )

    def test_candidate_runtime_and_revocation_key_mismatches_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            revocation_key = Ed25519PrivateKey.generate()
            key_spec = {
                "schema_version": "agenttrust.ed25519-public-key.v1",
                "key_id": "revocation-key-1",
                "public_key": public_key(revocation_key),
            }
            update = {
                "schema_version": "agenttrust.production-closure-revocation-update.v1",
                "registry_id": "production-revocations",
                "key_id": "wrong-key",
                "base_checkpoint_digest": "",
                "valid_for_seconds": 3600,
                "new_entries": [],
            }
            checkpoint = genesis_checkpoint(
                registry_id="production-revocations",
                key_id="revocation-key-1",
                initialized_at=fixture.now,
            )
            update["base_checkpoint_digest"] = checkpoint["checkpoint_digest"]
            runtime = {
                "environment": "production",
                "topology": ["zone-a", "zone-b", "zone-c"],
            }
            with self.assertRaisesRegex(GateError, "EVIDENCE_INTAKE_REVOCATION_INVALID"):
                validate_evidence_intake(
                    fixture.package, fixture.image_manifest, runtime, update,
                    fixture.anchors, key_spec,
                    revocation_checkpoint=checkpoint,
                    previous_revocation_registry=None,
                    expected_release_tag="v9.0.0",
                    expected_repository="agentsphere/control-plane",
                    now=fixture.now,
                )

            tampered = copy.deepcopy(fixture.image_manifest)
            tampered["images"]["runtime"] = (
                "registry.example/runtime@sha256:" + "f" * 64
            )
            with self.assertRaises(GateError):
                validate_evidence_intake(
                    fixture.package, tampered, runtime,
                    {**update, "key_id": "revocation-key-1"}, fixture.anchors, key_spec,
                    revocation_checkpoint=checkpoint,
                    previous_revocation_registry=None,
                    expected_release_tag="v9.0.0",
                    expected_repository="agentsphere/control-plane",
                    now=fixture.now,
                )

            with self.assertRaisesRegex(GateError, "EVIDENCE_INTAKE_RELEASE_BINDING_INVALID"):
                validate_evidence_intake(
                    fixture.package, fixture.image_manifest,
                    {**runtime, "topology": ["zone-a"]},
                    {**update, "key_id": "revocation-key-1"}, fixture.anchors, key_spec,
                    revocation_checkpoint=checkpoint,
                    previous_revocation_registry=None,
                    expected_release_tag="v9.0.0",
                    expected_repository="agentsphere/control-plane",
                    now=fixture.now,
                )


if __name__ == "__main__":
    unittest.main()
