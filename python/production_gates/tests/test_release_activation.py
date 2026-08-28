from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.release_activation import (
    ActivationError,
    PRODUCTION_IMAGE_KEYS,
    REQUIRED_PRODUCTION_GATES,
    verify_activation_documents,
)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ReleaseActivationTests(unittest.TestCase):
    def fixture(self) -> dict[str, object]:
        now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        release_id = "git:sha1:" + "1" * 40
        images = {
            name: f"registry.example/{name.replace('_', '-')}@sha256:{index:064x}"
            for index, name in enumerate(sorted(PRODUCTION_IMAGE_KEYS), start=1)
        }
        activation: dict[str, object] = {
            "schema_version": "agenttrust.production-release-activation.v1",
            "release_id": release_id,
            "scope": {},
            "images": images,
            "production_image_manifest": {},
            "signed_release_binding_digest": "3" * 64,
            "evidence_bundle_manifest_digest": "4" * 64,
            "requested_at": _time(now - timedelta(minutes=1)),
        }
        image_manifest = {
            "schema_version": "agenttrust.production-image-manifest.v1",
            "release_id": release_id,
            "release_tag": "v1.2.3",
            "repository": "example/AgentSphere",
            "created_at": _time(now - timedelta(minutes=10)),
            "images": activation["images"],
            "attestations": {
                name: {
                    "component": name.replace("_", "-"),
                    "subject_digest": image.rsplit("@", 1)[1],
                    "sbom_sha256": "a" * 64,
                    "provenance_attestation_url": f"https://example.test/attestations/{name}/provenance",
                    "sbom_attestation_url": f"https://example.test/attestations/{name}/sbom",
                }
                for name, image in images.items()
            },
            "manifest_digest": "",
        }
        image_manifest["manifest_digest"] = _digest(
            {key: value for key, value in image_manifest.items() if key != "manifest_digest"}
        )
        activation["production_image_manifest"] = image_manifest
        scope = {
            "release_id": release_id,
            "commit_digest": "1" * 64,
            "build_digest": image_manifest["manifest_digest"],
            "signed_git_provenance_digest": "b" * 64,
            "signed_release_binding_digest": activation["signed_release_binding_digest"],
            "release_digest": "c" * 64,
            "reviewer_keyring_digest": "d" * 64,
            "policy_digest": "5" * 64,
            "pack_set_digest": "6" * 64,
            "prompt_set_digest": "7" * 64,
            "model_set_digest": "8" * 64,
            "topology_digest": "9" * 64,
            "environment": "production",
            "valid_from": _time(now - timedelta(hours=1)),
            "valid_until": _time(now + timedelta(days=1)),
        }
        activation["scope"] = scope
        scope_digest = _digest(scope)
        gates = {
            gate: f"{index:064x}"
            for index, gate in enumerate(sorted(REQUIRED_PRODUCTION_GATES), start=1)
        }
        report = {
            "schema_version": "agenttrust.production-closure.v1",
            "release_id": release_id,
            "scope_digest": scope_digest,
            "input_digest": "e" * 64,
            "eligible": True,
            "blockers": [],
            "verified_gate_digests": gates,
            "evaluated_at": _time(now - timedelta(minutes=5)),
            "evidence_valid_until": _time(now + timedelta(hours=12)),
            "report_digest": "",
        }
        report["report_digest"] = _digest(report)

        certificate_signing = Ed25519PrivateKey.generate()
        certificate_key_id = "kms:closure:1"
        certificate = {
            "schema_version": "agenttrust.production-closure.v1",
            "certificate_id": "pc-" + str(report["report_digest"])[:24],
            "release_id": release_id,
            "scope_digest": scope_digest,
            "input_digest": report["input_digest"],
            "report_digest": report["report_digest"],
            "signed_git_provenance_digest": scope["signed_git_provenance_digest"],
            "signed_release_binding_digest": scope["signed_release_binding_digest"],
            "release_digest": scope["release_digest"],
            "reviewer_keyring_digest": scope["reviewer_keyring_digest"],
            "production_closure": True,
            "issued_at": _time(now - timedelta(minutes=2)),
            "expires_at": report["evidence_valid_until"],
            "key_id": certificate_key_id,
            "signature": "",
        }
        certificate["signature"] = _b64(
            certificate_signing.sign(canonical_json({**certificate, "signature": ""}))
        )
        certificate_key = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": certificate_key_id,
            "public_key": _b64(
                certificate_signing.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
        }

        registry_signing = Ed25519PrivateKey.generate()
        registry_key_id = "kms:revocation:1"
        registry = {
            "schema_version": "agenttrust.production-closure-revocation-registry.v1",
            "registry_id": "production-closure-registry",
            "sequence": 1,
            "previous_registry_digest": None,
            "published_at": _time(now - timedelta(minutes=1)),
            "expires_at": _time(now + timedelta(days=1)),
            "key_id": registry_key_id,
            "entries": [],
            "signature": "",
        }
        registry["signature"] = _b64(
            registry_signing.sign(canonical_json({**registry, "signature": ""}))
        )
        registry_key = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": registry_key_id,
            "public_key": _b64(
                registry_signing.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
        }
        return {
            "now": now,
            "activation": activation,
            "report": report,
            "certificate": certificate,
            "certificate_key": certificate_key,
            "revocation_registry": registry,
            "revocation_key": registry_key,
            "registry_signing": registry_signing,
        }

    def verify(self, fixture: dict[str, object]) -> dict[str, object]:
        return verify_activation_documents(
            activation=fixture["activation"],
            report=fixture["report"],
            certificate=fixture["certificate"],
            certificate_key=fixture["certificate_key"],
            revocation_registry=fixture["revocation_registry"],
            revocation_key=fixture["revocation_key"],
            now=fixture["now"],
        )

    def test_exact_release_is_admitted(self) -> None:
        receipt = self.verify(self.fixture())
        self.assertTrue(receipt["admitted"])
        self.assertEqual(receipt["revocation_registry_sequence"], 1)

    def test_material_drift_is_rejected(self) -> None:
        fixture = self.fixture()
        fixture["activation"]["images"]["runtime"] = (
            "registry.example/runtime@sha256:" + "a" * 64
        )
        with self.assertRaisesRegex(ActivationError, "ACTIVATION_IMAGE_MANIFEST_INVALID"):
            self.verify(fixture)

    def test_revoked_certificate_is_rejected(self) -> None:
        fixture = self.fixture()
        registry = fixture["revocation_registry"]
        certificate = fixture["certificate"]
        registry["entries"] = [
            {
                "certificate_id": certificate["certificate_id"],
                "release_id": certificate["release_id"],
                "reason_code": "RELEASE_ROLLED_BACK",
                "evidence_digest": "b" * 64,
                "revoked_at": registry["published_at"],
            }
        ]
        registry["signature"] = _b64(
            fixture["registry_signing"].sign(
                canonical_json({**registry, "signature": ""})
            )
        )
        with self.assertRaisesRegex(ActivationError, "ACTIVATION_CERTIFICATE_REVOKED"):
            self.verify(fixture)

    def test_unknown_gate_name_is_rejected_even_with_exact_cardinality(self) -> None:
        fixture = self.fixture()
        report = fixture["report"]
        gate_digests = report["verified_gate_digests"]
        gate_digests.pop(next(iter(gate_digests)))
        gate_digests["ATTACKER_SELECTED_GATE"] = "f" * 64
        report["report_digest"] = ""
        report["report_digest"] = _digest(report)
        certificate = fixture["certificate"]
        certificate["report_digest"] = report["report_digest"]
        certificate["certificate_id"] = "pc-" + report["report_digest"][:24]
        certificate["signature"] = "A" * 86
        with self.assertRaisesRegex(ActivationError, "ACTIVATION_GATES_INVALID"):
            self.verify(fixture)


if __name__ == "__main__":
    unittest.main()
