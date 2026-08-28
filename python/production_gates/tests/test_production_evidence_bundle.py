from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.evidence_publication import (
    publish_verified_evidence,
    verify_published_evidence,
)
from python.production_gates.production_evidence_bundle import (
    build_manifest,
    verify_bundle,
)
from python.production_gates.qualification import compile_qualification, scope_digest
from python.production_gates.release_preparation import prepare_activation_documents
from python.production_gates.revocation_checkpoint import genesis_checkpoint
from python.production_gates.tests.qualification_fixtures import (
    QualificationFixture,
    b64url,
    digest,
    public_key,
)


def utc(value) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ProductionEvidenceBundleTests(unittest.TestCase):
    def _documents(self, fixture: QualificationFixture):
        closure_input = compile_qualification(
            fixture.package, fixture.anchors, now=fixture.now
        )
        evidence_valid_until = min(
            [fixture.valid_until]
            + [
                __import__("datetime").datetime.fromisoformat(
                    item["expires_at"].replace("Z", "+00:00")
                )
                for item in [
                    *closure_input["batch_statuses"],
                    *closure_input["gate_evidence"],
                    *closure_input["exceptions"],
                ]
            ]
        )
        report = {
            "schema_version": "agenttrust.production-closure.v1",
            "release_id": fixture.release_id,
            "scope_digest": scope_digest(closure_input["scope"]),
            "input_digest": digest(closure_input),
            "eligible": True,
            "blockers": [],
            "verified_gate_digests": {
                gate["gate_id"]: digest(gate) for gate in closure_input["gate_evidence"]
            },
            "evaluated_at": utc(fixture.now),
            "evidence_valid_until": utc(evidence_valid_until),
            "report_digest": "",
        }
        report["report_digest"] = digest(report)
        closure_key = Ed25519PrivateKey.generate()
        closure_public = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": "closure-key-1",
            "public_key": public_key(closure_key),
        }
        certificate = {
            "schema_version": "agenttrust.production-closure.v1",
            "certificate_id": f"pc-{report['report_digest'][:24]}",
            "release_id": fixture.release_id,
            "scope_digest": report["scope_digest"],
            "input_digest": report["input_digest"],
            "report_digest": report["report_digest"],
            "signed_git_provenance_digest": closure_input["scope"][
                "signed_git_provenance_digest"
            ],
            "signed_release_binding_digest": closure_input["scope"][
                "signed_release_binding_digest"
            ],
            "release_digest": closure_input["scope"]["release_digest"],
            "reviewer_keyring_digest": closure_input["scope"]["reviewer_keyring_digest"],
            "production_closure": True,
            "issued_at": utc(fixture.now),
            "expires_at": report["evidence_valid_until"],
            "key_id": "closure-key-1",
            "signature": "",
        }
        certificate["signature"] = b64url(closure_key.sign(canonical_json(certificate)))
        unsigned_certificate = copy.deepcopy(certificate)
        unsigned_certificate["signature"] = ""
        certificate_payload = canonical_json(unsigned_certificate)
        certificate_request = {
            "schema_version": "agenttrust.production-closure-signing-request.v1",
            "algorithm": "Ed25519",
            "key_id": certificate["key_id"],
            "certificate": unsigned_certificate,
            "signing_payload": b64url(certificate_payload),
            "payload_sha256": hashlib.sha256(certificate_payload).hexdigest(),
        }
        revocation_key = Ed25519PrivateKey.generate()
        revocation_public = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": "revocation-key-1",
            "public_key": public_key(revocation_key),
        }
        revocation_checkpoint = genesis_checkpoint(
            registry_id="production-registry",
            key_id="revocation-key-1",
            initialized_at=fixture.now - timedelta(minutes=1),
        )
        registry = {
            "schema_version": "agenttrust.production-closure-revocation-registry.v1",
            "registry_id": "production-registry",
            "sequence": 1,
            "previous_registry_digest": None,
            "published_at": utc(fixture.now),
            "expires_at": utc(fixture.now + timedelta(days=1)),
            "key_id": "revocation-key-1",
            "entries": [],
            "signature": "",
        }
        registry["signature"] = b64url(revocation_key.sign(canonical_json(registry)))
        unsigned_registry = copy.deepcopy(registry)
        unsigned_registry["signature"] = ""
        registry_payload = canonical_json(unsigned_registry)
        revocation_request = {
            "schema_version": (
                "agenttrust.production-closure-revocation-signing-request.v1"
            ),
            "algorithm": "Ed25519",
            "key_id": registry["key_id"],
            "base_checkpoint_digest": revocation_checkpoint["checkpoint_digest"],
            "registry": unsigned_registry,
            "signing_payload": b64url(registry_payload),
            "payload_sha256": hashlib.sha256(registry_payload).hexdigest(),
        }
        certificate_request_digest = digest(certificate_request)
        certificate_audit = {
            "schema_version": "agenttrust.external-signing-audit-receipt.v1",
            "request_id": (
                "agenttrust-production_closure_certificate-"
                f"{certificate_request_digest[:32]}"
            ),
            "request_digest": certificate_request_digest,
            "request_kind": "PRODUCTION_CLOSURE_CERTIFICATE",
            "key_id": certificate["key_id"],
            "algorithm": "Ed25519",
            "payload_sha256": certificate_request["payload_sha256"],
            "document_signature_sha256": hashlib.sha256(
                certificate["signature"].encode("ascii")
            ).hexdigest(),
            "signed_at": utc(fixture.now),
        }
        signed_certificate_audit = {
            "schema_version": "agenttrust.signed-external-signing-audit-receipt.v1",
            "receipt": certificate_audit,
            "receipt_digest": digest(certificate_audit),
            "algorithm": "Ed25519",
            "key_id": certificate["key_id"],
            "signature": b64url(closure_key.sign(canonical_json(certificate_audit))),
        }
        certificate_signature = {
            "schema_version": "agenttrust.production-closure-external-signature.v2",
            "request_digest": certificate_request_digest,
            "algorithm": "Ed25519",
            "key_id": certificate["key_id"],
            "signed_at": utc(fixture.now),
            "audit_receipt_digest": signed_certificate_audit["receipt_digest"],
            "signature": certificate["signature"],
        }
        revocation_request_digest = digest(revocation_request)
        revocation_audit = {
            "schema_version": "agenttrust.external-signing-audit-receipt.v1",
            "request_id": (
                "agenttrust-production_closure_revocation_registry-"
                f"{revocation_request_digest[:32]}"
            ),
            "request_digest": revocation_request_digest,
            "request_kind": "PRODUCTION_CLOSURE_REVOCATION_REGISTRY",
            "key_id": registry["key_id"],
            "algorithm": "Ed25519",
            "payload_sha256": revocation_request["payload_sha256"],
            "document_signature_sha256": hashlib.sha256(
                registry["signature"].encode("ascii")
            ).hexdigest(),
            "signed_at": utc(fixture.now),
        }
        signed_revocation_audit = {
            "schema_version": "agenttrust.signed-external-signing-audit-receipt.v1",
            "receipt": revocation_audit,
            "receipt_digest": digest(revocation_audit),
            "algorithm": "Ed25519",
            "key_id": registry["key_id"],
            "signature": b64url(revocation_key.sign(canonical_json(revocation_audit))),
        }
        revocation_signature = {
            "schema_version": (
                "agenttrust.production-closure-revocation-external-signature.v2"
            ),
            "request_digest": revocation_request_digest,
            "algorithm": "Ed25519",
            "key_id": registry["key_id"],
            "signed_at": utc(fixture.now),
            "audit_receipt_digest": signed_revocation_audit["receipt_digest"],
            "signature": registry["signature"],
        }
        return (
            closure_input,
            report,
            certificate,
            certificate_request,
            certificate_signature,
            signed_certificate_audit,
            registry,
            revocation_request,
            revocation_signature,
            signed_revocation_audit,
            closure_public,
            revocation_public,
            revocation_checkpoint,
        )

    def _write_bundle(self, root: Path, fixture: QualificationFixture):
        (
            closure_input,
            report,
            certificate,
            certificate_request,
            certificate_signature,
            signed_certificate_audit,
            registry,
            revocation_request,
            revocation_signature,
            signed_revocation_audit,
            closure_key,
            revocation_key,
            revocation_checkpoint,
        ) = self._documents(fixture)
        documents = {
            "qualification_input": fixture.package,
            "closure_input": closure_input,
            "closure_report": report,
            "production_closure_certificate": certificate,
            "production_closure_signing_request": certificate_request,
            "production_closure_external_signature": certificate_signature,
            "production_closure_signing_audit_receipt": signed_certificate_audit,
            "production_closure_revocation_registry": registry,
            "production_closure_revocation_signing_request": revocation_request,
            "production_closure_revocation_external_signature": revocation_signature,
            "production_closure_revocation_signing_audit_receipt": (
                signed_revocation_audit
            ),
            "production_image_manifest": fixture.image_manifest,
        }
        paths = {}
        for role, value in documents.items():
            path = root / f"{role}.json"
            path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
            paths[role] = path
        manifest = build_manifest(
            root,
            paths,
            fixture.anchors,
            closure_key,
            revocation_key,
            revocation_checkpoint,
            created_at=fixture.now,
        )
        return manifest, closure_key, revocation_key, paths, revocation_checkpoint

    def test_positive_bundle_recompiles_and_verifies_all_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            manifest, closure_key, revocation_key, _, checkpoint = self._write_bundle(root, fixture)
            result = verify_bundle(
                root, manifest, fixture.anchors, closure_key, revocation_key, checkpoint,
                now=fixture.now,
            )
            self.assertTrue(result["verified"])
            self.assertEqual(result["release_id"], fixture.release_id)

    def test_manifest_artifact_and_revocation_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            manifest, closure_key, revocation_key, paths, checkpoint = self._write_bundle(root, fixture)
            tampered = copy.deepcopy(manifest)
            tampered["batch_evidence_verified"] = 34
            with self.assertRaises(GateError):
                verify_bundle(
                    root, tampered, fixture.anchors, closure_key, revocation_key, checkpoint,
                    now=fixture.now,
                )

            certificate = json.loads(paths["production_closure_certificate"].read_text())
            registry = json.loads(
                paths["production_closure_revocation_registry"].read_text()
            )
            registry["entries"] = [{
                "certificate_id": certificate["certificate_id"],
                "release_id": certificate["release_id"],
                "reason_code": "REGRESSION",
                "evidence_digest": "a" * 64,
                "revoked_at": registry["published_at"],
            }]
            paths["production_closure_revocation_registry"].write_text(
                json.dumps(registry, sort_keys=True, indent=2) + "\n"
            )
            rebuilt = build_manifest(
                root, paths, fixture.anchors, closure_key, revocation_key, checkpoint,
                created_at=fixture.now,
            )
            with self.assertRaises(GateError):
                verify_bundle(
                    root, rebuilt, fixture.anchors, closure_key, revocation_key, checkpoint,
                    now=fixture.now,
                )

    def test_image_manifest_is_scope_and_release_binding_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            manifest, closure_key, revocation_key, paths, checkpoint = self._write_bundle(root, fixture)
            # Bind a different but internally rehashed image manifest. The
            # closure scope still pins the original digest.
            image_manifest = json.loads(paths["production_image_manifest"].read_text())
            image_manifest["attestations"]["runtime"]["sbom_sha256"] = "e" * 64
            unsigned = dict(image_manifest)
            unsigned.pop("manifest_digest")
            image_manifest["manifest_digest"] = digest(unsigned)
            paths["production_image_manifest"].write_text(
                json.dumps(image_manifest, sort_keys=True, indent=2) + "\n"
            )
            rebuilt = build_manifest(
                root, paths, fixture.anchors, closure_key, revocation_key, checkpoint,
                created_at=fixture.now,
            )
            with self.assertRaisesRegex(GateError, "IMAGE_MANIFEST"):
                verify_bundle(
                    root, rebuilt, fixture.anchors, closure_key, revocation_key, checkpoint,
                    now=fixture.now,
                )

    def test_external_signature_is_bound_to_exact_signing_request(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            _, closure_key, revocation_key, paths, checkpoint = self._write_bundle(root, fixture)
            request_path = paths["production_closure_signing_request"]
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["payload_sha256"] = "f" * 64
            request_path.write_text(
                json.dumps(request, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            rebuilt = build_manifest(
                root, paths, fixture.anchors, closure_key, revocation_key, checkpoint,
                created_at=fixture.now,
            )
            with self.assertRaisesRegex(GateError, "SIGNING_REQUEST"):
                verify_bundle(
                    root, rebuilt, fixture.anchors, closure_key, revocation_key, checkpoint,
                    now=fixture.now,
                )

    def test_external_signing_audit_receipt_is_signature_verified(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            _, closure_key, revocation_key, paths, checkpoint = self._write_bundle(root, fixture)
            receipt_path = paths["production_closure_signing_audit_receipt"]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["signature"] = "A" * 86
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            rebuilt = build_manifest(
                root, paths, fixture.anchors, closure_key, revocation_key, checkpoint,
                created_at=fixture.now,
            )
            with self.assertRaisesRegex(GateError, "AUDIT_RECEIPT"):
                verify_bundle(
                    root, rebuilt, fixture.anchors, closure_key, revocation_key, checkpoint,
                    now=fixture.now,
                )

    def test_durable_bundle_is_not_limited_to_broker_response_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            manifest, closure_key, revocation_key, _, checkpoint = self._write_bundle(root, fixture)
            result = verify_bundle(
                root,
                manifest,
                fixture.anchors,
                closure_key,
                revocation_key,
                checkpoint,
                now=fixture.now + timedelta(minutes=20),
            )
            self.assertTrue(result["verified"])

    def test_runtime_evidence_publication_is_atomic_bound_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            bundle = root / "bundle"
            publications = root / "publications"
            bundle.mkdir(mode=0o700)
            publications.mkdir(mode=0o700)
            fixture = QualificationFixture(bundle)
            manifest, closure_key, revocation_key, paths, checkpoint = self._write_bundle(
                bundle, fixture
            )
            closure_input = json.loads(paths["closure_input"].read_text())
            activation, expectation = prepare_activation_documents(
                closure_input,
                fixture.image_manifest,
                manifest,
                fixture.release_binding,
                requested_at=fixture.now,
            )
            published, receipt = publish_verified_evidence(
                bundle,
                manifest,
                activation,
                expectation,
                fixture.anchors,
                closure_key,
                revocation_key,
                checkpoint,
                publications,
                volume_name="production-evidence",
                now=fixture.now,
            )
            self.assertTrue(receipt["filesystem_mode_read_only"])
            self.assertFalse(published.stat().st_mode & 0o222)
            verified = verify_published_evidence(
                bundle,
                manifest,
                activation,
                expectation,
                fixture.anchors,
                closure_key,
                revocation_key,
                checkpoint,
                published,
                volume_name="production-evidence",
                now=fixture.now,
            )
            self.assertEqual(verified["receipt_digest"], receipt["receipt_digest"])

            gate_file = published / "gate-evidence.json"
            gate_file.chmod(0o640)
            gate_file.write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(GateError, "PUBLICATION_(FILE|CONTENT)"):
                verify_published_evidence(
                    bundle,
                    manifest,
                    activation,
                    expectation,
                    fixture.anchors,
                    closure_key,
                    revocation_key,
                    checkpoint,
                    published,
                    volume_name="production-evidence",
                    now=fixture.now,
                )

    def test_duplicate_json_members_fail_before_bundle_construction(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixture = QualificationFixture(root)
            _, closure_key, revocation_key, paths, checkpoint = self._write_bundle(root, fixture)
            report_path = paths["closure_report"]
            report_path.write_text(
                report_path.read_text(encoding="utf-8").replace(
                    "{", '{"schema_version":"attacker-selected",', 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(GateError, "ARTIFACT_INVALID"):
                build_manifest(
                    root,
                    paths,
                    fixture.anchors,
                    closure_key,
                    revocation_key,
                    checkpoint,
                    created_at=fixture.now,
                )


if __name__ == "__main__":
    unittest.main()
