from __future__ import annotations

from datetime import datetime, timedelta, timezone
import copy
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.live_integrations import GateError
from python.production_gates.release_activation import PRODUCTION_IMAGE_KEYS
from python.production_gates.release_binding import (
    RELEASE_BINDING_ALGORITHM,
    RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
    RELEASE_BINDING_KEY_USAGE,
    build_release_binding,
    sign_release_binding,
    signed_release_binding_digest,
)
from python.production_gates.release_values import materialize_production_stack_values
from python.production_gates.tests.qualification_fixtures import (
    public_key,
    write_key,
)


class ProductionReleaseValuesTests(unittest.TestCase):
    def test_positive_evidence_digest_is_injected_without_hash_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw).resolve()
            now = datetime.now(timezone.utc)
            key = Ed25519PrivateKey.generate()
            images = {
                name: f"registry.test/{name.replace('_', '-')}@sha256:{index + 1:064x}"
                for index, name in enumerate(sorted(PRODUCTION_IMAGE_KEYS))
            }
            values = {
                "schema_version": "agenttrust.production-stack-values.v2",
                "release_id": f"git:sha1:{'a' * 40}",
                "release_digest": "0" * 64,
                "images": images,
                "evidence": {
                    "persistent_volume_name": "production-evidence",
                    "bundle_digest": "1" * 64,
                    "storage_size": "100Gi",
                },
            }
            binding = build_release_binding(
                "kind: List\n", values, {"topology": "three-zone"},
                provenance_digest="c" * 64, template_blob_object_id="d" * 40,
            )
            alternate_values = copy.deepcopy(values)
            alternate_values["evidence"]["bundle_digest"] = "2" * 64
            self.assertEqual(
                binding,
                build_release_binding(
                    "kind: List\n", alternate_values, {"topology": "three-zone"},
                    provenance_digest="c" * 64,
                    template_blob_object_id="d" * 40,
                ),
            )
            envelope = sign_release_binding(
                binding, write_key(directory, "release.key", key),
                issuer="release-authority", key_id="release-key-1", signed_at=now,
            )
            keyring = {
                "schema_version": RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
                "keys": [{
                    "issuer": "release-authority", "key_id": "release-key-1",
                    "key_usage": RELEASE_BINDING_KEY_USAGE,
                    "algorithm": RELEASE_BINDING_ALGORITHM,
                    "public_key": public_key(key), "status": "ACTIVE",
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                }],
            }
            manifest = {
                "schema_version": "agenttrust.production-image-manifest.v1",
                "release_id": values["release_id"], "release_tag": "v1.0.0",
                "repository": "org/repo",
                "created_at": now.isoformat().replace("+00:00", "Z"),
                "images": values["images"],
                "attestations": {
                    name: {
                        "component": name,
                        "subject_digest": image.rsplit("@", 1)[1],
                        "sbom_sha256": f"{index + 101:064x}",
                        "provenance_attestation_url": (
                            f"https://example.test/{name}/provenance"
                        ),
                        "sbom_attestation_url": f"https://example.test/{name}/sbom",
                    }
                    for index, (name, image) in enumerate(sorted(images.items()))
                },
            }
            from python.production_gates.git_provenance import canonical_json
            import hashlib
            manifest["manifest_digest"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
            activation = {
                "schema_version": "agenttrust.production-release-activation.v1",
                "release_id": values["release_id"],
                "scope": {
                    "release_id": values["release_id"],
                    "release_digest": binding["release_digest"],
                    "build_digest": manifest["manifest_digest"],
                },
                "images": values["images"],
                "production_image_manifest": manifest,
                "signed_release_binding_digest": signed_release_binding_digest(envelope),
                "evidence_bundle_manifest_digest": "f" * 64,
                "requested_at": now.isoformat(),
            }
            materialized = materialize_production_stack_values(
                envelope, keyring, activation, now=now
            )
            self.assertEqual(materialized["release_digest"], binding["release_digest"])
            self.assertEqual(materialized["evidence"]["bundle_digest"], "f" * 64)
            self.assertNotIn("bundle_digest", binding["static_values"]["evidence"])

            forged = dict(activation)
            forged["signed_release_binding_digest"] = "0" * 64
            with self.assertRaises(GateError):
                materialize_production_stack_values(envelope, keyring, forged, now=now)


if __name__ == "__main__":
    unittest.main()
