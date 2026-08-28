from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).parents[3]
SPEC = importlib.util.spec_from_file_location(
    "production_image_manifest", ROOT / "scripts/assemble-production-image-manifest.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProductionImageManifestTests(unittest.TestCase):
    def _records(self, root: Path) -> None:
        release_id = "git:sha1:" + "1" * 40
        for index, key in enumerate(sorted(MODULE.IMAGE_KEYS), start=1):
            digest = f"{index:064x}"
            value = {
                "schema_version": "agenttrust.production-image-record.v1",
                "image_key": key,
                "component": key.replace("_", "-"),
                "release_id": release_id,
                "release_tag": "v1.2.3",
                "image": f"ghcr.io/example/agentsphere-{key}@sha256:{digest}",
                "subject_digest": f"sha256:{digest}",
                "sbom_sha256": hashlib.sha256(key.encode()).hexdigest(),
                "provenance_attestation_url": f"https://github.example/attestations/{key}/provenance",
                "sbom_attestation_url": f"https://github.example/attestations/{key}/sbom",
            }
            (root / f"{key}.json").write_text(json.dumps(value), encoding="utf-8")

    def test_exact_attested_set_is_assembled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._records(root)
            manifest = MODULE.assemble(
                root,
                release_id="git:sha1:" + "1" * 40,
                release_tag="v1.2.3",
                repository="example/AgentSphere",
                created_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            )
            self.assertEqual(set(manifest["images"]), MODULE.IMAGE_KEYS)
            self.assertEqual(len(manifest["manifest_digest"]), 64)

    def test_missing_or_duplicate_subject_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._records(root)
            (root / "runtime.json").unlink()
            with self.assertRaisesRegex(MODULE.ManifestError, "INCOMPLETE"):
                MODULE.assemble(
                    root,
                    release_id="git:sha1:" + "1" * 40,
                    release_tag="v1.2.3",
                    repository="example/AgentSphere",
                )


if __name__ == "__main__":
    unittest.main()
