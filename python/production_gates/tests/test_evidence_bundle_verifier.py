from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/verify-evidence-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_evidence_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def read(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class EvidenceBundleVerifierTests(unittest.TestCase):
    def documents(self) -> dict[Path, dict[str, object]]:
        documents = {
            ROOT / f"evidence/batch-{batch:02}/IMPLEMENTATION_STATUS.json": read(
                ROOT / f"evidence/batch-{batch:02}/IMPLEMENTATION_STATUS.json"
            )
            for batch in range(1, 37)
        }
        for relative in (
            "config/production-runtime/conditions.json",
            "evidence/production-closure/production-readiness-report.json",
            "evidence/production-closure/gate-results.json",
            "evidence/production-closure/external-condition-matrix.json",
            "evidence/production-closure/CERTIFICATE_NOT_ISSUED.json",
            "evidence/production-closure/residual-risk-register.json",
        ):
            documents[ROOT / relative] = read(ROOT / relative)
        return documents

    def verify(self, documents: dict[Path, dict[str, object]]) -> None:
        manifest = read(
            ROOT / "evidence/production-closure/evidence-bundle-manifest.json"
        )

        def load(path: Path) -> dict[str, object]:
            return copy.deepcopy(documents[path])

        with patch.object(VERIFIER, "read_object", side_effect=load):
            VERIFIER.verify_non_certificate_truth(manifest)

    def test_current_non_certificate_truth_is_internally_consistent(self) -> None:
        self.verify(self.documents())

    def test_unknown_batch_gate_and_matrix_states_fail_closed(self) -> None:
        mutations = []

        def unknown_batch(documents: dict[Path, dict[str, object]]) -> None:
            documents[ROOT / "evidence/batch-01/IMPLEMENTATION_STATUS.json"][
                "status"
            ] = "LOCALLY_DONE"

        mutations.append(unknown_batch)

        def unknown_gate(documents: dict[Path, dict[str, object]]) -> None:
            gates = documents[
                ROOT / "evidence/production-closure/gate-results.json"
            ]["gates"]
            assert isinstance(gates, list) and isinstance(gates[0], dict)
            gates[0]["result"] = "PASS_BUT_UNSCOPED"

        mutations.append(unknown_gate)

        def unknown_matrix_state(documents: dict[Path, dict[str, object]]) -> None:
            matrix = documents[
                ROOT / "evidence/production-closure/external-condition-matrix.json"
            ]
            conditions = matrix["conditions"]
            assert isinstance(conditions, list) and isinstance(conditions[0], dict)
            conditions[0]["external_status"] = "PASS_LOCAL"
            material = dict(matrix)
            material.pop("matrix_digest")
            matrix["matrix_digest"] = VERIFIER.canonical_digest(material)

        mutations.append(unknown_matrix_state)

        for mutation in mutations:
            with self.subTest(mutation=mutation.__name__):
                documents = self.documents()
                mutation(documents)
                with self.assertRaises(RuntimeError):
                    self.verify(documents)

    def test_tampered_digest_closed_p1_and_claimed_heavy_pass_fail(self) -> None:
        documents = self.documents()
        matrix = documents[
            ROOT / "evidence/production-closure/external-condition-matrix.json"
        ]
        matrix["matrix_digest"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "EXTERNAL_MATRIX_INVALID"):
            self.verify(documents)

        documents = self.documents()
        risks = documents[
            ROOT / "evidence/production-closure/residual-risk-register.json"
        ]["risks"]
        assert isinstance(risks, list) and isinstance(risks[0], dict)
        risks[0]["status"] = "CLOSED"
        with self.assertRaisesRegex(RuntimeError, "RISK_REGISTER_INVALID"):
            self.verify(documents)

        documents = self.documents()
        readiness = documents[
            ROOT / "evidence/production-closure/production-readiness-report.json"
        ]
        local = readiness["local_code_gates"]
        assert isinstance(local, dict)
        local["rust_workspace_current_run"] = "PASS"
        with self.assertRaisesRegex(RuntimeError, "READINESS_TRUTH_MISMATCH"):
            self.verify(documents)

        documents = self.documents()
        readiness = documents[
            ROOT / "evidence/production-closure/production-readiness-report.json"
        ]
        local = readiness["local_code_gates"]
        assert isinstance(local, dict)
        local["postgresql_migrations"] = "PASS_STATIC_MANIFEST_66_STALE"
        with self.assertRaisesRegex(RuntimeError, "READINESS_TRUTH_MISMATCH"):
            self.verify(documents)

    def test_denial_reasons_cannot_be_silently_removed(self) -> None:
        documents = self.documents()
        denial = documents[
            ROOT / "evidence/production-closure/CERTIFICATE_NOT_ISSUED.json"
        ]
        denial["reason_codes"] = ["BATCH_STATUSES_NOT_EVIDENCE_VERIFIED"]
        with self.assertRaisesRegex(RuntimeError, "PRODUCTION_TRUTH_MISMATCH"):
            self.verify(documents)

    def test_release_code_manifest_covers_current_production_closure(self) -> None:
        entries = VERIFIER.release_code_manifest_required_items()
        self.assertIn("rust/crates/production-runtime/src/activation.rs", entries)
        self.assertIn("deploy/kubernetes/production-stack.yaml.tmpl", entries)
        self.assertIn(
            "infra/terraform/github-release-governance/environment_variables.tf",
            entries,
        )
        self.assertIn(".github/workflows/production-release.yml", entries)
        self.assertIn(
            "schemas/release/production-closure-revocation-update.schema.json",
            entries,
        )

    def test_release_code_manifest_rejects_noncanonical_and_unsafe_paths(self) -> None:
        relative = "config/production-runtime/release-code-manifest.txt"
        invalid_payloads = (
            f"{relative}\nREADME.md\n".encode(),
            f"{relative}\n{relative}\n".encode(),
            f"../escape\n{relative}\n".encode(),
            f"/absolute\n{relative}\n".encode(),
            f"bad\\path\n{relative}\n".encode(),
            f"./README.md\n{relative}\n".encode(),
            f"{relative}".encode(),
            f"{relative}\r\n".encode(),
            f"{relative}\x00\n".encode(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / relative
            source.parent.mkdir(parents=True)
            for payload in invalid_payloads:
                with self.subTest(payload=payload):
                    source.write_bytes(payload)
                    with self.assertRaises(VERIFIER.ReleaseCodeManifestError):
                        VERIFIER.load_release_code_manifest(root)

            target = root / "manifest-target.txt"
            target.write_text(f"{relative}\n", encoding="utf-8")
            source.unlink()
            source.symlink_to(target)
            with self.assertRaises(VERIFIER.ReleaseCodeManifestError):
                VERIFIER.load_release_code_manifest(root)

    def test_repository_digest_rejects_traversal_and_symlink_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "safe/source.txt"
            source.parent.mkdir()
            source.write_bytes(b"release-bytes")
            self.assertEqual(
                VERIFIER.repository_file_sha256(root, "safe/source.txt"),
                hashlib.sha256(b"release-bytes").hexdigest(),
            )
            with self.assertRaises(VERIFIER.ReleaseCodeManifestError):
                VERIFIER.repository_file_sha256(root, "../source.txt")

            alias = root / "alias"
            alias.symlink_to(source.parent, target_is_directory=True)
            with self.assertRaises(VERIFIER.ReleaseCodeManifestError):
                VERIFIER.repository_file_sha256(root, "alias/source.txt")

            hard_link = root / "hard-link.txt"
            os.link(source, hard_link)
            with self.assertRaises(VERIFIER.ReleaseCodeManifestError):
                VERIFIER.repository_file_sha256(root, "hard-link.txt")


if __name__ == "__main__":
    unittest.main()
