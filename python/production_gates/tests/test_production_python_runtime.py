from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates import runner_runtime


class ProductionPythonRuntimeTests(unittest.TestCase):
    def _manifest(self) -> dict[str, object]:
        return {
            "distributions": [
                {
                    "byte_count": 12,
                    "file_count": 1,
                    "files_digest": "a" * 64,
                    "name": name,
                    "version": "1.0.0",
                }
                for name in ("cryptography", "jsonschema", "openapi-spec-validator")
            ],
            "python": {
                "cache_tag": "cpython-314",
                "executable_sha256": "b" * 64,
                "implementation": "CPython",
                "runtime_root": "/opt/agenttrust/python",
                "version": "3.14.0",
            },
            "requirements_lock_sha256": "c" * 64,
            "schema_version": runner_runtime.SCHEMA_VERSION,
        }

    def _write_read_only(self, directory: Path, value: object) -> tuple[Path, str]:
        raw = canonical_json(value) + b"\n"
        path = directory / "runtime.json"
        path.write_bytes(raw)
        path.chmod(0o400)
        return path.resolve(), hashlib.sha256(raw).hexdigest()

    def test_verify_accepts_exact_canonical_runtime(self) -> None:
        expected = self._manifest()
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = self._write_read_only(Path(temporary), expected)
            with patch.object(runner_runtime, "inspect_runtime", return_value=expected):
                actual = runner_runtime.verify_runtime(
                    path,
                    manifest_sha256=digest,
                    python_sha256="b" * 64,
                    requirements_lock=Path("/nonexistent/read-only.lock"),
                )
        self.assertEqual(actual, expected)

    def test_verify_rejects_duplicate_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "runtime.json")
            raw = b'{"schema_version":"a","schema_version":"b"}\n'
            path.write_bytes(raw)
            path.chmod(0o400)
            with self.assertRaisesRegex(GateError, "DUPLICATE_KEY"):
                runner_runtime.verify_runtime(
                    path.resolve(),
                    manifest_sha256=hashlib.sha256(raw).hexdigest(),
                    python_sha256="b" * 64,
                    requirements_lock=Path("/nonexistent/read-only.lock"),
                )

    def test_verify_rejects_mutable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = self._write_read_only(Path(temporary), self._manifest())
            path.chmod(0o600)
            self.assertTrue(os.access(path, os.W_OK))
            with self.assertRaisesRegex(GateError, "PERMISSIONS_INVALID"):
                runner_runtime.verify_runtime(
                    path,
                    manifest_sha256=digest,
                    python_sha256="b" * 64,
                    requirements_lock=Path("/nonexistent/read-only.lock"),
                )

    def test_verify_rejects_runtime_drift(self) -> None:
        expected = self._manifest()
        drifted = json.loads(json.dumps(expected))
        drifted["distributions"][0]["version"] = "1.0.1"
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = self._write_read_only(Path(temporary), expected)
            with patch.object(runner_runtime, "inspect_runtime", return_value=drifted):
                with self.assertRaisesRegex(GateError, "MANIFEST_MISMATCH"):
                    runner_runtime.verify_runtime(
                        path,
                        manifest_sha256=digest,
                        python_sha256="b" * 64,
                        requirements_lock=Path("/nonexistent/read-only.lock"),
                    )

    def test_requirements_lock_is_exact_and_hash_bound(self) -> None:
        line = "cryptography==46.0.3 --hash=sha256:" + "d" * 64 + "\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "requirements.lock")
            path.write_text(line, encoding="utf-8")
            path.chmod(0o400)
            pins, digest = runner_runtime._requirements_lock(path.resolve())
        self.assertEqual(pins, {"cryptography": "46.0.3"})
        self.assertEqual(digest, hashlib.sha256(line.encode()).hexdigest())

    def test_requirements_lock_rejects_markers_and_indexes(self) -> None:
        values = (
            "cryptography==46.0.3; python_version > '3' --hash=sha256:" + "d" * 64,
            "--index-url https://example.invalid/simple",
        )
        for value in values:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary, "requirements.lock")
                path.write_text(value + "\n", encoding="utf-8")
                path.chmod(0o400)
                with self.assertRaisesRegex(GateError, "LOCK_INVALID"):
                    runner_runtime._requirements_lock(path.resolve())


if __name__ == "__main__":
    unittest.main()
