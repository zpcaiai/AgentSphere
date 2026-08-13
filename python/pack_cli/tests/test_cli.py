import json
from pathlib import Path
import tempfile
import unittest

from python.pack_cli.cli import scaffold, verify_manifest


class PackCliTests(unittest.TestCase):
    def test_scaffold_is_fail_closed_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = scaffold(Path(directory), "energy-safe", "publisher:1")
            digest = verify_manifest(files[0])
            self.assertEqual(len(digest), 64)
            value = json.loads(files[0].read_text())
            self.assertEqual(value["permissions"], [])
            self.assertFalse(value["arbitrary_code_execution"])

    def test_permissioned_write_without_compensation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = scaffold(Path(directory), "coding-safe", "publisher:1")[0]
            value = json.loads(manifest.read_text())
            value["tools"] = [{"effect_class": "WRITE_REVERSIBLE", "timeout_seconds": 5}]
            manifest.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "PACK_TOOL_INVALID"):
                verify_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
