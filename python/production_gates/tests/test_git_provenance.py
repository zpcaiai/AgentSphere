from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from python.production_gates.git_provenance import collect_git_provenance
from python.production_gates.live_integrations import GateError


class GitProvenanceTests(unittest.TestCase):
    def _run(self, root: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_real_git_objects_cleanliness_and_remote_are_verified(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self._run(root, "init", "-q")
            self._run(root, "config", "user.name", "AgentTrust Test")
            self._run(root, "config", "user.email", "agenttrust@example.test")
            (root / "source.txt").write_text("immutable\n", encoding="utf-8")
            self._run(root, "add", "source.txt")
            self._run(root, "commit", "-q", "-m", "immutable source")
            self._run(root, "remote", "add", "origin", "https://git.example.test/org/repo.git")
            result = collect_git_provenance(
                root, {"git.example.test"}, require_signed_commit=False
            )
            self.assertTrue(result.checks["clean_worktree"])
            self.assertEqual(len(result.checks["commit_object_id"]), 40)
            self.assertEqual(result.checks["remote_count"], 1)
            (root / "source.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(GateError):
                collect_git_provenance(root, {"git.example.test"},
                                       require_signed_commit=False)

    def test_file_and_credential_bearing_remotes_are_denied(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self._run(root, "init", "-q")
            self._run(root, "config", "user.name", "AgentTrust Test")
            self._run(root, "config", "user.email", "agenttrust@example.test")
            (root / "source.txt").write_text("immutable\n", encoding="utf-8")
            self._run(root, "add", "source.txt")
            self._run(root, "commit", "-q", "-m", "immutable source")
            self._run(root, "remote", "add", "origin", "file:///tmp/repo")
            with self.assertRaises(GateError):
                collect_git_provenance(root, {"git.example.test"},
                                       require_signed_commit=False)


if __name__ == "__main__":
    unittest.main()
