from __future__ import annotations

from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest

from python.production_gates.git_provenance import collect_git_provenance
from python.production_gates.live_integrations import GateError


class GitProvenanceTests(unittest.TestCase):
    def _run(self, root: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _output(self, root: Path, *args: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(root), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout

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

    def test_local_executable_and_transport_config_is_denied_without_execution(self):
        dangerous = (
            ("core.fsmonitor", "{sentinel}"),
            ("gpg.program", "{sentinel}"),
            ("credential.helper", "!{sentinel}"),
            ("http.sslVerify", "false"),
            ("url.https://evil.example/.insteadOf", "https://git.example.test/"),
        )
        for key, raw_value in dangerous:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                sentinel = root / "should-not-run"
                executable = root / "sentinel-helper"
                executable.write_text(
                    f"#!/bin/sh\ntouch '{sentinel}'\nexit 1\n", encoding="utf-8"
                )
                executable.chmod(0o700)
                self._run(root, "init", "-q")
                self._run(root, "config", "user.name", "AgentTrust Test")
                self._run(root, "config", "user.email", "agenttrust@example.test")
                (root / "source.txt").write_text("immutable\n", encoding="utf-8")
                self._run(root, "add", "source.txt")
                self._run(root, "commit", "-q", "-m", "immutable source")
                self._run(
                    root, "remote", "add", "origin",
                    "https://git.example.test/org/repo.git",
                )
                self._run(root, "config", "--local", key, raw_value.format(sentinel=executable))
                with self.assertRaisesRegex(GateError, "GIT_LOCAL_CONFIG_KEY_DENIED"):
                    collect_git_provenance(
                        root, {"git.example.test"}, require_signed_commit=False
                    )
                self.assertFalse(sentinel.exists())

    def test_replace_refs_cannot_change_commit_content_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self._run(root, "init", "-q")
            self._run(root, "config", "user.name", "AgentTrust Test")
            self._run(root, "config", "user.email", "agenttrust@example.test")
            (root / "source.txt").write_text("immutable\n", encoding="utf-8")
            self._run(root, "add", "source.txt")
            self._run(root, "commit", "-q", "-m", "immutable source")
            self._run(root, "remote", "add", "origin", "https://git.example.test/org/repo.git")
            head = self._output(root, "rev-parse", "HEAD").decode().strip()
            tree = self._output(root, "rev-parse", "HEAD^{tree}").decode().strip()
            replacement = self._output(
                root, "commit-tree", tree, "-p", head, "-m", "replacement commit"
            ).decode().strip()
            self._run(root, "replace", head, replacement)
            expected = self._output(root, "--no-replace-objects", "cat-file", "commit", head)
            replaced = self._output(root, "cat-file", "commit", head)
            self.assertNotEqual(expected, replaced)
            result = collect_git_provenance(
                root, {"git.example.test"}, require_signed_commit=False
            )
            self.assertEqual(
                result.checks["commit_content_digest"], hashlib.sha256(expected).hexdigest()
            )

    def test_committed_ignore_all_cannot_hide_dirty_initialized_submodule(self):
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw).resolve()
            dependency = workspace / "dependency"
            dependency.mkdir()
            self._run(dependency, "init", "-q")
            self._run(dependency, "config", "user.name", "AgentTrust Test")
            self._run(dependency, "config", "user.email", "agenttrust@example.test")
            (dependency / "source.txt").write_text("pinned\n", encoding="utf-8")
            self._run(dependency, "add", "source.txt")
            self._run(dependency, "commit", "-q", "-m", "pinned dependency")

            root = workspace / "superproject"
            root.mkdir()
            self._run(root, "init", "-q")
            self._run(root, "config", "user.name", "AgentTrust Test")
            self._run(root, "config", "user.email", "agenttrust@example.test")
            self._run(
                root,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                str(dependency),
                "vendor/dependency",
            )
            self._run(
                root,
                "config",
                "-f",
                ".gitmodules",
                "submodule.vendor/dependency.ignore",
                "all",
            )
            self._run(root, "add", ".gitmodules", "vendor/dependency")
            self._run(root, "commit", "-q", "-m", "pin dependency")
            self._run(
                root,
                "remote",
                "add",
                "origin",
                "https://git.example.test/org/repo.git",
            )

            nested_source = root / "vendor/dependency/source.txt"
            nested_source.write_text("dirty local build input\n", encoding="utf-8")
            hidden_status = self._output(
                root, "status", "--porcelain=v1", "--untracked-files=all"
            )
            self.assertEqual(hidden_status, b"")

            with self.assertRaisesRegex(GateError, "GIT_WORKTREE_DIRTY"):
                collect_git_provenance(
                    root, {"git.example.test"}, require_signed_commit=False
                )


if __name__ == "__main__":
    unittest.main()
