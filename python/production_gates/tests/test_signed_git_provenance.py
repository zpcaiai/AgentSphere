from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from python.production_gates.git_provenance import (
    GIT_PROVENANCE_ALGORITHM,
    GIT_PROVENANCE_KEYRING_SCHEMA_VERSION,
    GIT_PROVENANCE_KEY_USAGE,
    GateResult,
    canonical_json,
    collect_git_provenance,
    sign_git_provenance,
    signed_git_provenance_digest,
    verify_signed_git_provenance,
)
from python.production_gates.live_integrations import GateError
from python.production_gates.release_binding import (
    RELEASE_BINDING_ALGORITHM,
    RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
    RELEASE_BINDING_KEY_USAGE,
    build_release_binding,
    sign_release_binding,
)
from python.production_gates.tests.test_production_deployment import runtime_config, values


ROOT = Path(__file__).parents[3]
SPEC = importlib.util.spec_from_file_location(
    "render_production_stack_signed", ROOT / "scripts/render-production-stack.py"
)
assert SPEC is not None and SPEC.loader is not None
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def report() -> dict[str, object]:
    commit = "a" * 40
    host_by_name = {"origin": "git.example.test"}
    url_digests = {"origin": "b" * 64}
    remote_digest = hashlib.sha256(canonical_json({
        "origin": {"host": host_by_name["origin"], "url_digest": url_digests["origin"]}
    })).hexdigest()
    membership_digest = hashlib.sha256(canonical_json({
        "origin": {
            "host": host_by_name["origin"],
            "url_digest": url_digests["origin"],
            "tag_ref": "refs/tags/v1.0.0",
            "tag_object_id": "e" * 40,
            "peeled_commit_id": commit,
        }
    })).hexdigest()
    return GateResult(
        gate="GIT_IMMUTABLE_PROVENANCE",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"git://git.example.test/{commit}",
        checks={
            "release_id": f"git:sha1:{commit}",
            "object_format": "sha1",
            "commit_object_id": commit,
            "tree_object_id": "c" * 40,
            "commit_content_digest": "d" * 64,
            "clean_worktree_required": True,
            "clean_worktree": True,
            "submodules_pinned": True,
            "remote_count": 1,
            "remote_hosts": ["git.example.test"],
            "remote_hosts_by_name": host_by_name,
            "remote_url_digests": url_digests,
            "remote_set_digest": remote_digest,
            "commit_signature_required": True,
            "commit_signature_verified": True,
            "release_tag_required": True,
            "release_tag": "v1.0.0",
            "release_tag_object_id": "e" * 40,
            "release_tag_target": commit,
            "release_tag_signature_verified": True,
            "remote_release_tag_verified": True,
            "remote_release_tag_ref": "refs/tags/v1.0.0",
            "remote_tag_object_ids": {"origin": "e" * 40},
            "remote_tag_peeled_commit_ids": {"origin": commit},
            "remote_membership_digest": membership_digest,
            "signature_trust_format": "SSH_ALLOWED_SIGNERS",
            "git_allowed_signers_digest": "f" * 64,
        },
        production_evidence=True,
    ).as_dict()


class SignedGitProvenanceTests(unittest.TestCase):
    def signed_fixture(self, directory: Path) -> tuple[dict[str, object], dict[str, object]]:
        private = Ed25519PrivateKey.generate()
        raw_private = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        key_file = directory / "provenance.key"
        key_file.write_text(b64url(raw_private), encoding="ascii")
        key_file.chmod(0o600)
        now = datetime.now(timezone.utc)
        envelope = sign_git_provenance(
            report(), key_file, issuer="release-authority", key_id="git-2026-01",
            signed_at=now,
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        keyring = {
            "schema_version": GIT_PROVENANCE_KEYRING_SCHEMA_VERSION,
            "keys": [{
                "issuer": "release-authority",
                "key_id": "git-2026-01",
                "key_usage": GIT_PROVENANCE_KEY_USAGE,
                "algorithm": GIT_PROVENANCE_ALGORITHM,
                "public_key": b64url(public),
                "status": "ACTIVE",
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=1)).isoformat(),
            }],
        }
        return envelope, keyring

    def release_binding_fixture(
        self,
        directory: Path,
        template: str,
        release_values: dict[str, object],
        configuration: object,
        provenance: object,
    ) -> tuple[dict[str, object], dict[str, object]]:
        private = Ed25519PrivateKey.generate()
        raw_private = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        key_file = directory / "release-binding.key"
        key_file.write_text(b64url(raw_private), encoding="ascii")
        key_file.chmod(0o600)
        binding = build_release_binding(
            template,
            release_values,
            configuration,
            provenance_digest=signed_git_provenance_digest(provenance),
            template_blob_object_id="9" * 40,
        )
        release_values["release_digest"] = binding["release_digest"]
        now = datetime.now(timezone.utc)
        envelope = sign_release_binding(
            binding,
            key_file,
            issuer="release-authority",
            key_id="release-binding-2026-01",
            signed_at=now,
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        keyring = {
            "schema_version": RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
            "keys": [{
                "issuer": "release-authority",
                "key_id": "release-binding-2026-01",
                "key_usage": RELEASE_BINDING_KEY_USAGE,
                "algorithm": RELEASE_BINDING_ALGORITHM,
                "public_key": b64url(public),
                "status": "ACTIVE",
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=1)).isoformat(),
            }],
        }
        return envelope, keyring

    def test_envelope_and_keyring_validate_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            envelope, keyring = self.signed_fixture(Path(raw).resolve())
            for name, value in (
                ("signed-git-provenance.schema.json", envelope),
                ("git-provenance-keyring.schema.json", keyring),
            ):
                schema = json.loads((ROOT / "schemas/release" / name).read_text())
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(value)
            verified = verify_signed_git_provenance(envelope, keyring)
            self.assertEqual(verified["checks"]["release_id"], envelope["report"]["checks"]["release_id"])

    def test_tampering_wrong_usage_and_open_private_permissions_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw).resolve()
            envelope, keyring = self.signed_fixture(directory)
            tampered = copy.deepcopy(envelope)
            tampered["report"]["checks"]["tree_object_id"] = "e" * 40
            with self.assertRaises(GateError):
                verify_signed_git_provenance(tampered, keyring)
            wrong_usage = copy.deepcopy(keyring)
            wrong_usage["keys"][0]["key_usage"] = "OTHER"
            with self.assertRaises(GateError):
                verify_signed_git_provenance(envelope, wrong_usage)
            open_key = directory / "open.key"
            open_key.write_text("A" * 43, encoding="ascii")
            open_key.chmod(0o644)
            with self.assertRaisesRegex(GateError, "SIGNING_KEY_FILE_INVALID"):
                sign_git_provenance(
                    report(), open_key, issuer="release-authority", key_id="git-2026-01"
                )

    def test_render_binds_release_template_values_runtime_and_signed_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            envelope, keyring = self.signed_fixture(Path(raw).resolve())
            template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
            configuration = runtime_config()
            release_values = values()
            release_values["release_id"] = envelope["report"]["checks"]["release_id"]
            release_values["release_digest"] = "0" * 64
            signed_binding, binding_keyring = self.release_binding_fixture(
                Path(raw).resolve(), template, release_values, configuration, envelope
            )
            rendered = RENDER.render(
                template, release_values, configuration,
                git_provenance=envelope, git_provenance_keyring=keyring,
                release_binding=signed_binding,
                release_binding_keyring=binding_keyring,
            )
            self.assertIn(release_values["release_id"], rendered)

            latest = copy.deepcopy(release_values)
            latest["release_id"] = "latest"
            with self.assertRaisesRegex(RENDER.RenderError, "RELEASE_ID_INVALID"):
                RENDER.render(
                    template, latest, configuration,
                    git_provenance=envelope, git_provenance_keyring=keyring,
                    release_binding=signed_binding,
                    release_binding_keyring=binding_keyring,
                )
            forged_digest = copy.deepcopy(release_values)
            forged_digest["release_digest"] = "f" * 64
            with self.assertRaisesRegex(RENDER.RenderError, "RELEASE_BINDING_MISMATCH"):
                RENDER.render(
                    template, forged_digest, configuration,
                    git_provenance=envelope, git_provenance_keyring=keyring,
                    release_binding=signed_binding,
                    release_binding_keyring=binding_keyring,
                )
            forged_report = copy.deepcopy(envelope)
            forged_report["report"]["checks"]["commit_object_id"] = "f" * 40
            with self.assertRaisesRegex(RENDER.RenderError, "GIT_PROVENANCE_INVALID"):
                RENDER.render(
                    template, release_values, configuration,
                    git_provenance=forged_report, git_provenance_keyring=keyring,
                    release_binding=signed_binding,
                    release_binding_keyring=binding_keyring,
                )

    def test_remote_release_membership_fails_closed(self) -> None:
        class FakeRunner:
            def __init__(
                self,
                root: Path,
                tag_ref: bytes,
                peeled_ref: bytes,
                remote_names: bytes = b"origin\n",
            ) -> None:
                self.root = root
                self.tag_ref = tag_ref
                self.peeled_ref = peeled_ref
                self.remote_names = remote_names
                self.network_calls: list[tuple[str, ...]] = []

            def run(
                self,
                repository: Path,
                arguments: list[str],
                *,
                allow_failure: bool = False,
                network: bool = False,
            ) -> bytes:
                del allow_failure
                commit = "a" * 40
                responses = {
                    ("rev-parse", "--show-toplevel"): f"{self.root}\n".encode(),
                    ("config", "--local", "--null", "--name-only", "--list"): (
                        b"core.repositoryformatversion\0remote.origin.url\0remote.origin.fetch\0"
                    ),
                    ("config", "--worktree", "--null", "--name-only", "--list"): b"",
                    ("rev-parse", "HEAD"): f"{commit}\n".encode(),
                    ("cat-file", "-t", commit): b"commit\n",
                    ("rev-parse", "HEAD^{tree}"): ("c" * 40 + "\n").encode(),
                    (
                        "status",
                        "--porcelain=v1",
                        "--untracked-files=all",
                        "--ignore-submodules=none",
                    ): b"",
                    ("submodule", "status", "--recursive"): b"",
                    ("remote", "-v"): (
                        b"origin https://git.example.test/org/repo.git (fetch)\n"
                        b"origin https://git.example.test/org/repo.git (push)\n"
                    ),
                    ("remote",): self.remote_names,
                    ("cat-file", "commit", commit): b"tree signed-commit\n",
                    ("verify-commit", commit): b"",
                    ("rev-list", "-n", "1", "v1.0.0"): f"{commit}\n".encode(),
                    ("rev-parse", "refs/tags/v1.0.0^{tag}"): ("e" * 40 + "\n").encode(),
                    ("verify-tag", "v1.0.0"): b"",
                    (
                        "ls-remote", "--refs", "https://git.example.test/org/repo.git",
                        "refs/tags/v1.0.0",
                    ): self.tag_ref,
                    (
                        "ls-remote", "https://git.example.test/org/repo.git",
                        "refs/tags/v1.0.0^{}",
                    ): self.peeled_ref,
                }
                key = tuple(arguments)
                if key and key[0] == "ls-remote":
                    if not network:
                        raise AssertionError("ls-remote did not use neutral network runner")
                    self.network_calls.append(key)
                elif network:
                    raise AssertionError(f"non-network command escaped repository: {arguments}")
                if key not in responses:
                    raise AssertionError(f"unexpected git command: {arguments}")
                return responses[key]

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            allowed_signers = root / "allowed_signers"
            allowed_signers.write_text(
                "release@example.test ssh-ed25519 AAAATEST\n", encoding="ascii"
            )
            allowed_signers.chmod(0o600)
            correct_tag = ("e" * 40 + "\trefs/tags/v1.0.0\n").encode()
            correct_peeled = ("a" * 40 + "\trefs/tags/v1.0.0^{}\n").encode()
            passing_runner = FakeRunner(root, correct_tag, correct_peeled)
            result = collect_git_provenance(
                root, {"git.example.test"}, release_tag="v1.0.0",
                allowed_signers_file=allowed_signers,
                runner=passing_runner,
            )
            self.assertTrue(result.production_evidence)
            self.assertEqual(
                result.checks["git_allowed_signers_digest"],
                hashlib.sha256(allowed_signers.read_bytes()).hexdigest(),
            )
            self.assertEqual(len(passing_runner.network_calls), 2)
            self.assertTrue(all(
                "https://git.example.test/org/repo.git" in call
                for call in passing_runner.network_calls
            ))
            with self.assertRaisesRegex(GateError, "REMOTE_RELEASE_TAG_NOT_FOUND"):
                collect_git_provenance(
                    root, {"git.example.test"}, release_tag="v1.0.0",
                    allowed_signers_file=allowed_signers,
                    runner=FakeRunner(root, b"", correct_peeled),
                )
            wrong_tag_object = ("d" * 40 + "\trefs/tags/v1.0.0\n").encode()
            with self.assertRaisesRegex(GateError, "REMOTE_RELEASE_TAG_TARGET_MISMATCH"):
                collect_git_provenance(
                    root, {"git.example.test"}, release_tag="v1.0.0",
                    allowed_signers_file=allowed_signers,
                    runner=FakeRunner(root, wrong_tag_object, correct_peeled),
                )
            wrong_peeled = ("f" * 40 + "\trefs/tags/v1.0.0^{}\n").encode()
            with self.assertRaisesRegex(GateError, "REMOTE_RELEASE_TAG_TARGET_MISMATCH"):
                collect_git_provenance(
                    root, {"git.example.test"}, release_tag="v1.0.0",
                    allowed_signers_file=allowed_signers,
                    runner=FakeRunner(root, correct_tag, wrong_peeled),
                )
            with self.assertRaisesRegex(GateError, "GIT_REMOTE_NOT_CONFIGURED"):
                collect_git_provenance(
                    root, {"git.example.test"}, release_tag="v1.0.0",
                    allowed_signers_file=allowed_signers,
                    runner=FakeRunner(
                        root, correct_tag, correct_peeled, b"origin\nbackup\n"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
