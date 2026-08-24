from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from python.production_gates.git_provenance import (
    GateResult,
    canonical_json,
    sign_git_provenance,
)
from python.production_gates.live_integrations import GateError
from python.production_gates.release_binding import (
    RELEASE_BINDING_ALGORITHM,
    RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
    RELEASE_BINDING_KEY_USAGE,
    build_release_binding,
    produce_signed_release_binding,
    sign_release_binding,
    verify_signed_release_binding,
)


ROOT = Path(__file__).parents[3]


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def write_key(directory: Path, name: str, key: Ed25519PrivateKey) -> Path:
    path = directory / name
    path.write_text(
        b64url(key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )),
        encoding="ascii",
    )
    path.chmod(0o600)
    return path


def public_key(key: Ed25519PrivateKey) -> str:
    return b64url(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ))


class ReleaseBindingTests(unittest.TestCase):
    def test_strict_schema_signature_and_recomputed_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw).resolve()
            private = Ed25519PrivateKey.generate()
            key_file = write_key(directory, "release-binding.key", private)
            now = datetime.now(timezone.utc)
            keyring = {
                "schema_version": RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
                "keys": [{
                    "issuer": "release-authority",
                    "key_id": "release-binding-2026-01",
                    "key_usage": RELEASE_BINDING_KEY_USAGE,
                    "algorithm": RELEASE_BINDING_ALGORITHM,
                    "public_key": public_key(private),
                    "status": "ACTIVE",
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                }],
            }
            values = {
                "release_id": f"git:sha1:{'a' * 40}",
                "release_digest": "0" * 64,
                "images": {"runtime": f"example/runtime@sha256:{'b' * 64}"},
            }
            binding = build_release_binding(
                "kind: List\n",
                values,
                {"environment": "production"},
                provenance_digest="c" * 64,
                template_blob_object_id="d" * 40,
            )
            envelope = sign_release_binding(
                binding,
                key_file,
                issuer="release-authority",
                key_id="release-binding-2026-01",
                signed_at=now,
            )
            for name, value in (
                ("signed-release-binding.schema.json", envelope),
                ("release-binding-keyring.schema.json", keyring),
            ):
                schema = json.loads((ROOT / "schemas/release" / name).read_text())
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(value)
            verified = verify_signed_release_binding(envelope, keyring, now=now)
            self.assertEqual(verified["release_digest"], binding["release_digest"])

            tampered = copy.deepcopy(envelope)
            tampered_values = tampered["binding"]["values_without_release_digest"]
            tampered_values["images"]["runtime"] = (
                f"example/runtime@sha256:{'e' * 64}"
            )
            unsigned = {
                key: value for key, value in tampered["binding"].items()
                if key != "release_digest"
            }
            tampered["binding"]["release_digest"] = hashlib.sha256(
                canonical_json(unsigned)
            ).hexdigest()
            tampered["binding_digest"] = hashlib.sha256(
                canonical_json(tampered["binding"])
            ).hexdigest()
            with self.assertRaisesRegex(GateError, "SIGNATURE_INVALID"):
                verify_signed_release_binding(tampered, keyring, now=now)

    def test_producer_requires_exact_template_blob_from_provenance_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository = Path(raw).resolve()
            subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "AgentTrust Test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email", "test@example.test"],
                check=True,
            )
            template = repository / "deploy/kubernetes/production-stack.yaml.tmpl"
            template.parent.mkdir(parents=True)
            template.write_text("apiVersion: v1\nkind: List\nitems: []\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "release template"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "remote", "add", "origin",
                 "https://git.example.test/org/repo.git"],
                check=True,
            )
            head = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
            ).strip()
            tree = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"], text=True
            ).strip()
            commit_bytes = subprocess.check_output(
                ["git", "-C", str(repository), "cat-file", "commit", head]
            )
            host_by_name = {"origin": "git.example.test"}
            url_digests = {"origin": "1" * 64}
            remote_set_digest = hashlib.sha256(canonical_json({
                "origin": {"host": "git.example.test", "url_digest": "1" * 64}
            })).hexdigest()
            membership_digest = hashlib.sha256(canonical_json({
                "origin": {
                    "host": "git.example.test",
                    "url_digest": "1" * 64,
                    "tag_ref": "refs/tags/v1.0.0",
                    "tag_object_id": "2" * 40,
                    "peeled_commit_id": head,
                }
            })).hexdigest()
            report = GateResult(
                gate="GIT_IMMUTABLE_PROVENANCE",
                status="PASS_REAL_PROTOCOL",
                environment_reference=f"git://git.example.test/{head}",
                checks={
                    "release_id": f"git:sha1:{head}",
                    "object_format": "sha1",
                    "commit_object_id": head,
                    "tree_object_id": tree,
                    "commit_content_digest": hashlib.sha256(commit_bytes).hexdigest(),
                    "clean_worktree_required": True,
                    "clean_worktree": True,
                    "submodules_pinned": True,
                    "remote_count": 1,
                    "remote_hosts": ["git.example.test"],
                    "remote_hosts_by_name": host_by_name,
                    "remote_url_digests": url_digests,
                    "remote_set_digest": remote_set_digest,
                    "commit_signature_required": True,
                    "commit_signature_verified": True,
                    "release_tag_required": True,
                    "release_tag": "v1.0.0",
                    "release_tag_object_id": "2" * 40,
                    "release_tag_target": head,
                    "release_tag_signature_verified": True,
                    "remote_release_tag_verified": True,
                    "remote_release_tag_ref": "refs/tags/v1.0.0",
                    "remote_tag_object_ids": {"origin": "2" * 40},
                    "remote_tag_peeled_commit_ids": {"origin": head},
                    "remote_membership_digest": membership_digest,
                    "signature_trust_format": "SSH_ALLOWED_SIGNERS",
                    "git_allowed_signers_digest": "3" * 64,
                },
                production_evidence=True,
            ).as_dict()
            now = datetime.now(timezone.utc)
            git_private = Ed25519PrivateKey.generate()
            git_key_file = write_key(repository, "git-provenance.key", git_private)
            provenance = sign_git_provenance(
                report,
                git_key_file,
                issuer="git-release-authority",
                key_id="git-provenance-2026-01",
                signed_at=now,
            )
            provenance_keyring = {
                "schema_version": "agenttrust.git-provenance-keyring.v1",
                "keys": [{
                    "issuer": "git-release-authority",
                    "key_id": "git-provenance-2026-01",
                    "key_usage": "GIT_PROVENANCE_ATTESTATION",
                    "algorithm": "Ed25519",
                    "public_key": public_key(git_private),
                    "status": "ACTIVE",
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                }],
            }
            release_private = Ed25519PrivateKey.generate()
            release_key_file = write_key(repository, "release-binding.key", release_private)
            values = {
                "release_id": f"git:sha1:{head}",
                "release_digest": "0" * 64,
                "images": {},
            }
            envelope, finalized = produce_signed_release_binding(
                repository,
                template,
                values,
                {"environment": "production"},
                provenance,
                provenance_keyring,
                release_key_file,
                issuer="release-authority",
                key_id="release-binding-2026-01",
                signed_at=now,
            )
            self.assertEqual(finalized["release_digest"], envelope["binding"]["release_digest"])
            blob = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", f"{head}:deploy/kubernetes/production-stack.yaml.tmpl"],
                text=True,
            ).strip()
            self.assertEqual(envelope["binding"]["template_blob_object_id"], blob)

            template.write_text("apiVersion: v1\nkind: Secret\n", encoding="utf-8")
            with self.assertRaisesRegex(GateError, "TEMPLATE_NOT_FROM_COMMIT"):
                produce_signed_release_binding(
                    repository,
                    template,
                    values,
                    {"environment": "production"},
                    provenance,
                    provenance_keyring,
                    release_key_file,
                    issuer="release-authority",
                    key_id="release-binding-2026-01",
                    signed_at=now,
                )


if __name__ == "__main__":
    unittest.main()
