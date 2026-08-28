"""Cryptographic synthetic fixtures; never production evidence."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.git_provenance import (
    GIT_PROVENANCE_ALGORITHM,
    GIT_PROVENANCE_KEYRING_SCHEMA_VERSION,
    GIT_PROVENANCE_KEY_USAGE,
    GateResult,
    canonical_json,
    sign_git_provenance,
    signed_git_provenance_digest,
)
from python.production_gates.qualification import (
    ALGORITHM,
    DOMAIN_ASSURANCE,
    EXTERNAL_ASSURANCE_ROLES,
    EXTERNAL_CONDITIONS,
    GATE_CONDITION_REQUIREMENTS,
    QUALIFICATION_INPUT_SCHEMA_VERSION,
    QUALIFIED_RECORD_SCHEMA_VERSION,
    REVIEWER_KEYRING_SCHEMA_VERSION,
    REVIEWER_KEY_USAGE,
    SIGNED_WORM_RECEIPT_SCHEMA_VERSION,
    WORM_KEYRING_SCHEMA_VERSION,
    WORM_KEY_USAGE,
    WORM_RECEIPT_SCHEMA_VERSION,
    QualificationTrustAnchors,
    qualified_record_artifact_digest,
    reviewer_keyring_digest,
    scope_digest,
    signed_worm_receipt_digest,
)
from python.production_gates.production_evidence_bundle import PRODUCTION_IMAGE_KEYS
from python.production_gates.release_binding import (
    RELEASE_BINDING_ALGORITHM,
    RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
    RELEASE_BINDING_KEY_USAGE,
    build_release_binding,
    sign_release_binding,
    signed_release_binding_digest,
)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key(key: Ed25519PrivateKey) -> str:
    return b64url(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ))


def write_key(directory: Path, name: str, key: Ed25519PrivateKey) -> Path:
    path = directory / name
    path.write_text(b64url(key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )), encoding="ascii")
    path.chmod(0o600)
    return path


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def git_report() -> dict[str, Any]:
    commit = "a" * 40
    remote_set = {
        "origin": {"host": "git.example.test", "url_digest": "b" * 64}
    }
    membership = {
        "origin": {
            "host": "git.example.test",
            "url_digest": "b" * 64,
            "tag_ref": "refs/tags/v9.0.0",
            "tag_object_id": "e" * 40,
            "peeled_commit_id": commit,
        }
    }
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
            "remote_hosts_by_name": {"origin": "git.example.test"},
            "remote_url_digests": {"origin": "b" * 64},
            "remote_set_digest": digest(remote_set),
            "commit_signature_required": True,
            "commit_signature_verified": True,
            "release_tag_required": True,
            "release_tag": "v9.0.0",
            "release_tag_object_id": "e" * 40,
            "release_tag_target": commit,
            "release_tag_signature_verified": True,
            "remote_release_tag_verified": True,
            "remote_release_tag_ref": "refs/tags/v9.0.0",
            "remote_tag_object_ids": {"origin": "e" * 40},
            "remote_tag_peeled_commit_ids": {"origin": commit},
            "remote_membership_digest": digest(membership),
            "signature_trust_format": "SSH_ALLOWED_SIGNERS",
            "git_allowed_signers_digest": "f" * 64,
        },
        production_evidence=True,
    ).as_dict()


class QualificationFixture:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.now = datetime.now(timezone.utc)
        self.valid_from = self.now - timedelta(hours=2)
        self.valid_until = self.now + timedelta(days=1)
        self.environment_reference = "environment://production/qualification-test"
        self.git_key = Ed25519PrivateKey.generate()
        report = git_report()
        self.git_provenance = sign_git_provenance(
            report,
            write_key(directory, "git.key", self.git_key),
            issuer="git-release-authority",
            key_id="git-key-1",
            signed_at=self.now - timedelta(hours=1),
        )
        self.git_keyring = {
            "schema_version": GIT_PROVENANCE_KEYRING_SCHEMA_VERSION,
            "keys": [{
                "issuer": "git-release-authority",
                "key_id": "git-key-1",
                "key_usage": GIT_PROVENANCE_KEY_USAGE,
                "algorithm": GIT_PROVENANCE_ALGORITHM,
                "public_key": public_key(self.git_key),
                "status": "ACTIVE",
                "not_before": (self.now - timedelta(days=2)).isoformat(),
                "not_after": (self.now + timedelta(days=10)).isoformat(),
            }],
        }
        self.release_id = str(report["checks"]["release_id"])
        self.images = {
            component: (
                f"registry.example/{component.replace('_', '-')}@sha256:{index + 1:064x}"
            )
            for index, component in enumerate(sorted(PRODUCTION_IMAGE_KEYS))
        }
        self.image_manifest = {
            "schema_version": "agenttrust.production-image-manifest.v1",
            "release_id": self.release_id,
            "release_tag": "v9.0.0",
            "repository": "agentsphere/control-plane",
            "created_at": (self.now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "images": self.images,
            "attestations": {
                component: {
                    "component": component,
                    "subject_digest": image.rsplit("@", 1)[1],
                    "sbom_sha256": f"{index + 101:064x}",
                    "provenance_attestation_url": (
                        f"https://github.example/attestations/{component}/provenance"
                    ),
                    "sbom_attestation_url": (
                        f"https://github.example/attestations/{component}/sbom"
                    ),
                }
                for index, (component, image) in enumerate(sorted(self.images.items()))
            },
        }
        self.image_manifest["manifest_digest"] = digest(self.image_manifest)
        runtime = {"environment": "production", "topology": ["zone-a", "zone-b", "zone-c"]}
        self.release_key = Ed25519PrivateKey.generate()
        binding = build_release_binding(
            "apiVersion: v1\nkind: List\n",
            {
                "release_id": self.release_id,
                "release_digest": "0" * 64,
                "images": self.images,
                "evidence": {
                    "persistent_volume_name": "production-evidence",
                    "storage_size": "100Gi",
                },
            },
            runtime,
            provenance_digest=signed_git_provenance_digest(self.git_provenance),
            template_blob_object_id="9" * 40,
        )
        self.release_binding = sign_release_binding(
            binding,
            write_key(directory, "release.key", self.release_key),
            issuer="release-binding-authority",
            key_id="release-key-1",
            signed_at=self.now - timedelta(minutes=55),
        )
        self.release_keyring = {
            "schema_version": RELEASE_BINDING_KEYRING_SCHEMA_VERSION,
            "keys": [{
                "issuer": "release-binding-authority",
                "key_id": "release-key-1",
                "key_usage": RELEASE_BINDING_KEY_USAGE,
                "algorithm": RELEASE_BINDING_ALGORITHM,
                "public_key": public_key(self.release_key),
                "status": "ACTIVE",
                "not_before": (self.now - timedelta(days=2)).isoformat(),
                "not_after": (self.now + timedelta(days=10)).isoformat(),
            }],
        }
        self.scope = {
            "release_id": self.release_id,
            "commit_digest": report["checks"]["commit_content_digest"],
            "signed_git_provenance_digest": signed_git_provenance_digest(
                self.git_provenance
            ),
            "signed_release_binding_digest": signed_release_binding_digest(
                self.release_binding
            ),
            "release_digest": binding["release_digest"],
            "reviewer_keyring_digest": "0" * 64,
            "build_digest": self.image_manifest["manifest_digest"],
            "policy_digest": "2" * 64,
            "pack_set_digest": "3" * 64,
            "prompt_set_digest": "4" * 64,
            "model_set_digest": "5" * 64,
            "topology_digest": binding["runtime_config_digest"],
            "environment": "production",
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }
        self.worm_key = Ed25519PrivateKey.generate()
        self.worm_keyring = {
            "schema_version": WORM_KEYRING_SCHEMA_VERSION,
            "keys": [{
                "issuer": "evidence-archive-authority",
                "key_id": "worm-key-1",
                "key_usage": WORM_KEY_USAGE,
                "algorithm": ALGORITHM,
                "public_key": public_key(self.worm_key),
                "status": "ACTIVE",
                "not_before": (self.now - timedelta(days=2)).isoformat(),
                "not_after": (self.now + timedelta(days=100)).isoformat(),
            }],
        }
        roles = set().union(*EXTERNAL_ASSURANCE_ROLES.values())
        roles.update(*[required for _, required in DOMAIN_ASSURANCE.values()])
        self.reviewer_private: dict[str, Ed25519PrivateKey] = {}
        reviewer_keys = []
        organization_one_roles = {
            "RELEASE_ENGINEER", "SECURITY_ENGINEER", "CODING_DOMAIN_OWNER",
            "COMPLIANCE_OWNER", "CUSTOMER_RELEASE_AUTHORITY",
            "DISASTER_RECOVERY_OWNER", "SAFETY_ENGINEER", "SECURITY_OWNER",
        }
        for index, role in enumerate(sorted(roles)):
            key = Ed25519PrivateKey.generate()
            key_id = f"reviewer-key-{index:02}"
            reviewer_id = f"reviewer-{index:02}"
            organization = (
                "organization-1" if role in organization_one_roles else "organization-0"
            )
            self.reviewer_private[key_id] = key
            reviewer_keys.append({
                "key_id": key_id,
                "reviewer_id": reviewer_id,
                "organization": organization,
                "roles": [role],
                "key_usage": REVIEWER_KEY_USAGE,
                "algorithm": ALGORITHM,
                "public_key": public_key(key),
                "status": "ACTIVE",
                "not_before": (self.now - timedelta(days=2)).isoformat(),
                "not_after": (self.now + timedelta(days=10)).isoformat(),
                "revoked_at": None,
            })
        self.reviewer_keyring = {
            "schema_version": REVIEWER_KEYRING_SCHEMA_VERSION,
            "keyring_id": "production-reviewers",
            "version": 1,
            "issued_at": (self.now - timedelta(days=2)).isoformat(),
            "expires_at": (self.now + timedelta(days=10)).isoformat(),
            "keys": reviewer_keys,
        }
        self.scope["reviewer_keyring_digest"] = reviewer_keyring_digest(
            self.reviewer_keyring
        )
        self.scope_digest = scope_digest(self.scope)
        self.reviewers_by_role = {key["roles"][0]: key for key in reviewer_keys}
        self.package = self._package()
        self.anchors = QualificationTrustAnchors(
            self.git_keyring, self.release_keyring,
            self.reviewer_keyring, self.worm_keyring,
        )

    def _record(self, kind: str, record_id: str) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": QUALIFIED_RECORD_SCHEMA_VERSION,
            "kind": kind,
            "record_id": record_id,
            "release_id": self.release_id,
            "scope_digest": self.scope_digest,
            "environment_reference": self.environment_reference,
            "passed": True,
            "evidence_digests": {"raw-evidence": digest({"record_id": record_id})},
            "measured_at": (self.now - timedelta(minutes=45)).isoformat(),
            "expires_at": (self.now + timedelta(days=2)).isoformat(),
            "verification_policy_digest": "6" * 64,
        }
        value["record_digest"] = digest(value)
        return value

    def _receipt(self, record: dict[str, Any], index: int) -> dict[str, Any]:
        receipt = {
            "schema_version": WORM_RECEIPT_SCHEMA_VERSION,
            "receipt_id": f"receipt-{index:03}",
            "artifact_kind": record["kind"],
            "artifact_id": record["record_id"],
            "artifact_digest": qualified_record_artifact_digest(record),
            "release_id": self.release_id,
            "scope_digest": self.scope_digest,
            "environment_reference": self.environment_reference,
            "object_uri": (
                f"s3-object-lock://evidence.example.test/release/{index:03}.json"
                f"?versionIdDigest={index + 1:064x}"
            ),
            "retention_mode": "COMPLIANCE",
            "versioning_enabled": True,
            "verified_readback": True,
            "verification_result": "VERIFIED",
            "verification_policy_digest": record["verification_policy_digest"],
            "stored_at": (self.now - timedelta(minutes=30)).isoformat(),
            "retain_until": (self.now + timedelta(days=90)).isoformat(),
        }
        envelope: dict[str, Any] = {
            "schema_version": SIGNED_WORM_RECEIPT_SCHEMA_VERSION,
            "receipt": receipt,
            "receipt_digest": digest(receipt),
            "issuer": "evidence-archive-authority",
            "key_id": "worm-key-1",
            "key_usage": WORM_KEY_USAGE,
            "algorithm": ALGORITHM,
            "signed_at": (self.now - timedelta(minutes=20)).isoformat(),
        }
        envelope["signature"] = b64url(self.worm_key.sign(canonical_json(envelope)))
        return envelope

    def _expected_evidence(
        self,
        gate_id: str,
        conditions: dict[str, dict[str, Any]],
        receipts: dict[str, dict[str, Any]],
    ) -> dict[str, str]:
        result = {
            "signed_git_provenance": signed_git_provenance_digest(self.git_provenance),
            "signed_release_binding": signed_release_binding_digest(self.release_binding),
            "release": self.release_binding["binding"]["release_digest"],
        }
        for condition in GATE_CONDITION_REQUIREMENTS[gate_id]:
            result[f"condition:{condition}"] = qualified_record_artifact_digest(conditions[condition])
            result[f"worm:{condition}"] = signed_worm_receipt_digest(receipts[condition])
        return result

    def _reviewers(self, roles: set[str]) -> list[dict[str, Any]]:
        return [{
            "reviewer_id": self.reviewers_by_role[role]["reviewer_id"],
            "organization": self.reviewers_by_role[role]["organization"],
            "role": role,
            "key_id": self.reviewers_by_role[role]["key_id"],
            "signature": "",
        } for role in sorted(roles)]

    def _sign_assurance(self, assurance: dict[str, Any]) -> dict[str, Any]:
        payload = canonical_json(assurance)
        for reviewer in assurance["reviewers"]:
            reviewer["signature"] = b64url(
                self.reviewer_private[reviewer["key_id"]].sign(payload)
            )
        return assurance

    def _package(self) -> dict[str, Any]:
        batches = [self._record("BATCH", f"BATCH_{batch:02}") for batch in range(1, 36)]
        conditions = {
            condition: self._record("EXTERNAL_CONDITION", condition)
            for condition in sorted(EXTERNAL_CONDITIONS)
        }
        records = [*batches, *conditions.values()]
        receipt_list = [self._receipt(record, index) for index, record in enumerate(records)]
        receipts = {
            receipt["receipt"]["artifact_id"]: receipt for receipt in receipt_list
        }
        external = []
        for gate_id, roles in EXTERNAL_ASSURANCE_ROLES.items():
            assurance = {
                "schema_version": "agenttrust.external-gate-assurance-attestation.v1",
                "attestation_id": f"external-{gate_id.lower()}",
                "gate_id": gate_id,
                "release_id": self.release_id,
                "scope_digest": self.scope_digest,
                "environment_reference": self.environment_reference,
                "decision": "APPROVED",
                "automated": False,
                "change_ticket": "CHANGE-12345",
                "evidence_digests": self._expected_evidence(gate_id, conditions, receipts),
                "issued_at": (self.now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
                "expires_at": (self.now + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
                "reviewers": self._reviewers(set(roles)),
            }
            external.append(self._sign_assurance(assurance))
        domains = []
        for gate_id, (domain, roles) in DOMAIN_ASSURANCE.items():
            assurance = {
                "schema_version": "agenttrust.domain-assurance-attestation.v1",
                "attestation_id": f"domain-{domain.lower()}",
                "domain": domain,
                "release_id": self.release_id,
                "scope_digest": self.scope_digest,
                "environment_reference": self.environment_reference,
                "decision": "APPROVED",
                "automated": False,
                "evidence_digests": self._expected_evidence(gate_id, conditions, receipts),
                "issued_at": (self.now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
                "expires_at": (self.now + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
                "reviewers": self._reviewers(set(roles)),
            }
            domains.append(self._sign_assurance(assurance))
        return {
            "schema_version": QUALIFICATION_INPUT_SCHEMA_VERSION,
            "environment_reference": self.environment_reference,
            "scope": self.scope,
            "git_provenance": self.git_provenance,
            "release_binding": self.release_binding,
            "batch_records": batches,
            "condition_records": list(conditions.values()),
            "worm_receipts": receipt_list,
            "external_assurances": external,
            "domain_assurances": domains,
            "residual_risks": [],
            "exceptions": [],
        }
