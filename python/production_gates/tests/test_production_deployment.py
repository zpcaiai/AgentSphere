from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.git_provenance import (
    GateResult,
    canonical_json,
    sign_git_provenance,
    signed_git_provenance_digest,
)
from python.production_gates.release_binding import (
    build_release_binding,
    sign_release_binding,
)


ROOT = Path(__file__).parents[3]
RENDER_PATH = ROOT / "scripts" / "render-production-stack.py"
SPEC = importlib.util.spec_from_file_location("render_production_stack", RENDER_PATH)
assert SPEC is not None and SPEC.loader is not None
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)
BUILD_SPEC = importlib.util.spec_from_file_location(
    "build_production_image", ROOT / "scripts/build-production-image.py"
)
assert BUILD_SPEC is not None and BUILD_SPEC.loader is not None
BUILD = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(BUILD)

_RELEASE_COMMIT = "1" * 40
_RELEASE_ID = f"git:sha1:{_RELEASE_COMMIT}"
_PROVENANCE_DIRECTORY = tempfile.TemporaryDirectory()
_PROVENANCE_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_PROVENANCE_KEY_FILE = Path(_PROVENANCE_DIRECTORY.name).resolve() / "git-provenance.key"
_PROVENANCE_KEY_FILE.write_text(
    base64.urlsafe_b64encode(
        _PROVENANCE_PRIVATE.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode("ascii").rstrip("="),
    encoding="ascii",
)
_PROVENANCE_KEY_FILE.chmod(0o600)
_PROVENANCE_PUBLIC = base64.urlsafe_b64encode(
    _PROVENANCE_PRIVATE.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
).decode("ascii").rstrip("=")
_PROVENANCE_KEYRING = {
    "schema_version": "agenttrust.git-provenance-keyring.v1",
    "keys": [{
        "issuer": "test-release-authority",
        "key_id": "test-git-2026-01",
        "key_usage": "GIT_PROVENANCE_ATTESTATION",
        "algorithm": "Ed25519",
        "public_key": _PROVENANCE_PUBLIC,
        "status": "ACTIVE",
        "not_before": "2020-01-01T00:00:00+00:00",
        "not_after": "2100-01-01T00:00:00+00:00",
    }],
}
_RELEASE_BINDING_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
_RELEASE_BINDING_KEY_FILE = (
    Path(_PROVENANCE_DIRECTORY.name).resolve() / "release-binding.key"
)
_RELEASE_BINDING_KEY_FILE.write_text(
    base64.urlsafe_b64encode(
        _RELEASE_BINDING_PRIVATE.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode("ascii").rstrip("="),
    encoding="ascii",
)
_RELEASE_BINDING_KEY_FILE.chmod(0o600)
_RELEASE_BINDING_PUBLIC = base64.urlsafe_b64encode(
    _RELEASE_BINDING_PRIVATE.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
).decode("ascii").rstrip("=")
_RELEASE_BINDING_KEYRING = {
    "schema_version": "agenttrust.release-binding-keyring.v1",
    "keys": [{
        "issuer": "test-release-authority",
        "key_id": "test-release-binding-2026-01",
        "key_usage": "PRODUCTION_RELEASE_BINDING",
        "algorithm": "Ed25519",
        "public_key": _RELEASE_BINDING_PUBLIC,
        "status": "ACTIVE",
        "not_before": "2020-01-01T00:00:00+00:00",
        "not_after": "2100-01-01T00:00:00+00:00",
    }],
}
_RAW_RENDER = RENDER.render


def _signed_provenance() -> dict[str, object]:
    host_by_name = {"origin": "git.example.test"}
    url_digests = {"origin": "2" * 64}
    remote_set_digest = hashlib.sha256(canonical_json({
        "origin": {"host": host_by_name["origin"], "url_digest": url_digests["origin"]}
    })).hexdigest()
    membership_digest = hashlib.sha256(canonical_json({
        "origin": {
            "host": host_by_name["origin"],
            "url_digest": url_digests["origin"],
            "tag_ref": "refs/tags/v1.2.3",
            "tag_object_id": "3" * 40,
            "peeled_commit_id": _RELEASE_COMMIT,
        }
    })).hexdigest()
    report = GateResult(
        gate="GIT_IMMUTABLE_PROVENANCE",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"git://git.example.test/{_RELEASE_COMMIT}",
        checks={
            "release_id": _RELEASE_ID,
            "object_format": "sha1",
            "commit_object_id": _RELEASE_COMMIT,
            "tree_object_id": "4" * 40,
            "commit_content_digest": "5" * 64,
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
            "release_tag": "v1.2.3",
            "release_tag_object_id": "3" * 40,
            "release_tag_target": _RELEASE_COMMIT,
            "release_tag_signature_verified": True,
            "remote_release_tag_verified": True,
            "remote_release_tag_ref": "refs/tags/v1.2.3",
            "remote_tag_object_ids": {"origin": "3" * 40},
            "remote_tag_peeled_commit_ids": {"origin": _RELEASE_COMMIT},
            "remote_membership_digest": membership_digest,
            "signature_trust_format": "SSH_ALLOWED_SIGNERS",
            "git_allowed_signers_digest": "6" * 64,
        },
        production_evidence=True,
    ).as_dict()
    return sign_git_provenance(
        report,
        _PROVENANCE_KEY_FILE,
        issuer="test-release-authority",
        key_id="test-git-2026-01",
        signed_at=datetime.now(timezone.utc),
    )


def _render_with_signed_provenance(
    template: str, candidate_values: dict[str, object], configuration: object
) -> str:
    bound_values = copy.deepcopy(candidate_values)
    provenance = _signed_provenance()
    signed_binding: object = {}
    if (
        "release_digest" in bound_values
        and isinstance(bound_values.get("release_id"), str)
        and RENDER.GIT_RELEASE_ID.fullmatch(str(bound_values["release_id"]))
    ):
        binding = build_release_binding(
            template, bound_values, configuration,
            provenance_digest=signed_git_provenance_digest(provenance),
            template_blob_object_id="7" * 40,
        )
        bound_values["release_digest"] = binding["release_digest"]
        signed_binding = sign_release_binding(
            binding,
            _RELEASE_BINDING_KEY_FILE,
            issuer="test-release-authority",
            key_id="test-release-binding-2026-01",
        )
    return _RAW_RENDER(
        template,
        bound_values,
        configuration,
        git_provenance=provenance,
        git_provenance_keyring=_PROVENANCE_KEYRING,
        release_binding=signed_binding,
        release_binding_keyring=_RELEASE_BINDING_KEYRING,
    )


RENDER.render = _render_with_signed_provenance


def runtime_config() -> dict[str, object]:
    value = json.loads((ROOT / "config/production-runtime.example.json").read_text())

    def clean(item: object) -> object:
        if isinstance(item, str):
            return (item.replace(".production.example", ".prod.test")
                    .replace("REPLACE_WITH_ENTERPRISE_SUBJECT", "subject-1")
                    .replace("REPLACE_WITH_ORGANIZATION", "org-1")
                    .replace("REPLACE_WITH_APPROVED_MODEL_VERSION", "model-v1"))
        if isinstance(item, list):
            return [clean(nested) for nested in item]
        if isinstance(item, dict):
            result = {key: clean(nested) for key, nested in item.items()}
            for key in ("ca_bundle", "client_identity_pem", "bearer_token_file"):
                if isinstance(result.get(key), str):
                    result[key] = f"/etc/agenttrust/secrets/runtime/{Path(result[key]).name}"
            return result
        return item

    result = clean(value)
    assert isinstance(result, dict)
    result["endpoints"]["orchestrator"]["base_url"] = "https://agenttrust-orchestrator"
    for name, token in RENDER.RUNTIME_ENDPOINT_TOKENS.items():
        result["endpoints"][name]["tls"]["bearer_token_file"] = f"/etc/agenttrust/secrets/runtime/{token}"
    return result


def values() -> dict[str, object]:
    digest = "a" * 64
    execution_identity = "URI:spiffe://prod.test/execution"
    enterprise_identity = "URI:spiffe://prod.test/enterprise-control"
    enterprise_authority_identity = "URI:spiffe://prod.test/enterprise-authority"
    approval_identity = "URI:spiffe://prod.test/approval"
    tool_proxy_identity = "URI:spiffe://prod.test/tool-proxy"
    pep_identity = "URI:spiffe://prod.test/pep"
    policy_admin_identity = "URI:spiffe://prod.test/policy-admin"
    incident_release_identity = "URI:spiffe://prod.test/incident-release"
    incident_detector_identity = "URI:spiffe://prod.test/anomaly-detector"
    pack_marketplace_identity = "URI:spiffe://prod.test/pack-marketplace"
    production_authority_identities = {
        name: f"URI:spiffe://prod.test/{name.replace('_', '-')}"
        for name in RENDER.PRODUCTION_AUTHORITY_KEYS
    }
    authority_endpoints = {
        key: f"https://{key}.authority.prod.test" for key in RENDER.AUTHORITY_KEYS
    }
    authority_endpoints.update({
        "agents": "https://agenttrust-agent-registry",
        "approvals": "https://agenttrust-approval",
        "evidence": "https://agenttrust-evidence",
        "tools": "https://agenttrust-registry",
        "credentials": "https://agenttrust-identity",
        "audit": "https://agenttrust-audit",
        "policies": "https://agenttrust-policy-admin",
        "incidents": "https://agenttrust-incident-release",
        "packs": "https://agenttrust-pack-marketplace",
        "models": "https://agenttrust-model-gateway",
        "data": "https://agenttrust-data-governance",
        "context": "https://agenttrust-context-governance",
        "anomalies": "https://agenttrust-runtime-anomaly",
        "security_evaluations": "https://agenttrust-security-evaluation",
        "supply_chain": "https://agenttrust-pack-supply-chain",
        "domain_packs": "https://agenttrust-domain-runtime",
        "sre": "https://agenttrust-platform-sre",
    })
    return {
        "schema_version": "agenttrust.production-stack-values.v2",
        "release_id": _RELEASE_ID,
        "release_digest": digest,
        "images": {key: f"registry.test/agenttrust/{key}@sha256:{digest}" for key in RENDER.IMAGE_KEYS},
        "database": {
            "enterprise_application_role": "agenttrust_enterprise_app",
            "enterprise_authority_application_role": "agenttrust_enterprise_authority",
            "orchestrator_application_role": "agenttrust_orchestrator_app",
            "execution_application_role": "agenttrust_execution_app",
            "registry_application_role": "agenttrust_registry_app",
            "agent_registry_application_role": "agenttrust_agent_registry",
            "policy_admin_application_role": "agenttrust_policy_admin",
            "incident_release_application_role": "agenttrust_incident_release",
            "pack_marketplace_application_role": "agenttrust_pack_marketplace",
            "approval_application_role": "agenttrust_approval_app",
            "pep_application_role": "agenttrust_pep_app",
            "identity_application_role": "agenttrust_identity_app",
            "tool_proxy_application_role": "agenttrust_tool_proxy_app",
            "evidence_application_role": "agenttrust_evidence_app",
            "audit_application_role": "agenttrust_audit_app",
            "model_gateway_application_role": "agenttrust_model_gateway",
            "data_governance_application_role": "agenttrust_data_governance",
            "context_governance_application_role": "agenttrust_context_governance",
            "runtime_anomaly_application_role": "agenttrust_runtime_anomaly",
            "security_evaluation_application_role": "agenttrust_security_eval",
            "pack_supply_chain_application_role": "agenttrust_pack_supply_chain",
            "domain_runtime_application_role": "agenttrust_domain_runtime",
            "platform_sre_application_role": "agenttrust_platform_sre",
        },
        "execution": {
            "client_identities": ["URI:spiffe://prod.test/temporal-worker"],
            "outbound_client_identity": execution_identity,
            "approval_readiness_schema": "agenttrust.approval-readiness.v1",
            "pep_readiness_schema": "agenttrust.pep-readiness.v1",
            "tool_readiness_schema": "agenttrust.tool-proxy-readiness.v1",
            "evidence_readiness_schema": "agenttrust.evidence-readiness.v1",
        },
        "registry": {
            "client_identities": [
                enterprise_identity, tool_proxy_identity, pep_identity,
            ],
            "publisher_id": "publisher:agenttrust-platform",
            "publisher_key_id": "registry-publisher-2026-01",
        },
        "agent_registry": {
            "client_identities": [enterprise_identity],
            "lifecycle_endpoint": "https://lifecycle.prod.test",
        },
        "policy_admin": {
            "client_identities": [enterprise_identity, tool_proxy_identity],
            "outbound_client_identity": policy_admin_identity,
            "agent_instance_id": "22222222-2222-4222-8222-222222222222",
            "organization_id": "org-1",
            "agent_version": "1.0.0",
            "region": "cn-east-1",
            "tool_id": "policy-administration-executor",
            "tool_version": "1.0.0",
            "executor_credential_profile": "policy-administration-executor",
            "service_subject": "service:agenttrust-enterprise-control",
            "bundle_signing_key_id": "policy-bundle-signing-2026-01",
            "maximum_authentication_age_seconds": 900,
        },
        "incident_release": {
            "client_identities": [
                enterprise_identity, tool_proxy_identity, incident_detector_identity,
            ],
            "outbound_client_identity": incident_release_identity,
            "detection_client_identity": incident_detector_identity,
            "agent_instance_id": "33333333-3333-4333-8333-333333333333",
            "organization_id": "org-1",
            "agent_version": "1.0.0",
            "region": "cn-east-1",
            "tool_id": "incident-release-executor",
            "tool_version": "1.0.0",
            "executor_credential_profile": "incident-release-executor",
            "service_subject": "service:agenttrust-enterprise-control",
            "release_signing_key_id": "incident-release-signing-2026-01",
            "maximum_authentication_age_seconds": 900,
            "execution_lease_seconds": 60,
            "containment_endpoint": "https://containment.prod.test",
            "replay_endpoint": "https://replay.prod.test",
        },
        "pack_marketplace": {
            "client_identities": [enterprise_identity, tool_proxy_identity],
            "outbound_client_identity": pack_marketplace_identity,
            "agent_instance_id": "44444444-4444-4444-8444-444444444444",
            "organization_id": "org-1",
            "agent_version": "1.0.0",
            "region": "cn-east-1",
            "tool_id": "pack-marketplace-executor",
            "tool_version": "1.0.0",
            "executor_credential_profile": "pack-marketplace-executor",
            "ingress_subject": "service:agenttrust-enterprise-control",
            "executor_subject": tool_proxy_identity,
            "query_subject": "service:agenttrust-enterprise-control",
            "release_gate_id": "production-release-gate",
            "maximum_authentication_age_seconds": 900,
        },
        "enterprise_authority": {
            "client_identities": [enterprise_identity, tool_proxy_identity],
            "outbound_client_identity": enterprise_authority_identity,
            "agent_instance_id": "11111111-1111-4111-8111-111111111111",
            "organization_id": "org-1",
            "agent_version": "1.0.0",
            "region": "cn-east-1",
            "tool_id": "enterprise-control-executor",
            "tool_version": "1.0.0",
            "executor_credential_profile": "enterprise-executor",
            "service_subject": "service:agenttrust-enterprise-control",
            "maximum_authentication_age_seconds": 900,
            "vault_kv_mount": "secret",
            "vault_kv_prefix": "agenttrust/api-keys",
        },
        "production_authorities": {
            name: {
                "client_identities": [enterprise_identity, tool_proxy_identity],
                "outbound_client_identity": production_authority_identities[name],
                "evidence_client_identity": production_authority_identities[name],
                "instance_id": f"{index:08d}-1111-4111-8111-{index:012d}",
                "organization_id": "org-1",
                "agent_version": "1.0.0",
                "region": "cn-east-1",
                "service_subject": f"service:agenttrust-{name.replace('_', '-')}",
                "data_port": RENDER.PRODUCTION_AUTHORITY_SPECS[name][0],
                "management_port": RENDER.PRODUCTION_AUTHORITY_SPECS[name][1],
                "readiness_schema": RENDER.PRODUCTION_AUTHORITY_SPECS[name][2],
                "execution_lease_seconds": 60,
                "recovery_interval_seconds": 15,
                "signing_key_id": f"{name.replace('_', '-')}-signing-2026-01",
                "maximum_authentication_age_seconds": 900,
                "dependencies": {
                    dependency: f"https://{name.replace('_', '-')}-{dependency.replace('_', '-')}.prod.test"
                    for dependency in RENDER.PRODUCTION_AUTHORITY_DEPENDENCIES[name]
                },
            }
            for index, name in enumerate(sorted(RENDER.PRODUCTION_AUTHORITY_KEYS), start=1)
        },
        "transition": {
            "client_identities": ["URI:spiffe://prod.test/temporal-worker"]
        },
        "authorities": {
            "approval": {
                "client_identities": [
                    execution_identity, enterprise_identity, pep_identity,
                ],
                "evidence_source_identity": approval_identity,
                "issuer": "agenttrust-approval",
                "key_id": "approval-signing-2026-01",
                "principal_audience": "agenttrust-approval",
                "principal_issuer": "agenttrust-enterprise-control",
                "principal_key_id": "approval-principal-2026-01",
                "principal_signing_key_format": "RAW_BASE64URL",
                "service_subject": "service:agenttrust-enterprise-control",
                "assertion_ttl_seconds": 60,
                "accepted_strong_auth_acrs": ["urn:agenttrust:acr:mfa"],
                "maximum_authentication_age_seconds": 900,
            },
            "pep": {
                "client_identities": [
                    execution_identity, enterprise_identity, policy_admin_identity,
                ],
                "outbound_client_identity": pep_identity,
                "issuer": "agenttrust-pep",
                "key_id": "pep-signing-2026-01",
                "policy_bundle_signing_key_id": "policy-bundle-signing-2026-01",
                "human_assertion_audience": "agenttrust-pep-governance",
                "human_assertion_max_authentication_age_seconds": 900,
                "query_require_strong_auth": True,
            },
            "identity": {
                "client_identities": [
                    tool_proxy_identity, enterprise_identity, pep_identity,
                ],
                "issuer": "agenttrust-identity",
                "key_id": "identity-signing-2026-01",
                "tool_proxy_client_identity": tool_proxy_identity,
            },
            "tool_proxy": {"client_identities": [execution_identity]},
            "evidence": {
                "client_identities": [
                    execution_identity, enterprise_identity, approval_identity,
                ],
                "issuer": "agenttrust-evidence",
                "key_id": "evidence-signing-2026-01",
                "worm_endpoint": "https://worm.prod.test",
                "max_artifact_bytes": 104857600,
            },
            "audit": {
                "client_identities": [enterprise_identity],
                "issuer": "agenttrust-audit-retention",
                "key_id": "audit-signing-2026-01",
                "worm_endpoint": "https://worm.prod.test",
                "deletion_endpoint": "https://retention-delete.prod.test",
                "max_export_bytes": 67108864,
                "max_request_bytes": 1048576,
            },
        },
        "temporal": {"address": "temporal.prod.test:7233", "namespace": "agenttrust", "task_queue": "agenttrust-production", "server_name": "temporal.prod.test"},
        "vault": {
            "address": "https://vault.prod.test",
            **{
                key: (
                    f"kv/data/agenttrust/{key.removesuffix('_path').replace('_', '-')}"
                    if key.endswith("_path")
                    else f"agenttrust-{key.removesuffix('_role').replace('_', '-')}-role"
                )
                for key in RENDER.VAULT_KEYS - {"address"}
            },
        },
        "network": {
            "node_cidr": "10.1.0.0/16",
            "database_cidr": "10.2.0.0/24",
            "temporal_cidr": "10.3.0.0/24",
            "vault_cidr": "10.4.0.0/24",
            "iam_cidr": "10.5.0.0/24",
            "ingress_cidr": "10.6.0.0/24",
            "external_service_egress_cidr": "10.7.0.0/24",
            "tool_target_cidr": "10.8.0.0/24",
            "evidence_storage_cidr": "10.9.0.0/24",
            "dns_cidr": "169.254.20.10/32",
        },
        "evidence": {"persistent_volume_name": "agenttrust-evidence-pv", "bundle_digest": digest, "storage_size": "1Gi"},
        "ingress": {"class": "nginx", "console_host": "console.prod.test", "control_api_host": "api.prod.test", "console_tls_secret": "console-tls", "control_api_tls_secret": "api-tls"},
        "transition_facts": {key: "https://facts.prod.test/" for key in RENDER.FACT_KEYS},
        "enterprise": {
            "iam_issuer": "https://idp.prod.test",
            "iam_jwks_endpoint": "https://idp.prod.test/.well-known/jwks.json",
            "iam_audience": "agenttrust-control-api",
            "iam_authorization_endpoint": "https://idp.prod.test/oauth2/authorize",
            "iam_token_endpoint": "https://idp.prod.test/oauth2/token",
            "iam_userinfo_endpoint": "https://idp.prod.test/oauth2/userinfo",
            "pep_endpoint": "https://agenttrust-pep",
            "pep_readiness_schema": "agenttrust.pep-readiness.v1",
            "approval_client_identity": enterprise_identity,
            "human_assertion": {
                "issuer": "agenttrust-enterprise-control",
                "audience": "agenttrust-pep-governance",
                "key_id": "human-principal-2026-01",
                "signing_key_format": "RAW_BASE64URL",
                "service_subject": "service:agenttrust-enterprise-control",
                "assertion_ttl_seconds": 60,
                "accepted_authentication_contexts": ["urn:agenttrust:acr:mfa"],
                "maximum_authentication_age_seconds": 900,
            },
            "orchestrator_runtime_client_identities": [
                "URI:spiffe://prod.test/production-runtime"
            ],
            "orchestrator_bff_client_identities": [
                "URI:spiffe://prod.test/enterprise-control",
                "URI:spiffe://prod.test/enterprise-authority",
                policy_admin_identity,
                incident_release_identity,
                pack_marketplace_identity,
            ],
            "authority_endpoints": authority_endpoints,
            "authority_readiness_schemas": {
                key: f"agenttrust.{key}-readiness.v1"
                for key in RENDER.AUTHORITY_READINESS_KEYS
            } | RENDER.INTERNAL_READINESS_SCHEMAS,
        },
    }


class ProductionDeploymentTests(unittest.TestCase):
    def test_full_stack_rejects_worktree_release(self) -> None:
        unsafe = values()
        unsafe["release_id"] = "WORKTREE-NO-GIT"
        with self.assertRaisesRegex(RENDER.RenderError, "PRODUCTION_STACK_RELEASE_ID_INVALID"):
            RENDER.render("", unsafe, runtime_config())

    def test_release_instructions_and_multizone_gate_use_authoritative_stack(self) -> None:
        readme = (ROOT / "README.md").read_text()
        self.assertIn("scripts/render-production-stack.py", readme)
        self.assertIn("deploy/kubernetes/production-stack.yaml.tmpl", readme)
        self.assertIn("--values /protected/release/production-stack-values.json", readme)
        conditions = json.loads(
            (ROOT / "config/production-runtime/conditions.json").read_text()
        )["conditions"]
        multizone = next(
            condition for condition in conditions
            if condition["condition_id"] == "MULTIZONE_CONTROL_PLANE_TOPOLOGY"
        )
        self.assertIn(
            "deploy/kubernetes/production-stack.yaml.tmpl", multizone["runtime_paths"]
        )
        self.assertNotIn(
            "deploy/kubernetes/production-runtime.yaml.tmpl", multizone["runtime_paths"]
        )
        immutable_release = next(
            condition for condition in conditions
            if condition["condition_id"] == "IMMUTABLE_GIT_RELEASE_PROVENANCE"
        )
        self.assertIn(
            "scripts/render-production-stack.py", immutable_release["runtime_paths"]
        )
        self.assertIn(
            "deploy/kubernetes/production-stack.yaml.tmpl",
            immutable_release["runtime_paths"],
        )
        self.assertIn(
            "python/production_gates/tests/test_production_deployment.py",
            immutable_release["test_paths"],
        )
        self.assertNotIn(
            "scripts/render-production-runtime.py", immutable_release["runtime_paths"]
        )

    def test_complete_stack_renders_without_tokens(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        result = RENDER.render(template, values(), runtime_config())
        self.assertNotIn("@@", result)
        self.assertIn("kind: Job", result)
        self.assertEqual(result.count("kind: Deployment"), 27)
        self.assertEqual(result.count("kind: SecretProviderClass"), 26)
        self.assertEqual(result.count("kind: NetworkPolicy"), 30)
        self.assertEqual(result.count("kind: PodDisruptionBudget"), 27)
        self.assertEqual(result.count("kind: ServiceAccount"), 27)
        self.assertIn("kind: SecretProviderClass", result)
        self.assertIn("kind: NetworkPolicy", result)
        self.assertIn("ReadOnlyMany", result)
        self.assertNotIn("kind: Secret\n", result)
        self.assertIn('orchestrator-endpoint: "https://agenttrust-orchestrator"', result)
        self.assertIn("AGENT_TRUST_ORCHESTRATOR_RUNTIME_CLIENT_IDENTITIES", result)
        self.assertIn("AGENT_TRUST_ORCHESTRATOR_BFF_CLIENT_IDENTITIES", result)
        self.assertIn(
            "AGENT_TRUST_ENTERPRISE_APPLICATION_ROLE, value: \"agenttrust_enterprise_app\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_ORCHESTRATOR_APPLICATION_ROLE, value: \"agenttrust_orchestrator_app\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_ENTERPRISE_AUTHORITY_APPLICATION_ROLE, value: \"agenttrust_enterprise_authority\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_AGENT_REGISTRY_APPLICATION_ROLE, value: \"agenttrust_agent_registry\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_POLICY_ADMIN_APPLICATION_ROLE, value: \"agenttrust_policy_admin\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_INCIDENT_RELEASE_APPLICATION_ROLE, value: \"agenttrust_incident_release\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_PACK_MARKETPLACE_APPLICATION_ROLE, value: \"agenttrust_pack_marketplace\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_DATABASE_EXPECTED_ROLE, value: \"agenttrust_enterprise_app\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_ORCHESTRATOR_DATABASE_EXPECTED_ROLE, value: \"agenttrust_orchestrator_app\"",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_EXECUTION_DATABASE_EXPECTED_ROLE, value: \"agenttrust_execution_app\"",
            result,
        )
        for component, role in (
            ("APPROVAL", "agenttrust_approval_app"),
            ("PEP", "agenttrust_pep_app"),
            ("IDENTITY", "agenttrust_identity_app"),
            ("TOOL_PROXY", "agenttrust_tool_proxy_app"),
            ("EVIDENCE", "agenttrust_evidence_app"),
            ("AUDIT", "agenttrust_audit_app"),
        ):
            self.assertIn(
                f"AGENT_TRUST_{component}_DATABASE_EXPECTED_ROLE, value: \"{role}\"",
                result,
            )
        self.assertIn('objectName: "database-ca.pem"', result)
        self.assertIn('secretKey: "database_ca"', result)
        self.assertIn(
            "AGENT_TRUST_DATABASE_CA_FILE, value: /var/run/agenttrust/secrets/database-ca.pem",
            result,
        )
        self.assertIn(
            "AGENT_TRUST_DATABASE_PASSWORD_FILE, value: /var/run/agenttrust/secrets/database-password",
            result,
        )
        migration_spc = result.split(
            "kind: SecretProviderClass\nmetadata:\n  name: agenttrust-migrations",
            maxsplit=1,
        )[1].split("---", maxsplit=1)[0]
        self.assertEqual(
            ["database-url", "database-password", "database-ca.pem"],
            re.findall(r'objectName: "([^"]+)"', migration_spc),
        )
        self.assertEqual(
            migration_spc.count('secretPath: "kv/data/agenttrust/migration"'), 3
        )
        migration_job = result.split("kind: Job\n", maxsplit=1)[1].split(
            "---", maxsplit=1
        )[0]
        for migration_input in (
            "AGENT_TRUST_DATABASE_URL_FILE, value: /var/run/agenttrust/secrets/database-url",
            "AGENT_TRUST_DATABASE_PASSWORD_FILE, value: /var/run/agenttrust/secrets/database-password",
            "AGENT_TRUST_DATABASE_CA_FILE, value: /var/run/agenttrust/secrets/database-ca.pem",
            "secretProviderClass: agenttrust-migrations",
        ):
            self.assertIn(migration_input, migration_job)
        self.assertIn(
            'iam-jwks-endpoint: "https://idp.prod.test/.well-known/jwks.json"', result
        )
        self.assertIn("AGENT_TRUST_IAM_JWKS_ENDPOINT", result)
        self.assertIn('iam-audience: "agenttrust-control-api"', result)
        self.assertIn("AGENT_TRUST_IAM_AUDIENCE", result)
        self.assertIn("AGENT_TRUST_IAM_AUTHORIZATION_ENDPOINT", result)
        self.assertIn("AGENT_TRUST_IAM_TOKEN_ENDPOINT", result)
        self.assertIn("AGENT_TRUST_IAM_USERINFO_ENDPOINT", result)
        self.assertIn(
            'iam-authorization-endpoint: "https://idp.prod.test/oauth2/authorize"', result
        )
        self.assertIn('iam-token-endpoint: "https://idp.prod.test/oauth2/token"', result)
        self.assertIn(
            'iam-userinfo-endpoint: "https://idp.prod.test/oauth2/userinfo"', result
        )
        self.assertIn(
            'execution-endpoint: "https://agenttrust-execution/v1/executions/execute"',
            result,
        )
        for execution_input in (
            "AGENT_TRUST_EXECUTION_ENDPOINT",
            "AGENT_TRUST_EXECUTION_CA_FILE",
            "AGENT_TRUST_EXECUTION_CERTIFICATE_FILE",
            "AGENT_TRUST_EXECUTION_PRIVATE_KEY_FILE",
            "AGENT_TRUST_EXECUTION_TOKEN_FILE",
        ):
            self.assertIn(execution_input, result)
        self.assertIn("AGENT_TRUST_TRANSITION_CLIENT_IDENTITIES", result)
        self.assertIn("AGENT_TRUST_TRANSITION_TOKEN_BINDINGS_FILE", result)
        self.assertIn('objectName: "transition-token-bindings.json"', result)
        self.assertIn('objectName: "execution-token-bindings.json"', result)
        self.assertIn('objectName: "approval-verification-keys.json"', result)
        self.assertIn("AGENT_TRUST_EXECUTION_APPROVAL_VERIFICATION_KEYS_FILE", result)
        self.assertIn('objectName: "evidence-verification-keys.json"', result)
        self.assertIn("AGENT_TRUST_EXECUTION_EVIDENCE_VERIFICATION_KEYS_FILE", result)
        self.assertIn("AGENT_TRUST_EXECUTION_OUTBOUND_CLIENT_IDENTITY", result)
        self.assertIn('objectName: "evidence-verifying-keyring.json"', result)
        self.assertIn("AGENT_TRUST_EVIDENCE_VERIFYING_KEYRING_FILE", result)
        self.assertIn("name: agenttrust-execution-network", result)
        self.assertIn("containerPort: 8083", result)
        self.assertIn("containerPort: 9093", result)
        self.assertIn("name: agenttrust-registry-network", result)
        self.assertIn("containerPort: 8084", result)
        self.assertIn("containerPort: 9094", result)
        self.assertIn("AGENT_TRUST_REGISTRY_DATABASE_EXPECTED_ROLE", result)
        self.assertIn("AGENT_TRUST_REGISTRY_DATABASE_PASSWORD_FILE", result)
        self.assertIn('objectName: "database-password"', result)
        self.assertIn('secretKey: "database_password"', result)
        self.assertIn('objectName: "registry-token-bindings.json"', result)
        self.assertIn('objectName: "publisher-private-key"', result)
        self.assertIn(
            'from: [{ipBlock: {cidr: "10.1.0.0/16"}}]\n'
            "      ports: [{protocol: TCP, port: 9093}]",
            result,
        )
        for cidr in (
            "10.4.0.0/24", "10.5.0.0/24", "10.6.0.0/24", "10.7.0.0/24",
            "10.8.0.0/24", "10.9.0.0/24",
        ):
            self.assertIn(f'ipBlock: {{cidr: "{cidr}"}}', result)
        # The two callers share their caller-side Vault object, but transition authenticates
        # against per-SAN/tenant/scope digests and must not mount a server-global raw token.
        self.assertEqual(result.count("AGENT_TRUST_TRANSITION_TOKEN_FILE"), 2)
        self.assertIn(
            'objectName: "transition.token", secretPath: "kv/data/agenttrust/orchestrator", '
            'secretKey: "transition_token", filePermission: 0o440',
            result,
        )
        self.assertNotIn(
            "/var/run/agenttrust/secrets/transition/transition.token", result
        )
        self.assertIn('ipBlock: {cidr: "169.254.20.10/32"}', result)
        self.assertIn("{protocol: UDP, port: 53}", result)
        self.assertIn("{protocol: TCP, port: 53}", result)
        self.assertIn("AGENT_TRUST_ORCHESTRATOR_DATABASE_PASSWORD_FILE", result)
        self.assertIn("AGENT_TRUST_ORCHESTRATOR_TOKEN_BINDINGS_FILE", result)
        self.assertNotIn("AGENT_TRUST_ORCHESTRATOR_SERVICE_TOKEN_FILE", result)
        self.assertIn("AGENT_TRUST_EXECUTION_PEP_PREAPPROVE_TOKEN_FILE", result)
        self.assertIn("AGENT_TRUST_EXECUTION_PEP_AUTHORIZE_TOKEN_FILE", result)
        self.assertNotIn("AGENT_TRUST_EXECUTION_PEP_TOKEN_FILE", result)
        for service in (
            "approval", "pep", "identity", "tool-proxy", "evidence", "audit",
        ):
            self.assertIn(f"name: agenttrust-{service}", result)
        for service in ("agent-registry", "enterprise-authority"):
            self.assertIn(f"name: agenttrust-{service}", result)
        self.assertIn("name: agenttrust-policy-admin", result)
        for token_env in (
            "AGENT_TRUST_AGENT_REGISTRY_READ_TOKEN_FILE",
            "AGENT_TRUST_ORCHESTRATOR_READ_TOKEN_FILE",
            "AGENT_TRUST_EVIDENCE_READ_TOKEN_FILE",
            "AGENT_TRUST_INCIDENT_READ_TOKEN_FILE",
            "AGENT_TRUST_POLICY_ADMIN_READ_TOKEN_FILE",
            "AGENT_TRUST_TOOL_REGISTRY_READ_TOKEN_FILE",
            "AGENT_TRUST_IDENTITY_READ_TOKEN_FILE",
            "AGENT_TRUST_PACK_MARKETPLACE_READ_TOKEN_FILE",
            "AGENT_TRUST_TRACE_READ_TOKEN_FILE",
            "AGENT_TRUST_COMPLIANCE_READ_TOKEN_FILE",
            "AGENT_TRUST_AUDIT_READ_TOKEN_FILE",
            "AGENT_TRUST_SRE_READ_TOKEN_FILE",
            "AGENT_TRUST_DEPLOYMENT_READ_TOKEN_FILE",
            "AGENT_TRUST_POLICY_MUTATE_TOKEN_FILE",
            "AGENT_TRUST_INCIDENT_MUTATE_TOKEN_FILE",
            "AGENT_TRUST_PACK_MARKETPLACE_MUTATE_TOKEN_FILE",
            "AGENT_TRUST_ORCHESTRATOR_COMMAND_TOKEN_FILE",
            "AGENT_TRUST_ORCHESTRATOR_TRANSITIONS_TOKEN_FILE",
            "AGENT_TRUST_PEP_APPROVAL_TOKEN_FILE",
            "AGENT_TRUST_PEP_QUERY_TOKEN_FILE",
            "AGENT_TRUST_ENTERPRISE_MUTATE_TOKEN_FILE",
            "AGENT_TRUST_APPROVAL_READ_TOKEN_FILE",
            "AGENT_TRUST_APPROVAL_REQUEST_TOKEN_FILE",
            "AGENT_TRUST_APPROVAL_DECIDE_TOKEN_FILE",
            "AGENT_TRUST_APPROVAL_ISSUE_TOKEN_FILE",
            "AGENT_TRUST_APPROVAL_REVOKE_TOKEN_FILE",
        ):
            self.assertIn(token_env, result)
        self.assertNotIn("AGENT_TRUST_SERVICE_TOKEN_FILE", result)
        for human_assertion_input in (
            "AGENT_TRUST_HUMAN_ASSERTION_SIGNING_KEY_FILE",
            "AGENT_TRUST_HUMAN_ASSERTION_CLIENT_IDENTITY",
            "AGENT_TRUST_PEP_HUMAN_ASSERTION_KEYRING_FILE",
            "AGENT_TRUST_PEP_HUMAN_ASSERTION_AUDIENCE",
            "AGENT_TRUST_PEP_HUMAN_ASSERTION_MAX_AUTHENTICATION_AGE_SECONDS",
            "AGENT_TRUST_PEP_QUERY_REQUIRE_STRONG_AUTH",
        ):
            self.assertIn(human_assertion_input, result)
        self.assertIn('objectName: "human-principal-signing-key"', result)
        self.assertIn('objectName: "human-principal-keyring.json"', result)

    def test_native_tls_ports_probes_and_network_policy_are_aligned(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        result = RENDER.render(template, values(), runtime_config())
        self.assertNotIn("agenttrust-envoy-orchestrator", result)
        self.assertNotIn("agenttrust-envoy-transition", result)
        self.assertIn("AGENT_TRUST_ORCHESTRATOR_TLS_CERTIFICATE_FILE", result)
        self.assertIn("AGENT_TRUST_TRANSITION_TLS_CERTIFICATE_FILE", result)
        self.assertIn("containerPort: 8081", result)
        self.assertIn("containerPort: 8082", result)
        self.assertIn("containerPort: 9091", result)
        self.assertIn("ports: [{protocol: TCP, port: 8081}]", result)
        self.assertIn("ports: [{protocol: TCP, port: 8082}]", result)
        self.assertIn("--management-port", result)
        self.assertIn("path: /ready, port: management", result)
        self.assertIn("path: /ready, port: https, scheme: HTTPS", result)
        self.assertIn("containerPort: 9090", result)
        self.assertIn("path: /actuator/health/readiness, port: management", result)
        self.assertIn(
            'from: [{ipBlock: {cidr: "10.1.0.0/16"}}]\n'
            "      ports: [{protocol: TCP, port: 9091}]",
            result,
        )

    def test_transition_token_binding_runbook_has_rotation_contract(self) -> None:
        runbook = (ROOT / "docs/platform/production-deployment-runbook.md").read_text()
        normalized = " ".join(runbook.split())
        for required in (
            "`token_sha256`",
            "lowercase SHA-256 digest of that caller's bearer token",
            "`(client_identity, tenant_id, scope, token_sha256)`",
            "first add a binding containing the new digest",
            "roll the caller to the new raw token",
            "only then remove the old digest",
        ):
            self.assertIn(required, normalized)

    def test_orchestrator_runtime_and_bff_identities_must_be_distinct(self) -> None:
        unsafe = values()
        unsafe["enterprise"]["orchestrator_bff_client_identities"] = list(
            unsafe["enterprise"]["orchestrator_runtime_client_identities"]
        )
        with self.assertRaisesRegex(
            RENDER.RenderError, "ORCHESTRATOR_CLIENT_IDENTITIES_NOT_DISTINCT"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_database_application_roles_must_be_distinct_and_safe(self) -> None:
        unsafe = values()
        unsafe["database"]["orchestrator_application_role"] = unsafe["database"][
            "enterprise_application_role"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "APPLICATION_ROLES_NOT_DISTINCT"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["database"]["execution_application_role"] = unsafe["database"][
            "orchestrator_application_role"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "APPLICATION_ROLES_NOT_DISTINCT"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["database"]["registry_application_role"] = unsafe["database"][
            "execution_application_role"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "APPLICATION_ROLES_NOT_DISTINCT"):
            RENDER.render("", unsafe, runtime_config())

    def test_vault_workload_roles_and_paths_must_be_distinct(self) -> None:
        unsafe = values()
        unsafe["vault"]["incident_release_role"] = unsafe["vault"][
            "policy_admin_role"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "VAULT_ROLES_NOT_DISTINCT"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["vault"]["pack_marketplace_path"] = unsafe["vault"][
            "incident_release_path"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "VAULT_PATHS_NOT_DISTINCT"):
            RENDER.render("", unsafe, runtime_config())

    def test_production_network_dependencies_must_be_distinct(self) -> None:
        unsafe = values()
        unsafe["network"]["tool_target_cidr"] = unsafe["network"][
            "external_service_egress_cidr"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "NETWORK_CIDRS_OVERLAP"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["execution"]["pep_readiness_schema"] = 'ready",true'
        with self.assertRaisesRegex(RENDER.RenderError, "READINESS_SCHEMA_INVALID"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["execution"]["pep_readiness_schema"] = "agenttrust.wrong-readiness.v1"
        with self.assertRaisesRegex(
            RENDER.RenderError, "EXECUTION_READINESS_SCHEMA_MISMATCH"
        ):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["enterprise"]["authority_readiness_schemas"]["audit"] = (
            "agenttrust.audit-readiness.v1"
        )
        with self.assertRaisesRegex(
            RENDER.RenderError, "AUDIT_AUTHORITY_READINESS_SCHEMA_MISMATCH"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_execution_dependencies_are_internal_dns_and_peer_scoped(self) -> None:
        rendered = RENDER.render(
            (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(),
            values(),
            runtime_config(),
        )
        for endpoint in (
            "https://agenttrust-approval/", "https://agenttrust-pep/",
            "https://agenttrust-tool-proxy/", "https://agenttrust-evidence/",
        ):
            self.assertIn(endpoint, rendered)
        execution_policy = rendered.split(
            "name: agenttrust-execution-network", 1
        )[1].split("---", 1)[0]
        for peer in (
            "component: approval", "component: pep", "component: tool-proxy",
            "component: evidence",
        ):
            self.assertIn(peer, execution_policy)
        unsafe = values()
        unsafe["execution"]["pep_endpoint"] = "https://attacker.prod.test/"
        with self.assertRaisesRegex(RENDER.RenderError, "EXECUTION_INVALID"):
            RENDER.render("", unsafe, runtime_config())

        unsafe = values()
        unsafe["execution"]["outbound_client_identity"] = (
            "URI:spiffe://prod.test/" + "x" * 240
        )
        with self.assertRaisesRegex(
            RENDER.RenderError, "EXECUTION_OUTBOUND_CLIENT_IDENTITY_INVALID"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_all_evidence_publishers_are_bidirectionally_peer_scoped(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        service_and_target_ports = (
            "ports: [{protocol: TCP, port: 443}, {protocol: TCP, port: 8087}]"
        )
        publisher_policies = (
            ("execution", "agenttrust-execution-network"),
            ("enterprise-api", "agenttrust-enterprise-control-network"),
            ("approval", "agenttrust-approval-network"),
            ("domain-runtime", "agenttrust-domain-runtime-network"),
            ("pack-supply-chain", "agenttrust-pack-supply-chain-network"),
            ("security-evaluation", "agenttrust-security-evaluation-network"),
            ("runtime-anomaly", "agenttrust-runtime-anomaly-network"),
            ("context-governance", "agenttrust-context-governance-network"),
            ("data-governance", "agenttrust-data-governance-network"),
            ("platform-sre", "agenttrust-platform-sre-network"),
            ("model-gateway", "agenttrust-model-gateway-network"),
        )
        for component, policy_name in publisher_policies:
            with self.subTest(direction="egress", component=component):
                policy = template.split(f"name: {policy_name}", 1)[1].split(
                    "---", 1
                )[0]
                self.assertIn("app.kubernetes.io/component: evidence", policy)
                self.assertIn(service_and_target_ports, policy)

        evidence_policy = template.split(
            "name: agenttrust-evidence-network", 1
        )[1].split("---", 1)[0]
        for component, _ in publisher_policies:
            with self.subTest(direction="ingress", component=component):
                self.assertIn(
                    f"app.kubernetes.io/component: {component}", evidence_policy
                )
        self.assertIn(service_and_target_ports, evidence_policy)

    def test_execution_approval_authority_contract_is_deployed(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        for required in (
            'objectName: "approval.token"',
            'objectName: "approval-verification-keys.json"',
            "AGENT_TRUST_EXECUTION_APPROVAL_ENDPOINT",
            "AGENT_TRUST_EXECUTION_APPROVAL_TOKEN_FILE",
            "AGENT_TRUST_EXECUTION_APPROVAL_VERIFICATION_KEYS_FILE",
            "AGENT_TRUST_EXECUTION_APPROVAL_READINESS_SCHEMA",
            "name: agenttrust-approval",
            "app.kubernetes.io/name: agenttrust-execution",
        ):
            self.assertIn(required, template)
        runbook = (ROOT / "docs/platform/production-deployment-runbook.md").read_text()
        normalized_runbook = " ".join(runbook.split())
        for required in (
            "POST /v1/approvals/grants/consume",
            "agenttrust.approval-grant-receipt.v1",
            "agenttrust.approval-verification-keys.v1",
            "agenttrust.approval-readiness.v1",
        ):
            self.assertIn(required, normalized_runbook)
        self.assertIn(
            "execution never manufactures an approval from request data",
            normalized_runbook.lower(),
        )
        binary = (
            ROOT
            / "rust/crates/production-runtime/src/bin/agenttrust-execution-service.rs"
        ).read_text()
        execution = (
            ROOT / "rust/crates/production-runtime/src/execution.rs"
        ).read_text()
        for required in (
            "AGENT_TRUST_EXECUTION_APPROVAL_VERIFICATION_KEYS_FILE",
            'port("APPROVAL", None)?',
            "AGENT_TRUST_EXECUTION_OUTBOUND_CLIENT_IDENTITY",
            "validate_certificate_identity_file",
        ):
            self.assertIn(required, binary)
        for required in (
            '"/v1/authorize/pre-approval"',
            '"/v1/approvals/grants/consume"',
            '"agenttrust.approval-verification-keys.v1"',
            "signed.stage != EnforcementStage::PreApproval",
            "receipt.remaining_uses != 0",
            "grant.plan_hash != request.plan_hash",
            "authorization.approval_ids != expected_approval_ids",
            "source_service: self.source_service.clone()",
        ):
            self.assertIn(required, execution)

    def test_execution_materialization_and_dispatch_poll_contract_is_wired(self) -> None:
        worker = (ROOT / "python/durable_worker/worker.py").read_text()
        for required in (
            "agenttrust.action-materialization-ref.v1",
            "ORCHESTRATOR_INGRESS_POSTGRESQL",
            "execution-dispatch-or-poll",
            'status in {"PREPARED", "RUNNING", "COMPENSATING"}',
            "AGENT_TRUST_EXECUTION_ENDPOINT",
        ):
            self.assertIn(required, worker)
        self.assertNotIn('"action": state[', worker)

    def test_transition_client_identity_allowlist_rejects_injection(self) -> None:
        unsafe = values()
        unsafe["transition"]["client_identities"] = [
            'URI:spiffe://prod.test/worker",DNS:attacker'
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "CLIENT_IDENTITIES_INVALID"):
            RENDER.render("", unsafe, runtime_config())

    def test_iam_audience_rejects_injection(self) -> None:
        unsafe = values()
        unsafe["enterprise"]["iam_audience"] = 'agenttrust", audience: attacker'
        with self.assertRaisesRegex(RENDER.RenderError, "IAM_AUDIENCE_INVALID"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["database"]["enterprise_application_role"] = 'app";CREATE ROLE attacker;--'
        with self.assertRaisesRegex(RENDER.RenderError, "ENTERPRISE_APPLICATION_ROLE_INVALID"):
            RENDER.render("", unsafe, runtime_config())

    def test_explicit_iam_endpoints_reject_ambient_or_injected_values(self) -> None:
        for field, endpoint in (
            ("iam_authorization_endpoint", "http://idp.prod.test/oauth2/authorize"),
            ("iam_token_endpoint", 'https://idp.prod.test/oauth2/token"'),
            ("iam_userinfo_endpoint", "https://idp.prod.test/oauth2/userinfo?all=true"),
        ):
            unsafe = values()
            unsafe["enterprise"][field] = endpoint
            with self.subTest(field=field), self.assertRaisesRegex(
                RENDER.RenderError, field.upper()
            ):
                RENDER.render("", unsafe, runtime_config())

    def test_yaml_breaking_or_malformed_client_identity_is_rejected(self) -> None:
        for identity in (
            'URI:spiffe://prod.test/bff"}',
            "URI:spiffe://prod.test/bff,URI:spiffe://prod.test/runtime",
            "URI:spiffe://prod.test/bff path",
            "DNS:..",
        ):
            unsafe = values()
            unsafe["enterprise"]["orchestrator_bff_client_identities"] = [identity]
            with self.subTest(identity=identity), self.assertRaisesRegex(
                RENDER.RenderError, "ORCHESTRATOR_CLIENT_IDENTITIES_INVALID"
            ):
                RENDER.render("", unsafe, runtime_config())

    def test_mutable_image_is_rejected(self) -> None:
        unsafe = values()
        unsafe["images"]["runtime"] = "registry.test/runtime:latest"
        with self.assertRaisesRegex(RENDER.RenderError, "IMAGE_NOT_IMMUTABLE"):
            RENDER.render("", unsafe, runtime_config())

    def test_broad_egress_is_rejected(self) -> None:
        unsafe = values()
        unsafe["network"]["external_service_egress_cidr"] = "0.0.0.0/0"
        with self.assertRaisesRegex(RENDER.RenderError, "EXTERNAL_SERVICE_EGRESS_CIDR_INVALID"):
            RENDER.render("", unsafe, runtime_config())

    def test_dns_egress_requires_one_explicit_resolver_address(self) -> None:
        for cidr in ("10.96.0.0/24", "169.254.0.0/16", "0.0.0.0/0"):
            unsafe = values()
            unsafe["network"]["dns_cidr"] = cidr
            with self.subTest(cidr=cidr), self.assertRaisesRegex(
                RENDER.RenderError, "DNS_CIDR_INVALID"
            ):
                RENDER.render("", unsafe, runtime_config())

    def test_transition_allows_both_dependency_ready_callers(self) -> None:
        rendered = RENDER.render(
            (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(),
            values(),
            runtime_config(),
        )
        transition_policy = rendered.split(
            "name: agenttrust-transition-network", 1
        )[1].split("---", 1)[0]
        self.assertIn("app.kubernetes.io/component: temporal-worker", transition_policy)
        self.assertIn("app.kubernetes.io/component: orchestrator-api", transition_policy)
        self.assertIn("port: 8082", transition_policy)

    def test_runtime_placeholder_is_rejected(self) -> None:
        unsafe = runtime_config()
        unsafe["identity"]["subject_mappings"][0]["subject"] = "REPLACE_WITH_SUBJECT"
        with self.assertRaisesRegex(RENDER.RenderError, "HAS_PLACEHOLDER"):
            RENDER.render("", values(), unsafe)

    def test_yaml_breaking_https_endpoint_is_rejected(self) -> None:
        for endpoint in (
            'https://foo"bar', "https://foo bar", "https://foo|bar", "https://foo\\bar",
            "https://pep.prod.test:9443",
        ):
            unsafe = values()
            unsafe["enterprise"]["pep_endpoint"] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(
                RENDER.RenderError, "PEP_ENDPOINT_INVALID"
            ):
                RENDER.render("", unsafe, runtime_config())

    def test_enterprise_pep_human_assertion_trust_is_exactly_aligned(self) -> None:
        external = values()
        external["enterprise"]["pep_endpoint"] = "https://pep.prod.test"
        with self.assertRaisesRegex(RENDER.RenderError, "PEP_ENDPOINT_NOT_INTERNAL"):
            RENDER.render("", external, runtime_config())
        unsafe = values()
        unsafe["enterprise"]["human_assertion"]["audience"] = "wrong-audience"
        with self.assertRaisesRegex(
            RENDER.RenderError, "HUMAN_ASSERTION_AUDIENCE_MISMATCH"
        ):
            RENDER.render("", unsafe, runtime_config())

        missing_identity = values()
        missing_identity["authorities"]["pep"]["client_identities"] = [
            missing_identity["execution"]["outbound_client_identity"]
        ]
        with self.assertRaisesRegex(
            RENDER.RenderError, "PEP_CLIENT_IDENTITIES_NOT_EXACT"
        ):
            RENDER.render("", missing_identity, runtime_config())

    def test_pep_outbound_authority_material_and_egress_are_complete(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        for name in (
            "identity", "resource-state", "budget", "trajectory-risk", "registry",
            "environment", "pdp", "pdp-activation", "approval-verify", "ledger",
            "credential-issue",
        ):
            self.assertIn(f'objectName: "{name}.token"', template)
        for name in (
            "identity", "resource-state", "budget", "trajectory-risk", "registry",
            "environment", "approval", "ledger", "credential", "pdp-activation",
        ):
            self.assertIn(f'objectName: "{name}-verification-key"', template)
        rendered = RENDER.render(template, values(), runtime_config())
        pep_policy = rendered.split(
            "name: agenttrust-pep-network", 1
        )[1].split("---", 1)[0]
        for dependency in (
            "component: registry", "component: approval", "component: identity",
            'cidr: "10.2.0.0/24"', 'cidr: "10.7.0.0/24"',
        ):
            self.assertIn(dependency, pep_policy)

    def test_policy_activation_chain_uses_keyring_and_exact_pep_identity(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "AGENT_TRUST_POLICY_PEP_ACTIVATION_ENDPOINT",
            "AGENT_TRUST_POLICY_PEP_ACTIVATION_TOKEN_FILE",
            "AGENT_TRUST_POLICY_PEP_ACTIVATION_VERIFYING_KEY_FILE",
            "AGENT_TRUST_PEP_POLICY_BUNDLE_KEYRING_FILE",
            'objectName: "policy-bundle-keyring.json"',
            'objectName: "policy-bundle-verifying.key"',
            'objectName: "pdp-activation.token"',
            'objectName: "pdp-activation-verification-key"',
            'agenttrust.io/policy-bundle-signing-key-id: "policy-bundle-signing-2026-01"',
        ):
            self.assertIn(required, rendered)
        self.assertNotIn("AGENT_TRUST_PEP_ALLOWED_POLICY_BUNDLES", rendered)
        unsafe = values()
        unsafe["authorities"]["pep"]["client_identities"].remove(
            unsafe["policy_admin"]["outbound_client_identity"]
        )
        with self.assertRaisesRegex(
            RENDER.RenderError, "PEP_CLIENT_IDENTITIES_NOT_EXACT"
        ):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["authorities"]["pep"]["policy_bundle_signing_key_id"] = "wrong-key"
        with self.assertRaisesRegex(
            RENDER.RenderError, "POLICY_BUNDLE_SIGNING_KEY_ID_MISMATCH"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_audit_retention_authority_is_fail_closed_and_peer_scoped(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "name: agenttrust-audit",
            'image: "registry.test/agenttrust/audit@sha256:' + "a" * 64 + '"',
            "AGENT_TRUST_AUDIT_DATABASE_PASSWORD_FILE",
            "AGENT_TRUST_AUDIT_DATABASE_EXPECTED_ROLE",
            "AGENT_TRUST_AUDIT_VERIFYING_KEYRING_FILE",
            "AGENT_TRUST_AUDIT_TOKEN_BINDINGS_FILE",
            "AGENT_TRUST_AUDIT_WORM_PRIVATE_KEY_FILE",
            "AGENT_TRUST_AUDIT_DELETION_PRIVATE_KEY_FILE",
            "AGENT_TRUST_AUDIT_HUMAN_ASSERTION_KEYRING_FILE",
            "AGENT_TRUST_AUDIT_HUMAN_ASSERTION_AUDIENCE",
            "AGENT_TRUST_AUDIT_HUMAN_ASSERTION_MAX_AUTHENTICATION_AGE_SECONDS",
            "AGENT_TRUST_AUDIT_QUERY_REQUIRE_STRONG_AUTH",
            "containerPort: 8088",
            "containerPort: 9098",
            "path: /ready, port: management",
        ):
            self.assertIn(required, rendered)
        audit_policy = rendered.split(
            "name: agenttrust-audit-network", 1
        )[1].split("---", 1)[0]
        for required in (
            "component: enterprise-api",
            'cidr: "10.1.0.0/16"',
            'cidr: "10.2.0.0/24"',
            'cidr: "10.9.0.0/24"',
            'cidr: "10.7.0.0/24"',
            "port: 8088",
            "port: 9098",
        ):
            self.assertIn(required, audit_policy)
        unsafe = values()
        unsafe["authorities"]["audit"]["max_export_bytes"] = 67_108_865
        with self.assertRaisesRegex(RENDER.RenderError, "AUDIT_BOUNDS_INVALID"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["authorities"]["audit"]["client_identities"] = [
            unsafe["execution"]["outbound_client_identity"]
        ]
        with self.assertRaisesRegex(
            RENDER.RenderError, "AUDIT_ENTERPRISE_IDENTITY_MISSING"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_agent_registry_authority_is_independent_and_lifecycle_scoped(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "name: agenttrust-agent-registry",
            'image: "registry.test/agenttrust/agent_registry@sha256:' + "a" * 64 + '"',
            "AGENT_TRUST_AGENT_REGISTRY_DATABASE_EXPECTED_ROLE",
            "AGENT_TRUST_AGENT_REGISTRY_TOKEN_BINDINGS_FILE",
            "AGENT_TRUST_AGENT_REGISTRY_CURSOR_HMAC_KEY_FILE",
            "AGENT_TRUST_AGENT_REGISTRY_LIFECYCLE_BASE_URL",
            "AGENT_TRUST_AGENT_REGISTRY_IDENTITY_REVOCATION_TOKEN_FILE",
            "AGENT_TRUST_AGENT_REGISTRY_AUTHORIZATION_REVOCATION_TOKEN_FILE",
            "AGENT_TRUST_AGENT_REGISTRY_PACK_DEACTIVATION_TOKEN_FILE",
            "containerPort: 8089",
            "containerPort: 9099",
            'agent-registry-endpoint: "https://agenttrust-agent-registry"',
        ):
            self.assertIn(required, rendered)
        spc = rendered.split("name: agenttrust-agent-registry", 1)[1].split("---", 1)[0]
        self.assertEqual(spc.count("objectName:"), 14)
        policy = rendered.split("name: agenttrust-agent-registry-network", 1)[1].split("---", 1)[0]
        for required in (
            "component: enterprise-api", 'cidr: "10.1.0.0/16"',
            'cidr: "10.2.0.0/24"', 'cidr: "10.7.0.0/24"',
            "port: 8089", "port: 9099",
        ):
            self.assertIn(required, policy)
        unsafe = values()
        unsafe["agent_registry"]["client_identities"] = [
            "URI:spiffe://prod.test/unbound-caller"
        ]
        with self.assertRaisesRegex(
            RENDER.RenderError, "AGENT_REGISTRY_ENTERPRISE_IDENTITY_MISSING"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_policy_admin_authority_is_independent_fenced_and_fail_closed(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "name: agenttrust-policy-admin",
            'image: "registry.test/agenttrust/policy_admin@sha256:' + "a" * 64 + '"',
            "AGENT_TRUST_POLICY_DATABASE_EXPECTED_ROLE",
            "AGENT_TRUST_POLICY_TOKEN_BINDINGS_FILE",
            "AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE",
            "AGENT_TRUST_POLICY_ORCHESTRATOR_TOKEN_FILE",
            "AGENT_TRUST_POLICY_BUNDLE_SIGNING_PRIVATE_KEY_FILE",
            "containerPort: 8090",
            "containerPort: 9101",
            'policy-admin-endpoint: "https://agenttrust-policy-admin"',
            'policy-admin-readiness-schema: "agenttrust.policy-admin-readiness.v1"',
        ):
            self.assertIn(required, rendered)
        spc = rendered.split("name: agenttrust-policy-admin", 1)[1].split("---", 1)[0]
        self.assertEqual(spc.count("objectName:"), 15)
        policy = rendered.split(
            "name: agenttrust-policy-admin-network", 1
        )[1].split("---", 1)[0]
        for required in (
            "component: enterprise-api", "component: tool-proxy",
            'cidr: "10.1.0.0/16"', 'cidr: "10.2.0.0/24"',
            "component: orchestrator-api", "port: 8090", "port: 9101",
        ):
            self.assertIn(required, policy)
        unsafe = values()
        unsafe["policy_admin"]["client_identities"] = [
            "URI:spiffe://prod.test/unbound-caller"
        ]
        with self.assertRaisesRegex(
            RENDER.RenderError, "POLICY_ADMIN_CLIENT_IDENTITIES_NOT_EXACT"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_policy_admin_image_build_is_selective_and_immutable(self) -> None:
        digest = "registry.test/base@sha256:" + "b" * 64
        command = BUILD.command_for(
            "policy-admin", "registry.test/agenttrust/policy-admin:v1",
            [digest, digest], ROOT,
        )
        self.assertIn(str(ROOT / "Dockerfile.policy-admin"), command)
        self.assertIn("RUST_BUILDER_IMAGE=" + digest, command)
        self.assertIn("RUNTIME_BASE_IMAGE=" + digest, command)

    def test_incident_release_authority_is_isolated_fenced_and_fail_closed(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "name: agenttrust-incident-release",
            'image: "registry.test/agenttrust/incident_release@sha256:' + "a" * 64 + '"',
            "AGENT_TRUST_INCIDENT_DATABASE_EXPECTED_ROLE",
            "AGENT_TRUST_INCIDENT_TOKEN_BINDINGS_FILE",
            "AGENT_TRUST_INCIDENT_HUMAN_PRINCIPAL_KEYRING_FILE",
            "AGENT_TRUST_INCIDENT_ORCHESTRATOR_TOKEN_FILE",
            "AGENT_TRUST_INCIDENT_CONTAINMENT_TOKEN_FILE",
            "AGENT_TRUST_INCIDENT_REPLAY_TOKEN_FILE",
            "AGENT_TRUST_INCIDENT_RELEASE_SIGNING_KEY_FILE",
            "containerPort: 8090",
            "containerPort: 9101",
            'incident-endpoint: "https://agenttrust-incident-release"',
            'incident-readiness-schema: "agenttrust.incident-release-readiness.v1"',
        ):
            self.assertIn(required, rendered)
        spc = rendered.split("name: agenttrust-incident-release", 1)[1].split("---", 1)[0]
        self.assertEqual(spc.count("objectName:"), 15)
        policy = rendered.split(
            "name: agenttrust-incident-release-network", 1
        )[1].split("---", 1)[0]
        for required in (
            "component: enterprise-api", "component: tool-proxy",
            'cidr: "10.1.0.0/16"', 'cidr: "10.2.0.0/24"',
            'cidr: "10.7.0.0/24"', "component: orchestrator-api",
            "port: 8090", "port: 9101",
        ):
            self.assertIn(required, policy)
        unsafe = values()
        unsafe["incident_release"]["client_identities"] = [
            unsafe["enterprise"]["approval_client_identity"],
            unsafe["incident_release"]["detection_client_identity"],
        ]
        with self.assertRaisesRegex(
            RENDER.RenderError, "INCIDENT_RELEASE_CLIENT_IDENTITIES_NOT_EXACT"
        ):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["incident_release"]["replay_endpoint"] = unsafe["incident_release"][
            "containment_endpoint"
        ]
        with self.assertRaisesRegex(
            RENDER.RenderError, "INCIDENT_RELEASE_EFFECT_ENDPOINTS_NOT_DISTINCT"
        ):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["incident_release"]["outbound_client_identity"] = unsafe[
            "authorities"
        ]["pep"]["outbound_client_identity"]
        unsafe["enterprise"]["orchestrator_bff_client_identities"][3] = unsafe[
            "authorities"
        ]["pep"]["outbound_client_identity"]
        with self.assertRaisesRegex(
            RENDER.RenderError, "WORKLOAD_IDENTITIES_NOT_DISTINCT"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_pack_marketplace_authority_is_isolated_fenced_and_fail_closed(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "name: agenttrust-pack-marketplace",
            'image: "registry.test/agenttrust/pack_marketplace@sha256:' + "a" * 64 + '"',
            "AGENT_TRUST_MARKETPLACE_DATABASE_EXPECTED_ROLE",
            "AGENT_TRUST_MARKETPLACE_TOKEN_BINDINGS_FILE",
            "AGENT_TRUST_MARKETPLACE_ORCHESTRATOR_TOKEN_FILE",
            "AGENT_TRUST_MARKETPLACE_RELEASE_GATE_KEYRING_FILE",
            "AGENT_TRUST_MARKETPLACE_INGRESS_SUBJECT",
            "AGENT_TRUST_MARKETPLACE_EXECUTOR_SUBJECT",
            "AGENT_TRUST_MARKETPLACE_QUERY_SUBJECT",
            'pack-marketplace-endpoint: "https://agenttrust-pack-marketplace"',
            'pack-marketplace-readiness-schema: "agenttrust.pack-marketplace-readiness.v1"',
        ):
            self.assertIn(required, rendered)
        spc = rendered.split("name: agenttrust-pack-marketplace", 1)[1].split("---", 1)[0]
        self.assertEqual(spc.count("objectName:"), 13)
        policy = rendered.split(
            "name: agenttrust-pack-marketplace-network", 1
        )[1].split("---", 1)[0]
        for required in (
            "component: enterprise-api", "component: tool-proxy",
            'cidr: "10.1.0.0/16"', 'cidr: "10.2.0.0/24"',
            'cidr: "10.7.0.0/24"', "component: orchestrator-api",
            "port: 8090", "port: 9101",
        ):
            self.assertIn(required, policy)
        unsafe = values()
        unsafe["pack_marketplace"]["executor_subject"] = (
            unsafe["enterprise"]["approval_client_identity"]
        )
        with self.assertRaisesRegex(
            RENDER.RenderError, "PACK_MARKETPLACE_EXECUTOR_SUBJECT_MISMATCH"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_incident_and_marketplace_images_are_selective_and_immutable(self) -> None:
        digest = "registry.test/base@sha256:" + "b" * 64
        for component, dockerfile in (
            ("incident-release", "Dockerfile.incident-release"),
            ("pack-marketplace", "Dockerfile.pack-marketplace"),
        ):
            command = BUILD.command_for(
                component, f"registry.test/agenttrust/{component}:v1",
                [digest, digest], ROOT,
            )
            self.assertIn(str(ROOT / dockerfile), command)
            self.assertIn("RUST_BUILDER_IMAGE=" + digest, command)
            self.assertIn("RUNTIME_BASE_IMAGE=" + digest, command)

    def test_incident_and_marketplace_contracts_are_fully_wired(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        for forbidden in (
            "AGENT_TRUST_TOOL_PROXY_POLICY_EXECUTE_TOKEN_FILE",
            "AGENT_TRUST_TOOL_PROXY_INCIDENT_EXECUTE_TOKEN_FILE",
            "AGENT_TRUST_TOOL_PROXY_PACK_MARKETPLACE_EXECUTE_TOKEN_FILE",
            'objectName: "policy-execute.token"',
            'objectName: "incident-execute.token"',
            'objectName: "pack-marketplace-execute.token"',
        ):
            self.assertNotIn(forbidden, template)
        sources = (
            ROOT / "rust/crates/incident-release-gate/src/bin/agenttrust-incident-release-authority.rs",
            ROOT / "rust/crates/pack-marketplace/src/bin/agenttrust-pack-marketplace-service.rs",
        )
        for source in sources:
            env_names = set(re.findall(r"AGENT_TRUST_[A-Z0-9_]+", source.read_text()))
            self.assertTrue(env_names)
            for env_name in env_names:
                self.assertIn(env_name, template)
        tool_proxy = (
            ROOT / "rust/crates/tool-proxy/src/bin/agenttrust-tool-proxy-service.rs"
        ).read_text()
        for required in (
            '"policy-administration-executor"', '"policy-administration-authority"',
            '"incident-release-executor"', '"incident-release-authority"',
            '"pack-marketplace-executor"', '"pack-marketplace-authority"',
            '"/v1/policies/executions"', '"/v1/incidents/executions"',
            '"/v1/packs/executions"',
        ):
            self.assertIn(required, tool_proxy)
        incident_openapi = (
            ROOT / "schemas/openapi/incident-release-authority.openapi.yaml"
        ).read_text()
        pack_openapi = (ROOT / "schemas/openapi/pack-marketplace-v1.yaml").read_text()
        for route in (
            "/v1/incidents/detections", "/v1/incidents/actions",
            "/v1/incidents/executions", "/v1/authoritative/incidents",
        ):
            self.assertIn(route, incident_openapi)
        for route in (
            "/v1/packs/actions", "/v1/packs/executions", "/v1/authoritative/packs",
        ):
            self.assertIn(route, pack_openapi)
        runbook = (ROOT / "docs/platform/production-deployment-runbook.md").read_text()
        for command in (
            "ONBOARD_PUBLISHER", "VERIFY_PUBLISHER_KEY", "SET_PUBLISHER_TRUST",
            "CONFIGURE_TENANT_CATALOG", "SUBMIT_RELEASE", "REVIEW_RELEASE",
            "REQUEST_INSTALLATION", "APPROVE_INSTALLATION", "INSTALL", "ACTIVATE",
            "PLAN_UPGRADE", "RECORD_CANARY", "UPGRADE", "ROLLBACK", "DEACTIVATE",
            "REVOKE_RELEASE",
        ):
            self.assertIn(f"`{command}`", runbook)
        for section, expected, error in (
            ("policy_admin", "policy-administration-executor", "POLICY_ADMIN_EXECUTOR_PROFILE_INVALID"),
            ("incident_release", "incident-release-executor", "INCIDENT_RELEASE_EXECUTOR_PROFILE_INVALID"),
            ("pack_marketplace", "pack-marketplace-executor", "PACK_MARKETPLACE_EXECUTOR_PROFILE_INVALID"),
        ):
            unsafe = values()
            unsafe[section]["executor_credential_profile"] = expected + "-wrong"
            with self.subTest(section=section), self.assertRaisesRegex(
                RENDER.RenderError, error
            ):
                RENDER.render("", unsafe, runtime_config())

    def test_enterprise_authority_is_separate_from_bff_and_fail_closed(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        rendered = RENDER.render(template, values(), runtime_config())
        for required in (
            "name: agenttrust-enterprise-authority",
            'image: "registry.test/agenttrust/enterprise_authority@sha256:' + "a" * 64 + '"',
            "AGENT_TRUST_ENTERPRISE_DATABASE_EXPECTED_ROLE",
            "AGENT_TRUST_ENTERPRISE_TOKEN_BINDINGS_FILE",
            "AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE",
            "AGENT_TRUST_ENTERPRISE_ORCHESTRATOR_TOKEN_FILE",
            "AGENT_TRUST_ENTERPRISE_VAULT_TOKEN_FILE",
            "AGENT_TRUST_ENTERPRISE_API_KEY_PEPPER_FILE",
            "containerPort: 8449",
            "containerPort: 9100",
            'enterprise-authority-readiness-schema: "agenttrust.enterprise-authority-readiness.v1"',
        ):
            self.assertIn(required, rendered)
        spc = rendered.split("name: agenttrust-enterprise-authority", 1)[1].split("---", 1)[0]
        self.assertEqual(spc.count("objectName:"), 14)
        policy = rendered.split(
            "name: agenttrust-enterprise-authority-network", 1
        )[1].split("---", 1)[0]
        for required in (
            "component: enterprise-api", "component: tool-proxy",
            "component: orchestrator-api", 'cidr: "10.2.0.0/24"',
            'cidr: "10.4.0.0/24"', "port: 8449", "port: 9100",
        ):
            self.assertIn(required, policy)
        unsafe = values()
        unsafe["enterprise_authority"]["service_subject"] = "service:wrong"
        with self.assertRaisesRegex(
            RENDER.RenderError, "ENTERPRISE_AUTHORITY_SERVICE_SUBJECT_MISMATCH"
        ):
            RENDER.render("", unsafe, runtime_config())

    def test_service_and_target_ports_are_both_peer_scoped(self) -> None:
        rendered = RENDER.render(
            (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(),
            values(),
            runtime_config(),
        )
        self.assertGreaterEqual(
            rendered.count(
                "ports: [{protocol: TCP, port: 443}, {protocol: TCP, port: 8081}]"
            ),
            2,
        )
        self.assertGreaterEqual(
            rendered.count(
                "ports: [{protocol: TCP, port: 443}, {protocol: TCP, port: 8082}]"
            ),
            2,
        )

    def test_migration_manifest_has_exact_sql_set(self) -> None:
        manifest = (ROOT / "migrations/manifest.txt").read_text().splitlines()
        entries = {line for line in manifest if line and not line.startswith("#")}
        discovered = {path.relative_to(ROOT / "migrations").as_posix() for path in (ROOT / "migrations").rglob("*.sql")}
        self.assertEqual(entries, discovered)
        self.assertIn("transaction-ledger/0003_transaction_ledger_inbox_tenant.sql", entries)

    def test_console_build_binds_api_and_agui_trust_key(self) -> None:
        digest = "registry.test/base@sha256:" + "b" * 64
        command = BUILD.command_for(
            "console", "registry.test/agenttrust/console:v1", [digest, digest], ROOT,
            control_api_url="https://api.prod.test",
            agui_verify_key="A" * 43,
        )
        self.assertIn("VITE_CONTROL_API_URL=https://api.prod.test", command)
        self.assertIn("VITE_AGUI_VERIFY_KEY=" + "A" * 43, command)

    def test_console_build_rejects_missing_agui_trust_key(self) -> None:
        digest = "registry.test/base@sha256:" + "b" * 64
        with self.assertRaisesRegex(BUILD.BuildConfigurationError, "COMPONENT_INVALID"):
            BUILD.command_for(
                "console", "registry.test/agenttrust/console:v1", [digest, digest], ROOT,
                control_api_url="https://api.prod.test",
            )

    def test_authority_image_components_have_dedicated_dockerfiles(self) -> None:
        digest = "registry.test/base@sha256:" + "b" * 64
        for component, dockerfile in (
            ("approval", "Dockerfile.approval"),
            ("pep", "Dockerfile.pep"),
            ("identity", "Dockerfile.identity"),
            ("tool-proxy", "Dockerfile.tool-proxy"),
            ("evidence", "Dockerfile.evidence"),
            ("audit", "Dockerfile.audit-retention"),
            ("agent-registry", "Dockerfile.agent-registry"),
            ("enterprise-authority", "Dockerfile.enterprise-authority"),
            ("context-governance", "Dockerfile.context-governance"),
            ("security-evaluation", "Dockerfile.security-evaluation"),
            ("platform-sre", "Dockerfile.platform-sre"),
            ("runtime-anomaly", "Dockerfile.runtime-anomaly"),
        ):
            command = BUILD.command_for(
                component,
                f"registry.test/agenttrust/{component}:v1",
                [digest, digest],
                ROOT,
            )
            self.assertIn(str(ROOT / dockerfile), command)

    def test_new_authority_images_publish_exact_data_and_management_ports(self) -> None:
        for dockerfile_name, ports in (
            ("Dockerfile.model-gateway", "EXPOSE 8091 9101"),
            ("Dockerfile.data-governance", "EXPOSE 8092 9102"),
            ("Dockerfile.context-governance", "EXPOSE 8095 9105"),
            ("Dockerfile.runtime-anomaly", "EXPOSE 8094 9104"),
            ("Dockerfile.security-evaluation", "EXPOSE 8096 9106"),
            ("Dockerfile.pack-supply-chain", "EXPOSE 8093 9103"),
            ("Dockerfile.domain-runtime", "EXPOSE 8094 9104"),
            ("Dockerfile.platform-sre", "EXPOSE 8097 9107"),
        ):
            self.assertIn(ports, (ROOT / dockerfile_name).read_text())

    def test_build_context_excludes_host_outputs_and_credentials(self) -> None:
        ignored = (ROOT / ".dockerignore").read_text().splitlines()
        for required in (
            ".git", "target", "**/target", "**/node_modules", "evidence",
            "*.pem", "*.key", "*.p12", ".env", ".env.*",
        ):
            self.assertIn(required, ignored)
        for dockerfile_name in (
            "Dockerfile.transition", "Dockerfile.production-runtime", "Dockerfile.execution",
            "Dockerfile.registry", "Dockerfile.audit-retention",
            "Dockerfile.agent-registry", "Dockerfile.enterprise-authority",
            "Dockerfile.context-governance", "Dockerfile.security-evaluation",
            "Dockerfile.platform-sre", "Dockerfile.runtime-anomaly",
        ):
            dockerfile = (ROOT / dockerfile_name).read_text()
            self.assertNotIn("COPY . .", dockerfile)
            self.assertIn("COPY rust ./rust", dockerfile)

    def test_migration_runner_pins_search_path_and_hides_uri_from_argv(self) -> None:
        runner = (ROOT / "scripts/run-production-migrations.sh").read_text()
        self.assertLess(runner.index("unset PGPASSWORD"), runner.index('mode="${1:---apply}"'))
        self.assertIn("SET search_path = public", runner)
        self.assertIn("current_schemas(true)", runner)
        self.assertIn("FROM pg_catalog.pg_stat_ssl AS transport", runner)
        self.assertIn("MIGRATION_TLS_VERSION_INVALID", runner)
        self.assertIn("MIGRATION_PSQL_CLIENT_UNSUPPORTED", runner)
        self.assertIn('sslmode_summary', runner)
        self.assertIn('sslrootcert_summary', runner)
        self.assertIn('AGENT_TRUST_DATABASE_CA_FILE', runner)
        self.assertIn('AGENT_TRUST_DATABASE_PASSWORD_FILE', runner)
        self.assertIn('MIGRATION_DATABASE_TLS_ROOT_CERT_REQUIRED', runner)
        self.assertIn('export PGHOST="$database_host"', runner)
        self.assertIn('export PGPORT="$database_port"', runner)
        self.assertIn('export PGUSER="$database_user"', runner)
        self.assertIn('export PGDATABASE="$database_name"', runner)
        self.assertIn('export PGPASSFILE="$pgpass_file"', runner)
        self.assertIn('export PGSSLMINPROTOCOLVERSION=TLSv1.3', runner)
        self.assertIn('export PGCHANNELBINDING=require', runner)
        self.assertIn('export PGGSSENCMODE=disable', runner)
        self.assertIn('export PGCLIENTENCODING=UTF8', runner)
        self.assertIn('unset PGPASSWORD', runner)
        self.assertNotIn('PGDATABASE="$database_url"', runner)
        self.assertNotIn('psql "$database_url"', runner)
        self.assertIn("ENTERPRISE_APPLICATION_ROLE", runner)
        self.assertIn("ENTERPRISE_AUTHORITY_APPLICATION_ROLE", runner)
        self.assertIn("ORCHESTRATOR_APPLICATION_ROLE", runner)
        self.assertIn("EXECUTION_APPLICATION_ROLE", runner)
        self.assertIn("REGISTRY_APPLICATION_ROLE", runner)
        self.assertIn("AGENT_REGISTRY_APPLICATION_ROLE", runner)
        self.assertIn("POLICY_ADMIN_APPLICATION_ROLE", runner)
        self.assertIn("INCIDENT_RELEASE_APPLICATION_ROLE", runner)
        self.assertIn("PACK_MARKETPLACE_APPLICATION_ROLE", runner)
        self.assertIn("registry_publisher_keys", runner)
        self.assertIn("registry_snapshots", runner)
        self.assertIn("registry_idempotency_records", runner)
        self.assertIn("executor_profiles", runner)
        self.assertIn("credential_profiles", runner)
        self.assertIn("approval_profiles", runner)
        self.assertIn("execution_fence_seq", runner)
        self.assertIn("GRANT SELECT, INSERT ON TABLE public.execution_outbox", runner)
        for privilege_check in (
            "'public.executions', 'INSERT'",
            "'public.executions', 'UPDATE'",
            "'public.execution_outbox', 'SELECT'",
            "'public.execution_outbox', 'INSERT'",
        ):
            self.assertIn(privilege_check, runner)
        self.assertNotIn("'public.executions', 'INSERT,UPDATE'", runner)
        self.assertNotIn("'public.execution_outbox', 'SELECT,INSERT'", runner)
        self.assertIn("REVOKE ALL ON public.agenttrust_schema_migrations", runner)
        self.assertIn("MIGRATION_ENTERPRISE_AUTHORITY_EXCESS_COLUMN_UPDATE_GRANT", runner)
        self.assertIn("MIGRATION_AGENT_REGISTRY_GRANTS_INVALID", runner)
        self.assertIn("MIGRATION_INCIDENT_RELEASE_EXCESS_COLUMN_UPDATE_GRANT", runner)
        self.assertIn("MIGRATION_PACK_MARKETPLACE_EXCESS_COLUMN_UPDATE_GRANT", runner)
        self.assertIn("MIGRATION_INCIDENT_RELEASE_LEGACY_GATE_GRANT", runner)
        self.assertIn("MIGRATION_PEP_EXCESS_COLUMN_UPDATE_GRANT", runner)
        self.assertIn("MIGRATION_PEP_ACTIVATION_UPDATE_MISSING", runner)
        self.assertIn("MIGRATION_PEP_ACTIVE_BUNDLE_UPDATE_MISSING", runner)
        for activation_column in (
            "pdp_ack_digest",
            "pdp_ack_body",
            "response_digest",
            "response_body",
        ):
            self.assertIn(activation_column, runner)
        self.assertIn("policy_activation_intents", runner)
        self.assertIn("pep_policy_activation_requests", runner)
        self.assertIn("pep_active_policy_bundles", runner)
        self.assertIn("audit_human_assertion_uses", runner)

    def test_migration_runner_commits_body_and_history_atomically(self) -> None:
        runner = (ROOT / "scripts/run-production-migrations.sh").read_text()
        self.assertIn("append_atomic_migration_body", runner)
        self.assertIn("MIGRATION_TRANSACTION_BOUNDARY_INVALID", runner)
        self.assertIn(
            '\\else\nBEGIN;\nSQL\n    append_atomic_migration_body "$migration_snapshot" "$relative" "$sql_file"',
            runner,
        )
        self.assertIn(
            "VALUES ('$relative', '$digest', '$release_id');\nCOMMIT;\n\\endif",
            runner,
        )
        self.assertNotIn("\\i '$migration'", runner)
        self.assertNotIn("ON CONFLICT (migration_path) DO NOTHING", runner)
        self.assertIn('chmod 0400 "$migration_snapshot"', runner)
        self.assertIn('digest_file "$migration_snapshot"', runner)
        self.assertIn("MIGRATION_DIGEST_INVALID", runner)
        self.assertNotIn('digest_file "$migration"', runner)
        self.assertIn(
            'if [ "$mode" = "--apply" ]; then\n  printf \'%s\\n\' \'COMMIT;\'',
            runner,
        )

    def test_ci_dependencies_are_immutable_and_opa_is_checksum_pinned(self) -> None:
        expected_actions = {
            ("actions/checkout", "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"),
            ("actions/setup-java", "b6effb05e454b25005698d916606bdc6ffcbf961"),
            ("actions/setup-node", "a0853c24544627f65ddf259abe73b1d18a591444"),
            ("actions/setup-python", "ece7cb06caefa5fff74198d8649806c4678c61a1"),
            ("actions/upload-artifact", "ea165f8d65b6e75b540449e92b4886f43607fa02"),
            ("dtolnay/rust-toolchain", "4360b52568e2003a75bf9bc1d59f33a8e3fc893c"),
        }
        observed_actions: set[tuple[str, str]] = set()
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            workflow = path.read_text(encoding="utf-8")
            for action, revision in re.findall(
                r"uses:\s*([^@\s]+)@([0-9A-Za-z._-]+)", workflow
            ):
                self.assertRegex(revision, r"^[0-9a-f]{40}$", msg=str(path))
                observed_actions.add((action, revision))
        self.assertEqual(observed_actions, expected_actions)

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        linux_workflow = (ROOT / ".github/workflows/linux-isolation.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("permissions:\n  contents: read", linux_workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 3)
        self.assertEqual(linux_workflow.count("persist-credentials: false"), 1)
        self.assertIn("actions-runner-2-327-1", linux_workflow)
        self.assertIn('node-version: "24.19.0"', workflow)
        self.assertIn('test "$(node --version)" = "v24.19.0"', workflow)
        self.assertIn('test "$(npm --version)" = "11.17.0"', workflow)
        self.assertIn('readonly opa_version="1.19.0"', workflow)
        self.assertIn(
            'readonly expected_sha256="1dd5c5591ff856f5e20a1d66bafae9511ddf3c5552ed3b5070c70b2b6580ee3f"',
            workflow,
        )
        self.assertIn("github.com/open-policy-agent/opa/releases/download", workflow)
        self.assertIn("openpolicyagent.org/downloads", workflow)
        self.assertIn("--retry-all-errors", workflow)
        self.assertIn("sha256sum --check --strict", workflow)
        self.assertIn('stop_token="$(openssl rand -hex 32)"', workflow)
        self.assertIn('echo "::stop-commands::${stop_token}"', workflow)
        self.assertIn('echo "::${stop_token}::"', workflow)

    def test_ci_executes_tls_runner_replay_and_atomic_failure_probe(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("Enable verify-full TLS on the PostgreSQL service", workflow)
        self.assertIn("POSTGRES_HOST_AUTH_METHOD: scram-sha-256", workflow)
        self.assertIn("ssl_min_protocol_version='TLSv1.3'", workflow)
        self.assertIn('test "$tls_verified" = true:TLSv1.3', workflow)
        self.assertIn("sslmode=verify-full&sslrootcert=%s", workflow)
        self.assertIn("Bootstrap least-privilege migration and application roles", workflow)
        self.assertIn("Prove migration body and history rollback together", workflow)
        self.assertIn("CI_FORCED_HISTORY_FAILURE", workflow)
        self.assertIn("to_regclass('public.trust_bundles') IS NULL", workflow)
        self.assertIn("agenttrust-atomic-manifest.txt", workflow)
        self.assertIn("runner failed before the forced history fault was observed", workflow)
        self.assertIn("GRANT EXECUTE ON FUNCTION public.reject_first_migration_history()", workflow)
        standalone_replay = workflow.split(
            "- name: Replay every standalone migration after the runner",
            maxsplit=1,
        )[1].split(
            "- name: Recheck production migration history after standalone replay",
            maxsplit=1,
        )[0]
        self.assertIn(
            "PGHOST=localhost PGPORT=5432 PGUSER=agenttrust_migration_ci",
            standalone_replay,
        )
        self.assertIn("PGDATABASE=agenttrust PGSSLMODE=verify-full", standalone_replay)
        self.assertIn(
            "PGSSLMINPROTOCOLVERSION=TLSv1.3 PGCHANNELBINDING=require",
            standalone_replay,
        )
        self.assertIn("PGGSSENCMODE=disable PGCLIENTENCODING=UTF8", standalone_replay)
        self.assertIn("PGPASSWORD=agenttrust-ci-migration-password", standalone_replay)
        self.assertNotIn("\n        env:", standalone_replay)
        self.assertNotIn("-U postgres", standalone_replay)
        self.assertNotIn('PGDATABASE="$database_url"', standalone_replay)
        self.assertIn("AGENT_TRUST_DATABASE_PASSWORD_FILE", workflow)
        self.assertGreaterEqual(
            workflow.count("run-production-migrations.sh --apply"),
            3,
        )
        self.assertGreaterEqual(
            workflow.count("run-production-migrations.sh --check"),
            2,
        )

    def test_application_database_tls_identity_verification_is_required(self) -> None:
        java = (
            ROOT
            / "java/enterprise-control-api/src/main/java/com/agenttrust/control/DatabaseSecurityVerifier.java"
        ).read_text()
        for required in (
            '"verify-full".equals(parameters.get("sslmode"))',
            'parameters.get("sslrootcert")',
            'parameters.containsKey("sslfactory")',
            'parameters.containsKey("sslhostnameverifier")',
            '"-csearch_path=pg_catalog,public".equals(parameters.get("options"))',
            'current_setting(\'search_path\')',
            '"{pg_catalog,public}".equals(posture.resolvedSchemas())',
            "root.isAbsolute()",
        ):
            self.assertIn(required, java)
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        self.assertIn('objectName: "database-ca.pem"', template)

    def test_orchestrator_and_worker_readiness_cover_critical_dependencies(self) -> None:
        orchestrator = (ROOT / "python/durable_worker/orchestrator_api.py").read_text()
        worker = (ROOT / "python/durable_worker/worker.py").read_text()
        for source in (orchestrator, worker):
            for required in (
                "GetSystemInfoRequest",
                "AGENT_TRUST_TRANSITION_ENDPOINT",
                "AGENT_TRUST_EXECUTION_ENDPOINT",
                '"/ready"',
            ):
                self.assertIn(required, source)
        for required in (
            "agenttrust.transition-readiness.v1",
            "agenttrust.execution-readiness.v1",
        ):
            self.assertIn(required, worker)
        for required in (
            'normalized_database_options.get("options") != ["-csearch_path=pg_catalog,public"]',
            'role["search_path"] != "pg_catalog, public"',
            'role["resolved_schemas"] != "{pg_catalog,public}"',
        ):
            self.assertIn(required, orchestrator)
        self.assertIn("asyncio.wait_for", worker)
        self.assertIn("asyncio.wait_for", orchestrator)
        for required in ('"--management-listen"', '"--management-port"'):
            self.assertIn(required, worker)
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        self.assertIn("containerPort: 9092", template)
        self.assertIn("ports: [{protocol: TCP, port: 9092}]", template)

    def test_enterprise_readiness_includes_security_and_authority_dependencies(self) -> None:
        application = (
            ROOT / "java/enterprise-control-api/src/main/resources/application.yml"
        ).read_text()
        self.assertIn("readinessState,db,pep,jwks,authorities", application)
        readiness_source = "\n".join(
            path.read_text()
            for path in (ROOT / "java/enterprise-control-api/src/main/java").rglob("*.java")
        )
        for dependency in ('@Bean(name = "pep")', '@Bean(name = "jwks")', '@Bean(name = "authorities")'):
            self.assertIn(dependency, readiness_source)
        # IAM is intentionally explicit so OAuth token, user-info and JWKS all share the
        # rotating enterprise mTLS client instead of Spring's system-trust auto discovery.
        for dependency in (
            "class IamSecurityConfiguration", "JwtDecoder jwtDecoder(",
            "NimbusJwtDecoder.withJwkSetUri", "clients.rotatingRequestFactory()",
        ):
            self.assertIn(dependency, readiness_source)

    def test_orchestrator_image_uses_the_worker_lock_and_import_smoke(self) -> None:
        dockerfile = (ROOT / "Dockerfile.orchestrator").read_text()
        self.assertIn("python/durable_worker/requirements.production.txt", dockerfile)
        for module in ("aiohttp", "asyncpg", "cryptography", "temporalio"):
            self.assertIn(module, dockerfile)
        self.assertNotIn("COPY requirements-production.txt", dockerfile)

    def test_approval_v2_uses_atomic_rollout_and_public_review_keyring(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        approval = template.split(
            "kind: Deployment\nmetadata:\n  name: agenttrust-approval", 1
        )[1].split("---", 1)[0]
        self.assertIn("strategy: {type: Recreate}", approval)
        self.assertNotIn("type: RollingUpdate", approval)
        for required in (
            'objectName: "review-evidence-keys.json"',
            "AGENT_TRUST_APPROVAL_REVIEW_EVIDENCE_KEYRING_FILE",
            "/var/run/agenttrust/secrets/approval/review-evidence-keys.json",
        ):
            self.assertIn(required, template)
        migration = (
            ROOT
            / "migrations/enterprise-approval/0036_01_25_approval_review_evidence_v2.sql"
        ).read_text()
        self.assertIn("APPROVAL_V2_LEGACY_MUTABLE_STATE_MUST_BE_DRAINED", migration)
        self.assertIn("approval_cases_review_evidence_v2_check", migration)

    def test_approval_decision_evidence_publisher_identity_is_fail_closed(self) -> None:
        candidate = values()
        source_identity = candidate["authorities"]["approval"][
            "evidence_source_identity"
        ]
        rendered = RENDER.render(
            (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(),
            candidate,
            runtime_config(),
        )
        self.assertIn(
            f'AGENT_TRUST_APPROVAL_EVIDENCE_SOURCE_IDENTITY, value: "{source_identity}"',
            rendered,
        )
        self.assertNotIn("@@APPROVAL_EVIDENCE_SOURCE_IDENTITY@@", rendered)

        missing = values()
        del missing["authorities"]["approval"]["evidence_source_identity"]
        with self.assertRaisesRegex(
            RENDER.RenderError, "PRODUCTION_STACK_APPROVAL_AUTHORITY_INVALID"
        ):
            RENDER.render("", missing, runtime_config())

        untrusted = values()
        untrusted["authorities"]["approval"]["evidence_source_identity"] = (
            "URI:spiffe://prod.test/untrusted-approval"
        )
        with self.assertRaisesRegex(
            RENDER.RenderError, "PRODUCTION_STACK_APPROVAL_EVIDENCE_IDENTITY_MISSING"
        ):
            RENDER.render("", untrusted, runtime_config())

        collision = values()
        collision["authorities"]["approval"]["evidence_source_identity"] = collision[
            "execution"
        ]["outbound_client_identity"]
        with self.assertRaisesRegex(
            RENDER.RenderError, "PRODUCTION_STACK_WORKLOAD_IDENTITIES_NOT_DISTINCT"
        ):
            RENDER.render("", collision, runtime_config())

    def test_enterprise_bff_pins_the_approval_authority_public_key(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        enterprise_secrets = template.split(
            "kind: SecretProviderClass\nmetadata:\n  name: agenttrust-enterprise-control",
            1,
        )[1].split("---", 1)[0]
        self.assertIn(
            'objectName: "approval-authority-verification-keyring.json"',
            enterprise_secrets,
        )
        self.assertIn(
            'secretKey: "approval_authority_verification_keyring"',
            enterprise_secrets,
        )
        self.assertIn("filePermission: 0o440", enterprise_secrets)
        for required in (
            "AGENT_TRUST_APPROVAL_AUTHORITY_VERIFICATION_KEYRING_FILE",
            "/var/run/agenttrust/secrets/enterprise/approval-authority-verification-keyring.json",
        ):
            self.assertIn(required, template)


if __name__ == "__main__":
    unittest.main()
