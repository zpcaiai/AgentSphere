from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


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
    return {
        "schema_version": "agenttrust.production-stack-values.v1",
        "release_id": "v1.2.3",
        "release_digest": digest,
        "images": {key: f"registry.test/agenttrust/{key}@sha256:{digest}" for key in RENDER.IMAGE_KEYS},
        "database": {
            "enterprise_application_role": "agenttrust_enterprise_app",
            "orchestrator_application_role": "agenttrust_orchestrator_app",
            "execution_application_role": "agenttrust_execution_app",
        },
        "execution": {
            "client_identities": ["URI:spiffe://prod.test/temporal-worker"],
            "approval_endpoint": "https://approval.prod.test/",
            "approval_readiness_schema": "agenttrust.enterprise-approval-readiness.v1",
            "pep_endpoint": "https://pep.prod.test/",
            "pep_readiness_schema": "agenttrust.policy-pep-readiness.v1",
            "tool_endpoint": "https://tool-proxy.prod.test/",
            "tool_readiness_schema": "agenttrust.tool-proxy-readiness.v1",
            "evidence_endpoint": "https://evidence.prod.test/",
            "evidence_readiness_schema": "agenttrust.evidence-readiness.v1",
        },
        "transition": {
            "client_identities": ["URI:spiffe://prod.test/temporal-worker"]
        },
        "temporal": {"address": "temporal.prod.test:7233", "namespace": "agenttrust", "task_queue": "agenttrust-production", "server_name": "temporal.prod.test"},
        "vault": {"address": "https://vault.prod.test", **{key: "kv/data/agenttrust" if key.endswith("_path") else "agenttrust-role" for key in RENDER.VAULT_KEYS - {"address"}}},
        "network": {"node_cidr": "10.1.0.0/16", "database_cidr": "10.2.0.0/24", "temporal_cidr": "10.3.0.0/24", "trusted_service_cidr": "10.4.0.0/16", "execution_pep_cidr": "10.5.0.0/24", "execution_tool_cidr": "10.6.0.0/24", "execution_evidence_cidr": "10.7.0.0/24", "execution_approval_cidr": "10.8.0.0/24", "dns_cidr": "169.254.20.10/32"},
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
            "pep_endpoint": "https://pep.prod.test",
            "orchestrator_runtime_client_identities": [
                "URI:spiffe://prod.test/production-runtime"
            ],
            "orchestrator_bff_client_identities": [
                "URI:spiffe://prod.test/enterprise-control"
            ],
            "authority_endpoints": {
                key: "https://authority.prod.test" for key in RENDER.AUTHORITY_KEYS
            },
        },
    }


class ProductionDeploymentTests(unittest.TestCase):
    def test_complete_stack_renders_without_tokens(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        result = RENDER.render(template, values(), runtime_config())
        self.assertNotIn("@@", result)
        self.assertIn("kind: Job", result)
        self.assertEqual(result.count("kind: Deployment"), 7)
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
        self.assertIn('objectName: "database-ca.pem"', result)
        self.assertIn('secretKey: "database_ca"', result)
        self.assertIn(
            "AGENT_TRUST_DATABASE_CA_FILE, value: /var/run/agenttrust/secrets/database-ca.pem",
            result,
        )
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
        self.assertIn("name: agenttrust-execution-network", result)
        self.assertIn("containerPort: 8083", result)
        self.assertIn("containerPort: 9093", result)
        self.assertIn(
            'from: [{ipBlock: {cidr: "10.1.0.0/16"}}]\n'
            "      ports: [{protocol: TCP, port: 9093}]",
            result,
        )
        for cidr in ("10.5.0.0/24", "10.6.0.0/24", "10.7.0.0/24", "10.8.0.0/24"):
            self.assertIn(f'ipBlock: {{cidr: "{cidr}"}}', result)
        # The two callers share their caller-side Vault object, but transition authenticates
        # against per-SAN/tenant/scope digests and must not mount a server-global raw token.
        self.assertEqual(result.count("AGENT_TRUST_TRANSITION_TOKEN_FILE"), 2)
        self.assertIn(
            'objectName: "transition.token", secretPath: "kv/data/agenttrust", '
            'secretKey: "transition_token", filePermission: 0o440',
            result,
        )
        self.assertNotIn(
            "/var/run/agenttrust/secrets/transition/transition.token", result
        )
        self.assertIn('ipBlock: {cidr: "169.254.20.10/32"}', result)
        self.assertIn("{protocol: UDP, port: 53}", result)
        self.assertIn("{protocol: TCP, port: 53}", result)

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

    def test_execution_network_dependencies_must_be_distinct(self) -> None:
        unsafe = values()
        unsafe["network"]["execution_tool_cidr"] = unsafe["network"][
            "execution_pep_cidr"
        ]
        with self.assertRaisesRegex(RENDER.RenderError, "NETWORK_CIDRS_OVERLAP"):
            RENDER.render("", unsafe, runtime_config())
        unsafe = values()
        unsafe["execution"]["pep_readiness_schema"] = 'ready",true'
        with self.assertRaisesRegex(RENDER.RenderError, "READINESS_SCHEMA_INVALID"):
            RENDER.render("", unsafe, runtime_config())

    def test_execution_dependency_endpoints_and_egress_ports_are_closed(self) -> None:
        for field, endpoint in (
            ("approval_endpoint", "http://approval.prod.test/"),
            ("pep_endpoint", "http://pep.prod.test/"),
            ("tool_endpoint", "https://tool.prod.test/v1/escape"),
            ("evidence_endpoint", "https://evidence.prod.test:9443/"),
        ):
            unsafe = values()
            unsafe["execution"][field] = endpoint
            with self.subTest(field=field), self.assertRaisesRegex(
                RENDER.RenderError, "EXECUTION_.*_ENDPOINT"
            ):
                RENDER.render("", unsafe, runtime_config())
        with_explicit_port = values()
        with_explicit_port["execution"]["tool_endpoint"] = (
            "https://tool-proxy.prod.test:8443/"
        )
        rendered = RENDER.render(
            (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(),
            with_explicit_port,
            runtime_config(),
        )
        self.assertIn('cidr: "10.6.0.0/24"', rendered)
        self.assertIn("ports: [{protocol: TCP, port: 8443}]", rendered)

    def test_execution_approval_authority_contract_is_deployed(self) -> None:
        template = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text()
        for required in (
            'objectName: "approval.token"',
            'objectName: "approval-verification-keys.json"',
            "AGENT_TRUST_EXECUTION_APPROVAL_ENDPOINT",
            "AGENT_TRUST_EXECUTION_APPROVAL_TOKEN_FILE",
            "AGENT_TRUST_EXECUTION_APPROVAL_VERIFICATION_KEYS_FILE",
            "AGENT_TRUST_EXECUTION_APPROVAL_READINESS_SCHEMA",
            "@@EXECUTION_APPROVAL_CIDR@@",
            "@@EXECUTION_APPROVAL_PORT@@",
        ):
            self.assertIn(required, template)
        runbook = (ROOT / "docs/platform/production-deployment-runbook.md").read_text()
        normalized_runbook = " ".join(runbook.split())
        for required in (
            "POST /v1/approvals/grants/consume",
            "agenttrust.approval-grant-receipt.v1",
            "agenttrust.approval-verification-keys.v1",
            "agenttrust.enterprise-approval-readiness.v1",
            "execution never manufactures an approval from request data",
        ):
            self.assertIn(required, normalized_runbook)
        binary = (
            ROOT
            / "rust/crates/production-runtime/src/bin/agenttrust-execution-service.rs"
        ).read_text()
        execution = (
            ROOT / "rust/crates/production-runtime/src/execution.rs"
        ).read_text()
        for required in (
            "AGENT_TRUST_EXECUTION_APPROVAL_VERIFICATION_KEYS_FILE",
            'port("APPROVAL", None, None)?',
        ):
            self.assertIn(required, binary)
        for required in (
            '"/v1/authorize/pre-approval"',
            '"/v1/approvals/grants/consume"',
            '"agenttrust.approval-verification-keys.v1"',
            "stage: EnforcementStage::PreApproval",
            "receipt.remaining_uses != 0",
            "grant.plan_hash != request.plan_hash",
            "authorized.authorization.approval_ids != expected_approval_ids",
        ):
            self.assertIn(required, execution)

    def test_execution_materialization_and_dispatch_poll_contract_is_wired(self) -> None:
        worker = (ROOT / "python/durable_worker/worker.py").read_text()
        for required in (
            "agenttrust.action-materialization-ref.v1",
            "ORCHESTRATOR_INGRESS_POSTGRESQL",
            "execution-dispatch-or-poll",
            'execution_status in {"PREPARED", "RUNNING"}',
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
        unsafe["network"]["trusted_service_cidr"] = "0.0.0.0/0"
        with self.assertRaisesRegex(RENDER.RenderError, "TRUSTED_SERVICE_CIDR_INVALID"):
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

    def test_build_context_excludes_host_outputs_and_credentials(self) -> None:
        ignored = (ROOT / ".dockerignore").read_text().splitlines()
        for required in (
            ".git", "target", "**/target", "**/node_modules", "evidence",
            "*.pem", "*.key", "*.p12", ".env", ".env.*",
        ):
            self.assertIn(required, ignored)
        for dockerfile_name in (
            "Dockerfile.transition", "Dockerfile.production-runtime", "Dockerfile.execution"
        ):
            dockerfile = (ROOT / dockerfile_name).read_text()
            self.assertNotIn("COPY . .", dockerfile)
            self.assertIn("COPY rust ./rust", dockerfile)

    def test_migration_runner_pins_search_path_and_hides_uri_from_argv(self) -> None:
        runner = (ROOT / "scripts/run-production-migrations.sh").read_text()
        self.assertIn("SET search_path = public", runner)
        self.assertIn("current_schemas(true)", runner)
        self.assertIn('sslmode_summary', runner)
        self.assertIn('sslrootcert_summary', runner)
        self.assertIn('AGENT_TRUST_DATABASE_CA_FILE', runner)
        self.assertIn('MIGRATION_DATABASE_TLS_ROOT_CERT_REQUIRED', runner)
        self.assertIn('PGDATABASE="$database_url" psql', runner)
        self.assertNotIn('psql "$database_url"', runner)
        self.assertIn("ENTERPRISE_APPLICATION_ROLE", runner)
        self.assertIn("ORCHESTRATOR_APPLICATION_ROLE", runner)
        self.assertIn("EXECUTION_APPLICATION_ROLE", runner)
        self.assertIn("registry_snapshots", runner)
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
                "agenttrust.transition-readiness.v1",
                "agenttrust.execution-readiness.v1",
            ):
                self.assertIn(required, source)
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


if __name__ == "__main__":
    unittest.main()
