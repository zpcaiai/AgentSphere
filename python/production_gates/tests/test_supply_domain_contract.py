import json
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class SupplyDomainProductionContractTest(unittest.TestCase):
    def test_public_json_contracts_parse(self) -> None:
        paths = [
            ROOT / "schemas/domain-pack/domain-pack.schema.json",
            ROOT / "schemas/domain-pack/supply-chain-execution.schema.json",
            ROOT / "schemas/domain-pack/supply-chain-payload.schema.json",
            ROOT / "schemas/domain-pack/runtime-receipt.schema.json",
            ROOT / "schemas/domain-pack/authoritative-releases.schema.json",
            ROOT / "schemas/domain-pack/token-bindings.schema.json",
            ROOT / "schemas/domain-pack/receipt-keyring.schema.json",
            ROOT / "schemas/domain-packs/domain-execution.schema.json",
            ROOT / "schemas/domain-packs/domain-runtime-receipt.schema.json",
            ROOT / "schemas/domain-packs/domain-effect-receipt.schema.json",
            ROOT / "schemas/domain-packs/domain-evaluator-result.schema.json",
            ROOT / "schemas/domain-packs/domain-runtime-keyring.schema.json",
            ROOT / "schemas/domain-packs/domain-runtime-token-bindings.schema.json",
            ROOT / "schemas/domain-packs/domain-runtime-result.schema.json",
            ROOT / "schemas/domain-packs/authoritative-domain-state.schema.json",
            ROOT / "schemas/domain-packs/coding-action.schema.json",
            ROOT / "schemas/domain-packs/industrial-action.schema.json",
            ROOT / "schemas/domain-packs/industrial-operation.schema.json",
            ROOT / "schemas/domain-packs/energy-candidate.schema.json",
            ROOT / "schemas/domain-packs/energy-observation.schema.json",
            ROOT / "schemas/domain-packs/medical-review.schema.json",
            ROOT / "schemas/domain-packs/medical-assist.schema.json",
            ROOT / "schemas/domain-packs/sensitive-handoff.schema.json",
            ROOT / "schemas/domain-packs/sensitive-interaction.schema.json",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)

    def test_migrations_are_ordered_and_tenant_fail_closed(self) -> None:
        manifest = (ROOT / "migrations/manifest.txt").read_text(encoding="utf-8")
        ordered = [
            "pack-supply-chain/0036_01_16_production_pack_supply_chain.sql",
            "domain-packs/0036_01_18_production_coding_pack.sql",
            "domain-packs/0036_01_19_production_industrial_pack.sql",
            "domain-packs/0036_01_20_production_energy_pack.sql",
            "domain-packs/0036_01_21_production_medical_pack.sql",
            "domain-packs/0036_01_22_production_sensitive_pack.sql",
        ]
        offsets = [manifest.index(entry) for entry in ordered]
        self.assertEqual(offsets, sorted(offsets))
        for entry in ordered:
            migration = (ROOT / "migrations" / entry).read_text(encoding="utf-8")
            self.assertIn("FORCE ROW LEVEL SECURITY", migration)
            self.assertIn("REVOKE ALL", migration)
            self.assertNotIn("using (true)", migration.lower())

    def test_supply_authority_uses_exact_identity_scope_and_unknown(self) -> None:
        server = (ROOT / "rust/crates/pack-supply-chain/src/server.rs").read_text(encoding="utf-8")
        authority = (ROOT / "rust/crates/pack-supply-chain/src/production.rs").read_text(encoding="utf-8")
        binary = (ROOT / "rust/crates/pack-supply-chain/src/bin/agenttrust-pack-supply-chain-authority.rs").read_text(encoding="utf-8")
        token_schema = json.loads((ROOT / "schemas/domain-pack/token-bindings.schema.json").read_text(encoding="utf-8"))
        scopes = token_schema["properties"]["bindings"]["items"]["properties"]["scope"]["enum"]
        self.assertEqual(
            scopes,
            [
                "supply-chain:publish",
                "supply-chain:approve",
                "supply-chain:activate",
                "supply-chain:revoke",
                "supply-chain:read",
                "supply-chain:recover",
            ],
        )
        for scope in scopes:
            self.assertIn(scope, server if scope in {"supply-chain:read", "supply-chain:recover"} else authority)
        self.assertNotIn("supply-chain:execute", server)
        self.assertIn("TLS13", server)
        self.assertIn("identities.len()==1", server)
        self.assertIn("body.command.operation.required_scope()", server)
        self.assertIn("OutcomeUnknown", authority)
        self.assertIn("SET state='UNKNOWN'", authority)
        self.assertIn("installation_receipt_digest", authority)
        self.assertIn("reconciliation_receipt_digest", authority)
        self.assertIn("PermissionDiff::compute", authority)
        self.assertIn("permission_diff!=computed_diff", authority)
        self.assertIn("preflight_external", authority)
        self.assertIn("SUPPLY_CHAIN_COMMIT_OUTCOME_UNKNOWN", authority)
        self.assertIn("rolbypassrls", binary)
        self.assertIn("sslmode", binary)
        self.assertIn("verify-full", binary)

    def test_supply_wire_contract_and_container_are_fixed(self) -> None:
        openapi = (ROOT / "schemas/openapi/pack-supply-chain-v1.yaml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile.pack-supply-chain").read_text(encoding="utf-8")
        for required in [
            ":8093",
            "/v1/supply-chain/executions",
            "/v1/authoritative/supply-chain/releases",
            "X-AgentTrust-Authorization-Evidence-Digest",
            "X-AgentTrust-Ledger-Entry-Digest",
            "X-AgentTrust-Fence-Digest",
            "X-AgentTrust-Resource-Version",
        ]:
            self.assertIn(required, openapi)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn("EXPOSE 8093 9103", dockerfile)
        payload_schema = json.loads(
            (ROOT / "schemas/domain-pack/supply-chain-payload.schema.json").read_text(encoding="utf-8")
        )
        for name in ["approve", "activate", "rollback"]:
            self.assertEqual(payload_schema["$defs"][name]["properties"]["environment"], {"const": "production"})

    def test_shared_authority_evidence_wire_is_exact_and_retry_stable(self) -> None:
        sources = [
            ROOT / "rust/crates/pack-supply-chain/src/server.rs",
            ROOT / "rust/crates/domain-risk-packs/server.rs",
        ]
        producers = [
            ROOT / "rust/crates/pack-supply-chain/src/production.rs",
            ROOT / "rust/crates/domain-risk-packs/authority.rs",
        ]
        for path in sources:
            source = path.read_text(encoding="utf-8")
            self.assertIn("/authority-events", source)
            self.assertIn("AuthorityEvidenceEventRequest", source)
            self.assertIn("AuthorityEvidenceControlBinding", source)
            self.assertIn("SignedAuthorityEvidenceReceipt", source)
            self.assertIn("X-AgentTrust-Authority-Event-Id", source)
            self.assertIn("X-AgentTrust-Payload-Digest", source)
            self.assertIn("EvidenceEventType::StateTransition", source)
            self.assertNotIn("/v1/evidence/events", source)
            self.assertNotIn("expected_task_state_version", source)
        for path in producers:
            source = path.read_text(encoding="utf-8")
            self.assertIn('"evidence_occurred_at"', source)
            self.assertIn('"evidence_requested_at"', source)

    def test_domain_wire_container_and_immutable_image_builder_are_registered(self) -> None:
        openapi = (ROOT / "schemas/openapi/domain-runtime-v1.yaml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile.domain-runtime").read_text(encoding="utf-8")
        for required in [
            ":8094",
            "/v1/domain-runtime/executions",
            "/v1/authoritative/domain-runtime/executions",
            "/v1/domain-runtime/recoveries/{tenant_id}",
            "X-AgentTrust-Resource-Version",
        ]:
            self.assertIn(required, openapi)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn("EXPOSE 8094 9104", dockerfile)

        script = ROOT / "scripts/build-production-image.py"
        spec = importlib.util.spec_from_file_location("build_production_image", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        bases = [
            "registry.example/builder@sha256:" + "a" * 64,
            "registry.example/runtime@sha256:" + "b" * 64,
        ]
        for component, expected in [
            ("pack-supply-chain", ROOT / "Dockerfile.pack-supply-chain"),
            ("domain-runtime", ROOT / "Dockerfile.domain-runtime"),
        ]:
            command = module.command_for(
                component,
                f"registry.example/{component}:production",
                bases,
                ROOT,
            )
            self.assertIn(str(expected), command)

    def test_domain_management_routes_match_production_probes(self) -> None:
        server = (ROOT / "rust/crates/domain-risk-packs/server.rs").read_text(encoding="utf-8")
        stack = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(
            encoding="utf-8"
        )
        self.assertIn('route("/live",get(management_live))', server)
        self.assertIn('route("/ready",get(management_ready))', server)
        self.assertIn(
            '"schema_version":DOMAIN_READINESS_SCHEMA,"live":true', server
        )
        self.assertIn(
            "livenessProbe: {httpGet: {path: /live, port: management}", stack
        )
        self.assertIn(
            "readinessProbe: {httpGet: {path: /ready, port: management}", stack
        )

    def test_supply_and_platform_management_routes_match_production_probes(self) -> None:
        supply = (ROOT / "rust/crates/pack-supply-chain/src/server.rs").read_text(
            encoding="utf-8"
        )
        platform = (ROOT / "rust/crates/platform-sre/src/server.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn('route("/live",get(management_live))', supply)
        self.assertIn('route("/ready",get(management_ready))', supply)
        self.assertIn(
            '"schema_version":SUPPLY_READINESS_SCHEMA,"live":true', supply
        )
        self.assertIn('.route("/live", get(management_health))', platform)
        self.assertIn('.route("/ready", get(management_ready))', platform)
        self.assertIn('"schema_version": "agenttrust.sre-liveness.v1"', platform)

    def test_data_management_binding_accepts_kubernetes_probe_address(self) -> None:
        server = (ROOT / "rust/crates/data-governance/src/server.rs").read_text(
            encoding="utf-8"
        )
        stack = (ROOT / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(
            encoding="utf-8"
        )
        self.assertIn("config.data_address.ip().is_loopback()", server)
        self.assertIn("config.management_address.ip().is_loopback()", server)
        self.assertIn("config.management_address.ip().is_unspecified()", server)
        self.assertIn(
            "AGENT_TRUST_DATA_MANAGEMENT_LISTEN_ADDRESS, value: 0.0.0.0", stack
        )

    def test_domain_limited_write_is_dual_approved_and_single_use(self) -> None:
        shared = (ROOT / "migrations/domain-packs/0036_01_18_production_coding_pack.sql").read_text(encoding="utf-8")
        industrial = (ROOT / "migrations/domain-packs/0036_01_19_production_industrial_pack.sql").read_text(encoding="utf-8")
        energy = (ROOT / "migrations/domain-packs/0036_01_20_production_energy_pack.sql").read_text(encoding="utf-8")
        plugin = (ROOT / "rust/crates/domain-risk-packs/production.rs").read_text(encoding="utf-8")
        self.assertIn("domain_supervision_consume_guard", shared)
        self.assertIn("OLD.consumed_by_execution_id IS NOT NULL", shared)
        for migration in [industrial, energy]:
            self.assertIn("count(DISTINCT reviewer_subject)", migration)
            self.assertIn("reviewer_subject<>supervision.supervisor_subject", migration)
            self.assertIn("consumed_by_execution_id=NEW.execution_id", migration)
        self.assertIn("validate_approvals(envelope,now,2)", plugin)
        self.assertIn("approval.reviewer_subject==supervision.supervisor_subject", plugin)
        authority = (ROOT / "rust/crates/domain-risk-packs/authority.rs").read_text(encoding="utf-8")
        self.assertIn('row.get::<String,_>("reviewer_role")!=approval.reviewer_role', authority)
        self.assertIn('row.get::<String,_>("evidence_digest")!=approval.evidence_digest', authority)

    def test_authoritative_pages_digest_the_final_response_shape(self) -> None:
        supply = (ROOT / "rust/crates/pack-supply-chain/src/production.rs").read_text(encoding="utf-8")
        domain = (ROOT / "rust/crates/domain-risk-packs/authority.rs").read_text(encoding="utf-8")
        for source, schema in [
            (supply, "SUPPLY_RELEASES_SCHEMA"),
            (domain, "DOMAIN_STATE_SCHEMA"),
        ]:
            digest_block = source[source.index("The digest covers the exact response object"):]
            self.assertIn(f'"schema_version":{schema}', digest_block)
            self.assertIn('"authoritative":true', digest_block)
            self.assertIn('"items":&items', digest_block)
            self.assertIn('"next_cursor":&next_cursor', digest_block)

    def test_domain_receipt_has_typed_effect_and_evaluator_contracts(self) -> None:
        authority = (ROOT / "rust/crates/domain-risk-packs/authority.rs").read_text(encoding="utf-8")
        self.assertIn("TypedDomainEffectReceipt", authority)
        self.assertIn("TypedDomainEvaluatorResult", authority)
        self.assertIn("DOMAIN_RUNTIME_COMMIT_OUTCOME_UNKNOWN", authority)
        self.assertIn("actual_checks!=expected_checks", authority)
        self.assertIn("!all_pass", authority)
        plugin = (ROOT / "rust/crates/domain-risk-packs/production.rs").read_text(encoding="utf-8")
        self.assertIn("x-domain-pack-manifest-digest", plugin)
        self.assertIn("x-domain-before-digest", plugin)
        self.assertIn("x-domain-target-digest", plugin)

    def test_external_acceptance_boundary_is_not_overclaimed(self) -> None:
        supply_runbook = (ROOT / "docs/supply-chain/production-authority-runbook.md").read_text(encoding="utf-8")
        domain_runbook = (ROOT / "docs/domain-packs/risk-pack-operations.md").read_text(encoding="utf-8")
        self.assertIn("NOT_RUN", supply_runbook)
        self.assertIn("NOT_ISSUED", supply_runbook)
        self.assertIn("NOT_RUN", domain_runbook)
        self.assertIn("OPC UA", domain_runbook)
        self.assertIn("Modbus", domain_runbook)


if __name__ == "__main__":
    unittest.main()
