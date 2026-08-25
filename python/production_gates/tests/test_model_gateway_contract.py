from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class ModelGatewayProductionContractTest(unittest.TestCase):
    def test_public_json_contracts_are_strict_secret_free_and_batch18_aligned(self) -> None:
        names = (
            "provider-manifest.schema.json",
            "model-execution.schema.json",
            "token-bindings.schema.json",
            "provider-endpoints.schema.json",
            "provider-keyring.schema.json",
            "evidence-keyring.schema.json",
            "authoritative-executions.schema.json",
            "artifact-store-port.schema.json",
        )
        documents = {
            name: json.loads((ROOT / "schemas/model-gateway" / name).read_text())
            for name in names
        }
        execution = documents["model-execution.schema.json"]
        bindings = documents["token-bindings.schema.json"]
        evidence_keyring = documents["evidence-keyring.schema.json"]
        authoritative = documents["authoritative-executions.schema.json"]
        artifact = documents["artifact-store-port.schema.json"]

        self.assertFalse(documents["provider-manifest.schema.json"]["additionalProperties"])
        self.assertFalse(execution["$defs"]["request"]["additionalProperties"])
        self.assertEqual(
            bindings["properties"]["bindings"]["items"]["properties"]["scope"]["enum"],
            [
                "models:generate",
                "models:stream",
                "models:embeddings",
                "models:billing:reconcile",
                "models:executions:read",
            ],
        )
        required = execution["$defs"]["request"]["required"]
        for field in (
            "canonical_action",
            "data_label",
            "cross_domain_approval_id",
            "cross_domain_grant_id",
            "cross_domain_source_zone",
            "cross_domain_target_zone",
        ):
            self.assertIn(field, required)
        self.assertEqual(
            evidence_keyring["properties"]["keys"]["items"]["properties"]["key_usage"]["const"],
            "AUTHORITY_EVIDENCE_RECEIPT",
        )
        self.assertIn("removing only data_digest", authoritative["properties"]["data_digest"]["allOf"][1]["description"])
        self.assertFalse(artifact["$defs"]["request"]["additionalProperties"])
        self.assertFalse(artifact["$defs"]["result"]["additionalProperties"])

        serialized = json.dumps(documents, sort_keys=True)
        self.assertNotIn("api_key", serialized)
        self.assertNotIn("provider_url", serialized)
        summary = authoritative["$defs"]["summary"]["properties"]
        for raw_field in ("prompt_utf8", "output_utf8", "embedding", "stream_chunks"):
            self.assertNotIn(raw_field, summary)

    def test_openapi_binds_actions_and_authoritative_read(self) -> None:
        text = (ROOT / "schemas/openapi/model-gateway-v1.yaml").read_text()
        for route in (
            "/v1/models/generate",
            "/v1/models/stream",
            "/v1/models/embeddings",
            "/v1/models/billing/reconciliations",
            "/v1/authoritative/models/executions",
        ):
            self.assertIn(route, text)
        for header in (
            "X-AgentTrust-Tenant-Id",
            "X-AgentTrust-Action-Hash",
            "X-AgentTrust-Authorization-Id",
            "X-AgentTrust-Authorization-Digest",
            "X-AgentTrust-Policy-Decision-Id",
            "X-AgentTrust-Policy-Decision-Digest",
            "X-AgentTrust-Authorization-Evidence-Ref",
            "X-AgentTrust-Authorization-Evidence-Digest",
            "X-AgentTrust-Ledger-Execution-Id",
            "X-AgentTrust-Ledger-Entry-Id",
            "X-AgentTrust-Ledger-Entry-Digest",
            "X-AgentTrust-Fence-Digest",
            "X-AgentTrust-Resource-Version",
            "Idempotency-Key",
        ):
            self.assertIn(header, text)
        self.assertIn("removing only data_digest", text)
        self.assertNotIn("orchestrator task-state version", text)
        self.assertNotIn("residency_attestation_digest", text)

    def test_migration_has_rls_durable_outboxes_unknown_and_no_raw_payloads(self) -> None:
        sql = (ROOT / "migrations/model-gateway/0036_01_14_production_model_gateway.sql").read_text()
        tenant_tables = (
            "model_tenant_provider_approvals",
            "model_budget_accounts",
            "model_gateway_requests",
            "model_budget_reservations",
            "model_stream_chunk_digests",
            "model_execution_evidence",
            "model_billing_usage_lines",
            "model_billing_reconciliations",
            "model_evidence_outbox",
            "model_authority_evidence_outbox",
            "model_data_governance_outbox",
        )
        for table in tenant_tables:
            self.assertRegex(sql, rf"(?s)CREATE TABLE IF NOT EXISTS public\.{re.escape(table)}.*?tenant_id uuid")
            self.assertIn(f"'{table}'", sql)
        for marker in (
            "FORCE ROW LEVEL SECURITY",
            "'UNKNOWN'",
            "model_request_evidence_legacy_0015",
            "agenttrust_model_approval_transition_guard",
            "agenttrust_model_authority_outbox_guard",
            "agenttrust_model_data_outbox_guard",
            "policy_decision_id",
            "transformation_digest",
            "artifact_policy_evidence_digest",
        ):
            self.assertIn(marker, sql)
        self.assertNotRegex(sql, r"(?im)^\s*(prompt|response|output)\s+(text|bytea|jsonb)\b")

    def test_runtime_uses_exact_batch18_and_authority_evidence_wires(self) -> None:
        adapters = (ROOT / "rust/crates/model-gateway/src/adapters.rs").read_text()
        authority = (ROOT / "rust/crates/model-gateway/src/authority.rs").read_text()
        for route in (
            '"/v1/internal/data/evaluate"',
            '"/v1/internal/data/scan"',
            '"/v1/internal/data/sanitize"',
            '"/v1/internal/data/artifacts/authorize"',
            '"/v1/data/actions"',
            '"/v1/authoritative/data/mutations/{command_id}"',
            '"/v1/model-artifacts"',
            '"/v1/evidence/authority-events"',
        ):
            self.assertIn(route, adapters)
        for marker in (
            "durable_record_required",
            'result.state != "COMPLETED"',
            '#[serde(rename_all = "SCREAMING_SNAKE_CASE")]',
            "DataOperation::RegisterLabel",
            "DataOperation::RecordPolicyDecision",
            "DataOperation::RecordDlpScan",
            "DataOperation::RecordTransformReceipt",
            "DataOperation::ConsumeCrossDomainGrant",
            "DataOperation::AuthorizeExport",
            "DataOperation::CompleteExport",
            "durable_preflight_verified",
            "object_authorization_ref",
            "transform_receipt_digest",
            "model_data_governance_outbox",
            "AuthorityEvidenceEventRequest",
            "SignedAuthorityEvidenceReceipt",
            "AUTHORITY_EVIDENCE_RECEIPT",
            "model_authority_evidence_outbox",
            "receipt.verify(key, Utc::now())",
        ):
            self.assertIn(marker, adapters)
        self.assertNotIn("/v1/evidence/events", adapters)
        self.assertNotIn("/v1/evidence/append", adapters)
        self.assertNotIn("residency/attest", adapters)
        self.assertNotIn("residency/preflight", adapters)
        self.assertIn("UNKNOWN", authority)
        self.assertIn("FOR UPDATE", authority)
        self.assertIn("pg_catalog.set_config('app.tenant_id'", authority)
        self.assertIn("MODEL_PROVIDER_OUTCOME_UNKNOWN", authority)

    def test_frontend_authoritative_digest_is_only_final_response_minus_digest(self) -> None:
        authority = (ROOT / "rust/crates/model-gateway/src/authority.rs").read_text()
        start = authority.index("let mut page = AuthoritativeModelExecutionsPage")
        end = authority.index("Ok(page)", start)
        implementation = authority[start:end]
        self.assertIn('object.remove("data_digest")', implementation)
        self.assertIn("generated_at: Utc::now()", implementation)
        self.assertIn("authoritative: true", implementation)
        for query_only in ("cursor_created_at", "cursor_request_id", '"limit"', '"state"', '"operation"'):
            self.assertNotIn(query_only, implementation)

    def test_service_is_tls13_mtls_secret_file_only_and_dedicated_image(self) -> None:
        adapters = (ROOT / "rust/crates/model-gateway/src/adapters.rs").read_text()
        server = (ROOT / "rust/crates/model-gateway/src/server.rs").read_text()
        binary = (ROOT / "rust/crates/model-gateway/src/bin/agenttrust-model-gateway-service.rs").read_text()
        dockerfile = (ROOT / "Dockerfile.model-gateway").read_text()
        for marker in ("TLS13", "peer_certificates", "token_sha256", "models:executions:read"):
            self.assertIn(marker, server)
        for marker in ("AGENT_TRUST_PROFILE", "VerifyFull", "model_authority_evidence_outbox", "model_data_governance_outbox"):
            self.assertIn(marker, binary)
        self.assertIn("MODEL_PROVIDER_MANIFEST", adapters)
        self.assertIn("MODEL_PROVIDER_REVOCATION", adapters)
        self.assertIn("text/event-stream", adapters)
        self.assertNotIn("danger_accept_invalid", adapters + binary)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn("EXPOSE 8091 9101", dockerfile)


if __name__ == "__main__":
    unittest.main()
