from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def load_schema(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class ProtocolRuntimeHardeningContractTests(unittest.TestCase):
    def test_mcp_contract_is_tenant_and_durable_authority_bound(self) -> None:
        manifest = load_schema("schemas/mcp/server-manifest.schema.json")
        snapshot = load_schema("schemas/mcp/tool-schema-snapshot.schema.json")
        self.assertIn("tenant_id", manifest["required"])
        self.assertIn("tenant_id", snapshot["required"])
        source = (ROOT / "rust/crates/mcp-security-proxy/src/lib.rs").read_text()
        for marker in (
            "pub trait McpStateStore",
            "notifications/initialized",
            'rpc_request("tools/list"',
            '"structuredContent"',
            "approved_tool(&request.tenant_id",
            "validate_tool_snapshot(tool).is_err()",
            "canonical_action_hash(action)",
            "None if self.state_store.is_some()",
        ):
            self.assertIn(marker, source)

    def test_a2a_and_agui_contracts_bind_peer_state_and_resume_position(self) -> None:
        card = load_schema("schemas/a2a/agent-card.schema.json")
        task = load_schema("schemas/a2a/a2a-task.schema.json")
        self.assertTrue(
            {
                "protocol_version",
                "issued_at",
                "expires_at",
                "publisher_key_id",
                "signature",
            }.issubset(card["required"])
        )
        self.assertTrue(
            {"agent_card_hash", "agent_endpoint", "protocol_version"}.issubset(
                task["required"]
            )
        )
        source = (ROOT / "rust/crates/a2a-agui-adapter/src/lib.rs").read_text()
        for marker in (
            'Ok("tasks/cancel")',
            'Ok("CancelTask")',
            "pub trait A2aTaskStore",
            "pub trait AgUiEventStore",
            "token.after_sequence != snapshot.sequence",
            "A2aTaskState::Verifying",
        ):
            self.assertIn(marker, source)
        frontend = (ROOT / "web/shared/agui-client.ts").read_text()
        self.assertIn("ED25519_SIGNATURE_BASE64URL", frontend)
        self.assertEqual(
            load_schema("schemas/a2a/agui-safe-snapshot.schema.json")["properties"][
                "backend_signature"
            ]["maxLength"],
            86,
        )

    def test_industrial_contract_distinguishes_noop_unknown_and_verified(self) -> None:
        authorization = load_schema("schemas/industrial/edge-authorization.schema.json")
        receipt = load_schema("schemas/industrial/commit-receipt.schema.json")
        safe_stop = load_schema("schemas/industrial/safe-stop-record.schema.json")
        self.assertIn("purpose", authorization["required"])
        self.assertIn("arguments_digest", authorization["required"])
        self.assertEqual(
            authorization["properties"]["purpose"]["enum"], ["WRITE", "SAFE_STOP"]
        )
        self.assertEqual(receipt["properties"]["verified"]["const"], True)
        self.assertTrue(
            {"intent_journal_digest", "completion_journal_digest"}.issubset(
                safe_stop["required"]
            )
        )
        source = (ROOT / "rust/crates/industrial-edge-gateway/src/lib.rs").read_text()
        for marker in (
            "fn load_prepared(",
            "fn record_noop(",
            "INDUSTRIAL_CONVERGENCE_NOT_PROVEN",
            'auth.purpose != "WRITE"',
            'auth.purpose != "SAFE_STOP"',
            "self.verifier.verify(auth, now)?;",
            "write_arguments_digest(",
            "safe_stop_arguments_digest(",
        ):
            self.assertIn(marker, source)

    def test_model_contract_requires_signed_residency_billing_and_buffered_release(self) -> None:
        keyring = load_schema("schemas/model-gateway/provider-keyring.schema.json")
        usages = set(keyring["properties"]["keys"]["items"]["properties"]["key_usage"]["enum"])
        self.assertTrue(
            {
                "MODEL_PROVIDER_RESIDENCY",
                "MODEL_PROVIDER_BILLING",
            }.issubset(usages)
        )
        stream = load_schema("schemas/model-gateway/model-execution.schema.json")
        self.assertEqual(
            stream["$defs"]["streamEvent"]["properties"]["release_mode"]["const"],
            "DLP_VERIFIED_BUFFERED",
        )
        adapters = (ROOT / "rust/crates/model-gateway/src/adapters.rs").read_text()
        authority = (ROOT / "rust/crates/model-gateway/src/authority.rs").read_text()
        for marker in (
            "x-agenttrust-residency-attestation",
            "verify_residency_attestation",
            "verify_billing_statement",
        ):
            self.assertIn(marker, adapters)
        self.assertIn("provider_attestation_digest", authority)

    def test_runtime_migration_is_ordered_before_global_rls(self) -> None:
        manifest = (ROOT / "migrations/manifest.txt").read_text().splitlines()
        runtime = "protocol-adapters/0036_01_28_protocol_runtime_hardening.sql"
        self.assertIn(runtime, manifest)
        self.assertLess(manifest.index(runtime), len(manifest) - 1)
        migration = (ROOT / "migrations" / runtime).read_text()
        for table in (
            "mcp_authorization_consumptions",
            "a2a_task_links",
            "agui_stream_sequences",
            "industrial_operation_journal",
        ):
            self.assertIn(f"public.{table}", migration)


if __name__ == "__main__":
    unittest.main()
