from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from python.production_gates.external_services import (
    TlsPeerSnapshot,
    probe_a2a_agent_card,
    probe_mcp_http,
    probe_model_generation_stream,
    probe_mtls,
    probe_vault_secret_broker,
)
from python.production_gates.live_integrations import GateError


class FakeTls:
    def connect(self, host, port, ca_file, client_certificate, client_private_key,
                timeout_seconds):
        self.arguments = (host, port, ca_file, client_certificate, client_private_key,
                          timeout_seconds)
        return TlsPeerSnapshot("TLSv1.3", "TLS_AES_256_GCM_SHA384", "a" * 64, 2)


class FakeExternalHttp:
    def __init__(self, *, a2a_endpoint: str = "https://a2a.example.test/tasks") -> None:
        self.requests: list[tuple[str, str, dict[str, str], bytes | None]] = []
        self.a2a_endpoint = a2a_endpoint

    def request(self, method, url, *, headers=None, body=None, maximum_bytes=1_048_576,
                allow_http_local=False):
        del maximum_bytes, allow_http_local
        request_headers = dict(headers or {})
        self.requests.append((method, url, request_headers, body))
        if url.endswith("/v1/sys/health"):
            self._vault_auth(request_headers)
            return 200, {}, b'{"initialized":true,"sealed":false}'
        if url.endswith("/v1/auth/token/lookup-self"):
            self._vault_auth(request_headers)
            return 200, {}, b'{"data":{"ttl":300,"policies":["agenttrust-probe"]}}'
        if url.endswith("/v1/database/creds/probe"):
            self._vault_auth(request_headers)
            return 200, {}, b'{"lease_id":"database/creds/probe/lease","lease_duration":120,"data":{"opaque":"redacted-by-probe"}}'
        if url.endswith("/v1/sys/leases/revoke"):
            self._vault_auth(request_headers)
            assert json.loads(body or b"{}") == {"lease_id": "database/creds/probe/lease"}
            return 204, {}, b""
        if url.endswith("/v1/chat/completions"):
            assert request_headers.get("Authorization", "").startswith("Bearer ")
            request = json.loads(body or b"{}")
            if request.get("stream"):
                payload = b"\n".join([
                    b'data: {"choices":[{"delta":{"content":"AGENT"}}]}',
                    b'data: {"choices":[{"delta":{"content":"TRUST_OK"}}]}',
                    b'data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":3}}',
                    b"data: [DONE]",
                    b"",
                ])
                return 200, {"Content-Type": "text/event-stream; charset=utf-8"}, payload
            return 200, {"Content-Type": "application/json"}, json.dumps({
                "id": "provider-request-secret-id",
                "choices": [{"message": {"content": "AGENTTRUST_OK"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            }).encode()
        if url == "https://mcp.example.test/mcp":
            request = json.loads(body or b"{}")
            if request["method"] == "initialize":
                return 200, {"Mcp-Session-Id": "session-opaque"}, json.dumps({
                    "jsonrpc": "2.0", "id": 1, "result": {
                        "protocolVersion": "2025-03-26",
                        "serverInfo": {"name": "test", "version": "1"},
                    },
                }).encode()
            assert request_headers["Mcp-Session-Id"] == "session-opaque"
            return 200, {}, json.dumps({
                "jsonrpc": "2.0", "id": 2, "result": {"tools": [{
                    "name": "read", "inputSchema": {"type": "object", "properties": {}},
                }]},
            }).encode()
        if url.endswith("/.well-known/agent-card.json"):
            return 200, {}, json.dumps({
                "name": "approved-agent",
                "url": self.a2a_endpoint,
                "capabilities": {"streaming": True, "pushNotifications": False},
                "skills": [{"id": "read"}, {"id": "evaluate"}],
            }).encode()
        raise AssertionError((method, url))

    @staticmethod
    def _vault_auth(headers):
        assert headers.get("X-Vault-Token") == "vault-token"


class ExternalServicesTests(unittest.TestCase):
    def test_mtls_requires_private_permissions_and_reports_only_digests(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ca = root / "ca.pem"
            cert = root / "client.pem"
            key = root / "client.key"
            ca.write_text("ca", encoding="utf-8")
            cert.write_text("cert", encoding="utf-8")
            key.write_text("private", encoding="utf-8")
            key.chmod(0o600)
            result = probe_mtls("identity.example.test", 443, ca, cert, key,
                                transport=FakeTls())
            rendered = json.dumps(result.as_dict())
            self.assertTrue(result.checks["mutual_tls_handshake"])
            self.assertNotIn('"private"', rendered)
            key.chmod(0o644)
            with self.assertRaises(GateError):
                probe_mtls("identity.example.test", 443, ca, cert, key,
                           transport=FakeTls())

    def test_mtls_denies_non_public_literal_targets(self):
        with self.assertRaisesRegex(GateError, "MTLS_CONFIGURATION_INVALID"):
            probe_mtls("10.0.0.7", 443, Path("/missing-ca"), Path("/missing-cert"),
                       Path("/missing-key"), transport=FakeTls())

    def test_vault_health_token_and_dynamic_lease_lifecycle(self):
        os.environ["AGENTTRUST_TEST_VAULT_TOKEN"] = "vault-token"
        try:
            result = probe_vault_secret_broker(
                "https://vault.example.test", "AGENTTRUST_TEST_VAULT_TOKEN",
                dynamic_lease_path="database/creds/probe", transport=FakeExternalHttp(),
            )
        finally:
            os.environ.pop("AGENTTRUST_TEST_VAULT_TOKEN", None)
        self.assertTrue(result.checks["dynamic_lease_issued"])
        self.assertTrue(result.checks["dynamic_lease_revoked"])
        self.assertNotIn("vault-token", json.dumps(result.as_dict()))

    def test_model_generation_stream_usage_and_dlp_evidence_is_redacted(self):
        os.environ["AGENTTRUST_TEST_MODEL_KEY"] = "provider-key"
        try:
            result = probe_model_generation_stream(
                "https://models.example.test/v1/chat/completions",
                "AGENTTRUST_TEST_MODEL_KEY", "approved-model", "us",
                transport=FakeExternalHttp(),
            )
        finally:
            os.environ.pop("AGENTTRUST_TEST_MODEL_KEY", None)
        rendered = json.dumps(result.as_dict())
        self.assertEqual(result.checks["stream_chunk_count"], 3)
        self.assertEqual(result.checks["total_input_tokens"], 24)
        self.assertFalse(result.checks["data_residency_attested"])
        self.assertNotIn("provider-key", rendered)
        self.assertNotIn("AGENTTRUST_OK", rendered)

    def test_mcp_and_a2a_network_discovery_are_bounded_and_non_executing(self):
        transport = FakeExternalHttp()
        mcp = probe_mcp_http("https://mcp.example.test/mcp", transport=transport)
        a2a = probe_a2a_agent_card(
            "https://a2a.example.test/.well-known/agent-card.json", transport=transport
        )
        self.assertEqual(mcp.checks["tool_count"], 1)
        self.assertTrue(mcp.checks["tool_call_not_executed"])
        self.assertEqual(a2a.checks["skill_count"], 2)
        self.assertTrue(a2a.checks["task_submission_not_executed"])

    def test_a2a_task_endpoint_requires_strict_same_origin(self):
        with self.assertRaisesRegex(GateError, "A2A_AGENT_CARD_INVALID"):
            probe_a2a_agent_card(
                "https://a2a.example.test/.well-known/agent-card.json",
                transport=FakeExternalHttp(
                    a2a_endpoint="https://a2a.example.test:8443/tasks"
                ),
            )


if __name__ == "__main__":
    unittest.main()
