from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from python.production_gates.live_integrations import (
    ConfigurationMissing,
    GateError,
    probe_model_provider,
    probe_oidc,
    probe_s3,
    probe_temporal,
)


class FakeHttp:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def request(self, method: str, url: str, *, headers=None, body=None,
                maximum_bytes=1_048_576, allow_http_local=False):
        del maximum_bytes, allow_http_local
        if url.endswith("openid-configuration"):
            return 200, {}, json.dumps({
                "issuer": "https://iam.example.test/tenant",
                "jwks_uri": "https://iam.example.test/tenant/jwks",
            }).encode()
        if url.endswith("/jwks"):
            return 200, {}, json.dumps({"keys": [
                {
                    "kid": "key-1", "kty": "RSA", "alg": "RS256", "use": "sig",
                    "key_ops": ["verify"], "n": "base64url-modulus", "e": "AQAB",
                },
            ]}).encode()
        if url.endswith("/models"):
            self.assert_authorization(headers)
            return 200, {}, b'{"data":[{"id":"approved-model"}]}'
        if method == "PUT":
            self.objects[url] = body or b""
            return 200, {}, b""
        if method == "GET":
            return 200, {}, self.objects[url]
        if method == "HEAD":
            return (200 if url in self.objects else 404), {}, b""
        if method == "DELETE":
            self.objects.pop(url, None)
            return 204, {}, b""
        raise AssertionError(method)

    @staticmethod
    def assert_authorization(headers):
        assert headers and headers["Authorization"].startswith("Bearer ")


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, args, timeout_seconds):
        self.commands.append(list(args))
        self.assert_timeout(timeout_seconds)
        return b'{"ok":true}'

    @staticmethod
    def assert_timeout(value):
        assert value == 30


class LiveIntegrationTests(unittest.TestCase):
    def test_oidc_discovery_and_jwks_are_strict(self):
        result = probe_oidc("https://iam.example.test/tenant", "agenttrust", transport=FakeHttp())
        self.assertEqual(result.status, "PASS_REAL_PROTOCOL")
        self.assertEqual(result.checks["signing_key_count"], 1)
        with self.assertRaises(GateError):
            probe_oidc("http://iam.example.test", "agenttrust", transport=FakeHttp())
        with self.assertRaises(ConfigurationMissing):
            probe_oidc("", "", transport=FakeHttp())

    def test_temporal_protocol_probe_starts_describes_and_terminates(self):
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "temporal"
            binary.write_bytes(b"binary")
            result = probe_temporal(binary, "127.0.0.1:7233", "default", runner=runner)
        self.assertEqual(result.status, "PASS_REAL_PROTOCOL")
        flattened = [item for command in runner.commands for item in command]
        self.assertIn("start", flattened)
        self.assertIn("terminate", flattened)

    def test_temporal_production_mode_requires_digest_pinned_mtls(self):
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binary = root / "temporal"
            ca = root / "ca.pem"
            certificate = root / "client.pem"
            key = root / "client.key"
            binary.write_bytes(b"reviewed-temporal-binary")
            ca.write_text("ca", encoding="utf-8")
            certificate.write_text("certificate", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            key.chmod(0o600)
            import hashlib
            result = probe_temporal(
                binary, "temporal.production.example:7233", "agenttrust",
                require_production_tls=True,
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                ca_file=ca,
                client_certificate=certificate,
                client_private_key=key,
                tls_server_name="temporal.production.example",
                runner=runner,
            )
        flattened = [item for command in runner.commands for item in command]
        self.assertIn("--tls", flattened)
        self.assertIn("--tls-server-name", flattened)
        self.assertTrue(result.checks["binary_digest_verified"])

    def test_s3_round_trip_does_not_emit_credentials(self):
        os.environ["AGENTTRUST_TEST_S3_ACCESS"] = "access-value"
        os.environ["AGENTTRUST_TEST_S3_SECRET"] = "secret-value"
        try:
            result = probe_s3(
                "http://127.0.0.1:9000", "us-east-1",
                "AGENTTRUST_TEST_S3_ACCESS", "AGENTTRUST_TEST_S3_SECRET",
                allow_http_local=True, transport=FakeHttp(),
            )
        finally:
            os.environ.pop("AGENTTRUST_TEST_S3_ACCESS", None)
            os.environ.pop("AGENTTRUST_TEST_S3_SECRET", None)
        rendered = json.dumps(result.as_dict())
        self.assertNotIn("access-value", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertTrue(result.checks["payload_integrity"])

    def test_model_catalog_is_authenticated_and_bounded(self):
        os.environ["AGENTTRUST_TEST_MODEL_KEY"] = "provider-secret"
        try:
            result = probe_model_provider(
                "https://models.example.test/v1/models",
                "AGENTTRUST_TEST_MODEL_KEY",
                expected_model="approved-model",
                transport=FakeHttp(),
            )
        finally:
            os.environ.pop("AGENTTRUST_TEST_MODEL_KEY", None)
        self.assertTrue(result.checks["expected_model_present"])
        self.assertNotIn("provider-secret", json.dumps(result.as_dict()))


if __name__ == "__main__":
    unittest.main()
