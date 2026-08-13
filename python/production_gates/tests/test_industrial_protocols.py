from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from python.production_gates.industrial_protocols import probe_industrial_read
from python.production_gates.live_integrations import GateError


class ReceiptRunner:
    def __init__(self, resource: str, write_executed: bool = False) -> None:
        self.resource = resource
        self.write_executed = write_executed

    def run(self, arguments, timeout_seconds):
        assert timeout_seconds == 20
        assert arguments[1] == "read"
        assert "--output" in arguments
        return json.dumps({
            "schema_version": "agenttrust.industrial-probe-receipt.v1",
            "protocol": "opcua",
            "connected": True,
            "mutual_tls": True,
            "security_mode": "SIGN_AND_ENCRYPT",
            "server_certificate_sha256": "a" * 64,
            "resource_address_sha256": hashlib.sha256(self.resource.encode()).hexdigest(),
            "quality": "GOOD",
            "resource_version": "source-timestamp:42",
            "sampled_at": "2026-08-06T00:00:00Z",
            "value_sha256": "b" * 64,
            "write_executed": self.write_executed,
        }).encode()


class IndustrialProtocolTests(unittest.TestCase):
    def _files(self, root: Path):
        executable = root / "probe"
        ca = root / "ca.pem"
        cert = root / "client.pem"
        key = root / "client.key"
        executable.write_bytes(b"approved-protocol-client")
        ca.write_text("ca", encoding="utf-8")
        cert.write_text("cert", encoding="utf-8")
        key.write_text("key", encoding="utf-8")
        key.chmod(0o600)
        return executable, ca, cert, key

    def test_digest_bound_mtls_read_receipt_passes_without_value_or_credentials(self):
        resource = "ns=2;s=Plant/Line1/Temperature"
        with tempfile.TemporaryDirectory() as raw:
            executable, ca, cert, key = self._files(Path(raw).resolve())
            result = probe_industrial_read(
                "opcua", executable, hashlib.sha256(executable.read_bytes()).hexdigest(),
                "opc.tcp://edge.example.test:4840", resource, ca, cert, key,
                runner=ReceiptRunner(resource),
            )
        rendered = json.dumps(result.as_dict())
        self.assertTrue(result.checks["read_only"])
        self.assertFalse(result.checks["write_executed"])
        self.assertNotIn(resource, rendered)

    def test_probe_receipt_claiming_write_is_rejected(self):
        resource = "ns=2;s=Plant/Line1/Temperature"
        with tempfile.TemporaryDirectory() as raw:
            executable, ca, cert, key = self._files(Path(raw).resolve())
            with self.assertRaises(GateError):
                probe_industrial_read(
                    "opcua", executable, hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "opc.tcp://edge.example.test:4840", resource, ca, cert, key,
                    runner=ReceiptRunner(resource, write_executed=True),
                )


if __name__ == "__main__":
    unittest.main()
