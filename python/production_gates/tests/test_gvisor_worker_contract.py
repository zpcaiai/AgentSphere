import json
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[3]


class GvisorWorkerContractTests(unittest.TestCase):
    def test_attested_runsc_digest_is_rechecked_against_actual_binary_bytes(self) -> None:
        runtime = (ROOT / "rust/crates/sandbox-runtime/src/lib.rs").read_text()
        worker = (
            ROOT
            / "rust/crates/sandbox-runtime/src/bin/agenttrust-gvisor-worker.rs"
        ).read_text()

        self.assertIn("std::fs::read(&self.runsc_path)", runtime)
        self.assertIn("actual != runtime_digest", runtime)
        self.assertIn("let measured_runsc_digest = verify_runsc_binary(&runsc_path)?;", worker)
        self.assertIn("&measured_runsc_digest,", worker)
        self.assertIn(
            "expected_runsc_digest: attestation.runsc_binary_digest.clone()", worker
        )

    def test_receipt_is_independently_host_signed_and_not_spool_writable(self) -> None:
        worker = (
            ROOT
            / "rust/crates/sandbox-runtime/src/bin/agenttrust-gvisor-worker.rs"
        ).read_text()
        unit = (
            ROOT / "deploy/systemd/agenttrust-gvisor-worker@.service"
        ).read_text()
        tmpfiles = (
            ROOT / "deploy/systemd/agenttrust-gvisor-worker.tmpfiles.conf"
        ).read_text()

        self.assertIn("receipt.sign(&receipt_signing_key, &keyring", worker)
        self.assertIn("receipt.verify(&keyring", worker)
        self.assertIn("parse_strict_json(", worker)
        self.assertIn("LoadCredentialEncrypted=receipt-signing-key.json:", unit)
        self.assertIn("ReadOnlyPaths=/var/spool/agenttrust-gvisor/inbox", unit)
        self.assertNotIn("ReadWritePaths=/var/spool", unit)
        for protected in ("state", "replay", "results"):
            self.assertIn(
                f"d /var/lib/agenttrust-gvisor/{protected} 0700 ", tmpfiles
            )

    def test_public_contracts_require_native_mode_and_receipt_signature(self) -> None:
        runtime = json.loads(
            (ROOT / "schemas/execution/gvisor-runtime-attestation.schema.json").read_text()
        )
        receipt = json.loads(
            (ROOT / "schemas/execution/gvisor-execution-receipt.schema.json").read_text()
        )
        keyring = json.loads(
            (ROOT / "schemas/execution/gvisor-worker-keyring.schema.json").read_text()
        )

        self.assertEqual(
            runtime["properties"]["execution_mode"]["const"],
            "NATIVE_SYSTEMD_RUNSC",
        )
        self.assertNotIn("runtime_class_name", runtime["properties"])
        for field in ("issuer", "key_id", "key_usage", "signature"):
            self.assertIn(field, receipt["required"])
        self.assertEqual(
            receipt["properties"]["key_usage"]["const"],
            "AGENTTRUST_GVISOR_EXECUTION_RECEIPT_V1",
        )
        self.assertIn(
            "AGENTTRUST_GVISOR_EXECUTION_RECEIPT_V1",
            keyring["$defs"]["key"]["properties"]["key_usage"]["enum"],
        )


if __name__ == "__main__":
    unittest.main()
