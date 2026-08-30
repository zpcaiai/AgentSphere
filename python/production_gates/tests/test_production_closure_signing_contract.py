from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


class ProductionClosureSigningContractTests(unittest.TestCase):
    def test_production_configuration_and_cli_require_external_signing(self) -> None:
        config = json.loads(
            (ROOT / "config/production-closure/authority.production.json").read_text()
        )
        self.assertEqual(config["profile"], "production")
        self.assertTrue(config["fail_closed"])
        self.assertEqual(config["signing_key_source"], "EXTERNAL_KMS")
        self.assertEqual(
            config["required_batches"],
            {"first": 1, "last": 35, "status": "EVIDENCE_VERIFIED"},
        )

        cli = (
            ROOT
            / "rust/crates/production-closure/src/bin/production-closure.rs"
        ).read_text()
        self.assertIn(
            'Some("issue") => return Err("CLOSURE_EXTERNAL_SIGNING_REQUIRED")', cli
        )
        self.assertIn('Some("prepare-external-signing")', cli)
        self.assertIn('Some("finalize-external-signing")', cli)
        self.assertIn('Some("verify-revocation-registry")', cli)
        self.assertIn('Some("verify-revocation-successor")', cli)
        self.assertIn('Some("prepare-revocation-signing")', cli)
        self.assertIn('Some("finalize-revocation-signing")', cli)
        self.assertIn('Some("verify-activation")', cli)
        self.assertIn('Some("watch-activation")', cli)
        self.assertIn('Some("prepare-activation-directory")', cli)
        self.assertIn('Some("check-activation-watch")', cli)
        for anchor in (
            "const ACTIVATION_WATCH_INTERVAL: Duration = Duration::from_secs(25);",
            "fn read_watch_json",
            "fn write_watch_receipt",
            "fn refresh_activation",
            "fn serve_readiness",
            "fn verify_projected_registry_lineage",
            "registry_preserves(previous, registry)",
            ".verify_successor(&previous, &key, Utc::now())",
            "fs::rename(&temporary, path)",
            "file.set_permissions(fs::Permissions::from_mode(0o440))",
            "fn prepare_activation_directory",
            "builder.mode(0o750)",
            "current_filesystem_ids()",
            "fn initialize_activation_watch",
            "baseline_registry: PathBuf",
            "last_registry: Some(baseline)",
            "fn check_activation_watch",
            "TcpStream::connect_timeout(&address, Duration::from_secs(2))",
            ".take(16 * 1024 + 1)",
            'header_lines.next() != Some("HTTP/1.1 200 OK")',
        ):
            self.assertIn(anchor, cli)
        self.assertIn('Some("issue-local")', cli)
        self.assertIn('#[cfg(feature = "development-local-signing")]', cli)
        self.assertIn("require_development_local_signing()?", cli)
        self.assertIn("AGENT_TRUST_ALLOW_LOCAL_CLOSURE_SIGNING", cli)
        self.assertIn('"private_key_loaded":false', cli)

        manifest = (
            ROOT / "rust/crates/production-closure/Cargo.toml"
        ).read_text()
        self.assertIn("default = []", manifest)
        self.assertIn("development-local-signing = []", manifest)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn(
            "cargo test --locked -p agent-trust-production-closure --all-features --all-targets",
            workflow,
        )

    def test_external_request_and_response_schemas_are_strict(self) -> None:
        request = json.loads(
            (
                ROOT
                / "schemas/release/production-closure-signing-request.schema.json"
            ).read_text()
        )
        signature = json.loads(
            (
                ROOT
                / "schemas/release/production-closure-external-signature.schema.json"
            ).read_text()
        )
        revocations = json.loads(
            (
                ROOT
                / "schemas/release/production-closure-revocation-registry.schema.json"
            ).read_text()
        )
        reviewer_keyring = json.loads(
            (ROOT / "schemas/release/production-closure-reviewer-keyring.schema.json").read_text()
        )
        activation = json.loads(
            (ROOT / "schemas/release/production-closure-activation-receipt.schema.json").read_text()
        )
        revocation_request = json.loads(
            (ROOT / "schemas/release/production-closure-revocation-signing-request.schema.json").read_text()
        )
        self.assertFalse(request["additionalProperties"])
        self.assertFalse(signature["additionalProperties"])
        self.assertFalse(revocations["additionalProperties"])
        self.assertFalse(reviewer_keyring["additionalProperties"])
        self.assertFalse(activation["additionalProperties"])
        self.assertFalse(revocation_request["additionalProperties"])
        self.assertIn("base_checkpoint_digest", revocation_request["required"])
        self.assertEqual(
            request["properties"]["schema_version"]["const"],
            "agenttrust.production-closure-signing-request.v1",
        )
        self.assertEqual(request["properties"]["algorithm"]["const"], "Ed25519")
        self.assertEqual(
            request["properties"]["certificate"]["properties"]["signature"]["const"],
            "",
        )
        self.assertEqual(
            signature["properties"]["schema_version"]["const"],
            "agenttrust.production-closure-external-signature.v2",
        )
        self.assertIn("signed_at", signature["required"])
        self.assertIn("audit_receipt_digest", signature["required"])
        self.assertEqual(signature["properties"]["signature"]["minLength"], 86)
        self.assertEqual(signature["properties"]["signature"]["maxLength"], 86)
        self.assertEqual(
            revocations["properties"]["schema_version"]["const"],
            "agenttrust.production-closure-revocation-registry.v1",
        )
        self.assertEqual(revocations["properties"]["entries"]["maxItems"], 100000)
        watch_status = json.loads(
            (
                ROOT
                / "schemas/release/production-activation-watch-status.schema.json"
            ).read_text()
        )
        self.assertFalse(watch_status["additionalProperties"])
        self.assertEqual(watch_status["properties"]["maximum_age_seconds"]["const"], 60)

    def test_library_reconstructs_and_verifies_before_finalizing(self) -> None:
        source = (ROOT / "rust/crates/production-closure/src/lib.rs").read_text()
        required = [
            "pub struct ExternalCertificateSigningRequest",
            "pub struct ExternalCertificateSignature",
            "payload != self.certificate.signing_bytes()?",
            "self.request_digest != request.digest()?",
            "key.verify(&payload, &signature)",
            ".verify_offline(report, input, key, now)",
            "external_signing_request_closes_kms_flow_without_loading_a_private_key",
            "external_signing_rejects_request_response_and_signature_replay_tampering",
            "pub struct SignedCertificateRevocationRegistry",
            "pub fn verify_successor",
            "signed_revocation_registry_is_required_and_detects_revoked_certificate",
            "revocation_registry_rejects_rollback_staleness_and_tampering",
            "pub struct TrustedReviewerKeyring",
            "pub struct ExternalRevocationRegistrySigningRequest",
            "pub base_checkpoint_digest: String",
            "is_sha256(&self.base_checkpoint_digest)",
            "pub struct ProductionActivationVerifier",
            "previous.entries.iter().all",
            "pub input_digest: String",
            "pub evidence_valid_until: DateTime<Utc>",
            "pub const REQUIRED_BATCH_LAST: u8 = 35;",
            'blockers.insert(format!("BATCH_{:02}_UNEXPECTED", status.batch))',
        ]
        for anchor in required:
            self.assertIn(anchor, source)


if __name__ == "__main__":
    unittest.main()
