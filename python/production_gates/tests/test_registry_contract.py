from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).parents[3]


class RegistryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads((ROOT / "schemas/json/tool.schema.json").read_text())
        self.validator = Draft202012Validator(
            self.schema,
            format_checker=FormatChecker(),
        )

    def manifest(self) -> dict[str, object]:
        return {
            "schema_version": "agenttrust.registry.v1",
            "tool_id": "coding.repo-read",
            "tool_version": "1.2.3-rc.1+build.7",
            "status": "DRAFT",
            "domain": "coding",
            "display_name": "Repository read",
            "description": "Read one bounded repository path.",
            "input_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": False,
                "properties": {"path": {"type": "string"}},
            },
            "output_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": False,
                "properties": {"content": {"type": "string"}},
            },
            "effect_class": "PURE",
            "risk_level": "LOW",
            "executor_profile": "coding-read",
            "credential_profile": "none",
            "approval_profile": "none",
            "compensation": None,
            "limits": {"timeout_ms": 5000, "max_result_bytes": 4096},
            "network_profile_ref": "none",
            "filesystem_profile_ref": "repo-ro",
            "implementation": {
                "kind": "internal_service",
                "digest": "sha256:" + "a" * 64,
                "executor_id": "repo-reader",
            },
            "allowed_tenants": ["11111111-1111-4111-8111-111111111111"],
            "signature": None,
        }

    def test_complete_rust_wire_shape_is_accepted(self) -> None:
        self.validator.validate(self.manifest())

    def test_unknown_fields_and_non_semver_or_digest_are_rejected(self) -> None:
        for field, value in (
            ("tool_version", "latest"),
            ("tool_id", "not-namespaced"),
        ):
            invalid = self.manifest()
            invalid[field] = value
            self.assertTrue(list(self.validator.iter_errors(invalid)))
        invalid = self.manifest()
        invalid["implementation"]["digest"] = "sha256:" + "A" * 64
        self.assertTrue(list(self.validator.iter_errors(invalid)))
        invalid = self.manifest()
        invalid["unexpected"] = True
        self.assertTrue(list(self.validator.iter_errors(invalid)))

    def test_manifest_business_rules_match_rust_validation(self) -> None:
        invalid = self.manifest()
        invalid["credential_profile"] = "unexpected"
        self.assertTrue(list(self.validator.iter_errors(invalid)))

        invalid = self.manifest()
        invalid["display_name"] = " padded "
        self.assertTrue(list(self.validator.iter_errors(invalid)))

        invalid = self.manifest()
        invalid["effect_class"] = "COMPENSATABLE"
        invalid["compensation"] = None
        self.assertTrue(list(self.validator.iter_errors(invalid)))

        invalid = self.manifest()
        invalid["effect_class"] = "IRREVERSIBLE"
        invalid["risk_level"] = "LOW"
        self.assertTrue(list(self.validator.iter_errors(invalid)))

    def test_openapi_requires_idempotency_for_every_lifecycle_write(self) -> None:
        contract = (ROOT / "schemas/openapi/registry-v1.yaml").read_text()
        for action in ("validate", "sign", "activate", "deprecate", "revoke"):
            marker = f"/v1/tools/{{id}}/versions/{{version}}/{action}"
            start = contract.index(marker)
            block = contract[start : start + 1500]
            self.assertIn("#/components/parameters/IdempotencyKey", block)
            self.assertIn("#/components/schemas/ActivationRequest", block)
            self.assertIn("#/components/schemas/ActivationReceipt", block)
        self.assertIn("bearerFormat: opaque-service-token", contract)
        self.assertIn("/v1/authoritative/tools:", contract)
        self.assertIn("/ready:", contract)

    def test_registry_idempotency_storage_is_immutable_and_tenant_scoped(self) -> None:
        migration = (
            ROOT / "migrations/tool-registry/0036_01_production_registry.sql"
        ).read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS registry_idempotency_records", migration)
        self.assertIn("PRIMARY KEY (tenant_id, idempotency_key)", migration)
        self.assertIn("registry_idempotency_records_immutable", migration)
        self.assertIn("'ACTIVE','DEPRECATED','REVOKED'", migration)
        self.assertIn("REGISTRY_PUBLISHED_REVISION_BACKFILL_REQUIRED", migration)
        self.assertIn("REGISTRY_PUBLISHER_KEY_IN_USE", migration)


if __name__ == "__main__":
    unittest.main()
