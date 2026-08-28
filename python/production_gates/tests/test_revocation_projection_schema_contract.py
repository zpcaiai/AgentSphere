from __future__ import annotations

import json
from pathlib import Path
import unittest

from python.production_gates.revocation_projection import (
    REQUEST_SCHEMA_VERSION,
    _REQUEST_FIELDS,
)


class RevocationProjectionRequestSchemaTests(unittest.TestCase):
    def test_public_request_schema_exactly_matches_emitted_contract(self) -> None:
        root = Path(__file__).resolve().parents[3]
        schema = json.loads(
            (root / "schemas/release/production-revocation-projection-request.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(set(schema["required"]), _REQUEST_FIELDS)
        self.assertEqual(set(schema["properties"]), _REQUEST_FIELDS)
        self.assertEqual(
            REQUEST_SCHEMA_VERSION,
            schema["properties"]["schema_version"]["const"],
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            "production-closure-revocation-registry.schema.json",
            schema["properties"]["registry"]["$ref"],
        )


if __name__ == "__main__":
    unittest.main()
