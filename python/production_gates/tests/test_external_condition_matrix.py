from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


class ExternalConditionMatrixTests(unittest.TestCase):
    def test_matrix_is_complete_consistent_and_integrity_bound(self):
        path = ROOT / "evidence/production-closure/external-condition-matrix.json"
        matrix = json.loads(path.read_text(encoding="utf-8"))
        claimed = matrix.pop("matrix_digest")
        actual = hashlib.sha256(
            json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(claimed, actual)
        conditions = matrix["conditions"]
        identifiers = {condition["condition_id"] for condition in conditions}
        self.assertEqual(len(identifiers), len(conditions))
        self.assertEqual(matrix["summary"]["condition_count"], len(conditions))
        self.assertEqual(matrix["summary"]["code_gate_ready"], len(conditions))
        self.assertEqual(matrix["summary"]["external_verified"], 0)
        self.assertTrue(all(condition["blocking"] for condition in conditions))
        self.assertFalse(matrix["production_evidence"])
        self.assertFalse(matrix["eligible"])
        self.assertEqual(matrix["production_closure_certificate"], "NOT_ISSUED")


if __name__ == "__main__":
    unittest.main()
