from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from python.production_gates.dependency_dag import (
    DependencyDagError,
    EXPECTED_BATCHES,
    validate_dag,
    validate_repository_dags,
)


ROOT = Path(__file__).resolve().parents[3]


class DependencyDagTests(unittest.TestCase):
    def test_cli_is_independent_of_callers_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/check-batch-dependency-dag.py")],
                cwd=directory,
                check=True,
                capture_output=True,
                text=True,
            )
        report = json.loads(result.stdout)
        self.assertTrue(report["validated"])
        self.assertEqual(report["batch_count"], 36)

    def test_repository_snapshots_and_skill_metadata_match(self) -> None:
        dag, paths = validate_repository_dags(ROOT)
        self.assertEqual(tuple(dag.batches), EXPECTED_BATCHES)
        self.assertEqual(len(paths), 4)
        self.assertEqual(set(dag.build_order), set(EXPECTED_BATCHES))
        for batch, record in dag.batches.items():
            for dependency in (*record["contracts"], *record["implementation"]):
                self.assertLess(dag.build_order.index(dependency), dag.build_order.index(batch))

    def test_duplicate_yaml_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "DEPENDENCY_DAG.yaml"
            path.write_text(
                'version: "2.0.0"\nversion: "2.0.0"\nedge_semantics: {}\nbatches: {}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DependencyDagError, "DEPENDENCY_DAG_DUPLICATE_KEY"):
                validate_dag(path)

    def test_build_cycle_fails_closed(self) -> None:
        source = (
            ROOT
            / "skills/agent-trust-control-plane-batches-01-09-v2/DEPENDENCY_DAG.yaml"
        ).read_text(encoding="utf-8")
        source = source.replace(
            'implementation: []\n    runtime: []',
            'implementation: ["36"]\n    runtime: []',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "DEPENDENCY_DAG.yaml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(DependencyDagError, "DEPENDENCY_DAG_BUILD_CYCLE"):
                validate_dag(path)


if __name__ == "__main__":
    unittest.main()
