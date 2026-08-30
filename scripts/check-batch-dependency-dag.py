#!/usr/bin/env python3
"""Validate the canonical batch DAG snapshots and their Skill metadata."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from python.production_gates.dependency_dag import (
    DependencyDagError,
    validate_repository_dags,
)


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    try:
        dag, paths = validate_repository_dags(ROOT)
    except DependencyDagError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "validated": True,
                "version": dag.version,
                "batch_count": len(dag.batches),
                "snapshot_count": len(paths),
                "build_order": list(dag.build_order),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
