#!/usr/bin/env python3
"""Validate checked-in JSON assets and critical fail-closed configuration invariants."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def load(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"RUNTIME_ASSET_INVALID:{path.relative_to(ROOT)}") from error


def main() -> int:
    paths = sorted((ROOT / "schemas").rglob("*.json"))
    paths += sorted((ROOT / "config").rglob("*.json"))
    paths += sorted((ROOT / "conformance-tests").rglob("*.json"))
    paths += sorted((ROOT / "dlp").rglob("*.json"))
    if not paths:
        raise RuntimeError("RUNTIME_ASSET_SET_EMPTY")
    for path in paths:
        value = load(path)
        if not isinstance(value, dict):
            raise RuntimeError(f"RUNTIME_ASSET_NOT_OBJECT:{path.relative_to(ROOT)}")
        if path.is_relative_to(ROOT / "config"):
            version = value.get("schema_version")
            if not isinstance(version, str) or not version.startswith("agenttrust."):
                raise RuntimeError(f"RUNTIME_CONFIG_SCHEMA_MISSING:{path.relative_to(ROOT)}")
            if path.name.endswith("production.json") and value.get("fail_closed") is not True:
                raise RuntimeError(f"PRODUCTION_CONFIG_NOT_FAIL_CLOSED:{path.relative_to(ROOT)}")
    offline = load(ROOT / "config/data-governance/offline.production.json")
    if (
        offline.get("mode") != "OFFLINE"
        or offline.get("allowed_external_endpoints") != []
        or offline.get("telemetry_export") is not False
    ):
        raise RuntimeError("OFFLINE_PROFILE_HAS_EGRESS")
    print(f"validated {len(paths)} runtime JSON assets")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
