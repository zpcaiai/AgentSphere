#!/usr/bin/env python3
"""Offline verifier for the checked-in production-closure evidence bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence/production-closure/evidence-bundle-manifest.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "agenttrust.closure-evidence-bundle.v1":
        raise RuntimeError("EVIDENCE_BUNDLE_SCHEMA_UNSUPPORTED")
    seen: set[str] = set()
    for artifact in manifest.get("artifacts", []):
        relative = artifact.get("path", "")
        expected = artifact.get("sha256", "")
        path = (ROOT / relative).resolve()
        if (
            not relative
            or relative in seen
            or not path.is_relative_to(ROOT)
            or len(expected) != 64
            or not path.is_file()
        ):
            raise RuntimeError("EVIDENCE_BUNDLE_ENTRY_INVALID")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"EVIDENCE_BUNDLE_DIGEST_MISMATCH:{relative}")
        seen.add(relative)
    if not seen:
        raise RuntimeError("EVIDENCE_BUNDLE_EMPTY")
    print(f"verified {len(seen)} closure evidence artifacts; production certificate included=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
