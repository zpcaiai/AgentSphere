#!/usr/bin/env python3
"""Compile trusted production evidence into the only accepted ClosureInput."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from python.production_gates.live_integrations import GateError
from python.production_gates.qualification import (
    QualificationTrustAnchors,
    compile_qualification,
)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _read_json(path: Path, code: str) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError(code)
    try:
        if not 1 <= path.stat().st_size <= 64 * 1024 * 1024:
            raise GateError(code)
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError(code) from None


def _write_new(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise GateError("QUALIFICATION_OUTPUT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="compile-production-qualification")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--git-provenance-keyring", type=Path, required=True)
    parser.add_argument("--release-binding-keyring", type=Path, required=True)
    parser.add_argument("--reviewer-keyring", type=Path, required=True)
    parser.add_argument("--worm-keyring", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    anchors = QualificationTrustAnchors(
        git_provenance_keyring=_read_json(
            args.git_provenance_keyring, "QUALIFICATION_GIT_KEYRING_INVALID"
        ),
        release_binding_keyring=_read_json(
            args.release_binding_keyring, "QUALIFICATION_RELEASE_KEYRING_INVALID"
        ),
        reviewer_keyring=_read_json(
            args.reviewer_keyring, "QUALIFICATION_REVIEWER_KEYRING_INVALID"
        ),
        worm_keyring=_read_json(args.worm_keyring, "QUALIFICATION_WORM_KEYRING_INVALID"),
    )
    closure_input = compile_qualification(
        _read_json(args.input, "QUALIFICATION_INPUT_INVALID"), anchors
    )
    _write_new(args.output, closure_input)
    print(json.dumps({
        "release_id": closure_input["scope"]["release_id"],
        "batch_evidence_verified": len(closure_input["batch_statuses"]),
        "gate_evidence_verified": len(closure_input["gate_evidence"]),
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
