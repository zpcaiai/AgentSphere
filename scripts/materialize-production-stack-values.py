#!/usr/bin/env python3
"""Create final deployment values from signed static values and activation."""

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
from python.production_gates.release_values import materialize_production_stack_values


def _read(path: Path, code: str) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError(code)
    try:
        if not 1 <= path.stat().st_size <= 64 * 1024 * 1024:
            raise GateError(code)
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(code) from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="materialize-production-stack-values")
    parser.add_argument("--release-binding", type=Path, required=True)
    parser.add_argument("--release-binding-keyring", type=Path, required=True)
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.output.is_absolute() or args.output.exists() or not args.output.parent.is_dir():
        raise GateError("PRODUCTION_VALUES_OUTPUT_INVALID")
    values = materialize_production_stack_values(
        _read(args.release_binding, "PRODUCTION_VALUES_RELEASE_BINDING_INVALID"),
        _read(args.release_binding_keyring, "PRODUCTION_VALUES_KEYRING_INVALID"),
        _read(args.activation, "PRODUCTION_VALUES_ACTIVATION_INVALID"),
    )
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(values, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({
        "evidence_bundle_manifest_digest": values["evidence"]["bundle_digest"],
        "release_digest": values["release_digest"],
        "release_id": values["release_id"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
