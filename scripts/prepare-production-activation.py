#!/usr/bin/env python3
"""Prepare Python renderer activation and Rust admission expectation files."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from python.production_gates.live_integrations import GateError
from python.production_gates.release_preparation import prepare_activation_documents


def _read(path: Path) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError("PRODUCTION_ACTIVATION_INPUT_PATH_INVALID")
    try:
        if not 1 <= path.stat().st_size <= 64 * 1024 * 1024:
            raise GateError("PRODUCTION_ACTIVATION_INPUT_PATH_INVALID")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError("PRODUCTION_ACTIVATION_INPUT_INVALID") from None


def _write(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or not path.parent.is_dir():
        raise GateError("PRODUCTION_ACTIVATION_OUTPUT_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="prepare-production-activation")
    parser.add_argument("--closure-input", type=Path, required=True)
    parser.add_argument("--image-manifest", type=Path, required=True)
    parser.add_argument("--evidence-manifest", type=Path, required=True)
    parser.add_argument("--release-binding", type=Path, required=True)
    parser.add_argument("--activation-output", type=Path, required=True)
    parser.add_argument("--expectation-output", type=Path, required=True)
    args = parser.parse_args(argv)
    activation, expectation = prepare_activation_documents(
        _read(args.closure_input),
        _read(args.image_manifest),
        _read(args.evidence_manifest),
        _read(args.release_binding),
    )
    _write(args.activation_output, activation)
    _write(args.expectation_output, expectation)
    print(json.dumps({
        "evidence_bundle_manifest_digest": activation["evidence_bundle_manifest_digest"],
        "image_manifest_digest": expectation["build_digest"],
        "release_id": activation["release_id"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
