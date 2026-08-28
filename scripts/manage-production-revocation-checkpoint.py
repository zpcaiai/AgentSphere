#!/usr/bin/env python3
"""Initialize, validate, or atomically advance the production revocation checkpoint."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

from python.production_gates.live_integrations import GateError
from python.production_gates.revocation_checkpoint import (
    advance_checkpoint_file,
    initialize_checkpoint_file,
    read_checkpoint,
    verify_base_registry,
    verify_successor,
)


def _json(path: Path) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError("REVOCATION_CHECKPOINT_INPUT_INVALID")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError("REVOCATION_CHECKPOINT_INPUT_INVALID") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("initialize")
    initialize.add_argument("--checkpoint", type=Path, required=True)
    initialize.add_argument("--lock-file", type=Path, required=True)
    initialize.add_argument("--registry-id", required=True)
    initialize.add_argument("--key-id", required=True)
    base = commands.add_parser("verify-base")
    base.add_argument("--checkpoint", type=Path, required=True)
    base.add_argument("--previous-registry", type=Path)
    base.add_argument("--revocation-key", type=Path, required=True)
    successor = commands.add_parser("verify-successor")
    successor.add_argument("--checkpoint", type=Path, required=True)
    successor.add_argument("--registry", type=Path, required=True)
    successor.add_argument("--revocation-key", type=Path, required=True)
    advance = commands.add_parser("advance")
    advance.add_argument("--checkpoint", type=Path, required=True)
    advance.add_argument("--lock-file", type=Path, required=True)
    advance.add_argument("--registry", type=Path, required=True)
    advance.add_argument("--revocation-key", type=Path, required=True)
    advance.add_argument("--activation-receipt", type=Path, required=True)
    advance.add_argument("--expected-checkpoint-digest", required=True)
    advance.add_argument("--receipt-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "initialize":
            result = initialize_checkpoint_file(
                arguments.checkpoint,
                arguments.lock_file,
                registry_id=arguments.registry_id,
                key_id=arguments.key_id,
            )
        elif arguments.command == "verify-base":
            checkpoint = read_checkpoint(arguments.checkpoint)
            previous = (
                _json(arguments.previous_registry)
                if arguments.previous_registry is not None
                else None
            )
            result = dict(
                verify_base_registry(
                    checkpoint, previous, _json(arguments.revocation_key)
                )
            )
        elif arguments.command == "verify-successor":
            checkpoint, registry, digest = verify_successor(
                read_checkpoint(arguments.checkpoint),
                _json(arguments.registry),
                _json(arguments.revocation_key),
            )
            result = {
                "checkpoint_digest": checkpoint["checkpoint_digest"],
                "registry_digest": digest,
                "registry_id": registry["registry_id"],
                "sequence": registry["sequence"],
                "verified": True,
            }
        else:
            _, result = advance_checkpoint_file(
                arguments.checkpoint,
                arguments.lock_file,
                _json(arguments.registry),
                _json(arguments.revocation_key),
                _json(arguments.activation_receipt),
                expected_checkpoint_digest=arguments.expected_checkpoint_digest,
            )
            raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
            if (
                not arguments.receipt_output.is_absolute()
                or arguments.receipt_output.exists()
                or arguments.receipt_output.is_symlink()
            ):
                raise GateError("REVOCATION_CHECKPOINT_OUTPUT_INVALID")
            descriptor = os.open(
                arguments.receipt_output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except GateError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
