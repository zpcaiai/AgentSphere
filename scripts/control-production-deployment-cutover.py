#!/usr/bin/env python3
"""Prepare and verify externally signed production deployment control receipts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from python.production_gates.deployment_cutover import (
    finalize_external_signature,
    prepare_signing_request,
    validate_blue_green_inventory,
    verify_signed_receipt,
    verify_transition_chain,
)
from python.production_gates.live_integrations import GateError


def _duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GateError("DEPLOYMENT_CUTOVER_INPUT_DUPLICATE_KEY")
        result[key] = value
    return result


def _read(path: Path) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError("DEPLOYMENT_CUTOVER_INPUT_PATH_INVALID")
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_nlink != 1 or not 1 <= metadata.st_size <= 16 * 1024 * 1024:
        raise GateError("DEPLOYMENT_CUTOVER_INPUT_PATH_INVALID")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_duplicates)
    except GateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError("DEPLOYMENT_CUTOVER_INPUT_INVALID") from None


def _write(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise GateError("DEPLOYMENT_CUTOVER_OUTPUT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="control-production-deployment-cutover")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare-signing")
    prepare.add_argument(
        "--kind", choices=["WRITER_FENCE", "CUTOVER", "ROLLBACK", "UNFREEZE"], required=True
    )
    prepare.add_argument("--document", type=Path, required=True)
    prepare.add_argument("--key-id", required=True)
    prepare.add_argument("--output", type=Path, required=True)

    finalize = subparsers.add_parser("finalize-signing")
    finalize.add_argument("--request", type=Path, required=True)
    finalize.add_argument("--external-signature", type=Path, required=True)
    finalize.add_argument("--keyring", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify-receipt")
    verify.add_argument(
        "--kind", choices=["WRITER_FENCE", "CUTOVER", "ROLLBACK", "UNFREEZE"], required=True
    )
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--keyring", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)

    inventory = subparsers.add_parser("verify-inventory")
    inventory.add_argument("--inventory", type=Path, required=True)
    inventory.add_argument("--output", type=Path, required=True)

    chain = subparsers.add_parser("verify-chain")
    chain.add_argument("--writer-fence", type=Path, required=True)
    chain.add_argument("--inventory", type=Path, action="append", required=True)
    chain.add_argument("--transition", type=Path, action="append", required=True)
    chain.add_argument("--keyring", type=Path, required=True)
    chain.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "prepare-signing":
        result = prepare_signing_request(
            _read(args.document), document_kind=args.kind, key_id=args.key_id
        )
    elif args.command == "finalize-signing":
        result = finalize_external_signature(
            _read(args.request), _read(args.external_signature), _read(args.keyring)
        )
    elif args.command == "verify-receipt":
        result = verify_signed_receipt(
            _read(args.receipt), _read(args.keyring), expected_kind=args.kind
        )
    elif args.command == "verify-inventory":
        result = validate_blue_green_inventory(_read(args.inventory))
    elif args.command == "verify-chain":
        result = verify_transition_chain(
            _read(args.writer_fence),
            [_read(path) for path in args.inventory],
            [_read(path) for path in args.transition],
            _read(args.keyring),
        )
    else:  # pragma: no cover - argparse rejects this branch.
        raise GateError("DEPLOYMENT_CUTOVER_COMMAND_INVALID")
    _write(args.output, result)
    print(json.dumps({
        "command": args.command,
        "external_actions_executed": False,
        "output": str(args.output),
        "verified": args.command.startswith("verify-"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
