#!/usr/bin/env python3
"""Create a deterministic, coexistent release revision and stable traffic switch plan."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from python.production_gates.blue_green_stack import materialize_blue_green_stack


def _new_output(path: Path, payload: str) -> None:
    if (
        not path.is_absolute()
        or path.exists()
        or path.is_symlink()
        or path.resolve() != path
        or not path.parent.is_dir()
        or path.parent.is_symlink()
    ):
        raise RuntimeError("BLUE_GREEN_STACK_OUTPUT_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="materialize-production-blue-green-stack")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if (
        not args.input.is_absolute()
        or args.input.is_symlink()
        or args.input.resolve() != args.input
        or not args.input.is_file()
        or not 1 <= args.input.stat(follow_symlinks=False).st_size <= 32 * 1024 * 1024
    ):
        raise RuntimeError("BLUE_GREEN_STACK_INPUT_INVALID")
    rendered, plan = materialize_blue_green_stack(
        args.input.read_text(encoding="utf-8"),
        release_id=args.release_id,
        release_digest=args.release_digest,
    )
    _new_output(args.output, rendered)
    _new_output(args.plan_output, json.dumps(plan, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "external_actions_executed": False,
        "output": str(args.output),
        "plan_output": str(args.plan_output),
        "revision": plan["revision"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
