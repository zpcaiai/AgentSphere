#!/usr/bin/env python3
"""Generate or verify the offline production-runner Python manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

from python.production_gates.live_integrations import GateError
from python.production_gates.runner_runtime import (
    DEFAULT_REQUIRED_DISTRIBUTIONS,
    verify_runtime,
    write_runtime_manifest,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--requirements-lock", type=Path, required=True)
    generate.add_argument(
        "--required-distribution",
        action="append",
        default=list(DEFAULT_REQUIRED_DISTRIBUTIONS),
    )
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--manifest-sha256", required=True)
    verify.add_argument("--python-sha256", required=True)
    verify.add_argument("--requirements-lock", type=Path, required=True)
    verify.add_argument(
        "--required-distribution",
        action="append",
        default=list(DEFAULT_REQUIRED_DISTRIBUTIONS),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "generate":
            digest = write_runtime_manifest(
                arguments.output,
                requirements_lock=arguments.requirements_lock,
                required_distributions=arguments.required_distribution,
            )
            print(digest)
        else:
            verify_runtime(
                arguments.manifest,
                manifest_sha256=arguments.manifest_sha256,
                python_sha256=arguments.python_sha256,
                requirements_lock=arguments.requirements_lock,
                required_distributions=arguments.required_distribution,
            )
    except GateError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
