#!/usr/bin/env python3
"""Build production images only from immutable base images and an immutable output tag."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
from typing import Sequence


_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_OUTPUT = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class BuildConfigurationError(RuntimeError):
    pass


def command_for(component: str, output_image: str, bases: Sequence[str], root: Path) -> list[str]:
    if not _OUTPUT.fullmatch(output_image) or any(not _IMAGE.fullmatch(image) for image in bases):
        raise BuildConfigurationError("PRODUCTION_IMAGE_CONFIGURATION_INVALID")
    if component == "runtime" and len(bases) == 2:
        dockerfile = root / "Dockerfile.production-runtime"
        arguments = ["--build-arg", f"RUST_BUILDER_IMAGE={bases[0]}",
                     "--build-arg", f"RUNTIME_BASE_IMAGE={bases[1]}"]
    elif component == "orchestrator" and len(bases) == 1:
        dockerfile = root / "Dockerfile.orchestrator"
        arguments = ["--build-arg", f"PYTHON_BASE_IMAGE={bases[0]}"]
    else:
        raise BuildConfigurationError("PRODUCTION_IMAGE_COMPONENT_INVALID")
    if not dockerfile.is_file():
        raise BuildConfigurationError("PRODUCTION_IMAGE_DOCKERFILE_MISSING")
    return ["docker", "build", "--pull=false", "--file", str(dockerfile),
            *arguments, "--tag", output_image, str(root)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build-production-image")
    parser.add_argument("--component", choices=("runtime", "orchestrator"), required=True)
    parser.add_argument("--output-image", required=True)
    parser.add_argument("--base-image", action="append", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    command = command_for(args.component, args.output_image, args.base_image, root)
    subprocess.run(command, check=True, cwd=root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
