#!/usr/bin/env python3
"""Build production images only from immutable base images and an immutable output tag."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import re
import subprocess
from typing import Sequence
from urllib.parse import urlparse


_NAME_PART = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
_IMAGE = re.compile(
    rf"^{_NAME_PART}(?::[0-9]+)?(?:/{_NAME_PART})*@sha256:[0-9a-f]{{64}}$"
)
_OUTPUT = re.compile(
    rf"^{_NAME_PART}(?::[0-9]+)?(?:/{_NAME_PART})*:[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}$"
)


class BuildConfigurationError(RuntimeError):
    pass


def command_for(
    component: str,
    output_image: str,
    bases: Sequence[str],
    root: Path,
    *,
    control_api_url: str | None = None,
    agui_verify_key: str | None = None,
) -> list[str]:
    if not _OUTPUT.fullmatch(output_image) or any(not _IMAGE.fullmatch(image) for image in bases):
        raise BuildConfigurationError("PRODUCTION_IMAGE_CONFIGURATION_INVALID")
    if component == "runtime" and len(bases) == 2:
        dockerfile = root / "Dockerfile.production-runtime"
        arguments = ["--build-arg", f"RUST_BUILDER_IMAGE={bases[0]}",
                     "--build-arg", f"RUNTIME_BASE_IMAGE={bases[1]}"]
    elif component == "orchestrator" and len(bases) == 1:
        dockerfile = root / "Dockerfile.orchestrator"
        arguments = ["--build-arg", f"PYTHON_BASE_IMAGE={bases[0]}"]
    elif component == "transition" and len(bases) == 2:
        dockerfile = root / "Dockerfile.transition"
        arguments = ["--build-arg", f"RUST_BUILDER_IMAGE={bases[0]}",
                     "--build-arg", f"RUNTIME_BASE_IMAGE={bases[1]}"]
    elif component == "execution" and len(bases) == 2:
        dockerfile = root / "Dockerfile.execution"
        arguments = ["--build-arg", f"RUST_BUILDER_IMAGE={bases[0]}",
                     "--build-arg", f"RUNTIME_BASE_IMAGE={bases[1]}"]
    elif component == "enterprise-control" and len(bases) == 2:
        dockerfile = root / "Dockerfile.enterprise-control"
        arguments = ["--build-arg", f"MAVEN_BUILDER_IMAGE={bases[0]}",
                     "--build-arg", f"JAVA_RUNTIME_IMAGE={bases[1]}"]
    elif (
        component == "console" and len(bases) == 2 and _valid_https(control_api_url)
        and _valid_ed25519_key(agui_verify_key)
    ):
        dockerfile = root / "Dockerfile.console"
        arguments = ["--build-arg", f"NODE_BUILDER_IMAGE={bases[0]}",
                     "--build-arg", f"CONSOLE_BASE_IMAGE={bases[1]}",
                     "--build-arg", f"VITE_CONTROL_API_URL={control_api_url}",
                     "--build-arg", f"VITE_AGUI_VERIFY_KEY={agui_verify_key}"]
    elif component == "migrations" and len(bases) == 1:
        dockerfile = root / "Dockerfile.migrations"
        arguments = ["--build-arg", f"POSTGRES_CLIENT_IMAGE={bases[0]}"]
    else:
        raise BuildConfigurationError("PRODUCTION_IMAGE_COMPONENT_INVALID")
    if not dockerfile.is_file():
        raise BuildConfigurationError("PRODUCTION_IMAGE_DOCKERFILE_MISSING")
    return ["docker", "build", "--pull=false", "--file", str(dockerfile),
            *arguments, "--tag", output_image, str(root)]


def _valid_https(value: str | None) -> bool:
    if not value:
        return False
    if value != value.strip() or any(character in value for character in "\"'|\\\t\r\n"):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https" and bool(parsed.hostname)
        and parsed.username is None and parsed.password is None
        and parsed.query == "" and parsed.fragment == ""
        and (port is None or 1 <= port <= 65535)
        and not any(character.isspace() for character in value)
    )


def _valid_ed25519_key(value: str | None) -> bool:
    if value is None or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        return False
    return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build-production-image")
    parser.add_argument("--component", choices=(
        "runtime", "orchestrator", "transition", "execution", "enterprise-control", "console",
        "migrations",
    ), required=True)
    parser.add_argument("--output-image", required=True)
    parser.add_argument("--base-image", action="append", required=True)
    parser.add_argument("--control-api-url")
    parser.add_argument("--agui-verify-key")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    command = command_for(
        args.component, args.output_image, args.base_image, root,
        control_api_url=args.control_api_url, agui_verify_key=args.agui_verify_key,
    )
    subprocess.run(command, check=True, cwd=root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
