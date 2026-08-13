#!/usr/bin/env python3
"""Render the production runtime manifest with immutable, explicit inputs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from typing import Sequence


_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RenderError(RuntimeError):
    pass


def render(template: str, runtime_image: str, envoy_image: str, release_id: str) -> str:
    if not _IMAGE.fullmatch(runtime_image) or not _IMAGE.fullmatch(envoy_image):
        raise RenderError("PRODUCTION_DEPLOYMENT_IMAGE_NOT_IMMUTABLE")
    if not _RELEASE.fullmatch(release_id) or release_id == "WORKTREE-NO-GIT":
        raise RenderError("PRODUCTION_DEPLOYMENT_RELEASE_ID_INVALID")
    expected = {"@@PRODUCTION_RUNTIME_IMAGE@@", "@@ENVOY_IMAGE@@", "@@RELEASE_ID@@"}
    present = {token for token in expected if token in template}
    if present != expected:
        raise RenderError("PRODUCTION_DEPLOYMENT_TEMPLATE_INVALID")
    result = (
        template.replace("@@PRODUCTION_RUNTIME_IMAGE@@", runtime_image)
        .replace("@@ENVOY_IMAGE@@", envoy_image)
        .replace("@@RELEASE_ID@@", release_id)
    )
    if "@@" in result:
        raise RenderError("PRODUCTION_DEPLOYMENT_TEMPLATE_UNRESOLVED")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="render-production-runtime")
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--envoy-image", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.template.is_file() or not args.output.is_absolute() or args.output.exists():
        raise RenderError("PRODUCTION_DEPLOYMENT_PATH_INVALID")
    rendered = render(
        args.template.read_text(encoding="utf-8"), args.runtime_image,
        args.envoy_image, args.release_id,
    )
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
