#!/usr/bin/env python3
"""Build or verify a positive production evidence bundle manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from python.production_gates.live_integrations import GateError
from python.production_gates.production_evidence_bundle import (
    REQUIRED_ARTIFACT_ROLES,
    build_manifest,
    verify_bundle,
    write_new_json,
)
from python.production_gates.qualification import QualificationTrustAnchors


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _read_json(path: Path, code: str, *, limit: int = 64 * 1024 * 1024) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError(code)
    try:
        if not 1 <= path.stat().st_size <= limit:
            raise GateError(code)
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError(code) from None


def _add_trust_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--git-provenance-keyring", type=Path, required=True)
    parser.add_argument("--release-binding-keyring", type=Path, required=True)
    parser.add_argument("--reviewer-keyring", type=Path, required=True)
    parser.add_argument("--worm-keyring", type=Path, required=True)
    parser.add_argument("--closure-public-key", type=Path, required=True)
    parser.add_argument("--revocation-public-key", type=Path, required=True)
    parser.add_argument("--revocation-checkpoint", type=Path, required=True)


def _anchors(
    args: argparse.Namespace,
) -> tuple[QualificationTrustAnchors, object, object, object]:
    anchors = QualificationTrustAnchors(
        git_provenance_keyring=_read_json(args.git_provenance_keyring, "BUNDLE_GIT_KEYRING_INVALID"),
        release_binding_keyring=_read_json(
            args.release_binding_keyring, "BUNDLE_RELEASE_KEYRING_INVALID"
        ),
        reviewer_keyring=_read_json(args.reviewer_keyring, "BUNDLE_REVIEWER_KEYRING_INVALID"),
        worm_keyring=_read_json(args.worm_keyring, "BUNDLE_WORM_KEYRING_INVALID"),
    )
    return (
        anchors,
        _read_json(args.closure_public_key, "BUNDLE_CLOSURE_KEY_INVALID", limit=64 * 1024),
        _read_json(
            args.revocation_public_key, "BUNDLE_REVOCATION_KEY_INVALID", limit=64 * 1024
        ),
        _read_json(
            args.revocation_checkpoint,
            "BUNDLE_REVOCATION_CHECKPOINT_INVALID",
            limit=64 * 1024,
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify-production-evidence-bundle")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    verify = commands.add_parser("verify")
    for command in (build, verify):
        command.add_argument("--bundle-root", type=Path, required=True)
        command.add_argument("--manifest", type=Path, required=True)
        _add_trust_arguments(command)
    for role in sorted(REQUIRED_ARTIFACT_ROLES):
        build.add_argument(f"--{role.replace('_', '-')}", type=Path, required=True)
    args = parser.parse_args(argv)
    anchors, closure_key, revocation_key, revocation_checkpoint = _anchors(args)
    if args.command == "build":
        paths = {
            role: getattr(args, role)
            for role in REQUIRED_ARTIFACT_ROLES
        }
        manifest = build_manifest(
            args.bundle_root,
            paths,
            anchors,
            closure_key,
            revocation_key,
            revocation_checkpoint,
        )
        write_new_json(args.manifest, manifest)
        result = verify_bundle(
            args.bundle_root,
            manifest,
            anchors,
            closure_key,
            revocation_key,
            revocation_checkpoint,
        )
    else:
        result = verify_bundle(
            args.bundle_root,
            _read_json(args.manifest, "PRODUCTION_BUNDLE_MANIFEST_INVALID"),
            anchors,
            closure_key,
            revocation_key,
            revocation_checkpoint,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
