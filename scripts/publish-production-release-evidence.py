#!/usr/bin/env python3
"""Publish or reverify the immutable runtime layout for a positive bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from python.production_gates.evidence_publication import (
    publish_verified_evidence,
    verify_published_evidence,
)
from python.production_gates.live_integrations import GateError
from python.production_gates.qualification import QualificationTrustAnchors


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _read(path: Path, code: str, *, limit: int = 64 * 1024 * 1024) -> object:
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


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--activation-expectation", type=Path, required=True)
    parser.add_argument("--git-provenance-keyring", type=Path, required=True)
    parser.add_argument("--release-binding-keyring", type=Path, required=True)
    parser.add_argument("--reviewer-keyring", type=Path, required=True)
    parser.add_argument("--worm-keyring", type=Path, required=True)
    parser.add_argument("--closure-public-key", type=Path, required=True)
    parser.add_argument("--revocation-public-key", type=Path, required=True)
    parser.add_argument("--revocation-checkpoint", type=Path, required=True)
    parser.add_argument("--volume-name", required=True)


def _inputs(args: argparse.Namespace) -> tuple[object, ...]:
    anchors = QualificationTrustAnchors(
        git_provenance_keyring=_read(
            args.git_provenance_keyring, "EVIDENCE_PUBLICATION_GIT_KEYRING_INVALID"
        ),
        release_binding_keyring=_read(
            args.release_binding_keyring,
            "EVIDENCE_PUBLICATION_RELEASE_KEYRING_INVALID",
        ),
        reviewer_keyring=_read(
            args.reviewer_keyring, "EVIDENCE_PUBLICATION_REVIEWER_KEYRING_INVALID"
        ),
        worm_keyring=_read(
            args.worm_keyring, "EVIDENCE_PUBLICATION_WORM_KEYRING_INVALID"
        ),
    )
    return (
        _read(args.manifest, "EVIDENCE_PUBLICATION_MANIFEST_INVALID"),
        _read(args.activation, "EVIDENCE_PUBLICATION_ACTIVATION_INVALID"),
        _read(
            args.activation_expectation,
            "EVIDENCE_PUBLICATION_EXPECTATION_INVALID",
        ),
        anchors,
        _read(
            args.closure_public_key,
            "EVIDENCE_PUBLICATION_CLOSURE_KEY_INVALID",
            limit=64 * 1024,
        ),
        _read(
            args.revocation_public_key,
            "EVIDENCE_PUBLICATION_REVOCATION_KEY_INVALID",
            limit=64 * 1024,
        ),
        _read(
            args.revocation_checkpoint,
            "EVIDENCE_PUBLICATION_REVOCATION_CHECKPOINT_INVALID",
            limit=64 * 1024,
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="publish-production-release-evidence")
    commands = parser.add_subparsers(dest="command", required=True)
    publish = commands.add_parser("publish")
    verify = commands.add_parser("verify")
    for command in (publish, verify):
        _common(command)
    publish.add_argument("--publication-root", type=Path, required=True)
    verify.add_argument("--publication-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    (
        manifest,
        activation,
        expectation,
        anchors,
        closure_key,
        revocation_key,
        revocation_checkpoint,
    ) = _inputs(args)
    common = (
        args.bundle_root,
        manifest,
        activation,
        expectation,
        anchors,
        closure_key,
        revocation_key,
        revocation_checkpoint,
    )
    if args.command == "publish":
        directory, receipt = publish_verified_evidence(
            *common,
            args.publication_root,
            volume_name=args.volume_name,
        )
    else:
        directory = args.publication_directory
        receipt = verify_published_evidence(
            *common,
            directory,
            volume_name=args.volume_name,
        )
    print(
        json.dumps(
            {
                "evidence_bundle_manifest_digest": receipt[
                    "evidence_bundle_manifest_digest"
                ],
                "publication_directory": str(directory),
                "publication_receipt": str(directory / "publication-receipt.json"),
                "release_id": receipt["release_id"],
                "verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
