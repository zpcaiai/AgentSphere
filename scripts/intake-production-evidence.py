#!/usr/bin/env python3
"""Validate and stage externally collected production qualification evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from python.production_gates.evidence_intake import validate_evidence_intake
from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.qualification import QualificationTrustAnchors
from python.production_gates.revocation_checkpoint import read_checkpoint


def _reject_duplicate_key(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise GateError("EVIDENCE_INTAKE_DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _read(path: Path, code: str, *, limit: int = 128 * 1024 * 1024) -> object:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GateError(code)
    try:
        if not 1 <= path.stat(follow_symlinks=False).st_size <= limit:
            raise GateError(code)
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_key,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError(code) from None


def _write_new(directory: Path, name: str, value: object) -> None:
    path = directory / name
    payload = canonical_json(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="intake-production-evidence")
    parser.add_argument("--qualification-input", type=Path, required=True)
    parser.add_argument("--candidate-image-manifest", type=Path, required=True)
    parser.add_argument("--runtime-config", type=Path, required=True)
    parser.add_argument("--revocation-update", type=Path, required=True)
    parser.add_argument("--revocation-checkpoint", type=Path, required=True)
    parser.add_argument("--previous-revocation-registry", type=Path)
    parser.add_argument("--git-provenance-keyring", type=Path, required=True)
    parser.add_argument("--release-binding-keyring", type=Path, required=True)
    parser.add_argument("--reviewer-keyring", type=Path, required=True)
    parser.add_argument("--worm-keyring", type=Path, required=True)
    parser.add_argument("--revocation-public-key", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)

    output = args.output_directory
    if not output.is_absolute() or output.exists() or not output.parent.is_dir():
        raise GateError("EVIDENCE_INTAKE_OUTPUT_INVALID")
    qualification = _read(args.qualification_input, "EVIDENCE_INTAKE_INPUT_INVALID")
    image_manifest = _read(
        args.candidate_image_manifest, "EVIDENCE_INTAKE_IMAGE_MANIFEST_INVALID"
    )
    runtime = _read(args.runtime_config, "EVIDENCE_INTAKE_RUNTIME_INVALID")
    revocation_update = _read(
        args.revocation_update, "EVIDENCE_INTAKE_REVOCATION_INVALID"
    )
    revocation_checkpoint = read_checkpoint(args.revocation_checkpoint)
    previous_revocation_registry = (
        _read(
            args.previous_revocation_registry,
            "EVIDENCE_INTAKE_PREVIOUS_REVOCATION_INVALID",
        )
        if args.previous_revocation_registry is not None
        else None
    )
    revocation_key = _read(
        args.revocation_public_key, "EVIDENCE_INTAKE_REVOCATION_KEY_INVALID", limit=64 * 1024
    )
    anchors = QualificationTrustAnchors(
        git_provenance_keyring=_read(
            args.git_provenance_keyring, "EVIDENCE_INTAKE_GIT_KEYRING_INVALID"
        ),
        release_binding_keyring=_read(
            args.release_binding_keyring, "EVIDENCE_INTAKE_RELEASE_KEYRING_INVALID"
        ),
        reviewer_keyring=_read(
            args.reviewer_keyring, "EVIDENCE_INTAKE_REVIEWER_KEYRING_INVALID"
        ),
        worm_keyring=_read(args.worm_keyring, "EVIDENCE_INTAKE_WORM_KEYRING_INVALID"),
    )
    closure_input, receipt = validate_evidence_intake(
        qualification,
        image_manifest,
        runtime,
        revocation_update,
        anchors,
        revocation_key,
        revocation_checkpoint=revocation_checkpoint,
        previous_revocation_registry=previous_revocation_registry,
        expected_release_tag=args.release_tag,
        expected_repository=args.repository,
    )
    output.mkdir(mode=0o700)
    staged = {
        "qualification-input.json": qualification,
        "production-image-manifest.json": image_manifest,
        "production-runtime.json": runtime,
        "revocation-update.json": revocation_update,
        "revocation-checkpoint.json": revocation_checkpoint,
        "closure-input.json": closure_input,
        "evidence-intake-receipt.json": receipt,
    }
    if previous_revocation_registry is not None:
        staged["previous-revocation-registry.json"] = previous_revocation_registry
    for name, value in staged.items():
        _write_new(output, name, value)
    descriptor = os.open(output, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({
        "closure_input_digest": receipt["closure_input_digest"],
        "output_directory": str(output),
        "release_id": receipt["release_id"],
        "verified": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
