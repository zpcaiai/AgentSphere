#!/usr/bin/env python3
"""Synchronize the checked-in non-certificate evidence artifact digests."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from python.production_gates.release_code_manifest import (
    ReleaseCodeManifestError,
    load_release_code_manifest,
    repository_file_sha256,
)


MANIFEST = ROOT / "evidence/production-closure/evidence-bundle-manifest.json"
_FIELDS = {
    "schema_version",
    "release_id",
    "generated_at",
    "artifacts",
    "offline_verification_required",
    "production_certificate_included",
}
_ENTRY_FIELDS = {"path", "sha256"}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class SyncError(RuntimeError):
    pass


def _reject_duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SyncError(f"EVIDENCE_MANIFEST_DUPLICATE_JSON_KEY:{key}")
        value[key] = item
    return value


def _read_manifest() -> dict[str, object]:
    if (
        MANIFEST.is_symlink()
        or not MANIFEST.is_file()
        or not 1 <= MANIFEST.stat(follow_symlinks=False).st_size <= 16 * 1024 * 1024
    ):
        raise SyncError("EVIDENCE_MANIFEST_INVALID")
    try:
        value = json.loads(
            MANIFEST.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_key,
        )
    except SyncError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SyncError("EVIDENCE_MANIFEST_INVALID") from None
    if (
        not isinstance(value, dict)
        or set(value) != _FIELDS
        or value.get("schema_version") != "agenttrust.closure-evidence-bundle.v1"
        or value.get("release_id") != "WORKTREE-NO-GIT"
        or value.get("offline_verification_required") is not True
        or value.get("production_certificate_included") is not False
    ):
        raise SyncError("EVIDENCE_MANIFEST_NON_CERTIFICATE_TRUTH_INVALID")
    return value


def _existing_paths(value: object) -> set[str]:
    if not isinstance(value, list) or not value:
        raise SyncError("EVIDENCE_MANIFEST_ARTIFACTS_INVALID")
    paths: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict) or set(artifact) != _ENTRY_FIELDS:
            raise SyncError("EVIDENCE_MANIFEST_ARTIFACTS_INVALID")
        relative = artifact.get("path")
        digest = artifact.get("sha256")
        if (
            not isinstance(relative, str)
            or relative in paths
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
        ):
            raise SyncError("EVIDENCE_MANIFEST_ARTIFACTS_INVALID")
        paths.add(relative)
    return paths


def _sha256(relative: str) -> str:
    try:
        return repository_file_sha256(ROOT, relative)
    except ReleaseCodeManifestError:
        raise SyncError(f"EVIDENCE_MANIFEST_SOURCE_INVALID:{relative}") from None


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        raise SyncError("EVIDENCE_MANIFEST_GENERATED_AT_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SyncError("EVIDENCE_MANIFEST_GENERATED_AT_INVALID")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_write(value: object) -> None:
    payload = (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    ).encode("utf-8")
    temporary = MANIFEST.with_name(f".{MANIFEST.name}.{os.getpid()}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644, follow_symlinks=False)
        os.replace(temporary, MANIFEST)
        directory = os.open(MANIFEST.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise SyncError("EVIDENCE_MANIFEST_WRITE_FAILED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sync-closure-evidence-manifest")
    parser.add_argument("--generated-at")
    args = parser.parse_args(argv)
    manifest = _read_manifest()
    try:
        release_code = set(load_release_code_manifest(ROOT))
    except ReleaseCodeManifestError:
        raise SyncError("EVIDENCE_MANIFEST_RELEASE_CODE_INVALID") from None
    paths = _existing_paths(manifest.get("artifacts")) | release_code
    manifest["generated_at"] = _timestamp(args.generated_at)
    manifest["artifacts"] = [
        {"path": relative, "sha256": _sha256(relative)}
        for relative in sorted(paths)
    ]
    _atomic_write(manifest)
    print(f"synchronized {len(paths)} non-certificate evidence artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
