#!/usr/bin/env python3
"""Assemble an exact, attested image set for one immutable Git release."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from python.production_gates.git_provenance import canonical_json


SCHEMA_VERSION = "agenttrust.production-image-manifest.v1"
IMAGE_KEYS = frozenset({
    "runtime", "orchestrator", "transition", "execution", "registry",
    "agent_registry", "policy_admin", "incident_release", "pack_marketplace",
    "approval", "pep", "identity", "tool_proxy", "evidence", "audit",
    "enterprise", "enterprise_authority", "model_gateway", "data_governance",
    "context_governance", "runtime_anomaly", "security_evaluation",
    "pack_supply_chain", "domain_runtime", "platform_sre", "console",
    "migration", "envoy", "utility", "release_admission", "sandbox_worker",
})

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_URL = re.compile(r"^https://[^\s]+$")
_RECORD_FIELDS = {
    "schema_version", "image_key", "component", "release_id", "release_tag",
    "image", "subject_digest", "sbom_sha256", "provenance_attestation_url",
    "sbom_attestation_url",
}
_MANIFEST_FIELDS = {
    "schema_version", "release_id", "release_tag", "repository", "created_at",
    "images", "attestations", "manifest_digest",
}
_ATTESTATION_FIELDS = {
    "component", "subject_digest", "sbom_sha256",
    "provenance_attestation_url", "sbom_attestation_url",
}


class ManifestError(RuntimeError):
    pass


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _read_record(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= 64 * 1024:
        raise ManifestError("PRODUCTION_IMAGE_RECORD_INVALID")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ManifestError("PRODUCTION_IMAGE_RECORD_INVALID") from None
    if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
        raise ManifestError("PRODUCTION_IMAGE_RECORD_INVALID")
    return value


def assemble(
    records_directory: Path,
    *,
    release_id: str,
    release_tag: str,
    repository: str,
    created_at: datetime | None = None,
) -> dict[str, object]:
    root = records_directory.resolve()
    if (
        not records_directory.is_absolute()
        or not root.is_dir()
        or not _RELEASE_ID.fullmatch(release_id)
        or not _TAG.fullmatch(release_tag)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository)
    ):
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_INPUT_INVALID")
    timestamp = created_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_TIME_INVALID")

    records: dict[str, Mapping[str, Any]] = {}
    paths = sorted(root.glob("*.json"))
    if len(paths) != len(IMAGE_KEYS):
        raise ManifestError("PRODUCTION_IMAGE_SET_INCOMPLETE")
    for path in paths:
        record = _read_record(path)
        image_key = record.get("image_key")
        digest = record.get("subject_digest")
        image = record.get("image")
        if (
            record.get("schema_version") != "agenttrust.production-image-record.v1"
            or not isinstance(image_key, str)
            or image_key not in IMAGE_KEYS
            or image_key in records
            or record.get("release_id") != release_id
            or record.get("release_tag") != release_tag
            or not isinstance(record.get("component"), str)
            or not record["component"]
            or not isinstance(image, str)
            or not _IMAGE.fullmatch(image)
            or not isinstance(digest, str)
            or not _OCI_DIGEST.fullmatch(digest)
            or not image.endswith("@" + digest)
            or not isinstance(record.get("sbom_sha256"), str)
            or not _DIGEST.fullmatch(str(record["sbom_sha256"]))
            or not isinstance(record.get("provenance_attestation_url"), str)
            or not _URL.fullmatch(str(record["provenance_attestation_url"]))
            or not isinstance(record.get("sbom_attestation_url"), str)
            or not _URL.fullmatch(str(record["sbom_attestation_url"]))
        ):
            raise ManifestError("PRODUCTION_IMAGE_RECORD_INVALID")
        records[image_key] = record
    if set(records) != IMAGE_KEYS:
        raise ManifestError("PRODUCTION_IMAGE_SET_INCOMPLETE")

    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "release_id": release_id,
        "release_tag": release_tag,
        "repository": repository,
        "created_at": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "images": {key: records[key]["image"] for key in sorted(records)},
        "attestations": {
            key: {
                "component": records[key]["component"],
                "subject_digest": records[key]["subject_digest"],
                "sbom_sha256": records[key]["sbom_sha256"],
                "provenance_attestation_url": records[key]["provenance_attestation_url"],
                "sbom_attestation_url": records[key]["sbom_attestation_url"],
            }
            for key in sorted(records)
        },
    }
    manifest["manifest_digest"] = _digest(manifest)
    return manifest


def verify_manifest(
    value: object,
    *,
    release_id: str,
    release_tag: str,
    repository: str,
    now: datetime | None = None,
) -> dict[str, object]:
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() != timezone.utc.utcoffset(current_time):
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_TIME_INVALID")
    if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_INVALID")
    images = value.get("images")
    attestations = value.get("attestations")
    claimed_digest = value.get("manifest_digest")
    unsigned = dict(value)
    unsigned.pop("manifest_digest", None)
    try:
        created_at = datetime.fromisoformat(str(value.get("created_at")).replace("Z", "+00:00"))
    except ValueError:
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_INVALID") from None
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("release_id") != release_id
        or value.get("release_tag") != release_tag
        or value.get("repository") != repository
        or created_at.tzinfo is None
        or created_at.utcoffset() != timezone.utc.utcoffset(created_at)
        or created_at > current_time
        or not isinstance(claimed_digest, str)
        or not _DIGEST.fullmatch(claimed_digest)
        or claimed_digest != _digest(unsigned)
        or not isinstance(images, dict)
        or set(images) != IMAGE_KEYS
        or not isinstance(attestations, dict)
        or set(attestations) != IMAGE_KEYS
    ):
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_INVALID")
    for key in IMAGE_KEYS:
        image = images[key]
        attestation = attestations[key]
        if (
            not isinstance(image, str)
            or not _IMAGE.fullmatch(image)
            or not isinstance(attestation, dict)
            or set(attestation) != _ATTESTATION_FIELDS
            or not isinstance(attestation.get("component"), str)
            or not attestation["component"]
            or not isinstance(attestation.get("subject_digest"), str)
            or not _OCI_DIGEST.fullmatch(attestation["subject_digest"])
            or not image.endswith("@" + attestation["subject_digest"])
            or not isinstance(attestation.get("sbom_sha256"), str)
            or not _DIGEST.fullmatch(attestation["sbom_sha256"])
            or not isinstance(attestation.get("provenance_attestation_url"), str)
            or not _URL.fullmatch(attestation["provenance_attestation_url"])
            or not isinstance(attestation.get("sbom_attestation_url"), str)
            or not _URL.fullmatch(attestation["sbom_attestation_url"])
        ):
            raise ManifestError("PRODUCTION_IMAGE_MANIFEST_INVALID")
    return {
        "schema_version": "agenttrust.production-image-manifest-verification.v1",
        "verified": True,
        "release_id": release_id,
        "release_tag": release_tag,
        "image_count": len(images),
        "manifest_digest": claimed_digest,
    }


def _write_new(path: Path, value: object) -> None:
    if not path.is_absolute() or path.exists() or not path.parent.is_dir():
        raise ManifestError("PRODUCTION_IMAGE_MANIFEST_OUTPUT_INVALID")
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = path.open("xb")
    try:
        descriptor.write(payload)
        descriptor.flush()
    finally:
        descriptor.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="assemble-production-image-manifest")
    commands = parser.add_subparsers(dest="command", required=True)
    assemble_command = commands.add_parser("assemble")
    verify_command = commands.add_parser("verify")
    for command in (assemble_command, verify_command):
        command.add_argument("--release-id", required=True)
        command.add_argument("--release-tag", required=True)
        command.add_argument("--repository", required=True)
    assemble_command.add_argument("--records-directory", type=Path, required=True)
    assemble_command.add_argument("--output", type=Path, required=True)
    verify_command.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "assemble":
        manifest = assemble(
            args.records_directory,
            release_id=args.release_id,
            release_tag=args.release_tag,
            repository=args.repository,
        )
        _write_new(args.output, manifest)
        result = {
            "image_count": len(manifest["images"]),
            "manifest_digest": manifest["manifest_digest"],
            "release_id": manifest["release_id"],
        }
    else:
        if (
            not args.manifest.is_absolute()
            or args.manifest.is_symlink()
            or not args.manifest.is_file()
            or not 1 <= args.manifest.stat().st_size <= 1024 * 1024
        ):
            raise ManifestError("PRODUCTION_IMAGE_MANIFEST_PATH_INVALID")
        try:
            document = json.loads(args.manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise ManifestError("PRODUCTION_IMAGE_MANIFEST_INVALID") from None
        result = verify_manifest(
            document,
            release_id=args.release_id,
            release_tag=args.release_tag,
            repository=args.repository,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
