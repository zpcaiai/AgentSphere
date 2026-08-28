"""Atomic publication and re-verification of production runtime evidence.

The positive bundle remains the authority.  This adapter turns its verified
documents into the fixed file layout consumed by the release-admission job and
the production runtime.  It never overwrites an existing volume generation and
does not claim that POSIX permissions are locked-retention storage.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
from typing import Any, Mapping

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.production_evidence_bundle import verify_bundle
from python.production_gates.qualification import QualificationTrustAnchors
from python.production_gates.release_activation import (
    ActivationError,
    activation_material_digest,
    verify_activation_documents,
)
from python.production_gates.release_binding import verify_signed_release_binding
from python.production_gates.release_preparation import prepare_activation_documents


PUBLICATION_RECEIPT_SCHEMA_VERSION = (
    "agenttrust.production-evidence-publication-receipt.v1"
)
RUNTIME_FILE_NAMES = frozenset(
    {
        "production-certificate.json",
        "closure-report.json",
        "closure-input.json",
        "revocation-registry.json",
        "activation-expectation.json",
        "batch-statuses.json",
        "gate-evidence.json",
        "residual-risks.json",
        "exceptions.json",
    }
)
RECEIPT_FILE_NAME = "publication-receipt.json"

_ROLE_FILE_NAMES = {
    "production_closure_certificate": "production-certificate.json",
    "closure_report": "closure-report.json",
    "closure_input": "closure-input.json",
    "production_closure_revocation_registry": "revocation-registry.json",
}
_CLOSURE_LIST_FILES = {
    "batch_statuses": "batch-statuses.json",
    "gate_evidence": "gate-evidence.json",
    "residual_risks": "residual-risks.json",
    "exceptions": "exceptions.json",
}
_RECEIPT_FIELDS = {
    "schema_version",
    "release_id",
    "scope_digest",
    "volume_name",
    "evidence_bundle_manifest_digest",
    "activation_material_digest",
    "certificate_id",
    "revocation_registry_id",
    "revocation_registry_sequence",
    "revocation_registry_digest",
    "files",
    "directory_digest",
    "published_at",
    "filesystem_mode_read_only",
    "locked_retention_evidence_required",
    "receipt_digest",
}
_FILE_FIELDS = {"name", "sha256", "size"}
_VOLUME_NAME = re.compile(
    r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _json_loads(payload: bytes) -> object:
    return json.loads(payload, object_pairs_hook=_reject_duplicates)


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _current_time(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() != timezone.utc.utcoffset(current):
        raise GateError("EVIDENCE_PUBLICATION_TIME_INVALID")
    return current.astimezone(timezone.utc)


def _safe_bundle_path(root: Path, relative: object) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or len(relative) > 512
        or Path(relative).is_absolute()
        or Path(relative).as_posix() != relative
        or ".." in Path(relative).parts
    ):
        raise GateError("EVIDENCE_PUBLICATION_BUNDLE_PATH_INVALID")
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise GateError("EVIDENCE_PUBLICATION_BUNDLE_PATH_INVALID")
    return path


def _load_documents(
    bundle_root: Path, manifest: Mapping[str, Any]
) -> dict[str, object]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise GateError("EVIDENCE_PUBLICATION_MANIFEST_INVALID")
    documents: dict[str, object] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise GateError("EVIDENCE_PUBLICATION_MANIFEST_INVALID")
        role = artifact.get("role")
        expected_size = artifact.get("size")
        expected_digest = artifact.get("sha256")
        if (
            not isinstance(role, str)
            or role in documents
            or not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or not isinstance(expected_digest, str)
            or not _DIGEST.fullmatch(expected_digest)
        ):
            raise GateError("EVIDENCE_PUBLICATION_MANIFEST_INVALID")
        path = _safe_bundle_path(bundle_root, artifact.get("path"))
        try:
            payload = path.read_bytes()
            if (
                not 1 <= len(payload) <= 64 * 1024 * 1024
                or len(payload) != expected_size
                or hashlib.sha256(payload).hexdigest() != expected_digest
            ):
                raise GateError("EVIDENCE_PUBLICATION_ARTIFACT_MISMATCH")
            documents[role] = _json_loads(payload)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise GateError("EVIDENCE_PUBLICATION_ARTIFACT_INVALID") from None
    return documents


def _expected_material(
    bundle_root: Path,
    manifest_value: object,
    activation_value: object,
    expectation_value: object,
    trust_anchors: QualificationTrustAnchors,
    closure_public_key: object,
    revocation_public_key: object,
    revocation_checkpoint: object,
    *,
    volume_name: str,
    now: datetime | None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    current = _current_time(now)
    root = bundle_root.resolve()
    if (
        not bundle_root.is_absolute()
        or bundle_root.is_symlink()
        or root != bundle_root
        or not root.is_dir()
        or not isinstance(manifest_value, dict)
        or not isinstance(activation_value, dict)
        or not isinstance(expectation_value, dict)
        or not _VOLUME_NAME.fullmatch(volume_name)
    ):
        raise GateError("EVIDENCE_PUBLICATION_INPUT_INVALID")
    verified = verify_bundle(
        root,
        manifest_value,
        trust_anchors,
        closure_public_key,
        revocation_public_key,
        revocation_checkpoint,
        now=current,
    )
    documents = _load_documents(root, manifest_value)
    closure_input = documents.get("closure_input")
    qualification = documents.get("qualification_input")
    if not isinstance(closure_input, dict) or not isinstance(qualification, dict):
        raise GateError("EVIDENCE_PUBLICATION_INPUT_INVALID")
    release_binding = qualification.get("release_binding")
    binding = verify_signed_release_binding(
        release_binding, trust_anchors.release_binding_keyring, now=current
    )
    static_values = binding.get("static_values")
    evidence_values = (
        static_values.get("evidence") if isinstance(static_values, dict) else None
    )
    if (
        not isinstance(evidence_values, dict)
        or evidence_values.get("persistent_volume_name") != volume_name
    ):
        raise GateError("EVIDENCE_PUBLICATION_VOLUME_BINDING_INVALID")

    requested_at = _parse_utc(
        activation_value.get("requested_at"), "EVIDENCE_PUBLICATION_ACTIVATION_INVALID"
    )
    expected_activation, expected_expectation = prepare_activation_documents(
        closure_input,
        documents.get("production_image_manifest"),
        manifest_value,
        release_binding,
        requested_at=requested_at,
    )
    if (
        canonical_json(activation_value) != canonical_json(expected_activation)
        or canonical_json(expectation_value) != canonical_json(expected_expectation)
        or activation_value.get("evidence_bundle_manifest_digest")
        != verified["manifest_digest"]
    ):
        raise GateError("EVIDENCE_PUBLICATION_ACTIVATION_MISMATCH")
    try:
        activation_receipt = verify_activation_documents(
            activation=activation_value,
            report=documents.get("closure_report"),
            certificate=documents.get("production_closure_certificate"),
            certificate_key=closure_public_key,
            revocation_registry=documents.get(
                "production_closure_revocation_registry"
            ),
            revocation_key=revocation_public_key,
            now=current,
        )
        material_digest = activation_material_digest(activation_value)
    except ActivationError as error:
        raise GateError("EVIDENCE_PUBLICATION_ACTIVATION_INVALID") from error

    payload_values: dict[str, object] = {
        file_name: documents[role]
        for role, file_name in _ROLE_FILE_NAMES.items()
    }
    payload_values["activation-expectation.json"] = expectation_value
    for field, file_name in _CLOSURE_LIST_FILES.items():
        value = closure_input.get(field)
        if not isinstance(value, list):
            raise GateError("EVIDENCE_PUBLICATION_RUNTIME_INPUT_INVALID")
        payload_values[file_name] = value
    if set(payload_values) != RUNTIME_FILE_NAMES:
        raise GateError("EVIDENCE_PUBLICATION_RUNTIME_INPUT_INVALID")
    payloads = {name: _json_bytes(value) for name, value in payload_values.items()}
    metadata = {
        "release_id": verified["release_id"],
        "scope_digest": verified["scope_digest"],
        "volume_name": volume_name,
        "evidence_bundle_manifest_digest": verified["manifest_digest"],
        "activation_material_digest": material_digest,
        "certificate_id": activation_receipt["certificate_id"],
        "revocation_registry_id": activation_receipt["revocation_registry_id"],
        "revocation_registry_sequence": activation_receipt[
            "revocation_registry_sequence"
        ],
        "revocation_registry_digest": activation_receipt[
            "revocation_registry_digest"
        ],
    }
    return metadata, payloads


def _file_records(payloads: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
        for name, payload in sorted(payloads.items())
    ]


def _receipt(
    metadata: Mapping[str, Any], payloads: Mapping[str, bytes], published_at: datetime
) -> dict[str, object]:
    files = _file_records(payloads)
    value: dict[str, object] = {
        "schema_version": PUBLICATION_RECEIPT_SCHEMA_VERSION,
        **metadata,
        "files": files,
        "directory_digest": _digest(files),
        "published_at": published_at.isoformat().replace("+00:00", "Z"),
        "filesystem_mode_read_only": True,
        "locked_retention_evidence_required": True,
        "receipt_digest": "",
    }
    value["receipt_digest"] = _digest(value)
    return value


def _write_new(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _secure_root(publication_root: Path) -> Path:
    root = publication_root.resolve()
    try:
        metadata = publication_root.stat(follow_symlinks=False)
    except OSError:
        raise GateError("EVIDENCE_PUBLICATION_ROOT_INVALID") from None
    if (
        not publication_root.is_absolute()
        or publication_root.is_symlink()
        or root != publication_root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o022
        or not os.access(root, os.W_OK | os.X_OK)
    ):
        raise GateError("EVIDENCE_PUBLICATION_ROOT_INVALID")
    return root


def publish_verified_evidence(
    bundle_root: Path,
    manifest_value: object,
    activation_value: object,
    expectation_value: object,
    trust_anchors: QualificationTrustAnchors,
    closure_public_key: object,
    revocation_public_key: object,
    revocation_checkpoint: object,
    publication_root: Path,
    *,
    volume_name: str,
    now: datetime | None = None,
) -> tuple[Path, dict[str, object]]:
    """Publish a new content generation and return its embedded receipt."""

    current = _current_time(now)
    metadata, payloads = _expected_material(
        bundle_root,
        manifest_value,
        activation_value,
        expectation_value,
        trust_anchors,
        closure_public_key,
        revocation_public_key,
        revocation_checkpoint,
        volume_name=volume_name,
        now=current,
    )
    root = _secure_root(publication_root)
    target = root / volume_name
    if target.exists() or target.is_symlink():
        raise GateError("EVIDENCE_PUBLICATION_TARGET_EXISTS")
    receipt = _receipt(metadata, payloads, current)
    stage: Path | None = None
    try:
        for _ in range(16):
            candidate = root / f".agenttrust-evidence-{secrets.token_hex(12)}"
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                continue
            stage = candidate
            break
        if stage is None:
            raise GateError("EVIDENCE_PUBLICATION_STAGE_UNAVAILABLE")
        for name, payload in sorted(payloads.items()):
            _write_new(stage / name, payload)
        _write_new(stage / RECEIPT_FILE_NAME, _json_bytes(receipt))
        for child in stage.iterdir():
            child.chmod(0o440)
        descriptor = os.open(stage, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        stage.chmod(0o550)
        os.rename(stage, target)
        stage = None
        descriptor = os.open(root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        if stage is not None and stage.exists():
            stage.chmod(0o700)
            for child in stage.iterdir():
                child.chmod(0o600)
            shutil.rmtree(stage)
        raise
    verify_published_evidence(
        bundle_root,
        manifest_value,
        activation_value,
        expectation_value,
        trust_anchors,
        closure_public_key,
        revocation_public_key,
        revocation_checkpoint,
        target,
        volume_name=volume_name,
        now=current,
    )
    return target, receipt


def _strict_receipt(value: object) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != _RECEIPT_FIELDS:
        raise GateError("EVIDENCE_PUBLICATION_RECEIPT_INVALID")
    files = value.get("files")
    material = dict(value)
    claimed_digest = material.get("receipt_digest")
    material["receipt_digest"] = ""
    if (
        value.get("schema_version") != PUBLICATION_RECEIPT_SCHEMA_VERSION
        or value.get("filesystem_mode_read_only") is not True
        or value.get("locked_retention_evidence_required") is not True
        or not isinstance(files, list)
        or len(files) != len(RUNTIME_FILE_NAMES)
        or not isinstance(claimed_digest, str)
        or claimed_digest != _digest(material)
        or value.get("directory_digest") != _digest(files)
    ):
        raise GateError("EVIDENCE_PUBLICATION_RECEIPT_INVALID")
    return value


def verify_published_evidence(
    bundle_root: Path,
    manifest_value: object,
    activation_value: object,
    expectation_value: object,
    trust_anchors: QualificationTrustAnchors,
    closure_public_key: object,
    revocation_public_key: object,
    revocation_checkpoint: object,
    publication_directory: Path,
    *,
    volume_name: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Reverify a published generation against the authoritative bundle."""

    current = _current_time(now)
    metadata, payloads = _expected_material(
        bundle_root,
        manifest_value,
        activation_value,
        expectation_value,
        trust_anchors,
        closure_public_key,
        revocation_public_key,
        revocation_checkpoint,
        volume_name=volume_name,
        now=current,
    )
    directory = publication_directory.resolve()
    try:
        directory_metadata = publication_directory.stat(follow_symlinks=False)
    except OSError:
        raise GateError("EVIDENCE_PUBLICATION_DIRECTORY_INVALID") from None
    if (
        not publication_directory.is_absolute()
        or publication_directory.is_symlink()
        or directory != publication_directory
        or directory.name != volume_name
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_mode & 0o222
        or os.access(directory, os.W_OK)
    ):
        raise GateError("EVIDENCE_PUBLICATION_DIRECTORY_INVALID")
    try:
        children = {child.name: child for child in directory.iterdir()}
    except OSError:
        raise GateError("EVIDENCE_PUBLICATION_DIRECTORY_INVALID") from None
    if set(children) != RUNTIME_FILE_NAMES | {RECEIPT_FILE_NAME}:
        raise GateError("EVIDENCE_PUBLICATION_CONTENT_INVALID")
    observed_payloads: dict[str, bytes] = {}
    for name, path in children.items():
        try:
            file_metadata = path.stat(follow_symlinks=False)
            if (
                path.is_symlink()
                or not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_nlink != 1
                or file_metadata.st_mode & 0o222
                or not 1 <= file_metadata.st_size <= 64 * 1024 * 1024
            ):
                raise GateError("EVIDENCE_PUBLICATION_FILE_INVALID")
            observed_payloads[name] = path.read_bytes()
        except OSError:
            raise GateError("EVIDENCE_PUBLICATION_FILE_INVALID") from None
    if any(observed_payloads[name] != payload for name, payload in payloads.items()):
        raise GateError("EVIDENCE_PUBLICATION_CONTENT_MISMATCH")
    try:
        receipt_value = _json_loads(observed_payloads[RECEIPT_FILE_NAME])
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GateError("EVIDENCE_PUBLICATION_RECEIPT_INVALID") from None
    receipt = _strict_receipt(receipt_value)
    expected_receipt_fields = {
        **metadata,
        "files": _file_records(payloads),
        "directory_digest": _digest(_file_records(payloads)),
    }
    if any(receipt.get(key) != value for key, value in expected_receipt_fields.items()):
        raise GateError("EVIDENCE_PUBLICATION_RECEIPT_MISMATCH")
    _parse_utc(receipt.get("published_at"), "EVIDENCE_PUBLICATION_RECEIPT_INVALID")
    return dict(receipt)
