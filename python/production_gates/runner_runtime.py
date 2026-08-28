"""Fail-closed verification for a pre-provisioned production Python runtime.

Production release workflows must not resolve Python dependencies from a public
index while a release is in flight.  This module fingerprints the interpreter
and every installed distribution file below the interpreter prefix.  Operators
publish the canonical manifest when they build the dedicated runner image and
bind its SHA-256 through a protected environment variable.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import sysconfig
from typing import Any, Iterable, Mapping, Sequence

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


SCHEMA_VERSION = "agenttrust.production-python-runtime.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")
DEFAULT_REQUIRED_DISTRIBUTIONS = (
    "cryptography",
    "jsonschema",
    "openapi-spec-validator",
)
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_DISTRIBUTION_FILES = 200_000
MAX_DISTRIBUTION_BYTES = 4 * 1024 * 1024 * 1024
MAX_REQUIREMENTS_LOCK_BYTES = 16 * 1024 * 1024
LOCK_ENTRY_RE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,127})"
    r"==(?P<version>[^\s;@\\]{1,256})"
    r"(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)"
)


def _reject_duplicate_key(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GateError("PYTHON_RUNTIME_MANIFEST_DUPLICATE_KEY")
        value[key] = item
    return value


def _load_canonical_json(path: Path, *, expected_digest: str) -> Mapping[str, Any]:
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise GateError("PYTHON_RUNTIME_MANIFEST_PATH_INVALID")
    try:
        metadata_value = path.stat(follow_symlinks=False)
    except OSError as error:
        raise GateError("PYTHON_RUNTIME_MANIFEST_UNREADABLE") from error
    if (
        not stat.S_ISREG(metadata_value.st_mode)
        or metadata_value.st_nlink != 1
        or metadata_value.st_mode & 0o022
        or not 1 <= metadata_value.st_size <= MAX_MANIFEST_BYTES
        or not os.access(path, os.R_OK)
        or os.access(path, os.W_OK)
    ):
        raise GateError("PYTHON_RUNTIME_MANIFEST_PERMISSIONS_INVALID")
    if not SHA256_RE.fullmatch(expected_digest):
        raise GateError("PYTHON_RUNTIME_MANIFEST_DIGEST_INVALID")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GateError("PYTHON_RUNTIME_MANIFEST_UNREADABLE") from error
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise GateError("PYTHON_RUNTIME_MANIFEST_DIGEST_MISMATCH")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_key)
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError("PYTHON_RUNTIME_MANIFEST_JSON_INVALID") from error
    if not isinstance(value, dict):
        raise GateError("PYTHON_RUNTIME_MANIFEST_INVALID")
    if raw != canonical_json(value) + b"\n":
        raise GateError("PYTHON_RUNTIME_MANIFEST_NOT_CANONICAL")
    return value


def _normalize_distribution_name(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", value.strip().lower())
    if not NAME_RE.fullmatch(normalized):
        raise GateError("PYTHON_RUNTIME_DISTRIBUTION_NAME_INVALID")
    return normalized


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise GateError("PYTHON_RUNTIME_FILE_UNREADABLE") from error
    return digest.hexdigest()


def _trusted_regular_file(path: Path, *, executable: bool = False) -> os.stat_result:
    if path.is_symlink():
        raise GateError("PYTHON_RUNTIME_SYMLINK_FORBIDDEN")
    try:
        value = path.stat(follow_symlinks=False)
    except OSError as error:
        raise GateError("PYTHON_RUNTIME_FILE_UNREADABLE") from error
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_mode & 0o022
        or os.access(path, os.W_OK)
        or (executable and not os.access(path, os.X_OK))
    ):
        raise GateError("PYTHON_RUNTIME_FILE_PERMISSIONS_INVALID")
    return value


def _relative_to_root(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise GateError("PYTHON_RUNTIME_FILE_OUTSIDE_PREFIX") from error
    normalized = PurePosixPath(relative.as_posix())
    if normalized.is_absolute() or not normalized.parts or ".." in normalized.parts:
        raise GateError("PYTHON_RUNTIME_FILE_PATH_INVALID")
    return normalized.as_posix()


def _resolve_without_symlinks(path: Path) -> Path:
    if not path.is_absolute():
        raise GateError("PYTHON_RUNTIME_FILE_PATH_INVALID")
    normalized = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError("PYTHON_RUNTIME_FILE_UNREADABLE") from error
    # abspath removes dot components without resolving links.  A difference
    # therefore means that a file or one of its parents traversed a symlink.
    if normalized != resolved:
        raise GateError("PYTHON_RUNTIME_SYMLINK_FORBIDDEN")
    return resolved


@dataclass(frozen=True)
class DistributionRecord:
    name: str
    version: str
    file_count: int
    byte_count: int
    files_digest: str

    def as_json(self) -> dict[str, Any]:
        return {
            "byte_count": self.byte_count,
            "file_count": self.file_count,
            "files_digest": self.files_digest,
            "name": self.name,
            "version": self.version,
        }


def _requirements_lock(path: Path) -> tuple[dict[str, str], str]:
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_PATH_INVALID")
    value = _trusted_regular_file(path)
    if not 1 <= value.st_size <= MAX_REQUIREMENTS_LOCK_BYTES:
        raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_SIZE_INVALID")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_INVALID") from error
    logical_lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            if pending:
                raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_INVALID")
            continue
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        logical_lines.append((pending + line).strip())
        pending = ""
    if pending or not logical_lines:
        raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_INVALID")
    pins: dict[str, str] = {}
    for line in logical_lines:
        match = LOCK_ENTRY_RE.fullmatch(line)
        if match is None:
            raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_INVALID")
        name = _normalize_distribution_name(match.group("name"))
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", match.group("hashes"))
        if not hashes or len(hashes) != len(set(hashes)) or name in pins:
            raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_INVALID")
        pins[name] = match.group("version")
    return pins, hashlib.sha256(raw).hexdigest()


def _distribution_record(
    distribution: metadata.Distribution,
    *,
    runtime_root: Path,
    occupied_paths: set[str],
) -> DistributionRecord:
    raw_name = distribution.metadata.get("Name")
    version = distribution.version
    if not isinstance(raw_name, str) or not isinstance(version, str) or not version:
        raise GateError("PYTHON_RUNTIME_DISTRIBUTION_METADATA_INVALID")
    name = _normalize_distribution_name(raw_name)
    files = distribution.files
    if files is None:
        raise GateError("PYTHON_RUNTIME_DISTRIBUTION_RECORD_MISSING")
    entries: list[dict[str, Any]] = []
    byte_count = 0
    for package_path in sorted(files, key=lambda item: str(item)):
        located_raw = Path(distribution.locate_file(package_path))
        located = _resolve_without_symlinks(located_raw)
        relative = _relative_to_root(located, runtime_root)
        if relative in occupied_paths:
            raise GateError("PYTHON_RUNTIME_DISTRIBUTION_FILE_OVERLAP")
        file_metadata = _trusted_regular_file(located)
        byte_count += file_metadata.st_size
        if len(entries) >= MAX_DISTRIBUTION_FILES or byte_count > MAX_DISTRIBUTION_BYTES:
            raise GateError("PYTHON_RUNTIME_DISTRIBUTION_TOO_LARGE")
        entries.append(
            {
                "path": relative,
                "sha256": _sha256_file(located),
                "size": file_metadata.st_size,
            }
        )
        occupied_paths.add(relative)
    if not entries:
        raise GateError("PYTHON_RUNTIME_DISTRIBUTION_EMPTY")
    return DistributionRecord(
        name=name,
        version=version,
        file_count=len(entries),
        byte_count=byte_count,
        files_digest=hashlib.sha256(canonical_json(entries)).hexdigest(),
    )


def inspect_runtime(
    *,
    requirements_lock: Path,
    required_distributions: Iterable[str] = DEFAULT_REQUIRED_DISTRIBUTIONS,
) -> dict[str, Any]:
    executable = Path(sys.executable)
    try:
        executable = _resolve_without_symlinks(executable)
    except GateError as error:
        raise GateError("PYTHON_RUNTIME_EXECUTABLE_PATH_INVALID") from error
    _trusted_regular_file(executable, executable=True)
    raw_runtime_root = Path(sys.prefix)
    try:
        runtime_root = _resolve_without_symlinks(raw_runtime_root)
    except GateError as error:
        raise GateError("PYTHON_RUNTIME_PREFIX_INVALID") from error
    if runtime_root == Path("/") or not runtime_root.is_dir():
        raise GateError("PYTHON_RUNTIME_PREFIX_INVALID")
    root_metadata = runtime_root.stat(follow_symlinks=False)
    if root_metadata.st_mode & 0o022 or os.access(runtime_root, os.W_OK):
        raise GateError("PYTHON_RUNTIME_PREFIX_PERMISSIONS_INVALID")

    search_paths = sorted(
        {
            str(_resolve_without_symlinks(Path(value)))
            for key, value in sysconfig.get_paths().items()
            if key in {"purelib", "platlib"} and value
        }
    )
    if not search_paths:
        raise GateError("PYTHON_RUNTIME_SITE_PACKAGES_MISSING")
    for search_path in search_paths:
        search_path_value = Path(search_path)
        _relative_to_root(search_path_value, runtime_root)
        path_metadata = search_path_value.stat(follow_symlinks=False)
        if path_metadata.st_mode & 0o022 or os.access(search_path_value, os.W_OK):
            raise GateError("PYTHON_RUNTIME_SITE_PACKAGES_PERMISSIONS_INVALID")

    records: list[DistributionRecord] = []
    occupied_paths: set[str] = set()
    seen_names: set[str] = set()
    for distribution in metadata.distributions(path=search_paths):
        record = _distribution_record(
            distribution,
            runtime_root=runtime_root,
            occupied_paths=occupied_paths,
        )
        if record.name in seen_names:
            raise GateError("PYTHON_RUNTIME_DISTRIBUTION_DUPLICATE")
        seen_names.add(record.name)
        records.append(record)
    records.sort(key=lambda item: item.name)
    required = {_normalize_distribution_name(value) for value in required_distributions}
    if not required.issubset(seen_names):
        raise GateError("PYTHON_RUNTIME_REQUIRED_DISTRIBUTION_MISSING")
    pins, requirements_lock_sha256 = _requirements_lock(requirements_lock)
    installed_versions = {record.name: record.version for record in records}
    if (
        not required.issubset(pins)
        or any(installed_versions.get(name) != version for name, version in pins.items())
    ):
        raise GateError("PYTHON_RUNTIME_REQUIREMENTS_LOCK_MISMATCH")
    return {
        "distributions": [record.as_json() for record in records],
        "python": {
            "cache_tag": sys.implementation.cache_tag,
            "executable_sha256": _sha256_file(executable),
            "implementation": platform.python_implementation(),
            "runtime_root": str(runtime_root),
            "version": platform.python_version(),
        },
        "requirements_lock_sha256": requirements_lock_sha256,
        "schema_version": SCHEMA_VERSION,
    }


def verify_runtime(
    manifest_path: Path,
    *,
    manifest_sha256: str,
    python_sha256: str,
    requirements_lock: Path,
    required_distributions: Iterable[str] = DEFAULT_REQUIRED_DISTRIBUTIONS,
) -> Mapping[str, Any]:
    if not SHA256_RE.fullmatch(python_sha256):
        raise GateError("PYTHON_RUNTIME_EXECUTABLE_DIGEST_INVALID")
    manifest = _load_canonical_json(manifest_path, expected_digest=manifest_sha256)
    actual = inspect_runtime(
        requirements_lock=requirements_lock,
        required_distributions=required_distributions,
    )
    python_value = manifest.get("python")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or set(manifest)
        != {
            "schema_version",
            "python",
            "distributions",
            "requirements_lock_sha256",
        }
        or not isinstance(python_value, dict)
        or python_value.get("executable_sha256") != python_sha256
        or actual["python"]["executable_sha256"] != python_sha256
        or manifest != actual
    ):
        raise GateError("PYTHON_RUNTIME_MANIFEST_MISMATCH")
    return manifest


def write_runtime_manifest(
    output: Path,
    *,
    requirements_lock: Path,
    required_distributions: Iterable[str] = DEFAULT_REQUIRED_DISTRIBUTIONS,
) -> str:
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise GateError("PYTHON_RUNTIME_MANIFEST_OUTPUT_INVALID")
    parent = output.parent.resolve(strict=True)
    if parent == Path("/") or parent.is_symlink():
        raise GateError("PYTHON_RUNTIME_MANIFEST_OUTPUT_INVALID")
    value = inspect_runtime(
        requirements_lock=requirements_lock,
        required_distributions=required_distributions,
    )
    raw = canonical_json(value) + b"\n"
    temporary = parent / f".{output.name}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise
    return hashlib.sha256(raw).hexdigest()
