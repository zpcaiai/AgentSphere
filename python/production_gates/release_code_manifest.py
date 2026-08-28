"""Strict parser for the reviewed portable-release source inventory."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat


RELEASE_CODE_MANIFEST = "config/production-runtime/release-code-manifest.txt"
MAX_RELEASE_CODE_MANIFEST_BYTES = 1024 * 1024
MAX_RELEASE_CODE_FILE_BYTES = 128 * 1024 * 1024
_REPOSITORY_PATH = re.compile(r"^[A-Za-z0-9._@/-]+$")


class ReleaseCodeManifestError(RuntimeError):
    """The reviewed release-code inventory is absent or non-canonical."""


def _valid_relative_path(relative: str) -> bool:
    path = Path(relative)
    return (
        bool(relative)
        and _REPOSITORY_PATH.fullmatch(relative) is not None
        and not path.is_absolute()
        and path.as_posix() == relative
        and "." not in path.parts
        and ".." not in path.parts
    )


def repository_file_is_safe(
    root: Path,
    relative: str,
    *,
    maximum_bytes: int = MAX_RELEASE_CODE_FILE_BYTES,
) -> bool:
    """Return whether a listed repository file is regular and symlink-free."""

    if not _valid_relative_path(relative) or maximum_bytes < 1:
        return False
    try:
        root = root.resolve(strict=True)
        candidate = root / relative
        current = root
        for component in Path(relative).parts:
            current /= component
            if current.is_symlink():
                return False
        resolved = candidate.resolve(strict=True)
        metadata = candidate.stat(follow_symlinks=False)
        return (
            resolved.is_relative_to(root)
            and candidate.is_file()
            and metadata.st_nlink == 1
            and 0 <= metadata.st_size <= maximum_bytes
        )
    except OSError:
        return False


def repository_file_sha256(
    root: Path,
    relative: str,
    *,
    maximum_bytes: int = MAX_RELEASE_CODE_FILE_BYTES,
) -> str:
    """Hash stable bytes from a safe repository file without following links."""

    if not repository_file_is_safe(root, relative, maximum_bytes=maximum_bytes):
        raise ReleaseCodeManifestError("RELEASE_CODE_SOURCE_INVALID")
    source = root.resolve(strict=True) / relative
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError:
        raise ReleaseCodeManifestError("RELEASE_CODE_SOURCE_INVALID") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 <= metadata.st_size <= maximum_bytes
        ):
            raise ReleaseCodeManifestError("RELEASE_CODE_SOURCE_INVALID")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        current = os.fstat(descriptor)
        immutable_fields = (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
        if any(
            getattr(current, field) != getattr(metadata, field)
            for field in immutable_fields
        ):
            raise ReleaseCodeManifestError("RELEASE_CODE_SOURCE_CHANGED")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def load_release_code_manifest(
    root: Path,
    *,
    manifest_relative: str = RELEASE_CODE_MANIFEST,
) -> tuple[str, ...]:
    """Read a sorted, unique, canonical repository-relative path inventory."""

    if not _valid_relative_path(manifest_relative) or not repository_file_is_safe(
        root,
        manifest_relative,
        maximum_bytes=MAX_RELEASE_CODE_MANIFEST_BYTES,
    ):
        raise ReleaseCodeManifestError("RELEASE_CODE_MANIFEST_INVALID")
    source = root / manifest_relative
    try:
        payload = source.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise ReleaseCodeManifestError("RELEASE_CODE_MANIFEST_INVALID") from None
    if (
        not payload
        or not payload.endswith(b"\n")
        or "\r" in text
        or "\x00" in text
    ):
        raise ReleaseCodeManifestError("RELEASE_CODE_MANIFEST_INVALID")
    entries = tuple(text.splitlines())
    if (
        not entries
        or entries != tuple(sorted(entries))
        or len(entries) != len(set(entries))
        or any(not _valid_relative_path(relative) for relative in entries)
        or manifest_relative not in entries
    ):
        raise ReleaseCodeManifestError("RELEASE_CODE_MANIFEST_INVALID")
    return entries
