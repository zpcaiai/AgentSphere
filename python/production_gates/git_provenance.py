"""Immutable Git source provenance collector with fail-closed release checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Protocol, Sequence
from urllib.parse import urlparse

from python.production_gates.live_integrations import (
    ConfigurationMissing,
    GateError,
    GateResult,
)


_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SAFE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class GitRunner(Protocol):
    def run(self, repository: Path, arguments: Sequence[str], *, allow_failure: bool = False) -> bytes: ...


class SubprocessGitRunner:
    def run(self, repository: Path, arguments: Sequence[str], *, allow_failure: bool = False) -> bytes:
        try:
            completed = subprocess.run(
                ["git", "-C", str(repository), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=not allow_failure,
                env={
                    "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_OPTIONAL_LOCKS": "0",
                },
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise GateError("GIT_PROVENANCE_COMMAND_FAILED") from None
        if len(completed.stdout) > 8_000_000 or len(completed.stderr) > 1_000_000:
            raise GateError("GIT_PROVENANCE_OUTPUT_TOO_LARGE")
        if allow_failure and completed.returncode != 0:
            raise GateError("GIT_SIGNATURE_INVALID")
        return completed.stdout


def _remote_host(url: str) -> str:
    if "@" in url and ":" in url and "://" not in url:
        user_host, _, path = url.partition(":")
        host = user_host.rsplit("@", 1)[-1]
        if not path or not _SAFE_HOST.fullmatch(host):
            raise GateError("GIT_REMOTE_INVALID")
        return host.lower()
    parsed = urlparse(url)
    if (
        parsed.scheme not in {"https", "ssh"}
        or not parsed.hostname
        or parsed.username is not None and parsed.scheme == "https"
        or parsed.password is not None
        or not parsed.path.strip("/")
    ):
        raise GateError("GIT_REMOTE_INVALID")
    return parsed.hostname.lower()


def collect_git_provenance(
    repository: Path,
    allowed_remote_hosts: set[str],
    *,
    require_clean: bool = True,
    require_signed_commit: bool = True,
    release_tag: str | None = None,
    runner: GitRunner | None = None,
) -> GateResult:
    if (
        not repository.is_absolute()
        or not repository.is_dir()
        or not allowed_remote_hosts
        or any(not _SAFE_HOST.fullmatch(host) for host in allowed_remote_hosts)
        or release_tag is not None and not _SAFE_TAG.fullmatch(release_tag)
    ):
        raise ConfigurationMissing("GIT_PROVENANCE_CONFIGURATION_NOT_CONFIGURED")
    command = runner or SubprocessGitRunner()
    try:
        root = Path(command.run(repository, ["rev-parse", "--show-toplevel"]).decode().strip())
    except GateError:
        raise ConfigurationMissing("GIT_REPOSITORY_NOT_CONFIGURED") from None
    if root.resolve() != repository.resolve():
        raise GateError("GIT_REPOSITORY_ROOT_MISMATCH")
    head = command.run(repository, ["rev-parse", "HEAD"]).decode().strip()
    object_type = command.run(repository, ["cat-file", "-t", head]).decode().strip()
    tree = command.run(repository, ["rev-parse", "HEAD^{tree}"]).decode().strip()
    if not _OBJECT_ID.fullmatch(head) or not _OBJECT_ID.fullmatch(tree) or object_type != "commit":
        raise GateError("GIT_HEAD_INVALID")
    status = command.run(
        repository, ["status", "--porcelain=v1", "--untracked-files=all"]
    ).decode()
    if require_clean and status:
        raise GateError("GIT_WORKTREE_DIRTY")
    submodules = command.run(repository, ["submodule", "status", "--recursive"]).decode()
    if any(line.startswith(("-", "+", "U")) for line in submodules.splitlines()):
        raise GateError("GIT_SUBMODULE_STATE_INVALID")
    remote_lines = command.run(repository, ["remote", "-v"]).decode().splitlines()
    remotes: dict[str, str] = {}
    for line in remote_lines:
        parts = line.split()
        if len(parts) != 3 or parts[2] not in {"(fetch)", "(push)"}:
            raise GateError("GIT_REMOTE_INVALID")
        name, url = parts[0], parts[1]
        host = _remote_host(url)
        if host not in {item.lower() for item in allowed_remote_hosts}:
            raise GateError("GIT_REMOTE_HOST_DENIED")
        previous = remotes.setdefault(name, host)
        if previous != host:
            raise GateError("GIT_REMOTE_INVALID")
    if not remotes:
        raise GateError("GIT_REMOTE_NOT_CONFIGURED")
    commit_bytes = command.run(repository, ["cat-file", "commit", head])
    commit_signed = False
    if require_signed_commit:
        command.run(repository, ["verify-commit", head], allow_failure=True)
        commit_signed = True
    tag_verified = False
    if release_tag is not None:
        tag_target = command.run(repository, ["rev-list", "-n", "1", release_tag]).decode().strip()
        if tag_target != head:
            raise GateError("GIT_RELEASE_TAG_TARGET_MISMATCH")
        command.run(repository, ["verify-tag", release_tag], allow_failure=True)
        tag_verified = True
    algorithm = "sha256" if len(head) == 64 else "sha1"
    remote_set_digest = hashlib.sha256(
        json.dumps(remotes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return GateResult(
        gate="GIT_IMMUTABLE_PROVENANCE",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"git://{sorted(remotes.values())[0]}/{head}",
        checks={
            "release_id": f"git:{algorithm}:{head}",
            "object_format": algorithm,
            "commit_object_id": head,
            "tree_object_id": tree,
            "commit_content_digest": hashlib.sha256(commit_bytes).hexdigest(),
            "clean_worktree_required": require_clean,
            "clean_worktree": not bool(status),
            "submodules_pinned": True,
            "remote_count": len(remotes),
            "remote_set_digest": remote_set_digest,
            "commit_signature_required": require_signed_commit,
            "commit_signature_verified": commit_signed,
            "release_tag_required": release_tag is not None,
            "release_tag_signature_verified": tag_verified,
        },
    )


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise GateError("GIT_PROVENANCE_REPORT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-git-provenance")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--allowed-remote-host", action="append", required=True)
    parser.add_argument("--release-tag")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = collect_git_provenance(
            args.repository,
            set(args.allowed_remote_host),
            require_clean=True,
            require_signed_commit=True,
            release_tag=args.release_tag,
        )
        exit_code = 0
    except ConfigurationMissing as error:
        result = GateResult(
            "GIT_IMMUTABLE_PROVENANCE", "NOT_RUN_CONFIGURATION", "unconfigured",
            {"error_code": str(error)},
        )
        exit_code = 3
    except GateError as error:
        result = GateResult(
            "GIT_IMMUTABLE_PROVENANCE", "FAIL", "configured-repository",
            {"error_code": str(error)},
        )
        exit_code = 2
    report = result.as_dict()
    _write_new(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
