"""Immutable Git source provenance collector with fail-closed release checks."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from python.production_gates.live_integrations import (
    ConfigurationMissing,
    GateError,
    GateResult,
)


_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SAFE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_PUBLIC = re.compile(r"^[A-Za-z0-9_-]{43}$")
_BASE64URL_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")

SIGNED_GIT_PROVENANCE_SCHEMA_VERSION = "agenttrust.signed-git-provenance.v1"
GIT_PROVENANCE_KEYRING_SCHEMA_VERSION = "agenttrust.git-provenance-keyring.v1"
GIT_PROVENANCE_KEY_USAGE = "GIT_PROVENANCE_ATTESTATION"
GIT_PROVENANCE_ALGORITHM = "Ed25519"
PRODUCTION_STACK_TEMPLATE_GIT_PATH = "deploy/kubernetes/production-stack.yaml.tmpl"

_REPORT_FIELDS = {
    "schema_version", "gate", "status", "environment_reference", "checks",
    "production_evidence", "measured_at", "evidence_digest",
}
_CHECK_FIELDS = {
    "release_id", "object_format", "commit_object_id", "tree_object_id",
    "commit_content_digest", "clean_worktree_required", "clean_worktree",
    "submodules_pinned", "remote_count", "remote_hosts", "remote_hosts_by_name",
    "remote_url_digests", "remote_set_digest", "commit_signature_required",
    "commit_signature_verified",
    "release_tag_required", "release_tag", "release_tag_object_id", "release_tag_target",
    "release_tag_signature_verified", "remote_release_tag_verified",
    "remote_release_tag_ref", "remote_tag_object_ids",
    "remote_tag_peeled_commit_ids", "remote_membership_digest",
    "signature_trust_format", "git_allowed_signers_digest",
}
_ENVELOPE_FIELDS = {
    "schema_version", "report", "report_digest", "issuer", "key_id", "key_usage",
    "algorithm", "signed_at", "signature",
}
_KEYRING_FIELDS = {"schema_version", "keys"}
_KEY_FIELDS = {
    "issuer", "key_id", "key_usage", "algorithm", "public_key", "status",
    "not_before", "not_after",
}


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise GateError("GIT_PROVENANCE_CANONICAL_JSON_INVALID") from None


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _decode_base64url(value: object, expected_length: int, code: str) -> bytes:
    if not isinstance(value, str):
        raise GateError(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError):
        raise GateError(code) from None
    if (
        len(decoded) != expected_length
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise GateError(code)
    return decoded


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise GateError(code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise GateError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GateError(code)
    return parsed.astimezone(timezone.utc)


def _strict_mapping(value: object, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError(code)
    return value


def _valid_object_id(value: object, algorithm: str) -> bool:
    expected = 40 if algorithm == "sha1" else 64 if algorithm == "sha256" else 0
    return (
        isinstance(value, str)
        and len(value) == expected
        and value != "0" * expected
        and bool(_OBJECT_ID.fullmatch(value))
    )


def _canonical_remote(url: str) -> tuple[str, str]:
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 2_048
        or any(ord(c) < 33 or ord(c) > 126 for c in url)
    ):
        raise GateError("GIT_REMOTE_INVALID")
    if "@" in url and ":" in url and "://" not in url:
        user_host, _, raw_path = url.partition(":")
        user, separator, raw_host = user_host.rpartition("@")
        host = raw_host if separator else user_host
        if (
            not raw_path
            or not _SAFE_HOST.fullmatch(host)
            or any(part in {"", ".", ".."} for part in raw_path.split("/"))
            or user and not _SAFE_IDENTIFIER.fullmatch(user)
        ):
            raise GateError("GIT_REMOTE_INVALID")
        authority = f"{user}@{host.lower()}" if user else host.lower()
        return host.lower(), f"ssh://{authority}/{raw_path}"
    parsed = urlparse(url)
    if (
        parsed.scheme not in {"https", "ssh"}
        or not parsed.hostname
        or not _SAFE_HOST.fullmatch(parsed.hostname)
        or parsed.password is not None
        or parsed.username is not None and parsed.scheme == "https"
        or not parsed.path.strip("/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise GateError("GIT_REMOTE_INVALID")
    try:
        port = parsed.port
    except ValueError:
        raise GateError("GIT_REMOTE_INVALID") from None
    host = parsed.hostname.lower()
    authority = host if port is None else f"{host}:{port}"
    if parsed.username is not None:
        if not _SAFE_IDENTIFIER.fullmatch(parsed.username):
            raise GateError("GIT_REMOTE_INVALID")
        authority = f"{parsed.username}@{authority}"
    return host, f"{parsed.scheme}://{authority}/{parsed.path.strip('/')}"


def _parse_remote_ref(payload: bytes, expected_ref: str, algorithm: str) -> str:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise GateError("GIT_REMOTE_RELEASE_TAG_INVALID") from None
    if len(lines) != 1:
        raise GateError("GIT_REMOTE_RELEASE_TAG_NOT_FOUND")
    parts = lines[0].split()
    if (
        len(parts) != 2
        or parts[1] != expected_ref
        or not _valid_object_id(parts[0], algorithm)
    ):
        raise GateError("GIT_REMOTE_RELEASE_TAG_INVALID")
    return parts[0]


_ALLOWED_LOCAL_CONFIG_KEYS = {
    "core.repositoryformatversion",
    "core.filemode",
    "core.bare",
    "core.logallrefupdates",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.symlinks",
    "core.worktree",
    "extensions.objectformat",
    "extensions.refstorage",
    "extensions.worktreeconfig",
    "user.name",
    "user.email",
}
_ALLOWED_LOCAL_CONFIG_PATTERNS = (
    re.compile(r"^remote\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:url|pushurl|fetch|mirror|tagopt)$"),
    re.compile(r"^branch\.[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\.(?:remote|merge)$"),
    re.compile(r"^submodule\.[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\.(?:active|url|branch)$"),
)


def _parse_config_names(payload: bytes) -> list[str]:
    if len(payload) > 1_000_000:
        raise GateError("GIT_LOCAL_CONFIG_INVALID")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise GateError("GIT_LOCAL_CONFIG_INVALID") from None
    if not decoded:
        return []
    names = decoded.split("\0")
    if names[-1] == "":
        names.pop()
    if (
        not names
        or len(names) > 2_048
        or any(
            not name
            or len(name) > 512
            or any(ord(character) < 33 or ord(character) > 126 for character in name)
            for name in names
        )
    ):
        raise GateError("GIT_LOCAL_CONFIG_INVALID")
    return names


def _validate_local_git_config(command: "GitRunner", repository: Path) -> None:
    names: list[str] = []
    for scope in ("--local", "--worktree"):
        names.extend(_parse_config_names(command.run(
            repository, ["config", scope, "--null", "--name-only", "--list"]
        )))
    for name in names:
        normalized = name.lower()
        if normalized in _ALLOWED_LOCAL_CONFIG_KEYS:
            continue
        if any(pattern.fullmatch(name) for pattern in _ALLOWED_LOCAL_CONFIG_PATTERNS):
            continue
        raise GateError("GIT_LOCAL_CONFIG_KEY_DENIED")


def _read_protected_file(
    path: Path | None,
    *,
    missing_code: str,
    invalid_code: str,
    maximum_bytes: int,
    secret: bool = False,
) -> bytes:
    if path is None or not path.is_absolute() or path.is_symlink():
        raise ConfigurationMissing(missing_code)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ConfigurationMissing(missing_code) from None
    try:
        metadata = os.fstat(descriptor)
        permitted_owners = {0}
        if hasattr(os, "geteuid"):
            permitted_owners.add(os.geteuid())
        denied_mode = 0o077 if secret else 0o022
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum_bytes
            or os.name == "posix" and metadata.st_uid not in permitted_owners
            or os.name == "posix" and metadata.st_mode & denied_mode
        ):
            raise GateError(invalid_code)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if not value or len(value) > maximum_bytes or b"\x00" in value:
        raise GateError(invalid_code)
    return value


class GitRunner(Protocol):
    def run(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        allow_failure: bool = False,
        network: bool = False,
    ) -> bytes: ...


class SubprocessGitRunner:
    """Run Git with repository configuration unable to select executable helpers.

    Repository-local configuration is audited separately.  These command-scope
    settings are still applied to every invocation so a concurrent config edit
    cannot re-enable an executable fsmonitor, credential helper, transport, or
    signature verifier between the audit and a command.
    """

    def __init__(
        self,
        *,
        allowed_signers_file: Path | None = None,
        ssh_known_hosts_file: Path | None = None,
        ssh_identity_file: Path | None = None,
    ) -> None:
        self._allowed_signers_file = allowed_signers_file
        self._ssh_known_hosts_file = ssh_known_hosts_file
        self._ssh_identity_file = ssh_identity_file

    def _global_arguments(self) -> list[str]:
        result = [
            "--no-replace-objects",
            "--literal-pathspecs",
            "-c", "core.fsmonitor=false",
            "-c", "credential.helper=",
            "-c", "credential.interactive=never",
            "-c", "core.askPass=",
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", "protocol.ssh.allow=always",
            "-c", "protocol.file.allow=never",
            "-c", "protocol.ext.allow=never",
            "-c", "http.sslVerify=true",
            "-c", "http.followRedirects=false",
        ]
        if self._allowed_signers_file is not None:
            result.extend([
                "-c", "gpg.format=ssh",
                "-c", f"gpg.ssh.allowedSignersFile={self._allowed_signers_file}",
                "-c", "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c", "gpg.minTrustLevel=fully",
            ])
        return result

    def _environment(self) -> dict[str, str]:
        environment = {
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CEILING_DIRECTORIES": "/",
            "LC_ALL": "C",
            "LANG": "C",
        }
        if self._ssh_known_hosts_file is not None and self._ssh_identity_file is not None:
            ssh_arguments = [
                "/usr/bin/ssh",
                "-F", "/dev/null",
                "-oBatchMode=yes",
                "-oStrictHostKeyChecking=yes",
                "-oIdentitiesOnly=yes",
                f"-oUserKnownHostsFile={self._ssh_known_hosts_file}",
                "-oGlobalKnownHostsFile=/dev/null",
                f"-oIdentityFile={self._ssh_identity_file}",
                "-oClearAllForwardings=yes",
                "-oPermitLocalCommand=no",
                "-oProxyCommand=none",
                "-oProxyJump=none",
                "-oRequestTTY=no",
            ]
            environment["GIT_SSH_COMMAND"] = " ".join(
                shlex.quote(argument) for argument in ssh_arguments
            )
            environment["GIT_SSH_VARIANT"] = "ssh"
        return environment

    def run(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        allow_failure: bool = False,
        network: bool = False,
    ) -> bytes:
        command = ["git", *self._global_arguments()]
        if network:
            # ls-remote does not need a repository.  Running from the filesystem
            # root prevents discovery and loading of the audited repository's
            # local/worktree config during the network operation.
            command.extend(arguments)
            working_directory = Path("/")
        else:
            command.extend(["-C", str(repository), *arguments])
            working_directory = repository
        try:
            completed = subprocess.run(
                command,
                cwd=working_directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=not allow_failure,
                env=self._environment(),
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise GateError("GIT_PROVENANCE_COMMAND_FAILED") from None
        if len(completed.stdout) > 8_000_000 or len(completed.stderr) > 1_000_000:
            raise GateError("GIT_PROVENANCE_OUTPUT_TOO_LARGE")
        if allow_failure and completed.returncode != 0:
            raise GateError("GIT_SIGNATURE_INVALID")
        return completed.stdout


def read_production_template_blob(
    repository: Path,
    commit_object_id: str,
    object_format: str,
    *,
    runner: GitRunner | None = None,
) -> tuple[str, bytes]:
    """Read the production template from an exact commit without replacement refs."""
    if (
        not repository.is_absolute()
        or not repository.is_dir()
        or not _valid_object_id(commit_object_id, object_format)
    ):
        raise GateError("GIT_RELEASE_TEMPLATE_SOURCE_INVALID")
    command = runner or SubprocessGitRunner()
    try:
        root = Path(command.run(
            repository, ["rev-parse", "--show-toplevel"]
        ).decode("utf-8").strip())
    except (GateError, UnicodeDecodeError):
        raise GateError("GIT_RELEASE_TEMPLATE_SOURCE_INVALID") from None
    if root.resolve() != repository.resolve():
        raise GateError("GIT_REPOSITORY_ROOT_MISMATCH")
    _validate_local_git_config(command, repository)
    expression = f"{commit_object_id}:{PRODUCTION_STACK_TEMPLATE_GIT_PATH}"
    try:
        blob_object_id = command.run(
            repository, ["rev-parse", "--verify", expression]
        ).decode("utf-8").strip()
        object_type = command.run(
            repository, ["cat-file", "-t", blob_object_id]
        ).decode("utf-8").strip()
    except (GateError, UnicodeDecodeError):
        raise GateError("GIT_RELEASE_TEMPLATE_SOURCE_INVALID") from None
    if not _valid_object_id(blob_object_id, object_format) or object_type != "blob":
        raise GateError("GIT_RELEASE_TEMPLATE_SOURCE_INVALID")
    content = command.run(repository, ["cat-file", "blob", blob_object_id])
    if not content or len(content) > 8_000_000:
        raise GateError("GIT_RELEASE_TEMPLATE_SOURCE_INVALID")
    return blob_object_id, content


def _remote_host(url: str) -> str:
    return _canonical_remote(url)[0]


def collect_git_provenance(
    repository: Path,
    allowed_remote_hosts: set[str],
    *,
    require_clean: bool = True,
    require_signed_commit: bool = True,
    release_tag: str | None = None,
    allowed_signers_file: Path | None = None,
    ssh_known_hosts_file: Path | None = None,
    ssh_identity_file: Path | None = None,
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
    signature_trust_required = require_signed_commit or release_tag is not None
    allowed_signers_digest: str | None = None
    if signature_trust_required:
        allowed_signers = _read_protected_file(
            allowed_signers_file,
            missing_code="GIT_ALLOWED_SIGNERS_NOT_CONFIGURED",
            invalid_code="GIT_ALLOWED_SIGNERS_FILE_INVALID",
            maximum_bytes=1_048_576,
        )
        allowed_signers_digest = hashlib.sha256(allowed_signers).hexdigest()
    if (ssh_known_hosts_file is None) != (ssh_identity_file is None):
        raise ConfigurationMissing("GIT_SSH_TRANSPORT_NOT_CONFIGURED")
    if ssh_known_hosts_file is not None and ssh_identity_file is not None:
        _read_protected_file(
            ssh_known_hosts_file,
            missing_code="GIT_SSH_KNOWN_HOSTS_NOT_CONFIGURED",
            invalid_code="GIT_SSH_KNOWN_HOSTS_FILE_INVALID",
            maximum_bytes=1_048_576,
        )
        _read_protected_file(
            ssh_identity_file,
            missing_code="GIT_SSH_IDENTITY_NOT_CONFIGURED",
            invalid_code="GIT_SSH_IDENTITY_FILE_INVALID",
            maximum_bytes=64 * 1024,
            secret=True,
        )
    command = runner or SubprocessGitRunner(
        allowed_signers_file=allowed_signers_file,
        ssh_known_hosts_file=ssh_known_hosts_file,
        ssh_identity_file=ssh_identity_file,
    )
    try:
        root = Path(command.run(repository, ["rev-parse", "--show-toplevel"]).decode().strip())
    except GateError:
        raise ConfigurationMissing("GIT_REPOSITORY_NOT_CONFIGURED") from None
    if root.resolve() != repository.resolve():
        raise GateError("GIT_REPOSITORY_ROOT_MISMATCH")
    _validate_local_git_config(command, repository)
    head = command.run(repository, ["rev-parse", "HEAD"]).decode().strip()
    object_type = command.run(repository, ["cat-file", "-t", head]).decode().strip()
    tree = command.run(repository, ["rev-parse", "HEAD^{tree}"]).decode().strip()
    if not _OBJECT_ID.fullmatch(head) or not _OBJECT_ID.fullmatch(tree) or object_type != "commit":
        raise GateError("GIT_HEAD_INVALID")
    status = command.run(
        repository,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    ).decode()
    if require_clean and status:
        raise GateError("GIT_WORKTREE_DIRTY")
    submodules = command.run(repository, ["submodule", "status", "--recursive"]).decode()
    if any(line.startswith(("-", "+", "U")) for line in submodules.splitlines()):
        raise GateError("GIT_SUBMODULE_STATE_INVALID")
    try:
        configured_remote_names = command.run(repository, ["remote"]).decode("utf-8").splitlines()
        remote_lines = command.run(repository, ["remote", "-v"]).decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise GateError("GIT_REMOTE_INVALID") from None
    if (
        not configured_remote_names
        or len(configured_remote_names) > 64
        or len(configured_remote_names) != len(set(configured_remote_names))
        or any(not _SAFE_REMOTE_NAME.fullmatch(name) for name in configured_remote_names)
    ):
        raise GateError("GIT_REMOTE_INVALID")
    allowed_hosts = {item.lower() for item in allowed_remote_hosts}
    remotes: dict[str, tuple[str, str]] = {}
    remote_directions: dict[str, set[str]] = {}
    for line in remote_lines:
        parts = line.split()
        if (
            len(parts) != 3
            or parts[2] not in {"(fetch)", "(push)"}
            or not _SAFE_REMOTE_NAME.fullmatch(parts[0])
        ):
            raise GateError("GIT_REMOTE_INVALID")
        name, url = parts[0], parts[1]
        host, canonical_remote = _canonical_remote(url)
        if host not in allowed_hosts:
            raise GateError("GIT_REMOTE_HOST_DENIED")
        previous = remotes.setdefault(name, (host, canonical_remote))
        if previous != (host, canonical_remote):
            raise GateError("GIT_REMOTE_INVALID")
        remote_directions.setdefault(name, set()).add(parts[2])
    if set(remotes) != set(configured_remote_names) or any(
        directions != {"(fetch)", "(push)"} for directions in remote_directions.values()
    ):
        raise GateError("GIT_REMOTE_NOT_CONFIGURED")
    if (
        any(canonical.startswith("ssh://") for _, canonical in remotes.values())
        and (ssh_known_hosts_file is None or ssh_identity_file is None)
    ):
        raise ConfigurationMissing("GIT_SSH_TRANSPORT_NOT_CONFIGURED")
    commit_bytes = command.run(repository, ["cat-file", "commit", head])
    commit_signed = False
    if require_signed_commit:
        command.run(repository, ["verify-commit", head], allow_failure=True)
        commit_signed = True
    algorithm = "sha256" if len(head) == 64 else "sha1"
    tag_verified = False
    release_tag_object_id: str | None = None
    remote_tag_object_ids: dict[str, str] = {}
    remote_tag_peeled_commit_ids: dict[str, str] = {}
    remote_release_tag_ref: str | None = None
    if release_tag is not None:
        tag_target = command.run(repository, ["rev-list", "-n", "1", release_tag]).decode().strip()
        if tag_target != head:
            raise GateError("GIT_RELEASE_TAG_TARGET_MISMATCH")
        remote_release_tag_ref = f"refs/tags/{release_tag}"
        release_tag_object_id = command.run(
            repository, ["rev-parse", f"{remote_release_tag_ref}^{{tag}}"]
        ).decode().strip()
        if (
            not _valid_object_id(release_tag_object_id, algorithm)
            or release_tag_object_id == head
        ):
            raise GateError("GIT_RELEASE_TAG_OBJECT_INVALID")
        command.run(repository, ["verify-tag", release_tag], allow_failure=True)
        tag_verified = True
        peeled_ref = f"{remote_release_tag_ref}^{{}}"
        for remote_name in sorted(remotes):
            canonical_remote = remotes[remote_name][1]
            tag_object = _parse_remote_ref(
                command.run(
                    repository,
                    ["ls-remote", "--refs", canonical_remote, remote_release_tag_ref],
                    network=True,
                ),
                remote_release_tag_ref,
                algorithm,
            )
            peeled_commit = _parse_remote_ref(
                command.run(
                    repository,
                    ["ls-remote", canonical_remote, peeled_ref],
                    network=True,
                ),
                peeled_ref,
                algorithm,
            )
            if tag_object != release_tag_object_id or peeled_commit != head:
                raise GateError("GIT_REMOTE_RELEASE_TAG_TARGET_MISMATCH")
            remote_tag_object_ids[remote_name] = tag_object
            remote_tag_peeled_commit_ids[remote_name] = peeled_commit
    remote_hosts = sorted({host for host, _ in remotes.values()})
    remote_hosts_by_name = {
        name: host for name, (host, _) in sorted(remotes.items())
    }
    remote_url_digests = {
        name: hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        for name, (_, canonical) in sorted(remotes.items())
    }
    remote_set_digest = _digest(
        {
            name: {"host": host, "url_digest": remote_url_digests[name]}
            for name, (host, _) in sorted(remotes.items())
        }
    )
    remote_release_tag_verified = bool(
        release_tag is not None
        and tag_verified
        and len(remote_tag_object_ids) == len(remotes)
        and len(remote_tag_peeled_commit_ids) == len(remotes)
    )
    remote_membership_digest = (
        _digest({
            name: {
                "host": remote_hosts_by_name[name],
                "url_digest": remote_url_digests[name],
                "tag_ref": remote_release_tag_ref,
                "tag_object_id": remote_tag_object_ids[name],
                "peeled_commit_id": remote_tag_peeled_commit_ids[name],
            }
            for name in sorted(remotes)
        })
        if remote_release_tag_verified else None
    )
    return GateResult(
        gate="GIT_IMMUTABLE_PROVENANCE",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"git://{remote_hosts[0]}/{head}",
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
            "remote_hosts": remote_hosts,
            "remote_hosts_by_name": remote_hosts_by_name,
            "remote_url_digests": remote_url_digests,
            "remote_set_digest": remote_set_digest,
            "commit_signature_required": require_signed_commit,
            "commit_signature_verified": commit_signed,
            "release_tag_required": release_tag is not None,
            "release_tag": release_tag,
            "release_tag_object_id": release_tag_object_id,
            "release_tag_target": head if release_tag is not None else None,
            "release_tag_signature_verified": tag_verified,
            "remote_release_tag_verified": remote_release_tag_verified,
            "remote_release_tag_ref": remote_release_tag_ref,
            "remote_tag_object_ids": remote_tag_object_ids,
            "remote_tag_peeled_commit_ids": remote_tag_peeled_commit_ids,
            "remote_membership_digest": remote_membership_digest,
            "signature_trust_format": (
                "SSH_ALLOWED_SIGNERS" if signature_trust_required else "UNVERIFIED"
            ),
            "git_allowed_signers_digest": allowed_signers_digest,
        },
        production_evidence=(
            require_clean
            and require_signed_commit
            and tag_verified
            and remote_release_tag_verified
        ),
    )


def validate_git_provenance_report(
    value: object, *, require_production: bool = False
) -> Mapping[str, Any]:
    report = _strict_mapping(value, _REPORT_FIELDS, "GIT_PROVENANCE_REPORT_INVALID")
    claimed_evidence_digest = report.get("evidence_digest")
    unsigned_report = {key: child for key, child in report.items() if key != "evidence_digest"}
    if (
        report.get("schema_version") != "agenttrust.external-gate-report.v1"
        or report.get("gate") != "GIT_IMMUTABLE_PROVENANCE"
        or report.get("status") != "PASS_REAL_PROTOCOL"
        or not isinstance(claimed_evidence_digest, str)
        or not _DIGEST.fullmatch(claimed_evidence_digest)
        or claimed_evidence_digest != _digest(unsigned_report)
    ):
        raise GateError("GIT_PROVENANCE_REPORT_INVALID")
    measured_at = _parse_utc(report.get("measured_at"), "GIT_PROVENANCE_REPORT_INVALID")
    if measured_at > datetime.now(timezone.utc):
        raise GateError("GIT_PROVENANCE_REPORT_INVALID")
    if require_production and report.get("production_evidence") is not True:
        raise GateError("GIT_PROVENANCE_NOT_PRODUCTION_EVIDENCE")
    if not isinstance(report.get("production_evidence"), bool):
        raise GateError("GIT_PROVENANCE_REPORT_INVALID")

    checks = _strict_mapping(
        report.get("checks"), _CHECK_FIELDS, "GIT_PROVENANCE_CHECKS_INVALID"
    )
    algorithm = checks.get("object_format")
    commit_id = checks.get("commit_object_id")
    tree_id = checks.get("tree_object_id")
    expected_release = f"git:{algorithm}:{commit_id}"
    if (
        algorithm not in {"sha1", "sha256"}
        or not _valid_object_id(commit_id, str(algorithm))
        or not _valid_object_id(tree_id, str(algorithm))
        or checks.get("release_id") != expected_release
        or not isinstance(checks.get("commit_content_digest"), str)
        or not _DIGEST.fullmatch(str(checks["commit_content_digest"]))
        or checks.get("clean_worktree_required") is not True
        or checks.get("clean_worktree") is not True
        or checks.get("submodules_pinned") is not True
        or checks.get("commit_signature_required") is not True
        or checks.get("commit_signature_verified") is not True
        or checks.get("signature_trust_format") != "SSH_ALLOWED_SIGNERS"
        or not isinstance(checks.get("git_allowed_signers_digest"), str)
        or not _DIGEST.fullmatch(str(checks["git_allowed_signers_digest"]))
    ):
        raise GateError("GIT_PROVENANCE_COMMIT_FACTS_INVALID")

    remote_count = checks.get("remote_count")
    remote_hosts = checks.get("remote_hosts")
    remote_hosts_by_name = checks.get("remote_hosts_by_name")
    remote_url_digests = checks.get("remote_url_digests")
    if (
        not isinstance(remote_count, int)
        or isinstance(remote_count, bool)
        or not 1 <= remote_count <= 64
        or not isinstance(remote_hosts, list)
        or not remote_hosts
        or len(remote_hosts) > 64
        or any(not isinstance(host, str) for host in remote_hosts)
        or remote_hosts != sorted(set(remote_hosts))
        or any(not _SAFE_HOST.fullmatch(host) for host in remote_hosts)
        or not isinstance(remote_hosts_by_name, dict)
        or not isinstance(remote_url_digests, dict)
        or len(remote_hosts_by_name) != remote_count
        or set(remote_hosts_by_name) != set(remote_url_digests)
        or any(not isinstance(name, str) or not _SAFE_REMOTE_NAME.fullmatch(name)
               for name in remote_hosts_by_name)
        or any(not isinstance(host, str) or host not in remote_hosts
               for host in remote_hosts_by_name.values())
        or sorted(set(remote_hosts_by_name.values())) != remote_hosts
        or any(not isinstance(item, str) or not _DIGEST.fullmatch(item)
               for item in remote_url_digests.values())
    ):
        raise GateError("GIT_PROVENANCE_REMOTE_FACTS_INVALID")
    expected_remote_digest = _digest(
        {
            name: {
                "host": remote_hosts_by_name[name],
                "url_digest": remote_url_digests[name],
            }
            for name in sorted(remote_hosts_by_name)
        }
    )
    if (
        checks.get("remote_set_digest") != expected_remote_digest
        or report.get("environment_reference") != f"git://{remote_hosts[0]}/{commit_id}"
    ):
        raise GateError("GIT_PROVENANCE_REMOTE_FACTS_INVALID")

    tag_required = checks.get("release_tag_required")
    tag = checks.get("release_tag")
    tag_object_id = checks.get("release_tag_object_id")
    tag_target = checks.get("release_tag_target")
    tag_verified = checks.get("release_tag_signature_verified")
    if require_production and tag_required is not True:
        raise GateError("GIT_PROVENANCE_PRODUCTION_TAG_REQUIRED")
    if tag_required is True:
        if (
            not isinstance(tag, str)
            or not _SAFE_TAG.fullmatch(tag)
            or not _valid_object_id(tag_object_id, str(algorithm))
            or tag_object_id == commit_id
            or tag_target != commit_id
            or tag_verified is not True
        ):
            raise GateError("GIT_PROVENANCE_TAG_FACTS_INVALID")
        remote_ref = checks.get("remote_release_tag_ref")
        tag_objects = checks.get("remote_tag_object_ids")
        peeled_commits = checks.get("remote_tag_peeled_commit_ids")
        if (
            checks.get("remote_release_tag_verified") is not True
            or remote_ref != f"refs/tags/{tag}"
            or not isinstance(tag_objects, dict)
            or not isinstance(peeled_commits, dict)
            or set(tag_objects) != set(remote_hosts_by_name)
            or set(peeled_commits) != set(remote_hosts_by_name)
            or any(not _valid_object_id(item, str(algorithm)) or item != tag_object_id
                   for item in tag_objects.values())
            or any(item != commit_id for item in peeled_commits.values())
        ):
            raise GateError("GIT_PROVENANCE_REMOTE_MEMBERSHIP_INVALID")
        expected_membership_digest = _digest({
            name: {
                "host": remote_hosts_by_name[name],
                "url_digest": remote_url_digests[name],
                "tag_ref": remote_ref,
                "tag_object_id": tag_objects[name],
                "peeled_commit_id": peeled_commits[name],
            }
            for name in sorted(remote_hosts_by_name)
        })
        if checks.get("remote_membership_digest") != expected_membership_digest:
            raise GateError("GIT_PROVENANCE_REMOTE_MEMBERSHIP_INVALID")
    elif not (
        tag_required is False
        and tag is None
        and tag_object_id is None
        and tag_target is None
        and tag_verified is False
        and checks.get("remote_release_tag_verified") is False
        and checks.get("remote_release_tag_ref") is None
        and checks.get("remote_tag_object_ids") == {}
        and checks.get("remote_tag_peeled_commit_ids") == {}
        and checks.get("remote_membership_digest") is None
    ):
        raise GateError("GIT_PROVENANCE_TAG_FACTS_INVALID")
    return report


def _read_private_signing_key(path: Path) -> Ed25519PrivateKey:
    if not path.is_absolute() or path.is_symlink():
        raise ConfigurationMissing("GIT_PROVENANCE_SIGNING_KEY_NOT_CONFIGURED")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ConfigurationMissing("GIT_PROVENANCE_SIGNING_KEY_NOT_CONFIGURED") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 40
            or metadata.st_size > 128
            or os.name == "posix" and metadata.st_mode & 0o077
            or os.name == "posix" and hasattr(os, "geteuid") and metadata.st_uid != os.geteuid()
        ):
            raise GateError("GIT_PROVENANCE_SIGNING_KEY_FILE_INVALID")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            encoded = stream.read(129)
    finally:
        os.close(descriptor)
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError:
        raise GateError("GIT_PROVENANCE_SIGNING_KEY_INVALID") from None
    if text.strip() != text or not _BASE64URL_PUBLIC.fullmatch(text):
        raise GateError("GIT_PROVENANCE_SIGNING_KEY_INVALID")
    raw = _decode_base64url(text, 32, "GIT_PROVENANCE_SIGNING_KEY_INVALID")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError:
        raise GateError("GIT_PROVENANCE_SIGNING_KEY_INVALID") from None


def read_protected_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a raw Ed25519 key using the shared release-key file protections."""
    return _read_private_signing_key(path)


def _unsigned_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in sorted(_ENVELOPE_FIELDS - {"signature"})}


def sign_git_provenance(
    report: Mapping[str, Any],
    private_key_file: Path,
    *,
    issuer: str,
    key_id: str,
    signed_at: datetime | None = None,
) -> dict[str, Any]:
    validate_git_provenance_report(report, require_production=True)
    if not _SAFE_IDENTIFIER.fullmatch(issuer) or not _SAFE_KEY_ID.fullmatch(key_id):
        raise GateError("GIT_PROVENANCE_SIGNER_IDENTITY_INVALID")
    signing_key = _read_private_signing_key(private_key_file)
    raw_timestamp = signed_at or datetime.now(timezone.utc)
    if (
        raw_timestamp.tzinfo is None
        or raw_timestamp.utcoffset() != timezone.utc.utcoffset(raw_timestamp)
    ):
        raise GateError("GIT_PROVENANCE_SIGNED_AT_INVALID")
    timestamp = raw_timestamp.astimezone(timezone.utc)
    envelope: dict[str, Any] = {
        "schema_version": SIGNED_GIT_PROVENANCE_SCHEMA_VERSION,
        "report": dict(report),
        "report_digest": _digest(report),
        "issuer": issuer,
        "key_id": key_id,
        "key_usage": GIT_PROVENANCE_KEY_USAGE,
        "algorithm": GIT_PROVENANCE_ALGORITHM,
        "signed_at": timestamp.isoformat(),
    }
    envelope["signature"] = _encode_base64url(
        signing_key.sign(canonical_json(_unsigned_envelope(envelope)))
    )
    return envelope


def verify_signed_git_provenance(
    value: object,
    keyring_value: object,
    *,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    envelope = _strict_mapping(value, _ENVELOPE_FIELDS, "SIGNED_GIT_PROVENANCE_INVALID")
    if (
        envelope.get("schema_version") != SIGNED_GIT_PROVENANCE_SCHEMA_VERSION
        or envelope.get("key_usage") != GIT_PROVENANCE_KEY_USAGE
        or envelope.get("algorithm") != GIT_PROVENANCE_ALGORITHM
        or not isinstance(envelope.get("issuer"), str)
        or not _SAFE_IDENTIFIER.fullmatch(str(envelope["issuer"]))
        or not isinstance(envelope.get("key_id"), str)
        or not _SAFE_KEY_ID.fullmatch(str(envelope["key_id"]))
        or not isinstance(envelope.get("report_digest"), str)
        or not _DIGEST.fullmatch(str(envelope["report_digest"]))
        or not isinstance(envelope.get("signature"), str)
        or not _BASE64URL_SIGNATURE.fullmatch(str(envelope["signature"]))
    ):
        raise GateError("SIGNED_GIT_PROVENANCE_INVALID")
    report = validate_git_provenance_report(
        envelope.get("report"), require_production=True
    )
    if envelope["report_digest"] != _digest(report):
        raise GateError("SIGNED_GIT_PROVENANCE_REPORT_DIGEST_INVALID")
    signed_at = _parse_utc(envelope.get("signed_at"), "SIGNED_GIT_PROVENANCE_INVALID")
    raw_current_time = now or datetime.now(timezone.utc)
    if (
        raw_current_time.tzinfo is None
        or raw_current_time.utcoffset() != timezone.utc.utcoffset(raw_current_time)
    ):
        raise GateError("SIGNED_GIT_PROVENANCE_TIME_INVALID")
    current_time = raw_current_time.astimezone(timezone.utc)
    if signed_at > current_time:
        raise GateError("SIGNED_GIT_PROVENANCE_TIME_INVALID")

    keyring = _strict_mapping(
        keyring_value, _KEYRING_FIELDS, "GIT_PROVENANCE_KEYRING_INVALID"
    )
    keys = keyring.get("keys")
    if (
        keyring.get("schema_version") != GIT_PROVENANCE_KEYRING_SCHEMA_VERSION
        or not isinstance(keys, list)
        or not 1 <= len(keys) <= 64
    ):
        raise GateError("GIT_PROVENANCE_KEYRING_INVALID")
    matches: list[Mapping[str, Any]] = []
    identities: set[tuple[object, object, object]] = set()
    for raw_key in keys:
        key = _strict_mapping(raw_key, _KEY_FIELDS, "GIT_PROVENANCE_KEYRING_INVALID")
        if (
            not isinstance(key.get("issuer"), str)
            or not _SAFE_IDENTIFIER.fullmatch(str(key["issuer"]))
            or not isinstance(key.get("key_id"), str)
            or not _SAFE_KEY_ID.fullmatch(str(key["key_id"]))
            or key.get("key_usage") != GIT_PROVENANCE_KEY_USAGE
            or key.get("algorithm") != GIT_PROVENANCE_ALGORITHM
            or key.get("status") not in {"ACTIVE", "REVOKED"}
            or not isinstance(key.get("public_key"), str)
            or not _BASE64URL_PUBLIC.fullmatch(str(key["public_key"]))
        ):
            raise GateError("GIT_PROVENANCE_KEYRING_INVALID")
        identity = (key["issuer"], key["key_id"], key["key_usage"])
        if identity in identities:
            raise GateError("GIT_PROVENANCE_KEYRING_DUPLICATE")
        identities.add(identity)
        not_before = _parse_utc(key.get("not_before"), "GIT_PROVENANCE_KEYRING_INVALID")
        not_after = _parse_utc(key.get("not_after"), "GIT_PROVENANCE_KEYRING_INVALID")
        if not_before >= not_after:
            raise GateError("GIT_PROVENANCE_KEYRING_INVALID")
        if identity == (envelope["issuer"], envelope["key_id"], envelope["key_usage"]):
            if (
                key["status"] != "ACTIVE"
                or not not_before <= signed_at <= not_after
                or not not_before <= current_time <= not_after
            ):
                raise GateError("GIT_PROVENANCE_SIGNING_KEY_INACTIVE")
            matches.append(key)
    if len(matches) != 1:
        raise GateError("GIT_PROVENANCE_SIGNING_KEY_NOT_TRUSTED")
    key = matches[0]
    public_bytes = _decode_base64url(
        key["public_key"], 32, "GIT_PROVENANCE_PUBLIC_KEY_INVALID"
    )
    signature = _decode_base64url(
        envelope["signature"], 64, "GIT_PROVENANCE_SIGNATURE_INVALID"
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, canonical_json(_unsigned_envelope(envelope))
        )
    except (InvalidSignature, ValueError):
        raise GateError("GIT_PROVENANCE_SIGNATURE_INVALID") from None
    return report


def signed_git_provenance_digest(value: object) -> str:
    envelope = _strict_mapping(value, _ENVELOPE_FIELDS, "SIGNED_GIT_PROVENANCE_INVALID")
    return _digest(envelope)


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
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--git-allowed-signers-file", type=Path, required=True)
    parser.add_argument("--ssh-known-hosts-file", type=Path)
    parser.add_argument("--ssh-identity-file", type=Path)
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = collect_git_provenance(
            args.repository,
            set(args.allowed_remote_host),
            require_clean=True,
            require_signed_commit=True,
            release_tag=args.release_tag,
            allowed_signers_file=args.git_allowed_signers_file,
            ssh_known_hosts_file=args.ssh_known_hosts_file,
            ssh_identity_file=args.ssh_identity_file,
        )
        document = sign_git_provenance(
            result.as_dict(),
            args.signing_key_file,
            issuer=args.issuer,
            key_id=args.key_id,
        )
        exit_code = 0
    except ConfigurationMissing as error:
        document = GateResult(
            "GIT_IMMUTABLE_PROVENANCE", "NOT_RUN_CONFIGURATION", "unconfigured",
            {"error_code": str(error)},
        ).as_dict()
        exit_code = 3
    except GateError as error:
        document = GateResult(
            "GIT_IMMUTABLE_PROVENANCE", "FAIL", "configured-repository",
            {"error_code": str(error)},
        ).as_dict()
        exit_code = 2
    _write_new(args.output, document)
    print(json.dumps(document, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
