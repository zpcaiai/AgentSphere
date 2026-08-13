"""Encrypted PostgreSQL/object backup and isolated restore verification.

Commands are executed without a shell, database credentials are passed through a
dedicated child environment, output is bounded, and every artifact is hashed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import parse_qs, unquote, urlparse


_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_SAFE_TABLE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class BackupConfig:
    backup_root: Path
    object_roots: tuple[Path, ...]
    encryption_certificate: Path
    decryption_private_key: Path | None
    restore_object_root: Path | None
    pg_dump: Path
    pg_restore: Path
    psql: Path
    openssl: Path
    maximum_object_files: int
    maximum_object_bytes: int
    record_count_tables: tuple[str, ...]
    command_timeout_seconds: int

    @classmethod
    def load(cls, path: Path) -> "BackupConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if (
            raw.get("schema_version") != "agenttrust.backup-config.v1"
            or raw.get("profile") != "production"
            or raw.get("fail_closed") is not True
            or raw.get("encrypted") is not True
        ):
            raise ValueError("BACKUP_CONFIG_INVALID")
        config = cls(
            backup_root=Path(raw["backup_root"]),
            object_roots=tuple(Path(value) for value in raw.get("object_roots", [])),
            encryption_certificate=Path(raw["encryption_certificate"]),
            decryption_private_key=Path(raw["decryption_private_key"]) if raw.get("decryption_private_key") else None,
            restore_object_root=Path(raw["restore_object_root"]) if raw.get("restore_object_root") else None,
            pg_dump=Path(raw["binaries"]["pg_dump"]),
            pg_restore=Path(raw["binaries"]["pg_restore"]),
            psql=Path(raw["binaries"]["psql"]),
            openssl=Path(raw["binaries"]["openssl"]),
            maximum_object_files=int(raw["maximum_object_files"]),
            maximum_object_bytes=int(raw["maximum_object_bytes"]),
            record_count_tables=tuple(raw["record_count_tables"]),
            command_timeout_seconds=int(raw["command_timeout_seconds"]),
        )
        paths = [config.backup_root, config.encryption_certificate, config.pg_dump, config.pg_restore, config.psql, config.openssl, *config.object_roots]
        if config.restore_object_root is not None:
            paths.append(config.restore_object_root)
        if (
            any(not item.is_absolute() for item in paths)
            or config.backup_root in {Path("/"), Path.home()}
            or config.restore_object_root in {Path("/"), Path.home()}
            or config.restore_object_root in config.object_roots
            or config.maximum_object_files <= 0
            or config.maximum_object_bytes <= 0
            or not 1 <= config.command_timeout_seconds <= 86_400
            or not config.record_count_tables
            or any(not _SAFE_TABLE.fullmatch(table) for table in config.record_count_tables)
        ):
            raise ValueError("BACKUP_CONFIG_INVALID")
        return config


class CommandRunner(Protocol):
    def run(self, args: Sequence[str], *, env: Mapping[str, str], timeout: int) -> bytes: ...


class SubprocessRunner:
    def run(self, args: Sequence[str], *, env: Mapping[str, str], timeout: int) -> bytes:
        try:
            result = subprocess.run(
                list(args),
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(env),
                timeout=timeout,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError("BACKUP_COMMAND_FAILED") from exc
        if len(result.stdout) > 1_048_576 or len(result.stderr) > 1_048_576:
            raise RuntimeError("BACKUP_COMMAND_OUTPUT_TOO_LARGE")
        return result.stdout


def _postgres_env(database_url: str, *, override_database: str | None = None) -> dict[str, str]:
    parsed = urlparse(database_url)
    query = parse_qs(parsed.query)
    sslmode = query.get("sslmode", [""])[0]
    database = override_database or parsed.path.lstrip("/")
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or not parsed.hostname
        or not parsed.username
        or not database
        or sslmode not in {"require", "verify-ca", "verify-full"}
    ):
        raise ValueError("BACKUP_DATABASE_URL_INVALID")
    env = {
        "PATH": "/usr/bin:/bin",
        "PGHOST": parsed.hostname,
        "PGPORT": str(parsed.port or 5432),
        "PGUSER": unquote(parsed.username),
        "PGDATABASE": database,
        "PGSSLMODE": sslmode,
        "LC_ALL": "C",
    }
    if parsed.password:
        env["PGPASSWORD"] = unquote(parsed.password)
    return env


class BackupController:
    def __init__(self, config: BackupConfig, runner: CommandRunner | None = None) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()

    def _run(self, args: Sequence[str], env: Mapping[str, str]) -> bytes:
        return self._runner.run(args, env=env, timeout=self._config.command_timeout_seconds)

    def _encrypt(self, source: Path, destination: Path, env: Mapping[str, str]) -> None:
        self._run(
            [
                str(self._config.openssl), "cms", "-encrypt", "-binary", "-aes256",
                "-outform", "DER", "-in", str(source), "-out", str(destination),
                str(self._config.encryption_certificate),
            ],
            env,
        )
        if not destination.is_file() or destination.stat().st_size == 0:
            raise RuntimeError("BACKUP_ENCRYPTION_FAILED")

    def _archive_objects(self, destination: Path) -> tuple[int, int]:
        file_count = 0
        byte_count = 0
        with tarfile.open(destination, "w") as archive:
            for root in self._config.object_roots:
                resolved_root = root.resolve(strict=True)
                if not resolved_root.is_dir():
                    raise RuntimeError("BACKUP_OBJECT_ROOT_INVALID")
                for item in sorted(resolved_root.rglob("*")):
                    if item.is_symlink():
                        raise RuntimeError("BACKUP_OBJECT_SYMLINK_DENIED")
                    if not item.is_file():
                        continue
                    file_count += 1
                    byte_count += item.stat().st_size
                    if file_count > self._config.maximum_object_files or byte_count > self._config.maximum_object_bytes:
                        raise RuntimeError("BACKUP_OBJECT_CAPACITY_EXCEEDED")
                    archive.add(item, arcname=f"{resolved_root.name}/{item.relative_to(resolved_root)}", recursive=False)
        return file_count, byte_count

    def create(self, *, backup_id: str, release_digest: str, key_version: str, database_url: str, ledger_head_digest: str) -> Mapping[str, Any]:
        if (
            not _SAFE_ID.fullmatch(backup_id)
            or not _SAFE_ID.fullmatch(key_version)
            or not re.fullmatch(r"[0-9a-f]{64}", release_digest)
            or not re.fullmatch(r"[0-9a-f]{64}", ledger_head_digest)
        ):
            raise ValueError("BACKUP_REQUEST_INVALID")
        env = _postgres_env(database_url)
        root = self._config.backup_root.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        final = root / backup_id
        if final.exists():
            raise FileExistsError("BACKUP_ID_ALREADY_EXISTS")
        working = Path(tempfile.mkdtemp(prefix=f".{backup_id}-", dir=root))
        try:
            database_plain = working / "database.dump"
            database_encrypted = working / "database.dump.cms"
            objects_plain = working / "objects.tar"
            objects_encrypted = working / "objects.tar.cms"
            self._run([str(self._config.pg_dump), "--format=custom", "--no-owner", "--no-acl", f"--file={database_plain}"], env)
            if not database_plain.is_file() or database_plain.stat().st_size == 0:
                raise RuntimeError("BACKUP_DATABASE_EMPTY")
            lsn = self._run([str(self._config.psql), "--no-psqlrc", "--tuples-only", "--no-align", "--command=SELECT pg_current_wal_lsn();"], env).decode().strip()
            if not lsn or len(lsn) > 128:
                raise RuntimeError("BACKUP_LSN_INVALID")
            record_counts: dict[str, int] = {}
            for table in self._config.record_count_tables:
                value = self._run([str(self._config.psql), "--no-psqlrc", "--tuples-only", "--no-align", f"--command=SELECT count(*) FROM {table};"], env).decode().strip()
                if not value.isdigit():
                    raise RuntimeError("BACKUP_RECORD_COUNT_INVALID")
                record_counts[table] = int(value)
            object_count, object_bytes = self._archive_objects(objects_plain)
            self._encrypt(database_plain, database_encrypted, env)
            self._encrypt(objects_plain, objects_encrypted, env)
            database_plain.unlink()
            objects_plain.unlink()
            unsigned = {
                "schema_version": "agenttrust.backup-manifest.v1",
                "backup_id": backup_id,
                "release_digest": release_digest,
                "database_lsn": lsn,
                "database_artifact_digest": _file_digest(database_encrypted),
                "object_manifest_digest": _file_digest(objects_encrypted),
                "object_count": object_count,
                "object_bytes": object_bytes,
                "ledger_head_digest": ledger_head_digest,
                "record_counts": record_counts,
                "encrypted": True,
                "encryption_format": "CMS_AES256",
                "key_version": key_version,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "production_restore_verified": False,
            }
            manifest = {**unsigned, "backup_digest": _canonical_digest(unsigned)}
            (working / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            os.replace(working, final)
            return manifest
        except BaseException:
            shutil.rmtree(working, ignore_errors=True)
            raise

    def verify_restore(self, backup_id: str, *, database_url: str) -> Mapping[str, Any]:
        if (
            not _SAFE_ID.fullmatch(backup_id)
            or self._config.decryption_private_key is None
            or self._config.restore_object_root is None
        ):
            raise ValueError("RESTORE_REQUEST_INVALID")
        directory = self._config.backup_root.resolve() / backup_id
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        unsigned = dict(manifest)
        claimed_digest = unsigned.pop("backup_digest", "")
        if (
            claimed_digest != _canonical_digest(unsigned)
            or _file_digest(directory / "database.dump.cms") != manifest["database_artifact_digest"]
            or _file_digest(directory / "objects.tar.cms") != manifest["object_manifest_digest"]
        ):
            raise RuntimeError("RESTORE_MANIFEST_TAMPERED")
        env = _postgres_env(database_url)
        restore_target = self._config.restore_object_root.resolve() / backup_id
        if restore_target.exists():
            raise FileExistsError("RESTORE_OBJECT_TARGET_ALREADY_EXISTS")
        restore_target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        restore_target.mkdir(mode=0o700)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="agenttrust-restore-") as raw_temp:
            temp = Path(raw_temp)
            database_decrypted = temp / "database.dump"
            objects_decrypted = temp / "objects.tar"
            try:
                for source, destination in [
                    (directory / "database.dump.cms", database_decrypted),
                    (directory / "objects.tar.cms", objects_decrypted),
                ]:
                    self._run(
                        [str(self._config.openssl), "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(source), "-out", str(destination), "-recip", str(self._config.encryption_certificate), "-inkey", str(self._config.decryption_private_key)],
                        env,
                    )
                listing = self._run(
                    [str(self._config.pg_restore), "--list", str(database_decrypted)], env
                )
                if not listing.strip():
                    raise RuntimeError("RESTORE_DATABASE_ARCHIVE_INVALID")
                existing = self._run(
                    [str(self._config.psql), "--no-psqlrc", "--tuples-only", "--no-align",
                     "--command=SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema');"],
                    env,
                ).decode().strip()
                if existing != "0":
                    raise RuntimeError("RESTORE_DATABASE_TARGET_NOT_EMPTY")
                self._run(
                    [str(self._config.pg_restore), "--exit-on-error", "--no-owner", "--no-acl",
                     f"--dbname={env['PGDATABASE']}", str(database_decrypted)],
                    env,
                )
                actual_counts: dict[str, int] = {}
                for table, expected in manifest["record_counts"].items():
                    if not _SAFE_TABLE.fullmatch(table) or not isinstance(expected, int):
                        raise RuntimeError("RESTORE_MANIFEST_RECORD_COUNT_INVALID")
                    value = self._run(
                        [str(self._config.psql), "--no-psqlrc", "--tuples-only", "--no-align",
                         f"--command=SELECT count(*) FROM {table};"],
                        env,
                    ).decode().strip()
                    if not value.isdigit() or int(value) != expected:
                        raise RuntimeError("RESTORE_RECORD_COUNT_MISMATCH")
                    actual_counts[table] = int(value)

                restored_files = 0
                restored_bytes = 0
                with tarfile.open(objects_decrypted, "r") as archive:
                    for member in archive:
                        member_path = Path(member.name)
                        if (
                            member_path.is_absolute()
                            or ".." in member_path.parts
                            or member.issym()
                            or member.islnk()
                            or member.isdev()
                        ):
                            raise RuntimeError("RESTORE_OBJECT_ARCHIVE_UNSAFE")
                        target = restore_target.joinpath(*member_path.parts)
                        if member.isdir():
                            target.mkdir(mode=0o700, parents=True, exist_ok=True)
                            continue
                        if not member.isfile():
                            raise RuntimeError("RESTORE_OBJECT_ARCHIVE_UNSAFE")
                        restored_files += 1
                        restored_bytes += member.size
                        if (
                            restored_files > self._config.maximum_object_files
                            or restored_bytes > self._config.maximum_object_bytes
                        ):
                            raise RuntimeError("RESTORE_OBJECT_CAPACITY_EXCEEDED")
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        source = archive.extractfile(member)
                        if source is None:
                            raise RuntimeError("RESTORE_OBJECT_ARCHIVE_INVALID")
                        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with source, os.fdopen(fd, "wb") as destination:
                            shutil.copyfileobj(source, destination, length=1024 * 1024)
                if (
                    restored_files != manifest["object_count"]
                    or restored_bytes != manifest["object_bytes"]
                ):
                    raise RuntimeError("RESTORE_OBJECT_COUNT_MISMATCH")
            except BaseException:
                shutil.rmtree(restore_target, ignore_errors=True)
                raise
        report = {
            "schema_version": "agenttrust.restore-verification.v1",
            "backup_id": backup_id,
            "backup_digest": claimed_digest,
            "database_archive_verified": True,
            "object_archive_digest_verified": True,
            "database_restore_executed": True,
            "object_restore_executed": True,
            "record_counts_verified": actual_counts,
            "restored_object_count": restored_files,
            "restored_object_bytes": restored_bytes,
            "actual_restore_executed": True,
            "rto_milliseconds": int((time.monotonic() - started) * 1000),
            "production_evidence": False,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
        return {**report, "evidence_digest": _canonical_digest(report)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-backup-restore")
    parser.add_argument("--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--backup-id", required=True)
    create.add_argument("--release-digest", required=True)
    create.add_argument("--key-version", required=True)
    create.add_argument("--ledger-head-digest", required=True)
    verify = sub.add_parser("verify-restore")
    verify.add_argument("--backup-id", required=True)
    args = parser.parse_args(argv)
    database_url = os.environ.get("AGENT_TRUST_DATABASE_URL", "")
    controller = BackupController(BackupConfig.load(args.config))
    if args.command == "create":
        result = controller.create(backup_id=args.backup_id, release_digest=args.release_digest, key_version=args.key_version, database_url=database_url, ledger_head_digest=args.ledger_head_digest)
    else:
        result = controller.verify_restore(args.backup_id, database_url=database_url)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
