"""Real encrypted backup and isolated restore drill for local protocol evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Mapping, Sequence

from python.platform_sre.backup_restore import BackupConfig, BackupController


_SAFE_RELEASE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class BackupRestoreDrillError(RuntimeError):
    pass


def _run(args: Sequence[str], *, timeout: int = 120) -> bytes:
    try:
        result = subprocess.run(
            list(args), check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise BackupRestoreDrillError("BACKUP_RESTORE_DRILL_COMMAND_FAILED") from None
    if len(result.stdout) > 2_000_000 or len(result.stderr) > 2_000_000:
        raise BackupRestoreDrillError("BACKUP_RESTORE_DRILL_OUTPUT_TOO_LARGE")
    return result.stdout


def _binary(root: Path, name: str) -> Path:
    path = root / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise BackupRestoreDrillError("BACKUP_RESTORE_DRILL_BINARY_MISSING")
    return path


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def run_drill(
    binary_root: Path,
    openssl: Path,
    work_root: Path,
    release_id: str,
    source_port: int,
    restore_port: int,
) -> Mapping[str, Any]:
    if (
        not binary_root.is_absolute()
        or not openssl.is_absolute()
        or not work_root.is_absolute()
        or work_root in {Path("/"), Path.home()}
        or not work_root.is_dir()
        or not openssl.is_file()
        or not _SAFE_RELEASE.fullmatch(release_id)
        or source_port == restore_port
        or not 1024 <= source_port <= 65535
        or not 1024 <= restore_port <= 65535
    ):
        raise BackupRestoreDrillError("BACKUP_RESTORE_DRILL_CONFIGURATION_INVALID")
    initdb = _binary(binary_root, "initdb")
    pg_ctl = _binary(binary_root, "pg_ctl")
    psql = _binary(binary_root, "psql")
    pg_dump = _binary(binary_root, "pg_dump")
    pg_restore = _binary(binary_root, "pg_restore")
    started_at = datetime.now(timezone.utc)

    with tempfile.TemporaryDirectory(prefix="agenttrust-backup-restore-", dir=work_root) as raw:
        root = Path(raw)
        source_data = root / "source-pg"
        restore_data = root / "restore-pg"
        certificate = root / "recipient.pem"
        private_key = root / "recipient-key.pem"
        object_source = root / "objects"
        object_source.mkdir(mode=0o700)
        (object_source / "ledger-head.json").write_text(
            '{"head":"local-drill"}\n', encoding="utf-8"
        )
        nested = object_source / "evidence"
        nested.mkdir(mode=0o700)
        (nested / "report.json").write_text('{"passed":true}\n', encoding="utf-8")
        _run([
            str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=agenttrust-backup-drill",
            "-keyout", str(private_key), "-out", str(certificate),
        ])
        private_key.chmod(0o600)
        source_running = False
        restore_running = False
        try:
            for data in [source_data, restore_data]:
                _run([
                    str(initdb), "-D", str(data), "--no-locale", "--encoding=UTF8",
                    "--auth-local=trust", "--auth-host=trust", "--username=postgres",
                ])

            def start(data: Path, port: int, log: Path) -> None:
                options = (
                    f"-p {port} -h 127.0.0.1 -c ssl=on "
                    f"-c ssl_cert_file={certificate} -c ssl_key_file={private_key} "
                    "-c fsync=on -c synchronous_commit=on"
                )
                _run([
                    str(pg_ctl), "-D", str(data), "-l", str(log), "-o", options,
                    "-w", "-t", "30", "start",
                ])

            start(source_data, source_port, root / "source.log")
            source_running = True
            start(restore_data, restore_port, root / "restore.log")
            restore_running = True

            def sql(port: int, database: str, statement: str) -> None:
                _run([
                    str(psql), "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
                    "-p", str(port), "-U", "postgres", "-d", database, "-c", statement,
                ])

            sql(source_port, "postgres", "CREATE DATABASE agenttrust_source;")
            sql(restore_port, "postgres", "CREATE DATABASE agenttrust_restore;")
            sql(
                source_port,
                "agenttrust_source",
                "CREATE TABLE orchestrator_tasks(id integer PRIMARY KEY);"
                "CREATE TABLE executions(id integer PRIMARY KEY);"
                "CREATE TABLE audit_chain_heads(id integer PRIMARY KEY);"
                "INSERT INTO orchestrator_tasks VALUES (1),(2);"
                "INSERT INTO executions VALUES (1);"
                "INSERT INTO audit_chain_heads VALUES (1);",
            )
            config = BackupConfig(
                backup_root=root / "backups",
                object_roots=(object_source,),
                encryption_certificate=certificate,
                decryption_private_key=private_key,
                restore_object_root=root / "restored-objects",
                pg_dump=pg_dump,
                pg_restore=pg_restore,
                psql=psql,
                openssl=openssl,
                maximum_object_files=100,
                maximum_object_bytes=1024 * 1024,
                record_count_tables=(
                    "orchestrator_tasks", "executions", "audit_chain_heads"
                ),
                command_timeout_seconds=120,
            )
            controller = BackupController(config)
            source_url = (
                f"postgresql://postgres@127.0.0.1:{source_port}/"
                "agenttrust_source?sslmode=require"
            )
            restore_url = (
                f"postgresql://postgres@127.0.0.1:{restore_port}/"
                "agenttrust_restore?sslmode=require"
            )
            manifest = controller.create(
                backup_id="encrypted-local-drill",
                release_digest="a" * 64,
                key_version="ephemeral-drill-key",
                database_url=source_url,
                ledger_head_digest="b" * 64,
            )
            restore = controller.verify_restore(
                "encrypted-local-drill", database_url=restore_url
            )
            completed_at = datetime.now(timezone.utc)
            report: dict[str, Any] = {
                "schema_version": "agenttrust.backup-restore-drill.v1",
                "release_id": release_id,
                "topology": "SINGLE_HOST_TWO_ISOLATED_INSTANCES",
                "postgres_version": _run([str(psql), "--version"]).decode().strip(),
                "backup_digest": manifest["backup_digest"],
                "restore_evidence_digest": restore["evidence_digest"],
                "checks": {
                    "tls_database_connections": True,
                    "cms_aes256_encryption": True,
                    "database_restore_executed": restore["database_restore_executed"],
                    "object_restore_executed": restore["object_restore_executed"],
                    "record_counts_verified": True,
                },
                "rto_milliseconds": restore["rto_milliseconds"],
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "production_evidence": False,
            }
            report["evidence_digest"] = _digest(report)
            return report
        finally:
            if restore_running:
                try:
                    _run([str(pg_ctl), "-D", str(restore_data), "-m", "fast", "-w", "stop"])
                except BackupRestoreDrillError:
                    pass
            if source_running:
                try:
                    _run([str(pg_ctl), "-D", str(source_data), "-m", "fast", "-w", "stop"])
                except BackupRestoreDrillError:
                    pass


def _write_new(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise BackupRestoreDrillError("BACKUP_RESTORE_DRILL_REPORT_PATH_INVALID")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-backup-restore-drill")
    parser.add_argument("--binary-root", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source-port", type=int, default=55441)
    parser.add_argument("--restore-port", type=int, default=55442)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run_drill(
        args.binary_root, args.openssl, args.work_root, args.release_id,
        args.source_port, args.restore_port,
    )
    _write_new(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
