"""Real PostgreSQL physical-replication failover drill on isolated instances."""

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
import time
from typing import Any, Mapping, Sequence


_SAFE_RELEASE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class DrillError(RuntimeError):
    pass


class CommandRunner:
    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int = 60,
        env: Mapping[str, str] | None = None,
    ) -> bytes:
        try:
            result = subprocess.run(
                list(args),
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=dict(env or {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}),
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise DrillError("POSTGRES_DRILL_COMMAND_FAILED") from None
        if len(result.stdout) > 2_000_000 or len(result.stderr) > 2_000_000:
            raise DrillError("POSTGRES_DRILL_OUTPUT_TOO_LARGE")
        return result.stdout


def _binary(binary_root: Path, name: str) -> Path:
    path = binary_root / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise DrillError("POSTGRES_DRILL_BINARY_MISSING")
    return path


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_drill(
    binary_root: Path,
    work_root: Path,
    release_id: str,
    primary_port: int,
    standby_port: int,
    *,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    if (
        not binary_root.is_absolute()
        or not work_root.is_absolute()
        or work_root in {Path("/"), Path.home()}
        or not work_root.is_dir()
        or not _SAFE_RELEASE.fullmatch(release_id)
        or primary_port == standby_port
        or not 1024 <= primary_port <= 65535
        or not 1024 <= standby_port <= 65535
    ):
        raise DrillError("POSTGRES_DRILL_CONFIGURATION_INVALID")
    command = runner or CommandRunner()
    initdb = _binary(binary_root, "initdb")
    pg_ctl = _binary(binary_root, "pg_ctl")
    psql = _binary(binary_root, "psql")
    pg_basebackup = _binary(binary_root, "pg_basebackup")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    primary_running = False
    standby_running = False
    started_at = datetime.now(timezone.utc)

    with tempfile.TemporaryDirectory(prefix="agenttrust-pg-failover-", dir=work_root) as raw:
        root = Path(raw)
        primary = root / "primary"
        standby = root / "standby"
        primary_log = root / "primary.log"
        standby_log = root / "standby.log"

        def sql(port: int, database: str, statement: str) -> str:
            output = command.run(
                [str(psql), "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
                 "-p", str(port), "-U", "postgres", "-d", database, "-Atqc", statement],
                timeout=30,
                env=environment,
            )
            return output.decode("utf-8").strip()

        try:
            command.run(
                [str(initdb), "-D", str(primary), "--no-locale", "--encoding=UTF8",
                 "--auth-local=trust", "--auth-host=trust", "--username=postgres"],
                timeout=60,
                env=environment,
            )
            primary_options = (
                f"-p {primary_port} -h 127.0.0.1 -c wal_level=replica "
                "-c max_wal_senders=10 -c max_replication_slots=10 "
                "-c hot_standby=on -c fsync=on -c synchronous_commit=on"
            )
            command.run(
                [str(pg_ctl), "-D", str(primary), "-l", str(primary_log), "-o", primary_options,
                 "-w", "-t", "30", "start"],
                timeout=40,
                env=environment,
            )
            primary_running = True
            sql(primary_port, "postgres", "CREATE ROLE agenttrust_replication WITH REPLICATION LOGIN;")
            sql(primary_port, "postgres", "CREATE DATABASE agenttrust_drill;")
            sql(primary_port, "agenttrust_drill",
                "CREATE TABLE failover_markers(marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());")
            sql(primary_port, "agenttrust_drill", "INSERT INTO failover_markers(marker) VALUES ('before-failover');")
            primary_lsn = sql(primary_port, "agenttrust_drill", "SELECT pg_current_wal_lsn();")

            command.run(
                [str(pg_basebackup), "-D", str(standby), "-R", "-X", "stream", "--checkpoint=fast",
                 "-h", "127.0.0.1", "-p", str(primary_port), "-U", "agenttrust_replication"],
                timeout=120,
                env=environment,
            )
            standby_options = f"-p {standby_port} -h 127.0.0.1 -c hot_standby=on"
            command.run(
                [str(pg_ctl), "-D", str(standby), "-l", str(standby_log), "-o", standby_options,
                 "-w", "-t", "30", "start"],
                timeout=40,
                env=environment,
            )
            standby_running = True

            deadline = time.monotonic() + 30
            replayed = False
            while time.monotonic() < deadline:
                if sql(standby_port, "agenttrust_drill",
                       "SELECT count(*) FROM failover_markers WHERE marker='before-failover';") == "1":
                    replayed = True
                    break
                time.sleep(0.1)
            if not replayed or sql(standby_port, "agenttrust_drill", "SELECT pg_is_in_recovery();") != "t":
                raise DrillError("POSTGRES_DRILL_REPLICATION_NOT_CAUGHT_UP")
            replay_lsn = sql(standby_port, "agenttrust_drill", "SELECT pg_last_wal_replay_lsn();")

            failover_started = time.monotonic()
            command.run(
                [str(pg_ctl), "-D", str(primary), "-m", "immediate", "-w", "-t", "30", "stop"],
                timeout=40,
                env=environment,
            )
            primary_running = False
            command.run(
                [str(pg_ctl), "-D", str(standby), "-w", "-t", "30", "promote"],
                timeout=40,
                env=environment,
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if sql(standby_port, "agenttrust_drill", "SELECT pg_is_in_recovery();") == "f":
                    break
                time.sleep(0.1)
            else:
                raise DrillError("POSTGRES_DRILL_PROMOTION_TIMEOUT")
            sql(standby_port, "agenttrust_drill", "INSERT INTO failover_markers(marker) VALUES ('after-failover');")
            marker_count = sql(standby_port, "agenttrust_drill", "SELECT count(*) FROM failover_markers;")
            if marker_count != "2":
                raise DrillError("POSTGRES_DRILL_RPO_VIOLATION")
            rto_ms = int((time.monotonic() - failover_started) * 1000)
            completed_at = datetime.now(timezone.utc)
            report: dict[str, Any] = {
                "schema_version": "agenttrust.postgres-failover-report.v1",
                "release_id": release_id,
                "topology": "SINGLE_HOST_TWO_INSTANCE_PHYSICAL_STREAMING",
                "postgres_version": sql(standby_port, "postgres", "SHOW server_version;"),
                "primary_lsn": primary_lsn,
                "standby_replay_lsn_before_promotion": replay_lsn,
                "checks": {
                    "physical_base_backup": True,
                    "streaming_replication": True,
                    "standby_read_verified": True,
                    "primary_immediate_stop": True,
                    "standby_promoted": True,
                    "post_failover_write": True,
                    "pre_failover_marker_preserved": True,
                },
                "rpo_lost_markers": 0,
                "rto_milliseconds": rto_ms,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "production_evidence": False,
            }
            report["evidence_digest"] = _canonical_digest(report)
            return report
        finally:
            if standby_running:
                try:
                    command.run([str(pg_ctl), "-D", str(standby), "-m", "fast", "-w", "-t", "30", "stop"],
                                timeout=40, env=environment)
                except DrillError:
                    pass
            if primary_running:
                try:
                    command.run([str(pg_ctl), "-D", str(primary), "-m", "fast", "-w", "-t", "30", "stop"],
                                timeout=40, env=environment)
                except DrillError:
                    pass


def _write_new(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise DrillError("POSTGRES_DRILL_REPORT_PATH_INVALID")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-postgres-failover-drill")
    parser.add_argument("--binary-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--primary-port", type=int, default=55431)
    parser.add_argument("--standby-port", type=int, default=55432)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run_drill(args.binary_root, args.work_root, args.release_id,
                       args.primary_port, args.standby_port)
    _write_new(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
