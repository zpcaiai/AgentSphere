"""Controlled real-endpoint probe boundary for OPC UA, MQTT and Modbus.

Protocol clients are deployment-owned, reviewed binaries. This runner binds an
approved executable digest to fixed argv, requires mTLS material, accepts only
a strict redacted JSON receipt, and never invokes a shell. It is read-only by
construction; physical writes remain behind the Rust PEP/two-phase gateway.
"""

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

from python.production_gates.live_integrations import ConfigurationMissing, GateError, GateResult


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:=;-]{0,511}$")
_PROTOCOL_SCHEMES = {
    "opcua": {"opc.tcp"},
    "mqtt": {"mqtts", "ssl"},
    "modbus": {"modbus+tls"},
}


class Runner(Protocol):
    def run(self, arguments: Sequence[str], timeout_seconds: int) -> bytes: ...


class SubprocessRunner:
    def run(self, arguments: Sequence[str], timeout_seconds: int) -> bytes:
        try:
            completed = subprocess.run(
                list(arguments), check=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise GateError("INDUSTRIAL_PROTOCOL_PROBE_FAILED") from None
        if len(completed.stdout) > 1_048_576 or len(completed.stderr) > 1_048_576:
            raise GateError("INDUSTRIAL_PROTOCOL_OUTPUT_TOO_LARGE")
        return completed.stdout


def _regular_file(path: Path, code: str, private: bool = False) -> None:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ConfigurationMissing(code)
    if private and os.name == "posix" and path.stat().st_mode & 0o077:
        raise GateError("INDUSTRIAL_PRIVATE_KEY_PERMISSIONS_TOO_OPEN")


def probe_industrial_read(
    protocol: str,
    executable: Path,
    executable_sha256: str,
    endpoint: str,
    resource_address: str,
    ca_file: Path,
    client_certificate: Path,
    client_private_key: Path,
    *,
    timeout_seconds: int = 20,
    runner: Runner | None = None,
) -> GateResult:
    parsed = urlparse(endpoint)
    if (
        protocol not in _PROTOCOL_SCHEMES
        or parsed.scheme not in _PROTOCOL_SCHEMES[protocol]
        or not parsed.hostname
        or parsed.hostname in {"localhost", "127.0.0.1", "::1", "169.254.169.254"}
        or parsed.username is not None
        or parsed.password is not None
        or not _RESOURCE.fullmatch(resource_address)
        or not _SHA256.fullmatch(executable_sha256)
        or not 1 <= timeout_seconds <= 120
    ):
        raise GateError("INDUSTRIAL_PROTOCOL_CONFIGURATION_INVALID")
    _regular_file(executable, "INDUSTRIAL_PROTOCOL_CLIENT_NOT_CONFIGURED")
    _regular_file(ca_file, "INDUSTRIAL_CA_NOT_CONFIGURED")
    _regular_file(client_certificate, "INDUSTRIAL_CLIENT_CERTIFICATE_NOT_CONFIGURED")
    _regular_file(client_private_key, "INDUSTRIAL_CLIENT_PRIVATE_KEY_NOT_CONFIGURED", private=True)
    actual_executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    if actual_executable_digest != executable_sha256:
        raise GateError("INDUSTRIAL_PROTOCOL_CLIENT_DIGEST_MISMATCH")
    payload = (runner or SubprocessRunner()).run(
        [
            str(executable), "read", "--protocol", protocol, "--endpoint", endpoint,
            "--resource", resource_address, "--ca-file", str(ca_file),
            "--client-certificate", str(client_certificate),
            "--client-private-key", str(client_private_key), "--output", "json-redacted",
        ],
        timeout_seconds,
    )
    try:
        receipt = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GateError("INDUSTRIAL_PROTOCOL_RECEIPT_INVALID") from None
    allowed = {
        "schema_version", "protocol", "connected", "mutual_tls", "security_mode",
        "server_certificate_sha256", "resource_address_sha256", "quality",
        "resource_version", "sampled_at", "value_sha256", "write_executed",
    }
    if not isinstance(receipt, dict) or set(receipt) != allowed:
        raise GateError("INDUSTRIAL_PROTOCOL_RECEIPT_INVALID")
    digests = (
        receipt.get("server_certificate_sha256"),
        receipt.get("resource_address_sha256"),
        receipt.get("value_sha256"),
    )
    if (
        receipt.get("schema_version") != "agenttrust.industrial-probe-receipt.v1"
        or receipt.get("protocol") != protocol
        or receipt.get("connected") is not True
        or receipt.get("mutual_tls") is not True
        or receipt.get("quality") != "GOOD"
        or receipt.get("write_executed") is not False
        or not isinstance(receipt.get("security_mode"), str)
        or receipt.get("security_mode") in {"NONE", "PLAINTEXT", "ANONYMOUS"}
        or not isinstance(receipt.get("resource_version"), str)
        or not receipt.get("resource_version")
        or not isinstance(receipt.get("sampled_at"), str)
        or any(not isinstance(value, str) or not _SHA256.fullmatch(value) for value in digests)
        or receipt.get("resource_address_sha256")
        != hashlib.sha256(resource_address.encode()).hexdigest()
    ):
        raise GateError("INDUSTRIAL_PROTOCOL_RECEIPT_INVALID")
    return GateResult(
        gate=f"INDUSTRIAL_{protocol.upper()}_READ_ONLY_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"industrial://{protocol}/{parsed.hostname}:{parsed.port or 443}",
        checks={
            "approved_client_digest": actual_executable_digest,
            "connected": True,
            "mutual_tls": True,
            "security_mode": receipt["security_mode"],
            "server_certificate_digest": receipt["server_certificate_sha256"],
            "resource_address_digest": receipt["resource_address_sha256"],
            "quality_good": True,
            "resource_version_digest": hashlib.sha256(
                receipt["resource_version"].encode()
            ).hexdigest(),
            "value_digest": receipt["value_sha256"],
            "read_only": True,
            "write_executed": False,
            "device_credentials_redacted": True,
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-industrial-protocol-gate")
    parser.add_argument("--protocol", choices=sorted(_PROTOCOL_SCHEMES), required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--executable-sha256", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--client-certificate", type=Path, required=True)
    parser.add_argument("--client-private-key", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = probe_industrial_read(
            args.protocol, args.executable, args.executable_sha256, args.endpoint,
            args.resource, args.ca_file, args.client_certificate,
            args.client_private_key, timeout_seconds=args.timeout_seconds,
        )
        exit_code = 0
    except ConfigurationMissing as error:
        result = GateResult(
            f"INDUSTRIAL_{args.protocol.upper()}_READ_ONLY_REAL_PROTOCOL",
            "NOT_RUN_CONFIGURATION", "unconfigured", {"error_code": str(error)},
        )
        exit_code = 3
    except GateError as error:
        result = GateResult(
            f"INDUSTRIAL_{args.protocol.upper()}_READ_ONLY_REAL_PROTOCOL",
            "FAIL", "configured-target", {"error_code": str(error)},
        )
        exit_code = 2
    if not args.output.is_absolute() or args.output.exists():
        raise GateError("INDUSTRIAL_REPORT_PATH_INVALID")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(result.as_dict(), stream, sort_keys=True, indent=2)
        stream.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
