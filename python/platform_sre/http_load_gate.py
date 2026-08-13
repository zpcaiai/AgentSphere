"""Bounded HTTP load gate with latency and status evidence."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import ssl
import time
from typing import Any, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


class LoadGateError(RuntimeError):
    pass


_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


def _percentile(sorted_values: list[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, max(0, math.ceil(percentile * len(sorted_values)) - 1))
    return sorted_values[index]


def run_load_gate(
    url: str,
    requests: int,
    concurrency: int,
    expected_status: int,
    minimum_success_ratio: float,
    maximum_p99_ms: float,
    *,
    allow_http_local: bool = False,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    header_environments: dict[str, str] | None = None,
    body: bytes | None = None,
    duration_seconds: float | None = None,
) -> dict[str, Any]:
    parsed = urlparse(url)
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    request_headers = dict(headers or {})
    environment_headers = dict(header_environments or {})
    if (
        parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.scheme not in {"http", "https"}
        or parsed.scheme == "http" and not (allow_http_local and local)
        or not 1 <= requests <= 100_000
        or not 1 <= concurrency <= min(512, requests)
        or not 100 <= expected_status <= 599
        or not 0 < minimum_success_ratio <= 1
        or not 1 <= maximum_p99_ms <= 120_000
        or method not in {"GET", "POST"}
        or body is not None and len(body) > 1_048_576
        or duration_seconds is not None and not 1 <= duration_seconds <= 86_400
        or any(
            not _HEADER_NAME.fullmatch(name)
            or name.lower() in _SENSITIVE_HEADERS
            or not value
            or len(value) > 1024
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            for name, value in request_headers.items()
        )
        or any(
            not _HEADER_NAME.fullmatch(name)
            or not _ENVIRONMENT_NAME.fullmatch(environment)
            or name in request_headers
            for name, environment in environment_headers.items()
        )
    ):
        raise LoadGateError("HTTP_LOAD_CONFIGURATION_INVALID")
    for name, environment in environment_headers.items():
        value = os.environ.get(environment, "")
        if (
            not value
            or len(value) > 16_384
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise LoadGateError("HTTP_LOAD_SECRET_HEADER_NOT_CONFIGURED")
        request_headers[name] = value
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = build_opener(ProxyHandler({}) if local else ProxyHandler(), HTTPSHandler(context=context))

    schedule_started = time.perf_counter()

    def request_once(index: int) -> tuple[int, float]:
        if duration_seconds is not None and requests > 1:
            scheduled = schedule_started + (duration_seconds * index / (requests - 1))
            remaining = scheduled - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)
        started = time.perf_counter_ns()
        status = 0
        try:
            with opener.open(
                Request(
                    url,
                    data=body,
                    method=method,
                    headers={"Accept": "application/json", **request_headers},
                ),
                timeout=10,
            ) as response:
                status = response.status
                if len(response.read(65_537)) > 65_536:
                    raise LoadGateError("HTTP_LOAD_RESPONSE_TOO_LARGE")
        except HTTPError as exc:
            status = exc.code
            exc.close()
        except (URLError, TimeoutError, OSError):
            status = 0
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        return status, elapsed_ms

    started_at = datetime.now(timezone.utc)
    wall_started = time.perf_counter_ns()
    statuses: dict[int, int] = {}
    latencies: list[float] = []
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="agenttrust-load") as pool:
        futures = [pool.submit(request_once, index) for index in range(requests)]
        for future in as_completed(futures):
            status, latency = future.result()
            statuses[status] = statuses.get(status, 0) + 1
            latencies.append(latency)
    elapsed_seconds = (time.perf_counter_ns() - wall_started) / 1_000_000_000
    latencies.sort()
    successful = statuses.get(expected_status, 0)
    ratio = successful / requests
    p99 = _percentile(latencies, 0.99)
    duration_met = duration_seconds is None or elapsed_seconds >= duration_seconds * 0.99
    passed = ratio >= minimum_success_ratio and p99 <= maximum_p99_ms and duration_met
    report: dict[str, Any] = {
        "schema_version": "agenttrust.http-load-report.v1",
        "target_reference": f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}{parsed.path}",
        "requests": requests,
        "concurrency": concurrency,
        "expected_status": expected_status,
        "method": method,
        "request_header_names": sorted(name.lower() for name in request_headers),
        "secret_header_names": sorted(name.lower() for name in environment_headers),
        "request_body_digest": hashlib.sha256(body or b"").hexdigest(),
        "status_counts": {str(key): value for key, value in sorted(statuses.items())},
        "success_ratio": ratio,
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.50), 3),
            "p95": round(_percentile(latencies, 0.95), 3),
            "p99": round(p99, 3),
            "maximum": round(latencies[-1], 3),
        },
        "throughput_requests_per_second": round(requests / elapsed_seconds, 3),
        "sustained_duration_seconds": duration_seconds,
        "observed_duration_seconds": round(elapsed_seconds, 3),
        "sustained_duration_met": duration_met,
        "thresholds": {
            "minimum_success_ratio": minimum_success_ratio,
            "maximum_p99_ms": maximum_p99_ms,
        },
        "passed": passed,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "production_evidence": False,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["evidence_digest"] = hashlib.sha256(canonical).hexdigest()
    return report


def _write_new(path: Path, report: dict[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise LoadGateError("HTTP_LOAD_REPORT_PATH_INVALID")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-http-load-gate")
    parser.add_argument("--url", required=True)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--expected-status", type=int, default=200)
    parser.add_argument("--minimum-success-ratio", type=float, default=0.999)
    parser.add_argument("--maximum-p99-ms", type=float, default=1000)
    parser.add_argument("--allow-http-local", action="store_true")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--header-env", action="append", default=[])
    parser.add_argument("--body", default=None)
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    headers: dict[str, str] = {}
    for raw in args.header:
        if "=" not in raw:
            raise LoadGateError("HTTP_LOAD_HEADER_INVALID")
        name, value = raw.split("=", 1)
        if name in headers:
            raise LoadGateError("HTTP_LOAD_HEADER_DUPLICATE")
        headers[name] = value
    header_environments: dict[str, str] = {}
    for raw in args.header_env:
        if "=" not in raw:
            raise LoadGateError("HTTP_LOAD_HEADER_ENV_INVALID")
        name, environment = raw.split("=", 1)
        if name in header_environments:
            raise LoadGateError("HTTP_LOAD_HEADER_ENV_DUPLICATE")
        header_environments[name] = environment
    report = run_load_gate(
        args.url, args.requests, args.concurrency, args.expected_status,
        args.minimum_success_ratio, args.maximum_p99_ms,
        allow_http_local=args.allow_http_local,
        method=args.method,
        headers=headers,
        header_environments=header_environments,
        body=args.body.encode() if args.body is not None else None,
        duration_seconds=args.duration_seconds,
    )
    _write_new(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
