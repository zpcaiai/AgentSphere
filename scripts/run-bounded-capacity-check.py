#!/usr/bin/env python3
"""Deterministic local capacity check for bounded admission and rejection behavior."""

from __future__ import annotations

import argparse
from collections import deque
import json
import time


def run(capacity: int, requests: int) -> dict[str, int | float | str | bool]:
    if capacity < 1 or requests < 1 or requests > 10_000_000:
        raise ValueError("CAPACITY_INPUT_INVALID")
    queue: deque[int] = deque(maxlen=capacity)
    accepted = 0
    rejected = 0
    started = time.perf_counter_ns()
    for item in range(requests):
        if len(queue) == capacity:
            rejected += 1
        else:
            queue.append(item)
            accepted += 1
    elapsed = time.perf_counter_ns() - started
    return {
        "schema_version": "agenttrust.capacity-check.v1",
        "capacity": capacity,
        "requests": requests,
        "accepted": accepted,
        "rejected": rejected,
        "queue_high_watermark": len(queue),
        "elapsed_nanoseconds": elapsed,
        "bounded": len(queue) <= capacity,
        "production_evidence": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capacity", type=int, default=1000)
    parser.add_argument("--requests", type=int, default=10000)
    args = parser.parse_args()
    report = run(args.capacity, args.requests)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["bounded"] and report["rejected"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
