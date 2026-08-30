#!/usr/bin/env python3
"""Fail closed when Rust production adapters regress to unbounded HTTP reads."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "rust" / "crates"
HELPER_CRATE = CRATES / "bounded-http"
HELPER_SOURCE = HELPER_CRATE / "src" / "lib.rs"

EXPECTED_CONSUMERS = {
    "agent-registry-posture",
    "audit-retention",
    "context-governance",
    "data-governance",
    "domain-risk-packs",
    "enterprise-approval",
    "enterprise-control",
    "evidence-evaluator",
    "incident-release-gate",
    "model-gateway",
    "pack-marketplace",
    "pack-supply-chain",
    "platform-sre",
    "policy-administration",
    "policy-pep",
    "production-runtime",
    "runtime-anomaly",
    "security-evaluation-lab",
}

FORBIDDEN_RESPONSE_READS = {
    "whole-body bytes": re.compile(
        r"\.\s*bytes\s*\(\s*\)\s*\.\s*await", re.DOTALL
    ),
    "whole-body text": re.compile(
        r"\.\s*text\s*\(\s*\)\s*\.\s*await", re.DOTALL
    ),
    "whole-body text with charset": re.compile(
        r"\.\s*text_with_charset\s*\([^)]*\)\s*\.\s*await", re.DOTALL
    ),
    "serde response JSON": re.compile(
        r"\.\s*json\s*(?:::\s*<[^;{}()]+>)?\s*\(\s*\)\s*\.\s*await",
        re.DOTALL,
    ),
    # A manually collected bytes stream can silently bypass the shared limit and its typed errors.
    # True streaming protocols use their purpose-built, frame-aware readers instead.
    "direct response bytes stream": re.compile(r"\.\s*bytes_stream\s*\(\s*\)"),
}
HELPER_CALL = re.compile(r"\bread_bounded_body\s*\(")


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def crate_manifest(crate: str) -> dict:
    path = CRATES / crate / "Cargo.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    errors: list[str] = []
    rust_sources = sorted(CRATES.rglob("*.rs"))

    forbidden_examples = {
        "bytes": "response\n    .bytes()\n    .await",
        "text": "response.text().await",
        "text with charset": 'response.text_with_charset("utf-8").await',
        "generic JSON": "response\n    .json::<Vec<Receipt>>()\n    .await",
        "bytes stream": "response.bytes_stream()",
    }
    for description, example in forbidden_examples.items():
        if not any(pattern.search(example) for pattern in FORBIDDEN_RESPONSE_READS.values()):
            errors.append(f"HTTP bounds validator lost {description} detection")
    safe_request_builder = ".json(&payload).send().await"
    if any(pattern.search(safe_request_builder) for pattern in FORBIDDEN_RESPONSE_READS.values()):
        errors.append("HTTP bounds validator mistakes request serialization for a response read")

    # This is deliberately stricter than the production-only contract: test fixtures should use
    # the same bounded helper too, so no direct response aggregation can be mistaken for evidence.
    for source_path in rust_sources:
        source = source_path.read_text(encoding="utf-8")
        for description, pattern in FORBIDDEN_RESPONSE_READS.items():
            if pattern.search(source):
                errors.append(
                    "direct reqwest response read is forbidden "
                    f"({description}): {source_path.relative_to(ROOT)}"
                )

    helper = HELPER_SOURCE.read_text(encoding="utf-8")
    required_helper_fragments = {
        "zero limits fail closed": "if maximum == 0",
        "Content-Length is only an early rejection": ".content_length()",
        "responses are consumed incrementally": ".chunk()",
        "length accumulation is overflow checked": ".checked_add(incoming)",
        "oversized chunks fail before append": "if next > maximum",
        "the checked chunk is appended only afterwards": "body.extend_from_slice(&chunk)",
        "oversize has a typed failure": "BodyTooLarge",
        "transport failures have a typed failure": "Transport",
        "an oversized first chunk has a negative test": "checked_next_length(0, 4_097, 4_096)",
        "usize overflow has a negative test": "checked_next_length(usize::MAX, 1, usize::MAX)",
        "missing Content-Length has a protocol test": "missing_content_length_is_bounded_by_actual_bytes",
        "misreported Content-Length has a protocol test": "declared_length_over_limit_fails_before_a_short_body_is_trusted",
        "chunked overflow has a protocol test": "chunked_body_crossing_limit_fails_before_append",
        "an exact-limit response has a protocol test": "chunked_body_at_exact_limit_is_accepted",
        "a zero limit has a protocol test": "zero_limit_fails_closed",
        "a truncated response has a transport test": "truncated_declared_body_is_a_transport_failure",
    }
    for description, fragment in required_helper_fragments.items():
        if fragment not in helper:
            errors.append(f"bounded reader lost contract: {description}")
    call_index = helper.find("checked_next_length(body.len(), chunk.len(), maximum)?")
    append_index = helper.find("body.extend_from_slice(&chunk)")
    if call_index < 0 or append_index < 0 or call_index > append_index:
        errors.append("bounded reader must validate the next chunk before appending it")

    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if "rust/crates/bounded-http" not in workspace["workspace"]["members"]:
        errors.append("bounded-http is not a Cargo workspace member")

    declared_consumers: set[str] = set()
    for crate_dir in sorted(path for path in CRATES.iterdir() if path.is_dir()):
        manifest_path = crate_dir / "Cargo.toml"
        if not manifest_path.exists() or crate_dir.name == "bounded-http":
            continue
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        if "agent-trust-bounded-http" in manifest.get("dependencies", {}):
            declared_consumers.add(crate_dir.name)

    used_consumers: set[str] = set()
    helper_calls = 0
    for source_path in rust_sources:
        if HELPER_CRATE in source_path.parents:
            continue
        source = source_path.read_text(encoding="utf-8")
        calls = len(HELPER_CALL.findall(source))
        if calls:
            helper_calls += calls
            crate = source_path.relative_to(CRATES).parts[0]
            used_consumers.add(crate)

    if declared_consumers != EXPECTED_CONSUMERS:
        errors.append(
            "bounded-http manifest consumers drifted: "
            f"missing={sorted(EXPECTED_CONSUMERS - declared_consumers)}, "
            f"unexpected={sorted(declared_consumers - EXPECTED_CONSUMERS)}"
        )
    if used_consumers != EXPECTED_CONSUMERS:
        errors.append(
            "bounded reader call sites drifted: "
            f"missing={sorted(EXPECTED_CONSUMERS - used_consumers)}, "
            f"unexpected={sorted(used_consumers - EXPECTED_CONSUMERS)}"
        )

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    locked = {
        package["name"]: {dependency.split(" ", 1)[0] for dependency in package.get("dependencies", [])}
        for package in lock["package"]
        if package.get("version") == "0.1.0"
    }
    helper_package = locked.get("agent-trust-bounded-http")
    if helper_package != {"reqwest", "thiserror", "tokio"}:
        errors.append(
            f"bounded-http Cargo.lock entry drifted: dependencies={sorted(helper_package or set())}"
        )
    for crate in EXPECTED_CONSUMERS:
        package_name = crate_manifest(crate)["package"]["name"]
        if "agent-trust-bounded-http" not in locked.get(package_name, set()):
            errors.append(f"Cargo.lock omits bounded-http for {package_name}")

    if errors:
        fail(errors)
    print(
        "PASS rust HTTP bounds: "
        f"{len(rust_sources)} sources, 0 direct response aggregation bypasses, "
        f"{len(used_consumers)} consumer crates, {helper_calls} bounded call sites"
    )


if __name__ == "__main__":
    main()
