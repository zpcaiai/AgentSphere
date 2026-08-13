"""Batch 33 campaign CLI; actual attack effects remain in the isolated Rust runner."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


_CATEGORIES = {
    "PROMPT_INJECTION",
    "TOOL_ABUSE",
    "CREDENTIAL_THEFT",
    "DATA_EXFILTRATION",
    "POLICY_BYPASS",
    "MEMORY_POISONING",
    "SUPPLY_CHAIN",
    "CODING",
    "INDUSTRIAL",
    "ENERGY",
    "MEDICAL",
    "SENSITIVE_INTERACTION",
}


@dataclass(frozen=True)
class CompiledScenario:
    scenario_id: str
    digest: str
    seed: int
    category: str
    expected_controls: tuple[str, ...]
    cleanup_steps: tuple[str, ...]
    source: Mapping[str, Any]


def compile_scenario(value: Mapping[str, Any]) -> CompiledScenario:
    required = {
        "schema_version",
        "scenario_id",
        "version",
        "category",
        "target",
        "preconditions",
        "steps",
        "expected_controls",
        "success_criteria",
        "failure_criteria",
        "cleanup_steps",
        "seed",
    }
    list_fields = {
        "preconditions",
        "steps",
        "expected_controls",
        "success_criteria",
        "failure_criteria",
        "cleanup_steps",
    }
    if (
        set(value) != required
        or value.get("schema_version") != "agenttrust.attack-scenario.v1"
        or value.get("category") not in _CATEGORIES
        or not isinstance(value.get("scenario_id"), str)
        or not value["scenario_id"]
        or not isinstance(value.get("target"), str)
        or not value["target"]
        or not isinstance(value.get("seed"), int)
        or not 0 <= value["seed"] <= 2**63 - 1
        or any(not isinstance(value.get(field), list) or not value[field] for field in list_fields)
        or len(value["steps"]) > 256
    ):
        raise ValueError("ATTACK_SCENARIO_INVALID")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return CompiledScenario(
        scenario_id=value["scenario_id"],
        digest=hashlib.sha256(canonical).hexdigest(),
        seed=value["seed"],
        category=value["category"],
        expected_controls=tuple(value["expected_controls"]),
        cleanup_steps=tuple(value["cleanup_steps"]),
        source=dict(value),
    )


class CampaignRunner:
    """Bounded orchestration facade around an injected isolated execution boundary."""

    def __init__(
        self,
        isolated_executor: Callable[[CompiledScenario], Mapping[str, Any]],
        *,
        maximum_scenarios: int = 1000,
    ) -> None:
        if maximum_scenarios < 1 or maximum_scenarios > 10000:
            raise ValueError("CAMPAIGN_LIMIT_INVALID")
        self._executor = isolated_executor
        self._maximum_scenarios = maximum_scenarios

    def run(
        self,
        scenarios: Sequence[CompiledScenario],
        *,
        policy_digest: str,
        pack_digest: str,
        environment: str,
    ) -> dict[str, Any]:
        if (
            not scenarios
            or len(scenarios) > self._maximum_scenarios
            or len(policy_digest) != 64
            or len(pack_digest) != 64
            or environment not in {"isolated-test", "sandbox"}
        ):
            raise ValueError("CAMPAIGN_INPUT_INVALID")
        outcomes = []
        for scenario in scenarios:
            result = dict(self._executor(scenario))
            if set(result) != {"prevented", "detected", "contained", "recovered", "cleanup_verified"}:
                raise ValueError("CAMPAIGN_EXECUTOR_RESULT_INVALID")
            outcomes.append({"scenario_id": scenario.scenario_id, "digest": scenario.digest, **result})
        counts = {
            metric: sum(bool(outcome[metric]) for outcome in outcomes)
            for metric in ("prevented", "detected", "contained", "recovered", "cleanup_verified")
        }
        unsigned = {
            "schema_version": "agenttrust.security-campaign.v1",
            "environment": environment,
            "policy_digest": policy_digest,
            "pack_digest": pack_digest,
            "outcomes": outcomes,
            "counts": counts,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "production_certification": False,
        }
        unsigned["report_digest"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return unsigned


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-security-campaign")
    parser.add_argument("scenario", type=Path, nargs="+")
    parser.add_argument("--compile-only", action="store_true", required=True)
    args = parser.parse_args(argv)
    for path in args.scenario:
        compiled = compile_scenario(json.loads(path.read_text(encoding="utf-8")))
        print(json.dumps({"scenario_id": compiled.scenario_id, "digest": compiled.digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
