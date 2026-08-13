"""Local domain harnesses.

These harnesses deliberately label their output as simulation/shadow evidence. They
exercise policy inputs and safety invariants, but never claim physical or clinical
validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


_HEX = frozenset("0123456789abcdef")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class DatasetCase:
    case_id: str
    input: Mapping[str, Any]
    expected_decision: str
    expected_reason: str


class DatasetValidationError(ValueError):
    pass


def load_dataset(path: Path, *, expected_schema: str, maximum_cases: int = 10_000) -> tuple[DatasetCase, ...]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    cases = raw.get("cases") if isinstance(raw, dict) else None
    if raw.get("schema_version") != expected_schema or not isinstance(cases, list) or not 0 < len(cases) <= maximum_cases:
        raise DatasetValidationError("DOMAIN_DATASET_INVALID")
    ids: set[str] = set()
    parsed: list[DatasetCase] = []
    for value in cases:
        if (
            not isinstance(value, dict)
            or set(value) != {"case_id", "input", "expected_decision", "expected_reason"}
            or not isinstance(value["case_id"], str)
            or not value["case_id"]
            or value["case_id"] in ids
            or not isinstance(value["input"], dict)
            or value["expected_decision"] not in {"ALLOW", "DENY", "ESCALATE"}
            or not isinstance(value["expected_reason"], str)
            or not value["expected_reason"]
        ):
            raise DatasetValidationError("DOMAIN_DATASET_CASE_INVALID")
        ids.add(value["case_id"])
        parsed.append(DatasetCase(**value))
    return tuple(parsed)


class IndustrialDigitalTwin:
    """CAS-protected deterministic plant model with no physical I/O."""

    def __init__(self, *, minimum: float, maximum: float, value: float, resource_version: int = 1) -> None:
        if minimum >= maximum or not minimum <= value <= maximum or resource_version < 1:
            raise ValueError("INDUSTRIAL_TWIN_CONFIG_INVALID")
        self._minimum = minimum
        self._maximum = maximum
        self._value = value
        self._version = resource_version

    def commit(self, command: Mapping[str, Any]) -> Mapping[str, Any]:
        required = {"command_id", "value", "expected_value", "resource_version", "interlock_ok", "alarm_active", "approval_valid"}
        if set(command) != required or not command["command_id"]:
            raise ValueError("INDUSTRIAL_COMMAND_INVALID")
        reason = "INDUSTRIAL_SIMULATION_COMMITTED"
        allowed = True
        if command["resource_version"] != self._version or command["expected_value"] != self._value:
            allowed, reason = False, "INDUSTRIAL_STALE_STATE"
        elif not command["interlock_ok"] or command["alarm_active"]:
            allowed, reason = False, "INDUSTRIAL_INTERLOCK_OR_ALARM"
        elif not command["approval_valid"]:
            allowed, reason = False, "INDUSTRIAL_APPROVAL_REQUIRED"
        elif not self._minimum <= float(command["value"]) <= self._maximum:
            allowed, reason = False, "INDUSTRIAL_BOUND_VIOLATION"
        if allowed:
            self._value = float(command["value"])
            self._version += 1
        receipt = {
            "schema_version": "agenttrust.industrial-simulation.v1",
            "command_id": command["command_id"],
            "decision": "ALLOW" if allowed else "DENY",
            "reason_code": reason,
            "value": self._value,
            "resource_version": self._version,
            "evidence_scope": "SIMULATION_ONLY_NOT_PHYSICAL_EVIDENCE",
        }
        return {**receipt, "evidence_digest": _digest(receipt)}


class EnergyShadowEvaluator:
    """Evaluates candidate dispatch plans without dispatching them."""

    def evaluate(
        self,
        *,
        asset_id: str,
        telemetry_version: str,
        candidate_steps: Sequence[Mapping[str, Any]],
        minimum_power_kw: float,
        maximum_power_kw: float,
        maximum_steps: int = 288,
    ) -> Mapping[str, Any]:
        if (
            not asset_id
            or not telemetry_version
            or minimum_power_kw >= maximum_power_kw
            or not candidate_steps
            or len(candidate_steps) > maximum_steps
        ):
            raise ValueError("ENERGY_SHADOW_INPUT_INVALID")
        violations: list[Mapping[str, Any]] = []
        previous_interval = -1
        for index, step in enumerate(candidate_steps):
            if set(step) != {"interval", "power_kw"} or not isinstance(step["interval"], int):
                raise ValueError("ENERGY_SHADOW_STEP_INVALID")
            power = float(step["power_kw"])
            interval = step["interval"]
            if interval <= previous_interval:
                violations.append({"index": index, "reason_code": "ENERGY_INTERVAL_NOT_MONOTONIC"})
            if not minimum_power_kw <= power <= maximum_power_kw:
                violations.append({"index": index, "reason_code": "ENERGY_POWER_BOUND_VIOLATION"})
            previous_interval = interval
        unsigned = {
            "schema_version": "agenttrust.energy-shadow.v1",
            "asset_id": asset_id,
            "telemetry_version": telemetry_version,
            "candidate_digest": _digest(candidate_steps),
            "decision": "ALLOW" if not violations else "DENY",
            "violations": violations,
            "side_effect_count": 0,
            "evidence_scope": "SHADOW_ONLY_NOT_DISPATCH_EVIDENCE",
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        return {**unsigned, "evidence_digest": _digest(unsigned)}


def _medical_decision(value: Mapping[str, Any]) -> tuple[str, str]:
    if value.get("autonomous_diagnosis") or value.get("autonomous_treatment"):
        return "DENY", "MEDICAL_AUTONOMY_PROHIBITED"
    if value.get("crisis") and value.get("licensed_human_available"):
        return "ESCALATE", "MEDICAL_HUMAN_ESCALATION"
    if not value.get("consent_valid") or not value.get("care_relationship_active"):
        return "DENY", "MEDICAL_ACCESS_DENIED"
    if not set(value.get("requested_scopes", ())).issubset(set(value.get("approved_scopes", ()))):
        return "DENY", "MEDICAL_SCOPE_NOT_MINIMIZED"
    return "ALLOW", "MEDICAL_DRAFT_ONLY"


def _sensitive_decision(value: Mapping[str, Any]) -> tuple[str, str]:
    if value.get("crisis") or value.get("risk") in {"HIGH", "CRITICAL"}:
        return "ESCALATE", "SENSITIVE_HUMAN_ESCALATION"
    if not value.get("consent_valid"):
        return "ESCALATE", "SENSITIVE_CONSENT_REQUIRED"
    if value.get("coercion") or value.get("spiritual_scoring") or value.get("shaming"):
        return "DENY", "SENSITIVE_LANGUAGE_UNSAFE"
    if value.get("claims", 0) != value.get("verified_citations", -1):
        return "DENY", "SENSITIVE_CITATION_INVALID"
    return "ALLOW", "SENSITIVE_SUPPORT_ALLOWED"


def _run_dataset(cases: Iterable[DatasetCase], evaluator: Any, schema_version: str) -> Mapping[str, Any]:
    outcomes = []
    for case in cases:
        decision, reason = evaluator(case.input)
        outcomes.append({
            "case_id": case.case_id,
            "passed": decision == case.expected_decision and reason == case.expected_reason,
            "actual_decision": decision,
            "actual_reason": reason,
        })
    unsigned = {
        "schema_version": schema_version,
        "cases": outcomes,
        "passed": bool(outcomes) and all(item["passed"] for item in outcomes),
        "evidence_scope": "SOFTWARE_SAFETY_REGRESSION_ONLY",
    }
    return {**unsigned, "evidence_digest": _digest(unsigned)}


def run_medical_safety_dataset(cases: Iterable[DatasetCase]) -> Mapping[str, Any]:
    return _run_dataset(cases, _medical_decision, "agenttrust.medical-safety-report.v1")


def run_sensitive_dialogue_dataset(cases: Iterable[DatasetCase]) -> Mapping[str, Any]:
    return _run_dataset(cases, _sensitive_decision, "agenttrust.sensitive-dialogue-report.v1")
