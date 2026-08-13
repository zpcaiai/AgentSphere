"""Deterministic candidate planner; Rust/PEP remains the action authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Sequence


@dataclass(frozen=True)
class ForecastPoint:
    demand_kw: float
    renewable_kw: float
    confidence: float


@dataclass(frozen=True)
class ConstraintEnvelope:
    minimum_power_kw: float
    maximum_power_kw: float
    maximum_ramp_kw: float
    minimum_state_of_charge: float
    maximum_state_of_charge: float
    initial_state_of_charge: float
    energy_capacity_kwh: float
    interval_hours: float


@dataclass(frozen=True)
class CandidatePlan:
    schema_version: str
    algorithm: str
    setpoints_kw: tuple[float, ...]
    confidence: float
    out_of_distribution: bool
    requires_shadow_validation: bool
    constraint_digest: str
    fallback_reason: str | None


class EnergyPlanner:
    """Produces bounded candidates and deterministic fallbacks, never device commands."""

    schema_version = "agenttrust.energy-candidate.v1"

    def propose(
        self,
        forecast: Sequence[ForecastPoint],
        constraints: ConstraintEnvelope,
    ) -> CandidatePlan:
        self._validate(forecast, constraints)
        digest = _digest_constraints(constraints)
        confidence = min(point.confidence for point in forecast)
        out_of_distribution = confidence < 0.65 or any(
            abs(point.demand_kw - point.renewable_kw) > constraints.maximum_power_kw * 4.0
            for point in forecast
        )
        if out_of_distribution:
            return self.safe_fallback(len(forecast), constraints, digest, "FORECAST_OOD")

        state_of_charge = constraints.initial_state_of_charge
        previous = 0.0
        setpoints: list[float] = []
        for point in forecast:
            desired = point.renewable_kw - point.demand_kw
            desired = max(constraints.minimum_power_kw, min(constraints.maximum_power_kw, desired))
            desired = max(previous - constraints.maximum_ramp_kw, min(previous + constraints.maximum_ramp_kw, desired))
            projected = state_of_charge + (
                desired * constraints.interval_hours / constraints.energy_capacity_kwh
            )
            if projected < constraints.minimum_state_of_charge:
                desired = max(
                    0.0,
                    (constraints.minimum_state_of_charge - state_of_charge)
                    * constraints.energy_capacity_kwh
                    / constraints.interval_hours,
                )
            elif projected > constraints.maximum_state_of_charge:
                desired = min(
                    0.0,
                    (constraints.maximum_state_of_charge - state_of_charge)
                    * constraints.energy_capacity_kwh
                    / constraints.interval_hours,
                )
            desired = max(constraints.minimum_power_kw, min(constraints.maximum_power_kw, desired))
            state_of_charge += desired * constraints.interval_hours / constraints.energy_capacity_kwh
            setpoints.append(round(desired, 6))
            previous = desired

        return CandidatePlan(
            schema_version=self.schema_version,
            algorithm="DETERMINISTIC_CONSTRAINED_CANDIDATE_V1",
            setpoints_kw=tuple(setpoints),
            confidence=round(confidence, 6),
            out_of_distribution=False,
            requires_shadow_validation=True,
            constraint_digest=digest,
            fallback_reason=None,
        )

    def safe_fallback(
        self,
        horizon: int,
        constraints: ConstraintEnvelope,
        constraint_digest: str | None = None,
        reason: str = "PLANNER_UNAVAILABLE",
    ) -> CandidatePlan:
        if horizon < 1 or horizon > 10000:
            raise ValueError("ENERGY_HORIZON_INVALID")
        return CandidatePlan(
            schema_version=self.schema_version,
            algorithm="ZERO_POWER_SAFE_FALLBACK_V1",
            setpoints_kw=tuple(0.0 for _ in range(horizon)),
            confidence=1.0,
            out_of_distribution=True,
            requires_shadow_validation=True,
            constraint_digest=constraint_digest or _digest_constraints(constraints),
            fallback_reason=reason,
        )

    @staticmethod
    def _validate(forecast: Sequence[ForecastPoint], constraints: ConstraintEnvelope) -> None:
        values = [
            constraints.minimum_power_kw,
            constraints.maximum_power_kw,
            constraints.maximum_ramp_kw,
            constraints.minimum_state_of_charge,
            constraints.maximum_state_of_charge,
            constraints.initial_state_of_charge,
            constraints.energy_capacity_kwh,
            constraints.interval_hours,
        ]
        if (
            not forecast
            or len(forecast) > 10000
            or not all(math.isfinite(value) for value in values)
            or constraints.minimum_power_kw > 0.0
            or constraints.maximum_power_kw < 0.0
            or constraints.maximum_ramp_kw <= 0.0
            or not 0.0 <= constraints.minimum_state_of_charge < constraints.maximum_state_of_charge <= 1.0
            or not constraints.minimum_state_of_charge
            <= constraints.initial_state_of_charge
            <= constraints.maximum_state_of_charge
            or constraints.energy_capacity_kwh <= 0.0
            or constraints.interval_hours <= 0.0
            or any(
                not all(math.isfinite(value) for value in (point.demand_kw, point.renewable_kw, point.confidence))
                or not 0.0 <= point.confidence <= 1.0
                for point in forecast
            )
        ):
            raise ValueError("ENERGY_INPUT_INVALID")


def _digest_constraints(constraints: ConstraintEnvelope) -> str:
    canonical = json.dumps(constraints.__dict__, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
