from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Candidate:
    provider_key: str
    policy_allowed: bool
    evaluation_millionths: int
    latency_ms: int
    cost_microunits: int
    load_millionths: int


@dataclass(frozen=True)
class RouteDecision:
    schema_version: str
    provider_key: str
    score_millionths: int
    reasons: tuple[str, ...]


class ModelRouter:
    """Ranks only candidates already allowed by the authoritative DataPolicyPort."""

    def rank(self, candidates: Iterable[Candidate]) -> list[RouteDecision]:
        decisions: list[RouteDecision] = []
        for candidate in candidates:
            if not candidate.policy_allowed:
                continue
            if (
                not candidate.provider_key
                or not 0 <= candidate.evaluation_millionths <= 1_000_000
                or candidate.latency_ms < 0
                or candidate.cost_microunits < 0
                or not 0 <= candidate.load_millionths <= 1_000_000
            ):
                raise ValueError("MODEL_ROUTE_CANDIDATE_INVALID")
            score = max(
                0,
                candidate.evaluation_millionths
                - min(candidate.latency_ms * 100, 250_000)
                - min(candidate.cost_microunits, 250_000)
                - candidate.load_millionths // 4,
            )
            decisions.append(
                RouteDecision(
                    schema_version="agenttrust.model-route.v1",
                    provider_key=candidate.provider_key,
                    score_millionths=score,
                    reasons=(
                        f"evaluation={candidate.evaluation_millionths}",
                        f"latency_ms={candidate.latency_ms}",
                        f"cost_microunits={candidate.cost_microunits}",
                        f"load_millionths={candidate.load_millionths}",
                    ),
                )
            )
        return sorted(decisions, key=lambda item: (-item.score_millionths, item.provider_key))
