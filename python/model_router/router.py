from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
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
        try:
            bounded = tuple(islice(iter(candidates), 1_001))
        except Exception:
            # Iterators can be supplied by adapters. Do not leak their error text through
            # this public decision boundary.
            raise ValueError("MODEL_ROUTE_CANDIDATE_SET_INVALID") from None
        if not bounded or len(bounded) > 1_000:
            raise ValueError("MODEL_ROUTE_CANDIDATE_SET_INVALID")
        decisions: list[RouteDecision] = []
        seen: set[str] = set()
        for candidate in bounded:
            if not _valid_candidate(candidate):
                raise ValueError("MODEL_ROUTE_CANDIDATE_INVALID")
            if candidate.provider_key in seen:
                raise ValueError("MODEL_ROUTE_CANDIDATE_DUPLICATE")
            seen.add(candidate.provider_key)
            if not candidate.policy_allowed:
                continue
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
        if not decisions:
            raise ValueError("MODEL_ROUTE_NO_ALLOWED_CANDIDATE")
        return sorted(decisions, key=lambda item: (-item.score_millionths, item.provider_key))


def _valid_candidate(candidate: object) -> bool:
    if not isinstance(candidate, Candidate):
        return False
    if (
        type(candidate.policy_allowed) is not bool
        or not _provider_key(candidate.provider_key)
        or not _bounded_integer(candidate.evaluation_millionths, 1_000_000)
        or not _bounded_integer(candidate.latency_ms, 300_000)
        or not _bounded_integer(candidate.cost_microunits, 9_223_372_036_854_775_807)
        or not _bounded_integer(candidate.load_millionths, 1_000_000)
    ):
        return False
    return True


def _provider_key(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 768
        and value.isascii()
        and all(character.isprintable() and not character.isspace() for character in value)
    )


def _bounded_integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum
