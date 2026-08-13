"""Bounded semantic detector whose output can only supplement deterministic controls."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import math
import re
from typing import Iterable


_SUSPICIOUS = {
    "disable audit": 0.55,
    "ignore policy": 0.45,
    "steal credential": 0.75,
    "exfiltrate": 0.75,
    "metadata endpoint": 0.60,
    "bypass approval": 0.70,
}


@dataclass(frozen=True)
class Observation:
    tenant_id: str
    task_id: str
    sequence: int
    safe_text: str
    outbound_bytes: int
    new_destination_count: int
    privilege_delta: int


@dataclass(frozen=True)
class SemanticRiskSignal:
    schema_version: str
    tenant_id: str
    task_id: str
    sequence: int
    detector_version: str
    score: float
    reason_codes: tuple[str, ...]
    safe_feature_digest: str
    response_ceiling: str


class SemanticRiskDetector:
    """EWMA detector with bounded per-task memory and no direct kill authority."""

    schema_version = "agenttrust.risk-signal.v1"

    def __init__(self, *, window_size: int = 64, alpha: float = 0.25) -> None:
        if window_size < 2 or window_size > 4096 or not 0.0 < alpha <= 1.0:
            raise ValueError("ANOMALY_DETECTOR_CONFIG_INVALID")
        self._window_size = window_size
        self._alpha = alpha
        self._windows: dict[tuple[str, str], deque[tuple[int, int, int]]] = {}
        self._last_sequence: dict[tuple[str, str], int] = {}

    def observe(self, observation: Observation) -> SemanticRiskSignal:
        if not observation.tenant_id or not observation.task_id or observation.sequence < 1:
            raise ValueError("ANOMALY_OBSERVATION_INVALID")
        if min(observation.outbound_bytes, observation.new_destination_count, observation.privilege_delta) < 0:
            raise ValueError("ANOMALY_FEATURE_NEGATIVE")
        key = (observation.tenant_id, observation.task_id)
        last = self._last_sequence.get(key, 0)
        if observation.sequence <= last:
            raise ValueError("ANOMALY_SEQUENCE_REPLAY")

        window = self._windows.setdefault(key, deque(maxlen=self._window_size))
        outbound_baseline = _ewma((value[0] for value in window), self._alpha)
        destination_baseline = _ewma((value[1] for value in window), self._alpha)
        reasons: list[str] = []
        score = 0.0

        normalized_text = " ".join(re.findall(r"[a-z0-9]+", observation.safe_text.lower()))
        for phrase, weight in _SUSPICIOUS.items():
            if phrase in normalized_text:
                reasons.append("SEMANTIC_MANIPULATION")
                score += weight
                break
        if observation.outbound_bytes > max(4096, outbound_baseline * 3.0):
            reasons.append("OUTBOUND_VOLUME_DEVIATION")
            score += 0.35
        if observation.new_destination_count > max(2, destination_baseline * 2.0):
            reasons.append("DESTINATION_FANOUT_DEVIATION")
            score += 0.35
        if observation.privilege_delta > 0:
            reasons.append("PRIVILEGE_EXPANSION")
            score += min(0.5, observation.privilege_delta * 0.2)

        window.append(
            (
                observation.outbound_bytes,
                observation.new_destination_count,
                observation.privilege_delta,
            )
        )
        self._last_sequence[key] = observation.sequence
        safe_features = (
            f"{observation.tenant_id}|{observation.task_id}|{observation.sequence}|"
            f"{observation.outbound_bytes}|{observation.new_destination_count}|"
            f"{observation.privilege_delta}|{','.join(sorted(set(reasons)))}"
        )
        return SemanticRiskSignal(
            schema_version=self.schema_version,
            tenant_id=observation.tenant_id,
            task_id=observation.task_id,
            sequence=observation.sequence,
            detector_version="semantic-ewma-1",
            score=round(min(1.0, score), 6),
            reason_codes=tuple(sorted(set(reasons))),
            safe_feature_digest=hashlib.sha256(safe_features.encode()).hexdigest(),
            # PEP/Rust aggregation owns any stronger response.
            response_ceiling="REQUEST_CONTINUOUS_AUTHORIZATION",
        )

    def tracked_task_count(self) -> int:
        return len(self._windows)


def _ewma(values: Iterable[int], alpha: float) -> float:
    result = 0.0
    found = False
    for value in values:
        result = float(value) if not found else alpha * value + (1.0 - alpha) * result
        found = True
    return result if found and math.isfinite(result) else 0.0
