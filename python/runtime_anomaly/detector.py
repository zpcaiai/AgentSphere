"""Bounded semantic detector whose output can only supplement deterministic controls."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import math
import re
from threading import Lock
from typing import Iterable
from urllib.parse import unquote


_SUSPICIOUS = {
    "disable audit": 0.55,
    "ignore policy": 0.45,
    "steal credential": 0.75,
    "exfiltrate": 0.75,
    "metadata endpoint": 0.60,
    "bypass approval": 0.70,
}

_MAXIMUM_INTEGER = 9_223_372_036_854_775_807


@dataclass(frozen=True)
class Observation:
    tenant_id: str
    task_id: str
    sequence: int
    safe_text: str
    outbound_bytes: int
    new_destination_count: int
    privilege_delta: int
    failure_count: int = 0
    resource_count: int = 0
    side_effect_count: int = 0
    agent_type: str = "unknown"
    domain: str = "unknown"


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

    def __init__(
        self,
        *,
        window_size: int = 64,
        alpha: float = 0.25,
        maximum_tasks: int = 10_000,
        maximum_safe_text_bytes: int = 16_384,
    ) -> None:
        if (
            type(window_size) is not int
            or window_size < 2
            or window_size > 4096
            or not _valid_alpha(alpha)
            or type(maximum_tasks) is not int
            or maximum_tasks < 1
            or maximum_tasks > 100_000
            or type(maximum_safe_text_bytes) is not int
            or maximum_safe_text_bytes < 256
            or maximum_safe_text_bytes > 1_048_576
        ):
            raise ValueError("ANOMALY_DETECTOR_CONFIG_INVALID")
        self._window_size = window_size
        self._alpha = alpha
        self._maximum_tasks = maximum_tasks
        self._maximum_safe_text_bytes = maximum_safe_text_bytes
        self._windows: dict[tuple[str, str], deque[tuple[int, int, int, int, int, int]]] = {}
        self._last_sequence: dict[tuple[str, str], int] = {}
        self._lock = Lock()

    def observe(self, observation: Observation) -> SemanticRiskSignal:
        if not isinstance(observation, Observation):
            raise ValueError("ANOMALY_OBSERVATION_INVALID")
        if (
            not _identifier(observation.tenant_id)
            or not _identifier(observation.task_id)
            or not _bounded_integer(observation.sequence, minimum=1)
            or not isinstance(observation.safe_text, str)
            or len(observation.safe_text) > self._maximum_safe_text_bytes
        ):
            raise ValueError("ANOMALY_OBSERVATION_INVALID")
        try:
            safe_text_bytes = observation.safe_text.encode("utf-8")
        except UnicodeError:
            raise ValueError("ANOMALY_OBSERVATION_INVALID") from None
        if (
            not _bounded_integer(observation.outbound_bytes)
            or not _bounded_integer(observation.new_destination_count)
            or not _bounded_integer(observation.privilege_delta)
            or not _bounded_integer(observation.failure_count)
            or not _bounded_integer(observation.resource_count)
            or not _bounded_integer(observation.side_effect_count)
            or len(safe_text_bytes) > self._maximum_safe_text_bytes
            or not _identifier(observation.agent_type)
            or not _identifier(observation.domain)
        ):
            raise ValueError("ANOMALY_FEATURE_NEGATIVE")

        with self._lock:
            return self._observe_validated(observation, safe_text_bytes)

    def _observe_validated(
        self,
        observation: Observation,
        safe_text_bytes: bytes,
    ) -> SemanticRiskSignal:
        key = (observation.tenant_id, observation.task_id)
        if key not in self._windows and len(self._windows) >= self._maximum_tasks:
            raise ValueError("ANOMALY_TASK_CAPACITY_EXCEEDED")
        last = self._last_sequence.get(key, 0)
        if observation.sequence <= last:
            raise ValueError("ANOMALY_SEQUENCE_REPLAY")

        window = self._windows.setdefault(key, deque(maxlen=self._window_size))
        outbound_baseline = _ewma((value[0] for value in window), self._alpha)
        destination_baseline = _ewma((value[1] for value in window), self._alpha)
        reasons: list[str] = []
        score = 0.0

        normalized_text = _normalized_safe_text(
            observation.safe_text,
            maximum_bytes=self._maximum_safe_text_bytes,
        )
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
        if observation.failure_count >= 3:
            reasons.append("REPEATED_FAILURE_DEVIATION")
            score += min(0.4, observation.failure_count * 0.05)
        if observation.resource_count >= 128:
            reasons.append("RESOURCE_ENUMERATION_DEVIATION")
            score += 0.35
        if observation.side_effect_count >= 3:
            reasons.append("REPEATED_SIDE_EFFECT_DEVIATION")
            score += 0.45

        reason_codes = tuple(sorted(set(reasons)))
        safe_features = json.dumps(
            {
                "agent_type": observation.agent_type,
                "domain": observation.domain,
                "failure_count": observation.failure_count,
                "new_destination_count": observation.new_destination_count,
                "outbound_bytes": observation.outbound_bytes,
                "privilege_delta": observation.privilege_delta,
                "reason_codes": reason_codes,
                "resource_count": observation.resource_count,
                "safe_text_digest": hashlib.sha256(safe_text_bytes).hexdigest(),
                "sequence": observation.sequence,
                "side_effect_count": observation.side_effect_count,
                "task_id": observation.task_id,
                "tenant_id": observation.tenant_id,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        signal = SemanticRiskSignal(
            schema_version=self.schema_version,
            tenant_id=observation.tenant_id,
            task_id=observation.task_id,
            sequence=observation.sequence,
            detector_version="semantic-ewma-2",
            score=round(min(1.0, score), 6),
            reason_codes=reason_codes,
            safe_feature_digest=hashlib.sha256(safe_features.encode()).hexdigest(),
            # PEP/Rust aggregation owns any stronger response.
            response_ceiling="REQUEST_CONTINUOUS_AUTHORIZATION",
        )
        window.append(
            (
                observation.outbound_bytes,
                observation.new_destination_count,
                observation.privilege_delta,
                observation.failure_count,
                observation.resource_count,
                observation.side_effect_count,
            )
        )
        self._last_sequence[key] = observation.sequence
        return signal

    def tracked_task_count(self) -> int:
        with self._lock:
            return len(self._windows)


def _ewma(values: Iterable[int], alpha: float) -> float:
    result = 0.0
    found = False
    for value in values:
        result = float(value) if not found else alpha * value + (1.0 - alpha) * result
        found = True
    return result if found and math.isfinite(result) else 0.0


def _normalized_safe_text(value: str, *, maximum_bytes: int) -> str:
    """Decode a bounded safe summary for scoring; the result never gains action authority."""

    candidates = [value]
    current = value
    for _ in range(3):
        if len(current.encode("utf-8")) > maximum_bytes:
            break
        percent = unquote(current)
        if percent != current:
            if len(percent.encode("utf-8")) > maximum_bytes:
                break
            candidates.append(percent)
            current = percent
            continue
        padded = current + "=" * ((4 - len(current) % 4) % 4)
        try:
            raw = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
            decoded = raw.decode("utf-8") if len(raw) <= maximum_bytes else None
            if decoded is not None and not all(character.isprintable() for character in decoded):
                decoded = None
        except (ValueError, UnicodeError, binascii.Error):
            decoded = None
        if decoded is None or decoded == current:
            break
        candidates.append(decoded)
        current = decoded
    return " ".join(re.findall(r"[a-z0-9]+", " ".join(candidates).lower()))


def _identifier(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value)
    )


def _bounded_integer(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = _MAXIMUM_INTEGER,
) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _valid_alpha(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and 0.0 < value <= 1.0
    except (OverflowError, TypeError, ValueError):
        return False
