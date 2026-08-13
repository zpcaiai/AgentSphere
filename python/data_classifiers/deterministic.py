from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import re


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3
    REGULATED = 4


@dataclass(frozen=True)
class ClassificationResult:
    schema_version: str
    classification: Classification
    confidence: str
    finding_codes: tuple[str, ...]


class DeterministicClassifier:
    _secret = re.compile(
        r"(?i)(password\s*[:=]|api[_-]?key\s*[:=]|authorization\s*:\s*bearer|private key)"
    )
    _regulated = re.compile(r"(?:\b\d{17}[0-9Xx]\b|\b1[3-9]\d{9}\b)")

    def classify(self, payload: bytes, source_trusted: bool) -> ClassificationResult:
        if not payload:
            raise ValueError("DATA_CLASSIFIER_INPUT_INVALID")
        text = payload.decode("utf-8", errors="replace")
        if self._secret.search(text):
            return self._result(Classification.RESTRICTED, "DETERMINISTIC", "SECRET_PATTERN")
        if self._regulated.search(text):
            return self._result(Classification.REGULATED, "DETERMINISTIC", "PERSONAL_ID_PATTERN")
        if not source_trusted or "\ufffd" in text:
            return self._result(Classification.RESTRICTED, "UNKNOWN", "UNKNOWN_FAIL_CLOSED")
        return self._result(Classification.INTERNAL, "INFERRED", "NO_SENSITIVE_PATTERN")

    @staticmethod
    def _result(
        classification: Classification, confidence: str, finding: str
    ) -> ClassificationResult:
        return ClassificationResult(
            schema_version="agenttrust.data-classification.v1",
            classification=classification,
            confidence=confidence,
            finding_codes=(finding,),
        )
