"""Run signed-by-policy evaluator executables with deterministic resource boundaries.

The launcher does not grant network or filesystem access itself. Production manifests must use
an administrator-approved sandbox launcher (for example a locked-down container or WASI runner).
The executable digest is checked immediately before every invocation to prevent path swapping.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping, Sequence


class PluginExecutionError(RuntimeError):
    """Safe, machine-readable evaluator failure."""


@dataclass(frozen=True)
class EvaluatorManifest:
    schema_version: str
    evaluator_id: str
    evaluator_version: str
    command: tuple[str, ...]
    executable_sha256: str
    manifest_signature: str
    timeout_ms: int = 5_000
    maximum_input_bytes: int = 1_048_576
    maximum_output_bytes: int = 1_048_576

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EvaluatorManifest":
        command = value.get("command")
        if not isinstance(command, Sequence) or isinstance(command, (str, bytes)):
            raise PluginExecutionError("EVALUATOR_MANIFEST_INVALID")
        manifest = cls(
            schema_version=str(value.get("schema_version", "")),
            evaluator_id=str(value.get("evaluator_id", "")),
            evaluator_version=str(value.get("evaluator_version", "")),
            command=tuple(str(part) for part in command),
            executable_sha256=str(value.get("executable_sha256", "")),
            manifest_signature=str(value.get("manifest_signature", "")),
            timeout_ms=int(value.get("timeout_ms", 5_000)),
            maximum_input_bytes=int(value.get("maximum_input_bytes", 1_048_576)),
            maximum_output_bytes=int(value.get("maximum_output_bytes", 1_048_576)),
        )
        manifest.validate()
        return manifest

    def validate(self) -> None:
        if (
            self.schema_version != "agenttrust.evaluator-plugin.v1"
            or not self.evaluator_id
            or not self.evaluator_version
            or not self.command
            or len(self.executable_sha256) != 64
            or not self.manifest_signature
            or not 1 <= self.timeout_ms <= 60_000
            or not 1 <= self.maximum_input_bytes <= 8 * 1024 * 1024
            or not 1 <= self.maximum_output_bytes <= 8 * 1024 * 1024
        ):
            raise PluginExecutionError("EVALUATOR_MANIFEST_INVALID")


SignatureVerifier = Callable[[EvaluatorManifest], bool]


class EvaluatorRuntime:
    def __init__(
        self,
        manifest: EvaluatorManifest,
        signature_verifier: SignatureVerifier,
        approved_launcher_prefixes: set[str],
    ) -> None:
        manifest.validate()
        if not signature_verifier(manifest):
            raise PluginExecutionError("EVALUATOR_SIGNATURE_INVALID")
        if not approved_launcher_prefixes or manifest.command[0] not in approved_launcher_prefixes:
            raise PluginExecutionError("EVALUATOR_SANDBOX_NOT_APPROVED")
        self._manifest = manifest

    def evaluate(self, evaluation_input: Mapping[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(
            evaluation_input, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > self._manifest.maximum_input_bytes:
            raise PluginExecutionError("EVALUATOR_INPUT_TOO_LARGE")
        executable = Path(self._manifest.command[0]).resolve(strict=True)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if digest != self._manifest.executable_sha256:
            raise PluginExecutionError("EVALUATOR_EXECUTABLE_CHANGED")
        try:
            process = subprocess.run(
                self._manifest.command,
                input=encoded,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self._manifest.timeout_ms / 1_000,
                check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
        except subprocess.TimeoutExpired as error:
            raise PluginExecutionError("EVALUATOR_TIMEOUT") from error
        if process.returncode != 0:
            raise PluginExecutionError("EVALUATOR_FAILED")
        if len(process.stdout) > self._manifest.maximum_output_bytes:
            raise PluginExecutionError("EVALUATOR_OUTPUT_TOO_LARGE")
        try:
            result = json.loads(process.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PluginExecutionError("EVALUATOR_OUTPUT_INVALID") from error
        self._validate_result(result)
        return result

    @staticmethod
    def _validate_result(result: Any) -> None:
        if not isinstance(result, dict):
            raise PluginExecutionError("EVALUATOR_OUTPUT_INVALID")
        required = {"schema_version", "status", "checks", "findings", "evidence_refs"}
        if set(result) != required or result["schema_version"] != "agenttrust.evaluation.v1":
            raise PluginExecutionError("EVALUATOR_OUTPUT_INVALID")
        if result["status"] not in {"PASS", "FAIL", "NEEDS_HUMAN"}:
            raise PluginExecutionError("EVALUATOR_OUTPUT_INVALID")
        if not all(isinstance(result[field], list) for field in ("checks", "findings", "evidence_refs")):
            raise PluginExecutionError("EVALUATOR_OUTPUT_INVALID")
