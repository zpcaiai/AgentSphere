"""Allowlisted Chaos Mesh runner for dedicated non-production clusters."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Mapping, Protocol, Sequence


_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")


class Runner(Protocol):
    def run(self, args: Sequence[str], timeout: int) -> bytes: ...


class SubprocessRunner:
    def run(self, args: Sequence[str], timeout: int) -> bytes:
        try:
            completed = subprocess.run(list(args), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=timeout,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin"})
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError("CHAOS_COMMAND_FAILED") from exc
        if len(completed.stdout) > 2_000_000 or len(completed.stderr) > 2_000_000:
            raise RuntimeError("CHAOS_COMMAND_OUTPUT_TOO_LARGE")
        return completed.stdout


@dataclass(frozen=True)
class ChaosConfig:
    kubectl: Path
    manifest_root: Path
    allowed_context_pattern: str
    allowed_namespaces: tuple[str, ...]
    scenarios: Mapping[str, str]
    timeout_seconds: int

    @classmethod
    def load(cls, path: Path) -> "ChaosConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != "agenttrust.chaos-runner-config.v1" or raw.get("fail_closed") is not True:
            raise ValueError("CHAOS_CONFIG_INVALID")
        value = cls(Path(raw["kubectl"]), Path(raw["manifest_root"]), raw["allowed_context_pattern"],
            tuple(raw["allowed_namespaces"]), dict(raw["scenarios"]), int(raw["timeout_seconds"]))
        if (not value.kubectl.is_absolute() or not value.manifest_root.is_absolute()
            or not value.allowed_namespaces or any(not _SAFE_NAME.fullmatch(item) for item in value.allowed_namespaces)
            or not value.scenarios or any(not _SAFE_NAME.fullmatch(key) for key in value.scenarios)
            or not 1 <= value.timeout_seconds <= 7200):
            raise ValueError("CHAOS_CONFIG_INVALID")
        re.compile(value.allowed_context_pattern)
        return value


class ChaosRunner:
    def __init__(self, config: ChaosConfig, runner: Runner | None = None) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()

    def _run(self, args: Sequence[str]) -> bytes:
        return self._runner.run(args, self._config.timeout_seconds)

    def preflight(self, namespace: str, scenario: str) -> tuple[str, Path]:
        if namespace not in self._config.allowed_namespaces or scenario not in self._config.scenarios:
            raise PermissionError("CHAOS_TARGET_NOT_ALLOWLISTED")
        context = self._run([str(self._config.kubectl), "config", "current-context"]).decode().strip()
        if not re.fullmatch(self._config.allowed_context_pattern, context) or "prod" in context.lower():
            raise PermissionError("CHAOS_CONTEXT_DENIED")
        namespace_json = json.loads(self._run([str(self._config.kubectl), "get", "namespace", namespace, "-o", "json"]))
        labels = namespace_json.get("metadata", {}).get("labels", {})
        if labels.get("agenttrust.io/chaos-allowed") != "true":
            raise PermissionError("CHAOS_NAMESPACE_NOT_LABELED")
        root = self._config.manifest_root.resolve(strict=True)
        manifest = (root / self._config.scenarios[scenario]).resolve(strict=True)
        if manifest.parent != root or manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 1_000_000:
            raise PermissionError("CHAOS_MANIFEST_DENIED")
        return context, manifest

    def execute(self, namespace: str, scenario: str, *, execute: bool) -> Mapping[str, Any]:
        context, manifest = self.preflight(namespace, scenario)
        manifest_bytes = manifest.read_bytes()
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        if not execute:
            return {"schema_version":"agenttrust.chaos-report.v1","scenario":scenario,
                "namespace":namespace,"context":context,"manifest_digest":digest,
                "executed":False,"cleanup_verified":False,"production_evidence":False}
        if os.environ.get("AGENT_TRUST_CHAOS_ACK") != f"{context}:{namespace}:{scenario}":
            raise PermissionError("CHAOS_EXPLICIT_ACK_REQUIRED")
        rendered = manifest_bytes.decode().replace("${NAMESPACE}", namespace)
        if "${" in rendered:
            raise ValueError("CHAOS_MANIFEST_VARIABLE_UNRESOLVED")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8") as temp:
            temp.write(rendered)
            temp.flush()
            applied = False
            try:
                self._run([str(self._config.kubectl), "apply", "--server-side", "-f", temp.name])
                applied = True
                self._run([str(self._config.kubectl), "wait", "--for=condition=AllInjected", "--timeout=120s", "-f", temp.name])
            finally:
                if applied:
                    self._run([str(self._config.kubectl), "delete", "--wait=true", "--timeout=180s", "-f", temp.name])
        report = {"schema_version":"agenttrust.chaos-report.v1","scenario":scenario,
            "namespace":namespace,"context":context,"manifest_digest":digest,
            "executed":True,"cleanup_verified":True,"production_evidence":False,
            "completed_at":datetime.now(timezone.utc).isoformat()}
        return {**report,"evidence_digest":hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-chaos-runner")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    report = ChaosRunner(ChaosConfig.load(args.config)).execute(args.namespace, args.scenario, execute=args.execute)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
