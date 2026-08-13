"""Allowlisted real Kubernetes pod-loss recovery drill for disposable clusters."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Mapping, Sequence


_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_PINNED_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_ALLOWED_CONTEXT = re.compile(r"^kind-agenttrust-chaos-[a-z0-9-]+$")


class KubernetesDrillError(RuntimeError):
    pass


class Kubectl:
    def __init__(
        self, binary: Path, kubeconfig: Path, context: str, timeout_seconds: int
    ) -> None:
        if (
            not binary.is_absolute()
            or not binary.is_file()
            or not os.access(binary, os.X_OK)
            or not kubeconfig.is_absolute()
            or not kubeconfig.is_file()
            or not _ALLOWED_CONTEXT.fullmatch(context)
            or "prod" in context.lower()
            or not 30 <= timeout_seconds <= 1800
        ):
            raise KubernetesDrillError("KUBERNETES_DRILL_CONFIGURATION_INVALID")
        self.binary = binary
        self.kubeconfig = kubeconfig
        self.context = context
        self.timeout_seconds = timeout_seconds
        self._cache_directory = tempfile.TemporaryDirectory(
            prefix="agenttrust-kubectl-cache-"
        )

    def run(self, args: Sequence[str]) -> bytes:
        try:
            result = subprocess.run(
                [
                    str(self.binary), "--kubeconfig", str(self.kubeconfig),
                    "--cache-dir", self._cache_directory.name,
                    "--context", self.context, *args,
                ],
                # The process has no ambient HOME. Authentication and target
                # selection are bound to this explicitly supplied file.
                check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=self.timeout_seconds,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise KubernetesDrillError("KUBERNETES_DRILL_COMMAND_FAILED") from None
        if len(result.stdout) > 2_000_000 or len(result.stderr) > 2_000_000:
            raise KubernetesDrillError("KUBERNETES_DRILL_OUTPUT_TOO_LARGE")
        return result.stdout


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def run_drill(
    kubectl_binary: Path,
    kubeconfig: Path,
    context: str,
    namespace: str,
    image: str,
    timeout_seconds: int,
) -> Mapping[str, Any]:
    if not _SAFE_NAME.fullmatch(namespace) or not namespace.startswith("agenttrust-chaos-"):
        raise KubernetesDrillError("KUBERNETES_DRILL_NAMESPACE_DENIED")
    if not _PINNED_IMAGE.fullmatch(image):
        raise KubernetesDrillError("KUBERNETES_DRILL_IMAGE_NOT_PINNED")
    kubectl = Kubectl(kubectl_binary, kubeconfig, context, timeout_seconds)
    current = kubectl.run(["config", "current-context"]).decode().strip()
    if current != context:
        raise KubernetesDrillError("KUBERNETES_DRILL_CONTEXT_MISMATCH")
    started_at = datetime.now(timezone.utc)
    deployment = "agenttrust-recovery-probe"
    namespace_created = False
    cleanup_verified = False
    try:
        kubectl.run(["create", "namespace", namespace])
        namespace_created = True
        kubectl.run(["label", "namespace", namespace, "agenttrust.io/chaos-allowed=true"])
        manifest = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": deployment, "namespace": namespace},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": deployment}},
                "template": {
                    "metadata": {"labels": {"app": deployment}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532},
                        "containers": [{
                            "name": "probe",
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["/bin/sh", "-c", "sleep 3600"],
                            "resources": {
                                "requests": {"cpu": "5m", "memory": "8Mi"},
                                "limits": {"cpu": "50m", "memory": "32Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                        }],
                    },
                },
            },
        }
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", encoding="utf-8", delete=False
        ) as stream:
            json.dump(manifest, stream, sort_keys=True)
            manifest_path = Path(stream.name)
        try:
            kubectl.run(["apply", "-f", str(manifest_path)])
        finally:
            manifest_path.unlink(missing_ok=True)
        kubectl.run([
            "wait", "--namespace", namespace, "--for=condition=Available",
            f"--timeout={timeout_seconds}s", f"deployment/{deployment}",
        ])
        pod = json.loads(kubectl.run([
            "get", "pods", "--namespace", namespace, "-l", f"app={deployment}",
            "-o", "json",
        ]))
        items = pod.get("items", [])
        if len(items) != 1:
            raise KubernetesDrillError("KUBERNETES_DRILL_INITIAL_POD_INVALID")
        old_name = items[0]["metadata"]["name"]
        old_uid = items[0]["metadata"]["uid"]
        fault_started = time.monotonic()
        kubectl.run(["delete", "pod", old_name, "--namespace", namespace, "--wait=false"])
        deadline = time.monotonic() + timeout_seconds
        new_uid = ""
        while time.monotonic() < deadline:
            pod = json.loads(kubectl.run([
                "get", "pods", "--namespace", namespace, "-l", f"app={deployment}",
                "-o", "json",
            ]))
            ready = [
                item for item in pod.get("items", [])
                if item.get("metadata", {}).get("uid") != old_uid
                and any(
                    condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in item.get("status", {}).get("conditions", [])
                )
            ]
            if len(ready) == 1:
                new_uid = ready[0]["metadata"]["uid"]
                break
            time.sleep(0.1)
        if not new_uid:
            raise KubernetesDrillError("KUBERNETES_DRILL_RECOVERY_TIMEOUT")
        rto_ms = int((time.monotonic() - fault_started) * 1000)
        completed_at = datetime.now(timezone.utc)
    finally:
        if namespace_created:
            kubectl.run([
                "delete", "namespace", namespace, "--wait=true",
                f"--timeout={timeout_seconds}s",
            ])
            cleanup_verified = True
    report: dict[str, Any] = {
        "schema_version": "agenttrust.kubernetes-recovery-drill.v1",
        "context": context,
        "namespace": namespace,
        "image": image,
        "fault": "POD_DELETE",
        "checks": {
            "dedicated_context_allowlisted": True,
            "namespace_labeled": True,
            "initial_workload_available": True,
            "pod_uid_replaced": old_uid != new_uid,
            "replacement_ready": True,
            "cleanup_verified": cleanup_verified,
        },
        "rto_milliseconds": rto_ms,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "production_evidence": False,
    }
    report["evidence_digest"] = _digest(report)
    return report


def _write_new(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise KubernetesDrillError("KUBERNETES_DRILL_REPORT_PATH_INVALID")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-kubernetes-recovery-drill")
    parser.add_argument("--kubectl", type=Path, required=True)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run_drill(
        args.kubectl, args.kubeconfig, args.context, args.namespace,
        args.image, args.timeout_seconds,
    )
    _write_new(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
