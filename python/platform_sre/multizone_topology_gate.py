"""Read-only Kubernetes multi-zone topology and disruption-budget gate."""

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
_DIGEST_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")


class TopologyGateError(RuntimeError):
    pass


class Runner(Protocol):
    def run(self, arguments: Sequence[str], timeout_seconds: int) -> bytes: ...


class SubprocessRunner:
    def run(self, arguments: Sequence[str], timeout_seconds: int) -> bytes:
        try:
            completed = subprocess.run(
                list(arguments), check=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise TopologyGateError("MULTIZONE_KUBECTL_FAILED") from None
        if len(completed.stdout) > 32 * 1024 * 1024 or len(completed.stderr) > 2 * 1024 * 1024:
            raise TopologyGateError("MULTIZONE_KUBECTL_OUTPUT_TOO_LARGE")
        return completed.stdout


@dataclass(frozen=True)
class WorkloadRef:
    namespace: str
    kind: str
    name: str

    @classmethod
    def parse(cls, value: str) -> "WorkloadRef":
        parts = value.split("/")
        if (
            len(parts) != 3
            or parts[1] not in {"deployment", "statefulset"}
            or any(not _SAFE_NAME.fullmatch(part) for part in parts)
        ):
            raise TopologyGateError("MULTIZONE_WORKLOAD_REFERENCE_INVALID")
        return cls(*parts)


class MultiZoneTopologyGate:
    def __init__(
        self,
        kubectl: Path,
        kubeconfig: Path,
        context: str,
        workloads: Sequence[WorkloadRef],
        *,
        minimum_zones: int = 3,
        runner: Runner | None = None,
    ) -> None:
        if (
            not kubectl.is_absolute()
            or not kubeconfig.is_absolute()
            or not kubectl.is_file()
            or not kubeconfig.is_file()
            or not context
            or len(context) > 253
            or not workloads
            or len(workloads) > 256
            or not 2 <= minimum_zones <= 16
        ):
            raise TopologyGateError("MULTIZONE_CONFIGURATION_INVALID")
        self._kubectl = kubectl
        self._kubeconfig = kubeconfig
        self._context = context
        self._workloads = tuple(workloads)
        self._minimum_zones = minimum_zones
        self._runner = runner or SubprocessRunner()

    def _get(self, cache: Path, *arguments: str) -> dict[str, Any]:
        payload = self._runner.run(
            [str(self._kubectl), "--kubeconfig", str(self._kubeconfig),
             "--context", self._context, "--cache-dir", str(cache), *arguments,
             "-o", "json", "--request-timeout=20s"],
            30,
        )
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TopologyGateError("MULTIZONE_RESPONSE_INVALID") from None
        if not isinstance(value, dict):
            raise TopologyGateError("MULTIZONE_RESPONSE_INVALID")
        return value

    def run(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="agenttrust-kube-cache-") as raw_cache:
            cache = Path(raw_cache)
            nodes = self._get(cache, "get", "nodes")
            node_zones = self._ready_node_zones(nodes)
            workload_checks: list[dict[str, Any]] = []
            for reference in self._workloads:
                workload_checks.append(self._verify_workload(cache, reference, node_zones))
        report: dict[str, Any] = {
            "schema_version": "agenttrust.multizone-topology-report.v1",
            "context_digest": hashlib.sha256(self._context.encode()).hexdigest(),
            "minimum_zones": self._minimum_zones,
            "observed_zone_count": len(set(node_zones.values())),
            "ready_node_count": len(node_zones),
            "workloads": workload_checks,
            "passed": True,
            "read_only_probe": True,
            "production_evidence": False,
            "measured_at": datetime.now(timezone.utc).isoformat(),
        }
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report["evidence_digest"] = hashlib.sha256(canonical).hexdigest()
        return report

    def _ready_node_zones(self, document: Mapping[str, Any]) -> dict[str, str]:
        items = document.get("items")
        if not isinstance(items, list) or len(items) > 10_000:
            raise TopologyGateError("MULTIZONE_NODES_INVALID")
        node_zones: dict[str, str] = {}
        for node in items:
            if not isinstance(node, dict):
                raise TopologyGateError("MULTIZONE_NODES_INVALID")
            metadata = node.get("metadata", {})
            spec = node.get("spec", {})
            status = node.get("status", {})
            name = metadata.get("name") if isinstance(metadata, dict) else None
            labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
            zone = labels.get("topology.kubernetes.io/zone") if isinstance(labels, dict) else None
            conditions = status.get("conditions", []) if isinstance(status, dict) else []
            ready = any(
                isinstance(condition, dict)
                and condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in conditions
            )
            if (
                isinstance(name, str)
                and isinstance(zone, str)
                and ready
                and isinstance(spec, dict)
                and not spec.get("unschedulable", False)
            ):
                node_zones[name] = zone
        if len(set(node_zones.values())) < self._minimum_zones:
            raise TopologyGateError("MULTIZONE_INSUFFICIENT_READY_ZONES")
        return node_zones

    def _verify_workload(
        self, cache: Path, reference: WorkloadRef, node_zones: Mapping[str, str]
    ) -> dict[str, Any]:
        workload = self._get(
            cache, "-n", reference.namespace, "get", reference.kind, reference.name
        )
        spec = workload.get("spec")
        status = workload.get("status")
        if not isinstance(spec, dict) or not isinstance(status, dict):
            raise TopologyGateError("MULTIZONE_WORKLOAD_INVALID")
        replicas = spec.get("replicas")
        ready = status.get("readyReplicas", 0)
        template = spec.get("template")
        template_spec = template.get("spec") if isinstance(template, dict) else None
        if not isinstance(replicas, int) or replicas < self._minimum_zones or ready != replicas:
            raise TopologyGateError("MULTIZONE_WORKLOAD_NOT_READY")
        if not isinstance(template_spec, dict) or not self._has_zone_spread(template_spec):
            raise TopologyGateError("MULTIZONE_ZONE_SPREAD_MISSING")
        containers = template_spec.get("containers")
        if not isinstance(containers, list) or not containers or len(containers) > 64:
            raise TopologyGateError("MULTIZONE_CONTAINER_SECURITY_INVALID")
        pod_security = template_spec.get("securityContext", {})
        if (
            not isinstance(pod_security, dict)
            or pod_security.get("runAsNonRoot") is not True
            or pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
        ):
            raise TopologyGateError("MULTIZONE_CONTAINER_SECURITY_INVALID")
        for container in containers:
            security = container.get("securityContext", {}) if isinstance(container, dict) else {}
            if (
                not isinstance(container, dict)
                or not isinstance(container.get("image"), str)
                or not _DIGEST_IMAGE.fullmatch(container["image"])
                or security.get("readOnlyRootFilesystem") is not True
                or security.get("allowPrivilegeEscalation") is not False
                or security.get("capabilities", {}).get("drop") != ["ALL"]
            ):
                raise TopologyGateError("MULTIZONE_CONTAINER_SECURITY_INVALID")
        selector = spec.get("selector", {}).get("matchLabels")
        if not isinstance(selector, dict) or not selector:
            raise TopologyGateError("MULTIZONE_SELECTOR_INVALID")
        selector_text = ",".join(f"{key}={value}" for key, value in sorted(selector.items()))
        pods = self._get(
            cache, "-n", reference.namespace, "get", "pods", "-l", selector_text
        )
        pod_zones = self._pod_zones(pods, node_zones)
        if len(pod_zones) < self._minimum_zones:
            raise TopologyGateError("MULTIZONE_PODS_NOT_DISTRIBUTED")
        pdbs = self._get(
            cache, "-n", reference.namespace, "get", "poddisruptionbudgets"
        )
        if not self._matching_pdb(pdbs, selector):
            raise TopologyGateError("MULTIZONE_PDB_INVALID")
        workload_digest = hashlib.sha256(
            json.dumps(workload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "reference": f"{reference.namespace}/{reference.kind}/{reference.name}",
            "replicas": replicas,
            "ready_replicas": ready,
            "observed_pod_zones": len(pod_zones),
            "zone_spread_enforced": True,
            "pdb_allows_one_disruption": True,
            "images_digest_pinned": True,
            "pod_security_hardened": True,
            "workload_digest": workload_digest,
        }

    @staticmethod
    def _has_zone_spread(spec: Mapping[str, Any]) -> bool:
        constraints = spec.get("topologySpreadConstraints", [])
        if isinstance(constraints, list) and any(
            isinstance(item, dict)
            and item.get("topologyKey") == "topology.kubernetes.io/zone"
            and item.get("whenUnsatisfiable") == "DoNotSchedule"
            and item.get("maxSkew") == 1
            for item in constraints
        ):
            return True
        affinity = spec.get("affinity", {})
        required = (
            affinity.get("podAntiAffinity", {}).get("requiredDuringSchedulingIgnoredDuringExecution", [])
            if isinstance(affinity, dict) else []
        )
        return isinstance(required, list) and any(
            isinstance(item, dict)
            and item.get("topologyKey") == "topology.kubernetes.io/zone"
            for item in required
        )

    @staticmethod
    def _pod_zones(document: Mapping[str, Any], node_zones: Mapping[str, str]) -> set[str]:
        items = document.get("items")
        if not isinstance(items, list):
            raise TopologyGateError("MULTIZONE_PODS_INVALID")
        zones: set[str] = set()
        for pod in items:
            spec = pod.get("spec", {}) if isinstance(pod, dict) else {}
            status = pod.get("status", {}) if isinstance(pod, dict) else {}
            node = spec.get("nodeName") if isinstance(spec, dict) else None
            if status.get("phase") == "Running" and node in node_zones:
                zones.add(node_zones[node])
        return zones

    @staticmethod
    def _matching_pdb(document: Mapping[str, Any], selector: Mapping[str, Any]) -> bool:
        items = document.get("items")
        if not isinstance(items, list):
            raise TopologyGateError("MULTIZONE_PDB_INVALID")
        for pdb in items:
            if not isinstance(pdb, dict):
                continue
            spec = pdb.get("spec", {})
            status = pdb.get("status", {})
            labels = spec.get("selector", {}).get("matchLabels") if isinstance(spec, dict) else None
            if labels != selector or not isinstance(status, dict) or status.get("disruptionsAllowed", 0) < 1:
                continue
            minimum = spec.get("minAvailable")
            maximum = spec.get("maxUnavailable")
            if (isinstance(minimum, int) and minimum >= 2) or (
                isinstance(maximum, int) and maximum >= 1
            ):
                return True
        return False


def _write_new(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise TopologyGateError("MULTIZONE_REPORT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-multizone-topology-gate")
    parser.add_argument("--kubectl", type=Path, required=True)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--workload", action="append", required=True)
    parser.add_argument("--minimum-zones", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    gate = MultiZoneTopologyGate(
        args.kubectl, args.kubeconfig, args.context,
        [WorkloadRef.parse(value) for value in args.workload],
        minimum_zones=args.minimum_zones,
    )
    report = gate.run()
    _write_new(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
