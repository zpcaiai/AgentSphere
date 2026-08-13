from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from python.platform_sre.multizone_topology_gate import (
    MultiZoneTopologyGate,
    TopologyGateError,
    WorkloadRef,
)


class FakeKubectl:
    def __init__(self, zones: int = 3) -> None:
        self.zones = zones

    def run(self, arguments, timeout_seconds):
        assert timeout_seconds == 30
        args = list(arguments)
        get_index = args.index("get")
        resource = args[get_index + 1]
        if resource == "nodes":
            return self._nodes()
        if resource == "deployment":
            return json.dumps(self._workload()).encode()
        if resource == "pods":
            return self._pods()
        if resource == "poddisruptionbudgets":
            return json.dumps({"items": [{
                "spec": {
                    "selector": {"matchLabels": {"app": "gateway"}},
                    "minAvailable": 2,
                },
                "status": {"disruptionsAllowed": 1},
            }]}).encode()
        raise AssertionError(args)

    def _nodes(self):
        items = []
        for index in range(self.zones):
            items.append({
                "metadata": {"name": f"node-{index}", "labels": {
                    "topology.kubernetes.io/zone": f"zone-{index}",
                }},
                "spec": {"unschedulable": False},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            })
        return json.dumps({"items": items}).encode()

    def _pods(self):
        items = [{
            "spec": {"nodeName": f"node-{index}"},
            "status": {"phase": "Running"},
        } for index in range(self.zones)]
        return json.dumps({"items": items}).encode()

    @staticmethod
    def _workload():
        return {
            "metadata": {"name": "gateway", "namespace": "agenttrust"},
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "gateway"}},
                "template": {"spec": {
                    "securityContext": {
                        "runAsNonRoot": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "topologySpreadConstraints": [{
                        "maxSkew": 1,
                        "topologyKey": "topology.kubernetes.io/zone",
                        "whenUnsatisfiable": "DoNotSchedule",
                    }],
                    "containers": [{
                        "name": "gateway",
                        "image": "registry.example.test/gateway@sha256:" + "a" * 64,
                        "securityContext": {
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                    }],
                }},
            },
            "status": {"readyReplicas": 3},
        }


class MultiZoneTopologyGateTests(unittest.TestCase):
    def _gate(self, root: Path, zones: int) -> MultiZoneTopologyGate:
        kubectl = root / "kubectl"
        kubeconfig = root / "kubeconfig"
        kubectl.write_bytes(b"binary")
        kubeconfig.write_text("config", encoding="utf-8")
        return MultiZoneTopologyGate(
            kubectl, kubeconfig, "production-cluster",
            [WorkloadRef.parse("agenttrust/deployment/gateway")],
            runner=FakeKubectl(zones),
        )

    def test_three_zone_ready_hardened_workload_passes_read_only_gate(self):
        with tempfile.TemporaryDirectory() as raw:
            report = self._gate(Path(raw).resolve(), 3).run()
        self.assertTrue(report["passed"])
        self.assertTrue(report["read_only_probe"])
        self.assertFalse(report["production_evidence"])
        self.assertEqual(report["observed_zone_count"], 3)
        self.assertTrue(report["workloads"][0]["pdb_allows_one_disruption"])

    def test_one_zone_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(TopologyGateError):
                self._gate(Path(raw).resolve(), 1).run()


if __name__ == "__main__":
    unittest.main()
