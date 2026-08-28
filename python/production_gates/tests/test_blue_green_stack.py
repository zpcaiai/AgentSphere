from __future__ import annotations

import unittest

import yaml

from python.production_gates.blue_green_stack import materialize_blue_green_stack


SOURCE = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: agenttrust-config
  labels: {agenttrust.io/apply-phase: prerequisite}
data: {config.json: '{}'}
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: agenttrust-secrets
  labels: {agenttrust.io/apply-phase: prerequisite}
spec: {provider: vault, parameters: {objects: '[]'}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agenttrust-api
  labels: {agenttrust.io/apply-phase: workload}
spec:
  replicas: 3
  selector: {matchLabels: {app: agenttrust-api}}
  template:
    metadata: {labels: {app: agenttrust-api}}
    spec:
      topologySpreadConstraints:
        - {maxSkew: 1, topologyKey: topology.kubernetes.io/zone, whenUnsatisfiable: DoNotSchedule, labelSelector: {matchLabels: {app: agenttrust-api}}}
      containers:
        - name: api
          image: registry.example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          volumeMounts: [{name: config, mountPath: /config}]
      volumes:
        - {name: config, configMap: {name: agenttrust-config}}
        - {name: secrets, csi: {driver: secrets-store.csi.k8s.io, volumeAttributes: {secretProviderClass: agenttrust-secrets}}}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: agenttrust-api
  labels: {agenttrust.io/apply-phase: workload}
spec: {minAvailable: 2, selector: {matchLabels: {app: agenttrust-api}}}
---
apiVersion: v1
kind: Service
metadata:
  name: agenttrust-api
  labels: {agenttrust.io/apply-phase: workload}
spec: {selector: {app: agenttrust-api}, ports: [{port: 443, targetPort: 8443}]}
"""


class BlueGreenStackTests(unittest.TestCase):
    def test_two_releases_coexist_and_only_stable_service_switches(self) -> None:
        first, first_plan = materialize_blue_green_stack(
            SOURCE,
            release_id="git:sha1:" + "a" * 40,
            release_digest="1" * 64,
        )
        second, second_plan = materialize_blue_green_stack(
            SOURCE,
            release_id="git:sha1:" + "b" * 40,
            release_digest="2" * 64,
        )
        first_docs = list(yaml.safe_load_all(first))
        second_docs = list(yaml.safe_load_all(second))
        for kind in ("ConfigMap", "Deployment", "PodDisruptionBudget", "SecretProviderClass"):
            first_names = {item["metadata"]["name"] for item in first_docs if item["kind"] == kind}
            second_names = {item["metadata"]["name"] for item in second_docs if item["kind"] == kind}
            self.assertTrue(first_names.isdisjoint(second_names))
        first_service = next(item for item in first_docs if item["kind"] == "Service")
        second_service = next(item for item in second_docs if item["kind"] == "Service")
        self.assertEqual(first_service["metadata"]["name"], second_service["metadata"]["name"])
        self.assertNotEqual(first_service["spec"]["selector"], second_service["spec"]["selector"])
        self.assertEqual(first_service["metadata"]["labels"]["agenttrust.io/apply-phase"], "traffic")
        first_deployment = next(item for item in first_docs if item["kind"] == "Deployment")
        volume_names = [
            next(iter(volume.get("configMap", {}).values()), None)
            for volume in first_deployment["spec"]["template"]["spec"]["volumes"]
            if "configMap" in volume
        ]
        self.assertIn(first_plan["versioned_resources"]["ConfigMap"]["agenttrust-config"], volume_names)
        self.assertNotEqual(first_plan["revision"], second_plan["revision"])


if __name__ == "__main__":
    unittest.main()
