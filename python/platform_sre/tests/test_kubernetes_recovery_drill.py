from pathlib import Path
import tempfile
import unittest

from python.platform_sre.kubernetes_recovery_drill import (
    KubernetesDrillError,
    run_drill,
)


class KubernetesRecoveryDrillTests(unittest.TestCase):
    def test_production_context_and_mutable_image_are_denied_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            kubectl = Path(raw) / "kubectl"
            kubectl.write_bytes(b"binary")
            kubectl.chmod(0o700)
            kubeconfig = Path(raw) / "kubeconfig"
            kubeconfig.write_text("apiVersion: v1\n", encoding="utf-8")
            with self.assertRaisesRegex(
                KubernetesDrillError, "KUBERNETES_DRILL_IMAGE_NOT_PINNED"
            ):
                run_drill(
                    kubectl, kubeconfig, "kind-agenttrust-chaos-local",
                    "agenttrust-chaos-test", "alpine:latest", 60,
                )
            with self.assertRaisesRegex(
                KubernetesDrillError, "KUBERNETES_DRILL_CONFIGURATION_INVALID"
            ):
                run_drill(
                    kubectl, kubeconfig, "production", "agenttrust-chaos-test",
                    "alpine@sha256:" + "a" * 64, 60,
                )


if __name__ == "__main__":
    unittest.main()
