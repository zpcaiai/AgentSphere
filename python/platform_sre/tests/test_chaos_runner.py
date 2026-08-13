from pathlib import Path
import json
import tempfile
import unittest

from python.platform_sre.chaos_runner import ChaosConfig, ChaosRunner


class FakeRunner:
    def __init__(self, context="agenttrust-chaos-dev"):
        self.context = context
        self.commands = []

    def run(self, args, timeout):
        self.commands.append(tuple(args))
        if args[-2:] == ("config", "current-context") or args[-2:] == ["config", "current-context"]:
            return (self.context + "\n").encode()
        if "namespace" in args:
            return json.dumps({"metadata":{"labels":{"agenttrust.io/chaos-allowed":"true"}}}).encode()
        return b"ok"


class ChaosRunnerTests(unittest.TestCase):
    def test_dry_run_preflights_without_applying(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = root / "pod-kill.yaml"
            manifest.write_text("metadata:\n  namespace: ${NAMESPACE}\n", encoding="utf-8")
            fake = FakeRunner()
            config = ChaosConfig(Path("/usr/bin/kubectl"), root, r"agenttrust-chaos-[a-z]+",
                ("chaos-test",), {"pod-kill":"pod-kill.yaml"}, 10)
            report = ChaosRunner(config, fake).execute("chaos-test", "pod-kill", execute=False)
            self.assertFalse(report["executed"])
            self.assertFalse(any("apply" in command for command in fake.commands))

    def test_production_context_is_denied(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "pod-kill.yaml").write_text("kind: PodChaos\n", encoding="utf-8")
            config = ChaosConfig(Path("/usr/bin/kubectl"), root, r"agenttrust-.*",
                ("chaos-test",), {"pod-kill":"pod-kill.yaml"}, 10)
            with self.assertRaisesRegex(PermissionError, "CHAOS_CONTEXT_DENIED"):
                ChaosRunner(config, FakeRunner("agenttrust-production")).execute("chaos-test", "pod-kill", execute=False)


if __name__ == "__main__":
    unittest.main()
