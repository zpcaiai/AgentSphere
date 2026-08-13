import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from python.evaluator_runtime import EvaluatorManifest, EvaluatorRuntime, PluginExecutionError


class RuntimeTests(unittest.TestCase):
    def manifest(self, executable: str) -> EvaluatorManifest:
        return EvaluatorManifest(
            schema_version="agenttrust.evaluator-plugin.v1",
            evaluator_id="test",
            evaluator_version="1.0.0",
            command=(executable, "-c", "import sys;sys.stdout.write('{}')"),
            executable_sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
            manifest_signature="test-signature",
        )

    def test_unapproved_launcher_fails_closed(self) -> None:
        with self.assertRaisesRegex(PluginExecutionError, "SANDBOX_NOT_APPROVED"):
            EvaluatorRuntime(self.manifest(sys.executable), lambda _: True, set())

    def test_invalid_plugin_output_is_rejected(self) -> None:
        runtime = EvaluatorRuntime(
            self.manifest(sys.executable), lambda _: True, {sys.executable}
        )
        with self.assertRaisesRegex(PluginExecutionError, "OUTPUT_INVALID"):
            runtime.evaluate({"task_id": "task"})

    def test_executable_digest_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "plugin"
            executable.write_bytes(b"#!/bin/sh\n")
            executable.chmod(0o700)
            manifest = self.manifest(str(executable))
            runtime = EvaluatorRuntime(manifest, lambda _: True, {str(executable)})
            executable.write_bytes(b"#!/bin/sh\nexit 1\n")
            with self.assertRaisesRegex(PluginExecutionError, "EXECUTABLE_CHANGED"):
                runtime.evaluate({})


if __name__ == "__main__":
    unittest.main()
