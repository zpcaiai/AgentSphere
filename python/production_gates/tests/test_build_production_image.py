from pathlib import Path
import importlib.util
import unittest


_ROOT = Path(__file__).parents[3]
_SPEC = importlib.util.spec_from_file_location("build_production_image", _ROOT / "scripts/build-production-image.py")
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


class BuildProductionImageTests(unittest.TestCase):
    def test_mutable_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(_MODULE.BuildConfigurationError, "CONFIGURATION_INVALID"):
            _MODULE.command_for("orchestrator", "agenttrust/orchestrator:release-1", ["python:latest"], _ROOT)

    def test_runtime_build_is_digest_pinned_and_does_not_pull_mutable_bases(self) -> None:
        command = _MODULE.command_for(
            "runtime", "agenttrust/runtime:release-1",
            ["rust@sha256:" + "a" * 64, "distroless@sha256:" + "b" * 64], _ROOT,
        )
        self.assertIn("--pull=false", command)
        self.assertIn("RUST_BUILDER_IMAGE=rust@sha256:" + "a" * 64, command)


if __name__ == "__main__":
    unittest.main()
