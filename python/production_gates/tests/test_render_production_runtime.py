from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


_PATH = Path(__file__).parents[3] / "scripts" / "render-production-runtime.py"
_SPEC = importlib.util.spec_from_file_location("render_production_runtime", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


class RenderProductionRuntimeTests(unittest.TestCase):
    def test_requires_digest_pinned_images(self) -> None:
        with self.assertRaisesRegex(_MODULE.RenderError, "IMAGE_NOT_IMMUTABLE"):
            _MODULE.render("@@PRODUCTION_RUNTIME_IMAGE@@ @@ENVOY_IMAGE@@ @@RELEASE_ID@@",
                           "agenttrust/runtime:latest", "envoy@sha256:" + "b" * 64, "release-1")

    def test_rejects_worktree_release(self) -> None:
        with self.assertRaisesRegex(_MODULE.RenderError, "RELEASE_ID_INVALID"):
            _MODULE.render("@@PRODUCTION_RUNTIME_IMAGE@@ @@ENVOY_IMAGE@@ @@RELEASE_ID@@",
                           "agenttrust/runtime@sha256:" + "a" * 64,
                           "envoy@sha256:" + "b" * 64, "WORKTREE-NO-GIT")

    def test_renders_all_immutable_inputs(self) -> None:
        result = _MODULE.render(
            "image: @@PRODUCTION_RUNTIME_IMAGE@@\nsidecar: @@ENVOY_IMAGE@@\nrelease: @@RELEASE_ID@@\n",
            "agenttrust/runtime@sha256:" + "a" * 64,
            "envoyproxy/envoy@sha256:" + "b" * 64, "release-1",
        )
        self.assertNotIn("@@", result)
        self.assertIn("release-1", result)


if __name__ == "__main__":
    unittest.main()
