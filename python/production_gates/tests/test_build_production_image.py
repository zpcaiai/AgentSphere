from pathlib import Path
import importlib.util
import re
import tomllib
import unittest


_ROOT = Path(__file__).parents[3]
_SPEC = importlib.util.spec_from_file_location("build_production_image", _ROOT / "scripts/build-production-image.py")
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


class BuildProductionImageTests(unittest.TestCase):
    def test_every_cargo_dockerfile_uses_a_declared_binary(self) -> None:
        packages: dict[str, tuple[Path, set[str]]] = {}
        for manifest in (_ROOT / "rust/crates").glob("*/Cargo.toml"):
            data = tomllib.loads(manifest.read_text())
            package = data.get("package", {}).get("name")
            if not isinstance(package, str):
                continue
            crate = manifest.parent
            binaries = {
                item["name"] for item in data.get("bin", [])
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            binary_directory = crate / "src/bin"
            if binary_directory.is_dir():
                binaries.update(path.stem for path in binary_directory.glob("*.rs"))
            if (crate / "src/main.rs").is_file():
                binaries.add(package)
            packages[package] = (manifest, binaries)

        checked = 0
        for dockerfile in _ROOT.rglob("Dockerfile*"):
            if "skills" in dockerfile.parts or "target" in dockerfile.parts:
                continue
            content = dockerfile.read_text()
            if "cargo build" not in content:
                continue
            command = re.search(
                r"cargo\s+build\b.*?(?:-p|--package)\s+([A-Za-z0-9_-]+)"
                r"(.*?)(?:&&|\n\s*\n|\nFROM )",
                content,
                re.DOTALL,
            )
            with self.subTest(dockerfile=str(dockerfile)):
                self.assertIsNotNone(command)
                assert command is not None
                package, arguments = command.groups()
                self.assertIn(package, packages)
                binary_match = re.search(r"--bin\s+([A-Za-z0-9_-]+)", arguments)
                binary = binary_match.group(1) if binary_match else package
                self.assertIn(binary, packages[package][1])
                self.assertIn(f"/target/release/{binary}", content)
                self.assertIn(f"/usr/local/bin/{binary}", content)
            checked += 1
        self.assertEqual(checked, 26)

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

    def test_model_gateway_uses_dedicated_digest_pinned_dockerfile(self) -> None:
        command = _MODULE.command_for(
            "model-gateway",
            "agenttrust/model-gateway:release-1",
            ["rust@sha256:" + "a" * 64, "distroless@sha256:" + "b" * 64],
            _ROOT,
        )
        self.assertIn(str(_ROOT / "Dockerfile.model-gateway"), command)
        self.assertIn("RUST_BUILDER_IMAGE=rust@sha256:" + "a" * 64, command)
        self.assertIn("RUNTIME_BASE_IMAGE=distroless@sha256:" + "b" * 64, command)
        self.assertIn("--pull=false", command)

    def test_data_governance_uses_dedicated_digest_pinned_dockerfile(self) -> None:
        command = _MODULE.command_for(
            "data-governance",
            "agenttrust/data-governance:release-1",
            ["rust@sha256:" + "a" * 64, "distroless@sha256:" + "b" * 64],
            _ROOT,
        )
        self.assertIn(str(_ROOT / "Dockerfile.data-governance"), command)
        self.assertIn("RUST_BUILDER_IMAGE=rust@sha256:" + "a" * 64, command)
        self.assertIn("RUNTIME_BASE_IMAGE=distroless@sha256:" + "b" * 64, command)
        self.assertIn("--pull=false", command)


if __name__ == "__main__":
    unittest.main()
