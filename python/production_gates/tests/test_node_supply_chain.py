from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "validate_node_supply_chain", ROOT / "scripts/validate-node-supply-chain.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def integrity(byte: int) -> str:
    return "sha512-" + base64.b64encode(bytes([byte]) * 64).decode("ascii")


def fixture() -> tuple[dict[str, object], dict[str, object], str]:
    dev = {"esbuild": "0.25.12", "vitest": "3.2.4"}
    package = {
        "name": "console",
        "version": "1.0.0",
        "packageManager": "npm@11.17.0",
        "engines": {"node": "24.19.0", "npm": "11.17.0"},
        "dependencies": {},
        "devDependencies": dict(dev),
        "allowScripts": {"esbuild@0.25.12": True, "fsevents": False},
    }
    lock = {
        "name": "console",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "console",
                "version": "1.0.0",
                "engines": {"node": "24.19.0", "npm": "11.17.0"},
                "dependencies": {},
                "devDependencies": dict(dev),
            },
            "node_modules/esbuild": {
                "version": "0.25.12",
                "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.25.12.tgz",
                "integrity": integrity(1),
                "hasInstallScript": True,
            },
            "node_modules/fsevents": {
                "version": "2.3.3",
                "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                "integrity": integrity(2),
                "hasInstallScript": True,
            },
            "node_modules/vitest": {
                "version": "3.2.4",
                "resolved": "https://registry.npmjs.org/vitest/-/vitest-3.2.4.tgz",
                "integrity": integrity(3),
            },
        },
    }
    return package, lock, "strict-allow-scripts=true\n"


class NodeSupplyChainTests(unittest.TestCase):
    def validate(
        self, package: dict[str, object], lock: dict[str, object], npmrc: str
    ) -> tuple[int, int]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_path = root / "package.json"
            lock_path = root / "package-lock.json"
            npmrc_path = root / ".npmrc"
            package_path.write_text(json.dumps(package), encoding="utf-8")
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            npmrc_path.write_text(npmrc, encoding="utf-8")
            return MODULE.validate(package_path, lock_path, npmrc_path)

    def test_accepts_pinned_registry_and_explicit_script_policy(self) -> None:
        package, lock, npmrc = fixture()
        self.assertEqual(self.validate(package, lock, npmrc), (3, 2))

    def test_rejects_unapproved_registry(self) -> None:
        package, lock, npmrc = fixture()
        lock["packages"]["node_modules/esbuild"]["resolved"] = (
            "https://registry.npmmirror.com/esbuild/-/esbuild-0.25.12.tgz"
        )
        with self.assertRaisesRegex(RuntimeError, "REGISTRY_NOT_APPROVED"):
            self.validate(package, lock, npmrc)

    def test_binds_tarball_to_resolved_package_identity_and_version(self) -> None:
        package, lock, npmrc = fixture()
        lock["packages"]["node_modules/esbuild"]["resolved"] = (
            "https://registry.npmjs.org/not-esbuild/-/not-esbuild-9.9.9.tgz"
        )
        with self.assertRaisesRegex(RuntimeError, "TARBALL_IDENTITY_MISMATCH"):
            self.validate(package, lock, npmrc)

    def test_uses_resolved_identity_for_aliased_install_script(self) -> None:
        package, lock, npmrc = fixture()
        package["devDependencies"].pop("esbuild")
        lock["packages"][""]["devDependencies"].pop("esbuild")
        lock["packages"].pop("node_modules/esbuild")
        lock["packages"]["node_modules/script-alias"] = {
            "name": "real-script",
            "version": "1.2.3",
            "resolved": "https://registry.npmjs.org/real-script/-/real-script-1.2.3.tgz",
            "integrity": integrity(4),
            "hasInstallScript": True,
        }
        package["allowScripts"] = {"real-script@1.2.3": True, "fsevents": False}
        self.assertEqual(self.validate(package, lock, npmrc), (3, 2))

    def test_rejects_malformed_registry_port(self) -> None:
        package, lock, npmrc = fixture()
        lock["packages"]["node_modules/esbuild"]["resolved"] = (
            "https://registry.npmjs.org:invalid/esbuild/-/esbuild-0.25.12.tgz"
        )
        with self.assertRaisesRegex(RuntimeError, "REGISTRY_NOT_APPROVED"):
            self.validate(package, lock, npmrc)

    def test_rejects_noncanonical_lock_path(self) -> None:
        package, lock, npmrc = fixture()
        entry = lock["packages"].pop("node_modules/vitest")
        lock["packages"]["../node_modules/vitest"] = entry
        with self.assertRaisesRegex(RuntimeError, "LOCK_PATH_INVALID"):
            self.validate(package, lock, npmrc)

    def test_requires_each_direct_dependency_lock_entry(self) -> None:
        package, lock, npmrc = fixture()
        lock["packages"].pop("node_modules/vitest")
        with self.assertRaisesRegex(RuntimeError, "DIRECT_LOCK_ENTRY_INVALID:vitest"):
            self.validate(package, lock, npmrc)

    def test_rejects_unreviewed_install_script(self) -> None:
        package, lock, npmrc = fixture()
        package["allowScripts"] = {"fsevents": False}
        with self.assertRaisesRegex(RuntimeError, "SCRIPT_UNREVIEWED:esbuild@0.25.12"):
            self.validate(package, lock, npmrc)

    def test_rejects_unpinned_optional_dependency(self) -> None:
        package, lock, npmrc = fixture()
        package["optionalDependencies"] = {"optional-package": "^1.0.0"}
        lock["packages"][""]["optionalDependencies"] = {"optional-package": "^1.0.0"}
        with self.assertRaisesRegex(RuntimeError, "DIRECT_DEPENDENCY_NOT_PINNED"):
            self.validate(package, lock, npmrc)

    def test_rejects_unpinned_positive_approval(self) -> None:
        package, lock, npmrc = fixture()
        package["allowScripts"] = {"esbuild": True, "fsevents": False}
        with self.assertRaisesRegex(RuntimeError, "SCRIPT_APPROVAL_NOT_PINNED:esbuild"):
            self.validate(package, lock, npmrc)

    def test_requires_strict_script_enforcement(self) -> None:
        package, lock, _ = fixture()
        with self.assertRaisesRegex(RuntimeError, "STRICT_SCRIPTS_REQUIRED"):
            self.validate(package, lock, "strict-allow-scripts=false\n")

    def test_rejects_project_install_lifecycle_scripts(self) -> None:
        package, lock, npmrc = fixture()
        package["scripts"] = {"postinstall": "node install.js"}
        with self.assertRaisesRegex(RuntimeError, "ROOT_INSTALL_SCRIPT_FORBIDDEN"):
            self.validate(package, lock, npmrc)


if __name__ == "__main__":
    unittest.main()
