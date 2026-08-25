#!/usr/bin/env python3
"""Validate the control-console npm lock and install-script policy offline."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "web/control-console"
EXACT_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
NPM_PACKAGE_NAME = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$"
)
SHA512 = re.compile(r"^sha512-([A-Za-z0-9+/]+={0,2})$")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_DUPLICATE_KEY:{key}")
        value[key] = item
    return value


def _load_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_JSON_INVALID:{path.name}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_OBJECT_REQUIRED:{path.name}")
    return value


def _package_name(lock_path: str) -> str:
    marker = "node_modules/"
    normalized = PurePosixPath(lock_path)
    if (
        marker not in lock_path
        or normalized.is_absolute()
        or normalized.as_posix() != lock_path
        or "." in normalized.parts
        or ".." in normalized.parts
        or "\\" in lock_path
    ):
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_LOCK_PATH_INVALID:{lock_path}")
    name = lock_path.rsplit(marker, 1)[1]
    if not name or name.startswith("/") or name.endswith("/"):
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_LOCK_PATH_INVALID:{lock_path}")
    if name.startswith("@"):
        parts = name.split("/")
        if len(parts) != 2 or not all(parts):
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_LOCK_PATH_INVALID:{lock_path}")
    elif "/" in name:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_LOCK_PATH_INVALID:{lock_path}")
    return name


def _validate_registry_entry(
    lock_path: str, lock_name: str, version: str, entry: dict[str, object]
) -> str:
    resolved = entry.get("resolved")
    integrity = entry.get("integrity")
    resolved_name = entry.get("name", lock_name)
    if not isinstance(resolved, str) or not isinstance(integrity, str):
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_LOCK_PROVENANCE_MISSING:{lock_path}")
    if not isinstance(resolved_name, str) or NPM_PACKAGE_NAME.fullmatch(resolved_name) is None:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_RESOLVED_IDENTITY_INVALID:{lock_path}")
    try:
        parsed = urlsplit(resolved)
        port = parsed.port
    except ValueError as error:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_REGISTRY_NOT_APPROVED:{lock_path}") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_REGISTRY_NOT_APPROVED:{lock_path}")
    archive_name = resolved_name.rsplit("/", 1)[-1]
    expected_path = f"/{resolved_name}/-/{archive_name}-{version}.tgz"
    if parsed.path != expected_path:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_TARBALL_IDENTITY_MISMATCH:{lock_path}")
    match = SHA512.fullmatch(integrity)
    if match is None:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_SHA512_REQUIRED:{lock_path}")
    try:
        digest = base64.b64decode(match.group(1), validate=True)
    except (ValueError, binascii.Error) as error:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_SHA512_INVALID:{lock_path}") from error
    if len(digest) != 64:
        raise RuntimeError(f"NODE_SUPPLY_CHAIN_SHA512_INVALID:{lock_path}")
    return resolved_name


def _validate_npmrc(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RuntimeError("NODE_SUPPLY_CHAIN_NPMRC_MISSING") from error
    settings: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, separator, value = line.partition("=")
        key = key.strip().lower()
        if not separator or not key or key in settings:
            raise RuntimeError("NODE_SUPPLY_CHAIN_NPMRC_INVALID")
        settings[key] = value.strip().lower()
    if settings.get("strict-allow-scripts") != "true":
        raise RuntimeError("NODE_SUPPLY_CHAIN_STRICT_SCRIPTS_REQUIRED")
    if settings.get("dangerously-allow-all-scripts") == "true":
        raise RuntimeError("NODE_SUPPLY_CHAIN_ALL_SCRIPTS_FORBIDDEN")
    if "allow-scripts" in settings or settings.get("ignore-scripts") == "true":
        raise RuntimeError("NODE_SUPPLY_CHAIN_SCRIPT_POLICY_BYPASS")


def validate(package_path: Path, lock_path: Path, npmrc_path: Path) -> tuple[int, int]:
    package = _load_object(package_path)
    lock = _load_object(lock_path)
    packages = lock.get("packages")
    root = packages.get("") if isinstance(packages, dict) else None
    if (
        lock.get("lockfileVersion") != 3
        or lock.get("requires") is not True
        or not isinstance(packages, dict)
        or not isinstance(root, dict)
        or root.get("name") != package.get("name")
        or root.get("version") != package.get("version")
    ):
        raise RuntimeError("NODE_SUPPLY_CHAIN_LOCK_ROOT_INVALID")
    package_manager = package.get("packageManager")
    engines = package.get("engines")
    if (
        not isinstance(package_manager, str)
        or not package_manager.startswith("npm@")
        or EXACT_VERSION.fullmatch(package_manager.removeprefix("npm@")) is None
        or not isinstance(engines, dict)
        or set(engines) != {"node", "npm"}
        or any(
            not isinstance(version, str) or EXACT_VERSION.fullmatch(version) is None
            for version in engines.values()
        )
        or engines.get("npm") != package_manager.removeprefix("npm@")
        or root.get("engines") != engines
    ):
        raise RuntimeError("NODE_SUPPLY_CHAIN_TOOLCHAIN_NOT_PINNED")
    direct_dependencies: dict[str, str] = {}
    for group in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        declared = package.get(group, {})
        locked = root.get(group, {})
        if not isinstance(declared, dict) or declared != locked:
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_DIRECT_DEPENDENCY_DRIFT:{group}")
        if any(
            not isinstance(name, str)
            or NPM_PACKAGE_NAME.fullmatch(name) is None
            or not isinstance(version, str)
            or EXACT_VERSION.fullmatch(version) is None
            for name, version in declared.items()
        ):
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_DIRECT_DEPENDENCY_NOT_PINNED:{group}")
        for name, version in declared.items():
            existing = direct_dependencies.get(name)
            if existing is not None and existing != version:
                raise RuntimeError(f"NODE_SUPPLY_CHAIN_DIRECT_DEPENDENCY_CONFLICT:{name}")
            direct_dependencies[name] = version
    scripts = package.get("scripts", {})
    if not isinstance(scripts, dict):
        raise RuntimeError("NODE_SUPPLY_CHAIN_ROOT_SCRIPTS_INVALID")
    install_lifecycle = {"preinstall", "install", "postinstall", "prepare"}
    if install_lifecycle.intersection(scripts):
        raise RuntimeError("NODE_SUPPLY_CHAIN_ROOT_INSTALL_SCRIPT_FORBIDDEN")
    if package.get("bundledDependencies") or package.get("bundleDependencies"):
        raise RuntimeError("NODE_SUPPLY_CHAIN_BUNDLED_DEPENDENCIES_FORBIDDEN")

    install_names: set[str] = set()
    install_versions: dict[str, str] = {}
    registry_entries = 0
    for lock_path_name, raw_entry in packages.items():
        if lock_path_name == "":
            continue
        if not isinstance(lock_path_name, str) or not isinstance(raw_entry, dict):
            raise RuntimeError("NODE_SUPPLY_CHAIN_LOCK_ENTRY_INVALID")
        name = _package_name(lock_path_name)
        version = raw_entry.get("version")
        if not isinstance(version, str) or EXACT_VERSION.fullmatch(version) is None:
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_TRANSITIVE_VERSION_INVALID:{lock_path_name}")
        resolved_name = _validate_registry_entry(lock_path_name, name, version, raw_entry)
        registry_entries += 1
        if "hasInstallScript" in raw_entry and not isinstance(
            raw_entry["hasInstallScript"], bool
        ):
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_INSTALL_SCRIPT_FLAG_INVALID:{lock_path_name}")
        if raw_entry.get("hasInstallScript") is True:
            identifier = f"{resolved_name}@{version}"
            install_names.add(resolved_name)
            install_versions[identifier] = resolved_name

    for name, version in direct_dependencies.items():
        entry = packages.get(f"node_modules/{name}")
        if (
            not isinstance(entry, dict)
            or entry.get("version") != version
            or entry.get("name", name) != name
        ):
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_DIRECT_LOCK_ENTRY_INVALID:{name}")

    allow_scripts = package.get("allowScripts")
    if not isinstance(allow_scripts, dict) or not allow_scripts:
        raise RuntimeError("NODE_SUPPLY_CHAIN_SCRIPT_POLICY_MISSING")
    for selector, allowed in allow_scripts.items():
        if not isinstance(selector, str) or not isinstance(allowed, bool):
            raise RuntimeError("NODE_SUPPLY_CHAIN_SCRIPT_POLICY_INVALID")
        if allowed is True:
            if selector not in install_versions:
                raise RuntimeError(f"NODE_SUPPLY_CHAIN_SCRIPT_APPROVAL_NOT_PINNED:{selector}")
            if allow_scripts.get(install_versions[selector]) is False:
                raise RuntimeError(f"NODE_SUPPLY_CHAIN_SCRIPT_POLICY_CONFLICT:{selector}")
        elif selector not in install_names:
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_SCRIPT_DENIAL_UNUSED:{selector}")
    for identifier, name in install_versions.items():
        if allow_scripts.get(identifier) is not True and allow_scripts.get(name) is not False:
            raise RuntimeError(f"NODE_SUPPLY_CHAIN_SCRIPT_UNREVIEWED:{identifier}")

    _validate_npmrc(npmrc_path)
    return registry_entries, len(install_versions)


def main() -> int:
    packages, scripts = validate(
        CONSOLE / "package.json",
        CONSOLE / "package-lock.json",
        CONSOLE / ".npmrc",
    )
    print(
        f"validated {packages} checksum-locked npm packages and "
        f"{scripts} install-script entries"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
