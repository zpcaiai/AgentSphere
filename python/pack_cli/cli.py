"""Batch 28 Domain Pack CLI with conservative, deterministic defaults."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Sequence


_NAME = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
_EFFECTS = {"READ", "WRITE_REVERSIBLE", "WRITE_IRREVERSIBLE", "PHYSICAL"}


def scaffold(root: Path, name: str, publisher: str) -> list[Path]:
    if not _NAME.fullmatch(name) or not publisher.strip():
        raise ValueError("PACK_SCAFFOLD_INPUT_INVALID")
    target = root.resolve() / name
    resolved_root = root.resolve()
    if target.parent != resolved_root or target.exists():
        raise ValueError("PACK_SCAFFOLD_TARGET_INVALID")
    target.mkdir(parents=True)
    (target / "policies").mkdir()
    (target / "tests").mkdir()
    manifest = {
        "schema_version": "agenttrust.domain-pack.v1",
        "name": name,
        "version": "0.1.0",
        "publisher": publisher,
        "minimum_control_plane_version": "0.1.0",
        "permissions": [],
        "network_destinations": [],
        "data_classes": [],
        "tools": [],
        "production_activation": {
            "requires_signature": True,
            "requires_sbom": True,
            "requires_approval": True,
            "requires_release_certificate": True,
        },
        "arbitrary_code_execution": False,
    }
    files = [
        target / "pack.json",
        target / "policies" / "default-deny.rego",
        target / "tests" / "test_manifest.py",
        target / "README.md",
    ]
    files[0].write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files[1].write_text(
        "package agenttrust.pack\n\ndefault allow := false\n\n# Add narrow, reviewed rules only.\n",
        encoding="utf-8",
    )
    files[2].write_text(
        "import json\nfrom pathlib import Path\n\ndef test_manifest_is_default_deny():\n"
        "    value = json.loads((Path(__file__).parents[1] / 'pack.json').read_text())\n"
        "    assert value['arbitrary_code_execution'] is False\n"
        "    assert value['permissions'] == []\n",
        encoding="utf-8",
    )
    files[3].write_text(
        f"# {name}\n\nGenerated with fail-closed permissions. Review, sign, scan, and approve before activation.\n",
        encoding="utf-8",
    )
    return files


def verify_manifest(path: Path) -> str:
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("PACK_MANIFEST_INVALID") from error
    required = {
        "schema_version",
        "name",
        "version",
        "publisher",
        "minimum_control_plane_version",
        "permissions",
        "network_destinations",
        "data_classes",
        "tools",
        "production_activation",
        "arbitrary_code_execution",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value["schema_version"] != "agenttrust.domain-pack.v1"
        or not _NAME.fullmatch(str(value["name"]))
        or value["arbitrary_code_execution"] is not False
        or not all(isinstance(value[field], list) for field in ("permissions", "network_destinations", "data_classes", "tools"))
    ):
        raise ValueError("PACK_MANIFEST_INVALID")
    activation = value["production_activation"]
    if not isinstance(activation, dict) or not all(
        activation.get(field) is True
        for field in (
            "requires_signature",
            "requires_sbom",
            "requires_approval",
            "requires_release_certificate",
        )
    ):
        raise ValueError("PACK_PRODUCTION_GATES_MISSING")
    for tool in value["tools"]:
        if (
            not isinstance(tool, dict)
            or tool.get("effect_class") not in _EFFECTS
            or not isinstance(tool.get("timeout_seconds"), int)
            or not 1 <= tool["timeout_seconds"] <= 3600
            or tool.get("effect_class") != "READ" and not tool.get("compensation")
        ):
            raise ValueError("PACK_TOOL_INVALID")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-pack")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("new")
    create.add_argument("name")
    create.add_argument("--publisher", required=True)
    create.add_argument("--root", type=Path, default=Path.cwd())
    verify = commands.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    if args.command == "new":
        for generated in scaffold(args.root, args.name, args.publisher):
            print(generated)
    else:
        print(verify_manifest(args.manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
