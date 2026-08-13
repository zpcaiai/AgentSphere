#!/usr/bin/env python3
"""Generate dependency-free contract types for Rust, Python, Java, and TypeScript."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "schemas" / "contract-model.json"


def header(comment: str, digest: str) -> str:
    return f"{comment} GENERATED from schemas/contract-model.json; source_sha256={digest}; run ./scripts/generate-contracts.sh\n"


def pascal(value: str) -> str:
    return "".join(part.capitalize() for part in value.lower().split("_"))


def mapped(kind: str, lang: str) -> str:
    list_inner = kind[5:-1] if kind.startswith("list<") else None
    optional_inner = kind[9:-1] if kind.startswith("optional<") else None
    map_inner = kind[4:-1] if kind.startswith("map<") else None
    map_parts = map_inner.split(",", 1) if map_inner else None
    if lang == "rust":
        if list_inner:
            return f"Vec<{mapped(list_inner, lang)}>"
        if optional_inner:
            return f"Option<{mapped(optional_inner, lang)}>"
        if map_parts:
            return f"std::collections::BTreeMap<{mapped(map_parts[0], lang)}, {mapped(map_parts[1], lang)}>"
        return {
            "string": "String",
            "datetime": "String",
            "uint32": "u32",
            "uint64": "u64",
            "bool": "bool",
        }.get(kind, kind)
    if lang == "python":
        if list_inner:
            return f"list[{mapped(list_inner, lang)}]"
        if optional_inner:
            return f"{mapped(optional_inner, lang)} | None"
        if map_parts:
            return f"dict[{mapped(map_parts[0], lang)}, {mapped(map_parts[1], lang)}]"
        return {
            "string": "str",
            "datetime": "str",
            "uint32": "int",
            "uint64": "int",
            "bool": "bool",
        }.get(kind, kind)
    if lang == "java":
        if list_inner:
            return f"java.util.List<{mapped(list_inner, lang)}>"
        if optional_inner:
            return f"java.util.Optional<{mapped(optional_inner, lang)}>"
        if map_parts:
            return f"java.util.Map<{mapped(map_parts[0], lang)}, {mapped(map_parts[1], lang)}>"
        return {
            "string": "String",
            "datetime": "String",
            "uint32": "int",
            "uint64": "long",
            "bool": "boolean",
        }.get(kind, kind)
    if list_inner:
        return f"Array<{mapped(list_inner, lang)}>"
    if optional_inner:
        return f"{mapped(optional_inner, lang)} | null"
    if map_parts:
        return f"Readonly<Record<{mapped(map_parts[0], lang)}, {mapped(map_parts[1], lang)}>>"
    return {
        "string": "string",
        "datetime": "string",
        "uint32": "number",
        "uint64": "number",
        "bool": "boolean",
    }.get(kind, kind)


def render_rust(model: dict, digest: str) -> str:
    out = [header("//", digest)]
    for name, values in model["enums"].items():
        out += ["#[derive(Debug, Clone, Copy, PartialEq, Eq)]", f"pub enum {name} {{ " + ", ".join(pascal(v) for v in values) + " }", ""]
    for name, fields in model["records"].items():
        out += ["#[derive(Debug, Clone, PartialEq, Eq)]", f"pub struct {name} {{"]
        out += [f"    pub {field}: {mapped(kind, 'rust')}," for field, kind in fields.items()]
        out += ["}", ""]
    return "\n".join(out)


def render_python(model: dict, digest: str) -> str:
    out = [header("#", digest), "from dataclasses import dataclass", "from enum import Enum", ""]
    for name, values in model["enums"].items():
        out += [f"class {name}(str, Enum):"] + [f"    {value} = {value!r}" for value in values] + [""]
    for name, fields in model["records"].items():
        out += ["@dataclass(frozen=True, slots=True)", f"class {name}:"] + [f"    {field}: {mapped(kind, 'python')}" for field, kind in fields.items()] + [""]
    return "\n".join(out)


def render_java(model: dict, digest: str) -> str:
    out = [header("//", digest), "package com.agenttrust.v1;", "", "public final class Contracts {", "  private Contracts() {}"]
    for name, values in model["enums"].items():
        out.append(f"  public enum {name} {{ " + ", ".join(values) + " }")
    for name, fields in model["records"].items():
        params = ", ".join(f"{mapped(kind, 'java')} {field}" for field, kind in fields.items())
        out.append(f"  public record {name}({params}) {{}}")
    out += ["}", ""]
    return "\n".join(out)


def render_ts(model: dict, digest: str) -> str:
    out = [header("//", digest)]
    for name, values in model["enums"].items():
        out += [f"export type {name} = " + " | ".join(json.dumps(v) for v in values) + ";", ""]
    for name, fields in model["records"].items():
        out += [f"export interface {name} {{"] + [f"  readonly {field}: {mapped(kind, 'ts')};" for field, kind in fields.items()] + ["}", ""]
    return "\n".join(out)


def outputs() -> dict[Path, str]:
    raw = SOURCE.read_bytes()
    model = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    return {
        ROOT / "generated/rust/contracts.rs": render_rust(model, digest),
        ROOT / "generated/python/contracts.py": render_python(model, digest),
        ROOT / "generated/java/src/main/java/com/agenttrust/v1/Contracts.java": render_java(model, digest),
        ROOT / "generated/typescript/contracts.ts": render_ts(model, digest),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for path, content in outputs().items():
        if args.check:
            if not path.exists() or path.read_text() != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if stale:
        print("stale generated files: " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
