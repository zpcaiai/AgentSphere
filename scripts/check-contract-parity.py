#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source_path = ROOT / "schemas/contract-model.json"
source = json.loads(source_path.read_text())
digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
outputs = [
    ROOT / "generated/rust/contracts.rs",
    ROOT / "generated/python/contracts.py",
    ROOT / "generated/java/src/main/java/com/agenttrust/v1/Contracts.java",
    ROOT / "generated/typescript/contracts.ts",
]
for output in outputs:
    text = output.read_text()
    assert f"source_sha256={digest}" in text, output
    for enum, values in source["enums"].items():
        assert enum in text, (output, enum)
        for value in values:
            assert value in text or "".join(part.capitalize() for part in value.lower().split("_")) in text, (output, value)

transitions = json.loads((ROOT / "schemas/state-machines/task-transitions.yaml").read_text())
assert transitions["terminal_writer"] == "durable-orchestrator-transition-service"
assert ["VERIFYING", "COMPLETED"] in transitions["transitions"]
for schema_path in sorted((ROOT / "schemas/json").glob("*.schema.json")):
    schema = json.loads(schema_path.read_text())
    assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", schema_path
    if schema.get("type") == "object":
        assert schema.get("additionalProperties") is False, schema_path
print(f"contract parity OK: {len(outputs)} languages, {len(source['enums'])} enums")

