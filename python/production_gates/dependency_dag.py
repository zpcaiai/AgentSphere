"""Strict validation for the cross-batch dependency graph snapshots."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Iterable

import yaml


class DependencyDagError(RuntimeError):
    """A stable, fail-closed dependency graph validation error."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise DependencyDagError(f"DEPENDENCY_DAG_DUPLICATE_KEY:{key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


EXPECTED_BATCHES = tuple(f"{value:02d}" for value in range(1, 37))
EDGE_KINDS = ("contracts", "implementation", "runtime", "optional")
ROOT_KEYS = {"version", "edge_semantics", "batches"}
BATCH_KEYS = {"skill", *EDGE_KINDS}
SKILL_NAME = re.compile(r"agent-trust-[a-z0-9-]{1,96}\Z")


@dataclass(frozen=True)
class ValidatedDag:
    version: str
    batches: dict[str, dict[str, object]]
    build_order: tuple[str, ...]


def _secure_text(path: Path, maximum_bytes: int = 2 * 1024 * 1024) -> str:
    if path.is_symlink() or not path.is_file():
        raise DependencyDagError(f"DEPENDENCY_DAG_FILE_INVALID:{path}")
    metadata = path.stat(follow_symlinks=False)
    if not 1 <= metadata.st_size <= maximum_bytes:
        raise DependencyDagError(f"DEPENDENCY_DAG_FILE_INVALID:{path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise DependencyDagError(f"DEPENDENCY_DAG_FILE_INVALID:{path}") from error


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.load(_secure_text(path), Loader=_UniqueKeyLoader)
    except DependencyDagError:
        raise
    except yaml.YAMLError as error:
        raise DependencyDagError(f"DEPENDENCY_DAG_YAML_INVALID:{path}") from error
    if not isinstance(value, dict):
        raise DependencyDagError(f"DEPENDENCY_DAG_DOCUMENT_INVALID:{path}")
    return value


def _require_string_list(value: object, code: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise DependencyDagError(code)
    if len(value) != len(set(value)):
        raise DependencyDagError(code)
    return value


def _topological_order(
    batches: dict[str, dict[str, object]],
    edge_kinds: Iterable[str],
) -> tuple[str, ...]:
    dependencies: dict[str, set[str]] = {}
    dependents: dict[str, set[str]] = {batch: set() for batch in batches}
    for batch, record in batches.items():
        current: set[str] = set()
        for edge_kind in edge_kinds:
            current.update(record[edge_kind])  # type: ignore[arg-type]
        dependencies[batch] = current
        for dependency in current:
            dependents[dependency].add(batch)

    ready = deque(sorted(batch for batch, deps in dependencies.items() if not deps))
    order: list[str] = []
    while ready:
        batch = ready.popleft()
        order.append(batch)
        for dependent in sorted(dependents[batch]):
            dependencies[dependent].discard(batch)
            if not dependencies[dependent] and dependent not in order and dependent not in ready:
                ready.append(dependent)
    if len(order) != len(batches):
        cycle_members = sorted(batch for batch, deps in dependencies.items() if deps)
        raise DependencyDagError(
            "DEPENDENCY_DAG_BUILD_CYCLE:" + ",".join(cycle_members)
        )
    return tuple(order)


def validate_dag(path: Path) -> ValidatedDag:
    document = _load_yaml(path)
    if set(document) != ROOT_KEYS or document.get("version") != "2.0.0":
        raise DependencyDagError(f"DEPENDENCY_DAG_ROOT_INVALID:{path}")
    semantics = document.get("edge_semantics")
    if not isinstance(semantics, dict) or set(semantics) != set(EDGE_KINDS):
        raise DependencyDagError(f"DEPENDENCY_DAG_EDGE_SEMANTICS_INVALID:{path}")
    if any(not isinstance(semantics[kind], str) or not semantics[kind].strip() for kind in EDGE_KINDS):
        raise DependencyDagError(f"DEPENDENCY_DAG_EDGE_SEMANTICS_INVALID:{path}")

    raw_batches = document.get("batches")
    if not isinstance(raw_batches, dict) or tuple(sorted(raw_batches)) != EXPECTED_BATCHES:
        raise DependencyDagError(f"DEPENDENCY_DAG_BATCH_SET_INVALID:{path}")
    batches: dict[str, dict[str, object]] = {}
    for batch in EXPECTED_BATCHES:
        raw = raw_batches[batch]
        if not isinstance(raw, dict) or set(raw) != BATCH_KEYS:
            raise DependencyDagError(f"DEPENDENCY_DAG_BATCH_INVALID:{batch}")
        skill = raw.get("skill")
        if not isinstance(skill, str) or SKILL_NAME.fullmatch(skill) is None:
            raise DependencyDagError(f"DEPENDENCY_DAG_SKILL_INVALID:{batch}")
        record: dict[str, object] = {"skill": skill}
        for edge_kind in EDGE_KINDS:
            references = _require_string_list(
                raw.get(edge_kind), f"DEPENDENCY_DAG_EDGE_INVALID:{batch}:{edge_kind}"
            )
            if any(reference not in raw_batches or reference == batch for reference in references):
                raise DependencyDagError(
                    f"DEPENDENCY_DAG_EDGE_INVALID:{batch}:{edge_kind}"
                )
            record[edge_kind] = references
        batches[batch] = record

    build_order = _topological_order(batches, ("contracts", "implementation"))
    return ValidatedDag(version="2.0.0", batches=batches, build_order=build_order)


def _skill_front_matter(path: Path) -> dict[str, Any]:
    text = _secure_text(path)
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise DependencyDagError(f"DEPENDENCY_DAG_SKILL_METADATA_INVALID:{path}")
    payload = text[4 : text.index("\n---\n", 4)]
    try:
        value = yaml.load(payload, Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, DependencyDagError) as error:
        raise DependencyDagError(
            f"DEPENDENCY_DAG_SKILL_METADATA_INVALID:{path}"
        ) from error
    if not isinstance(value, dict):
        raise DependencyDagError(f"DEPENDENCY_DAG_SKILL_METADATA_INVALID:{path}")
    return value


def validate_repository_dags(repository: Path) -> tuple[ValidatedDag, tuple[Path, ...]]:
    roots = tuple(
        repository / "skills" / f"agent-trust-control-plane-batches-{start:02d}-{end:02d}-v2"
        for start, end in ((1, 9), (10, 18), (19, 27), (28, 36))
    )
    paths = tuple(root / "DEPENDENCY_DAG.yaml" for root in roots)
    validated = tuple(validate_dag(path) for path in paths)
    baseline = validated[0]
    for path, candidate in zip(paths[1:], validated[1:], strict=True):
        if candidate != baseline:
            raise DependencyDagError(f"DEPENDENCY_DAG_SNAPSHOT_DRIFT:{path}")

    discovered: dict[str, Path] = {}
    for root in roots:
        for skill_path in sorted((root / ".agents" / "skills").glob("*/SKILL.md")):
            metadata = _skill_front_matter(skill_path)
            name = metadata.get("name")
            batch = metadata.get("metadata", {}).get("batch") if isinstance(metadata.get("metadata"), dict) else None
            if not isinstance(name, str) or not isinstance(batch, str):
                raise DependencyDagError(
                    f"DEPENDENCY_DAG_SKILL_METADATA_INVALID:{skill_path}"
                )
            if batch in discovered:
                raise DependencyDagError(f"DEPENDENCY_DAG_DUPLICATE_BATCH_SKILL:{batch}")
            if batch not in baseline.batches or baseline.batches[batch]["skill"] != name:
                raise DependencyDagError(f"DEPENDENCY_DAG_SKILL_MISMATCH:{batch}:{name}")
            discovered[batch] = skill_path
    if tuple(sorted(discovered)) != EXPECTED_BATCHES:
        raise DependencyDagError("DEPENDENCY_DAG_SKILL_SET_INVALID")
    return baseline, paths
