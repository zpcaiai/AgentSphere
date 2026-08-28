"""Deterministic release-revision isolation for the production Kubernetes stack."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import yaml


_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_VERSIONED_KINDS = {"ConfigMap", "Deployment", "PodDisruptionBudget", "SecretProviderClass"}


class BlueGreenStackError(RuntimeError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: object) -> bool:
        return True


def _mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[object, object]:
    value: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in value:
            raise BlueGreenStackError("BLUE_GREEN_STACK_DUPLICATE_YAML_KEY")
        value[key] = loader.construct_object(value_node, deep=True)
    return value


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _mapping,
)


def release_revision(release_id: str, release_digest: str) -> str:
    if _RELEASE_ID.fullmatch(release_id) is None or _DIGEST.fullmatch(release_digest) is None:
        raise BlueGreenStackError("BLUE_GREEN_STACK_RELEASE_INVALID")
    git_digest = release_id.rsplit(":", 1)[1]
    return f"r-{git_digest[:12]}-{release_digest[:8]}"


def _versioned_name(name: object, revision: str) -> str:
    if not isinstance(name, str) or _DNS_LABEL.fullmatch(name) is None:
        raise BlueGreenStackError("BLUE_GREEN_STACK_RESOURCE_NAME_INVALID")
    maximum_base = 63 - len(revision) - 1
    base = name[:maximum_base].rstrip("-")
    value = f"{base}-{revision}"
    if not base or _DNS_LABEL.fullmatch(value) is None:
        raise BlueGreenStackError("BLUE_GREEN_STACK_RESOURCE_NAME_INVALID")
    return value


def _metadata(document: dict[str, Any]) -> dict[str, Any]:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise BlueGreenStackError("BLUE_GREEN_STACK_METADATA_INVALID")
    labels = metadata.setdefault("labels", {})
    if not isinstance(labels, dict):
        raise BlueGreenStackError("BLUE_GREEN_STACK_LABELS_INVALID")
    return metadata


def _add_revision_to_selector(value: object, revision: str) -> None:
    if not isinstance(value, dict):
        raise BlueGreenStackError("BLUE_GREEN_STACK_SELECTOR_INVALID")
    labels = value.setdefault("matchLabels", {})
    if not isinstance(labels, dict):
        raise BlueGreenStackError("BLUE_GREEN_STACK_SELECTOR_INVALID")
    labels["agenttrust.io/revision"] = revision


def _rewrite_pod_references(
    value: object,
    *,
    config_maps: dict[str, str],
    secret_providers: dict[str, str],
    deployments: dict[str, str],
    revision: str,
) -> None:
    if isinstance(value, list):
        for item in value:
            _rewrite_pod_references(
                item,
                config_maps=config_maps,
                secret_providers=secret_providers,
                deployments=deployments,
                revision=revision,
            )
        return
    if not isinstance(value, dict):
        return
    config_map = value.get("configMap")
    if isinstance(config_map, dict) and isinstance(config_map.get("name"), str):
        name = config_map["name"]
        if name in config_maps:
            config_map["name"] = config_maps[name]
    config_map_ref = value.get("configMapRef")
    if isinstance(config_map_ref, dict) and isinstance(config_map_ref.get("name"), str):
        name = config_map_ref["name"]
        if name in config_maps:
            config_map_ref["name"] = config_maps[name]
    attributes = value.get("volumeAttributes")
    if isinstance(attributes, dict):
        provider = attributes.get("secretProviderClass")
        if isinstance(provider, str) and provider in secret_providers:
            attributes["secretProviderClass"] = secret_providers[provider]
    target = value.get("scaleTargetRef")
    if isinstance(target, dict) and isinstance(target.get("name"), str):
        name = target["name"]
        if name in deployments:
            target["name"] = deployments[name]
    label_selector = value.get("labelSelector")
    if isinstance(label_selector, dict):
        _add_revision_to_selector(label_selector, revision)
    for child in value.values():
        _rewrite_pod_references(
            child,
            config_maps=config_maps,
            secret_providers=secret_providers,
            deployments=deployments,
            revision=revision,
        )


def materialize_blue_green_stack(
    source: str,
    *,
    release_id: str,
    release_digest: str,
) -> tuple[str, dict[str, object]]:
    revision = release_revision(release_id, release_digest)
    try:
        documents = [
            item for item in yaml.load_all(source, Loader=_UniqueKeyLoader) if item is not None
        ]
    except BlueGreenStackError:
        raise
    except yaml.YAMLError as error:
        raise BlueGreenStackError("BLUE_GREEN_STACK_YAML_INVALID") from error
    if not documents or any(not isinstance(item, dict) for item in documents):
        raise BlueGreenStackError("BLUE_GREEN_STACK_DOCUMENT_INVALID")

    maps: dict[str, dict[str, str]] = {
        "ConfigMap": {},
        "Deployment": {},
        "PodDisruptionBudget": {},
        "SecretProviderClass": {},
    }
    seen_resources: set[tuple[str, str]] = set()
    for document in documents:
        kind = document.get("kind")
        metadata = _metadata(document)
        name = metadata.get("name")
        if not isinstance(kind, str) or not isinstance(name, str):
            raise BlueGreenStackError("BLUE_GREEN_STACK_RESOURCE_INVALID")
        resource = (kind, name)
        if resource in seen_resources:
            raise BlueGreenStackError("BLUE_GREEN_STACK_RESOURCE_DUPLICATE")
        seen_resources.add(resource)
        if kind in _VERSIONED_KINDS:
            maps[kind][name] = _versioned_name(name, revision)

    for kind, names in maps.items():
        if len(names.values()) != len(set(names.values())):
            raise BlueGreenStackError(f"BLUE_GREEN_STACK_{kind.upper()}_NAME_COLLISION")

    traffic_services: list[str] = []
    workload_deployments: list[str] = []
    for document in documents:
        kind = document["kind"]
        metadata = _metadata(document)
        labels = metadata["labels"]
        original_name = metadata["name"]
        if kind in _VERSIONED_KINDS:
            metadata["name"] = maps[kind][original_name]
            labels["agenttrust.io/revision"] = revision
            labels["agenttrust.io/release-id"] = release_id
        if kind == "Deployment":
            workload_deployments.append(metadata["name"])
            spec = document.get("spec")
            if not isinstance(spec, dict):
                raise BlueGreenStackError("BLUE_GREEN_STACK_DEPLOYMENT_INVALID")
            _add_revision_to_selector(spec.get("selector"), revision)
            template = spec.get("template")
            template_metadata = template.get("metadata") if isinstance(template, dict) else None
            if not isinstance(template_metadata, dict):
                raise BlueGreenStackError("BLUE_GREEN_STACK_DEPLOYMENT_INVALID")
            pod_labels = template_metadata.setdefault("labels", {})
            if not isinstance(pod_labels, dict):
                raise BlueGreenStackError("BLUE_GREEN_STACK_DEPLOYMENT_INVALID")
            pod_labels["agenttrust.io/revision"] = revision
            pod_labels["agenttrust.io/release-id"] = release_id
            _rewrite_pod_references(
                spec,
                config_maps=maps["ConfigMap"],
                secret_providers=maps["SecretProviderClass"],
                deployments=maps["Deployment"],
                revision=revision,
            )
        elif kind == "PodDisruptionBudget":
            spec = document.get("spec")
            if not isinstance(spec, dict):
                raise BlueGreenStackError("BLUE_GREEN_STACK_PDB_INVALID")
            _add_revision_to_selector(spec.get("selector"), revision)
        elif kind == "Service":
            spec = document.get("spec")
            selector = spec.get("selector") if isinstance(spec, dict) else None
            if selector is not None:
                if not isinstance(selector, dict) or not selector:
                    raise BlueGreenStackError("BLUE_GREEN_STACK_SERVICE_SELECTOR_INVALID")
                selector["agenttrust.io/revision"] = revision
                labels["agenttrust.io/apply-phase"] = "traffic"
                labels["agenttrust.io/traffic-target-revision"] = revision
                traffic_services.append(original_name)
        else:
            _rewrite_pod_references(
                document,
                config_maps=maps["ConfigMap"],
                secret_providers=maps["SecretProviderClass"],
                deployments=maps["Deployment"],
                revision=revision,
            )

    if not traffic_services or not workload_deployments:
        raise BlueGreenStackError("BLUE_GREEN_STACK_WORKLOAD_SET_EMPTY")
    rendered = yaml.dump_all(
        documents,
        Dumper=_NoAliasDumper,
        explicit_start=True,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=False,
        width=120,
    )
    material = {
        "schema_version": "agenttrust.production-blue-green-stack-plan.v1",
        "release_id": release_id,
        "release_digest": release_digest,
        "revision": revision,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "rendered_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "versioned_resources": {
            kind: dict(sorted(names.items())) for kind, names in sorted(maps.items())
        },
        "traffic_services": sorted(traffic_services),
        "workload_deployments": sorted(workload_deployments),
    }
    return rendered, material
