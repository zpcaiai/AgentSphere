"""Fail-closed production deployment orchestration.

The orchestrator owns only Kubernetes observation/apply ordering.  Database
fencing, traffic switching and write unfreezing are deliberately delegated to
the externally authenticated deployment-cutover broker.  A successful result
therefore always contains the broker's independently signed receipts.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
from typing import Any, Mapping, Sequence

import yaml

from python.production_gates.blue_green_stack import release_revision
from python.production_gates.deployment_cutover_broker import (
    invoke_broker,
    prepare_broker_request,
    read_json,
)
from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError


_RELEASE_ID = re.compile(r"^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_NAMESPACE = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_IDENTIFIER = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")
_PHASES = {"prerequisite", "admission", "migration", "workload", "traffic"}


def _secure_input(path: Path, maximum: int = 64 * 1024 * 1024) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise GateError("PRODUCTION_DEPLOYMENT_INPUT_INVALID") from None
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.resolve() != path
        or not path.is_file()
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        raise GateError("PRODUCTION_DEPLOYMENT_INPUT_INVALID")


def _read_json(path: Path) -> object:
    _secure_input(path, 64 * 1024 * 1024)
    try:
        def _duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON member")
                result[key] = value
            return result
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GateError("PRODUCTION_DEPLOYMENT_JSON_INVALID") from None


def _write_json_new(path: Path, value: object) -> None:
    if (
        not path.is_absolute()
        or path.exists()
        or path.is_symlink()
        or not path.parent.is_dir()
    ):
        raise GateError("PRODUCTION_DEPLOYMENT_OUTPUT_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _documents(path: Path) -> list[dict[str, Any]]:
    _secure_input(path, 64 * 1024 * 1024)
    try:
        values = [item for item in yaml.safe_load_all(path.read_text(encoding="utf-8")) if item]
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        raise GateError("PRODUCTION_DEPLOYMENT_RENDERED_STACK_INVALID") from None
    if not values or any(not isinstance(item, dict) for item in values):
        raise GateError("PRODUCTION_DEPLOYMENT_RENDERED_STACK_INVALID")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        metadata = item.get("metadata")
        labels = metadata.get("labels") if isinstance(metadata, dict) else None
        phase = labels.get("agenttrust.io/apply-phase") if isinstance(labels, dict) else None
        kind = item.get("kind")
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if (
            not isinstance(kind, str)
            or not isinstance(name, str)
            or _IDENTIFIER.fullmatch(name) is None
            or phase not in _PHASES
            or (kind, name) in seen
        ):
            raise GateError("PRODUCTION_DEPLOYMENT_RENDERED_RESOURCE_INVALID")
        seen.add((kind, name))
        result.append(item)
    if not all(any(item["metadata"].get("labels", {}).get("agenttrust.io/apply-phase") == phase for item in result) for phase in _PHASES):
        raise GateError("PRODUCTION_DEPLOYMENT_PHASE_EMPTY")
    return result


def _plan_names(documents: Sequence[Mapping[str, Any]], phase: str, kind: str) -> list[str]:
    values = [
        str(item["metadata"]["name"])
        for item in documents
        if item.get("kind") == kind
        and item.get("metadata", {}).get("labels", {}).get("agenttrust.io/apply-phase") == phase
    ]
    if not values or len(values) != len(set(values)):
        raise GateError("PRODUCTION_DEPLOYMENT_RESOURCE_PLAN_INVALID")
    return sorted(values)


def _run_kubectl(base: Sequence[str], *arguments: str) -> str:
    try:
        result = subprocess.run(
            [*base, *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1_800,
        )
    except (OSError, subprocess.SubprocessError):
        raise GateError("PRODUCTION_DEPLOYMENT_KUBECTL_FAILED") from None
    return result.stdout


def _items(payload: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        raise GateError("PRODUCTION_DEPLOYMENT_CLUSTER_RESPONSE_INVALID") from None
    if isinstance(value, dict) and value.get("kind") == "List" and isinstance(value.get("items"), list):
        values = value["items"]
    elif isinstance(value, dict) and isinstance(value.get("metadata"), dict):
        values = [value]
    else:
        raise GateError("PRODUCTION_DEPLOYMENT_CLUSTER_RESPONSE_INVALID")
    if any(not isinstance(item, dict) for item in values):
        raise GateError("PRODUCTION_DEPLOYMENT_CLUSTER_RESPONSE_INVALID")
    return values


def _discover_source_release(base: Sequence[str], target_release_id: str) -> tuple[str, str]:
    """Find the release currently selected by stable services.

    The first deployment must be bootstrapped by the external deployment
    authority; silently treating an empty cluster as a source would break the
    writer-fence contract, so it is rejected.
    """
    service_items = _items(_run_kubectl(base, "get", "service", "-l", "agenttrust.io/traffic-target-revision", "-o", "json"))
    traffic_revisions: set[str] = set()
    for service in service_items:
        selector = service.get("spec", {}).get("selector")
        if isinstance(selector, dict) and isinstance(selector.get("agenttrust.io/revision"), str):
            traffic_revisions.add(selector["agenttrust.io/revision"])
    if len(traffic_revisions) != 1:
        raise GateError("PRODUCTION_DEPLOYMENT_ACTIVE_SOURCE_NOT_DISCOVERABLE")
    source_revision = next(iter(traffic_revisions))
    deployments = _items(_run_kubectl(base, "get", "deployment", "-l", f"agenttrust.io/revision={source_revision}", "-o", "json"))
    release_ids = {
        item.get("metadata", {}).get("labels", {}).get("agenttrust.io/release-id")
        for item in deployments
    }
    release_ids.discard(target_release_id)
    release_ids = {value for value in release_ids if isinstance(value, str) and _RELEASE_ID.fullmatch(value)}
    if len(release_ids) != 1:
        raise GateError("PRODUCTION_DEPLOYMENT_ACTIVE_SOURCE_NOT_DISCOVERABLE")
    return next(iter(release_ids)), source_revision


def _verify_traffic(base: Sequence[str], services: Sequence[str], target_revision: str) -> None:
    for service in services:
        service_items = _items(_run_kubectl(base, "get", "service", service, "-o", "json"))
        if len(service_items) != 1:
            raise GateError("PRODUCTION_DEPLOYMENT_TRAFFIC_OBSERVATION_INVALID")
        selector = service_items[0].get("spec", {}).get("selector")
        if not isinstance(selector, dict) or selector.get("agenttrust.io/revision") != target_revision:
            raise GateError("PRODUCTION_DEPLOYMENT_TRAFFIC_SELECTOR_MISMATCH")
        endpoint_items = _items(_run_kubectl(base, "get", "endpoints", service, "-o", "json"))
        addresses = []
        for endpoint in endpoint_items:
            for subset in endpoint.get("subsets", []):
                if isinstance(subset, dict):
                    addresses.extend(subset.get("addresses", []))
        if not addresses:
            raise GateError("PRODUCTION_DEPLOYMENT_TRAFFIC_ENDPOINTS_EMPTY")


def _scale_source_to_zero(base: Sequence[str], source_revision: str) -> list[str]:
    items = _items(_run_kubectl(base, "get", "deployment", "-l", f"agenttrust.io/revision={source_revision}", "-o", "json"))
    names = sorted({item.get("metadata", {}).get("name") for item in items if isinstance(item.get("metadata", {}).get("name"), str)})
    if not names:
        raise GateError("PRODUCTION_DEPLOYMENT_SOURCE_WORKLOADS_EMPTY")
    _run_kubectl(base, "scale", "deployment", "--replicas=0", "-l", f"agenttrust.io/revision={source_revision}")
    remaining = _items(_run_kubectl(base, "get", "deployment", "-l", f"agenttrust.io/revision={source_revision}", "-o", "json"))
    for item in remaining:
        status = item.get("status", {})
        if item.get("spec", {}).get("replicas", 0) != 0 or any(status.get(key, 0) != 0 for key in ("readyReplicas", "availableReplicas", "updatedReplicas")):
            raise GateError("PRODUCTION_DEPLOYMENT_SOURCE_WRITERS_REMAIN")
    return names


def _broker_operation(
    *,
    operation: str,
    source_release_id: str,
    target_release_id: str,
    environment_reference: str,
    previous_digest: str,
    writer_fence_digest: str,
    config: object,
    token_file: Path,
    root: Path,
) -> dict[str, Any]:
    request = prepare_broker_request(
        source_release_id=source_release_id,
        target_release_id=target_release_id,
        environment_reference=environment_reference,
        operation=operation,
        expected_previous_transition_digest=previous_digest,
        writer_fence_receipt_digest=writer_fence_digest,
    )
    response = invoke_broker(request, config, token_file)
    if response.get("operation") != operation:
        raise GateError("PRODUCTION_DEPLOYMENT_BROKER_OPERATION_MISMATCH")
    prefix = operation.lower().replace("_", "-")
    _write_json_new(root / f"{prefix}-request.json", request)
    _write_json_new(root / f"{prefix}-response.json", response)
    _write_json_new(root / f"{prefix}-signed-receipt.json", response["signed_receipt"])
    if response.get("inventory") is not None:
        _write_json_new(root / f"{prefix}-inventory.json", response["inventory"])
    return response


def execute_production_deployment(
    *,
    rendered_stack: Path,
    blue_green_plan: Path,
    release_id: str,
    environment_reference: str,
    kubectl: Path,
    kubeconfig: Path,
    context: str,
    namespace: str,
    broker_config: object,
    oidc_token_file: Path,
    output: Path,
    work_root: Path,
) -> dict[str, Any]:
    if _RELEASE_ID.fullmatch(release_id) is None or _NAMESPACE.fullmatch(namespace) is None:
        raise GateError("PRODUCTION_DEPLOYMENT_RELEASE_INVALID")
    try:
        kubectl_metadata = kubectl.stat(follow_symlinks=False)
    except OSError:
        raise GateError("PRODUCTION_DEPLOYMENT_RUNNER_PATH_INVALID") from None
    if (
        not kubectl.is_absolute()
        or kubectl.is_symlink()
        or not stat.S_ISREG(kubectl_metadata.st_mode)
        or kubectl_metadata.st_nlink != 1
        or kubectl_metadata.st_mode & 0o022
        or not os.access(kubectl, os.X_OK)
        or not kubeconfig.is_absolute()
        or kubeconfig.is_symlink()
    ):
        raise GateError("PRODUCTION_DEPLOYMENT_RUNNER_PATH_INVALID")
    for path in (rendered_stack, blue_green_plan, kubeconfig, oidc_token_file):
        _secure_input(path)
    if (
        not work_root.is_absolute()
        or not work_root.is_dir()
        or work_root.is_symlink()
        or stat.S_IMODE(work_root.stat(follow_symlinks=False).st_mode) != 0o700
    ):
        raise GateError("PRODUCTION_DEPLOYMENT_WORK_ROOT_INVALID")
    if not output.is_absolute() or output.exists() or output.is_symlink() or output.parent != work_root:
        raise GateError("PRODUCTION_DEPLOYMENT_OUTPUT_INVALID")
    plan = _read_json(blue_green_plan)
    rendered_digest = hashlib.sha256(rendered_stack.read_bytes()).hexdigest()
    if not isinstance(plan, dict) or plan.get("release_id") != release_id or plan.get("rendered_sha256") != rendered_digest or not _DIGEST.fullmatch(str(plan.get("release_digest", ""))):
        raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_INVALID")
    target_revision = str(plan.get("revision", ""))
    if target_revision != release_revision(release_id, str(plan["release_digest"])):
        raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_INVALID")
    documents = _documents(rendered_stack)
    services = plan.get("traffic_services")
    workloads = plan.get("workload_deployments")
    if not isinstance(services, list) or not services or any(not isinstance(name, str) for name in services):
        raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_INVALID")
    if not isinstance(workloads, list) or not workloads or any(not isinstance(name, str) for name in workloads):
        raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_INVALID")
    # Ensure the plan is actually derived from this rendered stack.
    if set(services) != set(_plan_names(documents, "traffic", "Service")) or set(workloads) != set(_plan_names(documents, "workload", "Deployment")):
        raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_MISMATCH")
    versioned_resources = plan.get("versioned_resources")
    if not isinstance(versioned_resources, dict):
        raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_INVALID")
    for kind in ("ConfigMap", "Deployment", "PodDisruptionBudget", "SecretProviderClass"):
        mapping = versioned_resources.get(kind)
        if not isinstance(mapping, dict) or any(not isinstance(source, str) or not isinstance(target, str) for source, target in mapping.items()):
            raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_INVALID")
        observed = {item["metadata"]["name"] for item in documents if item.get("kind") == kind}
        if set(mapping.values()) != observed:
            raise GateError("PRODUCTION_DEPLOYMENT_BLUE_GREEN_PLAN_MISMATCH")
    traffic_ingresses = _plan_names(documents, "traffic", "Ingress")
    base = [str(kubectl), "--kubeconfig", str(kubeconfig), "--context", context, "--namespace", namespace]
    _run_kubectl(base, "get", "namespace", namespace, "-o", "name")
    _run_kubectl(base, "apply", "--server-side", "--dry-run=server", "--field-manager=agenttrust-production-release", "-f", str(rendered_stack), "-o", "name")
    source_release_id, source_revision = _discover_source_release(base, release_id)
    config = broker_config
    state = "SOURCE_ACTIVE"
    try:
        for phase in ("prerequisite", "admission"):
            _run_kubectl(base, "apply", "--server-side", "--field-manager=agenttrust-production-release", "--selector", f"agenttrust.io/apply-phase={phase}", "-f", str(rendered_stack))
        admission_jobs = _plan_names(documents, "admission", "Job")
        for job in admission_jobs:
            _run_kubectl(base, "wait", "--for=condition=complete", f"job/{job}", "--timeout=30m")
        fence = _broker_operation(operation="WRITER_FENCE", source_release_id=source_release_id, target_release_id=release_id, environment_reference=environment_reference, previous_digest="0" * 64, writer_fence_digest="0" * 64, config=config, token_file=oidc_token_file, root=work_root)
        fence_digest = fence["signed_receipt"]["document"]["receipt_digest"]
        state = "DRAINED"
        _run_kubectl(base, "apply", "--server-side", "--field-manager=agenttrust-production-release", "--selector", "agenttrust.io/apply-phase=migration", "-f", str(rendered_stack))
        for job in _plan_names(documents, "migration", "Job"):
            _run_kubectl(base, "wait", "--for=condition=complete", f"job/{job}", "--timeout=30m")
        _run_kubectl(base, "apply", "--server-side", "--field-manager=agenttrust-production-release", "--selector", "agenttrust.io/apply-phase=workload", "-f", str(rendered_stack))
        for deployment in workloads:
            _run_kubectl(base, "rollout", "status", f"deployment/{deployment}", "--timeout=30m")
        cutover = _broker_operation(operation="CUTOVER", source_release_id=source_release_id, target_release_id=release_id, environment_reference=environment_reference, previous_digest="0" * 64, writer_fence_digest=fence_digest, config=config, token_file=oidc_token_file, root=work_root)
        cutover_digest = cutover["signed_receipt"]["document"]["receipt_digest"]
        state = "CUTOVER_COMMITTED"
        # The broker owns the selector switch.  Applying the traffic phase only
        # afterwards makes the rendered Ingress/Service bytes observable while
        # the database is still fenced and cannot move traffic early.
        _run_kubectl(base, "apply", "--server-side", "--field-manager=agenttrust-production-release", "--selector", "agenttrust.io/apply-phase=traffic", "-f", str(rendered_stack))
        for ingress in traffic_ingresses:
            _run_kubectl(base, "wait", "--for=jsonpath={.status.loadBalancer.ingress[0]}", f"ingress/{ingress}", "--timeout=10m")
        inventory = cutover.get("inventory")
        if not isinstance(inventory, dict) or inventory.get("target_revision") != target_revision or inventory.get("traffic_revision") != target_revision:
            raise GateError("PRODUCTION_DEPLOYMENT_CUTOVER_INVENTORY_MISMATCH")
        _verify_traffic(base, services, target_revision)
        _scale_source_to_zero(base, source_revision)
        unfreeze = _broker_operation(operation="UNFREEZE", source_release_id=source_release_id, target_release_id=release_id, environment_reference=environment_reference, previous_digest=cutover_digest, writer_fence_digest=fence_digest, config=config, token_file=oidc_token_file, root=work_root)
        state = "TARGET_ACTIVE"
        receipt = {
            "schema_version": "agenttrust.production-deployment-receipt.v2",
            "release_id": release_id,
            "source_release_id": source_release_id,
            "environment_reference": environment_reference,
            "target_revision": target_revision,
            "source_revision": source_revision,
            "rendered_stack_sha256": hashlib.sha256(rendered_stack.read_bytes()).hexdigest(),
            "blue_green_plan_sha256": hashlib.sha256(blue_green_plan.read_bytes()).hexdigest(),
            "fence_receipt_digest": fence_digest,
            "cutover_receipt_digest": cutover_digest,
            "unfreeze_receipt_digest": unfreeze["signed_receipt"]["document"]["receipt_digest"],
            "applied_phases": ["prerequisite", "admission", "migration", "workload", "traffic"],
            "traffic_services": sorted(services),
            "traffic_ingresses": sorted(traffic_ingresses),
            "workload_deployments": sorted(workloads),
            "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "deployment_succeeded": True,
        }
        receipt["receipt_digest"] = hashlib.sha256(canonical_json(receipt)).hexdigest()
        _write_json_new(output, receipt)
        return receipt
    except Exception:
        # A failed operation after CUTOVER must stay fenced unless the external
        # authority can produce a signed rollback and source unfreeze chain.
        if state != "CUTOVER_COMMITTED":
            raise
        try:
            rollback = _broker_operation(operation="ROLLBACK", source_release_id=source_release_id, target_release_id=release_id, environment_reference=environment_reference, previous_digest=cutover_digest, writer_fence_digest=fence_digest, config=config, token_file=oidc_token_file, root=work_root)
            _verify_traffic(base, services, source_revision)
            _broker_operation(operation="UNFREEZE", source_release_id=source_release_id, target_release_id=release_id, environment_reference=environment_reference, previous_digest=rollback["signed_receipt"]["document"]["receipt_digest"], writer_fence_digest=fence_digest, config=config, token_file=oidc_token_file, root=work_root)
        except Exception as rollback_error:
            raise GateError("PRODUCTION_DEPLOYMENT_ROLLBACK_FAILED") from rollback_error
        raise
