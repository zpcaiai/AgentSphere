"""Materialize dynamic production stack values after positive evidence exists."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import re
from typing import Any, Mapping

from python.production_gates.live_integrations import GateError
from python.production_gates.release_activation import (
    ActivationError,
    validate_image_manifest,
)
from python.production_gates.release_binding import (
    signed_release_binding_digest,
    verify_signed_release_binding,
)


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ACTIVATION_FIELDS = {
    "schema_version", "release_id", "scope", "images",
    "production_image_manifest", "signed_release_binding_digest",
    "evidence_bundle_manifest_digest", "requested_at",
}


def materialize_production_stack_values(
    release_binding: object,
    release_binding_keyring: object,
    activation: object,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Inject only certificate-bound dynamic digests into signed static values."""

    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None or checked_at.utcoffset() != timezone.utc.utcoffset(checked_at):
        raise GateError("PRODUCTION_VALUES_TIME_INVALID")
    binding = verify_signed_release_binding(
        release_binding, release_binding_keyring, now=checked_at
    )
    if not isinstance(activation, dict) or set(activation) != _ACTIVATION_FIELDS:
        raise GateError("PRODUCTION_VALUES_ACTIVATION_INVALID")
    static_values = binding.get("static_values")
    scope = activation.get("scope")
    images = activation.get("images")
    evidence_digest = activation.get("evidence_bundle_manifest_digest")
    if (
        activation.get("schema_version") != "agenttrust.production-release-activation.v1"
        or not isinstance(static_values, dict)
        or "release_digest" in static_values
        or not isinstance(scope, dict)
        or activation.get("release_id") != binding.get("release_id")
        or scope.get("release_id") != binding.get("release_id")
        or scope.get("release_digest") != binding.get("release_digest")
        or activation.get("signed_release_binding_digest")
        != signed_release_binding_digest(release_binding)
        or not isinstance(evidence_digest, str)
        or not _DIGEST.fullmatch(evidence_digest)
        or not isinstance(images, dict)
        or static_values.get("images") != images
    ):
        raise GateError("PRODUCTION_VALUES_ACTIVATION_BINDING_INVALID")
    try:
        manifest = validate_image_manifest(
            activation.get("production_image_manifest"),
            activation.get("release_id"),
            images,
            checked_at,
        )
    except ActivationError:
        raise GateError("PRODUCTION_VALUES_IMAGE_MANIFEST_INVALID") from None
    if manifest.get("manifest_digest") != scope.get("build_digest"):
        raise GateError("PRODUCTION_VALUES_IMAGE_MANIFEST_INVALID")

    values = copy.deepcopy(static_values)
    evidence = values.get("evidence")
    if not isinstance(evidence, dict) or "bundle_digest" in evidence:
        raise GateError("PRODUCTION_VALUES_EVIDENCE_INVALID")
    values["release_digest"] = binding["release_digest"]
    evidence["bundle_digest"] = evidence_digest
    return values
