#!/usr/bin/env python3
"""Request one externally executed, signed deployment transition."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from python.production_gates.deployment_cutover_broker import (
    OPERATIONS,
    invoke_broker,
    prepare_broker_request,
    read_json,
    validate_broker_request,
)
from python.production_gates.live_integrations import GateError


def _write_new(path: Path, value: object) -> None:
    if not _is_new_output(path):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_OUTPUT_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _is_new_output(path: Path) -> bool:
    return (
        path.is_absolute()
        and not path.exists()
        and not path.is_symlink()
        and path.parent.is_dir()
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="request-production-deployment-cutover")
    parser.add_argument("--source-release-id", required=True)
    parser.add_argument("--target-release-id", required=True)
    parser.add_argument("--environment-reference", required=True)
    parser.add_argument("--operation", choices=sorted(OPERATIONS), required=True)
    parser.add_argument("--expected-previous-transition-digest", required=True)
    parser.add_argument("--writer-fence-receipt-digest", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--oidc-token-file", type=Path, required=True)
    parser.add_argument("--request-output", type=Path, required=True)
    parser.add_argument("--response-output", type=Path, required=True)
    parser.add_argument("--signed-receipt-output", type=Path, required=True)
    parser.add_argument("--inventory-output", type=Path)
    args = parser.parse_args(argv)
    result_outputs = [args.response_output, args.signed_receipt_output]
    if args.inventory_output is not None:
        result_outputs.append(args.inventory_output)
    all_outputs = [args.request_output, *result_outputs]
    if len(set(all_outputs)) != len(all_outputs) or any(
        not _is_new_output(path) for path in result_outputs
    ):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_OUTPUT_INVALID")
    if (args.operation == "WRITER_FENCE") != (args.inventory_output is None):
        raise GateError("DEPLOYMENT_CUTOVER_BROKER_OUTPUT_INVALID")
    prepared = prepare_broker_request(
        source_release_id=args.source_release_id,
        target_release_id=args.target_release_id,
        environment_reference=args.environment_reference,
        operation=args.operation,
        expected_previous_transition_digest=args.expected_previous_transition_digest,
        writer_fence_receipt_digest=args.writer_fence_receipt_digest,
    )
    if args.request_output.exists():
        request = validate_broker_request(
            read_json(
                args.request_output, "DEPLOYMENT_CUTOVER_BROKER_REQUEST_INVALID"
            )
        )
        bound_fields = {
            "source_release_id", "target_release_id", "environment_reference",
            "operation", "expected_previous_transition_digest",
            "writer_fence_receipt_digest",
        }
        if any(request[field] != prepared[field] for field in bound_fields):
            raise GateError("DEPLOYMENT_CUTOVER_BROKER_REQUEST_INVALID")
    else:
        request = prepared
        _write_new(args.request_output, request)
    response = invoke_broker(
        request,
        read_json(args.config, "DEPLOYMENT_CUTOVER_BROKER_CONFIG_INVALID"),
        args.oidc_token_file,
    )
    _write_new(args.response_output, response)
    _write_new(args.signed_receipt_output, response["signed_receipt"])
    if args.inventory_output is not None:
        _write_new(args.inventory_output, response["inventory"])
    print(json.dumps({
        "external_action_executed_by_this_cli": False,
        "operation": args.operation,
        "request_id": request["request_id"],
        "signed_receipt_verified": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
