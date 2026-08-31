#!/usr/bin/env python3
"""Execute the fail-closed Kubernetes/broker production deployment sequence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from python.production_gates.production_deployment import execute_production_deployment
from python.production_gates.deployment_cutover_broker import read_json


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="execute-production-deployment")
    parser.add_argument("--rendered-stack", type=Path, required=True)
    parser.add_argument("--blue-green-plan", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--environment-reference", required=True)
    parser.add_argument("--kubectl", type=Path, required=True)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--broker-config", type=Path, required=True)
    parser.add_argument("--oidc-token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = execute_production_deployment(
        rendered_stack=args.rendered_stack,
        blue_green_plan=args.blue_green_plan,
        release_id=args.release_id,
        environment_reference=args.environment_reference,
        kubectl=args.kubectl,
        kubeconfig=args.kubeconfig,
        context=args.context,
        namespace=args.namespace,
        broker_config=read_json(args.broker_config, "DEPLOYMENT_CUTOVER_BROKER_CONFIG_INVALID"),
        oidc_token_file=args.oidc_token_file,
        output=args.output,
        work_root=args.work_root,
    )
    print(json.dumps({"deployment_succeeded": receipt["deployment_succeeded"], "receipt": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
