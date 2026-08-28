# Agent Trust & Compliance Control Plane — Batches 01-36

This repository implements the code-level foundation for all thirty-six dependency-safe batches as one workspace. Batches 01-18 provide the shared contracts and execution kernel. Batches 19-36 add audit retention and evidence graphs, supply-chain and Domain Pack governance, continuous authorization, incidents/replay, five risk packs, a marketplace, durable orchestration, agent posture, policy administration, governed context, a security evaluation lab, SRE recovery gates, an enterprise API/console, and the sole final production-closure authority.

Code implementation is not a production certification. Per-batch status remains `IN_PROGRESS` wherever required real-environment evidence is absent; Batch 36 does not issue a certificate unless Batches 01-35 are `EVIDENCE_VERIFIED` and every scoped gate passes.

## Verify locally

```bash
./scripts/generate-contracts.sh
./scripts/check-generated.sh
python3 scripts/check-contract-parity.py
python3 scripts/validate-runtime-assets.py
python3 -m unittest discover -s python -p 'test_*.py'
cargo test --workspace --all-targets
./scripts/run-policy-tests.sh
tsc --strict --noEmit --target ES2022 --moduleResolution node web/shared/agui-client.ts web/approval-console/src/approval-state.ts web/control-console/src/control-state.ts
```

The contract conformance commands also compile Proto, generated Rust/Python/Java/TypeScript, and state-transition vectors. PostgreSQL migrations live under `migrations/`; schemas, production profiles and operations guidance live under `schemas`, `config`, `deploy`, `policies` and `docs`.

## Production runtime assembly

`agent-trust-production-runtime` is the dependency-graph leaf that binds the production Gateway
to enterprise OIDC/JWKS, mTLS services, durable orchestration, secret leases, model generation and
SSE streaming, MCP/A2A, industrial edge, policy distribution, incident containment, backup,
enterprise integrations, lifecycle propagation, and closure evidence. It refuses missing endpoint,
CA, client-identity, token-file, subject-mapping, health-check, or evidence configuration. The
development Gateway remains a separate explicitly gated binary.

```bash
cargo build --locked --release -p agent-trust-production-runtime
python3 scripts/audit-production-runtime.py
python3 scripts/report-production-release-readiness.py || test $? -eq 2
python3 scripts/render-production-stack.py \
  --template /absolute/repository/deploy/kubernetes/production-stack.yaml.tmpl \
  --values /protected/release/production-stack-values.json \
  --runtime-config /protected/release/production-runtime.json \
  --git-provenance /protected/release/signed-git-provenance.json \
  --git-provenance-keyring /protected/release/git-provenance-keyring.json \
  --release-binding /protected/release/signed-release-binding.json \
  --release-binding-keyring /protected/release/release-binding-keyring.json \
  --activation /protected/release/activation.json \
  --closure-report /protected/release/closure-report.json \
  --production-certificate /protected/release/production-certificate.json \
  --closure-public-key /protected/trust/closure-public-key.json \
  --revocation-registry /protected/release/revocation-registry.json \
  --revocation-public-key /protected/trust/revocation-public-key.json \
  --output /absolute/new/manifest.yaml
```

The readiness command exits `2` while any release task remains open and never upgrades
local or historical results into production evidence. The full-stack template is the only
production deployment unit. The historical
`production-runtime.yaml.tmpl` and `render-production-runtime.py` pair may be used only for
component-level compatibility checks; it omits the authority, migration, identity, secret and
network-policy inventory required by a production release.

The example configuration is `config/production-runtime.example.json`. It contains no usable
credentials and must be rendered with deployment-owned endpoints, CA material, workload identity,
rotatable token files, subject mappings, exact model versions and scope-bound evidence files.

## Security boundary

A side-effecting request is accepted only after Canonical Action hashing, exact Registry resolution, two-stage PEP/approval, signed short-lived Execution Authorization, and Ledger reservation. Sandbox and Tool Proxy reject bare calls. Target secrets are leased inside the Proxy and filtered before audit. UNKNOWN external outcomes are reconciled from target facts and are never treated as ordinary failure.

Protocol and MCP adapters cannot authorize or receive raw credentials. Model selection filters by Data Policy before ranking. Delegation only narrows scope. Browser approval and admin actions are intents, not authorization facts. Industrial writes require fresh state, signed single-use edge authorization, compare-and-set and telemetry verification. Domain Pack actions reuse Canonical Action IR, PEP, Ledger and Evidence. Task completion remains separate from process success and requires ledger, evaluator and evidence agreement.

## Evidence boundary

Portable tests do not certify Linux namespace/cgroup/seccomp/gVisor isolation, live enterprise OIDC/Vault/Temporal/object-store/provider integrations, authoritative CN-standard compatibility, real MCP/A2A peers, OPC UA/MQTT/Modbus equipment, clinical or physical safety, regional crisis resources, HA/DR, production SLOs, customer acceptance, or final closure. Those statuses remain explicitly unresolved in per-batch `IMPLEMENTATION_STATUS.json` files until the named environments run.
