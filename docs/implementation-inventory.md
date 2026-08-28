# Implementation inventory for Batches 01-36

The repository started with specifications only. The implementation is one Rust workspace with dependency direction `contracts -> action IR -> registry -> PEP -> sandbox/proxy/ledger`; Gateway and identity consume shared contracts without creating duplicate DTOs.

| Batch | Authoritative code | Durable/config artifacts | Primary evidence |
|---|---|---|---|
| 01 | `rust/crates/contracts` | `schemas/json`, `schemas/proto`, `generated` | four-language compile and state guard tests |
| 02 | `rust/crates/gateway` | `config/gateway*.json`, `Dockerfile.gateway` | tenant/idempotency/trace/startup tests |
| 03 | `rust/crates/action-ir` | action schema and examples | duplicate-key, canonical hash, signature tests |
| 04 | `rust/crates/identity` | identity migration | audience, expiry, revocation, use-count tests |
| 05 | `rust/crates/registry` | registry migration and manifests | lifecycle, schema, tenant, revoke tests |
| 06 | `rust/crates/policy-pep`, `policies` | Common/Coding/Industrial Rego | hard-guard, PDP fail-closed, authorization tests |
| 07 | `rust/crates/sandbox-runtime` | `sandbox-profiles` | replay, output bound, process-group kill tests |
| 08 | `rust/crates/tool-proxy` | connector profiles are Registry-owned | DLP-before-audit, SSRF/path and lease tests |
| 09 | `rust/crates/transaction-ledger` | ledger migration | 100-way dedupe, UNKNOWN recovery, compensation tests |
| 10 | `rust/crates/evidence-evaluator`, `python/evaluator_runtime` | evidence schema/migration, offline CLI | tamper/delete/reorder, hard-gate, timeout tests |
| 11 | `rust/crates/protocol-adapter-sdk` | manifest schema/migration, conformance vectors | permission, mapping-loss, version negotiation tests |
| 12 | `rust/crates/mcp-security-proxy` | MCP schema/migration/config | drift freeze, strict JSON, injection, replay and full proxy tests |
| 13 | `rust/crates/a2a-agui-adapter`, `web/shared` | event schema/migration/config | scope reduction, revocation, sequence/resume/UI tests |
| 14 | `rust/crates/cn-standard-adapter` | version-package schema/migration | trust downgrade, extension override and unknown-version tests |
| 15 | `rust/crates/model-gateway`, `python/model_router` | provider schema/migration/config | policy-first fallback, two wire adapters, budget tests |
| 16 | `rust/crates/industrial-edge-gateway` | asset schema/migration/edge deployment | freshness, CAS, disconnect, protocol and buffer tests |
| 17 | `rust/crates/enterprise-approval`, `web/approval-console` | approval schema/migration/config | dual approval, role recheck, binding and atomic-use tests |
| 18 | `rust/crates/data-governance`, `python/data_classifiers` | label schema/migration/offline profile/DLP corpus | encoded/compressed DLP, cross-domain, offline tests |
| 19 | `rust/crates/audit-retention` | retention/export schema, migration and production profile | chain, Legal Hold, deletion/export tamper and restart tests |
| 20 | `rust/crates/pack-supply-chain` | Domain Pack schema and supply-chain migration | SBOM, provenance, signature, permission diff and revoke tests |
| 21 | `rust/crates/runtime-anomaly`, `python/runtime_anomaly` | signed signal/source registry, Canonical Action/PEP/ledger/fence authority, FORCE-RLS migration `0036_01_17`, TLS 1.3 mTLS data API, isolated management probes, bounded Supervisor/credential/incident/Evidence adapters, schemas/OpenAPI/container/config/runbook and threat corpus | deterministic trajectory/encoded-evasion/credential-revocation tests pass locally; crate build, real PostgreSQL/mTLS/endpoints, HA/DR/load and production false-positive/latency evaluation remain explicit `NOT_RUN` gates |
| 22 | `rust/crates/incident-release-gate` | incident schema/migration/config | containment, replay isolation and release-gate tests |
| 23-27 | `rust/crates/domain-risk-packs`, `python/energy_planner` | five domain schemas/migrations/configs and attack corpus | coding, industrial, energy, medical and sensitive negative tests |
| 28 | `rust/crates/pack-marketplace`, `python/pack_cli` | marketplace migration/config | scaffold, verify, install, approval, rollback and revoke tests |
| 29 | `rust/crates/durable-orchestrator`, `python/durable_worker` | runtime schema, OpenAPI, migration and Temporal production config | transitions, commands, recovery, completion and kill gates |
| 30 | `rust/crates/agent-registry-posture` | Agent BOM schema/migration/config | discovery separation, lifecycle, posture and tenant tests |
| 31 | `rust/crates/policy-administration` | policy bundle schema/migration/config | analysis, compile/sign, simulate, canary, rollback and exceptions |
| 32 | `rust/crates/context-governance` | Canonical Action ingress, Postgres FORCE-RLS authority/executor, TLS 1.3 mTLS API, object/vector/cache/supply-chain/legal-hold/poisoning/Evidence adapters, schemas/OpenAPI/container/runbook | managed dependency, fault-injection, multi-zone and sustained-load evidence remain external gates |
| 33 | `rust/crates/security-evaluation-lab`, `python/security_campaign` | attack DSL, dataset, migration/config | isolated runner, campaign, metrics, baseline and findings tests |
| 34 | `rust/crates/platform-sre`, `deploy` | recovery schema, migration, SRE config, resilience/chaos IaC | dependency semantics, capacity, restore and upgrade gates |
| 35 | `rust/crates/enterprise-control`, `java/enterprise-control-api`, `web/control-console` | governed OpenAPI, forced-RLS/idempotency migrations and production config | tenant/admin/BFF/task-status/webhook, quota/cost/API-key/license/integration, Java 21 warning-free and strict TypeScript tests |
| 36 | `rust/crates/production-closure` | certificate/external-signing/signed-revocation schemas, migration, KMS-only production flow, config and release runbook | gate aggregation, real-evidence requirement, private-key-free external signing, monotonic revocation verification and offline validation |

The `model_data_evidence` integration test proves the local Batch 18 policy → Batch 15 route → Batch 10 signed evidence path. Batch 19-36 tests prove their portable code paths and denial boundaries. Linux isolation, real identity/provider/protocol targets, Temporal/HA/DR, physical or clinical controls, enterprise acceptance and final production certification are not inferred from these tests.
