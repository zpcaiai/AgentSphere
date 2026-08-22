# Platform SRE production authority

The `agenttrust-platform-sre-service` binary is the only Batch 34 mutation authority. Human
commands enter `POST /v1/sre/actions`, are bound to a strong signed human assertion and normalized
to Canonical Action IR. The durable runtime alone calls `POST /v1/sre/executions`; the executor
requires the admitted action hash, exact PEP decision, immutable transaction-ledger entry,
resource-version fence and authorization Evidence facts.

The executor commits a typed domain mutation and `sre_evidence_outbox` record in one tenant-RLS
transaction. It then publishes the exact outbox payload to the Evidence authority. A restart from
`MUTATED_PENDING_EVIDENCE` resumes Evidence delivery without repeating the mutation; only the
matching Evidence receipt moves the execution to `SUCCEEDED`. External effect calls carry the same
immutable bindings and idempotency key. A response with substituted facts, an unexpected schema,
non-HTTPS endpoint, reused credential, oversized body or missing immutable evidence fails closed.
Evidence delivery uses the shared `GOVERNED_ACTION` authority-event wire, not an orchestrator
task-state version. The Evidence Authority rechecks PEP/ledger/fence fields and the SRE service
verifies both receipt and nested event signatures with a required historical Ed25519 keyring.

TLS is restricted to TLS 1.3. Data-plane business callers must present exactly one permitted DNS or
URI SAN, an independently scoped bearer credential, an exact tenant header, and the route-specific
subject. The bounded data-plane `/ready` response is mTLS-only for dependency probes.
The management listener contains only `/healthz` and `/readyz` and must bind loopback or an
explicitly isolated pod address. Secrets are accepted only through absolute, non-symlink regular
files with owner/group read-only permissions. PostgreSQL requires `sslmode=verify-full`, forced RLS,
an exact role and column-scoped updates; any cross-domain table grant prevents startup.
The configured Evidence client identity must exactly equal the outbound certificate's single SAN.

`SignedSreEngineReport` is an integrity receipt for deterministic engine output. Its immutable
fields are `engine_report_only=true` and `production_certification=false`. It never upgrades
`NOT_RUN`, `OBSERVED`, or local harness output into HA, DR, load, chaos, customer acceptance or
certification evidence.

The production migration is
`migrations/platform-sre/0036_01_13_production_platform_sre.sql`; public contracts are under
`schemas/platform-sre` and `schemas/openapi/platform-sre-v1.yaml`. Deployment wiring is deliberately
owned by the unified production-stack integration and is not duplicated in this crate.
