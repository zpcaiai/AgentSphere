# Context Governance production contract

This crate is the single Batch 32 authority for governed Memory, Prompt, and Knowledge lifecycle
operations. The in-memory types in `src/lib.rs` remain deterministic reference models; production
traffic enters `src/server.rs`, is normalized in `src/authority.rs`, persists through PostgreSQL,
and reaches external systems only through `src/adapters.rs`.

## Control paths

Mutation:

1. TLS 1.3 requires a client certificate issued by the configured CA. Exactly one DNS or URI SAN
   must match `AGENT_TRUST_CONTEXT_CLIENT_IDENTITIES`; Common Name is ignored.
2. The bearer token hash must match one binding of SAN, tenant, subject, and route scope in the
   strict `agenttrust.context-token-bindings.v1` document. One physical token cannot be reused by
   another binding.
3. `POST /v1/context/actions` validates an exact domain payload and creates Canonical Action IR.
   The durable orchestrator must return an acceptance and ledger Evidence receipt before ingress
   becomes `ACCEPTED`.
4. Only `POST /v1/context/executions` can mutate authoritative tables. Tool Proxy must forward the
   exact action hash, ledger execution and event facts, fence, resource version, PEP decision, and
   authorization Evidence facts. They are compared with the admitted Canonical Action and stored
   as immutable execution bindings.
5. Object, vector, cache, supply-chain, legal-hold, and poisoning effects are idempotent and bound
   to the same action, ledger, fence, tenant, resource, and idempotency key. The domain mutation,
   resource fence advance, and Evidence outbox append commit atomically.
   A partial unique execution fence permits only one in-flight action for a tenant/resource/version,
   preventing concurrent executors from both reaching external side effects.
6. The outbox posts the exact durable event to `POST /v1/evidence/authority-events` with the full
   Canonical Action, final PEP, ledger event, fence, and authorization Evidence binding. The
   Context workload SAN is bound as `source_service`; the returned authority and nested chain
   signatures are verified against the configured Ed25519 keyring before the execution moves from
   `MUTATED_PENDING_EVIDENCE` to `SUCCEEDED`. A bounded recovery loop retries the original event id,
   occurrence time, idempotency key, and payload digest without reconstructing current-time data.

Retrieval:

1. The `context:retrieve` SAN/tenant/subject/token binding and PEP Evidence headers are required.
2. PostgreSQL FORCE-RLS selects candidates by tenant, subject visibility, classification, trust,
   quarantine, tombstone, and expiry, then inserts an immutable retrieval decision. Replays with
   the same `retrieval_id` must exactly match and reuse that decision.
3. Only after the decision commits may the vector adapter be called. It receives an explicit
   `allowed_resources` set. Empty sets return no results without contacting the vector service.
4. Every returned resource must be in that exact set or the response fails closed.

No endpoint accepts document or prompt content. Clients stage encrypted content in the configured
object store and submit only an immutable object reference plus content digest. This prevents
secrets and full knowledge documents from entering Canonical Action, ledger, log, or Evidence
payloads.

## Lifecycle semantics

- `WRITE_MEMORY`: actor must equal owner; poison scan precedes immutable promotion and indexing.
- `DELETE_MEMORY`: legal hold is checked before object, vector, and cache purge. A held item moves
  to `HELD`; a completed purge writes an immutable tombstone and moves to `TOMBSTONED`.
- `PUBLISH_PROMPT`: signed supply-chain receipt, two approvers, poison scan, and immutable object
  promotion are required. Publication never activates a prompt.
- `ACTIVATE_PROMPT` and `ROLLBACK_PROMPT`: atomically retire the prior active version and activate
  an exact immutable target version with a bounded rollout percentage.
- `REGISTER_KNOWLEDGE_SOURCE`: owner, trust, subject allowlist, classification, jurisdiction, and
  provenance become tenant-scoped authoritative metadata.
- `PUBLISH_KNOWLEDGE_SNAPSHOT`: source trust, supply-chain receipt, poison scan, object promotion,
  vector index, expiry, and data-residency metadata must agree.
- `DELETE_KNOWLEDGE_SNAPSHOT`: legal hold precedes object, index, and cache purge; tombstones remain
  immutable.
- `QUARANTINE_RESOURCE`: index and cache are purged before the resource is made unavailable.
- `RELEASE_QUARANTINE`: remediation Evidence and a clean re-scan are required before reindexing.

Poisoning detector unavailability fails closed. A blocking finding stores the object in quarantine
and never creates a vector index. Supply-chain verification unavailability or denial also fails
closed.

## Required configuration

All variables are mandatory; there are no production defaults.

### Process and database

- `AGENT_TRUST_PROFILE=production`
- `AGENT_TRUST_CONTEXT_DATABASE_URL_FILE`
- `AGENT_TRUST_CONTEXT_DATABASE_PASSWORD_FILE`
- `AGENT_TRUST_CONTEXT_DATABASE_CA_FILE`
- `AGENT_TRUST_CONTEXT_DATABASE_EXPECTED_ROLE`
- `AGENT_TRUST_CONTEXT_DATABASE_MAX_CONNECTIONS`
- `AGENT_TRUST_CONTEXT_AGENT_INSTANCE_ID`
- `AGENT_TRUST_CONTEXT_ORGANIZATION_ID`
- `AGENT_TRUST_CONTEXT_AGENT_VERSION`
- `AGENT_TRUST_CONTEXT_REGION`
- `AGENT_TRUST_CONTEXT_TOOL_ID`
- `AGENT_TRUST_CONTEXT_TOOL_VERSION`
- `AGENT_TRUST_CONTEXT_EXECUTOR_CREDENTIAL_PROFILE`
- `AGENT_TRUST_CONTEXT_SERVICE_SUBJECT`
- `AGENT_TRUST_CONTEXT_EXECUTION_LEASE_SECONDS`
- `AGENT_TRUST_CONTEXT_RECOVERY_INTERVAL_SECONDS`

The database URL file contains a URL without a password. It must use `sslmode=verify-full` and
`application_name=agenttrust-context-governance`. Password, bearer token, and private-key files
must be absolute regular non-symlink files with no group or world permission bits.

The login role must be `NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT`,
with `row_security=on`, `search_path=pg_catalog, public`, and no schema CREATE, database TEMP,
routine EXECUTE, cross-domain table privileges, broad table UPDATE/DELETE/TRUNCATE, or unexpected
column updates. Startup requires exactly SELECT and INSERT on the eleven Context tables and exactly
the forty-three update columns enumerated in the binary. Migration ownership remains a separate
NOLOGIN role.

### Inbound TLS and route credentials

- `AGENT_TRUST_CONTEXT_LISTEN_ADDRESS`
- `AGENT_TRUST_CONTEXT_PORT=8095` (fixed)
- `AGENT_TRUST_CONTEXT_MANAGEMENT_LISTEN_ADDRESS`
- `AGENT_TRUST_CONTEXT_MANAGEMENT_PORT=9105` (fixed)
- `AGENT_TRUST_CONTEXT_TLS_CA_FILE`
- `AGENT_TRUST_CONTEXT_TLS_CERTIFICATE_FILE`
- `AGENT_TRUST_CONTEXT_TLS_PRIVATE_KEY_FILE`
- `AGENT_TRUST_CONTEXT_CLIENT_IDENTITIES`
- `AGENT_TRUST_CONTEXT_TOKEN_BINDINGS_FILE`

The management address must be loopback or unspecified and cannot equal the TLS data address.
It is a plaintext probe listener that exposes only bounded `/live` and `/ready` responses. When it
binds an unspecified address, a default-deny NetworkPolicy must restrict ingress to the configured
kubelet/node probe CIDRs. The TLS 1.3/mTLS data plane exposes `/ready`, action, executor, retrieval,
and authoritative resource routes.

### Outbound mTLS and dependencies

- `AGENT_TRUST_CONTEXT_OUTBOUND_CA_FILE`
- `AGENT_TRUST_CONTEXT_OUTBOUND_CERTIFICATE_FILE`
- `AGENT_TRUST_CONTEXT_OUTBOUND_PRIVATE_KEY_FILE`
- `AGENT_TRUST_CONTEXT_ORCHESTRATOR_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_OBJECT_STORE_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_VECTOR_INDEX_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_CACHE_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_SUPPLY_CHAIN_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_LEGAL_HOLD_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_POISONING_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_EVIDENCE_ENDPOINT` and `_TOKEN_FILE`
- `AGENT_TRUST_CONTEXT_EVIDENCE_CLIENT_IDENTITY`
- `AGENT_TRUST_CONTEXT_EVIDENCE_KEYRING_FILE`

Every endpoint must be an HTTPS origin root without credentials, query, or fragment. Redirects and
public trust roots are disabled. The shared outbound certificate is expected to be a dedicated
Context Governance workload identity; dependencies must independently authorize its SAN and token.
`AGENT_TRUST_CONTEXT_EVIDENCE_CLIENT_IDENTITY` must be that exact DNS or URI SAN, and the Evidence
keyring must be an absolute, non-symlink public-key document using
`agenttrust.ed25519-public-keyring.v1`. Unknown key ids, malformed or stale/future receipts,
request-binding drift, and either signature mismatch fail closed.

## Readiness and recovery

Data and management `/ready` return 200 only when PostgreSQL, orchestrator, object store, vector
index, cache, supply chain, legal hold, poisoning detector, and Evidence authority all report their
exact readiness schema. Any missing dependency returns 503.

External effects use the execution idempotency key. If a process exits after object promotion but
before vector indexing, retry repeats immutable promotion and continues indexing. If the process
exits after the database transaction but before Evidence acknowledgement, the outbox recovery loop
redelivers the same event. Operators must never manually mark an execution `SUCCEEDED`.

Use the queries and drills in
`docs/context/context-governance-runbook.md` to reconcile `SIDE_EFFECTS_PENDING` and
`MUTATED_PENDING_EVIDENCE`. `UNKNOWN` is a terminal state for manual investigation and is not
automatically rewritten.

## Evidence boundary

The code, migration, schemas, OpenAPI, container recipe, and static production contract tests are
implemented. Under the current shared-host resource freeze, Cargo compilation/tests and Docker
build are `NOT_RUN`. Real enterprise CA/IdP, managed PostgreSQL, locked object storage, vector
database, cache, supply-chain verifier, legal-hold service, poisoning campaign, Evidence authority,
multi-zone recovery, continuous load, customer acceptance, and certification remain `NOT_RUN`.
These absences must not be interpreted as production certification.
