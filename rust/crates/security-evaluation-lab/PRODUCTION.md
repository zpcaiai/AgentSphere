# Security evaluation authority production contract

The binary is `agenttrust-security-evaluation-authority`. It refuses root execution, plaintext
dependency URLs, database passwords embedded in URLs, database roles with superuser/BYPASSRLS/
INHERIT/replication, missing FORCE RLS, unexpected table grants, symlinks, loose private-file modes,
invalid keyrings, or a non-TLS data plane.

The data port uses TLS 1.3 with mandatory client certificates. A client certificate must contain
exactly one allowed DNS or URI SAN; CommonName is ignored. Each physical bearer token digest is
unique and bound to exactly one SAN, tenant, subject and data-plane route scope:

- `security-eval:mutate` for Canonical Action admission;
- `security-eval:execute` for Tool Proxy;
- `security-eval:query` for authoritative reads. Data readiness is mTLS-only so the BFF dependency
  probe does not require an arbitrary tenant binding.

The distinct management listener is plaintext by design and exposes only bounded `/live` and
`/ready` responses so Kubernetes probes do not need a workload client certificate. It may bind
loopback or an unspecified address; when unspecified, a default-deny NetworkPolicy must restrict
ingress to the configured kubelet/node probe CIDRs. It has no mutation or authoritative-read route.

## Required environment

All `*_FILE` values are absolute regular files. Private files must have one hard link, no symlink,
no world permissions, and be readable only by the effective UID or by its effective GID using an
exact `0440`-style group-readable mount. CA/certificate files must not be group/world writable.

| Variable | Purpose |
|---|---|
| `AGENT_TRUST_SECURITY_EVAL_DATABASE_URL_FILE` | PostgreSQL URL without password |
| `AGENT_TRUST_SECURITY_EVAL_DATABASE_PASSWORD_FILE` | PostgreSQL password |
| `AGENT_TRUST_SECURITY_EVAL_DATABASE_EXPECTED_ROLE` | exact NOINHERIT runtime role |
| `AGENT_TRUST_SECURITY_EVAL_DATABASE_CA_FILE` | database CA for VerifyFull |
| `AGENT_TRUST_SECURITY_EVAL_DATABASE_MAX_CONNECTIONS` | bounded pool, 2-100 |
| `AGENT_TRUST_SECURITY_EVAL_OUTBOUND_CA_FILE` | private dependency CA |
| `AGENT_TRUST_SECURITY_EVAL_OUTBOUND_CERTIFICATE_FILE` | outbound mTLS certificate |
| `AGENT_TRUST_SECURITY_EVAL_OUTBOUND_PRIVATE_KEY_FILE` | outbound mTLS key |
| `AGENT_TRUST_SECURITY_EVAL_ORCHESTRATOR_ENDPOINT` | HTTPS root |
| `AGENT_TRUST_SECURITY_EVAL_ORCHESTRATOR_TOKEN_FILE` | unique orchestrator token |
| `AGENT_TRUST_SECURITY_EVAL_ISOLATED_RUNNER_ENDPOINT` | HTTPS root |
| `AGENT_TRUST_SECURITY_EVAL_ISOLATED_RUNNER_TOKEN_FILE` | unique runner token |
| `AGENT_TRUST_SECURITY_EVAL_EVIDENCE_ENDPOINT` | HTTPS Evidence authority root |
| `AGENT_TRUST_SECURITY_EVAL_EVIDENCE_TOKEN_FILE` | unique Evidence token |
| `AGENT_TRUST_SECURITY_EVAL_EVIDENCE_CLIENT_IDENTITY` | exact outbound DNS/URI SAN recorded as Evidence source |
| `AGENT_TRUST_SECURITY_EVAL_EVIDENCE_KEYRING_FILE` | pinned Evidence Ed25519 public keyring |
| `AGENT_TRUST_SECURITY_EVAL_DATASET_KEYRING_FILE` | active Ed25519 dataset/scenario keys |
| `AGENT_TRUST_SECURITY_EVAL_REPORT_SIGNING_KEY_FILE` | exact 32-byte Ed25519 seed |
| `AGENT_TRUST_SECURITY_EVAL_REPORT_SIGNING_KEY_ID` | signer key ID |
| `AGENT_TRUST_SECURITY_EVAL_TOKEN_BINDINGS_FILE` | SAN/tenant/subject/scope/token digests |
| `AGENT_TRUST_SECURITY_EVAL_CLIENT_IDENTITIES` | comma-separated exact SANs |
| `AGENT_TRUST_SECURITY_EVAL_TLS_CA_FILE` | inbound client CA |
| `AGENT_TRUST_SECURITY_EVAL_TLS_CERTIFICATE_FILE` | server certificate |
| `AGENT_TRUST_SECURITY_EVAL_TLS_PRIVATE_KEY_FILE` | server key |
| `AGENT_TRUST_SECURITY_EVAL_DATA_ADDRESS` / `DATA_PORT=8096` | non-loopback data listener; fixed port |
| `AGENT_TRUST_SECURITY_EVAL_MANAGEMENT_ADDRESS` / `MANAGEMENT_PORT=9106` | distinct management listener; fixed port |
| `AGENT_TRUST_SECURITY_EVAL_MAXIMUM_CONCURRENCY` | bounded request concurrency |
| `AGENT_TRUST_SECURITY_EVAL_EXECUTION_LEASE_SECONDS` | 15-300 second pre-effect lease |
| `AGENT_TRUST_SECURITY_EVAL_AGENT_INSTANCE_ID` | canonical UUID |
| `AGENT_TRUST_SECURITY_EVAL_ORGANIZATION_ID` | service organization |
| `AGENT_TRUST_SECURITY_EVAL_AGENT_VERSION` | immutable service version |
| `AGENT_TRUST_SECURITY_EVAL_REGION` | jurisdiction/region |
| `AGENT_TRUST_SECURITY_EVAL_TOOL_ID` / `TOOL_VERSION` | registered executor tool |
| `AGENT_TRUST_SECURITY_EVAL_EXECUTOR_CREDENTIAL_PROFILE` | scoped credential profile |
| `AGENT_TRUST_SECURITY_EVAL_SERVICE_SUBJECT` | orchestrator service subject |

## PostgreSQL grants

The runtime role receives `SELECT, INSERT` on all security-evaluation runtime tables except that
`security_eval_evidence_events` is INSERT-only. It receives UPDATE only on datasets, campaigns,
findings, remediations, kill switches, resource versions, ingress, executions and the Evidence
outbox. It receives no DELETE, TRUNCATE, REFERENCES, TRIGGER, legacy-quarantine or cross-domain
table grant. Startup compares the exact grant set and checks FORCE RLS on all 17 tenant tables.
Database transition triggers protect immutable columns and one-way state machines even though the
runtime role has table-level UPDATE on those mutable aggregates.

The mutation and its Evidence outbox commit atomically. Publishing uses
`POST /v1/evidence/authority-events` with the durable task id, event time, payload digest and full
Canonical Action/PEP/ledger/fence binding. Recovery replays those exact values. The executor accepts
completion only after verifying the Evidence authority receipt and nested chain-event signatures,
the key id, request digest, tenant, task, event id, idempotency key and original payload digest.
Unknown keys, changed timestamps or payloads, and either signature mismatch fail closed in
`MUTATED_PENDING_EVIDENCE`.

## Image and deployment

The crate Dockerfile requires `RUST_BUILDER_IMAGE` and `RUNTIME_BASE_IMAGE` as externally supplied
digest-pinned images, uses `cargo build --locked --release`, copies only the authority binary and
runs as UID/GID 65532. The shared production image builder and Kubernetes stack must add the
`security-evaluation` component before deployment; this crate deliberately does not edit those
shared deployment files during concurrent stack work.

The service is production-path code, not production evidence. Real isolation, attacks, HA/DR, load,
customer acceptance and certification remain `NOT_RUN` until independently evidenced.
