# Runtime Anomaly authority production contract

`agenttrust-runtime-anomaly-authority` turns signed, safe-feature-only runtime events into
deterministic findings, trajectory aggregates and Continuous Authorization. It is not a semantic
model proxy and it does not permit a model score to issue `KILL`. Deterministic rules remain
available when the Python detector or its model provider is unavailable.

## Control boundary

Signal ingestion is an authenticated event path: the TLS certificate must have exactly one
allowlisted DNS or URI SAN, the bearer token is uniquely bound to SAN/tenant/source/scope, the
source is ACTIVE in PostgreSQL, and the JCS envelope verifies under that source's Ed25519 key.
Only bounded safe features are accepted; raw credentials, request payloads, private reasoning and
secret-like strings are rejected and never written to the database.

An actionable aggregate first updates the local trajectory status and revocation epoch in the
same transaction as the signal, finding, aggregate, response command and Evidence outbox. This is
the fail-closed state observed by continuous PEP integration. External Pause, lease revocation,
credential revocation, Kill and Incident effects are separate production actions. They are
normalized into Canonical Action IR, admitted by the durable orchestrator, authorized by PEP,
bound to an immutable ledger event/fence and executed only through Tool Proxy. A network-ambiguous
response becomes `UNKNOWN`; it is never replaced by an ungoverned fallback.
The downstream request and receipt wire contracts are versioned in
`schemas/runtime-anomaly/controlled-response-request.schema.json` and
`controlled-response-receipt.schema.json`; a receipt is accepted only when its response ID and
command digest match the exact governed command.

`task_execution_succeeded` means the authority transition and Evidence acknowledgement completed.
`process_outcome` records whether the supervised agent was paused, killed, denied or otherwise
contained. These states are deliberately separate.

## Listeners and credentials

The data listener is fixed at `8094` and must bind a non-loopback address. It uses TLS 1.3 with
mandatory client certificates. The distinct management listener is fixed at `9104`; it is
plaintext and exposes only bounded `/live` and `/ready` responses for Kubernetes probes. It may
bind loopback or an unspecified address. When unspecified, default-deny NetworkPolicy plus exact
kubelet/node probe-CIDR ingress is mandatory.

Data scopes are exact and non-interchangeable:

- `runtime-anomaly:signal` requires a non-null source binding;
- `runtime-anomaly:mutate` admits human authority commands;
- `runtime-anomaly:execute` is reserved for Tool Proxy;
- `runtime-anomaly:query` reads authoritative trajectories. Data readiness is mTLS-only so the
  BFF dependency probe never needs a tenant-scoped bearer credential.

All secret/token/key files are absolute regular, single-link, non-symlink files. Private files are
readable only by the effective UID or its matching effective GID using a CSI-compatible `0440`
mount; world access and write bits are rejected. Five outbound dependency tokens must have unique
paths and values. Outbound origins are HTTPS root URLs, use a private CA and workload mTLS, disable
redirects and public trust roots, and re-read tokens for rotation.
`AGENT_TRUST_RUNTIME_ANOMALY_EVIDENCE_CLIENT_IDENTITY` must equal the outbound certificate's
single SAN and `AGENT_TRUST_RUNTIME_ANOMALY_EVIDENCE_KEYRING_FILE` must contain the active and
retained historical Evidence Authority Ed25519 public keys.

## Required dependencies

The authority fails readiness unless PostgreSQL, the durable orchestrator, Supervisor,
credential authority, incident authority and Evidence authority return their exact configured
readiness schemas. Production startup also verifies a NOINHERIT database role without superuser,
BYPASSRLS, replication, schema-create or database-temporary privileges, exact table grants and
FORCE RLS on every authority table.

The legacy Batch 21 prototype tables are moved to the owner-only
`agenttrust_legacy_runtime_anomaly` schema by migration `0036_01_17`; no legacy row becomes trusted
authority state automatically.

## Recovery and evidence

Signal and execution Evidence outboxes are independently idempotent and recovered per configured
tenant with bounded batches. Database mutations commit before Evidence delivery and are not
reported as `SUCCEEDED` until the Evidence receipt matches the exact idempotency key and digest.
The outbox persists the original event time and replays an identical
`AuthorityEvidenceEventRequest`; it never regenerates timestamps after an unknown outcome.
Governed mutations use `GOVERNED_ACTION` and are revalidated by Evidence against the final PEP,
ledger and fence binding. Signed signal observations use `AUTHENTICATED_EVENT`, which cannot carry
or claim an action binding. Both nested event and receipt signatures are verified against the
configured Evidence keyring before local finalization.
Old authorization leases cannot be reused after a revocation epoch change. A paused trajectory
requires a reviewed recovery command, a new lease identifier and new authorization Evidence.
`KILLED` and `COMPLETED` are terminal.

## Evidence boundary

Source code, schemas and deterministic tests are not proof of real Linux isolation, production
IdP/CA/Vault, live credential revocation, real incident routing, HA/DR, sustained load, customer
acceptance or independent certification. Those gates remain `NOT_RUN` until their commands,
receipts and independent Evidence are archived. Production certification remains false.
