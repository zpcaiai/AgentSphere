# Runtime Anomaly and Continuous Authorization operations

## Deploy

1. Apply migrations through `0036_01_17` as the migration owner. Confirm the two prototype tables
   are owner-only under `agenttrust_legacy_runtime_anomaly`.
2. Create a dedicated NOLOGIN ownership role and a NOINHERIT runtime role. Grant only the table
   privileges enumerated by the binary; do not grant DELETE, schema CREATE, database TEMP or any
   routine execution.
3. Mount database CA/password, inbound CA/certificate/key, outbound CA/certificate/key, response
   Ed25519 seed, Evidence verification keyring, exact outbound Evidence SAN identity, route token
   bindings and five unique dependency tokens from the secret broker.
4. Register signal source keys through the governed action route. Bind each signal token to exactly
   one SAN, tenant and source ID. Rotate by registering a new source/key before revoking the old.
5. Verify the plaintext management port is route-limited to `/live` and `/ready`. If it binds
   `0.0.0.0`, validate default-deny plus the exact kubelet/node probe CIDRs before rollout.
6. Start a canary and require data readiness plus management readiness. Semantic detector outage
   must not change deterministic readiness or disable PEP/sandbox controls.

## Normal interpretation

- A signal receipt with `duplicate=true` is an exact digest match, not a second observation.
- `ACTIVE` means no local continuous-authorization restriction is present.
- `APPROVAL_REQUIRED` blocks scope growth until new authorization Evidence exists.
- `PAUSED` invalidates the previous lease epoch; recovery needs a new lease UUID.
- `KILLED` is terminal. Do not edit it back to ACTIVE.
- A response action receipt means orchestration was admitted; it does not prove the external
  supervisor, credential or incident process completed.
- An executor result separates `task_execution_succeeded` from `process_outcome`.

## Reconcile UNKNOWN

Never replay a response with a new idempotency key. Query the durable orchestrator and downstream
authority using the original response ID, command digest, action hash and ledger execution ID. If
the effect exists, reconcile its signed receipt through the original executor record. If the
effect is proven absent, an authorized operator may resume the original idempotent action. Preserve
the local PAUSED/KILLED and revocation epoch throughout reconciliation.

## Evidence recovery

The service retries only bounded, digest-identical Evidence deliveries. Inspect tenant-scoped
`runtime_anomaly_evidence_outbox` rows in `PENDING` or `UNKNOWN`; never update payload, digest or
delivered state manually. Restore the Evidence authority and let the recovery loop deliver the
original idempotency key. `MUTATED_PENDING_EVIDENCE` is not success.
Confirm delivery uses `/v1/evidence/authority-events`: governed mutations carry the persisted
PEP/ledger/fence binding, while signed observations carry `AUTHENTICATED_EVENT` and no action
binding. Receipt and nested event signatures must verify before the row becomes `DELIVERED`.

## Source compromise

Register a replacement source/key through Canonical Action/PEP/ledger, then revoke the compromised
source with approval Evidence. Revoke the associated route token and workload certificate in the
identity/secret authorities. Do not reuse its source ID, key ID or token digest. Open an incident
for any accepted signal after the compromise time and preserve those immutable events.

## Verification boundary

After the shared resource freeze is released, run the crate unit/contract tests, clippy and release
build, production migration validator, runtime asset validator and real PostgreSQL role/RLS matrix.
Then exercise actual mTLS SAN/token negatives, source-key rotation, detector outage, duplicate and
out-of-order events, Supervisor/credential/incident ambiguity, process restart and Evidence replay.
Archive exit codes and receipts. Until executed, each item remains `NOT_RUN`; local deterministic
tests do not certify Linux isolation, live endpoints, HA/DR, load or customer acceptance.
