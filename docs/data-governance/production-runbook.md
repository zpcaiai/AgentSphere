# Data Governance production runbook

This service is the Batch 18 production authority. The reference models in `src/lib.rs` remain useful
for deterministic policy tests, but production state belongs to PostgreSQL migration
`0036_01_15_production_data_governance.sql` and can change only through the Canonical Action IR → PEP
→ ledger/fence → typed executor → Evidence outbox path.

## Required environment

There are no production defaults. The process refuses a non-production profile or root UID.

Process and database:

- `AGENT_TRUST_PROFILE=production`
- `AGENT_TRUST_DATA_DATABASE_URL_FILE`
- `AGENT_TRUST_DATA_DATABASE_PASSWORD_FILE`
- `AGENT_TRUST_DATA_DATABASE_CA_FILE`
- `AGENT_TRUST_DATA_DATABASE_EXPECTED_ROLE`
- `AGENT_TRUST_DATA_DATABASE_MAX_CONNECTIONS`
- `AGENT_TRUST_DATA_AGENT_INSTANCE_ID`
- `AGENT_TRUST_DATA_ORGANIZATION_ID`
- `AGENT_TRUST_DATA_AGENT_VERSION`
- `AGENT_TRUST_DATA_REGION`
- `AGENT_TRUST_DATA_TOOL_ID`
- `AGENT_TRUST_DATA_TOOL_VERSION`
- `AGENT_TRUST_DATA_EXECUTOR_CREDENTIAL_PROFILE`
- `AGENT_TRUST_DATA_SERVICE_SUBJECT`
- `AGENT_TRUST_DATA_EXECUTION_LEASE_SECONDS`
- `AGENT_TRUST_DATA_RECOVERY_INTERVAL_SECONDS`
- `AGENT_TRUST_DATA_DEPLOYMENT_PROFILES_FILE`
- `AGENT_TRUST_DATA_PROFILE_KEYRING_FILE`

The database URL contains no password and must specify `sslmode=verify-full` and
`application_name=agenttrust-data-governance`. Deployment profiles use a bounded, unexpired Ed25519
signature whose key is present and not revoked in the configured keyring. An `OFFLINE` profile must
have no external endpoints, telemetry, or online update channel.

Inbound data plane:

- `AGENT_TRUST_DATA_LISTEN_ADDRESS`
- `AGENT_TRUST_DATA_PORT=8092`
- `AGENT_TRUST_DATA_MANAGEMENT_LISTEN_ADDRESS` (must be loopback)
- `AGENT_TRUST_DATA_MANAGEMENT_PORT=9102`
- `AGENT_TRUST_DATA_TLS_CA_FILE`
- `AGENT_TRUST_DATA_TLS_CERTIFICATE_FILE`
- `AGENT_TRUST_DATA_TLS_PRIVATE_KEY_FILE`
- `AGENT_TRUST_DATA_CLIENT_IDENTITIES`
- `AGENT_TRUST_DATA_TOKEN_BINDINGS_FILE`

TLS is 1.3 only. A certificate must expose exactly one authorized DNS or URI SAN; Common Name is
ignored. Each opaque bearer credential hash can bind only one SAN, tenant, subject, and one of:
`data:mutate`, `data:execute`, `data:evaluate`, `data:scan`, `data:sanitize`,
`data:artifact-authorize`, or `data:read`.

Outbound authorities:

- `AGENT_TRUST_DATA_OUTBOUND_CA_FILE`
- `AGENT_TRUST_DATA_OUTBOUND_CERTIFICATE_FILE`
- `AGENT_TRUST_DATA_OUTBOUND_PRIVATE_KEY_FILE`
- `AGENT_TRUST_DATA_ORCHESTRATOR_ENDPOINT`, `_TOKEN_FILE`, and `_READINESS_SCHEMA`
- `AGENT_TRUST_DATA_ENTERPRISE_DLP_ENDPOINT`, `_TOKEN_FILE`, and `_READINESS_SCHEMA`
- `AGENT_TRUST_DATA_OBJECT_WORM_ENDPOINT`, `_TOKEN_FILE`, and `_READINESS_SCHEMA`
- `AGENT_TRUST_DATA_LEGAL_HOLD_ENDPOINT`, `_TOKEN_FILE`, and `_READINESS_SCHEMA`
- `AGENT_TRUST_DATA_EVIDENCE_ENDPOINT`, `_TOKEN_FILE`, and `_READINESS_SCHEMA`
- `AGENT_TRUST_DATA_EVIDENCE_SOURCE_SERVICE` (the exact `DNS:` or `URI:` SAN presented by the
  outbound mTLS certificate)
- `AGENT_TRUST_DATA_EVIDENCE_ISSUER`
- `AGENT_TRUST_DATA_EVIDENCE_VERIFYING_KEYRING_FILE`

Endpoints are HTTPS origin roots with an explicit port and without credentials, query, or fragment.
Every dependency must return its configured exact schema and `ready=true` from `/ready`; for the
current shared Evidence authority this is `agenttrust.evidence-readiness.v1`. The outbound client has a
private CA, workload certificate, no public roots, and redirect policy `none`. Token and private-key
files must be absolute, regular, non-symlink, owner/group-readable only files. Configuration and CA
files may not be group/world writable and must have a single hard link.

The Evidence token is separately restricted to `evidence:authority-event`. Its Ed25519 public
keyring uses `agenttrust.ed25519-public-keyring.v1`; unknown key IDs, issuer drift, invalid event or
receipt signatures, noncanonical hashes, or any mismatch in tenant, task, authority event,
idempotency, payload digest, source kind, event draft, PEP binding, or ledger binding fail closed.
The configured source service must equal the certificate SAN observed by the Evidence authority.

The Enterprise DLP authority must expose `v1/dlp/scans`,
`v1/dlp/receipts/verify`, and `ready`; durable `RECORD_DLP_SCAN` execution is denied unless the
receipt-verification effect succeeds. Evidence is delivered as the shared
`AuthorityEvidenceEventRequest` to `POST /v1/evidence/authority-events`, with source kind
`GOVERNED_ACTION` and the exact Canonical Action, PEP, ledger, fence, and authorization-Evidence
binding. Only the local payload digest is sent; the safe mutation payload remains in the tenant-RLS
outbox and raw content is never transmitted. The returned `SignedAuthorityEvidenceReceipt` and its
nested signed event are verified before finalization. Legal-hold retention checks and object/WORM
completion receipts must echo the reference and canonical receipt digest admitted in the command.

## Database role and grants

Use a separate NOLOGIN migration owner. The runtime role must be
`NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT LOGIN`, have no database
TEMP or schema CREATE privilege, no routine EXECUTE grant, no legacy Batch 18 table grant, and exactly
the table/column grants below. Startup verifies these facts and exits with
`DATA_GOVERNANCE_DATABASE_ROLE_UNSAFE` on drift.

```sql
ALTER ROLE agenttrust_data_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOREPLICATION NOINHERIT LOGIN;
ALTER ROLE agenttrust_data_runtime SET row_security=on;
ALTER ROLE agenttrust_data_runtime SET search_path='pg_catalog, public';
REVOKE CREATE ON SCHEMA public FROM agenttrust_data_runtime;
REVOKE TEMP ON DATABASE agentsphere FROM agenttrust_data_runtime;

GRANT SELECT,INSERT ON TABLE
  data_resource_versions,data_authority_ingress,data_authority_executions,
  governed_data_labels,data_policy_decision_records,data_dlp_scan_summaries,
  data_transform_receipts,data_cross_domain_grants,data_cross_domain_consumptions,
  data_retention_records,data_legal_holds,data_export_intents,data_evidence_outbox
TO agenttrust_data_runtime;

GRANT UPDATE(resource_version,action_hash,ledger_execution_id,fence_digest,updated_at)
  ON data_resource_versions TO agenttrust_data_runtime;
GRANT UPDATE(state,receipt,updated_at)
  ON data_authority_ingress TO agenttrust_data_runtime;
GRANT UPDATE(state,execution_owner,execution_lease_until,evidence_event_id,result,completed_at,updated_at)
  ON data_authority_executions TO agenttrust_data_runtime;
GRANT UPDATE(consumed_at,consumption_id)
  ON data_cross_domain_grants TO agenttrust_data_runtime;
GRANT UPDATE(state,released_at,release_approval_id,release_evidence_ref,
  release_evidence_digest,release_adapter_receipt,release_action_hash,release_ledger_execution_id)
  ON data_legal_holds TO agenttrust_data_runtime;
GRANT UPDATE(state,artifact_ref,artifact_digest,watermark_digest,signature_digest,
  worm_receipt_ref,worm_receipt_digest,completion_adapter_receipt,completed_at,
  completion_action_hash,completion_ledger_execution_id)
  ON data_export_intents TO agenttrust_data_runtime;
GRANT UPDATE(state,delivery_receipt,delivered_at)
  ON data_evidence_outbox TO agenttrust_data_runtime;
```

The binary expects 26 base table grants and 39 update-column grants. Change code and this verifier
together if a schema transition legitimately changes those counts.

## Failure-closed invariants

- Canonical resources are operation-bound: `labels/<label_digest>`,
  `policy-decisions/<decision_id>`, `dlp-scans/<scan_id>`, `transforms/<transform_id>`,
  `cross-domain-grants/<grant_id>`, `retention/<retention_id>`,
  `legal-holds/<hold_id>`, and `export-intents/<export_id>`. The executor rejects a resource whose
  suffix differs from the operation payload identity, so a fence for resource X cannot mutate Y.
- Missing/unknown labels are treated as restricted, never public.
- Secrets never enter model context. Enterprise DLP unavailability returns 503, including during
  durable scan-receipt verification.
- A public/external/SaaS destination requires configured transforms for confidential-or-higher data.
- Offline profiles deny external/public/SaaS destinations and telemetry.
- Gzip/ZIP and oversized encoded inputs are denied; recursive JSON and Base64 inspection is bounded.
- Standard, unpadded, URL-safe, and URL-safe-unpadded Base64 are inspected for at most three decode
  layers. Invalid local DLP pattern initialization makes readiness false; JSON scans cap nodes,
  depth, paths, and findings rather than truncating to an apparent allow result.
- Redirect targets are not followed. A redirect requires a new authorization with a new destination
  digest and policy decision.
- Cross-domain grants are tenant, zones, object digest, expiry, approval, and single-use bound. A
  unique consumption row and row lock make concurrent replay fail.
- Legal hold may only transition `ACTIVE → RELEASED` with a distinct approval and external receipt.
  Place, release, and retention resolution serialize on a tenant/object advisory lock; a local active
  hold blocks `DELETE` and `ARCHIVE` even if an external response is stale.
- Export may only transition `AUTHORIZED → COMPLETED` with signature, watermark, and WORM receipt.
  Authorization rebinds the stored allowed decision to its exact policy-request digest,
  decision digest, label classification, destination kind, object digest, exact Enterprise DLP
  receipt, and any required transform receipt. A null transform pair is valid only when the exact
  durable decision has no required transformations; otherwise the immutable transform output must
  equal the exported object and contain every required transformation. The optional grant must be
  consumed for the same export ID before `AUTHORIZE_EXPORT`. The typed object-authorization
  reference/digest is mandatory and becomes immutable export-intent state. An allowed decision, DLP
  result, transform, grant, or object authorization cannot be replayed for another destination,
  classification, or object.
- Mutation, resource-fence advance, and immutable Evidence outbox append commit atomically. The
  client sees `COMPLETED` and the final `evidence://` reference/digest only after the Evidence
  authority acknowledges delivery; the local outbox reference remains available for reconciliation.
- A submitter polls `GET /v1/authoritative/data/mutations/{command_id}` with the same tenant and
  `data:read` identity. The route returns a result only after `COMPLETED` and revalidates both final
  Evidence fields; pending rows fail closed and never promote a `durable_record_required` proposal.
- Resource pagination returns `authoritative=true` and `data_digest`, the JCS SHA-256 of the full
  response with `data_digest` omitted. Consumers must verify both before using a page as an
  authoritative fence snapshot; the tenant header, page tenant, cursor, and digest remain bound.

The artifact write sequence is: persist the output label, persist the exact output policy decision,
persist the output Enterprise DLP summary, persist an actual output transform only when that decision
requires one, consume any cross-domain grant with `export_intent_id=authorization_id`, call artifact
authorization with those durable identifiers and digests, then submit `AUTHORIZE_EXPORT` with the
same export/authorization ID, returned `object_authorization_ref`/digest, and all prior bindings. A
prompt transform is not an output-artifact transform.

## Recovery and reconciliation

The bounded recovery loop reads `PENDING` outbox rows per configured tenant and reconstructs and
republishes the same authority-event request from the immutable event ID, Evidence-specific
idempotency key, payload digest, event occurrence time, delivery request time, task ID, and control
binding. The shared contract intentionally permits an old, byte-identical request to be replayed;
only future clock skew is rejected. Durable data commands follow the same rule: an old
`requested_at` remains valid only because the stored ingress Canonical Action, command body,
idempotency key, action hash, and PEP/ledger/fence bindings must all match exactly; a future timestamp
is denied. External effects use the execution idempotency key and must
return the exact same signed/immutable receipt on replay. Concurrent Evidence finalizers lock the
same outbox/execution pair; after one commits, later exact replays return the stored completed result
instead of attempting a second immutable transition.

```sql
BEGIN;
SELECT set_config('app.tenant_id', :'tenant_id', true);
SELECT action_id,state,execution_owner,execution_lease_until,evidence_event_id,updated_at
FROM data_authority_executions
WHERE state IN ('EXECUTING','MUTATED_PENDING_EVIDENCE')
ORDER BY updated_at;
SELECT event_id,idempotency_key,payload_digest,created_at
FROM data_evidence_outbox WHERE state='PENDING' ORDER BY created_at;
ROLLBACK;
```

Do not manually mark either table delivered/completed. If an execution lease expires before the
domain transaction, the next exact replay may claim it. If an external effect returned but its
result is unknown, retain the execution and reconcile the external idempotency receipt; do not issue
a new action or grant.

## Required drills and current evidence boundary

Run the negative and recovery matrix in `tests/data-governance/failure-injection-matrix.json` against
the real Enterprise DLP, object/WORM, legal-hold, Evidence, PostgreSQL, and mTLS identities. Verify
cross-tenant FORCE-RLS, concurrent grant consumption, crash-after-effect, crash-after-commit,
encoded/compressed escape, public-model fallback denial, redirect denial, and offline egress.

Code, migration, schemas, OpenAPI, container recipe, tests, and this runbook are implemented. Cargo
and Docker execution are `NOT_RUN` during the shared-host resource freeze. Real enterprise IdP/CA,
managed PostgreSQL, Enterprise DLP, locked retention object store, legal-hold system, Evidence
authority, multi-zone recovery, continuous load, customer acceptance, and independent certification
remain `NOT_RUN`. Batch 18 therefore remains `IN_PROGRESS`; this document is not production evidence
or a certificate. The production certificate state is `NOT_ISSUED`.
