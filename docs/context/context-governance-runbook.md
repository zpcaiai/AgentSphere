# Context Governance operations and recovery runbook

## Scope and evidence boundary

This runbook operates the Batch 32 Context Governance authority. It does not authorize an operator
to bypass Canonical Action, PEP, transaction ledger, resource fence, supply-chain, legal-hold,
poisoning, or Evidence controls. Database rows are diagnostics, not permission to issue or replay a
mutation. Managed-service and multi-zone drills require production change approval and separate
Evidence.

## Pre-deployment gates

1. Verify the image digest, SBOM, signature, provenance, and vulnerability policy before admitting
   the pinned non-root image.
2. Apply migrations with the migration-owner identity, then revoke its interactive credential.
3. Create a dedicated `NOINHERIT` login role. Grant SELECT and INSERT only on the eleven Context
   tables and UPDATE only on the forty-three columns listed by the binary startup query. Do not
   grant DELETE, TRUNCATE, table-level UPDATE, schema CREATE, database TEMP, or function EXECUTE.
4. Confirm FORCE RLS for every Context table:

   ```sql
   SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
     FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN (
      'governed_memory_entries','prompt_versions','knowledge_snapshots',
      'context_knowledge_sources','context_deletion_tombstones',
      'context_quarantine_records','context_resource_versions','context_action_ingress',
      'context_authority_executions','context_retrieval_decisions','context_evidence_outbox'
    ) ORDER BY c.relname;
   ```

5. Validate that TLS server, outbound mTLS, database CA, password, token, and private-key files are
   absolute regular files. Secret and private-key files must be mode 0400 or 0600 and not symlinks.
6. Issue one certificate with exactly one URI or DNS SAN per workload. Do not use Common Name.
7. Generate independent random tokens for every SAN, tenant, subject, and scope binding; store only
   SHA-256 hashes in the binding document.
8. Verify outbound dependency origins have no redirect and their tokens cannot be replayed against
   another dependency.
9. Start one canary replica and require both management and data-plane readiness before traffic.
   The management listener is plaintext and must remain route-limited to `/live` and `/ready`; if
   it binds `0.0.0.0`, verify default-deny plus exact kubelet/node probe-CIDR ingress before rollout.

## Normal signals

- `/live` is process liveness only.
- `/ready` proves all required dependencies answered their exact readiness schema at that moment.
- `context_action_ingress.state=ACCEPTED` proves orchestrator acceptance, not mutation success.
- `context_authority_executions.state=MUTATED_PENDING_EVIDENCE` proves the domain mutation and
  outbox append committed; it is not complete until the Evidence authority acknowledges it.
- `state=SUCCEEDED` requires a safe result, Evidence reference, Evidence digest, and Evidence
  receipt.
- A deletion tombstone distinguishes legal-hold blocked, object purge, vector purge, and cache
  purge. Do not infer deletion from one storage system alone.

## Diagnose pending side effects

Use a tenant-scoped read-only diagnostic transaction:

```sql
BEGIN READ ONLY;
SELECT set_config('app.tenant_id', :'tenant_id', true);
SELECT idempotency_key, action_id, resource, state, execution_owner,
       execution_lease_until, updated_at
  FROM context_authority_executions
 WHERE tenant_id=:'tenant_id'::uuid
   AND state IN ('PREPARED','SIDE_EFFECTS_PENDING')
 ORDER BY updated_at;
ROLLBACK;
```

Do not alter leases. Verify adapter receipts by idempotency key at object, vector, cache,
supply-chain, legal-hold, and poisoning services. A retry is safe only when every adapter enforces
the same immutable request digest. Restore a failed dependency and allow the original Tool Proxy
request to retry. If any adapter cannot prove idempotency, isolate the tenant and open an incident.

Failure-injection drills must cover process exit after each of these boundaries:

1. poisoning scan before object promotion;
2. object promotion before vector upsert;
3. vector upsert before PostgreSQL mutation;
4. PostgreSQL mutation and outbox commit before Evidence delivery;
5. Evidence acceptance before local delivered timestamp.

The expected result is either no mutation or one mutation with one stable resource-version advance;
never duplicate content, cross-tenant index entries, or a success response without Evidence.

## Recover Evidence delivery

```sql
BEGIN READ ONLY;
SELECT set_config('app.tenant_id', :'tenant_id', true);
SELECT e.idempotency_key, e.action_id, e.resource, e.updated_at,
       o.event_id, o.payload_digest, o.created_at
  FROM context_authority_executions e
  JOIN context_evidence_outbox o
    ON o.tenant_id=e.tenant_id AND o.idempotency_key=e.idempotency_key
 WHERE e.tenant_id=:'tenant_id'::uuid
   AND e.state='MUTATED_PENDING_EVIDENCE'
   AND o.delivered_at IS NULL
 ORDER BY o.created_at;
ROLLBACK;
```

Restore the Evidence authority. The bounded recovery loop redelivers the exact event id,
idempotency key, payload, payload digest, occurrence time, and full PEP/ledger/fence binding to
`/v1/evidence/authority-events`. Confirm the receipt key id exists in the pinned Evidence keyring,
both the nested chain event and outer receipt signatures verify, the receipt payload digest matches
the outbox, one authoritative Evidence reference exists, `delivered_at` is set, and the execution is
`SUCCEEDED`. Never edit outbox payloads, regenerate timestamps, bypass signature verification, or
mark rows delivered by SQL.

## Poisoning and quarantine

1. Confirm the resource is unavailable through authoritative read and vector search.
2. Confirm the vector and cache adapters provide absence receipts.
3. Preserve the immutable quarantined object for analysis; do not copy content into tickets or
   logs.
4. Record detector codes and digest, not full sensitive content.
5. Remediate at the source and create new immutable content or snapshot digest.
6. Submit `RELEASE_QUARANTINE` with remediation Evidence. The authority performs a new poison scan.
   Any finding keeps the resource quarantined and prevents reindexing.

Test direct and indirect instruction injection, base64/Unicode/directional encoding, anomalous
repetition, cross-tenant markers, secret requests, goal replacement, and attempted permanent
privilege elevation. Detector unavailability must return 503 and must not promote or index content.

## Deletion and legal hold

1. Submit the deletion with the exact content digest, object reference, index reference where
   applicable, legal-hold identifier, and reason.
2. If the hold service reports active, the authority records a blocked tombstone and retains the
   object/index/cache. Memory becomes `HELD`; a knowledge snapshot remains authoritative but is not
   reported as deleted.
3. After an approved hold release, submit a new deletion action with the next resource version.
4. Require absence receipts from object, vector, and cache adapters before the database writes the
   completed tombstone.
5. Query each system independently after its consistency window. A database tombstone without all
   three receipts is an incident.

Run deletion-event loss drills by making Evidence unavailable after the mutation transaction. The
resource stays deleted while the execution remains `MUTATED_PENDING_EVIDENCE`; recovery must
deliver the original Evidence event without recreating content.

## Prompt rollback

Publish does not activate. Activation and rollback target an exact immutable semantic version and
atomically retire the prior active version. Before rollback, verify the target supply-chain receipt,
object digest, approvals, and quarantine state. After rollback, read the authoritative active row
and resource fence, invalidate consuming-agent prompt caches through their governed adapter, and
capture consumer rollout Evidence. A local database transition alone does not prove every agent
has adopted the target prompt.

## Retrieval isolation drills

- Use identical embeddings in two tenants; each subject must receive only its tenant's allowlist.
- Remove a subject from source metadata; the immutable decision must contain no resource and the
  vector adapter must not be called.
- Return a high-similarity unauthorized resource from a fault-injected vector adapter; the authority
  must fail the whole response.
- Quarantine or expire a source between requests and confirm it disappears before similarity.
- Attempt a query with a token bound to another subject, tenant, SAN, or scope; expect 401 without
  a retrieval decision.
- Omit each PEP decision or authorization Evidence header; expect denial before vector traffic.
- Replay the exact `retrieval_id`; expect the same immutable decision id. Change any bound request
  or PEP field while reusing that id; expect an idempotency conflict before vector traffic.

## Rollback and incident escalation

Application rollback must preserve forward-compatible database migrations. Never drop immutable
tombstones, retrieval decisions, ingress actions, executions, resource fences, or Evidence outbox
rows. If a binary rollback cannot read the current schema, stop traffic and deploy a compatible
binary instead of reversing governance data.

Escalate immediately for cross-tenant result leakage, missing RLS, broad database grants, duplicate
adapter side effects, an unauthorized prompt activation, a missing deletion purge, Evidence payload
drift, or any `SUCCEEDED` execution without an authoritative Evidence receipt.

## Current validation status

Static source, schema, migration, OpenAPI, and Docker contract checks can run on a development
checkout. Real mTLS CA, managed PostgreSQL/RLS role, locked object store, vector database, cache,
supply-chain verifier, legal-hold service, poisoning campaign, Evidence authority, multi-zone
failover, load, customer acceptance, and independent certification remain external production
gates. Under the current shared-host resource freeze, Cargo tests and Docker build are `NOT_RUN`.
