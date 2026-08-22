# Agent Registry/Posture production runbook

The Agent Registry is the fact authority for registered Agent assets, ownership, BOMs,
relationships, lifecycle and posture. It does not own Tool manifests, issue credentials, make PEP
decisions or treat discovery as registration. `UNTRUSTED_OBSERVATION` is deliberately the only
database state accepted for discovery writes.

## Runtime contract

- Data plane: TLS 1.3 mTLS on `8089`; the leaf certificate must contain exactly one reviewed DNS or
  URI SAN. Every route also requires an exact tenant/route token binding.
- Management plane: `9099`; bind only to loopback or `0.0.0.0` behind a Kubernetes NetworkPolicy
  that permits probes from node CIDRs only.
- Database role: `agenttrust_agent_registry`, `NOINHERIT`, no superuser/BYPASSRLS/CREATE/TEMP.
  The DSN contains no password and pins `sslmode=verify-full` plus
  `search_path=pg_catalog,public`; the password and CA are separate mounted files.
- Production never constructs `AgentRegistry` (the in-memory domain test store). The executable
  constructs only `PostgresAgentRegistryAuthority`.
- Every mutation body contains `agenttrust.governed-authority-context.v1`: Canonical Action IR
  hash, PEP decision ID/digest, execution UUID, ledger entry UUID/digest and immutable
  authorization `evidence://` reference. The full context digest is returned in the receipt and
  every field is bound into the hash-linked audit event and Outbox payload.

Inbound route scopes are exact and their SHA-256 token digests must be globally distinct:
`agents:read`, `agents:register`, `agents:discover`, `agents:ownership:assign`,
`agents:ownership:confirm`, `agents:bom`, `agents:relationships:write`,
`agents:relationships:read`, `agents:posture:evaluate`, `agents:posture:read`, and
`agents:lifecycle`. Wildcards and shared assignment/confirmation tokens are rejected at startup.

Required environment/file mounts:

- `AGENT_TRUST_AGENT_REGISTRY_DATABASE_URL_FILE`, `...DATABASE_PASSWORD_FILE`,
  `...DATABASE_CA_FILE`, `...DATABASE_EXPECTED_ROLE`
- `...TLS_CA_FILE`, `...TLS_CERTIFICATE_FILE`, `...TLS_PRIVATE_KEY_FILE`
- `...CLIENT_IDENTITIES`, `...TOKEN_BINDINGS_FILE`, `...CURSOR_HMAC_KEY_FILE`
- `...LIFECYCLE_BASE_URL`, `...LIFECYCLE_CA_FILE`,
  `...LIFECYCLE_CLIENT_CERTIFICATE_FILE`, `...LIFECYCLE_CLIENT_PRIVATE_KEY_FILE`
- three distinct secrets: `...IDENTITY_REVOCATION_TOKEN_FILE`,
  `...AUTHORIZATION_REVOCATION_TOKEN_FILE`, `...PACK_DEACTIVATION_TOKEN_FILE`

The migration creates/upgrades these authority tables: `agent_assets`, `agent_discovery_facts`,
`agent_posture_findings`, `agent_boms`, `agent_ownership_confirmations`,
`agent_relationship_edges`, `agent_relationship_supersessions`, `agent_posture_resolutions`,
`agent_lifecycle_records`, `agent_registry_idempotency`, `agent_registry_audit_heads`,
`agent_registry_audit_events`, and `agent_registry_outbox`. The migration runner must grant the
runtime role:

- `SELECT, INSERT, UPDATE` on `agent_assets` and `agent_registry_audit_heads` (no `DELETE`);
- `SELECT, INSERT` on all other `agent_*` and `agent_registry_*` tables in the Batch 30 migration,
  including immutable posture resolution records;
- no `UPDATE`/`DELETE` on discovery facts, BOMs, confirmations, relationship/lifecycle records,
  posture findings, idempotency rows, audit events or outbox rows.

## Lifecycle failure handling

Suspension calls identity and authorization revocation. Retirement/revocation additionally calls
Pack deactivation. All calls use independent tokens and derived idempotency keys. The authoritative
lifecycle row is updated only after every external response supplies a bounded immutable
`evidence://` reference. Any timeout, non-2xx response, malformed receipt or duplicate evidence
reference returns `503` and rolls back the local transaction. A retry must reuse the same original
idempotency key.

## Readiness and overload

Both readiness listeners require the database schema/RLS data to be complete and the lifecycle
convergence gateway to answer successfully. The service limits request bodies to 1 MiB, list pages
to 100, graph depth to 5, assets/observations evaluated per posture run to 10,000 and new findings
to 1,000. It returns `429` instead of accepting unbounded work.

## Evidence and recovery

Every successful mutation appends one hash-linked `agent_registry_audit_events` row and one
immutable `agent_registry_outbox` row in the same transaction as state and idempotency response.
Restart recovery reads the persisted response and verifies its digest. Preserve outbox records for
the Batch 10 Evidence relay; an outbox row is transport input, not proof that Evidence ingestion has
completed. Production certification therefore remains `NOT_ISSUED` until external Evidence and
operational gates are actually run.

For incident triage, use the returned `trace_id` only. Responses never include SQL errors, stack
traces, bearer tokens, identity references, endpoint values or permission sets.
