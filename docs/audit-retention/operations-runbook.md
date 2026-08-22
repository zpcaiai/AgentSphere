# Audit retention operations

Batch 19 stores tenant-scoped signed chain heads, retention policies, Legal Holds, exports, and deletion evidence. Ingestion rejects sequence gaps, duplicate identifiers with different content, and capacity overflow. Queries require a tenant and are themselves audited.

Managed evidence storage must enable S3 versioning and Object Lock in
`COMPLIANCE` mode. Verify a deployment-owned protected object version without
mutating or deleting it:

```sh
AGENTTRUST_S3_ACCESS='deployment-injected' \
AGENTTRUST_S3_SECRET='deployment-injected' \
python3 -m python.production_gates.object_store_retention \
  --endpoint https://s3.example --region eu-west-1 \
  --bucket agenttrust-evidence --object-key releases/RELEASE/evidence.json \
  --version-id OPAQUE_VERSION --access-key-env AGENTTRUST_S3_ACCESS \
  --secret-key-env AGENTTRUST_S3_SECRET --minimum-remaining-days 30 \
  --output /absolute/new/object-lock.json
```

The gate verifies the bucket default, versioning, the exact version's retention
deadline and readability. It never attempts deletion and returns only digests.
A multi-zone restore and an independently witnessed deletion-denial exercise
remain part of the production HA/DR assurance.

## Production procedure

1. Verify the active signing key and retention-policy digest before enabling writers.
2. Monitor chain-head lag, rejected batches, hold count, export verification failures, and deletion backlog.
3. Before deletion, resolve active Legal Holds. A hold release requires a distinct releasing principal and a recorded reason.
4. Export a self-contained manifest, artifacts, chain head, schema version, key ID, and signature. Run offline verification before transfer.
5. Restore into an isolated database and object namespace. Recompute every artifact digest and chain link, reconcile record counts, then emit a recovery report.

Do not treat the in-memory unit tests as object-store durability, WORM, disaster recovery, or regulatory evidence. Those gates remain `NOT_RUN` in Batch 19 status.

## Production authority

`agenttrust-audit-retention-service` exposes TLS 1.3/mTLS on `8088` and plaintext management
`/ready` on `9098`. The management listener may bind loopback or wildcard; wildcard deployment
must use NetworkPolicy/firewall rules that admit only node/kubelet probe CIDRs. Readiness is 200
only when PostgreSQL, the object-lock gateway, the versioned-deletion gateway, and the reloadable
human-principal verification keyring all pass their authoritative checks. The response field set
is exactly `schema_version`, `ready`, `database_ready`, `worm_ready`,
`deletion_gateway_ready`, and `human_principal_keys_ready`; no key material or key identifiers are
exposed. The deletion gateway must return
`agenttrust.retention-deletion-readiness.v1` with `versioned_deletion_proof=true`; the WORM gateway
uses the fixed `agenttrust.worm-readiness.v1` contract.

The data listener requires a client certificate containing exactly one allowlisted DNS or URI SAN.
`schemas/audit-retention/token-bindings.schema.json` binds a physically distinct raw bearer token
SHA-256 digest to that SAN, one tenant, one subject, and one route scope. Scopes are
`audit:append`, `audit:query`, `audit:authoritative-query`, `audit:retention`, `audit:hold-place`, `audit:hold-release`,
`audit:export`, `audit:delete`, `audit:control`, and `audit:graph`. Every body tenant and actor,
`X-AgentTrust-Tenant-Id`, authenticated subject, and `Idempotency-Key` must match exactly.

`POST /v1/authoritative/audit` is the only Enterprise BFF audit-dashboard route. Its service token
uses `audit:authoritative-query`, while its signed human assertion uses `audit:query`; therefore the
BFF read credential cannot fall back to the raw machine `/v1/audit/query` path. The assertion is
bound to the exact method, path, tenant, BFF certificate SAN, service subject, idempotency key and
body. The authority independently enforces strong authentication and the role-derived
classification ceiling, then atomically records the query chain event, assertion JTI/digest,
signed receipt, exact replay response and outbox evidence. `audit-reader`, `compliance-auditor`,
and `security-auditor` are capped at `INTERNAL`; `audit-confidential-reader`,
`audit-restricted-reader`, and `audit-regulated-reader` raise the ceiling explicitly.

Required configuration is fail-closed:

- `AGENT_TRUST_AUDIT_DATABASE_URL_FILE`, `AGENT_TRUST_AUDIT_DATABASE_PASSWORD_FILE`,
  `AGENT_TRUST_AUDIT_DATABASE_CA_FILE`, and `AGENT_TRUST_AUDIT_DATABASE_EXPECTED_ROLE`;
- `AGENT_TRUST_AUDIT_ISSUER`, `AGENT_TRUST_AUDIT_SIGNING_KEY_ID`, and
  `AGENT_TRUST_AUDIT_SIGNING_PRIVATE_KEY_FILE` (unpadded base64url 32-byte Ed25519 seed), plus
  `AGENT_TRUST_AUDIT_VERIFYING_KEYRING_FILE`; the keyring contains the active and retained
  historical audit/export verification keys and conforms to the single canonical
  `schemas/evidence/ed25519-public-keyring.schema.json` contract;
- `AGENT_TRUST_AUDIT_HUMAN_ASSERTION_KEYRING_FILE` (the shared Vault/CSI object
  `human-principal-keyring.json`), `AGENT_TRUST_AUDIT_HUMAN_ASSERTION_AUDIENCE`,
  `AGENT_TRUST_AUDIT_HUMAN_ASSERTION_MAX_AUTHENTICATION_AGE_SECONDS` (30 through 86400), and
  `AGENT_TRUST_AUDIT_QUERY_REQUIRE_STRONG_AUTH`; the keyring conforms to
  `schemas/identity/human-principal-keyring.schema.json` and is reloaded for every query;
- `AGENT_TRUST_AUDIT_CLIENT_IDENTITIES`, `AGENT_TRUST_AUDIT_TOKEN_BINDINGS_FILE`,
  `AGENT_TRUST_AUDIT_TLS_CA_FILE`, `AGENT_TRUST_AUDIT_TLS_CERTIFICATE_FILE`, and
  `AGENT_TRUST_AUDIT_TLS_PRIVATE_KEY_FILE`;
- `AGENT_TRUST_AUDIT_WORM_ENDPOINT`, `AGENT_TRUST_AUDIT_WORM_TOKEN_FILE`,
  `AGENT_TRUST_AUDIT_WORM_CA_FILE`, `AGENT_TRUST_AUDIT_WORM_CERTIFICATE_FILE`, and
  `AGENT_TRUST_AUDIT_WORM_PRIVATE_KEY_FILE`;
- `AGENT_TRUST_AUDIT_DELETION_ENDPOINT`, `AGENT_TRUST_AUDIT_DELETION_TOKEN_FILE`,
  `AGENT_TRUST_AUDIT_DELETION_CA_FILE`, `AGENT_TRUST_AUDIT_DELETION_CERTIFICATE_FILE`, and
  `AGENT_TRUST_AUDIT_DELETION_PRIVATE_KEY_FILE`;
- `AGENT_TRUST_AUDIT_MAX_EXPORT_BYTES` (1 MiB through 64 MiB) and
  `AGENT_TRUST_AUDIT_MAX_REQUEST_BYTES` (64 KiB through 16 MiB).

The database URL must use `verify-full`, an out-of-band password, and the exact
`pg_catalog,public` search path. The runtime role is externally provisioned by the migration runner;
migrations never create a login role. It must be non-superuser, non-inheriting, unable to bypass
RLS, create schema objects, use database TEMP, mutate immutable rows, or delete Legal Holds.
It additionally has only `SELECT,INSERT` on `audit_human_assertion_uses`; the table is FORCE-RLS,
immutable, and unique by assertion JTI, assertion digest, and authoritative-query idempotency key.

Audit rows are never physically deleted. A deletion request resolves an immutable retention-policy
version, refuses a cutoff newer than the retention window, and excludes any object referenced by an
active Legal Hold, newer record, other policy, or other retained record. The real HTTPS deletion
gateway must return one exact, digest-bound provider version proof per requested object. The service
then persists the deletion proof, signed mutation receipt, chain event, replay response, and outbox
atomically. WORM writes and deletion commands are idempotency-bound so a database retry cannot
silently create a different external result.

The export route writes only complete chains. If the caller's classification ceiling cannot include
every record, it fails closed. `transformed=true` is rejected until a separately signed and offline
verifiable transformation-proof contract exists. `audit-export verify` remains the offline verifier.

## Ingestion and outbox boundary

`POST /v1/audit/records` is a real typed authority endpoint, but this repository currently has no
cross-authority HTTP dispatcher/client that drains the other services' outboxes into it. Likewise,
rows in `audit_retention_outbox` are committed evidence-to-dispatch, not proof that an external
broker or Evidence authority has consumed them. Until a separately deployed, checkpointed,
tenant-bound mTLS dispatcher exists and its delivery/replay evidence is verified, production event
ingestion from other authorities and outbox delivery remain `NOT_RUN`; do not infer them from local
row creation or the Audit service readiness result.
