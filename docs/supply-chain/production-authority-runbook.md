# Pack supply-chain production authority runbook

## Deployment contract

Run `agenttrust-pack-supply-chain-authority` as a dedicated non-root identity. Apply `migrations/pack-supply-chain/0036_01_16_production_pack_supply_chain.sql` after the shared identity, PEP, ledger, registry, marketplace and Evidence migrations. The data plane must bind port `8093`; the management plane must bind port `9103`. Management readiness is not an authorization endpoint and should be exposed only to the local pod/network monitor.

The process refuses a database role that is superuser, `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, replication, inherited, schema-create or database-temporary capable. The role must have `row_security=on`, `search_path=pg_catalog, public`, and PostgreSQL `sslmode=verify-full`. Grant only `CONNECT`, `USAGE` on `public`, `SELECT/INSERT/UPDATE` on the nine `supply_chain_*` tenant tables, `SELECT` on publisher/key tables, and function execution required by their triggers. Do not grant `DELETE`, schema `CREATE`, database `TEMP`, ownership, table-owner membership, or direct publisher/key mutation to the runtime role. Publisher/key provisioning belongs to a separate offline maintainer authority.

Ingress grants are exact and tenant scoped:

| Operation | Bearer scope |
| --- | --- |
| publish, validate | `supply-chain:publish` |
| approve | `supply-chain:approve` |
| activate, rollback | `supply-chain:activate` |
| quarantine, revoke | `supply-chain:revoke` |
| authoritative release query | `supply-chain:read` |
| expired-lease reconciliation | `supply-chain:recover` |

Each token digest may appear once in the token-binding document. A binding fixes one allowed mTLS SAN, tenant, subject and scope. The leaf client certificate must contain exactly one DNS or URI SAN and that value must match the binding.

## Required environment

The following variables have no production defaults except the two fixed ports; a missing or unsafe value aborts startup.

- Database: `AGENT_TRUST_SUPPLY_DATABASE_URL_FILE`, `AGENT_TRUST_SUPPLY_DATABASE_PASSWORD_FILE`, `AGENT_TRUST_SUPPLY_DATABASE_EXPECTED_ROLE`, `AGENT_TRUST_SUPPLY_DATABASE_CA_FILE`.
- Inbound TLS: `AGENT_TRUST_SUPPLY_TLS_CA_FILE`, `AGENT_TRUST_SUPPLY_TLS_CERTIFICATE_FILE`, `AGENT_TRUST_SUPPLY_TLS_PRIVATE_KEY_FILE`, `AGENT_TRUST_SUPPLY_CLIENT_IDENTITIES`.
- Listener: `AGENT_TRUST_SUPPLY_LISTEN_ADDRESS`, `AGENT_TRUST_SUPPLY_PORT=8093`, `AGENT_TRUST_SUPPLY_MANAGEMENT_LISTEN_ADDRESS`, `AGENT_TRUST_SUPPLY_MANAGEMENT_PORT=9103`.
- Runtime state: `AGENT_TRUST_SUPPLY_INSTANCE_ID`, `AGENT_TRUST_SUPPLY_EXECUTION_LEASE_SECONDS`, `AGENT_TRUST_SUPPLY_TOKEN_BINDINGS_FILE`, `AGENT_TRUST_SUPPLY_RECEIPT_KEYRING_FILE`.
- Evidence verification: `AGENT_TRUST_SUPPLY_EVIDENCE_KEYRING_FILE` and `AGENT_TRUST_SUPPLY_EVIDENCE_CLIENT_IDENTITY`. The identity is the exact single DNS/URI SAN in the outbound Evidence client certificate and must also be the `subject` of its `evidence:authority-event` token binding.
- Outbound mTLS: `AGENT_TRUST_SUPPLY_OUTBOUND_CA_FILE`, `AGENT_TRUST_SUPPLY_OUTBOUND_CERTIFICATE_FILE`, `AGENT_TRUST_SUPPLY_OUTBOUND_PRIVATE_KEY_FILE`.
- For each `COORDINATOR`, `REPOSITORY`, `SIGNER`, `SCANNER`, `SANDBOX`, `REVOCATION`, and `EVIDENCE`: `AGENT_TRUST_SUPPLY_<NAME>_ENDPOINT`, `AGENT_TRUST_SUPPLY_<NAME>_TOKEN_FILE`, `AGENT_TRUST_SUPPLY_<NAME>_READINESS_SCHEMA`.

Every dependency endpoint is a unique HTTPS origin root, every token file contains a unique physical token, redirects are disabled, outbound TLS is at least 1.3, and CA/certificate/key files are absolute regular non-symlink files. Private files must be single-link and readable only by the effective identity or its effective group.

Evidence outbox delivery uses only `POST /v1/evidence/authority-events`. It sends the persisted authority event ID and payload digest in headers and a shared `AuthorityEvidenceEventRequest` bound to the Canonical Action hash, final PEP evidence, ledger entry and fence. The request timestamps are persisted in the outbox, so a retry has the same request digest. The service accepts delivery only after validating the signed `SignedAuthorityEvidenceReceipt`, its embedded signed event, event key, source SAN, tenant/task/event/idempotency binding, payload hash, request digest and Evidence reference. The supply resource version is never submitted as an orchestrator task-state version.

## Readiness and recovery

`GET /ready` returns ready only when PostgreSQL and all seven typed outbound dependencies are ready with their exact configured readiness schemas. A failed signer, scanner, repository, sandbox, revocation feed or Evidence service therefore blocks admission.

`GET /v1/authoritative/supply-chain/releases` is the sole BFF/UI release-state source. It requires the same tenant in the mTLS/token binding, `X-AgentTrust-Tenant-Id`, and `tenant_id` query parameter. Pages contain at most 200 releases, an opaque continuation cursor, `authoritative=true`, a canonical `data_digest`, lifecycle and artifact summary digests, and up to 32 immutable Evidence receipt references per release. `data_digest` is the lowercase SHA-256 of the JCS serialization of the final response after removing only `data_digest`; therefore it covers `schema_version`, `tenant_id`, `authoritative`, `items`, and `next_cursor`. A BFF must verify and forward these values and must not reconstruct release state from Marketplace listings or browser cache.

For an expired execution lease, call the tenant-bound recovery route with `supply-chain:recover`. It changes only the durable command state to `UNKNOWN`. Inspect coordinator and downstream receipts, record reconciliation evidence, and issue a new canonical command only after determining whether the external effect occurred. Never edit terminal rows, reuse an idempotency key for different input, or replay an irreversible effect.

Quarantine blocks new admission immediately. Revocation records the immutable subject and impact digest and moves matching releases/installations to their terminal safety state. Rollback activates only a retained non-revoked exact version; it is not an escape from signature, approval or resource fencing. This authority accepts only the literal `production` environment. Approval recomputes the permission diff from the persisted current manifest and most recently approved production manifest; a mismatched caller diff or previous digest is denied, and a first release is compared with an empty baseline.

## Evidence boundary

Source, migration and local contract tests prove only the code path. Production certificate issuance, external publisher onboarding, external signing/HSM, scanner coverage, repository immutability, Linux sandbox isolation, multi-zone database/HA/DR, locked-retention Evidence delivery and sustained-load evidence remain `NOT_RUN` until performed in the named environment. Production certificates remain `NOT_ISSUED` without those artifacts.
