# Pack Marketplace production authority

The production binary is `agenttrust-pack-marketplace-service`. The data listener is TLS 1.3
with a required client certificate whose leaf certificate contains exactly one allowlisted DNS or
URI SAN. Bearer credentials are unique across SAN, tenant, and scope.

## Routes and fixed scopes

| Route | Scope | Purpose |
|---|---|---|
| `POST /v1/packs/actions` | `packs:mutate` | Human publisher, listing, install, activation, upgrade, rollback, and revocation command. Returns a 202 action receipt and never writes business state. |
| `POST /v1/packs/executions` | `packs:execute` | Runtime-only fenced mutation after Canonical Action IR, PEP, ledger, and authorization evidence reference plus digest. |
| `GET /v1/authoritative/packs` | `packs:read` | Tenant catalog, listing, installation, and lifecycle facts under FORCE RLS. |
| `GET /ready` | mTLS only | Data-listener readiness. Management listener exposes the same path only. |

The three scopes require distinct token SHA-256 values. Installation is always
`PENDING_APPROVAL`; install only reaches `INSTALLED`; activation is environment-specific. Even a
production `ACTIVE` installation never issues a credential and never bypasses PEP, sandbox, or
evidence controls for a task.

## Required environment

- Database: `AGENT_TRUST_MARKETPLACE_DATABASE_URL_FILE`,
  `AGENT_TRUST_MARKETPLACE_DATABASE_PASSWORD_FILE`,
  `AGENT_TRUST_MARKETPLACE_DATABASE_CA_FILE`,
  `AGENT_TRUST_MARKETPLACE_DATABASE_EXPECTED_ROLE`.
- Inbound TLS: `AGENT_TRUST_MARKETPLACE_TLS_CA_FILE`,
  `AGENT_TRUST_MARKETPLACE_TLS_CERTIFICATE_FILE`,
  `AGENT_TRUST_MARKETPLACE_TLS_PRIVATE_KEY_FILE`,
  `AGENT_TRUST_MARKETPLACE_CLIENT_IDENTITIES`.
- Outbound orchestrator mTLS: `AGENT_TRUST_MARKETPLACE_OUTBOUND_CA_FILE`,
  `AGENT_TRUST_MARKETPLACE_OUTBOUND_CERTIFICATE_FILE`,
  `AGENT_TRUST_MARKETPLACE_OUTBOUND_PRIVATE_KEY_FILE`,
  `AGENT_TRUST_MARKETPLACE_ORCHESTRATOR_ENDPOINT`,
  `AGENT_TRUST_MARKETPLACE_ORCHESTRATOR_TOKEN_FILE`.
- Trust material: `AGENT_TRUST_MARKETPLACE_TOKEN_BINDINGS_FILE`,
  `AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE`,
  `AGENT_TRUST_HUMAN_PRINCIPAL_AUDIENCE`,
  `AGENT_TRUST_MARKETPLACE_RELEASE_GATE_KEYRING_FILE`,
  `AGENT_TRUST_MARKETPLACE_RELEASE_GATE_ID`.
- Subjects: `AGENT_TRUST_MARKETPLACE_INGRESS_SUBJECT`,
  `AGENT_TRUST_MARKETPLACE_EXECUTOR_SUBJECT`,
  `AGENT_TRUST_MARKETPLACE_QUERY_SUBJECT`.
- Canonical action identity: `AGENT_TRUST_MARKETPLACE_AGENT_INSTANCE_ID`,
  `AGENT_TRUST_MARKETPLACE_ORGANIZATION_ID`, `AGENT_TRUST_MARKETPLACE_AGENT_VERSION`,
  `AGENT_TRUST_MARKETPLACE_REGION`, `AGENT_TRUST_MARKETPLACE_TOOL_ID`,
  `AGENT_TRUST_MARKETPLACE_TOOL_VERSION`,
  `AGENT_TRUST_MARKETPLACE_EXECUTOR_CREDENTIAL_PROFILE`.
- Network: `AGENT_TRUST_MARKETPLACE_LISTEN_ADDRESS`,
  `AGENT_TRUST_MARKETPLACE_PORT` (8090),
  `AGENT_TRUST_MARKETPLACE_MANAGEMENT_LISTEN_ADDRESS`,
  `AGENT_TRUST_MARKETPLACE_MANAGEMENT_PORT` (9101).
- Assertion freshness: `AGENT_TRUST_MARKETPLACE_MAXIMUM_AUTHENTICATION_AGE_SECONDS`.

Secrets and private keys must be absolute, regular, non-symlink files with private permissions.
The PostgreSQL URL contains no password and must use `sslmode=verify-full` plus
`options=-csearch_path=pg_catalog,public` exactly.

## Database role

Use a `NOINHERIT LOGIN` role such as `agenttrust_pack_marketplace` with `row_security=on` and
`search_path=pg_catalog, public`. It has no superuser, BYPASSRLS, create database/role, replication,
schema create, database TEMP, routine execute, DELETE, TRUNCATE, REFERENCES, or TRIGGER privilege.

Grant `SELECT, INSERT` on the 13 mutable/domain `marketplace_*` tables from migration
`0036_01_09_production_pack_marketplace.sql`. Grant only `INSERT` (never `SELECT`) on
`marketplace_evidence_events` and `marketplace_evidence_outbox`. Grant column-scoped `UPDATE`
only for:

- `marketplace_publishers(trust_status,verified_by,verified_at,revoked_at,updated_at)`;
- `marketplace_publisher_keys(status,revoked_at)`;
- `marketplace_tenant_catalog(control_plane_version,region,entitlements,allowed_compatibility,minimum_publisher_trust,maximum_risk,configured_by,updated_at)`;
- `marketplace_releases(review_status,reviewed_by,review_digest,published_at,revoked_at,updated_at)`;
- `marketplace_installations(state,approved_by,approval_digest,artifact_receipt_digest,previous_installation_id,production_certificate_digest,deactivation_reason_digest,approved_at,installed_at,activated_at,deactivated_at,revoked_at,updated_at)`;
- `marketplace_upgrade_plans(state,rollback_reason_digest,completed_at,rolled_back_at,updated_at)`;
- `marketplace_resource_versions(resource_version,action_hash,policy_decision_id,ledger_entry_id,ledger_execution_id,fence_digest,updated_at)`;
- `marketplace_action_ingress(state,receipt,updated_at)`;
- `marketplace_authority_executions(state,safe_result,safe_result_digest,stable_error,updated_at)`.

Evidence events and the Evidence outbox are insert-only for this authority. Delivery workers use a
separate role; the service cannot mark its own outbox rows as published.

## Evidence boundary

Local schema parsing or unit tests do not prove a production IdP, mTLS CA, PostgreSQL HA,
orchestrator, PEP, ledger, Evidence/WORM delivery, release signing key custody, or multi-zone
revocation propagation. Keep those gates `NOT_RUN` until the named external evidence exists.
