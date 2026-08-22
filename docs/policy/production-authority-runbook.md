# Policy Administration production authority

The production service is `agenttrust-policy-admin-service`. It listens on TLS/mTLS data port
`8090` and management port `9101`. Both listeners return the exact readiness contract
`agenttrust.policy-admin-readiness.v1` with the fields `schema_version`, `ready`,
`database_ready`, `signing_key_ready`, and `pep_activation_ready`. The management listener must remain cluster-internal;
the data listener requires a client certificate containing exactly one allow-listed DNS or URI
SAN. CommonName is never accepted.

## Security path

`POST /v1/policies/actions` requires `policy:mutate`, a canonical tenant header, a unique
idempotency key, and an Ed25519 human-principal assertion bound to the exact body, method, path,
tenant, SAN, service subject, route scope, and idempotency key. The authority validates the human
role, creates Canonical Action IR, and submits it to the durable orchestrator. It does not mutate
policy tables.

After PEP authorization and ledger admission, the runtime calls
`POST /v1/policies/executions` with the separate `policy:execute` credential and the exact action
hash, ledger execution UUID, fence digest, resource version, idempotency key, and trace ID. The
executor locks the tenant resource version, performs one lifecycle transition, advances the
version by exactly one, and atomically writes immutable local evidence and an evidence outbox
record. `GET /v1/authoritative/policies` uses the independent `policy:query` scope and keyset
pagination. A token hash may appear in only one SAN/tenant/scope binding.

Supported operations are `CREATE_DRAFT`, `VALIDATE`, `SIMULATE`, `SHADOW_EVALUATE`,
`IMPACT_ANALYZE`, `APPROVE`, `SIGN`, `PROMOTE`, `ROLLBACK`, `DEPRECATE`, `CREATE_EXCEPTION`, and
`REVOKE_EXCEPTION`. Signing requires a successful static analysis, a side-effect-free
simulation, and two distinct approving reviewers other than the author. The Ed25519 bundle JSON,
source digest, analysis digest, signature, key ID, and signing time are immutable. Promotions and
rollbacks refer only to a bundle digest. Environment order is `DEV` to `STAGING` to `CANARY` to
`PRODUCTION`; skipping a stage fails closed.

`PROMOTE` and `ROLLBACK` first commit a tenant/environment-bound `PENDING` activation intent and
promotion record, then call the PEP outside the database transaction with the stable
`policy-activation:{command_id}` idempotency key. The PEP verifies the immutable bundle against
its ACTIVE Ed25519 policy-bundle keyring, persists its own claim, and calls the authoritative PDP
with the same key. Only an exact signed PDP acknowledgement may atomically advance the PEP active
mapping and write activation evidence/outbox. Policy Administration independently verifies the
signed PEP acknowledgement before a second transaction marks the promotion `ACTIVE` and the
execution `SUCCEEDED`. A response loss is replayed exactly; timeout or ambiguity remains
`UNKNOWN`/`PENDING_ACTIVATION`. A unique unresolved tenant/environment gate prevents a later
activation from passing an unresolved one.

The Policy Studio reads authoritative source revisions, analyses, reviews, simulations/shadow
evaluations, impact reports, promotion history, and exceptions from the seven bounded routes below
`/v1/authoritative/policies/{policy_id}`. They all use `policy:query`. Exception creation requires
two approval IDs, an owner distinct from the issuer, bounded scope, a reason digest, non-empty
compensating controls, and expiry within 30 days. A tenant-scoped 30-second sweeper makes due
exceptions unusable and atomically emits expiry evidence; revocation and expiry are mutually
exclusive terminal states.

## Required environment and secret files

The following values are required. Variables ending in `_FILE` must be absolute, regular,
bounded files. Passwords, tokens, TLS private keys, and the 32-byte Ed25519 signing seed must use
private file permissions.

- Database: `AGENT_TRUST_POLICY_DATABASE_URL_FILE`,
  `AGENT_TRUST_POLICY_DATABASE_PASSWORD_FILE`, `AGENT_TRUST_POLICY_DATABASE_CA_FILE`, and
  `AGENT_TRUST_POLICY_DATABASE_EXPECTED_ROLE`.
- Inbound TLS: `AGENT_TRUST_POLICY_TLS_CA_FILE`,
  `AGENT_TRUST_POLICY_TLS_CERTIFICATE_FILE`, `AGENT_TRUST_POLICY_TLS_PRIVATE_KEY_FILE`, and
  `AGENT_TRUST_POLICY_CLIENT_IDENTITIES`.
- Route credentials and human identity: `AGENT_TRUST_POLICY_TOKEN_BINDINGS_FILE`,
  `AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE`, `AGENT_TRUST_HUMAN_PRINCIPAL_AUDIENCE`,
  `AGENT_TRUST_POLICY_SERVICE_SUBJECT`, and
  `AGENT_TRUST_POLICY_MAXIMUM_AUTHENTICATION_AGE_SECONDS`.
- Orchestrator mTLS: `AGENT_TRUST_POLICY_OUTBOUND_CA_FILE`,
  `AGENT_TRUST_POLICY_OUTBOUND_CERTIFICATE_FILE`,
  `AGENT_TRUST_POLICY_OUTBOUND_PRIVATE_KEY_FILE`,
  `AGENT_TRUST_POLICY_ORCHESTRATOR_ENDPOINT`, and
  `AGENT_TRUST_POLICY_ORCHESTRATOR_TOKEN_FILE`.
- Canonical Action identity: `AGENT_TRUST_POLICY_AGENT_INSTANCE_ID`,
  `AGENT_TRUST_POLICY_ORGANIZATION_ID`, `AGENT_TRUST_POLICY_AGENT_VERSION`,
  `AGENT_TRUST_POLICY_REGION`, `AGENT_TRUST_POLICY_TOOL_ID`,
  `AGENT_TRUST_POLICY_TOOL_VERSION`, and
  `AGENT_TRUST_POLICY_EXECUTOR_CREDENTIAL_PROFILE`.
- Bundle signing: `AGENT_TRUST_POLICY_BUNDLE_SIGNING_KEY_ID` and
  `AGENT_TRUST_POLICY_BUNDLE_SIGNING_PRIVATE_KEY_FILE`.
- PEP activation: `AGENT_TRUST_POLICY_PEP_ACTIVATION_ENDPOINT` (exact path
  `/v1/policies/activations`), `AGENT_TRUST_POLICY_PEP_ACTIVATION_TOKEN_FILE`, and
  `AGENT_TRUST_POLICY_PEP_ACTIVATION_VERIFYING_KEY_FILE`. The outbound certificate SAN must have a
  tenant-bound `pep:policy-activate` token entry at the PEP.
- Listeners: `AGENT_TRUST_POLICY_LISTEN_ADDRESS`, `AGENT_TRUST_POLICY_PORT`,
  `AGENT_TRUST_POLICY_MANAGEMENT_LISTEN_ADDRESS`, and
  `AGENT_TRUST_POLICY_MANAGEMENT_PORT`.

The PEP separately requires `AGENT_TRUST_PEP_POLICY_BUNDLE_KEYRING_FILE`. Its authority-bindings
document must contain signed `pdp_activation` configuration for exact endpoint
`/v1/policies/activations`, scope `pdp:policy-activate`, and key usage
`PDP_POLICY_ACTIVATION_ACK`. The keyring projects absolute Ed25519 public-key files with explicit
ACTIVE/RETIRED/REVOKED status and validity windows. There is no production bundle allowlist or
bootstrap authorization fallback: pre-approval, pre-execution, and governance calls require the
current tenant/deployment active digest from `pep_active_policy_bundles`, and reject a PDP response
whose digest or policy version differs.

The database URL must use `postgres` or `postgresql`, contain the exact expected role as the user,
omit a password, select one canonical database path, and contain only
`sslmode=verify-full&options=-csearch_path=pg_catalog,public`. Startup rejects superuser,
`BYPASSRLS`, inheritance, schema-create, database-temp, unsafe search paths, DELETE authority, or
evidence rewrite authority.

## Database grants

Provision `agenttrust_policy_admin` as `LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB
NOCREATEROLE NOREPLICATION`; revoke `CREATE` on schema `public` and `TEMP` on the database. All
fifteen policy tables use `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, and the exact
transaction-local `app.tenant_id` predicate.

Grant `SELECT, INSERT` on `policy_sources`, `policy_analysis_results`,
`policy_simulation_runs`, `policy_impact_reports`, `policy_reviews`, `policy_bundles`, `policy_exceptions`,
`policy_promotions`, `policy_resource_versions`, `policy_principal_assertion_replay`,
`policy_action_ingress`, `policy_authority_executions`, `policy_activation_intents`, and
`policy_evidence_events`. Grant only
`INSERT` on `policy_evidence_outbox`. Add these column grants and no broader table UPDATE:

- `policy_sources(lifecycle_state, updated_at)`
- `policy_bundles(status, deprecated_at)`
- `policy_exceptions(revoked_at, revocation_reason_digest, expired_at)`
- `policy_promotions(state, completed_at)`
- `policy_resource_versions(resource_version, action_hash, ledger_execution_id, fence_digest,
  updated_at)`
- `policy_action_ingress(state, receipt, updated_at)`
- `policy_authority_executions(state, safe_result, safe_result_digest, stable_error, updated_at)`
- `policy_activation_intents(state, claim_owner, claim_expires_at, acknowledgement_digest,
  acknowledgement, updated_at, activated_at)`

Grant no DELETE, TRUNCATE, REFERENCES, TRIGGER, sequence, function, schema-create, or database-temp
privileges. An external evidence dispatcher uses a separate role to read and acknowledge the
outbox; the Policy authority cannot mark its own evidence as published.

## Failure and recovery

If the orchestrator times out after admission, return `POLICY_OUTCOME_UNKNOWN`; retry the same
idempotency key and exact body. Never submit a new key until the durable admission result is
reconciled. A changed body, assertion JTI binding, ledger ID, action hash, fence, or resource
version is a conflict. A partially promoted environment remains on its prior signed snapshot;
the PAP being unavailable never changes the PEP snapshot. If the PEP call or response is
uncertain, retry the exact command after the claim lease; do not issue another tenant/environment
activation while the intent is `UNKNOWN`. Roll back by submitting an authorized
`ROLLBACK` command naming a previously signed, non-deprecated bundle digest. Database or signing
key readiness failure removes the Pod from service and does not create a development bypass.
