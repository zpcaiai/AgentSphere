# Production enterprise control authority

The Java control BFF is an authenticated ingress only. Every enterprise mutation is bound to one
verified human session by `agenttrust.signed-human-principal-assertion.v1`, normalized through the
shared Canonical Action IR implementation, durably admitted by the orchestrator, authorized by the
execution PEP, reserved/fenced by the ledger, and invoked through Tool Proxy. The BFF returns only
`agenttrust.enterprise-action-receipt.v1` with `execution_pending=true`; HTTP 202 is neither
business mutation success nor task completion.

The same binary exposes the executor route only to the exact Tool Proxy mTLS SAN and an independent
`enterprise:execute` token. It persists exact request/action/ledger/fence/resource-version/
idempotency/trace bindings under an advisory lock before setting `EXECUTING`. `EXECUTING` or
`UNKNOWN` is never replayed. The business mutation, resource-version CAS, safe result and outbox
commit atomically for database-only mutations. API-key issuance is intentionally more conservative:
the raw value is generated in the executor, HMAC-hashed for PostgreSQL, written once to a Vault KV
v2 path over TLS 1.3 mTLS, and then discarded. Only `vault-kv://...#vN` is returned. Any uncertainty
after the Vault request moves the execution to `UNKNOWN` for manual recovery; raw key material is
never returned through Tool Proxy, the BFF or browser.

Runtime configuration is entirely explicit:

- data `AGENT_TRUST_ENTERPRISE_LISTEN_ADDRESS`, `AGENT_TRUST_ENTERPRISE_PORT`
  (recommended `0.0.0.0:8449`); this listener is TLS 1.3 mTLS only
- management `AGENT_TRUST_ENTERPRISE_MANAGEMENT_LISTEN_ADDRESS`,
  `AGENT_TRUST_ENTERPRISE_MANAGEMENT_PORT` (recommended `0.0.0.0:9100`); it exposes only
  `GET /ready` with schema `agenttrust.enterprise-authority-readiness.v1`
- `AGENT_TRUST_ENTERPRISE_DATABASE_URL_FILE`, `...DATABASE_PASSWORD_FILE`,
  `...DATABASE_CA_FILE`, `...DATABASE_EXPECTED_ROLE`
  (`enterprise_authority_application_role`); the URL must use `sslmode=verify-full` and the exact
  `-csearch_path=pg_catalog,public` option
- server `...TLS_CA_FILE`, `...TLS_CERTIFICATE_FILE`, `...TLS_PRIVATE_KEY_FILE`
- `...CLIENT_IDENTITIES`, `...TOKEN_BINDINGS_FILE`
- shared `AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE`, `...AUDIENCE`
- outbound `...OUTBOUND_CA_FILE`, `...OUTBOUND_CERTIFICATE_FILE`,
  `...OUTBOUND_PRIVATE_KEY_FILE`
- `...ORCHESTRATOR_ENDPOINT`, `...ORCHESTRATOR_TOKEN_FILE`
- `...VAULT_ENDPOINT`, `...VAULT_TOKEN_FILE`, `...VAULT_KV_MOUNT`,
  `...VAULT_KV_PREFIX`, `...API_KEY_PEPPER_FILE`
- `...AGENT_INSTANCE_ID`, `...ORGANIZATION_ID`, `...AGENT_VERSION`, `...REGION`,
  `...TOOL_ID`, `...TOOL_VERSION`, `...EXECUTOR_CREDENTIAL_PROFILE`,
  `...SERVICE_SUBJECT`, `...MAXIMUM_AUTHENTICATION_AGE_SECONDS`

The database role is externally provisioned with no inheritance, superuser, database-create,
role-create, replication, temporary-schema or `BYPASSRLS` capabilities. Migration
`0036_01_07_production_enterprise_authority.sql` forces RLS on ingress/replay/execution/version/
outbox tables and guards immutable bindings and state transitions. The Java BFF role must not hold
business-table write grants.

After every table privilege has first been revoked, the migration runner grants
`enterprise_authority_application_role` only `USAGE` on `public`; `SELECT,INSERT` on
`enterprise_principal_assertion_replay`, `enterprise_action_ingress`,
`enterprise_resource_versions`, and `enterprise_authority_executions`; `INSERT` only on
`enterprise_authority_outbox`; column `UPDATE` on
`enterprise_action_ingress(state,receipt,updated_at)`,
`enterprise_resource_versions(resource_version,action_hash,ledger_execution_id,fence_digest,updated_at)`,
and `enterprise_authority_executions(state,safe_result,safe_result_digest,stable_error,updated_at)`;
plus the least business-table grants used by the eight operations: `SELECT,INSERT` on tenants,
organizations, projects, integrations, quota usage, cost usage, API keys and admin actions, with
column `UPDATE` only for quota counters and API-key revocation. It has no DELETE, TRUNCATE,
REFERENCES, TRIGGER, sequence, schema CREATE or function EXECUTE grant. The outbox publisher is a
separate role if publication-column updates are enabled.

The Java BFF adds exactly three deployment values: `AGENT_TRUST_ENTERPRISE_AUTHORITY_ENDPOINT`,
`AGENT_TRUST_ENTERPRISE_AUTHORITY_READINESS_SCHEMA` (the schema above), and the private token file
`AGENT_TRUST_ENTERPRISE_MUTATE_TOKEN_FILE`. They populate the `enterprise` endpoint/readiness key
and the independent `enterprise.mutate` operation-token key. The BFF must not receive the executor
token, Vault token, API-key pepper or enterprise database credentials.

Tool Registry must publish the exact versioned enterprise mutation tool and signed Tool Proxy
profile: executor `enterprise-control-executor`, target `enterprise-control-authority`, credential
profile `enterprise-executor`, `.svc.cluster.local` host with fixed RFC1918/ULA pins, and POST
`/v1/enterprise/mutations` only. This private control-plane exception does not permit loopback,
link-local, metadata, arbitrary DNS, methods or paths.

Final task completion still requires the existing Evidence authority to produce and verify its
signed execution receipt. Neither the ingress acceptance evidence nor this service's outbox digest
can substitute for that receipt.

Source presence and local static checks do not prove real CA/IdP, Vault, PostgreSQL RLS posture,
Temporal multi-zone durability, PEP/ledger/Tool Proxy integration, failure injection, HA/DR, load,
customer acceptance or certification. Those gates remain `NOT_RUN`/`NOT_ISSUED` without external
evidence.
