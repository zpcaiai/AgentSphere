# Credential Proxy operations

Monitor active lease count, provider latency/failure, connector saturation, timeout/Kill, redaction count, and output-schema rejection by tenant-hashed dimensions. A provider outage fails high-risk requests closed. On exposure, revoke lease/task/tenant epoch, stop the connector, rotate the target credential, scan sanitized audit hashes and protected raw artifact storage, and attach incident evidence. Raw responses must never reach normal Trace or logs.

The production data endpoint is TLS 1.3 mTLS on port `8086`; its caller needs a distinct opaque
token binding for `tools:execute`. The management `/ready` endpoint defaults to port `9096` and
must be kubelet/management-network only. Readiness verifies the external LOGIN database role,
FORCE RLS, PEP/credential/Registry keyrings, the signed current Registry aggregate and credential
authority availability. A Pod must inject its immutable UID as
`AGENT_TRUST_TOOL_PROXY_INSTANCE_ID`; a deployment name or replica ordinal is not a safe fence.

Inspect uncertain outcomes without retrying the target:

```sql
BEGIN;
SELECT set_config('app.tenant_id', :'tenant_id', true);
SELECT idempotency_key, ledger_execution_id, fence_digest, action_hash,
       state, execution_owner, execution_lease_until, stable_error, updated_at
FROM tool_proxy_invocations
WHERE tenant_id = :'tenant_id'::uuid AND state IN ('EXECUTING','UNKNOWN')
ORDER BY updated_at;
ROLLBACK;
```

An EXECUTING row is owned until `execution_lease_until`. Do not manually change it. The bounded
reconciler records an UNKNOWN audit/outbox event only after expiry. Resolve UNKNOWN by querying the
target's authoritative operation ID or verification API, then complete the upstream ledger/manual
recovery process; never create a new idempotency key to repeat the action.

The migration creates no role. Provision a distinct LOGIN role outside the migration with
`NOINHERIT`, no privileged flags, no TEMP and no public-schema CREATE; grant only
SELECT/INSERT/UPDATE on `tool_proxy_invocations` and INSERT on `tool_proxy_audit_events` and
`tool_proxy_outbox`. Keep `row_security=on` and the exact `search_path=pg_catalog,public` URL option.

`VaultTargetSecretProvider` maps a fixed approved profile and target to a Vault
dynamic-credential path, bounds lease TTL to 900 seconds, returns the secret in
a zeroizing/redacted container, tracks the opaque lease ID, and revokes the
lease with one bounded retry when the tool call finishes. The signed mapping must name the single
Vault `data.secret_field` to inject; all other response fields remain internal. The supplied HTTP client must be deployment
configured with the enterprise CA and workload client identity; arbitrary
target URLs and raw long-lived credentials are not accepted by the provider.

Before enablement, exercise health, self-lookup, issuance and immediate revoke
with a least-privilege probe token supplied only by environment reference:

```sh
AGENTTRUST_VAULT_PROBE_TOKEN='deployment-injected' \
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/vault-report.json vault \
  --endpoint https://vault.service.example \
  --token-env AGENTTRUST_VAULT_PROBE_TOKEN \
  --dynamic-lease-path database/creds/agenttrust-probe \
  --maximum-lease-seconds 900
```

The probe revokes its lease and records only counts/digests. Do not promote a
local or operator-created report to production evidence; bind it to the release
scope with the external-assurance verifier.
