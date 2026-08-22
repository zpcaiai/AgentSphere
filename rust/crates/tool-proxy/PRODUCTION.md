# Production Tool Proxy

The production binary is `agenttrust-tool-proxy-service`. It has no in-memory Registry,
credential-consumption, secret, or invocation-store fallback. The data listener requires TLS
1.3, a trusted client certificate containing exactly one configured DNS or URI SAN, and an
opaque bearer whose SHA-256 is bound to that SAN, tenant, subject and `tools:execute` scope.
`GET /ready` is available on the mTLS data listener and on the separate management listener;
the latter must remain reachable only by the kubelet/management network.

## Durable execution boundary

For `(tenant_id, Idempotency-Key)` the database stores the request, authorization, ledger,
fence and target-profile digests, never the raw workload credential or target lease. Every
executing row is fenced to the canonical UUID in `AGENT_TRUST_TOOL_PROXY_INSTANCE_ID` and has a
lease longer than the bounded target timeout. Only a lease-expired row can be reconciled to
`UNKNOWN`; another live replica cannot finalize it. The only valid transitions are:

```
PREPARED -> EXECUTING(owner, lease) -> SUCCEEDED
        \-> FAILED                    \-> UNKNOWN
```

PEP signature, current signed ACTIVE Registry snapshot, JSON arguments, fixed target and the
exactly-idempotent credential consumption are checked while PREPARED. `EXECUTING` is committed
before acquiring a Vault lease or invoking a target. A deterministic PREPARED rejection becomes
FAILED. Every failure after EXECUTING becomes UNKNOWN. SUCCEEDED stores the scrubbed result,
credential-consumption receipt, audit event and outbox record in one transaction before the HTTP
response. STARTED, REJECTED, SUCCEEDED and UNKNOWN audit/outbox records are committed with their
state transition. Retries replay SUCCEEDED/FAILED exactly; EXECUTING and UNKNOWN never invoke the
target. Startup and the bounded reconciler move only lease-expired EXECUTING rows to UNKNOWN.

## Mandatory files and environment

All file paths are absolute. Private files must be regular non-symlinks readable as `0400`, or
`0440` only when the file GID is the process effective GID. Public trust/config files reject
group/other writes. Database URLs contain no password and must have exactly
`sslmode=verify-full&options=-csearch_path=pg_catalog,public`.

- `AGENT_TRUST_TOOL_PROXY_DATABASE_URL_FILE`
- `AGENT_TRUST_TOOL_PROXY_DATABASE_PASSWORD_FILE`
- `AGENT_TRUST_TOOL_PROXY_DATABASE_CA_FILE`
- `AGENT_TRUST_TOOL_PROXY_DATABASE_EXPECTED_ROLE` (the exact externally provisioned LOGIN role)
- `AGENT_TRUST_TOOL_PROXY_INSTANCE_ID` (canonical UUID; use the immutable Pod UID)
- `AGENT_TRUST_TOOL_PROXY_TLS_CA_FILE`, `...TLS_CERTIFICATE_FILE`, `...TLS_PRIVATE_KEY_FILE`
- `AGENT_TRUST_TOOL_PROXY_CLIENT_IDENTITIES`, `...TOKEN_BINDINGS_FILE`
- `AGENT_TRUST_TOOL_PROXY_OUTBOUND_TLS_CERTIFICATE_FILE`, `...OUTBOUND_TLS_PRIVATE_KEY_FILE`
- `AGENT_TRUST_TOOL_PROXY_VERIFICATION_KEYS_FILE`
- `AGENT_TRUST_TOOL_PROXY_REGISTRY_ENDPOINT`, `...REGISTRY_CA_FILE`, `...REGISTRY_TOKEN_FILE`
- `AGENT_TRUST_TOOL_PROXY_CREDENTIAL_AUTHORITY_ENDPOINT`, `...CREDENTIAL_AUTHORITY_CA_FILE`, `...CREDENTIAL_AUTHORITY_TOKEN_FILE`
- `AGENT_TRUST_TOOL_PROXY_VAULT_ENDPOINT`, `...VAULT_CA_FILE`, `...VAULT_TOKEN_FILE`
- `AGENT_TRUST_TOOL_PROXY_TARGET_CA_FILE`, `...TARGET_PROFILES_FILE`

The verification keyring may keep old PEP, credential-authority and Registry keys during a
rotation, but must contain at least one key for every mandatory usage. Readiness fails if the
current Registry signed snapshot cannot be verified or the credential authority is unavailable.
The signed target profile pins tenant, HTTPS origin, public IP addresses, allowed operation/path,
target credential profile, Vault lease path and the single Vault `data.secret_field` used as the
target bearer. The whole Vault response is never forwarded. Each
`tenant + credential_profile + target_profile` owns a separate reqwest client and connection pool.
For every fixed HTTPS target call the proxy itself sets `X-AgentTrust-Tenant-Id`,
`X-AgentTrust-Action-Hash`, `X-AgentTrust-Authorization-Id`,
`X-AgentTrust-Authorization-Digest`, `X-AgentTrust-Policy-Decision-Id`,
`X-AgentTrust-Ledger-Execution-Id`,
`X-AgentTrust-Ledger-Entry-Id`, `X-AgentTrust-Ledger-Entry-Digest`,
`X-AgentTrust-Policy-Decision-Digest`, `X-AgentTrust-Authorization-Evidence-Ref`,
`X-AgentTrust-Authorization-Evidence-Digest`, `X-AgentTrust-Fence-Digest`, `X-AgentTrust-Resource-Version`,
`X-AgentTrust-Trace-Id`, and `Idempotency-Key` from the already verified authorization,
ledger reservation plus its digest-bound outbox event, and canonical action. Target arguments cannot choose or override these
headers. A production target executor must persist and compare every binding before applying a
side effect; the bearer lease alone is insufficient authorization.
Redirects, ambient DNS, embedded URL credentials,
plaintext endpoints, private/link-local/metadata addresses, arbitrary paths and arbitrary TCP are
not allowed. Percent-encoded/backslash path ambiguity and methods outside GET/POST/PUT/PATCH/DELETE
are rejected. Rotation is: add verification key, publish/re-sign dependent objects, roll all
consumers, observe readiness, then remove the old key.

Private-network exceptions are limited to four exact signed control-plane profiles:
`enterprise-control-executor` + `enterprise-control-authority` + `enterprise-executor`,
`policy-administration-executor` + `policy-administration-authority` +
`policy-administration-executor`, `incident-release-executor` +
`incident-release-authority` + `incident-release-executor`, and
`pack-marketplace-executor` + `pack-marketplace-authority` +
`pack-marketplace-executor`. Each profile is bound to its exact Service DNS name on port 443,
RFC1918/ULA pins (never loopback/link-local), and exactly one POST route respectively:
`/v1/enterprise/mutations`, `/v1/policies/executions`, `/v1/incidents/executions`, or
`/v1/packs/executions`. These exceptions do not relax SSRF policy for any other connector,
target, credential profile, hostname, port, method, or path.

The Registry client first verifies the Ed25519 signature, then downloads the complete ACTIVE set,
recomputes every immutable tool snapshot hash and the canonical aggregate Registry snapshot hash,
and rejects revision rollback or a changed digest at the same revision. The verified aggregate is
bounded to 4 MiB and cached for at most 64 tenants; each execution still performs an online signed
authoritative-set check, so a revoke cannot be hidden by an indefinitely stale local allow.

## Vault and failure handling

Vault and all control-plane HTTP clients use TLS 1.3, an explicit CA, client identity, bounded
timeouts and no redirects. Leases are at most 15 minutes and are revoked on connector success,
error and timeout before any result is persisted. A revoke failure is UNKNOWN because the target
may have acted; the Vault lease ID remains retained for retry/incident handling instead of being
forgotten on the failed revoke. Target and API responses are capped at 1 MiB, schema-validated and
scrubbed for sensitive keys, exact lease values, known credential formats and high-entropy opaque
values before they can enter audit or outbox payloads. Artifact references are accepted only as
`artifact://sha256/<lowercase digest>`.

The migration creates no database role and grants no application privileges. The production
migration runner must provision a distinct LOGIN role with `NOINHERIT`, no superuser/role/database/
replication/BYPASSRLS capabilities, no TEMP or public-schema CREATE, and only SELECT/INSERT/UPDATE
on invocations plus INSERT on audit/outbox. Runtime startup verifies the exact role and posture.

## External evidence boundary

The source and local static checks do not prove real Vault, enterprise CA, Postgres FORCE-RLS,
Registry/PEP/credential-authority rotation, target protocol compatibility, crash injection,
HA/DR, sustained load, physical write supervision, customer acceptance or independent
certification. Keep those gates `NOT_RUN`/`NOT_ISSUED` until evidence is captured in their own
authorized environments. Development adapters and mock backends are test fixtures only and are
not accepted by the production binary.
