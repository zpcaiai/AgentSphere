# Key rotation and emergency revocation

## Workload credential authority bootstrap

Run migrations through `migrations/manifest.txt`, then create a dedicated login with an external
secret. Do not put a password in the database URL. The following grant shape is the maximum
accepted by service readiness (replace the role name only):

```sql
CREATE ROLE agenttrust_identity_credential LOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, agenttrust_identity_credential;
REVOKE TEMP ON DATABASE agenttrust FROM PUBLIC, agenttrust_identity_credential;
GRANT CONNECT ON DATABASE agenttrust TO agenttrust_identity_credential;
GRANT USAGE ON SCHEMA public TO agenttrust_identity_credential;
GRANT SELECT ON agent_principals, credential_profiles,
  identity_credential_signing_keys TO agenttrust_identity_credential;
GRANT SELECT, INSERT, UPDATE ON credential_handles, identity_tenant_epochs,
  identity_task_lifecycle TO agenttrust_identity_credential;
GRANT SELECT, INSERT ON identity_revocations,
  identity_credential_idempotency TO agenttrust_identity_credential;
GRANT INSERT ON identity_credential_events,
  identity_credential_outbox TO agenttrust_identity_credential;
```

Provision exactly one `ACTIVE` Ed25519 public key row per configured tenant and issuer. Its public
key must match `AGENT_TRUST_IDENTITY_SIGNING_PRIVATE_KEY_FILE`; the service never writes key rows.
Mount all private files as regular, non-symlink files with `0400`, or `0440` only when the file GID
equals the process effective GID. Required configuration is:

- `AGENT_TRUST_IDENTITY_DATABASE_URL_FILE`: no embedded password; only
  `sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic`.
- `AGENT_TRUST_IDENTITY_DATABASE_PASSWORD_FILE` and
  `AGENT_TRUST_IDENTITY_DATABASE_CA_FILE`.
- `AGENT_TRUST_IDENTITY_DATABASE_EXPECTED_ROLE`.
- `AGENT_TRUST_IDENTITY_SIGNING_PRIVATE_KEY_FILE`, `AGENT_TRUST_IDENTITY_ISSUER`, and
  `AGENT_TRUST_IDENTITY_SIGNING_KEY_ID`.
- `AGENT_TRUST_IDENTITY_RESPONSE_KEYS_FILE`, validated by
  `schemas/identity/response-protection-keys.schema.json`.
- `AGENT_TRUST_IDENTITY_TOKEN_BINDINGS_FILE`, TLS CA/certificate/private key files, and the
  comma-separated exact DNS/URI SAN allowlist in `AGENT_TRUST_IDENTITY_CLIENT_IDENTITIES`.
- `AGENT_TRUST_IDENTITY_TOOL_PROXY_CLIENT_IDENTITY`: the one allowed DNS/URI SAN for
  `credentials:consume`; that SAN is rejected for issue/revoke bindings.

The data listener defaults to `127.0.0.1:8085`; the independent management readiness listener
defaults to `127.0.0.1:9095`. A deployment may bind management to an unspecified IP only behind a
management-only NetworkPolicy. `/ready` on the data listener still requires mTLS.

PEP calls `POST /v1/credentials/issue` with scope `credentials:issue`. Tool-proxy calls
`POST /v1/credentials/consume` with scope `credentials:consume`. Both send the opaque service token
in `Authorization: Bearer`, the canonical tenant in `X-AgentTrust-Tenant-Id`, and an HTTP
`Idempotency-Key` exactly equal to the body key. The consume body carries the raw workload handle,
safe binding receipt, tenant/agent/task/step/action/policy/tool/profile/operation/resource/target,
`audience=tool-proxy`, revocation epoch and claims digest. Binding signatures use key usage
`WORKLOAD_CREDENTIAL_BINDING`; consumption signatures use
`WORKLOAD_CREDENTIAL_CONSUMPTION`. Readiness responses use
`agenttrust.identity-credential-readiness.v1` and contain only `schema_version` plus `ready`.

## Credential signing-key rotation

1. Insert the new Ed25519 public key as `VERIFY_ONLY` for every configured tenant.
2. Mount the matching private seed and change the configured key ID during a controlled restart.
3. In one privileged transaction, demote the old `ACTIVE` row to `VERIFY_ONLY` and promote the new
   row to `ACTIVE`; the partial unique index forbids two active issuer keys.
4. Verify both readiness endpoints and issue/consume a canary through the real PEP and tool-proxy.
5. Retain the old row as `VERIFY_ONLY` until every credential signed by it is expired, consumed, or
   revoked. Readiness becomes 503 if a live credential references a revoked/missing key.
6. Mark the old key `REVOKED` only after the live-reference query is empty. A revoked key is
   terminal and cannot be restored.

## Idempotency response-envelope rotation

The response keyring has one active encryption key and up to seven decrypt-only historical keys.
Add the new key, make it active, and restart before retiring any old key. Readiness scans all
unscrubbed idempotency rows and returns 503 when a referenced key is missing. Exact issue replay
therefore survives process and node loss without storing a plaintext bearer.

Rows retain encrypted responses for seven days by default. After `replay_until`, a separately
controlled maintenance role may set only `response_ciphertext`, `response_nonce`, and
`encryption_key_id` to NULL. The immutable operation/request/response digests remain as a permanent
tombstone, so the same idempotency key can never issue or consume again; retries return
`IDENTITY_IDEMPOTENCY_REPLAY_EXPIRED`. Remove a historical key only after no non-NULL row references
it. Never delete idempotency rows or shorten `replay_until`.

## Credential emergency controls

Use the `credentials:revoke` mTLS/token binding and a unique `Idempotency-Key` for credential, task,
agent, or tenant revoke. Pause accepts no reason and freezes only new issue operations. Cancel,
kill, task revoke and all other revocations require a bounded reason code and synchronously mark
affected handles revoked before returning their durable event reference. Do not copy bearer handles,
service tokens, private keys, decrypted replay envelopes, or database passwords into incident or
acceptance evidence.

## OIDC and workload certificate rotation

1. Publish the new key in a versioned trust bundle before issuing with its `kid`.
2. Measure verifier refresh across Gateway, PEP, Proxy, and Sandbox.
3. Switch issuance, retain the old public key only through the maximum token TTL and bounded skew.
4. Remove the old key and bump the affected tenant/agent/task revocation epoch.
5. For compromise, revoke first, freeze new issuance, invalidate caches, scan credential-use events, and attach incident evidence.

The production verifier accepts only `RS256`/RSA, `ES256`/P-256, and
`EdDSA`/Ed25519 signing keys. It rejects symmetric/`none` algorithms,
duplicate `kid`, non-signing keys, stale JWKS snapshots, issuer/audience/`azp`
mismatch, missing nonce, unmapped subjects, and tenant or role escalation. Run
the bounded discovery/JWKS probe against the deployment issuer before rotating:

```sh
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/oidc-report.json oidc \
  --issuer https://idp.example/tenant --audience agenttrust-production
```

The report is a real-protocol preflight with `production_evidence=false`. A
rotation is production evidence only after the exact release/environment scope,
overlap window, failure test and recovery evidence are signed by the required
external reviewers.

Verify the workload client certificate and deployment CA independently; key
material is never copied into evidence:

```sh
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/mtls-report.json mtls \
  --host identity.service.example --port 443 \
  --ca-file /absolute/ca.pem --client-certificate /absolute/client.pem \
  --client-private-key /absolute/client.key
```
