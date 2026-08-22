# Identity threat model

The workload credential authority is a separate production boundary. It never enables the
in-memory credential service in production. A credential is a random 256-bit bearer handle;
PostgreSQL stores only its lowercase SHA-256 digest. The safe signed binding receipt contains
that digest plus tenant, agent, task, step, action, policy decision, tool, credential profile,
operation, resource, target profile, `audience=tool-proxy`, the authoritative agent revocation
epoch, issue/expiry times, and `max_uses=1`. The raw handle exists only in the issuance response,
the tool-proxy consumption request, and the encrypted idempotency response envelope.

Issue and consume lock `(tenant, Idempotency-Key)` before reading or changing state. Issue writes
the credential row, immutable audit/outbox rows, and an AES-256-GCM encrypted exact response in
one transaction before returning. Consume locks the credential row, verifies the handle digest,
binding signature, claims digest, complete scope, latest agent epoch and all revocations, then
atomically changes remaining uses from one to zero. Concurrent uses therefore produce exactly one
new success. A lost successful response is replayed byte-equivalently from its protected envelope;
a different request digest using the same key is rejected.

TLS is restricted to 1.3 and requires a client certificate chaining to the configured CA. The
certificate must expose exactly one configured DNS or URI SAN. An opaque service token is bound to
that exact SAN, tenant and one exact scope (`credentials:issue`, `credentials:consume`, or
`credentials:revoke`). The consume scope is issued only to tool-proxy. Duplicate authorization,
tenant or idempotency headers fail closed. Common Name is never an identity source.

Pause freezes new issue requests but leaves already issued credentials subject to their normal
expiry and consumption rules. Task cancel, kill or revoke, plus credential, agent or tenant revoke,
terminally revoke affected live handles. Consumption rechecks revocation and task state while
holding the credential row lock. Audit and outbox payload constraints prohibit bearer, handle,
token and secret fields; Debug implementations redact handles and signatures. Readiness fails on
missing FORCE RLS, excessive grants, absent active signer, unverifiable live-credential keys, or a
missing response-envelope decryption key.

OIDC human/agent bootstrap remains a separate trust path: subjects are mapped to tenant/owner
server-side and custom tenant claims are ignored. Wrong issuer, audience, algorithm, key, time,
nonce, ownership, scope, epoch or signature always fails closed.
