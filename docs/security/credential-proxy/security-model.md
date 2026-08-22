# Credential Proxy security model

The production Proxy accepts only a Canonical-Action-derived `ExecutionAuthorization` v2. It
verifies the PEP issuer/key usage/signature/TTL/single-use contract and exact tenant, action hash,
ledger execution, digest-bound ledger event, fence, idempotency key, tool/version/snapshot/implementation, operation,
resource/version, canonical arguments, environment, target, executor and credential profile. It
then verifies the credential-authority binding receipt against the SHA-256 of the raw outer handle
and atomically consumes that handle over TLS 1.3 mTLS. The signed consumption receipt must bind the
same credential ID, claims digest, action, audience, revocation epoch and zero remaining uses.

The Registry boundary is online and fail closed. The Proxy verifies the signed complete ACTIVE
set, reconstructs every immutable `ResolvedToolSnapshot`, recomputes the canonical aggregate hash,
and rejects revision rollback, same-revision equivocation, revoked/missing versions, schema drift or
implementation digest drift. A discovered capability is never treated as authorization.

Before any target side effect, Postgres commits `PREPARED -> EXECUTING` with the upstream ledger
execution/fence plus a Proxy instance-owner UUID and bounded execution lease. Result, sanitized
audit and outbox become durable in one transaction. Exact retries replay only persisted SUCCEEDED
or FAILED outcomes. EXECUTING and UNKNOWN are never replayed; only lease-expired execution can be
crash-recovered to UNKNOWN. This is deliberately conservative because a timeout cannot prove that
an external target did not act.

Target secrets exist only in `SecretLease`, are exposed only to a fixed connector, zeroized on
drop, and revoked with a bounded retry on success, error and timeout. Vault returns a JSON `data`
object, but the signed profile names the one scalar `secret_field` allowed to become the target
bearer; the complete object is never sent. HTTP origins, public pinned addresses, methods, paths,
content type and Vault lease path come from a signed target profile. Redirects, ambient DNS,
credential-bearing URLs, percent/backslash path ambiguity, metadata/private/link-local IPs and
arbitrary TCP are rejected. Connection pools are isolated by tenant, credential profile and target.

Target output is capped at 1 MiB, recursively scrubbed for sensitive field names, exact lease
values, known credential formats and high-entropy opaque values, marked when it contains untrusted
prompt-like content, and only then checked against the signed output schema. Artifact references
must be content-addressed lowercase SHA-256 references. Raw target output and target credentials do
not enter the invocation table, audit event or outbox.

Git, database and industrial connector traits remain fixed-purpose boundaries: task branches and
safe paths, registered SQL templates/resource versions, and allowlisted compare-and-set writes.
They are code interfaces, not evidence of real Git/database/OPC UA compatibility. Linux isolation,
real target protocols, Vault/CA/IAM, HA/DR, sustained load and supervised physical writes remain
separate external gates until their named environments produce evidence.
