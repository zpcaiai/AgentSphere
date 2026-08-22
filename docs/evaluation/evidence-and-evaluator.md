# Evidence and evaluator operations

Every security-relevant task event is appended to a per-task Ed25519 hash chain with a monotonic
sequence. Tool arguments and secrets are never span attributes; traces carry hashes, stable IDs and
approved safe summaries. Artifacts are content-addressed and store media type, classification,
retention and access policy. A task may enter `COMPLETED` only after the common hard gates and a
domain evaluator produce a signed, referenced result.

Offline verification:

```sh
cargo run -p agent-trust-evidence-evaluator --bin verify-evidence -- \
  evidence-package.json audit-key-2026 BASE64URL_ED25519_PUBLIC_KEY
```

Any missing, reordered or changed event fails the package hash/chain/signature checks. Artifact bytes
must additionally be fetched through the governed artifact store and compared with each content
hash before relying on the artifact. Python plugins run only behind an approved sandbox launcher;
their executable digest and signed manifest are rechecked on every call. Timeout, crash, malformed
output or a claimed PASS without hard-gate evidence becomes `NEEDS_HUMAN` or `FAIL`, never PASS.

Calibration baselines and real object-store/OTel evidence are external release gates and are not
established by local unit tests.

## Production Evidence Authority

`agenttrust-evidence-service` exposes TLS 1.3/mTLS on `8087` and a management-only `/ready` on
`9097` (loopback or wildcard bind; wildcard requires the production NetworkPolicy to admit only
kubelet/node probe CIDRs). Its production write path validates the exact tenant, ledger execution/fence,
PEP authorization/digest, request idempotency key and result hash before atomically inserting the
signed event, chain head, execution receipt and outbox record. A successful tool invocation is
still only an execution fact; task completion remains owned by the orchestrator and requires a
separately signed hard-gate evaluation with `PASS`.

Every route uses a physically distinct raw bearer credential whose SHA-256 digest is configured in
`schemas/evidence/token-bindings.schema.json` and bound to one client certificate SAN, tenant,
subject and scope. The binding subject is the exact certificate SAN, not the event actor. For
execution evidence, `actor_subject` is independently matched to the authoritative orchestrator
ingress owner in the same tenant transaction. Supported scopes are `evidence:append`,
`evidence:event`, `evidence:authority-event`, `evidence:read`, `evidence:artifact`,
`evidence:package` and `evidence:evaluate`. Reusing the same token digest for two scopes is rejected
at startup.

Required secrets/configuration:

- `AGENT_TRUST_EVIDENCE_DATABASE_URL_FILE`, `...DATABASE_PASSWORD_FILE`,
  `...DATABASE_CA_FILE`, and `...DATABASE_EXPECTED_ROLE` (`agenttrust_evidence`);
- `AGENT_TRUST_EVIDENCE_ISSUER`, `...SIGNING_KEY_ID`, and
  `...SIGNING_PRIVATE_KEY_FILE` (unpadded base64url 32-byte Ed25519 seed), plus
  `AGENT_TRUST_EVIDENCE_VERIFYING_KEYRING_FILE`; the keyring must contain the active key and all
  historical event/package keys needed for online replay and offline package verification;
- `AGENT_TRUST_EVIDENCE_CLIENT_IDENTITIES`, `...TOKEN_BINDINGS_FILE`,
  `...TLS_CA_FILE`, `...TLS_CERTIFICATE_FILE`, and `...TLS_PRIVATE_KEY_FILE`;
- `AGENT_TRUST_EVIDENCE_WORM_ENDPOINT`, `...WORM_TOKEN_FILE`, `...WORM_CA_FILE`,
  `...WORM_CERTIFICATE_FILE`, `...WORM_PRIVATE_KEY_FILE`, and
  `AGENT_TRUST_EVIDENCE_MAX_ARTIFACT_BYTES`.

The WORM adapter requires an HTTPS storage gateway to accept conditional content-addressed writes,
honor the exact `Idempotency-Key`, and return the same provider version receipt for exact replays.
Service readiness verifies the
gateway advertises `object_lock=true`; this is fail-closed runtime posture, not proof that a real
managed bucket, independent retention policy or disaster-recovery process has been accepted.

The production package endpoint rejects missing artifact attestations and signs a self-contained
manifest. `verify-evidence` accepts both the legacy inner package and the signed production wrapper.
The `/v1/evidence/events` lifecycle route binds the event to an exact orchestrator task state and
requires `source_service` to equal the single certificate SAN; `TASK_CREATED` and `PLAN_GENERATED`
also bind their payload hashes to the authoritative goal and plan digests. `TOOL_EXECUTED` is
rejected there and may enter only through the execution/PEP/fence-bound route.
State-owning authorities publish through `/v1/evidence/authority-events`. A
`GOVERNED_ACTION` request must carry the final action hash, PEP decision/evidence, ledger event,
execution and fence digests; the Evidence database verifies them against
`pep_execution_authorizations` before it signs and atomically appends the event. An
`AUTHENTICATED_EVENT` is allowed only for an existing orchestrator task and must carry no control
binding, so an observation cannot masquerade as an authorized action. Authority publishers retain
the immutable request timestamps in their durable outbox and replay the exact same bytes after an
unknown outcome. The signed receipt and nested chain event are verified against the configured
historical Evidence keyring before a local outbox is finalized.
The production evaluator derives chain and ledger gates from PostgreSQL. Callers cannot weaken the
baseline: `TASK_CREATED`, `PLAN_GENERATED`, `POLICY_EVALUATED`, `CREDENTIAL_ISSUED`,
`TOOL_PREPARED`, and `TOOL_EXECUTED` are mandatory request requirements. Missing required events,
unknown terminal state or any unhandled high-risk event yields `NEEDS_HUMAN`, never implicit PASS.
