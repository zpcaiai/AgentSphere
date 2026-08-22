# Supply chain and Domain Pack lifecycle

All executable extensions—Rust/Python/Java/npm artifacts, containers, adapters, policies, prompts, evaluators, models, and Domain Packs—enter through the Batch 20 authority. A production release is content addressed and binds the publisher and maintainer key, artifact digest, SBOM, provenance, source commit, build definition, signature envelope, license report, vulnerability report, immutable dependency lock, declared permissions and compatibility set. A mutable tag such as `latest` is rejected.

The authoritative lifecycle is `PUBLISHED -> VALIDATED -> APPROVED -> ACTIVE`. `QUARANTINED`, `REVOKED`, and `ROLLED_BACK` are fail-closed terminal paths; a quarantine may only advance to revocation. Validation requires repository, signer, scanner and sandbox receipts. Approval is a distinct operation, and activation requires the exact approved manifest and resource-version fence. New network, data, effect, executor, approval, compensation, or irreversible capabilities invalidate prior approval.

Every mutation arrives as Canonical Action IR with exact tenant, action, task, operation, resource, current state and production environment. The authority binds it to the PEP authorization and evidence, policy decision, ledger execution/event, execution fence, idempotency key, caller SAN/subject/scope and resource version before calling the typed supply-chain coordinator. The returned runtime receipt must be signed by the configured keyring and bind all of those values. Success writes the release mutation, receipt, evidence event and Evidence outbox entry in one tenant-RLS PostgreSQL transaction.

Idempotency is durable. A duplicate key with a different request digest is rejected. An expired in-flight lease or ambiguous external effect becomes `UNKNOWN`; it is never replayed automatically. Recovery only marks expired work `UNKNOWN` for human reconciliation. Evidence delivery is an outbox operation with its own idempotency key and receipt digest.

The Marketplace catalog and the supply-chain authority are separate authorities. Marketplace owns discovery and tenant intent; Batch 20 owns artifact/release admission and revocation. Neither writes the other's tables. The supply-chain data API is `POST /v1/supply-chain/executions` on port `8093`; authoritative BFF/UI reads use `GET /v1/authoritative/supply-chain/releases`; management readiness is isolated on `9103`. Data ingress requires TLS 1.3 mTLS, exactly one allowed DNS or URI SAN, a tenant-bound bearer token, and the operation scope `supply-chain:publish`, `supply-chain:approve`, `supply-chain:activate`, or `supply-chain:revoke`. Reads use `supply-chain:read`; recovery uses the separate `supply-chain:recover` grant.

Publisher onboarding starts `UNTRUSTED`. An independent reviewer verifies an Ed25519 key and its
fingerprint before the publisher becomes `VERIFIED`; the release still requires Batch 20 manifest
verification and a live Batch 22 Release Gate certificate bound to the immutable pack digest.
Pack names are reserved to the first verified publisher within the tenant, preventing same-name
takeover. Immutable artifact references reject `latest` tags.

Tenant installation evaluates the authoritative catalog profile: control-plane compatibility,
entitlement, region, verified publisher trust, and maximum risk. Permission expansion is computed
against the currently active installation and is visible in the mandatory approval record.
`PENDING_APPROVAL -> APPROVED -> INSTALLED -> ACTIVE` are distinct states. Production activation
requires the verified release-certificate digest, but activation never grants task credentials or
production authorization. Tasks still pass PEP, sandbox, ledger, and Evidence controls.

Upgrade requires an installed target, retained active predecessor, strict SemVer increase, migration
and rollback digests, and a passed durable canary result. Rollback reactivates only a non-revoked,
still-trusted predecessor. Release or publisher revocation atomically marks affected installations
`REVOKED`, so they cannot resolve for new tasks; the running-task response is explicitly `PAUSE`,
`KILL`, or `ALLOW_TO_FINISH` and remains a separate orchestrator action.

The developer scaffold command remains:

```sh
python3 -m python.pack_cli.cli new example-pack --publisher publisher:example --root /safe/output
python3 -m python.pack_cli.cli verify /safe/output/example-pack/pack.json
```

The generated pack is default-deny. A CLI digest or local unit test is not a production certificate. External PKI, repository, signer, SBOM/provenance producer, scanner, Linux isolation sandbox, revocation feed and locked-retention Evidence services must all report ready before this authority becomes ready. Their real-environment acceptance remains `NOT_RUN` until corresponding signed evidence exists.
