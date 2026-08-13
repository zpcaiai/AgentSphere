# Production closure and certificate revocation

Batch 36 is the sole final closure authority. It binds commit, build, policy, pack, prompt, model, topology, environment, evidence, and expiry. It requires Batches 01–35 to be `EVIDENCE_VERIFIED`, exactly one valid result for every required gate, real-environment or independent evidence for external gates, no unaccepted residual risk, and no P0/P1 waiver.

Current repository state is `IN_PROGRESS`; no Production Closure Certificate is issued. To issue one, run all contract, migration, security, domain, HA/DR, upgrade, enterprise, and evidence-graph gates against the exact production candidate. Review residual risks and only then call the closure authority backed by external KMS.

For revocation, record certificate ID, release, reason, approver, time, and replacement/rollback decision; publish it to the revocation registry; block new activations; notify active environments; and preserve evidence. Offline consumers must reject expired or revoked certificates after synchronizing revocation state.

Industrial, medical, and sensitive-interaction acceptance must be supplied as
`agenttrust.domain-assurance-attestation.v1`. The complete reviewer roster signs
the same canonical JSON payload. Verify it offline with:

```sh
cargo run -p agent-trust-production-closure --bin production-closure -- \
  verify-domain-assurance attestation.json reviewer-public-keys.json EXPECTED_SCOPE_SHA256
```

The verifier requires two distinct qualified roles for the selected domain,
distinct reviewer keys, a production environment reference, approved
non-automated review, bounded validity, and digest-pinned source evidence.
Unit tests and locally generated keys never constitute external acceptance.

All other real-environment gates use
`agenttrust.external-gate-assurance-attestation.v1`. Two distinct reviewer keys
from at least two organizations sign the same canonical payload. Each gate has
mandatory role pairs; `ENTERPRISE_ACCEPTANCE`, for example, requires both
`CUSTOMER_RELEASE_AUTHORITY` and `INDEPENDENT_AUDITOR`. Convert a valid signed
attestation into closure `GateEvidence` with:

```sh
cargo run -p agent-trust-production-closure --bin production-closure -- \
  verify-external-assurance external-attestation.json reviewer-public-keys.json \
  EXPECTED_SCOPE_SHA256 /absolute/new/gate-evidence.json
```

The verifier requires `environment://production/...`, a release ID and change
ticket, non-automated approval, digest-pinned evidence, bounded 30-day validity,
qualified roles, distinct reviewer/key identities, two organizations and valid
Ed25519 signatures. Repository code or a CI account cannot self-issue customer,
expert or independent certification.

Before constructing the closure scope, collect immutable Git provenance from a
clean repository root. The gate rejects local/file remotes, unapproved hosts,
unpinned submodules, dirty files, invalid signatures and tags that do not point
to `HEAD`:

```sh
python3 -m python.production_gates.git_provenance \
  --repository /absolute/repository --allowed-remote-host github.com \
  --release-tag v1.0.0 --output /absolute/new/git-provenance.json
```

`WORKTREE-NO-GIT` is never promoted to an immutable release ID. Initialize or
publish Git only through the repository owner's release process; this runbook
does not authorize creating a remote, signing key, tag, commit or push.
