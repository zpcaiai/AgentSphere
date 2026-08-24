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
  --release-tag v1.0.0 \
  --git-allowed-signers-file /protected/release/git-allowed-signers \
  --signing-key-file /protected/release/git-provenance-ed25519.key \
  --issuer release-authority --key-id git-provenance-2026-01 \
  --output /absolute/new/signed-git-provenance.json
```

Commit and annotated-tag verification is SSH-signature-only. The protected
`git-allowed-signers` file is the deployment authority's explicit signer trust root; it
must be an absolute, regular, single-link file owned by root or the release process and
not writable by group or other users. Its SHA-256 digest is bound into the signed report.
Repository-local and worktree Git configuration is strict-allowlisted: executable
fsmonitor, credential, GPG/SSH program, URL rewrite, HTTP override, include, proxy and
custom upload-pack settings fail closed before status or signature verification.

For an SSH Git remote, also provide `--ssh-known-hosts-file` and
`--ssh-identity-file`. Both must be protected absolute files; the identity must be mode
`0600`. The collector disables user/system Git configuration, replacement objects,
credential helpers, redirects, arbitrary protocols, SSH forwarding/proxy commands and
interactive authentication. Remote tag queries use the exact audited canonical URL from
a neutral non-repository directory. HTTPS remotes do not use these two SSH transport
arguments and always require TLS certificate verification with redirects disabled.

Next, have the independent release authority bind the exact deployment inputs. The
producer proves that the template bytes are the blob at the fixed path
`deploy/kubernetes/production-stack.yaml.tmpl` in the provenance commit, then signs the
Git provenance digest, blob object ID, template digest, canonical non-secret values,
runtime-config digest, release ID and computed release digest. It writes a new finalized
values document; neither output may already exist:

```sh
python3 -m python.production_gates.release_binding \
  --repository /absolute/repository \
  --template /absolute/repository/deploy/kubernetes/production-stack.yaml.tmpl \
  --values /protected/release/production-stack-values.input.json \
  --runtime-config /protected/release/production-runtime.json \
  --git-provenance /protected/release/signed-git-provenance.json \
  --git-provenance-keyring /protected/release/git-provenance-keyring.json \
  --signing-key-file /protected/release/release-binding-ed25519.key \
  --issuer release-authority --key-id release-binding-2026-01 \
  --output /absolute/new/signed-release-binding.json \
  --finalized-values-output /absolute/new/production-stack-values.json
```

The renderer accepts only that finalized values file plus the signed binding and a
deployment-owned `agenttrust.release-binding-keyring.v1` public keyring. Recomputing a
checksum after changing an image, template, value or runtime setting cannot authorize the
change: the exact binding must still verify under an active release-authority key.

`WORKTREE-NO-GIT` is never promoted to an immutable release ID. Initialize or
publish Git only through the repository owner's release process; this runbook
does not authorize creating a remote, signing key, tag, commit or push.
