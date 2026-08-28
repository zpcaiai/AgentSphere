# Production closure and certificate revocation

Batch 36 is the sole final closure authority. It binds commit, build, policy, pack, prompt, model, topology, environment, evidence, and expiry. It requires Batches 01–35 to be `EVIDENCE_VERIFIED`, exactly one valid result for every required gate, real-environment or independent evidence for external gates, no unaccepted residual risk, and no P0/P1 waiver.

Current repository state is `IN_PROGRESS`; no Production Closure Certificate is issued. To issue one, run all contract, migration, security, domain, HA/DR, upgrade, enterprise, and evidence-graph gates against the exact production candidate. Review residual risks and only then call the closure authority backed by external KMS.

The production CLI does not accept a local private key. Use the private-key-free
`prepare-external-signing` and `finalize-external-signing` commands documented in
`docs/release/production-closure-external-signing.md`. The legacy `issue` command fails
closed; `issue-local` is explicitly development-only and cannot satisfy production evidence.

For revocation, record certificate ID, release, reason, approver, time, and replacement/rollback decision; publish it to the signed revocation registry; block new activations; notify active environments; and preserve evidence. Offline consumers must reject expired or revoked certificates after synchronizing the monotonic registry sequence and predecessor digest. `production-closure verify` requires the current signed registry; use `verify-revocation-successor` before advancing a persisted local checkpoint.

Industrial, medical, and sensitive-interaction acceptance must be supplied as
`agenttrust.domain-assurance-attestation.v1`. The complete reviewer roster signs
the same canonical JSON payload. Verify it offline with:

```sh
cargo run -p agent-trust-production-closure --bin production-closure -- \
  verify-domain-assurance attestation.json reviewer-keyring.json closure-scope.json \
  /absolute/new/domain-gate-evidence.json
```

The verifier requires two distinct qualified roles for the selected domain,
distinct reviewer keys from a deployment-owned
`agenttrust.production-closure-reviewer-keyring.v1`, a production environment reference, approved
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
  verify-external-assurance external-attestation.json reviewer-keyring.json \
  closure-scope.json /absolute/new/gate-evidence.json
```

The verifier requires `environment://production/...`, a release ID and change
ticket, non-automated approval, digest-pinned evidence, bounded 30-day validity,
qualified roles, distinct reviewer/key identities, two organizations and valid
Ed25519 signatures. Repository code or a CI account cannot self-issue customer,
expert or independent certification.

Every keyring entry binds the reviewer identity, organization, qualified roles, the
`PRODUCTION_ASSURANCE_REVIEW` key usage, Ed25519 public key, validity window, status and revocation
time. The keyring's canonical digest is part of the production closure scope. A key with a
mismatched identity, organization or role, a wrong usage, an inactive validity window, or a
revoked status fails closed. Converted `GateEvidence` expires at the earliest attestation, scope,
keyring or participating reviewer-key expiry.

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
runtime-config digest, release ID and computed release digest. Release Binding v2 signs
only static values: `release_digest` and `evidence.bundle_digest` are deliberately
excluded because each is derived from material that transitively contains the binding.
It writes a new prepared static-values document; neither output may already exist:

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
  --prepared-values-output /absolute/new/production-stack-static-values.json
```

After the positive evidence bundle and activation document exist, materialize the final
values. This step injects the binding's `release_digest` and the activation's verified
`evidence_bundle_manifest_digest`; no caller-supplied placeholder is retained:

```sh
python3 scripts/materialize-production-stack-values.py \
  --release-binding /protected/release/signed-release-binding.json \
  --release-binding-keyring /protected/trust/release-binding-keyring.json \
  --activation /protected/release/activation.json \
  --output /absolute/new/production-stack-values.json
```

The renderer accepts only that materialized values file plus the signed binding and a
deployment-owned `agenttrust.release-binding-keyring.v1` public keyring. Recomputing a
checksum after changing an image, template, static value, runtime setting, or evidence
bundle cannot authorize the change: the exact binding and activation must both verify.

`WORKTREE-NO-GIT` is never promoted to an immutable release ID. Initialize or
publish Git only through the repository owner's release process; this runbook
does not authorize creating a remote, signing key, tag, commit or push.
