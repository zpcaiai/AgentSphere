# Production release lifecycle

This lifecycle turns an immutable source tag into a production deployment without
turning CI output, local probes, or unsigned operator input into certification
evidence. Every workflow is fail closed and must be dispatched from the protected
default branch. The signed annotated tag supplied as `release_tag` must peel to
that exact default-branch `GITHUB_SHA`; each workflow then checks out that commit
detached before processing release material.

The release train therefore holds the protected default branch at the tagged
commit until candidate, intake, assurance, and deployment have all finished. A
later default-branch commit intentionally makes an older tag ineligible for a new
production workflow dispatch instead of silently running newer workflow code
against older release material.

## Trust and runner boundary

The four protected GitHub environments are `production-candidate`,
`production-evidence`, `production-assurance`, and `production`. They require
independent reviewers and deny administrator/self bypass. The four release
stages run only on dedicated Linux runners with these label sets:

- candidate source verification, image build, and assembly: `self-hosted, linux, production-candidate, actions-runner-2-327-1`
- evidence intake: `self-hosted, linux, production-evidence, actions-runner-2-327-1`
- assurance and external signing: `self-hosted, linux, production-assurance, actions-runner-2-327-1`
- Kubernetes deployment: `self-hosted, linux, production-deploy, actions-runner-2-327-1`

Trust roots are absolute deployment-owned files. They are never downloaded from,
or included in, a release artifact. Each protected environment supplies the
subset it uses:

- `AGENT_TRUST_GIT_VERIFICATION_CONFIG_FILE`
- `AGENT_TRUST_GIT_PROVENANCE_KEYRING_FILE`
- `AGENT_TRUST_RELEASE_BINDING_KEYRING_FILE`
- `AGENT_TRUST_REVIEWER_KEYRING_FILE`
- `AGENT_TRUST_WORM_KEYRING_FILE`
- `AGENT_TRUST_CLOSURE_PUBLIC_KEY_FILE`
- `AGENT_TRUST_REVOCATION_PUBLIC_KEY_FILE`
- `AGENT_TRUST_REVOCATION_CHECKPOINT_FILE`

Every trust file must be a canonical, single-link regular file that the runner
can read but cannot modify, with no group/other write permission. The assurance
broker configuration and the deployment kubeconfig use the same host-owned
file boundary.

The revocation checkpoint is a deployment-owned, durable monotonic head shared
across release runs. Evidence intake and assurance receive a read-only mount of
`AGENT_TRUST_REVOCATION_CHECKPOINT_FILE`; the production deployment runner is
the only workflow principal with mutation access. The deployment environment
also supplies the independently provisioned
`AGENT_TRUST_REVOCATION_CHECKPOINT_LOCK_FILE`. Both paths are canonical absolute
regular files on storage that preserves advisory locks, atomic rename, and
directory `fsync` semantics across runner restarts. They are never sourced from
GitHub artifacts.

Every self-hosted environment also pins its ambient executable paths and
SHA-256 digests through protected variables: `AGENT_TRUST_GH_BINARY`,
`AGENT_TRUST_GH_SHA256`, `AGENT_TRUST_GIT_BINARY`,
`AGENT_TRUST_GIT_SHA256`, `AGENT_TRUST_DOCKER_BINARY`, and
`AGENT_TRUST_DOCKER_SHA256`. The deployment environment additionally pins
`AGENT_TRUST_KUBECTL_BINARY` and `AGENT_TRUST_KUBECTL_SHA256`. The assurance
environment pins `AGENT_TRUST_CARGO_BINARY`, `AGENT_TRUST_CARGO_SHA256`,
`AGENT_TRUST_RUSTC_BINARY`, and `AGENT_TRUST_RUSTC_SHA256`, verifies exact
Rust/Cargo 1.89.0 versions, and builds the closure binary with Cargo offline.

Every Python call, including the first runner preflight, uses the canonical
absolute `AGENT_TRUST_PYTHON_BINARY`; no workflow-installed interpreter is in
the production path. Its protected `AGENT_TRUST_PYTHON_SHA256` must match, and
the workflow verifies the complete pre-provisioned installed-distribution file
tree against the canonical, read-only
`AGENT_TRUST_PYTHON_RUNTIME_MANIFEST_FILE` and protected
`AGENT_TRUST_PYTHON_RUNTIME_MANIFEST_SHA256`; an exact executable digest alone
is not accepted as a runtime fingerprint.

No production workflow resolves Python packages from PyPI. Each environment
sets `AGENT_TRUST_PYTHON_WHEELHOUSE_DIRECTORY` to a canonical, runner-read-only
directory and pins `wheelhouse-manifest.json` with the protected
`AGENT_TRUST_PYTHON_WHEELHOUSE_MANIFEST_SHA256`. The directory contains only
that manifest, `requirements-ci.lock`, and the wheels declared by the manifest.
The manifest schema is `agenttrust.python-wheelhouse.v1` and binds Python 3.14,
the SHA-256 of every recursively included repository requirements source, the
fully resolved lock digest, and the sorted filename, size, and SHA-256 of every
wheel. The job validates every byte and rejects URLs and nested requirements in
the lock. It never modifies the runtime during a release: the dedicated runner
image must already contain the locked dependency closure, the complete runtime
manifest must bind the same lock digest and exact installed distribution
versions, and `pip check` must pass. Missing, writable, stale, or incomplete
wheelhouse or runtime material stops the release.

The signing environment also supplies
`AGENT_TRUST_SIGNING_BROKER_CONFIG_FILE`. That strict configuration references
an HTTPS signing endpoint, TLS 1.3 CA, mTLS certificate/private key, and GitHub
workload-OIDC audience. The workflow sends digest-bound Ed25519 payloads to the
broker but never receives or loads a closure or revocation signing private key.

## 1. Candidate

Dispatch `production-release-candidate` from the protected default branch and provide the
signed annotated tag. It proves that the tag peels to the dispatch SHA and that the
committed `.github/CODEOWNERS` digest matches the protected environment value. It runs the complete
reusable CI matrix, builds every production image from digest-pinned bases,
pushes digest references, produces SBOM and build-provenance attestations, and
attests `production-image-manifest.json`. Record the successful run ID.

The later workflows do not trust an artifact name alone. They query the GitHub
Actions run, require the expected workflow path, successful completion, exact
commit SHA, and verify GitHub attestations with the expected signer workflow,
source digest, and protected-default-branch source ref. The separately verified
annotated tag provides the exact tag-to-commit binding.

## 2. Real evidence intake

On the dedicated evidence runner, set
`AGENT_TRUST_QUALIFICATION_SOURCE_DIRECTORY` to an absolute, non-symlink,
deployment-owned directory that the runner can read and traverse but cannot
modify, with no group/other write permission. It contains:

- `qualification-input.json`: all required signed release, batch, external
  condition, WORM, customer/domain, and independent-review evidence
- `production-runtime.json`: the exact production runtime configuration
- `revocation-update.json`: the next bounded revocation registry update
- `previous-revocation-registry.json`: the exact current signed registry when
  the deployment checkpoint sequence is greater than zero; it must be absent
  only for the one-time sequence-zero genesis

Run `production-evidence-intake` with the candidate run ID. The workflow verifies
the candidate manifest and every dynamically declared OCI image attestation,
compiles the external evidence with deployment-owned keyrings, binds it to the
exact image manifest and runtime configuration, validates the revocation update,
and requires its `base_checkpoint_digest` to equal the durable checkpoint head.
The workflow snapshots and attests that checkpoint, then records its digest,
sequence, current registry digest, and previous-registry artifact digest in the
intake receipt. It does not create
probes, reviewer signatures, customer approvals, WORM receipts, or physical
safety evidence.

Checkpoint genesis is an explicit out-of-band provisioning operation, not a
workflow fallback. Before the first release, an authorized operator invokes
`scripts/manage-production-revocation-checkpoint.py initialize` with the
absolute checkpoint and lock paths plus the fixed registry and key IDs. The
command creates both files exclusively and cannot reset or overwrite an
existing chain. At sequence zero no previous registry is permitted. At every
later sequence, intake fails unless the provided signed previous registry
matches the checkpoint ID, key, sequence, and registry digest exactly.

Batches 01–35 are the qualified prerequisites. Batch 36 is the final Production
Closure created only after those prerequisites and the real-environment gates
verify; placing Batch 36 inside its own qualification input would create a
self-attestation cycle and is intentionally rejected by the closure design.

## 3. External assurance and activation

Run `production-assurance` with both upstream run IDs. It redownloads both
artifacts, verifies their workflow identities and attestations, reverifies every
OCI subject, recompiles the qualification package, and compares it with the
intake closure input.

The workflow then:

1. evaluates the Rust production closure report;
2. prepares a certificate signing request without a private key;
3. gets a short-lived GitHub OIDC token and calls the mTLS signing broker;
4. independently finalizes and verifies the returned certificate signature;
5. repeats the same two-phase flow for the revocation registry and verifies
   that it is the exact successor of the attested deployment checkpoint;
6. builds and verifies the positive certificate-bearing evidence manifest;
7. prepares activation and the Rust admission expectation; and
8. independently verifies activation with both Rust and Python, comparing their
   release, certificate, report, scope, revocation, and expiry decisions.

The resulting `production-assurance-<commit>` artifact contains public evidence,
both signing requests, both detached v2 signatures, and both externally signed
audit receipts, never trust roots or signing private keys. The 12-role positive
bundle binds every request, envelope, and audit-receipt triple, including the
request digest, document-signature digest, signing time, and external audit
signature. The evidence manifest, activation, and runtime configuration each
receive a GitHub build provenance attestation.

## 4. Evidence publication and production deployment

Before deployment, provision the release evidence storage mount and the static
PersistentVolume mapping named by the signed stack values. Set the protected
`AGENT_TRUST_RELEASE_EVIDENCE_ROOT` variable to the mount's canonical absolute
path. The root must exist, be owned by the deployment boundary, have mode
`0700`, and contain no symlink component.

The release workflow obtains `persistent_volume_name` only from the verified v2
release binding. On the first run it uses the fixed evidence publisher to
reverify the bundle, activation, release binding, and trust anchors, then
atomically creates `$AGENT_TRUST_RELEASE_EVIDENCE_ROOT/<volume-name>`. A rerun
never overwrites that generation: it must reverify the existing directory. The
published generation contains exactly these read-only runtime files:

- `production-certificate.json`
- `closure-report.json`
- `closure-input.json`
- `revocation-registry.json`
- `activation-expectation.json`
- `batch-statuses.json`
- `gate-evidence.json`
- `residual-risks.json`
- `exceptions.json`

It also contains `publication-receipt.json`, which binds the release, scope,
volume name, evidence-manifest and activation digests, the activated revocation
registry ID, sequence, and digest, all nine file digests, and the complete
directory digest. The release workflow independently verifies that receipt,
attests and uploads it before any Kubernetes apply, and binds its `volume_name`,
`directory_digest`, `receipt_digest`, and revocation registry identity into the
deployment receipt. The receipt truthfully records
`locked_retention_evidence_required=true`: POSIX read-only modes are not object
lock, WORM, or locked-retention evidence.

The deployment path is implemented by
`scripts/execute-production-deployment.py`. It discovers the currently selected
release from stable Service selectors, refuses an empty or ambiguous source,
and delegates every state-changing database/traffic operation to the external
mTLS/OIDC deployment-cutover broker. The broker must return an Ed25519-signed
receipt for each operation; the client verifies the request, response,
inventory, signature and predecessor digest before continuing.

The provisioned PersistentVolume must map the signed volume name to that exact
publication directory and mount it read-only into the admission job and
runtime. The publisher rejects writable generations, symlink/hard-link
substitutions, extra or missing files, and any byte mismatch with the verified
assurance artifact.

The `production` environment also supplies:

- `AGENT_TRUST_KUBECTL_BINARY` and its exact
  `AGENT_TRUST_KUBECTL_SHA256`
- `AGENT_TRUST_KUBECONFIG_FILE`
- `AGENT_TRUST_KUBERNETES_CONTEXT`
- `AGENT_TRUST_KUBERNETES_NAMESPACE`
- `AGENT_TRUST_DEPLOYMENT_CUTOVER_BROKER_CONFIG_FILE` (mTLS CA/client
  certificate/key and deployment-cutover keyring)
- `AGENT_TRUST_DEPLOYMENT_ENVIRONMENT_REFERENCE`

Run `production-release` with the assurance run ID. It reverifies the positive
bundle, signatures, revocation state, activation, runtime binding, candidate
manifest, and every OCI attestation. The dedicated materializer reconstructs
deployment values from signed v2 `static_values`, injects only the verified
release digest and positive evidence-manifest digest, and the renderer binds the
result to the signed Git provenance and activation receipt.

Immediately before evidence publication, the release workflow advances the
live checkpoint with a compare-and-swap under the deployment-owned lock. The
expected checkpoint digest comes from the already verified intake receipt and
must equal its attested checkpoint snapshot; the new signed registry and
activation receipt must agree on registry ID, sequence, and digest. Replaying
the same registry is idempotent, but any different live head is a hard conflict
that requires a new candidate/intake/assurance chain. The CAS receipt binds both
checkpoint digests and both sequences, is attested and uploaded, and is included
in the final deployment receipt. No workflow can silently create a new genesis
or reset the sequence to one.

After a full server-side dry run, the release uses server-side apply and the
signed broker state machine in this strict order:

1. `prerequisite`
2. `admission`, then wait for every admission Job to complete
3. signed `WRITER_FENCE`; the broker proves zero in-flight actions, outbox rows
   and execution leases plus a fresh database checkpoint, backup and restore
   receipt
4. `migration`, then wait for every migration Job to complete
5. `workload`, then wait for every versioned Deployment rollout while the
   previous revision remains available
6. signed `CUTOVER`; the broker switches stable Service selectors and returns a
   source/target inventory. The client verifies target-only endpoints.
7. scale every source-revision Deployment to zero and verify no ready/available
   source writer remains
8. signed `UNFREEZE`; the broker activates the target lease. Any failure after
   CUTOVER requires a signed `ROLLBACK` followed by a source `UNFREEZE`; a
   failed rollback leaves the database fenced for manual recovery.

Any failure stops the sequence; later phases are not applied. Database migration
rollback is never inferred or run automatically. A successful deployment emits
an attested v2 receipt containing the exact source/target release and revision,
rendered stack and blue-green-plan digests, and the three externally signed
fence/cutover/unfreeze receipt digests. The versioned materializer makes
ConfigMaps, SecretProviderClasses, Deployments and PDBs coexist across
releases; only stable Services are traffic resources.

## What remains external

The workflows are executable control paths, not evidence that a production
environment exists. Release remains ineligible until operators have actually:

- applied repository rules and all four protected environments;
- provisioned and hardened the four dedicated self-hosted runner pools;
- recorded and independently approved each immutable runner image or AMI digest,
  Actions Runner 2.327.1 package digest, kernel/runtime baseline, and protected
  runner-group assignment (a label by itself is not runner provenance);
- installed the approved `gh`, Git, Docker, kubectl, Python, Cargo, and Rust
  binaries and published their exact protected path/digest variables;
- provisioned the read-only Python runtime manifest and offline, fully hashed
  wheelhouse/lock closure for the exact runner architecture;
- configured enterprise Git/IdP/JWKS, mTLS CA/Vault, external signing broker,
  and the deployment-cutover broker trust roots (including its keyring and
  writer-fence/rollback authority);
- provisioned multi-zone Temporal, managed database, locked-retention evidence
  storage, Kubernetes, gVisor nodes, and the release-specific PersistentVolume
  mapping, including independent locked-retention proof for the published
  generation;
- provisioned the one-time revocation checkpoint genesis plus durable shared
  checkpoint/lock storage with correct read-only intake and assurance mounts,
  exclusive deployment mutation authority, atomic rename, locking, and crash
  durability guarantees;
- executed real model, streaming, billing, DLP/residency, MCP/A2A, industrial
  protocol, supervised physical-write, HA/DR, fault, and sustained-load gates;
- collected unexpired customer, domain-expert, safety, and independent-review
  signatures plus their signed WORM receipts; and
- created and pushed the exact signed commit and annotated release tag, then ran
  candidate -> evidence intake -> assurance -> release successfully.

Until those facts exist and verify, `EVIDENCE_VERIFIED=0`, `eligible=false`, and
`NOT_ISSUED` remain the correct production status.
