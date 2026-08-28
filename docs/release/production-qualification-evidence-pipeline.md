# Production qualification and positive evidence bundle

This pipeline is the only supported bridge from production observations to a
`Production Closure Input`. It does not make repository tests into production
evidence and it does not modify the checked-in, certificate-free negative
baseline.

## Trust boundary

The qualification package is untrusted input. In particular, it cannot carry
or select its own trust roots, batch statuses, or closure `GateEvidence`.
Deployment operators provide four protected keyrings separately:

- the Git provenance keyring;
- the release-binding keyring;
- `agenttrust.production-closure-reviewer-keyring.v1`;
- `agenttrust.worm-evidence-keyring.v1`.

The compiler verifies the exact immutable Git release and signed release
binding, including the release ID, commit content, digest-pinned image set, and
runtime topology. The closure scope also binds the signed provenance digest,
signed release-binding digest, release digest, and normalized reviewer-keyring
digest. `WORKTREE-NO-GIT`, mutable images, non-production environments, expired
evidence, inactive or revoked keys, unknown fields, duplicate records, and
cross-release or cross-scope material fail closed.

Assemble the attested 30-image production manifest before constructing the
scope and set `scope.build_digest` to its `manifest_digest`. The image manifest
is not accepted as a self-trust input to qualification; the positive-bundle
verifier later requires its image set to equal the signed release binding and
its digest to equal the already reviewer-signed closure scope.

Every Batch 01–35 report and every one of the 17 external-condition reports is
stored as a `qualified-evidence-record.v1`. A separately trusted WORM authority
must issue a signed receipt for the exact record digest after applying the
record's verification policy. The receipt binds the release, scope,
environment, immutable object version, compliance retention, readback result,
and `VERIFIED` result. A plain JSON claim of `EVIDENCE_VERIFIED` is never an
accepted input.

Reviewer attestations are verified against the deployment-owned reviewer
keyring. The keyring binds key IDs to reviewer identities, organizations,
qualified roles, validity, usage, and revocation. External gate attestations
require two organizations; domain attestations require their exact qualified
role pairs. All reviewers sign the same canonical roster and exact evidence
digest map.

## Fixed 17-condition to 15-gate mapping

The mapping is executable code in
`python/production_gates/qualification.py`; packages cannot replace it.

| Closure gate | Required external conditions |
| --- | --- |
| `CONTRACT_COMPATIBILITY` | qualified Batch 01–35 set |
| `SUPPLY_CHAIN_PROVENANCE` | immutable Git provenance; locked-retention object storage |
| `MULTITENANT_ISOLATION` | enterprise IdP/JWKS; workload mTLS CA; dynamic secret leases |
| `IDEMPOTENCY_AND_RECOVERY` | multi-zone Temporal; managed multi-zone database |
| `CONTINUOUS_AUTHORIZATION` | enterprise IdP/JWKS; workload mTLS CA; dynamic secret leases |
| `DOMAIN_CODING` | real MCP endpoint; real A2A endpoint |
| `DOMAIN_INDUSTRIAL` | OPC UA/MQTT/Modbus endpoints; supervised physical write |
| `DOMAIN_ENERGY` | OPC UA/MQTT/Modbus endpoints; supervised physical write |
| `DOMAIN_MEDICAL` | customer, expert, and independent acceptance |
| `DOMAIN_SENSITIVE_INTERACTION` | customer, expert, and independent acceptance |
| `SECURITY_CAMPAIGN` | dedicated Linux gVisor; enterprise IdP/JWKS; model/DLP/billing/residency |
| `HA_DR_RESTORE` | Temporal; database; locked storage; multi-zone topology; network/storage/control-plane faults |
| `UPGRADE_ROLLBACK` | multi-zone topology; network/storage/control-plane faults |
| `CONTROL_EVIDENCE_GRAPH` | locked-retention storage; immutable Git provenance |
| `ENTERPRISE_ACCEPTANCE` | model/DLP/billing/residency; MCP; A2A; industrial protocols; sustained load; customer/expert/auditor acceptance |

Each signed assurance digest map contains the exact condition record and WORM
receipt digests plus `signed_git_provenance`, `signed_release_binding`, and
`release`. After signature verification, the compiler adds the attestation and
reviewer-keyring digests. The supply-chain gate therefore satisfies the Rust
closure authority's source-binding checks without caller-provided
`GateEvidence`.

## Compile the closure input

All paths are absolute. The output must not exist.

```sh
python3 scripts/compile-production-qualification.py \
  --input /protected/release/qualification-input.json \
  --git-provenance-keyring /protected/trust/git-provenance-keyring.json \
  --release-binding-keyring /protected/trust/release-binding-keyring.json \
  --reviewer-keyring /protected/trust/production-reviewers.json \
  --worm-keyring /protected/trust/worm-evidence-keyring.json \
  --output /absolute/new/production-closure-input.json
```

The compiler emits exactly 35 batch statuses and 15 gate records in canonical,
deterministic order. Batch status is derived as `EVIDENCE_VERIFIED` only after
the record, signed WORM receipt, release provenance, and release binding pass.
It includes scope, measurement, and expiry. Gate and batch expiry is bounded by
the underlying evidence and trust material; the Rust evaluator derives
`evidence_valid_until`, and a production certificate cannot outlive it.

Evaluate this output with the production-closure CLI. An eligible report must
have no blockers, must bind the exact closure-input digest, and must contain all
15 recomputed gate digests. Issue the certificate through the external signing
flow and publish the signed revocation registry before activation.

## Positive evidence bundle

The positive bundle is distinct from
`evidence/production-closure/evidence-bundle-manifest.json`, which accurately
documents the current non-certified baseline. A positive bundle contains 12
artifacts:

- qualification input;
- compiler-derived closure input;
- eligible closure report;
- externally signed Production Closure Certificate;
- the exact certificate signing request;
- the certificate signer's v2 detached envelope, including its audit-receipt digest;
- the signed certificate-signing audit receipt;
- current signed revocation registry;
- the exact revocation signing request, bound to the deployment-owned checkpoint;
- the revocation signer's v2 detached envelope, including its audit-receipt digest;
- the signed revocation-signing audit receipt;
- exact 31-image production manifest with provenance and SBOM attestations.

Create a manifest only after those artifacts exist:

```sh
python3 scripts/verify-production-evidence-bundle.py build \
  --bundle-root /absolute/production-bundle \
  --manifest /absolute/new/production-bundle-manifest.json \
  --qualification-input /absolute/production-bundle/qualification-input.json \
  --closure-input /absolute/production-bundle/closure-input.json \
  --closure-report /absolute/production-bundle/closure-report.json \
  --production-closure-certificate /absolute/production-bundle/certificate.json \
  --production-closure-signing-request /absolute/production-bundle/certificate-signing-request.json \
  --production-closure-external-signature /absolute/production-bundle/certificate-external-signature.json \
  --production-closure-signing-audit-receipt /absolute/production-bundle/certificate-signing-audit-receipt.json \
  --production-closure-revocation-registry /absolute/production-bundle/revocations.json \
  --production-closure-revocation-signing-request /absolute/production-bundle/revocation-signing-request.json \
  --production-closure-revocation-external-signature /absolute/production-bundle/revocation-external-signature.json \
  --production-closure-revocation-signing-audit-receipt /absolute/production-bundle/revocation-signing-audit-receipt.json \
  --production-image-manifest /absolute/production-bundle/production-images.json \
  --git-provenance-keyring /protected/trust/git-provenance-keyring.json \
  --release-binding-keyring /protected/trust/release-binding-keyring.json \
  --reviewer-keyring /protected/trust/production-reviewers.json \
  --worm-keyring /protected/trust/worm-evidence-keyring.json \
  --closure-public-key /protected/trust/closure-public-key.json \
  --revocation-public-key /protected/trust/revocation-public-key.json \
  --revocation-checkpoint /protected/release/revocation-checkpoint.json \
  --revocation-checkpoint /protected/release/revocation-checkpoint.json
```

For subsequent offline verification, replace `build` with `verify` and omit
the 12 artifact arguments. The verifier rejects symlinks and traversal,
checks every byte digest and pinned trust-root digest, reruns the qualification
compiler, requires byte-equivalent canonical closure input, recomputes the
eligible report and input/gate digests, verifies the certificate signature and
all scope trust bindings, verifies the short-lived revocation registry, and
rejects a revoked certificate. It also requires the image manifest release ID
and digest-pinned image set to match the signed release binding, requires
`scope.build_digest` to equal the image-manifest digest. The activation
expectation is derived afterward from the already signed scope and is carried
by the final activation artifact, avoiding a bundle/activation hash cycle.

The revocation checkpoint remains outside the 12-role bundle as a
deployment-owned trust anchor. Its validated digest is pinned in the manifest,
and the verifier requires the revocation signing request and registry sequence
to be the checkpoint's exact direct successor.

The checked-in negative baseline inventory is reviewed and sorted, but it is
not a production certificate. After any source change, run
`scripts/sync-closure-evidence-manifest.py` before the offline verifier; the
result must still retain `WORKTREE-NO-GIT` and `NOT_ISSUED` until immutable Git
and external production evidence really exist.

Trust roots remain outside the evidence bundle. Publishing an attacker-chosen
key next to an attacker-signed artifact never creates a valid positive bundle.

## Publish the runtime evidence generation

The admission Job and production runtime consume a fixed, read-only directory;
CI artifacts do not become a Kubernetes volume by implication. On the protected
deployment runner, publish a new volume generation only after the positive
bundle and activation have been independently attested:

```sh
python3 scripts/publish-production-release-evidence.py publish \
  --bundle-root /absolute/production-assurance \
  --manifest /absolute/production-assurance/evidence-manifest.json \
  --activation /absolute/production-assurance/activation.json \
  --activation-expectation /absolute/production-assurance/activation-expectation.json \
  --git-provenance-keyring /protected/trust/git-provenance-keyring.json \
  --release-binding-keyring /protected/trust/release-binding-keyring.json \
  --reviewer-keyring /protected/trust/production-reviewers.json \
  --worm-keyring /protected/trust/worm-evidence-keyring.json \
  --closure-public-key /protected/trust/closure-public-key.json \
  --revocation-public-key /protected/trust/revocation-public-key.json \
  --volume-name agenttrust-evidence-<release-generation> \
  --publication-root /protected/evidence-volumes
```

`volume-name` must equal the `persistent_volume_name` in the signed release
binding. The publisher recompiles qualification, verifies certificate,
revocation and activation, writes the nine standardized runtime documents plus
`publication-receipt.json` into a private staging directory, fsyncs it, removes
write permission and atomically renames it. It never overwrites a prior
generation. A release retry uses the `verify` subcommand with
`--publication-directory` instead of `--publication-root`.

The receipt says `filesystem_mode_read_only=true` and
`locked_retention_evidence_required=true`. POSIX modes are not WORM or managed
object-lock evidence; the separately qualified locked-retention condition must
still be real and current.
