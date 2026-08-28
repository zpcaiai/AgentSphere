# Production closure external signing

Production closure uses a private-key-free, two-phase signing flow. The closure process never
loads a production private key. A KMS or approved signing service signs the exact Ed25519 payload,
and the finalizer verifies the detached signature before it writes a certificate.

This flow does not make an ineligible release eligible. `prepare-external-signing` rejects a
report unless all Batch 01–35 statuses and all closure gates are verified for the exact production
scope. The current checked-in evidence therefore continues to produce `NOT_ISSUED`.

## Prepare the immutable request

```bash
production-closure prepare-external-signing \
  closure-report.json closure-input.json kms:key:production-closure \
  closure-signing-request.json
```

The command creates a new file and refuses to overwrite an existing one. The request binds the
release, scope, report, validity window, key ID, canonical signing payload and its SHA-256 digest.
Keep the entire request as release evidence.

Validate `closure-signing-request.json` against
`schemas/release/production-closure-signing-request.schema.json`. Send only the decoded
`signing_payload` bytes to an approved Ed25519 KMS operation. Do not reserialize the embedded
certificate and do not sign the payload digest unless the KMS API is explicitly configured for
the same message-signing semantics.

The KMS integration returns a detached document:

```json
{
  "schema_version": "agenttrust.production-closure-external-signature.v2",
  "request_digest": "<sha256 of canonical signing request>",
  "algorithm": "Ed25519",
  "key_id": "kms:key:production-closure",
  "signed_at": "2030-01-01T00:00:00Z",
  "audit_receipt_digest": "<sha256 of the external signer audit receipt>",
  "signature": "<base64url Ed25519 signature without padding>"
}
```

The KMS adapter must obtain `request_digest` from the prepare command output or recompute it with
JCS. It must not accept a caller-supplied key ID outside its release policy. The v2 detached
envelope preserves the signer's timestamp and audit-receipt digest; the finalizer rejects stale or
malformed metadata, while the protected CI attestation binds the complete envelope as release
evidence.

## Finalize and verify

```bash
production-closure finalize-external-signing \
  closure-signing-request.json closure-external-signature.json \
  closure-public-key.json closure-report.json closure-input.json \
  production-closure-certificate.json

production-closure verify \
  production-closure-certificate.json closure-report.json closure-input.json \
  closure-public-key.json \
  signed-revocation-registry.json revocation-registry-public-key.json
```

Finalization reconstructs the canonical payload, verifies its digest, checks request/report/scope
bindings, checks the detached signature with the independently supplied public key, and performs
the normal offline certificate verification. The report and certificate both bind the canonical
SHA-256 digest of the entire closure input, not only its scope. A request, response, public-key,
input or report mismatch fails closed. The output is created atomically with `create_new`
semantics.

The certificate expiry is exactly the earliest expiry of its production scope, Batch 01–35
evidence, required gate evidence, trusted reviewer keys/keyring, and any active exception. It
cannot outlive a source that justified issuance.

Certificate verification also requires a current
`agenttrust.production-closure-revocation-registry.v1` snapshot. The signed snapshot is valid for
at most seven days, has a monotonic sequence, and binds the previous signed snapshot digest.
Consumers must persist the latest verified sequence and digest. Before replacing it, prove the
new snapshot is its exact successor:

```bash
production-closure verify-revocation-successor \
  previous-registry.json current-registry.json revocation-registry-public-key.json

production-closure verify-revocation-registry \
  current-registry.json revocation-registry-public-key.json
```

The first snapshot must have `sequence=1` and `previous_registry_digest=null`. Later snapshots must
increment by one and name the full signed digest of the previous snapshot. Missing, expired,
out-of-order, tampered or incorrectly signed registries fail closed. A consumer that loses its
trusted local checkpoint must re-bootstrap through the release authority; it must not trust an
arbitrary older chain supplied with a certificate.

Create registry snapshots through the same private-key-free boundary. The update contains only
new revocations; the preparer verifies the prior signed snapshot and carries every prior entry
forward. `-` is permitted only for sequence 1:

```bash
production-closure prepare-revocation-signing \
  revocation-update.json previous-registry.json revocation-registry-public-key.json \
  revocation-signing-request.json

production-closure finalize-revocation-signing \
  revocation-signing-request.json revocation-external-signature.json \
  previous-registry.json revocation-registry-public-key.json \
  signed-revocation-registry.json
```

The KMS signs the request's decoded `signing_payload`. A successor that removes or mutates any
historical revocation fails both finalization and `verify-revocation-successor`.

Before opening traffic or production writes, compare the verified certificate with the exact
deployment material and emit a create-new activation receipt:

```bash
production-closure verify-activation \
  production-closure-certificate.json closure-report.json closure-input.json \
  closure-public-key.json signed-revocation-registry.json \
  revocation-registry-public-key.json activation-expectation.json \
  activation-receipt.json
```

The expectation pins release ID, scope, build, release and topology digests. Missing, expired,
revoked or mismatched inputs never produce a receipt with `production_write_enabled=true`.

## Local signing boundary

The old `issue` command is disabled and returns `CLOSURE_EXTERNAL_SIGNING_REQUIRED`. Local signing
and `ClosureAuthority` are excluded from both the default library and binary. They are available
only in an explicitly built development binary:

```bash
cargo run -p agent-trust-production-closure \
  --features development-local-signing --bin production-closure -- issue-local ...
```

The development command still requires both runtime guards:

```text
AGENT_TRUST_PROFILE=development
AGENT_TRUST_ALLOW_LOCAL_CLOSURE_SIGNING=I_UNDERSTAND_LOCAL_KEYS_ARE_NOT_PRODUCTION
```

Local signing is never production evidence and must not be used to populate a production
certificate registry.

## Operational controls

- Bind the KMS authorization policy to the production closure key, release approver identities,
  change ticket and expected request digest.
- Log the KMS request ID, key version and returned request digest without logging private material.
- Retain the request, detached response, public-key version and final certificate in locked object
  storage and Batch 19 evidence.
- Revoke the certificate when the release, scope, key version, topology or evidence is revoked.
- Require independent review of the KMS policy and public-key distribution before issuance.
