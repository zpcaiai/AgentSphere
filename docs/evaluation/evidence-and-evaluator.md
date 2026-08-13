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
