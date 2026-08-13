# Protocol Adapter SDK security and versioning

Adapters map protocol identity, capability, request, error, stream and artifact semantics into the
canonical IR. They cannot authorize, receive raw credentials, call the executor or write task state.
Production manifests are signed, digest-pinned and limited to `SUBMIT_IR`, `RETURN_RESULT`, approved
network profiles and read-only configuration. Security-critical mapping loss blocks conformance.

For every protocol release, import a version bundle, run golden/invalid/duplicate/cancel/disconnect
vectors, review the mapping report, then approve the exact adapter version. Unknown critical features
fail closed. A rollout keeps the prior version available until evidence from the new version passes;
rollback means reactivating the prior immutable bundle, never mutating an approved bundle.

The Echo adapter is a conformance example, not a production protocol implementation. Runtime process
or WASM isolation still requires Linux/WASI deployment evidence.
