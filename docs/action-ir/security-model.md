# Action IR security model

Adapters can create only `ActionDraft`. `VerifiedAction` has no public constructor and is created after schema/version, canonical hash, trusted key, Ed25519 signature, time window, signer binding, and revocation checks. Real secrets are rejected by key name and only credential references enter the IR. Policy input has one constructor joining Canonical Action, immutable Registry snapshot, runtime, and trajectory risk.

