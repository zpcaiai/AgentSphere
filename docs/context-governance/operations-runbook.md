# Memory, prompt, knowledge, and policy operations

Memory writes require tenant, subject, owner, originating action digest, policy digest, TTL, and object digest. Retrieval applies tenant and subject authorization before generating candidates. Poisoned entries are quarantined. Deletion creates a tombstone unless an active Legal Hold requires preservation.

Prompts and knowledge snapshots are supply-chain assets with immutable version, provenance digest, signature, trust, expiry, rollback, and revocation. Context assembly has a hard token budget and never silently inserts expired or unauthorized material.

Policy changes pass static analysis, deterministic compilation, signature, side-effect-free simulation, impact review, separated approval, canary, and rollback. Exceptions are narrow, owned, time-limited, and compensated; P0/P1 exceptions are disabled in production.
