# Registry lifecycle

Tool versions move `DRAFT -> VALIDATED -> SIGNED -> ACTIVE -> DEPRECATED -> REVOKED`. Active security fields are immutable in application code and by PostgreSQL trigger. Revoked is terminal. Execution resolves exact versions only and binds schema, manifest, implementation digest, profiles, limits, compensation, revision, and deterministic snapshot hash.

