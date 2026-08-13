# Contract security invariants

- Task completion is distinct from process success and requires a passing evaluator from `VERIFYING`.
- Signed Goal, Plan, Delegation, Approval, Authorization Lease, and Execution Authorization bind immutable hashes and expiry.
- Child delegation is a subset of the parent tool/resource lease.
- IDs are UUIDs; times are UTC RFC 3339; engineering values carry explicit units in domain payloads.
- Trace and public records contain references and hashes, never raw tokens, private keys, prompts, source bundles, or regulated payloads.
- Only the durable transition service may write terminal Task state.

