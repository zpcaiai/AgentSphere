# Enterprise approval governance

Approval binds tenant, task/step, action, plan, parameters, resource/version, policy version,
environment, maximum risk, TTL and use count. The service resolves strong-authenticated approvers,
roles, resource ownership and separation-of-duties. Dual approval requires distinct subjects. The
same rules are re-evaluated immediately before atomic grant consumption, so role or ownership changes
invalidate an old decision.

The Vue console renders safe summaries and evidence references and emits only an intent. It never
creates a grant or updates status optimistically. Notification delivery failure is audited but cannot
approve. Cancel/kill revokes task grants. Break-glass is short-lived, cannot override safety
interlocks, and leaves the case in `POST_REVIEW_REQUIRED` until a strong-authenticated review.

Persist cases, decisions, grants/use counts and notification outbox in PostgreSQL. Production must use
transactional row locking for consumption and outbox delivery. The in-memory Rust core proves
bindings/concurrency semantics; enterprise IdP, database failover and notification providers require
live integration evidence.
