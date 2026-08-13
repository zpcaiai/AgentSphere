# Fail-closed behavior

PDP timeout/bad response, bundle mismatch, stale state, Registry unavailability/revocation, dev identity in production, missing idempotency, unknown/failed obligation, or approval drift denies execution. Cached ALLOW is never extended for writes or HIGH/CRITICAL actions. Continuous decisions invoke the external Runtime Supervisor for Pause/Kill; alerts alone are insufficient.

