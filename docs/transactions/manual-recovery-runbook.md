# Unknown outcome and manual recovery

Never map network timeout directly to FAILED. Locate the immutable execution by tenant/idempotency key, inspect external operation ID and target-system facts, and reconcile to SUCCEEDED/FAILED only with evidence. If facts are ambiguous, open `ManualRecoveryCase` with impact, last known state, and bounded operator steps. Compensation runs LIFO as new controlled actions and only when current resource version/value still matches. Record human evidence and rerun evaluation.
