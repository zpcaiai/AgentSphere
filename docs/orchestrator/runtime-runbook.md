# Durable orchestrator runbook

The Batch 29 state machine is authoritative for task and step state. Commands include an idempotency identifier and expected state version. A plan digest change invalidates the active lease. Completion requires terminal runtime state plus ledger success for side effects, evaluator hard-gate pass, and verified evidence. Kill remains distinct from cancel and needs both credential revocation and Rust supervisor acknowledgement.

Production configuration selects PostgreSQL and Temporal and disables the development in-memory store. During database or workflow-engine partition, stop admitting state-changing commands, retain bounded work, and reconcile command identifiers after recovery. During supervisor loss, mark kill unconfirmed and continue credential revocation; never report the task killed until acknowledgement arrives.

The production ingress authority binds an idempotency key to the complete canonical gateway
envelope, not only to the Action payload hash. A changed request identifier, trace, identity,
timestamp, tenant context, or payload under the same key is a conflict. START and every later
command are accepted only after the exact command has an append-only PostgreSQL event and the
receipt URI matches the current tenant, task, and positive event sequence. The stream has a
database uniqueness boundary on `(tenant_id, task_id, command_id)` and an ingress foreign key;
database triggers reject event mutation/deletion and reject changes to immutable ingress fields
or invalid status transitions. The runtime database role receives only `SELECT`/`INSERT` on both
tables plus column-level `UPDATE(status, updated_at)` on ingress. It receives no stream update or
delete authority.

An admission receipt proves durable workflow/START acceptance and deliberately reports
`execution_pending=true`; it never proves that a tool ran or that the task completed. If Temporal
accepted a command but its PostgreSQL event is unavailable, the API returns a stable dependency
error and heals only when the authoritative transition cursor and command fingerprint provide an
unambiguous binding.

Use `python3 -m python.production_gates.live_integrations ... temporal` for a
bounded real-CLI namespace/workflow start/describe/terminate protocol probe.
For a production endpoint, add
`--production-tls`, `--binary-sha256`, `--ca-file`, `--client-certificate`,
`--client-private-key`, and `--tls-server-name`. Production mode rejects local
addresses, unpinned CLI binaries, incomplete mTLS material and overly broad key
permissions. The lifecycle report never upgrades a local development server
into production evidence and remains non-certifying until scoped HA and
failover evidence is externally signed. Temporal cluster failover, production
PostgreSQL failover, supervisor outage, and distributed partition recovery
remain external gates.
