# Durable orchestrator runbook

The Batch 29 state machine is authoritative for task and step state. Commands include an idempotency identifier and expected state version. A plan digest change invalidates the active lease. Completion requires terminal runtime state plus ledger success for side effects, evaluator hard-gate pass, and verified evidence. Kill remains distinct from cancel and needs both credential revocation and Rust supervisor acknowledgement.

Production configuration selects PostgreSQL and Temporal and disables the development in-memory store. During database or workflow-engine partition, stop admitting state-changing commands, retain bounded work, and reconcile command identifiers after recovery. During supervisor loss, mark kill unconfirmed and continue credential revocation; never report the task killed until acknowledgement arrives.

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
