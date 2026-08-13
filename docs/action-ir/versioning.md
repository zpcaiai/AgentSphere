# Action migration

The current major is `agenttrust.action.v1`. Migrations are pure one-way functions that emit source/target version, migration ID, and before/after hashes. A v0 `arguments` object becomes a typed v1 payload only when no conflicting payload exists. Missing or ambiguous fields return `ACTION_IR_MIGRATION_LOSSY`; execution never guesses.

