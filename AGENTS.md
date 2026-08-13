# Agent Trust Control Plane implementation rules

1. Treat `skills/**/SKILL.md` as implementation instructions, not implementation evidence.
2. Keep one dependency-acyclic architecture and consume shared contracts.
3. Do not claim a batch complete without code, migrations, tests, reports, and evidence.
4. Production paths fail closed; development bypasses must be explicit and cannot enter production.
5. Never use mocks as evidence for Linux isolation, real protocol compatibility, HA/DR, or physical safety.
6. Public contract changes update schemas, generated clients, and compatibility tests together.
7. A production action passes Canonical Action IR, PEP authorization, ledger, and evidence paths.
8. Task completion and process execution success remain separate states.

