# Security evaluation campaign runbook

This runbook operates the Batch 33 control-plane authority. A signed report proves what the
evaluation engine observed for one immutable campaign configuration. It is explicitly
`ENGINE_EVALUATION_ONLY`, always has `production_certified=false`, and is not customer acceptance,
independent certification, real Linux isolation evidence, or production red-team evidence.

## Control path and trust boundaries

The public action route never writes campaign state. It normalizes the request into Canonical
Action IR and submits it to the shared orchestrator. Only Tool Proxy may call the executor route,
and every request must bind the exact tenant, action hash, ledger execution and immutable ledger
event, fence, resource version, policy decision, authorization Evidence, idempotency key, and trace.

The executor first commits an immutable execution claim. Before any runner call it locks the
campaign and verifies:

- an `isolated-*` profile and pinned environment-attestation digest;
- an ephemeral sandbox, isolated tenant, or digital twin target;
- exact step, request, token, cost and deadline budgets;
- `production_access_allowed=false` and `physical_effects_allowed=false`;
- an armed, non-tripped kill switch.

The isolated runner must return an exact receipt proving the same limits, no production access,
no physical side effect, an armed kill switch, and a cleanup digest. Network ambiguity becomes
`UNKNOWN` and is never replayed. A successful database mutation commits an immutable local event
and outbox record. The action remains `MUTATED_PENDING_EVIDENCE` until the Evidence authority
returns an idempotent receipt; then and only then does the executor return `SUCCEEDED`.

The TLS 1.3/mTLS data listener and plaintext Kubernetes management listener are separate. The
management listener exposes only bounded `/live` and `/ready` handlers and must be isolated by
default-deny plus exact kubelet/node probe-CIDR ingress whenever it binds an unspecified address.

## Dataset and scenario admission

Dataset manifests and scenario definitions are canonicalized with JCS, SHA-256 pinned and verified
against the configured Ed25519 keyring. A `(tenant, dataset, version)` or
`(tenant, scenario, version)` record is immutable. Revoked or quarantined material cannot be added
to a new approved campaign. Never place samples, secrets or vulnerability detail in logs or safe
summaries.

Scenario definitions declare target, preconditions, ordered steps, expected controls, success and
failure criteria, and cleanup. The shared catalog covers prompt/goal injection, tool and credential
abuse, MCP declaration/behavior mismatch, recursive A2A cascade, context/memory poisoning,
identity spoofing, approval bypass, sandbox escape, slow encoded exfiltration, coding, industrial,
energy, medical and sensitive-interaction domains. Industrial, energy and medical physical control
steps are accepted only as `DIGITAL_TWIN_ONLY`.

## Campaign workflow

1. Register a signed dataset version and signed scenarios.
2. Create a campaign with release, configuration, policy, pack, model and prompt digests.
3. Attach scenarios with deterministic seeds; approval requires at least one scenario.
4. Approve, then start through the isolated runner. Do not call a runner directly.
5. Record immutable results with typed prevent/detect/contain/recover values, coverage, Evidence
   references and cleanup receipts.
6. Open findings for control failures. High or critical findings require remediation and retest.
7. Link a change digest, run a candidate campaign and record the retest. A finding is verified only
   after a passing retest linked to the remediation and candidate result.
8. Complete the campaign. The authority requires common plus coding, industrial, energy, medical
   and sensitive-interaction coverage, at least eight threat surfaces, and a result for every
   attached scenario.
9. Review the signed report. Any open high/critical finding, high-risk control failure, regression
   beyond the configured integer threshold, cleanup failure, or incomplete Evidence blocks release.
10. Publish a baseline only from an unblocked report with complete cleanup and Evidence.

Task completion and campaign execution are separate. An accepted action receipt says only that the
orchestrator admitted the action. A campaign may finish `FAILED`, `CLEANUP_FAILED` or `KILLED` while
the state-transition action itself has executed successfully.

## Emergency containment

Trip the environment kill switch through the same Canonical Action/PEP/ledger/Evidence path. The
runner receipt must prove containment. The switch is one-way in the production authority; recovery
requires a new isolated environment and new attestation, not an in-place reset. If the runner
crashes, cleanup fails, the provider is unavailable, a dataset signature is corrupt, or Evidence is
partially unavailable, retain the failed/unknown state, preserve outbox data and open an incident.
Never manually edit campaign, execution, result, report or Evidence rows.

## Verification commands

When the shared resource freeze is released, run from the repository root:

```sh
cargo test --locked -p agent-trust-security-evaluation-lab
cargo clippy --locked -p agent-trust-security-evaluation-lab --all-targets -- -D warnings
cargo build --locked --release -p agent-trust-security-evaluation-lab --bin agenttrust-security-evaluation-authority
python3 scripts/validate-production-migrations.py
python3 scripts/validate-runtime-assets.py
```

Then run a real PostgreSQL role/RLS matrix, TLS/mTLS SAN and token negative matrix, runner crash,
cleanup failure, corrupt dataset, provider outage, partial Evidence outage, concurrent fence,
process restart and outbox replay tests in an isolated non-production environment. Archive commands,
exit codes, signed reports and Evidence receipts. Until those commands actually run, their state is
`NOT_RUN`; do not convert source tests into evidence.

## External evidence boundary

Real gVisor/runsc isolation, model-provider attacks, MCP/A2A endpoints, HA/DR, sustained load,
physical protocol safety, customer acceptance, expert signature and independent certification all
remain external gates. No local deterministic test or engine signature satisfies those gates.
