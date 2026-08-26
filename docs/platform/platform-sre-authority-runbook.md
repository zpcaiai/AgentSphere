# Platform SRE authority operations runbook

## Safety boundary

Batch 34 governs the reliability control plane; it does not certify it. The authority records
tenant-scoped SLOs, burn alerts and incident links; multi-zone topology and health; immutable
backup manifests, WORM artifacts, ledger heads and key-recovery evidence; isolated restore drills;
DR plans and failover/failback; controlled chaos; sustained load and noisy-neighbor results;
schema/API/policy/pack-compatible canaries and rollback; cost/capacity; and trace/log/metric
evidence. A signed engine report always says `production_certification=false`.

Real multi-zone topology, managed PostgreSQL promotion, locked-retention object storage, KMS key
recovery, network/storage faults, representative sustained load and independent observation remain
`NOT_RUN` until their named adapters return immutable evidence from the actual production-owned
environment. Existing Python harness reports with `production_evidence=false` are useful local
checks, never substitutes for those gates.

## Control path

1. The operator authenticates with mTLS, route bearer token and a fresh strong human assertion.
2. `POST /v1/sre/actions` validates the exact command shape, role, approval count, tenant,
   resource version and request digest, then persists replay protection and a Canonical Action IR.
3. The durable orchestrator obtains PEP authorization, reserves the ledger entry and resource
   fence, and invokes `POST /v1/sre/executions` through Tool Proxy.
4. The executor verifies that the full executor request is the payload of the admitted action. It
   uses idempotent HTTPS/mTLS adapters for external effects and commits domain state plus the
   Evidence outbox atomically.
5. Evidence delivery changes `MUTATED_PENDING_EVIDENCE` to `SUCCEEDED`. A timeout before the
   Evidence receipt is an unknown process outcome, not a successful task claim. Retry the same
   idempotency key; never create a replacement command.

Disruptive operations (`FAILOVER`, `FAILBACK`, `EXECUTE_CHAOS`, `EXECUTE_LOAD`, `PLAN_UPGRADE`,
`ROLLBACK_UPGRADE`) require two approval IDs in the verified assertion. Backup, restore,
topology registration and campaign planning require at least one. Production chaos targets are
hard-denied by the command schema and database constraint.

## Dependency failure semantics

| Action | Policy/identity/ledger unavailable | Evidence unavailable | Adapter unavailable |
| --- | --- | --- | --- |
| Read-only status | Signed snapshot may permit bounded degraded read | Bounded degraded read with local journal | Not applicable |
| Ordinary/high-risk write | Fail closed | Mutation may be committed only with durable outbox; API remains incomplete until delivery | Fail closed before mutation |
| Credential or release change | Fail closed | Fail closed/incomplete | Fail closed |
| Emergency stop in a downstream safety system | Downstream safety controller may stop locally | Tamper-evident local journal and later reconciliation required | Safety stop must not depend on this authority |

Observability failure never broadens authorization. Overload rejects admission through bounded
queues/pools and records backpressure. Do not disable a readiness dependency to make a rollout
green.

## Database role

The schema owner applies the migration. The runtime role is `NOINHERIT NOSUPERUSER NOBYPASSRLS
NOCREATEDB NOCREATEROLE NOREPLICATION`, cannot create in `public`, cannot use database `TEMP`, and
uses `search_path=pg_catalog,public` with `row_security=on`. Grant only `SELECT, INSERT` on the 24
tables listed in the service startup gate. Grant `UPDATE` only on these columns:

- `sre_service_slos`: service, SLI/target/window/burn settings, release flag, status, version,
  updated time.
- `sre_deployment_topologies`: declared topology fields, status, version, updated time.
- `sre_dr_plans`, `sre_chaos_campaigns`, `sre_load_campaigns`: status and updated time.
- `deployment_rollouts`: status, canary percent and updated time.
- `sre_resource_versions`: version and action/ledger/fence facts plus updated time.
- `sre_action_ingress`: state, receipt and updated time.
- `sre_authority_executions`: state, lease owner/time, external/safe/Evidence result columns and
  updated time.
- `sre_evidence_outbox`: delivered time, delivery attempts and next-attempt time.

Never grant table-level `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, sequence access,
schema create, or any cross-domain table. The binary compares the complete observed table and
column grant sets and exits on drift.

## Required configuration

All file variables are absolute secure files. Core variables are:

- database URL/password/CA/role: `AGENT_TRUST_SRE_DATABASE_*`;
- inbound CA/certificate/key, listen/management addresses and ports:
  `AGENT_TRUST_SRE_TLS_*`, `AGENT_TRUST_SRE_LISTEN_ADDRESS`,
  `AGENT_TRUST_SRE_PORT=8097`, `AGENT_TRUST_SRE_MANAGEMENT_LISTEN_ADDRESS`,
  `AGENT_TRUST_SRE_MANAGEMENT_PORT=9107`;
- outbound CA/certificate/key: `AGENT_TRUST_SRE_OUTBOUND_*`;
- orchestrator and eight separated targets: `AGENT_TRUST_SRE_ORCHESTRATOR_*` and
  `AGENT_TRUST_SRE_{TOPOLOGY_PROBE,BACKUP,RECOVERY,DR,CHAOS,LOAD,UPGRADE,EVIDENCE}_{ENDPOINT,TOKEN_FILE}`;
- exact client SANs, token bindings, route subjects and human keyring/audience:
  `AGENT_TRUST_SRE_CLIENT_IDENTITIES`, `AGENT_TRUST_SRE_TOKEN_BINDINGS_FILE`,
  `AGENT_TRUST_SRE_{INGRESS,EXECUTOR,QUERY}_SUBJECT`, and
  `AGENT_TRUST_SRE_HUMAN_PRINCIPAL_*`;
- Evidence response verification and exact outbound SAN:
  `AGENT_TRUST_SRE_EVIDENCE_KEYRING_FILE` and
  `AGENT_TRUST_SRE_EVIDENCE_CLIENT_IDENTITY`;
- service identity and engine report signing key/id: `AGENT_TRUST_SRE_AGENT_*`,
  `AGENT_TRUST_SRE_ORGANIZATION_ID`, `AGENT_TRUST_SRE_REGION`,
  `AGENT_TRUST_SRE_TOOL_*`, `AGENT_TRUST_SRE_REPORT_SIGNING_KEY_*`.

Every endpoint is a distinct HTTPS root; every dependency uses a distinct bearer secret. The
outbound client requires TLS 1.3 mTLS, disables redirects, uses fixed connect/overall timeouts and
never reads a token from an environment value. The topology probe address must resolve through the
declared DNS path into `EXTERNAL_SERVICE_EGRESS_CIDR`; the platform SRE NetworkPolicy permits only
that explicit CIDR on 443/8443 and must not be widened for probe rollout.

## Zone health probes

`RECORD_ZONE_HEALTH` accepts only the observation/topology IDs, zone and a canonical
`probe_spec_digest`. The dedicated topology-probe adapter performs the measurement and returns the
component/dependency booleans, replica counts, observation time and immutable probe digest. The
authority rejects client-supplied measurements, an incomplete or extra fact, and any receipt whose
`probe_spec_digest` differs from the command. Missing configuration, readiness failure, transport
failure, malformed content type, oversized response or absent receipt all fail closed before the
database mutation. This corrects the unreleased v1 schema to match its runtime trust boundary; it
does not certify any real multi-zone environment.

## Backup and recovery

Before accepting a backup receipt verify the database artifact, object manifest, ledger head and
key recovery artifacts are encrypted and WORM locked, carry four distinct immutable evidence
records, and meet the declared retention. A restore target must be isolated from production. Pass
only on exact record counts, object integrity, ledger reconciliation, key recovery and measured
RTO/RPO. Keep failed drill records; never rewrite them.

## DR, chaos and load

Failover is allowed only from `READY` and failback only from `FAILED_OVER`. Adapter success is
insufficient if measured RTO/RPO exceed the plan. Chaos campaigns target an isolated environment,
bound fault budget, blast radius, abort conditions and cleanup digest. Failure to verify cleanup is
`CLEANUP_FAILED`. Load results bind the release/workload/duration/concurrency/quota and must record
percentiles, throughput, backpressure and noisy-neighbor isolation.

When an adapter call times out, inspect the authority execution by tenant and idempotency key. If
it remains `SIDE_EFFECTS_PENDING`, retry the same key so the adapter can replay its receipt. If it
is `MUTATED_PENDING_EVIDENCE`, do not repeat the external effect; the authority resumes Evidence
delivery with the original persisted timestamp, event ID and request bytes. Require
`/v1/evidence/authority-events`, the complete final PEP/ledger/fence binding, and a valid signed
receipt before finalization. `UNKNOWN` requires incident handling and reconciliation, not a blind retry.

## Upgrade and rollback

The plan is rejected unless schema, API, policy and pack compatibility are all true and the
rollback artifact is digest bound. Canary percentages increase monotonically through declared
steps. Any unsafe allow, Evidence gap or excessive error rate sets `ROLLING_BACK`. Rollback must
return the exact planned artifact digest through the upgrade adapter. Promotion at 100% remains an
engine state; the production closure gate still needs its independent evidence.

## Validation and evidence status

Static/local commands may validate schemas, migration ordering, contracts and source tests. The
resource-constrained session intentionally did not run Cargo, Docker, PostgreSQL, pytest or load
tests. Record those as `NOT_RUN`, not passed. Production readiness requires fresh reports from the
actual multi-zone/database/object-store/KMS/network/load environment plus customer acceptance and
independent certification where applicable.
