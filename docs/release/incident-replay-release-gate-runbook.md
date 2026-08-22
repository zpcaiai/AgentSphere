# Incident, Replay and Release Gate authority runbook

Batch 22 is an engine authority, not the Batch 36 production-closure issuer. Its signed release receipt always has `engine_certificate_only=true` and `production_closure=false`. A deployment remains blocked until Batch 36 consumes this receipt together with the other real-environment gates.

## Production boundary

The TLS 1.3 data plane listens on port `8090`; the unauthenticated management readiness listener is restricted by the pod/network boundary on port `9101`. The data plane requires a client certificate with exactly one allowed DNS or URI SAN, a canonical `X-AgentTrust-Tenant-Id`, and a physical bearer credential uniquely bound to that SAN, tenant, subject and route scope.

| Route | Scope | Caller | Result |
| --- | --- | --- | --- |
| `POST /v1/incidents/detections` | `incident:detect` | Runtime anomaly authority; token subject must equal exact SAN | 202 Canonical Action admission |
| `POST /v1/incidents/actions` | `incident:mutate` | Incident Console/BFF with strong signed human assertion | 202 Canonical Action admission |
| `POST /v1/incidents/executions` | `incident:execute` | Production execution runtime; token subject must equal exact SAN | Durable fenced mutation |
| `GET /v1/authoritative/incidents` | `incident:query` | Enterprise BFF | Authoritative tenant page |
| `GET /v1/authoritative/incidents/{incident_id}` | `incident:query` | Enterprise BFF | Complete ordered timeline |
| `GET /ready` | data mTLS or management network | Probe | Exact `agenttrust.incident-release-readiness.v1` |

The unified human action route selects the workflow through `operation`: `TRIAGE`, `CONTAIN`, `INVESTIGATE`, `PRESERVE_EVIDENCE`, `PLAN_REPLAY`, `COMPLETE_REPLAY`, `PUBLISH_ROOT_CAUSE`, `BEGIN_REMEDIATION`, `TRIGGER_RECERTIFICATION`, `EVALUATE_RELEASE`, `START_CANARY`, `RECORD_CANARY`, `ROLLBACK_RELEASE`, or `CLOSE`. The request contract is `schemas/incidents/incident-command.schema.json`; receipt fields are exactly the `agenttrust.incident-action-receipt.v1` schema.

Every write follows Canonical Action IR -> PEP -> transaction ledger/fence -> authority execution -> immutable local evidence/outbox. The executor rejects requests missing the admitted action hash, ledger execution UUID, the UUID and digest of the exact RESERVED ledger event signed by PEP, fence digest, current resource version, PEP decision ID/digest, or authorization Evidence reference/digest. Containment and replay dependencies must echo the same ledger event ID/digest in their signed response; a later RUNNING event cannot replace the fact that was authorized.

## Replay and containment invariants

- `LOGICAL` plans accept no credential, lease, resource reference or external side effect. The replay effect receipt must report `effect_count=0` and no production access.
- `SANDBOX` plans accept only `sandbox://` resources and `test-only` credentials. Any production-access observation fails the run.
- `LIVE` plans require a fresh unexpired lease digest and at least two approval IDs. Execution obtains a new PEP/ledger/fence binding; the old incident execution cannot be replayed.
- Containment requires kill, credential revocation, integration isolation and artifact freeze. It requires approval or a maximum-15-minute break-glass record with compensating controls and review due within 24 hours. The containment coordinator must return at least four immutable evidence references/digests under the same idempotency key.
- External containment and replay calls use different HTTPS roots and different physical token files. Their idempotency key and authorization/ledger bindings survive an authority restart; expired execution leases can be claimed by another replica.

## Release gate

`EVALUATE_RELEASE` requires two approvals and the exact control baseline `CONTRACT`, `IDENTITY`, `POLICY`, `SANDBOX`, `IDEMPOTENCY`, `ROLLBACK`, `TRACE`, `THREAT`, `COMPLIANCE`, and `DOMAIN_EVALUATOR`. Every evidence item must bind the same release digest, pass, be within the definition age, and have an Evidence URI and SHA-256 digest. Any open P0/P1 incident blocks issuance. The receipt binds definition/evidence, rollback artifact and canary plan, is valid for at most seven days, and is Ed25519 signed from the mounted release-engine key.

Canary percentage is bounded to 1-10. Failed canary metrics force `ROLLBACK_REQUIRED`; rollback is a new authorized action and produces its own immutable event.

## Required environment

Database: `AGENT_TRUST_INCIDENT_DATABASE_URL_FILE`, `AGENT_TRUST_INCIDENT_DATABASE_PASSWORD_FILE`, `AGENT_TRUST_INCIDENT_DATABASE_CA_FILE`, `AGENT_TRUST_INCIDENT_DATABASE_EXPECTED_ROLE`.

Inbound identity: `AGENT_TRUST_INCIDENT_TLS_CA_FILE`, `AGENT_TRUST_INCIDENT_TLS_CERTIFICATE_FILE`, `AGENT_TRUST_INCIDENT_TLS_PRIVATE_KEY_FILE`, `AGENT_TRUST_INCIDENT_CLIENT_IDENTITIES`, `AGENT_TRUST_INCIDENT_TOKEN_BINDINGS_FILE`, `AGENT_TRUST_INCIDENT_HUMAN_PRINCIPAL_KEYRING_FILE`, `AGENT_TRUST_INCIDENT_HUMAN_PRINCIPAL_AUDIENCE`, `AGENT_TRUST_INCIDENT_MAXIMUM_AUTHENTICATION_AGE_SECONDS`.

Outbound mTLS: `AGENT_TRUST_INCIDENT_OUTBOUND_CA_FILE`, `AGENT_TRUST_INCIDENT_OUTBOUND_CERTIFICATE_FILE`, `AGENT_TRUST_INCIDENT_OUTBOUND_PRIVATE_KEY_FILE`.

Dependencies: `AGENT_TRUST_INCIDENT_ORCHESTRATOR_ENDPOINT`, `AGENT_TRUST_INCIDENT_ORCHESTRATOR_TOKEN_FILE`, `AGENT_TRUST_INCIDENT_CONTAINMENT_ENDPOINT`, `AGENT_TRUST_INCIDENT_CONTAINMENT_TOKEN_FILE`, `AGENT_TRUST_INCIDENT_REPLAY_ENDPOINT`, `AGENT_TRUST_INCIDENT_REPLAY_TOKEN_FILE`. All endpoints are exact HTTPS roots; the two effect endpoints and token files must differ.

Release/action identity: `AGENT_TRUST_INCIDENT_RELEASE_SIGNING_KEY_FILE`, `AGENT_TRUST_INCIDENT_RELEASE_SIGNING_KEY_ID`, `AGENT_TRUST_INCIDENT_AGENT_INSTANCE_ID`, `AGENT_TRUST_INCIDENT_ORGANIZATION_ID`, `AGENT_TRUST_INCIDENT_AGENT_VERSION`, `AGENT_TRUST_INCIDENT_REGION`, `AGENT_TRUST_INCIDENT_TOOL_ID`, `AGENT_TRUST_INCIDENT_TOOL_VERSION`, `AGENT_TRUST_INCIDENT_EXECUTOR_CREDENTIAL_PROFILE`, `AGENT_TRUST_INCIDENT_SERVICE_SUBJECT`, `AGENT_TRUST_INCIDENT_EXECUTION_LEASE_SECONDS`.

Listeners: `AGENT_TRUST_INCIDENT_LISTEN_ADDRESS`, `AGENT_TRUST_INCIDENT_PORT`, `AGENT_TRUST_INCIDENT_MANAGEMENT_LISTEN_ADDRESS`, `AGENT_TRUST_INCIDENT_MANAGEMENT_PORT`.

## Database role

Provision the external LOGIN role `incident_authority_application_role` as `NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION`, with `row_security=on` and fixed `search_path=pg_catalog, public`. Revoke schema `CREATE`, database `TEMP`, sequence, direct function `EXECUTE`, `DELETE`, and `TRUNCATE`; grant only database `CONNECT`, schema `USAGE`, and the table privileges below.

Grant `SELECT,INSERT` on the authority tables. Grant only these updates:

- `incidents(status,owner,severity,resource_version,updated_at)`;
- `incident_action_ingress(state,receipt,updated_at)`;
- `incident_resource_versions(resource_version,action_hash,ledger_execution_id,fence_digest,updated_at)`;
- `incident_authority_executions(state,execution_owner,execution_lease_until,safe_result,safe_result_digest,stable_error,updated_at)`;
- `release_gate_runs(state,updated_at)`;
- `incident_evidence_outbox(authority_receipt,authority_receipt_digest,published_at,delivery_attempts)`.

All tenant tables use `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`. Timeline, containment, preservation, replay plans/runs, root-cause, recertification, certificates, canary events, local evidence and assertion-use rows are immutable by triggers.

## Evidence boundary

The local transaction returns an `outbox://incident-evidence/...` reference, not a signed Evidence-authority receipt. Production closure must wait for the outbox publisher to store a signed authority receipt. Code and local tests do not prove a real containment drill, sandbox isolation, live replay, multi-zone HA, canary rollback, or customer acceptance; keep those gates `NOT_RUN` until their named environment evidence exists.
