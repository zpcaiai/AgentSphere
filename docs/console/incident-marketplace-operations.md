# Incident and Pack Marketplace console operations

The enterprise console is a tenant-bound BFF. The browser authenticates with the server session,
sends `X-XSRF-TOKEN`, and uses the command UUID as `Idempotency-Key`. It never receives an
authority bearer token or a human-assertion signing key. The Java BFF signs the exact request and
forwards it to the authority Canonical Action ingress. HTTP `202` means only that the command was
durably accepted with `execution_pending=true`; it is not lifecycle completion or production
authorization.

## Authority routes and scopes

| Console route | Authority route | Service token | Required authority scope |
|---|---|---|---|
| `GET /v1/tenants/{tenantId}/incidents` | `GET /v1/authoritative/incidents` | `AGENT_TRUST_INCIDENT_READ_TOKEN_FILE` | `incident:query` |
| `GET /v1/tenants/{tenantId}/incidents/{incidentId}` | `GET /v1/authoritative/incidents/{incidentId}` | `AGENT_TRUST_INCIDENT_READ_TOKEN_FILE` | `incident:query` |
| `POST /v1/tenants/{tenantId}/incidents/actions` | `POST /v1/incidents/actions` | `AGENT_TRUST_INCIDENT_MUTATE_TOKEN_FILE` | `incident:mutate` |
| `GET /v1/tenants/{tenantId}/packs` | `GET /v1/authoritative/packs` | `AGENT_TRUST_PACK_MARKETPLACE_READ_TOKEN_FILE` | `packs:read` |
| `POST /v1/tenants/{tenantId}/packs/actions` | `POST /v1/packs/actions` | `AGENT_TRUST_PACK_MARKETPLACE_MUTATE_TOKEN_FILE` | `packs:mutate` |

Read routes still require a PEP query decision. Write routes require current strong authentication,
an exact tenant binding, a permitted role, an optimistic resource version, a bounded timestamp,
an idempotency binding, and a signed `X-AgentTrust-Human-Assertion`. Missing or invalid authority
configuration fails closed.

## Incident workflow

The human console exposes 14 governed operations: `TRIAGE`, `CONTAIN`, `INVESTIGATE`,
`PRESERVE_EVIDENCE`, `PLAN_REPLAY`, `COMPLETE_REPLAY`, `PUBLISH_ROOT_CAUSE`,
`BEGIN_REMEDIATION`, `TRIGGER_RECERTIFICATION`, `EVALUATE_RELEASE`, `START_CANARY`,
`RECORD_CANARY`, `ROLLBACK_RELEASE`, and `CLOSE`. `DETECT` remains machine-only.

The console displays the exact authoritative incident, evidence references, and ordered timeline.
Logical replay must have no resource or credential bindings. Sandbox replay must use `test-only`
credentials and `sandbox://` resources. Live replay requires a fresh, expiring lease and at least two
independent approvals. Release gate, canary, and rollback actions also require two approvals. Root
cause and release definition digests are recomputed in the browser and verified again by the BFF and
authority; this browser calculation is convenience validation, not trust evidence.

## Pack lifecycle

The Marketplace console exposes exactly 16 typed commands: `ONBOARD_PUBLISHER`,
`VERIFY_PUBLISHER_KEY`, `SET_PUBLISHER_TRUST`, `CONFIGURE_TENANT_CATALOG`, `SUBMIT_RELEASE`,
`REVIEW_RELEASE`, `REQUEST_INSTALLATION`, `APPROVE_INSTALLATION`, `INSTALL`, `ACTIVATE`,
`PLAN_UPGRADE`, `RECORD_CANARY`, `UPGRADE`, `ROLLBACK`, `DEACTIVATE`, and `REVOKE_RELEASE`.
The selected type determines the exact allowed fields and canonical resource identifier; unknown
fields are rejected before submission and again at the BFF.

The catalog renders publisher, supply-chain digest, release certificate, risk, compatibility,
region, entitlement, review, permission-expansion, installation, and activation state. These states
must not be collapsed:

- `INSTALL` stages verified artifacts; it does not activate them.
- `ACTIVATE` changes tenant lifecycle state; `ACTIVE` does not authorize a particular task.
- A release certificate has `engine_certificate_only=true` and `production_closure=false`.
- Per-task production use still requires current policy, identity, approval, lease, and execution
  authorization at the action boundary.

## Operational verification

Before enabling routes, verify the four token files are root-readable only, the configured authority
endpoints are internal HTTPS endpoints with pinned trust, and readiness returns exactly
`agenttrust.incident-release-readiness.v1` or `agenttrust.pack-marketplace-readiness.v1`. Validate the
OpenAPI/Java/browser parity with `python3 scripts/validate-enterprise-api-contract.py`.

Maven, Vitest, Playwright, live authority integration, and browser accessibility runs are separate
evidence gates. Source presence or a `202` receipt must never be recorded as those gates passing.
