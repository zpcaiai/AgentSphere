# Enterprise Approval production runtime

The `agenttrust-approval-service` binary is fail-closed. It serves the approval
API over native TLS 1.3 with a required client certificate. The certificate
must contain exactly one SAN and that SAN must exactly match one configured
`DNS:` or `URI:` identity. The separate management listener serves only
`GET /ready`; it defaults to `127.0.0.1:9095` and may be explicitly bound to an
unspecified address for a kubelet probe protected by network policy. The TLS
data listener also exposes mTLS-only `GET /ready` for service-to-service
readiness checks.

The BFF approval inbox reads `GET /v1/authoritative/approvals` with
`approvals:read`. Pages contain at most 100 `agenttrust.approval-case-view.v1`
safe views and a canonical `data_digest`. The optional cursor is Ed25519 signed,
expires after 15 minutes, and is bound to the exact tenant and dashboard
`resource` selector. The view never returns request justification, assertion
documents, approver identities, or fabricated evidence references. Every v2 case carries exact
`agenttrust.approval-review-material.v1` material, the complete
`agenttrust.authority-evidence-event-request.v1` sent to the existing Evidence Authority, and its
`agenttrust.signed-authority-evidence-receipt.v1`. The request is an `AUTHENTICATED_EVENT` with
event type `APPROVAL_REVIEW_PREPARED`; its payload hash is JCS SHA-256 of the material and its
artifact list is exactly diff/risk/snapshot for Coding or risk/snapshot for Industrial. Approval
recomputes the request digest, verifies the shared receipt, pins tenant, task, issuer, key and exact
mTLS source SAN, and exposes three immutable Evidence references. Missing, stale or mismatched
evidence fails closed.

Create that binding through `POST /v1/domain-runtime/approval-review-evidence`, not in the
approval process. The caller must present mTLS plus a tenant-bound
`domain-runtime:approval-review-evidence` credential and exact tenant, idempotency, authority-event
and payload-digest headers. The domain-risk producer pins `source_service` to its configured
outbound SAN, calls Evidence Authority with its dedicated `evidence:authority-event` token, verifies
the bounded signed response, and returns the complete material/request/receipt tuple consumed here.

## Required configuration

All file paths are absolute, regular, non-symlink paths. Secret files reject
group/world access except read access for the current process group, reject NUL
and embedded newlines, and allow at most one trailing line ending.

| Variable | Contract |
| --- | --- |
| `AGENT_TRUST_APPROVAL_DATABASE_URL_FILE` | Secret file containing a PostgreSQL URL with `sslmode=verify-full`, `options=-csearch_path=pg_catalog,public`, no password, and the exact expected role as username. |
| `AGENT_TRUST_APPROVAL_DATABASE_PASSWORD_FILE` | Independent secret file containing the database password. The password is passed through `PgConnectOptions` and never accepted in the URL. |
| `AGENT_TRUST_APPROVAL_DATABASE_CA_FILE` | PostgreSQL server CA bundle. |
| `AGENT_TRUST_APPROVAL_DATABASE_EXPECTED_ROLE` | Lowercase PostgreSQL application role. Startup rejects superuser, BYPASSRLS, CREATEDB, CREATEROLE, schema-create, delete, signed-grant replacement, disabled row security, or a non-exact search path. |
| `AGENT_TRUST_APPROVAL_ISSUER` | Issuer embedded in signed grants and receipts. |
| `AGENT_TRUST_APPROVAL_KEY_ID` | Signing key ID matching `[A-Za-z0-9._-]{1,128}`. |
| `AGENT_TRUST_APPROVAL_PRIVATE_KEY_FILE` | Secret raw 32-byte or base64url-no-pad Ed25519 signing key. |
| `AGENT_TRUST_APPROVAL_CLIENT_IDENTITIES` | Comma-separated exact `DNS:` or `URI:` client SAN allow-list. |
| `AGENT_TRUST_APPROVAL_TOKEN_BINDINGS_FILE` | `agenttrust.approval-token-bindings.v1` document. Each raw token digest is bound to one mTLS identity, tenant, service subject, and scope. A digest cannot be reused across scopes or subjects. |
| `AGENT_TRUST_APPROVAL_PRINCIPAL_KEYS_FILE` | Independent `agenttrust.approval-principal-keyring.v1` Ed25519 public keyring for human principal assertions. Every key has an explicit canonical tenant allow-list. |
| `AGENT_TRUST_APPROVAL_PRINCIPAL_AUDIENCE` | Expected audience, which must exactly match the keyring and every assertion. |
| `AGENT_TRUST_APPROVAL_REVIEW_EVIDENCE_KEYRING_FILE` | Public-only `AUTHORITY_EVIDENCE_RECEIPT` trust policy for the Evidence Authority issuer/key and allowlisted independent review-fact source SANs. Approval never mounts an Evidence Authority private key. |
| `AGENT_TRUST_APPROVAL_DECISION_EVIDENCE_KEYRING_FILE` | `agenttrust.approval-decision-evidence-keyring.v1` public keyring. Exactly one `ACTIVE` Ed25519 entry must match the configured Approval signer; `VERIFY_ONLY` entries validate historical receipts at their original `decided_at`. Key validity is half-open `[not_before, expires_at)`. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_RECEIPT_KEYRING_FILE` | Public-only `agenttrust.approval-review-evidence-keyring.v2` trust policy used to verify Evidence Authority delivery receipts. Every configured tenant and the exact decision publisher source identity require an `ACTIVE` key entry. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_SOURCE_IDENTITY` | Exact `DNS:` or `URI:` SAN on the outbound client certificate. It must also be the subject/client identity of the dedicated Evidence token binding and an active `source_services` member in the receipt keyring. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_ENDPOINT` | Exact HTTPS origin of the Evidence Authority; base paths, query strings, userinfo, redirects, non-TLS endpoints, and system trust are rejected. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_READINESS_SCHEMA` | Must be `agenttrust.evidence-readiness.v1`; Approval readiness requires `ready`, `database_ready`, and `worm_ready` all true. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_TOKEN_FILE` | Dedicated rotating `evidence:authority-event` scope token. The file is re-read before every readiness and delivery request. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_CA_FILE` | Pinned Evidence Authority server CA bundle. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_CLIENT_CERTIFICATE_FILE` | Outbound mTLS certificate whose single SAN is the configured Evidence source identity. |
| `AGENT_TRUST_APPROVAL_EVIDENCE_CLIENT_PRIVATE_KEY_FILE` | Private outbound mTLS key; must be an absolute single-link private regular file. |
| `AGENT_TRUST_APPROVAL_TLS_CA_FILE` | Client-certificate CA bundle. |
| `AGENT_TRUST_APPROVAL_TLS_CERTIFICATE_FILE` | Server certificate chain. |
| `AGENT_TRUST_APPROVAL_TLS_PRIVATE_KEY_FILE` | Server private key secret file. |

## Human identity boundary

Opaque service tokens authenticate BFF or service callers only and do not
carry human roles, resource ownership, or strong-auth claims. Case creation,
decision, grant issuance, and revocation also require exactly one
`x-agenttrust-principal-assertion` header. It is the base64url-no-pad encoding
of a `SignedApprovalPrincipalAssertion`, signed by an independent configured
Ed25519 key and valid for at most 300 seconds.

The assertion binds tenant, human subject, roles, owned resources, strong-auth
state, issuer, audience, issue/expiry times, UUID JTI, exact client certificate
identity, scope, and request digest. The request digest is lowercase SHA-256 of
RFC 8785 JCS over:

```json
{
  "schema_version": "agenttrust.approval-principal-request-binding.v1",
  "method": "POST",
  "path": "/the/exact/request/path",
  "tenant_id": "the-canonical-tenant-uuid",
  "client_identity": "DNS:or-URI:exact-mtls-san",
  "service_subject": "the-token-bound-service-subject",
  "scope": "approvals:request|approvals:decide|approvals:issue|approvals:revoke",
  "idempotency_key": "the-exact-header-value",
  "body": {}
}
```

`body` is the strict typed DTO reserialization, not the original byte sequence.
Set-valued arrays (`roles`, `owned_resources`, and `required_roles`) are sorted
lexicographically before JCS. Path UUIDs and the tenant UUID use canonical
lowercase hyphenated form.

The four human mutations and exact service scopes are:

| Path | Scope | Strict body |
| --- | --- | --- |
| `POST /v1/approvals/cases` | `approvals:request` | `{"schema_version":"agenttrust.approval-case-create.v2","request":ApprovalRequest,"policy":ApprovalPolicy}` |
| `POST /v1/approvals/cases/{case_id}/decisions` | `approvals:decide` | `{"schema_version":"agenttrust.approval-decision.v1","decision":"APPROVE|REJECT|POST_REVIEWED","reason":"..."}` |
| `POST /v1/approvals/cases/{case_id}/grants` | `approvals:issue` | `{"schema_version":"agenttrust.enterprise-approval.v1"}` |
| `POST /v1/approvals/grants/{grant_id}/revoke` | `approvals:revoke` | `{"schema_version":"agenttrust.enterprise-approval.v1","reason":"..."}` |

`ApprovalRequest` contains, in typed DTO declaration order, `tenant_id`,
`task_id`, `step_id`, `action_hash`, `plan_hash`, `parameter_hash`, `resource`,
`resource_version`, `policy_version`, `environment`, `risk`,
`review_context`, `review_evidence`, `requester_subject`, `agent_owner_subject`, `justification`,
`requested_ttl_seconds`, and `requested_uses`. `ApprovalPolicy` contains
`policy_id`, `policy_version`, `approval_type`, `minimum_approvers`,
`required_roles`, `prohibit_requester`, `prohibit_agent_owner`,
`require_resource_owner`, `maximum_ttl_seconds`, `maximum_uses`, and
`maximum_risk`. Unknown fields are rejected.
Human justification, decision-reason and revocation-reason limits are measured over their UTF-8
encoding and may not exceed 4096 bytes; the OpenAPI and JSON Schemas expose the required
`x-agenttrust-max-utf8-bytes` keyword, and production handlers enforce it before persistence.

RFC 8785 JCS sorts every JSON object member lexicographically, so wire object
member order is irrelevant to the request digest. Arrays retain their order;
the typed Rust DTO uses ordered sets for `required_roles`, while the assertion
uses ordered sets for `roles` and `owned_resources`, producing lexicographically
sorted arrays. The signed assertion's `signature` field is the base64url-no-pad
64-byte Ed25519 signature over JCS of the complete assertion with
`signature:""`. The HTTP header is base64url-no-pad of the UTF-8 JSON encoding
of the complete signed assertion, with no JWS wrapper.

Every accepted assertion JTI and signed payload digest is durably recorded in
the same tenant-scoped transaction as the mutation. A JTI may replay only the
same issuer, subject, scope, request digest, signed assertion, and expiry.
The fixed, test-only cross-language vector is
`schemas/approval/principal-assertion.golden.json`; it includes the exact JCS,
digest, Ed25519 public key/signature, full assertion, and encoded header value.
Its published private seed is test material and must never be configured in a
deployment.

## Database and grant invariants

Apply `migrations/enterprise-approval/0036_01_02_production_approval.sql` in the
immutable production manifest order. It forces RLS for every approval table
using `current_setting('app.tenant_id', true)`, records immutable idempotency
responses, assertions, events, and signed consumption receipts, and constrains
grants to one use. The migration is environment-independent and intentionally
does not create roles or grant application privileges; the production migration
runner must configure the expected least-privilege role before service startup.

Apply `0036_01_25_approval_review_evidence_v2.sql` before the v2 workload. It refuses to run while
any legacy case remains mutable or any unrevoked single-use grant still derives from a legacy
request. Terminal legacy rows are retained as audit history but are excluded from the approval
inbox because the service will not invent their missing review facts. The approval Deployment uses
`Recreate`, preventing v1 and v2 request/response contracts from serving concurrently.

Apply `0036_01_26_approval_decision_evidence.sql` next. Every human decision, its immutable
`agenttrust.approval-decision-evidence.v1` receipt, and one independent Evidence Authority request
commit in one tenant-scoped transaction. A deferred reverse constraint prevents a decision without
both receipt and outbox row. The signed receipt binds tenant, case, task, decision, reason digest,
stable request/idempotency digests, actor, principal request binding, action/plan/parameter/resource
versions, final case status, and the exact outbox request. Retrying the same idempotency key with a
fresh assertion JTI returns the first receipt only when the stable actor and assertion request digest
still match; a changed semantic request fails closed.

The delivery worker claims one row at a time with `FOR UPDATE SKIP LOCKED`, a lease longer than the
bounded TLS request, tenant round-robin fairness, and capped exponential retry. Network errors,
timeouts, non-success responses, malformed bodies, invalid signatures, and uncertain outcomes stay
pending as `OUTCOME_UNKNOWN`/`RECEIPT_INVALID`; they never fabricate successful Evidence delivery.
Only a strictly verified `agenttrust.signed-authority-evidence-receipt.v1` can atomically set the
delivery columns. The application role needs UPDATE on exactly `delivery_attempts`,
`next_attempt_at`, `lease_owner`, `lease_expires_at`, `last_attempt_at`, `last_error_code`,
`signed_authority_receipt`, and `delivered_at`; startup rejects a missing delivery privilege and
also rejects DELETE or immutable payload replacement privileges.

Both readiness endpoints query every configured tenant under its RLS context. Any undelivered row
with `CONFIGURATION_INVALID` or `RECEIPT_INVALID` fails readiness immediately; an
`OUTCOME_UNKNOWN` backlog older than five minutes also fails readiness. Publish retries and every
mark/release/batch database failure emit bounded structured
`agenttrust.approval-evidence-delivery-alert.v1` records, while database mutations propagate errors
instead of being silently treated as an empty batch. Backlog health does not terminate startup:
the Pod remains out of service through readiness while its worker retries old rows, then becomes
Ready automatically after the corrected Evidence configuration drains the queue.

Grant consumption selects and locks the exact tenant/action/plan/parameter/
resource-version/policy/environment binding, verifies the stored Ed25519 grant,
changes `remaining_uses` from one to zero, and persists the stable replay
response and signed receipt in one transaction. Final authorization retrieves
the receipt only through the tenant-bound opaque
`GET /v1/approvals/consumptions/{consumption_ref}` endpoint using
`approvals:verify`; malformed, unknown, or cross-tenant references return the
same non-disclosing not-found response.
