# Model Gateway production operations

Batch 15 supplies a fail-closed production authority for model generation, streaming, embeddings,
budget accounting, provider billing reconciliation, governed output export and an authoritative
BFF/operations read model. Source implementation does not certify real providers, Batch 18,
PostgreSQL HA, WORM retention, invoices, load, DLP, residency or customer acceptance; those gates
remain `IN_PROGRESS`/`NOT_RUN` until release-specific external Evidence exists.

## Public authority

The TLS 1.3 mTLS data plane listens only on port `8091`. The loopback or unspecified management
plane listens only on `9101` and exposes `/live` and dependency-aware `/ready`.

- `POST /v1/models/generate` requires `models:generate`.
- `POST /v1/models/stream` requires `models:stream` and returns bounded ordered SSE.
- `POST /v1/models/embeddings` requires `models:embeddings`.
- `POST /v1/models/billing/reconciliations` requires `models:billing:reconcile`.
- `GET /v1/authoritative/models/executions` requires `models:executions:read`.

Every state-changing request binds tenant, idempotency key, Canonical Action hash, PEP
authorization ID/digest, policy decision ID/digest, authorization Evidence ref/digest, ledger
execution and RESERVED-entry ID/digest, fence digest, model resource version and trace ID. The
resource version is the canonical decimal version of the state-owning model resource; it is not an
orchestrator task-state version and is never mapped to lifecycle Evidence.

The authoritative executions endpoint requires query `tenant_id` to equal the tenant header and
token tenant. It supports state/operation filters and paired keyset cursor fields, with a maximum of
200 safe summaries. It never returns prompts, generated text, embeddings or stream chunks.
`data_digest` is independently reproducible: remove only `data_digest` from the final response,
including `schema_version`, `tenant_id`, `authoritative`, `items`, `next_cursor` and `generated_at`,
then compute SHA-256 over RFC 8785/JCS bytes. Query and filter fields absent from the response are not
digest material.

## Execution closure

The durable coordinator in `0036_01_14_production_model_gateway.sql` atomically stores the safe
request digest and reserves budget before dispatch. Provider revisions are immutable signed
manifests, tenant approvals are RLS-scoped, and signed revocations win immediately. Provider URLs
and credentials exist only in private deployment files. The deterministic route ranker receives
only providers allowed by the same policy decision; an empty set fails. Once a provider call starts,
timeouts, lost responses, malformed streams and post-effect dependency failures move the request to
`UNKNOWN`, retain accounted budget and never try another provider.

For each candidate the gateway uses the exact Batch 18 typed sequence:

1. `POST /v1/internal/data/evaluate`, then submit its exact `record_payload` as
   `RECORD_POLICY_DECISION` to `POST /v1/data/actions`.
2. `POST /v1/internal/data/scan`, then persist `RECORD_DLP_SCAN`.
3. If required, `POST /v1/internal/data/sanitize`, verify the transformation receipt digest,
   persist `RECORD_TRANSFORM_RECEIPT`, update lineage and re-evaluate policy.
4. Poll `GET /v1/authoritative/data/mutations/{command_id}`. A proposal, pending execution or
   `durable_record_required=true` is never sufficient. Only HTTP 200, `state=COMPLETED`, exact
   command/resource/result bindings and non-empty final `evidence_ref`/`evidence_digest` may be used.

There is no invented residency attestation route. Residency is enforced by the exact policy request
fields `source_jurisdiction`, `destination_jurisdiction`, `destination_kind`, `deployment_profile`
and the optional cross-domain approval. DLP dependency failure, compressed/encoded/unknown content,
secret findings, blocking findings, unsafe redirects, a missing completed mutation or an unsatisfied
transformation fails closed.

After the single provider response, the gateway performs output DLP and creates the output object's
own durable `REGISTER_LABEL`, policy decision and DLP summary. It never reuses a prompt transform for
the output. If a cross-domain grant is present, approval, grant, source zone and target zone must all
be present; `CONSUME_CROSS_DOMAIN_GRANT` uses the exact zones from grant issuance and binds the same
`export_intent_id` later used as artifact `authorization_id` and `AUTHORIZE_EXPORT.export_id`.

The gateway then calls only `POST /v1/internal/data/artifacts/authorize`, requiring
`durable_preflight_verified=true` and exact durable label, decision, DLP, optional transform and grant
bindings. It persists `AUTHORIZE_EXPORT` including the DLP receipt and explicit nullable transform
pair plus the exact `object_authorization_ref` and `object_authorization_digest` returned by that
preflight. The configured locked Artifact/WORM writer alone receives the output bytes at
`POST /v1/model-artifacts`; the gateway verifies artifact, watermark, signature, WORM and canonical
receipt digests, then persists `COMPLETE_EXPORT`. Batch 18 artifact authorization does not itself
write the output object. A missing real writer or receipt fails closed.

Raw prompt/output bytes are never database columns. The initial successful response may carry
untrusted output to the caller, but durable replay and the authoritative read API expose only safe
metadata and the governed `artifact://sha256/...` reference. Public execution requests cap the
requested output at 1 MiB so the canonical JSON artifact remains inside the Batch 18 bounded DLP
transport; provider manifests may advertise larger limits, but they cannot raise this request cap.

## Evidence and crash replay

Execution and billing Evidence use the shared state-owning authority wire:
`POST /v1/evidence/authority-events` with `AuthorityEvidenceEventRequest`, source
`GOVERNED_ACTION`, the full Canonical Action/PEP/ledger/fence control binding, and a returned
`SignedAuthorityEvidenceReceipt`. The receipt must match tenant, task, authority event,
idempotency, source kind, exact request digest and payload digest; its embedded event hash,
Ed25519 signature and `AUTHORITY_EVIDENCE_RECEIPT` keyring entry are verified.

`model_authority_evidence_outbox` stores the complete request, including the original
`requested_at` and `occurred_at`, before network dispatch. Retries replay that exact request rather
than rebuilding timestamps. `model_data_governance_outbox` does the same for every Batch 18 command
and stores only safe metadata proposals, never prompt/output content. Both outboxes transition only
from `PREPARED` to their final state under immutable triggers.

## Required environment

Process and listeners:

- `AGENT_TRUST_PROFILE=production`
- `AGENT_TRUST_MODEL_INSTANCE_ID`
- `AGENT_TRUST_MODEL_LISTEN_ADDRESS`, `AGENT_TRUST_MODEL_PORT=8091`
- `AGENT_TRUST_MODEL_MANAGEMENT_LISTEN_ADDRESS`, `AGENT_TRUST_MODEL_MANAGEMENT_PORT=9101`
- `AGENT_TRUST_MODEL_EXECUTION_LEASE_SECONDS`, `AGENT_TRUST_MODEL_RECOVERY_INTERVAL_SECONDS`

Inbound identity and PostgreSQL:

- `AGENT_TRUST_MODEL_TLS_CA_FILE`, `AGENT_TRUST_MODEL_TLS_CERTIFICATE_FILE`,
  `AGENT_TRUST_MODEL_TLS_PRIVATE_KEY_FILE`
- `AGENT_TRUST_MODEL_CLIENT_IDENTITIES`, `AGENT_TRUST_MODEL_TOKEN_BINDINGS_FILE`
- `AGENT_TRUST_MODEL_DATABASE_URL_FILE`, `AGENT_TRUST_MODEL_DATABASE_PASSWORD_FILE`,
  `AGENT_TRUST_MODEL_DATABASE_CA_FILE`, `AGENT_TRUST_MODEL_DATABASE_EXPECTED_ROLE`,
  `AGENT_TRUST_MODEL_DATABASE_MAX_CONNECTIONS`

Outbound mTLS and signed configuration:

- `AGENT_TRUST_MODEL_OUTBOUND_CA_FILE`, `AGENT_TRUST_MODEL_OUTBOUND_CERTIFICATE_FILE`,
  `AGENT_TRUST_MODEL_OUTBOUND_PRIVATE_KEY_FILE`
- `AGENT_TRUST_MODEL_PROVIDER_ENDPOINTS_FILE`, `AGENT_TRUST_MODEL_PROVIDER_KEYRING_FILE`
- `AGENT_TRUST_MODEL_EVIDENCE_KEYRING_FILE`, `AGENT_TRUST_MODEL_EVIDENCE_SOURCE_SERVICE`

Mandatory adapters, each with `<PREFIX>_ENDPOINT` and `<PREFIX>_TOKEN_FILE`:

- `AGENT_TRUST_MODEL_DATA_POLICY_*` (`data:evaluate`)
- `AGENT_TRUST_MODEL_DLP_*` (`data:scan`)
- `AGENT_TRUST_MODEL_DATA_SANITIZER_*` (`data:sanitize`)
- `AGENT_TRUST_MODEL_DATA_ARTIFACT_AUTHORIZER_*` (`data:artifact-authorize`)
- `AGENT_TRUST_MODEL_DATA_MUTATION_*` (`data:mutate`)
- `AGENT_TRUST_MODEL_DATA_READ_*` (`data:read`)
- `AGENT_TRUST_MODEL_ARTIFACT_STORE_*` (writer-specific scope limited to
  `POST /v1/model-artifacts`)
- `AGENT_TRUST_MODEL_EVIDENCE_*` (`evidence:authority-event`)

The artifact writer also requires `AGENT_TRUST_MODEL_ARTIFACT_STORE_JURISDICTION` and
`AGENT_TRUST_MODEL_ARTIFACT_STORE_DESTINATION_KIND`. `EVIDENCE_SOURCE_SERVICE` is exactly the one
`DNS:` or `URI:` SAN presented by the outbound client certificate.

All secret/token/key/database files are absolute regular non-symlink files owned by the effective
UID with no group/world permission bits. Every endpoint is an origin-only HTTPS URL; redirects and
ambient root certificates are disabled.

## PostgreSQL grants

Use a dedicated `NOINHERIT` login without superuser, BYPASSRLS, schema CREATE, database TEMP,
routine EXECUTE or destructive table privileges. Preserve migration `PUBLIC` revocations and grant
only:

```sql
GRANT USAGE ON SCHEMA public TO agenttrust_model_gateway;
GRANT SELECT ON TABLE
  public.model_provider_revisions, public.model_provider_revocations,
  public.model_tenant_provider_approvals, public.model_budget_accounts,
  public.model_gateway_requests, public.model_budget_reservations,
  public.model_stream_chunk_digests, public.model_execution_evidence,
  public.model_billing_usage_lines, public.model_billing_reconciliations,
  public.model_evidence_outbox, public.model_authority_evidence_outbox,
  public.model_data_governance_outbox
TO agenttrust_model_gateway;
GRANT INSERT ON TABLE
  public.model_gateway_requests, public.model_budget_reservations,
  public.model_stream_chunk_digests, public.model_execution_evidence,
  public.model_billing_usage_lines, public.model_billing_reconciliations,
  public.model_evidence_outbox, public.model_authority_evidence_outbox,
  public.model_data_governance_outbox
TO agenttrust_model_gateway;
GRANT UPDATE (reserved_microunits, spent_microunits, account_version, updated_at)
  ON public.model_budget_accounts TO agenttrust_model_gateway;
GRANT UPDATE (state, owner_instance_id, lease_expires_at, selected_provider_key,
  provider_request_id, output_digest, output_artifact_ref, output_artifact_digest,
  safe_response, stable_error, evidence_ref, evidence_digest, updated_at, completed_at)
  ON public.model_gateway_requests TO agenttrust_model_gateway;
GRANT UPDATE (actual_microunits, state, provider_key, provider_request_id, finalized_at)
  ON public.model_budget_reservations TO agenttrust_model_gateway;
GRANT UPDATE (provider_statement_digest, reconciliation_state, reconciled_at)
  ON public.model_billing_usage_lines TO agenttrust_model_gateway;
GRANT UPDATE (state, signed_receipt, evidence_ref, evidence_digest, updated_at, delivered_at)
  ON public.model_authority_evidence_outbox TO agenttrust_model_gateway;
GRANT UPDATE (state, mutation_result, evidence_ref, evidence_digest, updated_at, completed_at)
  ON public.model_data_governance_outbox TO agenttrust_model_gateway;
```

The database URL contains no password and must set
`sslmode=verify-full&application_name=agenttrust-model-gateway`. Startup checks the exact role and
grant envelope and refuses broader authority.

## Release gates

Build only through `scripts/build-production-image.py --component model-gateway` with digest-pinned
Rust builder and runtime bases. Source and lightweight contract checks do not replace the separately
required real PostgreSQL migration/RLS test, TLS/SAN/token test, signed manifest/revocation test,
provider generation/stream/embeddings and interruption tests, Batch 18 plus enterprise DLP test,
locked multi-zone WORM test, data-residency/cross-domain grant exercise, real invoice reconciliation,
HA/DR fault injection, sustained load and independent release Evidence.
