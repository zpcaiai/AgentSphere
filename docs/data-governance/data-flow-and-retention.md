# Data flow, DLP and retention

Labels follow `Source → Prompt → Model → Tool → Trace → Artifact → Export`. Merge selects the strictest
classification/retention and lowest confidence while preserving jurisdiction, domain tags and lineage
hashes. Unknown or unavailable classification fails closed as restricted. Domain packs may add tags
but cannot redefine core classifications.

Prompt Guard scans structured and encoded content, rejects secrets, and records transformation hashes.
Artifact export re-runs policy/DLP and requires a single-use cross-domain approval where zones or
jurisdictions differ. Redirect targets are evaluated as new destinations. Gzip/ZIP payloads are denied
until safely unpacked in a bounded scanner. Offline deployment has no external endpoints, telemetry
export or public-model fallback.

Retention is label-driven and recorded as delete/archive/legal-hold actions with evidence. Legal hold
may extend but never shorten retention. The deterministic corpus covers secrets, personal identifiers,
base64 and compressed evasions. Production must additionally prove network egress denial and object
store deletion/legal-hold behavior.

The production authority is `agenttrust-data-governance-service`. Durable metadata writes enter
`POST /v1/data/actions`, become Canonical Action IR, and are executed only through the exact
PEP/ledger/fence/Evidence binding at `POST /v1/data/executions`. Policy evaluation, DLP scanning,
Prompt sanitization, and Artifact authorization are typed ephemeral routes; their returned record
proposal is not authoritative until submitted through the mutation path. PostgreSQL never stores raw
Prompt, Artifact, DLP sample, transformed content, provider credential, or bearer token.
Artifact authorization also performs a tenant-RLS durable preflight: the exact output label,
non-shadow allowed decision, Enterprise DLP receipt, required output transform, and optional
single-use cross-domain grant must already exist. `AUTHORIZE_EXPORT` repeats these bindings and
requires a grant consumption for the same export ID plus the exact typed object-authorization
reference/digest, preventing a caller from bypassing the typed preflight with a direct durable
command.

Enterprise DLP, object/WORM, legal-hold, and Evidence integrations use TLS client identity, an opaque
per-authority token, an exact tenant, and bounded receipts. Redirect following and public trust roots
are disabled. Encoded content is decoded at most one declared layer plus three deterministic local
inspection layers; Gzip and ZIP are denied until a certified bounded unpacker is configured.
Durable mutations publish only a payload hash, safe summary, task identity, and the exact governed
action/PEP/ledger/fence binding through the shared authority-event Evidence contract. The Evidence
authority's signed event and signed receipt are verified against the configured issuer and Ed25519
keyring before a mutation becomes `COMPLETED`; lost responses are recovered by byte-identical replay
of immutable outbox time and idempotency fields.
Authoritative resource pages carry `authoritative=true` and a JCS `data_digest` over the response
with that digest field omitted, so downstream BFFs can reject incomplete or altered snapshots.

See [production-runbook.md](production-runbook.md) for required environment, least-privilege grants,
recovery, negative tests, and the current evidence boundary.
