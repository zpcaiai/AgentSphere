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
