# Model Gateway operations

Routing has two ordered stages. The authoritative `DataPolicyPort` first removes non-compliant
provider/model versions using tenant, classification, jurisdiction, deployment and capability data.
Only that allowed set reaches the deterministic Rust/Python ranker. Fallback cannot reintroduce a
denied provider. An empty set fails explicitly.

Provider versions and endpoint digests are immutable and revocable. Controlled transports resolve
endpoints and credentials; adapters receive neither raw secrets nor arbitrary URLs. Budget is reserved
before calls and finalized once. Provider overruns retain the full reservation and fail the request,
rather than releasing already-spent capacity. Raw prompts are excluded from normal traces; evidence
records input/output hashes, exact model version, provider request ID, route reasons and usage.

Before production, reconcile token/cost fields with each real provider, verify retry idempotency and
stream interruption behavior, and run DLP against provider responses. The local adapters and fake
transport tests do not establish real billing or provider availability.

The bounded `python.production_gates.live_integrations model` command verifies
real HTTPS authentication and catalog compatibility without sending prompts or
printing credentials. The separate `model-generation` gate sends only a fixed,
non-sensitive probe, requires both non-stream and SSE completion, provider usage
fields, bounded output and DLP scans, and optionally binds a data-residency
attestation digest:

```sh
AGENTTRUST_MODEL_PROBE_KEY='deployment-injected' \
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/model-generation.json model-generation \
  --completions-url https://provider.example/v1/chat/completions \
  --api-key-env AGENTTRUST_MODEL_PROBE_KEY --model approved-version \
  --declared-region eu-west \
  --residency-attestation-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The Rust gateway now applies response DLP to normal and streaming output,
enforces ordered bounded streams with an explicit final marker, reserves and
finalizes budget exactly once, and rejects provider usage/cost reconciliation
mismatches. Protocol probes still set `invoice_reconciliation=false`: production
requires actual invoice/export reconciliation, retry/interruption exercises and
signed residency evidence for the exact release.
