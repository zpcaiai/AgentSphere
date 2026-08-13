# Credential Proxy operations

Monitor active lease count, provider latency/failure, connector saturation, timeout/Kill, redaction count, and output-schema rejection by tenant-hashed dimensions. A provider outage fails high-risk requests closed. On exposure, revoke lease/task/tenant epoch, stop the connector, rotate the target credential, scan sanitized audit hashes and protected raw artifact storage, and attach incident evidence. Raw responses must never reach normal Trace or logs.

`VaultTargetSecretProvider` maps a fixed approved profile and target to a Vault
dynamic-credential path, bounds lease TTL to 900 seconds, returns the secret in
a zeroizing/redacted container, tracks the opaque lease ID, and revokes the
lease when the tool call finishes. The supplied HTTP client must be deployment
configured with the enterprise CA and workload client identity; arbitrary
target URLs and raw long-lived credentials are not accepted by the provider.

Before enablement, exercise health, self-lookup, issuance and immediate revoke
with a least-privilege probe token supplied only by environment reference:

```sh
AGENTTRUST_VAULT_PROBE_TOKEN='deployment-injected' \
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/vault-report.json vault \
  --endpoint https://vault.service.example \
  --token-env AGENTTRUST_VAULT_PROBE_TOKEN \
  --dynamic-lease-path database/creds/agenttrust-probe \
  --maximum-lease-seconds 900
```

The probe revokes its lease and records only counts/digests. Do not promote a
local or operator-created report to production evidence; bind it to the release
scope with the external-assurance verifier.
