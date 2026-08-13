# MCP Security Proxy threat model and runbook

MCP servers are untrusted supply-chain and runtime principals. Main threats are schema/binary drift,
prompt injection in results, secret exfiltration, undeclared file/network writes, endpoint redirects,
credential theft, cross-tenant pooling and replayed authorization. Controls are signed manifests,
immutable schema snapshots, canonical Action IR, PEP authorization, opaque credential handles,
input/output validation, bounded calls, content/control separation and behavior/effect comparison.

Operational lifecycle: register in `PENDING`; verify publisher, SBOM, digest and endpoints; run sandbox
probes; approve exact tool snapshots; monitor drift. Any schema, digest, permission or endpoint change
freezes the server. Undeclared side effects quarantine it. Revocation blocks new calls immediately;
operators then revoke credential leases, terminate inflight work, preserve sanitized evidence and
review affected task IDs. Never unfreeze by editing an old snapshot—register a new reviewed version.

Local tests use controlled transports. Real third-party MCP servers, vulnerability feeds and sandbox
network observation remain deployment gates.

For a registered HTTPS endpoint, the read-only wire probe performs MCP
`initialize` and `tools/list`, carries the negotiated session ID, validates
bounded object input schemas, and hashes the normalized tool surface without
calling a tool:

```sh
AGENTTRUST_MCP_PROBE_TOKEN='deployment-injected' \
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/mcp-report.json mcp \
  --endpoint https://mcp.example/mcp --bearer-env AGENTTRUST_MCP_PROBE_TOKEN
```

Compare the returned schema digest to the approved manifest. A protocol PASS is
not behavioral safety evidence and remains `production_evidence=false` until
the sandbox observation, supply-chain evidence and scoped external assurance
are verified.
