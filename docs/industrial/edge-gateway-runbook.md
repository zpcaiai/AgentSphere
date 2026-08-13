# Industrial Edge Gateway deployment and incident runbook

Production starts `READ_ONLY`. Register exact site/area/line/asset/channel mappings, engineering
units, limits, rate bounds, criticality, freshness and protocol security profiles. OPC UA requires
signed/encrypted mode and trusted certificates; MQTT requires fixed topic ACL/QoS; Modbus requires
reviewed register, endian and function-code mappings. Device credentials stay on the edge.

Limited write requires a fresh good-quality read, interlock/range/rate evaluation, central signed
single-use EdgeAuthorization, local policy no looser than central, compare-and-set commit and
post-write telemetry convergence. Every step journals before/requested/after state. Disconnect denies
new high-risk writes; only explicitly signed safe-stop actions are permitted. Buffers are bounded and
report dropped samples.

On incident: switch to read-only, revoke issuer keys, request safe stop if the plant procedure allows,
preserve the local journal, reconcile unknown commits with device telemetry, and require human review
before re-enabling writes. Simulator tests are not evidence for real PLC/protocol behavior; Batch 24
and site acceptance remain mandatory.

Deployment-owned protocol clients can be exercised through the controlled
read-only boundary. The client executable must be digest-pinned, receives fixed
arguments without a shell, uses mTLS, and must return the strict redacted
`agenttrust.industrial-probe-receipt.v1` contract. A receipt claiming a write is
rejected.

```sh
python3 -m python.production_gates.industrial_protocols \
  --protocol opcua --executable /opt/agenttrust/bin/opcua-probe \
  --executable-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --endpoint opc.tcp://plc.example:4840 --resource ns=2;s=Line1.Speed \
  --ca-file /etc/agenttrust/ca.pem \
  --client-certificate /etc/agenttrust/probe.pem \
  --client-private-key /run/secrets/probe.key \
  --output /absolute/new/opcua-read.json
```

Use `mqtts://` for MQTT and `modbus+tls://` for Modbus. Supervised writes are
never performed by this probe. They must traverse Canonical Action IR, PEP,
signed single-use `EdgeAuthorization`, a fresh read, interlock/range/rate
checks, prepare/commit compare-and-set, post-write convergence, immutable local
journal and on-site human supervision. The resulting site evidence then needs
the industrial domain assurance signatures; a protocol receipt alone cannot
authorize or certify a write.
