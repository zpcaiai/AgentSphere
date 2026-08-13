# A2A real-endpoint discovery gate

The deployment gate fetches an HTTPS Agent Card, requires the advertised task
endpoint to stay on the same origin, bounds and de-duplicates skills, records a
card digest, and never submits a task:

```sh
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/a2a-card.json a2a \
  --card-url https://agent.example/.well-known/agent-card.json
```

Task delegation, streaming, reconnect, revocation latency and peer behavior
remain separate active tests. Their Action IR/PEP/ledger/evidence chain and
scoped external assurance are required before a production closure decision.
