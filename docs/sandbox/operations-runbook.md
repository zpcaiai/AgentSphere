# Sandbox operations runbook

Pause sends process-group stop and freezes future work; Cancel sends bounded graceful termination; Kill sends process-group SIGKILL and precedes cleanup. Supervisor owners renew bounded leases and reconcilers handle orphaned executions. Inspect cleanup receipts for workspace removal and credential revocation. Any remaining process, mount, network flow, or credential moves the execution to manual recovery and opens an incident.

