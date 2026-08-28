# Sandbox operations runbook

Pause sends process-group stop and freezes future work; Cancel sends bounded graceful termination; Kill sends process-group SIGKILL and precedes cleanup. Supervisor owners renew bounded leases and reconcilers handle orphaned executions. Inspect cleanup receipts for workspace removal and credential revocation. Any remaining process, mount, network flow, or credential moves the execution to manual recovery and opens an incident.

For the dedicated gVisor path, stop dispatch before rotating the runtime attestation,
worker keyring, encrypted receipt credential, runsc binary or worker binary. Never delete
an O_EXCL replay record to retry an uncertain result. Verify the host signature and exact
job, authorization, Action, runtime, runsc, image/config, output and cleanup bindings before
Evidence ingest. Missing or invalid receipt, incomplete cleanup, or ambiguous systemd exit
is `UNKNOWN` and requires reconciliation; it is not execution or Task success.
