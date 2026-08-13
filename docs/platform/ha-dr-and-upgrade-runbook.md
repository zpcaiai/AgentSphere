# Platform HA, DR, capacity, and upgrade runbook

Security dependencies fail closed for writes and credential issuance. Read-only degradation requires a valid signed snapshot. Emergency stop may execute locally when central services are unavailable, but must enter a tamper-evident local journal for reconciliation.

Queues, pools, workflow admission, webhooks, exports, and campaign runs are bounded. Reject overload with a safe code; never accumulate unbounded work. Capacity evidence records the exact build, topology, workload mix, duration, saturation point, and percentile latency.

Backups bind database LSN, object manifest, ledger head, configuration, keys, and scope digest. A restore passes only in an isolated environment with exact record counts, object integrity, ledger reconciliation, and measured RTO/RPO. Upgrade requires schema/API/policy/pack compatibility, canary observation, and a tested rollback digest.

The repository includes bounded, destructive-test-safe local harnesses for a
two-instance PostgreSQL physical failover and an HTTP load sample:

```sh
python3 -m python.platform_sre.postgres_failover_drill \
  --binary-root /absolute/postgres/bin --work-root /absolute/scratch \
  --release-id RELEASE --output /absolute/new/failover.json
python3 -m python.platform_sre.http_load_gate \
  --url https://candidate.example/healthz --requests 2000 --concurrency 32 \
  --expected-status 200 --minimum-success-ratio 0.999 \
  --maximum-p99-ms 1000 --duration-seconds 3600 \
  --header-env Authorization=AGENTTRUST_LOAD_AUTHORIZATION \
  --output /absolute/new/load.json
python3 -m python.platform_sre.kubernetes_recovery_drill \
  --kubectl /absolute/kubectl --kubeconfig /absolute/kubeconfig \
  --context kind-agenttrust-chaos-test --namespace agenttrust-chaos-test \
  --image registry/image@sha256:... --output /absolute/new/recovery.json
python3 -m python.platform_sre.multizone_topology_gate \
  --kubectl /absolute/kubectl --kubeconfig /absolute/production-kubeconfig \
  --context production --minimum-zones 3 \
  --workload agenttrust/deployment/gateway \
  --workload agenttrust/statefulset/worker \
  --output /absolute/new/multizone-topology.json
```

Both schemas intentionally mark these harness reports as
`production_evidence=false`. Multi-zone failover, representative sustained
load, multi-node/control-plane/network/storage chaos, deployment-key encrypted
backup, isolated restore, and signed RTO/RPO evidence
must still be produced by the deployment-owned production gate.

The multi-zone topology probe is read-only and requires ready replicas across
at least three zones, `DoNotSchedule` zone spread (or required anti-affinity), a
working disruption budget, digest-pinned images and hardened pod security. The
load runner can hold a configured duration and reads sensitive headers only
from environment variables; reports contain header names, never values.

Production gVisor mode additionally requires an absolute digest-pinned `runsc`
binary and a root-owned, non-writable, unexpired dedicated-host attestation.
That attestation must be signed by the expected public key whose file digest is
provided through protected deployment configuration:

```sh
AGENT_TRUST_ISOLATION_MODE=production \
AGENT_TRUST_LINUX_TEST_IMAGE='registry/image@sha256:...' \
AGENT_TRUST_RUNSC_BINARY=/usr/local/sbin/runsc \
AGENT_TRUST_RUNSC_SHA256='...' \
AGENT_TRUST_DEDICATED_HOST_ATTESTATION=/etc/agenttrust/host.json \
AGENT_TRUST_DEDICATED_HOST_ATTESTATION_SIGNATURE=/etc/agenttrust/host.json.sig \
AGENT_TRUST_DEDICATED_HOST_ATTESTATION_PUBLIC_KEY=/etc/agenttrust/host-attestor.pem \
AGENT_TRUST_DEDICATED_HOST_ATTESTATION_PUBLIC_KEY_SHA256='...' \
AGENT_TRUST_ISOLATION_REPORT=/absolute/new/linux-runsc.json \
./scripts/run-linux-isolation-gate.sh
```

The gate also verifies the selected container runtime and that the sandbox
kernel differs from the host kernel. Without all of these checks it fails
closed and emits no production report.
