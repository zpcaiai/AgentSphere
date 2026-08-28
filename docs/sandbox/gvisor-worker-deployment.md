# Dedicated gVisor worker deployment

The production worker is a native, one-shot Linux service. It directly invokes a
digest-pinned rootless `runsc` binary on a dedicated cgroup-v2 host. It is not a
Kubernetes Deployment, does not run `runsc` inside a RuntimeClass Pod, and must never
receive a Docker/Podman socket or a host-root mount. The `sandbox_worker` OCI release
subject is only the attested transport for the same native binary.

## Trust and dispatch chain

1. The execution coordinator materializes Canonical Action IR and reserves the durable
   execution ledger fence.
2. PEP emits a short-lived, single-use `ExecutionAuthorization` binding the Action Hash,
   Tool Snapshot Hash, OCI image digest, policy/approval/resource versions, sandbox,
   network and credential profiles, ledger execution/event/fence digests and limits.
3. The trusted sandbox dispatcher resolves a versioned executor template and OCI bundle,
   then signs `agenttrust.gvisor-execution-job.v1`. The Tool image digest and `config.json`
   digest are different from—and simultaneously bound with—the `runsc` binary digest.
4. The dispatcher publishes the signed job as
   `/var/spool/agenttrust-gvisor/inbox/<authorization-uuid>.json` only after the complete
   file and bundle are fsynced and made non-writable to the worker group. It starts exactly
   `agenttrust-gvisor-worker@<authorization-uuid>.service`; callers cannot override the
   binary, trust roots, runtime, replay ledger or output paths.
5. Before creating runsc state, the worker verifies the PEP signature, recomputed Tool
   Snapshot Hash, dispatcher signature, signed and unexpired dedicated-host runtime
   attestation, immutable OCI config, non-root/read-only/capability/seccomp/cgroup/network
   settings, and the exact root-owned `runsc` binary bytes against the runtime attestation
   SHA-256. `OciGvisorCommandBuilder` re-reads and verifies those bytes immediately before
   forming the exact command. It then creates an O_EXCL durable replay
   record. A repeated Authorization is rejected even after a host restart.
6. The worker invokes `runsc --network=none --rootless=true`, bounds stdout/stderr and
   elapsed time, kills the whole worker process group on timeout, forces runsc state
   deletion, removes the bundle, and writes an immutable, host-signed
   `agenttrust.gvisor-execution-receipt.v1` plus bounded output files. The receipt binds
   worker hostname, runtime attestation, actual runsc bytes, workload/config digests,
   outputs, replay consumption and cleanup.
7. The coordinator verifies the receipt with the independent
   `AGENTTRUST_GVISOR_EXECUTION_RECEIPT_V1` public key and imports its digest into the Evidence service
   before the transaction ledger can move from process success to governed execution
   success. Process exit success never means Task completion.

The shared spool is a deployment adapter, not an authorization source. It must be on a
local encrypted filesystem or an authenticated queue materialized by a host-local agent.
NFS with weak identity, mutable jobs, symlinks, world-writable parents and best-effort
delivery are forbidden. The dispatcher account can create inbox/workspace material but
cannot modify replay records, results, trust roots, the worker binary, `runsc` or the
systemd unit. `/var/lib/agenttrust-gvisor/replay`, `state`, and `results` are mode `0700`
and owned only by the worker identity, so the dispatcher cannot erase replay fences,
rewrite output, or forge a receipt. Only `workspaces` and the inbox use the dedicated
`agenttrust-gvisor-spool` group. The dispatcher is a member of that group; the worker is
the workspace owner and receives inbox read access. Neither identity is a member of the
other's primary group. The worker account cannot sign jobs or runtime attestations.

Execution receipts use a fifth, independent Ed25519 key usage. The private seed is loaded
only from systemd `LoadCredentialEncrypted` as `%d/receipt-signing-key.json`; it is never
stored in the OCI transport image, job, workspace, shared spool, result directory, or
Evidence record. The worker refuses a secret file with group/world permissions and
verifies that its derived public key exactly matches the active, unrevoked receipt key in
`gvisor-worker-keyring.json`. Evidence ingest must reject unsigned, stale-key, invalid-
signature, digest-mismatched, or cleanup-incomplete receipts.

## Installation and rotation

Verify the signed Git release, the `sandbox_worker` image provenance/SBOM attestations and
its exact subject digest on a separate release host. Extract
`/usr/local/bin/agenttrust-gvisor-worker` without installing Docker on the sandbox host,
record its lowercase SHA-256 in `/etc/agenttrust/gvisor/worker-binary.sha256` using the
absolute destination path, and install it mode `0755`, root-owned, at
`/usr/local/libexec/agenttrust-gvisor-worker`. Install the separately attested `runsc`
binary at `/usr/local/sbin/runsc`; its prefixed digest must match the active signed
`runtime-attestation.json`.

Install the service and tmpfiles definitions from `deploy/systemd`, create distinct
`agenttrust-dispatch` and `agenttrust-sandbox` identities plus the non-login shared group
`agenttrust-gvisor-spool`, add only the dispatcher identity to that group persistently (the
worker unit receives it per-process through `SupplementaryGroups`), and run `systemd-tmpfiles --create`,
then reload systemd. Keep `/etc/agenttrust/gvisor/worker-keyring.json`, runtime attestation,
binary digest file, encrypted `receipt-signing-key.cred`, and unit root-owned and not
group/world writable. Provision the receipt key with
`systemd-creds encrypt --name=receipt-signing-key.json` and validate the plaintext before
encryption against `schemas/execution/gvisor-receipt-signing-key.schema.json`; never place
the plaintext document under `/etc`. Runtime attestations use
`execution_mode=NATIVE_SYSTEMD_RUNSC` and expire within thirty days. Rotate by installing
new trust material atomically, run the
dedicated Linux isolation gate, then admit new jobs; never extend timestamps in place.

## Kubernetes RuntimeClass alternative

The production stack declares `RuntimeClass/agenttrust-gvisor` with handler `runsc` and a
restricted `agenttrust-sandboxes` namespace whose ingress and egress are both default
denied. A Kubernetes executor may create one immutable Job per signed authorization in
that namespace, but the launcher must preserve the same Action/PEP/ledger/evidence and
receipt contracts. The control-plane stack deliberately does not deploy the native
one-shot worker as a Pod. Node labels or a RuntimeClass object are declarations; only the
real Linux isolation report and signed host/runtime attestation are execution evidence.

## External production gate

No macOS test, source inspection, RuntimeClass declaration or mocked OCI engine proves
gVisor isolation. Release evidence remains `NOT_RUN_EXTERNAL_ENVIRONMENT` until a dedicated
Linux runner verifies the pinned `runsc`, cgroup v2, seccomp, user namespaces, distinct
sandbox kernel, PID/memory limits, metadata and host/socket denial, process cleanup and the
signed host attestation for the exact release.
