# Production isolation requirements

macOS local process execution is development-only. Production requires Linux cgroup v2, PID/mount/IPC/UTS/network namespaces, non-root UID/GID, read-only rootfs, no-new-privileges, dropped capabilities, seccomp allowlist, no host/Docker sockets, ephemeral workspaces, and gVisor `runsc` or equivalent. The dedicated Linux CI must prove fork-bomb limits, host/metadata/socket denial, child cleanup, and network termination; mocks cannot certify these properties.

Run the baseline with an immutable image:

```sh
AGENT_TRUST_ISOLATION_MODE=baseline \
AGENT_TRUST_LINUX_TEST_IMAGE='registry/image@sha256:...' \
AGENT_TRUST_ISOLATION_REPORT=/absolute/new/report.json \
./scripts/run-linux-isolation-gate.sh
```

Production mode additionally requires a real Linux host and registered gVisor
`runsc` runtime. The report schema prevents a baseline or `runc` result from
being represented as production evidence. The production execution entrypoint is the
native systemd worker in `docs/sandbox/gvisor-worker-deployment.md`, not a nested `runsc`
inside a Kubernetes Pod. It admits only PEP-authorized, dispatcher-signed jobs with an
independent registry snapshot attestation and `NATIVE_SYSTEMD_RUNSC` host attestation,
then emits an independently host-signed cleanup-complete receipt. RuntimeClass
configuration is a Kubernetes alternative/declaration and is never substituted for the
real Linux isolation report.

The dedicated GitHub Actions host must run Actions Runner 2.327.1 or newer so
the immutable Node 24 actions can start. Operators add the
`actions-runner-2-327-1` label only after verifying that minimum version; the
isolation workflow includes that label in `runs-on`, uses read-only repository
permissions, and does not persist checkout credentials. A queued job without a
matching verified runner remains `NOT_RUN_EXTERNAL_ENVIRONMENT`, never passing
isolation evidence.
