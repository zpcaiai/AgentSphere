# Production activation watcher runbook

`watch-activation` is the runtime liveness boundary for a previously qualified
Production Closure release. A one-time activation receipt is insufficient: the
watcher rereads and verifies the certificate, report, ClosureInput, all public
keys, the current signed revocation registry, its short-lived signed projection
head, and the activation expectation
every 25 seconds. It never uses cached copies as the current authorization
inputs; it retains only the last accepted registry to enforce monotonicity.

Prepare the dedicated `subPath` directory from an init container running as UID
`65531` and primary GID `65532`. The target must not already exist:

```text
production-closure prepare-activation-directory /activation/live
```

The command accepts exactly one absolute path. Its parent must be an existing,
non-symlink directory and the process must be able to create a child. It uses
create-new directory semantics, fixes the new directory to mode `0750`, checks
that Linux FS UID/GID equal the current process, verifies that it is still an
empty non-symlink directory, and fsyncs both the new directory and its parent.
An existing file, directory, or symlink is always rejected.

Run the watcher with 12 positional arguments:

```text
production-closure watch-activation \
  /run/agenttrust/closure/production-certificate.json \
  /run/agenttrust/closure/closure-report.json \
  /run/agenttrust/closure/closure-input.json \
  /run/agenttrust/trust/closure-public-key.json \
  /run/agenttrust/evidence/revocation-registry.json \
  /run/agenttrust/trust/current-revocation-registry.json \
  /run/agenttrust/trust/current-revocation-projection.json \
  /run/agenttrust/trust/revocation-projection-public-key.json \
  /run/agenttrust/trust/revocation-public-key.json \
  /run/agenttrust/activation/expectation.json \
  /run/agenttrust/activation/dynamic-receipt.json \
  127.0.0.1:8091
```

This is the exact sidecar contract: the 11 paths must be absolute;
the final argument must be a nonzero loopback socket. Input files must be
regular, single-link, non-symlink files no larger than their contract limit and
must not be group/world writable. The receipt parent directory must also not be
a symlink or group/world writable. Mount trust and evidence inputs read-only;
mount only the receipt directory read-write.

On every successful check the watcher creates a mode `0600` temporary file in
the receipt directory, writes and fsyncs it, changes it to mode `0440`, fsyncs
the metadata, atomically renames it over the dynamic receipt, then fsyncs the
parent directory. It does not chown the file: run the sidecar as UID `65531`
with primary GID `65532`, matching the runtime guardian owner/reader contract.
A failed check does not replace the last receipt. The process keeps retrying,
but readiness becomes unavailable immediately and a consumer must independently
reject any receipt whose `verified_at` is more than 60 seconds old or whose
`valid_until` has passed.

At startup the watcher securely reads and verifies the evidence-bundle baseline
registry, then initializes its monotonic state from that exact sequence and
digest. Every live registry must have a valid revocation signature and an exact,
unexpired projection head signed by the separate projection authority. The
watcher rejects lower sequences, rejects a different digest at the same
sequence, and rejects omission or mutation of any previously accepted
revocation entry. A signed projection head can therefore authenticate a jump
from baseline N to current N+k after a pod restart without requiring transient
N+1 through N+k-1 files to remain mounted. The projection broker may return
success only after its checkpoint-bound write and exact watcher acknowledgement
set succeed; the release workflow independently reads that same head through
the production CSI path before advancing the durable checkpoint.

Probe `GET /ready` on `127.0.0.1:8091`. It returns HTTP 200 only when the most
recent full verification succeeded, is at most 60 seconds old, and its receipt
has not expired. Otherwise it returns HTTP 503. The JSON body conforms to
`schemas/release/production-activation-watch-status.schema.json`. Any other
path returns HTTP 404. Do not expose this listener outside the pod network
namespace.

Kubernetes must use an exec probe because the watcher intentionally listens
only on the sidecar loopback interface:

```text
/usr/local/bin/production-closure check-activation-watch 127.0.0.1:8091
```

The one-shot checker rejects non-loopback addresses, uses two-second bounded
connect/read/write timeouts, sends exactly `GET /ready`, caps the complete HTTP
response at 16 KiB, and returns success only for `HTTP/1.1 200 OK` with the
strict status schema, `ready=true`, valid receipt/registry/projection digests,
the accepted registry sequence and projection ID, and `last_success_at` no more
than 60 seconds old. Every unavailable, malformed,
stale, future-dated, or non-200 response exits with the CLI failure status 2.

Operational alerts should fire on any `CLOSURE_WATCH_*` stderr code, a 503
readiness result, a receipt older than 60 seconds, a registry rollback, or a
successor-chain failure. Keep the deployment unavailable until both the durable
checkpoint and the watcher recover; never copy forward or hand-edit a receipt.

The production database has an independent fail-closed activation lease. The
`agenttrust-activation-lease-renewer` sidecar runs as the `platform_sre` role,
renews a 45-second lease every 10 seconds only when the activation receipt,
revocation projection and release binding are fresh, and exposes loopback
`/ready` and `/active` probes. A stale receipt, changed projection head,
expired certificate, lost database connection or CAS conflict fences all
production base-table writes through the database trigger. The renewer never
transitions a lease from `FENCED` to `ACTIVE`; only the externally signed
deployment-cutover broker may perform the writer-fence, cutover, rollback and
unfreeze transitions.
