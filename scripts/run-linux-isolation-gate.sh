#!/bin/sh
set -eu

MODE=${AGENT_TRUST_ISOLATION_MODE:-baseline}
IMAGE=${AGENT_TRUST_LINUX_TEST_IMAGE:-}
REPORT=${AGENT_TRUST_ISOLATION_REPORT:-}
RUNSC_BINARY=${AGENT_TRUST_RUNSC_BINARY:-}
RUNSC_SHA256=${AGENT_TRUST_RUNSC_SHA256:-}
HOST_ATTESTATION=${AGENT_TRUST_DEDICATED_HOST_ATTESTATION:-}
HOST_ATTESTATION_SIGNATURE=${AGENT_TRUST_DEDICATED_HOST_ATTESTATION_SIGNATURE:-}
HOST_ATTESTATION_PUBLIC_KEY=${AGENT_TRUST_DEDICATED_HOST_ATTESTATION_PUBLIC_KEY:-}
HOST_ATTESTATION_PUBLIC_KEY_SHA256=${AGENT_TRUST_DEDICATED_HOST_ATTESTATION_PUBLIC_KEY_SHA256:-}
EXPECTED_RUNNER_GROUP=${AGENT_TRUST_EXPECTED_RUNNER_GROUP:-}
EXPECTED_RUNNER_LABELS=${AGENT_TRUST_EXPECTED_RUNNER_LABELS:-}
EXPECTED_NODE_POOL=${AGENT_TRUST_EXPECTED_NODE_POOL:-}
SOURCE_REPOSITORY=${GITHUB_REPOSITORY:-NOT_APPLICABLE}
SOURCE_COMMIT=${GITHUB_SHA:-NOT_APPLICABLE}
SOURCE_WORKFLOW_REF=${GITHUB_WORKFLOW_REF:-NOT_APPLICABLE}
RUNNER_IDENTITY=${RUNNER_NAME:-NOT_APPLICABLE}

case "$MODE" in
  baseline|production) ;;
  *) echo "AGENT_TRUST_ISOLATION_MODE must be baseline or production" >&2; exit 2 ;;
esac
case "$IMAGE" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "AGENT_TRUST_LINUX_TEST_IMAGE must be pinned by sha256 digest" >&2; exit 2 ;;
esac
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker-compatible OCI engine is required" >&2
  exit 2
fi

server_os=$(docker info --format '{{.OSType}}')
cgroup_version=$(docker info --format '{{.CgroupVersion}}')
security_options=$(docker info --format '{{json .SecurityOptions}}')
server_kernel=$(docker info --format '{{.KernelVersion}}')
server_runtime=$(docker info --format '{{.DefaultRuntime}}')

test "$server_os" = linux
test "$cgroup_version" = 2
printf '%s' "$security_options" | grep -q 'seccomp'

runtime_args=
production_evidence=false
runsc_binary_digest=NOT_APPLICABLE
runsc_version_digest=NOT_APPLICABLE
host_attestation_digest=NOT_APPLICABLE
host_attestation_public_key_digest=NOT_APPLICABLE
host_attestation_expires_at=NOT_APPLICABLE
guest_kernel=NOT_MEASURED
if test "$MODE" = production; then
  test "$(uname -s)" = Linux
  test -f /sys/fs/cgroup/cgroup.controllers
  test -r /proc/sys/user/max_user_namespaces
  test "$(cat /proc/sys/user/max_user_namespaces)" -gt 0
  docker info --format '{{json .Runtimes}}' | grep -q 'runsc'
  case "$RUNSC_BINARY" in /*) ;; *) echo "AGENT_TRUST_RUNSC_BINARY must be absolute" >&2; exit 2 ;; esac
  test -x "$RUNSC_BINARY"
  test ! -L "$RUNSC_BINARY"
  case "$RUNSC_SHA256" in
    ????????????????????????????????????????????????????????????????) ;;
    *) echo "AGENT_TRUST_RUNSC_SHA256 must be a sha256 digest" >&2; exit 2 ;;
  esac
  case "$RUNSC_SHA256" in *[!0-9a-f]*) echo "AGENT_TRUST_RUNSC_SHA256 must be lowercase hexadecimal" >&2; exit 2 ;; esac
  runsc_binary_digest=$(sha256sum "$RUNSC_BINARY" | awk '{print $1}')
  test "$runsc_binary_digest" = "$RUNSC_SHA256"
  runsc_version=$("$RUNSC_BINARY" --version 2>&1)
  test -n "$runsc_version"
  runsc_version_digest=$(printf '%s' "$runsc_version" | sha256sum | awk '{print $1}')

  command -v openssl >/dev/null 2>&1
  for attestation_path in "$HOST_ATTESTATION" "$HOST_ATTESTATION_SIGNATURE" "$HOST_ATTESTATION_PUBLIC_KEY"; do
    case "$attestation_path" in /*) ;; *) echo "dedicated-host attestation paths must be absolute" >&2; exit 2 ;; esac
    test -f "$attestation_path"
    test ! -L "$attestation_path"
  done
  case "$HOST_ATTESTATION_PUBLIC_KEY_SHA256" in
    ????????????????????????????????????????????????????????????????) ;;
    *) echo "AGENT_TRUST_DEDICATED_HOST_ATTESTATION_PUBLIC_KEY_SHA256 must be a sha256 digest" >&2; exit 2 ;;
  esac
  case "$HOST_ATTESTATION_PUBLIC_KEY_SHA256" in *[!0-9a-f]*) echo "host attestation key digest must be lowercase hexadecimal" >&2; exit 2 ;; esac
  test "$(sha256sum "$HOST_ATTESTATION_PUBLIC_KEY" | awk '{print $1}')" = "$HOST_ATTESTATION_PUBLIC_KEY_SHA256"
  host_attestation_public_key_digest=$HOST_ATTESTATION_PUBLIC_KEY_SHA256
  openssl dgst -sha256 -verify "$HOST_ATTESTATION_PUBLIC_KEY" \
    -signature "$HOST_ATTESTATION_SIGNATURE" "$HOST_ATTESTATION" >/dev/null
  host_attestation_digest=$(sha256sum "$HOST_ATTESTATION" | awk '{print $1}')
  test -n "$EXPECTED_RUNNER_GROUP"
  test -n "$EXPECTED_RUNNER_LABELS"
  test -n "$EXPECTED_NODE_POOL"
  test "$RUNNER_IDENTITY" != NOT_APPLICABLE
  test "$SOURCE_REPOSITORY" != NOT_APPLICABLE
  test "$SOURCE_COMMIT" != NOT_APPLICABLE
  test "$SOURCE_WORKFLOW_REF" != NOT_APPLICABLE
  host_attestation_expires_at=$(python3 - "$HOST_ATTESTATION" "$(hostname)" "$RUNNER_IDENTITY" "$EXPECTED_RUNNER_GROUP" "$EXPECTED_RUNNER_LABELS" "$EXPECTED_NODE_POOL" "$RUNSC_SHA256" <<'PY'
import json
import os
import stat
import sys
from datetime import datetime, timezone

(
    path,
    expected_hostname,
    expected_runner_name,
    expected_runner_group,
    expected_runner_labels,
    expected_node_pool,
    expected_runsc_digest,
) = sys.argv[1:]
metadata = os.stat(path, follow_symlinks=False)
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
    raise SystemExit("dedicated-host attestation must be root-owned and not group/world writable")
with open(path, encoding="utf-8") as stream:
    attestation = json.load(stream)
expected = {
    "schema_version",
    "hostname",
    "environment",
    "runtime",
    "dedicated",
    "issuer",
    "runner_name",
    "runner_group",
    "runner_labels",
    "node_pool",
    "runsc_binary_sha256",
    "issued_at",
    "expires_at",
}
if set(attestation) != expected:
    raise SystemExit("dedicated-host attestation has an unexpected contract")
if attestation["schema_version"] != "agenttrust.dedicated-linux-host-attestation.v1":
    raise SystemExit("dedicated-host attestation schema is unsupported")
if attestation["hostname"] != expected_hostname:
    raise SystemExit("dedicated-host attestation hostname mismatch")
if attestation["environment"] != "production" or attestation["runtime"] != "runsc":
    raise SystemExit("dedicated-host attestation is not for production runsc")
if attestation["dedicated"] is not True:
    raise SystemExit("host is not attested as dedicated")
if not isinstance(attestation["issuer"], str) or not attestation["issuer"].strip():
    raise SystemExit("dedicated-host attestation issuer is missing")
required_labels = {
    "self-hosted", "linux", "gvisor", "cgroup-v2",
    "production-isolation", "actions-runner-2-327-1",
    "agenttrust-production-gvisor",
}
expected_labels = set(expected_runner_labels.split(","))
actual_labels = attestation["runner_labels"]
if (
    attestation["runner_name"] != expected_runner_name
    or attestation["runner_group"] != expected_runner_group
    or not isinstance(actual_labels, list)
    or len(actual_labels) != len(set(actual_labels))
    or set(actual_labels) != expected_labels
    or not required_labels.issubset(set(actual_labels))
    or attestation["node_pool"] != expected_node_pool
    or attestation["runsc_binary_sha256"] != expected_runsc_digest
):
    raise SystemExit("dedicated-host runner binding mismatch")
def timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SystemExit("attestation timestamps must be UTC RFC3339")
    return datetime.fromisoformat(value[:-1] + "+00:00")
now = datetime.now(timezone.utc)
issued = timestamp(attestation["issued_at"])
expires = timestamp(attestation["expires_at"])
if issued > now or expires <= now or expires <= issued:
    raise SystemExit("dedicated-host attestation is not currently valid")
if (expires - issued).total_seconds() > 30 * 24 * 60 * 60:
    raise SystemExit("dedicated-host attestation validity exceeds 30 days")
print(attestation["expires_at"])
PY
  )
  runtime_args='--runtime runsc'
  server_runtime=runsc
  production_evidence=true
fi

probe_name="agenttrust-isolation-probe-$$"
fork_name="agenttrust-fork-limit-probe-$$"
cleanup() {
  docker rm -f "$probe_name" >/dev/null 2>&1 || true
  docker rm -f "$fork_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# shellcheck disable=SC2086
docker run --rm --name "$probe_name" $runtime_args \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8388608 \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 32 \
  --memory 67108864 \
  --memory-swap 67108864 \
  --cpus 0.25 \
  "$IMAGE" /bin/sh -ec '
    test "$(id -u)" = 65532
    awk '\''$2 == "/" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit found ? 0 : 1 }'\'' /proc/mounts
    test "$(awk '\''/CapEff/ {print $2}'\'' /proc/self/status)" = 0000000000000000
    test "$(awk '\''/NoNewPrivs/ {print $2}'\'' /proc/self/status)" = 1
    test "$(awk '\''$1 == "Seccomp:" {print $2}'\'' /proc/self/status)" = 2
    test -f /sys/fs/cgroup/cgroup.controllers
    test "$(cat /sys/fs/cgroup/pids.max)" = 32
    test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
    test ! -S /var/run/docker.sock
    test ! -e /Users
    if grep -Eq "^[[:space:]]*(eth|en|wlan)[0-9]*:" /proc/net/dev; then exit 40; fi
    if wget -T 2 -q -O /tmp/metadata http://169.254.169.254/latest/meta-data/ 2>/dev/null; then exit 41; fi
  '

test -z "$(docker ps -a --filter "name=^/${probe_name}$" --format '{{.ID}}')"

# Verify the cgroup limit against a real process fan-out. The probe is isolated,
# bounded to 32 PIDs, and always removed by the trap.
# shellcheck disable=SC2086
docker run -d --name "$fork_name" $runtime_args \
  --network none \
  --read-only \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 32 \
  --memory 67108864 \
  --memory-swap 67108864 \
  --cpus 0.25 \
  "$IMAGE" /bin/sh -c 'while :; do sleep 30 & done' >/dev/null

if test "$MODE" = production; then
  test "$(docker inspect --format '{{.HostConfig.Runtime}}' "$fork_name")" = runsc
  # A runsc sandbox exposes its own userspace kernel rather than the host kernel.
  # shellcheck disable=SC2086
  guest_kernel=$(docker run --rm $runtime_args --network none --read-only \
    --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 8 --memory 33554432 --memory-swap 33554432 --cpus 0.1 \
    "$IMAGE" uname -r)
  test -n "$guest_kernel"
  test "$guest_kernel" != "$server_kernel"
fi

fork_exit=$(docker wait "$fork_name")
test "$fork_exit" -ne 0
test "$(docker inspect --format '{{.State.OOMKilled}}' "$fork_name")" = false
docker logs "$fork_name" 2>&1 | grep -q 'Resource temporarily unavailable'
docker rm -f "$fork_name" >/dev/null
test -z "$(docker ps -a --filter "name=^/${fork_name}$" --format '{{.ID}}')"
trap - EXIT INT TERM

if test -n "$REPORT"; then
  if test -e "$REPORT"; then
    echo "isolation report already exists" >&2
    exit 2
  fi
  python3 - "$REPORT" "$MODE" "$IMAGE" "$server_kernel" "$server_runtime" "$production_evidence" "$runsc_binary_digest" "$runsc_version_digest" "$host_attestation_digest" "$host_attestation_public_key_digest" "$host_attestation_expires_at" "$guest_kernel" "$RUNNER_IDENTITY" "$EXPECTED_RUNNER_GROUP" "$EXPECTED_RUNNER_LABELS" "$EXPECTED_NODE_POOL" "$SOURCE_REPOSITORY" "$SOURCE_COMMIT" "$SOURCE_WORKFLOW_REF" <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

(
    path, mode, image, kernel, runtime, production, runsc_digest, version_digest,
    host_attestation_digest, host_attestation_public_key_digest,
    host_attestation_expires_at, guest_kernel, runner_name, runner_group,
    runner_labels, node_pool, repository, commit, workflow_ref,
) = sys.argv[1:]
report = {
    "schema_version": "agenttrust.linux-isolation-report.v1",
    "mode": mode,
    "image": image,
    "server_kernel": kernel,
    "runtime": runtime,
    "runsc_binary_digest": runsc_digest,
    "runsc_version_digest": version_digest,
    "dedicated_host_attestation_digest": host_attestation_digest,
    "dedicated_host_attestation_public_key_digest": host_attestation_public_key_digest,
    "dedicated_host_attestation_expires_at": host_attestation_expires_at,
    "sandbox_kernel": guest_kernel,
    "runner_name": runner_name,
    "runner_group": runner_group or "NOT_APPLICABLE",
    "runner_labels": sorted(label for label in runner_labels.split(",") if label),
    "node_pool": node_pool or "NOT_APPLICABLE",
    "source_repository": repository,
    "source_commit": commit,
    "source_workflow_ref": workflow_ref,
    "checks": {
        "linux_oci_engine": True,
        "cgroup_v2": True,
        "seccomp_filter": True,
        "non_root": True,
        "read_only_rootfs": True,
        "no_new_privileges": True,
        "capabilities_dropped": True,
        "network_namespace_none": True,
        "metadata_denied": True,
        "docker_socket_absent": True,
        "host_home_absent": True,
        "pid_limit_enforced": True,
        "memory_limit_enforced": True,
        "cleanup_verified": True,
        "dedicated_linux_host": mode == "production",
        "runsc_binary_digest_verified": mode == "production",
        "runsc_runtime_selected": mode == "production",
        "sandbox_kernel_isolated_from_host": mode == "production",
        "user_namespaces_available": mode == "production",
    },
    "production_evidence": production == "true",
    "measured_at": datetime.now(timezone.utc).isoformat(),
    "valid_until": host_attestation_expires_at,
}
canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
report["evidence_digest"] = hashlib.sha256(canonical).hexdigest()
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(report, stream, sort_keys=True, indent=2)
    stream.write("\n")
PY
fi

echo "Linux OCI isolation checks passed; production_evidence=$production_evidence runtime=$server_runtime"
