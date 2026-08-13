#!/bin/sh
set -eu

if command -v opa >/dev/null 2>&1; then
  exec opa test policies -v
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "OPA CLI or Docker is required" >&2
  exit 2
fi

# This is the verified linux/arm64 OPA 1.19.0 static image used by the local
# closure run. Other architectures must provide their own immutable digest.
: "${AGENT_TRUST_OPA_IMAGE:=openpolicyagent/opa@sha256:2f42ca765bb739b40fc23ee625b3287012acdf8120ad4fcbdab68433a17be144}"
case "$AGENT_TRUST_OPA_IMAGE" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *)
    echo "AGENT_TRUST_OPA_IMAGE must be pinned by sha256 digest" >&2
    exit 2
    ;;
esac

exec docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 128m \
  --cpus 1 \
  --mount "type=bind,src=$PWD/policies,dst=/policies,readonly" \
  "$AGENT_TRUST_OPA_IMAGE" test /policies -v
