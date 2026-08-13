#!/bin/sh
set -eu
: "${GATEWAY_URL:=https://127.0.0.1:8443/healthz}"
: "${CONCURRENCY:=32}"
: "${REQUESTS:=1000}"
if ! command -v oha >/dev/null 2>&1; then
  echo "oha is required for the gateway load baseline" >&2
  exit 2
fi
oha -n "$REQUESTS" -c "$CONCURRENCY" --no-tui "$GATEWAY_URL"

