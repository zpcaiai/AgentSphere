#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-.}"
mkdir -p "$TARGET/.agents/skills"
cp -R "$(cd "$(dirname "$0")/.." && pwd)/.agents/skills/." "$TARGET/.agents/skills/"
echo "Installed Agent Trust Control Plane skills into $TARGET/.agents/skills"
