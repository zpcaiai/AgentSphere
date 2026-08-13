#!/bin/sh
set -eu
python3 "$(dirname "$0")/generate_contracts.py" --check

