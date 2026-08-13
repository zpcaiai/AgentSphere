#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/target/contract-conformance"
mkdir -p "$out/rust" "$out/java" "$out/typescript"

python3 -m unittest discover -s "$root/tests/conformance" -p 'test_*.py'
rustc --edition=2024 "$root/tests/conformance/generated_contracts.rs" --out-dir "$out/rust"
javac -d "$out/java" \
  "$root/generated/java/src/main/java/com/agenttrust/v1/Contracts.java" \
  "$root/tests/conformance/ContractSmokeTest.java"
java -cp "$out/java" ContractSmokeTest
tsc --strict --noEmit --target ES2022 --moduleResolution node \
  --outDir "$out/typescript" "$root/tests/conformance/generated_contracts.ts"
