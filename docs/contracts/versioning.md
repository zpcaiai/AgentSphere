# Contract versioning

JSON Schema 2020-12 is authoritative for JSON boundaries; Protobuf is authoritative for RPC field numbers. Generated language types come only from `schemas/contract-model.json`. Minor changes may add optional fields. Removing fields, reusing Protobuf numbers, narrowing enums, or changing security semantics requires a new major schema and migration vectors. Unknown security enums and protobuf zero values fail closed.

Run `./scripts/generate-contracts.sh`, `./scripts/check-generated.sh`, and `python3 scripts/check-contract-parity.py` after every contract change.

