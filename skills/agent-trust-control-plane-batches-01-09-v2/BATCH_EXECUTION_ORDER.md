# Recommended implementation order

Batch numbering is a capability catalog, not a strict build order. Use this dependency-safe order:

1. **Trust foundation**: 01 → 03 → 05 → 04 → 02 → 06 → 07 → 08 → 09 → 10.
2. **Minimal enterprise loop**: 17 → 29.
3. **Protocol and gateway expansion**: 11 → 12 → 13 → 14 → 15 → 16.
4. **Governance foundation**: 18 → 19 → 20 → 21 → 22.
5. **Inventory and policy/context governance**: 30 → 31 → 32.
6. **Domain packs**: 23 → 24 → 25 → 26 → 27 → 28.
7. **Verification and production platform**: 33 → 34 → 35 → 36.

Do not execute all batches blindly. Each batch must consume actual prior code and update `IMPLEMENTATION_STATUS.json` with evidence.
