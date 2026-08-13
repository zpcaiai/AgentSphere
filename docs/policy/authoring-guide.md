# Policy authoring

Common policy owns tenant, active tool, production identity, classification, and protected-control-plane rules. Coding policy owns repository/branch/path/change/network constraints. Industrial policy owns asset/tag/value/delta, freshness, interlock/alarm, simulation, approval, and CAS guards. Every rule requires positive, negative, and boundary tests; run `scripts/run-policy-tests.sh` with a checksum-verified OPA CLI.

