# Domain Risk Pack operations

- Coding: pin repository and base commit, restrict branch/path/command/network scope, prevent direct protected-branch writes, scan secrets and dependencies, require build/test/evaluator evidence and rollback.
- Industrial: progress through simulator, digital twin, read-only, shadow, and supervised write. Validate fresh good-quality telemetry, alarm/interlock/maintenance/range/ramp rules, use prepare plus compare-and-set commit, and observe physical convergence. ACK is not physical success.
- Energy: Python emits candidates only. Rust/PEP validates each setpoint and trajectory; hard limits beat economic objectives. Low-confidence or out-of-distribution input selects a deterministic safe fallback. Start in shadow.
- Medical: minimize fields, prove care relationship, enforce region/model policy, expose read-only tools, and route high-risk recommendations to a qualified human. No code test constitutes clinical certification.
- Sensitive interaction: require consent and minimum disclosure, reject manipulation, use conservative minor handling, and resolve escalation destinations from a reliable versioned regional directory. Never hardcode crisis contact details in the Pack.

Every domain action still traverses Canonical Action IR, PEP, Ledger, Evidence, and the durable orchestrator. Domain packs do not duplicate those controls.
