# Policy enforcement flow

The Rust PEP runs deterministic hard guards before PDP evaluation at PRE_APPROVAL and again at PRE_EXECUTION. Decisions bind PolicyInput hash, policy bundle, TTL, and known typed obligations. Minimal approvals bind action, task/step, resource version, policy version, expiry, and single use. Successful enforcement creates a signed, short-lived, single-use Execution Authorization; Sandbox and Proxy reject bare calls.

