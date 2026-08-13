# A2A delegation and AG-UI threat model

Delegation may only reduce the parent lease: tools, resources, budget, TTL, call count and depth are
intersections or lower ceilings. Agent Card discovery never grants trust. Tokens bind root task,
parent task/step, child agent, issuer key and tenant revocation epoch. Revoke token/root task or bump
the tenant epoch to stop descendants.

AG-UI events are backend-signed, strictly sequenced and deduplicated. A stale resume token requires a
safe snapshot; replay never repeats commands. Browsers may submit an approval intent but cannot emit
an authoritative `APPROVAL_RECORDED` event. Remote `completed` maps to internal `COMPLETED` only after
the evaluator returns PASS. Compromised cards, confused deputy delegation, recursive budget abuse,
event reordering and UI fact forgery are covered by negative tests.
