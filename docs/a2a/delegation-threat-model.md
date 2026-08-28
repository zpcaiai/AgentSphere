# A2A delegation and AG-UI threat model

Delegation may only reduce the parent lease: tools, resources, budget, TTL, call count and depth are
intersections or lower ceilings. Agent Card discovery never grants trust. Tokens bind root task,
parent task/step, child agent, issuer key and tenant revocation epoch. Revoke token/root task or bump
the tenant epoch to stop descendants.

Production Agent Cards are HTTPS, publisher-subject signed, expiry bounded, and pinned into each
durable task record by card hash, endpoint and negotiated protocol version. The native adapter
supports A2A 0.3 `message/send`, `tasks/get`, `tasks/cancel` and A2A 1.0 `SendMessage`, `GetTask`,
`CancelTask`. It normalizes the official input/auth-required, canceled, rejected and failed states.
Cancel first commits local `CANCELLING`; an ambiguous remote result stays there until a signed,
tenant-scoped poll reconciles it. A remote completion remains `VERIFYING` until evaluator PASS.

AG-UI events are backend-signed, strictly sequenced and deduplicated. A stale resume token requires a
safe snapshot; replay never repeats commands. Browsers may submit an approval intent but cannot emit
an authoritative `APPROVAL_RECORDED` event. Remote `completed` maps to internal `COMPLETED` only after
the evaluator returns PASS. Compromised cards, confused deputy delegation, recursive budget abuse,
event reordering and UI fact forgery are covered by negative tests.

Production event sequence reservation, append, replay and latest-snapshot lookup use the durable
`AgUiEventStore`. Every replayed event is backend-signature checked, tenant/task bound and strictly
increasing. Safe snapshots also sign their embedded opaque resume position; sensitive control or
credential fields are rejected from `safe_payload`. These local contract tests do not constitute a
real peer, reconnect, cancellation-latency or behavioral-safety result.
