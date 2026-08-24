# Enterprise approval console

`ApprovalConsole.vue` renders only secret-screened, domain-specific review facts and exactly three
immutable risk-package, state-snapshot, and approval-attestation Evidence references. Coding cases
require diff/command/network/rollback; industrial cases require current/target/range/interlock/
physical-impact. Missing, mixed-domain, extended, secret-like, or unbound values are rejected
before rendering. The component emits an
`ApprovalIntent`; the server must re-authenticate the approver, resolve roles/ownership, apply SoD,
sign the grant, and publish a verified `APPROVAL_RECORDED` event. The browser is never an approval
truth source and never stores credentials or grant-signing keys.
