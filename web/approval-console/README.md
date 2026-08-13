# Enterprise approval console

`ApprovalConsole.vue` renders only safe summaries and evidence references. The component emits an
`ApprovalIntent`; the server must re-authenticate the approver, resolve roles/ownership, apply SoD,
sign the grant, and publish a verified `APPROVAL_RECORDED` event. The browser is never an approval
truth source and never stores credentials or grant-signing keys.
