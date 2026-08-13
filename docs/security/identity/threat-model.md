# Identity threat model

Workload tokens bind issuer, audience, tenant, agent, task, step, action hash, policy decision, key ID, expiry, and revocation epoch. OIDC subjects are mapped to tenant/owner server-side; custom tenant claims are ignored. mTLS certificate fingerprints use the same trusted mapping. Wrong issuer/audience/algorithm/key/time/nonce, cross-task scope, replay after max uses, and revocation all fail closed. Token and secret values have redacted Debug output and are not audit fields.

