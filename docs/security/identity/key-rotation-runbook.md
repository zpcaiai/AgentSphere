# Key rotation and emergency revocation

1. Publish the new key in a versioned trust bundle before issuing with its `kid`.
2. Measure verifier refresh across Gateway, PEP, Proxy, and Sandbox.
3. Switch issuance, retain the old public key only through the maximum token TTL and bounded skew.
4. Remove the old key and bump the affected tenant/agent/task revocation epoch.
5. For compromise, revoke first, freeze new issuance, invalidate caches, scan credential-use events, and attach incident evidence.

The production verifier accepts only `RS256`/RSA, `ES256`/P-256, and
`EdDSA`/Ed25519 signing keys. It rejects symmetric/`none` algorithms,
duplicate `kid`, non-signing keys, stale JWKS snapshots, issuer/audience/`azp`
mismatch, missing nonce, unmapped subjects, and tenant or role escalation. Run
the bounded discovery/JWKS probe against the deployment issuer before rotating:

```sh
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/oidc-report.json oidc \
  --issuer https://idp.example/tenant --audience agenttrust-production
```

The report is a real-protocol preflight with `production_evidence=false`. A
rotation is production evidence only after the exact release/environment scope,
overlap window, failure test and recovery evidence are signed by the required
external reviewers.

Verify the workload client certificate and deployment CA independently; key
material is never copied into evidence:

```sh
python3 -m python.production_gates.live_integrations \
  --output /absolute/new/mtls-report.json mtls \
  --host identity.service.example --port 443 \
  --ca-file /absolute/ca.pem --client-certificate /absolute/client.pem \
  --client-private-key /absolute/client.key
```
