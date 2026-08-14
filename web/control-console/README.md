# Enterprise Control Console

This Vue application is the tenant-scoped enterprise operations plane. It renders BFF authority
views, a verified/resumable AG-UI task stream, approval inbox, policy simulation, agent inventory,
and governed workflows for tenants, organizations, projects, integrations, quota, cost, policy
promotion, task commands and API-key lifecycle.

The browser is deliberately not an authority. It cannot mark a task complete, create an approval
grant, promote a policy directly, expose arbitrary structured authority data, or hide a partial
source failure. Every management write binds the immutable request payload into an admin intent;
the API must reauthenticate, verify CSRF/idempotency, recompute the digest, call PEP, enforce SoD,
and persist audit/evidence.

## Run

Development requires an HTTPS control API (a local TLS reverse proxy is recommended):

```sh
VITE_CONTROL_API_URL=https://control.dev.example \
VITE_AGUI_VERIFY_KEY=<base64url-ed25519-public-key> npm run dev
```

Bootstrap calls authenticated `GET /v1/session`; the BFF returns scoped identity context and a
request-bound CSRF value whose required header name is `X-XSRF-TOKEN`. No bearer token, JavaScript
cookie parsing or user-controlled DOM dataset is trusted. Production builds
fail closed unless both the HTTPS API URL and Ed25519 public key are valid.

## Verification

```sh
npm ci
npm run check
npm run test:e2e
```

The one-time API key secret exists only in component memory and is cleared on explicit dismissal or
unmount. No secret, resume token or authority payload is written to browser storage.
