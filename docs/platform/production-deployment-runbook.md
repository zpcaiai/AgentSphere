# Production deployment runbook

`deploy/kubernetes/production-stack.yaml.tmpl` is the complete deployment unit for the
gateway/runtime, orchestrator ingress API, Temporal worker, authoritative transition
service, execution service, enterprise API, browser console and schema migration Job. It intentionally does
not include Temporal, PostgreSQL, Vault, the evidence PersistentVolume, public TLS
certificates, the enterprise IdP, or authoritative fact services. Those are production
dependencies owned outside this repository; the stack fails closed when they are absent.

## Prerequisites

Before rendering, the platform owner must provide:

- a Kubernetes cluster with at least three schedulable zones and nodes, an ingress class,
  cert-manager or deployment-owned TLS Secrets, NetworkPolicy enforcement, the Secrets
  Store CSI driver and HashiCorp Vault provider;
- a Vault address with Kubernetes auth roles dedicated to runtime, orchestrator,
  transition, execution, enterprise API and migrations. Do not reuse one role across workloads;
- dedicated PostgreSQL roles for the enterprise application, orchestrator application,
  execution and migrations. They must be distinct, must not be superuser or `BYPASSRLS`, and must
  not inherit broad roles. Set `database.enterprise_application_role` and
  `database.orchestrator_application_role` and `database.execution_application_role` to
  the exact unquoted role names used by the three application connection secrets. All connection URLs must use
  `sslmode=verify-full`;
  The renderer also passes those exact names to each application as its expected database
  role; startup rejects a connection whose `current_user` does not match, even if that
  unexpected role is otherwise non-superuser and non-`BYPASSRLS`;
  The enterprise Vault path must expose `database_ca`; its generated JDBC URL value must
  contain exactly one `sslmode=verify-full` and one
  `sslrootcert=/var/run/agenttrust/secrets/enterprise/database-ca.pem`, plus the encoded
  JDBC option `options=-csearch_path%3Dpg_catalog%2Cpublic`. Startup verifies both the
  configured value and the resolved server-side search path. Custom SSL
  factories/hostname verifiers and implicit trust stores are rejected. The orchestrator
  database URL must bind its own mounted CA with equivalent full hostname verification;
  Specifically, the orchestrator Vault path must expose `database_ca` and its URL must
  contain exactly one `sslmode=verify-full` and one
  `sslrootcert=/var/run/agenttrust/secrets/orchestrator/database-ca.pem`, plus exactly one
  `options=-csearch_path%3Dpg_catalog%2Cpublic`; startup also verifies the resolved schemas;
  The execution Vault path exposes `database_url` and `database_ca` separately. Its URL
  must contain exactly one `sslmode=verify-full` and the same exact encoded search-path
  option, and must not contain any other `ssl*` option. The execution service supplies
  the absolute mounted CA directly to the PostgreSQL driver and verifies its expected
  role and resolved schemas before serving;
  The migration Vault path must likewise expose `database_ca`; its URI must contain
  exactly one `sslmode=verify-full` and one
  `sslrootcert=/var/run/agenttrust/secrets/database-ca.pem`. The runner rejects a missing,
  relative, unreadable or symlinked CA file before invoking `psql`;
- multi-zone Temporal with mTLS and a namespace/task queue dedicated to this release;
- the in-cluster execution service. It exposes native TLS 1.3/mTLS on `8083` through the
  `agenttrust-execution` Service and an unserviced plain management listener on `9093`
  for `GET /ready`. Only the orchestrator API and Temporal worker may enter `8083`; only
  the node CIDR may enter `9093`. Configure exact caller SANs and a reviewed
  `execution_token_bindings` document whose entries bind exact SAN, tenant,
  `executions:execute` scope and lowercase caller-token SHA-256. The server never mounts
  a global raw execution token. Each of the approval authority, PEP, tool proxy and
  evidence uses the dedicated CIDR/port from values, the shared execution outbound mTLS
  identity, its own raw token, and an exact deployment-owned readiness schema value that
  must match the corresponding authority's reviewed contract. PostgreSQL is the only
  other execution egress;
- the approval authority reached by execution must expose authenticated `GET /ready` and
  `POST /v1/approvals/grants/consume` over hostname-verifying mTLS. The latter accepts the
  exact tenant/task/step/action/plan/parameters/resource/resource-version/policy-version/
  environment/risk binding and returns `agenttrust.approval-grant-receipt.v1` with a
  signed grant, `consumed_at`, zero `remaining_uses` and a non-empty `consumption_ref`.
  Set `execution.approval_readiness_schema` to the authority's exact
  `agenttrust.enterprise-approval-readiness.v1` contract. It must bind the action hash carried in
  `Idempotency-Key` to one durable consume result so a retry cannot consume a second grant
  or silently change the result. Execution accepts only a current, single-use
  `agenttrust.enterprise-approval.v1` grant signed by an Ed25519 key from the mounted
  `agenttrust.approval-verification-keys.v1` keyring, then forwards the verified minimal
  grant to PEP and requires PEP's authorization to name that exact approval ID. A missing,
  expired, replayed, mismatched or unverifiable grant fails closed; execution never
  manufactures an approval from request data. The key document contains unique
  `{key_id, issuer, algorithm: "Ed25519", public_key_base64}` entries whose public keys
  are standard-base64 encoded 32-byte Ed25519 keys;
- an orchestrator server certificate whose SAN includes the in-cluster DNS name
  `agenttrust-orchestrator`, plus separate client certificates whose SANs exactly match
  `enterprise.orchestrator_runtime_client_identities` and
  `enterprise.orchestrator_bff_client_identities`. The renderer rejects overlap between
  the two allowlists. The orchestrator service token stored in the enterprise Vault path
  must equal the orchestrator-side token, while the certificates and private keys remain
  workload-specific;
- transition exposes native TLS 1.3/mTLS only on its data service. Its unexposed port
  `9091` is a plain HTTP management listener for kubelet startup/readiness probes and
  checks all seven authoritative fact dependencies; NetworkPolicy restricts that port to
  the configured node CIDR;
  Set `transition.client_identities` to the exact SAN identities of authorized callers.
  The transition Vault path must provide a reviewed `transition_token_bindings` JSON
  document. Every binding contains the caller's exact certificate SAN in
  `client_identity`, one `tenant_id`, the exact `transitions:apply` scope and
  `token_sha256`, the lowercase SHA-256 digest of that caller's bearer token. The raw
  caller token remains only in the caller's Vault path; transition mounts the binding
  document and never mounts a server-global transition token. A certificate chaining to
  the CA or possession of a bearer token alone is not sufficient, and this document must
  never be generated from untrusted request data. Duplicate exact
  `(client_identity, tenant_id, scope, token_sha256)` bindings are invalid. To rotate a
  token without an authorization gap, first add a binding containing the new digest,
  roll the caller to the new raw token, confirm successful bound calls, and only then
  remove the old digest;
- a pre-provisioned read-only PersistentVolume whose `release-id`, `SHA256SUMS` and
  evidence files bind the exact immutable release. The workload mounts it as `ReadOnlyMany`;
- digest-pinned application and base images, a signed Git release ID, a base64url
  Ed25519 AG-UI verification public key, and authoritative HTTPS endpoints;
- all workload-reached HTTPS dependencies on port `443` or `8443`. The renderer rejects
  a URL on any other port because the corresponding egress policy would not carry it;
- explicit, non-overlapping database, Temporal, node, trusted-service, execution approval,
  execution PEP, execution tool-proxy and execution evidence CIDRs, plus
  `network.dns_cidr` set to the single cluster resolver address (`/32` for IPv4 or `/128`
  for IPv6). Use the NodeLocal DNSCache address when enabled, otherwise the kube-dns
  Service address. The policy also selects standard kube-dns Pods for CNI implementations
  that enforce after Service DNAT. The renderer rejects `/0`; the rendered
  NetworkPolicies contain no unrestricted egress.

Vault object names and keys are listed in the six `SecretProviderClass` resources. CSI
mount permissions are `0440`; Pods set `fsGroup: 65532`, and the production CSI
driver/provider must support applying that mount group. Verify the effective ownership and
mode before rollout. Secrets are mounted directly and never placed in ConfigMaps,
Kubernetes Secret objects, Pod values, image layers or command lines. CSI rotation updates
the mounted files; processes that read a value only during startup still require a
  controlled rollout after rotation. Verify readiness and the new certificate/key identity.

Spring Session uses the BFF's application-global opaque session tables and deliberately has
no tenant business key or RLS policy. Do not share that table namespace, session cookie, or
database credentials with another application. Tenant scope is reconstructed from the verified
OIDC/JWT principal on every request; no session-table enumeration endpoint is exposed.

Enterprise readiness is dependency-aware: the database, PEP, exact IdP JWKS URL and all
configured authorities must be healthy. Set `enterprise.iam_jwks_endpoint` to the exact
HTTPS key-set URL. JWKS must return a non-empty `keys` array; PEP and authority `/ready`
calls use the enterprise outbound mTLS identity plus the service token and accept only
`{"ready":true}` or a status of `UP`/`READY`. A missing or degraded dependency keeps the
Pod out of service; liveness remains process-only.
Set `enterprise.iam_audience` to the exact production access-token audience. It is a
bounded identifier (letters, digits, `.`, `_`, `:`, `-`) rather than a free-form YAML
fragment; the API requires both issuer and audience to match before accepting a JWT.
Set `enterprise.iam_authorization_endpoint`, `enterprise.iam_token_endpoint` and
`enterprise.iam_userinfo_endpoint` to exact HTTPS IdP endpoints. The API does not use
ambient OIDC discovery in production; token exchange, UserInfo and JWKS retrieval use the
same hostname-verifying mTLS client and pinned enterprise trust store.

## Image build

Every base passed to `scripts/build-production-image.py` must be digest-pinned. Build the
seven release images with `runtime`, `orchestrator`, `transition`, `execution`,
`enterprise-control`, `console` and `migrations`. Console build additionally requires the exact public API URL
and Ed25519 verification key:

```sh
python3 scripts/build-production-image.py \
  --component console \
  --output-image registry.example/agenttrust/console:RELEASE \
  --base-image node-builder.example/node@sha256:... \
  --base-image nginx.example/nginx-unprivileged@sha256:... \
  --control-api-url https://control.example.com \
  --agui-verify-key BASE64URL_ED25519_PUBLIC_KEY
```

The console URL and verification key are public build-time trust configuration, not
secrets. The console image pins its CSP `connect-src` to that one API origin.

## Render and validate

Prepare a deployment-owned values JSON matching
`deploy/kubernetes/production-stack-values.schema.json`, plus a runtime JSON based on
`config/production-runtime.example.json`. The runtime config must contain no
`REPLACE_WITH` or `.production.example` values. Its listener, secret-file, evidence-file,
internal orchestrator, mTLS identity and 15 endpoint/token contracts are checked by the
renderer.

The enterprise BFF's orchestrator endpoint is deliberately fixed to the in-stack
`https://agenttrust-orchestrator` service and is not a values-file escape hatch. Other
authority endpoints remain explicit external HTTPS inputs.

The execution activity sends only a durable `agenttrust.action-materialization-ref.v1`
pointing to `ORCHESTRATOR_INGRESS_POSTGRESQL`, tenant/task/action identifiers, the ingress
digest and a stable derived idempotency key. Canonical Action bytes do not enter Temporal
history. The same execution request is used for both initial dispatch and bounded polling;
the execution service must atomically materialize and digest-check the stored action, pass
it through PEP/ledger/evidence, enforce its fence token, and return the same authoritative
outcome for retries. `PREPARED` and `RUNNING` remain nonterminal observations; a transport
failure is not rewritten as an authoritative `UNKNOWN` outcome.

For any tool or policy path that requires approval, first complete the authoritative
approval case. Execution then consumes and cryptographically verifies that grant before
requesting its single-use execution authorization from PEP. An approval ID supplied by a
browser, Temporal history or the caller request is not authoritative. Exercise both the
approved and rejected/expired/mismatched paths during production acceptance, while keeping
the outcome and evidence gates distinct from mere task acceptance.
The execution service first calls the existing PEP authority at
`POST /v1/authorize/pre-approval`; only that signed policy outcome determines whether the
approval consume step is required, after which `POST /v1/authorize/execution` binds the
verified grant. Both PEP calls reuse the dedicated PEP mTLS/token configuration.

The native-TLS orchestrator API `/ready` verifies PostgreSQL, Temporal, transition and
execution with the same mounted mTLS identities/tokens used for real traffic. Its HTTPS
startup/readiness probes therefore drain the API when any critical dependency is
unavailable; TCP is retained only for liveness.

The worker exposes an unserviced plain-HTTP management listener on `9092`. `/ready`
performs bounded parallel checks of Temporal `GetSystemInfo`, transition HTTPS/mTLS/token
readiness, and execution HTTPS/mTLS/token readiness. Transition readiness must bind
`schema_version=agenttrust.transition-readiness.v1`; execution readiness must bind
`schema_version=agenttrust.execution-readiness.v1`; either requires exact `ready=true`.
The whole dependency group is bounded below the kubelet probe timeout. NetworkPolicy permits `9092` only
from the configured node CIDR. Liveness is a socket probe so a dependency outage drains
the worker without forcing a restart loop.

```sh
output=$(mktemp /tmp/agenttrust-production.XXXXXX.yaml)
rm "$output"
python3 scripts/render-production-stack.py \
  --template deploy/kubernetes/production-stack.yaml.tmpl \
  --values /protected/release/production-stack-values.json \
  --runtime-config /protected/release/production-runtime.json \
  --output "$output"
kubectl apply --dry-run=client --validate=false -f "$output"
```

The renderer writes a new absolute output path with mode `0600` and refuses to overwrite
an existing file. Do not check rendered deployment values or manifests into this
repository; although non-secret by contract, they expose production topology.

## Apply order

Apply only the objects labelled `agenttrust.io/apply-phase=prerequisite`, wait for CSI
objects and claims to be ready, then apply the migration Job. Do not deploy workloads
until the Job succeeds.

```sh
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=prerequisite
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=migration
kubectl wait --for=condition=complete --timeout=30m \
  job/agenttrust-migrate-RENDERED_RELEASE_NAME
kubectl logs job/agenttrust-migrate-RENDERED_RELEASE_NAME --all-containers
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=workload
kubectl rollout status deployment/agenttrust-transition --timeout=10m
kubectl rollout status deployment/agenttrust-execution --timeout=10m
kubectl rollout status deployment/agenttrust-temporal-worker --timeout=10m
kubectl rollout status deployment/agenttrust-orchestrator-api --timeout=10m
kubectl rollout status deployment/agenttrust-production-runtime --timeout=10m
kubectl rollout status deployment/agenttrust-enterprise-control --timeout=10m
kubectl rollout status deployment/agenttrust-console --timeout=10m
```

The migration runner takes a transaction-level advisory lock, verifies TLS and database
role posture, pins an effective `{pg_catalog,public}` lookup path, records the SHA-256 and
release ID of every migration and refuses changed or unexpected history. It grants only
the explicit current enterprise/Spring Session and orchestrator ingress tables (plus the
stream identity sequence) to their dedicated roles. Execution gets only its materialized
ingress/tool snapshot reads, ledger reads/writes, outbox insert and fence-sequence usage;
it denies schema creation, migration history access and cross-domain DML. Re-run a digest-pinned migration image in check mode
after rollout:

```sh
run-production-migrations --check
```

`transaction-ledger/0003_transaction_ledger_inbox_tenant.sql` deliberately stops if a
legacy `execution_inbox` row cannot be assigned to a tenant. A database owner must supply
and independently review an explicit tenant backfill before retrying; never guess or map
such rows to a default tenant.

For an existing installation, place the control plane in an approved maintenance window
before applying this release: drain all legacy ledger and enterprise writers, wait for
in-flight transactions/outboxes to settle, take and verify a point-in-time recovery
checkpoint, then run the migration Job. Keep writers drained until `--check` succeeds.
This is mandatory because the tenant-isolation closure changes keys, foreign keys and
`NOT NULL`/RLS enforcement; it is not an online dual-write migration. The runner sets a
five-second lock timeout and aborts rather than waiting indefinitely. On lock timeout or
backfill failure, keep workloads stopped, identify the blocking transaction or unresolved
row, perform a reviewed backfill, and retry the same immutable migration image. Do not
drop constraints, disable RLS or start mixed old/new writers to force progress.

## Verification and rollback

Verify all Pods use the rendered digests, are Ready in three zones, respect disruption
budgets, and have no unexpected egress. Exercise an authenticated browser smoke test,
create/query/cancel one non-production task, approve/reject one test case, and verify its
Action IR, PEP decision, ledger record, signed AG-UI events and evidence package.

Application rollback must use a known compatible digest. Database changes here are
forward-only; do not down-migrate a production database. If a rollout fails after schema
application, retain the new schema and roll application images back only after the
compatibility gate passes. Real HA/DR, sustained load, physical writes, customer
acceptance and certificate issuance remain separate evidence gates.
