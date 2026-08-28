# Production deployment runbook

`deploy/kubernetes/production-stack.yaml.tmpl` is the production deployment unit for
the Agent Trust control plane. It renders twenty-seven Deployments: the production runtime,
orchestrator API, Temporal worker, transition authority, execution service, Tool
Registry, Agent Registry, Policy Administration Authority, Incident/Release Authority,
Pack Marketplace Authority, Approval Authority, execution PEP, Identity/Credential
Authority, Tool Proxy, Evidence Authority, Audit Retention, Enterprise Mutation Authority,
enterprise BFF and browser console. It also renders the forward-only
migration Job, Services, ServiceAccounts, PodDisruptionBudgets, SecretProviderClasses,
default-deny and peer-scoped NetworkPolicies, ingress and immutable release metadata. It
also creates the cluster-scoped `agenttrust-gvisor` RuntimeClass plus the restricted
`agenttrust-sandboxes` namespace, ServiceAccount, quota and default-deny ingress/egress
policy. The one-shot `sandbox_worker` image is an attested native-worker transport artifact;
it is intentionally not deployed as a long-running Pod and never receives a Docker socket
or host-root mount.

This manifest is deployable configuration, not production certification. PostgreSQL,
multi-zone Temporal, Vault, enterprise IdP, WORM object storage, public ingress
certificates, external authoritative fact services,
HA/DR exercises, load evidence and customer or assessor sign-off remain external gates.
Keep their evidence status `NOT_RUN`, `NOT_ISSUED`, `IN_PROGRESS` or `NOT_CERTIFIED`
until the named production evidence exists.

## Release-scoped blue/green cutover

`scripts/materialize-production-blue-green-stack.py` derives a deterministic
revision from the signed release ID and release digest. ConfigMaps,
SecretProviderClasses, Deployments and PodDisruptionBudgets are revision-named
and label-bound so two releases can coexist. Stable Services are the only
traffic objects and receive a revision selector during the cutover operation.

`scripts/execute-production-deployment.py` performs the apply order and never
changes database state itself. It first obtains a short-lived GitHub OIDC token
and calls the mTLS deployment-cutover broker for a signed `WRITER_FENCE`, then
applies admission and migration Jobs, starts the new revision, waits for every
Deployment, requests signed `CUTOVER`, verifies Service selectors and non-empty
Endpoints, scales the source revision to zero, and requests signed `UNFREEZE`.
The broker response must validate against the deployment keyring and the
source/target inventory. A post-cutover failure requires signed `ROLLBACK` and
source `UNFREEZE`; if those cannot be obtained the database remains fenced.
No local flag, kubectl output, or CI account can substitute for these signed
external receipts.

## PEP compatibility gate

The in-stack Rust PEP serves `POST /v1/authorize/pre-approval`,
`POST /v1/authorize/execution`, `POST /v1/authorize/approval` and
`POST /v1/authorize/query`. The enterprise BFF uses only the latter two governance routes;
enterprise mutations are Canonical Action IR submissions and never call an
`/v1/authorize/admin` shortcut. Approval and query requests carry an exact tenant header,
route-specific opaque token, stable Idempotency-Key and a request-bound Ed25519 human
principal assertion. The PEP verifies issuer, audience, key usage, mTLS SAN, service
subject, scope, body digest, authentication age and JTI before consulting the external PDP
and writing immutable governance evidence.

The following enterprise endpoints are intentionally fixed to in-stack authorities:

- orchestrator: `https://agenttrust-orchestrator`;
- agent registry: `https://agenttrust-agent-registry`;
- tool registry: `https://agenttrust-registry`;
- approvals: `https://agenttrust-approval`;
- credentials: `https://agenttrust-identity`;
- evidence: `https://agenttrust-evidence`;
- policies: `https://agenttrust-policy-admin`;
- incidents: `https://agenttrust-incident-release`;
- packs: `https://agenttrust-pack-marketplace`.

## Cluster and external prerequisites

Provide all of the following before rendering:

- a Kubernetes cluster with at least three schedulable zones, enforced NetworkPolicy,
  an ingress class, Secrets Store CSI plus Vault provider, and kubelet/node probe
  addresses represented by `network.node_cidr`;
- all thirty-one digest-pinned release images, including the `sandbox_worker` transport
  artifact, AgentTrust-owned Envoy/utility wrapper subjects and release admission image;
- dedicated Linux sandbox hosts with cgroup v2, user namespaces, a digest-pinned rootless
  `runsc`, signed runtime attestation and the native systemd worker unit; Kubernetes-based
  one-shot executors additionally require the `runsc` RuntimeClass handler and the exact
  dedicated-node labels rendered by this stack;
- production PostgreSQL with TLS hostname verification, reviewed backups and a separate
  migration login that owns or can alter migration objects without being superuser or
  `BYPASSRLS`;
- multi-zone Temporal with a dedicated namespace/task queue and mTLS identity;
- Vault roles scoped independently to runtime, orchestrator, transition, execution,
  registry, agent registry, approval, PEP, identity, tool proxy, evidence, audit,
  policy administration, incident/release, pack marketplace, enterprise mutation
  authority, enterprise BFF and migrations;
- explicit enterprise IdP issuer, JWKS, authorization, token and UserInfo HTTPS endpoints;
- WORM storage whose readiness response is exactly
  `{"schema_version":"agenttrust.worm-readiness.v1","ready":true,"object_lock":true}`;
- a dedicated egress gateway CIDR for external HTTPS authorities. Its L7/DNS policy must
  allow only reviewed hostnames; `0.0.0.0/0` is forbidden;
- an immutable Git release ID and a read-only evidence PersistentVolume bound to it.

Certificates are production inputs. Verify chain, SAN, EKU, validity, rotation owner and
revocation independently. Rendering a certificate path does not change issuance status.

## PostgreSQL identities and least privilege

Pre-create fifteen distinct application logins matching the values exactly:

1. `database.enterprise_application_role`
2. `database.enterprise_authority_application_role`
3. `database.orchestrator_application_role`
4. `database.execution_application_role`
5. `database.registry_application_role`
6. `database.agent_registry_application_role`
7. `database.policy_admin_application_role`
8. `database.incident_release_application_role`
9. `database.pack_marketplace_application_role`
10. `database.approval_application_role`
11. `database.pep_application_role`
12. `database.identity_application_role`
13. `database.tool_proxy_application_role`
14. `database.evidence_application_role`
15. `database.audit_application_role`

Each must be `LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
NOBYPASSRLS`, own no object, have no role membership, have `row_security=on`, and resolve
the search path to exactly `{pg_catalog,public}`. The runner rejects a missing, duplicate,
non-login, inheriting, owner or privileged role. It revokes `TEMPORARY` from `PUBLIC` and
all application roles, grants only `CONNECT` and schema `USAGE`, clears historical
table/column/sequence/function ACLs, then installs exact service grants. It also rejects
migration-history access, cross-domain DML, unexpected sequence use and executable
functions in `public`.

The exact grants are:

- enterprise BFF: only read/append plus exact state-column updates on remote-action and
  approval-intent queues, and Spring Session CRUD; it has no business-table, idempotency,
  API-key or admin-action access;
- enterprise mutation authority: read/append on its replay/ingress/version/execution
  tables, insert-only outbox, exact state/version/result columns, read/append on the eight
  business tables used by its versioned operations, quota-counter updates and API-key
  revocation columns only;
- orchestrator: its application tables and stream identity sequence;
- execution: materialized ingress/tool snapshot reads, ledger execution reads/writes,
  insert-only idempotency, read/insert outbox and its fence sequence;
- registry: registry reads/appends, with update only on mutable version/key/revision tables;
- agent registry: select/insert on exactly thirteen inventory, posture, lifecycle,
  idempotency, audit and outbox tables; update is limited to `agent_assets` and
  `agent_registry_audit_heads`;
- policy administration: select/insert on its policy state and activation-intent tables,
  insert-only evidence outbox, and exact lifecycle, promotion, activation claim/ack,
  version, ingress and execution-result columns;
- incident/release: select/insert on fifteen live incident/replay/release-gate state
  tables, insert-only on both Evidence tables, exact updates on five state tables, and
  zero privileges on the legacy `release_gate_results` table;
- pack marketplace: exactly 26 SELECT/INSERT privileges across thirteen domain/state
  tables plus two INSERT-only Evidence privileges; UPDATE is restricted to the exact 54
  columns used by the nine mutable state tables;
- approval: select/insert on eight tables, update only case status/timestamp and the six
  consumption/revocation columns on grants;
- PEP: select/insert on the authorization/governance tables and all five activation
  tables; the existing authorization-request update remains table-scoped, while activation
  updates are column-scoped to `state`, claim ownership/lease, PDP acknowledgement,
  response, completion and update fields on `pep_policy_activation_requests`, and to the
  activation/policy/sequence/bundle/version/PDP-ack/activation-time fields on
  `pep_active_policy_bundles`; the other three activation tables are append/read only;
- identity: the exact read/mutable/append/write-only split verified at startup;
- tool proxy: select/insert/update invocations and insert-only audit/outbox;
- evidence: append/read immutable records, controlled chain-head update, and read-only
  execution/PEP authorization bindings.
- audit: append/read immutable audit assets and human-assertion replay uses, controlled
  chain-head update, and only the three release columns on Legal Hold; it receives no
  authority-table or migration access.

Rust database URL files must contain a username equal to the expected role, must not embed
a password, and must contain only the database path plus exact `sslmode=verify-full`,
absolute mounted `sslrootcert`, and `options=-csearch_path=pg_catalog,public`. Passwords
are mounted separately, including `AGENT_TRUST_ORCHESTRATOR_DATABASE_PASSWORD_FILE` and
the execution, registry, policy, incident/release, pack marketplace, approval, PEP,
identity, tool-proxy, evidence and audit equivalents.
The enterprise BFF uses config-tree JDBC URL/user/password files and equivalent role/TLS
checks. The migration URI is passwordless, uses `verify-full` and its mounted CA, and is
parsed into individual libpq variables so it is never put in argv. Mount the migration
password independently as `AGENT_TRUST_DATABASE_PASSWORD_FILE`; the runner converts it to
a mode `0600` temporary `PGPASSFILE` on the memory-backed `/tmp` volume and removes it on
normal exit, validation failure, or termination.
The database endpoint must support TLS 1.3 and SCRAM-SHA-256-PLUS channel binding; the
migration runner disables inherited GSS encryption and rejects any connection contract that
would fall back to a weaker or differently routed session. The migration image must provide
PostgreSQL `psql`/libpq 13 or newer; the runner rejects older or unidentifiable clients and
asserts the negotiated `TLSv1.3` version from `pg_stat_ssl` inside the migration transaction.

## Vault and secret material

The twenty-seven SecretProviderClasses list every required object. Policy Administration,
Incident/Release and Pack Marketplace each use independent Vault roles and paths; their
SecretProviderClasses mount exactly 15, 15 and 13 objects respectively. Agent Registry and
Enterprise Mutation Authority each mount exactly fourteen objects. Files mount directly at
`0440`, Pods run with `fsGroup: 65532`, and no raw credential belongs in a ConfigMap,
Kubernetes Secret, image layer, command line or values file. Verify effective mode and
ownership with the installed CSI provider.

Issue each caller certificate with exactly one allowed DNS or URI SAN. Values SANs must
match Vault certificates; rendering cannot inspect a certificate. Server certificates
must cover Service DNS. Signing keys are Ed25519 raw base64url 32-byte seeds unless the
named contract says otherwise. Verification material must independently bind issuer, key
ID and key usage.

## Caller tokens and server digest bindings

Every raw bearer token is private to one caller, tenant and route scope. Each server mounts
only a reviewed digest-binding document, not a server-global raw token. A CA chain, allowed
SAN or token alone is insufficient. Documents reject unknown identities, malformed
tenants/scopes, duplicates and forbidden raw-token digest reuse.

| Server | Data / management | Required scopes |
| --- | --- | --- |
| Orchestrator | 8081 TLS | `orchestrator:runtime`, `orchestrator:read`, `orchestrator:command`, `orchestrator:transitions` |
| Execution | 8083 TLS / 9093 | `executions:execute` |
| Registry | 8084 TLS / 9094 | `registry:read`, `registry:write` |
| Agent Registry | 8089 TLS / 9099 | `agents:read`, `agents:register`, `agents:discover`, `agents:ownership:assign`, `agents:ownership:confirm`, `agents:bom`, `agents:relationships:write`, `agents:relationships:read`, `agents:posture:evaluate`, `agents:posture:read`, `agents:lifecycle` |
| Policy Administration | 8090 TLS / 9101 | `policy:mutate`, `policy:execute`, `policy:query` |
| Incident / Release | 8090 TLS / 9101 | `incident:detect`, `incident:mutate`, `incident:execute`, `incident:query` |
| Pack Marketplace | 8090 TLS / 9101 | `packs:mutate`, `packs:execute`, `packs:read` |
| Approval | 8085 TLS / 9095 | `approvals:read`, `approvals:request`, `approvals:decide`, `approvals:issue`, `approvals:revoke`, `approvals:consume`, `approvals:verify` |
| Execution and governance PEP | 8086 TLS / 9096 | `pep:preapprove`, `pep:authorize`, `pep:approval`, `pep:query`, `pep:policy-activate` |
| Identity | 8085 TLS / 9095 | `credentials:read`, `credentials:issue`, `credentials:consume`, `credentials:revoke` |
| Tool Proxy | 8086 TLS / 9096 | `tools:execute` |
| Evidence | 8087 TLS / 9097 | `evidence:append`, `evidence:event`, `evidence:authority-event`, `evidence:read`, `evidence:artifact`, `evidence:package`, `evidence:evaluate` |
| Audit Retention | 8088 TLS / 9098 | `audit:append`, `audit:query`, `audit:authoritative-query`, `audit:retention`, `audit:hold-place`, `audit:hold-release`, `audit:export`, `audit:delete`, `audit:control`, `audit:graph` |
| Enterprise Mutation Authority | 8449 TLS / 9100 | `enterprise:mutate`, `enterprise:execute` |

The BFF mounts 13 distinct read tokens, six operation tokens (including independent
`policy:mutate`, `incident:mutate`, `packs:mutate` and `enterprise:mutate` tokens), two enterprise-PEP
tokens and five Approval tokens. Java hashes and rejects reuse inside each provider group.
`AGENT_TRUST_SERVICE_TOKEN_FILE` has been removed. Its certificate SAN must be present in
Orchestrator, Agent Registry, Tool Registry, Approval, Identity, Evidence, Audit and
Enterprise Mutation Authority allowlists as applicable. The Tool Proxy certificate has a
separate `enterprise:execute` binding and never receives the BFF mutate token.

Orchestrator mounts `agenttrust.orchestrator-token-bindings.v1`. Runtime uses one
`orchestrator:runtime` token; the BFF uses separate `orchestrator:read`,
`orchestrator:command` and `orchestrator:transitions` tokens. The old
`orchestrator-service.token` does not exist. For transition, every reviewed binding is the
exact `(client_identity, tenant_id, scope, token_sha256)` tuple, and `token_sha256` is the
lowercase SHA-256 digest of that caller's bearer token. For rotation, first add a binding
containing the new digest, roll the caller to the new raw token, verify the bound call,
and only then remove the old digest.

Execution uses distinct `AGENT_TRUST_EXECUTION_PEP_PREAPPROVE_TOKEN_FILE` and
`AGENT_TRUST_EXECUTION_PEP_AUTHORIZE_TOKEN_FILE`; equality is rejected. Approval consume,
Tool Proxy execute and Evidence append use separate tokens. Execution never manufactures
an approval from request data. It calls `POST /v1/approvals/grants/consume`, validates
`agenttrust.approval-grant-receipt.v1` using
`agenttrust.approval-verification-keys.v1`, and requires PEP to bind the consumed grant.
Approval readiness is exactly `agenttrust.approval-readiness.v1` with
`ready=true`.

## Execution PEP outbound authorities

`pep-authority-bindings.json` must be `agenttrust.pep-authority-bindings.v1` and reference
only mounted PEP files. The PEP SecretProviderClass supplies one outbound certificate/key,
a pinned CA, eleven physically distinct raw token files and ten distinct Ed25519
verification-key files. The entries are `identity`, `resource_state`, `budget`,
`trajectory_risk`, `registry`, `environment`, `pdp`, `pdp_activation`, `approval`,
`ledger` and `credential`. Token files are:

`identity.token`, `resource-state.token`, `budget.token`, `trajectory-risk.token`,
`registry.token`, `environment.token`, `pdp.token`, `pdp-activation.token`,
`approval-verify.token`, `ledger.token`, and `credential-issue.token`.

All eleven token SHA-256 digests must be globally unique. Signed fact, PDP activation,
approval, ledger and
credential responses use separate verification-key files and expected issuer/key usage.
Credential is fixed to scope `credentials:issue` and `/v1/credentials/issue`; approval
uses independent `approvals:verify`. The PEP outbound SAN must be accepted by Registry,
Approval and Identity. Its NetworkPolicy allows only PostgreSQL, those three Services and
the dedicated external-authority egress gateway.

Policy activation has no production allowlist fallback. `AGENT_TRUST_PEP_ALLOWED_POLICY_BUNDLES`
must be absent. PEP mounts `agenttrust.policy-bundle-keyring.v1` plus every referenced
Ed25519 verifying-key file; the active key ID must equal
`policy_admin.bundle_signing_key_id`. Policy Administration calls exactly
`POST https://agenttrust-pep/v1/policies/activations` with its outbound mTLS SAN and a
dedicated `pep:policy-activate` token, then verifies the PEP acknowledgement with the
separate mounted PEP activation key. The `pdp_activation` binding calls exactly the
reviewed PDP activation route with scope `pdp:policy-activate`, key usage
`PDP_POLICY_ACTIVATION_ACK`, its own token and verification key. Neither raw token may be
reused across SAN, tenant, route or scope. PEP readiness covers PostgreSQL, bundle keyring
and the PDP activation client; Policy readiness covers PostgreSQL and the PEP activation
client/key.

## Policy, incident/release and pack authority routes

All three authorities expose TLS data on `8090` and node-only plaintext management
readiness on `9101`, run three replicas, require a three-zone spread plus hostname
anti-affinity, and have `minAvailable: 2`. Enterprise BFF has read and mutation tokens;
Tool Proxy obtains each execute bearer only from the Vault lease path/field named by its
signed target profile; there are no ambient `*_EXECUTE_TOKEN_FILE` variables or static
execute-token mounts. Their outbound mTLS SANs have separate Orchestrator bindings and raw
tokens.

The signed `agenttrust.tool-proxy-target-profiles.v1` inventory must contain only the
following in-cluster control targets: `policy-administration-executor` /
`policy-administration-authority` / `agenttrust-policy-admin` /
`POST /v1/policies/executions`; `incident-release-executor` /
`incident-release-authority` / `agenttrust-incident-release` /
`POST /v1/incidents/executions`; and `pack-marketplace-executor` /
`pack-marketplace-authority` / `agenttrust-pack-marketplace` /
`POST /v1/packs/executions`. Each credential profile must equal the matching Authority
`*_EXECUTOR_CREDENTIAL_PROFILE`. Every allowed lowercase operation ID maps to that
profile's one fixed POST route; no generic `.svc.cluster.local` target or alternate method,
host or path is permitted. Each leased token remains uniquely bound by the receiving
Authority to Tool Proxy's outbound SAN, tenant, subject and execute scope.

Incident/Release accepts detector-only `POST /v1/incidents/detections`, human
`POST /v1/incidents/actions`, Tool Proxy `POST /v1/incidents/executions`, and query-only
`GET /v1/authoritative/incidents[/{incident_id}]`. Its fourteen command operations are
`TRIAGE`, `CONTAIN`, `INVESTIGATE`, `PRESERVE_EVIDENCE`, `PLAN_REPLAY`,
`COMPLETE_REPLAY`, `PUBLISH_ROOT_CAUSE`, `BEGIN_REMEDIATION`,
`TRIGGER_RECERTIFICATION`, `EVALUATE_RELEASE`, `START_CANARY`, `RECORD_CANARY`,
`ROLLBACK_RELEASE` and `CLOSE`. Containment and replay use distinct reviewed HTTPS roots,
distinct tokens and the authority outbound identity. A release certificate remains an
engine certificate and does not assert production closure.

Pack Marketplace accepts `POST /v1/packs/actions`, Tool Proxy-only
`POST /v1/packs/executions` and `GET /v1/authoritative/packs`. The complete command set is
`ONBOARD_PUBLISHER`, `VERIFY_PUBLISHER_KEY`, `SET_PUBLISHER_TRUST`,
`CONFIGURE_TENANT_CATALOG`, `SUBMIT_RELEASE`, `REVIEW_RELEASE`,
`REQUEST_INSTALLATION`, `APPROVE_INSTALLATION`, `INSTALL`, `ACTIVATE`, `PLAN_UPGRADE`,
`RECORD_CANARY`, `UPGRADE`, `ROLLBACK`, `DEACTIVATE` and `REVOKE_RELEASE`. Its release
gate keyring must verify the Incident/Release certificate and production activation still
requires the certificate plus policy/approval/tool/evidence chain. Supply-chain egress is
limited to the reviewed external-service gateway CIDR.

## Tool Proxy and Evidence

Tool Proxy uses Pod UID as `AGENT_TRUST_TOOL_PROXY_INSTANCE_ID`. Its outbound SAN is
accepted by Registry for `registry:read` and Identity for `credentials:consume`, using
distinct tokens. Verification usages include `PEP_EXECUTION_AUTHORIZATION`,
`WORKLOAD_CREDENTIAL_BINDING`, `WORKLOAD_CREDENTIAL_CONSUMPTION`, `REGISTRY_SNAPSHOT` and
`TOOL_PROXY_TARGET_PROFILES`. Egress is limited to database, Registry, Identity, Vault
broker and reviewed target CIDRs.

Evidence uses its own signing key, exact client/token bindings and WORM mTLS. Execution
gets `evidence:append`; BFF/artifact/package/evaluator callers get only their route scope.
Lifecycle publishers get a physically distinct `evidence:event` token. State-owning authorities
get a distinct `evidence:authority-event` token, and every submitted
event's `source_service` must equal the caller certificate's single accepted SAN. The
binding `subject` must equal that same SAN; `actor_subject` remains the governed human or
workload and, for execution evidence, is independently checked against the authoritative
orchestrator ingress row. The
`evidence-verifying-keyring.json` mount retains the active verification key and every
historical key still referenced by persisted evidence; it is never inferred from the active
private key. The Evidence database role has read-only access to `orchestrator_tasks`,
`executions` and `pep_execution_authorizations`, plus `SELECT,INSERT` on
`evidence_event_requests` and `authority_evidence_event_requests`; it also has read-only access to `orchestrator_ingress_actions`
for actor binding and receives no mutation privilege on those authority tables.
Readiness requires PostgreSQL, execution/PEP read bindings and
`agenttrust.worm-readiness.v1` with object lock. Ingress is limited to the explicitly
allowlisted production callers for those route scopes; egress is only PostgreSQL and locked
storage.

## Audit retention and compliance evidence

Audit Retention uses a dedicated signing key, historical verification keyring, exact
SAN/tenant/scope/token-digest bindings, PostgreSQL FORCE RLS and separate mTLS clients for
locked WORM storage and the retention-deletion gateway. Query, export, policy, Legal Hold,
Control Catalog, Evidence Graph and deletion operations are bounded and durably replayed;
queries and exports themselves append immutable audit evidence. Legal Hold release is a
separate scope and may update only `released_by`, `released_at` and `release_reason`.
The BFF's authoritative read uses service scope `audit:authoritative-query` plus a
request-bound human assertion whose scope remains `audit:query`; the service persists JTI
use in `audit_human_assertion_uses`. Deletion succeeds only with a versioned provider proof and never claims that an external
backup was removed without that proof. Readiness requires PostgreSQL, the signing/keyring
posture, loaded human-principal verification keys, exact `agenttrust.worm-readiness.v1`, and
`agenttrust.retention-deletion-readiness.v1` with versioned deletion proof support.

## Readiness and network policy

Rust authorities expose TLS 1.3/mTLS on data and plaintext `/ready` only on management.
Management Services are absent and kubelet ingress is node-CIDR-only. BFF authority
readiness uses mTLS without bearer and accepts only the schema-specific exact field set;
Agent Registry additionally reports database/lifecycle readiness, Evidence reports
database/WORM readiness, and Audit reports database/WORM/deletion/human-key readiness.
Configure the PEP and all authority
readiness schemas explicitly; HTTP 200, `UP`, `READY` or a global token is not evidence.

`network.dns_cidr` is one resolver address (`/32` or `/128`). The other nine CIDRs are
non-overlapping: node, database, Temporal, Vault, IAM, ingress, external egress, tool
targets and evidence storage. Default deny is supplemented only by exact peers and ports.
Verify rendered policy with the installed CNI because Service DNAT ordering differs.

## Build, render and apply

Build the exact thirty-one release subjects using `scripts/build-production-image.py`: `runtime`,
`orchestrator`, `transition`, `execution`, `registry`, `agent-registry`, `approval`, `pep`,
`policy-admin`, `incident-release`, `pack-marketplace`, `identity`, `tool-proxy`,
`evidence`, `audit`, `enterprise-control`,
`enterprise-authority`, `model-gateway`, `data-governance`, `context-governance`,
`runtime-anomaly`, `security-evaluation`, `pack-supply-chain`, `domain-runtime`,
`platform-sre`, `console`, `migrations`, `release-admission`, `sandbox-worker`, and the
AgentTrust-owned `envoy` and `utility` wrapper subjects. Every base is digest-pinned; the
candidate workflow requires SBOM and provenance attestations for every subject. The
`sandbox-worker` artifact is installed as a native binary on a dedicated Linux host after
its image attestation and extracted binary digest are verified; do not run it as a normal
Deployment or mount host `runsc` into a Pod.

Prepare `agenttrust.production-stack-values.v2` values and a runtime config based on
`config/production-runtime.example.json`. Rendering rejects placeholders, mutable images,
unsafe endpoints, duplicate roles, identity mismatches, overlapping CIDRs and non-internal
deployed authorities. The renderer requires the Enterprise BFF SAN to be accepted by the
in-stack PEP and requires the BFF human-assertion audience and authentication-age bound to
exactly match the PEP trust configuration.

```sh
output=$(mktemp /tmp/agenttrust-production.XXXXXX.yaml)
rm "$output"
python3 scripts/render-production-stack.py \
  --template /absolute/repository/deploy/kubernetes/production-stack.yaml.tmpl \
  --values /protected/release/production-stack-values.json \
  --runtime-config /protected/release/production-runtime.json \
  --git-provenance /protected/release/signed-git-provenance.json \
  --git-provenance-keyring /protected/release/git-provenance-keyring.json \
  --release-binding /protected/release/signed-release-binding.json \
  --release-binding-keyring /protected/release/release-binding-keyring.json \
  --activation /protected/release/activation.json \
  --closure-report /protected/release/closure-report.json \
  --production-certificate /protected/release/production-certificate.json \
  --closure-public-key /protected/trust/closure-public-key.json \
  --revocation-registry /protected/release/revocation-registry.json \
  --revocation-public-key /protected/trust/revocation-public-key.json \
  --output "$output"
kubectl apply --dry-run=server -f "$output"
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=prerequisite
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=admission
kubectl wait --for=condition=complete --timeout=10m job \
  --selector agenttrust.io/apply-phase=admission
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=migration
kubectl wait --for=condition=complete --timeout=30m job \
  --selector agenttrust.io/apply-phase=migration
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=workload
# Wait for every rendered Deployment before exposing either ingress.
kubectl rollout status deployment \
  --selector app.kubernetes.io/part-of=agenttrust-control-plane --timeout=10m
kubectl apply -f "$output" --selector agenttrust.io/apply-phase=traffic
```

The renderer creates a new absolute output file at `0600` and refuses overwrite. Do not
commit rendered topology. Server-side dry-run is required for installed CRDs/admission.
Run `run-production-migrations --check` before admitting writers.

Check all twenty-seven Deployments:

```sh
for deployment in \
  agenttrust-production-runtime agenttrust-orchestrator-api agenttrust-temporal-worker \
  agenttrust-transition agenttrust-execution agenttrust-registry agenttrust-approval \
  agenttrust-pep agenttrust-identity agenttrust-tool-proxy agenttrust-evidence \
  agenttrust-audit agenttrust-agent-registry agenttrust-policy-admin \
  agenttrust-incident-release agenttrust-pack-marketplace agenttrust-enterprise-authority \
  agenttrust-model-gateway agenttrust-data-governance agenttrust-context-governance \
  agenttrust-runtime-anomaly agenttrust-security-evaluation agenttrust-pack-supply-chain \
  agenttrust-domain-runtime agenttrust-platform-sre agenttrust-enterprise-control \
  agenttrust-console
do
  kubectl rollout status "deployment/$deployment" --timeout=10m
done
```

Migrations are forward-only. Drain legacy writers, settle transactions/outboxes and
verify a recovery checkpoint before an upgrade. Keep writers drained until check mode
passes. Never guess tenant backfills, disable RLS or mix old/new writers.

## Verification and rollback

Verify digests, zones, PDBs, secret modes, SANs, readiness schemas and CNI flows. Exercise
positive and negative calls for every scope: token/SAN/tenant mismatch, cross-scope reuse,
expired keys, idempotency conflict, Approval replay, PEP token separation, Tool Proxy
unknown outcome and WORM failure. Trace one accepted action through Canonical Action IR,
PEP, ledger, tool execution and signed evidence. Task acceptance and process execution
success remain separate states.

Application rollback uses a known schema-compatible immutable digest. Never reverse the
database migration. Do not bypass readiness. Real multi-zone failover, DR, sustained load,
model/DLP/data-residency acceptance, industrial endpoints and supervised physical writes,
customer sign-off, independent certification and production certificate issuance remain
external evidence gates.
