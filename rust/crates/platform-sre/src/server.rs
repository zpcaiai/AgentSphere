//! TLS 1.3/mTLS Platform SRE data plane and loopback management readiness plane.

use crate::authority::*;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ActionHash, ArtifactRef,
    AuthorityEvidenceControlBinding, AuthorityEvidenceEventRequest, AuthorityEvidenceSourceKind,
    EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft, EvidenceEventType, ExecutionId,
    HumanPrincipalKeyring, IdempotencyKey, SignedAuthorityEvidenceReceipt, TaskId, TenantId,
    human_principal_request_digest,
};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;

pub const SRE_MUTATE_SCOPE: &str = "sre:mutate";
pub const SRE_EXECUTE_SCOPE: &str = "sre:execute";
pub const SRE_READ_SCOPE: &str = "sre:read";

#[derive(Debug, Clone)]
pub struct SreServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub ingress_subject: String,
    pub executor_subject: String,
    pub query_subject: String,
    pub maximum_authentication_age_seconds: i64,
}

#[derive(Debug, Clone)]
struct SrePeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    ingress: SreIngressAuthority,
    executor: SreExecutor,
    tokens: Arc<SreTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    ingress_subject: String,
    executor_subject: String,
    query_subject: String,
    maximum_authentication_age_seconds: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBindingDocument {
    schema_version: String,
    bindings: Vec<TokenBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBinding {
    client_identity: String,
    tenant_id: String,
    subject: String,
    scope: String,
    token_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenAuthorization {
    client_identity: String,
    tenant_id: String,
    subject: String,
    scope: String,
    token_sha256: String,
}

pub struct SreTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl SreTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, SreAuthorityError> {
        validate_identities(allowed_identities)?;
        if !path.is_absolute() {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        let raw = std::fs::read(path).map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument =
            strict_json(&raw).map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.sre-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    SRE_MUTATE_SCOPE | SRE_EXECUTE_SCOPE | SRE_READ_SCOPE
                )
                || !identifier(&binding.subject, 256)
                || !digest(&binding.token_sha256)
                || !uuid::Uuid::parse_str(&binding.tenant_id)
                    .is_ok_and(|value| value.to_string() == binding.tenant_id)
                || !credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(SreAuthorityError::ConfigurationInvalid);
            }
        }
        let tenants = bindings
            .iter()
            .map(|binding| binding.tenant_id.clone())
            .collect::<BTreeSet<_>>();
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) || tenants.iter().any(|tenant| {
            [SRE_MUTATE_SCOPE, SRE_EXECUTE_SCOPE, SRE_READ_SCOPE]
                .iter()
                .any(|scope| {
                    !bindings
                        .iter()
                        .any(|binding| &binding.tenant_id == tenant && &binding.scope == scope)
                })
        }) {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, SreAuthorityError> {
        let authorization = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=8_192).contains(&value.len())
                    && !value.bytes().any(|byte| byte.is_ascii_whitespace())
            })
            .ok_or(SreAuthorityError::PrincipalDenied)?;
        let supplied = hex::encode(Sha256::digest(authorization.as_bytes()));
        let matches = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.client_identity == peer
                    && binding.tenant_id == tenant
                    && binding.scope == scope
                    && constant_time_equal(&supplied, &binding.token_sha256)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(SreAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn router(
    ingress: SreIngressAuthority,
    executor: SreExecutor,
    tokens: Arc<SreTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    ingress_subject: String,
    executor_subject: String,
    query_subject: String,
    maximum_authentication_age_seconds: i64,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/sre/actions", post(submit_action))
        .route("/v1/sre/executions", post(execute_mutation))
        .route(
            "/v1/authoritative/sre/resources",
            get(authoritative_resources),
        )
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(45),
        ))
        .with_state(ServerState {
            ingress,
            executor,
            tokens,
            principal_keyring,
            ingress_subject,
            executor_subject,
            query_subject,
            maximum_authentication_age_seconds,
        })
}

async fn data_ready(State(state): State<ServerState>) -> Result<Json<Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn submit_action(
    State(state): State<ServerState>,
    Extension(SrePeerIdentity(peer)): Extension<SrePeerIdentity>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<(StatusCode, Json<SreActionReceipt>), ApiError> {
    require_json_content_type(&headers)?;
    let body: SreCommandRequest = strict_json(&bytes)?;
    let tenant = exact_tenant(&headers, body.tenant_id.to_string())?;
    let service_subject = state
        .tokens
        .authorize(&peer, &tenant.0, SRE_MUTATE_SCOPE, &headers)?;
    if service_subject != state.ingress_subject {
        return Err(SreAuthorityError::PrincipalDenied.into());
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = human_principal_request_digest(
        "POST",
        "/v1/sre/actions",
        &tenant,
        &peer,
        &service_subject,
        SRE_MUTATE_SCOPE,
        idempotency_key,
        &body,
    )
    .map_err(|_| SreAuthorityError::RequestInvalid)?;
    let assertion = single_header(&headers, "x-agenttrust-human-assertion")
        .ok_or(SreAuthorityError::PrincipalDenied)?;
    let principal = state
        .principal_keyring
        .verify_encoded(
            assertion,
            &tenant,
            &peer,
            &service_subject,
            SRE_MUTATE_SCOPE,
            &request_digest,
            true,
            state.maximum_authentication_age_seconds,
            Utc::now(),
        )
        .map_err(|_| SreAuthorityError::PrincipalDenied)?;
    let receipt = state
        .ingress
        .submit(&principal, body, &request_digest, idempotency_key)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_mutation(
    State(state): State<ServerState>,
    Extension(SrePeerIdentity(peer)): Extension<SrePeerIdentity>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<SreMutationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let body: SreExecutorRequest = strict_json(&bytes)?;
    let tenant = exact_tenant_from_header(&headers)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, SRE_EXECUTE_SCOPE, &headers)?;
    if subject != state.executor_subject {
        return Err(SreAuthorityError::PrincipalDenied.into());
    }
    let binding = SreExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.to_string(),
        ledger_execution_id: parse_uuid_header(&headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: parse_uuid_header(&headers, "x-agenttrust-ledger-entry-id")?,
        ledger_event_digest: required_header(&headers, "x-agenttrust-ledger-entry-digest")?
            .to_string(),
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.to_string(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?
            .parse()
            .map_err(|_| SreAuthorityError::RequestInvalid)?,
        idempotency_key: required_idempotency_key(&headers)?.to_string(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.to_string(),
        policy_decision_id: required_header(&headers, "x-agenttrust-policy-decision-id")?
            .to_string(),
        policy_decision_digest: required_header(&headers, "x-agenttrust-policy-decision-digest")?
            .to_string(),
        authorization_evidence_ref: required_header(
            &headers,
            "x-agenttrust-authorization-evidence-ref",
        )?
        .to_string(),
        authorization_evidence_digest: required_header(
            &headers,
            "x-agenttrust-authorization-evidence-digest",
        )?
        .to_string(),
    };
    Ok(Json(state.executor.execute(binding, body).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcePageQuery {
    after: Option<String>,
    limit: Option<i64>,
}

async fn authoritative_resources(
    State(state): State<ServerState>,
    Extension(SrePeerIdentity(peer)): Extension<SrePeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<ResourcePageQuery>,
) -> Result<Json<SreResourcePage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, SRE_READ_SCOPE, &headers)?;
    if subject != state.query_subject {
        return Err(SreAuthorityError::PrincipalDenied.into());
    }
    Ok(Json(
        state
            .ingress
            .authoritative_page(&tenant, query.after.as_deref(), query.limit.unwrap_or(100))
            .await?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SreAdapterKind {
    TopologyProbe,
    Backup,
    Recovery,
    DisasterRecovery,
    Chaos,
    Load,
    Upgrade,
    Evidence,
}

#[derive(Debug, Clone)]
pub struct SreAdapterTarget {
    pub endpoint: url::Url,
    pub token_file: PathBuf,
}

#[derive(Clone)]
pub struct HttpSreEffectPort {
    client: reqwest::Client,
    targets: BTreeMap<SreAdapterKind, SreAdapterTarget>,
    evidence_client_identity: String,
    evidence_keyring: SreEvidenceKeyring,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyringDocument {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SreEvidenceKeyring {
    keys: Arc<BTreeMap<String, VerifyingKey>>,
}

impl SreEvidenceKeyring {
    pub fn from_json(raw: &[u8]) -> Result<Self, SreAuthorityError> {
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        let document: EvidenceKeyringDocument =
            strict_json(raw).map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.ed25519-public-keyring.v1"
            || document.keys.is_empty()
            || document.keys.len() > 1_024
        {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for (key_id, encoded) in document.keys {
            if !identifier(&key_id, 128) {
                return Err(SreAuthorityError::ConfigurationInvalid);
            }
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SreAuthorityError::ConfigurationInvalid)?
                .try_into()
                .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
            if keys.insert(key_id, key).is_some() {
                return Err(SreAuthorityError::ConfigurationInvalid);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }
}

impl HttpSreEffectPort {
    fn required_adapter_kinds() -> BTreeSet<SreAdapterKind> {
        BTreeSet::from([
            SreAdapterKind::TopologyProbe,
            SreAdapterKind::Backup,
            SreAdapterKind::Recovery,
            SreAdapterKind::DisasterRecovery,
            SreAdapterKind::Chaos,
            SreAdapterKind::Load,
            SreAdapterKind::Upgrade,
            SreAdapterKind::Evidence,
        ])
    }

    fn adapter_route(operation: SreOperation) -> Option<(SreAdapterKind, &'static str)> {
        match operation {
            SreOperation::ConfigureSlo
            | SreOperation::RecordSli
            | SreOperation::UpdateBurnAlert
            | SreOperation::LinkIncident
            | SreOperation::RegisterTopology
            | SreOperation::PlanDr
            | SreOperation::PlanChaos
            | SreOperation::PlanLoad
            | SreOperation::PlanUpgrade
            | SreOperation::RecordCanary
            | SreOperation::RecordCostCapacity
            | SreOperation::RecordObservability => None,
            SreOperation::RecordZoneHealth => {
                Some((SreAdapterKind::TopologyProbe, "v1/topology/zone-health"))
            }
            SreOperation::CreateBackup => Some((SreAdapterKind::Backup, "v1/backups")),
            SreOperation::VerifyRestore => Some((SreAdapterKind::Recovery, "v1/restores/verify")),
            SreOperation::Failover => Some((SreAdapterKind::DisasterRecovery, "v1/dr/failover")),
            SreOperation::Failback => Some((SreAdapterKind::DisasterRecovery, "v1/dr/failback")),
            SreOperation::ExecuteChaos => Some((SreAdapterKind::Chaos, "v1/chaos/execute")),
            SreOperation::ExecuteLoad => Some((SreAdapterKind::Load, "v1/load/execute")),
            SreOperation::RollbackUpgrade => {
                Some((SreAdapterKind::Upgrade, "v1/upgrades/rollback"))
            }
        }
    }

    pub fn new(
        client: reqwest::Client,
        targets: BTreeMap<SreAdapterKind, SreAdapterTarget>,
        evidence_client_identity: String,
        evidence_keyring: SreEvidenceKeyring,
    ) -> Result<Self, SreAuthorityError> {
        let required = Self::required_adapter_kinds();
        if targets.keys().copied().collect::<BTreeSet<_>>() != required {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        let mut endpoints = BTreeSet::new();
        let mut token_digests = BTreeSet::new();
        for target in targets.values() {
            validate_https_root(&target.endpoint)?;
            if !target.token_file.is_absolute()
                || !endpoints.insert(target.endpoint.as_str().to_string())
                || !token_digests.insert(hex::encode(Sha256::digest(
                    read_token(&target.token_file)?.as_bytes(),
                )))
            {
                return Err(SreAuthorityError::ConfigurationInvalid);
            }
        }
        if evidence_client_identity.len() > 512
            || !(evidence_client_identity.starts_with("DNS:")
                || evidence_client_identity.starts_with("URI:"))
            || evidence_client_identity.contains(char::is_whitespace)
        {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            client,
            targets,
            evidence_client_identity,
            evidence_keyring,
        })
    }

    fn target(
        &self,
        operation: SreOperation,
    ) -> Result<Option<(&SreAdapterTarget, &'static str)>, SreAuthorityError> {
        let selected = Self::adapter_route(operation);
        selected
            .map(|(kind, path)| {
                self.targets
                    .get(&kind)
                    .map(|target| (target, path))
                    .ok_or(SreAuthorityError::ConfigurationInvalid)
            })
            .transpose()
    }

    async fn invoke(
        &self,
        target: &SreAdapterTarget,
        path: &str,
        binding: &SreExecutionBinding,
        request: &SreExecutorRequest,
    ) -> Result<SreExternalReceipt, SreAuthorityError> {
        let response = self
            .client
            .post(
                target
                    .endpoint
                    .join(path)
                    .map_err(|_| SreAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&target.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &binding.tenant_id.0)
            .header("Idempotency-Key", &binding.idempotency_key)
            .header("X-AgentTrust-Action-Hash", &binding.action_hash)
            .header(
                "X-AgentTrust-Ledger-Execution-Id",
                binding.ledger_execution_id.to_string(),
            )
            .header(
                "X-AgentTrust-Ledger-Entry-Id",
                binding.ledger_event_id.to_string(),
            )
            .header(
                "X-AgentTrust-Ledger-Entry-Digest",
                &binding.ledger_event_digest,
            )
            .header("X-AgentTrust-Fence-Digest", &binding.fence_digest)
            .header(
                "X-AgentTrust-Policy-Decision-Id",
                &binding.policy_decision_id,
            )
            .header(
                "X-AgentTrust-Policy-Decision-Digest",
                &binding.policy_decision_digest,
            )
            .header(
                "X-AgentTrust-Authorization-Evidence-Ref",
                &binding.authorization_evidence_ref,
            )
            .header(
                "X-AgentTrust-Authorization-Evidence-Digest",
                &binding.authorization_evidence_digest,
            )
            .header("X-AgentTrust-Trace-Id", &binding.trace_id)
            .json(request)
            .send()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(SreAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 1_048_576)
            || !exact_content_type(response.headers(), "application/json")
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 1_048_576)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        strict_json(&bytes).map_err(|_| SreAuthorityError::DependencyUnavailable)
    }
}

#[async_trait::async_trait]
impl SreEffectPort for HttpSreEffectPort {
    async fn ready(&self) -> bool {
        for (kind, target) in &self.targets {
            let schema = if *kind == SreAdapterKind::Evidence {
                "agenttrust.evidence-readiness.v1"
            } else {
                "agenttrust.sre-adapter-readiness.v1"
            };
            if !dependency_ready(&self.client, &target.endpoint, &target.token_file, schema).await {
                return false;
            }
        }
        true
    }

    async fn execute(
        &self,
        binding: &SreExecutionBinding,
        request: &SreExecutorRequest,
    ) -> Result<Option<SreExternalReceipt>, SreAuthorityError> {
        let Some((target, path)) = self.target(request.command.operation)? else {
            if request.command.operation.external_effect() {
                return Err(SreAuthorityError::ConfigurationInvalid);
            }
            return Ok(None);
        };
        self.invoke(target, path, binding, request).await.map(Some)
    }

    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: uuid::Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<SreEvidenceDeliveryReceipt, SreAuthorityError> {
        if !digest(payload_digest)
            || evidence_canonical_digest(payload)? != payload_digest
            || !(1..=128).contains(&idempotency_key.len())
        {
            return Err(SreAuthorityError::RequestInvalid);
        }
        let target = self
            .targets
            .get(&SreAdapterKind::Evidence)
            .ok_or(SreAuthorityError::ConfigurationInvalid)?;
        let task_id = evidence_uuid_field(payload, "task_id")?;
        let occurred_at = evidence_time_field(payload, "recorded_at")?;
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId(task_id.to_string()),
            authority_event_id: event_id.to_string(),
            idempotency_key: IdempotencyKey(idempotency_key.into()),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(AuthorityEvidenceControlBinding {
                action_hash: ActionHash(evidence_digest_field(payload, "action_hash")?),
                ledger_execution_id: ExecutionId(
                    evidence_uuid_field(payload, "ledger_execution_id")?.to_string(),
                ),
                ledger_event_id: evidence_uuid_field(payload, "ledger_event_id")?.to_string(),
                ledger_event_digest: evidence_digest_field(payload, "ledger_event_digest")?,
                fence_digest: evidence_digest_field(payload, "fence_digest")?,
                policy_decision_id: evidence_string_field(payload, "policy_decision_id", 256)?
                    .into(),
                policy_decision_digest: evidence_digest_field(payload, "policy_decision_digest")?,
                authorization_evidence_ref: evidence_string_field(
                    payload,
                    "authorization_evidence_ref",
                    2_048,
                )?
                .into(),
                authorization_evidence_digest: evidence_digest_field(
                    payload,
                    "authorization_evidence_digest",
                )?,
            }),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                task_id: TaskId(task_id.to_string()),
                event_type: EvidenceEventType::StateTransition,
                actor_subject: evidence_string_field(payload, "actor_subject", 512)?.into(),
                source_service: self.evidence_client_identity.clone(),
                trace_id: evidence_string_field(payload, "trace_id", 256)?.into(),
                span_id: event_id.to_string(),
                payload_hash: payload_digest.into(),
                safe_summary: "Platform SRE governed action persisted".into(),
                artifact_refs: Vec::<ArtifactRef>::new(),
                occurred_at,
            },
            requested_at: occurred_at,
        };
        request
            .request_digest()
            .map_err(|_| SreAuthorityError::RequestInvalid)?;
        let response = self
            .client
            .post(
                target
                    .endpoint
                    .join("v1/evidence/authority-events")
                    .map_err(|_| SreAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&target.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", idempotency_key)
            .header("X-AgentTrust-Authority-Event-Id", event_id.to_string())
            .header("X-AgentTrust-Payload-Digest", payload_digest)
            .json(&request)
            .send()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
            || !exact_content_type(response.headers(), "application/json")
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let receipt: SignedAuthorityEvidenceReceipt =
            strict_json(&bytes).map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let key = self
            .evidence_keyring
            .key(&receipt.key_id)
            .ok_or(SreAuthorityError::DependencyUnavailable)?;
        let verification = receipt.verify(key, Utc::now());
        verification.map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if receipt.tenant_id != request.tenant_id
            || receipt.task_id != request.task_id
            || receipt.authority_event_id != request.authority_event_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.source_kind != request.source_kind
            || receipt.payload_digest != payload_digest
            || receipt.event.draft != request.event
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        Ok(SreEvidenceDeliveryReceipt {
            schema_version: "agenttrust.sre-evidence-delivery-receipt.v1".into(),
            evidence_ref: receipt.evidence_ref,
            evidence_digest: receipt.evidence_digest,
            payload_digest: receipt.payload_digest,
            idempotency_key: receipt.idempotency_key.0,
        })
    }
}

fn evidence_string_field<'a>(
    payload: &'a Value,
    name: &str,
    maximum: usize,
) -> Result<&'a str, SreAuthorityError> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn evidence_uuid_field(payload: &Value, name: &str) -> Result<uuid::Uuid, SreAuthorityError> {
    let value = evidence_string_field(payload, name, 36)?;
    uuid::Uuid::parse_str(value)
        .ok()
        .filter(|parsed| !parsed.is_nil() && parsed.to_string() == value)
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn evidence_digest_field(payload: &Value, name: &str) -> Result<String, SreAuthorityError> {
    let value = evidence_string_field(payload, name, 64)?;
    if !digest(value) {
        return Err(SreAuthorityError::RequestInvalid);
    }
    Ok(value.into())
}

fn evidence_time_field(payload: &Value, name: &str) -> Result<DateTime<Utc>, SreAuthorityError> {
    DateTime::parse_from_rfc3339(evidence_string_field(payload, name, 64)?)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| SreAuthorityError::RequestInvalid)
}

fn evidence_canonical_digest(value: &Value) -> Result<String, SreAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| SreAuthorityError::RequestInvalid)
}

#[derive(Clone)]
pub struct HttpSreOrchestrator {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
}

impl HttpSreOrchestrator {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
    ) -> Result<Self, SreAuthorityError> {
        validate_https_root(&endpoint)?;
        if !token_file.is_absolute() {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        read_token(&token_file)?;
        Ok(Self {
            client,
            endpoint,
            token_file,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchestratorAcceptance {
    schema_version: String,
    action_id: String,
    task_id: String,
    accepted: bool,
    start_requested: bool,
    execution_pending: bool,
    ingress_digest: String,
    evidence_ref: String,
    evidence_digest: String,
}

#[async_trait::async_trait]
impl SreOrchestratorPort for HttpSreOrchestrator {
    async fn ready(&self) -> bool {
        dependency_ready(
            &self.client,
            &self.endpoint,
            &self.token_file,
            "agenttrust.orchestrator-readiness.v1",
        )
        .await
    }

    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &agent_trust_gateway::InboundEnvelope,
    ) -> Result<SreActionReceipt, SreAuthorityError> {
        let response = self
            .client
            .post(
                self.endpoint
                    .join("v1/actions")
                    .map_err(|_| SreAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .json(envelope)
            .send()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(SreAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
            || !exact_content_type(response.headers(), "application/json")
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let accepted: OrchestratorAcceptance =
            strict_json(&bytes).map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if accepted.schema_version != "agenttrust.action-acceptance.v1"
            || !accepted.accepted
            || !accepted.start_requested
            || !accepted.execution_pending
            || !canonical_uuid(&accepted.action_id)
            || !canonical_uuid(&accepted.task_id)
            || !digest(&accepted.ingress_digest)
            || !evidence_reference(&accepted.evidence_ref)
            || !digest(&accepted.evidence_digest)
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        Ok(SreActionReceipt {
            schema_version: SRE_ACTION_RECEIPT_SCHEMA.into(),
            action_id: accepted.action_id,
            task_id: accepted.task_id,
            accepted: true,
            execution_pending: true,
            ingress_digest: accepted.ingress_digest,
            ledger_evidence_ref: accepted.evidence_ref,
            ledger_evidence_digest: accepted.evidence_digest,
        })
    }
}

pub async fn serve(
    config: SreServerConfig,
    application: Router,
    readiness_ingress: SreIngressAuthority,
    readiness_executor: SreExecutor,
) -> Result<(), SreAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !identifier(&config.ingress_subject, 256)
        || !identifier(&config.executor_subject, 256)
        || !identifier(&config.query_subject, 256)
        || !(60..=86_400).contains(&config.maximum_authentication_age_seconds)
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.allowed_client_identities),
    };
    let management = Router::new()
        .route("/live", get(management_health))
        .route("/ready", get(management_ready))
        .route("/healthz", get(management_health))
        .route("/readyz", get(management_ready))
        .with_state((readiness_ingress, readiness_executor));
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn management_health() -> Json<Value> {
    Json(serde_json::json!({
        "schema_version": "agenttrust.sre-liveness.v1",
        "live": true
    }))
}

async fn management_ready(
    State((ingress, executor)): State<(SreIngressAuthority, SreExecutor)>,
) -> Result<Json<Value>, ApiError> {
    readiness(&ingress, &executor).await
}

async fn readiness(
    ingress: &SreIngressAuthority,
    executor: &SreExecutor,
) -> Result<Json<Value>, ApiError> {
    let ingress_ready = ingress.ready().await;
    let executor_ready = executor.ready().await;
    if !ingress_ready || !executor_ready {
        return Err(SreAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(serde_json::json!({
        "schema_version": SRE_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "orchestrator_ready": true,
        "effect_adapters_ready": true,
        "production_certification": false
    })))
}

#[derive(Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, SrePeerIdentity>;
    type Future =
        Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        let allowed = self.allowed_identities.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            let certificates = stream.get_ref().1.peer_certificates().ok_or_else(|| {
                IoError::new(ErrorKind::PermissionDenied, "client certificate missing")
            })?;
            let identity = certificates
                .first()
                .and_then(|certificate| exact_certificate_identity(certificate.as_ref(), &allowed))
                .ok_or_else(|| IoError::new(ErrorKind::PermissionDenied, "client SAN denied"))?;
            Ok((stream, Extension(SrePeerIdentity(identity)).layer(service)))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, SreAuthorityError> {
    let mut ca_reader =
        BufReader::new(File::open(ca_file).map_err(|_| SreAuthorityError::ConfigurationInvalid)?);
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| SreAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    if certificates.is_empty() || certificates.len() > 4 {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| SreAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| SreAuthorityError::ConfigurationInvalid)?
        .ok_or(SreAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| SreAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(SreAuthorityError);

impl From<SreAuthorityError> for ApiError {
    fn from(value: SreAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            SreAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            SreAuthorityError::RequestInvalid => StatusCode::BAD_REQUEST,
            SreAuthorityError::NotFound => StatusCode::NOT_FOUND,
            SreAuthorityError::IdempotencyConflict
            | SreAuthorityError::StateConflict
            | SreAuthorityError::ExternalReceiptInvalid
            | SreAuthorityError::CertificationBoundary => StatusCode::CONFLICT,
            SreAuthorityError::DependencyUnavailable
            | SreAuthorityError::OutcomeUnknown
            | SreAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.sre-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn exact_tenant(headers: &HeaderMap, body_tenant: String) -> Result<TenantId, SreAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant {
        return Err(SreAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, SreAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| SreAuthorityError::PrincipalDenied)?;
    if parsed.to_string() != value {
        return Err(SreAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.to_string()))
}

fn parse_uuid_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<uuid::Uuid, SreAuthorityError> {
    let raw = required_header(headers, name)?;
    uuid::Uuid::parse_str(raw)
        .ok()
        .filter(|value| value.to_string() == raw)
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), SreAuthorityError> {
    if single_header(headers, "content-type") != Some("application/json") {
        return Err(SreAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, SreAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !(16..=128).contains(&value.len())
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte)))
    {
        return Err(SreAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, SreAuthorityError> {
    single_header(headers, name).ok_or(SreAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn exact_content_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn strict_json<T: DeserializeOwned>(raw: &[u8]) -> Result<T, SreAuthorityError> {
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err(SreAuthorityError::RequestInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| SreAuthorityError::RequestInvalid)?;
    deserializer
        .end()
        .map_err(|_| SreAuthorityError::RequestInvalid)?;
    serde_json::from_value(value.0).map_err(|_| SreAuthorityError::RequestInvalid)
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate object members")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > 65_536 {
            return Err(de::Error::custom("JSON string capacity exceeded"));
        }
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
            if values.len() > 10_000 {
                return Err(de::Error::custom("JSON array capacity exceeded"));
            }
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            let value = object.next_value::<StrictJsonValue>()?;
            values.insert(key, value.0);
            if values.len() > 256 {
                return Err(de::Error::custom("JSON object capacity exceeded"));
            }
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

async fn dependency_ready(
    client: &reqwest::Client,
    endpoint: &url::Url,
    token_file: &Path,
    expected_schema: &str,
) -> bool {
    let Ok(token) = read_token(token_file) else {
        return false;
    };
    let Ok(url) = endpoint.join("ready") else {
        return false;
    };
    let Ok(response) = client.get(url).bearer_auth(token).send().await else {
        return false;
    };
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > 16_384)
        || !exact_content_type(response.headers(), "application/json")
    {
        return false;
    }
    let Ok(bytes) = read_bounded_body(response, 16_384).await else {
        return false;
    };
    let Ok(readiness) = strict_json::<DependencyReadiness>(&bytes) else {
        return false;
    };
    readiness.schema_version == expected_schema && readiness.ready
}

fn validate_https_root(value: &url::Url) -> Result<(), SreAuthorityError> {
    if value.scheme() != "https"
        || value.cannot_be_a_base()
        || value.host_str().is_none()
        || value.username() != ""
        || value.password().is_some()
        || value.query().is_some()
        || value.fragment().is_some()
        || value.path() != "/"
    {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn read_token(path: &Path) -> Result<String, SreAuthorityError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 8_194
        || metadata.len() < 16
    {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    let value =
        std::fs::read_to_string(path).map_err(|_| SreAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-sre-token-compare-v1");
    let tag = hmac::sign(&key, second.as_bytes());
    hmac::verify(&key, first.as_bytes(), tag.as_ref()).is_ok()
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn evidence_reference(value: &str) -> bool {
    (value.starts_with("evidence://") || value.starts_with("urn:agenttrust:evidence:"))
        && value.len() <= 2_048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), SreAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(SreAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn exact_certificate_identity(certificate: &[u8], allowed: &BTreeSet<String>) -> Option<String> {
    let identities = certificate_subject_alt_names(certificate).ok()?;
    if identities.len() == 1 && allowed.contains(&identities[0]) {
        identities.into_iter().next()
    } else {
        None
    }
}

// Minimal strict DER walk for X.509 subjectAltName.  CommonName is intentionally ignored and a
// certificate with more than one SAN is rejected so one credential maps to one workload identity.
fn certificate_subject_alt_names(certificate: &[u8]) -> Result<Vec<String>, ()> {
    let (outer_tag, outer, outer_end) = der_element(certificate, 0)?;
    if outer_tag != 0x30 || outer_end != certificate.len() {
        return Err(());
    }
    let (tbs_tag, tbs, _) = der_element(outer, 0)?;
    if tbs_tag != 0x30 {
        return Err(());
    }
    let mut offset = 0;
    let mut san = None;
    while offset < tbs.len() {
        let (tag, value, next) = der_element(tbs, offset)?;
        offset = next;
        if tag != 0xa3 {
            continue;
        }
        let (extensions_tag, extensions, end) = der_element(value, 0)?;
        if extensions_tag != 0x30 || end != value.len() {
            return Err(());
        }
        let mut extension_offset = 0;
        while extension_offset < extensions.len() {
            let (tag, extension, next) = der_element(extensions, extension_offset)?;
            extension_offset = next;
            if tag != 0x30 {
                return Err(());
            }
            let (oid_tag, oid, mut field_offset) = der_element(extension, 0)?;
            if oid_tag != 0x06 {
                return Err(());
            }
            let (mut value_tag, mut extension_value, next_field) =
                der_element(extension, field_offset)?;
            field_offset = next_field;
            if value_tag == 0x01 {
                let parsed = der_element(extension, field_offset)?;
                value_tag = parsed.0;
                extension_value = parsed.1;
                field_offset = parsed.2;
            }
            if value_tag != 0x04 || field_offset != extension.len() {
                return Err(());
            }
            if oid == [0x55, 0x1d, 0x11] && san.replace(extension_value).is_some() {
                return Err(());
            }
        }
    }
    let extension = san.ok_or(())?;
    let (names_tag, names, names_end) = der_element(extension, 0)?;
    if names_tag != 0x30 || names_end != extension.len() {
        return Err(());
    }
    let mut identities = Vec::new();
    let mut name_offset = 0;
    while name_offset < names.len() {
        let (tag, raw, next) = der_element(names, name_offset)?;
        name_offset = next;
        let prefix = match tag {
            0x82 => "DNS:",
            0x86 => "URI:",
            _ => return Err(()),
        };
        let value = std::str::from_utf8(raw).map_err(|_| ())?;
        if value.is_empty()
            || value.len() > 508
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(());
        }
        identities.push(format!("{prefix}{value}"));
    }
    if identities.is_empty() {
        return Err(());
    }
    Ok(identities)
}

fn der_element(input: &[u8], offset: usize) -> Result<(u8, &[u8], usize), ()> {
    let tag = *input.get(offset).ok_or(())?;
    let first = *input.get(offset + 1).ok_or(())?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let octets = usize::from(first & 0x7f);
        if octets == 0 || octets > 4 || input.get(offset + 2) == Some(&0) {
            return Err(());
        }
        let mut length = 0usize;
        for byte in input.get(offset + 2..offset + 2 + octets).ok_or(())? {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(())?;
        }
        if length < 128 {
            return Err(());
        }
        (length, 2 + octets)
    };
    let start = offset.checked_add(header).ok_or(())?;
    let end = start.checked_add(length).ok_or(())?;
    Ok((tag, input.get(start..end).ok_or(())?, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_external_effect_has_exactly_one_production_adapter_route() {
        let expected = [
            (SreOperation::ConfigureSlo, None),
            (SreOperation::RecordSli, None),
            (SreOperation::UpdateBurnAlert, None),
            (SreOperation::LinkIncident, None),
            (SreOperation::RegisterTopology, None),
            (
                SreOperation::RecordZoneHealth,
                Some((SreAdapterKind::TopologyProbe, "v1/topology/zone-health")),
            ),
            (
                SreOperation::CreateBackup,
                Some((SreAdapterKind::Backup, "v1/backups")),
            ),
            (
                SreOperation::VerifyRestore,
                Some((SreAdapterKind::Recovery, "v1/restores/verify")),
            ),
            (SreOperation::PlanDr, None),
            (
                SreOperation::Failover,
                Some((SreAdapterKind::DisasterRecovery, "v1/dr/failover")),
            ),
            (
                SreOperation::Failback,
                Some((SreAdapterKind::DisasterRecovery, "v1/dr/failback")),
            ),
            (SreOperation::PlanChaos, None),
            (
                SreOperation::ExecuteChaos,
                Some((SreAdapterKind::Chaos, "v1/chaos/execute")),
            ),
            (SreOperation::PlanLoad, None),
            (
                SreOperation::ExecuteLoad,
                Some((SreAdapterKind::Load, "v1/load/execute")),
            ),
            (SreOperation::PlanUpgrade, None),
            (SreOperation::RecordCanary, None),
            (
                SreOperation::RollbackUpgrade,
                Some((SreAdapterKind::Upgrade, "v1/upgrades/rollback")),
            ),
            (SreOperation::RecordCostCapacity, None),
            (SreOperation::RecordObservability, None),
        ];
        for (operation, route) in expected {
            assert_eq!(HttpSreEffectPort::adapter_route(operation), route);
            assert_eq!(operation.external_effect(), route.is_some());
        }
        assert_eq!(
            HttpSreEffectPort::required_adapter_kinds(),
            BTreeSet::from([
                SreAdapterKind::TopologyProbe,
                SreAdapterKind::Backup,
                SreAdapterKind::Recovery,
                SreAdapterKind::DisasterRecovery,
                SreAdapterKind::Chaos,
                SreAdapterKind::Load,
                SreAdapterKind::Upgrade,
                SreAdapterKind::Evidence,
            ])
        );
    }

    #[test]
    fn token_document_rejects_duplicate_json_members() {
        let raw = br#"{"schema_version":"agenttrust.sre-token-bindings.v1","schema_version":"agenttrust.sre-token-bindings.v1","bindings":[]}"#;
        assert_eq!(
            strict_json::<TokenBindingDocument>(raw).err(),
            Some(SreAuthorityError::RequestInvalid)
        );
    }

    #[test]
    fn adapter_urls_must_be_https_roots_without_credentials() {
        for invalid in [
            "http://adapter.example/",
            "https://user@adapter.example/",
            "https://adapter.example/v1",
            "https://adapter.example/?token=secret",
        ] {
            let parsed = url::Url::parse(invalid)
                .unwrap_or_else(|error| panic!("url parse failed: {error}"));
            assert_eq!(
                validate_https_root(&parsed),
                Err(SreAuthorityError::ConfigurationInvalid)
            );
        }
    }

    #[test]
    fn client_identity_requires_one_exact_san() {
        assert!(
            validate_identities(&BTreeSet::from([
                "URI:spiffe://agenttrust.example/sre-runtime".into()
            ]))
            .is_ok()
        );
        assert_eq!(
            validate_identities(&BTreeSet::from(["CN:legacy".into()])),
            Err(SreAuthorityError::ConfigurationInvalid)
        );
    }
}
