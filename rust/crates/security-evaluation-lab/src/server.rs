//! TLS 1.3/mTLS production boundary for the security-evaluation authority.

use crate::authority::*;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ActionHash, ArtifactRef,
    AuthorityEvidenceControlBinding, AuthorityEvidenceEventRequest, AuthorityEvidenceSourceKind,
    EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft, EvidenceEventType, ExecutionId,
    IdempotencyKey, SignedAuthorityEvidenceReceipt, TaskId, TenantId,
};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const SECURITY_EVAL_MUTATE_SCOPE: &str = "security-eval:mutate";
pub const SECURITY_EVAL_EXECUTE_SCOPE: &str = "security-eval:execute";
pub const SECURITY_EVAL_QUERY_SCOPE: &str = "security-eval:query";

#[derive(Debug, Clone)]
pub struct SecurityEvalServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub maximum_concurrency: usize,
}

#[derive(Debug, Clone)]
struct SecurityEvalPeerIdentity(String);

#[derive(Clone)]
struct DataState {
    ingress: SecurityEvalIngressAuthority,
    executor: SecurityEvalExecutor,
    tokens: Arc<SecurityEvalTokenAuthorizer>,
}

#[derive(Clone)]
struct ManagementState {
    ingress: SecurityEvalIngressAuthority,
    executor: SecurityEvalExecutor,
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

pub struct SecurityEvalTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl SecurityEvalTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, SecurityEvalAuthorityError> {
        validate_identities(allowed_identities)?;
        let metadata = std::fs::metadata(path)
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
        if !path.is_absolute() || !metadata.is_file() || metadata.len() > 1_048_576 {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        let raw =
            std::fs::read(path).map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
        let document: TokenBindingDocument = serde_json::from_slice(&raw)
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.security-eval-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    SECURITY_EVAL_MUTATE_SCOPE
                        | SECURITY_EVAL_EXECUTE_SCOPE
                        | SECURITY_EVAL_QUERY_SCOPE
                )
                || !identifier(&binding.subject, 256)
                || !digest(&binding.token_sha256)
                || !Uuid::parse_str(&binding.tenant_id)
                    .is_ok_and(|value| !value.is_nil() && value.to_string() == binding.tenant_id)
                || !credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, SecurityEvalAuthorityError> {
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| (16..=8_192).contains(&value.len()))
            .ok_or(SecurityEvalAuthorityError::PrincipalDenied)?;
        let supplied = hex::encode(Sha256::digest(token.as_bytes()));
        let matching = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.client_identity == peer
                    && binding.tenant_id == tenant
                    && binding.scope == scope
                    && constant_time_equal(&supplied, &binding.token_sha256)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(SecurityEvalAuthorityError::PrincipalDenied);
        }
        Ok(matching[0].subject.clone())
    }
}

pub fn data_router(
    ingress: SecurityEvalIngressAuthority,
    executor: SecurityEvalExecutor,
    tokens: Arc<SecurityEvalTokenAuthorizer>,
    maximum_concurrency: usize,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/security-evaluations/actions", post(submit_action))
        .route("/v1/security-evaluations/executions", post(execute_action))
        .route(
            "/v1/authoritative/security-evaluations/campaigns",
            get(authoritative_campaigns),
        )
        .route(
            "/v1/authoritative/security-evaluations/campaigns/{campaign_id}",
            get(authoritative_campaign),
        )
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(45),
        ))
        .layer(ConcurrencyLimitLayer::new(maximum_concurrency))
        .with_state(DataState {
            ingress,
            executor,
            tokens,
        })
}

pub fn management_router(
    ingress: SecurityEvalIngressAuthority,
    executor: SecurityEvalExecutor,
) -> Router {
    Router::new()
        .route("/live", get(management_live))
        .route("/ready", get(management_ready))
        .layer(DefaultBodyLimit::max(4_096))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(5),
        ))
        .layer(ConcurrencyLimitLayer::new(32))
        .with_state(ManagementState { ingress, executor })
}

async fn data_ready(State(state): State<DataState>) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn management_ready(
    State(state): State<ManagementState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn management_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schema_version": SECURITY_EVAL_READINESS_SCHEMA,
        "live": true
    }))
}

async fn readiness(
    ingress: &SecurityEvalIngressAuthority,
    executor: &SecurityEvalExecutor,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (ingress_ready, executor_ready) = tokio::join!(ingress.ready(), executor.ready());
    if !ingress_ready || !executor_ready {
        return Err(SecurityEvalAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(serde_json::json!({
        "schema_version": SECURITY_EVAL_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "orchestrator_ready": true,
        "isolated_runner_ready": true,
        "evidence_authority_ready": true,
        "dataset_keyring_ready": true,
        "report_signer_ready": true,
        "production_certification": false
    })))
}

async fn submit_action(
    State(state): State<DataState>,
    Extension(SecurityEvalPeerIdentity(peer)): Extension<SecurityEvalPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<SecurityEvalCommandRequest>,
) -> Result<(StatusCode, Json<SecurityEvalActionReceipt>), ApiError> {
    let tenant = exact_tenant(&headers, body.tenant_id)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, SECURITY_EVAL_MUTATE_SCOPE, &headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = request_digest(
        "POST",
        "/v1/security-evaluations/actions",
        &tenant,
        &peer,
        &subject,
        SECURITY_EVAL_MUTATE_SCOPE,
        idempotency_key,
        &body,
    )?;
    let receipt = state
        .ingress
        .submit(
            SecurityEvalPrincipal {
                tenant_id: tenant,
                subject,
                actor_kind: "SERVICE".into(),
            },
            body,
            &request_digest,
            idempotency_key,
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_action(
    State(state): State<DataState>,
    Extension(SecurityEvalPeerIdentity(peer)): Extension<SecurityEvalPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<SecurityEvalExecutorRequest>,
) -> Result<Json<SecurityEvalMutationResult>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    let subject =
        state
            .tokens
            .authorize(&peer, &tenant.0, SECURITY_EVAL_EXECUTE_SCOPE, &headers)?;
    if subject != peer {
        return Err(SecurityEvalAuthorityError::PrincipalDenied.into());
    }
    let binding = SecurityEvalExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.into(),
        ledger_execution_id: uuid_header(&headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: uuid_header(&headers, "x-agenttrust-ledger-entry-id")?,
        ledger_event_digest: required_header(&headers, "x-agenttrust-ledger-entry-digest")?.into(),
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.into(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?
            .parse()
            .map_err(|_| SecurityEvalAuthorityError::RequestInvalid)?,
        idempotency_key: required_idempotency_key(&headers)?.into(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.into(),
        policy_decision_id: required_header(&headers, "x-agenttrust-policy-decision-id")?.into(),
        policy_decision_digest: required_header(&headers, "x-agenttrust-policy-decision-digest")?
            .into(),
        authorization_evidence_ref: required_header(
            &headers,
            "x-agenttrust-authorization-evidence-ref",
        )?
        .into(),
        authorization_evidence_digest: required_header(
            &headers,
            "x-agenttrust-authorization-evidence-digest",
        )?
        .into(),
    };
    Ok(Json(state.executor.execute(binding, body).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignPageQuery {
    after_campaign_id: Option<Uuid>,
    limit: Option<i64>,
}

async fn authoritative_campaigns(
    State(state): State<DataState>,
    Extension(SecurityEvalPeerIdentity(peer)): Extension<SecurityEvalPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<CampaignPageQuery>,
) -> Result<Json<AuthoritativeCampaignPage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant.0, SECURITY_EVAL_QUERY_SCOPE, &headers)?;
    Ok(Json(
        state
            .ingress
            .authoritative_page(&tenant, query.after_campaign_id, query.limit.unwrap_or(100))
            .await?,
    ))
}

async fn authoritative_campaign(
    State(state): State<DataState>,
    Extension(SecurityEvalPeerIdentity(peer)): Extension<SecurityEvalPeerIdentity>,
    headers: HeaderMap,
    AxumPath(campaign_id): AxumPath<Uuid>,
) -> Result<Json<AuthoritativeCampaign>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant.0, SECURITY_EVAL_QUERY_SCOPE, &headers)?;
    Ok(Json(
        state
            .ingress
            .authoritative_detail(&tenant, campaign_id)
            .await?,
    ))
}

#[derive(Clone)]
pub struct HttpSecurityEvalOrchestrator {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
}

impl HttpSecurityEvalOrchestrator {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
    ) -> Result<Self, SecurityEvalAuthorityError> {
        validate_https_root(&endpoint)?;
        if !token_file.is_absolute() {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[async_trait::async_trait]
impl SecurityEvalOrchestratorPort for HttpSecurityEvalOrchestrator {
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
    ) -> Result<SecurityEvalActionReceipt, SecurityEvalAuthorityError> {
        let response = self
            .client
            .post(
                self.endpoint
                    .join("v1/actions")
                    .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .json(envelope)
            .send()
            .await
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(SecurityEvalAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|value| value > 65_536)
        {
            return Err(SecurityEvalAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(SecurityEvalAuthorityError::DependencyUnavailable);
        }
        let accepted: OrchestratorAcceptance = serde_json::from_slice(&bytes)
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
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
            return Err(SecurityEvalAuthorityError::DependencyUnavailable);
        }
        Ok(SecurityEvalActionReceipt {
            schema_version: SECURITY_EVAL_ACTION_RECEIPT_SCHEMA.into(),
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

#[derive(Clone)]
pub struct HttpSecurityEvalEvidence {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
    client_identity: String,
    keyring: SecurityEvalEvidenceKeyring,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyringDocument {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SecurityEvalEvidenceKeyring {
    keys: Arc<BTreeMap<String, VerifyingKey>>,
}

impl SecurityEvalEvidenceKeyring {
    pub fn from_json(raw: &[u8]) -> Result<Self, SecurityEvalAuthorityError> {
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        let document: EvidenceKeyringDocument =
            strict_json(raw).map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.ed25519-public-keyring.v1"
            || document.keys.is_empty()
            || document.keys.len() > 1_024
        {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for (key_id, encoded) in document.keys {
            if !identifier(&key_id, 128) {
                return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
            }
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?
                .try_into()
                .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
            if keys.insert(key_id, key).is_some() {
                return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
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

impl HttpSecurityEvalEvidence {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
        client_identity: String,
        keyring: SecurityEvalEvidenceKeyring,
    ) -> Result<Self, SecurityEvalAuthorityError> {
        validate_https_root(&endpoint)?;
        if !token_file.is_absolute() {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        read_token(&token_file)?;
        if client_identity.len() > 512
            || !(client_identity.starts_with("DNS:") || client_identity.starts_with("URI:"))
            || client_identity.contains(char::is_whitespace)
        {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            client,
            endpoint,
            token_file,
            client_identity,
            keyring,
        })
    }
}

#[async_trait::async_trait]
impl SecurityEvalEvidencePort for HttpSecurityEvalEvidence {
    async fn ready(&self) -> bool {
        dependency_ready(
            &self.client,
            &self.endpoint,
            &self.token_file,
            "agenttrust.evidence-readiness.v1",
        )
        .await
    }

    async fn publish(
        &self,
        record: &SecurityEvalEvidenceOutboxRecord,
    ) -> Result<SecurityEvalEvidenceReceipt, SecurityEvalAuthorityError> {
        if !digest(&record.payload_digest)
            || evidence_canonical_digest(&record.payload)? != record.payload_digest
            || !digest(&record.event_digest)
        {
            return Err(SecurityEvalAuthorityError::EvidenceMissing);
        }
        let tenant = TenantId(record.tenant_id.to_string());
        let task_id = evidence_uuid_field(&record.payload, "task_id")?;
        let recorded_at = evidence_time_field(&record.payload, "recorded_at")?;
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId(task_id.to_string()),
            authority_event_id: record.evidence_event_id.to_string(),
            idempotency_key: IdempotencyKey(record.evidence_event_id.to_string()),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(AuthorityEvidenceControlBinding {
                action_hash: ActionHash(evidence_digest_field(&record.payload, "action_hash")?),
                ledger_execution_id: ExecutionId(
                    evidence_uuid_field(&record.payload, "ledger_execution_id")?.to_string(),
                ),
                ledger_event_id: evidence_uuid_field(&record.payload, "ledger_event_id")?
                    .to_string(),
                ledger_event_digest: evidence_digest_field(&record.payload, "ledger_event_digest")?,
                fence_digest: evidence_digest_field(&record.payload, "fence_digest")?,
                policy_decision_id: evidence_string_field(
                    &record.payload,
                    "policy_decision_id",
                    256,
                )?
                .into(),
                policy_decision_digest: evidence_digest_field(
                    &record.payload,
                    "policy_decision_digest",
                )?,
                authorization_evidence_ref: evidence_string_field(
                    &record.payload,
                    "authorization_evidence_ref",
                    2_048,
                )?
                .into(),
                authorization_evidence_digest: evidence_digest_field(
                    &record.payload,
                    "authorization_evidence_digest",
                )?,
            }),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: tenant,
                task_id: TaskId(task_id.to_string()),
                event_type: EvidenceEventType::Evaluation,
                actor_subject: evidence_string_field(&record.payload, "actor_subject", 512)?.into(),
                source_service: self.client_identity.clone(),
                trace_id: evidence_string_field(&record.payload, "trace_id", 256)?.into(),
                span_id: record.evidence_event_id.to_string(),
                payload_hash: record.payload_digest.clone(),
                safe_summary: "Security evaluation authority mutation persisted".into(),
                artifact_refs: Vec::<ArtifactRef>::new(),
                occurred_at: recorded_at.clone(),
            },
            requested_at: recorded_at,
        };
        let request_digest = request
            .request_digest()
            .map_err(|_| SecurityEvalAuthorityError::EvidenceMissing)?;
        let response = self
            .client
            .post(
                self.endpoint
                    .join("v1/evidence/authority-events")
                    .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.token_file)?)
            .header("X-AgentTrust-Tenant-Id", record.tenant_id.to_string())
            .header("Idempotency-Key", record.evidence_event_id.to_string())
            .header(
                "X-AgentTrust-Authority-Event-Id",
                record.evidence_event_id.to_string(),
            )
            .header("X-AgentTrust-Payload-Digest", &record.payload_digest)
            .json(&request)
            .send()
            .await
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(SecurityEvalAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|value| value > 65_536)
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                != Some("application/json")
        {
            return Err(SecurityEvalAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(SecurityEvalAuthorityError::DependencyUnavailable);
        }
        let receipt: SignedAuthorityEvidenceReceipt =
            strict_json(&bytes).map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
        let key = self
            .keyring
            .key(&receipt.key_id)
            .ok_or(SecurityEvalAuthorityError::DependencyUnavailable)?;
        receipt
            .verify(key, Utc::now())
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
        if receipt.tenant_id != request.tenant_id
            || receipt.task_id != request.task_id
            || receipt.authority_event_id != request.authority_event_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.source_kind != request.source_kind
            || receipt.request_digest != request_digest
            || receipt.payload_digest != record.payload_digest
            || receipt.event.draft != request.event
        {
            return Err(SecurityEvalAuthorityError::DependencyUnavailable);
        }
        Ok(SecurityEvalEvidenceReceipt {
            schema_version: SECURITY_EVAL_EVIDENCE_RECEIPT_SCHEMA.into(),
            tenant_id: record.tenant_id,
            evidence_event_id: record.evidence_event_id,
            event_digest: record.event_digest.clone(),
            payload_digest: receipt.payload_digest,
            evidence_ref: receipt.evidence_ref,
            evidence_digest: receipt.evidence_digest,
            accepted: true,
        })
    }
}

fn evidence_string_field<'a>(
    payload: &'a serde_json::Value,
    name: &str,
    maximum: usize,
) -> Result<&'a str, SecurityEvalAuthorityError> {
    payload
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or(SecurityEvalAuthorityError::EvidenceMissing)
}

fn evidence_uuid_field(
    payload: &serde_json::Value,
    name: &str,
) -> Result<Uuid, SecurityEvalAuthorityError> {
    let value = evidence_string_field(payload, name, 36)?;
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| !parsed.is_nil() && parsed.to_string() == value)
        .ok_or(SecurityEvalAuthorityError::EvidenceMissing)
}

fn evidence_digest_field(
    payload: &serde_json::Value,
    name: &str,
) -> Result<String, SecurityEvalAuthorityError> {
    let value = evidence_string_field(payload, name, 64)?;
    if !digest(value) {
        return Err(SecurityEvalAuthorityError::EvidenceMissing);
    }
    Ok(value.into())
}

fn evidence_time_field(
    payload: &serde_json::Value,
    name: &str,
) -> Result<DateTime<Utc>, SecurityEvalAuthorityError> {
    DateTime::parse_from_rfc3339(evidence_string_field(payload, name, 64)?)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| SecurityEvalAuthorityError::EvidenceMissing)
}

fn evidence_canonical_digest(
    value: &serde_json::Value,
) -> Result<String, SecurityEvalAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| SecurityEvalAuthorityError::EvidenceMissing)
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

#[derive(Clone)]
pub struct HttpIsolatedRunner {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
}

impl HttpIsolatedRunner {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
    ) -> Result<Self, SecurityEvalAuthorityError> {
        validate_https_root(&endpoint)?;
        if !token_file.is_absolute() {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
        read_token(&token_file)?;
        Ok(Self {
            client,
            endpoint,
            token_file,
        })
    }
}

#[async_trait::async_trait]
impl IsolatedRunnerPort for HttpIsolatedRunner {
    async fn ready(&self) -> bool {
        dependency_ready(
            &self.client,
            &self.endpoint,
            &self.token_file,
            "agenttrust.isolated-security-runner-readiness.v1",
        )
        .await
    }

    async fn execute(
        &self,
        binding: &SecurityEvalExecutionBinding,
        request: &SecurityEvalExecutorRequest,
    ) -> Result<Option<IsolatedRunnerReceipt>, SecurityEvalAuthorityError> {
        let path = match request.command.operation {
            SecurityEvalOperation::StartCampaign => "v1/security-evaluations/runs",
            SecurityEvalOperation::AbortCampaign => "v1/security-evaluations/aborts",
            SecurityEvalOperation::TripKillSwitch => "v1/security-evaluations/kill-switches",
            _ => return Ok(None),
        };
        let response = self
            .client
            .post(
                self.endpoint
                    .join(path)
                    .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.token_file)?)
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
            .json(request)
            .send()
            .await
            .map_err(|_| SecurityEvalAuthorityError::OutcomeUnknown)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|value| value > 262_144)
        {
            return Err(SecurityEvalAuthorityError::OutcomeUnknown);
        }
        let bytes = read_bounded_body(response, 262_144)
            .await
            .map_err(|_| SecurityEvalAuthorityError::OutcomeUnknown)?;
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(SecurityEvalAuthorityError::OutcomeUnknown);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| SecurityEvalAuthorityError::OutcomeUnknown)
    }
}

pub async fn serve(
    config: SecurityEvalServerConfig,
    data: Router,
    management: Router,
) -> Result<(), SecurityEvalAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !(1..=10_000).contains(&config.maximum_concurrency)
        || config.data_address == config.management_address
        || config.data_address.ip().is_loopback()
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
    {
        return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let data_acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.allowed_client_identities.clone()),
    };
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(data_acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| SecurityEvalAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
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
        || response.content_length().is_some_and(|value| value > 4_096)
    {
        return false;
    }
    let Ok(bytes) = read_bounded_body(response, 4_096).await else {
        return false;
    };
    if bytes.is_empty() || bytes.len() > 4_096 {
        return false;
    }
    serde_json::from_slice::<DependencyReadiness>(&bytes)
        .is_ok_and(|value| value.schema_version == expected_schema && value.ready)
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
    type Service = AddExtension<S, SecurityEvalPeerIdentity>;
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
            Ok((
                stream,
                Extension(SecurityEvalPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, SecurityEvalAuthorityError> {
    for path in [ca_file, certificate_file, private_key_file] {
        let metadata = std::fs::metadata(path)
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
        if !path.is_absolute() || !metadata.is_file() || metadata.len() > 4_194_304 {
            return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
        }
    }
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file)
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file)
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?
        .ok_or(SecurityEvalAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(SecurityEvalAuthorityError);

impl From<SecurityEvalAuthorityError> for ApiError {
    fn from(value: SecurityEvalAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            SecurityEvalAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            SecurityEvalAuthorityError::RequestInvalid
            | SecurityEvalAuthorityError::IsolationDenied
            | SecurityEvalAuthorityError::SignatureInvalid => StatusCode::BAD_REQUEST,
            SecurityEvalAuthorityError::NotFound => StatusCode::NOT_FOUND,
            SecurityEvalAuthorityError::IdempotencyConflict
            | SecurityEvalAuthorityError::StateConflict
            | SecurityEvalAuthorityError::EvidenceMissing
            | SecurityEvalAuthorityError::BudgetExhausted
            | SecurityEvalAuthorityError::KillSwitchTripped => StatusCode::CONFLICT,
            SecurityEvalAuthorityError::DependencyUnavailable
            | SecurityEvalAuthorityError::OutcomeUnknown
            | SecurityEvalAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.security-eval-authority-error.v1",
                "error": self.0.to_string(),
                "trace_id": Uuid::new_v4().to_string(),
                "safe_summary": "security evaluation request was not completed"
            })),
        )
            .into_response()
    }
}

fn exact_tenant(
    headers: &HeaderMap,
    body_tenant: Uuid,
) -> Result<TenantId, SecurityEvalAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant.to_string() || body_tenant.is_nil() {
        return Err(SecurityEvalAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, SecurityEvalAuthorityError> {
    let raw = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed = Uuid::parse_str(raw).map_err(|_| SecurityEvalAuthorityError::PrincipalDenied)?;
    if parsed.is_nil() || parsed.to_string() != raw {
        return Err(SecurityEvalAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(raw.into()))
}

fn uuid_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Uuid, SecurityEvalAuthorityError> {
    let raw = required_header(headers, name)?;
    Uuid::parse_str(raw)
        .ok()
        .filter(|value| !value.is_nil() && value.to_string() == raw)
        .ok_or(SecurityEvalAuthorityError::RequestInvalid)
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, SecurityEvalAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !(16..=128).contains(&value.len())
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/'))
        })
    {
        return Err(SecurityEvalAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, SecurityEvalAuthorityError> {
    single_header(headers, name).ok_or(SecurityEvalAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RequestBinding<'a, T: Serialize> {
    schema_version: &'static str,
    method: &'a str,
    path: &'a str,
    tenant_id: &'a TenantId,
    client_identity: &'a str,
    subject: &'a str,
    scope: &'a str,
    idempotency_key: &'a str,
    body: &'a T,
}

#[allow(clippy::too_many_arguments)]
fn request_digest<T: Serialize>(
    method: &str,
    path: &str,
    tenant: &TenantId,
    client_identity: &str,
    subject: &str,
    scope: &str,
    idempotency_key: &str,
    body: &T,
) -> Result<String, SecurityEvalAuthorityError> {
    if method != "POST"
        || path != "/v1/security-evaluations/actions"
        || scope != SECURITY_EVAL_MUTATE_SCOPE
        || !identifier(client_identity, 512)
        || !identifier(subject, 256)
    {
        return Err(SecurityEvalAuthorityError::RequestInvalid);
    }
    serde_jcs::to_vec(&RequestBinding {
        schema_version: "agenttrust.security-eval-service-request-binding.v1",
        method,
        path,
        tenant_id: tenant,
        client_identity,
        subject,
        scope,
        idempotency_key,
        body,
    })
    .map(|bytes| hex::encode(Sha256::digest(bytes)))
    .map_err(|_| SecurityEvalAuthorityError::RequestInvalid)
}

fn read_token(path: &Path) -> Result<String, SecurityEvalAuthorityError> {
    let metadata =
        std::fs::metadata(path).map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() > 8_194 {
        return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| SecurityEvalAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
    }
    Ok(token.into())
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-security-eval-token-compare-v1",
    );
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
    Uuid::parse_str(value).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == value)
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        })
}

fn evidence_reference(value: &str) -> bool {
    (value.starts_with("evidence://") || value.starts_with("urn:agenttrust:evidence:"))
        && value.len() <= 2_048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

fn validate_https_root(value: &url::Url) -> Result<(), SecurityEvalAuthorityError> {
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), SecurityEvalAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(SecurityEvalAuthorityError::ConfigurationInvalid);
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

// CommonName is intentionally ignored.  A workload certificate must have exactly one DNS/URI SAN.
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
mod server_unit_tests {
    use super::*;

    #[test]
    fn route_scopes_are_non_interchangeable() {
        let scopes = BTreeSet::from([
            SECURITY_EVAL_MUTATE_SCOPE,
            SECURITY_EVAL_EXECUTE_SCOPE,
            SECURITY_EVAL_QUERY_SCOPE,
        ]);
        assert_eq!(scopes.len(), 3);
    }

    #[test]
    fn only_https_dependency_roots_are_accepted() {
        assert!(
            validate_https_root(
                &url::Url::parse("https://runner.internal/")
                    .unwrap_or_else(|error| panic!("url: {error}"))
            )
            .is_ok()
        );
        assert!(
            validate_https_root(
                &url::Url::parse("https://runner.internal/v1")
                    .unwrap_or_else(|error| panic!("url: {error}"))
            )
            .is_err()
        );
        assert!(
            validate_https_root(
                &url::Url::parse("http://runner.internal/")
                    .unwrap_or_else(|error| panic!("url: {error}"))
            )
            .is_err()
        );
    }
}
