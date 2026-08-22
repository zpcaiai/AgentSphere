//! TLS 1.3/mTLS incident, replay, and release-gate production boundary.

use crate::authority::*;
use agent_trust_contracts::{HumanPrincipalKeyring, TenantId, human_principal_request_digest};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use chrono::Utc;
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
use uuid::Uuid;

pub const INCIDENT_DETECT_SCOPE: &str = "incident:detect";
pub const INCIDENT_MUTATE_SCOPE: &str = "incident:mutate";
pub const INCIDENT_EXECUTE_SCOPE: &str = "incident:execute";
pub const INCIDENT_QUERY_SCOPE: &str = "incident:query";

#[derive(Debug, Clone)]
pub struct IncidentServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub service_subject: String,
    pub maximum_authentication_age_seconds: i64,
}

#[derive(Debug, Clone)]
struct IncidentPeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    ingress: IncidentIngressAuthority,
    executor: IncidentExecutor,
    tokens: Arc<IncidentTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    service_subject: String,
    maximum_authentication_age_seconds: i64,
}

#[derive(Clone)]
struct ReadinessState {
    ingress: IncidentIngressAuthority,
    executor: IncidentExecutor,
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

pub struct IncidentTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl IncidentTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, IncidentAuthorityError> {
        validate_identities(allowed_identities)?;
        if !path.is_absolute() {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        let raw =
            std::fs::read(path).map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument = serde_json::from_slice(&raw)
            .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.incident-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    INCIDENT_DETECT_SCOPE
                        | INCIDENT_MUTATE_SCOPE
                        | INCIDENT_EXECUTE_SCOPE
                        | INCIDENT_QUERY_SCOPE
                )
                || !identifier(&binding.subject, 256)
                || !digest(&binding.token_sha256)
                || !Uuid::parse_str(&binding.tenant_id)
                    .is_ok_and(|value| value.to_string() == binding.tenant_id)
                // A physical credential cannot cross tenant, SAN, subject, or route scope.
                || !credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(IncidentAuthorityError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, IncidentAuthorityError> {
        let authorization = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| (16..=8_192).contains(&value.len()))
            .ok_or(IncidentAuthorityError::PrincipalDenied)?;
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
            return Err(IncidentAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }
}

pub fn router(
    ingress: IncidentIngressAuthority,
    executor: IncidentExecutor,
    tokens: Arc<IncidentTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    service_subject: String,
    maximum_authentication_age_seconds: i64,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/incidents/detections", post(submit_detection))
        .route("/v1/incidents/actions", post(submit_action))
        .route("/v1/incidents/executions", post(execute_mutation))
        .route("/v1/authoritative/incidents", get(authoritative_incidents))
        .route(
            "/v1/authoritative/incidents/{incident_id}",
            get(authoritative_incident),
        )
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::new(Duration::from_secs(45)))
        .with_state(ServerState {
            ingress,
            executor,
            tokens,
            principal_keyring,
            service_subject,
            maximum_authentication_age_seconds,
        })
}

async fn data_ready(State(state): State<ServerState>) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn submit_detection(
    State(state): State<ServerState>,
    Extension(IncidentPeerIdentity(peer)): Extension<IncidentPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<IncidentCommandRequest>,
) -> Result<(StatusCode, Json<IncidentActionReceipt>), ApiError> {
    let tenant = exact_tenant(&headers, body.tenant_id.to_string())?;
    let subject =
        state
            .tokens
            .authorize(&peer, &tenant.0, INCIDENT_DETECT_SCOPE, &headers)?;
    if subject != peer {
        return Err(IncidentAuthorityError::PrincipalDenied.into());
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = service_request_digest(
        "/v1/incidents/detections",
        &tenant,
        &peer,
        &subject,
        INCIDENT_DETECT_SCOPE,
        idempotency_key,
        &body,
    )?;
    let receipt = state
        .ingress
        .submit_detection(tenant, subject, body, &request_digest, idempotency_key)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn submit_action(
    State(state): State<ServerState>,
    Extension(IncidentPeerIdentity(peer)): Extension<IncidentPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<IncidentCommandRequest>,
) -> Result<(StatusCode, Json<IncidentActionReceipt>), ApiError> {
    let tenant = exact_tenant(&headers, body.tenant_id.to_string())?;
    let service_subject =
        state
            .tokens
            .authorize(&peer, &tenant.0, INCIDENT_MUTATE_SCOPE, &headers)?;
    if service_subject != state.service_subject {
        return Err(IncidentAuthorityError::PrincipalDenied.into());
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = human_principal_request_digest(
        "POST",
        "/v1/incidents/actions",
        &tenant,
        &peer,
        &service_subject,
        INCIDENT_MUTATE_SCOPE,
        idempotency_key,
        &body,
    )
    .map_err(|_| IncidentAuthorityError::RequestInvalid)?;
    let assertion = single_header(&headers, "x-agenttrust-human-assertion")
        .ok_or(IncidentAuthorityError::PrincipalDenied)?;
    let principal = state
        .principal_keyring
        .verify_encoded(
            assertion,
            &tenant,
            &peer,
            &service_subject,
            INCIDENT_MUTATE_SCOPE,
            &request_digest,
            true,
            state.maximum_authentication_age_seconds,
            Utc::now(),
        )
        .map_err(|_| IncidentAuthorityError::PrincipalDenied)?;
    let receipt = state
        .ingress
        .submit_human(&principal, body, &request_digest, idempotency_key)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_mutation(
    State(state): State<ServerState>,
    Extension(IncidentPeerIdentity(peer)): Extension<IncidentPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<IncidentExecutorRequest>,
) -> Result<Json<IncidentMutationResult>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    let subject =
        state
            .tokens
            .authorize(&peer, &tenant.0, INCIDENT_EXECUTE_SCOPE, &headers)?;
    if subject != peer {
        return Err(IncidentAuthorityError::PrincipalDenied.into());
    }
    let binding = IncidentExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.to_string(),
        ledger_execution_id: parse_uuid_header(&headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: parse_uuid_header(&headers, "x-agenttrust-ledger-entry-id")?,
        ledger_event_digest: required_header(&headers, "x-agenttrust-ledger-entry-digest")?
            .to_string(),
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.to_string(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?
            .parse()
            .map_err(|_| IncidentAuthorityError::RequestInvalid)?,
        idempotency_key: required_idempotency_key(&headers)?.to_string(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.to_string(),
        policy_decision_id: required_header(&headers, "x-agenttrust-policy-decision-id")?
            .to_string(),
        policy_decision_digest: required_header(
            &headers,
            "x-agenttrust-policy-decision-digest",
        )?
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
struct IncidentPageQuery {
    after_incident_id: Option<Uuid>,
    limit: Option<i64>,
}

async fn authoritative_incidents(
    State(state): State<ServerState>,
    Extension(IncidentPeerIdentity(peer)): Extension<IncidentPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<IncidentPageQuery>,
) -> Result<Json<AuthoritativeIncidentPage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant.0, INCIDENT_QUERY_SCOPE, &headers)?;
    Ok(Json(
        state
            .ingress
            .authoritative_page(&tenant, query.after_incident_id, query.limit.unwrap_or(100))
            .await?,
    ))
}

async fn authoritative_incident(
    State(state): State<ServerState>,
    Extension(IncidentPeerIdentity(peer)): Extension<IncidentPeerIdentity>,
    headers: HeaderMap,
    AxumPath(incident_id): AxumPath<Uuid>,
) -> Result<Json<AuthoritativeIncident>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant.0, INCIDENT_QUERY_SCOPE, &headers)?;
    Ok(Json(
        state
            .ingress
            .authoritative_detail(&tenant, incident_id)
            .await?,
    ))
}

#[derive(Clone)]
pub struct HttpIncidentOrchestrator {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
}

impl HttpIncidentOrchestrator {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
    ) -> Result<Self, IncidentAuthorityError> {
        validate_https_root(&endpoint)?;
        if !token_file.is_absolute() {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        read_token(&token_file)?;
        Ok(Self {
            client,
            endpoint,
            token_file,
        })
    }
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[async_trait::async_trait]
impl IncidentOrchestratorPort for HttpIncidentOrchestrator {
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
    ) -> Result<IncidentActionReceipt, IncidentAuthorityError> {
        let response = self
            .client
            .post(
                self.endpoint
                    .join("v1/actions")
                    .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .json(envelope)
            .send()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(IncidentAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        let accepted: OrchestratorAcceptance = serde_json::from_slice(&bytes)
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
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
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        Ok(IncidentActionReceipt {
            schema_version: INCIDENT_ACTION_RECEIPT_SCHEMA.into(),
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
pub struct HttpIncidentEffectPort {
    client: reqwest::Client,
    containment_endpoint: url::Url,
    containment_token_file: PathBuf,
    replay_endpoint: url::Url,
    replay_token_file: PathBuf,
}

impl HttpIncidentEffectPort {
    pub fn new(
        client: reqwest::Client,
        containment_endpoint: url::Url,
        containment_token_file: PathBuf,
        replay_endpoint: url::Url,
        replay_token_file: PathBuf,
    ) -> Result<Self, IncidentAuthorityError> {
        validate_https_root(&containment_endpoint)?;
        validate_https_root(&replay_endpoint)?;
        if containment_endpoint == replay_endpoint
            || !containment_token_file.is_absolute()
            || !replay_token_file.is_absolute()
            || containment_token_file == replay_token_file
            || read_token(&containment_token_file)? == read_token(&replay_token_file)?
        {
            return Err(IncidentAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            client,
            containment_endpoint,
            containment_token_file,
            replay_endpoint,
            replay_token_file,
        })
    }

    async fn invoke(
        &self,
        endpoint: &url::Url,
        token_file: &Path,
        path: &str,
        binding: &IncidentExecutionBinding,
        request: &IncidentExecutorRequest,
    ) -> Result<ExternalEffectReceipt, IncidentAuthorityError> {
        let response = self
            .client
            .post(
                endpoint
                    .join(path)
                    .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(token_file)?)
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
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 262_144)
        {
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(IncidentAuthorityError::DependencyUnavailable);
        }
        serde_json::from_slice(&bytes).map_err(|_| IncidentAuthorityError::DependencyUnavailable)
    }
}

#[async_trait::async_trait]
impl IncidentEffectPort for HttpIncidentEffectPort {
    async fn ready(&self) -> bool {
        let containment = dependency_ready(
            &self.client,
            &self.containment_endpoint,
            &self.containment_token_file,
            "agenttrust.containment-readiness.v1",
        );
        let replay = dependency_ready(
            &self.client,
            &self.replay_endpoint,
            &self.replay_token_file,
            "agenttrust.replay-readiness.v1",
        );
        let (containment, replay) = tokio::join!(containment, replay);
        containment && replay
    }

    async fn execute(
        &self,
        binding: &IncidentExecutionBinding,
        request: &IncidentExecutorRequest,
    ) -> Result<Option<ExternalEffectReceipt>, IncidentAuthorityError> {
        match request.command.operation {
            IncidentAuthorityOperation::Detect | IncidentAuthorityOperation::Contain => self
                .invoke(
                    &self.containment_endpoint,
                    &self.containment_token_file,
                    "v1/containment/actions",
                    binding,
                    request,
                )
                .await
                .map(Some),
            IncidentAuthorityOperation::CompleteReplay => self
                .invoke(
                    &self.replay_endpoint,
                    &self.replay_token_file,
                    "v1/replays/runs",
                    binding,
                    request,
                )
                .await
                .map(Some),
            _ => Ok(None),
        }
    }
}

pub async fn serve(
    config: IncidentServerConfig,
    application: Router,
    readiness_authority: IncidentIngressAuthority,
    readiness_executor: IncidentExecutor,
) -> Result<(), IncidentAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !identifier(&config.service_subject, 256)
        || !(60..=86_400).contains(&config.maximum_authentication_age_seconds)
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(IncidentAuthorityError::ConfigurationInvalid);
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
        .route("/ready", get(management_ready))
        .with_state(ReadinessState {
            ingress: readiness_authority,
            executor: readiness_executor,
        });
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| IncidentAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn management_ready(
    State(state): State<ReadinessState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn readiness(
    authority: &IncidentIngressAuthority,
    executor: &IncidentExecutor,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (authority_ready, effects_ready) = tokio::join!(authority.ready(), executor.ready());
    if !authority_ready || !effects_ready {
        return Err(IncidentAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(serde_json::json!({
        "schema_version": INCIDENT_AUTHORITY_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "orchestrator_ready": true,
        "containment_replay_ready": true,
        "release_signer_ready": true
    })))
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
            .is_some_and(|length| length > 4_096)
    {
        return false;
    }
    let Ok(bytes) = response.bytes().await else {
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
    type Service = AddExtension<S, IncidentPeerIdentity>;
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
                Extension(IncidentPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, IncidentAuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(IncidentAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file)
            .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file)
            .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?
        .ok_or(IncidentAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(IncidentAuthorityError);

impl From<IncidentAuthorityError> for ApiError {
    fn from(value: IncidentAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            IncidentAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            IncidentAuthorityError::RequestInvalid
            | IncidentAuthorityError::ReplayBoundaryViolation => StatusCode::BAD_REQUEST,
            IncidentAuthorityError::NotFound => StatusCode::NOT_FOUND,
            IncidentAuthorityError::IdempotencyConflict
            | IncidentAuthorityError::StateConflict
            | IncidentAuthorityError::EvidenceMissing => StatusCode::CONFLICT,
            IncidentAuthorityError::DependencyUnavailable
            | IncidentAuthorityError::OutcomeUnknown
            | IncidentAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.incident-authority-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn exact_tenant(
    headers: &HeaderMap,
    body_tenant: String,
) -> Result<TenantId, IncidentAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant {
        return Err(IncidentAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, IncidentAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed = Uuid::parse_str(value).map_err(|_| IncidentAuthorityError::PrincipalDenied)?;
    if parsed.to_string() != value {
        return Err(IncidentAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.to_string()))
}

fn parse_uuid_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Uuid, IncidentAuthorityError> {
    let raw = required_header(headers, name)?;
    Uuid::parse_str(raw)
        .ok()
        .filter(|value| value.to_string() == raw)
        .ok_or(IncidentAuthorityError::RequestInvalid)
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, IncidentAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !(16..=128).contains(&value.len())
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte)))
    {
        return Err(IncidentAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, IncidentAuthorityError> {
    single_header(headers, name).ok_or(IncidentAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn read_token(path: &Path) -> Result<String, IncidentAuthorityError> {
    let metadata =
        std::fs::metadata(path).map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() > 8_194 {
        return Err(IncidentAuthorityError::ConfigurationInvalid);
    }
    let value =
        std::fs::read_to_string(path).map_err(|_| IncidentAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(IncidentAuthorityError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceRequestBinding<'a, T: Serialize> {
    schema_version: &'static str,
    method: &'static str,
    path: &'a str,
    tenant_id: &'a TenantId,
    client_identity: &'a str,
    subject: &'a str,
    scope: &'a str,
    idempotency_key: &'a str,
    body: &'a T,
}

#[allow(clippy::too_many_arguments)]
fn service_request_digest<T: Serialize>(
    path: &str,
    tenant: &TenantId,
    client_identity: &str,
    subject: &str,
    scope: &str,
    idempotency_key: &str,
    body: &T,
) -> Result<String, IncidentAuthorityError> {
    if !path.starts_with('/')
        || !identifier(client_identity, 512)
        || !identifier(subject, 256)
        || scope != INCIDENT_DETECT_SCOPE
    {
        return Err(IncidentAuthorityError::RequestInvalid);
    }
    serde_jcs::to_vec(&ServiceRequestBinding {
        schema_version: "agenttrust.incident-service-request-binding.v1",
        method: "POST",
        path,
        tenant_id: tenant,
        client_identity,
        subject,
        scope,
        idempotency_key,
        body,
    })
    .map(|bytes| hex::encode(Sha256::digest(bytes)))
    .map_err(|_| IncidentAuthorityError::RequestInvalid)
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-incident-token-compare-v1");
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
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn evidence_reference(value: &str) -> bool {
    (value.starts_with("evidence://") || value.starts_with("urn:agenttrust:evidence:"))
        && value.len() <= 2_048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

fn validate_https_root(value: &url::Url) -> Result<(), IncidentAuthorityError> {
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(IncidentAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn validate_identities(
    identities: &BTreeSet<String>,
) -> Result<(), IncidentAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(IncidentAuthorityError::ConfigurationInvalid);
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

// Strict DER walk for subjectAltName. CommonName is intentionally ignored and certificates with
// multiple DNS/URI identities are rejected so a workload has one exact service identity.
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
mod server_tests {
    use super::*;

    #[test]
    fn route_scopes_are_distinct() {
        let scopes = BTreeSet::from([
            INCIDENT_DETECT_SCOPE,
            INCIDENT_MUTATE_SCOPE,
            INCIDENT_EXECUTE_SCOPE,
            INCIDENT_QUERY_SCOPE,
        ]);
        assert_eq!(scopes.len(), 4);
    }

    #[test]
    fn endpoints_must_be_https_roots() {
        assert!(validate_https_root(&url::Url::parse("https://authority.internal/").unwrap_or_else(|error| panic!("url: {error}"))).is_ok());
        assert!(validate_https_root(&url::Url::parse("https://authority.internal/v1").unwrap_or_else(|error| panic!("url: {error}"))).is_err());
        assert!(validate_https_root(&url::Url::parse("http://authority.internal/").unwrap_or_else(|error| panic!("url: {error}"))).is_err());
    }
}
