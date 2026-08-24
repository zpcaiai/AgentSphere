//! TLS 1.3 enterprise ingress/executor service with exact SAN and scoped-token binding.

use crate::authority::*;
use crate::principal::HumanPrincipalKeyring;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{TenantId, human_principal_request_digest};
use axum::extract::{DefaultBodyLimit, State};
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
use serde::Deserialize;
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

pub const ENTERPRISE_READINESS_SCHEMA: &str = "agenttrust.enterprise-authority-readiness.v1";

#[derive(Debug, Clone)]
pub struct EnterpriseServerConfig {
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
struct EnterprisePeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    ingress: EnterpriseIngressAuthority,
    executor: EnterpriseExecutor,
    tokens: Arc<EnterpriseTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    service_subject: String,
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

pub struct EnterpriseTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl EnterpriseTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, EnterpriseAuthorityError> {
        validate_identities(allowed_identities)?;
        let raw =
            std::fs::read(path).map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(EnterpriseAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument = serde_json::from_slice(&raw)
            .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.enterprise-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(EnterpriseAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    "enterprise:mutate" | "enterprise:execute"
                )
                || !identifier(&binding.subject)
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
                return Err(EnterpriseAuthorityError::ConfigurationInvalid);
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
            ["enterprise:mutate", "enterprise:execute"]
                .iter()
                .any(|scope| {
                    !bindings
                        .iter()
                        .any(|binding| &binding.tenant_id == tenant && &binding.scope == scope)
                })
        }) {
            return Err(EnterpriseAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, EnterpriseAuthorityError> {
        let authorization = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| (16..=8_192).contains(&value.len()))
            .ok_or(EnterpriseAuthorityError::PrincipalDenied)?;
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
            return Err(EnterpriseAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }
}

pub fn router(
    ingress: EnterpriseIngressAuthority,
    executor: EnterpriseExecutor,
    tokens: Arc<EnterpriseTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    service_subject: String,
    maximum_authentication_age_seconds: i64,
) -> Router {
    let state = ServerState {
        ingress,
        executor,
        tokens,
        principal_keyring,
        service_subject,
        maximum_authentication_age_seconds,
    };
    Router::new()
        .route("/ready", get(ready))
        .route("/v1/enterprise/actions", post(submit_action))
        .route("/v1/enterprise/mutations", post(execute_mutation))
        .layer(DefaultBodyLimit::max(262_144))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

async fn ready(State(state): State<ServerState>) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.ingress_store_ready().await {
        return Err(ApiError(EnterpriseAuthorityError::DependencyUnavailable));
    }
    Ok(Json(serde_json::json!({
        "schema_version": ENTERPRISE_READINESS_SCHEMA,
        "ready": true
    })))
}

async fn submit_action(
    State(state): State<ServerState>,
    Extension(EnterprisePeerIdentity(peer)): Extension<EnterprisePeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<EnterpriseMutationRequest>,
) -> Result<(StatusCode, Json<EnterpriseActionReceipt>), ApiError> {
    let tenant = exact_tenant(&headers, body.tenant_id.to_string())?;
    let service_subject =
        state
            .tokens
            .authorize(&peer, &tenant.0, "enterprise:mutate", &headers)?;
    if service_subject != state.service_subject {
        return Err(ApiError(EnterpriseAuthorityError::PrincipalDenied));
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = human_principal_request_digest(
        "POST",
        "/v1/enterprise/actions",
        &tenant,
        &peer,
        &service_subject,
        "enterprise:mutate",
        idempotency_key,
        &body,
    )
    .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    let assertion = single_header(&headers, "x-agenttrust-human-assertion")
        .ok_or(EnterpriseAuthorityError::PrincipalDenied)?;
    let principal = state.principal_keyring.verify_encoded(
        assertion,
        &tenant,
        &peer,
        &service_subject,
        "enterprise:mutate",
        &request_digest,
        state.maximum_authentication_age_seconds,
        Utc::now(),
    )?;
    let receipt = state
        .ingress
        .submit(&principal, body, &request_digest, idempotency_key)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_mutation(
    State(state): State<ServerState>,
    Extension(EnterprisePeerIdentity(peer)): Extension<EnterprisePeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<EnterpriseExecutorRequest>,
) -> Result<Json<EnterpriseMutationResult>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant.0, "enterprise:execute", &headers)?;
    let binding = EnterpriseExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.to_string(),
        ledger_execution_id: required_header(&headers, "x-agenttrust-ledger-execution-id")?
            .to_string(),
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.to_string(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?.to_string(),
        idempotency_key: required_idempotency_key(&headers)?.to_string(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.to_string(),
    };
    Ok(Json(state.executor.execute(binding, body).await?))
}

impl ServerState {
    async fn ingress_store_ready(&self) -> bool {
        // Both ingress and executor use the same authority pool/independent DB role.
        self.ingress.ready().await
    }
}

#[derive(Clone)]
pub struct HttpEnterpriseOrchestrator {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
}

impl HttpEnterpriseOrchestrator {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
    ) -> Result<Self, EnterpriseAuthorityError> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || !token_file.is_absolute()
        {
            return Err(EnterpriseAuthorityError::ConfigurationInvalid);
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

#[async_trait::async_trait]
impl EnterpriseOrchestratorPort for HttpEnterpriseOrchestrator {
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &agent_trust_gateway::InboundEnvelope,
    ) -> Result<EnterpriseActionReceipt, EnterpriseAuthorityError> {
        let token = read_token(&self.token_file)?;
        let url = self
            .endpoint
            .join("v1/actions")
            .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("content-type", "application/json")
            .json(envelope)
            .send()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(EnterpriseAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return Err(EnterpriseAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() {
            return Err(EnterpriseAuthorityError::DependencyUnavailable);
        }
        let accepted: OrchestratorAcceptance = serde_json::from_slice(&bytes)
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        if accepted.schema_version != "agenttrust.action-acceptance.v1" {
            return Err(EnterpriseAuthorityError::DependencyUnavailable);
        }
        let receipt = EnterpriseActionReceipt {
            schema_version: ENTERPRISE_ACTION_RECEIPT_SCHEMA.into(),
            action_id: accepted.action_id,
            task_id: accepted.task_id,
            accepted: accepted.accepted,
            start_requested: accepted.start_requested,
            execution_pending: accepted.execution_pending,
            ingress_digest: accepted.ingress_digest,
            evidence_ref: accepted.evidence_ref,
            evidence_digest: accepted.evidence_digest,
        };
        // The acceptance evidence proves durable workflow admission only.  Completion remains
        // gated on the separate signed Evidence authority receipt emitted after execution.
        Ok(receipt)
    }
}

pub async fn serve(
    config: EnterpriseServerConfig,
    application: Router,
    readiness: EnterpriseIngressAuthority,
) -> Result<(), EnterpriseAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !identifier(&config.service_subject)
        || !(60..=86_400).contains(&config.maximum_authentication_age_seconds)
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(EnterpriseAuthorityError::ConfigurationInvalid);
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
        .with_state(readiness);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn management_ready(
    State(readiness): State<EnterpriseIngressAuthority>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !readiness.ready().await {
        return Err(ApiError(EnterpriseAuthorityError::DependencyUnavailable));
    }
    Ok(Json(serde_json::json!({
        "schema_version": ENTERPRISE_READINESS_SCHEMA,
        "ready": true
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
    type Service = AddExtension<S, EnterprisePeerIdentity>;
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
                Extension(EnterprisePeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, EnterpriseAuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(EnterpriseAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?
        .ok_or(EnterpriseAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(EnterpriseAuthorityError);

impl From<EnterpriseAuthorityError> for ApiError {
    fn from(value: EnterpriseAuthorityError) -> Self {
        Self(value)
    }
}

impl From<crate::principal::PrincipalAssertionError> for ApiError {
    fn from(_: crate::principal::PrincipalAssertionError) -> Self {
        Self(EnterpriseAuthorityError::PrincipalDenied)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            EnterpriseAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            EnterpriseAuthorityError::RequestInvalid => StatusCode::BAD_REQUEST,
            EnterpriseAuthorityError::IdempotencyConflict
            | EnterpriseAuthorityError::StateConflict => StatusCode::CONFLICT,
            EnterpriseAuthorityError::OutcomeUnknown
            | EnterpriseAuthorityError::DependencyUnavailable
            | EnterpriseAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.enterprise-authority-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn exact_tenant(
    headers: &HeaderMap,
    body_tenant: String,
) -> Result<TenantId, EnterpriseAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant {
        return Err(EnterpriseAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, EnterpriseAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| EnterpriseAuthorityError::PrincipalDenied)?;
    if parsed.to_string() != value {
        return Err(EnterpriseAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.to_string()))
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, EnterpriseAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !(16..=128).contains(&value.len())
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte)))
    {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, EnterpriseAuthorityError> {
    single_header(headers, name).ok_or(EnterpriseAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn read_token(path: &Path) -> Result<String, EnterpriseAuthorityError> {
    let metadata =
        std::fs::metadata(path).map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() > 8_194 {
        return Err(EnterpriseAuthorityError::ConfigurationInvalid);
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(EnterpriseAuthorityError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-enterprise-token-compare-v1");
    let tag = hmac::sign(&key, second.as_bytes());
    hmac::verify(&key, first.as_bytes(), tag.as_ref()).is_ok()
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), EnterpriseAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(EnterpriseAuthorityError::ConfigurationInvalid);
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

// Minimal strict DER walk for subjectAltName. CommonName is intentionally never consulted.
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
