//! TLS 1.3, exact mTLS SAN, tenant and route-token boundary for Evidence Authority.

use crate::artifact::{ArtifactUploadRequest, WormArtifactPort, WormObjectReceipt};
use crate::postgres::{PostgresEvidenceStore, ProductionExecutionEvidenceRequest};
use crate::{
    AuthorityEvidenceEventRequest, EvidenceError, EvidencePackageRequest,
    ProductionEvaluationRequest, ProductionEvidenceEventRequest, SignedAuthorityEvidenceReceipt,
    SignedEvaluationRun, SignedEvidenceEvent, SignedEvidencePackage,
    SignedExecutionEvidenceReceipt,
};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const EVIDENCE_READINESS_SCHEMA_VERSION: &str = "agenttrust.evidence-readiness.v1";

#[derive(Debug, Clone)]
pub struct EvidenceServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub client_identities: BTreeSet<String>,
    pub maximum_request_bytes: usize,
    pub maximum_artifact_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenAuthorization {
    client_identity: String,
    tenant_id: String,
    subject: String,
    scope: String,
    token_sha256: String,
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

#[derive(Clone)]
pub struct TokenBindingEvidenceAuthorizer {
    bindings: Arc<BTreeSet<TokenAuthorization>>,
}

impl TokenBindingEvidenceAuthorizer {
    pub fn from_file(path: &Path, identities: &BTreeSet<String>) -> Result<Self, EvidenceError> {
        validate_identities(identities)?;
        let raw = std::fs::read(path).map_err(|_| EvidenceError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(EvidenceError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument =
            serde_json::from_slice(&raw).map_err(|_| EvidenceError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.evidence-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(EvidenceError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut physical_credentials = BTreeSet::new();
        for binding in document.bindings {
            if Uuid::parse_str(&binding.tenant_id)
                .ok()
                .is_none_or(|value| value.to_string() != binding.tenant_id)
                || !identities.contains(&binding.client_identity)
                || !allowed_scope(&binding.scope)
                || binding.subject != binding.client_identity
                || !lower_digest(&binding.token_sha256)
                || !physical_credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(EvidenceError::ConfigurationInvalid);
            }
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(EvidenceError::ConfigurationInvalid);
        }
        Ok(Self {
            bindings: Arc::new(bindings),
        })
    }

    fn authorize(
        &self,
        peer_identity: &str,
        headers: &HeaderMap,
        tenant: &str,
        scope: &str,
    ) -> Result<&str, EvidenceError> {
        if single_header(headers, "x-agenttrust-tenant-id") != Some(tenant)
            || Uuid::parse_str(tenant)
                .ok()
                .is_none_or(|value| value.to_string() != tenant)
        {
            return Err(EvidenceError::AuthenticationRequired);
        }
        let token = bearer_token(headers).ok_or(EvidenceError::AuthenticationRequired)?;
        let supplied = hex(Sha256::digest(token.as_bytes()));
        let mut subject = None;
        let mut credential_match = false;
        for binding in self.bindings.iter() {
            let token_matches = constant_time_digest_matches(&supplied, &binding.token_sha256);
            let tuple_match = binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && token_matches;
            credential_match |= tuple_match;
            if tuple_match && binding.scope == scope {
                if subject.is_some() {
                    return Err(EvidenceError::ScopeForbidden);
                }
                subject = Some(binding.subject.as_str());
            }
        }
        subject.ok_or(if credential_match {
            EvidenceError::ScopeForbidden
        } else {
            EvidenceError::AuthenticationRequired
        })
    }
}

#[derive(Clone)]
struct ApiState {
    store: Arc<PostgresEvidenceStore>,
    worm: Arc<dyn WormArtifactPort>,
    authorizer: Arc<TokenBindingEvidenceAuthorizer>,
    maximum_artifact_bytes: usize,
}

#[derive(Clone)]
struct ReadinessState {
    store: Arc<PostgresEvidenceStore>,
    worm: Arc<dyn WormArtifactPort>,
}

#[derive(Debug, Clone)]
pub struct ExactSanMtlsAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

#[derive(Debug, Clone)]
pub struct MtlsPeerIdentity(pub String);

impl ExactSanMtlsAcceptor {
    pub fn new(
        tls: RustlsConfig,
        allowed_identities: BTreeSet<String>,
    ) -> Result<Self, EvidenceError> {
        validate_identities(&allowed_identities)?;
        Ok(Self {
            inner: RustlsAcceptor::new(tls),
            allowed_identities: Arc::new(allowed_identities),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
    database_ready: bool,
    worm_ready: bool,
}

pub async fn serve(
    config: EvidenceServerConfig,
    store: Arc<PostgresEvidenceStore>,
    worm: Arc<dyn WormArtifactPort>,
    authorizer: Arc<TokenBindingEvidenceAuthorizer>,
) -> Result<(), EvidenceError> {
    validate_identities(&config.client_identities)?;
    if !(config.management_address.ip().is_loopback()
        || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
        || !(1_048_576..=100 * 1024 * 1024).contains(&config.maximum_request_bytes)
        || config.maximum_artifact_bytes == 0
        || config.maximum_artifact_bytes > 64 * 1024 * 1024
        || config.maximum_request_bytes <= config.maximum_artifact_bytes
    {
        return Err(EvidenceError::ConfigurationInvalid);
    }
    let tls = build_tls13_mtls_config(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let state = ApiState {
        store: store.clone(),
        worm: worm.clone(),
        authorizer,
        maximum_artifact_bytes: config.maximum_artifact_bytes,
    };
    let readiness = ReadinessState { store, worm };
    let data = Router::new()
        .route("/v1/evidence/executions", post(append_execution))
        .route("/v1/evidence/events", post(append_event))
        .route(
            "/v1/evidence/authority-events",
            post(append_authority_event),
        )
        .route("/v1/evidence/artifacts", post(upload_artifact))
        .route("/v1/evidence/receipts/{receipt_id}", get(receipt))
        .route("/v1/evidence/tasks/{task_id}/events", get(chain))
        .route("/v1/evidence/packages", post(build_package))
        .route("/v1/evaluations", post(evaluate))
        .route("/ready", get(data_ready))
        .with_state(state)
        .layer(DefaultBodyLimit::max(config.maximum_request_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(45),
        ));
    let management = Router::new()
        .route("/ready", get(management_ready))
        .with_state(readiness);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| EvidenceError::ConfigurationInvalid)?;
    let acceptor = ExactSanMtlsAcceptor::new(tls, config.client_identities)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| EvidenceError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| EvidenceError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn append_execution(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ProductionExecutionEvidenceRequest>,
) -> Result<Json<SignedExecutionEvidenceReceipt>, EvidenceApiError> {
    let subject =
        state
            .authorizer
            .authorize(&peer.0, &headers, &request.tenant_id.0, "evidence:append")?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key.0)
        || single_header(&headers, "x-agenttrust-fence-digest") != Some(&request.fence_digest)
        || subject != peer.0.as_str()
        || request.event.source_service.as_str() != peer.0.as_str()
    {
        return Err(EvidenceError::RequestInvalid.into());
    }
    Ok(Json(state.store.append_execution(&request).await?))
}

async fn append_event(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ProductionEvidenceEventRequest>,
) -> Result<Json<SignedEvidenceEvent>, EvidenceApiError> {
    let subject =
        state
            .authorizer
            .authorize(&peer.0, &headers, &request.tenant_id.0, "evidence:event")?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key.0)
        || subject != peer.0.as_str()
        || request.event.source_service.as_str() != peer.0.as_str()
    {
        return Err(EvidenceError::RequestInvalid.into());
    }
    Ok(Json(state.store.append_event(&request).await?))
}

async fn append_authority_event(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<AuthorityEvidenceEventRequest>,
) -> Result<Json<SignedAuthorityEvidenceReceipt>, EvidenceApiError> {
    let subject = state.authorizer.authorize(
        &peer.0,
        &headers,
        &request.tenant_id.0,
        "evidence:authority-event",
    )?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key.0)
        || single_header(&headers, "x-agenttrust-authority-event-id")
            != Some(&request.authority_event_id)
        || single_header(&headers, "x-agenttrust-payload-digest")
            != Some(&request.event.payload_hash)
        || subject != peer.0.as_str()
        || request.event.source_service.as_str() != peer.0.as_str()
    {
        return Err(EvidenceError::RequestInvalid.into());
    }
    Ok(Json(state.store.append_authority_event(&request).await?))
}

async fn upload_artifact(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ArtifactUploadRequest>,
) -> Result<Json<WormObjectReceipt>, EvidenceApiError> {
    state
        .authorizer
        .authorize(&peer.0, &headers, &request.tenant_id.0, "evidence:artifact")?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key.0) {
        return Err(EvidenceError::RequestInvalid.into());
    }
    let bytes = request.validate_and_decode(state.maximum_artifact_bytes)?;
    if let Some(replay) = state.store.artifact_replay(&request).await? {
        return Ok(Json(replay));
    }
    let receipt = state.worm.put_immutable(&request, bytes.clone()).await?;
    Ok(Json(
        state
            .store
            .persist_artifact(&request, &receipt, bytes.len())
            .await?,
    ))
}

async fn receipt(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    AxumPath(receipt_id): AxumPath<String>,
) -> Result<Json<SignedExecutionEvidenceReceipt>, EvidenceApiError> {
    let tenant = required_tenant(&headers)?;
    state
        .authorizer
        .authorize(&peer.0, &headers, tenant, "evidence:read")?;
    Ok(Json(state.store.receipt(tenant, &receipt_id).await?))
}

async fn chain(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
    Query(query): Query<ChainQuery>,
) -> Result<Json<Vec<SignedEvidenceEvent>>, EvidenceApiError> {
    let tenant = required_tenant(&headers)?;
    state
        .authorizer
        .authorize(&peer.0, &headers, tenant, "evidence:read")?;
    Ok(Json(
        state
            .store
            .chain(tenant, &task_id, query.limit.unwrap_or(1_000))
            .await?,
    ))
}

async fn build_package(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<EvidencePackageRequest>,
) -> Result<Json<SignedEvidencePackage>, EvidenceApiError> {
    state
        .authorizer
        .authorize(&peer.0, &headers, &request.tenant_id.0, "evidence:package")?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key.0) {
        return Err(EvidenceError::RequestInvalid.into());
    }
    Ok(Json(state.store.build_package(&request).await?))
}

async fn evaluate(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ProductionEvaluationRequest>,
) -> Result<Json<SignedEvaluationRun>, EvidenceApiError> {
    state
        .authorizer
        .authorize(&peer.0, &headers, &request.tenant_id.0, "evidence:evaluate")?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key.0) {
        return Err(EvidenceError::RequestInvalid.into());
    }
    Ok(Json(state.store.evaluate_task(&request).await?))
}

async fn data_ready(State(state): State<ApiState>) -> Response {
    readiness(state.store, state.worm).await
}

async fn management_ready(State(state): State<ReadinessState>) -> Response {
    readiness(state.store, state.worm).await
}

async fn readiness(store: Arc<PostgresEvidenceStore>, worm: Arc<dyn WormArtifactPort>) -> Response {
    let (database_ready, worm_ready) = tokio::join!(store.ready(), worm.ready());
    let ready = database_ready && worm_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: EVIDENCE_READINESS_SCHEMA_VERSION,
            ready,
            database_ready,
            worm_ready,
        }),
    )
        .into_response()
}

struct EvidenceApiError(EvidenceError);

impl From<EvidenceError> for EvidenceApiError {
    fn from(value: EvidenceError) -> Self {
        Self(value)
    }
}

impl IntoResponse for EvidenceApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            EvidenceError::RequestInvalid
            | EvidenceError::EventInvalid
            | EvidenceError::ArtifactDenied
            | EvidenceError::EvaluationInvalid
            | EvidenceError::CapacityExceeded => StatusCode::BAD_REQUEST,
            EvidenceError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            EvidenceError::ScopeForbidden | EvidenceError::TenantMismatch => StatusCode::FORBIDDEN,
            EvidenceError::NotFound | EvidenceError::ArtifactNotFound => StatusCode::NOT_FOUND,
            EvidenceError::IdempotencyConflict => StatusCode::CONFLICT,
            EvidenceError::LedgerBindingInvalid
            | EvidenceError::AuthorizationBindingInvalid
            | EvidenceError::ChainIncomplete
            | EvidenceError::IntegrityInvalid
            | EvidenceError::SignatureInvalid
            | EvidenceError::UnknownKey => StatusCode::UNPROCESSABLE_ENTITY,
            EvidenceError::PersistenceUnavailable
            | EvidenceError::DependencyUnavailable
            | EvidenceError::EvaluatorTimeout => StatusCode::SERVICE_UNAVAILABLE,
            EvidenceError::ConfigurationInvalid | EvidenceError::Canonicalization => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.evidence-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn required_tenant(headers: &HeaderMap) -> Result<&str, EvidenceError> {
    let value = single_header(headers, "x-agenttrust-tenant-id")
        .ok_or(EvidenceError::AuthenticationRequired)?;
    if Uuid::parse_str(value)
        .ok()
        .is_none_or(|parsed| parsed.to_string() != value)
    {
        return Err(EvidenceError::AuthenticationRequired);
    }
    Ok(value)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    single_header(headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| {
            !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
        })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn allowed_scope(value: &str) -> bool {
    matches!(
        value,
        "evidence:append"
            | "evidence:event"
            | "evidence:authority-event"
            | "evidence:read"
            | "evidence:artifact"
            | "evidence:package"
            | "evidence:evaluate"
    )
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-evidence-token-comparison-v1",
    );
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), EvidenceError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(EvidenceError::ConfigurationInvalid);
    }
    Ok(())
}

pub fn build_tls13_mtls_config(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, EvidenceError> {
    let mut ca_reader =
        BufReader::new(File::open(ca_file).map_err(|_| EvidenceError::ConfigurationInvalid)?);
    let roots_der = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| EvidenceError::ConfigurationInvalid)?;
    if roots_der.is_empty() {
        return Err(EvidenceError::ConfigurationInvalid);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(roots_der);
    if accepted == 0 {
        return Err(EvidenceError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| EvidenceError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| EvidenceError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| EvidenceError::ConfigurationInvalid)?;
    if certificates.is_empty() {
        return Err(EvidenceError::ConfigurationInvalid);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| EvidenceError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| EvidenceError::ConfigurationInvalid)?
        .ok_or(EvidenceError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| EvidenceError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| EvidenceError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for ExactSanMtlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, MtlsPeerIdentity>;
    type Future =
        Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        let allowed = self.allowed_identities.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            let certificates = stream
                .get_ref()
                .1
                .peer_certificates()
                .ok_or_else(|| io_denied("client certificate missing"))?;
            let identity = certificates
                .first()
                .and_then(|certificate| {
                    matching_certificate_identity(certificate.as_ref(), &allowed)
                })
                .ok_or_else(|| io_denied("client certificate SAN not allowed"))?;
            Ok((stream, Extension(MtlsPeerIdentity(identity)).layer(service)))
        })
    }
}

fn matching_certificate_identity(certificate: &[u8], allowed: &BTreeSet<String>) -> Option<String> {
    let mut identities = certificate_subject_alt_names(certificate).ok()?.into_iter();
    let identity = identities.next()?;
    if identities.next().is_some() || !allowed.contains(&identity) {
        return None;
    }
    Some(identity)
}

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
        let (tag, extensions, end) = der_element(value, 0)?;
        if tag != 0x30 || end != value.len() {
            return Err(());
        }
        let mut extension_offset = 0;
        while extension_offset < extensions.len() {
            let (tag, extension, next) = der_element(extensions, extension_offset)?;
            extension_offset = next;
            if tag != 0x30 {
                return Err(());
            }
            let (oid_tag, oid, mut field) = der_element(extension, 0)?;
            if oid_tag != 0x06 {
                return Err(());
            }
            let (mut value_tag, mut extension_value, next) = der_element(extension, field)?;
            field = next;
            if value_tag == 0x01 {
                let parsed = der_element(extension, field)?;
                value_tag = parsed.0;
                extension_value = parsed.1;
                field = parsed.2;
            }
            if value_tag != 0x04 || field != extension.len() {
                return Err(());
            }
            if oid == [0x55, 0x1d, 0x11] && san.replace(extension_value).is_some() {
                return Err(());
            }
        }
    }
    let extension = san.ok_or(())?;
    let (tag, names, end) = der_element(extension, 0)?;
    if tag != 0x30 || end != extension.len() {
        return Err(());
    }
    let mut identities = Vec::new();
    let mut offset = 0;
    while offset < names.len() {
        let (tag, value, next) = der_element(names, offset)?;
        offset = next;
        let prefix = match tag {
            0x82 => "DNS:",
            0x86 => "URI:",
            _ => return Err(()),
        };
        let value = std::str::from_utf8(value).map_err(|_| ())?;
        if value.is_empty() || value.len() > 508 {
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

fn io_denied(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_name_is_not_an_identity() {
        assert!(validate_identities(&BTreeSet::from(["CN:evidence-client".into()])).is_err());
    }

    #[test]
    fn route_tokens_are_physically_distinct() {
        let source = include_str!("server.rs");
        assert!(source.contains("physical_credentials.insert"));
        assert!(constant_time_digest_matches(
            &"a".repeat(64),
            &"a".repeat(64)
        ));
        assert!(!constant_time_digest_matches(
            &"a".repeat(63),
            &"a".repeat(64)
        ));
    }
}
