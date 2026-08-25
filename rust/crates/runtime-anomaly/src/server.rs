//! TLS 1.3/mTLS data plane and probe-only management plane for Runtime Anomaly.

use crate::authority::*;
use agent_trust_contracts::TenantId;
use axum::extract::{DefaultBodyLimit, Query, State};
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

pub const ANOMALY_SIGNAL_SCOPE: &str = "runtime-anomaly:signal";
pub const ANOMALY_MUTATE_SCOPE: &str = "runtime-anomaly:mutate";
pub const ANOMALY_EXECUTE_SCOPE: &str = "runtime-anomaly:execute";
pub const ANOMALY_QUERY_SCOPE: &str = "runtime-anomaly:query";

#[derive(Debug, Clone)]
pub struct RuntimeAnomalyServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub maximum_concurrency: usize,
}

#[derive(Debug, Clone)]
struct RuntimeAnomalyPeerIdentity(String);

#[derive(Clone)]
struct DataState {
    authority: RuntimeAnomalyAuthority,
    executor: RuntimeAnomalyExecutor,
    tokens: Arc<RuntimeAnomalyTokenAuthorizer>,
}

#[derive(Clone)]
struct ManagementState {
    authority: RuntimeAnomalyAuthority,
    executor: RuntimeAnomalyExecutor,
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
    source_id: Option<String>,
    token_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenAuthorization {
    client_identity: String,
    tenant_id: String,
    subject: String,
    scope: String,
    source_id: Option<String>,
    token_sha256: String,
}

pub struct RuntimeAnomalyTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl RuntimeAnomalyTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, RuntimeAnomalyAuthorityError> {
        validate_private_file(path, 1_048_576)?;
        let raw =
            std::fs::read(path).map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let document: TokenBindingDocument = serde_json::from_slice(&raw)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.runtime-anomaly-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            let signal_scope = binding.scope == ANOMALY_SIGNAL_SCOPE;
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    ANOMALY_SIGNAL_SCOPE
                        | ANOMALY_MUTATE_SCOPE
                        | ANOMALY_EXECUTE_SCOPE
                        | ANOMALY_QUERY_SCOPE
                )
                || signal_scope != binding.source_id.is_some()
                || binding
                    .source_id
                    .as_ref()
                    .is_some_and(|value| !identifier(value, 128))
                || !identifier(&binding.subject, 256)
                || !digest(&binding.token_sha256)
                || !canonical_uuid(&binding.tenant_id)
                || !credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    source_id: binding.source_id,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|value| &value.client_identity == identity)
        }) {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    pub fn tenants(&self) -> BTreeSet<TenantId> {
        self.bindings
            .iter()
            .filter_map(|binding| {
                canonical_uuid(&binding.tenant_id).then(|| TenantId(binding.tenant_id.clone()))
            })
            .collect()
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &TenantId,
        scope: &str,
        source_id: Option<&str>,
        headers: &HeaderMap,
    ) -> Result<String, RuntimeAnomalyAuthorityError> {
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| (16..=8_192).contains(&value.len()))
            .ok_or(RuntimeAnomalyAuthorityError::PrincipalDenied)?;
        let supplied = hex::encode(Sha256::digest(token.as_bytes()));
        let matches = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.client_identity == peer
                    && binding.tenant_id == tenant.0
                    && binding.scope == scope
                    && binding.source_id.as_deref() == source_id
                    && constant_time_equal(&supplied, &binding.token_sha256)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(RuntimeAnomalyAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }
}

pub fn data_router(
    authority: RuntimeAnomalyAuthority,
    executor: RuntimeAnomalyExecutor,
    tokens: Arc<RuntimeAnomalyTokenAuthorizer>,
    maximum_concurrency: usize,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/runtime-anomaly/signals", post(consume_signal))
        .route("/v1/runtime-anomaly/actions", post(submit_action))
        .route("/v1/runtime-anomaly/executions", post(execute_action))
        .route(
            "/v1/authoritative/runtime-anomaly/trajectories",
            get(authoritative_trajectories),
        )
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::new(Duration::from_secs(45)))
        .layer(ConcurrencyLimitLayer::new(maximum_concurrency))
        .with_state(DataState {
            authority,
            executor,
            tokens,
        })
}

pub fn management_router(
    authority: RuntimeAnomalyAuthority,
    executor: RuntimeAnomalyExecutor,
) -> Router {
    Router::new()
        .route("/live", get(management_live))
        .route("/ready", get(management_ready))
        .layer(DefaultBodyLimit::max(4_096))
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
        .layer(ConcurrencyLimitLayer::new(32))
        .with_state(ManagementState {
            authority,
            executor,
        })
}

async fn data_ready(State(state): State<DataState>) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.authority, &state.executor).await
}

async fn management_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schema_version": ANOMALY_READINESS_SCHEMA,
        "live": true
    }))
}

async fn management_ready(
    State(state): State<ManagementState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.authority, &state.executor).await
}

async fn readiness(
    authority: &RuntimeAnomalyAuthority,
    executor: &RuntimeAnomalyExecutor,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (authority_ready, executor_ready) = tokio::join!(authority.ready(), executor.ready());
    if !authority_ready || !executor_ready {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(serde_json::json!({
        "schema_version": ANOMALY_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "orchestrator_ready": true,
        "response_dependencies_ready": true,
        "evidence_authority_ready": true,
        "deterministic_rules_ready": true,
        "semantic_detector_required": false,
        "production_certification": false
    })))
}

async fn consume_signal(
    State(state): State<DataState>,
    Extension(RuntimeAnomalyPeerIdentity(peer)): Extension<RuntimeAnomalyPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<SignedRiskSignalEnvelope>,
) -> Result<Json<SignalIngestReceipt>, ApiError> {
    let tenant = exact_tenant(&headers, &body.signal.tenant_id.0)?;
    state.tokens.authorize(
        &peer,
        &tenant,
        ANOMALY_SIGNAL_SCOPE,
        Some(&body.source_id),
        &headers,
    )?;
    Ok(Json(state.authority.consume(tenant, &peer, body).await?))
}

async fn submit_action(
    State(state): State<DataState>,
    Extension(RuntimeAnomalyPeerIdentity(peer)): Extension<RuntimeAnomalyPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<RuntimeAnomalyCommandRequest>,
) -> Result<Json<RuntimeAnomalyActionReceipt>, ApiError> {
    let tenant = exact_tenant(&headers, &body.tenant_id.to_string())?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant, ANOMALY_MUTATE_SCOPE, None, &headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let digest = request_digest(
        "POST",
        "/v1/runtime-anomaly/actions",
        &tenant,
        &peer,
        &subject,
        ANOMALY_MUTATE_SCOPE,
        idempotency_key,
        &body,
    )?;
    if single_header(&headers, "x-agenttrust-request-digest") != Some(digest.as_str()) {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid.into());
    }
    Ok(Json(
        state
            .authority
            .submit_admin_action(tenant, subject, body, &digest, idempotency_key)
            .await?,
    ))
}

async fn execute_action(
    State(state): State<DataState>,
    Extension(RuntimeAnomalyPeerIdentity(peer)): Extension<RuntimeAnomalyPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<RuntimeAnomalyExecutorRequest>,
) -> Result<Json<RuntimeAnomalyMutationResult>, ApiError> {
    let tenant = exact_tenant(&headers, &body.command.tenant_id.to_string())?;
    let _executor_subject =
        state
            .tokens
            .authorize(&peer, &tenant, ANOMALY_EXECUTE_SCOPE, None, &headers)?;
    let binding = execution_binding_from_headers(&headers, tenant)?;
    Ok(Json(state.executor.execute(binding, body).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    after: Option<String>,
    limit: Option<i64>,
}

async fn authoritative_trajectories(
    State(state): State<DataState>,
    Extension(RuntimeAnomalyPeerIdentity(peer)): Extension<RuntimeAnomalyPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<AuthoritativeTrajectoryPage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant, ANOMALY_QUERY_SCOPE, None, &headers)?;
    Ok(Json(
        state
            .authority
            .authoritative_trajectories(&tenant, query.after.as_deref(), query.limit.unwrap_or(100))
            .await?,
    ))
}

fn execution_binding_from_headers(
    headers: &HeaderMap,
    tenant: TenantId,
) -> Result<RuntimeAnomalyExecutionBinding, RuntimeAnomalyAuthorityError> {
    Ok(RuntimeAnomalyExecutionBinding {
        schema_version: required_header(headers, "x-agenttrust-binding-schema")?.into(),
        tenant_id: tenant,
        action_hash: required_digest_header(headers, "x-agenttrust-action-hash")?.into(),
        ledger_execution_id: uuid_header(headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: uuid_header(headers, "x-agenttrust-ledger-event-id")?,
        ledger_event_digest: required_digest_header(headers, "x-agenttrust-ledger-event-digest")?
            .into(),
        fence_digest: required_digest_header(headers, "x-agenttrust-fence-digest")?.into(),
        resource_version: required_header(headers, "x-agenttrust-resource-version")?
            .parse::<u64>()
            .ok()
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)?,
        idempotency_key: required_idempotency_key(headers)?.into(),
        trace_id: required_header(headers, "x-agenttrust-trace-id")?.into(),
        policy_decision_id: required_header(headers, "x-agenttrust-policy-decision-id")?.into(),
        policy_decision_digest: required_digest_header(
            headers,
            "x-agenttrust-policy-decision-digest",
        )?
        .into(),
        authorization_evidence_ref: required_header(
            headers,
            "x-agenttrust-authorization-evidence-ref",
        )?
        .into(),
        authorization_evidence_digest: required_digest_header(
            headers,
            "x-agenttrust-authorization-evidence-digest",
        )?
        .into(),
    })
}

pub async fn serve(
    config: RuntimeAnomalyServerConfig,
    data: Router,
    management: Router,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !(1..=10_000).contains(&config.maximum_concurrency)
        || config.data_address.ip().is_loopback()
        || config.data_address == config.management_address
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
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
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
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
    type Service = AddExtension<S, RuntimeAnomalyPeerIdentity>;
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
                Extension(RuntimeAnomalyPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, RuntimeAnomalyAuthorityError> {
    for path in [ca_file, certificate_file] {
        validate_public_file(path, 4_194_304)?;
    }
    validate_private_file(private_key_file, 4_194_304)?;
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    if certificates.is_empty() || certificates.len() > 8 {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?
        .ok_or(RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(RuntimeAnomalyAuthorityError);

impl From<RuntimeAnomalyAuthorityError> for ApiError {
    fn from(value: RuntimeAnomalyAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            RuntimeAnomalyAuthorityError::PrincipalDenied
            | RuntimeAnomalyAuthorityError::SourceDenied
            | RuntimeAnomalyAuthorityError::SignatureInvalid => StatusCode::UNAUTHORIZED,
            RuntimeAnomalyAuthorityError::RequestInvalid => StatusCode::BAD_REQUEST,
            RuntimeAnomalyAuthorityError::NotFound => StatusCode::NOT_FOUND,
            RuntimeAnomalyAuthorityError::IdempotencyConflict
            | RuntimeAnomalyAuthorityError::StateConflict => StatusCode::CONFLICT,
            RuntimeAnomalyAuthorityError::DependencyUnavailable
            | RuntimeAnomalyAuthorityError::OutcomeUnknown
            | RuntimeAnomalyAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.runtime-anomaly-authority-error.v1",
                "error": self.0.to_string(),
                "trace_id": Uuid::new_v4().to_string(),
                "safe_summary": "runtime anomaly request was not completed"
            })),
        )
            .into_response()
    }
}

fn exact_tenant(
    headers: &HeaderMap,
    body_tenant: &str,
) -> Result<TenantId, RuntimeAnomalyAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant || !canonical_uuid(body_tenant) {
        return Err(RuntimeAnomalyAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, RuntimeAnomalyAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    if !canonical_uuid(value) {
        return Err(RuntimeAnomalyAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.into()))
}

fn uuid_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Uuid, RuntimeAnomalyAuthorityError> {
    let raw = required_header(headers, name)?;
    Uuid::parse_str(raw)
        .ok()
        .filter(|value| !value.is_nil() && value.to_string() == raw)
        .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn required_digest_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, RuntimeAnomalyAuthorityError> {
    let value = required_header(headers, name)?;
    if digest(value) {
        Ok(value)
    } else {
        Err(RuntimeAnomalyAuthorityError::RequestInvalid)
    }
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, RuntimeAnomalyAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !(16..=256).contains(&value.len())
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/'))
        })
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, RuntimeAnomalyAuthorityError> {
    single_header(headers, name).ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)
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
) -> Result<String, RuntimeAnomalyAuthorityError> {
    if method != "POST"
        || path != "/v1/runtime-anomaly/actions"
        || scope != ANOMALY_MUTATE_SCOPE
        || !identifier(client_identity, 512)
        || !identifier(subject, 256)
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    serde_jcs::to_vec(&RequestBinding {
        schema_version: "agenttrust.runtime-anomaly-service-request-binding.v1",
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
    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

pub fn validate_public_file(
    path: &Path,
    maximum_size: u64,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
    }
    Ok(())
}

fn validate_private_file(
    path: &Path,
    maximum_size: u64,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        let effective_gid = nix::unistd::Gid::effective().as_raw();
        let allowed = 0o400
            | if metadata.gid() == effective_gid {
                0o040
            } else {
                0
            };
        let readable = (metadata.uid() == effective_uid && mode & 0o400 != 0)
            || (metadata.gid() == effective_gid && mode & 0o040 != 0);
        if metadata.nlink() != 1 || !readable || mode & !allowed != 0 {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
    }
    Ok(())
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-runtime-anomaly-token-v1");
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

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), RuntimeAnomalyAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
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

// CommonName is intentionally ignored. A workload certificate has exactly one DNS or URI SAN.
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
    fn scopes_are_exact_and_non_interchangeable() {
        let scopes = BTreeSet::from([
            ANOMALY_SIGNAL_SCOPE,
            ANOMALY_MUTATE_SCOPE,
            ANOMALY_EXECUTE_SCOPE,
            ANOMALY_QUERY_SCOPE,
        ]);
        assert_eq!(scopes.len(), 4);
    }

    #[test]
    fn certificate_requires_exactly_one_supported_san() {
        assert!(certificate_subject_alt_names(&[]).is_err());
        assert!(validate_identities(&BTreeSet::from(["CN:legacy".into()])).is_err());
        assert!(
            validate_identities(&BTreeSet::from(["URI:spiffe://agenttrust/anomaly".into()]))
                .is_ok()
        );
    }
}
