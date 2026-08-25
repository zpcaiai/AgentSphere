//! TLS 1.3/mTLS Context Governance data plane and loopback management plane.

use crate::authority::*;
use agent_trust_contracts::TenantId;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use nix::unistd::Uid;
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const CONTEXT_MUTATE_SCOPE: &str = "context:mutate";
pub const CONTEXT_EXECUTE_SCOPE: &str = "context:execute";
pub const CONTEXT_RETRIEVE_SCOPE: &str = "context:retrieve";
pub const CONTEXT_READ_SCOPE: &str = "context:read";

#[derive(Debug, Clone)]
pub struct ContextServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub recovery_interval_seconds: u64,
}

#[derive(Debug, Clone)]
struct ContextPeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    ingress: ContextIngressAuthority,
    executor: ContextExecutor,
    retrieval: RetrievalAuthorizer,
    tokens: Arc<ContextTokenAuthorizer>,
}

#[derive(Clone)]
struct ReadinessState {
    ingress: ContextIngressAuthority,
    executor: ContextExecutor,
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

pub struct ContextTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl ContextTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, ContextAuthorityError> {
        validate_identities(allowed_identities)?;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
        if !path.is_absolute()
            || !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        let raw = std::fs::read(path).map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument = strict_json(&raw)?;
        if document.schema_version != "agenttrust.context-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut physical_credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    CONTEXT_MUTATE_SCOPE
                        | CONTEXT_EXECUTE_SCOPE
                        | CONTEXT_RETRIEVE_SCOPE
                        | CONTEXT_READ_SCOPE
                )
                || !identifier(&binding.subject, 256)
                || !digest(&binding.token_sha256)
                || !Uuid::parse_str(&binding.tenant_id)
                    .is_ok_and(|value| value.to_string() == binding.tenant_id)
                // One physical bearer credential cannot cross SAN, tenant, subject, or scope.
                || !physical_credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(ContextAuthorityError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, ContextAuthorityError> {
        let authorization = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=8192).contains(&value.len())
                    && !value.bytes().any(|byte| byte.is_ascii_whitespace())
            })
            .ok_or(ContextAuthorityError::PrincipalDenied)?;
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
            return Err(ContextAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }

    fn tenants(&self) -> BTreeSet<TenantId> {
        self.bindings
            .iter()
            .map(|binding| TenantId(binding.tenant_id.clone()))
            .collect()
    }
}

pub fn router(
    ingress: ContextIngressAuthority,
    executor: ContextExecutor,
    retrieval: RetrievalAuthorizer,
    tokens: Arc<ContextTokenAuthorizer>,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/context/actions", post(submit_action))
        .route("/v1/context/executions", post(execute_mutation))
        .route("/v1/context/retrievals", post(retrieve_context))
        .route(
            "/v1/authoritative/context/resources",
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
            retrieval,
            tokens,
        })
}

async fn data_ready(State(state): State<ServerState>) -> Result<Json<Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn submit_action(
    State(state): State<ServerState>,
    Extension(ContextPeerIdentity(peer)): Extension<ContextPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<ContextActionReceipt>), ApiError> {
    require_json_content_type(&headers)?;
    let request: ContextCommandRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, CONTEXT_MUTATE_SCOPE, &headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = service_request_digest(
        "/v1/context/actions",
        &tenant,
        &peer,
        &subject,
        CONTEXT_MUTATE_SCOPE,
        idempotency_key,
        &request,
    )?;
    let receipt = state
        .ingress
        .submit(tenant, subject, request, &request_digest, idempotency_key)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_mutation(
    State(state): State<ServerState>,
    Extension(ContextPeerIdentity(peer)): Extension<ContextPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ContextMutationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: ContextExecutorRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.command.tenant_id)?;
    let executor_subject =
        state
            .tokens
            .authorize(&peer, &tenant.0, CONTEXT_EXECUTE_SCOPE, &headers)?;
    if executor_subject != peer {
        return Err(ContextAuthorityError::PrincipalDenied.into());
    }
    let binding = ContextExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.into(),
        ledger_execution_id: parse_uuid_header(&headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: parse_uuid_header(&headers, "x-agenttrust-ledger-entry-id")?,
        ledger_event_digest: required_header(&headers, "x-agenttrust-ledger-entry-digest")?.into(),
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.into(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?
            .parse()
            .map_err(|_| ContextAuthorityError::RequestInvalid)?,
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
    Ok(Json(state.executor.execute(binding, request).await?))
}

async fn retrieve_context(
    State(state): State<ServerState>,
    Extension(ContextPeerIdentity(peer)): Extension<ContextPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ContextRetrievalResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: ContextRetrievalRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, CONTEXT_RETRIEVE_SCOPE, &headers)?;
    if subject != request.subject {
        return Err(ContextAuthorityError::PrincipalDenied.into());
    }
    let binding = RetrievalAuthorizationBinding {
        tenant_id: tenant,
        client_subject: subject,
        policy_decision_id: required_header(&headers, "x-agenttrust-policy-decision-id")?.into(),
        policy_decision_digest: required_header(&headers, "x-agenttrust-policy-decision-digest")?
            .into(),
        policy_evidence_ref: required_header(&headers, "x-agenttrust-authorization-evidence-ref")?
            .into(),
        policy_evidence_digest: required_header(
            &headers,
            "x-agenttrust-authorization-evidence-digest",
        )?
        .into(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.into(),
    };
    Ok(Json(state.retrieval.retrieve(binding, request).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextPageQuery {
    after: Option<String>,
    limit: Option<i64>,
}

async fn authoritative_resources(
    State(state): State<ServerState>,
    Extension(ContextPeerIdentity(peer)): Extension<ContextPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<ContextPageQuery>,
) -> Result<Json<AuthoritativeContextPage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state
        .tokens
        .authorize(&peer, &tenant.0, CONTEXT_READ_SCOPE, &headers)?;
    Ok(Json(
        state
            .ingress
            .authoritative_page(&tenant, query.after.as_deref(), query.limit.unwrap_or(100))
            .await?,
    ))
}

pub async fn serve(
    config: ContextServerConfig,
    application: Router,
    tokens: Arc<ContextTokenAuthorizer>,
    readiness_ingress: ContextIngressAuthority,
    readiness_executor: ContextExecutor,
) -> Result<(), ContextAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !(5..=300).contains(&config.recovery_interval_seconds)
        || config.data_address.ip().is_loopback()
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(ContextAuthorityError::ConfigurationInvalid);
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
        .route("/live", get(management_live))
        .route("/ready", get(management_ready))
        .with_state(ReadinessState {
            ingress: readiness_ingress.clone(),
            executor: readiness_executor.clone(),
        });
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    let recovery_tenants = tokens.tenants();
    let recovery_executor = readiness_executor;
    let recovery_interval = config.recovery_interval_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(recovery_interval));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            for tenant in &recovery_tenants {
                let _ = recovery_executor.recover_pending_evidence(tenant, 25).await;
            }
        }
    });
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn management_live() -> Json<Value> {
    Json(serde_json::json!({
        "schema_version": CONTEXT_READINESS_SCHEMA,
        "live": true
    }))
}

async fn management_ready(State(state): State<ReadinessState>) -> Result<Json<Value>, ApiError> {
    readiness(&state.ingress, &state.executor).await
}

async fn readiness(
    ingress: &ContextIngressAuthority,
    executor: &ContextExecutor,
) -> Result<Json<Value>, ApiError> {
    let (ingress_ready, executor_ready) = tokio::join!(ingress.ready(), executor.ready());
    if !ingress_ready || !executor_ready {
        return Err(ContextAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(serde_json::json!({
        "schema_version": CONTEXT_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "orchestrator_ready": true,
        "object_store_ready": true,
        "vector_index_ready": true,
        "cache_ready": true,
        "supply_chain_ready": true,
        "legal_hold_ready": true,
        "poisoning_detector_ready": true,
        "evidence_ready": true
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
    type Service = AddExtension<S, ContextPeerIdentity>;
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
                Extension(ContextPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, ContextAuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| ContextAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(ContextAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| ContextAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| ContextAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?
        .ok_or(ContextAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(ContextAuthorityError);

impl From<ContextAuthorityError> for ApiError {
    fn from(value: ContextAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ContextAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            ContextAuthorityError::RequestInvalid => StatusCode::BAD_REQUEST,
            ContextAuthorityError::NotFound => StatusCode::NOT_FOUND,
            ContextAuthorityError::IdempotencyConflict
            | ContextAuthorityError::StateConflict
            | ContextAuthorityError::SupplyChainDenied
            | ContextAuthorityError::LegalHoldBlocked
            | ContextAuthorityError::PoisoningDetected => StatusCode::CONFLICT,
            ContextAuthorityError::DependencyUnavailable
            | ContextAuthorityError::OutcomeUnknown
            | ContextAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.context-authority-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn exact_tenant(headers: &HeaderMap, body_tenant: Uuid) -> Result<TenantId, ContextAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant.to_string() {
        return Err(ContextAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, ContextAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed = Uuid::parse_str(value).map_err(|_| ContextAuthorityError::PrincipalDenied)?;
    if parsed.to_string() != value {
        return Err(ContextAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.into()))
}

fn parse_uuid_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Uuid, ContextAuthorityError> {
    let value = required_header(headers, name)?;
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(ContextAuthorityError::RequestInvalid)
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, ContextAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !valid_idempotency_key(value) {
        return Err(ContextAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, ContextAuthorityError> {
    single_header(headers, name).ok_or(ContextAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), ContextAuthorityError> {
    if single_header(headers, "content-type") != Some("application/json") {
        return Err(ContextAuthorityError::RequestInvalid);
    }
    Ok(())
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
) -> Result<String, ContextAuthorityError> {
    if path != "/v1/context/actions"
        || !identifier(client_identity, 512)
        || !identifier(subject, 256)
        || scope != CONTEXT_MUTATE_SCOPE
    {
        return Err(ContextAuthorityError::RequestInvalid);
    }
    canonical_digest(&ServiceRequestBinding {
        schema_version: "agenttrust.context-service-request-binding.v1",
        method: "POST",
        path,
        tenant_id: tenant,
        client_identity,
        subject,
        scope,
        idempotency_key,
        body,
    })
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-context-token-compare-v1");
    let tag = hmac::sign(&key, second.as_bytes());
    hmac::verify(&key, first.as_bytes(), tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), ContextAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(ContextAuthorityError::ConfigurationInvalid);
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

// Strict DER walk for subjectAltName. CommonName is deliberately ignored. Certificates with
// multiple DNS/URI identities are rejected so one connection maps to one workload identity.
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

fn strict_json<T: DeserializeOwned>(raw: &[u8]) -> Result<T, ContextAuthorityError> {
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err(ContextAuthorityError::RequestInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| ContextAuthorityError::RequestInvalid)?;
    deserializer
        .end()
        .map_err(|_| ContextAuthorityError::RequestInvalid)?;
    serde_json::from_value(value.0).map_err(|_| ContextAuthorityError::RequestInvalid)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_scopes_are_distinct() {
        let scopes = BTreeSet::from([
            CONTEXT_MUTATE_SCOPE,
            CONTEXT_EXECUTE_SCOPE,
            CONTEXT_RETRIEVE_SCOPE,
            CONTEXT_READ_SCOPE,
        ]);
        assert_eq!(scopes.len(), 4);
    }

    #[test]
    fn duplicate_token_binding_fields_are_rejected() {
        let raw = br#"{"schema_version":"agenttrust.context-token-bindings.v1","schema_version":"agenttrust.context-token-bindings.v1","bindings":[]}"#;
        assert!(strict_json::<TokenBindingDocument>(raw).is_err());
    }
}
