//! TLS 1.3/mTLS data-governance data plane and loopback-only management plane.

use crate::authority::*;
use crate::service::*;
use agent_trust_contracts::TenantId;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use nix::unistd::{Gid, Uid};
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
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const DATA_MUTATE_SCOPE: &str = "data:mutate";
pub const DATA_EXECUTE_SCOPE: &str = "data:execute";
pub const DATA_EVALUATE_SCOPE: &str = "data:evaluate";
pub const DATA_SCAN_SCOPE: &str = "data:scan";
pub const DATA_SANITIZE_SCOPE: &str = "data:sanitize";
pub const DATA_ARTIFACT_SCOPE: &str = "data:artifact-authorize";
pub const DATA_READ_SCOPE: &str = "data:read";

#[derive(Debug, Clone)]
pub struct DataServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub recovery_interval_seconds: u64,
}

#[derive(Debug, Clone)]
struct DataPeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    ingress: DataIngressAuthority,
    executor: DataExecutor,
    decision: DataDecisionService,
    tokens: Arc<DataTokenAuthorizer>,
}

#[derive(Clone)]
struct ReadinessState {
    ingress: DataIngressAuthority,
    executor: DataExecutor,
    decision: DataDecisionService,
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

pub struct DataTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl DataTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, DataAuthorityError> {
        validate_identities(allowed_identities)?;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        let mode = metadata.mode() & 0o777;
        let effective_uid = Uid::effective().as_raw();
        let effective_gid = Gid::effective().as_raw();
        let allowed = 0o400 | if metadata.gid() == effective_gid { 0o040 } else { 0 };
        let readable = (metadata.uid() == effective_uid && mode & 0o400 != 0)
            || (metadata.gid() == effective_gid && mode & 0o040 != 0);
        if !path.is_absolute()
            || !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > 1_048_576
            || !readable
            || mode & !allowed != 0
        {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        let raw = std::fs::read(path).map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument = strict_json(&raw)?;
        if document.schema_version != "agenttrust.data-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    DATA_MUTATE_SCOPE | DATA_EXECUTE_SCOPE | DATA_EVALUATE_SCOPE
                        | DATA_SCAN_SCOPE | DATA_SANITIZE_SCOPE | DATA_ARTIFACT_SCOPE
                        | DATA_READ_SCOPE
                )
                || !identifier(&binding.subject, 256)
                || !digest(&binding.token_sha256)
                || !Uuid::parse_str(&binding.tenant_id)
                    .is_ok_and(|value| value.to_string() == binding.tenant_id)
                // One physical bearer credential can bind exactly one SAN, tenant, subject,
                // and route scope. Reusing it for a broader privilege set is rejected.
                || !credentials.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(DataAuthorityError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings.iter().any(|binding| &binding.client_identity == identity)
        }) {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, DataAuthorityError> {
        let authorization = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=8192).contains(&value.len())
                    && !value.bytes().any(|byte| byte.is_ascii_whitespace())
            })
            .ok_or(DataAuthorityError::PrincipalDenied)?;
        let supplied = hex::encode(Sha256::digest(authorization.as_bytes()));
        let matches = self.bindings.iter().filter(|binding| {
            binding.client_identity == peer
                && binding.tenant_id == tenant
                && binding.scope == scope
                && constant_time_equal(&supplied, &binding.token_sha256)
        }).collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(DataAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }

    fn tenants(&self) -> BTreeSet<TenantId> {
        self.bindings.iter()
            .map(|binding| TenantId(binding.tenant_id.clone()))
            .collect()
    }
}

pub fn router(
    ingress: DataIngressAuthority,
    executor: DataExecutor,
    decision: DataDecisionService,
    tokens: Arc<DataTokenAuthorizer>,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/data/actions", post(submit_action))
        .route("/v1/data/executions", post(execute_mutation))
        .route("/v1/internal/data/evaluate", post(evaluate_policy))
        .route("/v1/internal/data/scan", post(inspect_dlp))
        .route("/v1/internal/data/sanitize", post(sanitize_prompt))
        .route("/v1/internal/data/artifacts/authorize", post(authorize_artifact))
        .route("/v1/authoritative/data/resources", get(authoritative_resources))
        .route(
            "/v1/authoritative/data/mutations/{command_id}",
            get(completed_mutation),
        )
        .layer(DefaultBodyLimit::max(12 * 1024 * 1024))
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(TimeoutLayer::new(Duration::from_secs(45)))
        .with_state(ServerState { ingress, executor, decision, tokens })
}

async fn data_ready(State(state): State<ServerState>) -> Result<Json<Value>, ApiError> {
    readiness(&state.ingress, &state.executor, &state.decision).await
}

async fn submit_action(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<DataActionReceipt>), ApiError> {
    require_json_content_type(&headers)?;
    let request: DataCommandRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    let subject = state.tokens.authorize(&peer, &tenant.0, DATA_MUTATE_SCOPE, &headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = service_request_digest(
        "/v1/data/actions", &tenant, &peer, &subject, DATA_MUTATE_SCOPE,
        idempotency_key, &request,
    )?;
    let receipt = state.ingress.submit(
        tenant, subject, request, &request_digest, idempotency_key,
    ).await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_mutation(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DataMutationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: DataExecutorRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.command.tenant_id)?;
    let executor_subject = state.tokens.authorize(
        &peer, &tenant.0, DATA_EXECUTE_SCOPE, &headers,
    )?;
    if executor_subject != peer {
        return Err(DataAuthorityError::PrincipalDenied.into());
    }
    let binding = DataExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.into(),
        ledger_execution_id: parse_uuid_header(&headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: parse_uuid_header(&headers, "x-agenttrust-ledger-entry-id")?,
        ledger_event_digest: required_header(&headers, "x-agenttrust-ledger-entry-digest")?.into(),
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.into(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?
            .parse().map_err(|_| DataAuthorityError::RequestInvalid)?,
        idempotency_key: required_idempotency_key(&headers)?.into(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.into(),
        policy_decision_id: required_header(&headers, "x-agenttrust-policy-decision-id")?.into(),
        policy_decision_digest: required_header(
            &headers, "x-agenttrust-policy-decision-digest",
        )?.into(),
        authorization_evidence_ref: required_header(
            &headers, "x-agenttrust-authorization-evidence-ref",
        )?.into(),
        authorization_evidence_digest: required_header(
            &headers, "x-agenttrust-authorization-evidence-digest",
        )?.into(),
    };
    Ok(Json(state.executor.execute(binding, request).await?))
}

async fn evaluate_policy(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PolicyEvaluationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: PolicyEvaluationRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    state.tokens.authorize(&peer, &tenant.0, DATA_EVALUATE_SCOPE, &headers)?;
    Ok(Json(state.decision.evaluate(request)?))
}

async fn inspect_dlp(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DlpInspectionResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: DlpInspectionRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    state.tokens.authorize(&peer, &tenant.0, DATA_SCAN_SCOPE, &headers)?;
    Ok(Json(state.decision.inspect(request).await?))
}

async fn sanitize_prompt(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PromptSanitizationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: PromptSanitizationRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    state.tokens.authorize(&peer, &tenant.0, DATA_SANITIZE_SCOPE, &headers)?;
    Ok(Json(state.decision.sanitize(request).await?))
}

async fn authorize_artifact(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ArtifactAuthorizationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let request: ArtifactAuthorizationRequest = strict_json(&body)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    state.tokens.authorize(&peer, &tenant.0, DATA_ARTIFACT_SCOPE, &headers)?;
    Ok(Json(state.decision.authorize_artifact(request).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    after: Option<String>,
    limit: Option<i64>,
}

async fn authoritative_resources(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<AuthoritativeDataPage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state.tokens.authorize(&peer, &tenant.0, DATA_READ_SCOPE, &headers)?;
    Ok(Json(state.ingress.authoritative_page(
        &tenant, query.after.as_deref(), query.limit.unwrap_or(100),
    ).await?))
}

async fn completed_mutation(
    State(state): State<ServerState>,
    Extension(DataPeerIdentity(peer)): Extension<DataPeerIdentity>,
    headers: HeaderMap,
    AxumPath(raw_command_id): AxumPath<String>,
) -> Result<Json<DataMutationResult>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    state.tokens.authorize(&peer, &tenant.0, DATA_READ_SCOPE, &headers)?;
    let command_id = Uuid::parse_str(&raw_command_id)
        .ok()
        .filter(|value| value.to_string() == raw_command_id)
        .ok_or(DataAuthorityError::RequestInvalid)?;
    Ok(Json(state.ingress.completed_mutation(&tenant, command_id).await?))
}

pub async fn serve(
    config: DataServerConfig,
    application: Router,
    tokens: Arc<DataTokenAuthorizer>,
    readiness_ingress: DataIngressAuthority,
    readiness_executor: DataExecutor,
    readiness_decision: DataDecisionService,
) -> Result<(), DataAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !(5..=300).contains(&config.recovery_interval_seconds)
        || !config.management_address.ip().is_loopback()
        || config.data_address == config.management_address
    {
        return Err(DataAuthorityError::ConfigurationInvalid);
    }
    let tls = build_server_tls(
        &config.tls_ca_file, &config.tls_certificate_file, &config.tls_private_key_file,
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
            decision: readiness_decision,
        });
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await.map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
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
            .await.map_err(|_| DataAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await.map_err(|_| DataAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn management_live() -> Json<Value> {
    Json(serde_json::json!({
        "schema_version": DATA_READINESS_SCHEMA,
        "live": true
    }))
}

async fn management_ready(State(state): State<ReadinessState>) -> Result<Json<Value>, ApiError> {
    readiness(&state.ingress, &state.executor, &state.decision).await
}

async fn readiness(
    ingress: &DataIngressAuthority,
    executor: &DataExecutor,
    decision: &DataDecisionService,
) -> Result<Json<Value>, ApiError> {
    let (ingress_ready, executor_ready, inspection_ready) = tokio::join!(
        ingress.ready(), executor.ready(), decision.ready(),
    );
    if !ingress_ready || !executor_ready || !inspection_ready {
        return Err(DataAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(serde_json::json!({
        "schema_version": DATA_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "orchestrator_ready": true,
        "enterprise_dlp_ready": true,
        "object_worm_ready": true,
        "legal_hold_ready": true,
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
    type Service = AddExtension<S, DataPeerIdentity>;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        let allowed = self.allowed_identities.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            let certificates = stream.get_ref().1.peer_certificates().ok_or_else(|| {
                IoError::new(ErrorKind::PermissionDenied, "client certificate missing")
            })?;
            let identity = certificates.first()
                .and_then(|certificate| exact_certificate_identity(certificate.as_ref(), &allowed))
                .ok_or_else(|| IoError::new(ErrorKind::PermissionDenied, "client SAN denied"))?;
            Ok((stream, Extension(DataPeerIdentity(identity)).layer(service)))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, DataAuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| DataAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(DataAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build().map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| DataAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| DataAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| DataAuthorityError::ConfigurationInvalid)?
        .ok_or(DataAuthorityError::ConfigurationInvalid)?;
    let mut server = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| DataAuthorityError::ConfigurationInvalid)?
    .with_client_cert_verifier(verifier)
    .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
    .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(DataAuthorityError);

impl From<DataAuthorityError> for ApiError {
    fn from(value: DataAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.0.to_string();
        let trace_id = Uuid::new_v4().to_string();
        let safe_digest = sha256(code.as_bytes());
        let status = match self.0 {
            DataAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            DataAuthorityError::RequestInvalid => StatusCode::BAD_REQUEST,
            DataAuthorityError::NotFound => StatusCode::NOT_FOUND,
            DataAuthorityError::IdempotencyConflict
            | DataAuthorityError::StateConflict
            | DataAuthorityError::DlpDenied
            | DataAuthorityError::CrossDomainReplayed
            | DataAuthorityError::LegalHoldBlocked => StatusCode::CONFLICT,
            DataAuthorityError::DependencyUnavailable
            | DataAuthorityError::OutcomeUnknown
            | DataAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.data-authority-error.v1",
                "error": code,
                "trace_id": trace_id,
                "safe_digest": safe_digest
            })),
        ).into_response()
    }
}

fn exact_tenant(headers: &HeaderMap, body_tenant: Uuid) -> Result<TenantId, DataAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant.to_string() {
        return Err(DataAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, DataAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed = Uuid::parse_str(value).map_err(|_| DataAuthorityError::PrincipalDenied)?;
    if parsed.to_string() != value {
        return Err(DataAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.into()))
}

fn parse_uuid_header(headers: &HeaderMap, name: &'static str) -> Result<Uuid, DataAuthorityError> {
    let value = required_header(headers, name)?;
    Uuid::parse_str(value).ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(DataAuthorityError::RequestInvalid)
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, DataAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !valid_idempotency_key(value) {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, DataAuthorityError> {
    single_header(headers, name).ok_or(DataAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), DataAuthorityError> {
    if single_header(headers, "content-type") != Some("application/json") {
        return Err(DataAuthorityError::RequestInvalid);
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
) -> Result<String, DataAuthorityError> {
    if path != "/v1/data/actions"
        || !identifier(client_identity, 512)
        || !identifier(subject, 256)
        || scope != DATA_MUTATE_SCOPE
    {
        return Err(DataAuthorityError::RequestInvalid);
    }
    canonical_digest(&ServiceRequestBinding {
        schema_version: "agenttrust.data-service-request-binding.v1",
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
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-data-token-compare-v1");
    let tag = hmac::sign(&key, second.as_bytes());
    hmac::verify(&key, first.as_bytes(), tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), DataAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(DataAuthorityError::ConfigurationInvalid);
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

// Strict DER walk for subjectAltName. CommonName is deliberately ignored. Exactly one DNS/URI SAN
// is required so a transport connection maps to one workload identity without alias ambiguity.
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
        if value.is_empty() || value.len() > 508
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
            length = length.checked_mul(256)
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

/// Decode bounded JSON while rejecting duplicate keys, excessive nesting, and trailing data.
/// Production configuration loaders use the same parser as HTTP routes so signed material has
/// exactly one semantic representation before canonicalization.
pub fn strict_json<T: DeserializeOwned>(raw: &[u8]) -> Result<T, DataAuthorityError> {
    if raw.is_empty() || raw.len() > 12 * 1024 * 1024 {
        return Err(DataAuthorityError::RequestInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| DataAuthorityError::RequestInvalid)?;
    deserializer.end().map_err(|_| DataAuthorityError::RequestInvalid)?;
    serde_json::from_value(value.0).map_err(|_| DataAuthorityError::RequestInvalid)
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor { depth: 0 })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate object members")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where E: de::Error {
        Number::from_f64(value).map(Value::Number).map(StrictJsonValue)
            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: de::Error {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: de::Error {
        if value.len() > 11 * 1024 * 1024 {
            return Err(de::Error::custom("JSON string capacity exceeded"));
        }
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where A: SeqAccess<'de> {
        if self.depth >= 32 {
            return Err(de::Error::custom("JSON depth exceeded"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
        })? {
            values.push(value.0);
            if values.len() > 100_000 {
                return Err(de::Error::custom("JSON array capacity exceeded"));
            }
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where A: MapAccess<'de> {
        if self.depth >= 32 {
            return Err(de::Error::custom("JSON depth exceeded"));
        }
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > 256 || values.contains_key(&key) {
                return Err(de::Error::custom("duplicate or oversized JSON object member"));
            }
            let value = object.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value.0);
            if values.len() > 512 {
                return Err(de::Error::custom("JSON object capacity exceeded"));
            }
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

struct StrictJsonSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for StrictJsonSeed {
    type Value = StrictJsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_json_members_are_rejected() {
        assert!(strict_json::<Value>(br#"{"tenant_id":"a","tenant_id":"b"}"#).is_err());
    }

    #[test]
    fn certificate_identity_requires_one_san_and_ignores_common_name() {
        assert!(exact_certificate_identity(b"not-a-certificate", &BTreeSet::new()).is_none());
    }
}
