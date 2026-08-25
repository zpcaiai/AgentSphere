//! TLS 1.3/mTLS data plane and isolated management plane for the Model Gateway.

use crate::authority::*;
use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use agent_trust_contracts::TenantId;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, OriginalUri, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware::AddExtension;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use futures::stream;
use nix::unistd::Uid;
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
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

pub const GENERATE_SCOPE: &str = "models:generate";
pub const STREAM_SCOPE: &str = "models:stream";
pub const EMBEDDINGS_SCOPE: &str = "models:embeddings";
pub const BILLING_SCOPE: &str = "models:billing:reconcile";
pub const EXECUTIONS_READ_SCOPE: &str = "models:executions:read";

#[derive(Debug, Clone)]
pub struct ModelServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
    pub recovery_interval_seconds: u64,
}

#[derive(Debug, Clone)]
struct ModelPeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    authority: ModelExecutionAuthority,
    tokens: Arc<ModelTokenAuthorizer>,
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

pub struct ModelTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl ModelTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, AuthorityError> {
        validate_identities(allowed_identities)?;
        validate_private_file(path, 1_048_576)?;
        let raw = std::fs::read(path).map_err(|_| AuthorityError::ConfigurationInvalid)?;
        let document: TokenBindingDocument = strict_json(&raw, 1_048_576)?;
        if document.schema_version != "agenttrust.model-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut physical_tokens = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    GENERATE_SCOPE
                        | STREAM_SCOPE
                        | EMBEDDINGS_SCOPE
                        | BILLING_SCOPE
                        | EXECUTIONS_READ_SCOPE
                )
                || !bounded_identifier(&binding.subject, 256)
                || !lower_digest(&binding.token_sha256)
                || !Uuid::parse_str(&binding.tenant_id)
                    .is_ok_and(|value| value.to_string() == binding.tenant_id)
                || !physical_tokens.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(AuthorityError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, AuthorityError> {
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=8192).contains(&value.len())
                    && !value.bytes().any(|byte| byte.is_ascii_whitespace())
            })
            .ok_or(AuthorityError::PrincipalDenied)?;
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
            return Err(AuthorityError::PrincipalDenied);
        }
        Ok(matching[0].subject.clone())
    }

    fn tenants(&self) -> BTreeSet<Uuid> {
        self.bindings
            .iter()
            .filter_map(|binding| Uuid::parse_str(&binding.tenant_id).ok())
            .collect()
    }
}

pub fn router(
    authority: ModelExecutionAuthority,
    tokens: Arc<ModelTokenAuthorizer>,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/models/generate", post(generate))
        .route("/v1/models/stream", post(model_stream))
        .route("/v1/models/embeddings", post(embeddings))
        .route(
            "/v1/authoritative/models/executions",
            get(authoritative_executions),
        )
        .route(
            "/v1/models/billing/reconciliations",
            post(reconcile_billing),
        )
        .layer(DefaultBodyLimit::max(64 * 1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(310),
        ))
        .with_state(ServerState { authority, tokens })
}

async fn data_ready(State(state): State<ServerState>) -> Result<Json<Value>, ApiError> {
    readiness(&state.authority).await
}

async fn generate(
    State(state): State<ServerState>,
    Extension(ModelPeerIdentity(peer)): Extension<ModelPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ModelExecutionResult>, ApiError> {
    let (request, binding) = authenticated_request(
        &state.tokens,
        &peer,
        GENERATE_SCOPE,
        ModelOperation::Generate,
        &headers,
        &body,
    )?;
    let (result, events) = state.authority.execute(request, binding).await?;
    if !events.is_empty() {
        return Err(AuthorityError::StateConflict.into());
    }
    Ok(Json(result))
}

async fn embeddings(
    State(state): State<ServerState>,
    Extension(ModelPeerIdentity(peer)): Extension<ModelPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ModelExecutionResult>, ApiError> {
    let (request, binding) = authenticated_request(
        &state.tokens,
        &peer,
        EMBEDDINGS_SCOPE,
        ModelOperation::Embeddings,
        &headers,
        &body,
    )?;
    let (result, events) = state.authority.execute(request, binding).await?;
    if !events.is_empty() {
        return Err(AuthorityError::StateConflict.into());
    }
    Ok(Json(result))
}

async fn model_stream(
    State(state): State<ServerState>,
    Extension(ModelPeerIdentity(peer)): Extension<ModelPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let (request, binding) = authenticated_request(
        &state.tokens,
        &peer,
        STREAM_SCOPE,
        ModelOperation::Stream,
        &headers,
        &body,
    )?;
    let (_, events) = state.authority.execute(request, binding).await?;
    if events.is_empty() {
        return Err(AuthorityError::StateConflict.into());
    }
    let encoded = events
        .into_iter()
        .map(|event| {
            serde_json::to_string(&event)
                .map(|data| Event::default().event("model.chunk").data(data))
                .map_err(|_| AuthorityError::DependencyUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Sse::new(stream::iter(
        encoded.into_iter().map(Ok::<Event, Infallible>),
    )))
}

async fn reconcile_billing(
    State(state): State<ServerState>,
    Extension(ModelPeerIdentity(peer)): Extension<ModelPeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<BillingReconciliationResult>, ApiError> {
    if single_header(&headers, "content-type") != Some("application/json") {
        return Err(AuthorityError::RequestInvalid.into());
    }
    let request: BillingStatementRequest = strict_json(&body, 64 * 1_048_576)?;
    let tenant = exact_tenant(&headers, request.tenant_id)?;
    let _subject = state
        .tokens
        .authorize(&peer, &tenant.0, BILLING_SCOPE, &headers)?;
    let binding = binding_from_headers(&headers, tenant)?;
    Ok(Json(state.authority.reconcile(request, binding).await?))
}

async fn authoritative_executions(
    State(state): State<ServerState>,
    Extension(ModelPeerIdentity(peer)): Extension<ModelPeerIdentity>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<AuthoritativeModelExecutionsPage>, ApiError> {
    let query = parse_execution_list_query(&uri)?;
    let tenant = exact_tenant(&headers, query.tenant_id)?;
    let _subject = state.tokens.authorize(
        &peer,
        &tenant.0,
        EXECUTIONS_READ_SCOPE,
        &headers,
    )?;
    let _trace_id = required_header(&headers, "x-agenttrust-trace-id")?;
    Ok(Json(state.authority.list_executions(query).await?))
}

fn parse_execution_list_query(uri: &Uri) -> Result<ModelExecutionListQuery, AuthorityError> {
    let raw = uri.query().ok_or(AuthorityError::RequestInvalid)?;
    if raw.is_empty() || raw.len() > 4096 {
        return Err(AuthorityError::RequestInvalid);
    }
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if value.is_empty()
            || value.len() > 512
            || value.bytes().any(|byte| byte.is_ascii_control())
            || fields.insert(key.into_owned(), value.into_owned()).is_some()
        {
            return Err(AuthorityError::RequestInvalid);
        }
    }
    if fields
        .keys()
        .any(|key| !matches!(key.as_str(), "tenant_id" | "state" | "operation" | "limit" | "cursor_created_at" | "cursor_request_id"))
    {
        return Err(AuthorityError::RequestInvalid);
    }
    let tenant_raw = fields
        .remove("tenant_id")
        .ok_or(AuthorityError::RequestInvalid)?;
    let tenant_id = Uuid::parse_str(&tenant_raw).map_err(|_| AuthorityError::RequestInvalid)?;
    if tenant_id.is_nil() || tenant_id.to_string() != tenant_raw {
        return Err(AuthorityError::RequestInvalid);
    }
    let state = fields.remove("state");
    if state.as_deref().is_some_and(|value| {
        !matches!(value, "PREPARED" | "EXECUTING" | "SUCCEEDED" | "FAILED" | "UNKNOWN")
    }) {
        return Err(AuthorityError::RequestInvalid);
    }
    let operation = match fields.remove("operation").as_deref() {
        None => None,
        Some("GENERATE") => Some(ModelOperation::Generate),
        Some("STREAM") => Some(ModelOperation::Stream),
        Some("EMBEDDINGS") => Some(ModelOperation::Embeddings),
        Some(_) => return Err(AuthorityError::RequestInvalid),
    };
    let limit = match fields.remove("limit") {
        None => 50,
        Some(raw) => {
            let value = raw
                .parse::<u16>()
                .map_err(|_| AuthorityError::RequestInvalid)?;
            if value.to_string() != raw || !(1..=200).contains(&value) {
                return Err(AuthorityError::RequestInvalid);
            }
            value
        }
    };
    let cursor_created_at = fields
        .remove("cursor_created_at")
        .map(|raw| {
            chrono::DateTime::parse_from_rfc3339(&raw)
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|_| AuthorityError::RequestInvalid)
        })
        .transpose()?;
    let cursor_request_id = fields
        .remove("cursor_request_id")
        .map(|raw| {
            let value = Uuid::parse_str(&raw).map_err(|_| AuthorityError::RequestInvalid)?;
            if value.is_nil() || value.to_string() != raw {
                return Err(AuthorityError::RequestInvalid);
            }
            Ok(value)
        })
        .transpose()?;
    if !fields.is_empty() || cursor_created_at.is_some() != cursor_request_id.is_some() {
        return Err(AuthorityError::RequestInvalid);
    }
    Ok(ModelExecutionListQuery {
        tenant_id,
        state,
        operation,
        limit,
        cursor_created_at,
        cursor_request_id,
    })
}

fn authenticated_request(
    tokens: &ModelTokenAuthorizer,
    peer: &str,
    scope: &str,
    operation: ModelOperation,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(ModelExecutionRequest, ExecutionBinding), AuthorityError> {
    if single_header(headers, "content-type") != Some("application/json") {
        return Err(AuthorityError::RequestInvalid);
    }
    let request: ModelExecutionRequest = strict_json(body, 5 * 1_048_576)?;
    if request.operation != operation {
        return Err(AuthorityError::RequestInvalid);
    }
    let tenant = exact_tenant(headers, request.tenant_id)?;
    let _subject = tokens.authorize(peer, &tenant.0, scope, headers)?;
    let binding = binding_from_headers(headers, tenant)?;
    Ok((request, binding))
}

fn binding_from_headers(
    headers: &HeaderMap,
    tenant_id: TenantId,
) -> Result<ExecutionBinding, AuthorityError> {
    Ok(ExecutionBinding {
        tenant_id,
        action_hash: required_header(headers, "x-agenttrust-action-hash")?.into(),
        authorization_id: uuid_header(headers, "x-agenttrust-authorization-id")?,
        authorization_digest: required_header(
            headers,
            "x-agenttrust-authorization-digest",
        )?
        .into(),
        policy_decision_id: required_header(headers, "x-agenttrust-policy-decision-id")?.into(),
        policy_decision_digest: required_header(
            headers,
            "x-agenttrust-policy-decision-digest",
        )?
        .into(),
        authorization_evidence_ref: required_header(
            headers,
            "x-agenttrust-authorization-evidence-ref",
        )?
        .into(),
        authorization_evidence_digest: required_header(
            headers,
            "x-agenttrust-authorization-evidence-digest",
        )?
        .into(),
        ledger_execution_id: uuid_header(headers, "x-agenttrust-ledger-execution-id")?,
        ledger_event_id: uuid_header(headers, "x-agenttrust-ledger-entry-id")?,
        ledger_event_digest: required_header(
            headers,
            "x-agenttrust-ledger-entry-digest",
        )?
        .into(),
        fence_digest: required_header(headers, "x-agenttrust-fence-digest")?.into(),
        resource_version: required_header(headers, "x-agenttrust-resource-version")?.into(),
        idempotency_key: required_header(headers, "idempotency-key")?.into(),
        trace_id: required_header(headers, "x-agenttrust-trace-id")?.into(),
    })
}

pub async fn serve(
    config: ModelServerConfig,
    application: Router,
    tokens: Arc<ModelTokenAuthorizer>,
    authority: ModelExecutionAuthority,
) -> Result<(), AuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !(5..=300).contains(&config.recovery_interval_seconds)
        || config.data_address.ip().is_loopback()
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    validate_public_file(&config.tls_ca_file, 4 * 1_048_576)?;
    validate_public_file(&config.tls_certificate_file, 4 * 1_048_576)?;
    validate_private_file(&config.tls_private_key_file, 4 * 1_048_576)?;
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.allowed_client_identities),
    };
    let management_authority = authority.clone();
    let management = Router::new()
        .route(
            "/live",
            get(|| async {
                Json(json!({"schema_version": READINESS_SCHEMA, "live": true}))
            }),
        )
        .route(
            "/ready",
            get(move || {
                let authority = management_authority.clone();
                async move { readiness(&authority).await }
            }),
        );
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    let tenants = tokens.tenants();
    let recovery_authority = authority;
    let recovery_interval = config.recovery_interval_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(recovery_interval));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            for tenant in &tenants {
                let _ = recovery_authority.recover_tenant(*tenant).await;
            }
        }
    });
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn readiness(authority: &ModelExecutionAuthority) -> Result<Json<Value>, ApiError> {
    authority.ready().await?;
    Ok(Json(json!({
        "schema_version": READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "provider_registry_ready": true,
        "data_governance_authority_ready": true,
        "artifact_store_ready": true,
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
    type Service = AddExtension<S, ModelPeerIdentity>;
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
                Extension(ModelPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, AuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| AuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| AuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| AuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| AuthorityError::ConfigurationInvalid)?
        .ok_or(AuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| AuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(AuthorityError);

impl From<AuthorityError> for ApiError {
    fn from(value: AuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            AuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            AuthorityError::RequestInvalid | AuthorityError::BindingInvalid => {
                StatusCode::BAD_REQUEST
            }
            AuthorityError::IdempotencyConflict
            | AuthorityError::BudgetExceeded
            | AuthorityError::NoCompliantProvider
            | AuthorityError::ProviderDenied
            | AuthorityError::StateConflict
            | AuthorityError::ProviderOutcomeUnknown => StatusCode::CONFLICT,
            AuthorityError::DependencyUnavailable
            | AuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(json!({
                "schema_version": "agenttrust.model-error.v1",
                "error": self.0.to_string(),
                "trace_id": "not-available"
            })),
        )
            .into_response()
    }
}

fn exact_tenant(headers: &HeaderMap, body_tenant: Uuid) -> Result<TenantId, AuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed = Uuid::parse_str(value).map_err(|_| AuthorityError::PrincipalDenied)?;
    if parsed != body_tenant || parsed.to_string() != value {
        return Err(AuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.into()))
}

fn uuid_header(headers: &HeaderMap, name: &'static str) -> Result<Uuid, AuthorityError> {
    let value = required_header(headers, name)?;
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(AuthorityError::RequestInvalid)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, AuthorityError> {
    single_header(headers, name).ok_or(AuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn strict_json<T: DeserializeOwned>(raw: &[u8], maximum: usize) -> Result<T, AuthorityError> {
    let limits = ParseLimits {
        max_body_bytes: maximum,
        max_depth: 64,
        max_array_items: 100_000,
        max_string_bytes: 4_194_304,
        max_object_keys: 2048,
        max_number_chars: 128,
    };
    let value = parse_strict_json(raw, &limits).map_err(|_| AuthorityError::RequestInvalid)?;
    serde_json::from_value(value).map_err(|_| AuthorityError::RequestInvalid)
}

pub fn validate_private_file(path: &Path, maximum: u64) -> Result<(), AuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn validate_public_file(path: &Path, maximum: u64) -> Result<(), AuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-model-token-compare-v1");
    let tag = hmac::sign(&key, second.as_bytes());
    hmac::verify(&key, first.as_bytes(), tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), AuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(AuthorityError::ConfigurationInvalid);
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

// Strict DER walk for subjectAltName. CN fallback and multi-SAN identities are rejected.
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

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(test)]
mod server_tests {
    use super::*;

    #[test]
    fn duplicate_json_members_fail_closed() {
        let raw = br#"{"schema_version":"one","schema_version":"two"}"#;
        assert!(strict_json::<Value>(raw, 1024).is_err());
    }

    #[test]
    fn token_compare_is_exact() {
        assert!(constant_time_equal(&"a".repeat(64), &"a".repeat(64)));
        assert!(!constant_time_equal(&"a".repeat(64), &"b".repeat(64)));
    }

    #[test]
    fn authoritative_query_is_tenant_bound_and_rejects_ambiguous_pagination() {
        let valid: Result<Uri, _> = "/v1/authoritative/models/executions?tenant_id=00000000-0000-4000-8000-000000000001&limit=50&state=SUCCEEDED".parse();
        assert!(valid
            .as_ref()
            .is_ok_and(|uri| parse_execution_list_query(uri).is_ok()));
        let duplicate: Result<Uri, _> = "/v1/authoritative/models/executions?tenant_id=00000000-0000-4000-8000-000000000001&limit=5&limit=10".parse();
        assert!(duplicate
            .as_ref()
            .is_ok_and(|uri| parse_execution_list_query(uri).is_err()));
        let partial_cursor: Result<Uri, _> = "/v1/authoritative/models/executions?tenant_id=00000000-0000-4000-8000-000000000001&cursor_request_id=00000000-0000-4000-8000-000000000002".parse();
        assert!(partial_cursor
            .as_ref()
            .is_ok_and(|uri| parse_execution_list_query(uri).is_err()));
    }
}
