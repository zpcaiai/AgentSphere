//! TLS 1.3/mTLS Pack Marketplace ingress, authoritative query, and executor boundary.

use crate::authority::*;
use crate::principal::HumanPrincipalKeyring;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{TenantId, human_principal_request_digest};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
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
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
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

pub const PACKS_MUTATE_SCOPE: &str = "packs:mutate";
pub const PACKS_EXECUTE_SCOPE: &str = "packs:execute";
pub const PACKS_READ_SCOPE: &str = "packs:read";

#[derive(Debug, Clone)]
pub struct MarketplaceServerConfig {
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
struct MarketplacePeerIdentity(String);

#[derive(Clone)]
struct ServerState {
    ingress: MarketplaceIngressAuthority,
    executor: MarketplaceExecutor,
    tokens: Arc<MarketplaceTokenAuthorizer>,
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

pub struct MarketplaceTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl MarketplaceTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, MarketplaceAuthorityError> {
        validate_identities(allowed_identities)?;
        if !path.is_absolute() {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        let raw =
            std::fs::read(path).map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument =
            strict_json(&raw).map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.pack-marketplace-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    PACKS_MUTATE_SCOPE | PACKS_EXECUTE_SCOPE | PACKS_READ_SCOPE
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
                return Err(MarketplaceAuthorityError::ConfigurationInvalid);
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
            [PACKS_MUTATE_SCOPE, PACKS_EXECUTE_SCOPE, PACKS_READ_SCOPE]
                .iter()
                .any(|scope| {
                    !bindings
                        .iter()
                        .any(|binding| &binding.tenant_id == tenant && &binding.scope == scope)
                })
        }) {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: &str,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, MarketplaceAuthorityError> {
        let authorization = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=8_192).contains(&value.len())
                    && !value.bytes().any(|byte| byte.is_ascii_whitespace())
            })
            .ok_or(MarketplaceAuthorityError::PrincipalDenied)?;
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
            return Err(MarketplaceAuthorityError::PrincipalDenied);
        }
        Ok(matches[0].subject.clone())
    }
}

pub fn router(
    ingress: MarketplaceIngressAuthority,
    executor: MarketplaceExecutor,
    tokens: Arc<MarketplaceTokenAuthorizer>,
    principal_keyring: Arc<HumanPrincipalKeyring>,
    ingress_subject: String,
    executor_subject: String,
    query_subject: String,
    maximum_authentication_age_seconds: i64,
) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/packs/actions", post(submit_action))
        .route("/v1/packs/executions", post(execute_mutation))
        .route("/v1/authoritative/packs", get(authoritative_packs))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
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

async fn data_ready(State(state): State<ServerState>) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&state.ingress).await
}

async fn submit_action(
    State(state): State<ServerState>,
    Extension(MarketplacePeerIdentity(peer)): Extension<MarketplacePeerIdentity>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<(StatusCode, Json<MarketplaceActionReceipt>), ApiError> {
    require_json_content_type(&headers)?;
    let body: MarketplaceCommandRequest = strict_json(&bytes)?;
    let tenant = exact_tenant(&headers, body.tenant_id.to_string())?;
    let service_subject = state
        .tokens
        .authorize(&peer, &tenant.0, PACKS_MUTATE_SCOPE, &headers)?;
    if service_subject != state.ingress_subject {
        return Err(ApiError(MarketplaceAuthorityError::PrincipalDenied));
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let request_digest = human_principal_request_digest(
        "POST",
        "/v1/packs/actions",
        &tenant,
        &peer,
        &service_subject,
        PACKS_MUTATE_SCOPE,
        idempotency_key,
        &body,
    )
    .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    let encoded = single_header(&headers, "x-agenttrust-human-assertion")
        .ok_or(MarketplaceAuthorityError::PrincipalDenied)?;
    let principal = state.principal_keyring.verify_encoded(
        encoded,
        &tenant,
        &peer,
        &service_subject,
        PACKS_MUTATE_SCOPE,
        &request_digest,
        state.maximum_authentication_age_seconds,
        Utc::now(),
    )?;
    let route_kind = body.command.route_kind();
    let receipt = state
        .ingress
        .submit(
            &principal,
            body,
            &request_digest,
            idempotency_key,
            route_kind,
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn execute_mutation(
    State(state): State<ServerState>,
    Extension(MarketplacePeerIdentity(peer)): Extension<MarketplacePeerIdentity>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<MarketplaceMutationResult>, ApiError> {
    require_json_content_type(&headers)?;
    let body: MarketplaceExecutorRequest = strict_json(&bytes)?;
    let tenant = exact_tenant_from_header(&headers)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, PACKS_EXECUTE_SCOPE, &headers)?;
    if subject != state.executor_subject {
        return Err(ApiError(MarketplaceAuthorityError::PrincipalDenied));
    }
    let binding = MarketplaceExecutionBinding {
        tenant_id: tenant,
        action_hash: required_header(&headers, "x-agenttrust-action-hash")?.to_string(),
        policy_decision_id: required_header(&headers, "x-agenttrust-policy-decision-id")?
            .to_string(),
        policy_decision_digest: required_header(&headers, "x-agenttrust-policy-decision-digest")?
            .to_string(),
        ledger_entry_id: required_header(&headers, "x-agenttrust-ledger-entry-id")?.to_string(),
        ledger_entry_digest: required_header(&headers, "x-agenttrust-ledger-entry-digest")?
            .to_string(),
        ledger_execution_id: parse_uuid_header(&headers, "x-agenttrust-ledger-execution-id")?,
        fence_digest: required_header(&headers, "x-agenttrust-fence-digest")?.to_string(),
        resource_version: required_header(&headers, "x-agenttrust-resource-version")?
            .parse()
            .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?,
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
        idempotency_key: required_idempotency_key(&headers)?.to_string(),
        trace_id: required_header(&headers, "x-agenttrust-trace-id")?.to_string(),
    };
    Ok(Json(state.executor.execute(binding, body).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackPageQuery {
    query: Option<String>,
    after_pack_id: Option<String>,
    limit: Option<i64>,
}

async fn authoritative_packs(
    State(state): State<ServerState>,
    Extension(MarketplacePeerIdentity(peer)): Extension<MarketplacePeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<PackPageQuery>,
) -> Result<Json<AuthoritativePackPage>, ApiError> {
    let tenant = exact_tenant_from_header(&headers)?;
    let subject = state
        .tokens
        .authorize(&peer, &tenant.0, PACKS_READ_SCOPE, &headers)?;
    if subject != state.query_subject {
        return Err(ApiError(MarketplaceAuthorityError::PrincipalDenied));
    }
    Ok(Json(
        state
            .ingress
            .authoritative_page(
                &tenant,
                query.query.as_deref(),
                query.after_pack_id.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}

#[derive(Clone)]
pub struct HttpMarketplaceOrchestrator {
    client: reqwest::Client,
    endpoint: url::Url,
    token_file: PathBuf,
}

impl HttpMarketplaceOrchestrator {
    pub fn new(
        client: reqwest::Client,
        endpoint: url::Url,
        token_file: PathBuf,
    ) -> Result<Self, MarketplaceAuthorityError> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || !token_file.is_absolute()
        {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
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
impl MarketplaceOrchestratorPort for HttpMarketplaceOrchestrator {
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &agent_trust_gateway::InboundEnvelope,
    ) -> Result<MarketplaceActionReceipt, MarketplaceAuthorityError> {
        let url = self
            .endpoint
            .join("v1/actions")
            .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(read_token(&self.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .json(envelope)
            .send()
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(MarketplaceAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return Err(MarketplaceAuthorityError::DependencyUnavailable);
        }
        let mut content_types = response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter();
        if content_types.next().and_then(|value| value.to_str().ok()) != Some("application/json")
            || content_types.next().is_some()
        {
            return Err(MarketplaceAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(MarketplaceAuthorityError::DependencyUnavailable);
        }
        let accepted: OrchestratorAcceptance =
            strict_json(&bytes).map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        if accepted.schema_version != "agenttrust.action-acceptance.v1"
            || !accepted.accepted
            || !accepted.start_requested
            || !accepted.execution_pending
            || !digest(&accepted.ingress_digest)
            || !digest(&accepted.evidence_digest)
            || !accepted.evidence_ref.starts_with("urn:agenttrust:")
        {
            return Err(MarketplaceAuthorityError::DependencyUnavailable);
        }
        Ok(MarketplaceActionReceipt {
            schema_version: MARKETPLACE_ACTION_RECEIPT_SCHEMA.into(),
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
    config: MarketplaceServerConfig,
    application: Router,
    readiness_authority: MarketplaceIngressAuthority,
) -> Result<(), MarketplaceAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !identifier(&config.ingress_subject, 256)
        || !identifier(&config.executor_subject, 256)
        || !identifier(&config.query_subject, 256)
        || !(60..=86_400).contains(&config.maximum_authentication_age_seconds)
        || !(config.management_address.ip().is_loopback()
            || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(MarketplaceAuthorityError::ConfigurationInvalid);
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
        .with_state(readiness_authority);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn management_ready(
    State(authority): State<MarketplaceIngressAuthority>,
) -> Result<Json<serde_json::Value>, ApiError> {
    readiness(&authority).await
}

async fn readiness(
    authority: &MarketplaceIngressAuthority,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !authority.ready().await {
        return Err(ApiError(MarketplaceAuthorityError::DependencyUnavailable));
    }
    Ok(Json(serde_json::json!({
        "schema_version": MARKETPLACE_READINESS_SCHEMA,
        "ready": true,
        "database_ready": true,
        "release_gate_keyring_ready": true
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
    type Service = AddExtension<S, MarketplacePeerIdentity>;
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
                Extension(MarketplacePeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, MarketplaceAuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?,
    );
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(MarketplaceAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file)
            .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file)
            .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?
        .ok_or(MarketplaceAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(MarketplaceAuthorityError);

impl From<MarketplaceAuthorityError> for ApiError {
    fn from(value: MarketplaceAuthorityError) -> Self {
        Self(value)
    }
}

impl From<crate::principal::PrincipalAssertionError> for ApiError {
    fn from(_: crate::principal::PrincipalAssertionError) -> Self {
        Self(MarketplaceAuthorityError::PrincipalDenied)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            MarketplaceAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            MarketplaceAuthorityError::RequestInvalid => StatusCode::BAD_REQUEST,
            MarketplaceAuthorityError::NotFound => StatusCode::NOT_FOUND,
            MarketplaceAuthorityError::IdempotencyConflict
            | MarketplaceAuthorityError::StateConflict
            | MarketplaceAuthorityError::ReviewSeparationRequired
            | MarketplaceAuthorityError::SignatureInvalid
            | MarketplaceAuthorityError::CompatibilityDenied
            | MarketplaceAuthorityError::EntitlementDenied
            | MarketplaceAuthorityError::RegionDenied
            | MarketplaceAuthorityError::TrustDenied
            | MarketplaceAuthorityError::RiskDenied => StatusCode::CONFLICT,
            MarketplaceAuthorityError::OutcomeUnknown
            | MarketplaceAuthorityError::DependencyUnavailable
            | MarketplaceAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.pack-marketplace-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn exact_tenant(
    headers: &HeaderMap,
    body_tenant: String,
) -> Result<TenantId, MarketplaceAuthorityError> {
    let tenant = exact_tenant_from_header(headers)?;
    if tenant.0 != body_tenant {
        return Err(MarketplaceAuthorityError::PrincipalDenied);
    }
    Ok(tenant)
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), MarketplaceAuthorityError> {
    if single_header(headers, "content-type") != Some("application/json") {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn strict_json<T: DeserializeOwned>(raw: &[u8]) -> Result<T, MarketplaceAuthorityError> {
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    deserializer
        .end()
        .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    serde_json::from_value(value.0).map_err(|_| MarketplaceAuthorityError::RequestInvalid)
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

fn exact_tenant_from_header(headers: &HeaderMap) -> Result<TenantId, MarketplaceAuthorityError> {
    let value = required_header(headers, "x-agenttrust-tenant-id")?;
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| MarketplaceAuthorityError::PrincipalDenied)?;
    if parsed.to_string() != value {
        return Err(MarketplaceAuthorityError::PrincipalDenied);
    }
    Ok(TenantId(value.to_string()))
}

fn parse_uuid_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<uuid::Uuid, MarketplaceAuthorityError> {
    let raw = required_header(headers, name)?;
    uuid::Uuid::parse_str(raw)
        .ok()
        .filter(|value| value.to_string() == raw)
        .ok_or(MarketplaceAuthorityError::RequestInvalid)
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, MarketplaceAuthorityError> {
    let value = required_header(headers, "idempotency-key")?;
    if !(16..=128).contains(&value.len())
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte)))
    {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, MarketplaceAuthorityError> {
    single_header(headers, name).ok_or(MarketplaceAuthorityError::RequestInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn read_token(path: &Path) -> Result<String, MarketplaceAuthorityError> {
    let metadata =
        std::fs::metadata(path).map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() > 8_194 {
        return Err(MarketplaceAuthorityError::ConfigurationInvalid);
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(MarketplaceAuthorityError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}

fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-pack-marketplace-token-compare-v1",
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

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), MarketplaceAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(MarketplaceAuthorityError::ConfigurationInvalid);
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

// Strict DER walk for subjectAltName. CommonName is intentionally ignored.
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
