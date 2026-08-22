//! Fail-closed TLS 1.3 boundary for the production workload credential authority.

use super::*;
use agent_trust_contracts::{IdempotencyKey, WorkloadCredentialBindingRequest};
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
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const IDENTITY_READINESS_SCHEMA: &str = "agenttrust.identity-credential-readiness.v1";
const TOKEN_BINDING_SCHEMA: &str = "agenttrust.identity-token-bindings.v1";

#[derive(Debug, Clone)]
pub struct IdentityCredentialServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub client_identities: BTreeSet<String>,
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
pub struct TokenBindingIdentityAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
    tenants: BTreeSet<TenantId>,
}

#[derive(Clone)]
struct RequestContext {
    tenant_id: TenantId,
    subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoritativeCredentialQuery {
    resource: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoritativeCredentialPage {
    schema_version: &'static str,
    authoritative: bool,
    tenant_id: TenantId,
    resource: String,
    items: Vec<AuthoritativeCredentialView>,
    next_cursor: Option<String>,
    data_digest: String,
}

#[derive(Serialize)]
struct AuthoritativeCredentialPageMaterial<'a> {
    schema_version: &'static str,
    authoritative: bool,
    tenant_id: &'a TenantId,
    resource: &'a str,
    items: &'a [AuthoritativeCredentialView],
    next_cursor: Option<&'a str>,
}

impl TokenBindingIdentityAuthorizer {
    pub fn from_file(
        path: &Path,
        identities: &BTreeSet<String>,
        tool_proxy_identity: &str,
    ) -> Result<Self, IdentityError> {
        validate_identities(identities)?;
        if !identities.contains(tool_proxy_identity) {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        let raw = std::fs::read(path).map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        let document: TokenBindingDocument = serde_json::from_slice(&raw)
            .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
        if document.schema_version != TOKEN_BINDING_SCHEMA || document.bindings.is_empty() {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        let mut bindings = BTreeSet::new();
        let mut unique_security_tuples = BTreeSet::new();
        let mut tenants = BTreeSet::new();
        for binding in document.bindings {
            if !identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    "credentials:issue"
                        | "credentials:consume"
                        | "credentials:revoke"
                        | "credentials:read"
                )
                || !valid_subject(&binding.subject)
                || !lower_digest(&binding.token_sha256)
                || (binding.scope == "credentials:consume")
                    != (binding.client_identity == tool_proxy_identity)
            {
                return Err(IdentityError::ProductionTrustNotConfigured);
            }
            let tenant_uuid = Uuid::parse_str(&binding.tenant_id)
                .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
            if tenant_uuid.to_string() != binding.tenant_id {
                return Err(IdentityError::ProductionTrustNotConfigured);
            }
            let tenant = TenantId(binding.tenant_id.clone());
            if !unique_security_tuples.insert((
                binding.client_identity.clone(),
                tenant.0.clone(),
                binding.token_sha256.clone(),
            )) || !bindings.insert(TokenAuthorization {
                client_identity: binding.client_identity,
                tenant_id: tenant.0.clone(),
                subject: binding.subject,
                scope: binding.scope,
                token_sha256: binding.token_sha256,
            }) {
                return Err(IdentityError::ProductionTrustNotConfigured);
            }
            tenants.insert(tenant);
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        if !bindings.iter().any(|binding| {
            binding.client_identity == tool_proxy_identity && binding.scope == "credentials:consume"
        }) {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        Ok(Self { bindings, tenants })
    }

    pub fn tenants(&self) -> &BTreeSet<TenantId> {
        &self.tenants
    }

    fn authorize(
        &self,
        peer_identity: &str,
        headers: &HeaderMap,
        required_scope: &str,
    ) -> Result<RequestContext, IdentityError> {
        let tenant = single_header(headers, "x-agenttrust-tenant-id")
            .and_then(|value| {
                Uuid::parse_str(value)
                    .ok()
                    .filter(|tenant| tenant.to_string() == value)
            })
            .map(|tenant| tenant.to_string())
            .ok_or(IdentityError::ManagementForbidden)?;
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
            })
            .ok_or(IdentityError::ManagementForbidden)?;
        let supplied = hex::encode(Sha256::digest(token.as_bytes()));
        let mut context = None;
        for binding in &self.bindings {
            let tuple_matches = binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && binding.scope == required_scope;
            if tuple_matches && constant_time_digest_matches(&supplied, &binding.token_sha256) {
                if context.is_some() {
                    return Err(IdentityError::ManagementForbidden);
                }
                context = Some(RequestContext {
                    tenant_id: TenantId(tenant.clone()),
                    subject: binding.subject.clone(),
                });
            }
        }
        context.ok_or(IdentityError::ManagementForbidden)
    }
}

#[derive(Clone)]
struct ApiState {
    authority: Arc<PostgresCredentialAuthority>,
    authorizer: Arc<TokenBindingIdentityAuthorizer>,
}

#[derive(Clone)]
struct ManagementState {
    authority: Arc<PostgresCredentialAuthority>,
    tenants: Arc<BTreeSet<TenantId>>,
}

#[derive(Clone, Debug)]
struct IdentityPeerIdentity(String);

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    schema_version: &'static str,
    error: String,
}

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

pub async fn serve(
    config: IdentityCredentialServerConfig,
    authority: Arc<PostgresCredentialAuthority>,
    authorizer: Arc<TokenBindingIdentityAuthorizer>,
) -> Result<(), IdentityError> {
    validate_identities(&config.client_identities)?;
    if authorizer.tenants().is_empty() {
        return Err(IdentityError::ProductionTrustNotConfigured);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let management_state = ManagementState {
        authority: authority.clone(),
        tenants: Arc::new(authorizer.tenants().clone()),
    };
    let api_state = ApiState {
        authority,
        authorizer,
    };
    let data = Router::new()
        .route("/ready", get(data_ready))
        .route(
            "/v1/authoritative/credentials",
            get(list_authoritative_credentials),
        )
        .route("/v1/credentials/issue", post(issue))
        .route("/v1/credentials/consume", post(consume))
        .route(
            "/v1/credentials/{credential_id}/revoke",
            post(revoke_credential),
        )
        .route("/v1/tasks/{task_id}/pause", post(pause_task))
        .route("/v1/tasks/{task_id}/unfreeze", post(unfreeze_task))
        .route("/v1/tasks/{task_id}/revoke", post(revoke_task))
        .route("/v1/tasks/{task_id}/cancel", post(cancel_task))
        .route("/v1/tasks/{task_id}/kill", post(kill_task))
        .route("/v1/agents/{agent_id}/revoke", post(revoke_agent))
        .route("/v1/tenants/{tenant_id}/revoke", post(revoke_tenant))
        .with_state(api_state)
        .layer(Extension(management_state.clone()))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)));
    let management = Router::new()
        .route("/ready", get(management_ready))
        .with_state(management_state);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| IdentityError::StoreFailure)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| IdentityError::StoreFailure)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| IdentityError::StoreFailure)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn list_authoritative_credentials(
    State(state): State<ApiState>,
    Extension(peer): Extension<IdentityPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<AuthoritativeCredentialQuery>,
) -> Response {
    let result = async {
        let context = state
            .authorizer
            .authorize(&peer.0, &headers, "credentials:read")?;
        let resource = query.resource.as_deref().unwrap_or("summary");
        let limit = query.limit.unwrap_or(50);
        if !valid_dashboard_resource(resource)
            || !(1..=100).contains(&limit)
            || query.cursor.is_some()
        {
            return Err(IdentityError::RequestInvalid);
        }
        let items = state
            .authority
            .list_authoritative_credentials(&context.tenant_id, limit, Utc::now())
            .await?;
        let material = AuthoritativeCredentialPageMaterial {
            schema_version: "agenttrust.authoritative-credential-page.v1",
            authoritative: true,
            tenant_id: &context.tenant_id,
            resource,
            items: &items,
            next_cursor: None,
        };
        let data_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&material).map_err(|_| IdentityError::RequestInvalid)?,
        ));
        Ok(AuthoritativeCredentialPage {
            schema_version: "agenttrust.authoritative-credential-page.v1",
            authoritative: true,
            tenant_id: context.tenant_id,
            resource: resource.to_string(),
            items,
            next_cursor: None,
            data_digest,
        })
    }
    .await;
    result_response(result)
}

async fn issue(
    State(state): State<ApiState>,
    Extension(peer): Extension<IdentityPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<WorkloadCredentialBindingRequest>,
) -> Response {
    let result = async {
        let context = state
            .authorizer
            .authorize(&peer.0, &headers, "credentials:issue")?;
        require_tenant_and_idempotency(
            &headers,
            &context.tenant_id,
            &request.tenant_id,
            &request.idempotency_key,
        )?;
        state
            .authority
            .issue(&request, &context.subject, Utc::now())
            .await
    }
    .await;
    result_response(result)
}

async fn consume(
    State(state): State<ApiState>,
    Extension(peer): Extension<IdentityPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<WorkloadCredentialConsumptionRequest>,
) -> Response {
    let result = async {
        let context = state
            .authorizer
            .authorize(&peer.0, &headers, "credentials:consume")?;
        require_tenant_and_idempotency(
            &headers,
            &context.tenant_id,
            &request.tenant_id,
            &request.idempotency_key,
        )?;
        state
            .authority
            .consume(&request, &context.subject, Utc::now())
            .await
    }
    .await;
    result_response(result)
}

async fn revoke_credential(
    State(state): State<ApiState>,
    Extension(peer): Extension<IdentityPeerIdentity>,
    AxumPath(credential_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialLifecycleRequest>,
) -> Response {
    let authority = state.authority.clone();
    lifecycle_authorized(
        state.authorizer.clone(),
        &peer,
        &headers,
        move |context, idempotency| async move {
            authority
                .revoke_credential(
                    &context.tenant_id,
                    &credential_id,
                    &request,
                    &idempotency,
                    &context.subject,
                    Utc::now(),
                )
                .await
        },
    )
    .await
}

macro_rules! task_handler {
    ($name:ident, $operation:literal) => {
        async fn $name(
            State(state): State<ApiState>,
            Extension(peer): Extension<IdentityPeerIdentity>,
            AxumPath(task_id): AxumPath<String>,
            headers: HeaderMap,
            Json(request): Json<CredentialLifecycleRequest>,
        ) -> Response {
            let authority = state.authority.clone();
            lifecycle_authorized(
                state.authorizer.clone(),
                &peer,
                &headers,
                move |context, idempotency| async move {
                    authority
                        .set_task_state(
                            &context.tenant_id,
                            &task_id,
                            $operation,
                            &request,
                            &idempotency,
                            &context.subject,
                            Utc::now(),
                        )
                        .await
                },
            )
            .await
        }
    };
}
task_handler!(pause_task, "PAUSE_TASK");
task_handler!(unfreeze_task, "UNFREEZE_TASK");
task_handler!(revoke_task, "REVOKE_TASK");
task_handler!(cancel_task, "CANCEL_TASK");
task_handler!(kill_task, "KILL_TASK");

async fn revoke_agent(
    State(state): State<ApiState>,
    Extension(peer): Extension<IdentityPeerIdentity>,
    AxumPath(agent_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialLifecycleRequest>,
) -> Response {
    let authority = state.authority.clone();
    lifecycle_authorized(
        state.authorizer.clone(),
        &peer,
        &headers,
        move |context, idempotency| async move {
            authority
                .revoke_agent_or_tenant(
                    &context.tenant_id,
                    "agent",
                    &agent_id,
                    &request,
                    &idempotency,
                    &context.subject,
                    Utc::now(),
                )
                .await
        },
    )
    .await
}

async fn revoke_tenant(
    State(state): State<ApiState>,
    Extension(peer): Extension<IdentityPeerIdentity>,
    AxumPath(tenant_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialLifecycleRequest>,
) -> Response {
    let authority = state.authority.clone();
    lifecycle_authorized(
        state.authorizer.clone(),
        &peer,
        &headers,
        move |context, idempotency| async move {
            if context.tenant_id.0 != tenant_id {
                return Err(IdentityError::TenantMismatch);
            }
            authority
                .revoke_agent_or_tenant(
                    &context.tenant_id,
                    "tenant",
                    &tenant_id,
                    &request,
                    &idempotency,
                    &context.subject,
                    Utc::now(),
                )
                .await
        },
    )
    .await
}

async fn lifecycle_authorized<F, Fut>(
    authorizer: Arc<TokenBindingIdentityAuthorizer>,
    peer: &IdentityPeerIdentity,
    headers: &HeaderMap,
    operation: F,
) -> Response
where
    F: FnOnce(RequestContext, IdempotencyKey) -> Fut,
    Fut: Future<Output = Result<CredentialLifecycleReceipt, IdentityError>>,
{
    let result = async {
        let context = authorizer.authorize(&peer.0, headers, "credentials:revoke")?;
        let idempotency = required_idempotency(headers)?;
        operation(context, idempotency).await
    }
    .await;
    result_response(result)
}

fn require_tenant_and_idempotency(
    headers: &HeaderMap,
    authorized: &TenantId,
    requested: &TenantId,
    body_key: &IdempotencyKey,
) -> Result<(), IdentityError> {
    if authorized != requested || required_idempotency(headers)? != *body_key {
        return Err(IdentityError::ManagementForbidden);
    }
    Ok(())
}

fn required_idempotency(headers: &HeaderMap) -> Result<IdempotencyKey, IdentityError> {
    let key = single_header(headers, "idempotency-key")
        .filter(|value| valid_idempotency_header(value))
        .ok_or(IdentityError::IdempotencyInvalid)?;
    Ok(IdempotencyKey(key.to_string()))
}

async fn management_ready(State(state): State<ManagementState>) -> Response {
    readiness_response(&state).await
}

async fn data_ready(
    Extension(state): Extension<ManagementState>,
    Extension(_peer): Extension<IdentityPeerIdentity>,
) -> Response {
    readiness_response(&state).await
}

async fn readiness_response(state: &ManagementState) -> Response {
    let ready = state.authority.ready(&state.tenants).await;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: IDENTITY_READINESS_SCHEMA,
            ready,
        }),
    )
        .into_response()
}

fn result_response<T: Serialize>(result: Result<T, IdentityError>) -> Response {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => error_response(error),
    }
}

fn error_response(error: IdentityError) -> Response {
    let status = match error {
        IdentityError::ManagementForbidden | IdentityError::TenantMismatch => StatusCode::FORBIDDEN,
        IdentityError::CredentialNotFound => StatusCode::NOT_FOUND,
        IdentityError::IdempotencyConflict
        | IdentityError::IdempotencyReplayExpired
        | IdentityError::TaskFrozen
        | IdentityError::UsageExceeded => StatusCode::CONFLICT,
        IdentityError::Revoked
        | IdentityError::SubjectRevoked
        | IdentityError::ExpiredOrNotYetValid => StatusCode::GONE,
        IdentityError::StoreFailure
        | IdentityError::ProductionTrustNotConfigured
        | IdentityError::ResponseProtectionInvalid
        | IdentityError::SigningKeyInvalid => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(ErrorResponse {
            schema_version: IDENTITY_SCHEMA_VERSION,
            error: error.to_string(),
        }),
    )
        .into_response()
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-identity-token-comparison-v1",
    );
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn valid_idempotency_header(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn valid_dashboard_resource(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), IdentityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || !identity.bytes().all(|byte| byte.is_ascii_graphic())
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(IdentityError::ProductionTrustNotConfigured);
    }
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, IdentityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| IdentityError::ProductionTrustNotConfigured)?,
    );
    let roots_der = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
    if roots_der.is_empty() {
        return Err(IdentityError::ProductionTrustNotConfigured);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(roots_der);
    if accepted == 0 {
        return Err(IdentityError::ProductionTrustNotConfigured);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| IdentityError::ProductionTrustNotConfigured)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
    if certificates.is_empty() {
        return Err(IdentityError::ProductionTrustNotConfigured);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| IdentityError::ProductionTrustNotConfigured)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| IdentityError::ProductionTrustNotConfigured)?
        .ok_or(IdentityError::ProductionTrustNotConfigured)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| IdentityError::ProductionTrustNotConfigured)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, IdentityPeerIdentity>;
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
            Ok((
                stream,
                Extension(IdentityPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn io_denied(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn matching_certificate_identity(certificate: &[u8], allowed: &BTreeSet<String>) -> Option<String> {
    let identities = certificate_subject_alt_names(certificate).ok()?;
    if identities.len() != 1 {
        return None;
    }
    let identity = identities.into_iter().next()?;
    allowed.contains(&identity).then_some(identity)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_security_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "authorization",
            "Bearer first".parse().unwrap_or_else(|_| panic!("header")),
        );
        headers.append(
            "authorization",
            "Bearer second".parse().unwrap_or_else(|_| panic!("header")),
        );
        assert!(single_header(&headers, "authorization").is_none());
    }

    #[test]
    fn common_name_is_not_a_client_identity() {
        assert!(validate_identities(&BTreeSet::from(["CN:identity".into()])).is_err());
    }

    #[test]
    fn token_digest_comparison_is_exact() {
        assert!(constant_time_digest_matches(
            &"a".repeat(64),
            &"a".repeat(64)
        ));
        assert!(!constant_time_digest_matches(
            &"a".repeat(63),
            &"a".repeat(64)
        ));
    }

    #[test]
    fn dashboard_resource_is_bounded_and_canonical() {
        assert!(valid_dashboard_resource("credentials"));
        assert!(valid_dashboard_resource("task_credentials"));
        assert!(!valid_dashboard_resource("Credentials"));
        assert!(!valid_dashboard_resource("credentials/../../tenant"));
        assert!(!valid_dashboard_resource(&"a".repeat(101)));
    }
}
