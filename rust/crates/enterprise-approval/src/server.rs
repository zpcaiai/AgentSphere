//! Native TLS 1.3, exact mTLS SAN identity, and token-bound approval API.

use super::*;
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

pub const APPROVAL_READINESS_SCHEMA_VERSION: &str = "agenttrust.approval-readiness.v1";

#[derive(Debug, Clone)]
pub struct ApprovalServerConfig {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalServicePrincipal {
    tenant_id: TenantId,
    subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoritativeApprovalQuery {
    resource: Option<String>,
    limit: Option<u16>,
    cursor: Option<String>,
}

pub struct TokenBindingApprovalAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
    tenants: BTreeSet<TenantId>,
}

impl TokenBindingApprovalAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed_identities: &BTreeSet<String>,
    ) -> Result<Self, ApprovalError> {
        validate_client_identities(allowed_identities)?;
        let raw = std::fs::read(path).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument =
            serde_json::from_slice(&raw).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.approval-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut unique_credentials = BTreeSet::new();
        let mut tenants = BTreeSet::new();
        for binding in document.bindings {
            if !allowed_identities.contains(&binding.client_identity)
                || !allowed_scope(&binding.scope)
                || !subject_identifier(&binding.subject)
                || !digest(&binding.token_sha256)
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            let parsed_tenant = Uuid::parse_str(&binding.tenant_id)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let tenant = parsed_tenant.to_string();
            if tenant != binding.tenant_id {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            let credential = (
                binding.client_identity.clone(),
                tenant.clone(),
                binding.token_sha256.clone(),
            );
            if !unique_credentials.insert(credential) {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            tenants.insert(TenantId(tenant.clone()));
            if !bindings.insert(TokenAuthorization {
                client_identity: binding.client_identity,
                tenant_id: tenant,
                subject: binding.subject,
                scope: binding.scope,
                token_sha256: binding.token_sha256,
            }) {
                return Err(ApprovalError::ConfigurationInvalid);
            }
        }
        if allowed_identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        for tenant in &tenants {
            for scope in [
                "approvals:read",
                "approvals:request",
                "approvals:decide",
                "approvals:issue",
                "approvals:revoke",
                "approvals:consume",
                "approvals:verify",
            ] {
                if !bindings
                    .iter()
                    .any(|binding| binding.tenant_id == tenant.0 && binding.scope == scope)
                {
                    return Err(ApprovalError::ConfigurationInvalid);
                }
            }
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
        scope: &str,
    ) -> Result<ApprovalServicePrincipal, ApprovalError> {
        let tenant = single_header(headers, "x-agenttrust-tenant-id")
            .and_then(|value| {
                let parsed = Uuid::parse_str(value).ok()?;
                (parsed.to_string() == value).then(|| parsed.to_string())
            })
            .ok_or(ApprovalError::AuthenticationRequired)?;
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
            })
            .ok_or(ApprovalError::AuthenticationRequired)?;
        let supplied_digest = hex::encode(Sha256::digest(token.as_bytes()));
        let mut principal = None;
        let mut credential_matched = false;
        for binding in &self.bindings {
            // The digest comparison is always performed for every configured tuple.
            let token_matches =
                constant_time_digest_matches(&supplied_digest, &binding.token_sha256);
            let credential_tuple_matches = binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && token_matches;
            credential_matched |= credential_tuple_matches;
            if credential_tuple_matches && binding.scope == scope {
                if principal.is_some() {
                    return Err(ApprovalError::ScopeForbidden);
                }
                principal = Some(ApprovalServicePrincipal {
                    tenant_id: TenantId(tenant.clone()),
                    subject: binding.subject.clone(),
                });
            }
        }
        principal.ok_or(if credential_matched {
            ApprovalError::ScopeForbidden
        } else {
            ApprovalError::AuthenticationRequired
        })
    }
}

#[derive(Clone)]
pub struct ApprovalApiState {
    store: Arc<PostgresApprovalStore>,
    authorizer: Arc<TokenBindingApprovalAuthorizer>,
    principal_keyring: Arc<ApprovalPrincipalAssertionKeyring>,
}

impl ApprovalApiState {
    pub fn production(
        store: Arc<PostgresApprovalStore>,
        authorizer: Arc<TokenBindingApprovalAuthorizer>,
        principal_keyring: Arc<ApprovalPrincipalAssertionKeyring>,
    ) -> Result<Self, ApprovalError> {
        if authorizer.bindings.is_empty()
            || authorizer.tenants.is_empty()
            || principal_keyring.is_empty()
            || authorizer
                .tenants
                .iter()
                .any(|tenant| !principal_keyring.covers_tenant_at(tenant, Utc::now()))
            || authorizer
                .tenants
                .iter()
                .any(|tenant| !store.review_evidence_covers(tenant, Utc::now()))
            || authorizer
                .tenants
                .iter()
                .any(|tenant| !store.decision_evidence_delivery_covers(tenant, Utc::now()))
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            authorizer,
            principal_keyring,
        })
    }
}

#[derive(Debug, Clone)]
struct ApprovalPeerIdentity(String);

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

#[derive(Clone)]
struct ManagementState {
    store: Arc<PostgresApprovalStore>,
    principal_keyring: Arc<ApprovalPrincipalAssertionKeyring>,
    tenants: BTreeSet<TenantId>,
}

pub async fn serve(
    config: ApprovalServerConfig,
    state: ApprovalApiState,
) -> Result<(), ApprovalError> {
    validate_client_identities(&config.client_identities)?;
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let management_state = ManagementState {
        store: state.store.clone(),
        principal_keyring: state.principal_keyring.clone(),
        tenants: state.authorizer.tenants.clone(),
    };
    let management = Router::new()
        .route("/ready", get(ready))
        .with_state(management_state);
    let data = approval_router(state)
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)));
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| ApprovalError::ConfigurationInvalid)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| ApprovalError::DatabaseUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| ApprovalError::DatabaseUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

fn approval_router(state: ApprovalApiState) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route(
            "/v1/authoritative/approvals",
            get(list_authoritative_approvals),
        )
        .route("/v1/approvals/cases", post(create_case))
        .route("/v1/approvals/cases/{case_id}", get(get_case))
        .route("/v1/approvals/cases/{case_id}/decisions", post(decide))
        .route("/v1/approvals/cases/{case_id}/grants", post(issue_grant))
        .route("/v1/approvals/grants/{grant_id}/revoke", post(revoke_grant))
        .route("/v1/approvals/grants/consume", post(consume_grant))
        .route(
            "/v1/approvals/consumptions/{consumption_ref}",
            get(get_consumption),
        )
        .with_state(state)
}

async fn data_ready(State(state): State<ApprovalApiState>) -> Response {
    let now = Utc::now();
    let available = state.store.ready().await
        && principal_keys_ready(
            &state.principal_keyring,
            &state.authorizer.tenants,
            now,
        )
        && review_evidence_keys_ready(
            &state.store,
            &state.authorizer.tenants,
            now,
        )
        && decision_evidence_delivery_keys_ready(
            &state.store,
            &state.authorizer.tenants,
            now,
        )
        && state.store.decision_evidence_outbox_ready(
            &state.authorizer.tenants, now,
        ).await;
    readiness_response(available)
}

async fn ready(State(state): State<ManagementState>) -> Response {
    let now = Utc::now();
    let available = state.store.ready().await
        && principal_keys_ready(&state.principal_keyring, &state.tenants, now)
        && review_evidence_keys_ready(&state.store, &state.tenants, now)
        && decision_evidence_delivery_keys_ready(&state.store, &state.tenants, now)
        && state.store.decision_evidence_outbox_ready(&state.tenants, now).await;
    readiness_response(available)
}

fn principal_keys_ready(
    keyring: &ApprovalPrincipalAssertionKeyring,
    tenants: &BTreeSet<TenantId>,
    now: DateTime<Utc>,
) -> bool {
    !tenants.is_empty()
        && tenants
            .iter()
            .all(|tenant| keyring.covers_tenant_at(tenant, now))
}

fn review_evidence_keys_ready(
    store: &PostgresApprovalStore,
    tenants: &BTreeSet<TenantId>,
    now: DateTime<Utc>,
) -> bool {
    !tenants.is_empty()
        && tenants
            .iter()
            .all(|tenant| store.review_evidence_covers(tenant, now))
}

fn decision_evidence_delivery_keys_ready(
    store: &PostgresApprovalStore,
    tenants: &BTreeSet<TenantId>,
    now: DateTime<Utc>,
) -> bool {
    !tenants.is_empty()
        && tenants
            .iter()
            .all(|tenant| store.decision_evidence_delivery_covers(tenant, now))
}

fn readiness_response(available: bool) -> Response {
    let status = if available {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "schema_version": APPROVAL_READINESS_SCHEMA_VERSION,
            "ready": available
        })),
    )
        .into_response()
}

async fn create_case(
    State(state): State<ApprovalApiState>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ApprovalCaseCreateEnvelope>,
) -> Result<(StatusCode, Json<ApprovalCase>), ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:request")?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let now = Utc::now();
    let principal = required_human_principal(
        &state,
        &peer.0,
        &service,
        "approvals:request",
        "POST",
        "/v1/approvals/cases",
        idempotency_key,
        &request,
        now,
        &headers,
    )?;
    let case = state
        .store
        .create_case(&request, &principal, idempotency_key, now)
        .await?;
    Ok((StatusCode::CREATED, Json(case)))
}

async fn get_case(
    State(state): State<ApprovalApiState>,
    AxumPath(case_id): AxumPath<String>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
) -> Result<Json<ApprovalCase>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:read")?;
    Ok(Json(
        state.store.get_case(&service.tenant_id, &case_id).await?,
    ))
}

async fn list_authoritative_approvals(
    State(state): State<ApprovalApiState>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<AuthoritativeApprovalQuery>,
) -> Result<Json<AuthoritativeApprovalPage>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:read")?;
    let resource = query.resource.as_deref().unwrap_or("summary");
    let limit = query.limit.unwrap_or(50);
    Ok(Json(
        state
            .store
            .list_authoritative_cases(
                &service.tenant_id,
                resource,
                limit,
                query.cursor.as_deref(),
                Utc::now(),
            )
            .await?,
    ))
}

async fn decide(
    State(state): State<ApprovalApiState>,
    AxumPath(case_id): AxumPath<String>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ApprovalDecisionEnvelope>,
) -> Result<Json<ApprovalDecisionResult>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:decide")?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let now = Utc::now();
    let path = format!("/v1/approvals/cases/{case_id}/decisions");
    let principal = required_human_principal(
        &state,
        &peer.0,
        &service,
        "approvals:decide",
        "POST",
        &path,
        idempotency_key,
        &request,
        now,
        &headers,
    )?;
    Ok(Json(
        state
            .store
            .decide(&case_id, &request, &principal, idempotency_key, now)
            .await?,
    ))
}

async fn issue_grant(
    State(state): State<ApprovalApiState>,
    AxumPath(case_id): AxumPath<String>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ApprovalGrantIssueRequest>,
) -> Result<Json<EnterpriseApprovalGrant>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:issue")?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let now = Utc::now();
    let path = format!("/v1/approvals/cases/{case_id}/grants");
    let principal = required_human_principal(
        &state,
        &peer.0,
        &service,
        "approvals:issue",
        "POST",
        &path,
        idempotency_key,
        &request,
        now,
        &headers,
    )?;
    Ok(Json(
        state
            .store
            .issue_grant(&case_id, &request, &principal, idempotency_key, now)
            .await?,
    ))
}

async fn revoke_grant(
    State(state): State<ApprovalApiState>,
    AxumPath(grant_id): AxumPath<String>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ApprovalGrantRevocationRequest>,
) -> Result<Json<ApprovalGrantRevocationReceipt>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:revoke")?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let now = Utc::now();
    let path = format!("/v1/approvals/grants/{grant_id}/revoke");
    let principal = required_human_principal(
        &state,
        &peer.0,
        &service,
        "approvals:revoke",
        "POST",
        &path,
        idempotency_key,
        &request,
        now,
        &headers,
    )?;
    Ok(Json(
        state
            .store
            .revoke_grant(&grant_id, &request, &principal, idempotency_key, now)
            .await?,
    ))
}

async fn consume_grant(
    State(state): State<ApprovalApiState>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ApprovalConsumptionRequest>,
) -> Result<Json<ApprovalGrantReceipt>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:consume")?;
    let idempotency_key = required_idempotency_key(&headers)?;
    Ok(Json(
        state
            .store
            .consume_grant(
                &request,
                &service.tenant_id,
                &service.subject,
                &peer.0,
                idempotency_key,
                Utc::now(),
            )
            .await?,
    ))
}

async fn get_consumption(
    State(state): State<ApprovalApiState>,
    AxumPath(consumption_ref): AxumPath<String>,
    Extension(peer): Extension<ApprovalPeerIdentity>,
    headers: HeaderMap,
) -> Result<Json<SignedApprovalConsumptionReceipt>, ApprovalApiError> {
    let service = state
        .authorizer
        .authorize(&peer.0, &headers, "approvals:verify")?;
    Ok(Json(
        state
            .store
            .get_consumption_by_reference(&service.tenant_id, &consumption_ref)
            .await?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn required_human_principal<T: Serialize>(
    state: &ApprovalApiState,
    peer_identity: &str,
    service: &ApprovalServicePrincipal,
    scope: &str,
    method: &'static str,
    path: &str,
    idempotency_key: &str,
    body: &T,
    now: DateTime<Utc>,
    headers: &HeaderMap,
) -> Result<ApprovalPrincipal, ApprovalError> {
    let request_digest = approval_principal_request_digest(
        method,
        path,
        &service.tenant_id.0,
        peer_identity,
        &service.subject,
        scope,
        idempotency_key,
        body,
    )?;
    let assertion = single_header(headers, "x-agenttrust-principal-assertion")
        .ok_or(ApprovalError::AuthenticationRequired)?;
    state.principal_keyring.verify_encoded(
        assertion,
        &service.tenant_id,
        peer_identity,
        scope,
        &request_digest,
        now,
    )
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, ApprovalError> {
    single_header(headers, "Idempotency-Key")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
        })
        .ok_or(ApprovalError::IdempotencyInvalid)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

struct ApprovalApiError(ApprovalError);

impl From<ApprovalError> for ApprovalApiError {
    fn from(value: ApprovalError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApprovalApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ApprovalError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            ApprovalError::ScopeForbidden
            | ApprovalError::ApproverNotEligible
            | ApprovalError::ApproverRoleChanged
            | ApprovalError::BreakGlassDenied => StatusCode::FORBIDDEN,
            ApprovalError::CaseNotFound | ApprovalError::GrantInvalid => StatusCode::NOT_FOUND,
            ApprovalError::IdempotencyConflict
            | ApprovalError::DuplicateApprover
            | ApprovalError::GrantReplayed
            | ApprovalError::ConcurrentMutation
            | ApprovalError::LifecycleInvalid => StatusCode::CONFLICT,
            ApprovalError::Expired | ApprovalError::Revoked | ApprovalError::GrantNotReady => {
                StatusCode::GONE
            }
            ApprovalError::DatabaseUnavailable | ApprovalError::ConfigurationInvalid => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ApprovalError::IdempotencyInvalid
            | ApprovalError::PolicyInvalid
            | ApprovalError::RequestInvalid
            | ApprovalError::BindingChanged => StatusCode::BAD_REQUEST,
            ApprovalError::NotificationFailed => StatusCode::BAD_GATEWAY,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.approval-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-approval-token-comparison-v1",
    );
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn allowed_scope(value: &str) -> bool {
    matches!(
        value,
        "approvals:read"
            | "approvals:request"
            | "approvals:decide"
            | "approvals:issue"
            | "approvals:revoke"
            | "approvals:consume"
            | "approvals:verify"
    )
}

fn subject_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn validate_client_identities(identities: &BTreeSet<String>) -> Result<(), ApprovalError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(ApprovalError::ConfigurationInvalid);
    }
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, ApprovalError> {
    let mut ca_reader =
        BufReader::new(File::open(ca_file).map_err(|_| ApprovalError::ConfigurationInvalid)?);
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ApprovalError::ConfigurationInvalid)?;
    if ca_certificates.is_empty() {
        return Err(ApprovalError::ConfigurationInvalid);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 || rejected != 0 {
        return Err(ApprovalError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| ApprovalError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| ApprovalError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ApprovalError::ConfigurationInvalid)?;
    if certificates.is_empty() {
        return Err(ApprovalError::ConfigurationInvalid);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| ApprovalError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| ApprovalError::ConfigurationInvalid)?
        .ok_or(ApprovalError::ConfigurationInvalid)?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ApprovalError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| ApprovalError::ConfigurationInvalid)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, ApprovalPeerIdentity>;
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
                .ok_or_else(|| io_denied("approval client certificate missing"))?;
            let identity = certificates
                .first()
                .and_then(|certificate| exact_certificate_identity(certificate.as_ref(), &allowed))
                .ok_or_else(|| io_denied("approval client certificate SAN is not exact"))?;
            Ok((
                stream,
                Extension(ApprovalPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn io_denied(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn exact_certificate_identity(certificate: &[u8], allowed: &BTreeSet<String>) -> Option<String> {
    let identities = certificate_subject_alt_names(certificate).ok()?;
    if identities.len() == 1 && allowed.contains(&identities[0]) {
        identities.into_iter().next()
    } else {
        None
    }
}

/// Pins the configured outbound Evidence source identity to the leaf
/// certificate's single DNS/URI SAN before the service can become ready.
pub fn validate_certificate_identity_file(
    certificate_file: &Path,
    expected_identity: &str,
) -> Result<(), ApprovalError> {
    let allowed = BTreeSet::from([expected_identity.to_string()]);
    validate_client_identities(&allowed)?;
    let mut reader = BufReader::new(
        File::open(certificate_file).map_err(|_| ApprovalError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ApprovalError::ConfigurationInvalid)?;
    let leaf = certificates
        .first()
        .ok_or(ApprovalError::ConfigurationInvalid)?;
    if exact_certificate_identity(leaf.as_ref(), &allowed).as_deref() != Some(expected_identity) {
        return Err(ApprovalError::ConfigurationInvalid);
    }
    Ok(())
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
    let mut tbs_offset = 0;
    let mut san_extension = None;
    while tbs_offset < tbs.len() {
        let (tag, value, next) = der_element(tbs, tbs_offset)?;
        tbs_offset = next;
        if tag != 0xa3 {
            continue;
        }
        let (extensions_tag, extensions, extensions_end) = der_element(value, 0)?;
        if extensions_tag != 0x30 || extensions_end != value.len() {
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
            if oid == [0x55, 0x1d, 0x11] && san_extension.replace(extension_value).is_some() {
                return Err(());
            }
        }
    }
    let extension = san_extension.ok_or(())?;
    let (names_tag, names, names_end) = der_element(extension, 0)?;
    if names_tag != 0x30 || names_end != extension.len() {
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
    fn common_name_is_never_an_approval_identity() {
        assert!(validate_client_identities(&BTreeSet::from(["CN:approval".into()])).is_err());
    }

    #[test]
    fn token_comparison_is_exact() {
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
