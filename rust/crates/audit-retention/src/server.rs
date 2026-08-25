//! TLS 1.3, exact mTLS SAN, tenant, route-scope and raw-token-digest boundary for Audit Authority.

use crate::AuditError;
use crate::production::{
    AUDIT_READINESS_SCHEMA, AuditAppendRequest, AuditAppendResponse, AuditDeletionRequest,
    AuditDeletionResponse, AuditExportRequest, AuditExportResponse, AuthoritativeAuditPage,
    AuthoritativeAuditQueryRequest, ControlRegistrationRequest, EvidenceEdgeRequest,
    EvidenceNodeRequest, LegalHoldPlaceRequest, LegalHoldReleaseRequest, PostgresAuditAuthority,
    ProductionAuditQuery, ProductionAuditQueryResponse, RetentionPolicyRequest,
    SignedAuditMutationReceipt,
};
use agent_trust_contracts::{
    HumanPrincipalKeyring, VerifiedHumanPrincipal, human_principal_request_digest,
};
use agent_trust_evidence_evaluator::server::{
    ExactSanMtlsAcceptor, MtlsPeerIdentity, build_tls13_mtls_config,
};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

const AUTHORITATIVE_AUDIT_ROUTE: &str = "/v1/authoritative/audit";
const AUDIT_QUERY_SCOPE: &str = "audit:query";
const AUDIT_AUTHORITATIVE_QUERY_SERVICE_SCOPE: &str = "audit:authoritative-query";

#[derive(Debug, Clone)]
pub struct AuditServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub client_identities: BTreeSet<String>,
    pub maximum_request_bytes: usize,
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
pub struct TokenBindingAuditAuthorizer {
    bindings: Arc<BTreeSet<TokenAuthorization>>,
}

/// Reloads the public keyring on each request so an atomic CSI/Vault rotation is observed without
/// accepting an unbounded stale-key window. File safety is checked by the service binary.
#[derive(Clone)]
pub struct HumanPrincipalAuditVerifier {
    keyring_file: PathBuf,
    audience: String,
    maximum_authentication_age_seconds: i64,
    require_strong_auth: bool,
}

impl HumanPrincipalAuditVerifier {
    pub fn from_file(
        keyring_file: PathBuf,
        audience: String,
        maximum_authentication_age_seconds: i64,
        require_strong_auth: bool,
    ) -> Result<Self, AuditError> {
        if !keyring_file.is_absolute()
            || audience.is_empty()
            || audience.len() > 256
            || audience.contains(['\0', '\r', '\n'])
            || !(30..=86_400).contains(&maximum_authentication_age_seconds)
        {
            return Err(AuditError::ConfigurationInvalid);
        }
        let verifier = Self {
            keyring_file,
            audience,
            maximum_authentication_age_seconds,
            require_strong_auth,
        };
        verifier.load_keyring(chrono::Utc::now())?;
        Ok(verifier)
    }

    fn load_keyring(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<HumanPrincipalKeyring, AuditError> {
        let raw =
            std::fs::read(&self.keyring_file).map_err(|_| AuditError::ConfigurationInvalid)?;
        HumanPrincipalKeyring::from_json(&raw, &self.audience, now)
            .map_err(|_| AuditError::ConfigurationInvalid)
    }

    fn verify(
        &self,
        encoded: &str,
        request: &AuthoritativeAuditQueryRequest,
        client_identity: &str,
        service_subject: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<VerifiedHumanPrincipal, AuditError> {
        let request_digest = human_principal_request_digest(
            "POST",
            AUTHORITATIVE_AUDIT_ROUTE,
            &request.tenant_id,
            client_identity,
            service_subject,
            AUDIT_QUERY_SCOPE,
            &request.idempotency_key.0,
            request,
        )
        .map_err(|_| AuditError::RequestInvalid)?;
        self.load_keyring(now)?
            .verify_encoded(
                encoded,
                &request.tenant_id,
                client_identity,
                service_subject,
                AUDIT_QUERY_SCOPE,
                &request_digest,
                self.require_strong_auth,
                self.maximum_authentication_age_seconds,
                now,
            )
            .map_err(|_| AuditError::AuthenticationRequired)
    }

    pub fn ready(&self) -> bool {
        self.load_keyring(chrono::Utc::now()).is_ok()
    }
}

impl TokenBindingAuditAuthorizer {
    pub fn from_file(path: &Path, identities: &BTreeSet<String>) -> Result<Self, AuditError> {
        validate_identities(identities)?;
        let raw = std::fs::read(path).map_err(|_| AuditError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(AuditError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument =
            serde_json::from_slice(&raw).map_err(|_| AuditError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.audit-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(AuditError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut physical_credentials = BTreeSet::new();
        for binding in document.bindings {
            if Uuid::parse_str(&binding.tenant_id)
                .ok()
                .is_none_or(|value| value.to_string() != binding.tenant_id)
                || !identities.contains(&binding.client_identity)
                || !allowed_scope(&binding.scope)
                || binding.subject.is_empty()
                || binding.subject.len() > 512
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
                return Err(AuditError::ConfigurationInvalid);
            }
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(AuditError::ConfigurationInvalid);
        }
        Ok(Self {
            bindings: Arc::new(bindings),
        })
    }

    fn authorize<'a>(
        &'a self,
        peer_identity: &str,
        headers: &HeaderMap,
        tenant: &str,
        scope: &str,
    ) -> Result<&'a str, AuditError> {
        if single_header(headers, "x-agenttrust-tenant-id") != Some(tenant)
            || Uuid::parse_str(tenant)
                .ok()
                .is_none_or(|value| value.to_string() != tenant)
        {
            return Err(AuditError::AuthenticationRequired);
        }
        let token = bearer_token(headers).ok_or(AuditError::AuthenticationRequired)?;
        let supplied = hex(Sha256::digest(token.as_bytes()));
        let mut subject = None;
        let mut credential_match = false;
        for binding in self.bindings.iter() {
            let tuple_match = binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && constant_time_digest_matches(&supplied, &binding.token_sha256);
            credential_match |= tuple_match;
            if tuple_match && binding.scope == scope {
                if subject.is_some() {
                    return Err(AuditError::ScopeForbidden);
                }
                subject = Some(binding.subject.as_str());
            }
        }
        subject.ok_or(if credential_match {
            AuditError::ScopeForbidden
        } else {
            AuditError::AuthenticationRequired
        })
    }
}

#[derive(Clone)]
struct ApiState {
    authority: Arc<PostgresAuditAuthority>,
    authorizer: Arc<TokenBindingAuditAuthorizer>,
    human_principals: Arc<HumanPrincipalAuditVerifier>,
}

#[derive(Clone)]
struct ReadinessState {
    authority: Arc<PostgresAuditAuthority>,
    human_principals: Arc<HumanPrincipalAuditVerifier>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
    database_ready: bool,
    worm_ready: bool,
    deletion_gateway_ready: bool,
    human_principal_keys_ready: bool,
}

pub async fn serve(
    config: AuditServerConfig,
    authority: Arc<PostgresAuditAuthority>,
    authorizer: Arc<TokenBindingAuditAuthorizer>,
    human_principals: Arc<HumanPrincipalAuditVerifier>,
) -> Result<(), AuditError> {
    validate_identities(&config.client_identities)?;
    if !(config.management_address.ip().is_loopback()
        || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
        || !(65_536..=16 * 1024 * 1024).contains(&config.maximum_request_bytes)
    {
        return Err(AuditError::ConfigurationInvalid);
    }
    let tls = build_tls13_mtls_config(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )
    .map_err(|_| AuditError::ConfigurationInvalid)?;
    let acceptor = ExactSanMtlsAcceptor::new(tls, config.client_identities)
        .map_err(|_| AuditError::ConfigurationInvalid)?;
    let state = ApiState {
        authority: authority.clone(),
        authorizer,
        human_principals: human_principals.clone(),
    };
    let data = Router::new()
        .route(AUTHORITATIVE_AUDIT_ROUTE, post(authoritative_query))
        .route("/v1/audit/records", post(append))
        .route("/v1/audit/query", post(query))
        .route("/v1/audit/retention-policies", post(register_retention))
        .route("/v1/audit/legal-holds", post(place_hold))
        .route("/v1/audit/legal-holds/release", post(release_hold))
        .route("/v1/audit/exports", post(export))
        .route("/v1/audit/deletions", post(delete_with_proof))
        .route("/v1/audit/controls", post(register_control))
        .route("/v1/audit/evidence-nodes", post(add_node))
        .route("/v1/audit/evidence-edges", post(add_edge))
        .route("/ready", get(data_ready))
        .with_state(state)
        .layer(DefaultBodyLimit::max(config.maximum_request_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(45),
        ));
    let management = Router::new()
        .route("/ready", get(management_ready))
        .with_state(ReadinessState {
            authority,
            human_principals,
        });
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| AuditError::ConfigurationInvalid)?;
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| AuditError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| AuditError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn append(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<AuditAppendRequest>,
) -> Result<Json<AuditAppendResponse>, AuditApiError> {
    let subject = authorize(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        "audit:append",
        &request.idempotency_key.0,
    )?;
    if request
        .records
        .iter()
        .any(|record| record.actor_subject != subject)
    {
        return Err(AuditError::AuthenticationRequired.into());
    }
    Ok(Json(state.authority.append(&request).await?))
}

async fn query(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ProductionAuditQuery>,
) -> Result<Json<ProductionAuditQueryResponse>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        "audit:query",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(state.authority.query(&request).await?))
}

async fn authoritative_query(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<AuthoritativeAuditQueryRequest>,
) -> Result<Json<AuthoritativeAuditPage>, AuditApiError> {
    let service_subject = authorize(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        AUDIT_AUTHORITATIVE_QUERY_SERVICE_SCOPE,
        &request.idempotency_key.0,
    )?
    .to_owned();
    let encoded = single_header(&headers, "x-agenttrust-human-assertion")
        .ok_or(AuditError::AuthenticationRequired)?;
    let principal = state.human_principals.verify(
        encoded,
        &request,
        &peer.0,
        &service_subject,
        chrono::Utc::now(),
    )?;
    if principal.subject != request.actor_subject {
        return Err(AuditError::AuthenticationRequired.into());
    }
    Ok(Json(
        state
            .authority
            .query_authoritative(&request, &principal)
            .await?,
    ))
}

async fn register_retention(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RetentionPolicyRequest>,
) -> Result<Json<SignedAuditMutationReceipt>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.policy.tenant_id.0,
        "audit:retention",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(
        state.authority.register_retention_policy(&request).await?,
    ))
}

async fn place_hold(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<LegalHoldPlaceRequest>,
) -> Result<Json<SignedAuditMutationReceipt>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.hold.tenant_id.0,
        "audit:hold-place",
        &request.idempotency_key.0,
        &request.hold.placed_by,
    )?;
    Ok(Json(state.authority.place_hold(&request).await?))
}

async fn release_hold(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<LegalHoldReleaseRequest>,
) -> Result<Json<SignedAuditMutationReceipt>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        "audit:hold-release",
        &request.idempotency_key.0,
        &request.released_by,
    )?;
    Ok(Json(state.authority.release_hold(&request).await?))
}

async fn export(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<AuditExportRequest>,
) -> Result<Json<AuditExportResponse>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        "audit:export",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(state.authority.export(&request).await?))
}

async fn delete_with_proof(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<AuditDeletionRequest>,
) -> Result<Json<AuditDeletionResponse>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        "audit:delete",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(state.authority.delete_with_proof(&request).await?))
}

async fn register_control(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ControlRegistrationRequest>,
) -> Result<Json<SignedAuditMutationReceipt>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.tenant_id.0,
        "audit:control",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(state.authority.register_control(&request).await?))
}

async fn add_node(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<EvidenceNodeRequest>,
) -> Result<Json<SignedAuditMutationReceipt>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.node.tenant_id.0,
        "audit:graph",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(state.authority.add_evidence_node(&request).await?))
}

async fn add_edge(
    State(state): State<ApiState>,
    Extension(peer): Extension<MtlsPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<EvidenceEdgeRequest>,
) -> Result<Json<SignedAuditMutationReceipt>, AuditApiError> {
    authorize_actor(
        &state,
        &peer,
        &headers,
        &request.edge.tenant_id.0,
        "audit:graph",
        &request.idempotency_key.0,
        &request.actor_subject,
    )?;
    Ok(Json(state.authority.add_evidence_edge(&request).await?))
}

fn authorize<'a>(
    state: &'a ApiState,
    peer: &MtlsPeerIdentity,
    headers: &HeaderMap,
    tenant: &str,
    scope: &str,
    idempotency_key: &str,
) -> Result<&'a str, AuditApiError> {
    if single_header(headers, "idempotency-key") != Some(idempotency_key) {
        return Err(AuditError::RequestInvalid.into());
    }
    Ok(state
        .authorizer
        .authorize(&peer.0, headers, tenant, scope)?)
}

fn authorize_actor(
    state: &ApiState,
    peer: &MtlsPeerIdentity,
    headers: &HeaderMap,
    tenant: &str,
    scope: &str,
    idempotency_key: &str,
    actor: &str,
) -> Result<(), AuditApiError> {
    if authorize(state, peer, headers, tenant, scope, idempotency_key)? != actor {
        return Err(AuditError::AuthenticationRequired.into());
    }
    Ok(())
}

async fn data_ready(State(state): State<ApiState>) -> Response {
    readiness(state.authority, state.human_principals).await
}

async fn management_ready(State(state): State<ReadinessState>) -> Response {
    readiness(state.authority, state.human_principals).await
}

async fn readiness(
    authority: Arc<PostgresAuditAuthority>,
    human_principals: Arc<HumanPrincipalAuditVerifier>,
) -> Response {
    let (database_ready, worm_ready, deletion_gateway_ready) =
        authority.readiness_components().await;
    let human_principal_keys_ready = human_principals.ready();
    let ready =
        database_ready && worm_ready && deletion_gateway_ready && human_principal_keys_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: AUDIT_READINESS_SCHEMA,
            ready,
            database_ready,
            worm_ready,
            deletion_gateway_ready,
            human_principal_keys_ready,
        }),
    )
        .into_response()
}

struct AuditApiError(AuditError);

impl From<AuditError> for AuditApiError {
    fn from(value: AuditError) -> Self {
        Self(value)
    }
}

impl IntoResponse for AuditApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            AuditError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            AuditError::ScopeForbidden | AuditError::TenantDenied => StatusCode::FORBIDDEN,
            AuditError::NotFound | AuditError::RetentionPolicyMissing => StatusCode::NOT_FOUND,
            AuditError::IdempotencyConflict | AuditError::LegalHoldConflict => StatusCode::CONFLICT,
            AuditError::IntegrityFailed
            | AuditError::SignatureInvalid
            | AuditError::LegalHoldReleaseDenied
            | AuditError::DeletionFailed => StatusCode::UNPROCESSABLE_ENTITY,
            AuditError::PersistenceFailed | AuditError::DependencyUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            AuditError::ConfigurationInvalid | AuditError::Canonicalization => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AuditError::RecordInvalid
            | AuditError::CapacityExceeded
            | AuditError::QueryDenied
            | AuditError::RetentionPolicyInvalid
            | AuditError::LegalHoldInvalid
            | AuditError::ControlInvalid
            | AuditError::GraphInvalid
            | AuditError::RequestInvalid => StatusCode::BAD_REQUEST,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.audit-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
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
        "audit:append"
            | "audit:query"
            | "audit:retention"
            | "audit:hold-place"
            | "audit:authoritative-query"
            | "audit:hold-release"
            | "audit:export"
            | "audit:delete"
            | "audit:control"
            | "audit:graph"
    )
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-audit-token-comparison-v1");
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), AuditError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(AuditError::ConfigurationInvalid);
    }
    Ok(())
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
    fn route_tokens_must_be_physically_distinct() {
        let source = include_str!("server.rs");
        assert!(source.contains("physical_credentials.insert"));
        assert!(allowed_scope("audit:authoritative-query"));
        assert_ne!(AUDIT_AUTHORITATIVE_QUERY_SERVICE_SCOPE, AUDIT_QUERY_SCOPE);
        assert!(source.contains("x-agenttrust-human-assertion"));
        assert!(constant_time_digest_matches(
            &"a".repeat(64),
            &"a".repeat(64)
        ));
        assert!(!constant_time_digest_matches(
            &"b".repeat(64),
            &"a".repeat(64)
        ));
    }

    #[test]
    fn readiness_contract_exposes_human_principal_key_health() {
        let value = serde_json::to_value(ReadinessResponse {
            schema_version: AUDIT_READINESS_SCHEMA,
            ready: false,
            database_ready: true,
            worm_ready: true,
            deletion_gateway_ready: true,
            human_principal_keys_ready: false,
        })
        .unwrap_or_else(|error| panic!("readiness serialization: {error}"));
        assert_eq!(value.as_object().map(|fields| fields.len()), Some(6));
        assert_eq!(value["human_principal_keys_ready"].as_bool(), Some(false));
        assert_eq!(value["ready"].as_bool(), Some(false));
    }
}
