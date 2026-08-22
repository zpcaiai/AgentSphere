//! TLS 1.3, exact single-SAN mTLS boundary for the production Agent Registry authority.

use crate::RegistryError;
use crate::production::{
    BomUpdateRequest, DiscoveryIngestRequest, LifecycleRequest, OwnershipAssignmentRequest,
    OwnershipConfirmationRequest, PostgresAgentRegistryAuthority, PostureEvaluationRequest,
    RegistrationRequest, RelationshipEdgeRequest,
};
use agent_trust_contracts::TenantId;
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
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
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

pub const AGENT_REGISTRY_READINESS_SCHEMA: &str = "agenttrust.agent-registry-readiness.v1";
pub const AGENT_REGISTRY_ERROR_SCHEMA: &str = "agenttrust.agent-registry-error.v1";
const TOKEN_BINDING_SCHEMA: &str = "agenttrust.agent-registry-token-bindings.v1";

#[derive(Debug, Clone)]
pub struct AgentRegistryServerConfig {
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
pub struct TokenBindingAgentRegistryAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
    tenants: BTreeSet<TenantId>,
}

#[derive(Clone)]
struct RequestContext {
    tenant_id: TenantId,
    subject: String,
}

impl TokenBindingAgentRegistryAuthorizer {
    pub fn from_file(path: &Path, identities: &BTreeSet<String>) -> Result<Self, RegistryError> {
        validate_identities(identities)?;
        let raw = std::fs::read(path).map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(RegistryError::ProductionTrustNotConfigured);
        }
        let document = strict_token_document(&raw)?;
        if document.schema_version != TOKEN_BINDING_SCHEMA
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(RegistryError::ProductionTrustNotConfigured);
        }
        let mut bindings = BTreeSet::new();
        let mut token_digests = BTreeSet::new();
        let mut tenants = BTreeSet::new();
        for binding in document.bindings {
            let tenant = Uuid::parse_str(&binding.tenant_id)
                .ok()
                .filter(|value| value.to_string() == binding.tenant_id)
                .ok_or(RegistryError::ProductionTrustNotConfigured)?;
            if !identities.contains(&binding.client_identity)
                || !valid_subject(&binding.subject)
                || !valid_scope(&binding.scope)
                || !lower_digest(&binding.token_sha256)
                || !token_digests.insert(binding.token_sha256.clone())
            {
                return Err(RegistryError::ProductionTrustNotConfigured);
            }
            let tenant_id = TenantId(tenant.to_string());
            if !bindings.insert(TokenAuthorization {
                client_identity: binding.client_identity,
                tenant_id: tenant_id.0.clone(),
                subject: binding.subject,
                scope: binding.scope,
                token_sha256: binding.token_sha256,
            }) {
                return Err(RegistryError::ProductionTrustNotConfigured);
            }
            tenants.insert(tenant_id);
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(RegistryError::ProductionTrustNotConfigured);
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
    ) -> Result<RequestContext, RegistryError> {
        let tenant = single_header(headers, "x-agenttrust-tenant-id")
            .and_then(|value| {
                Uuid::parse_str(value)
                    .ok()
                    .filter(|tenant| tenant.to_string() == value)
            })
            .map(|tenant| tenant.to_string())
            .ok_or(RegistryError::ManagementForbidden)?;
        if let Some(legacy) = optional_single_header(headers, "x-tenant-id")? {
            if legacy != tenant {
                return Err(RegistryError::ManagementForbidden);
            }
        }
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
            })
            .ok_or(RegistryError::ManagementForbidden)?;
        let supplied = hex::encode(Sha256::digest(token.as_bytes()));
        let mut context = None;
        for binding in &self.bindings {
            if binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && binding.scope == required_scope
                && constant_time_digest_matches(&supplied, &binding.token_sha256)
            {
                if context.is_some() {
                    return Err(RegistryError::ManagementForbidden);
                }
                context = Some(RequestContext {
                    tenant_id: TenantId(tenant.clone()),
                    subject: binding.subject.clone(),
                });
            }
        }
        context.ok_or(RegistryError::ManagementForbidden)
    }
}

fn strict_token_document(raw: &[u8]) -> Result<TokenBindingDocument, RegistryError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    deserializer
        .end()
        .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    serde_json::from_value(value.0).map_err(|_| RegistryError::ProductionTrustNotConfigured)
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
        formatter.write_str("strict JSON without duplicate object members")
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
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
            if values.len() > 10_001 {
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
            if values.len() > 10_001 {
                return Err(de::Error::custom("JSON object capacity exceeded"));
            }
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[derive(Clone)]
struct ApiState {
    authority: Arc<PostgresAgentRegistryAuthority>,
    authorizer: Arc<TokenBindingAgentRegistryAuthorizer>,
}

#[derive(Clone)]
struct ManagementState {
    authority: Arc<PostgresAgentRegistryAuthority>,
    tenants: Arc<BTreeSet<TenantId>>,
}

#[derive(Clone, Debug)]
struct AgentRegistryPeerIdentity(String);

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
    database_ready: bool,
    lifecycle_dependencies_ready: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    schema_version: &'static str,
    error: String,
    trace_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentQuery {
    resource: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingsQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipQuery {
    root: String,
    maximum_depth: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

pub async fn serve(
    config: AgentRegistryServerConfig,
    authority: Arc<PostgresAgentRegistryAuthority>,
    authorizer: Arc<TokenBindingAgentRegistryAuthorizer>,
) -> Result<(), RegistryError> {
    validate_identities(&config.client_identities)?;
    if authorizer.tenants().is_empty() {
        return Err(RegistryError::ProductionTrustNotConfigured);
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
        .route("/v1/authoritative/agents", get(list_agents))
        .route("/v1/agents/registrations", post(register_agent))
        .route("/v1/discovery/observations", post(ingest_discovery))
        .route(
            "/v1/agents/{agent_id}/ownership/assignments",
            post(assign_ownership),
        )
        .route(
            "/v1/agents/{agent_id}/ownership/confirmations",
            post(confirm_ownership),
        )
        .route("/v1/agents/{agent_id}/bom", post(update_bom))
        .route("/v1/relationships", post(add_relationship))
        .route("/v1/relationships/graph", get(query_relationships))
        .route("/v1/posture/evaluations", post(evaluate_posture))
        .route("/v1/posture/findings", get(list_findings))
        .route(
            "/v1/agents/{agent_id}/lifecycle",
            post(transition_lifecycle),
        )
        .with_state(api_state)
        .layer(Extension(management_state.clone()))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)));
    let management = Router::new()
        .route("/ready", get(management_ready))
        .with_state(management_state);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| RegistryError::StoreFailure)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| RegistryError::StoreFailure)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn list_agents(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> Response {
    let result = async {
        let context = state
            .authorizer
            .authorize(&peer.0, &headers, "agents:read")?;
        state
            .authority
            .list_agents(
                &context.tenant_id,
                query.resource.as_deref().unwrap_or("summary"),
                query.cursor.as_deref(),
                query.limit.unwrap_or(50),
                chrono::Utc::now(),
            )
            .await
    }
    .await;
    result_response(result)
}

async fn register_agent(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:register",
        &request_tenant,
        move |context, key| async move {
            authority
                .register(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn ingest_discovery(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<DiscoveryIngestRequest>,
) -> Response {
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:discover",
        &request_tenant,
        move |context, key| async move {
            authority
                .ingest_discovery(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn assign_ownership(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    AxumPath(agent_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<OwnershipAssignmentRequest>,
) -> Response {
    if request.agent_id != agent_id {
        return error_response(RegistryError::TenantMismatch);
    }
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:ownership:assign",
        &request_tenant,
        move |context, key| async move {
            authority
                .assign_ownership(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn confirm_ownership(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    AxumPath(agent_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<OwnershipConfirmationRequest>,
) -> Response {
    if request.agent_id != agent_id {
        return error_response(RegistryError::TenantMismatch);
    }
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:ownership:confirm",
        &request_tenant,
        move |context, key| async move {
            authority
                .confirm_ownership(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn update_bom(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    AxumPath(agent_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<BomUpdateRequest>,
) -> Response {
    if request.agent_id != agent_id {
        return error_response(RegistryError::TenantMismatch);
    }
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:bom",
        &request_tenant,
        move |context, key| async move {
            authority
                .update_bom(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn add_relationship(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RelationshipEdgeRequest>,
) -> Response {
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:relationships:write",
        &request_tenant,
        move |context, key| async move {
            authority
                .add_relationship(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn evaluate_posture(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<PostureEvaluationRequest>,
) -> Response {
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:posture:evaluate",
        &request_tenant,
        move |context, key| async move {
            authority
                .evaluate_posture(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn transition_lifecycle(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    AxumPath(agent_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<LifecycleRequest>,
) -> Response {
    if request.agent_id != agent_id {
        return error_response(RegistryError::TenantMismatch);
    }
    let authority = state.authority.clone();
    let request_tenant = request.tenant_id.clone();
    authorized_write(
        &state,
        &peer,
        &headers,
        "agents:lifecycle",
        &request_tenant,
        move |context, key| async move {
            authority
                .transition_lifecycle(&request, &key, &context.subject, chrono::Utc::now())
                .await
        },
    )
    .await
}

async fn list_findings(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<FindingsQuery>,
) -> Response {
    let result = async {
        let context = state
            .authorizer
            .authorize(&peer.0, &headers, "agents:posture:read")?;
        state
            .authority
            .list_findings(
                &context.tenant_id,
                query.cursor.as_deref(),
                query.limit.unwrap_or(50),
                chrono::Utc::now(),
            )
            .await
    }
    .await;
    result_response(result)
}

async fn query_relationships(
    State(state): State<ApiState>,
    Extension(peer): Extension<AgentRegistryPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<RelationshipQuery>,
) -> Response {
    let result = async {
        let context = state
            .authorizer
            .authorize(&peer.0, &headers, "agents:relationships:read")?;
        state
            .authority
            .query_relationship_graph(
                &context.tenant_id,
                &query.root,
                query.maximum_depth.unwrap_or(3),
                query.limit.unwrap_or(50),
            )
            .await
    }
    .await;
    result_response(result)
}

async fn authorized_write<F, Fut, T>(
    state: &ApiState,
    peer: &AgentRegistryPeerIdentity,
    headers: &HeaderMap,
    scope: &str,
    request_tenant: &TenantId,
    operation: F,
) -> Response
where
    F: FnOnce(RequestContext, String) -> Fut,
    Fut: Future<Output = Result<T, RegistryError>>,
    T: Serialize,
{
    let result = async {
        let context = state.authorizer.authorize(&peer.0, headers, scope)?;
        if &context.tenant_id != request_tenant {
            return Err(RegistryError::TenantMismatch);
        }
        let key = required_idempotency(headers)?;
        operation(context, key).await
    }
    .await;
    result_response(result)
}

async fn management_ready(State(state): State<ManagementState>) -> Response {
    readiness_response(&state).await
}

async fn data_ready(
    Extension(state): Extension<ManagementState>,
    Extension(_peer): Extension<AgentRegistryPeerIdentity>,
) -> Response {
    readiness_response(&state).await
}

async fn readiness_response(state: &ManagementState) -> Response {
    let database_ready = state.authority.ready(&state.tenants, false).await;
    let lifecycle_dependencies_ready = state.authority.lifecycle_ready().await;
    let ready = database_ready && lifecycle_dependencies_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: AGENT_REGISTRY_READINESS_SCHEMA,
            ready,
            database_ready,
            lifecycle_dependencies_ready,
        }),
    )
        .into_response()
}

fn result_response<T: Serialize>(result: Result<T, RegistryError>) -> Response {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => error_response(error),
    }
}

fn error_response(error: RegistryError) -> Response {
    let status = match error {
        RegistryError::ManagementForbidden | RegistryError::TenantMismatch => StatusCode::FORBIDDEN,
        RegistryError::NotFound => StatusCode::NOT_FOUND,
        RegistryError::RegistrationConflict
        | RegistryError::ObservationConflict
        | RegistryError::IdempotencyConflict
        | RegistryError::LifecycleDenied => StatusCode::CONFLICT,
        RegistryError::CapacityExceeded => StatusCode::TOO_MANY_REQUESTS,
        RegistryError::StoreFailure
        | RegistryError::PersistenceFailed
        | RegistryError::ProductionTrustNotConfigured
        | RegistryError::PropagationFailed => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(ErrorResponse {
            schema_version: AGENT_REGISTRY_ERROR_SCHEMA,
            error: error.to_string(),
            trace_id: Uuid::new_v4().to_string(),
        }),
    )
        .into_response()
}

fn required_idempotency(headers: &HeaderMap) -> Result<String, RegistryError> {
    single_header(headers, "idempotency-key")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        })
        .map(str::to_string)
        .ok_or(RegistryError::IdempotencyInvalid)
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-agent-registry-token-comparison-v1",
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

fn optional_single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, RegistryError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| RegistryError::ManagementForbidden)?;
    if values.next().is_some() {
        return Err(RegistryError::ManagementForbidden);
    }
    Ok(Some(value))
}

fn valid_scope(value: &str) -> bool {
    matches!(
        value,
        "agents:read"
            | "agents:register"
            | "agents:discover"
            | "agents:ownership:assign"
            | "agents:ownership:confirm"
            | "agents:bom"
            | "agents:relationships:write"
            | "agents:relationships:read"
            | "agents:posture:evaluate"
            | "agents:posture:read"
            | "agents:lifecycle"
    )
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), RegistryError> {
    if identities.is_empty()
        || identities.len() > 1_000
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity[4..].is_empty()
                || !identity[4..].bytes().all(|byte| byte.is_ascii_graphic())
        })
    {
        return Err(RegistryError::ProductionTrustNotConfigured);
    }
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, RegistryError> {
    let mut roots = RootCertStore::empty();
    let ca = File::open(ca_file).map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    for certificate in rustls_pemfile::certs(&mut BufReader::new(ca)) {
        roots
            .add(certificate.map_err(|_| RegistryError::ProductionTrustNotConfigured)?)
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    }
    if roots.is_empty() {
        return Err(RegistryError::ProductionTrustNotConfigured);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    let certificate =
        File::open(certificate_file).map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    if certificates.is_empty() {
        return Err(RegistryError::ProductionTrustNotConfigured);
    }
    let private_key =
        File::open(private_key_file).map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(private_key))
        .map_err(|_| RegistryError::ProductionTrustNotConfigured)?
        .ok_or(RegistryError::ProductionTrustNotConfigured)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, AgentRegistryPeerIdentity>;
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
                Extension(AgentRegistryPeerIdentity(identity)).layer(service),
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
        identities.push(general_name_identity(tag, value)?);
    }
    if identities.len() != 1 {
        return Err(());
    }
    Ok(identities)
}

fn general_name_identity(tag: u8, value: &[u8]) -> Result<String, ()> {
    let prefix = match tag {
        0x82 => "DNS:",
        0x86 => "URI:",
        // IP, email, directoryName, otherName and every future GeneralName form are denied;
        // accepting one reviewed DNS/URI SAN does not excuse an additional unreviewed identity.
        _ => return Err(()),
    };
    let value = std::str::from_utf8(value).map_err(|_| ())?;
    if value.is_empty() || value.len() > 508 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(());
    }
    Ok(format!("{prefix}{value}"))
}

fn der_element(input: &[u8], offset: usize) -> Result<(u8, &[u8], usize), ()> {
    let tag = *input.get(offset).ok_or(())?;
    let first = *input.get(offset + 1).ok_or(())?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(());
        }
        let mut length = 0_usize;
        for index in 0..count {
            let byte = usize::from(*input.get(offset + 2 + index).ok_or(())?);
            if index == 0 && byte == 0 {
                return Err(());
            }
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(byte))
                .ok_or(())?;
        }
        if length < 128 {
            return Err(());
        }
        (length, 2 + count)
    };
    let start = offset.checked_add(header).ok_or(())?;
    let end = start.checked_add(length).ok_or(())?;
    Ok((tag, input.get(start..end).ok_or(())?, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_route_specific_and_no_wildcard_exists() {
        for scope in [
            "agents:read",
            "agents:register",
            "agents:discover",
            "agents:ownership:assign",
            "agents:ownership:confirm",
            "agents:bom",
            "agents:relationships:write",
            "agents:relationships:read",
            "agents:posture:evaluate",
            "agents:posture:read",
            "agents:lifecycle",
        ] {
            assert!(valid_scope(scope));
        }
        assert!(!valid_scope("agents:*"));
        assert!(!valid_scope("agents:admin"));
    }

    #[test]
    fn certificate_identity_requires_exactly_one_allowed_san() {
        let allowed = BTreeSet::from(["DNS:agent-client.internal".into()]);
        assert!(validate_identities(&allowed).is_ok());
        assert!(validate_identities(&BTreeSet::from(["CN:agent-client".into()])).is_err());
        assert!(general_name_identity(0x82, b"agent-client.internal").is_ok());
        assert!(general_name_identity(0x86, b"spiffe://agenttrust/agent-client").is_ok());
        assert!(general_name_identity(0x87, &[127, 0, 0, 1]).is_err());
        assert!(general_name_identity(0x81, b"agent@example.invalid").is_err());
        assert!(general_name_identity(0xa0, b"unreviewed-other-name").is_err());
        assert!(general_name_identity(0x82, b"agent\0client.internal").is_err());
        assert!(general_name_identity(0x86, "spiffe://agenttrust/é".as_bytes()).is_err());
    }

    #[test]
    fn token_digest_is_lowercase_sha256() {
        assert!(lower_digest(&"a".repeat(64)));
        assert!(!lower_digest(&"A".repeat(64)));
        assert!(!lower_digest("raw-token"));
    }

    #[test]
    fn token_binding_json_rejects_duplicate_members() {
        let duplicate = br#"{
          "schema_version":"agenttrust.agent-registry-token-bindings.v1",
          "schema_version":"agenttrust.agent-registry-token-bindings.v1",
          "bindings":[]
        }"#;
        assert_eq!(
            strict_token_document(duplicate).err(),
            Some(RegistryError::ProductionTrustNotConfigured)
        );
    }
}
