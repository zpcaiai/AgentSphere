//! TLS 1.3/mTLS HTTP boundary and typed supply-chain runtime adapter.

use crate::production::*;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ActionHash, AuthorityEvidenceControlBinding,
    AuthorityEvidenceEventRequest, AuthorityEvidenceSourceKind,
    EVIDENCE_EVENT_SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION, EvidenceEventDraft,
    EvidenceEventType, ExecutionId, IdempotencyKey, SignedAuthorityEvidenceReceipt, TaskId,
    TenantId,
};
use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;
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
use uuid::Uuid;

pub const SUPPLY_READINESS_SCHEMA: &str = "agenttrust.supply-chain-readiness.v1";
pub const SUPPLY_RECOVER_SCOPE: &str = "supply-chain:recover";
pub const EVIDENCE_KEYRING_SCHEMA: &str = "agenttrust.ed25519-public-keyring.v1";

#[derive(Debug, Clone)]
pub struct SupplyServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub allowed_client_identities: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct ExactPeerIdentity(pub String);

#[derive(Clone)]
struct ServerState {
    authority: SupplyChainAuthority,
    tokens: Arc<SupplyTokenAuthorizer>,
}

#[derive(Clone)]
struct ReadinessState {
    authority: SupplyChainAuthority,
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

pub struct SupplyTokenAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
}

impl SupplyTokenAuthorizer {
    pub fn from_file(
        path: &Path,
        allowed: &BTreeSet<String>,
    ) -> Result<Self, SupplyAuthorityError> {
        validate_identities(allowed)?;
        let raw = read_private_bytes(path, 1, 1_048_576)?;
        let document: TokenBindingDocument =
            serde_json::from_slice(&raw).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.supply-chain-token-bindings.v1"
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut physical_tokens = BTreeSet::new();
        for binding in document.bindings {
            if !allowed.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    "supply-chain:publish"
                        | "supply-chain:approve"
                        | "supply-chain:activate"
                        | "supply-chain:revoke"
                        | "supply-chain:read"
                        | SUPPLY_RECOVER_SCOPE
                )
                || !identifier(&binding.subject, 512)
                || !canonical_uuid(&binding.tenant_id)
                || !digest(&binding.token_sha256)
                || !physical_tokens.insert(binding.token_sha256.clone())
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(SupplyAuthorityError::ConfigurationInvalid);
            }
        }
        if allowed.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        Ok(Self { bindings })
    }

    fn authorize(
        &self,
        peer: &str,
        tenant: Uuid,
        scope: &str,
        headers: &HeaderMap,
    ) -> Result<String, SupplyAuthorityError> {
        let bearer = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                (16..=8192).contains(&value.len())
                    && value.bytes().all(|byte| byte.is_ascii_graphic())
            })
            .ok_or(SupplyAuthorityError::PrincipalDenied)?;
        let supplied = hex::encode(Sha256::digest(bearer.as_bytes()));
        let tenant = tenant.to_string();
        let mut subject = None;
        let mut match_count = 0_usize;
        for binding in &self.bindings {
            if binding.client_identity == peer
                && binding.tenant_id == tenant
                && binding.scope == scope
                && constant_time_equal(&supplied, &binding.token_sha256)
            {
                match_count += 1;
                if subject.is_none() {
                    subject = Some(binding.subject.clone());
                }
            }
        }
        match subject {
            Some(subject) if match_count == 1 => Ok(subject),
            _ => Err(SupplyAuthorityError::PrincipalDenied),
        }
    }
}

pub fn router(authority: SupplyChainAuthority, tokens: Arc<SupplyTokenAuthorizer>) -> Router {
    Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/supply-chain/executions", post(execute))
        .route(
            "/v1/authoritative/supply-chain/releases",
            get(authoritative_releases),
        )
        .route("/v1/supply-chain/recoveries/{tenant_id}", post(recover))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ))
        .with_state(ServerState { authority, tokens })
}

async fn data_ready(State(state): State<ServerState>) -> Result<Json<serde_json::Value>, ApiError> {
    ready(&state.authority).await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseQuery {
    tenant_id: Uuid,
    limit: Option<u16>,
    cursor: Option<String>,
}

async fn authoritative_releases(
    State(state): State<ServerState>,
    Extension(ExactPeerIdentity(peer)): Extension<ExactPeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<ReleaseQuery>,
) -> Result<Json<AuthoritativeReleasePage>, ApiError> {
    if required_header(&headers, "x-agenttrust-tenant-id")? != query.tenant_id.to_string() {
        return Err(SupplyAuthorityError::PrincipalDenied.into());
    }
    state
        .tokens
        .authorize(&peer, query.tenant_id, "supply-chain:read", &headers)?;
    let page = state
        .authority
        .authoritative_releases(
            query.tenant_id,
            i64::from(query.limit.unwrap_or(50)),
            query.cursor.as_deref(),
        )
        .await?;
    Ok(Json(page))
}

async fn execute(
    State(state): State<ServerState>,
    Extension(ExactPeerIdentity(peer)): Extension<ExactPeerIdentity>,
    headers: HeaderMap,
    Json(body): Json<SupplyExecutionRequest>,
) -> Result<(StatusCode, Json<SupplyMutationResult>), ApiError> {
    require_exact_binding_headers(&headers, &body)?;
    let subject = state.tokens.authorize(
        &peer,
        body.command.tenant_id,
        body.command.operation.required_scope(),
        &headers,
    )?;
    if subject != body.actor_subject {
        return Err(SupplyAuthorityError::PrincipalDenied.into());
    }
    let result = state.authority.execute(body).await?;
    Ok((StatusCode::OK, Json(result)))
}

async fn recover(
    State(state): State<ServerState>,
    Extension(ExactPeerIdentity(peer)): Extension<ExactPeerIdentity>,
    AxumPath(tenant_id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let header_tenant = required_header(&headers, "x-agenttrust-tenant-id")?;
    if header_tenant != tenant_id.to_string() {
        return Err(SupplyAuthorityError::PrincipalDenied.into());
    }
    state
        .tokens
        .authorize(&peer, tenant_id, SUPPLY_RECOVER_SCOPE, &headers)?;
    let recovered = state.authority.recover_expired(tenant_id, 100).await?;
    Ok(Json(
        serde_json::json!({"schema_version":"agenttrust.supply-chain-recovery.v1","marked_unknown":recovered}),
    ))
}

fn require_exact_binding_headers(
    headers: &HeaderMap,
    body: &SupplyExecutionRequest,
) -> Result<(), SupplyAuthorityError> {
    let expected = [
        ("x-agenttrust-tenant-id", body.command.tenant_id.to_string()),
        ("idempotency-key", body.binding.idempotency_key.clone()),
        (
            "x-agenttrust-action-id",
            body.command.command_id.to_string(),
        ),
        (
            "x-agenttrust-authorization-id",
            body.binding.authorization_id.to_string(),
        ),
        (
            "x-agenttrust-authorization-digest",
            body.binding.authorization_digest.clone(),
        ),
        (
            "x-agenttrust-policy-decision-id",
            body.binding.policy_decision_id.clone(),
        ),
        (
            "x-agenttrust-policy-decision-digest",
            body.binding.policy_decision_digest.clone(),
        ),
        (
            "x-agenttrust-authorization-evidence-ref",
            body.binding.authorization_evidence_ref.clone(),
        ),
        (
            "x-agenttrust-authorization-evidence-digest",
            body.binding.authorization_evidence_digest.clone(),
        ),
        (
            "x-agenttrust-ledger-execution-id",
            body.binding.ledger_execution_id.to_string(),
        ),
        (
            "x-agenttrust-ledger-entry-id",
            body.binding.ledger_event_id.to_string(),
        ),
        (
            "x-agenttrust-ledger-entry-digest",
            body.binding.ledger_event_digest.clone(),
        ),
        (
            "x-agenttrust-fence-digest",
            body.binding.fence_digest.clone(),
        ),
        (
            "x-agenttrust-resource-version",
            body.binding.resource_version.to_string(),
        ),
        ("x-agenttrust-trace-id", body.binding.trace_id.clone()),
    ];
    for (name, value) in expected {
        if single_header(headers, name) != Some(value.as_str()) {
            return Err(SupplyAuthorityError::BindingInvalid);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SupplyDependency {
    pub name: String,
    pub endpoint: url::Url,
    pub token_file: PathBuf,
    pub readiness_schema: String,
}

#[derive(Clone)]
pub struct HttpSupplyChainRuntimePort {
    client: reqwest::Client,
    coordinator: SupplyDependency,
    dependencies: Arc<Vec<SupplyDependency>>,
    evidence_keyring: EvidenceEventKeyring,
    evidence_client_identity: String,
}

impl HttpSupplyChainRuntimePort {
    pub fn new(
        client: reqwest::Client,
        coordinator: SupplyDependency,
        dependencies: Vec<SupplyDependency>,
        evidence_keyring: EvidenceEventKeyring,
        evidence_client_identity: String,
    ) -> Result<Self, SupplyAuthorityError> {
        if dependencies.len() != 6
            || dependencies
                .iter()
                .map(|value| value.name.as_str())
                .collect::<BTreeSet<_>>()
                != BTreeSet::from([
                    "evidence",
                    "repository",
                    "revocation",
                    "sandbox",
                    "scanner",
                    "signer",
                ])
        {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        let mut urls = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        for dependency in std::iter::once(&coordinator).chain(dependencies.iter()) {
            validate_https_root(&dependency.endpoint)?;
            if !identifier(&dependency.name, 64)
                || !identifier(&dependency.readiness_schema, 128)
                || !dependency.token_file.is_absolute()
                || !urls.insert(dependency.endpoint.as_str().to_string())
                || !tokens.insert(read_token(&dependency.token_file)?)
            {
                return Err(SupplyAuthorityError::ConfigurationInvalid);
            }
        }
        if !(evidence_client_identity.starts_with("DNS:")||evidence_client_identity.starts_with("URI:"))
            // `EvidenceEventDraft::source_service` has a shared-contract limit of 256 bytes.
            // Enforce it during startup, rather than discovering an unusable SAN after the
            // mutation has already committed to the local outbox.
            ||!identifier(&evidence_client_identity,256)
        {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            client,
            coordinator,
            dependencies: Arc::new(dependencies),
            evidence_keyring,
            evidence_client_identity,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyringDocument {
    schema_version: String,
    keys: std::collections::BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct EvidenceEventKeyring {
    keys: Arc<std::collections::BTreeMap<String, VerifyingKey>>,
}

impl EvidenceEventKeyring {
    pub fn from_json(raw: &[u8]) -> Result<Self, SupplyAuthorityError> {
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        let document: EvidenceKeyringDocument =
            serde_json::from_slice(raw).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != EVIDENCE_KEYRING_SCHEMA
            || document.keys.is_empty()
            || document.keys.len() > 1024
        {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        let mut keys = std::collections::BTreeMap::new();
        for (key_id, encoded) in document.keys {
            let bytes: [u8; 32] = <[u8; 32]>::try_from(
                URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?,
            )
            .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
            if !identifier(&key_id, 128) || keys.insert(key_id, key).is_some() {
                return Err(SupplyAuthorityError::ConfigurationInvalid);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    pub fn verify(
        &self,
        receipt: &SignedAuthorityEvidenceReceipt,
        request: &AuthorityEvidenceEventRequest,
        payload_digest: &str,
        source_identity: &str,
    ) -> Result<AuthorityEvidenceDelivery, SupplyAuthorityError> {
        self.verify_for_source_kind(
            receipt,
            request,
            payload_digest,
            source_identity,
            AuthorityEvidenceSourceKind::GovernedAction,
        )
    }

    pub fn verify_for_source_kind(
        &self,
        receipt: &SignedAuthorityEvidenceReceipt,
        request: &AuthorityEvidenceEventRequest,
        payload_digest: &str,
        source_identity: &str,
        expected_source_kind: AuthorityEvidenceSourceKind,
    ) -> Result<AuthorityEvidenceDelivery, SupplyAuthorityError> {
        let key = self
            .keys
            .get(&receipt.key_id)
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        receipt
            .verify(key, Utc::now())
            .map_err(|_| SupplyAuthorityError::ReceiptInvalid)?;
        let request_digest = request
            .request_digest()
            .map_err(|_| SupplyAuthorityError::ReceiptInvalid)?;
        if receipt.tenant_id != request.tenant_id
            || receipt.task_id != request.task_id
            || receipt.authority_event_id != request.authority_event_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.source_kind != expected_source_kind
            || receipt.source_kind != request.source_kind
            || receipt.request_digest != request_digest
            || receipt.payload_digest != payload_digest
            || receipt.event.draft != request.event
            || receipt.event.draft.source_service != source_identity
        {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        Ok(AuthorityEvidenceDelivery {
            evidence_ref: receipt.evidence_ref.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
        })
    }
}

#[async_trait]
impl SupplyChainRuntimePort for HttpSupplyChainRuntimePort {
    async fn execute(
        &self,
        request: &SupplyExecutionRequest,
        request_digest: &str,
        action_hash: &str,
    ) -> Result<SupplyRuntimeReceipt, SupplyAuthorityError> {
        let response = self
            .client
            .post(
                self.coordinator
                    .endpoint
                    .join("v1/supply-chain/effects")
                    .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.coordinator.token_file)?)
            .header(
                "X-AgentTrust-Tenant-Id",
                request.command.tenant_id.to_string(),
            )
            .header("Idempotency-Key", &request.binding.idempotency_key)
            .header("X-AgentTrust-Action-Hash", action_hash)
            .header(
                "X-AgentTrust-Authorization-Id",
                request.binding.authorization_id.to_string(),
            )
            .header(
                "X-AgentTrust-Authorization-Digest",
                &request.binding.authorization_digest,
            )
            .header(
                "X-AgentTrust-Policy-Decision-Digest",
                &request.binding.policy_decision_digest,
            )
            .header(
                "X-AgentTrust-Authorization-Evidence-Ref",
                &request.binding.authorization_evidence_ref,
            )
            .header(
                "X-AgentTrust-Authorization-Evidence-Digest",
                &request.binding.authorization_evidence_digest,
            )
            .header(
                "X-AgentTrust-Ledger-Execution-Id",
                request.binding.ledger_execution_id.to_string(),
            )
            .header(
                "X-AgentTrust-Ledger-Entry-Id",
                request.binding.ledger_event_id.to_string(),
            )
            .header(
                "X-AgentTrust-Ledger-Entry-Digest",
                &request.binding.ledger_event_digest,
            )
            .header("X-AgentTrust-Fence-Digest", &request.binding.fence_digest)
            .header("X-AgentTrust-Request-Digest", request_digest)
            .json(request)
            .send()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 262_144)
        {
            return Err(SupplyAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 262_144)
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(SupplyAuthorityError::DependencyUnavailable);
        }
        serde_json::from_slice(&bytes).map_err(|_| SupplyAuthorityError::DependencyUnavailable)
    }

    async fn ready(&self) -> bool {
        let coordinator = dependency_ready(&self.client, &self.coordinator);
        let dependencies = async {
        for dependency in self.dependencies.iter() {
                if !dependency_ready(&self.client, dependency).await {
                    return false;
                }
            }
            true
        };
        let (coordinator, dependencies) = tokio::join!(coordinator, dependencies);
        coordinator && dependencies
    }

    async fn deliver_evidence(
        &self,
        tenant_id: Uuid,
        idempotency_key: &str,
        payload: &serde_json::Value,
        payload_digest: &str,
    ) -> Result<AuthorityEvidenceDelivery, SupplyAuthorityError> {
        let dependency = self
            .dependencies
            .iter()
            .find(|dependency| dependency.name == "evidence")
            .ok_or(SupplyAuthorityError::ConfigurationInvalid)?;
        let task_id = payload
            .get("task_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let actor_subject = payload
            .get("actor_subject")
            .and_then(serde_json::Value::as_str)
            .filter(|value| identifier(value, 512))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let trace_id = payload
            .get("trace_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| identifier(value, 256))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let tenant_string = tenant_id.to_string();
        if payload.get("tenant_id").and_then(serde_json::Value::as_str)
            != Some(tenant_string.as_str())
            || !digest(payload_digest)
        {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        let authority_event_id = payload
            .get("event_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let action_hash = payload
            .get("action_hash")
            .and_then(serde_json::Value::as_str)
            .filter(|value| digest(value))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let ledger_execution_id = payload
            .get("ledger_execution_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let ledger_event_id = payload
            .get("ledger_event_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let ledger_event_digest = payload
            .get("ledger_event_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| digest(value))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let fence_digest = payload
            .get("fence_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| digest(value))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let policy_decision_id = payload
            .get("policy_decision_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| identifier(value, 256))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let policy_decision_digest = payload
            .get("policy_decision_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| digest(value))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let authorization_evidence_ref = payload
            .get("authorization_evidence_ref")
            .and_then(serde_json::Value::as_str)
            .filter(|value| identifier(value, 2048))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let authorization_evidence_digest = payload
            .get("authorization_evidence_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| digest(value))
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        let occurred_at = parse_evidence_time(payload, "evidence_occurred_at")?;
        let requested_at = parse_evidence_time(payload, "evidence_requested_at")?;
        if occurred_at > requested_at + chrono::Duration::minutes(1)
            || requested_at > Utc::now() + chrono::Duration::minutes(1)
        {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: TenantId(tenant_id.to_string()),
            task_id: TaskId(task_id.to_string()),
            authority_event_id: authority_event_id.to_string(),
            idempotency_key: IdempotencyKey(idempotency_key.into()),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(AuthorityEvidenceControlBinding {
                action_hash: ActionHash(action_hash.into()),
                ledger_execution_id: ExecutionId(ledger_execution_id.to_string()),
                ledger_event_id: ledger_event_id.to_string(),
                ledger_event_digest: ledger_event_digest.into(),
                fence_digest: fence_digest.into(),
                policy_decision_id: policy_decision_id.into(),
                policy_decision_digest: policy_decision_digest.into(),
                authorization_evidence_ref: authorization_evidence_ref.into(),
                authorization_evidence_digest: authorization_evidence_digest.into(),
            }),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_SCHEMA_VERSION.into(),
                tenant_id: TenantId(tenant_id.to_string()),
                task_id: TaskId(task_id.to_string()),
                event_type: EvidenceEventType::StateTransition,
                actor_subject: actor_subject.into(),
                source_service: self.evidence_client_identity.clone(),
                trace_id: trace_id.into(),
                span_id: payload
                    .get("command_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| identifier(value, 256))
                    .ok_or(SupplyAuthorityError::ReceiptInvalid)?
                    .into(),
                payload_hash: payload_digest.into(),
                safe_summary: "Supply-chain authority outcome persisted".into(),
                artifact_refs: Vec::new(),
                occurred_at,
            },
            requested_at,
        };
        let response = self
            .client
            .post(
                dependency
                    .endpoint
                    .join("v1/evidence/authority-events")
                    .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&dependency.token_file)?)
            .header("X-AgentTrust-Tenant-Id", tenant_id.to_string())
            .header("Idempotency-Key", idempotency_key)
            .header(
                "X-AgentTrust-Authority-Event-Id",
                authority_event_id.to_string(),
            )
            .header("X-AgentTrust-Payload-Digest", payload_digest)
            .json(&request)
            .send()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 262_144)
        {
            return Err(SupplyAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 262_144)
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(SupplyAuthorityError::DependencyUnavailable);
        }
        let receipt: SignedAuthorityEvidenceReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        self.evidence_keyring.verify(
            &receipt,
            &request,
            payload_digest,
            &self.evidence_client_identity,
        )
    }
}

async fn dependency_ready(client: &reqwest::Client, dependency: &SupplyDependency) -> bool {
    let Ok(token) = read_token(&dependency.token_file) else {
        return false;
    };
    let Ok(url) = dependency.endpoint.join("ready") else {
        return false;
    };
    let Ok(response) = client.get(url).bearer_auth(token).send().await else {
        return false;
    };
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > 4096)
    {
        return false;
    }
    let Ok(bytes) = read_bounded_body(response, 4_096).await else {
        return false;
    };
    !bytes.is_empty()
        && bytes.len() <= 4096
        && serde_json::from_slice::<DependencyReadiness>(&bytes)
            .is_ok_and(|value| value.schema_version == dependency.readiness_schema && value.ready)
}

pub async fn serve(
    config: SupplyServerConfig,
    application: Router,
    authority: SupplyChainAuthority,
) -> Result<(), SupplyAuthorityError> {
    validate_identities(&config.allowed_client_identities)?;
    if !(config.management_address.ip().is_loopback()
        || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(SupplyAuthorityError::ConfigurationInvalid);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let acceptor = ExactPeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.allowed_client_identities),
    };
    let management = Router::new()
        .route("/live", get(management_live))
        .route("/ready", get(management_ready))
        .with_state(ReadinessState { authority });
    let listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    let data = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(application.into_make_service())
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)
    };
    let management = async move {
        axum::serve(listener, management)
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data, management)?;
    Ok(())
}

async fn management_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({"schema_version":SUPPLY_READINESS_SCHEMA,"live":true}))
}
async fn management_ready(
    State(state): State<ReadinessState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ready(&state.authority).await
}
async fn ready(authority: &SupplyChainAuthority) -> Result<Json<serde_json::Value>, ApiError> {
    if !authority.ready().await {
        return Err(SupplyAuthorityError::DependencyUnavailable.into());
    }
    Ok(Json(
        serde_json::json!({"schema_version":SUPPLY_READINESS_SCHEMA,"ready":true,"database_ready":true,"repository_ready":true,"signer_ready":true,"scanner_ready":true,"sandbox_ready":true,"revocation_ready":true,"evidence_ready":true}),
    ))
}

#[derive(Clone)]
pub struct ExactPeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}
impl ExactPeerIdentityAcceptor {
    pub fn new(
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
        allowed_identities: BTreeSet<String>,
    ) -> Result<Self, SupplyAuthorityError> {
        validate_identities(&allowed_identities)?;
        let tls = build_server_tls(ca_file, certificate_file, private_key_file)?;
        Ok(Self {
            inner: RustlsAcceptor::new(tls),
            allowed_identities: Arc::new(allowed_identities),
        })
    }
}
impl<I, S> Accept<I, S> for ExactPeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, ExactPeerIdentity>;
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
                Extension(ExactPeerIdentity(identity)).layer(service),
            ))
        })
    }
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, SupplyAuthorityError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?,
    );
    let ca = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca);
    if accepted == 0 || rejected != 0 {
        return Err(SupplyAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?
        .ok_or(SupplyAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

struct ApiError(SupplyAuthorityError);
impl From<SupplyAuthorityError> for ApiError {
    fn from(value: SupplyAuthorityError) -> Self {
        Self(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            SupplyAuthorityError::PrincipalDenied => StatusCode::UNAUTHORIZED,
            SupplyAuthorityError::RequestInvalid
            | SupplyAuthorityError::BindingInvalid
            | SupplyAuthorityError::PackInvalid
            | SupplyAuthorityError::SignatureInvalid
            | SupplyAuthorityError::PublisherDenied
            | SupplyAuthorityError::ReceiptInvalid => StatusCode::BAD_REQUEST,
            SupplyAuthorityError::ApprovalDenied
            | SupplyAuthorityError::RecoveryDenied
            | SupplyAuthorityError::IdempotencyConflict
            | SupplyAuthorityError::StateConflict => StatusCode::CONFLICT,
            SupplyAuthorityError::DependencyUnavailable
            | SupplyAuthorityError::OutcomeUnknown
            | SupplyAuthorityError::ConfigurationInvalid => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status,Json(serde_json::json!({"schema_version":"agenttrust.supply-chain-error.v1","error":self.0.code()}))).into_response()
    }
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, SupplyAuthorityError> {
    single_header(headers, name).ok_or(SupplyAuthorityError::RequestInvalid)
}
fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}
fn read_token(path: &Path) -> Result<String, SupplyAuthorityError> {
    let raw = read_private_bytes(path, 16, 8194)?;
    let value =
        std::str::from_utf8(&raw).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(SupplyAuthorityError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}
fn read_private_bytes(
    path: &Path,
    minimum: u64,
    maximum: u64,
) -> Result<Vec<u8>, SupplyAuthorityError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() < minimum
        || metadata.len() > maximum
    {
        return Err(SupplyAuthorityError::ConfigurationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        let uid = nix::unistd::Uid::effective().as_raw();
        let gid = nix::unistd::Gid::effective().as_raw();
        let allowed = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
        let readable = (metadata.uid() == uid && mode & 0o400 != 0)
            || (metadata.gid() == gid && mode & 0o040 != 0);
        if metadata.nlink() != 1 || !readable || mode & !allowed != 0 {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
    }
    std::fs::read(path).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)
}
fn constant_time_equal(first: &str, second: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-supply-token-compare-v1");
    let tag = hmac::sign(&key, second.as_bytes());
    hmac::verify(&key, first.as_bytes(), tag.as_ref()).is_ok()
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}
fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}
fn parse_evidence_time(
    payload: &serde_json::Value,
    key: &str,
) -> Result<chrono::DateTime<Utc>, SupplyAuthorityError> {
    let value = payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| SupplyAuthorityError::ReceiptInvalid)
}
fn validate_https_root(value: &url::Url) -> Result<(), SupplyAuthorityError> {
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(SupplyAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}
fn validate_identities(identities: &BTreeSet<String>) -> Result<(), SupplyAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err(SupplyAuthorityError::ConfigurationInvalid);
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
fn certificate_subject_alt_names(certificate: &[u8]) -> Result<Vec<String>, ()> {
    let (tag, outer, end) = der_element(certificate, 0)?;
    if tag != 0x30 || end != certificate.len() {
        return Err(());
    }
    let (tag, tbs, _) = der_element(outer, 0)?;
    if tag != 0x30 {
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
            let (tag, oid, mut field_offset) = der_element(extension, 0)?;
            if tag != 0x06 {
                return Err(());
            }
            let (mut value_tag, mut extension_value, next) = der_element(extension, field_offset)?;
            field_offset = next;
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
    let (tag, names, end) = der_element(extension, 0)?;
    if tag != 0x30 || end != extension.len() {
        return Err(());
    }
    let mut identities = Vec::new();
    let mut offset = 0;
    while offset < names.len() {
        let (tag, raw, next) = der_element(names, offset)?;
        offset = next;
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
