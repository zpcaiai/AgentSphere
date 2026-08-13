//! Bounded, tenant-aware Agent Gateway and admission control.

use agent_trust_contracts::{ActionId, AgentInstanceId, TaskId, TenantId};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::limit::ConcurrencyLimitLayer;
use uuid::Uuid;

pub const GATEWAY_SCHEMA_VERSION: &str = "agenttrust.gateway.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IngressProtocol {
    Http,
    Grpc,
    WebSocket,
    Sse,
    McpInternal,
}

#[derive(Debug, Clone)]
pub struct RequestParts {
    pub method: Method,
    pub route: String,
    pub headers: HeaderMap,
    pub peer_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    pub subject: String,
    pub tenant_id: TenantId,
    pub agent_instance_id: AgentInstanceId,
    pub owner_subject: String,
    pub trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: TenantId,
    pub quota_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub invalid_input_replaced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundEnvelope {
    pub request_id: String,
    pub trace_context: TraceContext,
    pub identity_context: IdentityContext,
    pub tenant_context: TenantContext,
    pub protocol: IngressProtocol,
    pub content_type: String,
    pub schema_version: String,
    pub idempotency_key: Option<String>,
    pub received_at: DateTime<Utc>,
    pub payload: Vec<u8>,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressResponse {
    pub action_id: ActionId,
    pub task_id: TaskId,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionView {
    pub action_id: ActionId,
    pub task_id: TaskId,
    pub status: String,
    pub owner_subject: String,
    pub tenant_id: TenantId,
}

#[async_trait]
pub trait IdentityVerifierPort: Send + Sync {
    async fn verify(&self, request: &RequestParts) -> Result<IdentityContext, GatewayError>;
    fn production_ready(&self) -> bool;
}

#[async_trait]
pub trait OrchestratorSubmissionPort: Send + Sync {
    async fn submit(&self, envelope: InboundEnvelope) -> Result<IngressResponse, GatewayError>;
    async fn get(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &ActionId,
    ) -> Result<ActionView, GatewayError>;
    async fn cancel(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &ActionId,
    ) -> Result<(), GatewayError>;
    async fn kill(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &ActionId,
    ) -> Result<(), GatewayError>;
    async fn stream_snapshot(
        &self,
        tenant: &TenantId,
        owner: &str,
        task: &TaskId,
    ) -> Result<Vec<String>, GatewayError>;
    async fn ready(&self) -> bool;
}

pub trait TenantResolver: Send + Sync {
    fn resolve(
        &self,
        identity: &IdentityContext,
        headers: &HeaderMap,
    ) -> Result<TenantContext, GatewayError>;
}

pub struct TrustedTenantResolver;
impl TenantResolver for TrustedTenantResolver {
    fn resolve(
        &self,
        identity: &IdentityContext,
        headers: &HeaderMap,
    ) -> Result<TenantContext, GatewayError> {
        if headers
            .get("x-tenant-id")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|claimed| claimed != identity.tenant_id.0)
        {
            return Err(GatewayError::TenantMismatch);
        }
        Ok(TenantContext {
            tenant_id: identity.tenant_id.clone(),
            quota_profile: "default".into(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub production: bool,
    pub global_concurrency: usize,
    pub max_body_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub per_tenant_concurrency: usize,
    pub per_agent_concurrency: usize,
    pub per_tenant_requests_per_minute: u32,
    pub require_idempotency_key: bool,
    pub idempotency_ttl: Duration,
    pub max_idempotency_records: usize,
    pub max_idempotency_records_per_tenant: usize,
    pub request_timeout: Duration,
    pub downstream_timeout: Duration,
    pub circuit_failure_threshold: u32,
    pub circuit_open_duration: Duration,
    pub max_stream_events: usize,
    pub max_stream_duration: Duration,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            production: true,
            global_concurrency: 512,
            max_body_bytes: 1_048_576,
            max_header_bytes: 32_768,
            max_headers: 64,
            per_tenant_concurrency: 16,
            per_agent_concurrency: 8,
            per_tenant_requests_per_minute: 600,
            require_idempotency_key: true,
            idempotency_ttl: Duration::from_secs(24 * 60 * 60),
            max_idempotency_records: 100_000,
            max_idempotency_records_per_tenant: 10_000,
            request_timeout: Duration::from_secs(30),
            downstream_timeout: Duration::from_secs(20),
            circuit_failure_threshold: 5,
            circuit_open_duration: Duration::from_secs(30),
            max_stream_events: 100,
            max_stream_duration: Duration::from_secs(60 * 60),
        }
    }
}

struct RateWindow {
    started: std::time::Instant,
    count: u32,
}

struct ReplayRecord {
    payload_hash: String,
    recorded_at: std::time::Instant,
}

#[derive(Default)]
struct CircuitState {
    consecutive_failures: u32,
    open_until: Option<std::time::Instant>,
}

#[derive(Default)]
struct AdmissionState {
    tenant_semaphores: Mutex<BTreeMap<TenantId, Arc<Semaphore>>>,
    agent_semaphores: Mutex<BTreeMap<(TenantId, AgentInstanceId), Arc<Semaphore>>>,
    rate_windows: Mutex<BTreeMap<TenantId, RateWindow>>,
    idempotency: Mutex<BTreeMap<(TenantId, String), ReplayRecord>>,
    circuit: Mutex<CircuitState>,
}

struct AdmissionPermits {
    _tenant: OwnedSemaphorePermit,
    _agent: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub struct GatewayState {
    config: GatewayConfig,
    verifier: Arc<dyn IdentityVerifierPort>,
    tenants: Arc<dyn TenantResolver>,
    ingress: Arc<dyn OrchestratorSubmissionPort>,
    admission: Arc<AdmissionState>,
}

impl GatewayState {
    pub fn new(
        config: GatewayConfig,
        verifier: Arc<dyn IdentityVerifierPort>,
        tenants: Arc<dyn TenantResolver>,
        ingress: Arc<dyn OrchestratorSubmissionPort>,
    ) -> Result<Self, GatewayError> {
        if config.production && !verifier.production_ready() {
            return Err(GatewayError::ProductionIdentityNotConfigured);
        }
        if config.max_body_bytes == 0
            || config.global_concurrency == 0
            || config.per_tenant_concurrency == 0
            || config.per_agent_concurrency == 0
            || config.per_tenant_requests_per_minute == 0
            || config.idempotency_ttl.is_zero()
            || config.max_idempotency_records == 0
            || config.max_idempotency_records_per_tenant == 0
            || config.max_idempotency_records_per_tenant > config.max_idempotency_records
            || config.request_timeout.is_zero()
            || config.downstream_timeout.is_zero()
            || config.downstream_timeout > config.request_timeout
            || config.circuit_failure_threshold == 0
            || config.circuit_open_duration.is_zero()
            || config.max_stream_events == 0
            || config.max_stream_duration.is_zero()
        {
            return Err(GatewayError::ConfigurationInvalid);
        }
        Ok(Self {
            config,
            verifier,
            tenants,
            ingress,
            admission: Arc::new(AdmissionState::default()),
        })
    }

    async fn authenticate_and_tenant(
        &self,
        method: Method,
        route: &str,
        headers: HeaderMap,
    ) -> Result<(IdentityContext, TenantContext, TraceContext, String), GatewayError> {
        validate_headers(&headers, &self.config)?;
        let request_id = headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|id| valid_token(id, 128))
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let trace = extract_trace(&headers);
        let identity = tokio::time::timeout(
            self.config.request_timeout,
            self.verifier.verify(&RequestParts {
                method,
                route: route.into(),
                headers: headers.clone(),
                peer_identity: None,
            }),
        )
        .await
        .map_err(|_| GatewayError::DeadlineExceeded)??;
        let tenant = self.tenants.resolve(&identity, &headers)?;
        Ok((identity, tenant, trace, request_id))
    }

    fn acquire_concurrency(
        &self,
        tenant: &TenantId,
        agent: &AgentInstanceId,
    ) -> Result<AdmissionPermits, GatewayError> {
        let tenant_semaphore = self
            .admission
            .tenant_semaphores
            .lock()
            .entry(tenant.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.per_tenant_concurrency)))
            .clone();
        let tenant_permit = tenant_semaphore
            .try_acquire_owned()
            .map_err(|_| GatewayError::ConcurrencyLimited)?;
        let agent_semaphore = self
            .admission
            .agent_semaphores
            .lock()
            .entry((tenant.clone(), agent.clone()))
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.per_agent_concurrency)))
            .clone();
        let agent_permit = agent_semaphore
            .try_acquire_owned()
            .map_err(|_| GatewayError::ConcurrencyLimited)?;
        Ok(AdmissionPermits {
            _tenant: tenant_permit,
            _agent: agent_permit,
        })
    }

    fn check_rate(&self, tenant: &TenantId) -> Result<(), GatewayError> {
        let mut windows = self.admission.rate_windows.lock();
        let window = windows.entry(tenant.clone()).or_insert_with(|| RateWindow {
            started: std::time::Instant::now(),
            count: 0,
        });
        if window.started.elapsed() >= Duration::from_secs(60) {
            window.started = std::time::Instant::now();
            window.count = 0;
        }
        if window.count >= self.config.per_tenant_requests_per_minute {
            return Err(GatewayError::RateLimited);
        }
        window.count += 1;
        Ok(())
    }

    fn check_idempotency(
        &self,
        tenant: &TenantId,
        key: Option<&str>,
        payload_hash: &str,
    ) -> Result<(), GatewayError> {
        let Some(key) = key else {
            return if self.config.require_idempotency_key {
                Err(GatewayError::IdempotencyConflict)
            } else {
                Ok(())
            };
        };
        if !valid_token(key, 128) {
            return Err(GatewayError::IdempotencyConflict);
        }
        let mut records = self.admission.idempotency.lock();
        records.retain(|_, record| record.recorded_at.elapsed() < self.config.idempotency_ttl);
        match records.get(&(tenant.clone(), key.to_string())) {
            Some(existing) if existing.payload_hash != payload_hash => {
                Err(GatewayError::IdempotencyConflict)
            }
            Some(_) => Ok(()),
            None => {
                let tenant_records = records
                    .keys()
                    .filter(|(record_tenant, _)| record_tenant == tenant)
                    .count();
                if records.len() >= self.config.max_idempotency_records
                    || tenant_records >= self.config.max_idempotency_records_per_tenant
                {
                    return Err(GatewayError::RateLimited);
                }
                records.insert(
                    (tenant.clone(), key.to_string()),
                    ReplayRecord {
                        payload_hash: payload_hash.into(),
                        recorded_at: std::time::Instant::now(),
                    },
                );
                Ok(())
            }
        }
    }

    fn before_downstream(&self) -> Result<(), GatewayError> {
        let mut circuit = self.admission.circuit.lock();
        if let Some(open_until) = circuit.open_until {
            if open_until > std::time::Instant::now() {
                return Err(GatewayError::DownstreamUnavailable);
            }
            circuit.open_until = None;
            circuit.consecutive_failures = 0;
        }
        Ok(())
    }

    fn record_downstream<T>(&self, result: &Result<T, GatewayError>) {
        let mut circuit = self.admission.circuit.lock();
        match result {
            Err(GatewayError::DownstreamUnavailable | GatewayError::DeadlineExceeded) => {
                circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
                if circuit.consecutive_failures >= self.config.circuit_failure_threshold {
                    circuit.open_until =
                        Some(std::time::Instant::now() + self.config.circuit_open_duration);
                }
            }
            _ => {
                circuit.consecutive_failures = 0;
                circuit.open_until = None;
            }
        }
    }

    async fn call_downstream<T, F>(&self, future: F) -> Result<T, GatewayError>
    where
        F: Future<Output = Result<T, GatewayError>>,
    {
        self.before_downstream()?;
        let result = tokio::time::timeout(self.config.downstream_timeout, future)
            .await
            .unwrap_or(Err(GatewayError::DeadlineExceeded));
        self.record_downstream(&result);
        result
    }

    async fn downstream_ready(&self) -> bool {
        if self.before_downstream().is_err() {
            return false;
        }
        let result = match tokio::time::timeout(
            self.config.downstream_timeout,
            self.ingress.ready(),
        )
        .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(GatewayError::DownstreamUnavailable),
            Err(_) => Err(GatewayError::DeadlineExceeded),
        };
        self.record_downstream(&result);
        result.is_ok()
    }
}

pub fn data_plane_router(state: GatewayState) -> Router {
    let max_body = state.config.max_body_bytes;
    let global_concurrency = state.config.global_concurrency;
    Router::new()
        .route("/v1/actions", post(post_action))
        // Axum 0.8 captures a complete path segment. A parameter with a
        // literal suffix (`{action_id}:cancel`) panics while building the
        // router, so GET and command POSTs intentionally share this segment.
        .route(
            "/v1/actions/{action_operation}",
            get(get_action).post(control_action_route),
        )
        .route("/v1/streams/{task_id}", get(stream_task))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(ConcurrencyLimitLayer::new(global_concurrency))
        .with_state(state)
}

pub fn management_router() -> Router {
    Router::new().route("/metrics", get(|| async { "# bounded metrics listener\n" }))
}

/// Management plane for production assemblies. Readiness includes the configured
/// orchestrator and circuit state but never accepts data-plane credentials or actions.
pub fn production_management_router(state: GatewayState) -> Router {
    Router::new()
        .route("/metrics", get(|| async { "# bounded metrics listener\n" }))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state)
}

async fn post_action(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IngressResponse>, HttpGatewayError> {
    if body.len() > state.config.max_body_bytes {
        return Err(GatewayError::BodyTooLarge.into());
    }
    let (identity, tenant, trace, request_id) = state
        .authenticate_and_tenant(Method::POST, "/v1/actions", headers.clone())
        .await
        .map_err(HttpGatewayError::from)?;
    let _permits = state
        .acquire_concurrency(&tenant.tenant_id, &identity.agent_instance_id)
        .map_err(HttpGatewayError::from)?;
    state
        .check_rate(&tenant.tenant_id)
        .map_err(HttpGatewayError::from)?;
    let payload_hash = hex_string(Sha256::digest(&body));
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    state
        .check_idempotency(&tenant.tenant_id, idempotency_key.as_deref(), &payload_hash)
        .map_err(HttpGatewayError::from)?;
    let envelope = InboundEnvelope {
        request_id,
        trace_context: trace,
        identity_context: identity,
        tenant_context: tenant,
        protocol: IngressProtocol::Http,
        content_type: headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/json")
            .into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key,
        received_at: Utc::now(),
        payload: body.to_vec(),
        payload_hash,
    };
    let response = state
        .call_downstream(state.ingress.submit(envelope))
        .await
        .map_err(HttpGatewayError::from)?;
    Ok(Json(response))
}

async fn get_action(
    State(state): State<GatewayState>,
    Path(action_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ActionView>, HttpGatewayError> {
    let action = ActionId::parse(action_id)
        .map_err(|_| HttpGatewayError::from(GatewayError::NotFoundOrForbidden))?;
    let (identity, tenant, _, _) = state
        .authenticate_and_tenant(Method::GET, "/v1/actions/{id}", headers)
        .await
        .map_err(HttpGatewayError::from)?;
    let _permits = state
        .acquire_concurrency(&tenant.tenant_id, &identity.agent_instance_id)
        .map_err(HttpGatewayError::from)?;
    state
        .check_rate(&tenant.tenant_id)
        .map_err(HttpGatewayError::from)?;
    Ok(Json(
        state
            .call_downstream(
                state
                    .ingress
                    .get(&tenant.tenant_id, &identity.owner_subject, &action),
            )
            .await
            .map_err(HttpGatewayError::from)?,
    ))
}

async fn control_action_route(
    State(state): State<GatewayState>,
    Path(action_operation): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpGatewayError> {
    let (action_id, kill) = if let Some(action_id) = action_operation.strip_suffix(":cancel") {
        (action_id, false)
    } else if let Some(action_id) = action_operation.strip_suffix(":kill") {
        (action_id, true)
    } else {
        return Err(GatewayError::NotFoundOrForbidden.into());
    };
    control_action(&state, action_id, headers, kill).await?;
    Ok(StatusCode::ACCEPTED)
}
async fn control_action(
    state: &GatewayState,
    action_id: &str,
    headers: HeaderMap,
    kill: bool,
) -> Result<(), HttpGatewayError> {
    let action = ActionId::parse(action_id)
        .map_err(|_| HttpGatewayError::from(GatewayError::NotFoundOrForbidden))?;
    let (identity, tenant, _, _) = state
        .authenticate_and_tenant(
            Method::POST,
            if kill {
                "/v1/actions/{id}:kill"
            } else {
                "/v1/actions/{id}:cancel"
            },
            headers,
        )
        .await
        .map_err(HttpGatewayError::from)?;
    let _permits = state
        .acquire_concurrency(&tenant.tenant_id, &identity.agent_instance_id)
        .map_err(HttpGatewayError::from)?;
    state
        .check_rate(&tenant.tenant_id)
        .map_err(HttpGatewayError::from)?;
    if kill {
        state
            .call_downstream(state.ingress.kill(
                &tenant.tenant_id,
                &identity.owner_subject,
                &action,
            ))
            .await?
    } else {
        state
            .call_downstream(state.ingress.cancel(
                &tenant.tenant_id,
                &identity.owner_subject,
                &action,
            ))
            .await?
    }
    Ok(())
}

async fn stream_task(
    State(state): State<GatewayState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpGatewayError> {
    let task = TaskId::parse(task_id)
        .map_err(|_| HttpGatewayError::from(GatewayError::NotFoundOrForbidden))?;
    let (identity, tenant, _, _) = state
        .authenticate_and_tenant(Method::GET, "/v1/streams/{id}", headers)
        .await
        .map_err(HttpGatewayError::from)?;
    let _permits = state
        .acquire_concurrency(&tenant.tenant_id, &identity.agent_instance_id)
        .map_err(HttpGatewayError::from)?;
    state
        .check_rate(&tenant.tenant_id)
        .map_err(HttpGatewayError::from)?;
    let mut events = state
        .call_downstream(state.ingress.stream_snapshot(
            &tenant.tenant_id,
            &identity.owner_subject,
            &task,
        ))
        .await?;
    events.truncate(state.config.max_stream_events);
    Ok((
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-store"),
        ],
        events
            .into_iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect::<String>(),
    )
        .into_response())
}

async fn health() -> StatusCode {
    StatusCode::OK
}
async fn ready(State(state): State<GatewayState>) -> StatusCode {
    if state.downstream_ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn validate_headers(headers: &HeaderMap, config: &GatewayConfig) -> Result<(), GatewayError> {
    if headers.len() > config.max_headers {
        return Err(GatewayError::HeaderTooLarge);
    }
    let size: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum();
    if size > config.max_header_bytes {
        return Err(GatewayError::HeaderTooLarge);
    }
    Ok(())
}

fn extract_trace(headers: &HeaderMap) -> TraceContext {
    let supplied = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok());
    let valid = supplied.filter(|value| {
        value.len() == 55
            && value.starts_with("00-")
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() || *byte == b'-')
    });
    match valid {
        Some(value) => TraceContext {
            trace_id: value[3..35].to_string(),
            parent_span_id: Some(value[36..52].to_string()),
            invalid_input_replaced: false,
        },
        None => TraceContext {
            trace_id: Uuid::new_v4().simple().to_string(),
            parent_span_id: None,
            invalid_input_replaced: supplied.is_some(),
        },
    }
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}
fn hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatewayError {
    #[error("GATEWAY_UNAUTHENTICATED")]
    Unauthenticated,
    #[error("GATEWAY_FORBIDDEN")]
    Forbidden,
    #[error("GATEWAY_TENANT_MISMATCH")]
    TenantMismatch,
    #[error("GATEWAY_RATE_LIMITED")]
    RateLimited,
    #[error("GATEWAY_CONCURRENCY_LIMITED")]
    ConcurrencyLimited,
    #[error("GATEWAY_BODY_TOO_LARGE")]
    BodyTooLarge,
    #[error("GATEWAY_HEADER_TOO_LARGE")]
    HeaderTooLarge,
    #[error("GATEWAY_UNSUPPORTED_PROTOCOL")]
    UnsupportedProtocol,
    #[error("GATEWAY_DEADLINE_EXCEEDED")]
    DeadlineExceeded,
    #[error("GATEWAY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("GATEWAY_DOWNSTREAM_UNAVAILABLE")]
    DownstreamUnavailable,
    #[error("GATEWAY_PRODUCTION_IDENTITY_NOT_CONFIGURED")]
    ProductionIdentityNotConfigured,
    #[error("GATEWAY_NOT_FOUND_OR_FORBIDDEN")]
    NotFoundOrForbidden,
    #[error("GATEWAY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug)]
pub struct HttpGatewayError {
    error: GatewayError,
    trace_id: String,
}
impl From<GatewayError> for HttpGatewayError {
    fn from(error: GatewayError) -> Self {
        Self {
            error,
            trace_id: Uuid::new_v4().simple().to_string(),
        }
    }
}
impl IntoResponse for HttpGatewayError {
    fn into_response(self) -> Response {
        let status = match self.error {
            GatewayError::Unauthenticated => StatusCode::UNAUTHORIZED,
            GatewayError::Forbidden | GatewayError::TenantMismatch => StatusCode::FORBIDDEN,
            GatewayError::RateLimited | GatewayError::ConcurrencyLimited => {
                StatusCode::TOO_MANY_REQUESTS
            }
            GatewayError::BodyTooLarge | GatewayError::HeaderTooLarge => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            GatewayError::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            GatewayError::IdempotencyConflict => StatusCode::CONFLICT,
            GatewayError::NotFoundOrForbidden => StatusCode::NOT_FOUND,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        let body = serde_json::json!({"error":{"code":self.error.to_string(),"trace_id":self.trace_id,"summary":"request could not be processed"}});
        let mut response = (status, Json(body)).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert("retry-after", http::HeaderValue::from_static("1"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tower::ServiceExt;

    struct Verifier {
        tenant: TenantId,
        production: bool,
    }
    #[async_trait]
    impl IdentityVerifierPort for Verifier {
        async fn verify(&self, _: &RequestParts) -> Result<IdentityContext, GatewayError> {
            Ok(IdentityContext {
                subject: "agent".into(),
                tenant_id: self.tenant.clone(),
                agent_instance_id: AgentInstanceId::new(),
                owner_subject: "user".into(),
                trust_level: "verified".into(),
            })
        }
        fn production_ready(&self) -> bool {
            self.production
        }
    }
    struct Ingress;
    #[async_trait]
    impl OrchestratorSubmissionPort for Ingress {
        async fn submit(&self, _: InboundEnvelope) -> Result<IngressResponse, GatewayError> {
            Ok(IngressResponse {
                action_id: ActionId::new(),
                task_id: TaskId::new(),
                accepted: true,
            })
        }
        async fn get(
            &self,
            _: &TenantId,
            _: &str,
            action: &ActionId,
        ) -> Result<ActionView, GatewayError> {
            Ok(ActionView {
                action_id: action.clone(),
                task_id: TaskId::new(),
                status: "RUNNING".into(),
                owner_subject: "user".into(),
                tenant_id: TenantId::new(),
            })
        }
        async fn cancel(&self, _: &TenantId, _: &str, _: &ActionId) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn kill(&self, _: &TenantId, _: &str, _: &ActionId) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn stream_snapshot(
            &self,
            _: &TenantId,
            _: &str,
            _: &TaskId,
        ) -> Result<Vec<String>, GatewayError> {
            Ok(vec!["event".into()])
        }
        async fn ready(&self) -> bool {
            true
        }
    }

    struct SlowVerifier;
    #[async_trait]
    impl IdentityVerifierPort for SlowVerifier {
        async fn verify(&self, _: &RequestParts) -> Result<IdentityContext, GatewayError> {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Err(GatewayError::Unauthenticated)
        }
        fn production_ready(&self) -> bool {
            true
        }
    }

    fn state(config: GatewayConfig, tenant: TenantId) -> Result<GatewayState, GatewayError> {
        GatewayState::new(
            config,
            Arc::new(Verifier {
                tenant,
                production: true,
            }),
            Arc::new(TrustedTenantResolver),
            Arc::new(Ingress),
        )
    }

    #[test]
    fn production_requires_real_verifier() {
        let tenant = TenantId::new();
        let config = GatewayConfig::default();
        assert!(matches!(
            GatewayState::new(
                config,
                Arc::new(Verifier {
                    tenant,
                    production: false
                }),
                Arc::new(TrustedTenantResolver),
                Arc::new(Ingress)
            ),
            Err(GatewayError::ProductionIdentityNotConfigured)
        ));
    }

    #[tokio::test]
    async fn forged_tenant_header_is_rejected() {
        let tenant = TenantId::new();
        let state = state(GatewayConfig::default(), tenant).unwrap_or_else(|_| panic!("state"));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-tenant-id",
            "00000000-0000-0000-0000-000000000000"
                .parse()
                .unwrap_or_else(|_| panic!("header")),
        );
        assert!(matches!(
            state
                .authenticate_and_tenant(Method::POST, "/v1/actions", headers)
                .await,
            Err(GatewayError::TenantMismatch)
        ));
    }

    #[test]
    fn same_key_different_payload_conflicts_per_tenant() {
        let tenant = TenantId::new();
        let state =
            state(GatewayConfig::default(), tenant.clone()).unwrap_or_else(|_| panic!("state"));
        assert!(
            state
                .check_idempotency(&tenant, Some("client:key"), "hash-a")
                .is_ok()
        );
        assert_eq!(
            state.check_idempotency(&tenant, Some("client:key"), "hash-b"),
            Err(GatewayError::IdempotencyConflict)
        );
    }

    #[test]
    fn idempotency_is_required_and_replay_storage_is_bounded() {
        let tenant = TenantId::new();
        let config = GatewayConfig {
            max_idempotency_records: 1,
            max_idempotency_records_per_tenant: 1,
            ..GatewayConfig::default()
        };
        let state = state(config, tenant.clone()).unwrap_or_else(|_| panic!("state"));
        assert_eq!(
            state.check_idempotency(&tenant, None, "hash-a"),
            Err(GatewayError::IdempotencyConflict)
        );
        assert!(
            state
                .check_idempotency(&tenant, Some("request-1"), "hash-a")
                .is_ok()
        );
        assert_eq!(
            state.check_idempotency(&tenant, Some("request-2"), "hash-b"),
            Err(GatewayError::RateLimited)
        );
    }

    #[test]
    fn concurrency_is_bounded_per_tenant_and_per_agent() {
        let tenant = TenantId::new();
        let config = GatewayConfig {
            per_tenant_concurrency: 2,
            per_agent_concurrency: 1,
            ..GatewayConfig::default()
        };
        let state = state(config, tenant.clone()).unwrap_or_else(|_| panic!("state"));
        let first_agent = AgentInstanceId::new();
        let second_agent = AgentInstanceId::new();
        let _first = state
            .acquire_concurrency(&tenant, &first_agent)
            .unwrap_or_else(|_| panic!("first permit"));
        assert!(matches!(
            state.acquire_concurrency(&tenant, &first_agent),
            Err(GatewayError::ConcurrencyLimited)
        ));
        assert!(state.acquire_concurrency(&tenant, &second_agent).is_ok());
    }

    #[test]
    fn invalid_trace_is_replaced_without_reflection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "secret-token".parse().unwrap_or_else(|_| panic!("header")),
        );
        let trace = extract_trace(&headers);
        assert!(trace.invalid_input_replaced);
        assert_ne!(trace.trace_id, "secret-token");
    }

    #[tokio::test]
    async fn action_command_routes_build_and_dispatch_without_panicking() {
        let tenant = TenantId::new();
        let state = state(GatewayConfig::default(), tenant).unwrap_or_else(|_| panic!("state"));
        let action = ActionId::new();
        let router = data_plane_router(state);

        for operation in ["cancel", "kill"] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/actions/{}:{operation}", action.0))
                .body(Body::empty())
                .unwrap_or_else(|_| panic!("request"));
            let response = router
                .clone()
                .oneshot(request)
                .await
                .unwrap_or_else(|_| panic!("response"));
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let unsupported = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/actions/{}:approve", action.0))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("request"));
        let response = router
            .oneshot(unsupported)
            .await
            .unwrap_or_else(|_| panic!("response"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn action_submission_requires_idempotency_and_size_guards_run_first() {
        let tenant = TenantId::new();
        let gateway_state =
            state(GatewayConfig::default(), tenant).unwrap_or_else(|_| panic!("state"));
        let router = data_plane_router(gateway_state);
        let missing_key = Request::builder()
            .method(Method::POST)
            .uri("/v1/actions")
            .body(Body::from("{}"))
            .unwrap_or_else(|_| panic!("request"));
        let response = router
            .clone()
            .oneshot(missing_key)
            .await
            .unwrap_or_else(|_| panic!("response"));
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let small_config = GatewayConfig {
            max_body_bytes: 1,
            ..GatewayConfig::default()
        };
        let small_state =
            state(small_config, TenantId::new()).unwrap_or_else(|_| panic!("small state"));
        let oversized = Request::builder()
            .method(Method::POST)
            .uri("/v1/actions")
            .header("idempotency-key", "request-1")
            .body(Body::from("{}"))
            .unwrap_or_else(|_| panic!("request"));
        let response = data_plane_router(small_state)
            .oneshot(oversized)
            .await
            .unwrap_or_else(|_| panic!("response"));
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn rate_limit_applies_to_queries_and_returns_bounded_retry_advice() {
        let tenant = TenantId::new();
        let config = GatewayConfig {
            per_tenant_requests_per_minute: 1,
            ..GatewayConfig::default()
        };
        let state = state(config, tenant).unwrap_or_else(|_| panic!("state"));
        let router = data_plane_router(state);
        let action = ActionId::new();
        let first = Request::builder()
            .uri(format!("/v1/actions/{}", action.0))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("request"));
        assert_eq!(
            router
                .clone()
                .oneshot(first)
                .await
                .unwrap_or_else(|_| panic!("response"))
                .status(),
            StatusCode::OK
        );
        let second = Request::builder()
            .uri(format!("/v1/actions/{}", action.0))
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("request"));
        let response = router
            .oneshot(second)
            .await
            .unwrap_or_else(|_| panic!("response"));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
    }

    #[tokio::test]
    async fn downstream_timeout_and_circuit_breaker_fail_closed() {
        let tenant = TenantId::new();
        let config = GatewayConfig {
            request_timeout: Duration::from_millis(20),
            downstream_timeout: Duration::from_millis(5),
            circuit_failure_threshold: 2,
            ..GatewayConfig::default()
        };
        let state = state(config, tenant).unwrap_or_else(|_| panic!("state"));
        assert_eq!(
            state
                .call_downstream(async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(())
                })
                .await,
            Err(GatewayError::DeadlineExceeded)
        );
        assert_eq!(
            state
                .call_downstream(async { Err::<(), _>(GatewayError::DownstreamUnavailable) })
                .await,
            Err(GatewayError::DownstreamUnavailable)
        );
        let called = Arc::new(AtomicBool::new(false));
        let marker = called.clone();
        assert_eq!(
            state
                .call_downstream(async move {
                    marker.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await,
            Err(GatewayError::DownstreamUnavailable)
        );
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn slow_identity_verifier_is_bounded_by_the_request_deadline() {
        let config = GatewayConfig {
            request_timeout: Duration::from_millis(5),
            downstream_timeout: Duration::from_millis(5),
            ..GatewayConfig::default()
        };
        let state = GatewayState::new(
            config,
            Arc::new(SlowVerifier),
            Arc::new(TrustedTenantResolver),
            Arc::new(Ingress),
        )
        .unwrap_or_else(|_| panic!("state"));
        assert!(matches!(
            state
                .authenticate_and_tenant(Method::GET, "/v1/actions/{id}", HeaderMap::new())
                .await,
            Err(GatewayError::DeadlineExceeded)
        ));
    }
}
