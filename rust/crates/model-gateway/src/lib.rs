//! Deterministic data-policy filtering followed by bounded model route optimization.

use agent_trust_contracts::{
    DataClassification, DataPolicyPort, DataPolicyRequest, PolicyVersion, SchemaVersion, TaskId,
    TenantId,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;

pub const MODEL_SCHEMA_VERSION: &str = "agenttrust.model.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentKind {
    PublicApi,
    Vpc,
    OnPrem,
    Local,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelCapability {
    Generate,
    Stream,
    Embeddings,
    ToolCalling,
    StructuredOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    pub schema_version: String,
    pub provider_id: String,
    pub model_id: String,
    pub model_version: String,
    pub region: String,
    pub jurisdiction: String,
    pub deployment: DeploymentKind,
    pub capabilities: BTreeSet<ModelCapability>,
    pub endpoint_digest: String,
    pub data_terms_version: String,
    pub approved_tenants: BTreeSet<TenantId>,
    pub approved: bool,
    pub revoked: bool,
    pub maximum_context_bytes: usize,
    pub maximum_output_bytes: usize,
    pub cost_microunits_per_token: u64,
}

impl ProviderProfile {
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.provider_id, self.model_id, self.model_version
        )
    }
}

#[derive(Default)]
pub struct ProviderRegistry {
    providers: RwLock<BTreeMap<String, ProviderProfile>>,
}
impl ProviderRegistry {
    pub fn approve(&self, profile: ProviderProfile) -> Result<(), ModelError> {
        validate_profile(&profile)?;
        if !profile.approved || profile.revoked {
            return Err(ModelError::ProviderDenied);
        }
        let key = profile.key();
        if self.providers.read().contains_key(&key) {
            return Err(ModelError::VersionConflict);
        }
        self.providers.write().insert(key, profile);
        Ok(())
    }
    pub fn revoke(&self, key: &str) -> Result<(), ModelError> {
        self.providers
            .write()
            .get_mut(key)
            .ok_or(ModelError::ProviderNotFound)
            .map(|provider| provider.revoked = true)
    }
    pub fn active(&self) -> Vec<ProviderProfile> {
        self.providers
            .read()
            .values()
            .filter(|provider| provider.approved && !provider.revoked)
            .cloned()
            .collect()
    }
    pub fn resolve(&self, key: &str) -> Result<ProviderProfile, ModelError> {
        self.providers
            .read()
            .get(key)
            .filter(|provider| provider.approved && !provider.revoked)
            .cloned()
            .ok_or(ModelError::ProviderNotFound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequestEnvelope {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub task_type: String,
    pub classification: DataClassification,
    pub source_jurisdiction: String,
    pub deployment_profile: String,
    pub required_capabilities: BTreeSet<ModelCapability>,
    pub allowed_provider_ids: BTreeSet<String>,
    pub maximum_latency_ms: u64,
    pub maximum_cost_microunits: u64,
    pub maximum_output_bytes: usize,
    pub prompt: Vec<u8>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteCandidate {
    pub provider_key: String,
    pub score_millionths: u32,
    pub reasons: Vec<String>,
}

pub trait RoutePlanner: Send + Sync {
    fn rank(
        &self,
        request: &ModelRequestEnvelope,
        candidates: &[ProviderProfile],
    ) -> Result<Vec<RouteCandidate>, ModelError>;
}

pub struct DeterministicRoutePlanner;
impl RoutePlanner for DeterministicRoutePlanner {
    fn rank(
        &self,
        _request: &ModelRequestEnvelope,
        candidates: &[ProviderProfile],
    ) -> Result<Vec<RouteCandidate>, ModelError> {
        let mut ranked: Vec<RouteCandidate> = candidates
            .iter()
            .map(|candidate| {
                let deployment_score: u32 = match candidate.deployment {
                    DeploymentKind::Local => 1_000_000,
                    DeploymentKind::OnPrem => 900_000,
                    DeploymentKind::Vpc => 750_000,
                    DeploymentKind::PublicApi => 500_000,
                };
                RouteCandidate {
                    provider_key: candidate.key(),
                    score_millionths: deployment_score.saturating_sub(
                        (candidate.cost_microunits_per_token.min(100_000) * 2) as u32,
                    ),
                    reasons: vec![
                        format!("deployment:{:?}", candidate.deployment),
                        format!("unit_cost:{}", candidate.cost_microunits_per_token),
                    ],
                }
            })
            .collect();
        ranked.sort_by(|left, right| {
            right
                .score_millionths
                .cmp(&left.score_millionths)
                .then_with(|| left.provider_key.cmp(&right.provider_key))
        });
        Ok(ranked)
    }
}

#[derive(Debug, Clone)]
pub struct ProviderRequest {
    pub request_hash: String,
    pub prompt: Vec<u8>,
    pub maximum_output_bytes: usize,
    pub idempotency_key: String,
}
#[derive(Debug, Clone)]
pub struct ProviderResponse {
    pub provider_request_id: String,
    pub output: Vec<u8>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelStreamChunk {
    pub schema_version: String,
    pub sequence: u64,
    pub bytes: Vec<u8>,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProviderStreamResponse {
    pub provider_request_id: String,
    pub chunks: Vec<ModelStreamChunk>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[async_trait]
pub trait ModelProviderAdapter: Send + Sync {
    fn provider_key(&self) -> &str;
    async fn generate(&self, request: ProviderRequest) -> Result<ProviderResponse, ModelError>;
    async fn stream(&self, request: ProviderRequest) -> Result<ProviderStreamResponse, ModelError> {
        let response = self.generate(request).await?;
        Ok(ProviderStreamResponse {
            provider_request_id: response.provider_request_id,
            chunks: vec![ModelStreamChunk {
                schema_version: MODEL_SCHEMA_VERSION.into(),
                sequence: 1,
                bytes: response.output,
                finish_reason: Some(response.finish_reason),
            }],
            input_tokens: response.input_tokens,
            output_tokens: response.output_tokens,
        })
    }
    async fn embeddings(&self, _request: ProviderRequest) -> Result<Vec<f32>, ModelError> {
        Err(ModelError::CapabilityMissing)
    }
}

#[async_trait]
pub trait ProviderWireTransport: Send + Sync {
    async fn send(
        &self,
        endpoint_profile: &str,
        body: serde_json::Value,
        maximum_output_bytes: usize,
    ) -> Result<serde_json::Value, ModelError>;
}

/// OpenAI-compatible request/response mapping. Authentication and endpoint resolution are owned
/// by the injected controlled transport, so this adapter never receives raw credentials or URLs.
pub struct OpenAiCompatibleAdapter<T: ProviderWireTransport> {
    provider_key: String,
    endpoint_profile: String,
    model: String,
    transport: Arc<T>,
}
impl<T: ProviderWireTransport> OpenAiCompatibleAdapter<T> {
    pub fn new(
        provider_key: String,
        endpoint_profile: String,
        model: String,
        transport: Arc<T>,
    ) -> Result<Self, ModelError> {
        if provider_key.is_empty() || endpoint_profile.is_empty() || model.is_empty() {
            return Err(ModelError::ConfigurationInvalid);
        }
        Ok(Self {
            provider_key,
            endpoint_profile,
            model,
            transport,
        })
    }
}
#[async_trait]
impl<T: ProviderWireTransport> ModelProviderAdapter for OpenAiCompatibleAdapter<T> {
    fn provider_key(&self) -> &str {
        &self.provider_key
    }
    async fn generate(&self, request: ProviderRequest) -> Result<ProviderResponse, ModelError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [{"role":"user", "content": String::from_utf8_lossy(&request.prompt)}],
            "stream": false,
            "metadata": {"request_hash": request.request_hash, "idempotency_key": request.idempotency_key}
        });
        let value = self
            .transport
            .send(&self.endpoint_profile, body, request.maximum_output_bytes)
            .await?;
        let output = value
            .pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str)
            .ok_or(ModelError::ProviderProtocolInvalid)?
            .as_bytes()
            .to_vec();
        Ok(ProviderResponse {
            provider_request_id: string_field(&value, "id")?,
            output,
            input_tokens: u64_field(&value, "/usage/prompt_tokens")?,
            output_tokens: u64_field(&value, "/usage/completion_tokens")?,
            finish_reason: value
                .pointer("/choices/0/finish_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        })
    }
}

/// Local inference mapping for an on-premises worker contract.
pub struct LocalInferenceAdapter<T: ProviderWireTransport> {
    provider_key: String,
    endpoint_profile: String,
    model_digest: String,
    transport: Arc<T>,
}
impl<T: ProviderWireTransport> LocalInferenceAdapter<T> {
    pub fn new(
        provider_key: String,
        endpoint_profile: String,
        model_digest: String,
        transport: Arc<T>,
    ) -> Result<Self, ModelError> {
        if provider_key.is_empty()
            || endpoint_profile.is_empty()
            || model_digest
                .strip_prefix("sha256:")
                .is_none_or(|digest| digest.len() != 64)
        {
            return Err(ModelError::ConfigurationInvalid);
        }
        Ok(Self {
            provider_key,
            endpoint_profile,
            model_digest,
            transport,
        })
    }
}
#[async_trait]
impl<T: ProviderWireTransport> ModelProviderAdapter for LocalInferenceAdapter<T> {
    fn provider_key(&self) -> &str {
        &self.provider_key
    }
    async fn generate(&self, request: ProviderRequest) -> Result<ProviderResponse, ModelError> {
        let body = serde_json::json!({
            "schema_version": MODEL_SCHEMA_VERSION,
            "model_digest": self.model_digest,
            "prompt_utf8": String::from_utf8_lossy(&request.prompt),
            "request_hash": request.request_hash,
            "idempotency_key": request.idempotency_key,
            "maximum_output_bytes": request.maximum_output_bytes
        });
        let value = self
            .transport
            .send(&self.endpoint_profile, body, request.maximum_output_bytes)
            .await?;
        let output = string_pointer(&value, "/output")?.as_bytes().to_vec();
        Ok(ProviderResponse {
            provider_request_id: string_field(&value, "request_id")?,
            output,
            input_tokens: u64_field(&value, "/input_tokens")?,
            output_tokens: u64_field(&value, "/output_tokens")?,
            finish_reason: string_pointer(&value, "/finish_reason")?.to_owned(),
        })
    }
}

fn string_field(value: &serde_json::Value, field: &str) -> Result<String, ModelError> {
    string_pointer(value, &format!("/{field}")).map(str::to_owned)
}
fn string_pointer<'a>(value: &'a serde_json::Value, pointer: &str) -> Result<&'a str, ModelError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or(ModelError::ProviderProtocolInvalid)
}
fn u64_field(value: &serde_json::Value, pointer: &str) -> Result<u64, ModelError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or(ModelError::ProviderProtocolInvalid)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetReservation {
    pub reservation_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub amount_microunits: u64,
}

#[derive(Default)]
struct BudgetState {
    limits: BTreeMap<TenantId, u64>,
    reserved: BTreeMap<TenantId, u64>,
    reservations: BTreeMap<String, BudgetReservation>,
    finalized: BTreeSet<String>,
}
#[derive(Default)]
pub struct BudgetManager {
    state: Mutex<BudgetState>,
}
impl BudgetManager {
    pub fn set_limit(&self, tenant: TenantId, microunits: u64) {
        self.state.lock().limits.insert(tenant, microunits);
    }
    pub fn reserve(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        amount_microunits: u64,
    ) -> Result<BudgetReservation, ModelError> {
        if amount_microunits == 0 {
            return Err(ModelError::BudgetExceeded);
        }
        let mut state = self.state.lock();
        let limit = *state
            .limits
            .get(&tenant_id)
            .ok_or(ModelError::BudgetExceeded)?;
        let used = *state.reserved.get(&tenant_id).unwrap_or(&0);
        if used.saturating_add(amount_microunits) > limit {
            return Err(ModelError::BudgetExceeded);
        }
        let reservation = BudgetReservation {
            reservation_id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            task_id,
            amount_microunits,
        };
        state.reserved.insert(tenant_id, used + amount_microunits);
        state
            .reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        Ok(reservation)
    }
    pub fn finalize(&self, reservation_id: &str, actual_microunits: u64) -> Result<(), ModelError> {
        let mut state = self.state.lock();
        if state.finalized.contains(reservation_id) {
            return Err(ModelError::BudgetReservationReplayed);
        }
        let reservation = state
            .reservations
            .get(reservation_id)
            .cloned()
            .ok_or(ModelError::BudgetReservationNotFound)?;
        state.reservations.remove(reservation_id);
        state.finalized.insert(reservation_id.into());
        if actual_microunits > reservation.amount_microunits {
            // The provider already performed the call. Preserve the full reservation in
            // accounted usage instead of releasing budget after an overrun.
            return Err(ModelError::BudgetExceeded);
        }
        let used = state
            .reserved
            .get(&reservation.tenant_id)
            .copied()
            .unwrap_or(0);
        state.reserved.insert(
            reservation.tenant_id,
            used - reservation.amount_microunits + actual_microunits,
        );
        Ok(())
    }
}

pub struct PromptDataGuard;
impl PromptDataGuard {
    pub fn inspect(prompt: &[u8], maximum_bytes: usize) -> Result<String, ModelError> {
        if prompt.is_empty() || prompt.len() > maximum_bytes {
            return Err(ModelError::PromptDenied);
        }
        let text = String::from_utf8_lossy(prompt).to_ascii_lowercase();
        if [
            "password=",
            "api_key=",
            "authorization: bearer",
            "-----begin private key-----",
        ]
        .iter()
        .any(|marker| text.contains(marker))
        {
            return Err(ModelError::SecretDetected);
        }
        Ok(hex(Sha256::digest(prompt)))
    }
}

pub struct ResponseDataGuard;
impl ResponseDataGuard {
    pub fn inspect(response: &[u8], maximum_bytes: usize) -> Result<String, ModelError> {
        if response.is_empty() || response.len() > maximum_bytes {
            return Err(ModelError::ResponseTooLarge);
        }
        let text = String::from_utf8_lossy(response).to_ascii_lowercase();
        if [
            "password=",
            "api_key=",
            "authorization: bearer",
            "-----begin private key-----",
        ]
        .iter()
        .any(|marker| text.contains(marker))
        {
            return Err(ModelError::SecretDetected);
        }
        Ok(hex(Sha256::digest(response)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelEvidence {
    pub request_hash: String,
    pub provider_key: String,
    pub provider_request_id: String,
    pub route_reasons: Vec<String>,
    pub data_policy_version: PolicyVersion,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microunits: u64,
    pub output_hash: String,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelGatewayResult {
    pub output: Vec<u8>,
    pub untrusted_content: bool,
    pub evidence: ModelEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStreamGatewayResult {
    pub chunks: Vec<ModelStreamChunk>,
    pub untrusted_content: bool,
    pub evidence: ModelEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderUsageLine {
    pub provider_key: String,
    pub provider_request_id: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub billed_microunits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BillingReconciliation {
    pub schema_version: String,
    pub matched_requests: usize,
    pub total_metered_microunits: u64,
    pub total_billed_microunits: u64,
    pub statement_digest: String,
}

pub fn reconcile_provider_billing(
    evidence: &[ModelEvidence],
    statement: &[ProviderUsageLine],
) -> Result<BillingReconciliation, ModelError> {
    if evidence.is_empty() || evidence.len() != statement.len() || evidence.len() > 1_000_000 {
        return Err(ModelError::BillingMismatch);
    }
    let mut by_request = BTreeMap::new();
    for line in statement {
        if line.provider_request_id.is_empty()
            || line.provider_key.is_empty()
            || by_request
                .insert(line.provider_request_id.as_str(), line)
                .is_some()
        {
            return Err(ModelError::BillingMismatch);
        }
    }
    let mut total_metered = 0_u64;
    let mut total_billed = 0_u64;
    for item in evidence {
        let line = by_request
            .get(item.provider_request_id.as_str())
            .ok_or(ModelError::BillingMismatch)?;
        if line.provider_key != item.provider_key
            || line.input_tokens != item.input_tokens
            || line.output_tokens != item.output_tokens
            || line.billed_microunits != item.cost_microunits
        {
            return Err(ModelError::BillingMismatch);
        }
        total_metered = total_metered
            .checked_add(item.cost_microunits)
            .ok_or(ModelError::BillingMismatch)?;
        total_billed = total_billed
            .checked_add(line.billed_microunits)
            .ok_or(ModelError::BillingMismatch)?;
    }
    let statement_digest = hex(Sha256::digest(
        serde_jcs::to_vec(statement).map_err(|_| ModelError::BillingMismatch)?,
    ));
    Ok(BillingReconciliation {
        schema_version: MODEL_SCHEMA_VERSION.into(),
        matched_requests: evidence.len(),
        total_metered_microunits: total_metered,
        total_billed_microunits: total_billed,
        statement_digest,
    })
}

pub struct ModelGateway<D: DataPolicyPort, R: RoutePlanner> {
    data_policy: Arc<D>,
    registry: Arc<ProviderRegistry>,
    route_planner: Arc<R>,
    budget: Arc<BudgetManager>,
    adapters: BTreeMap<String, Arc<dyn ModelProviderAdapter>>,
}

impl<D: DataPolicyPort, R: RoutePlanner> ModelGateway<D, R> {
    pub fn new(
        data_policy: Arc<D>,
        registry: Arc<ProviderRegistry>,
        route_planner: Arc<R>,
        budget: Arc<BudgetManager>,
        adapters: Vec<Arc<dyn ModelProviderAdapter>>,
    ) -> Result<Self, ModelError> {
        let adapters: BTreeMap<String, Arc<dyn ModelProviderAdapter>> = adapters
            .into_iter()
            .map(|adapter| (adapter.provider_key().into(), adapter))
            .collect();
        if adapters.is_empty() {
            return Err(ModelError::ConfigurationInvalid);
        }
        Ok(Self {
            data_policy,
            registry,
            route_planner,
            budget,
            adapters,
        })
    }
    pub async fn generate(
        &self,
        request: ModelRequestEnvelope,
    ) -> Result<ModelGatewayResult, ModelError> {
        validate_request(&request)?;
        let prompt_hash = PromptDataGuard::inspect(&request.prompt, 4 * 1024 * 1024)?;
        let candidates = self.allowed_candidates(&request)?;
        let ranked = self.route_planner.rank(&request, &candidates)?;
        if ranked.is_empty() {
            return Err(ModelError::NoCompliantProvider);
        }
        let reservation = self.budget.reserve(
            request.tenant_id.clone(),
            request.task_id.clone(),
            request.maximum_cost_microunits,
        )?;
        let provider_request = ProviderRequest {
            request_hash: prompt_hash.clone(),
            prompt: request.prompt.clone(),
            maximum_output_bytes: request.maximum_output_bytes,
            idempotency_key: request.idempotency_key.clone(),
        };
        let mut last_error = ModelError::ProviderUnavailable;
        for route in ranked {
            let provider = match self.registry.resolve(&route.provider_key) {
                Ok(provider) => provider,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let Some(adapter) = self.adapters.get(&route.provider_key) else {
                last_error = ModelError::ProviderUnavailable;
                continue;
            };
            match adapter.generate(provider_request.clone()).await {
                Ok(response) => {
                    let tokens = response.input_tokens.saturating_add(response.output_tokens);
                    let cost = tokens.saturating_mul(provider.cost_microunits_per_token);
                    if response.output.len() > request.maximum_output_bytes
                        || response.output.len() > provider.maximum_output_bytes
                    {
                        self.budget.finalize(&reservation.reservation_id, cost)?;
                        return Err(ModelError::ResponseTooLarge);
                    }
                    let output_hash = ResponseDataGuard::inspect(
                        &response.output,
                        request
                            .maximum_output_bytes
                            .min(provider.maximum_output_bytes),
                    );
                    self.budget.finalize(&reservation.reservation_id, cost)?;
                    let output_hash = output_hash?;
                    let decision = self
                        .data_policy
                        .evaluate(&data_policy_request(&request, &provider))
                        .map_err(|_| ModelError::DataPolicyDenied)?;
                    return Ok(ModelGatewayResult {
                        output: response.output.clone(),
                        untrusted_content: true,
                        evidence: ModelEvidence {
                            request_hash: prompt_hash,
                            provider_key: provider.key(),
                            provider_request_id: response.provider_request_id,
                            route_reasons: route.reasons,
                            data_policy_version: decision.policy_version,
                            input_tokens: response.input_tokens,
                            output_tokens: response.output_tokens,
                            cost_microunits: cost,
                            output_hash,
                            created_at: Utc::now(),
                        },
                    });
                }
                Err(error) => last_error = error,
            }
        }
        let _ = self.budget.finalize(&reservation.reservation_id, 0);
        Err(last_error)
    }

    pub async fn stream(
        &self,
        request: ModelRequestEnvelope,
    ) -> Result<ModelStreamGatewayResult, ModelError> {
        validate_request(&request)?;
        if !request
            .required_capabilities
            .contains(&ModelCapability::Stream)
        {
            return Err(ModelError::CapabilityMissing);
        }
        let prompt_hash = PromptDataGuard::inspect(&request.prompt, 4 * 1024 * 1024)?;
        let candidates = self.allowed_candidates(&request)?;
        let ranked = self.route_planner.rank(&request, &candidates)?;
        let reservation = self.budget.reserve(
            request.tenant_id.clone(),
            request.task_id.clone(),
            request.maximum_cost_microunits,
        )?;
        let provider_request = ProviderRequest {
            request_hash: prompt_hash.clone(),
            prompt: request.prompt.clone(),
            maximum_output_bytes: request.maximum_output_bytes,
            idempotency_key: request.idempotency_key.clone(),
        };
        let mut last_error = ModelError::ProviderUnavailable;
        for route in ranked {
            let provider = match self.registry.resolve(&route.provider_key) {
                Ok(provider) => provider,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let Some(adapter) = self.adapters.get(&route.provider_key) else {
                last_error = ModelError::ProviderUnavailable;
                continue;
            };
            match adapter.stream(provider_request.clone()).await {
                Ok(response) => {
                    let mut expected_sequence = 1_u64;
                    let mut output = Vec::new();
                    if response.chunks.is_empty() || response.chunks.len() > 10_000 {
                        self.budget.finalize(&reservation.reservation_id, 0)?;
                        return Err(ModelError::StreamInvalid);
                    }
                    for (index, chunk) in response.chunks.iter().enumerate() {
                        let final_chunk = index + 1 == response.chunks.len();
                        if chunk.schema_version != MODEL_SCHEMA_VERSION
                            || chunk.sequence != expected_sequence
                            || chunk.bytes.is_empty()
                            || chunk.finish_reason.is_some() != final_chunk
                        {
                            self.budget.finalize(&reservation.reservation_id, 0)?;
                            return Err(ModelError::StreamInvalid);
                        }
                        expected_sequence += 1;
                        output.extend_from_slice(&chunk.bytes);
                        if output.len()
                            > request
                                .maximum_output_bytes
                                .min(provider.maximum_output_bytes)
                        {
                            self.budget.finalize(&reservation.reservation_id, 0)?;
                            return Err(ModelError::ResponseTooLarge);
                        }
                    }
                    let tokens = response.input_tokens.saturating_add(response.output_tokens);
                    let cost = tokens.saturating_mul(provider.cost_microunits_per_token);
                    let output_hash = ResponseDataGuard::inspect(
                        &output,
                        request
                            .maximum_output_bytes
                            .min(provider.maximum_output_bytes),
                    );
                    self.budget.finalize(&reservation.reservation_id, cost)?;
                    let output_hash = output_hash?;
                    let decision = self
                        .data_policy
                        .evaluate(&data_policy_request(&request, &provider))
                        .map_err(|_| ModelError::DataPolicyDenied)?;
                    return Ok(ModelStreamGatewayResult {
                        chunks: response.chunks,
                        untrusted_content: true,
                        evidence: ModelEvidence {
                            request_hash: prompt_hash,
                            provider_key: provider.key(),
                            provider_request_id: response.provider_request_id,
                            route_reasons: route.reasons,
                            data_policy_version: decision.policy_version,
                            input_tokens: response.input_tokens,
                            output_tokens: response.output_tokens,
                            cost_microunits: cost,
                            output_hash,
                            created_at: Utc::now(),
                        },
                    });
                }
                Err(error) => last_error = error,
            }
        }
        let _ = self.budget.finalize(&reservation.reservation_id, 0);
        Err(last_error)
    }
    fn allowed_candidates(
        &self,
        request: &ModelRequestEnvelope,
    ) -> Result<Vec<ProviderProfile>, ModelError> {
        let mut allowed = Vec::new();
        for provider in self.registry.active() {
            if !provider.approved_tenants.contains(&request.tenant_id)
                || !request.allowed_provider_ids.contains(&provider.provider_id)
                || !request
                    .required_capabilities
                    .is_subset(&provider.capabilities)
                || request.prompt.len() > provider.maximum_context_bytes
            {
                continue;
            }
            let decision = self
                .data_policy
                .evaluate(&data_policy_request(request, &provider))
                .map_err(|_| ModelError::DataPolicyDenied)?;
            if decision.allowed {
                allowed.push(provider);
            }
        }
        if allowed.is_empty() {
            Err(ModelError::NoCompliantProvider)
        } else {
            Ok(allowed)
        }
    }
}

fn data_policy_request(
    request: &ModelRequestEnvelope,
    provider: &ProviderProfile,
) -> DataPolicyRequest {
    DataPolicyRequest {
        schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
        tenant_id: request.tenant_id.clone(),
        classification: request.classification,
        source_jurisdiction: request.source_jurisdiction.clone(),
        destination_jurisdiction: provider.jurisdiction.clone(),
        destination_kind: format!("model:{:?}", provider.deployment),
        deployment_profile: request.deployment_profile.clone(),
        contains_secret: false,
        cross_domain_approval_id: None,
    }
}
fn validate_profile(profile: &ProviderProfile) -> Result<(), ModelError> {
    if profile.schema_version != MODEL_SCHEMA_VERSION
        || profile.provider_id.is_empty()
        || profile.model_id.is_empty()
        || profile.model_version.is_empty()
        || profile.capabilities.is_empty()
        || profile.maximum_context_bytes == 0
        || profile.maximum_output_bytes == 0
        || profile
            .endpoint_digest
            .strip_prefix("sha256:")
            .is_none_or(|hash| hash.len() != 64)
    {
        Err(ModelError::ProviderInvalid)
    } else {
        Ok(())
    }
}
fn validate_request(request: &ModelRequestEnvelope) -> Result<(), ModelError> {
    if request.schema_version != MODEL_SCHEMA_VERSION
        || request.task_type.is_empty()
        || request.allowed_provider_ids.is_empty()
        || request.required_capabilities.is_empty()
        || request.maximum_latency_ms == 0
        || request.maximum_cost_microunits == 0
        || request.maximum_output_bytes == 0
        || request.idempotency_key.is_empty()
    {
        Err(ModelError::RequestInvalid)
    } else {
        Ok(())
    }
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    #[error("MODEL_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("MODEL_PROVIDER_INVALID")]
    ProviderInvalid,
    #[error("MODEL_PROVIDER_DENIED")]
    ProviderDenied,
    #[error("MODEL_PROVIDER_NOT_FOUND")]
    ProviderNotFound,
    #[error("MODEL_PROVIDER_UNAVAILABLE")]
    ProviderUnavailable,
    #[error("MODEL_PROVIDER_PROTOCOL_INVALID")]
    ProviderProtocolInvalid,
    #[error("MODEL_VERSION_CONFLICT")]
    VersionConflict,
    #[error("MODEL_REQUEST_INVALID")]
    RequestInvalid,
    #[error("MODEL_PROMPT_DENIED")]
    PromptDenied,
    #[error("MODEL_SECRET_DETECTED")]
    SecretDetected,
    #[error("MODEL_DATA_POLICY_DENIED")]
    DataPolicyDenied,
    #[error("MODEL_NO_COMPLIANT_PROVIDER")]
    NoCompliantProvider,
    #[error("MODEL_CAPABILITY_MISSING")]
    CapabilityMissing,
    #[error("MODEL_BUDGET_EXCEEDED")]
    BudgetExceeded,
    #[error("MODEL_BUDGET_RESERVATION_NOT_FOUND")]
    BudgetReservationNotFound,
    #[error("MODEL_BUDGET_RESERVATION_REPLAYED")]
    BudgetReservationReplayed,
    #[error("MODEL_RESPONSE_TOO_LARGE")]
    ResponseTooLarge,
    #[error("MODEL_STREAM_INVALID")]
    StreamInvalid,
    #[error("MODEL_BILLING_MISMATCH")]
    BillingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{ContractError, DataPolicyDecision};
    use parking_lot::Mutex;

    struct Policy;
    impl DataPolicyPort for Policy {
        fn evaluate(
            &self,
            request: &DataPolicyRequest,
        ) -> Result<DataPolicyDecision, ContractError> {
            let sensitive = matches!(
                request.classification,
                DataClassification::Restricted | DataClassification::Regulated
            );
            let public = request.destination_kind.contains("PublicApi");
            Ok(DataPolicyDecision {
                schema_version: SchemaVersion("agenttrust.data-policy.v1".into()),
                allowed: !(request.contains_secret || sensitive && public)
                    && request.source_jurisdiction == request.destination_jurisdiction,
                policy_version: PolicyVersion("data-v1".into()),
                reason_codes: vec![],
                required_transformations: vec![],
                maximum_retention_seconds: 3600,
            })
        }
    }
    struct Adapter {
        key: String,
        fail: bool,
        calls: Mutex<u32>,
    }
    struct Wire;
    #[async_trait]
    impl ProviderWireTransport for Wire {
        async fn send(
            &self,
            _: &str,
            body: serde_json::Value,
            _: usize,
        ) -> Result<serde_json::Value, ModelError> {
            if body.get("messages").is_some() {
                Ok(serde_json::json!({
                    "id":"openai-request",
                    "choices":[{"message":{"content":"openai-output"},"finish_reason":"stop"}],
                    "usage":{"prompt_tokens":2,"completion_tokens":3}
                }))
            } else {
                Ok(serde_json::json!({
                    "request_id":"local-request", "output":"local-output",
                    "input_tokens":2, "output_tokens":3, "finish_reason":"stop"
                }))
            }
        }
    }
    #[async_trait]
    impl ModelProviderAdapter for Adapter {
        fn provider_key(&self) -> &str {
            &self.key
        }
        async fn generate(&self, request: ProviderRequest) -> Result<ProviderResponse, ModelError> {
            *self.calls.lock() += 1;
            if self.fail {
                Err(ModelError::ProviderUnavailable)
            } else {
                Ok(ProviderResponse {
                    provider_request_id: Uuid::new_v4().to_string(),
                    output: b"safe output".to_vec(),
                    input_tokens: request.prompt.len() as u64,
                    output_tokens: 2,
                    finish_reason: "stop".into(),
                })
            }
        }
    }
    fn profile(
        tenant: &TenantId,
        provider_id: &str,
        deployment: DeploymentKind,
        cost: u64,
    ) -> ProviderProfile {
        ProviderProfile {
            schema_version: MODEL_SCHEMA_VERSION.into(),
            provider_id: provider_id.into(),
            model_id: "model".into(),
            model_version: "1".into(),
            region: "cn".into(),
            jurisdiction: "CN".into(),
            deployment,
            capabilities: BTreeSet::from([ModelCapability::Generate, ModelCapability::Stream]),
            endpoint_digest: format!("sha256:{}", "a".repeat(64)),
            data_terms_version: "1".into(),
            approved_tenants: BTreeSet::from([tenant.clone()]),
            approved: true,
            revoked: false,
            maximum_context_bytes: 4096,
            maximum_output_bytes: 4096,
            cost_microunits_per_token: cost,
        }
    }
    fn request(tenant: TenantId, classification: DataClassification) -> ModelRequestEnvelope {
        ModelRequestEnvelope {
            schema_version: MODEL_SCHEMA_VERSION.into(),
            tenant_id: tenant,
            task_id: TaskId::new(),
            task_type: "chat".into(),
            classification,
            source_jurisdiction: "CN".into(),
            deployment_profile: "private".into(),
            required_capabilities: BTreeSet::from([ModelCapability::Generate]),
            allowed_provider_ids: BTreeSet::from(["public".into(), "local".into()]),
            maximum_latency_ms: 1000,
            maximum_cost_microunits: 100_000,
            maximum_output_bytes: 1024,
            prompt: b"safe prompt".to_vec(),
            idempotency_key: Uuid::new_v4().to_string(),
        }
    }

    #[tokio::test]
    async fn restricted_data_never_routes_or_falls_back_to_public() {
        let tenant = TenantId::new();
        let registry = Arc::new(ProviderRegistry::default());
        let public = profile(&tenant, "public", DeploymentKind::PublicApi, 1);
        let local = profile(&tenant, "local", DeploymentKind::Local, 2);
        registry
            .approve(public.clone())
            .unwrap_or_else(|_| panic!("public"));
        registry
            .approve(local.clone())
            .unwrap_or_else(|_| panic!("local"));
        let public_adapter = Arc::new(Adapter {
            key: public.key(),
            fail: false,
            calls: Mutex::new(0),
        });
        let local_adapter = Arc::new(Adapter {
            key: local.key(),
            fail: false,
            calls: Mutex::new(0),
        });
        let budget = Arc::new(BudgetManager::default());
        budget.set_limit(tenant.clone(), 1_000_000);
        let gateway = ModelGateway::new(
            Arc::new(Policy),
            registry,
            Arc::new(DeterministicRoutePlanner),
            budget,
            vec![public_adapter.clone(), local_adapter.clone()],
        )
        .unwrap_or_else(|_| panic!("gateway"));
        let result = gateway
            .generate(request(tenant, DataClassification::Restricted))
            .await
            .unwrap_or_else(|_| panic!("generate"));
        assert!(result.evidence.provider_key.starts_with("local:"));
        assert_eq!(*public_adapter.calls.lock(), 0);
    }

    #[tokio::test]
    async fn two_provider_wire_contracts_map_to_one_bounded_response() {
        let request = ProviderRequest {
            request_hash: "a".repeat(64),
            prompt: b"safe".to_vec(),
            maximum_output_bytes: 1024,
            idempotency_key: "idem".into(),
        };
        let openai = OpenAiCompatibleAdapter::new(
            "openai:model:1".into(),
            "controlled-openai".into(),
            "model".into(),
            Arc::new(Wire),
        )
        .unwrap_or_else(|_| panic!("openai adapter"));
        let local = LocalInferenceAdapter::new(
            "local:model:1".into(),
            "controlled-local".into(),
            format!("sha256:{}", "b".repeat(64)),
            Arc::new(Wire),
        )
        .unwrap_or_else(|_| panic!("local adapter"));
        assert_eq!(
            openai
                .generate(request.clone())
                .await
                .unwrap_or_else(|_| panic!("openai"))
                .output,
            b"openai-output"
        );
        assert_eq!(
            local
                .generate(request)
                .await
                .unwrap_or_else(|_| panic!("local"))
                .output,
            b"local-output"
        );
    }

    #[test]
    fn secrets_and_concurrent_overspend_are_denied() {
        assert_eq!(
            PromptDataGuard::inspect(b"api_key=secret", 1024),
            Err(ModelError::SecretDetected)
        );
        assert_eq!(
            ResponseDataGuard::inspect(b"Authorization: Bearer leaked-token", 1024),
            Err(ModelError::SecretDetected)
        );
        let tenant = TenantId::new();
        let budget = Arc::new(BudgetManager::default());
        budget.set_limit(tenant.clone(), 100);
        assert!(budget.reserve(tenant.clone(), TaskId::new(), 80).is_ok());
        assert_eq!(
            budget.reserve(tenant, TaskId::new(), 30).err(),
            Some(ModelError::BudgetExceeded)
        );
    }

    #[test]
    fn provider_cost_overrun_is_accounted_and_cannot_release_the_reservation() {
        let tenant = TenantId::new();
        let budget = BudgetManager::default();
        budget.set_limit(tenant.clone(), 100);
        let reservation = budget
            .reserve(tenant.clone(), TaskId::new(), 80)
            .unwrap_or_else(|_| panic!("reserve"));
        assert_eq!(
            budget.finalize(&reservation.reservation_id, 81),
            Err(ModelError::BudgetExceeded)
        );
        assert_eq!(
            budget.finalize(&reservation.reservation_id, 0),
            Err(ModelError::BudgetReservationReplayed)
        );
        assert_eq!(
            budget.reserve(tenant, TaskId::new(), 21).err(),
            Some(ModelError::BudgetExceeded)
        );
    }

    #[test]
    fn revoked_exact_model_version_is_unavailable() {
        let tenant = TenantId::new();
        let registry = ProviderRegistry::default();
        let provider = profile(&tenant, "local", DeploymentKind::Local, 1);
        let key = provider.key();
        registry
            .approve(provider)
            .unwrap_or_else(|_| panic!("approve"));
        registry.revoke(&key).unwrap_or_else(|_| panic!("revoke"));
        assert_eq!(
            registry.resolve(&key).err(),
            Some(ModelError::ProviderNotFound)
        );
    }

    #[tokio::test]
    async fn stream_is_bounded_metered_and_reconciles_provider_billing() {
        let tenant = TenantId::new();
        let registry = Arc::new(ProviderRegistry::default());
        let provider = profile(&tenant, "local", DeploymentKind::Local, 2);
        registry
            .approve(provider.clone())
            .unwrap_or_else(|_| panic!("provider"));
        let adapter = Arc::new(Adapter {
            key: provider.key(),
            fail: false,
            calls: Mutex::new(0),
        });
        let budget = Arc::new(BudgetManager::default());
        budget.set_limit(tenant.clone(), 1_000_000);
        let gateway = ModelGateway::new(
            Arc::new(Policy),
            registry,
            Arc::new(DeterministicRoutePlanner),
            budget,
            vec![adapter],
        )
        .unwrap_or_else(|_| panic!("gateway"));
        let mut model_request = request(tenant, DataClassification::Internal);
        model_request.required_capabilities = BTreeSet::from([ModelCapability::Stream]);
        model_request.allowed_provider_ids = BTreeSet::from(["local".into()]);
        let result = gateway
            .stream(model_request)
            .await
            .unwrap_or_else(|_| panic!("stream"));
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].sequence, 1);
        let statement = vec![ProviderUsageLine {
            provider_key: result.evidence.provider_key.clone(),
            provider_request_id: result.evidence.provider_request_id.clone(),
            input_tokens: result.evidence.input_tokens,
            output_tokens: result.evidence.output_tokens,
            billed_microunits: result.evidence.cost_microunits,
        }];
        let reconciliation =
            reconcile_provider_billing(std::slice::from_ref(&result.evidence), &statement)
                .unwrap_or_else(|_| panic!("reconciliation"));
        assert_eq!(reconciliation.matched_requests, 1);
        let mut tampered = statement;
        tampered[0].billed_microunits += 1;
        assert_eq!(
            reconcile_provider_billing(std::slice::from_ref(&result.evidence), &tampered),
            Err(ModelError::BillingMismatch)
        );
    }
}
