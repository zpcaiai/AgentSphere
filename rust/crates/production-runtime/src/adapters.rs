use crate::{config::IdentityConfig, http::SecureHttpTransport};
use agent_trust_contracts::{AgentInstanceId, SchemaVersion, TenantId};
use agent_trust_gateway::{
    ActionView, GatewayError, IdentityContext, IdentityVerifierPort, InboundEnvelope,
    IngressResponse, OrchestratorSubmissionPort, RequestParts,
};
use agent_trust_identity::{
    AgentPrincipal, EnterpriseOidcJwtVerifier, FederatedTrustBundleProvider,
    FederatedTrustBundleSnapshot, IDENTITY_SCHEMA_VERSION, IdentityError, IdentityFederationPort,
};
use agent_trust_industrial_edge_gateway::{
    AssetChannel, IndustrialAdapter, IndustrialError, TelemetrySample,
};
use agent_trust_model_gateway::{
    MODEL_SCHEMA_VERSION, ModelError, ModelProviderAdapter, ModelStreamChunk, ProviderRequest,
    ProviderResponse, ProviderStreamResponse, ProviderWireTransport,
};
use agent_trust_sandbox_runtime::{CredentialLifecyclePort, SandboxError};
use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use http::header::AUTHORIZATION;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use url::Url;

pub struct RefreshingJwksProvider {
    issuer: String,
    path: String,
    ttl: Duration,
    transport: SecureHttpTransport,
    cache: RwLock<Option<FederatedTrustBundleSnapshot>>,
}

impl RefreshingJwksProvider {
    pub fn new(config: &IdentityConfig) -> Result<Self, IdentityError> {
        config
            .validate()
            .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
        let parsed = Url::parse(&config.jwks_endpoint)
            .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
        let path = parsed.path().to_string();
        let transport = SecureHttpTransport::for_jwks(&config.jwks_endpoint, &config.jwks_tls)
            .map_err(|_| IdentityError::ProductionTrustNotConfigured)?;
        Ok(Self {
            issuer: config.issuer.clone(),
            path,
            ttl: Duration::from_secs(config.jwks_ttl_seconds),
            transport,
            cache: RwLock::new(None),
        })
    }
    fn refresh_blocking(&self) -> Result<(), IdentityError> {
        let now = Utc::now();
        let bytes = self
            .transport
            .get_bytes_blocking(&self.path)
            .map_err(|_| IdentityError::TrustBundleUnavailable)?;
        let version = format!("sha256:{}", hex(Sha256::digest(&bytes)));
        let valid_until = now
            + ChronoDuration::from_std(self.ttl)
                .map_err(|_| IdentityError::TrustBundleUnavailable)?;
        let snapshot = FederatedTrustBundleSnapshot::from_jwks(
            self.issuer.clone(),
            version,
            valid_until,
            &bytes,
        )?;
        *self.cache.write() = Some(snapshot);
        Ok(())
    }
}

impl FederatedTrustBundleProvider for RefreshingJwksProvider {
    fn current(&self) -> Result<FederatedTrustBundleSnapshot, IdentityError> {
        let now = Utc::now();
        if let Some(snapshot) = self
            .cache
            .read()
            .as_ref()
            .filter(|item| now < item.valid_until)
        {
            return Ok(snapshot.clone());
        }
        Err(IdentityError::TrustBundleUnavailable)
    }
}

pub struct ProductionIdentityVerifier {
    verifier: Arc<EnterpriseOidcJwtVerifier>,
    trust: Arc<RefreshingJwksProvider>,
    audience: String,
    agents: BTreeMap<String, AgentInstanceId>,
    require_mtls_peer: bool,
}

impl ProductionIdentityVerifier {
    pub fn new(config: &IdentityConfig) -> Result<Self, IdentityError> {
        let trust = Arc::new(RefreshingJwksProvider::new(config)?);
        let verifier = Arc::new(EnterpriseOidcJwtVerifier::new(
            config.issuer.clone(),
            config.audience.clone(),
            config.authorized_party.clone(),
            trust.clone(),
            30,
        )?);
        let mut agents = BTreeMap::new();
        for mapping in &config.subject_mappings {
            let tenant = TenantId::parse(mapping.tenant_id.clone())
                .map_err(|_| IdentityError::TenantMismatch)?;
            let agent = AgentInstanceId::parse(mapping.agent_instance_id.clone())
                .map_err(|_| IdentityError::OwnershipUnknown)?;
            let principal = AgentPrincipal {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                subject: mapping.subject.clone(),
                organization_id: mapping.organization_id.clone(),
                tenant_id: tenant,
                owner_subject: mapping.owner_subject.clone(),
                roles: mapping.roles.iter().cloned().collect::<BTreeSet<_>>(),
                auth_strength: mapping.auth_strength.clone(),
            };
            verifier.map_subject(mapping.subject.clone(), principal);
            if agents.insert(mapping.subject.clone(), agent).is_some() {
                return Err(IdentityError::OwnershipUnknown);
            }
        }
        Ok(Self {
            verifier,
            trust,
            audience: config.audience.clone(),
            agents,
            require_mtls_peer: config.require_mtls_peer,
        })
    }

    pub async fn warm(&self) -> Result<(), IdentityError> {
        let trust = self.trust.clone();
        tokio::task::spawn_blocking(move || trust.refresh_blocking())
            .await
            .map_err(|_| IdentityError::TrustBundleUnavailable)??;
        Ok(())
    }

    pub async fn refresh_loop(self: Arc<Self>) {
        let interval = (self.trust.ttl / 2).max(Duration::from_secs(15));
        loop {
            tokio::time::sleep(interval).await;
            let trust = self.trust.clone();
            let _ = tokio::task::spawn_blocking(move || trust.refresh_blocking()).await;
        }
    }
}

#[async_trait]
impl IdentityVerifierPort for ProductionIdentityVerifier {
    async fn verify(&self, request: &RequestParts) -> Result<IdentityContext, GatewayError> {
        if self.require_mtls_peer {
            let peer = request
                .headers
                .get("x-agenttrust-peer-certificate-sha256")
                .and_then(|value| value.to_str().ok())
                .ok_or(GatewayError::Unauthenticated)?;
            if peer.len() != 64 || !peer.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(GatewayError::Unauthenticated);
            }
        }
        let header = request
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(GatewayError::Unauthenticated)?;
        let token = header
            .strip_prefix("Bearer ")
            .filter(|value| !value.is_empty())
            .ok_or(GatewayError::Unauthenticated)?;
        let principal = self
            .verifier
            .verify_federated_token(token, &self.audience, Utc::now())
            .await
            .map_err(|_| GatewayError::Unauthenticated)?;
        let agent = self
            .agents
            .get(&principal.subject)
            .cloned()
            .ok_or(GatewayError::Forbidden)?;
        Ok(IdentityContext {
            subject: principal.subject,
            tenant_id: principal.tenant_id,
            agent_instance_id: agent,
            owner_subject: principal.owner_subject,
            trust_level: principal.auth_strength,
        })
    }
    fn production_ready(&self) -> bool {
        self.trust.current().is_ok()
    }
}

#[derive(Clone)]
pub struct HttpOrchestratorAdapter {
    transport: SecureHttpTransport,
}
impl HttpOrchestratorAdapter {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}

#[derive(Serialize)]
struct ActionQuery<'a> {
    tenant_id: &'a TenantId,
    owner: &'a str,
    action_id: &'a agent_trust_contracts::ActionId,
}
#[derive(Serialize)]
struct TaskQuery<'a> {
    tenant_id: &'a TenantId,
    owner: &'a str,
    task_id: &'a agent_trust_contracts::TaskId,
}
#[derive(Deserialize)]
struct ReadyResponse {
    ready: bool,
}
#[derive(Deserialize)]
struct StreamResponse {
    events: Vec<String>,
}
#[derive(Deserialize)]
struct AckResponse {
    accepted: bool,
}

#[async_trait]
impl OrchestratorSubmissionPort for HttpOrchestratorAdapter {
    async fn submit(&self, envelope: InboundEnvelope) -> Result<IngressResponse, GatewayError> {
        let tenant_id = envelope.tenant_context.tenant_id.0.clone();
        self.transport
            .post_json_tenant(
                "/v1/actions",
                &tenant_id,
                &envelope,
                envelope.idempotency_key.as_deref(),
            )
            .await
            .map_err(|_| GatewayError::DownstreamUnavailable)
    }
    async fn get(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &agent_trust_contracts::ActionId,
    ) -> Result<ActionView, GatewayError> {
        self.transport
            .post_json_tenant(
                "/v1/actions/query",
                &tenant.0,
                &ActionQuery {
                    tenant_id: tenant,
                    owner,
                    action_id: action,
                },
                None,
            )
            .await
            .map_err(|_| GatewayError::NotFoundOrForbidden)
    }
    async fn cancel(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &agent_trust_contracts::ActionId,
    ) -> Result<(), GatewayError> {
        let response: AckResponse = self
            .transport
            .post_json_tenant(
                "/v1/actions/cancel",
                &tenant.0,
                &ActionQuery {
                    tenant_id: tenant,
                    owner,
                    action_id: action,
                },
                Some(&format!("cancel:{}", action.0)),
            )
            .await
            .map_err(|_| GatewayError::DownstreamUnavailable)?;
        if response.accepted {
            Ok(())
        } else {
            Err(GatewayError::DownstreamUnavailable)
        }
    }
    async fn kill(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &agent_trust_contracts::ActionId,
    ) -> Result<(), GatewayError> {
        let response: AckResponse = self
            .transport
            .post_json_tenant(
                "/v1/actions/kill",
                &tenant.0,
                &ActionQuery {
                    tenant_id: tenant,
                    owner,
                    action_id: action,
                },
                Some(&format!("kill:{}", action.0)),
            )
            .await
            .map_err(|_| GatewayError::DownstreamUnavailable)?;
        if response.accepted {
            Ok(())
        } else {
            Err(GatewayError::DownstreamUnavailable)
        }
    }
    async fn stream_snapshot(
        &self,
        tenant: &TenantId,
        owner: &str,
        task: &agent_trust_contracts::TaskId,
    ) -> Result<Vec<String>, GatewayError> {
        let response: StreamResponse = self
            .transport
            .post_json_tenant(
                "/v1/tasks/stream-snapshot",
                &tenant.0,
                &TaskQuery {
                    tenant_id: tenant,
                    owner,
                    task_id: task,
                },
                None,
            )
            .await
            .map_err(|_| GatewayError::DownstreamUnavailable)?;
        Ok(response.events)
    }
    async fn ready(&self) -> bool {
        self.transport
            .get_bytes("/ready")
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ReadyResponse>(&bytes).ok())
            .is_some_and(|response| response.ready)
    }
}

#[derive(Clone)]
pub struct ControlledModelTransport {
    profiles: BTreeMap<String, SecureHttpTransport>,
}
impl ControlledModelTransport {
    pub fn new(profiles: BTreeMap<String, SecureHttpTransport>) -> Result<Self, ModelError> {
        if profiles.is_empty() || profiles.keys().any(|key| key.is_empty()) {
            return Err(ModelError::ConfigurationInvalid);
        }
        Ok(Self { profiles })
    }
}

pub struct ProductionModelAdapter {
    provider_key: String,
    model: String,
    transport: SecureHttpTransport,
}
impl ProductionModelAdapter {
    pub fn new(
        provider_key: String,
        model: String,
        transport: SecureHttpTransport,
    ) -> Result<Self, ModelError> {
        if provider_key.is_empty() || model.is_empty() {
            return Err(ModelError::ConfigurationInvalid);
        }
        Ok(Self {
            provider_key,
            model,
            transport,
        })
    }
    fn body(&self, request: &ProviderRequest, stream: bool) -> Value {
        let mut body = json!({"model": self.model, "messages": [{"role": "user",
            "content": String::from_utf8_lossy(&request.prompt)}], "stream": stream,
            "metadata": {"request_hash": request.request_hash,
                "idempotency_key": request.idempotency_key}});
        if stream {
            body["stream_options"] = json!({"include_usage": true});
        }
        body
    }
}

#[async_trait]
impl ModelProviderAdapter for ProductionModelAdapter {
    fn provider_key(&self) -> &str {
        &self.provider_key
    }
    async fn generate(&self, request: ProviderRequest) -> Result<ProviderResponse, ModelError> {
        let value: Value = self
            .transport
            .post_json(
                "/v1/chat/completions",
                &self.body(&request, false),
                Some(&request.idempotency_key),
            )
            .await
            .map_err(|_| ModelError::ProviderUnavailable)?;
        parse_model_response(value, request.maximum_output_bytes)
    }
    async fn stream(&self, request: ProviderRequest) -> Result<ProviderStreamResponse, ModelError> {
        let bytes = self
            .transport
            .post_json_bytes(
                "/v1/chat/completions",
                &self.body(&request, true),
                Some(&request.idempotency_key),
                request.maximum_output_bytes,
                "text/event-stream",
            )
            .await
            .map_err(|_| ModelError::ProviderUnavailable)?;
        parse_sse_response(&bytes, request.maximum_output_bytes)
    }
    async fn embeddings(&self, request: ProviderRequest) -> Result<Vec<f32>, ModelError> {
        let body = json!({"model": self.model, "input": String::from_utf8_lossy(&request.prompt),
            "metadata": {"request_hash": request.request_hash, "idempotency_key": request.idempotency_key}});
        let value: Value = self
            .transport
            .post_json("/v1/embeddings", &body, Some(&request.idempotency_key))
            .await
            .map_err(|_| ModelError::ProviderUnavailable)?;
        let values = value
            .pointer("/data/0/embedding")
            .and_then(Value::as_array)
            .ok_or(ModelError::ProviderProtocolInvalid)?;
        if values.is_empty() || values.len() > 65_536 {
            return Err(ModelError::ProviderProtocolInvalid);
        }
        values
            .iter()
            .map(|item| {
                item.as_f64()
                    .map(|number| number as f32)
                    .filter(|number| number.is_finite())
                    .ok_or(ModelError::ProviderProtocolInvalid)
            })
            .collect()
    }
}

fn parse_model_response(value: Value, maximum: usize) -> Result<ProviderResponse, ModelError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ModelError::ProviderProtocolInvalid)?;
    let output = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or(ModelError::ProviderProtocolInvalid)?
        .as_bytes()
        .to_vec();
    if output.len() > maximum {
        return Err(ModelError::ResponseTooLarge);
    }
    let input_tokens = value
        .pointer("/usage/prompt_tokens")
        .and_then(Value::as_u64)
        .ok_or(ModelError::ProviderProtocolInvalid)?;
    let output_tokens = value
        .pointer("/usage/completion_tokens")
        .and_then(Value::as_u64)
        .ok_or(ModelError::ProviderProtocolInvalid)?;
    let finish_reason = value
        .pointer("/choices/0/finish_reason")
        .and_then(Value::as_str)
        .ok_or(ModelError::ProviderProtocolInvalid)?;
    Ok(ProviderResponse {
        provider_request_id: id.into(),
        output,
        input_tokens,
        output_tokens,
        finish_reason: finish_reason.into(),
    })
}

fn parse_sse_response(bytes: &[u8], maximum: usize) -> Result<ProviderStreamResponse, ModelError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ModelError::StreamInvalid)?;
    let mut request_id = None;
    let mut chunks = Vec::new();
    let mut input_tokens = 0;
    let mut output_tokens = 0;
    let mut total = 0usize;
    let mut event_count = 0usize;
    for line in text.lines().filter_map(|line| line.strip_prefix("data: ")) {
        event_count = event_count
            .checked_add(1)
            .ok_or(ModelError::StreamInvalid)?;
        if event_count > 10_002 {
            return Err(ModelError::StreamInvalid);
        }
        if line == "[DONE]" {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|_| ModelError::StreamInvalid)?;
        let event_request_id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::StreamInvalid)?;
        match request_id.as_deref() {
            Some(expected) if expected != event_request_id => {
                return Err(ModelError::StreamInvalid);
            }
            None => request_id = Some(event_request_id.to_owned()),
            _ => {}
        }
        if let Some(usage) = value.get("usage") {
            input_tokens = usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(input_tokens);
            output_tokens = usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(output_tokens);
        }
        let content = value
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
            .unwrap_or("");
        let finish = value
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if content.is_empty() && finish.is_none() {
            continue;
        }
        if chunks
            .last()
            .is_some_and(|chunk: &ModelStreamChunk| chunk.finish_reason.is_some())
        {
            return Err(ModelError::StreamInvalid);
        }
        // OpenAI-compatible streams commonly send finish_reason in a final event with
        // no content. Attach it to the preceding non-empty chunk so the shared bounded
        // stream contract keeps every chunk non-empty and exactly one terminal marker.
        if content.is_empty() {
            let terminal = chunks.last_mut().ok_or(ModelError::StreamInvalid)?;
            terminal.finish_reason = finish;
            continue;
        }
        total = total
            .checked_add(content.len())
            .ok_or(ModelError::ResponseTooLarge)?;
        if total > maximum || chunks.len() >= 10_000 {
            return Err(ModelError::ResponseTooLarge);
        }
        chunks.push(ModelStreamChunk {
            schema_version: MODEL_SCHEMA_VERSION.into(),
            sequence: chunks.len() as u64 + 1,
            bytes: content.as_bytes().to_vec(),
            finish_reason: finish,
        });
    }
    if chunks.is_empty()
        || !chunks
            .last()
            .is_some_and(|chunk| chunk.finish_reason.is_some())
    {
        return Err(ModelError::StreamInvalid);
    }
    if input_tokens == 0 || output_tokens == 0 {
        return Err(ModelError::BillingMismatch);
    }
    Ok(ProviderStreamResponse {
        provider_request_id: request_id.ok_or(ModelError::StreamInvalid)?,
        chunks,
        input_tokens,
        output_tokens,
    })
}
#[async_trait]
impl ProviderWireTransport for ControlledModelTransport {
    async fn send(
        &self,
        endpoint_profile: &str,
        body: Value,
        maximum_output_bytes: usize,
    ) -> Result<Value, ModelError> {
        if maximum_output_bytes == 0 || maximum_output_bytes > 32 * 1024 * 1024 {
            return Err(ModelError::RequestInvalid);
        }
        let transport = self
            .profiles
            .get(endpoint_profile)
            .ok_or(ModelError::ProviderNotFound)?;
        let value: Value = transport
            .post_json(
                "/v1/chat/completions",
                &body,
                body.pointer("/metadata/idempotency_key")
                    .and_then(Value::as_str),
            )
            .await
            .map_err(|_| ModelError::ProviderUnavailable)?;
        let size = serde_json::to_vec(&value)
            .map_err(|_| ModelError::ProviderProtocolInvalid)?
            .len();
        if size > maximum_output_bytes {
            return Err(ModelError::ResponseTooLarge);
        }
        Ok(value)
    }
}

#[derive(Clone)]
pub struct SecretBrokerCredentialLifecycle {
    transport: SecureHttpTransport,
}
impl SecretBrokerCredentialLifecycle {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
#[async_trait]
impl CredentialLifecyclePort for SecretBrokerCredentialLifecycle {
    async fn revoke_all(&self, credential_refs: &[String]) -> Result<(), SandboxError> {
        if credential_refs.is_empty() || credential_refs.len() > 1_000 {
            return Err(SandboxError::CleanupIncomplete);
        }
        let response: AckResponse = self
            .transport
            .post_json(
                "/v1/leases/revoke",
                &json!({"credential_refs": credential_refs}),
                None,
            )
            .await
            .map_err(|_| SandboxError::CleanupIncomplete)?;
        if response.accepted {
            Ok(())
        } else {
            Err(SandboxError::CleanupIncomplete)
        }
    }
}

#[derive(Clone)]
pub struct HttpIndustrialAdapter {
    transport: SecureHttpTransport,
}
impl HttpIndustrialAdapter {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
#[async_trait]
impl IndustrialAdapter for HttpIndustrialAdapter {
    async fn read(&self, channel: &AssetChannel) -> Result<TelemetrySample, IndustrialError> {
        self.transport
            .post_json("/v1/industrial/read", channel, None)
            .await
            .map_err(|_| IndustrialError::TelemetryUnavailable)
    }
    async fn compare_and_set(
        &self,
        channel: &AssetChannel,
        expected_version: &str,
        expected_value: &Value,
        new_value: &Value,
    ) -> Result<TelemetrySample, IndustrialError> {
        self.transport
            .post_json(
                "/v1/industrial/compare-and-set",
                &json!({
                    "channel": channel, "expected_version": expected_version,
                    "expected_value": expected_value, "new_value": new_value
                }),
                Some(&format!(
                    "industrial-cas:{}:{}",
                    channel.resource.key(),
                    expected_version
                )),
            )
            .await
            .map_err(|_| IndustrialError::ResourceVersionChanged)
    }
    async fn safe_stop(&self, channel: &AssetChannel) -> Result<(), IndustrialError> {
        let response: AckResponse = self
            .transport
            .post_json(
                "/v1/industrial/safe-stop",
                channel,
                Some(&format!("industrial-safe-stop:{}", channel.resource.key())),
            )
            .await
            .map_err(|_| IndustrialError::JournalFailed)?;
        if response.accepted {
            Ok(())
        } else {
            Err(IndustrialError::JournalFailed)
        }
    }
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
    fn parses_bounded_generation_usage() {
        let response = parse_model_response(json!({
            "id": "request-1", "choices": [{"message": {"content": "safe"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1}
        }), 16).unwrap_or_else(|_| panic!("response"));
        assert_eq!(response.provider_request_id, "request-1");
        assert_eq!(response.output, b"safe");
        assert_eq!(response.input_tokens, 2);
    }

    #[test]
    fn parses_real_sse_chunks_and_usage() {
        let stream = concat!(
            "data: {\"id\":\"request-2\",\"choices\":[{\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"request-2\",\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n",
            "data: [DONE]\n\n"
        );
        let response =
            parse_sse_response(stream.as_bytes(), 32).unwrap_or_else(|_| panic!("stream"));
        assert_eq!(response.chunks.len(), 2);
        assert_eq!(response.output_tokens, 2);
        assert_eq!(response.chunks[1].finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn attaches_contentless_terminal_sse_event_to_last_chunk() {
        let stream = concat!(
            "data: {\"id\":\"request-4\",\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"request-4\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}\n\n",
            "data: [DONE]\n\n"
        );
        let response =
            parse_sse_response(stream.as_bytes(), 32).unwrap_or_else(|_| panic!("stream"));
        assert_eq!(response.chunks.len(), 1);
        assert_eq!(response.chunks[0].bytes, b"hello");
        assert_eq!(response.chunks[0].finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn rejects_sse_request_id_substitution() {
        let stream = concat!(
            "data: {\"id\":\"request-5\",\"choices\":[{\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"other-request\",\"choices\":[{\"delta\":{\"content\":\"b\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"
        );
        assert!(matches!(
            parse_sse_response(stream.as_bytes(), 32),
            Err(ModelError::StreamInvalid)
        ));
    }

    #[test]
    fn rejects_oversized_model_output() {
        let result = parse_model_response(
            json!({
                "id": "request-3", "choices": [{"message": {"content": "too-large"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            }),
            3,
        );
        assert!(matches!(result, Err(ModelError::ResponseTooLarge)));
    }
}
