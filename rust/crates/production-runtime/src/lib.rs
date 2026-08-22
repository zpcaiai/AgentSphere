//! Production-only assembly and real external-service adapters.
//!
//! This crate is intentionally a dependency-graph leaf. Domain crates own contracts and
//! fail-closed business logic; this crate owns network, TLS, credential-file and filesystem
//! bindings. Constructing the complete adapter set validates every mandatory endpoint.

pub mod adapters;
pub mod config;
pub mod execution;
pub mod execution_server;
pub mod http;
pub mod ops;
pub mod protocols;

use adapters::{
    ControlledModelTransport, HttpIndustrialAdapter, HttpOrchestratorAdapter,
    ProductionIdentityVerifier, ProductionModelAdapter, SecretBrokerCredentialLifecycle,
};
use agent_trust_action_ir::{NormalizationContext, ParseLimits, normalize, parse_draft};
use agent_trust_contracts::{ActionId, TaskId, TenantId};
use agent_trust_gateway::{
    ActionView, GatewayError, InboundEnvelope, IngressResponse, OrchestratorSubmissionPort,
};
use async_trait::async_trait;
use chrono::Duration;
use config::{ConfigurationError, ProductionRuntimeConfig};
use futures::future::join_all;
use http::SecureHttpTransport;
use ops::{
    FilesystemEvidenceSource, HttpAuthoritativeService, HttpBackupPort, HttpContainmentPort,
    HttpEnterpriseIntegration, HttpLifecyclePropagationPort, HttpNotificationAdapter,
    HttpRecertificationPort, HttpRuntimeControlPort,
};
use protocols::{A2aPeerClient, HttpMcpTransport};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct ProductionAdapterSet {
    pub identity: Arc<ProductionIdentityVerifier>,
    pub orchestrator: Arc<HttpOrchestratorAdapter>,
    pub model_transport: ControlledModelTransport,
    pub model_adapters: BTreeMap<String, ProductionModelAdapter>,
    pub secret_broker: SecretBrokerCredentialLifecycle,
    pub industrial: HttpIndustrialAdapter,
    pub backup: HttpBackupPort,
    pub containment: HttpContainmentPort,
    pub recertification: HttpRecertificationPort,
    pub enterprise_integration: HttpEnterpriseIntegration,
    pub authority: HttpAuthoritativeService,
    pub notification: HttpNotificationAdapter,
    pub runtime_control: HttpRuntimeControlPort,
    pub lifecycle: HttpLifecyclePropagationPort,
    pub evidence: FilesystemEvidenceSource,
    pub mcp: HttpMcpTransport,
    pub a2a: A2aPeerClient,
    health: BTreeMap<String, (SecureHttpTransport, String)>,
}

impl ProductionAdapterSet {
    pub fn from_config(config: &ProductionRuntimeConfig) -> Result<Self, ConfigurationError> {
        config.validate()?;
        let endpoint = |name: &str| -> Result<SecureHttpTransport, ConfigurationError> {
            SecureHttpTransport::new(
                config
                    .endpoints
                    .get(name)
                    .ok_or(ConfigurationError::Invalid)?,
            )
            .map_err(|_| ConfigurationError::Invalid)
        };
        let mut models = BTreeMap::new();
        let mut model_adapters = BTreeMap::new();
        let mut mcp = BTreeMap::new();
        let mut a2a = BTreeMap::new();
        for (name, value) in &config.endpoints {
            if let Some(profile) = name.strip_prefix("model:") {
                if profile.is_empty() {
                    return Err(ConfigurationError::Invalid);
                }
                let transport =
                    SecureHttpTransport::new(value).map_err(|_| ConfigurationError::Invalid)?;
                models.insert(profile.to_string(), transport.clone());
                let model = config
                    .model_versions
                    .get(profile)
                    .ok_or(ConfigurationError::Invalid)?;
                model_adapters.insert(
                    profile.to_string(),
                    ProductionModelAdapter::new(profile.to_string(), model.clone(), transport)
                        .map_err(|_| ConfigurationError::Invalid)?,
                );
            }
            if let Some(server) = name.strip_prefix("mcp:") {
                if server.is_empty() {
                    return Err(ConfigurationError::Invalid);
                }
                mcp.insert(
                    server.to_string(),
                    SecureHttpTransport::new(value).map_err(|_| ConfigurationError::Invalid)?,
                );
            }
            if let Some(peer) = name.strip_prefix("a2a:") {
                if peer.is_empty() {
                    return Err(ConfigurationError::Invalid);
                }
                a2a.insert(
                    peer.to_string(),
                    SecureHttpTransport::new(value).map_err(|_| ConfigurationError::Invalid)?,
                );
            }
        }
        let health = config
            .endpoints
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.clone(),
                    (
                        SecureHttpTransport::new(value).map_err(|_| ConfigurationError::Invalid)?,
                        value
                            .health_path
                            .clone()
                            .ok_or(ConfigurationError::Invalid)?,
                    ),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ConfigurationError>>()?;
        Ok(Self {
            identity: Arc::new(
                ProductionIdentityVerifier::new(&config.identity)
                    .map_err(|_| ConfigurationError::Invalid)?,
            ),
            orchestrator: Arc::new(HttpOrchestratorAdapter::new(endpoint("orchestrator")?)),
            model_transport: ControlledModelTransport::new(models)
                .map_err(|_| ConfigurationError::Invalid)?,
            model_adapters,
            secret_broker: SecretBrokerCredentialLifecycle::new(endpoint("secret_broker")?),
            industrial: HttpIndustrialAdapter::new(endpoint("industrial")?),
            backup: HttpBackupPort::new(endpoint("backup")?),
            containment: HttpContainmentPort::new(endpoint("containment")?),
            recertification: HttpRecertificationPort::new(endpoint("recertification")?),
            enterprise_integration: HttpEnterpriseIntegration::new(endpoint(
                "enterprise_integration",
            )?),
            authority: HttpAuthoritativeService::new(
                endpoint("authority")?,
                "control-plane".into(),
            )
            .map_err(|_| ConfigurationError::Invalid)?,
            notification: HttpNotificationAdapter::new(endpoint("notification")?),
            runtime_control: HttpRuntimeControlPort::new(endpoint("runtime_control")?),
            lifecycle: HttpLifecyclePropagationPort::new(endpoint("lifecycle")?),
            evidence: FilesystemEvidenceSource::new(config.evidence_files.clone()),
            mcp: HttpMcpTransport::new(mcp).map_err(|_| ConfigurationError::Invalid)?,
            a2a: A2aPeerClient::new(a2a).map_err(|_| ConfigurationError::Invalid)?,
            health,
        })
    }
}

/// Keeps every production adapter alive and makes Gateway readiness depend on all
/// configured external bindings, while delegating action operations only to the
/// durable orchestrator.
pub struct ProductionOrchestratorBinding {
    runtime: Arc<ProductionAdapterSet>,
}
impl ProductionOrchestratorBinding {
    pub fn new(runtime: Arc<ProductionAdapterSet>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl OrchestratorSubmissionPort for ProductionOrchestratorBinding {
    async fn submit(&self, envelope: InboundEnvelope) -> Result<IngressResponse, GatewayError> {
        self.runtime
            .orchestrator
            .submit(canonicalize_production_action(envelope)?)
            .await
    }
    async fn get(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &ActionId,
    ) -> Result<ActionView, GatewayError> {
        self.runtime.orchestrator.get(tenant, owner, action).await
    }
    async fn cancel(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &ActionId,
    ) -> Result<(), GatewayError> {
        self.runtime
            .orchestrator
            .cancel(tenant, owner, action)
            .await
    }
    async fn kill(
        &self,
        tenant: &TenantId,
        owner: &str,
        action: &ActionId,
    ) -> Result<(), GatewayError> {
        self.runtime.orchestrator.kill(tenant, owner, action).await
    }
    async fn stream_snapshot(
        &self,
        tenant: &TenantId,
        owner: &str,
        task: &TaskId,
    ) -> Result<Vec<String>, GatewayError> {
        self.runtime
            .orchestrator
            .stream_snapshot(tenant, owner, task)
            .await
    }
    async fn ready(&self) -> bool {
        if !self.runtime.orchestrator.ready().await {
            return false;
        }
        join_all(
            self.runtime
                .health
                .values()
                .map(|(transport, path)| transport.get_bytes(path)),
        )
        .await
        .into_iter()
        .all(|result| result.is_ok())
    }
}

/// Converts the untrusted ingress body into the single canonical Action IR representation and
/// binds every identity field available at the gateway boundary before any durable admission.
/// The orchestrator receives JCS bytes and a hash of those exact bytes, never caller formatting.
fn canonicalize_production_action(
    mut envelope: InboundEnvelope,
) -> Result<InboundEnvelope, GatewayError> {
    if envelope.content_type.split(';').next().map(str::trim) != Some("application/json") {
        return Err(GatewayError::Forbidden);
    }
    let draft = parse_draft(&envelope.payload, &ParseLimits::default())
        .map_err(|_| GatewayError::Forbidden)?;
    let action =
        normalize(draft, &NormalizationContext::default()).map_err(|_| GatewayError::Forbidden)?;
    let identity = &envelope.identity_context;
    let tenant = &envelope.tenant_context.tenant_id;
    let received_at = envelope.received_at;
    if &identity.tenant_id != tenant
        || action.agent.tenant_id != *tenant
        || action.resource.tenant_id != *tenant
        || action.environment.tenant_id != *tenant
        || action.agent.agent_instance_id != identity.agent_instance_id
        || action.agent.owner_subject != identity.owner_subject
        || action.agent.trust_level != identity.trust_level
        || !action
            .environment
            .deployment
            .eq_ignore_ascii_case("production")
        || action.environment.simulation
        || !action
            .agent
            .deployment_environment
            .eq_ignore_ascii_case("production")
        || action.agent.issued_at > received_at + Duration::minutes(5)
        || action.agent.expires_at <= received_at
        || action.requested_at > received_at + Duration::minutes(5)
    {
        return Err(GatewayError::Forbidden);
    }
    let canonical = serde_jcs::to_vec(&action).map_err(|_| GatewayError::Forbidden)?;
    envelope.payload_hash = format!("{:x}", Sha256::digest(&canonical));
    envelope.payload = canonical;
    Ok(envelope)
}

#[cfg(test)]
mod production_action_tests {
    use super::*;
    use agent_trust_action_ir::{ACTION_SCHEMA_VERSION, ActionDraft, TypedPayload};
    use agent_trust_contracts::{
        AgentIdentity, AgentInstanceId, DataClassification, DataContext, ExecutionEnvironment,
        ExpectedOutcome, Intent, ResourceSelector, RiskContext, RiskLevel, SchemaVersion, StepId,
        StrictJsonObject, ToolId, ToolRef, ToolVersion,
    };
    use agent_trust_gateway::{IdentityContext, IngressProtocol, TenantContext, TraceContext};
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn envelope() -> InboundEnvelope {
        let now = Utc::now();
        let tenant = TenantId::new();
        let agent = AgentInstanceId::new();
        let action = ActionDraft {
            schema_version: SchemaVersion(ACTION_SCHEMA_VERSION.into()),
            action_id: ActionId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            agent: AgentIdentity {
                schema_version: SchemaVersion(
                    agent_trust_contracts::CONTRACT_SCHEMA_VERSION.into(),
                ),
                agent_type: "coding".into(),
                agent_instance_id: agent.clone(),
                organization_id: "org-1".into(),
                tenant_id: tenant.clone(),
                owner_subject: "user:1".into(),
                model_provider: "approved".into(),
                model_id: "model-v1".into(),
                agent_version: "1.0.0".into(),
                deployment_environment: "production".into(),
                trust_level: "verified".into(),
                auth_context_ref: "auth:1".into(),
                issued_at: now - Duration::minutes(1),
                expires_at: now + Duration::hours(1),
            },
            intent: Intent {
                goal_hash: "g".repeat(64),
                operation: " read ".into(),
                justification_code: "user_request".into(),
                safe_summary: Some("inspect repository".into()),
            },
            tool: ToolRef {
                tool_id: ToolId("coding.repo-read".into()),
                tool_version: ToolVersion("1.0.0".into()),
            },
            payload: TypedPayload {
                type_id: "coding.command.v1".into(),
                schema_version: "1".into(),
                data: StrictJsonObject::from_iter([(
                    "path".into(),
                    Value::String("src/./main".into()),
                )]),
            },
            resource: ResourceSelector {
                scheme: "repo".into(),
                tenant_id: tenant.clone(),
                locator: "org/repository".into(),
                version: None,
            },
            environment: ExecutionEnvironment {
                tenant_id: tenant.clone(),
                deployment: "production".into(),
                region: "cn-north-1".into(),
                zone: Some("cn-north-1a".into()),
                simulation: false,
            },
            current_state_version: None,
            risk: RiskContext {
                declared_risk: RiskLevel::Low,
                trajectory_risk_ref: None,
                scope_delta: 0,
                automation_allowed: true,
            },
            data: DataContext {
                classification: DataClassification::Internal,
                jurisdiction: "CN".into(),
                export_constraints: Vec::new(),
            },
            expected_outcome: ExpectedOutcome {
                metric: "records".into(),
                operator: "gte".into(),
                target: Value::from(0),
            },
            credential_refs: Vec::new(),
            requested_at: now,
            extensions: BTreeMap::new(),
        };
        let payload = serde_json::to_vec_pretty(&action)
            .unwrap_or_else(|error| panic!("serialize action: {error}"));
        InboundEnvelope {
            request_id: "request-1".into(),
            trace_context: TraceContext {
                trace_id: "0".repeat(32),
                parent_span_id: None,
                invalid_input_replaced: false,
            },
            identity_context: IdentityContext {
                subject: "workload:1".into(),
                tenant_id: tenant.clone(),
                agent_instance_id: agent,
                owner_subject: "user:1".into(),
                trust_level: "verified".into(),
            },
            tenant_context: TenantContext {
                tenant_id: tenant,
                quota_profile: "default".into(),
            },
            protocol: IngressProtocol::Http,
            content_type: "application/json; charset=utf-8".into(),
            schema_version: agent_trust_gateway::GATEWAY_SCHEMA_VERSION.into(),
            idempotency_key: Some("idempotency-0001".into()),
            received_at: now,
            payload_hash: format!("{:x}", Sha256::digest(&payload)),
            payload,
        }
    }

    #[test]
    fn production_ingress_normalizes_and_hashes_exact_canonical_action() {
        let original = envelope();
        let original_hash = original.payload_hash.clone();
        let normalized = canonicalize_production_action(original)
            .unwrap_or_else(|error| panic!("canonical action: {error}"));
        assert_ne!(normalized.payload_hash, original_hash);
        assert_eq!(
            normalized.payload_hash,
            format!("{:x}", Sha256::digest(&normalized.payload))
        );
        let value: serde_json::Value = serde_json::from_slice(&normalized.payload)
            .unwrap_or_else(|error| panic!("canonical JSON: {error}"));
        assert_eq!(value["intent"]["operation"], "read");
        assert_eq!(value["intent"]["justification_code"], "USER_REQUEST");
    }

    #[test]
    fn production_ingress_rejects_identity_and_environment_mismatch() {
        let mut wrong_tenant = envelope();
        wrong_tenant.identity_context.tenant_id = TenantId::new();
        assert!(matches!(
            canonicalize_production_action(wrong_tenant),
            Err(GatewayError::Forbidden)
        ));
        let mut simulation = envelope();
        let mut value: serde_json::Value = serde_json::from_slice(&simulation.payload)
            .unwrap_or_else(|error| panic!("action JSON: {error}"));
        value["environment"]["simulation"] = Value::Bool(true);
        simulation.payload =
            serde_json::to_vec(&value).unwrap_or_else(|error| panic!("action JSON: {error}"));
        assert!(matches!(
            canonicalize_production_action(simulation),
            Err(GatewayError::Forbidden)
        ));
    }
}
