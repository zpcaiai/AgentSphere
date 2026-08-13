//! Production-only assembly and real external-service adapters.
//!
//! This crate is intentionally a dependency-graph leaf. Domain crates own contracts and
//! fail-closed business logic; this crate owns network, TLS, credential-file and filesystem
//! bindings. Constructing the complete adapter set validates every mandatory endpoint.

pub mod adapters;
pub mod config;
pub mod http;
pub mod ops;
pub mod protocols;

use adapters::{
    ControlledModelTransport, HttpIndustrialAdapter, HttpOrchestratorAdapter,
    ProductionIdentityVerifier, ProductionModelAdapter, SecretBrokerCredentialLifecycle,
};
use agent_trust_contracts::{ActionId, TaskId, TenantId};
use agent_trust_gateway::{
    ActionView, GatewayError, InboundEnvelope, IngressResponse, OrchestratorSubmissionPort,
};
use async_trait::async_trait;
use config::{ConfigurationError, ProductionRuntimeConfig};
use futures::future::join_all;
use http::SecureHttpTransport;
use ops::{
    FilesystemEvidenceSource, HttpAuthoritativeService, HttpBackupPort, HttpContainmentPort,
    HttpEnterpriseIntegration, HttpLifecyclePropagationPort, HttpNotificationAdapter,
    HttpPolicyDistributionPort, HttpRecertificationPort, HttpRuntimeControlPort,
};
use protocols::{A2aPeerClient, HttpMcpTransport};
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
    pub policy_distribution: HttpPolicyDistributionPort,
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
            policy_distribution: HttpPolicyDistributionPort::new(endpoint("policy_distribution")?),
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
        self.runtime.orchestrator.submit(envelope).await
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
