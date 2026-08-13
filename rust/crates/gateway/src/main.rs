use agent_trust_contracts::{ActionId, AgentInstanceId, TaskId, TenantId};
use agent_trust_gateway::{
    ActionView, GatewayConfig, GatewayError, GatewayState, IdentityContext, IdentityVerifierPort,
    InboundEnvelope, IngressResponse, OrchestratorSubmissionPort, RequestParts,
    TrustedTenantResolver, data_plane_router, management_router,
};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};

struct ExplicitDevVerifier;
#[async_trait]
impl IdentityVerifierPort for ExplicitDevVerifier {
    async fn verify(&self, request: &RequestParts) -> Result<IdentityContext, GatewayError> {
        let subject = request
            .headers
            .get("x-dev-subject")
            .and_then(|value| value.to_str().ok())
            .ok_or(GatewayError::Unauthenticated)?;
        let tenant = request
            .headers
            .get("x-dev-tenant")
            .and_then(|value| value.to_str().ok())
            .ok_or(GatewayError::Unauthenticated)?;
        let agent = request
            .headers
            .get("x-dev-agent")
            .and_then(|value| value.to_str().ok())
            .ok_or(GatewayError::Unauthenticated)?;
        Ok(IdentityContext {
            subject: subject.into(),
            tenant_id: TenantId::parse(tenant.to_string())
                .map_err(|_| GatewayError::Unauthenticated)?,
            agent_instance_id: AgentInstanceId::parse(agent.to_string())
                .map_err(|_| GatewayError::Unauthenticated)?,
            owner_subject: subject.into(),
            trust_level: "development".into(),
        })
    }
    fn production_ready(&self) -> bool {
        false
    }
}

/// Explicit fail-closed adapter used only by the development binary. A
/// production assembly must inject the Batch 29 implementation through the
/// library port and therefore can never become ready with this adapter.
struct RejectAllOrchestrator;
#[async_trait]
impl OrchestratorSubmissionPort for RejectAllOrchestrator {
    async fn submit(&self, _: InboundEnvelope) -> Result<IngressResponse, GatewayError> {
        Err(GatewayError::DownstreamUnavailable)
    }
    async fn get(&self, _: &TenantId, _: &str, _: &ActionId) -> Result<ActionView, GatewayError> {
        Err(GatewayError::NotFoundOrForbidden)
    }
    async fn cancel(&self, _: &TenantId, _: &str, _: &ActionId) -> Result<(), GatewayError> {
        Err(GatewayError::DownstreamUnavailable)
    }
    async fn kill(&self, _: &TenantId, _: &str, _: &ActionId) -> Result<(), GatewayError> {
        Err(GatewayError::DownstreamUnavailable)
    }
    async fn stream_snapshot(
        &self,
        _: &TenantId,
        _: &str,
        _: &TaskId,
    ) -> Result<Vec<String>, GatewayError> {
        Err(GatewayError::DownstreamUnavailable)
    }
    async fn ready(&self) -> bool {
        false
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = std::env::var("AGENTTRUST_PROFILE").unwrap_or_else(|_| "production".into());
    if profile != "development"
        || std::env::var("AGENTTRUST_ENABLE_DEV_VERIFIER").as_deref() != Ok("true")
    {
        return Err(
            "GATEWAY_PRODUCTION_IDENTITY_NOT_CONFIGURED: install Batch 04 production verifier"
                .into(),
        );
    }
    let config = GatewayConfig {
        production: false,
        ..GatewayConfig::default()
    };
    let state = GatewayState::new(
        config,
        Arc::new(ExplicitDevVerifier),
        Arc::new(TrustedTenantResolver),
        Arc::new(RejectAllOrchestrator),
    )?;
    let data_addr: SocketAddr = std::env::var("AGENTTRUST_DATA_LISTENER")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let management_addr: SocketAddr = std::env::var("AGENTTRUST_MANAGEMENT_LISTENER")
        .unwrap_or_else(|_| "127.0.0.1:9090".into())
        .parse()?;
    let management = tokio::net::TcpListener::bind(management_addr).await?;
    tokio::spawn(async move {
        let _ = axum::serve(management, management_router()).await;
    });
    let data = tokio::net::TcpListener::bind(data_addr).await?;
    axum::serve(data, data_plane_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}
