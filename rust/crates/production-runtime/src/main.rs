use agent_trust_gateway::{
    GatewayConfig, GatewayState, TrustedTenantResolver, data_plane_router,
    production_management_router,
};
use agent_trust_production_runtime::{
    ProductionAdapterSet, ProductionOrchestratorBinding, config::ProductionRuntimeConfig,
};
use std::{env, net::SocketAddr, path::Path, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let config_path = arguments
        .next()
        .ok_or("PRODUCTION_RUNTIME_CONFIG_PATH_REQUIRED")?;
    if arguments.next().is_some() {
        return Err("PRODUCTION_RUNTIME_ARGUMENTS_INVALID".into());
    }
    let config = ProductionRuntimeConfig::load(Path::new(&config_path))?;
    let adapters = Arc::new(ProductionAdapterSet::from_config(&config)?);
    let data_address: SocketAddr = config.listeners.data.parse()?;
    let management_address: SocketAddr = config.listeners.management.parse()?;
    let identity = adapters.identity.clone();
    identity.warm().await?;
    let refresh_identity = identity.clone();
    tokio::spawn(async move {
        refresh_identity.refresh_loop().await;
    });
    let state = GatewayState::new(
        GatewayConfig::default(),
        identity,
        Arc::new(TrustedTenantResolver),
        Arc::new(ProductionOrchestratorBinding::new(adapters)),
    )?;
    let management_state = state.clone();
    let management = tokio::net::TcpListener::bind(management_address).await?;
    tokio::spawn(async move {
        let _ = axum::serve(management, production_management_router(management_state)).await;
    });
    let data = tokio::net::TcpListener::bind(data_address).await?;
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
