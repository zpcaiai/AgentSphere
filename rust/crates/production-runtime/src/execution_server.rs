//! Native TLS 1.3 execution-service HTTP boundary.

use crate::execution::{
    ActiveToolRegistryPort, ApprovalGrantPort, CanonicalActionMaterializer,
    EXECUTION_READINESS_SCHEMA, ExecutionCoordinator, ExecutionError, ExecutionEvidencePort,
    ExecutionRequest, PreExecutionPepPort, ProductionToolProxyPort,
};
use agent_trust_transaction_ledger::{ExecutionLedger, LedgerError};
use axum::extract::{DefaultBodyLimit, State};
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ExecutionServerConfig {
    pub data_address: SocketAddr,
    pub management_address: SocketAddr,
    pub tls_ca_file: std::path::PathBuf,
    pub tls_certificate_file: std::path::PathBuf,
    pub tls_private_key_file: std::path::PathBuf,
    pub client_identities: BTreeSet<String>,
    pub token_bindings_file: std::path::PathBuf,
}

#[derive(Debug, Clone)]
struct PeerIdentity(String);

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenAuthorization {
    client_identity: String,
    tenant_id: String,
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
    scope: String,
    token_sha256: String,
}

#[derive(Serialize)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    schema_version: &'static str,
    error: &'a str,
}

struct AppState<M, R, A, P, T, E, L>
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    coordinator: Arc<ExecutionCoordinator<M, R, A, P, T, E, L>>,
    token_bindings: Arc<BTreeSet<TokenAuthorization>>,
}

impl<M, R, A, P, T, E, L> Clone for AppState<M, R, A, P, T, E, L>
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    fn clone(&self) -> Self {
        Self {
            coordinator: self.coordinator.clone(),
            token_bindings: self.token_bindings.clone(),
        }
    }
}

pub async fn serve<M, R, A, P, T, E, L>(
    config: ExecutionServerConfig,
    coordinator: Arc<ExecutionCoordinator<M, R, A, P, T, E, L>>,
) -> Result<(), ExecutionError>
where
    M: CanonicalActionMaterializer + 'static,
    R: ActiveToolRegistryPort + 'static,
    A: ApprovalGrantPort + 'static,
    P: PreExecutionPepPort + 'static,
    T: ProductionToolProxyPort + 'static,
    E: ExecutionEvidencePort + 'static,
    L: ExecutionLedger + 'static,
{
    validate_identities(&config.client_identities)?;
    let bindings = Arc::new(load_token_bindings(
        &config.token_bindings_file,
        &config.client_identities,
    )?);
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let state = AppState {
        coordinator,
        token_bindings: bindings,
    };
    let management = Router::new()
        .route("/ready", get(ready::<M, R, A, P, T, E, L>))
        .with_state(state.clone());
    let data = Router::new()
        .route("/ready", get(data_ready::<M, R, A, P, T, E, L>))
        .route(
            "/v1/executions/execute",
            post(execute::<M, R, A, P, T, E, L>),
        )
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(90),
        ))
        .with_state(state);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| ExecutionError::DependencyUnavailable)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| ExecutionError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| ExecutionError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn ready<M, R, A, P, T, E, L>(State(state): State<AppState<M, R, A, P, T, E, L>>) -> Response
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    readiness_response(state.coordinator.ready().await)
}

async fn data_ready<M, R, A, P, T, E, L>(
    State(state): State<AppState<M, R, A, P, T, E, L>>,
    Extension(peer): Extension<PeerIdentity>,
    headers: HeaderMap,
) -> Response
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    if !authorized(&state.token_bindings, &peer.0, None, &headers) {
        return error(StatusCode::FORBIDDEN, "EXECUTION_SCOPE_UNAUTHORIZED");
    }
    readiness_response(state.coordinator.ready().await)
}

async fn execute<M, R, A, P, T, E, L>(
    State(state): State<AppState<M, R, A, P, T, E, L>>,
    Extension(peer): Extension<PeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ExecutionRequest>,
) -> Response
where
    M: CanonicalActionMaterializer,
    R: ActiveToolRegistryPort,
    A: ApprovalGrantPort,
    P: PreExecutionPepPort,
    T: ProductionToolProxyPort,
    E: ExecutionEvidencePort,
    L: ExecutionLedger,
{
    if headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        != Some(&request.idempotency_key)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "EXECUTION_IDEMPOTENCY_HEADER_MISMATCH",
        );
    }
    if !authorized(
        &state.token_bindings,
        &peer.0,
        Some(&request.tenant_id),
        &headers,
    ) {
        return error(StatusCode::FORBIDDEN, "EXECUTION_SCOPE_UNAUTHORIZED");
    }
    match state.coordinator.execute(request).await {
        Ok(outcome) => Json(outcome).into_response(),
        Err(failure) => error(error_status(&failure), error_code(&failure)),
    }
}

fn readiness_response(ready: bool) -> Response {
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: EXECUTION_READINESS_SCHEMA,
            ready,
        }),
    )
        .into_response()
}

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            schema_version: "agenttrust.execution-error.v1",
            error: code,
        }),
    )
        .into_response()
}

fn error_status(error: &ExecutionError) -> StatusCode {
    match error {
        ExecutionError::RequestInvalid
        | ExecutionError::MaterializationInvalid
        | ExecutionError::ActionIr(_) => StatusCode::BAD_REQUEST,
        ExecutionError::AuthorizationDenied => StatusCode::FORBIDDEN,
        ExecutionError::DependencyResponseInvalid | ExecutionError::EvidenceInvalid => {
            StatusCode::BAD_GATEWAY
        }
        ExecutionError::Ledger(LedgerError::IdempotencyConflict) => StatusCode::CONFLICT,
        ExecutionError::Ledger(LedgerError::StaleFence | LedgerError::TransitionInvalid) => {
            StatusCode::CONFLICT
        }
        ExecutionError::Registry(
            agent_trust_registry::RegistryError::ToolNotFound
            | agent_trust_registry::RegistryError::VersionNotActive
            | agent_trust_registry::RegistryError::ToolRevoked
            | agent_trust_registry::RegistryError::VersionRequired,
        ) => StatusCode::FORBIDDEN,
        ExecutionError::Registry(
            agent_trust_registry::RegistryError::ArgumentInvalid
            | agent_trust_registry::RegistryError::OutputInvalid
            | agent_trust_registry::RegistryError::SchemaInvalid
            | agent_trust_registry::RegistryError::ManifestHashMismatch
            | agent_trust_registry::RegistryError::ImplementationDigestMismatch
            | agent_trust_registry::RegistryError::CompensationInvalid,
        ) => StatusCode::BAD_GATEWAY,
        ExecutionError::Configuration
        | ExecutionError::DependencyUnavailable
        | ExecutionError::Ledger(_)
        | ExecutionError::Registry(_)
        | ExecutionError::Evidence(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn error_code(error: &ExecutionError) -> &'static str {
    match error {
        ExecutionError::Configuration => "EXECUTION_CONFIGURATION_INVALID",
        ExecutionError::RequestInvalid | ExecutionError::ActionIr(_) => "EXECUTION_REQUEST_INVALID",
        ExecutionError::MaterializationInvalid => "EXECUTION_MATERIALIZATION_INVALID",
        ExecutionError::AuthorizationDenied => "EXECUTION_AUTHORIZATION_DENIED",
        ExecutionError::DependencyUnavailable => "EXECUTION_DEPENDENCY_UNAVAILABLE",
        ExecutionError::DependencyResponseInvalid => "EXECUTION_DEPENDENCY_RESPONSE_INVALID",
        ExecutionError::EvidenceInvalid | ExecutionError::Evidence(_) => {
            "EXECUTION_EVIDENCE_INVALID"
        }
        ExecutionError::Registry(
            agent_trust_registry::RegistryError::ToolNotFound
            | agent_trust_registry::RegistryError::VersionNotActive
            | agent_trust_registry::RegistryError::ToolRevoked
            | agent_trust_registry::RegistryError::VersionRequired,
        ) => "EXECUTION_TOOL_NOT_AUTHORIZED",
        ExecutionError::Registry(
            agent_trust_registry::RegistryError::ArgumentInvalid
            | agent_trust_registry::RegistryError::OutputInvalid
            | agent_trust_registry::RegistryError::SchemaInvalid
            | agent_trust_registry::RegistryError::ManifestHashMismatch
            | agent_trust_registry::RegistryError::ImplementationDigestMismatch
            | agent_trust_registry::RegistryError::CompensationInvalid,
        ) => "EXECUTION_REGISTRY_RESPONSE_INVALID",
        ExecutionError::Registry(_) => "EXECUTION_REGISTRY_UNAVAILABLE",
        ExecutionError::Ledger(LedgerError::IdempotencyConflict) => {
            "EXECUTION_IDEMPOTENCY_CONFLICT"
        }
        ExecutionError::Ledger(_) => "EXECUTION_LEDGER_UNAVAILABLE",
    }
}

fn authorized(
    bindings: &BTreeSet<TokenAuthorization>,
    identity: &str,
    tenant: Option<&str>,
    headers: &HeaderMap,
) -> bool {
    let Some(token) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    if token.is_empty() || token.len() > 8_192 || token.contains(char::is_whitespace) {
        return false;
    }
    let supplied = format!("{:x}", Sha256::digest(token.as_bytes()));
    let mut accepted = false;
    for binding in bindings {
        let digest_matches = constant_time_digest_matches(&supplied, &binding.token_sha256);
        let tuple_matches = binding.client_identity == identity
            && binding.scope == "executions:execute"
            && tenant.is_none_or(|expected| binding.tenant_id == expected);
        accepted |= tuple_matches && digest_matches;
    }
    accepted
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-execution-token-comparison-v1",
    );
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), ExecutionError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(ExecutionError::Configuration);
    }
    Ok(())
}

fn load_token_bindings(
    path: &Path,
    identities: &BTreeSet<String>,
) -> Result<BTreeSet<TokenAuthorization>, ExecutionError> {
    let raw = std::fs::read(path).map_err(|_| ExecutionError::Configuration)?;
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err(ExecutionError::Configuration);
    }
    let document: TokenBindingDocument =
        serde_json::from_slice(&raw).map_err(|_| ExecutionError::Configuration)?;
    if document.schema_version != "agenttrust.execution-token-bindings.v1"
        || document.bindings.is_empty()
    {
        return Err(ExecutionError::Configuration);
    }
    let mut result = BTreeSet::new();
    for binding in document.bindings {
        if binding.scope != "executions:execute"
            || !identities.contains(&binding.client_identity)
            || Uuid::parse_str(&binding.tenant_id).is_err()
            || !digest(&binding.token_sha256)
            || !result.insert(TokenAuthorization {
                client_identity: binding.client_identity,
                tenant_id: binding.tenant_id,
                scope: binding.scope,
                token_sha256: binding.token_sha256,
            })
        {
            return Err(ExecutionError::Configuration);
        }
    }
    if identities.iter().any(|identity| {
        !result
            .iter()
            .any(|binding| &binding.client_identity == identity)
    }) {
        return Err(ExecutionError::Configuration);
    }
    Ok(result)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, ExecutionError> {
    let mut ca_reader =
        BufReader::new(File::open(ca_file).map_err(|_| ExecutionError::Configuration)?);
    let roots_der = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ExecutionError::Configuration)?;
    if roots_der.is_empty() {
        return Err(ExecutionError::Configuration);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(roots_der);
    if accepted == 0 {
        return Err(ExecutionError::Configuration);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| ExecutionError::Configuration)?;
    let mut certificate_reader =
        BufReader::new(File::open(certificate_file).map_err(|_| ExecutionError::Configuration)?);
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ExecutionError::Configuration)?;
    if certificates.is_empty() {
        return Err(ExecutionError::Configuration);
    }
    let mut key_reader =
        BufReader::new(File::open(private_key_file).map_err(|_| ExecutionError::Configuration)?);
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| ExecutionError::Configuration)?
        .ok_or(ExecutionError::Configuration)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ExecutionError::Configuration)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| ExecutionError::Configuration)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, PeerIdentity>;
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
            Ok((stream, Extension(PeerIdentity(identity)).layer(service)))
        })
    }
}

fn io_denied(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn matching_certificate_identity(certificate: &[u8], allowed: &BTreeSet<String>) -> Option<String> {
    let mut identities = certificate_subject_alt_names(certificate).ok()?.into_iter();
    let identity = identities.next()?;
    if identities.next().is_some() || !allowed.contains(&identity) {
        return None;
    }
    Some(identity)
}

/// Ensures the certificate used for outbound authority calls carries exactly the configured
/// DNS/URI SAN. Evidence binds `source_service` to this value, so a configuration-only alias is
/// never allowed to stand in for certificate identity.
pub fn validate_certificate_identity_file(
    certificate_file: &Path,
    expected_identity: &str,
) -> Result<(), ExecutionError> {
    let expected = BTreeSet::from([expected_identity.to_string()]);
    validate_identities(&expected)?;
    let mut reader =
        BufReader::new(File::open(certificate_file).map_err(|_| ExecutionError::Configuration)?);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ExecutionError::Configuration)?;
    let leaf = certificates.first().ok_or(ExecutionError::Configuration)?;
    if matching_certificate_identity(leaf.as_ref(), &expected).as_deref() != Some(expected_identity)
    {
        return Err(ExecutionError::Configuration);
    }
    Ok(())
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
        let prefix = match tag {
            0x82 => "DNS:",
            0x86 => "URI:",
            _ => return Err(()),
        };
        let value = std::str::from_utf8(value).map_err(|_| ())?;
        if value.is_empty() || value.len() > 508 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_digest_comparison_is_exact() {
        assert!(constant_time_digest_matches(
            &"a".repeat(64),
            &"a".repeat(64)
        ));
        assert!(!constant_time_digest_matches(
            &"a".repeat(63),
            &"a".repeat(64)
        ));
    }

    #[test]
    fn identity_configuration_rejects_common_names() {
        assert!(validate_identities(&["URI:spiffe://worker".into()].into_iter().collect()).is_ok());
        assert!(validate_identities(&["CN:worker".into()].into_iter().collect()).is_err());
    }
}
