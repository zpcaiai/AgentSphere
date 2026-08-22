//! TLS 1.3/mTLS HTTP boundary for the production Tool Proxy.

use super::production::{
    HttpsRegistryClient, ProductionExecutionOutcome, ProductionProxyError,
    ProductionToolProxyService, TOOL_PROXY_READINESS_SCHEMA_VERSION,
};
use super::*;
use axum::extract::rejection::JsonRejection;
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
use std::collections::BTreeSet;
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tower::Layer;

const TOKEN_BINDING_SCHEMA: &str = "agenttrust.tool-proxy-token-bindings.v1";
const MAX_CONCURRENT_EXECUTIONS: usize = 256;

#[derive(Debug, Clone)]
pub struct ToolProxyServerConfig {
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
pub struct TokenBindingToolProxyAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
    tenants: BTreeSet<TenantId>,
}

#[derive(Clone)]
struct RequestContext {
    tenant_id: TenantId,
    #[allow(dead_code)]
    subject: String,
}

impl TokenBindingToolProxyAuthorizer {
    pub fn from_file(
        path: &Path,
        identities: &BTreeSet<String>,
    ) -> Result<Self, ProductionProxyError> {
        validate_identities(identities)?;
        let raw = std::fs::read(path).map_err(|_| ProductionProxyError::RegistryTrustInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ProductionProxyError::RegistryTrustInvalid);
        }
        let document: TokenBindingDocument =
            serde_json::from_slice(&raw).map_err(|_| ProductionProxyError::RegistryTrustInvalid)?;
        if document.schema_version != TOKEN_BINDING_SCHEMA
            || document.bindings.is_empty()
            || document.bindings.len() > 10_000
        {
            return Err(ProductionProxyError::RegistryTrustInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut security_tuples = BTreeSet::new();
        let mut tenants = BTreeSet::new();
        for binding in document.bindings {
            let tenant = Uuid::parse_str(&binding.tenant_id)
                .ok()
                .filter(|value| value.to_string() == binding.tenant_id)
                .map(|value| TenantId(value.to_string()))
                .ok_or(ProductionProxyError::RegistryTrustInvalid)?;
            if !identities.contains(&binding.client_identity)
                || binding.scope != "tools:execute"
                || !valid_subject(&binding.subject)
                || !lower_digest(&binding.token_sha256)
                || !security_tuples.insert((
                    binding.client_identity.clone(),
                    binding.tenant_id.clone(),
                    binding.token_sha256.clone(),
                ))
                || !bindings.insert(TokenAuthorization {
                    client_identity: binding.client_identity,
                    tenant_id: binding.tenant_id,
                    subject: binding.subject,
                    scope: binding.scope,
                    token_sha256: binding.token_sha256,
                })
            {
                return Err(ProductionProxyError::RegistryTrustInvalid);
            }
            tenants.insert(tenant);
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(ProductionProxyError::RegistryTrustInvalid);
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
    ) -> Result<RequestContext, ProductionProxyError> {
        let tenant = single_header(headers, "x-agenttrust-tenant-id")
            .and_then(|value| {
                Uuid::parse_str(value)
                    .ok()
                    .filter(|id| id.to_string() == value)
            })
            .map(|value| value.to_string())
            .ok_or(ProductionProxyError::RegistryTrustInvalid)?;
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
            })
            .ok_or(ProductionProxyError::RegistryTrustInvalid)?;
        let supplied = hex_string(Sha256::digest(token.as_bytes()));
        let mut result = None;
        for binding in &self.bindings {
            let tuple_matches = binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && binding.scope == "tools:execute";
            if tuple_matches && constant_time_digest_matches(&supplied, &binding.token_sha256) {
                if result.is_some() {
                    return Err(ProductionProxyError::RegistryTrustInvalid);
                }
                result = Some(RequestContext {
                    tenant_id: TenantId(tenant.clone()),
                    subject: binding.subject.clone(),
                });
            }
        }
        result.ok_or(ProductionProxyError::RegistryTrustInvalid)
    }
}

#[derive(Clone)]
struct ApiState {
    service: Arc<ProductionToolProxyService<HttpsRegistryClient>>,
    authorizer: Arc<TokenBindingToolProxyAuthorizer>,
    capacity: Arc<Semaphore>,
}

#[derive(Clone)]
struct ReadinessState {
    service: Arc<ProductionToolProxyService<HttpsRegistryClient>>,
    registry: Arc<HttpsRegistryClient>,
    credentials: Arc<dyn WorkloadCredentialConsumptionPort>,
    authorization: Arc<ProxyAuthorizationVerifier>,
    tenants: Arc<BTreeSet<TenantId>>,
}

#[derive(Clone, Debug)]
struct ToolProxyPeerIdentity(String);

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    schema_version: &'static str,
    error: String,
}

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

pub struct ToolProxyServerDependencies {
    pub service: Arc<ProductionToolProxyService<HttpsRegistryClient>>,
    pub registry: Arc<HttpsRegistryClient>,
    pub credentials: Arc<dyn WorkloadCredentialConsumptionPort>,
    pub authorization: Arc<ProxyAuthorizationVerifier>,
    pub authorizer: Arc<TokenBindingToolProxyAuthorizer>,
}

pub async fn serve(
    config: ToolProxyServerConfig,
    dependencies: ToolProxyServerDependencies,
) -> Result<(), ProductionProxyError> {
    validate_identities(&config.client_identities)?;
    if dependencies.authorizer.tenants().is_empty() {
        return Err(ProductionProxyError::RegistryTrustInvalid);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let readiness = ReadinessState {
        service: dependencies.service.clone(),
        registry: dependencies.registry,
        credentials: dependencies.credentials,
        authorization: dependencies.authorization,
        tenants: Arc::new(dependencies.authorizer.tenants().clone()),
    };
    let recovery_store = readiness.service.store().clone();
    let recovery_tenants = readiness.tenants.clone();
    let recovery_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let _ = recovery_store
                .recover_expired_executing(&recovery_tenants)
                .await;
        }
    });
    let data = Router::new()
        .route("/ready", get(data_ready))
        .route("/v1/tools/execute", post(execute))
        .with_state(ApiState {
            service: dependencies.service,
            authorizer: dependencies.authorizer,
            capacity: Arc::new(Semaphore::new(MAX_CONCURRENT_EXECUTIONS)),
        })
        .layer(Extension(readiness.clone()))
        .layer(DefaultBodyLimit::max(1_048_576));
    let management = Router::new()
        .route("/ready", get(management_ready))
        .with_state(readiness);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)
    };
    let result = tokio::try_join!(data_plane, management_plane).map(|_| ());
    recovery_task.abort();
    result
}

async fn execute(
    State(state): State<ApiState>,
    Extension(peer): Extension<ToolProxyPeerIdentity>,
    headers: HeaderMap,
    payload: Result<Json<AuthorizedToolRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(request) => request,
        Err(rejection) => {
            let too_large = rejection.status() == StatusCode::PAYLOAD_TOO_LARGE;
            return (
                if too_large {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                },
                Json(ErrorResponse {
                    schema_version: PROXY_SCHEMA_VERSION,
                    error: if too_large {
                        "PROXY_REQUEST_TOO_LARGE".into()
                    } else {
                        "PROXY_REQUEST_INVALID".into()
                    },
                }),
            )
                .into_response();
        }
    };
    let result = async {
        let _permit = state
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| ProductionProxyError::Dependency("overloaded".into()))?;
        let context = state.authorizer.authorize(&peer.0, &headers)?;
        let header_idempotency = required_idempotency(&headers)?;
        if context.tenant_id != request.tenant_id || header_idempotency != request.idempotency_key {
            return Err(ProductionProxyError::RegistryTrustInvalid);
        }
        tokio::time::timeout(Duration::from_secs(960), state.service.execute(request))
            .await
            .map_err(|_| ProductionProxyError::Dependency("timeout".into()))?
    }
    .await;
    match result {
        Ok(ProductionExecutionOutcome::Succeeded(result)) => {
            (StatusCode::OK, Json(result)).into_response()
        }
        Ok(ProductionExecutionOutcome::Failed(code)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                schema_version: PROXY_SCHEMA_VERSION,
                error: code,
            }),
        )
            .into_response(),
        Ok(ProductionExecutionOutcome::Unknown) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                schema_version: PROXY_SCHEMA_VERSION,
                error: "PROXY_EXECUTION_UNKNOWN".into(),
            }),
        )
            .into_response(),
        Err(error) => error_response(error),
    }
}

async fn management_ready(State(state): State<ReadinessState>) -> Response {
    readiness_response(&state).await
}

async fn data_ready(
    Extension(state): Extension<ReadinessState>,
    Extension(_peer): Extension<ToolProxyPeerIdentity>,
) -> Response {
    readiness_response(&state).await
}

async fn readiness_response(state: &ReadinessState) -> Response {
    let ready = if state.authorization.ready() {
        let (store, registry, credentials) = tokio::join!(
            state.service.store().ready(&state.tenants),
            state.registry.ready(&state.tenants),
            state.credentials.ready(),
        );
        store && registry && credentials
    } else {
        false
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: TOOL_PROXY_READINESS_SCHEMA_VERSION,
            ready,
        }),
    )
        .into_response()
}

fn error_response(error: ProductionProxyError) -> Response {
    let status = match error {
        ProductionProxyError::IdempotencyConflict | ProductionProxyError::StateConflict => {
            StatusCode::CONFLICT
        }
        ProductionProxyError::RegistryTrustInvalid => StatusCode::FORBIDDEN,
        ProductionProxyError::StoreUnavailable | ProductionProxyError::Dependency(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    (
        status,
        Json(ErrorResponse {
            schema_version: PROXY_SCHEMA_VERSION,
            error: error.to_string(),
        }),
    )
        .into_response()
}

fn required_idempotency(headers: &HeaderMap) -> Result<IdempotencyKey, ProductionProxyError> {
    single_header(headers, "idempotency-key")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        })
        .map(|value| IdempotencyKey(value.into()))
        .ok_or(ProductionProxyError::IdempotencyConflict)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-tool-proxy-token-v1");
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), ProductionProxyError> {
    if identities.is_empty()
        || identities.len() > 4_096
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || !identity.bytes().all(|byte| byte.is_ascii_graphic())
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(ProductionProxyError::RegistryTrustInvalid);
    }
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, ProductionProxyError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| ProductionProxyError::RegistryTrustInvalid)?,
    );
    let roots_der = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ProductionProxyError::RegistryTrustInvalid)?;
    if roots_der.is_empty() {
        return Err(ProductionProxyError::RegistryTrustInvalid);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(roots_der);
    if accepted == 0 {
        return Err(ProductionProxyError::RegistryTrustInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| ProductionProxyError::RegistryTrustInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| ProductionProxyError::RegistryTrustInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| ProductionProxyError::RegistryTrustInvalid)?;
    if certificates.is_empty() {
        return Err(ProductionProxyError::RegistryTrustInvalid);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| ProductionProxyError::RegistryTrustInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| ProductionProxyError::RegistryTrustInvalid)?
        .ok_or(ProductionProxyError::RegistryTrustInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ProductionProxyError::RegistryTrustInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| ProductionProxyError::RegistryTrustInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, ToolProxyPeerIdentity>;
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
                Extension(ToolProxyPeerIdentity(identity)).layer(service),
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

// Minimal fail-closed DER parser for the single DNS/URI SAN rule. It accepts no
// alternative identity source (CN is deliberately ignored).
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
    let san = san.ok_or(())?;
    let (tag, names, end) = der_element(san, 0)?;
    if tag != 0x30 || end != san.len() {
        return Err(());
    }
    let mut names_offset = 0;
    let mut identities = Vec::new();
    while names_offset < names.len() {
        let (tag, value, next) = der_element(names, names_offset)?;
        names_offset = next;
        let prefix = match tag {
            0x82 => "DNS:",
            0x86 => "URI:",
            _ => return Err(()),
        };
        let value = std::str::from_utf8(value).map_err(|_| ())?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(());
        }
        identities.push(format!("{prefix}{value}"));
    }
    Ok(identities)
}

fn der_element(input: &[u8], offset: usize) -> Result<(u8, &[u8], usize), ()> {
    let tag = *input.get(offset).ok_or(())?;
    let first = *input.get(offset + 1).ok_or(())?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(());
        }
        let mut length = 0_usize;
        for index in 0..count {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*input.get(offset + 2 + index)?)))
                .ok_or(())?;
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
    fn duplicate_headers_and_weak_bindings_fail_closed() {
        let mut headers = HeaderMap::new();
        headers.append(
            "Idempotency-Key",
            "one".parse().unwrap_or_else(|_| panic!("header")),
        );
        headers.append(
            "Idempotency-Key",
            "two".parse().unwrap_or_else(|_| panic!("header")),
        );
        assert!(required_idempotency(&headers).is_err());
        assert!(!lower_digest(&"A".repeat(64)));
        assert!(!valid_subject("bad subject"));
    }
}
