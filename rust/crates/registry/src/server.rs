//! Native TLS 1.3 and mTLS boundary for the production Registry service.

use super::*;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::AddExtension;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const REGISTRY_READINESS_SCHEMA: &str = "agenttrust.registry-readiness.v1";

#[derive(Debug, Clone)]
pub struct RegistryServerConfig {
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

pub struct TokenBindingRegistryAuthorizer {
    bindings: BTreeSet<TokenAuthorization>,
    tenants: BTreeSet<TenantId>,
}

impl TokenBindingRegistryAuthorizer {
    pub fn from_file(path: &Path, identities: &BTreeSet<String>) -> Result<Self, RegistryError> {
        validate_identities(identities)?;
        let raw =
            std::fs::read(path).map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(RegistryError::ManagementIdentityNotConfigured);
        }
        let document: TokenBindingDocument = serde_json::from_slice(&raw)
            .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
        if document.schema_version != "agenttrust.registry-token-bindings.v1"
            || document.bindings.is_empty()
        {
            return Err(RegistryError::ManagementIdentityNotConfigured);
        }
        let mut bindings = BTreeSet::new();
        let mut authorization_keys = BTreeSet::new();
        let mut tenants = BTreeSet::new();
        for binding in document.bindings {
            if !identities.contains(&binding.client_identity)
                || !matches!(binding.scope.as_str(), "registry:read" | "registry:write")
                || binding.subject.trim().is_empty()
                || binding.subject.len() > 256
                || !digest(&binding.token_sha256)
            {
                return Err(RegistryError::ManagementIdentityNotConfigured);
            }
            let tenant_uuid = Uuid::parse_str(&binding.tenant_id)
                .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
            let tenant = TenantId(tenant_uuid.to_string());
            tenants.insert(tenant);
            if !authorization_keys.insert((
                binding.client_identity.clone(),
                tenant_uuid.to_string(),
                binding.token_sha256.clone(),
            )) {
                return Err(RegistryError::ManagementIdentityNotConfigured);
            }
            if !bindings.insert(TokenAuthorization {
                client_identity: binding.client_identity,
                tenant_id: tenant_uuid.to_string(),
                subject: binding.subject,
                scope: binding.scope,
                token_sha256: binding.token_sha256,
            }) {
                return Err(RegistryError::ManagementIdentityNotConfigured);
            }
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(RegistryError::ManagementIdentityNotConfigured);
        }
        Ok(Self { bindings, tenants })
    }

    pub fn tenants(&self) -> &BTreeSet<TenantId> {
        &self.tenants
    }
}

#[async_trait]
impl RegistryAdminAuthorizer for TokenBindingRegistryAuthorizer {
    async fn authorize(
        &self,
        peer_identity: &str,
        headers: &HeaderMap,
        write: bool,
    ) -> Result<RegistryAdminContext, RegistryError> {
        let tenant = single_header(headers, "x-agenttrust-tenant-id")
            .and_then(|value| Uuid::parse_str(value).ok())
            .map(|value| value.to_string())
            .ok_or(RegistryError::ManagementForbidden)?;
        let token = single_header(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| {
                !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
            })
            .ok_or(RegistryError::ManagementForbidden)?;
        let supplied = hex::encode(Sha256::digest(token.as_bytes()));
        let mut match_context = None;
        for binding in &self.bindings {
            let scope_allowed =
                binding.scope == "registry:write" || (!write && binding.scope == "registry:read");
            let tuple_matches = binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && scope_allowed;
            if tuple_matches && constant_time_digest_matches(&supplied, &binding.token_sha256) {
                if match_context.is_some() {
                    return Err(RegistryError::ManagementForbidden);
                }
                match_context = Some(RegistryAdminContext {
                    tenant_id: TenantId(tenant.clone()),
                    subject: binding.subject.clone(),
                    can_write: binding.scope == "registry:write",
                });
            }
        }
        match_context.ok_or(RegistryError::ManagementForbidden)
    }

    fn production_ready(&self) -> bool {
        !self.bindings.is_empty() && !self.tenants.is_empty()
    }
}

#[derive(Clone)]
struct ManagementState {
    registry: Arc<PostgresRegistryStore>,
    tenants: Arc<BTreeSet<TenantId>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
}

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

pub async fn serve(
    config: RegistryServerConfig,
    api_state: RegistryApiState,
    registry: Arc<PostgresRegistryStore>,
    tenants: BTreeSet<TenantId>,
) -> Result<(), RegistryError> {
    validate_identities(&config.client_identities)?;
    if tenants.is_empty() {
        return Err(RegistryError::ManagementIdentityNotConfigured);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let management_state = ManagementState {
        registry,
        tenants: Arc::new(tenants),
    };
    let data = registry_management_router(api_state)
        .route("/ready", get(data_ready))
        .layer(Extension(management_state.clone()))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ));
    let management = Router::new()
        .route("/ready", get(ready))
        .with_state(management_state);
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| RegistryError::UnavailableFailClosed)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| RegistryError::UnavailableFailClosed)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| RegistryError::UnavailableFailClosed)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn ready(State(state): State<ManagementState>) -> Response {
    readiness_response(&state).await
}

async fn data_ready(
    Extension(state): Extension<ManagementState>,
    Extension(_peer): Extension<RegistryPeerIdentity>,
) -> Response {
    readiness_response(&state).await
}

async fn readiness_response(state: &ManagementState) -> Response {
    let check = async {
        if !state.registry.ready().await {
            return false;
        }
        for tenant in state.tenants.iter() {
            if !state.registry.publisher_ready(tenant).await {
                return false;
            }
        }
        true
    };
    let available = tokio::time::timeout(std::time::Duration::from_millis(1_500), check)
        .await
        .unwrap_or(false);
    let status = if available {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: REGISTRY_READINESS_SCHEMA,
            ready: available,
        }),
    )
        .into_response()
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-registry-token-comparison-v1",
    );
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), RegistryError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(RegistryError::ManagementIdentityNotConfigured);
    }
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, RegistryError> {
    let mut ca_reader = BufReader::new(
        File::open(ca_file).map_err(|_| RegistryError::ManagementIdentityNotConfigured)?,
    );
    let roots_der = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
    if roots_der.is_empty() {
        return Err(RegistryError::ManagementIdentityNotConfigured);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(roots_der);
    if accepted == 0 {
        return Err(RegistryError::ManagementIdentityNotConfigured);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| RegistryError::ManagementIdentityNotConfigured)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
    if certificates.is_empty() {
        return Err(RegistryError::ManagementIdentityNotConfigured);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| RegistryError::ManagementIdentityNotConfigured)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?
        .ok_or(RegistryError::ManagementIdentityNotConfigured)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| RegistryError::ManagementIdentityNotConfigured)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, RegistryPeerIdentity>;
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
                Extension(RegistryPeerIdentity(identity)).layer(service),
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
    fn common_name_identity_is_rejected() {
        assert!(validate_identities(&BTreeSet::from(["CN:registry".into()])).is_err());
    }

    #[test]
    fn duplicate_security_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "authorization",
            axum::http::HeaderValue::from_static("Bearer first"),
        );
        headers.append(
            "authorization",
            axum::http::HeaderValue::from_static("Bearer second"),
        );
        assert!(single_header(&headers, "authorization").is_none());
    }
}
