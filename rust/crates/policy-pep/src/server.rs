//! TLS 1.3/mTLS and token-bound HTTP boundary for the production PEP authority.

use crate::authority::{
    FinalAuthorizationRequest, PEP_AUTHORITY_READINESS_SCHEMA, PepAuthority, PepAuthorityError,
    PreApprovalRequest,
};
use crate::governance::{
    APPROVAL_ROUTE, APPROVAL_SCOPE, ApprovalAuthorizationRequest, HumanPrincipalVerifier,
    QUERY_ROUTE, QUERY_SCOPE, QueryAuthorizationRequest,
};
use agent_trust_contracts::{
    PepPolicyActivationAcknowledgement, PolicyActivationRequest, TenantId,
};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const POLICY_ACTIVATION_ROUTE: &str = "/v1/policies/activations";
pub const POLICY_ACTIVATION_SCOPE: &str = "pep:policy-activate";

#[derive(Debug, Clone)]
pub struct PepServerConfig {
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
pub struct TokenBindingPepAuthorizer {
    bindings: Arc<BTreeSet<TokenAuthorization>>,
}

impl TokenBindingPepAuthorizer {
    pub fn from_file(
        path: &Path,
        identities: &BTreeSet<String>,
    ) -> Result<Self, PepAuthorityError> {
        validate_identities(identities)?;
        let raw = std::fs::read(path).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let document: TokenBindingDocument =
            serde_json::from_slice(&raw).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.pep-token-bindings.v1"
            || document.bindings.is_empty()
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let mut bindings = BTreeSet::new();
        let mut security_tuples = BTreeSet::new();
        for binding in document.bindings {
            if !identities.contains(&binding.client_identity)
                || !matches!(
                    binding.scope.as_str(),
                    "pep:preapprove"
                        | "pep:authorize"
                        | POLICY_ACTIVATION_SCOPE
                        | APPROVAL_SCOPE
                        | QUERY_SCOPE
                )
                || binding.subject.is_empty()
                || binding.subject.len() > 256
                || !digest(&binding.token_sha256)
                || Uuid::parse_str(&binding.tenant_id).is_err()
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
                return Err(PepAuthorityError::ConfigurationInvalid);
            }
        }
        if identities.iter().any(|identity| {
            !bindings
                .iter()
                .any(|binding| &binding.client_identity == identity)
        }) {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            bindings: Arc::new(bindings),
        })
    }

    fn authorize(
        &self,
        peer_identity: &str,
        headers: &HeaderMap,
        tenant: &str,
        scope: &str,
    ) -> Result<&str, PepAuthorityError> {
        if single_header(headers, "x-agenttrust-tenant-id") != Some(tenant)
            || Uuid::parse_str(tenant).is_err()
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let token = bearer_token(headers).ok_or(PepAuthorityError::AuthorizationDenied)?;
        let supplied = hex(Sha256::digest(token.as_bytes()));
        let mut subject = None;
        for binding in self.bindings.iter() {
            if binding.client_identity == peer_identity
                && binding.tenant_id == tenant
                && binding.scope == scope
                && constant_time_digest_matches(&supplied, &binding.token_sha256)
            {
                if subject.is_some() {
                    return Err(PepAuthorityError::AuthorizationDenied);
                }
                subject = Some(binding.subject.as_str());
            }
        }
        subject.ok_or(PepAuthorityError::AuthorizationDenied)
    }
}

#[derive(Clone)]
struct ApiState {
    authority: Arc<PepAuthority>,
    authorizer: Arc<TokenBindingPepAuthorizer>,
    human_principals: Arc<HumanPrincipalVerifier>,
}

#[derive(Clone)]
struct ReadinessState {
    authority: Arc<PepAuthority>,
    human_principals: Arc<HumanPrincipalVerifier>,
}

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
}

#[derive(Debug, Clone)]
struct PepPeerIdentity(String);

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: &'static str,
    ready: bool,
}

pub async fn serve(
    config: PepServerConfig,
    authority: Arc<PepAuthority>,
    authorizer: Arc<TokenBindingPepAuthorizer>,
    human_principals: Arc<HumanPrincipalVerifier>,
) -> Result<(), PepAuthorityError> {
    validate_identities(&config.client_identities)?;
    if !(config.management_address.ip().is_loopback()
        || config.management_address.ip().is_unspecified())
        || config.data_address == config.management_address
    {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    let tls = build_server_tls(
        &config.tls_ca_file,
        &config.tls_certificate_file,
        &config.tls_private_key_file,
    )?;
    let state = ApiState {
        authority: authority.clone(),
        authorizer,
        human_principals: human_principals.clone(),
    };
    // `/ready` on the data listener is deliberately mTLS-only. The execution client probes
    // it without a tenant header, while every authorization route additionally requires an
    // exact SAN/tenant/scope/token tuple.
    let data = Router::new()
        .route("/v1/authorize/pre-approval", post(preapprove))
        .route("/v1/authorize/execution", post(authorize))
        .route(POLICY_ACTIVATION_ROUTE, post(activate_policy))
        .route(APPROVAL_ROUTE, post(authorize_approval))
        .route(QUERY_ROUTE, post(authorize_query))
        .route(
            "/v1/evidence/governance/{evidence_id}",
            get(governance_evidence),
        )
        .route("/ready", get(data_ready))
        .with_state(state)
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ));
    let management = Router::new()
        .route("/ready", get(management_ready))
        .with_state(ReadinessState {
            authority,
            human_principals,
        });
    let management_listener = tokio::net::TcpListener::bind(config.management_address)
        .await
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(tls),
        allowed_identities: Arc::new(config.client_identities),
    };
    let data_plane = async move {
        axum_server::bind(config.data_address)
            .acceptor(acceptor)
            .serve(data.into_make_service())
            .await
            .map_err(|_| PepAuthorityError::DependencyUnavailable)
    };
    let management_plane = async move {
        axum::serve(management_listener, management)
            .await
            .map_err(|_| PepAuthorityError::DependencyUnavailable)
    };
    tokio::try_join!(data_plane, management_plane)?;
    Ok(())
}

async fn preapprove(
    State(state): State<ApiState>,
    Extension(peer): Extension<PepPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<PreApprovalRequest>,
) -> Result<Json<crate::authority::PreApprovalResponse>, PepApiError> {
    state.authorizer.authorize(
        &peer.0,
        &headers,
        &request.action.environment.tenant_id.0,
        "pep:preapprove",
    )?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key) {
        return Err(PepAuthorityError::RequestInvalid.into());
    }
    Ok(Json(state.authority.preapprove(request).await?))
}

async fn authorize(
    State(state): State<ApiState>,
    Extension(peer): Extension<PepPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<FinalAuthorizationRequest>,
) -> Result<Json<crate::authority::FinalAuthorizationResponse>, PepApiError> {
    state.authorizer.authorize(
        &peer.0,
        &headers,
        &request.action.environment.tenant_id.0,
        "pep:authorize",
    )?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key)
        || single_header(&headers, "x-agenttrust-fence-digest") != Some(&request.fence_digest)
    {
        return Err(PepAuthorityError::RequestInvalid.into());
    }
    Ok(Json(state.authority.authorize(request).await?))
}

async fn activate_policy(
    State(state): State<ApiState>,
    Extension(peer): Extension<PepPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<PolicyActivationRequest>,
) -> Result<Json<PepPolicyActivationAcknowledgement>, PepApiError> {
    state.authorizer.authorize(
        &peer.0,
        &headers,
        &request.tenant_id.0,
        POLICY_ACTIVATION_SCOPE,
    )?;
    if single_header(&headers, "idempotency-key") != Some(&request.idempotency_key) {
        return Err(PepAuthorityError::RequestInvalid.into());
    }
    Ok(Json(state.authority.activate_policy(request).await?))
}

async fn authorize_approval(
    State(state): State<ApiState>,
    Extension(peer): Extension<PepPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<ApprovalAuthorizationRequest>,
) -> Result<Json<crate::governance::GovernanceAuthorizationResponse>, PepApiError> {
    let tenant = request.principal.tenant_id.clone();
    let service_subject = state
        .authorizer
        .authorize(&peer.0, &headers, &tenant.0, APPROVAL_SCOPE)?
        .to_owned();
    let idempotency_key = required_header(&headers, "idempotency-key")?.to_owned();
    let encoded_assertion = required_header(&headers, "x-agenttrust-human-assertion")?;
    let assertion = state.human_principals.verify(
        encoded_assertion,
        &request,
        &tenant,
        &peer.0,
        &service_subject,
        APPROVAL_ROUTE,
        APPROVAL_SCOPE,
        &idempotency_key,
        true,
        chrono::Utc::now(),
    )?;
    Ok(Json(
        state
            .authority
            .authorize_approval_governance(
                request,
                assertion,
                idempotency_key,
                peer.0,
                service_subject,
            )
            .await?,
    ))
}

async fn authorize_query(
    State(state): State<ApiState>,
    Extension(peer): Extension<PepPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<QueryAuthorizationRequest>,
) -> Result<Json<crate::governance::GovernanceAuthorizationResponse>, PepApiError> {
    let tenant = request.principal.tenant_id.clone();
    let service_subject = state
        .authorizer
        .authorize(&peer.0, &headers, &tenant.0, QUERY_SCOPE)?
        .to_owned();
    let idempotency_key = required_header(&headers, "idempotency-key")?.to_owned();
    let encoded_assertion = required_header(&headers, "x-agenttrust-human-assertion")?;
    let assertion = state.human_principals.verify(
        encoded_assertion,
        &request,
        &tenant,
        &peer.0,
        &service_subject,
        QUERY_ROUTE,
        QUERY_SCOPE,
        &idempotency_key,
        state.human_principals.query_requires_strong_auth(),
        chrono::Utc::now(),
    )?;
    Ok(Json(
        state
            .authority
            .authorize_query_governance(
                request,
                assertion,
                idempotency_key,
                peer.0,
                service_subject,
            )
            .await?,
    ))
}

async fn governance_evidence(
    State(state): State<ApiState>,
    Extension(peer): Extension<PepPeerIdentity>,
    AxumPath(evidence_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, PepApiError> {
    let tenant = required_header(&headers, "x-agenttrust-tenant-id")?;
    state
        .authorizer
        .authorize(&peer.0, &headers, tenant, QUERY_SCOPE)?;
    let tenant = TenantId(tenant.to_owned());
    match state
        .authority
        .governance_evidence(&tenant, &evidence_id)
        .await?
    {
        Some(evidence) => Ok(Json(evidence).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn data_ready(State(state): State<ApiState>) -> Response {
    readiness(state.authority, state.human_principals).await
}

async fn management_ready(State(state): State<ReadinessState>) -> Response {
    readiness(state.authority, state.human_principals).await
}

async fn readiness(
    authority: Arc<PepAuthority>,
    human_principals: Arc<HumanPrincipalVerifier>,
) -> Response {
    let ready = human_principals.ready()
        && tokio::time::timeout(Duration::from_secs(5), authority.ready())
            .await
            .unwrap_or(false);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            schema_version: PEP_AUTHORITY_READINESS_SCHEMA,
            ready,
        }),
    )
        .into_response()
}

struct PepApiError(PepAuthorityError);

impl From<PepAuthorityError> for PepApiError {
    fn from(value: PepAuthorityError) -> Self {
        Self(value)
    }
}

impl IntoResponse for PepApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            PepAuthorityError::RequestInvalid | PepAuthorityError::ResponseInvalid => {
                StatusCode::BAD_REQUEST
            }
            PepAuthorityError::AuthorizationDenied => StatusCode::FORBIDDEN,
            PepAuthorityError::IdempotencyConflict | PepAuthorityError::IdempotencyInProgress => {
                StatusCode::CONFLICT
            }
            PepAuthorityError::DependencyUnavailable
            | PepAuthorityError::DependencyResponseInvalid
            | PepAuthorityError::PersistenceUnavailable
            | PepAuthorityError::IdempotencyIndeterminate => StatusCode::SERVICE_UNAVAILABLE,
            PepAuthorityError::ConfigurationInvalid => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "agenttrust.pep-error.v1",
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    single_header(headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| {
            !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
        })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, PepAuthorityError> {
    single_header(headers, name)
        .filter(|value| !value.is_empty())
        .ok_or(PepAuthorityError::RequestInvalid)
}

fn constant_time_digest_matches(supplied: &str, expected: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"agenttrust-pep-token-comparison-v1");
    let expected_tag = hmac::sign(&key, expected.as_bytes());
    hmac::verify(&key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn validate_identities(identities: &BTreeSet<String>) -> Result<(), PepAuthorityError> {
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, PepAuthorityError> {
    let mut ca_reader =
        BufReader::new(File::open(ca_file).map_err(|_| PepAuthorityError::ConfigurationInvalid)?);
    let roots_der = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    if roots_der.is_empty() {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(roots_der);
    if accepted == 0 {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| PepAuthorityError::ConfigurationInvalid)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    if certificates.is_empty() {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| PepAuthorityError::ConfigurationInvalid)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?
        .ok_or(PepAuthorityError::ConfigurationInvalid)?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PepAuthorityError::ConfigurationInvalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
            .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddExtension<S, PepPeerIdentity>;
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
            Ok((stream, Extension(PepPeerIdentity(identity)).layer(service)))
        })
    }
}

fn matching_certificate_identity(certificate: &[u8], allowed: &BTreeSet<String>) -> Option<String> {
    let mut identities = certificate_subject_alt_names(certificate).ok()?.into_iter();
    let identity = identities.next()?;
    if identities.next().is_some() || !allowed.contains(&identity) {
        return None;
    }
    Some(identity)
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
            // The allowlist binds the complete SAN identity, not a preferred alias selected
            // from a certificate that also carries an unreviewed IP/email/otherName SAN.
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

fn io_denied(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    fn common_name_is_not_an_identity() {
        assert!(validate_identities(&BTreeSet::from(["CN:pep-client".into()])).is_err());
    }

    #[test]
    fn digest_comparison_is_constant_time_and_exact() {
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
    fn one_raw_token_cannot_be_reused_across_governance_scopes() {
        let identity = "URI:spiffe://agenttrust/enterprise-bff";
        let path = std::env::temp_dir().join(format!(
            "agenttrust-pep-token-cross-scope-{}.json",
            Uuid::new_v4()
        ));
        let document = serde_json::json!({
            "schema_version": "agenttrust.pep-token-bindings.v1",
            "bindings": [
                {
                    "client_identity": identity,
                    "tenant_id": "00000000-0000-4000-8000-000000000001",
                    "subject": "enterprise-bff",
                    "scope": APPROVAL_SCOPE,
                    "token_sha256": "a".repeat(64)
                },
                {
                    "client_identity": identity,
                    "tenant_id": "00000000-0000-4000-8000-000000000001",
                    "subject": "enterprise-bff",
                    "scope": QUERY_SCOPE,
                    "token_sha256": "a".repeat(64)
                }
            ]
        });
        let encoded = serde_json::to_vec(&document)
            .unwrap_or_else(|error| panic!("test token bindings must serialize: {error}"));
        std::fs::write(&path, encoded)
            .unwrap_or_else(|error| panic!("test token bindings must be writable: {error}"));
        let result =
            TokenBindingPepAuthorizer::from_file(&path, &BTreeSet::from([identity.to_owned()]));
        let _ = std::fs::remove_file(path);
        assert!(matches!(
            result,
            Err(PepAuthorityError::ConfigurationInvalid)
        ));
    }
}
