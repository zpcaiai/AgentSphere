use agent_trust_durable_orchestrator::facts::{
    FactResolutionError, HttpsApprovalWait, HttpsCredentialLease, HttpsEvaluator, HttpsEvidence,
    HttpsExecutionLedger, HttpsFactClient, HttpsPolicyCheckpoint, HttpsRuntimeSupervisor,
    ProductionFactResolver,
};
use agent_trust_durable_orchestrator::runtime::{
    AuthoritativeTransitionEngine, RuntimeTransitionError, RuntimeTransitionRequest,
};
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
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
use std::env;
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    engine: AuthoritativeTransitionEngine<ProductionFactResolver>,
    token_bindings: Arc<BTreeSet<TokenAuthorization>>,
}

#[derive(Debug, Clone)]
struct PeerIdentity(String);

#[derive(Debug, Clone)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
    allowed_identities: Arc<BTreeSet<String>>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenAuthorization {
    client_identity: String,
    tenant_id: String,
    scope: String,
    token_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ServerArguments {
    listen: String,
    port: u16,
    management_listen: String,
    management_port: u16,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    schema_version: &'static str,
    error: &'a str,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), FactResolutionError> {
    let arguments = parse_args()?;
    let allowed_identities = Arc::new(parse_client_identities(&required_env(
        "AGENT_TRUST_TRANSITION_CLIENT_IDENTITIES",
    )?)?);
    let token_bindings = Arc::new(load_token_bindings(
        &required_path("AGENT_TRUST_TRANSITION_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let server_tls = build_server_tls(
        &required_path("AGENT_TRUST_TRANSITION_TLS_CA_FILE")?,
        &required_path("AGENT_TRUST_TRANSITION_TLS_CERTIFICATE_FILE")?,
        &required_path("AGENT_TRUST_TRANSITION_TLS_PRIVATE_KEY_FILE")?,
    )?;
    let ca = required_path("AGENT_TRUST_FACT_CA_FILE")?;
    let certificate = required_path("AGENT_TRUST_FACT_CERTIFICATE_FILE")?;
    let private_key = required_path("AGENT_TRUST_FACT_PRIVATE_KEY_FILE")?;
    let binding =
        |endpoint_name: &str, token_name: &str| -> Result<HttpsFactClient, FactResolutionError> {
            HttpsFactClient::new(
                &required_env(endpoint_name)?,
                required_secret(token_name)?,
                &ca,
                &certificate,
                &private_key,
            )
        };
    let resolver = ProductionFactResolver::new(
        Arc::new(HttpsPolicyCheckpoint(binding(
            "AGENT_TRUST_POLICY_FACT_ENDPOINT",
            "AGENT_TRUST_POLICY_FACT_TOKEN",
        )?)),
        Arc::new(HttpsApprovalWait(binding(
            "AGENT_TRUST_APPROVAL_FACT_ENDPOINT",
            "AGENT_TRUST_APPROVAL_FACT_TOKEN",
        )?)),
        Arc::new(HttpsCredentialLease(binding(
            "AGENT_TRUST_CREDENTIAL_FACT_ENDPOINT",
            "AGENT_TRUST_CREDENTIAL_FACT_TOKEN",
        )?)),
        Arc::new(HttpsExecutionLedger(binding(
            "AGENT_TRUST_LEDGER_FACT_ENDPOINT",
            "AGENT_TRUST_LEDGER_FACT_TOKEN",
        )?)),
        Arc::new(HttpsEvaluator(binding(
            "AGENT_TRUST_EVALUATOR_FACT_ENDPOINT",
            "AGENT_TRUST_EVALUATOR_FACT_TOKEN",
        )?)),
        Arc::new(HttpsEvidence(binding(
            "AGENT_TRUST_EVIDENCE_FACT_ENDPOINT",
            "AGENT_TRUST_EVIDENCE_FACT_TOKEN",
        )?)),
        Arc::new(HttpsRuntimeSupervisor(binding(
            "AGENT_TRUST_SUPERVISOR_FACT_ENDPOINT",
            "AGENT_TRUST_SUPERVISOR_FACT_TOKEN",
        )?)),
    );
    let state = AppState {
        engine: AuthoritativeTransitionEngine::new(resolver),
        token_bindings,
    };
    // The data-plane listener always requires a client certificate. A separate, narrow
    // management listener exposes only dependency-aware readiness so kubelet does not need
    // transition-service credentials and a TCP-only probe cannot mask failed fact services.
    let management_app = Router::new()
        .route("/ready", get(ready))
        .with_state(state.clone());
    let app = Router::new()
        .route("/ready", get(ready))
        .route("/v1/transitions/apply", post(apply))
        .layer(DefaultBodyLimit::max(1_048_576))
        .with_state(state);
    let address = format!("{}:{}", arguments.listen, arguments.port)
        .parse::<SocketAddr>()
        .map_err(|_| FactResolutionError::Configuration)?;
    let management_address = format!(
        "{}:{}",
        arguments.management_listen, arguments.management_port
    )
    .parse::<SocketAddr>()
    .map_err(|_| FactResolutionError::Configuration)?;
    let management_listener = tokio::net::TcpListener::bind(management_address)
        .await
        .map_err(|_| FactResolutionError::Unavailable)?;
    let data_plane = async move {
        let acceptor = PeerIdentityAcceptor {
            inner: RustlsAcceptor::new(server_tls),
            allowed_identities,
        };
        axum_server::bind(address)
            .acceptor(acceptor)
            .serve(app.into_make_service())
            .await
            .map_err(|_| FactResolutionError::Unavailable)
    };
    let management = async move {
        axum::serve(management_listener, management_app)
            .await
            .map_err(|_| FactResolutionError::Unavailable)
    };
    tokio::try_join!(data_plane, management)?;
    Ok(())
}

fn build_server_tls(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<RustlsConfig, FactResolutionError> {
    let mut ca_reader =
        BufReader::new(File::open(ca_file).map_err(|_| FactResolutionError::Configuration)?);
    let ca_certificates = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| FactResolutionError::Configuration)?;
    if ca_certificates.is_empty() {
        return Err(FactResolutionError::Configuration);
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(ca_certificates);
    if accepted == 0 {
        return Err(FactResolutionError::Configuration);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| FactResolutionError::Configuration)?;

    let mut certificate_reader = BufReader::new(
        File::open(certificate_file).map_err(|_| FactResolutionError::Configuration)?,
    );
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| FactResolutionError::Configuration)?;
    if certificates.is_empty() {
        return Err(FactResolutionError::Configuration);
    }
    let mut key_reader = BufReader::new(
        File::open(private_key_file).map_err(|_| FactResolutionError::Configuration)?,
    );
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| FactResolutionError::Configuration)?
        .ok_or(FactResolutionError::Configuration)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| FactResolutionError::Configuration)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, PrivateKeyDer::clone_key(&private_key))
        .map_err(|_| FactResolutionError::Configuration)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

async fn ready(State(state): State<AppState>) -> Response {
    if state.engine.ready().await {
        Json(serde_json::json!({
            "schema_version": "agenttrust.transition-readiness.v1",
            "ready": true
        }))
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "schema_version": "agenttrust.transition-readiness.v1",
                "ready": false,
                "error": "ORCHESTRATOR_AUTHORITATIVE_FACT_UNAVAILABLE"
            })),
        )
            .into_response()
    }
}

async fn apply(
    State(state): State<AppState>,
    Extension(peer_identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RuntimeTransitionRequest>,
) -> Response {
    let supplied = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(supplied) = supplied else {
        return error_response(StatusCode::UNAUTHORIZED, "ORCHESTRATOR_UNAUTHENTICATED");
    };
    let token_sha256 = token_digest(supplied);
    let binding = TokenAuthorization {
        client_identity: peer_identity.0,
        tenant_id: request.current.tenant_id.clone(),
        scope: "transitions:apply".into(),
        token_sha256,
    };
    let mut token_authorized = false;
    for expected in state.token_bindings.iter() {
        // Always execute the constant-time digest comparison so binding position and the
        // presence of an identity/tenant tuple do not change token-comparison work.
        let digest_matches = token_matches(&binding.token_sha256, &expected.token_sha256);
        let tuple_matches = expected.client_identity == binding.client_identity
            && expected.tenant_id == binding.tenant_id
            && expected.scope == binding.scope;
        token_authorized |= tuple_matches && digest_matches;
    }
    if !token_authorized {
        return error_response(StatusCode::FORBIDDEN, "ORCHESTRATOR_SCOPE_UNAUTHORIZED");
    }
    match state.engine.apply(request).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => {
            let status = match &error {
                RuntimeTransitionError::RequestInvalid | RuntimeTransitionError::FactsInvalid => {
                    StatusCode::BAD_REQUEST
                }
                RuntimeTransitionError::ConcurrentCommand => StatusCode::CONFLICT,
                RuntimeTransitionError::IdempotencyConflict => StatusCode::CONFLICT,
                RuntimeTransitionError::FactResolution(FactResolutionError::Unavailable)
                | RuntimeTransitionError::FactResolution(FactResolutionError::Configuration) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                RuntimeTransitionError::FactResolution(FactResolutionError::ResponseInvalid) => {
                    StatusCode::BAD_GATEWAY
                }
                RuntimeTransitionError::CapacityExceeded => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::FORBIDDEN,
            };
            error_response(status, stable_error_code(&error))
        }
    }
}

fn token_matches(supplied: &str, expected: &str) -> bool {
    let comparison_key = hmac::Key::new(
        hmac::HMAC_SHA256,
        b"agenttrust-transition-token-comparison-v1",
    );
    let expected_tag = hmac::sign(&comparison_key, expected.as_bytes());
    hmac::verify(&comparison_key, supplied.as_bytes(), expected_tag.as_ref()).is_ok()
}

fn token_digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn stable_error_code(error: &RuntimeTransitionError) -> &str {
    match error {
        RuntimeTransitionError::RequestInvalid => "ORCHESTRATOR_TRANSITION_REQUEST_INVALID",
        RuntimeTransitionError::FactsInvalid => "ORCHESTRATOR_TRANSITION_FACTS_INVALID",
        RuntimeTransitionError::ConcurrentCommand => "ORCHESTRATOR_CONCURRENT_COMMAND",
        RuntimeTransitionError::IdempotencyConflict => "ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT",
        RuntimeTransitionError::TerminalTask => "ORCHESTRATOR_TERMINAL_TASK",
        RuntimeTransitionError::TransitionDenied => "ORCHESTRATOR_TRANSITION_DENIED",
        RuntimeTransitionError::AuthorizationInvalid => "ORCHESTRATOR_AUTHORIZATION_INVALID",
        RuntimeTransitionError::ContainmentIncomplete => "ORCHESTRATOR_CONTAINMENT_INCOMPLETE",
        RuntimeTransitionError::CompletionEvidenceMissing => {
            "ORCHESTRATOR_COMPLETION_EVIDENCE_MISSING"
        }
        RuntimeTransitionError::CapacityExceeded => "ORCHESTRATOR_RUNTIME_CAPACITY_EXCEEDED",
        RuntimeTransitionError::FactResolution(FactResolutionError::Configuration) => {
            "ORCHESTRATOR_FACT_BINDING_CONFIGURATION_INVALID"
        }
        RuntimeTransitionError::FactResolution(FactResolutionError::Unavailable) => {
            "ORCHESTRATOR_AUTHORITATIVE_FACT_UNAVAILABLE"
        }
        RuntimeTransitionError::FactResolution(FactResolutionError::Denied) => {
            "ORCHESTRATOR_AUTHORITATIVE_FACT_DENIED"
        }
        RuntimeTransitionError::FactResolution(FactResolutionError::ResponseInvalid) => {
            "ORCHESTRATOR_AUTHORITATIVE_FACT_RESPONSE_INVALID"
        }
    }
}

fn error_response(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            schema_version: "agenttrust.transition-error.v1",
            error: code,
        }),
    )
        .into_response()
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
            let certificates = stream.get_ref().1.peer_certificates().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "client certificate missing",
                )
            })?;
            let identity = certificates
                .first()
                .and_then(|certificate| {
                    matching_certificate_identity(certificate.as_ref(), &allowed)
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "client certificate identity is not allowed",
                    )
                })?;
            Ok((stream, Extension(PeerIdentity(identity)).layer(service)))
        })
    }
}

fn parse_client_identities(value: &str) -> Result<BTreeSet<String>, FactResolutionError> {
    let identities = value
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity
                    .split_once(':')
                    .is_none_or(|(_, value)| value.is_empty())
        })
    {
        return Err(FactResolutionError::Configuration);
    }
    Ok(identities)
}

fn load_token_bindings(
    path: &Path,
    allowed: &BTreeSet<String>,
) -> Result<BTreeSet<TokenAuthorization>, FactResolutionError> {
    let raw = std::fs::read(path).map_err(|_| FactResolutionError::Configuration)?;
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err(FactResolutionError::Configuration);
    }
    let document = serde_json::from_slice::<TokenBindingDocument>(&raw)
        .map_err(|_| FactResolutionError::Configuration)?;
    if document.schema_version != "agenttrust.transition-token-bindings.v1"
        || document.bindings.is_empty()
    {
        return Err(FactResolutionError::Configuration);
    }
    let mut bindings = BTreeSet::new();
    for binding in document.bindings {
        if binding.scope != "transitions:apply"
            || !allowed.contains(&binding.client_identity)
            || Uuid::parse_str(&binding.tenant_id).is_err()
            || binding.token_sha256.len() != 64
            || !binding
                .token_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FactResolutionError::Configuration);
        }
        let authorization = TokenAuthorization {
            client_identity: binding.client_identity,
            tenant_id: binding.tenant_id,
            scope: binding.scope,
            token_sha256: binding.token_sha256,
        };
        if !bindings.insert(authorization) {
            return Err(FactResolutionError::Configuration);
        }
    }
    if allowed.iter().any(|identity| {
        !bindings
            .iter()
            .any(|candidate| &candidate.client_identity == identity)
    }) {
        return Err(FactResolutionError::Configuration);
    }
    Ok(bindings)
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
    let mut tbs_offset = 0;
    let mut san_extension = None;
    while tbs_offset < tbs.len() {
        let (tag, value, next) = der_element(tbs, tbs_offset)?;
        tbs_offset = next;
        if tag != 0xa3 {
            continue;
        }
        let (extensions_tag, extensions, extensions_end) = der_element(value, 0)?;
        if extensions_tag != 0x30 || extensions_end != value.len() {
            return Err(());
        }
        let mut extension_offset = 0;
        while extension_offset < extensions.len() {
            let (tag, extension, next) = der_element(extensions, extension_offset)?;
            extension_offset = next;
            if tag != 0x30 {
                return Err(());
            }
            let (oid_tag, oid, mut field_offset) = der_element(extension, 0)?;
            if oid_tag != 0x06 {
                return Err(());
            }
            let (mut value_tag, mut extension_value, next_field) =
                der_element(extension, field_offset)?;
            field_offset = next_field;
            if value_tag == 0x01 {
                let parsed = der_element(extension, field_offset)?;
                value_tag = parsed.0;
                extension_value = parsed.1;
                field_offset = parsed.2;
            }
            if value_tag != 0x04 || field_offset != extension.len() {
                return Err(());
            }
            if oid == [0x55, 0x1d, 0x11] && san_extension.replace(extension_value).is_some() {
                return Err(());
            }
        }
    }
    let extension = san_extension.ok_or(())?;
    let (names_tag, names, names_end) = der_element(extension, 0)?;
    if names_tag != 0x30 || names_end != extension.len() {
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
        let mut length = 0_usize;
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

fn parse_args() -> Result<ServerArguments, FactResolutionError> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from<I>(arguments: I) -> Result<ServerArguments, FactResolutionError>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = ServerArguments {
        listen: "127.0.0.1".to_string(),
        port: 8_082,
        management_listen: "127.0.0.1".to_string(),
        management_port: 9_091,
    };
    let mut args = arguments.into_iter();
    while let Some(argument) = args.next() {
        let value = args.next().ok_or(FactResolutionError::Configuration)?;
        match argument.as_str() {
            "--listen" => parsed.listen = value,
            "--port" => {
                parsed.port = value
                    .parse::<u16>()
                    .map_err(|_| FactResolutionError::Configuration)?;
            }
            "--management-listen" => parsed.management_listen = value,
            "--management-port" => {
                parsed.management_port = value
                    .parse::<u16>()
                    .map_err(|_| FactResolutionError::Configuration)?;
            }
            _ => return Err(FactResolutionError::Configuration),
        }
    }
    if parsed.listen.is_empty()
        || parsed.management_listen.is_empty()
        || parsed.port == 0
        || parsed.management_port == 0
        || parsed.port == parsed.management_port
    {
        return Err(FactResolutionError::Configuration);
    }
    Ok(parsed)
}

fn required_env(name: &str) -> Result<String, FactResolutionError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(FactResolutionError::Configuration)
}

fn required_path(name: &str) -> Result<PathBuf, FactResolutionError> {
    let path = PathBuf::from(required_env(name)?);
    if !secure_file(
        &path,
        name.contains("PRIVATE_KEY") || name.contains("TOKEN"),
    )? {
        return Err(FactResolutionError::Configuration);
    }
    Ok(path)
}

fn required_secret(name: &str) -> Result<String, FactResolutionError> {
    let path = PathBuf::from(required_env(&format!("{name}_FILE"))?);
    if !secure_file(&path, true)?
        || std::fs::metadata(&path)
            .map_err(|_| FactResolutionError::Configuration)?
            .len()
            > 65_536
    {
        return Err(FactResolutionError::Configuration);
    }
    let raw = std::fs::read_to_string(path).map_err(|_| FactResolutionError::Configuration)?;
    let value = raw.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(FactResolutionError::Configuration);
    }
    Ok(value.to_string())
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, FactResolutionError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| FactResolutionError::Configuration)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let effective_uid = nix::unistd::geteuid().as_raw();
    let effective_gid = nix::unistd::getegid().as_raw();
    let owner_can_read = metadata.uid() == effective_uid && mode & 0o400 != 0;
    let group_can_read = metadata.gid() == effective_gid && mode & 0o040 != 0;
    let access_valid = if private {
        (owner_can_read || group_can_read)
            && (mode & 0o040 == 0 || metadata.gid() == effective_gid)
            && mode & !0o440 == 0
    } else {
        mode & 0o022 == 0 && (owner_can_read || group_can_read || mode & 0o004 != 0)
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() > 0
        && metadata.len() <= 1_048_576
        && access_valid)
}

#[cfg(not(unix))]
fn secure_file(path: &Path, _private: bool) -> Result<bool, FactResolutionError> {
    let metadata = std::fs::metadata(path).map_err(|_| FactResolutionError::Configuration)?;
    Ok(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1_048_576)
}

#[cfg(test)]
mod tests {
    use super::{ServerArguments, parse_args_from, token_digest, token_matches};

    #[test]
    fn bearer_comparison_rejects_prefixes_and_length_changes() {
        assert!(token_matches("correct-token", "correct-token"));
        assert!(!token_matches("correct", "correct-token"));
        assert!(!token_matches("correct-token-extra", "correct-token"));
    }

    #[test]
    fn token_digest_is_stable_and_secret_is_not_stored() {
        assert_eq!(
            token_digest("correct-token"),
            "5f6a2a6ba63161fc34d2a9048e2c81619c03198b0ef8b9cbc7591332078b637f"
        );
    }

    #[test]
    fn management_listener_is_separate_and_configurable() {
        assert_eq!(
            parse_args_from(Vec::new())
                .unwrap_or_else(|error| panic!("default arguments: {error}")),
            ServerArguments {
                listen: "127.0.0.1".into(),
                port: 8_082,
                management_listen: "127.0.0.1".into(),
                management_port: 9_091,
            }
        );
        let parsed = parse_args_from([
            "--listen".into(),
            "0.0.0.0".into(),
            "--port".into(),
            "8443".into(),
            "--management-listen".into(),
            "0.0.0.0".into(),
            "--management-port".into(),
            "9092".into(),
        ])
        .unwrap_or_else(|error| panic!("configured arguments: {error}"));
        assert_eq!(parsed.port, 8_443);
        assert_eq!(parsed.management_port, 9_092);
        assert!(parse_args_from(["--management-port".into(), "8082".into()]).is_err());
    }
}
