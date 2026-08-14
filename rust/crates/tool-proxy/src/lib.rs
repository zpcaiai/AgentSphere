//! Authorized target-credential brokering, fixed-purpose connectors, and pre-trace DLP.

use agent_trust_contracts::{ActionHash, ExecutionAuthorization, TenantId};
use agent_trust_identity::{CredentialHandle, CredentialService};
use agent_trust_registry::{ResolvedToolSnapshot, ToolRegistry};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

pub const PROXY_SCHEMA_VERSION: &str = "agenttrust.proxy.v1";

pub struct SecretLease {
    pub lease_id: String,
    pub profile: String,
    pub tenant_id: TenantId,
    pub target: String,
    pub expires_at: DateTime<Utc>,
    secret: Vec<u8>,
}

impl SecretLease {
    fn expose_to_connector(&self) -> &[u8] {
        &self.secret
    }
}
impl fmt::Debug for SecretLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretLease")
            .field("lease_id", &self.lease_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl Drop for SecretLease {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[async_trait]
pub trait TargetSecretProvider: Send + Sync {
    async fn lease(
        &self,
        profile: &str,
        tenant: &TenantId,
        target: &str,
        ttl: Duration,
    ) -> Result<SecretLease, ProxyError>;
    async fn revoke(&self, lease_id: &str) -> Result<(), ProxyError>;
}

pub struct InMemoryTargetSecretProvider {
    secrets: RwLock<BTreeMap<(TenantId, String, String), Vec<u8>>>,
    active: RwLock<BTreeSet<String>>,
    available: RwLock<bool>,
}

impl Default for InMemoryTargetSecretProvider {
    fn default() -> Self {
        Self {
            secrets: RwLock::new(BTreeMap::new()),
            active: RwLock::new(BTreeSet::new()),
            available: RwLock::new(true),
        }
    }
}

impl InMemoryTargetSecretProvider {
    pub fn insert(&self, tenant: TenantId, profile: String, target: String, secret: Vec<u8>) {
        self.secrets
            .write()
            .insert((tenant, profile, target), secret);
    }
    pub fn set_available(&self, available: bool) {
        *self.available.write() = available;
    }
    pub fn active_count(&self) -> usize {
        self.active.read().len()
    }
}

#[async_trait]
impl TargetSecretProvider for InMemoryTargetSecretProvider {
    async fn lease(
        &self,
        profile: &str,
        tenant: &TenantId,
        target: &str,
        ttl: Duration,
    ) -> Result<SecretLease, ProxyError> {
        if !*self.available.read() {
            return Err(ProxyError::SecretProviderUnavailable);
        }
        let secret = self
            .secrets
            .read()
            .get(&(tenant.clone(), profile.to_string(), target.to_string()))
            .cloned()
            .ok_or(ProxyError::CredentialScopeDenied)?;
        let lease_id = Uuid::new_v4().to_string();
        self.active.write().insert(lease_id.clone());
        Ok(SecretLease {
            lease_id,
            profile: profile.into(),
            tenant_id: tenant.clone(),
            target: target.into(),
            expires_at: Utc::now()
                + chrono::Duration::from_std(ttl).map_err(|_| ProxyError::CredentialScopeDenied)?,
            secret,
        })
    }
    async fn revoke(&self, lease_id: &str) -> Result<(), ProxyError> {
        self.active.write().remove(lease_id);
        Ok(())
    }
}

pub struct SensitiveVaultToken(String);
impl SensitiveVaultToken {
    pub fn new(value: String) -> Result<Self, ProxyError> {
        if value.is_empty()
            || value.len() > 16_384
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            Err(ProxyError::SecretProviderConfigurationInvalid)
        } else {
            Ok(Self(value))
        }
    }
    fn expose_to_transport(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SensitiveVaultToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveVaultToken([REDACTED])")
    }
}
impl Drop for SensitiveVaultToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VaultLeaseProfile {
    pub credential_profile: String,
    pub target: String,
    pub lease_path: String,
}

#[derive(Debug)]
pub struct VaultLeaseMaterial {
    pub lease_id: String,
    pub lease_duration_seconds: u64,
    pub secret: Vec<u8>,
}
impl Drop for VaultLeaseMaterial {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[async_trait]
pub trait VaultLeaseTransport: Send + Sync {
    async fn issue(
        &self,
        lease_path: &str,
        maximum_ttl: Duration,
    ) -> Result<VaultLeaseMaterial, ProxyError>;
    async fn revoke(&self, vault_lease_id: &str) -> Result<(), ProxyError>;
}

/// Production Vault transport. The supplied reqwest client must be constructed
/// with the deployment CA and client identity; this type refuses plaintext,
/// credential-bearing URLs, redirects, and unbounded responses.
pub struct ReqwestVaultLeaseTransport {
    endpoint: Url,
    token: SensitiveVaultToken,
    client: reqwest::Client,
}

impl ReqwestVaultLeaseTransport {
    pub fn new(
        endpoint: Url,
        token: SensitiveVaultToken,
        client: reqwest::Client,
    ) -> Result<Self, ProxyError> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ProxyError::SecretProviderConfigurationInvalid);
        }
        Ok(Self {
            endpoint,
            token,
            client,
        })
    }

    fn url(&self, path: &str) -> Result<Url, ProxyError> {
        self.endpoint
            .join(path)
            .map_err(|_| ProxyError::SecretProviderConfigurationInvalid)
    }
}

#[async_trait]
impl VaultLeaseTransport for ReqwestVaultLeaseTransport {
    async fn issue(
        &self,
        lease_path: &str,
        maximum_ttl: Duration,
    ) -> Result<VaultLeaseMaterial, ProxyError> {
        let response = self
            .client
            .post(self.url(&format!("v1/{lease_path}"))?)
            .header("X-Vault-Token", self.token.expose_to_transport())
            .header("Accept", "application/json")
            .json(&serde_json::json!({}))
            .timeout(maximum_ttl.min(Duration::from_secs(30)))
            .send()
            .await
            .map_err(|_| ProxyError::SecretProviderUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 1_048_576)
        {
            return Err(ProxyError::SecretProviderUnavailable);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| ProxyError::SecretProviderUnavailable)?;
        if bytes.len() > 1_048_576 {
            return Err(ProxyError::SecretProviderUnavailable);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ProxyError::SecretProviderUnavailable)?;
        let lease_id = value
            .get("lease_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .ok_or(ProxyError::SecretProviderUnavailable)?;
        let lease_duration_seconds = value
            .get("lease_duration")
            .and_then(Value::as_u64)
            .filter(|duration| *duration > 0 && *duration <= maximum_ttl.as_secs().max(1))
            .ok_or(ProxyError::SecretProviderUnavailable)?;
        let data = value
            .get("data")
            .and_then(Value::as_object)
            .filter(|data| !data.is_empty() && data.len() <= 64)
            .ok_or(ProxyError::SecretProviderUnavailable)?;
        let secret = serde_jcs::to_vec(data).map_err(|_| ProxyError::SecretProviderUnavailable)?;
        if secret.len() > 256 * 1024 {
            return Err(ProxyError::SecretProviderUnavailable);
        }
        Ok(VaultLeaseMaterial {
            lease_id: lease_id.into(),
            lease_duration_seconds,
            secret,
        })
    }

    async fn revoke(&self, vault_lease_id: &str) -> Result<(), ProxyError> {
        if vault_lease_id.is_empty() || vault_lease_id.len() > 1024 {
            return Err(ProxyError::SecretProviderUnavailable);
        }
        let response = self
            .client
            .post(self.url("v1/sys/leases/revoke")?)
            .header("X-Vault-Token", self.token.expose_to_transport())
            .json(&serde_json::json!({"lease_id":vault_lease_id}))
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| ProxyError::SecretProviderUnavailable)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ProxyError::SecretProviderUnavailable)
        }
    }
}

pub struct VaultTargetSecretProvider<T: VaultLeaseTransport> {
    transport: Arc<T>,
    profiles: BTreeMap<(String, String), String>,
    active: RwLock<BTreeMap<String, String>>,
}

impl<T: VaultLeaseTransport> VaultTargetSecretProvider<T> {
    pub fn new(transport: Arc<T>, profiles: Vec<VaultLeaseProfile>) -> Result<Self, ProxyError> {
        if profiles.is_empty() || profiles.len() > 4096 {
            return Err(ProxyError::SecretProviderConfigurationInvalid);
        }
        let valid = |value: &str, allow_slash: bool| {
            !value.is_empty()
                && value.len() <= 512
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || b"_.:-".contains(&byte)
                        || allow_slash && byte == b'/'
                })
                && !value.contains("..")
        };
        let mut by_scope = BTreeMap::new();
        for profile in profiles {
            if !valid(&profile.credential_profile, false)
                || !valid(&profile.target, false)
                || !valid(&profile.lease_path, true)
                || by_scope
                    .insert(
                        (profile.credential_profile, profile.target),
                        profile.lease_path,
                    )
                    .is_some()
            {
                return Err(ProxyError::SecretProviderConfigurationInvalid);
            }
        }
        Ok(Self {
            transport,
            profiles: by_scope,
            active: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn active_count(&self) -> usize {
        self.active.read().len()
    }
}

#[async_trait]
impl<T: VaultLeaseTransport> TargetSecretProvider for VaultTargetSecretProvider<T> {
    async fn lease(
        &self,
        profile: &str,
        tenant: &TenantId,
        target: &str,
        ttl: Duration,
    ) -> Result<SecretLease, ProxyError> {
        if ttl.is_zero() || ttl > Duration::from_secs(900) {
            return Err(ProxyError::CredentialScopeDenied);
        }
        let lease_path = self
            .profiles
            .get(&(profile.into(), target.into()))
            .ok_or(ProxyError::CredentialScopeDenied)?;
        let mut material = self.transport.issue(lease_path, ttl).await?;
        let lease_id = Uuid::new_v4().to_string();
        self.active
            .write()
            .insert(lease_id.clone(), material.lease_id.clone());
        let secret = std::mem::take(&mut material.secret);
        Ok(SecretLease {
            lease_id,
            profile: profile.into(),
            tenant_id: tenant.clone(),
            target: target.into(),
            expires_at: Utc::now()
                + chrono::Duration::seconds(material.lease_duration_seconds as i64),
            secret,
        })
    }

    async fn revoke(&self, lease_id: &str) -> Result<(), ProxyError> {
        let vault_lease_id = self
            .active
            .write()
            .remove(lease_id)
            .ok_or(ProxyError::SecretProviderUnavailable)?;
        self.transport.revoke(&vault_lease_id).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedToolRequest {
    pub authorization: ExecutionAuthorization,
    pub tool: ResolvedToolSnapshot,
    pub tenant_id: TenantId,
    pub workload_credential: CredentialHandle,
    pub operation: String,
    pub resource: String,
    pub target_profile: String,
    pub arguments: Map<String, Value>,
    pub trace_id: String,
}

#[derive(Debug, Clone)]
pub struct ConnectorContext {
    pub tenant_id: TenantId,
    pub operation: String,
    pub resource: String,
    pub target_profile: String,
    pub max_response_bytes: u64,
    pub deadline: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RawToolResult {
    pub value: Value,
    pub artifact_ref: Option<String>,
}

#[async_trait]
pub trait Connector: Send + Sync {
    fn executor_profile(&self) -> &str;
    async fn execute(
        &self,
        context: &ConnectorContext,
        arguments: &Map<String, Value>,
        lease: &SecretLease,
    ) -> Result<RawToolResult, ProxyError>;
    async fn verify(&self, _: &ConnectorContext, _: &RawToolResult) -> Result<(), ProxyError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedToolResult {
    pub schema_version: String,
    pub value: Value,
    pub artifact_ref: Option<String>,
    pub redacted_paths: Vec<String>,
    pub untrusted_content: bool,
    pub result_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuditEvent {
    pub trace_id: String,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub tool: String,
    pub sanitized_result_hash: String,
    pub redaction_count: usize,
    pub succeeded: bool,
}

#[async_trait]
pub trait ProxyAuditSink: Send + Sync {
    async fn record(&self, event: ProxyAuditEvent) -> Result<(), ProxyError>;
}

pub struct ResponseFilter {
    sensitive_keys: BTreeSet<String>,
    patterns: Vec<Regex>,
}

impl Default for ResponseFilter {
    fn default() -> Self {
        Self {
            sensitive_keys: [
                "password",
                "token",
                "secret",
                "api_key",
                "private_key",
                "authorization",
                "cookie",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            patterns: [
                r"(?i)bearer\s+[a-z0-9._~-]{12,}",
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            ]
            .into_iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect(),
        }
    }
}

impl ResponseFilter {
    pub fn apply(
        &self,
        mut value: Value,
        secret_fingerprints: &[&[u8]],
    ) -> Result<(Value, Vec<String>, bool), ProxyError> {
        let fingerprints: Vec<String> = secret_fingerprints
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .filter(|text| text.len() >= 4)
            .map(str::to_string)
            .collect();
        let mut redacted = Vec::new();
        let mut untrusted = false;
        self.walk(
            &mut value,
            "$",
            &fingerprints,
            &mut redacted,
            &mut untrusted,
        );
        Ok((value, redacted, untrusted))
    }
    fn walk(
        &self,
        value: &mut Value,
        path: &str,
        fingerprints: &[String],
        redacted: &mut Vec<String>,
        untrusted: &mut bool,
    ) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let child_path = format!("{path}.{key}");
                    if self.sensitive_keys.contains(&key.to_ascii_lowercase()) {
                        *child = Value::String("[REDACTED]".into());
                        redacted.push(child_path);
                    } else {
                        self.walk(child, &child_path, fingerprints, redacted, untrusted);
                    }
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    self.walk(
                        child,
                        &format!("{path}[{index}]"),
                        fingerprints,
                        redacted,
                        untrusted,
                    );
                }
            }
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                if lower.contains("ignore previous instructions") || lower.contains("system prompt")
                {
                    *untrusted = true;
                }
                if fingerprints
                    .iter()
                    .any(|fingerprint| text.contains(fingerprint))
                    || self.patterns.iter().any(|pattern| pattern.is_match(text))
                {
                    *text = "[REDACTED]".into();
                    redacted.push(path.into());
                }
            }
            _ => {}
        }
    }
}

pub struct ProxyAuthorizationVerifier {
    keys: RwLock<BTreeMap<String, (String, VerifyingKey)>>,
    used: RwLock<BTreeSet<String>>,
}

impl Default for ProxyAuthorizationVerifier {
    fn default() -> Self {
        Self {
            keys: RwLock::new(BTreeMap::new()),
            used: RwLock::new(BTreeSet::new()),
        }
    }
}
impl ProxyAuthorizationVerifier {
    pub fn add_key(&self, key_id: String, issuer: String, key: VerifyingKey) {
        self.keys.write().insert(key_id, (issuer, key));
    }
    pub fn verify_and_consume(
        &self,
        request: &AuthorizedToolRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ProxyError> {
        let authorization = &request.authorization;
        let (issuer, key) = self
            .keys
            .read()
            .get(&authorization.key_id)
            .cloned()
            .ok_or(ProxyError::AuthorizationInvalid)?;
        if issuer != authorization.issuer
            || authorization.action_hash.0.is_empty()
            || authorization.tool_snapshot_hash != request.tool.snapshot_hash
            || authorization.credential_profile != request.tool.credential_profile
        {
            return Err(ProxyError::AuthorizationInvalid);
        }
        authorization
            .verify(&key, now)
            .map_err(|_| ProxyError::AuthorizationInvalid)?;
        if authorization.single_use
            && !self
                .used
                .write()
                .insert(authorization.authorization_id.clone())
        {
            return Err(ProxyError::AuthorizationReplayed);
        }
        Ok(())
    }
}

pub struct ToolProxy<R: ToolRegistry> {
    registry: Arc<R>,
    authorization: Arc<ProxyAuthorizationVerifier>,
    credentials: Arc<CredentialService>,
    secrets: Arc<dyn TargetSecretProvider>,
    connectors: BTreeMap<String, Arc<dyn Connector>>,
    filter: ResponseFilter,
    audit: Arc<dyn ProxyAuditSink>,
}

impl<R: ToolRegistry> ToolProxy<R> {
    pub fn new(
        registry: Arc<R>,
        authorization: Arc<ProxyAuthorizationVerifier>,
        credentials: Arc<CredentialService>,
        secrets: Arc<dyn TargetSecretProvider>,
        connectors: Vec<Arc<dyn Connector>>,
        audit: Arc<dyn ProxyAuditSink>,
    ) -> Result<Self, ProxyError> {
        let mut by_profile = BTreeMap::new();
        for connector in connectors {
            if by_profile
                .insert(connector.executor_profile().to_string(), connector)
                .is_some()
            {
                return Err(ProxyError::ConnectorInvalid);
            }
        }
        Ok(Self {
            registry,
            authorization,
            credentials,
            secrets,
            connectors: by_profile,
            filter: ResponseFilter::default(),
            audit,
        })
    }

    pub async fn execute(
        &self,
        request: AuthorizedToolRequest,
    ) -> Result<SanitizedToolResult, ProxyError> {
        self.authorization
            .verify_and_consume(&request, Utc::now())?;
        if self
            .registry
            .is_revoked(
                &agent_trust_contracts::ToolRef {
                    tool_id: request.tool.tool_id.clone(),
                    tool_version: request.tool.tool_version.clone(),
                },
                &request.tool.implementation.digest,
            )
            .await
            .map_err(|_| ProxyError::RegistryUnavailable)?
        {
            return Err(ProxyError::RegistryRevoked);
        }
        self.registry
            .validate_arguments(&request.tool, &request.arguments)
            .await
            .map_err(|_| ProxyError::ArgumentInvalid)?;
        let _workload_claims = self
            .credentials
            .validate_and_consume(
                &request.workload_credential,
                "tool-proxy",
                &request.authorization.action_hash,
                &request.resource,
                &request.operation,
                Utc::now(),
            )
            .map_err(|_| ProxyError::CredentialScopeDenied)?;
        let connector = self
            .connectors
            .get(&request.tool.executor_profile)
            .cloned()
            .ok_or(ProxyError::ConnectorInvalid)?;
        let timeout = Duration::from_millis(
            request
                .authorization
                .max_execution_ms
                .min(request.tool.limits.timeout_ms),
        );
        let lease = self
            .secrets
            .lease(
                &request.tool.credential_profile,
                &request.tenant_id,
                &request.target_profile,
                timeout,
            )
            .await?;
        let lease_id = lease.lease_id.clone();
        let context = ConnectorContext {
            tenant_id: request.tenant_id.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            target_profile: request.target_profile.clone(),
            max_response_bytes: request
                .authorization
                .max_result_bytes
                .min(request.tool.limits.max_result_bytes),
            deadline: Utc::now()
                + chrono::Duration::from_std(timeout).map_err(|_| ProxyError::Timeout)?,
        };
        let execution = tokio::time::timeout(
            timeout,
            connector.execute(&context, &request.arguments, &lease),
        )
        .await;
        let raw_result = match execution {
            Ok(result) => result,
            Err(_) => Err(ProxyError::Timeout),
        };
        let revoke_result = self.secrets.revoke(&lease_id).await; // Release on success, error, and timeout before any persistence.
        let raw = raw_result?;
        revoke_result?;
        connector.verify(&context, &raw).await?;
        let (value, redacted_paths, untrusted_content) = self
            .filter
            .apply(raw.value, &[lease.expose_to_connector()])?;
        self.registry
            .validate_output(&request.tool, &value)
            .await
            .map_err(|_| ProxyError::OutputInvalid)?;
        let result_hash = hex_string(Sha256::digest(
            serde_jcs::to_vec(&value).map_err(|_| ProxyError::OutputInvalid)?,
        ));
        let result = SanitizedToolResult {
            schema_version: PROXY_SCHEMA_VERSION.into(),
            value,
            artifact_ref: raw.artifact_ref,
            redacted_paths,
            untrusted_content,
            result_hash: result_hash.clone(),
        };
        self.audit
            .record(ProxyAuditEvent {
                trace_id: request.trace_id,
                tenant_id: request.tenant_id,
                action_hash: request.authorization.action_hash,
                tool: format!("{}@{}", request.tool.tool_id.0, request.tool.tool_version.0),
                sanitized_result_hash: result_hash,
                redaction_count: result.redacted_paths.len(),
                succeeded: true,
            })
            .await?;
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct HttpOperation {
    pub method: reqwest::Method,
    pub path: String,
    pub content_type: String,
}
#[derive(Debug, Clone)]
pub struct HttpTargetProfile {
    pub base_url: Url,
    pub operations: BTreeMap<String, HttpOperation>,
}

pub struct HttpConnector {
    executor_profile: String,
    client: reqwest::Client,
    targets: BTreeMap<String, HttpTargetProfile>,
}
impl HttpConnector {
    pub fn new(
        executor_profile: String,
        targets: BTreeMap<String, HttpTargetProfile>,
    ) -> Result<Self, ProxyError> {
        for profile in targets.values() {
            validate_public_https_target(&profile.base_url)?;
            for operation in profile.operations.values() {
                if !operation.path.starts_with('/') || operation.path.contains("..") {
                    return Err(ProxyError::SsrfDenied);
                }
            }
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProxyError::ConnectorInvalid)?;
        Ok(Self {
            executor_profile,
            client,
            targets,
        })
    }
}

#[async_trait]
impl Connector for HttpConnector {
    fn executor_profile(&self) -> &str {
        &self.executor_profile
    }
    async fn execute(
        &self,
        context: &ConnectorContext,
        arguments: &Map<String, Value>,
        lease: &SecretLease,
    ) -> Result<RawToolResult, ProxyError> {
        let profile = self
            .targets
            .get(&context.target_profile)
            .ok_or(ProxyError::TargetDenied)?;
        let operation = profile
            .operations
            .get(&context.operation)
            .ok_or(ProxyError::TargetDenied)?;
        let url = profile
            .base_url
            .join(operation.path.trim_start_matches('/'))
            .map_err(|_| ProxyError::SsrfDenied)?;
        validate_public_https_target(&url)?;
        let token = std::str::from_utf8(lease.expose_to_connector())
            .map_err(|_| ProxyError::SecretProviderUnavailable)?;
        let response = self
            .client
            .request(operation.method.clone(), url)
            .bearer_auth(token)
            .header("content-type", &operation.content_type)
            .json(&Value::Object(arguments.clone()))
            .send()
            .await
            .map_err(|_| ProxyError::ConnectorFailed)?;
        let bytes = response
            .bytes()
            .await
            .map_err(|_| ProxyError::ConnectorFailed)?;
        if bytes.len() as u64 > context.max_response_bytes {
            return Err(ProxyError::ResponseTooLarge);
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| ProxyError::OutputInvalid)?;
        Ok(RawToolResult {
            value,
            artifact_ref: None,
        })
    }
}

fn validate_public_https_target(url: &Url) -> Result<(), ProxyError> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(ProxyError::SsrfDenied);
    }
    let host = url
        .host_str()
        .ok_or(ProxyError::SsrfDenied)?
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") || host == "metadata.google.internal" {
        return Err(ProxyError::SsrfDenied);
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && (ip.is_loopback() || ip.is_unspecified() || is_private_ip(ip))
    {
        return Err(ProxyError::SsrfDenied);
    }
    Ok(())
}
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_broadcast(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[derive(Debug, Clone)]
pub enum GitOperation {
    Read { path: String },
    CreateTaskBranch { branch: String },
    PushTaskBranch { branch: String },
    CreatePullRequest { branch: String, title: String },
}
#[async_trait]
pub trait GitBackend: Send + Sync {
    async fn execute(
        &self,
        repository: &str,
        operation: GitOperation,
        credential: &[u8],
    ) -> Result<Value, ProxyError>;
}
pub struct GitConnector<B: GitBackend> {
    executor_profile: String,
    repositories: BTreeMap<String, String>,
    backend: Arc<B>,
}
impl<B: GitBackend> GitConnector<B> {
    pub fn new(
        executor_profile: String,
        repositories: BTreeMap<String, String>,
        backend: Arc<B>,
    ) -> Self {
        Self {
            executor_profile,
            repositories,
            backend,
        }
    }
}
#[async_trait]
impl<B: GitBackend> Connector for GitConnector<B> {
    fn executor_profile(&self) -> &str {
        &self.executor_profile
    }
    async fn execute(
        &self,
        context: &ConnectorContext,
        arguments: &Map<String, Value>,
        lease: &SecretLease,
    ) -> Result<RawToolResult, ProxyError> {
        let repository = self
            .repositories
            .get(&context.target_profile)
            .ok_or(ProxyError::TargetDenied)?;
        let operation = match context.operation.as_str() {
            "read" => GitOperation::Read {
                path: safe_relative(
                    arguments
                        .get("path")
                        .and_then(Value::as_str)
                        .ok_or(ProxyError::ArgumentInvalid)?,
                )?,
            },
            "create_task_branch" => GitOperation::CreateTaskBranch {
                branch: safe_task_branch(
                    arguments
                        .get("branch")
                        .and_then(Value::as_str)
                        .ok_or(ProxyError::ArgumentInvalid)?,
                )?,
            },
            "push_task_branch" => GitOperation::PushTaskBranch {
                branch: safe_task_branch(
                    arguments
                        .get("branch")
                        .and_then(Value::as_str)
                        .ok_or(ProxyError::ArgumentInvalid)?,
                )?,
            },
            "create_pr" => GitOperation::CreatePullRequest {
                branch: safe_task_branch(
                    arguments
                        .get("branch")
                        .and_then(Value::as_str)
                        .ok_or(ProxyError::ArgumentInvalid)?,
                )?,
                title: arguments
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("Agent change")
                    .chars()
                    .take(120)
                    .collect(),
            },
            _ => return Err(ProxyError::TargetDenied),
        };
        let value = self
            .backend
            .execute(repository, operation, lease.expose_to_connector())
            .await?;
        Ok(RawToolResult {
            value,
            artifact_ref: None,
        })
    }
}
fn safe_relative(path: &str) -> Result<String, ProxyError> {
    if path.starts_with('/') || path.split('/').any(|part| part == "..") || path.contains('\0') {
        Err(ProxyError::PathTraversal)
    } else {
        Ok(path.into())
    }
}
fn safe_task_branch(branch: &str) -> Result<String, ProxyError> {
    if branch.starts_with("agent/")
        && !branch.contains("..")
        && !matches!(branch, "main" | "master")
    {
        Ok(branch.into())
    } else {
        Err(ProxyError::TargetDenied)
    }
}

#[derive(Debug, Clone)]
pub struct SqlTemplate {
    pub statement_id: String,
    pub sql: String,
    pub write: bool,
    pub max_rows: u32,
}
#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    async fn execute_template(
        &self,
        dsn_ref: &str,
        template: &SqlTemplate,
        parameters: &Map<String, Value>,
        credential: &[u8],
    ) -> Result<Value, ProxyError>;
}
pub struct DatabaseConnector<B: DatabaseBackend> {
    executor_profile: String,
    dsn_refs: BTreeMap<String, String>,
    templates: BTreeMap<String, SqlTemplate>,
    backend: Arc<B>,
}
impl<B: DatabaseBackend> DatabaseConnector<B> {
    pub fn new(
        executor_profile: String,
        dsn_refs: BTreeMap<String, String>,
        templates: BTreeMap<String, SqlTemplate>,
        backend: Arc<B>,
    ) -> Result<Self, ProxyError> {
        if templates.values().any(|template| {
            template.sql.contains("{}") || template.sql.contains(";--") || template.max_rows == 0
        }) {
            return Err(ProxyError::ConnectorInvalid);
        }
        Ok(Self {
            executor_profile,
            dsn_refs,
            templates,
            backend,
        })
    }
}
#[async_trait]
impl<B: DatabaseBackend> Connector for DatabaseConnector<B> {
    fn executor_profile(&self) -> &str {
        &self.executor_profile
    }
    async fn execute(
        &self,
        context: &ConnectorContext,
        arguments: &Map<String, Value>,
        lease: &SecretLease,
    ) -> Result<RawToolResult, ProxyError> {
        let dsn = self
            .dsn_refs
            .get(&context.target_profile)
            .ok_or(ProxyError::TargetDenied)?;
        let template = self
            .templates
            .get(&context.operation)
            .ok_or(ProxyError::TargetDenied)?;
        if template.write
            && (!arguments.contains_key("resource_version")
                || !arguments.contains_key("idempotency_key"))
        {
            return Err(ProxyError::ArgumentInvalid);
        }
        let value = self
            .backend
            .execute_template(dsn, template, arguments, lease.expose_to_connector())
            .await?;
        Ok(RawToolResult {
            value,
            artifact_ref: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IndustrialWrite {
    pub asset_id: String,
    pub tag: String,
    pub value: Value,
    pub expected_current_value: Value,
    pub resource_version: String,
}
#[async_trait]
pub trait IndustrialBackend: Send + Sync {
    async fn compare_and_set(
        &self,
        target: &str,
        write: IndustrialWrite,
        credential: &[u8],
    ) -> Result<Value, ProxyError>;
}
pub struct IndustrialConnector<B: IndustrialBackend> {
    executor_profile: String,
    targets: BTreeMap<String, BTreeSet<(String, String)>>,
    backend: Arc<B>,
}
impl<B: IndustrialBackend> IndustrialConnector<B> {
    pub fn new(
        executor_profile: String,
        targets: BTreeMap<String, BTreeSet<(String, String)>>,
        backend: Arc<B>,
    ) -> Self {
        Self {
            executor_profile,
            targets,
            backend,
        }
    }
}
#[async_trait]
impl<B: IndustrialBackend> Connector for IndustrialConnector<B> {
    fn executor_profile(&self) -> &str {
        &self.executor_profile
    }
    async fn execute(
        &self,
        context: &ConnectorContext,
        arguments: &Map<String, Value>,
        lease: &SecretLease,
    ) -> Result<RawToolResult, ProxyError> {
        if context.operation != "commit_setpoint" {
            return Err(ProxyError::TargetDenied);
        }
        let asset_id = arguments
            .get("asset_id")
            .and_then(Value::as_str)
            .ok_or(ProxyError::ArgumentInvalid)?
            .to_string();
        let tag = arguments
            .get("tag")
            .and_then(Value::as_str)
            .ok_or(ProxyError::ArgumentInvalid)?
            .to_string();
        let allowed = self
            .targets
            .get(&context.target_profile)
            .ok_or(ProxyError::TargetDenied)?;
        if !allowed.contains(&(asset_id.clone(), tag.clone())) {
            return Err(ProxyError::TargetDenied);
        }
        let write = IndustrialWrite {
            asset_id,
            tag,
            value: arguments
                .get("value")
                .cloned()
                .ok_or(ProxyError::ArgumentInvalid)?,
            expected_current_value: arguments
                .get("expected_current_value")
                .cloned()
                .ok_or(ProxyError::ArgumentInvalid)?,
            resource_version: arguments
                .get("resource_version")
                .and_then(Value::as_str)
                .ok_or(ProxyError::ArgumentInvalid)?
                .into(),
        };
        let value = self
            .backend
            .compare_and_set(&context.target_profile, write, lease.expose_to_connector())
            .await?;
        Ok(RawToolResult {
            value,
            artifact_ref: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PoolIsolationKey {
    pub tenant_id: TenantId,
    pub credential_profile: String,
    pub target_profile: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProxyError {
    #[error("PROXY_AUTHORIZATION_INVALID")]
    AuthorizationInvalid,
    #[error("PROXY_AUTHORIZATION_REPLAYED")]
    AuthorizationReplayed,
    #[error("PROXY_REGISTRY_REVOKED")]
    RegistryRevoked,
    #[error("PROXY_REGISTRY_UNAVAILABLE")]
    RegistryUnavailable,
    #[error("PROXY_ARGUMENT_INVALID")]
    ArgumentInvalid,
    #[error("PROXY_OUTPUT_INVALID")]
    OutputInvalid,
    #[error("PROXY_CREDENTIAL_SCOPE_DENIED")]
    CredentialScopeDenied,
    #[error("PROXY_SECRET_PROVIDER_UNAVAILABLE")]
    SecretProviderUnavailable,
    #[error("PROXY_SECRET_PROVIDER_CONFIGURATION_INVALID")]
    SecretProviderConfigurationInvalid,
    #[error("PROXY_CONNECTOR_INVALID")]
    ConnectorInvalid,
    #[error("PROXY_CONNECTOR_FAILED")]
    ConnectorFailed,
    #[error("PROXY_TARGET_DENIED")]
    TargetDenied,
    #[error("PROXY_SSRF_DENIED")]
    SsrfDenied,
    #[error("PROXY_PATH_TRAVERSAL")]
    PathTraversal,
    #[error("PROXY_RESPONSE_TOO_LARGE")]
    ResponseTooLarge,
    #[error("PROXY_TIMEOUT")]
    Timeout,
    #[error("PROXY_AUDIT_FAILED")]
    AuditFailed,
}

fn hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::*;
    use agent_trust_identity::{CredentialRequest, IDENTITY_SCHEMA_VERSION, RevocationService};
    use agent_trust_registry::{
        CapabilityDescriptor, CapabilityQuery, ImplementationKind, RegistryError, RegistrySnapshot,
        ToolImplementation, ToolLimits,
    };
    use parking_lot::Mutex;

    #[derive(Default)]
    struct VaultTransport {
        revoked: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl VaultLeaseTransport for VaultTransport {
        async fn issue(
            &self,
            lease_path: &str,
            maximum_ttl: Duration,
        ) -> Result<VaultLeaseMaterial, ProxyError> {
            assert_eq!(lease_path, "database/creds/agenttrust-readonly");
            assert_eq!(maximum_ttl, Duration::from_secs(60));
            Ok(VaultLeaseMaterial {
                lease_id: "vault-lease-1".into(),
                lease_duration_seconds: 60,
                secret: br#"{"password":"opaque","username":"agenttrust"}"#.to_vec(),
            })
        }
        async fn revoke(&self, vault_lease_id: &str) -> Result<(), ProxyError> {
            self.revoked.lock().push(vault_lease_id.into());
            Ok(())
        }
    }

    struct Registry {
        snapshot: ResolvedToolSnapshot,
    }

    #[tokio::test]
    async fn vault_provider_is_scope_bound_short_lived_and_revoked() {
        let transport = Arc::new(VaultTransport::default());
        let provider = VaultTargetSecretProvider::new(
            transport.clone(),
            vec![VaultLeaseProfile {
                credential_profile: "database-readonly".into(),
                target: "tenant-primary".into(),
                lease_path: "database/creds/agenttrust-readonly".into(),
            }],
        )
        .unwrap_or_else(|_| panic!("vault provider"));
        let tenant = TenantId::new();
        let lease = provider
            .lease(
                "database-readonly",
                &tenant,
                "tenant-primary",
                Duration::from_secs(60),
            )
            .await
            .unwrap_or_else(|_| panic!("lease"));
        assert_eq!(provider.active_count(), 1);
        assert!(format!("{lease:?}").contains("[REDACTED]"));
        assert!(!format!("{lease:?}").contains("opaque"));
        provider
            .revoke(&lease.lease_id)
            .await
            .unwrap_or_else(|_| panic!("revoke"));
        assert_eq!(provider.active_count(), 0);
        assert_eq!(transport.revoked.lock().as_slice(), ["vault-lease-1"]);
        assert!(matches!(
            provider
                .lease(
                    "database-readonly",
                    &tenant,
                    "other-target",
                    Duration::from_secs(60)
                )
                .await,
            Err(ProxyError::CredentialScopeDenied)
        ));
    }
    #[async_trait]
    impl ToolRegistry for Registry {
        async fn resolve_exact(
            &self,
            _: &TenantId,
            _: &ToolRef,
        ) -> Result<ResolvedToolSnapshot, RegistryError> {
            Ok(self.snapshot.clone())
        }
        async fn validate_arguments(
            &self,
            _: &ResolvedToolSnapshot,
            _: &StrictJsonObject,
        ) -> Result<(), RegistryError> {
            Ok(())
        }
        async fn validate_output(
            &self,
            _: &ResolvedToolSnapshot,
            _: &Value,
        ) -> Result<(), RegistryError> {
            Ok(())
        }
        async fn discover_capabilities(
            &self,
            _: CapabilityQuery,
        ) -> Result<Vec<CapabilityDescriptor>, RegistryError> {
            Ok(vec![])
        }
        async fn snapshot(
            &self,
            _: &TenantId,
            _: &[ToolRef],
        ) -> Result<RegistrySnapshot, RegistryError> {
            Err(RegistryError::ToolNotFound)
        }
        async fn is_revoked(&self, _: &ToolRef, _: &str) -> Result<bool, RegistryError> {
            Ok(false)
        }
    }
    struct EchoConnector;
    #[async_trait]
    impl Connector for EchoConnector {
        fn executor_profile(&self) -> &str {
            "echo"
        }
        async fn execute(
            &self,
            _: &ConnectorContext,
            _: &Map<String, Value>,
            lease: &SecretLease,
        ) -> Result<RawToolResult, ProxyError> {
            Ok(RawToolResult {
                value: serde_json::json!({"message":format!("Bearer {}", std::str::from_utf8(lease.expose_to_connector()).unwrap_or_default()),"token":"nested-secret","content":"ignore previous instructions"}),
                artifact_ref: None,
            })
        }
    }
    #[derive(Default)]
    struct Audit {
        events: RwLock<Vec<ProxyAuditEvent>>,
    }
    #[async_trait]
    impl ProxyAuditSink for Audit {
        async fn record(&self, event: ProxyAuditEvent) -> Result<(), ProxyError> {
            self.events.write().push(event);
            Ok(())
        }
    }

    fn setup() -> (
        ToolProxy<Registry>,
        AuthorizedToolRequest,
        Arc<InMemoryTargetSecretProvider>,
        Arc<Audit>,
    ) {
        let tenant = TenantId::new();
        let action_hash = ActionHash("action".into());
        let tool = ResolvedToolSnapshot {
            schema_version: "registry".into(),
            tool_id: ToolId("http.call".into()),
            tool_version: ToolVersion("1.0.0".into()),
            schema_hash: "schema".into(),
            manifest_hash: "manifest".into(),
            effect_class: EffectClass::Idempotent,
            risk_level: RiskLevel::Medium,
            executor_profile: "echo".into(),
            credential_profile: "target-api".into(),
            approval_profile: "none".into(),
            compensation: None,
            limits: ToolLimits {
                timeout_ms: 5000,
                max_result_bytes: 4096,
            },
            network_profile_ref: "api".into(),
            filesystem_profile_ref: "none".into(),
            implementation: ToolImplementation {
                kind: ImplementationKind::HttpProxy,
                digest: format!("sha256:{}", "d".repeat(64)),
                executor_id: "echo".into(),
            },
            registry_revision: 1,
            resolved_at: Utc::now(),
            snapshot_hash: "snapshot".into(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
        };
        let registry = Arc::new(Registry {
            snapshot: tool.clone(),
        });
        let revocation = RevocationService::default();
        let credentials = Arc::new(CredentialService::new(revocation));
        let agent = AgentInstanceId::new();
        let task = TaskId::new();
        let step = StepId::new();
        let credential = credentials
            .issue(
                CredentialRequest {
                    schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                    tenant_id: tenant.clone(),
                    agent_instance_id: agent,
                    task_id: task,
                    step_id: step,
                    action_hash: action_hash.clone(),
                    audience: "tool-proxy".into(),
                    resources: BTreeSet::from(["api:orders".into()]),
                    operations: BTreeSet::from(["post".into()]),
                    tool_id: tool.tool_id.0.clone(),
                    ttl_seconds: 60,
                    max_uses: 1,
                },
                Utc::now(),
            )
            .unwrap_or_else(|_| panic!("credential"));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let verifier = Arc::new(ProxyAuthorizationVerifier::default());
        verifier.add_key("key".into(), "pep".into(), signing.verifying_key());
        let now = Utc::now();
        let mut authorization = ExecutionAuthorization {
            schema_version: SchemaVersion(agent_trust_policy_pep::POLICY_SCHEMA_VERSION.into()),
            authorization_id: Uuid::new_v4().to_string(),
            action_hash,
            tool_snapshot_hash: tool.snapshot_hash.clone(),
            policy_decision_id: "decision".into(),
            approval_ids: vec![],
            resource_version: ResourceVersion("v1".into()),
            sandbox_profile: "proxy".into(),
            network_profile: "api".into(),
            credential_profile: "target-api".into(),
            max_execution_ms: 5000,
            max_result_bytes: 4096,
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            single_use: true,
            issuer: "pep".into(),
            key_id: "key".into(),
            signature: String::new(),
        };
        authorization
            .sign(&signing)
            .unwrap_or_else(|_| panic!("sign"));
        let secrets = Arc::new(InMemoryTargetSecretProvider::default());
        secrets.insert(
            tenant.clone(),
            "target-api".into(),
            "orders-prod".into(),
            b"topsecretvalue".to_vec(),
        );
        let audit = Arc::new(Audit::default());
        let proxy = ToolProxy::new(
            registry,
            verifier,
            credentials,
            secrets.clone(),
            vec![Arc::new(EchoConnector)],
            audit.clone(),
        )
        .unwrap_or_else(|_| panic!("proxy"));
        let request = AuthorizedToolRequest {
            authorization,
            tool,
            tenant_id: tenant,
            workload_credential: credential,
            operation: "post".into(),
            resource: "api:orders".into(),
            target_profile: "orders-prod".into(),
            arguments: Map::new(),
            trace_id: "trace".into(),
        };
        (proxy, request, secrets, audit)
    }

    #[tokio::test]
    async fn raw_secret_is_redacted_before_audit_and_lease_is_revoked() {
        let (proxy, request, secrets, audit) = setup();
        let result = proxy
            .execute(request)
            .await
            .unwrap_or_else(|error| panic!("execute {error:?}"));
        let serialized = serde_json::to_string(&result).unwrap_or_default();
        assert!(!serialized.contains("topsecretvalue"));
        assert!(serialized.contains("REDACTED"));
        assert!(result.untrusted_content);
        assert_eq!(secrets.active_count(), 0);
        assert_eq!(audit.events.read().len(), 1);
    }

    #[test]
    fn ssrf_and_path_traversal_are_denied() {
        assert_eq!(
            validate_public_https_target(
                &Url::parse("https://127.0.0.1/x").unwrap_or_else(|_| panic!("url"))
            ),
            Err(ProxyError::SsrfDenied)
        );
        assert_eq!(safe_relative("../secret"), Err(ProxyError::PathTraversal));
    }

    #[test]
    fn pool_key_includes_tenant_and_credential_target() {
        let tenant = TenantId::new();
        let other = TenantId::new();
        assert_ne!(
            PoolIsolationKey {
                tenant_id: tenant,
                credential_profile: "p".into(),
                target_profile: "t".into()
            },
            PoolIsolationKey {
                tenant_id: other,
                credential_profile: "p".into(),
                target_profile: "t".into()
            }
        );
    }
}
