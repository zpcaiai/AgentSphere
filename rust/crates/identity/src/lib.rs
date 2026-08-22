//! Verifiable workload identities, short-lived task credentials, and revocation.

use agent_trust_contracts::{ActionHash, AgentInstanceId, SchemaVersion, StepId, TaskId, TenantId};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;

pub const IDENTITY_SCHEMA_VERSION: &str = "agenttrust.identity.v1";

mod production;
pub mod server;
pub use production::{
    CredentialAuthoritySigner, CredentialLifecycleReceipt, CredentialLifecycleRequest,
    IdentityResponseProtector, PostgresCredentialAuthority,
    SignedWorkloadCredentialConsumptionReceipt, WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE,
    WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION,
    WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION, WorkloadCredentialConsumptionRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProfile {
    Development,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPrincipal {
    pub schema_version: SchemaVersion,
    pub subject: String,
    pub organization_id: String,
    pub tenant_id: TenantId,
    pub owner_subject: String,
    pub roles: BTreeSet<String>,
    pub auth_strength: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub schema_version: SchemaVersion,
    pub agent_instance_id: AgentInstanceId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub tenant_id: TenantId,
    pub owner_subject: String,
    pub action_hash: ActionHash,
    pub policy_decision_id: String,
    pub trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub schema_version: SchemaVersion,
    pub principal: AgentPrincipal,
    pub workload: WorkloadIdentity,
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    pub token_id: String,
    pub revocation_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadClaims {
    schema_version: String,
    iss: String,
    aud: String,
    sub: String,
    jti: String,
    tenant_id: TenantId,
    agent_instance_id: AgentInstanceId,
    task_id: TaskId,
    step_id: StepId,
    owner_subject: String,
    action_hash: ActionHash,
    policy_decision_id: String,
    roles: BTreeSet<String>,
    auth_strength: String,
    trust_level: String,
    revocation_epoch: u64,
    nbf: i64,
    iat: i64,
    exp: i64,
}

#[derive(Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

pub struct SensitiveToken(String);

impl SensitiveToken {
    pub fn expose_to_transport(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SensitiveToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveToken([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct WorkloadTokenRequest {
    pub principal: AgentPrincipal,
    pub workload: WorkloadIdentity,
    pub audience: String,
    pub ttl: chrono::Duration,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct CredentialHandle(pub String);

impl fmt::Debug for CredentialHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialHandle([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub schema_version: SchemaVersion,
    pub tenant_id: TenantId,
    pub agent_instance_id: AgentInstanceId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub audience: String,
    pub resources: BTreeSet<String>,
    pub operations: BTreeSet<String>,
    pub tool_id: String,
    pub ttl_seconds: u64,
    pub max_uses: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    pub schema_version: SchemaVersion,
    pub credential_id: String,
    pub tenant_id: TenantId,
    pub agent_instance_id: AgentInstanceId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub audience: String,
    pub resources: BTreeSet<String>,
    pub operations: BTreeSet<String>,
    pub tool_id: String,
    pub revocation_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
}

#[derive(Clone)]
pub struct TrustBundleSnapshot {
    pub version: String,
    pub issuer: String,
    pub keys: BTreeMap<String, VerifyingKey>,
    pub valid_until: DateTime<Utc>,
}

pub trait TrustBundleProvider: Send + Sync {
    fn current(&self) -> Result<TrustBundleSnapshot, IdentityError>;
}

#[derive(Clone)]
pub struct StaticTrustBundle(TrustBundleSnapshot);
impl StaticTrustBundle {
    pub fn new(snapshot: TrustBundleSnapshot) -> Self {
        Self(snapshot)
    }
}
impl TrustBundleProvider for StaticTrustBundle {
    fn current(&self) -> Result<TrustBundleSnapshot, IdentityError> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct RevocationState {
    minimum_epoch_by_tenant: BTreeMap<TenantId, u64>,
    revoked_tokens: BTreeSet<String>,
    revoked_credentials: BTreeSet<String>,
    revoked_tasks: BTreeSet<TaskId>,
    revoked_agents: BTreeSet<AgentInstanceId>,
    frozen_tasks: BTreeSet<TaskId>,
}

#[derive(Clone, Default)]
pub struct RevocationService {
    state: Arc<RwLock<RevocationState>>,
}

impl RevocationService {
    pub fn revoke_credential(&self, handle: &CredentialHandle) {
        self.state
            .write()
            .revoked_credentials
            .insert(handle.0.clone());
    }
    pub fn revoke_token(&self, token_id: impl Into<String>) {
        self.state.write().revoked_tokens.insert(token_id.into());
    }
    pub fn revoke_task(&self, task: &TaskId) {
        self.state.write().revoked_tasks.insert(task.clone());
    }
    pub fn revoke_agent(&self, agent: &AgentInstanceId) {
        self.state.write().revoked_agents.insert(agent.clone());
    }
    pub fn freeze_task(&self, task: &TaskId) {
        self.state.write().frozen_tasks.insert(task.clone());
    }
    pub fn bump_tenant_epoch(&self, tenant: &TenantId) -> u64 {
        let mut state = self.state.write();
        let epoch = state
            .minimum_epoch_by_tenant
            .entry(tenant.clone())
            .or_insert(0);
        *epoch += 1;
        *epoch
    }
    pub fn current_epoch(&self, tenant: &TenantId) -> u64 {
        *self
            .state
            .read()
            .minimum_epoch_by_tenant
            .get(tenant)
            .unwrap_or(&0)
    }

    fn check(
        &self,
        token_id: Option<&str>,
        credential_id: Option<&str>,
        tenant: &TenantId,
        task: &TaskId,
        agent: &AgentInstanceId,
        epoch: u64,
    ) -> Result<(), IdentityError> {
        let state = self.state.read();
        if epoch < *state.minimum_epoch_by_tenant.get(tenant).unwrap_or(&0)
            || token_id.is_some_and(|id| state.revoked_tokens.contains(id))
            || credential_id.is_some_and(|id| state.revoked_credentials.contains(id))
            || state.revoked_tasks.contains(task)
            || state.revoked_agents.contains(agent)
        {
            return Err(IdentityError::Revoked);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct WorkloadTokenIssuer {
    issuer: String,
    key_id: String,
    signing_key: Arc<SigningKey>,
    revocation: RevocationService,
}

impl WorkloadTokenIssuer {
    pub fn new(
        profile: RuntimeProfile,
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: Option<SigningKey>,
        revocation: RevocationService,
    ) -> Result<Self, IdentityError> {
        let issuer = issuer.into();
        let key_id = key_id.into();
        if profile == RuntimeProfile::Production
            && (issuer.starts_with("dev:") || key_id.starts_with("dev-") || signing_key.is_none())
        {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        Ok(Self {
            issuer,
            key_id,
            signing_key: Arc::new(signing_key.ok_or(IdentityError::ProductionTrustNotConfigured)?),
            revocation,
        })
    }

    pub fn issue(
        &self,
        request: WorkloadTokenRequest,
        now: DateTime<Utc>,
    ) -> Result<SensitiveToken, IdentityError> {
        if request.ttl <= chrono::Duration::zero() || request.ttl > chrono::Duration::minutes(15) {
            return Err(IdentityError::InvalidTtl);
        }
        if request.principal.tenant_id != request.workload.tenant_id
            || request.principal.owner_subject != request.workload.owner_subject
        {
            return Err(IdentityError::TenantMismatch);
        }
        if self
            .revocation
            .state
            .read()
            .frozen_tasks
            .contains(&request.workload.task_id)
        {
            return Err(IdentityError::Revoked);
        }
        let claims = WorkloadClaims {
            schema_version: IDENTITY_SCHEMA_VERSION.into(),
            iss: self.issuer.clone(),
            aud: request.audience,
            sub: format!("agent:{}", request.workload.agent_instance_id.0),
            jti: Uuid::new_v4().to_string(),
            tenant_id: request.workload.tenant_id.clone(),
            agent_instance_id: request.workload.agent_instance_id.clone(),
            task_id: request.workload.task_id.clone(),
            step_id: request.workload.step_id.clone(),
            owner_subject: request.workload.owner_subject.clone(),
            action_hash: request.workload.action_hash.clone(),
            policy_decision_id: request.workload.policy_decision_id.clone(),
            roles: request.principal.roles,
            auth_strength: request.principal.auth_strength,
            trust_level: request.workload.trust_level,
            revocation_epoch: self.revocation.current_epoch(&request.workload.tenant_id),
            nbf: now.timestamp() - 2,
            iat: now.timestamp(),
            exp: (now + request.ttl).timestamp(),
        };
        let header = JwtHeader {
            alg: "EdDSA".into(),
            typ: "JWT".into(),
            kid: self.key_id.clone(),
        };
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| IdentityError::TokenInvalid)?);
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).map_err(|_| IdentityError::TokenInvalid)?);
        let signing_input = format!("{header}.{payload}");
        let signature =
            URL_SAFE_NO_PAD.encode(self.signing_key.sign(signing_input.as_bytes()).to_bytes());
        Ok(SensitiveToken(format!("{signing_input}.{signature}")))
    }
}

#[derive(Clone)]
pub struct WorkloadTokenVerifier {
    expected_issuer: String,
    trust: Arc<dyn TrustBundleProvider>,
    revocation: RevocationService,
    clock_skew_seconds: i64,
}

impl WorkloadTokenVerifier {
    pub fn new(
        expected_issuer: impl Into<String>,
        trust: Arc<dyn TrustBundleProvider>,
        revocation: RevocationService,
        clock_skew_seconds: i64,
    ) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            trust,
            revocation,
            clock_skew_seconds: clock_skew_seconds.clamp(0, 60),
        }
    }

    pub fn verify(
        &self,
        token: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthContext, IdentityError> {
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(IdentityError::TokenInvalid);
        }
        let header: JwtHeader = decode_json(segments[0])?;
        if header.alg != "EdDSA" || header.typ != "JWT" {
            return Err(IdentityError::AlgorithmDenied);
        }
        let claims: WorkloadClaims = decode_json(segments[1])?;
        if claims.schema_version != IDENTITY_SCHEMA_VERSION {
            return Err(IdentityError::TokenInvalid);
        }
        if claims.iss != self.expected_issuer || claims.aud != audience {
            return Err(IdentityError::IssuerOrAudience);
        }
        let now_ts = now.timestamp();
        if now_ts + self.clock_skew_seconds < claims.nbf
            || now_ts - self.clock_skew_seconds >= claims.exp
        {
            return Err(IdentityError::ExpiredOrNotYetValid);
        }
        let bundle = self.trust.current()?;
        if now >= bundle.valid_until || bundle.issuer != claims.iss {
            return Err(IdentityError::TrustBundleUnavailable);
        }
        let key = bundle
            .keys
            .get(&header.kid)
            .ok_or(IdentityError::UnknownKey)?;
        let signature_raw = URL_SAFE_NO_PAD
            .decode(segments[2])
            .map_err(|_| IdentityError::TokenInvalid)?;
        let signature =
            Signature::from_slice(&signature_raw).map_err(|_| IdentityError::TokenInvalid)?;
        key.verify(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
        )
        .map_err(|_| IdentityError::SignatureInvalid)?;
        self.revocation.check(
            Some(&claims.jti),
            None,
            &claims.tenant_id,
            &claims.task_id,
            &claims.agent_instance_id,
            claims.revocation_epoch,
        )?;
        Ok(AuthContext {
            schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
            principal: AgentPrincipal {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                subject: claims.sub,
                organization_id: String::new(),
                tenant_id: claims.tenant_id.clone(),
                owner_subject: claims.owner_subject.clone(),
                roles: claims.roles,
                auth_strength: claims.auth_strength,
            },
            workload: WorkloadIdentity {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                agent_instance_id: claims.agent_instance_id,
                task_id: claims.task_id,
                step_id: claims.step_id,
                tenant_id: claims.tenant_id,
                owner_subject: claims.owner_subject,
                action_hash: claims.action_hash,
                policy_decision_id: claims.policy_decision_id,
                trust_level: claims.trust_level,
            },
            issuer: claims.iss,
            audience: claims.aud,
            key_id: header.kid,
            token_id: claims.jti,
            revocation_epoch: claims.revocation_epoch,
            issued_at: DateTime::from_timestamp(claims.iat, 0)
                .ok_or(IdentityError::TokenInvalid)?,
            expires_at: DateTime::from_timestamp(claims.exp, 0)
                .ok_or(IdentityError::TokenInvalid)?,
        })
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, IdentityError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| IdentityError::TokenInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| IdentityError::TokenInvalid)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: i64,
    nbf: Option<i64>,
    iat: i64,
    azp: Option<String>,
    nonce: Option<String>,
    #[serde(default)]
    roles: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub enum FederatedJwk {
    RsaRs256 { modulus: Vec<u8>, exponent: Vec<u8> },
    EcP256Es256 { x: [u8; 32], y: [u8; 32] },
    OkpEd25519 { public_key: [u8; 32] },
}

#[derive(Debug, Clone)]
pub struct FederatedTrustBundleSnapshot {
    pub version: String,
    pub issuer: String,
    pub keys: BTreeMap<String, FederatedJwk>,
    pub valid_until: DateTime<Utc>,
}

impl FederatedTrustBundleSnapshot {
    pub fn from_jwks(
        issuer: String,
        version: String,
        valid_until: DateTime<Utc>,
        jwks_json: &[u8],
    ) -> Result<Self, IdentityError> {
        #[derive(Deserialize)]
        struct Jwks {
            keys: Vec<Jwk>,
        }
        #[derive(Deserialize)]
        struct Jwk {
            kid: String,
            kty: String,
            alg: String,
            #[serde(default, rename = "use")]
            usage: Option<String>,
            #[serde(default)]
            key_ops: Vec<String>,
            #[serde(default)]
            crv: Option<String>,
            #[serde(default)]
            n: Option<String>,
            #[serde(default)]
            e: Option<String>,
            #[serde(default)]
            x: Option<String>,
            #[serde(default)]
            y: Option<String>,
        }
        let document: Jwks =
            serde_json::from_slice(jwks_json).map_err(|_| IdentityError::JwksInvalid)?;
        if issuer.is_empty()
            || version.is_empty()
            || document.keys.is_empty()
            || document.keys.len() > 100
        {
            return Err(IdentityError::JwksInvalid);
        }
        let mut keys = BTreeMap::new();
        for item in document.keys {
            if item.kid.is_empty()
                || item.usage.as_deref().is_some_and(|usage| usage != "sig")
                || !item.key_ops.is_empty()
                    && !item.key_ops.iter().any(|operation| operation == "verify")
            {
                return Err(IdentityError::JwksInvalid);
            }
            let key = match (item.kty.as_str(), item.alg.as_str()) {
                ("RSA", "RS256") => {
                    let modulus = decode_jwk_component(item.n.as_deref())?;
                    let exponent = decode_jwk_component(item.e.as_deref())?;
                    if modulus.len() < 256 || modulus.len() > 1024 || exponent.is_empty() {
                        return Err(IdentityError::JwksInvalid);
                    }
                    FederatedJwk::RsaRs256 { modulus, exponent }
                }
                ("EC", "ES256") if item.crv.as_deref() == Some("P-256") => {
                    let x: [u8; 32] = decode_jwk_component(item.x.as_deref())?
                        .try_into()
                        .map_err(|_| IdentityError::JwksInvalid)?;
                    let y: [u8; 32] = decode_jwk_component(item.y.as_deref())?
                        .try_into()
                        .map_err(|_| IdentityError::JwksInvalid)?;
                    FederatedJwk::EcP256Es256 { x, y }
                }
                ("OKP", "EdDSA") if item.crv.as_deref() == Some("Ed25519") => {
                    let public_key: [u8; 32] = decode_jwk_component(item.x.as_deref())?
                        .try_into()
                        .map_err(|_| IdentityError::JwksInvalid)?;
                    FederatedJwk::OkpEd25519 { public_key }
                }
                _ => return Err(IdentityError::AlgorithmDenied),
            };
            if keys.insert(item.kid, key).is_some() {
                return Err(IdentityError::JwksInvalid);
            }
        }
        Ok(Self {
            version,
            issuer,
            keys,
            valid_until,
        })
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

fn decode_jwk_component(value: Option<&str>) -> Result<Vec<u8>, IdentityError> {
    URL_SAFE_NO_PAD
        .decode(value.ok_or(IdentityError::JwksInvalid)?)
        .map_err(|_| IdentityError::JwksInvalid)
}

pub trait FederatedTrustBundleProvider: Send + Sync {
    fn current(&self) -> Result<FederatedTrustBundleSnapshot, IdentityError>;
}

#[derive(Clone)]
pub struct StaticFederatedTrustBundle(FederatedTrustBundleSnapshot);
impl StaticFederatedTrustBundle {
    pub fn new(snapshot: FederatedTrustBundleSnapshot) -> Self {
        Self(snapshot)
    }
}
impl FederatedTrustBundleProvider for StaticFederatedTrustBundle {
    fn current(&self) -> Result<FederatedTrustBundleSnapshot, IdentityError> {
        Ok(self.0.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}
impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
    fn multiple(&self) -> bool {
        matches!(self, Self::Many(values) if values.len() > 1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnterpriseOidcClaims {
    iss: String,
    aud: AudienceClaim,
    sub: String,
    exp: i64,
    nbf: Option<i64>,
    iat: i64,
    azp: Option<String>,
    nonce: Option<String>,
    #[serde(default)]
    roles: BTreeSet<String>,
}

/// Enterprise OIDC verifier for the asymmetric algorithms commonly published
/// by real IdPs. JWKS refresh/network policy remains owned by the injected
/// trust-bundle provider; this verifier never trusts tenant claims from JWTs.
pub struct EnterpriseOidcJwtVerifier {
    expected_issuer: String,
    expected_audience: String,
    expected_authorized_party: Option<String>,
    trust: Arc<dyn FederatedTrustBundleProvider>,
    subject_mapping: RwLock<BTreeMap<String, AgentPrincipal>>,
    clock_skew_seconds: i64,
}

impl EnterpriseOidcJwtVerifier {
    pub fn new(
        expected_issuer: String,
        expected_audience: String,
        expected_authorized_party: Option<String>,
        trust: Arc<dyn FederatedTrustBundleProvider>,
        clock_skew_seconds: i64,
    ) -> Result<Self, IdentityError> {
        if !expected_issuer.starts_with("https://") || expected_audience.is_empty() {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        Ok(Self {
            expected_issuer,
            expected_audience,
            expected_authorized_party,
            trust,
            subject_mapping: RwLock::new(BTreeMap::new()),
            clock_skew_seconds: clock_skew_seconds.clamp(0, 60),
        })
    }

    pub fn map_subject(&self, subject: String, principal: AgentPrincipal) {
        self.subject_mapping.write().insert(subject, principal);
    }

    pub fn verify_oidc(
        &self,
        token: &str,
        expected_nonce: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<AgentPrincipal, IdentityError> {
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(IdentityError::TokenInvalid);
        }
        let header: JwtHeader = decode_json(segments[0])?;
        if header.typ != "JWT" || !matches!(header.alg.as_str(), "RS256" | "ES256" | "EdDSA") {
            return Err(IdentityError::AlgorithmDenied);
        }
        let claims: EnterpriseOidcClaims = decode_json(segments[1])?;
        if claims.iss != self.expected_issuer
            || !claims.aud.contains(&self.expected_audience)
            || self
                .expected_authorized_party
                .as_ref()
                .is_some_and(|expected| claims.azp.as_ref() != Some(expected))
            || claims.aud.multiple() && self.expected_authorized_party.is_none()
        {
            return Err(IdentityError::IssuerOrAudience);
        }
        if expected_nonce.is_some_and(|nonce| claims.nonce.as_deref() != Some(nonce)) {
            return Err(IdentityError::NonceInvalid);
        }
        let now_ts = now.timestamp();
        if now_ts - self.clock_skew_seconds >= claims.exp
            || now_ts + self.clock_skew_seconds < claims.nbf.unwrap_or(claims.iat)
        {
            return Err(IdentityError::ExpiredOrNotYetValid);
        }
        let bundle = self.trust.current()?;
        if bundle.issuer != claims.iss || now >= bundle.valid_until {
            return Err(IdentityError::TrustBundleUnavailable);
        }
        let key = bundle
            .keys
            .get(&header.kid)
            .ok_or(IdentityError::UnknownKey)?;
        let signature = URL_SAFE_NO_PAD
            .decode(segments[2])
            .map_err(|_| IdentityError::TokenInvalid)?;
        let signing_input = format!("{}.{}", segments[0], segments[1]);
        verify_federated_signature(key, &header.alg, signing_input.as_bytes(), &signature)?;
        let mut principal = self
            .subject_mapping
            .read()
            .get(&claims.sub)
            .cloned()
            .ok_or(IdentityError::OwnershipUnknown)?;
        principal.roles = principal
            .roles
            .intersection(&claims.roles)
            .cloned()
            .collect();
        Ok(principal)
    }
}

#[async_trait]
impl IdentityFederationPort for EnterpriseOidcJwtVerifier {
    async fn verify_federated_token(
        &self,
        token: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentPrincipal, IdentityError> {
        if audience != self.expected_audience {
            return Err(IdentityError::IssuerOrAudience);
        }
        self.verify_oidc(token, None, now)
    }
}

fn verify_federated_signature(
    key: &FederatedJwk,
    algorithm: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    let result = match (key, algorithm) {
        (FederatedJwk::RsaRs256 { modulus, exponent }, "RS256") => RsaPublicKeyComponents {
            n: modulus.as_slice(),
            e: exponent.as_slice(),
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature),
        (FederatedJwk::EcP256Es256 { x, y }, "ES256") => {
            let mut public_key = Vec::with_capacity(65);
            public_key.push(4);
            public_key.extend_from_slice(x);
            public_key.extend_from_slice(y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key).verify(message, signature)
        }
        (FederatedJwk::OkpEd25519 { public_key }, "EdDSA") => {
            UnparsedPublicKey::new(&ED25519, public_key).verify(message, signature)
        }
        _ => return Err(IdentityError::AlgorithmDenied),
    };
    result.map_err(|_| IdentityError::SignatureInvalid)
}

/// OIDC verifier with a trusted JWKS snapshot and a server-side tenant mapping.
/// Tenant and organization are never accepted from token-controlled custom claims.
pub struct OidcJwtVerifier {
    expected_issuer: String,
    expected_audience: String,
    expected_authorized_party: Option<String>,
    trust: Arc<dyn TrustBundleProvider>,
    subject_mapping: RwLock<BTreeMap<String, AgentPrincipal>>,
    clock_skew_seconds: i64,
}

impl OidcJwtVerifier {
    pub fn new(
        expected_issuer: String,
        expected_audience: String,
        expected_authorized_party: Option<String>,
        trust: Arc<dyn TrustBundleProvider>,
        clock_skew_seconds: i64,
    ) -> Result<Self, IdentityError> {
        if !expected_issuer.starts_with("https://") || expected_audience.is_empty() {
            return Err(IdentityError::ProductionTrustNotConfigured);
        }
        Ok(Self {
            expected_issuer,
            expected_audience,
            expected_authorized_party,
            trust,
            subject_mapping: RwLock::new(BTreeMap::new()),
            clock_skew_seconds: clock_skew_seconds.clamp(0, 60),
        })
    }
    pub fn map_subject(&self, subject: String, principal: AgentPrincipal) {
        self.subject_mapping.write().insert(subject, principal);
    }
    pub fn verify_oidc(
        &self,
        token: &str,
        expected_nonce: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<AgentPrincipal, IdentityError> {
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(IdentityError::TokenInvalid);
        }
        let header: JwtHeader = decode_json(segments[0])?;
        if header.alg != "EdDSA" || header.typ != "JWT" {
            return Err(IdentityError::AlgorithmDenied);
        }
        let claims: OidcClaims = decode_json(segments[1])?;
        if claims.iss != self.expected_issuer
            || claims.aud != self.expected_audience
            || self
                .expected_authorized_party
                .as_ref()
                .is_some_and(|expected| claims.azp.as_ref() != Some(expected))
        {
            return Err(IdentityError::IssuerOrAudience);
        }
        if expected_nonce.is_some_and(|nonce| claims.nonce.as_deref() != Some(nonce)) {
            return Err(IdentityError::NonceInvalid);
        }
        let now_ts = now.timestamp();
        if now_ts - self.clock_skew_seconds >= claims.exp
            || now_ts + self.clock_skew_seconds < claims.nbf.unwrap_or(claims.iat)
        {
            return Err(IdentityError::ExpiredOrNotYetValid);
        }
        let bundle = self.trust.current()?;
        if bundle.issuer != claims.iss || now >= bundle.valid_until {
            return Err(IdentityError::TrustBundleUnavailable);
        }
        let key = bundle
            .keys
            .get(&header.kid)
            .ok_or(IdentityError::UnknownKey)?;
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(segments[2])
                .map_err(|_| IdentityError::TokenInvalid)?,
        )
        .map_err(|_| IdentityError::TokenInvalid)?;
        key.verify(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
        )
        .map_err(|_| IdentityError::SignatureInvalid)?;
        let mut principal = self
            .subject_mapping
            .read()
            .get(&claims.sub)
            .cloned()
            .ok_or(IdentityError::OwnershipUnknown)?;
        principal.roles = principal
            .roles
            .intersection(&claims.roles)
            .cloned()
            .collect();
        Ok(principal)
    }
}

#[async_trait]
impl IdentityFederationPort for OidcJwtVerifier {
    async fn verify_federated_token(
        &self,
        token: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentPrincipal, IdentityError> {
        if audience != self.expected_audience {
            return Err(IdentityError::IssuerOrAudience);
        }
        self.verify_oidc(token, None, now)
    }
}

/// mTLS identities are resolved by certificate fingerprint through a trusted server-side map.
#[derive(Default)]
pub struct MtlsIdentityVerifier {
    mappings: RwLock<BTreeMap<String, AgentPrincipal>>,
}
impl MtlsIdentityVerifier {
    pub fn register_fingerprint(
        &self,
        sha256_fingerprint: String,
        principal: AgentPrincipal,
    ) -> Result<(), IdentityError> {
        if sha256_fingerprint.len() != 64
            || !sha256_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(IdentityError::CertificateInvalid);
        }
        self.mappings
            .write()
            .insert(sha256_fingerprint.to_ascii_lowercase(), principal);
        Ok(())
    }
    pub fn verify_fingerprint(
        &self,
        sha256_fingerprint: &str,
    ) -> Result<AgentPrincipal, IdentityError> {
        self.mappings
            .read()
            .get(&sha256_fingerprint.to_ascii_lowercase())
            .cloned()
            .ok_or(IdentityError::CertificateInvalid)
    }
}

struct CredentialRecord {
    claims: CredentialClaims,
    remaining_uses: u32,
}

#[derive(Clone)]
pub struct CredentialService {
    records: Arc<RwLock<BTreeMap<String, CredentialRecord>>>,
    revocation: RevocationService,
}

impl CredentialService {
    pub fn new(revocation: RevocationService) -> Self {
        Self {
            records: Arc::new(RwLock::new(BTreeMap::new())),
            revocation,
        }
    }

    pub fn issue(
        &self,
        request: CredentialRequest,
        now: DateTime<Utc>,
    ) -> Result<CredentialHandle, IdentityError> {
        if request.schema_version.0 != IDENTITY_SCHEMA_VERSION
            || request.max_uses == 0
            || request.ttl_seconds == 0
            || request.ttl_seconds > 900
            || request.resources.is_empty()
            || request.operations.is_empty()
        {
            return Err(IdentityError::CredentialScopeInvalid);
        }
        if self
            .revocation
            .state
            .read()
            .frozen_tasks
            .contains(&request.task_id)
        {
            return Err(IdentityError::Revoked);
        }
        let credential_id = Uuid::new_v4().to_string();
        let claims = CredentialClaims {
            schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
            credential_id: credential_id.clone(),
            tenant_id: request.tenant_id.clone(),
            agent_instance_id: request.agent_instance_id,
            task_id: request.task_id,
            step_id: request.step_id,
            action_hash: request.action_hash,
            audience: request.audience,
            resources: request.resources,
            operations: request.operations,
            tool_id: request.tool_id,
            revocation_epoch: self.revocation.current_epoch(&request.tenant_id),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(request.ttl_seconds as i64),
            max_uses: request.max_uses,
        };
        self.records.write().insert(
            credential_id.clone(),
            CredentialRecord {
                remaining_uses: claims.max_uses,
                claims,
            },
        );
        Ok(CredentialHandle(credential_id))
    }

    pub fn validate_and_consume(
        &self,
        handle: &CredentialHandle,
        audience: &str,
        action_hash: &ActionHash,
        resource: &str,
        operation: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialClaims, IdentityError> {
        let mut records = self.records.write();
        let record = records
            .get_mut(&handle.0)
            .ok_or(IdentityError::CredentialNotFound)?;
        self.revocation.check(
            None,
            Some(&handle.0),
            &record.claims.tenant_id,
            &record.claims.task_id,
            &record.claims.agent_instance_id,
            record.claims.revocation_epoch,
        )?;
        if now < record.claims.issued_at || now >= record.claims.expires_at {
            return Err(IdentityError::ExpiredOrNotYetValid);
        }
        if record.claims.audience != audience
            || &record.claims.action_hash != action_hash
            || !record.claims.resources.contains(resource)
            || !record.claims.operations.contains(operation)
        {
            return Err(IdentityError::CredentialScopeInvalid);
        }
        if record.remaining_uses == 0 {
            return Err(IdentityError::UsageExceeded);
        }
        record.remaining_uses -= 1;
        Ok(record.claims.clone())
    }

    pub fn remaining_uses(&self, handle: &CredentialHandle) -> Option<u32> {
        self.records
            .read()
            .get(&handle.0)
            .map(|record| record.remaining_uses)
    }
}

#[async_trait]
pub trait IdentityFederationPort: Send + Sync {
    async fn verify_federated_token(
        &self,
        token: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentPrincipal, IdentityError>;
}

#[derive(Clone, Default)]
pub struct AgentOwnershipResolver {
    owners: Arc<RwLock<BTreeMap<AgentInstanceId, (TenantId, String)>>>,
}

impl AgentOwnershipResolver {
    pub fn register(&self, agent: AgentInstanceId, tenant: TenantId, owner: String) {
        self.owners.write().insert(agent, (tenant, owner));
    }
    pub fn resolve(&self, agent: &AgentInstanceId) -> Result<(TenantId, String), IdentityError> {
        self.owners
            .read()
            .get(agent)
            .cloned()
            .ok_or(IdentityError::OwnershipUnknown)
    }
}

pub fn scope_hash(claims: &CredentialClaims) -> Result<String, IdentityError> {
    let bytes = serde_jcs::to_vec(claims).map_err(|_| IdentityError::TokenInvalid)?;
    Ok(hex_string(Sha256::digest(bytes).as_slice()))
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("IDENTITY_PRODUCTION_TRUST_NOT_CONFIGURED")]
    ProductionTrustNotConfigured,
    #[error("IDENTITY_TOKEN_INVALID")]
    TokenInvalid,
    #[error("IDENTITY_ALGORITHM_DENIED")]
    AlgorithmDenied,
    #[error("IDENTITY_ISSUER_OR_AUDIENCE_INVALID")]
    IssuerOrAudience,
    #[error("IDENTITY_EXPIRED_OR_NOT_YET_VALID")]
    ExpiredOrNotYetValid,
    #[error("IDENTITY_UNKNOWN_KEY")]
    UnknownKey,
    #[error("IDENTITY_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("IDENTITY_TRUST_BUNDLE_UNAVAILABLE")]
    TrustBundleUnavailable,
    #[error("IDENTITY_REVOKED")]
    Revoked,
    #[error("IDENTITY_TENANT_MISMATCH")]
    TenantMismatch,
    #[error("IDENTITY_TTL_INVALID")]
    InvalidTtl,
    #[error("IDENTITY_CREDENTIAL_NOT_FOUND")]
    CredentialNotFound,
    #[error("IDENTITY_CREDENTIAL_SCOPE_INVALID")]
    CredentialScopeInvalid,
    #[error("IDENTITY_USAGE_EXCEEDED")]
    UsageExceeded,
    #[error("IDENTITY_OWNERSHIP_UNKNOWN")]
    OwnershipUnknown,
    #[error("IDENTITY_NONCE_INVALID")]
    NonceInvalid,
    #[error("IDENTITY_CERTIFICATE_INVALID")]
    CertificateInvalid,
    #[error("IDENTITY_JWKS_INVALID")]
    JwksInvalid,
    #[error("IDENTITY_STORE_FAILURE")]
    StoreFailure,
    #[error("IDENTITY_IDEMPOTENCY_INVALID")]
    IdempotencyInvalid,
    #[error("IDENTITY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("IDENTITY_IDEMPOTENCY_REPLAY_EXPIRED")]
    IdempotencyReplayExpired,
    #[error("IDENTITY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("IDENTITY_MANAGEMENT_FORBIDDEN")]
    ManagementForbidden,
    #[error("IDENTITY_RESPONSE_PROTECTION_INVALID")]
    ResponseProtectionInvalid,
    #[error("IDENTITY_SIGNING_KEY_INVALID")]
    SigningKeyInvalid,
    #[error("IDENTITY_TASK_FROZEN")]
    TaskFrozen,
    #[error("IDENTITY_SUBJECT_REVOKED")]
    SubjectRevoked,
    #[error("IDENTITY_IN_MEMORY_PRODUCTION_FORBIDDEN")]
    InMemoryProductionForbidden,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (
        WorkloadTokenIssuer,
        WorkloadTokenVerifier,
        RevocationService,
        WorkloadTokenRequest,
    ) {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let revocation = RevocationService::default();
        let bundle = TrustBundleSnapshot {
            version: "1".into(),
            issuer: "issuer".into(),
            keys: BTreeMap::from([("kid".into(), key.verifying_key())]),
            valid_until: Utc::now() + chrono::Duration::hours(1),
        };
        let issuer = WorkloadTokenIssuer::new(
            RuntimeProfile::Development,
            "issuer",
            "kid",
            Some(key),
            revocation.clone(),
        )
        .unwrap_or_else(|_| panic!("issuer"));
        let verifier = WorkloadTokenVerifier::new(
            "issuer",
            Arc::new(StaticTrustBundle::new(bundle)),
            revocation.clone(),
            5,
        );
        let tenant = TenantId::new();
        let agent = AgentInstanceId::new();
        let task = TaskId::new();
        let step = StepId::new();
        let request = WorkloadTokenRequest {
            principal: AgentPrincipal {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                subject: "user:1".into(),
                organization_id: "org".into(),
                tenant_id: tenant.clone(),
                owner_subject: "user:1".into(),
                roles: BTreeSet::from(["agent-owner".into()]),
                auth_strength: "mfa".into(),
            },
            workload: WorkloadIdentity {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                agent_instance_id: agent,
                task_id: task,
                step_id: step,
                tenant_id: tenant,
                owner_subject: "user:1".into(),
                action_hash: ActionHash("hash".into()),
                policy_decision_id: "p".into(),
                trust_level: "verified".into(),
            },
            audience: "gateway".into(),
            ttl: chrono::Duration::minutes(5),
        };
        (issuer, verifier, revocation, request)
    }

    #[test]
    fn production_rejects_dev_or_missing_signer() {
        assert!(matches!(
            WorkloadTokenIssuer::new(
                RuntimeProfile::Production,
                "dev:issuer",
                "dev-key",
                None,
                RevocationService::default()
            ),
            Err(IdentityError::ProductionTrustNotConfigured)
        ));
    }

    #[test]
    fn audience_and_tamper_are_rejected() {
        let (issuer, verifier, _, request) = setup();
        let token = issuer
            .issue(request, Utc::now())
            .unwrap_or_else(|_| panic!("token"));
        assert!(
            verifier
                .verify(token.expose_to_transport(), "gateway", Utc::now())
                .is_ok()
        );
        assert_eq!(
            verifier.verify(token.expose_to_transport(), "proxy", Utc::now()),
            Err(IdentityError::IssuerOrAudience)
        );
        let mut tampered = token.expose_to_transport().to_string();
        tampered.push('a');
        assert!(verifier.verify(&tampered, "gateway", Utc::now()).is_err());
    }

    #[test]
    fn task_revocation_invalidates_cached_trust() {
        let (issuer, verifier, revocation, request) = setup();
        let task = request.workload.task_id.clone();
        let token = issuer
            .issue(request, Utc::now())
            .unwrap_or_else(|_| panic!("token"));
        revocation.revoke_task(&task);
        assert_eq!(
            verifier.verify(token.expose_to_transport(), "gateway", Utc::now()),
            Err(IdentityError::Revoked)
        );
    }

    #[test]
    fn single_use_consumption_is_atomic() {
        let (_, _, revocation, request) = setup();
        let service = CredentialService::new(revocation);
        let credential_request = CredentialRequest {
            schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
            tenant_id: request.workload.tenant_id,
            agent_instance_id: request.workload.agent_instance_id,
            task_id: request.workload.task_id,
            step_id: request.workload.step_id,
            action_hash: request.workload.action_hash.clone(),
            audience: "proxy".into(),
            resources: BTreeSet::from(["repo:a".into()]),
            operations: BTreeSet::from(["read".into()]),
            tool_id: "coding.repo-read".into(),
            ttl_seconds: 60,
            max_uses: 1,
        };
        let handle = service
            .issue(credential_request, Utc::now())
            .unwrap_or_else(|_| panic!("credential"));
        assert!(
            service
                .validate_and_consume(
                    &handle,
                    "proxy",
                    &request.workload.action_hash,
                    "repo:a",
                    "read",
                    Utc::now()
                )
                .is_ok()
        );
        assert!(matches!(
            service.validate_and_consume(
                &handle,
                "proxy",
                &request.workload.action_hash,
                "repo:a",
                "read",
                Utc::now()
            ),
            Err(IdentityError::UsageExceeded)
        ));
    }

    #[test]
    fn oidc_uses_trusted_subject_mapping_and_role_intersection() {
        let now = Utc::now();
        let key = SigningKey::from_bytes(&[17u8; 32]);
        let issuer = "https://identity.example";
        let audience = "agent-gateway";
        let trust = TrustBundleSnapshot {
            version: "oidc-1".into(),
            issuer: issuer.into(),
            keys: BTreeMap::from([("oidc-key".into(), key.verifying_key())]),
            valid_until: now + chrono::Duration::hours(1),
        };
        let verifier = OidcJwtVerifier::new(
            issuer.into(),
            audience.into(),
            Some("gateway-client".into()),
            Arc::new(StaticTrustBundle::new(trust)),
            5,
        )
        .unwrap_or_else(|_| panic!("oidc verifier"));
        let tenant = TenantId::new();
        verifier.map_subject(
            "subject-1".into(),
            AgentPrincipal {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                subject: "subject-1".into(),
                organization_id: "trusted-org".into(),
                tenant_id: tenant.clone(),
                owner_subject: "subject-1".into(),
                roles: BTreeSet::from(["admin".into(), "viewer".into()]),
                auth_strength: "mfa".into(),
            },
        );
        let header = JwtHeader {
            alg: "EdDSA".into(),
            typ: "JWT".into(),
            kid: "oidc-key".into(),
        };
        let claims = OidcClaims {
            iss: issuer.into(),
            aud: audience.into(),
            sub: "subject-1".into(),
            exp: (now + chrono::Duration::minutes(5)).timestamp(),
            nbf: Some((now - chrono::Duration::seconds(1)).timestamp()),
            iat: now.timestamp(),
            azp: Some("gateway-client".into()),
            nonce: Some("nonce-1".into()),
            roles: BTreeSet::from(["viewer".into(), "token-injected-role".into()]),
        };
        let encoded_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap_or_else(|_| panic!("serialize header")));
        let encoded_claims = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap_or_else(|_| panic!("serialize claims")));
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes());
        let token = format!("{signing_input}.{signature}");

        let principal = verifier
            .verify_oidc(&token, Some("nonce-1"), now)
            .unwrap_or_else(|_| panic!("verified oidc"));
        assert_eq!(principal.tenant_id, tenant);
        assert_eq!(principal.organization_id, "trusted-org");
        assert_eq!(principal.roles, BTreeSet::from(["viewer".into()]));
        assert_eq!(
            verifier.verify_oidc(&token, Some("wrong-nonce"), now),
            Err(IdentityError::NonceInvalid)
        );
    }

    #[test]
    fn enterprise_jwks_supports_eddsa_es256_and_rs256_material() {
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

        let now = Utc::now();
        let issuer = "https://enterprise-idp.example";
        let audience = "agent-gateway";
        let ed_key = SigningKey::from_bytes(&[27_u8; 32]);
        let random = SystemRandom::new();
        let ec_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .unwrap_or_else(|_| panic!("generate ec key"));
        let ec_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ec_pkcs8.as_ref(), &random)
                .unwrap_or_else(|_| panic!("parse ec key"));
        let ec_public = ec_key.public_key().as_ref();
        assert_eq!(ec_public.len(), 65);
        let jwks = serde_json::json!({"keys":[
            {
                "kid":"ed-key", "kty":"OKP", "alg":"EdDSA", "use":"sig",
                "key_ops":["verify"], "crv":"Ed25519",
                "x":URL_SAFE_NO_PAD.encode(ed_key.verifying_key().as_bytes())
            },
            {
                "kid":"ec-key", "kty":"EC", "alg":"ES256", "use":"sig",
                "key_ops":["verify"], "crv":"P-256",
                "x":URL_SAFE_NO_PAD.encode(&ec_public[1..33]),
                "y":URL_SAFE_NO_PAD.encode(&ec_public[33..65])
            },
            {
                "kid":"rsa-key", "kty":"RSA", "alg":"RS256", "use":"sig",
                "key_ops":["verify"],
                "n":URL_SAFE_NO_PAD.encode([0x80_u8; 256]),
                "e":URL_SAFE_NO_PAD.encode([1_u8, 0, 1])
            }
        ]});
        let bundle = FederatedTrustBundleSnapshot::from_jwks(
            issuer.into(),
            "jwks-v1".into(),
            now + chrono::Duration::hours(1),
            &serde_json::to_vec(&jwks).unwrap_or_else(|_| panic!("serialize jwks")),
        )
        .unwrap_or_else(|_| panic!("jwks"));
        assert_eq!(bundle.key_count(), 3);
        let verifier = EnterpriseOidcJwtVerifier::new(
            issuer.into(),
            audience.into(),
            Some("gateway-client".into()),
            Arc::new(StaticFederatedTrustBundle::new(bundle)),
            5,
        )
        .unwrap_or_else(|_| panic!("enterprise verifier"));
        let tenant = TenantId::new();
        verifier.map_subject(
            "enterprise-subject".into(),
            AgentPrincipal {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                subject: "enterprise-subject".into(),
                organization_id: "trusted-enterprise".into(),
                tenant_id: tenant.clone(),
                owner_subject: "enterprise-subject".into(),
                roles: BTreeSet::from(["viewer".into()]),
                auth_strength: "phishing-resistant-mfa".into(),
            },
        );
        let claims = EnterpriseOidcClaims {
            iss: issuer.into(),
            aud: AudienceClaim::One(audience.into()),
            sub: "enterprise-subject".into(),
            exp: (now + chrono::Duration::minutes(5)).timestamp(),
            nbf: Some((now - chrono::Duration::seconds(1)).timestamp()),
            iat: now.timestamp(),
            azp: Some("gateway-client".into()),
            nonce: Some("nonce-2".into()),
            roles: BTreeSet::from(["viewer".into(), "untrusted-admin".into()]),
        };
        let encoded_claims = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap_or_else(|_| panic!("claims")));

        for (kid, algorithm) in [("ed-key", "EdDSA"), ("ec-key", "ES256")] {
            let header = JwtHeader {
                alg: algorithm.into(),
                typ: "JWT".into(),
                kid: kid.into(),
            };
            let encoded_header = URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap_or_else(|_| panic!("header")));
            let signing_input = format!("{encoded_header}.{encoded_claims}");
            let signature = if algorithm == "EdDSA" {
                ed_key.sign(signing_input.as_bytes()).to_bytes().to_vec()
            } else {
                ec_key
                    .sign(&random, signing_input.as_bytes())
                    .unwrap_or_else(|_| panic!("ec signature"))
                    .as_ref()
                    .to_vec()
            };
            let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
            let principal = verifier
                .verify_oidc(&token, Some("nonce-2"), now)
                .unwrap_or_else(|_| panic!("verify {algorithm}"));
            assert_eq!(principal.tenant_id, tenant);
            assert_eq!(principal.roles, BTreeSet::from(["viewer".into()]));
        }
    }

    #[test]
    fn mtls_fingerprint_is_validated_and_server_mapped() {
        let (_, _, _, request) = setup();
        let verifier = MtlsIdentityVerifier::default();
        assert_eq!(
            verifier.register_fingerprint("not-a-sha256".into(), request.principal.clone()),
            Err(IdentityError::CertificateInvalid)
        );
        let fingerprint = "A1".repeat(32);
        verifier
            .register_fingerprint(fingerprint.clone(), request.principal.clone())
            .unwrap_or_else(|_| panic!("fingerprint"));
        assert_eq!(
            verifier
                .verify_fingerprint(&fingerprint.to_ascii_lowercase())
                .map(|principal| principal.tenant_id),
            Ok(request.principal.tenant_id)
        );
    }

    #[test]
    fn credential_handle_debug_is_redacted() {
        let handle = CredentialHandle("credential-bearer-secret".into());
        let rendered = format!("{handle:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("credential-bearer-secret"));
    }
}
