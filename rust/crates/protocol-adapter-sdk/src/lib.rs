//! Security-bounded protocol adapter SDK and conformance runner.

use agent_trust_action_ir::{ActionDraft, ParseLimits, parse_draft};
use agent_trust_contracts::{SchemaVersion, TenantId};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const ADAPTER_SCHEMA_VERSION: &str = "agenttrust.protocol-adapter.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdapterPermission {
    SubmitActionDraft,
    ReturnResult,
    EmitProtocolEvent,
    ReadCapabilitySnapshot,
    NetworkToDeclaredEndpoint,
    ExecutorAccess,
    SecretAccess,
    TaskStateWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersionBundle {
    pub protocol: String,
    pub minimum_version: String,
    pub maximum_version: String,
    pub schema_hash: String,
    pub critical_features: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterManifest {
    pub schema_version: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub implementation_digest: String,
    pub versions: Vec<ProtocolVersionBundle>,
    pub permissions: BTreeSet<AdapterPermission>,
    pub network_endpoints: BTreeSet<String>,
    pub supports_streaming: bool,
    pub supports_cancellation: bool,
    pub supports_delegation: bool,
    pub supports_artifacts: bool,
    pub publisher_id: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl AdapterManifest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AdapterError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| AdapterError::ManifestInvalid)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), AdapterError> {
        validate_manifest(self)?;
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.signature)
                .map_err(|_| AdapterError::SignatureInvalid)?,
        )
        .map_err(|_| AdapterError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| AdapterError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MappingLossSeverity {
    Informational,
    ReviewRequired,
    SecurityCritical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MappingLoss {
    pub source_path: String,
    pub target_concept: String,
    pub reason_code: String,
    pub severity: MappingLossSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingResult<T> {
    pub schema_version: String,
    pub value: T,
    pub losses: Vec<MappingLoss>,
    pub coverage_millionths: u32,
}

impl<T> MappingResult<T> {
    pub fn enforce_security_complete(self) -> Result<Self, AdapterError> {
        if self.schema_version != ADAPTER_SCHEMA_VERSION
            || self.coverage_millionths > 1_000_000
            || self
                .losses
                .iter()
                .any(|loss| loss.severity == MappingLossSeverity::SecurityCritical)
        {
            return Err(AdapterError::SecurityMappingLoss);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentityClaim {
    pub external_subject: String,
    pub external_tenant_hint: Option<String>,
    pub claimed_trust_level: String,
    pub authentication_evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedIdentityClaim {
    pub schema_version: SchemaVersion,
    pub external_subject: String,
    pub tenant_id: TenantId,
    pub trust_level: String,
    pub verified: bool,
}

pub trait IdentityClaimMapper: Send + Sync {
    fn normalize_identity(
        &self,
        claim: ExternalIdentityClaim,
        trusted_tenant: TenantId,
        evidence_verified: bool,
    ) -> Result<MappingResult<NormalizedIdentityClaim>, AdapterError>;
}

pub struct DefaultIdentityClaimMapper;
impl IdentityClaimMapper for DefaultIdentityClaimMapper {
    fn normalize_identity(
        &self,
        claim: ExternalIdentityClaim,
        trusted_tenant: TenantId,
        evidence_verified: bool,
    ) -> Result<MappingResult<NormalizedIdentityClaim>, AdapterError> {
        if claim.external_subject.is_empty() {
            return Err(AdapterError::IdentityInvalid);
        }
        let claimed_high_trust =
            !matches!(claim.claimed_trust_level.as_str(), "untrusted" | "unknown");
        let mut losses = Vec::new();
        if claimed_high_trust && !evidence_verified {
            losses.push(MappingLoss {
                source_path: "identity.claimed_trust_level".into(),
                target_concept: "identity.trust_level".into(),
                reason_code: "UNVERIFIED_SELF_ASSERTED_TRUST_DOWNGRADED".into(),
                severity: MappingLossSeverity::ReviewRequired,
            });
        }
        Ok(MappingResult {
            schema_version: ADAPTER_SCHEMA_VERSION.into(),
            value: NormalizedIdentityClaim {
                schema_version: SchemaVersion(ADAPTER_SCHEMA_VERSION.into()),
                external_subject: claim.external_subject,
                tenant_id: trusted_tenant,
                trust_level: if evidence_verified {
                    "verified".into()
                } else {
                    "untrusted".into()
                },
                verified: evidence_verified,
            },
            coverage_millionths: if losses.is_empty() {
                1_000_000
            } else {
                900_000
            },
            losses,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolEventKind {
    Started,
    Progress,
    Artifact,
    ApprovalRequired,
    Cancelled,
    Failed,
    ResultAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEvent {
    pub schema_version: String,
    pub sequence: u64,
    pub kind: ProtocolEventKind,
    pub trace_id: String,
    pub safe_summary: String,
    pub payload_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterHealth {
    pub schema_version: String,
    pub healthy: bool,
    pub manifest_digest: String,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolError {
    pub schema_version: String,
    pub code: String,
    pub safe_summary: String,
    pub retryable: bool,
}

#[async_trait]
pub trait ProtocolAdapter: Send + Sync {
    fn manifest(&self) -> &AdapterManifest;
    async fn discover_capabilities(&self) -> Result<Vec<String>, AdapterError>;
    fn normalize_identity(
        &self,
        claim: ExternalIdentityClaim,
        trusted_tenant: TenantId,
        evidence_verified: bool,
    ) -> Result<MappingResult<NormalizedIdentityClaim>, AdapterError>;
    fn parse_request(
        &self,
        protocol_version: &str,
        features: &BTreeSet<String>,
        bytes: &[u8],
    ) -> Result<MappingResult<ActionDraft>, AdapterError>;
    #[allow(clippy::wrong_self_convention)]
    fn from_action_result(&self, result: &Value) -> Result<Value, AdapterError>;
    fn map_error(&self, error_code: &str) -> ProtocolError;
    fn stream_event(&self, event: ProtocolEvent) -> Result<Value, AdapterError>;
    async fn health_check(&self) -> AdapterHealth;
}

pub struct EchoJsonAdapter {
    manifest: AdapterManifest,
    identity_mapper: DefaultIdentityClaimMapper,
    parse_limits: ParseLimits,
}

impl EchoJsonAdapter {
    pub fn new(manifest: AdapterManifest) -> Result<Self, AdapterError> {
        validate_manifest(&manifest)?;
        Ok(Self {
            manifest,
            identity_mapper: DefaultIdentityClaimMapper,
            parse_limits: ParseLimits::default(),
        })
    }

    fn negotiated_bundle(
        &self,
        version: &str,
        features: &BTreeSet<String>,
    ) -> Result<&ProtocolVersionBundle, AdapterError> {
        let bundle = self
            .manifest
            .versions
            .iter()
            .find(|bundle| {
                version >= bundle.minimum_version.as_str()
                    && version <= bundle.maximum_version.as_str()
            })
            .ok_or(AdapterError::VersionUnsupported)?;
        if !features.is_subset(&bundle.critical_features) {
            return Err(AdapterError::UnknownCriticalFeature);
        }
        Ok(bundle)
    }
}

#[async_trait]
impl ProtocolAdapter for EchoJsonAdapter {
    fn manifest(&self) -> &AdapterManifest {
        &self.manifest
    }
    async fn discover_capabilities(&self) -> Result<Vec<String>, AdapterError> {
        Ok(vec!["echo.action-draft".into()])
    }
    fn normalize_identity(
        &self,
        claim: ExternalIdentityClaim,
        trusted_tenant: TenantId,
        evidence_verified: bool,
    ) -> Result<MappingResult<NormalizedIdentityClaim>, AdapterError> {
        self.identity_mapper
            .normalize_identity(claim, trusted_tenant, evidence_verified)
    }
    fn parse_request(
        &self,
        protocol_version: &str,
        features: &BTreeSet<String>,
        bytes: &[u8],
    ) -> Result<MappingResult<ActionDraft>, AdapterError> {
        self.negotiated_bundle(protocol_version, features)?;
        let value =
            parse_draft(bytes, &self.parse_limits).map_err(|_| AdapterError::RequestInvalid)?;
        Ok(MappingResult {
            schema_version: ADAPTER_SCHEMA_VERSION.into(),
            value,
            losses: vec![],
            coverage_millionths: 1_000_000,
        })
    }
    fn from_action_result(&self, result: &Value) -> Result<Value, AdapterError> {
        if result.to_string().len() > 1_048_576 {
            Err(AdapterError::ResponseInvalid)
        } else {
            Ok(serde_json::json!({"result":result,"untrusted":true}))
        }
    }
    fn map_error(&self, error_code: &str) -> ProtocolError {
        ProtocolError {
            schema_version: ADAPTER_SCHEMA_VERSION.into(),
            code: format!("ADAPTER_UPSTREAM_{error_code}"),
            safe_summary: "upstream protocol request failed".into(),
            retryable: matches!(error_code, "TIMEOUT" | "DISCONNECTED"),
        }
    }
    fn stream_event(&self, event: ProtocolEvent) -> Result<Value, AdapterError> {
        if event.schema_version != ADAPTER_SCHEMA_VERSION
            || event.sequence == 0
            || event.trace_id.is_empty()
            || event.safe_summary.len() > 512
        {
            Err(AdapterError::StreamInvalid)
        } else {
            serde_json::to_value(event).map_err(|_| AdapterError::StreamInvalid)
        }
    }
    async fn health_check(&self) -> AdapterHealth {
        AdapterHealth {
            schema_version: ADAPTER_SCHEMA_VERSION.into(),
            healthy: true,
            manifest_digest: hex(Sha256::digest(
                serde_jcs::to_vec(&self.manifest).unwrap_or_default(),
            )),
            checked_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConformanceReport {
    pub schema_version: String,
    pub manifest_valid: bool,
    pub least_privilege: bool,
    pub cancellation_semantics: bool,
    pub streaming_semantics: bool,
    pub findings: Vec<String>,
}

pub struct ConformanceRunner;
impl ConformanceRunner {
    pub fn inspect_manifest(manifest: &AdapterManifest) -> ConformanceReport {
        let forbidden = [
            AdapterPermission::ExecutorAccess,
            AdapterPermission::SecretAccess,
            AdapterPermission::TaskStateWrite,
        ];
        let least_privilege = forbidden
            .iter()
            .all(|permission| !manifest.permissions.contains(permission));
        let mut findings = Vec::new();
        if !least_privilege {
            findings.push("FORBIDDEN_RUNTIME_PERMISSION".into());
        }
        ConformanceReport {
            schema_version: ADAPTER_SCHEMA_VERSION.into(),
            manifest_valid: validate_manifest(manifest).is_ok(),
            least_privilege,
            cancellation_semantics: manifest.supports_cancellation,
            streaming_semantics: manifest.supports_streaming,
            findings,
        }
    }
}

fn validate_manifest(manifest: &AdapterManifest) -> Result<(), AdapterError> {
    if manifest.schema_version != ADAPTER_SCHEMA_VERSION
        || manifest.adapter_id.is_empty()
        || manifest.adapter_version.is_empty()
        || manifest.versions.is_empty()
        || !valid_sha256(&manifest.implementation_digest)
        || manifest
            .versions
            .iter()
            .any(|bundle| !valid_hash(&bundle.schema_hash))
        || manifest
            .permissions
            .contains(&AdapterPermission::ExecutorAccess)
        || manifest
            .permissions
            .contains(&AdapterPermission::SecretAccess)
        || manifest
            .permissions
            .contains(&AdapterPermission::TaskStateWrite)
    {
        return Err(AdapterError::ManifestInvalid);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hash)
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdapterError {
    #[error("ADAPTER_MANIFEST_INVALID")]
    ManifestInvalid,
    #[error("ADAPTER_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("ADAPTER_IDENTITY_INVALID")]
    IdentityInvalid,
    #[error("ADAPTER_SECURITY_MAPPING_LOSS")]
    SecurityMappingLoss,
    #[error("ADAPTER_VERSION_UNSUPPORTED")]
    VersionUnsupported,
    #[error("ADAPTER_UNKNOWN_CRITICAL_FEATURE")]
    UnknownCriticalFeature,
    #[error("ADAPTER_REQUEST_INVALID")]
    RequestInvalid,
    #[error("ADAPTER_RESPONSE_INVALID")]
    ResponseInvalid,
    #[error("ADAPTER_STREAM_INVALID")]
    StreamInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> AdapterManifest {
        AdapterManifest {
            schema_version: ADAPTER_SCHEMA_VERSION.into(),
            adapter_id: "echo".into(),
            adapter_version: "1.0.0".into(),
            implementation_digest: format!("sha256:{}", "a".repeat(64)),
            versions: vec![ProtocolVersionBundle {
                protocol: "echo".into(),
                minimum_version: "1.0".into(),
                maximum_version: "1.9".into(),
                schema_hash: "b".repeat(64),
                critical_features: BTreeSet::from(["cancel".into()]),
            }],
            permissions: BTreeSet::from([
                AdapterPermission::SubmitActionDraft,
                AdapterPermission::ReturnResult,
            ]),
            network_endpoints: BTreeSet::new(),
            supports_streaming: true,
            supports_cancellation: true,
            supports_delegation: false,
            supports_artifacts: true,
            publisher_id: "publisher".into(),
            signer_key_id: "key".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn executor_secret_and_state_permissions_are_architecturally_denied() {
        let mut bad = manifest();
        bad.permissions.insert(AdapterPermission::ExecutorAccess);
        assert_eq!(
            EchoJsonAdapter::new(bad).err(),
            Some(AdapterError::ManifestInvalid)
        );
    }

    #[test]
    fn self_asserted_identity_trust_is_downgraded() {
        let mapped = DefaultIdentityClaimMapper
            .normalize_identity(
                ExternalIdentityClaim {
                    external_subject: "agent:1".into(),
                    external_tenant_hint: Some("forged".into()),
                    claimed_trust_level: "administrator".into(),
                    authentication_evidence_ref: None,
                },
                TenantId::new(),
                false,
            )
            .unwrap_or_else(|_| panic!("identity"));
        assert_eq!(mapped.value.trust_level, "untrusted");
        assert!(!mapped.losses.is_empty());
    }

    #[test]
    fn unknown_critical_feature_and_version_fail_closed() {
        let adapter = EchoJsonAdapter::new(manifest()).unwrap_or_else(|_| panic!("adapter"));
        assert_eq!(
            adapter.negotiated_bundle("2.0", &BTreeSet::new()).err(),
            Some(AdapterError::VersionUnsupported)
        );
        assert_eq!(
            adapter
                .negotiated_bundle("1.0", &BTreeSet::from(["admin".into()]))
                .err(),
            Some(AdapterError::UnknownCriticalFeature)
        );
    }
}
