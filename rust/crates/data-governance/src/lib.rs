//! Data classification, propagation, DLP, cross-domain, and deployment policy.

pub mod adapters;
pub mod authority;
pub mod server;
pub mod service;

use agent_trust_contracts::{
    ApprovalId, ContractError, DataClassification, DataPolicyDecision, DataPolicyPort,
    DataPolicyRequest, PolicyVersion, SchemaVersion, TenantId,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DATA_SCHEMA_VERSION: &str = "agenttrust.data-governance.v1";
pub const MAX_INSPECTION_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_JSON_SCAN_DEPTH: usize = 32;
pub const MAX_JSON_SCAN_NODES: usize = 100_000;
pub const MAX_DLP_FINDINGS: usize = 4_096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LabelConfidence {
    Unknown,
    Inferred,
    Deterministic,
    HumanVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataLineageRef {
    pub source_id: String,
    pub source_hash: String,
    pub transformation_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DataLabel {
    pub schema_version: String,
    pub classification: DataClassification,
    pub domain_tags: BTreeSet<String>,
    pub jurisdictions: BTreeSet<String>,
    pub contains_secret: bool,
    pub contains_personal_data: bool,
    pub export_restricted: bool,
    pub retention_label: String,
    pub confidence: LabelConfidence,
    pub lineage: DataLineageRef,
}

pub struct LabelPropagator;
impl LabelPropagator {
    pub fn merge(
        labels: &[DataLabel],
        transformation_hash: String,
    ) -> Result<DataLabel, DataError> {
        if labels.is_empty() || labels.len() > 64 || !is_digest(&transformation_hash) {
            return Err(DataError::LabelInvalid);
        }
        let classification = labels
            .iter()
            .map(|label| label.classification)
            .max()
            .ok_or(DataError::LabelInvalid)?;
        let mut domain_tags = BTreeSet::new();
        let mut jurisdictions = BTreeSet::new();
        let mut transforms = Vec::new();
        for label in labels {
            validate_label(label)?;
            if transforms
                .len()
                .saturating_add(label.lineage.transformation_hashes.len())
                >= 1024
            {
                return Err(DataError::LabelInvalid);
            }
            domain_tags.extend(label.domain_tags.clone());
            jurisdictions.extend(label.jurisdictions.clone());
            transforms.extend(label.lineage.transformation_hashes.clone());
        }
        if domain_tags.len() > 64 || jurisdictions.len() > 32 || transforms.len() >= 1024 {
            return Err(DataError::LabelInvalid);
        }
        transforms.push(transformation_hash);
        if transforms.iter().collect::<BTreeSet<_>>().len() != transforms.len() {
            return Err(DataError::LabelInvalid);
        }
        Ok(DataLabel {
            schema_version: DATA_SCHEMA_VERSION.into(),
            classification,
            domain_tags,
            jurisdictions,
            contains_secret: labels.iter().any(|label| label.contains_secret),
            contains_personal_data: labels.iter().any(|label| label.contains_personal_data),
            export_restricted: labels.iter().any(|label| label.export_restricted),
            retention_label: retention_label_for(classification).into(),
            confidence: labels
                .iter()
                .map(|label| label.confidence)
                .min()
                .unwrap_or(LabelConfidence::Unknown),
            lineage: DataLineageRef {
                source_id: "derived".into(),
                source_hash: hex(Sha256::digest(
                    serde_jcs::to_vec(labels).map_err(|_| DataError::LabelInvalid)?,
                )),
                transformation_hashes: transforms,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DlpFindingKind {
    Secret,
    PersonalData,
    IndustrialSensitive,
    EncodedPayload,
    CompressedPayload,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpFinding {
    pub kind: DlpFindingKind,
    pub path: String,
    pub value_hash: String,
    pub blocking: bool,
}

pub struct DlpScanner {
    available: RwLock<bool>,
    patterns_valid: bool,
    secret_patterns: Vec<Regex>,
    personal_patterns: Vec<Regex>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRequest {
    pub schema_version: String,
    pub source_id: String,
    pub jurisdiction: String,
    pub source_trusted: bool,
    pub domain_tags: BTreeSet<String>,
    /// A human override may only raise sensitivity. The Evidence reference is metadata only.
    pub human_override: Option<DataClassification>,
    pub human_override_evidence_ref: Option<String>,
}

pub struct DataClassifier<'a> {
    scanner: &'a DlpScanner,
}

impl<'a> DataClassifier<'a> {
    pub fn new(scanner: &'a DlpScanner) -> Self {
        Self { scanner }
    }

    pub fn classify(
        &self,
        request: &ClassificationRequest,
        content: &[u8],
    ) -> Result<DataLabel, DataError> {
        if request.schema_version != DATA_SCHEMA_VERSION
            || request.source_id.is_empty()
            || request.source_id.len() > 512
            || !request
                .source_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || !valid_jurisdiction(&request.jurisdiction)
            || request.domain_tags.len() > 64
            || request.domain_tags.iter().any(|value| {
                value.is_empty()
                    || value.len() > 256
                    || !value.bytes().all(|byte| byte.is_ascii_graphic())
            })
            || !match (
                &request.human_override,
                &request.human_override_evidence_ref,
            ) {
                (None, None) => true,
                (Some(_), Some(value)) => {
                    value.starts_with("evidence://")
                        && value.len() <= 2048
                        && value.bytes().all(|byte| byte.is_ascii_graphic())
                }
                _ => false,
            }
        {
            return Err(DataError::LabelInvalid);
        }
        let findings = self.scanner.scan_bytes(content)?;
        let contains_secret = findings
            .iter()
            .any(|finding| finding.kind == DlpFindingKind::Secret);
        let contains_personal_data = findings
            .iter()
            .any(|finding| finding.kind == DlpFindingKind::PersonalData);
        let industrial = findings
            .iter()
            .any(|finding| finding.kind == DlpFindingKind::IndustrialSensitive);
        let deterministic = if contains_personal_data {
            DataClassification::Regulated
        } else if contains_secret || industrial || findings.iter().any(|value| value.blocking) {
            DataClassification::Restricted
        } else if request.source_trusted {
            DataClassification::Internal
        } else {
            // Unknown untrusted material is never inferred PUBLIC/INTERNAL.
            DataClassification::Restricted
        };
        let classification = request
            .human_override
            .map(|override_value| override_value.max(deterministic))
            .unwrap_or(deterministic);
        Ok(DataLabel {
            schema_version: DATA_SCHEMA_VERSION.into(),
            classification,
            domain_tags: request.domain_tags.clone(),
            jurisdictions: BTreeSet::from([request.jurisdiction.clone()]),
            contains_secret,
            contains_personal_data,
            export_restricted: classification >= DataClassification::Restricted,
            retention_label: retention_label_for(classification).into(),
            confidence: if request.human_override.is_some() {
                LabelConfidence::HumanVerified
            } else {
                LabelConfidence::Deterministic
            },
            lineage: DataLineageRef {
                source_id: request.source_id.clone(),
                source_hash: hex(Sha256::digest(content)),
                transformation_hashes: Vec::new(),
            },
        })
    }
}
impl Default for DlpScanner {
    fn default() -> Self {
        let secret_patterns = [
            r"(?i)password\s*[:=]",
            r"(?i)api[_-]?key\s*[:=]",
            r"(?i)authorization\s*:\s*bearer",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        ]
        .iter()
        .map(|pattern| Regex::new(pattern))
        .collect::<Result<Vec<_>, _>>();
        let personal_patterns = [
            r"\b\d{17}[0-9Xx]\b",
            r"\b1[3-9]\d{9}\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        ]
        .iter()
        .map(|pattern| Regex::new(pattern))
        .collect::<Result<Vec<_>, _>>();
        let patterns_valid = secret_patterns.is_ok() && personal_patterns.is_ok();
        Self {
            available: RwLock::new(patterns_valid),
            patterns_valid,
            secret_patterns: secret_patterns.unwrap_or_default(),
            personal_patterns: personal_patterns.unwrap_or_default(),
        }
    }
}
impl DlpScanner {
    pub fn set_available(&self, available: bool) {
        *self.available.write() = available && self.patterns_valid;
    }
    pub fn is_available(&self) -> bool {
        self.patterns_valid && *self.available.read()
    }
    pub fn scan_bytes(&self, bytes: &[u8]) -> Result<Vec<DlpFinding>, DataError> {
        if !self.is_available() {
            return Err(DataError::DlpUnavailable);
        }
        if bytes.is_empty() || bytes.len() > MAX_INSPECTION_BYTES {
            return Err(DataError::ContentInvalid);
        }
        if bytes.starts_with(&[0x1f, 0x8b]) || bytes.starts_with(b"PK\x03\x04") {
            return Ok(vec![finding(
                DlpFindingKind::CompressedPayload,
                "$",
                bytes,
                true,
            )]);
        }
        let text = String::from_utf8_lossy(bytes);
        let mut findings = self.scan_text(&text, "$", true);
        let mut encoded = text.trim().as_bytes().to_vec();
        for depth in 1..=3 {
            let encoded_text = String::from_utf8_lossy(&encoded);
            if !looks_base64(&encoded_text) {
                break;
            }
            let Some(decoded) = decode_base64_layer(encoded_text.trim()) else {
                break;
            };
            if decoded.is_empty() || decoded.len() > MAX_INSPECTION_BYTES {
                findings.push(finding(DlpFindingKind::EncodedPayload, "$", bytes, true));
                break;
            }
            if decoded.starts_with(&[0x1f, 0x8b]) || decoded.starts_with(b"PK\x03\x04") {
                findings.push(finding(DlpFindingKind::EncodedPayload, "$", bytes, true));
                findings.push(finding(
                    DlpFindingKind::CompressedPayload,
                    &format!("$[base64:{depth}]"),
                    &decoded,
                    true,
                ));
                break;
            }
            let mut decoded_findings = self.scan_text(
                &String::from_utf8_lossy(&decoded),
                &format!("$[base64:{depth}]"),
                true,
            );
            if !decoded_findings.is_empty() {
                findings.push(finding(DlpFindingKind::EncodedPayload, "$", bytes, true));
                findings.append(&mut decoded_findings);
            }
            encoded = decoded;
        }
        Ok(findings)
    }
    pub fn scan_json(&self, value: &Value) -> Result<Vec<DlpFinding>, DataError> {
        if !self.is_available() {
            return Err(DataError::DlpUnavailable);
        }
        let mut findings = Vec::new();
        let mut nodes = 0usize;
        scan_json_value(self, value, "$", 0, &mut nodes, &mut findings)?;
        Ok(findings)
    }
    fn scan_text(&self, text: &str, path: &str, blocking: bool) -> Vec<DlpFinding> {
        let mut findings = Vec::new();
        if self
            .secret_patterns
            .iter()
            .any(|pattern| pattern.is_match(text))
        {
            findings.push(finding(DlpFindingKind::Secret, path, text.as_bytes(), true));
        }
        if self
            .personal_patterns
            .iter()
            .any(|pattern| pattern.is_match(text))
        {
            findings.push(finding(
                DlpFindingKind::PersonalData,
                path,
                text.as_bytes(),
                blocking,
            ));
        }
        if text.to_ascii_lowercase().contains("plc-password")
            || text.to_ascii_lowercase().contains("sis-bypass")
        {
            findings.push(finding(
                DlpFindingKind::IndustrialSensitive,
                path,
                text.as_bytes(),
                true,
            ));
        }
        findings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentMode {
    Saas,
    Vpc,
    OnPrem,
    Offline,
    Hybrid,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentPolicy {
    pub profile_id: String,
    pub mode: DeploymentMode,
    pub allowed_external_endpoints: BTreeSet<String>,
    pub telemetry_export: bool,
    pub update_channel: String,
    pub maximum_classification: DataClassification,
}
impl DeploymentPolicy {
    pub fn validate(&self) -> Result<(), DataError> {
        if self.profile_id.is_empty()
            || self.profile_id.len() > 128
            || !self
                .profile_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || self.update_channel.is_empty()
            || self.update_channel.len() > 128
            || !self
                .update_channel
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || self.allowed_external_endpoints.len() > 100
            || self.allowed_external_endpoints.iter().any(|endpoint| {
                url::Url::parse(endpoint).map_or(true, |value| {
                    value.scheme() != "https"
                        || value.host_str().is_none()
                        || !value.username().is_empty()
                        || value.password().is_some()
                        || value.path() != "/"
                        || value.query().is_some()
                        || value.fragment().is_some()
                        || value.as_str() != endpoint
                })
            })
        {
            return Err(DataError::DeploymentInvalid);
        }
        if self.mode == DeploymentMode::Offline
            && (!self.allowed_external_endpoints.is_empty()
                || self.telemetry_export
                || self.update_channel != "offline-bundle")
        {
            return Err(DataError::DeploymentInvalid);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct DeploymentPolicyResolver {
    profiles: RwLock<BTreeMap<String, DeploymentPolicy>>,
}
impl DeploymentPolicyResolver {
    pub fn register(&self, profile: DeploymentPolicy) -> Result<(), DataError> {
        profile.validate()?;
        self.profiles
            .write()
            .insert(profile.profile_id.clone(), profile);
        Ok(())
    }
    pub fn resolve(&self, profile: &str) -> Result<DeploymentPolicy, DataError> {
        self.profiles
            .read()
            .get(profile)
            .cloned()
            .ok_or(DataError::DeploymentInvalid)
    }
}

pub struct DataPolicyPortImpl {
    policy_version: PolicyVersion,
    deployments: DeploymentPolicyResolver,
}
impl DataPolicyPortImpl {
    pub fn new(policy_version: PolicyVersion) -> Result<Self, DataError> {
        if policy_version.0.is_empty() {
            Err(DataError::PolicyInvalid)
        } else {
            Ok(Self {
                policy_version,
                deployments: DeploymentPolicyResolver::default(),
            })
        }
    }
    pub fn deployments(&self) -> &DeploymentPolicyResolver {
        &self.deployments
    }
    pub fn evaluate_checked(
        &self,
        request: &DataPolicyRequest,
    ) -> Result<DataPolicyDecision, DataError> {
        if request.schema_version.0 != agent_trust_contracts::CONTRACT_SCHEMA_VERSION
            || !uuid::Uuid::parse_str(&request.tenant_id.0)
                .is_ok_and(|value| value.to_string() == request.tenant_id.0)
            || !valid_jurisdiction(&request.source_jurisdiction)
            || !valid_jurisdiction(&request.destination_jurisdiction)
            || request.destination_kind.is_empty()
            || request.destination_kind.len() > 2048
            || !request
                .destination_kind
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || request.deployment_profile.is_empty()
            || request.deployment_profile.len() > 128
            || !request
                .deployment_profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || request
                .cross_domain_approval_id
                .as_ref()
                .is_some_and(|approval| {
                    !uuid::Uuid::parse_str(&approval.0)
                        .is_ok_and(|value| value.to_string() == approval.0)
                })
        {
            return Err(DataError::PolicyInvalid);
        }
        let deployment = self.deployments.resolve(&request.deployment_profile)?;
        let mut reasons = Vec::new();
        let mut allowed = true;
        if request.contains_secret {
            allowed = false;
            reasons.push("SECRET_OUTBOUND_DENIED".into());
        }
        if request.classification > deployment.maximum_classification {
            allowed = false;
            reasons.push("DEPLOYMENT_CLASSIFICATION_LIMIT".into());
        }
        if matches!(
            request.classification,
            DataClassification::Restricted | DataClassification::Regulated
        ) && request
            .destination_kind
            .to_ascii_lowercase()
            .contains("publicapi")
        {
            allowed = false;
            reasons.push("PUBLIC_MODEL_DENIED".into());
        }
        if request.source_jurisdiction != request.destination_jurisdiction
            && request.cross_domain_approval_id.is_none()
        {
            allowed = false;
            reasons.push("CROSS_DOMAIN_APPROVAL_REQUIRED".into());
        }
        let destination = request.destination_kind.to_ascii_lowercase();
        // Preserve the caller's exact URL while parsing. Typed destinations such
        // as `model:OnPrem` are not network URLs; only an explicit `://` form is.
        // A malformed explicit URL fails closed instead of becoming an unknown
        // opaque destination string.
        let destination_url = if destination.contains("://") {
            Some(
                url::Url::parse(&request.destination_kind)
                    .map_err(|_| DataError::DeploymentInvalid)?,
            )
        } else {
            None
        };
        let named_private_boundary_crossing = destination.contains("public")
            || destination.contains("external")
            || destination.contains("saas");
        let url_is_private = destination_url.is_some()
            && matches!(
                &deployment.mode,
                DeploymentMode::Vpc | DeploymentMode::OnPrem
            );
        let url_is_saas =
            destination_url.is_some() && matches!(&deployment.mode, DeploymentMode::Saas);
        let crosses_private_boundary = named_private_boundary_crossing || url_is_saas;
        let external_egress = crosses_private_boundary
            || destination.contains("internet")
            || destination.contains("cross-region")
            || (destination_url.is_some() && !url_is_private);
        let remains_private = destination.contains("onprem")
            || destination.contains("on-prem")
            || destination.contains("private")
            || destination.contains("vpc")
            || destination.contains("internal")
            || destination.contains("offline")
            || destination.contains("local")
            || destination.contains("opcua")
            || destination.contains("mqtt")
            || destination.contains("modbus")
            || url_is_private;
        if !external_egress && !remains_private {
            allowed = false;
            reasons.push("DESTINATION_KIND_UNKNOWN".into());
        }
        if let Some(destination_url) = destination_url {
            let mut origin = destination_url.clone();
            origin.set_path("/");
            origin.set_query(None);
            origin.set_fragment(None);
            if destination_url.scheme() != "https"
                || !destination_url.username().is_empty()
                || destination_url.password().is_some()
                || !deployment
                    .allowed_external_endpoints
                    .contains(origin.as_str())
            {
                allowed = false;
                reasons.push("DESTINATION_ENDPOINT_DENIED".into());
            }
        }
        if deployment.mode == DeploymentMode::Offline && external_egress {
            allowed = false;
            reasons.push("OFFLINE_EGRESS_DENIED".into());
        }
        if reasons.is_empty() {
            reasons.push("DATA_FLOW_ALLOWED".into());
        }
        Ok(DataPolicyDecision {
            schema_version: SchemaVersion(DATA_SCHEMA_VERSION.into()),
            allowed,
            policy_version: self.policy_version.clone(),
            reason_codes: reasons,
            // A private/on-prem model is the permitted semantic-preservation path for
            // restricted data. Mandatory outbound transforms apply when the payload crosses
            // that private boundary; PromptGuard/DLP still inspect every payload independently.
            required_transformations: if request.classification >= DataClassification::Confidential
                && crosses_private_boundary
            {
                vec!["REDACT_PII".into(), "HASH_TRACE_PAYLOAD".into()]
            } else {
                vec![]
            },
            maximum_retention_seconds: retention_for(request.classification),
        })
    }
}
impl DataPolicyPort for DataPolicyPortImpl {
    fn evaluate(&self, request: &DataPolicyRequest) -> Result<DataPolicyDecision, ContractError> {
        self.evaluate_checked(request)
            .map_err(|_| ContractError::ScopeExceeded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptTransformResult {
    pub schema_version: String,
    pub sanitized_prompt: String,
    pub original_hash: String,
    pub transformed_hash: String,
    pub transformations: Vec<String>,
    pub reversible: bool,
}
pub struct PromptGuard<'a> {
    scanner: &'a DlpScanner,
}
impl<'a> PromptGuard<'a> {
    pub fn new(scanner: &'a DlpScanner) -> Self {
        Self { scanner }
    }
    pub fn sanitize(
        &self,
        prompt: &[u8],
        label: &DataLabel,
        private_processing: bool,
    ) -> Result<PromptTransformResult, DataError> {
        validate_label(label)?;
        let findings = self.scanner.scan_bytes(prompt)?;
        if findings
            .iter()
            .any(|finding| finding.kind == DlpFindingKind::Secret)
            || label.contains_secret
        {
            return Err(DataError::SecretDenied);
        }
        if label.classification >= DataClassification::Restricted && !private_processing {
            return Err(DataError::FlowDenied);
        }
        let mut sanitized =
            String::from_utf8(prompt.to_vec()).map_err(|_| DataError::ContentInvalid)?;
        let mut transformations = Vec::new();
        if findings
            .iter()
            .any(|finding| finding.kind == DlpFindingKind::PersonalData)
        {
            for pattern in &self.scanner.personal_patterns {
                sanitized = pattern
                    .replace_all(&sanitized, "[PII_REDACTED]")
                    .into_owned();
            }
            transformations.push("REDACT_PII".into());
        }
        Ok(PromptTransformResult {
            schema_version: DATA_SCHEMA_VERSION.into(),
            original_hash: hex(Sha256::digest(prompt)),
            transformed_hash: hex(Sha256::digest(sanitized.as_bytes())),
            sanitized_prompt: sanitized,
            transformations,
            reversible: false,
        })
    }
}

pub struct ArtifactExportGuard<'a> {
    scanner: &'a DlpScanner,
    policy: &'a DataPolicyPortImpl,
}
impl<'a> ArtifactExportGuard<'a> {
    pub fn new(scanner: &'a DlpScanner, policy: &'a DataPolicyPortImpl) -> Self {
        Self { scanner, policy }
    }

    pub fn inspect(
        &self,
        bytes: &[u8],
        label: &DataLabel,
        request: &DataPolicyRequest,
    ) -> Result<DataPolicyDecision, DataError> {
        validate_label(label)?;
        if self
            .scanner
            .scan_bytes(bytes)?
            .iter()
            .any(|finding| finding.blocking)
        {
            return Err(DataError::DlpDenied);
        }
        let decision = self.policy.evaluate_checked(request)?;
        if !decision.allowed {
            return Err(DataError::FlowDenied);
        }
        Ok(decision)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossDomainGrant {
    pub schema_version: String,
    pub grant_id: ApprovalId,
    pub tenant_id: TenantId,
    pub source_zone: String,
    pub target_zone: String,
    pub data_hash: String,
    pub classification: DataClassification,
    pub expires_at: DateTime<Utc>,
    pub single_use: bool,
}
#[derive(Default)]
pub struct CrossDomainApprovalService {
    grants: Mutex<BTreeMap<String, CrossDomainGrant>>,
    used: Mutex<BTreeSet<String>>,
}
impl CrossDomainApprovalService {
    pub fn issue(&self, grant: CrossDomainGrant) -> Result<(), DataError> {
        if grant.schema_version != DATA_SCHEMA_VERSION
            || grant.source_zone == grant.target_zone
            || grant.data_hash.len() != 64
            || !grant.single_use
            || grant.expires_at <= Utc::now()
        {
            return Err(DataError::CrossDomainInvalid);
        }
        self.grants.lock().insert(grant.grant_id.0.clone(), grant);
        Ok(())
    }
    pub fn verify_and_consume(
        &self,
        grant_id: &ApprovalId,
        tenant: &TenantId,
        source: &str,
        target: &str,
        data_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DataError> {
        let grant = self
            .grants
            .lock()
            .get(&grant_id.0)
            .cloned()
            .ok_or(DataError::CrossDomainInvalid)?;
        if &grant.tenant_id != tenant
            || grant.source_zone != source
            || grant.target_zone != target
            || grant.data_hash != data_hash
            || now >= grant.expires_at
        {
            return Err(DataError::CrossDomainInvalid);
        }
        if !self.used.lock().insert(grant_id.0.clone()) {
            return Err(DataError::CrossDomainReplayed);
        }
        Ok(())
    }
}

pub struct RetentionResolver;
impl RetentionResolver {
    pub fn resolve(label: &DataLabel, legal_hold: bool) -> Result<u64, DataError> {
        validate_label(label)?;
        if legal_hold {
            Ok(u64::MAX)
        } else {
            Ok(retention_for(label.classification))
        }
    }
}

fn scan_json_value(
    scanner: &DlpScanner,
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    findings: &mut Vec<DlpFinding>,
) -> Result<(), DataError> {
    *nodes = nodes.checked_add(1).ok_or(DataError::ContentInvalid)?;
    if depth > MAX_JSON_SCAN_DEPTH
        || *nodes > MAX_JSON_SCAN_NODES
        || path.len() > 4096
        || findings.len() > MAX_DLP_FINDINGS
    {
        return Err(DataError::ContentInvalid);
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let child = format!("{path}.{key}");
                if ["password", "token", "secret", "api_key", "authorization"]
                    .contains(&key.to_ascii_lowercase().as_str())
                {
                    if findings.len() == MAX_DLP_FINDINGS {
                        return Err(DataError::ContentInvalid);
                    }
                    findings.push(finding(
                        DlpFindingKind::Secret,
                        &child,
                        value.to_string().as_bytes(),
                        true,
                    ));
                }
                scan_json_value(scanner, value, &child, depth + 1, nodes, findings)?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                scan_json_value(
                    scanner,
                    value,
                    &format!("{path}[{index}]"),
                    depth + 1,
                    nodes,
                    findings,
                )?;
            }
        }
        Value::String(text) => {
            let mut text_findings = if text.is_empty() {
                Vec::new()
            } else {
                scanner.scan_bytes(text.as_bytes())?
            };
            for finding in &mut text_findings {
                finding.path = path.into();
            }
            if findings
                .len()
                .checked_add(text_findings.len())
                .is_none_or(|count| count > MAX_DLP_FINDINGS)
            {
                return Err(DataError::ContentInvalid);
            }
            findings.append(&mut text_findings);
        }
        _ => {}
    }
    Ok(())
}
fn finding(kind: DlpFindingKind, path: &str, bytes: &[u8], blocking: bool) -> DlpFinding {
    DlpFinding {
        kind,
        path: path.into(),
        value_hash: hex(Sha256::digest(bytes)),
        blocking,
    }
}
fn looks_base64(text: &str) -> bool {
    let value = text.trim();
    value.len() >= 16
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-' | b'=')
        })
        && value.bytes().filter(|byte| *byte == b'=').count() <= 2
        && value
            .find('=')
            .is_none_or(|index| value[index..].bytes().all(|byte| byte == b'='))
}

fn decode_base64_layer(value: &str) -> Option<Vec<u8>> {
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(value).ok())
}
fn validate_label(label: &DataLabel) -> Result<(), DataError> {
    if label.schema_version != DATA_SCHEMA_VERSION
        || label.retention_label.is_empty()
        || label.retention_label.len() > 128
        || !label
            .retention_label
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || label.lineage.source_id.is_empty()
        || label.lineage.source_id.len() > 512
        || !label
            .lineage
            .source_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || !is_digest(&label.lineage.source_hash)
        || label.lineage.transformation_hashes.len() > 1024
        || label
            .lineage
            .transformation_hashes
            .iter()
            .any(|value| !is_digest(value))
        || label
            .lineage
            .transformation_hashes
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != label.lineage.transformation_hashes.len()
        || label.domain_tags.len() > 64
        || label.domain_tags.iter().any(|value| {
            value.is_empty()
                || value.len() > 256
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        || label.jurisdictions.is_empty()
        || label.jurisdictions.len() > 32
        || label
            .jurisdictions
            .iter()
            .any(|value| !valid_jurisdiction(value))
        || label.confidence == LabelConfidence::Unknown
            && label.classification < DataClassification::Restricted
        || label.contains_secret
            && (label.classification < DataClassification::Restricted || !label.export_restricted)
        || label.contains_personal_data
            && (label.classification != DataClassification::Regulated || !label.export_restricted)
    {
        Err(DataError::LabelInvalid)
    } else {
        Ok(())
    }
}

pub fn validate_data_label(label: &DataLabel) -> Result<(), DataError> {
    validate_label(label)
}
fn retention_for(classification: DataClassification) -> u64 {
    match classification {
        DataClassification::Public => 365 * 24 * 3600,
        DataClassification::Internal => 180 * 24 * 3600,
        DataClassification::Confidential => 90 * 24 * 3600,
        DataClassification::Restricted => 30 * 24 * 3600,
        DataClassification::Regulated => 7 * 24 * 3600,
    }
}
fn retention_label_for(classification: DataClassification) -> &'static str {
    match classification {
        DataClassification::Public => "PUBLIC_365D",
        DataClassification::Internal => "INTERNAL_180D",
        DataClassification::Confidential => "CONFIDENTIAL_90D",
        DataClassification::Restricted => "RESTRICTED_30D",
        DataClassification::Regulated => "REGULATED_7D_REVIEW",
    }
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn valid_jurisdiction(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DataError {
    #[error("DATA_LABEL_INVALID")]
    LabelInvalid,
    #[error("DATA_DLP_UNAVAILABLE")]
    DlpUnavailable,
    #[error("DATA_DLP_DENIED")]
    DlpDenied,
    #[error("DATA_SECRET_DENIED")]
    SecretDenied,
    #[error("DATA_FLOW_DENIED")]
    FlowDenied,
    #[error("DATA_POLICY_INVALID")]
    PolicyInvalid,
    #[error("DATA_DEPLOYMENT_INVALID")]
    DeploymentInvalid,
    #[error("DATA_CONTENT_INVALID")]
    ContentInvalid,
    #[error("DATA_CROSS_DOMAIN_INVALID")]
    CrossDomainInvalid,
    #[error("DATA_CROSS_DOMAIN_REPLAYED")]
    CrossDomainReplayed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    fn label(classification: DataClassification) -> DataLabel {
        DataLabel {
            schema_version: DATA_SCHEMA_VERSION.into(),
            classification,
            domain_tags: BTreeSet::from(["test".into()]),
            jurisdictions: BTreeSet::from(["CN".into()]),
            contains_secret: false,
            contains_personal_data: false,
            export_restricted: false,
            retention_label: "default".into(),
            confidence: LabelConfidence::Deterministic,
            lineage: DataLineageRef {
                source_id: "source".into(),
                source_hash: "a".repeat(64),
                transformation_hashes: vec![],
            },
        }
    }
    fn policy() -> DataPolicyPortImpl {
        let policy = DataPolicyPortImpl::new(PolicyVersion("data-v1".into()))
            .unwrap_or_else(|_| panic!("policy"));
        policy
            .deployments()
            .register(DeploymentPolicy {
                profile_id: "private".into(),
                mode: DeploymentMode::OnPrem,
                allowed_external_endpoints: BTreeSet::new(),
                telemetry_export: false,
                update_channel: "signed-bundle".into(),
                maximum_classification: DataClassification::Regulated,
            })
            .unwrap_or_else(|_| panic!("profile"));
        policy
            .deployments()
            .register(DeploymentPolicy {
                profile_id: "offline".into(),
                mode: DeploymentMode::Offline,
                allowed_external_endpoints: BTreeSet::new(),
                telemetry_export: false,
                update_channel: "offline-bundle".into(),
                maximum_classification: DataClassification::Regulated,
            })
            .unwrap_or_else(|_| panic!("profile"));
        policy
    }

    #[test]
    fn secret_and_base64_escape_are_blocked() {
        let scanner = DlpScanner::default();
        assert!(
            !scanner
                .scan_bytes(b"password=secret")
                .unwrap_or_default()
                .is_empty()
        );
        let encoded = STANDARD.encode("api_key=secret");
        assert!(
            scanner
                .scan_bytes(encoded.as_bytes())
                .unwrap_or_default()
                .iter()
                .any(|finding| finding.kind == DlpFindingKind::EncodedPayload)
        );
        let url_safe_unpadded = URL_SAFE_NO_PAD.encode("authorization: bearer secret");
        assert!(
            scanner
                .scan_bytes(url_safe_unpadded.as_bytes())
                .unwrap_or_default()
                .iter()
                .any(|finding| finding.kind == DlpFindingKind::EncodedPayload)
        );
    }
    #[test]
    fn restricted_public_fallback_and_offline_egress_are_denied() {
        let policy = policy();
        let request = DataPolicyRequest {
            schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
            tenant_id: TenantId::new(),
            classification: DataClassification::Restricted,
            source_jurisdiction: "CN".into(),
            destination_jurisdiction: "CN".into(),
            destination_kind: "model:PublicApi".into(),
            deployment_profile: "private".into(),
            contains_secret: false,
            cross_domain_approval_id: None,
        };
        assert!(
            !policy
                .evaluate_checked(&request)
                .unwrap_or_else(|_| panic!("decision"))
                .allowed
        );
        let offline = DataPolicyRequest {
            classification: DataClassification::Internal,
            destination_kind: "external-http".into(),
            deployment_profile: "offline".into(),
            ..request
        };
        assert!(
            !policy
                .evaluate_checked(&offline)
                .unwrap_or_else(|_| panic!("decision"))
                .allowed
        );
    }
    #[test]
    fn restricted_private_model_does_not_require_an_unperformed_outbound_transform() {
        let policy = policy();
        let decision = policy
            .evaluate_checked(&DataPolicyRequest {
                schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
                tenant_id: TenantId::new(),
                classification: DataClassification::Restricted,
                source_jurisdiction: "CN".into(),
                destination_jurisdiction: "CN".into(),
                destination_kind: "model:OnPrem".into(),
                deployment_profile: "private".into(),
                contains_secret: false,
                cross_domain_approval_id: None,
            })
            .unwrap_or_else(|_| panic!("decision"));
        assert!(decision.allowed);
        assert!(decision.required_transformations.is_empty());
        assert_eq!(decision.reason_codes, vec!["DATA_FLOW_ALLOWED"]);
    }
    #[test]
    fn explicit_https_destination_must_match_a_canonical_profile_origin() {
        let policy = policy();
        policy
            .deployments()
            .register(DeploymentPolicy {
                profile_id: "saas".into(),
                mode: DeploymentMode::Saas,
                allowed_external_endpoints: BTreeSet::from(["https://approved.example/".into()]),
                telemetry_export: false,
                update_channel: "signed".into(),
                maximum_classification: DataClassification::Confidential,
            })
            .unwrap_or_else(|_| panic!("profile"));
        let request = DataPolicyRequest {
            schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
            tenant_id: TenantId::new(),
            classification: DataClassification::Internal,
            source_jurisdiction: "CN".into(),
            destination_jurisdiction: "CN".into(),
            destination_kind: "https://approved.example/v1/process".into(),
            deployment_profile: "saas".into(),
            contains_secret: false,
            cross_domain_approval_id: None,
        };
        assert!(
            policy
                .evaluate_checked(&request)
                .unwrap_or_else(|_| panic!("decision"))
                .allowed
        );
        let denied = DataPolicyRequest {
            destination_kind: "https://unapproved.example/v1/process".into(),
            ..request
        };
        assert!(
            !policy
                .evaluate_checked(&denied)
                .unwrap_or_else(|_| panic!("decision"))
                .allowed
        );
    }
    #[test]
    fn transformation_boundary_distinguishes_private_and_saas_https_origins() {
        let policy = policy();
        policy
            .deployments()
            .register(DeploymentPolicy {
                profile_id: "private-url".into(),
                mode: DeploymentMode::OnPrem,
                allowed_external_endpoints: BTreeSet::from(["https://approved.private/".into()]),
                telemetry_export: false,
                update_channel: "signed".into(),
                maximum_classification: DataClassification::Regulated,
            })
            .unwrap_or_else(|_| panic!("profile"));
        policy
            .deployments()
            .register(DeploymentPolicy {
                profile_id: "saas-url".into(),
                mode: DeploymentMode::Saas,
                allowed_external_endpoints: BTreeSet::from(["https://approved.saas/".into()]),
                telemetry_export: false,
                update_channel: "signed".into(),
                maximum_classification: DataClassification::Regulated,
            })
            .unwrap_or_else(|_| panic!("profile"));
        let private = policy
            .evaluate_checked(&DataPolicyRequest {
                schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
                tenant_id: TenantId::new(),
                classification: DataClassification::Confidential,
                source_jurisdiction: "CN".into(),
                destination_jurisdiction: "CN".into(),
                destination_kind: "https://approved.private/v1/process".into(),
                deployment_profile: "private-url".into(),
                contains_secret: false,
                cross_domain_approval_id: None,
            })
            .unwrap_or_else(|_| panic!("decision"));
        assert!(private.allowed);
        assert!(private.required_transformations.is_empty());
        let saas = policy
            .evaluate_checked(&DataPolicyRequest {
                destination_kind: "https://approved.saas/v1/process".into(),
                deployment_profile: "saas-url".into(),
                ..DataPolicyRequest {
                    schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
                    tenant_id: TenantId::new(),
                    classification: DataClassification::Confidential,
                    source_jurisdiction: "CN".into(),
                    destination_jurisdiction: "CN".into(),
                    destination_kind: String::new(),
                    deployment_profile: String::new(),
                    contains_secret: false,
                    cross_domain_approval_id: None,
                }
            })
            .unwrap_or_else(|_| panic!("decision"));
        assert!(saas.allowed);
        assert_eq!(saas.required_transformations.len(), 2);
    }
    #[test]
    fn cross_domain_grant_is_tenant_hash_bound_and_single_use() {
        let service = CrossDomainApprovalService::default();
        let grant = CrossDomainGrant {
            schema_version: DATA_SCHEMA_VERSION.into(),
            grant_id: ApprovalId::new(),
            tenant_id: TenantId::new(),
            source_zone: "zone-a".into(),
            target_zone: "zone-b".into(),
            data_hash: "b".repeat(64),
            classification: DataClassification::Confidential,
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            single_use: true,
        };
        service
            .issue(grant.clone())
            .unwrap_or_else(|_| panic!("issue"));
        assert!(
            service
                .verify_and_consume(
                    &grant.grant_id,
                    &grant.tenant_id,
                    "zone-a",
                    "zone-b",
                    &grant.data_hash,
                    Utc::now()
                )
                .is_ok()
        );
        assert_eq!(
            service.verify_and_consume(
                &grant.grant_id,
                &grant.tenant_id,
                "zone-a",
                "zone-b",
                &grant.data_hash,
                Utc::now()
            ),
            Err(DataError::CrossDomainReplayed)
        );
    }
    #[test]
    fn unknown_confidence_cannot_be_labeled_low_risk() {
        let mut value = label(DataClassification::Public);
        value.confidence = LabelConfidence::Unknown;
        assert_eq!(validate_label(&value), Err(DataError::LabelInvalid));
    }

    #[test]
    fn encoded_compressed_content_is_blocked_without_unbounded_expansion() {
        let scanner = DlpScanner::default();
        let encoded = STANDARD.encode([0x1f, 0x8b, 0x08, 0x00]);
        let findings = scanner.scan_bytes(encoded.as_bytes()).unwrap_or_default();
        assert!(
            findings
                .iter()
                .any(|value| value.kind == DlpFindingKind::EncodedPayload)
        );
        assert!(
            findings
                .iter()
                .any(|value| value.kind == DlpFindingKind::CompressedPayload)
        );
        assert_eq!(
            scanner.scan_bytes(&vec![b'a'; MAX_INSPECTION_BYTES + 1]),
            Err(DataError::ContentInvalid)
        );
    }

    #[test]
    fn concurrent_cross_domain_replay_has_exactly_one_winner() {
        let service = Arc::new(CrossDomainApprovalService::default());
        let grant = CrossDomainGrant {
            schema_version: DATA_SCHEMA_VERSION.into(),
            grant_id: ApprovalId::new(),
            tenant_id: TenantId::new(),
            source_zone: "zone-a".into(),
            target_zone: "zone-b".into(),
            data_hash: "c".repeat(64),
            classification: DataClassification::Restricted,
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            single_use: true,
        };
        service
            .issue(grant.clone())
            .unwrap_or_else(|_| panic!("issue"));
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let service = service.clone();
                let grant = grant.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    service.verify_and_consume(
                        &grant.grant_id,
                        &grant.tenant_id,
                        "zone-a",
                        "zone-b",
                        &grant.data_hash,
                        Utc::now(),
                    )
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let successes = handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn deterministic_classifier_never_assigns_untrusted_unknown_content_public() {
        let scanner = DlpScanner::default();
        let label = DataClassifier::new(&scanner)
            .classify(
                &ClassificationRequest {
                    schema_version: DATA_SCHEMA_VERSION.into(),
                    source_id: "untrusted-upload".into(),
                    jurisdiction: "CN".into(),
                    source_trusted: false,
                    domain_tags: BTreeSet::from(["upload".into()]),
                    human_override: None,
                    human_override_evidence_ref: None,
                },
                b"ordinary looking but unverified text",
            )
            .unwrap_or_else(|_| panic!("classification"));
        assert_eq!(label.classification, DataClassification::Restricted);
        assert!(label.export_restricted);
    }
}
