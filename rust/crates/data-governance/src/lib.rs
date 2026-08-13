//! Data classification, propagation, DLP, cross-domain, and deployment policy.

use agent_trust_contracts::{
    ApprovalId, ContractError, DataClassification, DataPolicyDecision, DataPolicyPort,
    DataPolicyRequest, PolicyVersion, SchemaVersion, TenantId,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DATA_SCHEMA_VERSION: &str = "agenttrust.data-governance.v1";

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
        if labels.is_empty() || transformation_hash.len() != 64 {
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
            domain_tags.extend(label.domain_tags.clone());
            jurisdictions.extend(label.jurisdictions.clone());
            transforms.extend(label.lineage.transformation_hashes.clone());
        }
        transforms.push(transformation_hash);
        Ok(DataLabel {
            schema_version: DATA_SCHEMA_VERSION.into(),
            classification,
            domain_tags,
            jurisdictions,
            contains_secret: labels.iter().any(|label| label.contains_secret),
            contains_personal_data: labels.iter().any(|label| label.contains_personal_data),
            export_restricted: labels.iter().any(|label| label.export_restricted),
            retention_label: strictest_retention(labels),
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
    secret_patterns: Vec<Regex>,
    personal_patterns: Vec<Regex>,
}
impl Default for DlpScanner {
    fn default() -> Self {
        Self {
            available: RwLock::new(true),
            secret_patterns: [
                r"(?i)password\s*[:=]",
                r"(?i)api[_-]?key\s*[:=]",
                r"(?i)authorization\s*:\s*bearer",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            ]
            .iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect(),
            personal_patterns: [
                r"\b\d{17}[0-9Xx]\b",
                r"\b1[3-9]\d{9}\b",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ]
            .iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect(),
        }
    }
}
impl DlpScanner {
    pub fn set_available(&self, available: bool) {
        *self.available.write() = available;
    }
    pub fn scan_bytes(&self, bytes: &[u8]) -> Result<Vec<DlpFinding>, DataError> {
        if !*self.available.read() {
            return Err(DataError::DlpUnavailable);
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
        if looks_base64(&text)
            && let Ok(decoded) = STANDARD.decode(text.trim())
        {
            let mut decoded_findings =
                self.scan_text(&String::from_utf8_lossy(&decoded), "$[base64]", true);
            if !decoded_findings.is_empty() {
                findings.push(finding(DlpFindingKind::EncodedPayload, "$", bytes, true));
                findings.append(&mut decoded_findings);
            }
        }
        Ok(findings)
    }
    pub fn scan_json(&self, value: &Value) -> Result<Vec<DlpFinding>, DataError> {
        if !*self.available.read() {
            return Err(DataError::DlpUnavailable);
        }
        let mut findings = Vec::new();
        scan_json_value(self, value, "$", &mut findings);
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
        if self.profile_id.is_empty() || self.update_channel.is_empty() {
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
        if deployment.mode == DeploymentMode::Offline
            && (request.destination_kind.contains("Public")
                || request.destination_kind.contains("external"))
        {
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
            required_transformations: if request.classification >= DataClassification::Confidential
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
    findings: &mut Vec<DlpFinding>,
) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let child = format!("{path}.{key}");
                if ["password", "token", "secret", "api_key", "authorization"]
                    .contains(&key.to_ascii_lowercase().as_str())
                {
                    findings.push(finding(
                        DlpFindingKind::Secret,
                        &child,
                        value.to_string().as_bytes(),
                        true,
                    ));
                }
                scan_json_value(scanner, value, &child, findings);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                scan_json_value(scanner, value, &format!("{path}[{index}]"), findings);
            }
        }
        Value::String(text) => findings.extend(scanner.scan_text(text, path, true)),
        _ => {}
    }
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
        && value.len().is_multiple_of(4)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}
fn validate_label(label: &DataLabel) -> Result<(), DataError> {
    if label.schema_version != DATA_SCHEMA_VERSION
        || label.retention_label.is_empty()
        || label.lineage.source_id.is_empty()
        || label.lineage.source_hash.len() != 64
        || label.jurisdictions.is_empty()
        || label.confidence == LabelConfidence::Unknown
            && label.classification < DataClassification::Restricted
    {
        Err(DataError::LabelInvalid)
    } else {
        Ok(())
    }
}
fn strictest_retention(labels: &[DataLabel]) -> String {
    labels
        .iter()
        .map(|label| label.retention_label.clone())
        .max()
        .unwrap_or_else(|| "default".into())
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
}
