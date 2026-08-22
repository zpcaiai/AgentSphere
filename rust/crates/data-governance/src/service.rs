//! Ephemeral typed evaluation, DLP, sanitization, and artifact-authorization service.
//!
//! Content is bounded in memory and is never passed to the durable authority store. Callers must
//! persist the returned metadata proposal through `/v1/data/actions`, which in turn traverses
//! Canonical Action IR, PEP, ledger, fence, and Evidence.

use crate::authority::{
    ArtifactDurablePreflight, DataAuthorityError, PostgresDataAuthorityStore, adapter_reference,
    canonical_digest, digest, identifier, sha256,
};
use crate::{
    ArtifactExportGuard, DataError, DataLabel, DataPolicyPortImpl, DeploymentPolicy,
    DlpFinding, DlpFindingKind, DlpScanner, MAX_INSPECTION_BYTES, PromptGuard,
};
use agent_trust_contracts::{DataClassification, DataPolicyDecision, DataPolicyRequest, TenantId};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

pub const POLICY_EVALUATION_SCHEMA: &str = "agenttrust.data-policy-evaluation.v1";
pub const DLP_INSPECTION_SCHEMA: &str = "agenttrust.data-dlp-inspection.v1";
pub const PROMPT_SANITIZATION_SCHEMA: &str = "agenttrust.prompt-sanitization.v1";
pub const ARTIFACT_AUTHORIZATION_SCHEMA: &str = "agenttrust.artifact-authorization.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseDlpReceipt {
    pub schema_version: String,
    pub scan_id: Uuid,
    pub tenant_id: Uuid,
    pub content_digest: String,
    pub size_bytes: u64,
    pub finding_counts: BTreeMap<String, u64>,
    pub findings_digest: String,
    pub blocking: bool,
    pub engine_revision: String,
    pub receipt_ref: String,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectAuthorizationReceipt {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub authorization_id: Uuid,
    pub object_ref: String,
    pub object_digest: String,
    pub label_digest: String,
    pub decision_id: Uuid,
    pub destination_digest: String,
    pub decision_digest: String,
    pub policy_request_digest: String,
    pub dlp_receipt_digest: String,
    pub transform_id: Option<Uuid>,
    pub transform_receipt_digest: Option<String>,
    pub cross_domain_grant_id: Option<Uuid>,
    pub cross_domain_approval_id: Option<String>,
    pub allowed: bool,
    pub worm_required: bool,
    pub receipt_ref: String,
    pub receipt_digest: String,
}

#[async_trait]
pub trait DataInspectionPort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn inspect(
        &self,
        tenant: &TenantId,
        scan_id: Uuid,
        content_digest: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<EnterpriseDlpReceipt, DataAuthorityError>;
    async fn authorize_object(
        &self,
        tenant: &TenantId,
        request: &ArtifactAuthorizationRequest,
        decision_digest: &str,
        policy_request_digest: &str,
        dlp_receipt_digest: &str,
    ) -> Result<ObjectAuthorizationReceipt, DataAuthorityError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub evaluation_id: Uuid,
    pub label: DataLabel,
    pub request: DataPolicyRequest,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationResult {
    pub schema_version: String,
    pub decision_id: Uuid,
    pub request_digest: String,
    pub decision: DataPolicyDecision,
    pub decision_digest: String,
    pub durable_record_required: bool,
    pub record_payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentEncoding {
    Identity,
    Base64,
    Gzip,
    Zip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DlpInspectionRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub scan_id: Uuid,
    pub media_type: String,
    pub content_encoding: ContentEncoding,
    /// Base64 is transport framing only. The decoded content is never logged or persisted.
    pub content_base64: String,
    pub classification: DataClassification,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DlpInspectionResult {
    pub schema_version: String,
    pub scan_id: Uuid,
    pub content_digest: String,
    pub size_bytes: u64,
    pub finding_counts: BTreeMap<String, u64>,
    pub findings_digest: String,
    pub blocking: bool,
    pub engine_revision: String,
    pub engine_receipt_ref: String,
    pub engine_receipt_digest: String,
    pub durable_record_required: bool,
    pub record_payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptSanitizationRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub transform_id: Uuid,
    pub dlp_scan_id: Uuid,
    pub media_type: String,
    pub content_encoding: ContentEncoding,
    pub content_base64: String,
    pub label: DataLabel,
    pub private_processing: bool,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PromptSanitizationResult {
    pub schema_version: String,
    pub transform_id: Uuid,
    pub sanitized_content_base64: String,
    pub input_digest: String,
    pub output_digest: String,
    pub transformations: Vec<String>,
    pub reversible: bool,
    pub dlp_receipt_digest: String,
    pub transform_receipt_digest: String,
    pub durable_record_required: bool,
    pub record_payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAuthorizationRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub authorization_id: Uuid,
    pub object_ref: String,
    pub object_digest: String,
    pub destination_digest: String,
    pub media_type: String,
    pub content_encoding: ContentEncoding,
    pub content_base64: String,
    pub label: DataLabel,
    pub label_digest: String,
    pub policy_request: DataPolicyRequest,
    pub decision_id: Uuid,
    pub dlp_scan_id: Uuid,
    pub dlp_receipt_digest: String,
    pub transform_id: Option<Uuid>,
    pub transform_receipt_digest: Option<String>,
    pub cross_domain_grant_id: Option<Uuid>,
    pub redirect_target_digests: Vec<String>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAuthorizationResult {
    pub schema_version: String,
    pub authorization_id: Uuid,
    pub allowed: bool,
    pub durable_preflight_verified: bool,
    pub label_digest: String,
    pub decision_id: Uuid,
    pub decision: DataPolicyDecision,
    pub decision_digest: String,
    pub policy_request_digest: String,
    pub dlp_scan_id: Uuid,
    pub dlp_receipt_digest: String,
    pub transform_id: Option<Uuid>,
    pub transform_receipt_digest: Option<String>,
    pub object_authorization_ref: String,
    pub object_authorization_digest: String,
    pub worm_required: bool,
    pub durable_export_intent_required: bool,
}

#[derive(Clone)]
pub struct DataDecisionService {
    policy: Arc<DataPolicyPortImpl>,
    scanner: Arc<DlpScanner>,
    inspection: Arc<dyn DataInspectionPort>,
    store: PostgresDataAuthorityStore,
}

impl DataDecisionService {
    pub fn new(
        policy_version: agent_trust_contracts::PolicyVersion,
        profiles: Vec<DeploymentPolicy>,
        inspection: Arc<dyn DataInspectionPort>,
        store: PostgresDataAuthorityStore,
    ) -> Result<Self, DataAuthorityError> {
        if profiles.is_empty() || profiles.len() > 100 {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        let policy = DataPolicyPortImpl::new(policy_version)
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        for profile in profiles {
            policy.deployments().register(profile)
                .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        }
        Ok(Self {
            policy: Arc::new(policy),
            scanner: Arc::new(DlpScanner::default()),
            inspection,
            store,
        })
    }

    pub async fn ready(&self) -> bool {
        self.scanner.is_available()
            && self.store.ready().await
            && self.inspection.ready().await
    }

    pub fn evaluate(
        &self,
        request: PolicyEvaluationRequest,
    ) -> Result<PolicyEvaluationResult, DataAuthorityError> {
        validate_policy_evaluation(&request)?;
        let request_digest = canonical_digest(&request.request)?;
        let decision = self.policy.evaluate_checked(&request.request)
            .map_err(|_| DataAuthorityError::RequestInvalid)?;
        let decision_digest = canonical_digest(&decision)?;
        let record_payload = json!({
            "decision_id": request.evaluation_id,
            "request_digest": request_digest,
            "request": request.request,
            "decision": decision,
            "decision_digest": decision_digest,
            "shadow": false,
            "evaluated_at": Utc::now(),
        });
        Ok(PolicyEvaluationResult {
            schema_version: POLICY_EVALUATION_SCHEMA.into(),
            decision_id: request.evaluation_id,
            request_digest,
            decision,
            decision_digest,
            durable_record_required: true,
            record_payload,
        })
    }

    pub async fn inspect(
        &self,
        request: DlpInspectionRequest,
    ) -> Result<DlpInspectionResult, DataAuthorityError> {
        validate_inspection_request(&request)?;
        let bytes = decode_content(&request.content_base64, request.content_encoding)?;
        let tenant = TenantId(request.tenant_id.to_string());
        let content_digest = sha256(&bytes);
        let local = local_scan(&self.scanner, &request.media_type, &bytes)?;
        let enterprise = self.inspection.inspect(
            &tenant,
            request.scan_id,
            &content_digest,
            &request.media_type,
            &bytes,
        ).await?;
        validate_enterprise_dlp(&enterprise, &request, &content_digest, bytes.len())?;
        let mut counts = enterprise.finding_counts.clone();
        for finding in &local {
            let key = finding_kind(finding.kind.clone());
            let count = counts.entry(key.into()).or_default();
            *count = count.checked_add(1)
                .filter(|value| *value <= 1_000_000)
                .ok_or(DataAuthorityError::DependencyUnavailable)?;
        }
        let findings_digest = canonical_digest(&json!({
            "enterprise_findings_digest": enterprise.findings_digest,
            "local_findings": local,
            "combined_counts": counts,
        }))?;
        let blocking = dlp_receipt_blocks(&enterprise)
            || local.iter().any(|finding| finding.blocking);
        let size_bytes = u64::try_from(bytes.len())
            .map_err(|_| DataAuthorityError::RequestInvalid)?;
        let record_payload = json!({
            "scan_id": request.scan_id,
            "content_digest": content_digest,
            "size_bytes": size_bytes,
            "finding_counts": counts,
            "findings_digest": findings_digest,
            "engine_revision": enterprise.engine_revision,
            "engine_receipt_ref": enterprise.receipt_ref,
            "engine_receipt_digest": enterprise.receipt_digest,
            "high_risk": request.classification >= DataClassification::Confidential,
            "blocking": blocking,
        });
        Ok(DlpInspectionResult {
            schema_version: DLP_INSPECTION_SCHEMA.into(),
            scan_id: request.scan_id,
            content_digest,
            size_bytes,
            finding_counts: counts,
            findings_digest,
            blocking,
            engine_revision: enterprise.engine_revision,
            engine_receipt_ref: enterprise.receipt_ref,
            engine_receipt_digest: enterprise.receipt_digest,
            durable_record_required: true,
            record_payload,
        })
    }

    pub async fn sanitize(
        &self,
        request: PromptSanitizationRequest,
    ) -> Result<PromptSanitizationResult, DataAuthorityError> {
        validate_sanitization_request(&request)?;
        let bytes = decode_content(&request.content_base64, request.content_encoding)?;
        let local = local_scan(&self.scanner, &request.media_type, &bytes)?;
        if local.iter().any(|finding| finding.kind != DlpFindingKind::PersonalData) {
            return Err(DataAuthorityError::DlpDenied);
        }
        let tenant = TenantId(request.tenant_id.to_string());
        let input_digest = sha256(&bytes);
        let enterprise = self.inspection.inspect(
            &tenant,
            request.dlp_scan_id,
            &input_digest,
            &request.media_type,
            &bytes,
        ).await?;
        validate_enterprise_common(
            &enterprise,
            request.tenant_id,
            request.dlp_scan_id,
            &input_digest,
            bytes.len(),
        )?;
        if dlp_receipt_blocks(&enterprise) {
            return Err(DataAuthorityError::DlpDenied);
        }
        let transformed = PromptGuard::new(&self.scanner)
            .sanitize(&bytes, &request.label, request.private_processing)
            .map_err(|_| DataAuthorityError::DlpDenied)?;
        // A durable transform receipt must never have an empty operation list.
        // Record a deterministic verification marker when sanitization is a no-op.
        let transformations = if transformed.transformations.is_empty() {
            vec!["DLP_VERIFIED_NO_CHANGE".into()]
        } else {
            transformed.transformations.clone()
        };
        let mut record_payload = json!({
            "transform_id": request.transform_id,
            "input_digest": transformed.original_hash,
            "output_digest": transformed.transformed_hash,
            "transformations": transformations,
            "reversible": transformed.reversible,
            "key_reference_digest": Value::Null,
            "dlp_scan_id": request.dlp_scan_id,
            "dlp_receipt_digest": enterprise.receipt_digest,
        });
        let transform_receipt_digest = canonical_digest(&record_payload)?;
        record_payload.as_object_mut()
            .ok_or(DataAuthorityError::DependencyUnavailable)?
            .insert(
                "transform_receipt_digest".into(),
                Value::String(transform_receipt_digest.clone()),
            );
        Ok(PromptSanitizationResult {
            schema_version: PROMPT_SANITIZATION_SCHEMA.into(),
            transform_id: request.transform_id,
            sanitized_content_base64: STANDARD.encode(transformed.sanitized_prompt.as_bytes()),
            input_digest: transformed.original_hash,
            output_digest: transformed.transformed_hash,
            transformations,
            reversible: transformed.reversible,
            dlp_receipt_digest: enterprise.receipt_digest,
            transform_receipt_digest,
            durable_record_required: true,
            record_payload,
        })
    }

    pub async fn authorize_artifact(
        &self,
        request: ArtifactAuthorizationRequest,
    ) -> Result<ArtifactAuthorizationResult, DataAuthorityError> {
        validate_artifact_request(&request)?;
        let bytes = decode_content(&request.content_base64, request.content_encoding)?;
        if sha256(&bytes) != request.object_digest {
            return Err(DataAuthorityError::RequestInvalid);
        }
        if local_scan(&self.scanner, &request.media_type, &bytes)?
            .iter()
            .any(|finding| finding.blocking)
        {
            return Err(DataAuthorityError::DlpDenied);
        }
        let tenant = TenantId(request.tenant_id.to_string());
        let enterprise = self.inspection.inspect(
            &tenant,
            request.dlp_scan_id,
            &request.object_digest,
            &request.media_type,
            &bytes,
        ).await?;
        validate_enterprise_common(
            &enterprise,
            request.tenant_id,
            request.dlp_scan_id,
            &request.object_digest,
            bytes.len(),
        )?;
        if dlp_receipt_blocks(&enterprise)
            || enterprise.receipt_digest != request.dlp_receipt_digest
        {
            return Err(DataAuthorityError::DlpDenied);
        }
        let decision = ArtifactExportGuard::new(&self.scanner, &self.policy)
            .inspect(&bytes, &request.label, &request.policy_request)
            .map_err(|_| DataAuthorityError::DlpDenied)?;
        let decision_digest = canonical_digest(&decision)?;
        let policy_request_digest = canonical_digest(&request.policy_request)?;
        self.store.verify_artifact_preflight(
            &tenant,
            &ArtifactDurablePreflight {
                authorization_id: request.authorization_id,
                object_ref: request.object_ref.clone(),
                object_digest: request.object_digest.clone(),
                label: serde_json::to_value(&request.label)
                    .map_err(|_| DataAuthorityError::DependencyUnavailable)?,
                label_digest: request.label_digest.clone(),
                policy_request: serde_json::to_value(&request.policy_request)
                    .map_err(|_| DataAuthorityError::DependencyUnavailable)?,
                policy_request_digest: policy_request_digest.clone(),
                decision_id: request.decision_id,
                decision: serde_json::to_value(&decision)
                    .map_err(|_| DataAuthorityError::DependencyUnavailable)?,
                decision_digest: decision_digest.clone(),
                required_transformations: decision.required_transformations
                    .iter().cloned().collect(),
                dlp_scan_id: request.dlp_scan_id,
                dlp_receipt_digest: request.dlp_receipt_digest.clone(),
                transform_id: request.transform_id,
                transform_receipt_digest: request.transform_receipt_digest.clone(),
                cross_domain_grant_id: request.cross_domain_grant_id,
                cross_domain_approval_id: request.policy_request.cross_domain_approval_id
                    .as_ref()
                    .and_then(|value| Uuid::parse_str(&value.0).ok()),
                source_jurisdiction: request.policy_request.source_jurisdiction.clone(),
                target_jurisdiction: request.policy_request.destination_jurisdiction.clone(),
                classification: request.label.classification,
            },
        ).await?;
        let object = self.inspection.authorize_object(
            &tenant,
            &request,
            &decision_digest,
            &policy_request_digest,
            &enterprise.receipt_digest,
        ).await?;
        validate_object_receipt(
            &object,
            &request,
            &decision_digest,
            &policy_request_digest,
            &enterprise.receipt_digest,
        )?;
        if !object.allowed {
            return Err(DataAuthorityError::DlpDenied);
        }
        Ok(ArtifactAuthorizationResult {
            schema_version: ARTIFACT_AUTHORIZATION_SCHEMA.into(),
            authorization_id: request.authorization_id,
            allowed: true,
            durable_preflight_verified: true,
            label_digest: request.label_digest,
            decision_id: request.decision_id,
            decision,
            decision_digest,
            policy_request_digest,
            dlp_scan_id: request.dlp_scan_id,
            dlp_receipt_digest: enterprise.receipt_digest,
            transform_id: request.transform_id,
            transform_receipt_digest: request.transform_receipt_digest,
            object_authorization_ref: object.receipt_ref,
            object_authorization_digest: object.receipt_digest,
            worm_required: object.worm_required,
            durable_export_intent_required: true,
        })
    }
}

fn validate_policy_evaluation(request: &PolicyEvaluationRequest) -> Result<(), DataAuthorityError> {
    let now = Utc::now();
    if request.schema_version != POLICY_EVALUATION_SCHEMA
        || request.request.tenant_id.0 != request.tenant_id.to_string()
        || request.request.classification != request.label.classification
        || request.request.contains_secret != request.label.contains_secret
        || request.request.source_jurisdiction.is_empty()
        || request.request.destination_jurisdiction.is_empty()
        || request.request.destination_kind.is_empty()
        || request.request.deployment_profile.is_empty()
        || request.requested_at < now - Duration::minutes(5)
        || request.requested_at > now + Duration::minutes(1)
        || crate::validate_data_label(&request.label).is_err()
    {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_inspection_request(request: &DlpInspectionRequest) -> Result<(), DataAuthorityError> {
    validate_content_request(
        &request.schema_version,
        DLP_INSPECTION_SCHEMA,
        &request.media_type,
        &request.content_base64,
        request.requested_at,
    )
}

fn validate_sanitization_request(
    request: &PromptSanitizationRequest,
) -> Result<(), DataAuthorityError> {
    validate_content_request(
        &request.schema_version,
        PROMPT_SANITIZATION_SCHEMA,
        &request.media_type,
        &request.content_base64,
        request.requested_at,
    )?;
    crate::validate_data_label(&request.label)
        .map_err(|_| DataAuthorityError::RequestInvalid)
}

fn validate_artifact_request(
    request: &ArtifactAuthorizationRequest,
) -> Result<(), DataAuthorityError> {
    validate_content_request(
        &request.schema_version,
        ARTIFACT_AUTHORIZATION_SCHEMA,
        &request.media_type,
        &request.content_base64,
        request.requested_at,
    )?;
    if !(request.object_ref.starts_with("artifact://") || request.object_ref.starts_with("object://"))
        || !identifier(&request.object_ref, 2048)
        || !digest(&request.object_digest)
        || !digest(&request.label_digest)
        || canonical_digest(&request.label).ok().as_deref()
            != Some(request.label_digest.as_str())
        || !digest(&request.destination_digest)
        || !digest(&request.dlp_receipt_digest)
        || request.transform_id.is_some() != request.transform_receipt_digest.is_some()
        || request.transform_receipt_digest.as_deref().is_some_and(|value| !digest(value))
        || request.policy_request.tenant_id.0 != request.tenant_id.to_string()
        || request.policy_request.classification != request.label.classification
        || request.policy_request.contains_secret != request.label.contains_secret
        || request.label.lineage.source_hash != request.object_digest
        || !request.label.jurisdictions.contains(&request.policy_request.source_jurisdiction)
        || !request.redirect_target_digests.is_empty()
        || request.cross_domain_grant_id.is_some()
            != request.policy_request.cross_domain_approval_id.is_some()
        || crate::validate_data_label(&request.label).is_err()
    {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn local_scan(
    scanner: &DlpScanner,
    media_type: &str,
    bytes: &[u8],
) -> Result<Vec<DlpFinding>, DataAuthorityError> {
    if media_type == "application/json" {
        let document: Value = serde_json::from_slice(bytes)
            .map_err(|_| DataAuthorityError::RequestInvalid)?;
        scanner.scan_json(&document).map_err(local_scan_error)
    } else {
        scanner.scan_bytes(bytes).map_err(local_scan_error)
    }
}

fn local_scan_error(error: DataError) -> DataAuthorityError {
    match error {
        DataError::DlpUnavailable => DataAuthorityError::DependencyUnavailable,
        DataError::ContentInvalid => DataAuthorityError::RequestInvalid,
        _ => DataAuthorityError::DlpDenied,
    }
}

fn validate_content_request(
    actual_schema: &str,
    expected_schema: &str,
    media_type: &str,
    content_base64: &str,
    requested_at: DateTime<Utc>,
) -> Result<(), DataAuthorityError> {
    let maximum_encoded = MAX_INSPECTION_BYTES
        .checked_mul(4)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_add(8))
        .ok_or(DataAuthorityError::ConfigurationInvalid)?;
    let now = Utc::now();
    if actual_schema != expected_schema
        || !matches!(
            media_type,
            "text/plain" | "application/json" | "application/octet-stream"
                | "application/pdf" | "text/csv"
        )
        || content_base64.is_empty()
        || content_base64.len() > maximum_encoded
        || requested_at < now - Duration::minutes(5)
        || requested_at > now + Duration::minutes(1)
    {
        return Err(DataAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn decode_content(
    transport_base64: &str,
    encoding: ContentEncoding,
) -> Result<Vec<u8>, DataAuthorityError> {
    let decoded = STANDARD.decode(transport_base64)
        .map_err(|_| DataAuthorityError::RequestInvalid)?;
    if decoded.is_empty() || decoded.len() > MAX_INSPECTION_BYTES {
        return Err(DataAuthorityError::RequestInvalid);
    }
    match encoding {
        ContentEncoding::Identity => Ok(decoded),
        ContentEncoding::Base64 => {
            let encoded = std::str::from_utf8(&decoded)
                .map_err(|_| DataAuthorityError::RequestInvalid)?;
            let nested = STANDARD.decode(encoded.trim())
                .map_err(|_| DataAuthorityError::RequestInvalid)?;
            if nested.is_empty() || nested.len() > MAX_INSPECTION_BYTES {
                return Err(DataAuthorityError::RequestInvalid);
            }
            Ok(nested)
        }
        // Archive expansion is delegated to a separately certified bounded unpacker. Until that
        // dependency is configured, production denies compressed input instead of scanning only
        // an outer container and producing a false negative.
        ContentEncoding::Gzip | ContentEncoding::Zip => Err(DataAuthorityError::DlpDenied),
    }
}

fn validate_enterprise_dlp(
    receipt: &EnterpriseDlpReceipt,
    request: &DlpInspectionRequest,
    content_digest: &str,
    size: usize,
) -> Result<(), DataAuthorityError> {
    validate_enterprise_common(
        receipt,
        request.tenant_id,
        request.scan_id,
        content_digest,
        size,
    )
}

fn validate_enterprise_common(
    receipt: &EnterpriseDlpReceipt,
    tenant: Uuid,
    scan_id: Uuid,
    content_digest: &str,
    size: usize,
) -> Result<(), DataAuthorityError> {
    let mut unsigned = receipt.clone();
    unsigned.receipt_digest.clear();
    let expected = canonical_digest(&unsigned)?;
    if receipt.schema_version != "agenttrust.enterprise-dlp-receipt.v1"
        || receipt.tenant_id != tenant
        || receipt.scan_id != scan_id
        || receipt.content_digest != content_digest
        || receipt.size_bytes != u64::try_from(size).map_err(|_| DataAuthorityError::RequestInvalid)?
        || receipt.finding_counts.len() > 32
        || receipt.finding_counts.keys().any(|key| {
            !matches!(
                key.as_str(),
                "SECRET" | "PERSONAL_DATA" | "INDUSTRIAL_SENSITIVE" | "ENCODED_PAYLOAD"
                    | "COMPRESSED_PAYLOAD" | "UNKNOWN"
            )
        })
        || receipt.finding_counts.values().any(|count| *count > 1_000_000)
        || !digest(&receipt.findings_digest)
        || !identifier(&receipt.engine_revision, 256)
        || !adapter_reference(&receipt.receipt_ref)
        || receipt.receipt_digest != expected
    {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn dlp_receipt_blocks(receipt: &EnterpriseDlpReceipt) -> bool {
    receipt.blocking
        || receipt.finding_counts.iter().any(|(kind, count)| {
            *count > 0
                && matches!(
                    kind.as_str(),
                    "SECRET" | "INDUSTRIAL_SENSITIVE" | "ENCODED_PAYLOAD"
                        | "COMPRESSED_PAYLOAD" | "UNKNOWN"
                )
        })
}

fn validate_object_receipt(
    receipt: &ObjectAuthorizationReceipt,
    request: &ArtifactAuthorizationRequest,
    decision_digest: &str,
    policy_request_digest: &str,
    dlp_receipt_digest: &str,
) -> Result<(), DataAuthorityError> {
    let mut unsigned = receipt.clone();
    unsigned.receipt_digest.clear();
    if receipt.schema_version != "agenttrust.object-authorization-receipt.v1"
        || receipt.tenant_id != request.tenant_id
        || receipt.authorization_id != request.authorization_id
        || receipt.object_ref != request.object_ref
        || receipt.object_digest != request.object_digest
        || receipt.label_digest != request.label_digest
        || receipt.decision_id != request.decision_id
        || receipt.destination_digest != request.destination_digest
        || receipt.decision_digest != decision_digest
        || receipt.policy_request_digest != policy_request_digest
        || receipt.dlp_receipt_digest != dlp_receipt_digest
        || receipt.transform_id != request.transform_id
        || receipt.transform_receipt_digest != request.transform_receipt_digest
        || receipt.cross_domain_grant_id != request.cross_domain_grant_id
        || receipt.cross_domain_approval_id
            != request.policy_request.cross_domain_approval_id.as_ref().map(|value| value.0.clone())
        || !receipt.worm_required
        || !receipt.receipt_ref.starts_with("object://")
        || !adapter_reference(&receipt.receipt_ref)
        || receipt.receipt_digest != canonical_digest(&unsigned)?
    {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn finding_kind(kind: DlpFindingKind) -> &'static str {
    match kind {
        DlpFindingKind::Secret => "SECRET",
        DlpFindingKind::PersonalData => "PERSONAL_DATA",
        DlpFindingKind::IndustrialSensitive => "INDUSTRIAL_SENSITIVE",
        DlpFindingKind::EncodedPayload => "ENCODED_PAYLOAD",
        DlpFindingKind::CompressedPayload => "COMPRESSED_PAYLOAD",
    }
}
