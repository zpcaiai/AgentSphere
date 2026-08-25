//! Controlled HTTPS adapters for signed providers and Batch 18 runtime ports.

use crate::authority::*;
use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ActionHash, ApprovalId, ArtifactRef,
    AuthorityEvidenceControlBinding, AuthorityEvidenceEventRequest, AuthorityEvidenceSourceKind,
    DataPolicyDecision, DataPolicyRequest, EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft,
    EvidenceEventType, ExecutionId, IdempotencyKey, SignedAuthorityEvidenceReceipt, TenantId,
};
use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_CONTROL_RESPONSE: usize = 4 * 1_048_576;
const MAX_PROVIDER_RESPONSE: usize = 12 * 1_048_576;

#[derive(Debug, Clone)]
pub struct AdapterEndpoint {
    pub endpoint: Url,
    pub token_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ModelRuntimeEndpoints {
    pub data_policy: AdapterEndpoint,
    pub dlp: AdapterEndpoint,
    pub sanitizer: AdapterEndpoint,
    pub artifact_authorizer: AdapterEndpoint,
    pub data_mutation: AdapterEndpoint,
    pub data_read: AdapterEndpoint,
    pub artifact_store: AdapterEndpoint,
    pub artifact_store_jurisdiction: String,
    pub artifact_store_destination_kind: String,
    pub evidence: AdapterEndpoint,
    pub evidence_source_service: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEndpointDocument {
    schema_version: String,
    profiles: Vec<ProviderEndpointRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEndpointRecord {
    endpoint_profile: String,
    provider_key: String,
    protocol: String,
    endpoint: Url,
    token_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderKeyringDocument {
    schema_version: String,
    keys: Vec<ProviderKeyRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderKeyRecord {
    key_id: String,
    key_usage: String,
    public_key_base64url: String,
    status: String,
}

#[derive(Debug, Clone)]
struct ProviderKeyring {
    keys: BTreeMap<String, VerifyingKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyringDocument {
    schema_version: String,
    keys: Vec<EvidenceKeyRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyRecord {
    key_id: String,
    key_usage: String,
    public_key_base64url: String,
    status: String,
}

#[derive(Debug, Clone)]
struct EvidenceKeyring {
    keys: BTreeMap<String, VerifyingKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedProviderManifest {
    schema_version: String,
    provider_id: String,
    model_id: String,
    model_version: String,
    revision: u64,
    region: String,
    jurisdiction: String,
    deployment: String,
    protocol: String,
    capabilities: BTreeSet<String>,
    endpoint_profile: String,
    endpoint_digest: String,
    data_terms_version: String,
    maximum_context_bytes: usize,
    maximum_output_bytes: usize,
    cost_microunits_per_token: u64,
    issuer: String,
    key_id: String,
    key_usage: String,
    signature: String,
}

#[derive(Serialize)]
struct UnsignedManifest<'a> {
    schema_version: &'a str,
    provider_id: &'a str,
    model_id: &'a str,
    model_version: &'a str,
    revision: u64,
    region: &'a str,
    jurisdiction: &'a str,
    deployment: &'a str,
    protocol: &'a str,
    capabilities: &'a BTreeSet<String>,
    endpoint_profile: &'a str,
    endpoint_digest: &'a str,
    data_terms_version: &'a str,
    maximum_context_bytes: usize,
    maximum_output_bytes: usize,
    cost_microunits_per_token: u64,
    issuer: &'a str,
    key_id: &'a str,
    key_usage: &'a str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedProviderRevocation {
    schema_version: String,
    provider_id: String,
    model_id: String,
    model_version: String,
    provider_revision: u64,
    provider_manifest_digest: String,
    reason_code: String,
    revoked_at: DateTime<Utc>,
    issuer: String,
    key_id: String,
    key_usage: String,
    signature: String,
}

#[derive(Serialize)]
struct UnsignedRevocation<'a> {
    schema_version: &'a str,
    provider_id: &'a str,
    model_id: &'a str,
    model_version: &'a str,
    provider_revision: u64,
    provider_manifest_digest: &'a str,
    reason_code: &'a str,
    revoked_at: DateTime<Utc>,
    issuer: &'a str,
    key_id: &'a str,
    key_usage: &'a str,
}

#[derive(Debug)]
struct ApprovedProvider {
    manifest: SignedProviderManifest,
    manifest_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyEvaluationRequest {
    schema_version: String,
    tenant_id: Uuid,
    evaluation_id: Uuid,
    label: ModelDataLabel,
    request: DataPolicyRequest,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEvaluationResult {
    schema_version: String,
    decision_id: Uuid,
    request_digest: String,
    decision: DataPolicyDecision,
    decision_digest: String,
    durable_record_required: bool,
    record_payload: Value,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ContentEncoding {
    Identity,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct DlpInspectionRequest {
    schema_version: String,
    tenant_id: Uuid,
    scan_id: Uuid,
    media_type: String,
    content_encoding: ContentEncoding,
    content_base64: String,
    classification: agent_trust_contracts::DataClassification,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DlpInspectionResult {
    schema_version: String,
    scan_id: Uuid,
    content_digest: String,
    size_bytes: u64,
    finding_counts: BTreeMap<String, u64>,
    findings_digest: String,
    blocking: bool,
    engine_revision: String,
    engine_receipt_ref: String,
    engine_receipt_digest: String,
    durable_record_required: bool,
    record_payload: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct PromptSanitizationRequest {
    schema_version: String,
    tenant_id: Uuid,
    transform_id: Uuid,
    dlp_scan_id: Uuid,
    media_type: String,
    content_encoding: ContentEncoding,
    content_base64: String,
    label: ModelDataLabel,
    private_processing: bool,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptSanitizationResult {
    schema_version: String,
    transform_id: Uuid,
    sanitized_content_base64: String,
    input_digest: String,
    output_digest: String,
    transformations: Vec<String>,
    reversible: bool,
    dlp_receipt_digest: String,
    transform_receipt_digest: String,
    durable_record_required: bool,
    record_payload: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactAuthorizationRequest {
    schema_version: String,
    tenant_id: Uuid,
    authorization_id: Uuid,
    object_ref: String,
    object_digest: String,
    destination_digest: String,
    media_type: String,
    content_encoding: ContentEncoding,
    content_base64: String,
    label: ModelDataLabel,
    label_digest: String,
    policy_request: DataPolicyRequest,
    decision_id: Uuid,
    dlp_scan_id: Uuid,
    dlp_receipt_digest: String,
    transform_id: Option<Uuid>,
    transform_receipt_digest: Option<String>,
    cross_domain_grant_id: Option<Uuid>,
    redirect_target_digests: Vec<String>,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactAuthorizationResult {
    schema_version: String,
    authorization_id: Uuid,
    allowed: bool,
    durable_preflight_verified: bool,
    label_digest: String,
    decision_id: Uuid,
    decision: DataPolicyDecision,
    decision_digest: String,
    policy_request_digest: String,
    dlp_scan_id: Uuid,
    dlp_receipt_digest: String,
    transform_id: Option<Uuid>,
    transform_receipt_digest: Option<String>,
    object_authorization_ref: String,
    object_authorization_digest: String,
    worm_required: bool,
    durable_export_intent_required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DataOperation {
    RegisterLabel,
    RecordPolicyDecision,
    RecordDlpScan,
    RecordTransformReceipt,
    ConsumeCrossDomainGrant,
    AuthorizeExport,
    CompleteExport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataCommandRequest {
    schema_version: String,
    tenant_id: Uuid,
    command_id: Uuid,
    task_id: Uuid,
    resource: String,
    operation: DataOperation,
    expected_resource_version: u64,
    requested_at: DateTime<Utc>,
    payload: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataActionReceipt {
    schema_version: String,
    action_id: String,
    task_id: String,
    accepted: bool,
    execution_pending: bool,
    ingress_digest: String,
    ledger_evidence_ref: String,
    ledger_evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataMutationResult {
    schema_version: String,
    command_id: Uuid,
    operation: DataOperation,
    resource: String,
    resource_version: u64,
    state: String,
    result_digest: String,
    evidence_outbox_ref: String,
    evidence_ref: Option<String>,
    evidence_digest: Option<String>,
    safe_receipts: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWriteRequest<'a> {
    schema_version: &'static str,
    tenant_id: String,
    authorization_ref: &'a str,
    authorization_digest: &'a str,
    export_evidence_ref: &'a str,
    export_evidence_digest: &'a str,
    object_ref: &'a str,
    object_digest: &'a str,
    media_type: &'static str,
    content_base64: String,
    idempotency_key: &'a str,
    trace_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWriteResponse {
    schema_version: String,
    artifact_ref: String,
    artifact_digest: String,
    watermark_digest: String,
    signature_digest: String,
    worm_receipt_ref: String,
    worm_receipt_digest: String,
    receipt_ref: String,
    receipt_digest: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelEvidencePayload<'a> {
    schema_version: &'static str,
    tenant_id: String,
    action_hash: &'a str,
    authorization_digest: &'a str,
    policy_decision_digest: &'a str,
    authorization_evidence_ref: &'a str,
    authorization_evidence_digest: &'a str,
    ledger_execution_id: Uuid,
    ledger_event_id: Uuid,
    ledger_event_digest: &'a str,
    fence_digest: &'a str,
    resource_version: &'a str,
    idempotency_key: &'a str,
    request_digest: String,
    prompt_digest: String,
    provider_key: &'a str,
    provider_request_id: &'a str,
    provider_manifest_digest: &'a str,
    route_decision_digest: &'a str,
    data_policy_version: &'a str,
    pre_transform_policy_decision_digest: &'a str,
    data_policy_decision_digest: &'a str,
    transformation_digest: &'a str,
    input_dlp_report_digest: &'a str,
    pre_transform_policy_evidence_ref: &'a str,
    pre_transform_policy_evidence_digest: &'a str,
    data_policy_evidence_ref: &'a str,
    data_policy_evidence_digest: &'a str,
    transform_evidence_ref: &'a Option<String>,
    transform_evidence_digest: &'a Option<String>,
    input_dlp_evidence_ref: &'a str,
    input_dlp_evidence_digest: &'a str,
    output_dlp_report_digest: &'a str,
    residency_policy_evidence_ref: &'a str,
    residency_policy_evidence_digest: &'a str,
    output_dlp_evidence_ref: &'a str,
    output_dlp_evidence_digest: &'a str,
    output_label_evidence_ref: &'a str,
    output_label_evidence_digest: &'a str,
    artifact_policy_evidence_ref: &'a str,
    artifact_policy_evidence_digest: &'a str,
    grant_consumption_evidence_ref: &'a Option<String>,
    grant_consumption_evidence_digest: &'a Option<String>,
    export_authorization_evidence_ref: &'a str,
    export_authorization_evidence_digest: &'a str,
    export_completion_evidence_ref: &'a str,
    export_completion_evidence_digest: &'a str,
    artifact_store_receipt_ref: &'a str,
    artifact_store_receipt_digest: &'a str,
    artifact_ref: &'a str,
    artifact_digest: &'a str,
    output_digest: &'a str,
    input_tokens: u64,
    output_tokens: u64,
    cost_microunits: u64,
    trace_id: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BillingEvidenceRequest<'a> {
    schema_version: &'static str,
    tenant_id: String,
    action_hash: &'a str,
    authorization_digest: &'a str,
    policy_decision_digest: &'a str,
    authorization_evidence_ref: &'a str,
    authorization_evidence_digest: &'a str,
    ledger_execution_id: Uuid,
    ledger_event_id: Uuid,
    ledger_event_digest: &'a str,
    fence_digest: &'a str,
    resource_version: &'a str,
    idempotency_key: &'a str,
    provider_id: &'a str,
    statement_period: &'a str,
    statement_digest: &'a str,
    residency_policy_evidence_digest: &'a str,
    matched: bool,
    matched_requests: u64,
    total_metered_microunits: u64,
    total_billed_microunits: u64,
    trace_id: &'a str,
}

#[derive(Clone)]
pub struct HttpProductionModelRuntime {
    pool: PgPool,
    client: reqwest::Client,
    endpoints: ModelRuntimeEndpoints,
    provider_profiles: BTreeMap<String, ProviderEndpointRecord>,
    keyring: ProviderKeyring,
    evidence_keyring: EvidenceKeyring,
}

impl HttpProductionModelRuntime {
    pub fn from_files(
        pool: PgPool,
        client: reqwest::Client,
        endpoints: ModelRuntimeEndpoints,
        provider_profiles_file: &Path,
        provider_keyring_file: &Path,
        evidence_keyring_file: &Path,
    ) -> Result<Self, AuthorityError> {
        validate_endpoint(&endpoints.data_policy)?;
        validate_endpoint(&endpoints.dlp)?;
        validate_endpoint(&endpoints.sanitizer)?;
        validate_endpoint(&endpoints.artifact_authorizer)?;
        validate_endpoint(&endpoints.data_mutation)?;
        validate_endpoint(&endpoints.data_read)?;
        validate_endpoint(&endpoints.artifact_store)?;
        validate_endpoint(&endpoints.evidence)?;
        if !jurisdiction(&endpoints.artifact_store_jurisdiction)
            || !identifier(&endpoints.artifact_store_destination_kind, 2048)
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        if endpoints.evidence_source_service.is_empty()
            || endpoints.evidence_source_service.len() > 256
            || !(endpoints.evidence_source_service.starts_with("DNS:")
                || endpoints.evidence_source_service.starts_with("URI:"))
            || endpoints
                .evidence_source_service
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let provider_profiles: ProviderEndpointDocument = private_json(provider_profiles_file)?;
        if provider_profiles.schema_version != "agenttrust.model-provider-endpoints.v1"
            || provider_profiles.profiles.len() < 2
            || provider_profiles.profiles.len() > 1000
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let mut profiles = BTreeMap::new();
        for profile in provider_profiles.profiles {
            validate_provider_endpoint(&profile)?;
            if profiles
                .insert(profile.endpoint_profile.clone(), profile)
                .is_some()
            {
                return Err(AuthorityError::ConfigurationInvalid);
            }
        }
        let keyring_document: ProviderKeyringDocument = private_json(provider_keyring_file)?;
        if keyring_document.schema_version != "agenttrust.model-provider-keyring.v1"
            || keyring_document.keys.is_empty()
            || keyring_document.keys.len() > 1000
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for record in keyring_document.keys {
            if record.status != "ACTIVE"
                || !matches!(
                    record.key_usage.as_str(),
                    "MODEL_PROVIDER_MANIFEST" | "MODEL_PROVIDER_REVOCATION"
                )
                || record.key_id.is_empty()
                || record.key_id.len() > 128
            {
                return Err(AuthorityError::ConfigurationInvalid);
            }
            let raw = URL_SAFE_NO_PAD
                .decode(record.public_key_base64url.as_bytes())
                .map_err(|_| AuthorityError::ConfigurationInvalid)?;
            let key_bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| AuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| AuthorityError::ConfigurationInvalid)?;
            if keys
                .insert(format!("{}:{}", record.key_usage, record.key_id), key)
                .is_some()
            {
                return Err(AuthorityError::ConfigurationInvalid);
            }
        }
        let evidence_document: EvidenceKeyringDocument = private_json(evidence_keyring_file)?;
        if evidence_document.schema_version != "agenttrust.model-evidence-keyring.v1"
            || evidence_document.keys.is_empty()
            || evidence_document.keys.len() > 1000
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let mut evidence_keys = BTreeMap::new();
        for record in evidence_document.keys {
            if record.status != "ACTIVE"
                || record.key_usage != "AUTHORITY_EVIDENCE_RECEIPT"
                || record.key_id.is_empty()
                || record.key_id.len() > 128
            {
                return Err(AuthorityError::ConfigurationInvalid);
            }
            let raw = URL_SAFE_NO_PAD
                .decode(record.public_key_base64url.as_bytes())
                .map_err(|_| AuthorityError::ConfigurationInvalid)?;
            let key_bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| AuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| AuthorityError::ConfigurationInvalid)?;
            if evidence_keys.insert(record.key_id, key).is_some() {
                return Err(AuthorityError::ConfigurationInvalid);
            }
        }
        Ok(Self {
            pool,
            client,
            endpoints,
            provider_profiles: profiles,
            keyring: ProviderKeyring { keys },
            evidence_keyring: EvidenceKeyring {
                keys: evidence_keys,
            },
        })
    }

    async fn approved_providers(
        &self,
        request: &ModelExecutionRequest,
    ) -> Result<Vec<ApprovedProvider>, AuthorityError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.set_config('app.tenant_id',$1,true)")
            .bind(request.tenant_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let rows = sqlx::query(
            "SELECT r.manifest,r.manifest_digest,a.allowed_deployment_profiles,\
             a.allowed_source_jurisdictions,a.maximum_request_microunits,\
             x.reason_code AS revocation_reason,x.revoked_at,x.issuer AS revocation_issuer,\
             x.signing_key_id AS revocation_key_id,x.revocation_digest,x.signature AS revocation_signature \
             FROM public.model_tenant_provider_approvals a JOIN public.model_provider_revisions r \
             ON r.provider_id=a.provider_id AND r.model_id=a.model_id \
             AND r.model_version=a.model_version AND r.revision=a.provider_revision \
             LEFT JOIN public.model_provider_revocations x ON x.provider_id=r.provider_id \
             AND x.model_id=r.model_id AND x.model_version=r.model_version \
             AND x.provider_revision=r.revision \
             WHERE a.tenant_id=$1 AND a.status='ACTIVE' AND a.expires_at>now() \
             AND r.status='ACTIVE' ORDER BY r.provider_id,r.model_id,r.model_version,r.revision",
        )
        .bind(request.tenant_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let mut approved = Vec::new();
        for row in rows {
            let value: Value = row
                .try_get("manifest")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let manifest: SignedProviderManifest = serde_json::from_value(value.clone())
                .map_err(|_| AuthorityError::ProviderDenied)?;
            let stored_digest: String = row
                .try_get("manifest_digest")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let deployments: Vec<String> = row
                .try_get("allowed_deployment_profiles")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let jurisdictions: Vec<String> = row
                .try_get("allowed_source_jurisdictions")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let maximum_request: i64 = row
                .try_get("maximum_request_microunits")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            verify_manifest(&self.keyring, &manifest, &value, &stored_digest)?;
            if let Some(revocation_digest) = row
                .try_get::<Option<String>, _>("revocation_digest")
                .map_err(|_| AuthorityError::DependencyUnavailable)?
            {
                let revocation = SignedProviderRevocation {
                    schema_version: "agenttrust.model-provider-revocation.v1".into(),
                    provider_id: manifest.provider_id.clone(),
                    model_id: manifest.model_id.clone(),
                    model_version: manifest.model_version.clone(),
                    provider_revision: manifest.revision,
                    provider_manifest_digest: stored_digest.clone(),
                    reason_code: row
                        .try_get("revocation_reason")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                    revoked_at: row
                        .try_get("revoked_at")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                    issuer: row
                        .try_get("revocation_issuer")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                    key_id: row
                        .try_get("revocation_key_id")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                    key_usage: "MODEL_PROVIDER_REVOCATION".into(),
                    signature: row
                        .try_get("revocation_signature")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                };
                verify_revocation(&self.keyring, &revocation, &revocation_digest)?;
                continue;
            }
            let provider_key = provider_key(&manifest);
            let endpoint = self
                .provider_profiles
                .get(&manifest.endpoint_profile)
                .ok_or(AuthorityError::ProviderDenied)?;
            if endpoint.provider_key != provider_key
                || endpoint.protocol != manifest.protocol
                || digest(endpoint.endpoint.as_str().as_bytes()) != manifest.endpoint_digest
                || !request.allowed_provider_ids.contains(&manifest.provider_id)
                || !request
                    .required_capabilities
                    .is_subset(&manifest.capabilities)
                || request.prompt_utf8.len() > manifest.maximum_context_bytes
                || request.maximum_output_bytes > manifest.maximum_output_bytes
                || !deployments.contains(&request.deployment_profile)
                || !jurisdictions.contains(&request.source_jurisdiction)
                || maximum_request <= 0
                || request.maximum_cost_microunits
                    > u64::try_from(maximum_request).map_err(|_| AuthorityError::ProviderDenied)?
            {
                continue;
            }
            approved.push(ApprovedProvider {
                manifest,
                manifest_digest: stored_digest,
            });
        }
        Ok(approved)
    }

    async fn evaluate_policy(
        &self,
        request: &PolicyEvaluationRequest,
    ) -> Result<PolicyEvaluationResult, AuthorityError> {
        let response: PolicyEvaluationResult = self
            .post_tenant_json(
                &self.endpoints.data_policy,
                "/v1/internal/data/evaluate",
                request.tenant_id,
                request,
                MAX_CONTROL_RESPONSE,
            )
            .await?;
        let request_digest = canonical_digest(&request.request)?;
        let decision_digest = canonical_digest(&response.decision)?;
        if response.schema_version != "agenttrust.data-policy-evaluation.v1"
            || response.decision_id != request.evaluation_id
            || response.request_digest != request_digest
            || response.decision_digest != decision_digest
            || !response.durable_record_required
            || !valid_shared_policy_decision(&response.decision)
            || response.record_payload.get("decision_id")
                != Some(&Value::String(response.decision_id.to_string()))
            || response.record_payload.get("request_digest")
                != Some(&Value::String(response.request_digest.clone()))
            || response.record_payload.get("request")
                != serde_json::to_value(&request.request).ok().as_ref()
            || response.record_payload.get("decision")
                != serde_json::to_value(&response.decision).ok().as_ref()
            || response.record_payload.get("decision_digest")
                != Some(&Value::String(response.decision_digest.clone()))
            || response.record_payload.get("shadow") != Some(&Value::Bool(false))
            || response
                .record_payload
                .as_object()
                .is_none_or(|value| value.len() != 7)
        {
            return Err(AuthorityError::ProviderDenied);
        }
        Ok(response)
    }

    async fn inspect_dlp(
        &self,
        request: &DlpInspectionRequest,
    ) -> Result<DlpInspectionResult, AuthorityError> {
        let response: DlpInspectionResult = self
            .post_tenant_json(
                &self.endpoints.dlp,
                "/v1/internal/data/scan",
                request.tenant_id,
                request,
                MAX_CONTROL_RESPONSE,
            )
            .await?;
        let decoded = STANDARD
            .decode(request.content_base64.as_bytes())
            .map_err(|_| AuthorityError::RequestInvalid)?;
        let high_risk =
            request.classification >= agent_trust_contracts::DataClassification::Confidential;
        if response.schema_version != "agenttrust.data-dlp-inspection.v1"
            || response.scan_id != request.scan_id
            || response.content_digest != digest(&decoded)
            || response.size_bytes != decoded.len() as u64
            || response.finding_counts.len() > 16
            || response.finding_counts.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "SECRET"
                        | "PERSONAL_DATA"
                        | "INDUSTRIAL_SENSITIVE"
                        | "ENCODED_PAYLOAD"
                        | "COMPRESSED_PAYLOAD"
                        | "UNKNOWN"
                )
            })
            || response
                .finding_counts
                .values()
                .any(|value| *value > 1_000_000)
            || !lower_digest(&response.findings_digest)
            || !identifier(&response.engine_revision, 256)
            || !adapter_reference(&response.engine_receipt_ref)
            || !lower_digest(&response.engine_receipt_digest)
            || !response.durable_record_required
            || response.record_payload.get("scan_id")
                != Some(&Value::String(response.scan_id.to_string()))
            || response.record_payload.get("content_digest")
                != Some(&Value::String(response.content_digest.clone()))
            || response
                .record_payload
                .get("size_bytes")
                .and_then(Value::as_u64)
                != Some(response.size_bytes)
            || response.record_payload.get("finding_counts")
                != serde_json::to_value(&response.finding_counts).ok().as_ref()
            || response.record_payload.get("findings_digest")
                != Some(&Value::String(response.findings_digest.clone()))
            || response.record_payload.get("engine_revision")
                != Some(&Value::String(response.engine_revision.clone()))
            || response.record_payload.get("engine_receipt_ref")
                != Some(&Value::String(response.engine_receipt_ref.clone()))
            || response.record_payload.get("engine_receipt_digest")
                != Some(&Value::String(response.engine_receipt_digest.clone()))
            || response.record_payload.get("high_risk") != Some(&Value::Bool(high_risk))
            || response.record_payload.get("blocking") != Some(&Value::Bool(response.blocking))
            || response
                .record_payload
                .as_object()
                .is_none_or(|value| value.len() != 10)
        {
            return Err(AuthorityError::ProviderDenied);
        }
        Ok(response)
    }

    async fn sanitize_prompt(
        &self,
        request: &PromptSanitizationRequest,
        scan: &DlpInspectionResult,
    ) -> Result<PromptSanitizationResult, AuthorityError> {
        let response: PromptSanitizationResult = self
            .post_tenant_json(
                &self.endpoints.sanitizer,
                "/v1/internal/data/sanitize",
                request.tenant_id,
                request,
                MAX_CONTROL_RESPONSE,
            )
            .await?;
        let input = STANDARD
            .decode(request.content_base64.as_bytes())
            .map_err(|_| AuthorityError::RequestInvalid)?;
        let output = STANDARD
            .decode(response.sanitized_content_base64.as_bytes())
            .map_err(|_| AuthorityError::ProviderDenied)?;
        let mut unsigned_receipt = response.record_payload.clone();
        let recorded_receipt_digest = unsigned_receipt
            .as_object_mut()
            .and_then(|object| object.remove("transform_receipt_digest"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(AuthorityError::ProviderDenied)?;
        if response.schema_version != "agenttrust.prompt-sanitization.v1"
            || response.transform_id != request.transform_id
            || response.input_digest != digest(&input)
            || response.output_digest != digest(&output)
            || response.dlp_receipt_digest != scan.engine_receipt_digest
            || response.transform_receipt_digest != recorded_receipt_digest
            || response.transform_receipt_digest != canonical_digest(&unsigned_receipt)?
            || response.transformations.is_empty()
            || response.transformations.len() > 16
            || response
                .transformations
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != response.transformations.len()
            || response
                .transformations
                .iter()
                .any(|value| !identifier(value, 256))
            || response.reversible
            || !response.durable_record_required
            || response.record_payload.get("transform_id")
                != Some(&Value::String(response.transform_id.to_string()))
            || response.record_payload.get("input_digest")
                != Some(&Value::String(response.input_digest.clone()))
            || response.record_payload.get("output_digest")
                != Some(&Value::String(response.output_digest.clone()))
            || response.record_payload.get("transformations")
                != serde_json::to_value(&response.transformations)
                    .ok()
                    .as_ref()
            || response.record_payload.get("reversible") != Some(&Value::Bool(false))
            || response.record_payload.get("key_reference_digest") != Some(&Value::Null)
            || response.record_payload.get("dlp_scan_id")
                != Some(&Value::String(request.dlp_scan_id.to_string()))
            || response.record_payload.get("dlp_receipt_digest")
                != Some(&Value::String(response.dlp_receipt_digest.clone()))
            || response.record_payload.get("transform_receipt_digest")
                != Some(&Value::String(response.transform_receipt_digest.clone()))
            || response
                .record_payload
                .as_object()
                .is_none_or(|value| value.len() != 9)
        {
            return Err(AuthorityError::ProviderDenied);
        }
        Ok(response)
    }

    async fn persist_data_record(
        &self,
        request: &ModelExecutionRequest,
        phase: &str,
        operation: DataOperation,
        resource: String,
        expected_resource_version: u64,
        payload: Value,
    ) -> Result<DataMutationResult, AuthorityError> {
        let command_id = deterministic_uuid(&json!({
            "tenant_id": request.tenant_id,
            "model_action_id": request.action_id,
            "phase": phase,
            "operation": operation,
            "resource": resource,
            "payload_digest": canonical_digest(&payload)?,
        }))?;
        let proposed = DataCommandRequest {
            schema_version: "agenttrust.data-governance-command.v1".into(),
            tenant_id: request.tenant_id,
            command_id,
            task_id: request.task_id,
            resource: resource.clone(),
            operation,
            expected_resource_version,
            requested_at: Utc::now(),
            payload,
        };
        let idempotency_key =
            digest(format!("{}:{}:{}", request.tenant_id, request.action_id, phase).as_bytes());
        let (command, completed) = self
            .prepare_data_command(request.action_id, phase, &idempotency_key, &proposed)
            .await?;
        if let Some(result) = completed {
            return Ok(result);
        }
        let url = service_url(&self.endpoints.data_mutation.endpoint, "/v1/data/actions")?;
        let token = read_secret(&self.endpoints.data_mutation.token_file, 16, 8192)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token.as_str())
            .header("accept", "application/json")
            .header("x-agenttrust-tenant-id", request.tenant_id.to_string())
            .header("idempotency-key", &idempotency_key)
            .json(&command)
            .send()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let receipt: DataActionReceipt =
            bounded_json_response(response, MAX_CONTROL_RESPONSE).await?;
        if receipt.schema_version != "agenttrust.data-governance-action-receipt.v1"
            || receipt.action_id != command.command_id.to_string()
            || receipt.task_id != request.task_id.to_string()
            || !receipt.accepted
            || !receipt.execution_pending
            || !lower_digest(&receipt.ingress_digest)
            || !evidence_reference(&receipt.ledger_evidence_ref)
            || !lower_digest(&receipt.ledger_evidence_digest)
        {
            return Err(AuthorityError::DependencyUnavailable);
        }
        let result = self
            .completed_data_mutation(
                request.tenant_id,
                command.command_id,
                command.operation,
                &command.resource,
            )
            .await?;
        self.complete_data_command(
            request.action_id,
            phase,
            &idempotency_key,
            &command,
            &result,
        )
        .await?;
        Ok(result)
    }

    async fn prepare_data_command(
        &self,
        action_id: Uuid,
        phase: &str,
        idempotency_key: &str,
        proposed: &DataCommandRequest,
    ) -> Result<(DataCommandRequest, Option<DataMutationResult>), AuthorityError> {
        if !identifier(phase, 256) || !identifier(idempotency_key, 128) {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let command_value =
            serde_json::to_value(proposed).map_err(|_| AuthorityError::DependencyUnavailable)?;
        let command_digest = canonical_digest(proposed)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.set_config('app.tenant_id',$1,true)")
            .bind(proposed.tenant_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
            .bind(format!(
                "model-data-governance:{}:{idempotency_key}",
                proposed.tenant_id
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT action_id,phase,idempotency_key,command,command_digest,state,mutation_result \
             FROM public.model_data_governance_outbox WHERE tenant_id=$1 \
             AND (command_id=$2 OR idempotency_key=$3 OR (action_id=$4 AND phase=$5)) FOR UPDATE",
        )
        .bind(proposed.tenant_id)
        .bind(proposed.command_id)
        .bind(idempotency_key)
        .bind(action_id)
        .bind(phase)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?
        {
            let existing: DataCommandRequest = serde_json::from_value(
                row.try_get("command")
                    .map_err(|_| AuthorityError::DependencyUnavailable)?,
            )
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let stored_digest: String = row
                .try_get("command_digest")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            if row.try_get::<Uuid, _>("action_id").ok() != Some(action_id)
                || row.try_get::<String, _>("phase").ok().as_deref() != Some(phase)
                || row.try_get::<String, _>("idempotency_key").ok().as_deref()
                    != Some(idempotency_key)
                || stored_digest != canonical_digest(&existing)?
                || !same_data_command_material(&existing, proposed)
            {
                return Err(AuthorityError::IdempotencyConflict);
            }
            let state: String = row
                .try_get("state")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let completed = if state == "COMPLETED" {
                let result: DataMutationResult = serde_json::from_value(
                    row.try_get("mutation_result")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                )
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
                validate_completed_mutation(&result, &existing)?;
                Some(result)
            } else if state == "PREPARED" {
                None
            } else {
                return Err(AuthorityError::DependencyUnavailable);
            };
            transaction
                .commit()
                .await
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            return Ok((existing, completed));
        }
        sqlx::query(
            "INSERT INTO public.model_data_governance_outbox \
             (tenant_id,command_id,action_id,phase,idempotency_key,command,command_digest,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,'PREPARED')",
        )
        .bind(proposed.tenant_id)
        .bind(proposed.command_id)
        .bind(action_id)
        .bind(phase)
        .bind(idempotency_key)
        .bind(command_value)
        .bind(command_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        Ok((proposed.clone(), None))
    }

    async fn complete_data_command(
        &self,
        action_id: Uuid,
        phase: &str,
        idempotency_key: &str,
        command: &DataCommandRequest,
        result: &DataMutationResult,
    ) -> Result<(), AuthorityError> {
        validate_completed_mutation(result, command)?;
        let result_value =
            serde_json::to_value(result).map_err(|_| AuthorityError::DependencyUnavailable)?;
        let evidence_ref = mutation_evidence_ref(result)?;
        let evidence_digest = mutation_evidence_digest(result)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.set_config('app.tenant_id',$1,true)")
            .bind(command.tenant_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let updated = sqlx::query(
            "UPDATE public.model_data_governance_outbox SET state='COMPLETED',\
             mutation_result=$7,evidence_ref=$8,evidence_digest=$9,updated_at=now(),completed_at=now() \
             WHERE tenant_id=$1 AND command_id=$2 AND action_id=$3 AND phase=$4 \
             AND idempotency_key=$5 AND command_digest=$6 AND state='PREPARED'",
        )
        .bind(command.tenant_id)
        .bind(command.command_id)
        .bind(action_id)
        .bind(phase)
        .bind(idempotency_key)
        .bind(canonical_digest(command)?)
        .bind(&result_value)
        .bind(evidence_ref)
        .bind(evidence_digest)
        .execute(&mut *transaction).await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if updated.rows_affected() != 1 {
            let existing: Value = sqlx::query_scalar(
                "SELECT mutation_result FROM public.model_data_governance_outbox \
                 WHERE tenant_id=$1 AND command_id=$2 AND state='COMPLETED'",
            )
            .bind(command.tenant_id)
            .bind(command.command_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?
            .ok_or(AuthorityError::IdempotencyConflict)?;
            if existing != result_value {
                return Err(AuthorityError::IdempotencyConflict);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    }

    async fn completed_data_mutation(
        &self,
        tenant_id: Uuid,
        command_id: Uuid,
        operation: DataOperation,
        resource: &str,
    ) -> Result<DataMutationResult, AuthorityError> {
        let path = format!("/v1/authoritative/data/mutations/{command_id}");
        let url = service_url(&self.endpoints.data_read.endpoint, &path)?;
        let token = read_secret(&self.endpoints.data_read.token_file, 16, 8192)?;
        for attempt in 0..40_u8 {
            let response = self
                .client
                .get(url.clone())
                .bearer_auth(token.as_str())
                .header("accept", "application/json")
                .header("x-agenttrust-tenant-id", tenant_id.to_string())
                .send()
                .await
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                if attempt == 39 {
                    return Err(AuthorityError::DependencyUnavailable);
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                continue;
            }
            let result: DataMutationResult =
                bounded_json_response(response, MAX_CONTROL_RESPONSE).await?;
            validate_completed_mutation_fields(&result, command_id, operation, resource)?;
            return Ok(result);
        }
        Err(AuthorityError::DependencyUnavailable)
    }

    async fn post_tenant_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        endpoint: &AdapterEndpoint,
        path: &str,
        tenant_id: Uuid,
        body: &T,
        maximum: usize,
    ) -> Result<R, AuthorityError> {
        let url = service_url(&endpoint.endpoint, path)?;
        let token = read_secret(&endpoint.token_file, 16, 8192)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token.as_str())
            .header("accept", "application/json")
            .header("x-agenttrust-tenant-id", tenant_id.to_string())
            .json(body)
            .send()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        bounded_json_response(response, maximum).await
    }

    async fn append_evidence_event(
        &self,
        proposed: &AuthorityEvidenceEventRequest,
        action_id: Uuid,
        event_kind: &str,
    ) -> Result<SignedAuthorityEvidenceReceipt, AuthorityError> {
        let (request, delivered) = self
            .prepare_authority_evidence(proposed, action_id, event_kind)
            .await?;
        if let Some(receipt) = delivered {
            return Ok(receipt);
        }
        let url = service_url(
            &self.endpoints.evidence.endpoint,
            "/v1/evidence/authority-events",
        )?;
        let token = read_secret(&self.endpoints.evidence.token_file, 16, 8192)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token.as_str())
            .header("accept", "application/json")
            .header("x-agenttrust-tenant-id", &request.tenant_id.0)
            .header("idempotency-key", &request.idempotency_key.0)
            .header(
                "x-agenttrust-authority-event-id",
                &request.authority_event_id,
            )
            .header("x-agenttrust-payload-digest", &request.event.payload_hash)
            .json(&request)
            .send()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let receipt: SignedAuthorityEvidenceReceipt =
            bounded_json_response(response, MAX_CONTROL_RESPONSE).await?;
        let key = self
            .evidence_keyring
            .keys
            .get(&receipt.key_id)
            .ok_or(AuthorityError::DependencyUnavailable)?;
        let expected_request_digest = request
            .request_digest()
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if receipt.tenant_id != request.tenant_id
            || receipt.task_id != request.task_id
            || receipt.authority_event_id != request.authority_event_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.source_kind != request.source_kind
            || receipt.request_digest != expected_request_digest
            || receipt.payload_digest != request.event.payload_hash
            || receipt.event.draft != request.event
            || receipt.event.draft.source_service != self.endpoints.evidence_source_service
            || receipt.verify(key, Utc::now()).is_err()
        {
            return Err(AuthorityError::DependencyUnavailable);
        }
        self.complete_authority_evidence(&request, action_id, event_kind, &receipt)
            .await?;
        Ok(receipt)
    }

    async fn prepare_authority_evidence(
        &self,
        proposed: &AuthorityEvidenceEventRequest,
        action_id: Uuid,
        event_kind: &str,
    ) -> Result<
        (
            AuthorityEvidenceEventRequest,
            Option<SignedAuthorityEvidenceReceipt>,
        ),
        AuthorityError,
    > {
        if !identifier(event_kind, 128)
            || !event_kind
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let tenant =
            Uuid::parse_str(&proposed.tenant_id.0).map_err(|_| AuthorityError::BindingInvalid)?;
        let event_id = Uuid::parse_str(&proposed.authority_event_id)
            .map_err(|_| AuthorityError::BindingInvalid)?;
        let request_digest = proposed
            .request_digest()
            .map_err(|_| AuthorityError::BindingInvalid)?;
        let request_value =
            serde_json::to_value(proposed).map_err(|_| AuthorityError::DependencyUnavailable)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.set_config('app.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
            .bind(format!(
                "model-authority-evidence:{tenant}:{}",
                proposed.idempotency_key.0
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT action_id,event_kind,request,request_digest,state,signed_receipt \
             FROM public.model_authority_evidence_outbox WHERE tenant_id=$1 \
             AND (authority_event_id=$2 OR idempotency_key=$3) FOR UPDATE",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(&proposed.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?
        {
            let existing: AuthorityEvidenceEventRequest = serde_json::from_value(
                row.try_get("request")
                    .map_err(|_| AuthorityError::DependencyUnavailable)?,
            )
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let stored_digest: String = row
                .try_get("request_digest")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            if row.try_get::<Uuid, _>("action_id").ok() != Some(action_id)
                || row.try_get::<String, _>("event_kind").ok().as_deref() != Some(event_kind)
                || stored_digest
                    != existing
                        .request_digest()
                        .map_err(|_| AuthorityError::DependencyUnavailable)?
                || !same_authority_evidence_material(&existing, proposed)
            {
                return Err(AuthorityError::IdempotencyConflict);
            }
            let state: String = row
                .try_get("state")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let delivered = if state == "DELIVERED" {
                let receipt: SignedAuthorityEvidenceReceipt = serde_json::from_value(
                    row.try_get("signed_receipt")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                )
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
                verify_authority_receipt(
                    &self.evidence_keyring,
                    &self.endpoints.evidence_source_service,
                    &existing,
                    &receipt,
                )?;
                Some(receipt)
            } else if state == "PREPARED" {
                None
            } else {
                return Err(AuthorityError::DependencyUnavailable);
            };
            transaction
                .commit()
                .await
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            return Ok((existing, delivered));
        }
        sqlx::query(
            "INSERT INTO public.model_authority_evidence_outbox \
             (tenant_id,authority_event_id,action_id,event_kind,idempotency_key,request,\
              request_digest,state) VALUES ($1,$2,$3,$4,$5,$6,$7,'PREPARED')",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(action_id)
        .bind(event_kind)
        .bind(&proposed.idempotency_key.0)
        .bind(request_value)
        .bind(request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        Ok((proposed.clone(), None))
    }

    async fn complete_authority_evidence(
        &self,
        request: &AuthorityEvidenceEventRequest,
        action_id: Uuid,
        event_kind: &str,
        receipt: &SignedAuthorityEvidenceReceipt,
    ) -> Result<(), AuthorityError> {
        let tenant =
            Uuid::parse_str(&request.tenant_id.0).map_err(|_| AuthorityError::BindingInvalid)?;
        let event_id = Uuid::parse_str(&request.authority_event_id)
            .map_err(|_| AuthorityError::BindingInvalid)?;
        let receipt_value =
            serde_json::to_value(receipt).map_err(|_| AuthorityError::DependencyUnavailable)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.set_config('app.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let updated = sqlx::query(
            "UPDATE public.model_authority_evidence_outbox SET state='DELIVERED',\
             signed_receipt=$6,evidence_ref=$7,evidence_digest=$8,updated_at=now(),delivered_at=now() \
             WHERE tenant_id=$1 AND authority_event_id=$2 AND action_id=$3 AND event_kind=$4 \
             AND idempotency_key=$5 AND state='PREPARED'",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(action_id)
        .bind(event_kind)
        .bind(&request.idempotency_key.0)
        .bind(receipt_value)
        .bind(&receipt.evidence_ref)
        .bind(&receipt.evidence_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if updated.rows_affected() != 1 {
            let existing: Value = sqlx::query_scalar(
                "SELECT signed_receipt FROM public.model_authority_evidence_outbox \
                 WHERE tenant_id=$1 AND authority_event_id=$2 AND state='DELIVERED'",
            )
            .bind(tenant)
            .bind(event_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?
            .ok_or(AuthorityError::IdempotencyConflict)?;
            if existing
                != serde_json::to_value(receipt)
                    .map_err(|_| AuthorityError::DependencyUnavailable)?
            {
                return Err(AuthorityError::IdempotencyConflict);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    }

    async fn provider_response(
        &self,
        profile: &ProviderEndpointRecord,
        body: &Value,
        accept: &str,
    ) -> Result<(String, Vec<u8>), AuthorityError> {
        let token = read_secret(&profile.token_file, 16, 8192)?;
        let response = self
            .client
            .post(profile.endpoint.clone())
            .bearer_auth(token.as_str())
            .header("accept", accept)
            .json(body)
            .send()
            .await
            .map_err(|_| AuthorityError::ProviderOutcomeUnknown)?;
        if !response.status().is_success() {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let bytes = bounded_bytes(response, MAX_PROVIDER_RESPONSE)
            .await
            .map_err(|_| AuthorityError::ProviderOutcomeUnknown)?;
        Ok((content_type, bytes))
    }

    async fn dependency_ready(&self, endpoint: &AdapterEndpoint) -> Result<(), AuthorityError> {
        let url = service_url(&endpoint.endpoint, "/ready")?;
        let token = read_secret(&endpoint.token_file, 16, 8192)?;
        let response = self
            .client
            .get(url)
            .bearer_auth(token.as_str())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let value: Value = bounded_json_response(response, 65_536).await?;
        if value.get("ready") != Some(&Value::Bool(true)) {
            return Err(AuthorityError::DependencyUnavailable);
        }
        Ok(())
    }
}

#[async_trait]
impl ProductionModelRuntime for HttpProductionModelRuntime {
    async fn plan(
        &self,
        request: &ModelExecutionRequest,
        _binding: &ExecutionBinding,
    ) -> Result<RoutePlan, AuthorityError> {
        let providers = self.approved_providers(request).await?;
        let mut candidates = Vec::new();
        for approved in providers {
            let manifest = &approved.manifest;
            let phase_key = approved.manifest_digest.as_str();
            let policy_request = DataPolicyRequest {
                schema_version: agent_trust_contracts::SchemaVersion(
                    "agenttrust.contracts.v1".into(),
                ),
                tenant_id: TenantId(request.tenant_id.to_string()),
                classification: request.classification,
                source_jurisdiction: request.source_jurisdiction.clone(),
                destination_jurisdiction: manifest.jurisdiction.clone(),
                destination_kind: model_destination_kind(&manifest.deployment).into(),
                deployment_profile: request.deployment_profile.clone(),
                contains_secret: request.data_label.contains_secret,
                cross_domain_approval_id: request
                    .cross_domain_approval_id
                    .map(|value| ApprovalId(value.to_string())),
            };
            let pre_evaluation_id = deterministic_uuid(&json!({
                "model_action_id": request.action_id,
                "phase": "PRE_TRANSFORM_POLICY",
                "provider_manifest_digest": phase_key,
                "prompt_digest": request.data_label.lineage.source_hash,
            }))?;
            let pre_policy_request = PolicyEvaluationRequest {
                schema_version: "agenttrust.data-policy-evaluation.v1".into(),
                tenant_id: request.tenant_id,
                evaluation_id: pre_evaluation_id,
                label: request.data_label.clone(),
                request: policy_request.clone(),
                requested_at: Utc::now(),
            };
            let pre_policy = self.evaluate_policy(&pre_policy_request).await?;
            let pre_policy_record = self
                .persist_data_record(
                    request,
                    &format!("PRE_POLICY:{phase_key}"),
                    DataOperation::RecordPolicyDecision,
                    format!("policy-decisions/{}", pre_policy.decision_id),
                    0,
                    pre_policy.record_payload.clone(),
                )
                .await?;
            if !pre_policy.decision.allowed
                && pre_policy.decision.required_transformations.is_empty()
            {
                continue;
            }

            let scan_id = deterministic_uuid(&json!({
                "model_action_id": request.action_id,
                "phase": "INPUT_DLP",
                "provider_manifest_digest": phase_key,
                "content_digest": request.data_label.lineage.source_hash,
            }))?;
            let dlp_request = DlpInspectionRequest {
                schema_version: "agenttrust.data-dlp-inspection.v1".into(),
                tenant_id: request.tenant_id,
                scan_id,
                media_type: "text/plain".into(),
                content_encoding: ContentEncoding::Identity,
                content_base64: STANDARD.encode(request.prompt_utf8.as_bytes()),
                classification: request.classification,
                requested_at: Utc::now(),
            };
            let inspected = self.inspect_dlp(&dlp_request).await?;
            let input_dlp_record = self
                .persist_data_record(
                    request,
                    &format!("INPUT_DLP:{phase_key}"),
                    DataOperation::RecordDlpScan,
                    format!("dlp-scans/{}", inspected.scan_id),
                    0,
                    inspected.record_payload.clone(),
                )
                .await?;
            if dlp_denied_or_mislabeled(&inspected, &request.data_label) {
                continue;
            }

            let findings_present = inspected.finding_counts.values().any(|value| *value > 0);
            let sanitize_required = !pre_policy.decision.allowed
                || !pre_policy.decision.required_transformations.is_empty()
                || findings_present;
            let mut governed_label = request.data_label.clone();
            let (
                transformed_prompt,
                transformation_digest,
                transform_evidence_ref,
                transform_evidence_digest,
                applied_transformations,
            ) = if sanitize_required {
                let transform_id = deterministic_uuid(&json!({
                    "model_action_id": request.action_id,
                    "phase": "INPUT_SANITIZE",
                    "provider_manifest_digest": phase_key,
                    "dlp_scan_id": inspected.scan_id,
                }))?;
                let sanitize_request = PromptSanitizationRequest {
                    schema_version: "agenttrust.prompt-sanitization.v1".into(),
                    tenant_id: request.tenant_id,
                    transform_id,
                    dlp_scan_id: inspected.scan_id,
                    media_type: "text/plain".into(),
                    content_encoding: ContentEncoding::Identity,
                    content_base64: STANDARD.encode(request.prompt_utf8.as_bytes()),
                    label: governed_label.clone(),
                    private_processing: manifest.deployment != "PUBLIC_API",
                    requested_at: Utc::now(),
                };
                let sanitized = self.sanitize_prompt(&sanitize_request, &inspected).await?;
                let required = pre_policy
                    .decision
                    .required_transformations
                    .iter()
                    .collect::<BTreeSet<_>>();
                let applied = sanitized.transformations.iter().collect::<BTreeSet<_>>();
                if !required.is_subset(&applied) {
                    continue;
                }
                let transform_record = self
                    .persist_data_record(
                        request,
                        &format!("INPUT_TRANSFORM:{phase_key}"),
                        DataOperation::RecordTransformReceipt,
                        format!("transforms/{}", sanitized.transform_id),
                        0,
                        sanitized.record_payload.clone(),
                    )
                    .await?;
                let transformed_bytes = STANDARD
                    .decode(sanitized.sanitized_content_base64.as_bytes())
                    .map_err(|_| AuthorityError::ProviderDenied)?;
                let transformed = String::from_utf8(transformed_bytes)
                    .map_err(|_| AuthorityError::ProviderDenied)?;
                if transformed.is_empty() || transformed.len() > 4_194_304 {
                    continue;
                }
                let lineage_digest = sanitized.transform_receipt_digest.clone();
                if governed_label
                    .lineage
                    .transformation_hashes
                    .contains(&lineage_digest)
                    || governed_label.lineage.transformation_hashes.len() >= 1024
                {
                    continue;
                }
                governed_label
                    .lineage
                    .transformation_hashes
                    .push(lineage_digest);
                governed_label.lineage.source_id = format!("transform:{}", sanitized.transform_id);
                governed_label.lineage.source_hash = sanitized.output_digest.clone();
                (
                    transformed,
                    sanitized.output_digest,
                    Some(mutation_evidence_ref(&transform_record)?.to_owned()),
                    Some(mutation_evidence_digest(&transform_record)?.to_owned()),
                    sanitized.transformations,
                )
            } else {
                (
                    request.prompt_utf8.clone(),
                    digest(request.prompt_utf8.as_bytes()),
                    None,
                    None,
                    Vec::new(),
                )
            };

            let (policy, policy_record) = if sanitize_required {
                let post_evaluation_id = deterministic_uuid(&json!({
                    "model_action_id": request.action_id,
                    "phase": "POST_TRANSFORM_POLICY",
                    "provider_manifest_digest": phase_key,
                    "transformation_digest": transformation_digest,
                }))?;
                let post_policy_request = PolicyEvaluationRequest {
                    schema_version: "agenttrust.data-policy-evaluation.v1".into(),
                    tenant_id: request.tenant_id,
                    evaluation_id: post_evaluation_id,
                    label: governed_label,
                    request: policy_request.clone(),
                    requested_at: Utc::now(),
                };
                let post = self.evaluate_policy(&post_policy_request).await?;
                let post_record = self
                    .persist_data_record(
                        request,
                        &format!("POST_POLICY:{phase_key}"),
                        DataOperation::RecordPolicyDecision,
                        format!("policy-decisions/{}", post.decision_id),
                        0,
                        post.record_payload.clone(),
                    )
                    .await?;
                (post, post_record)
            } else {
                (pre_policy.clone(), pre_policy_record.clone())
            };
            let required = policy
                .decision
                .required_transformations
                .iter()
                .collect::<BTreeSet<_>>();
            let applied = applied_transformations.iter().collect::<BTreeSet<_>>();
            if !policy.decision.allowed || !required.is_subset(&applied) {
                continue;
            }
            let route_reasons = vec![
                format!("deployment:{}", manifest.deployment),
                format!("region:{}", manifest.region),
                format!("data_policy:{}", policy.decision.policy_version.0),
                format!("unit_cost:{}", manifest.cost_microunits_per_token),
            ];
            let route_material = json!({
                "schema_version": "agenttrust.model-route-decision.v1",
                "provider_key": provider_key(manifest),
                "provider_manifest_digest": approved.manifest_digest,
                "pre_transform_policy_decision_digest": pre_policy.decision_digest,
                "pre_transform_policy_evidence_digest": mutation_evidence_digest(&pre_policy_record)?,
                "data_policy_decision_digest": policy.decision_digest,
                "data_policy_evidence_digest": mutation_evidence_digest(&policy_record)?,
                "input_dlp_evidence_digest": mutation_evidence_digest(&input_dlp_record)?,
                "residency_policy_request_digest": policy.request_digest,
                "transformation_digest": transformation_digest,
                "reasons": route_reasons
            });
            candidates.push((
                deployment_rank(&manifest.deployment),
                manifest.cost_microunits_per_token,
                provider_key(manifest),
                RoutePlan {
                    schema_version: ROUTE_PLAN_SCHEMA.into(),
                    provider_key: provider_key(manifest),
                    provider_manifest_digest: approved.manifest_digest,
                    endpoint_profile: manifest.endpoint_profile.clone(),
                    model_id: manifest.model_id.clone(),
                    model_version: manifest.model_version.clone(),
                    provider_jurisdiction: manifest.jurisdiction.clone(),
                    protocol: manifest.protocol.clone(),
                    cost_microunits_per_token: manifest.cost_microunits_per_token,
                    route_decision_digest: canonical_digest(&route_material)?,
                    route_reasons,
                    data_policy_version: policy.decision.policy_version.0,
                    pre_transform_policy_decision_digest: pre_policy.decision_digest,
                    pre_transform_policy_evidence_ref: mutation_evidence_ref(&pre_policy_record)?
                        .to_owned(),
                    pre_transform_policy_evidence_digest: mutation_evidence_digest(
                        &pre_policy_record,
                    )?
                    .to_owned(),
                    data_policy_decision_digest: policy.decision_digest,
                    data_policy_evidence_ref: mutation_evidence_ref(&policy_record)?.to_owned(),
                    data_policy_evidence_digest: mutation_evidence_digest(&policy_record)?
                        .to_owned(),
                    transformation_digest,
                    transform_evidence_ref,
                    transform_evidence_digest,
                    dlp_report_digest: inspected.findings_digest,
                    input_dlp_evidence_ref: mutation_evidence_ref(&input_dlp_record)?.to_owned(),
                    input_dlp_evidence_digest: mutation_evidence_digest(&input_dlp_record)?
                        .to_owned(),
                    residency_policy_request_digest: policy.request_digest,
                    transformed_prompt_utf8: transformed_prompt,
                },
            ));
        }
        candidates.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        candidates
            .into_iter()
            .next()
            .map(|(_, _, _, plan)| plan)
            .ok_or(AuthorityError::NoCompliantProvider)
    }

    async fn invoke(
        &self,
        request: &ModelExecutionRequest,
        _binding: &ExecutionBinding,
        plan: &RoutePlan,
    ) -> Result<ProviderOutcome, AuthorityError> {
        let profile = self
            .provider_profiles
            .get(&plan.endpoint_profile)
            .filter(|profile| {
                profile.provider_key == plan.provider_key && profile.protocol == plan.protocol
            })
            .ok_or(AuthorityError::ProviderDenied)?;
        let body = provider_request_body(request, plan);
        match request.operation {
            ModelOperation::Generate => {
                let (content_type, bytes) = self
                    .provider_response(profile, &body, "application/json")
                    .await?;
                if content_type != "application/json" {
                    return Err(AuthorityError::ProviderOutcomeUnknown);
                }
                parse_generate_response(&bytes, plan)
            }
            ModelOperation::Embeddings => {
                let (content_type, bytes) = self
                    .provider_response(profile, &body, "application/json")
                    .await?;
                if content_type != "application/json" {
                    return Err(AuthorityError::ProviderOutcomeUnknown);
                }
                parse_embedding_response(&bytes, plan)
            }
            ModelOperation::Stream => {
                let (content_type, bytes) = self
                    .provider_response(profile, &body, "text/event-stream")
                    .await?;
                match profile.protocol.as_str() {
                    "OPENAI_COMPATIBLE" if content_type == "text/event-stream" => {
                        parse_openai_sse(&bytes, plan)
                    }
                    "LOCAL_INFERENCE"
                        if matches!(
                            content_type.as_str(),
                            "application/x-ndjson" | "application/jsonl"
                        ) =>
                    {
                        parse_local_json_lines(&bytes, plan)
                    }
                    _ => Err(AuthorityError::ProviderOutcomeUnknown),
                }
            }
        }
    }

    async fn complete(
        &self,
        request: &ModelExecutionRequest,
        binding: &ExecutionBinding,
        plan: &RoutePlan,
        outcome: &ProviderOutcome,
    ) -> Result<CompletionEvidence, AuthorityError> {
        let output = canonical_output_bytes(outcome)?;
        let output_digest = digest(&output);
        let mut output_label = request.data_label.clone();
        output_label.lineage.source_id = format!("model-output:{}", outcome.provider_request_id);
        output_label.lineage.source_hash = output_digest.clone();
        if !output_label
            .jurisdictions
            .contains(&plan.provider_jurisdiction)
        {
            if output_label.jurisdictions.len() >= 32 {
                return Err(AuthorityError::ProviderOutcomeUnknown);
            }
            output_label
                .jurisdictions
                .insert(plan.provider_jurisdiction.clone());
        }
        if output_label
            .lineage
            .transformation_hashes
            .contains(&plan.route_decision_digest)
            || output_label.lineage.transformation_hashes.len() >= 1024
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        output_label
            .lineage
            .transformation_hashes
            .push(plan.route_decision_digest.clone());
        let output_scan_id = deterministic_uuid(&json!({
            "model_action_id": request.action_id,
            "phase": "OUTPUT_DLP",
            "provider_request_id": outcome.provider_request_id,
            "output_digest": output_digest,
        }))?;
        let output_dlp_request = DlpInspectionRequest {
            schema_version: "agenttrust.data-dlp-inspection.v1".into(),
            tenant_id: request.tenant_id,
            scan_id: output_scan_id,
            media_type: "application/json".into(),
            content_encoding: ContentEncoding::Identity,
            content_base64: STANDARD.encode(&output),
            classification: request.classification,
            requested_at: Utc::now(),
        };
        let output_dlp = self.inspect_dlp(&output_dlp_request).await?;
        let output_dlp_record = self
            .persist_data_record(
                request,
                "OUTPUT_DLP",
                DataOperation::RecordDlpScan,
                format!("dlp-scans/{}", output_dlp.scan_id),
                0,
                output_dlp.record_payload.clone(),
            )
            .await?;
        if dlp_denied_or_mislabeled(&output_dlp, &output_label) {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }

        let object_ref = format!("artifact://sha256/{output_digest}");
        let label_digest = canonical_digest(&output_label)?;
        let label_payload = json!({
            "object_ref": object_ref,
            "object_version": "1",
            "object_digest": output_digest,
            "label": output_label,
            "label_digest": label_digest,
            "source_evidence_ref": mutation_evidence_ref(&output_dlp_record)?,
            "source_evidence_digest": mutation_evidence_digest(&output_dlp_record)?,
        });
        let output_label_record = self
            .persist_data_record(
                request,
                "OUTPUT_LABEL",
                DataOperation::RegisterLabel,
                format!("labels/{label_digest}"),
                0,
                label_payload,
            )
            .await?;
        // Do not treat the proposal as durable proof. A completed mutation with final Evidence is
        // required even though the label record is consumed by the next Batch 18 preflight.
        mutation_evidence_ref(&output_label_record)?;
        mutation_evidence_digest(&output_label_record)?;
        let destination_digest = canonical_digest(&json!({
            "schema_version": "agenttrust.model-artifact-destination.v1",
            "jurisdiction": self.endpoints.artifact_store_jurisdiction,
            "destination_kind": self.endpoints.artifact_store_destination_kind,
            "endpoint_origin_digest": digest(self.endpoints.artifact_store.endpoint.as_str().as_bytes()),
        }))?;
        let artifact_policy_request = DataPolicyRequest {
            schema_version: agent_trust_contracts::SchemaVersion("agenttrust.contracts.v1".into()),
            tenant_id: TenantId(request.tenant_id.to_string()),
            classification: request.classification,
            source_jurisdiction: plan.provider_jurisdiction.clone(),
            destination_jurisdiction: self.endpoints.artifact_store_jurisdiction.clone(),
            destination_kind: self.endpoints.artifact_store_destination_kind.clone(),
            deployment_profile: request.deployment_profile.clone(),
            contains_secret: output_label.contains_secret,
            cross_domain_approval_id: request
                .cross_domain_approval_id
                .map(|value| ApprovalId(value.to_string())),
        };
        let artifact_policy_evaluation_id = deterministic_uuid(&json!({
            "model_action_id": request.action_id,
            "phase": "ARTIFACT_POLICY",
            "object_digest": output_digest,
            "policy_request_digest": canonical_digest(&artifact_policy_request)?,
        }))?;
        let artifact_policy_evaluation = self
            .evaluate_policy(&PolicyEvaluationRequest {
                schema_version: "agenttrust.data-policy-evaluation.v1".into(),
                tenant_id: request.tenant_id,
                evaluation_id: artifact_policy_evaluation_id,
                label: output_label.clone(),
                request: artifact_policy_request.clone(),
                requested_at: Utc::now(),
            })
            .await?;
        let artifact_policy_record = self
            .persist_data_record(
                request,
                "ARTIFACT_POLICY",
                DataOperation::RecordPolicyDecision,
                format!(
                    "policy-decisions/{}",
                    artifact_policy_evaluation.decision_id
                ),
                0,
                artifact_policy_evaluation.record_payload.clone(),
            )
            .await?;
        if !artifact_policy_evaluation.decision.allowed
            || !artifact_policy_evaluation
                .decision
                .required_transformations
                .is_empty()
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        mutation_evidence_ref(&artifact_policy_record)?;
        mutation_evidence_digest(&artifact_policy_record)?;
        let artifact_authorization_id = deterministic_uuid(&json!({
            "model_action_id": request.action_id,
            "phase": "ARTIFACT_AUTHORIZE",
            "object_digest": output_digest,
            "destination_digest": destination_digest,
        }))?;
        let grant_consumption_record = if let Some(grant_id) = request.cross_domain_grant_id {
            let source_zone = request
                .cross_domain_source_zone
                .as_deref()
                .ok_or(AuthorityError::BindingInvalid)?;
            let target_zone = request
                .cross_domain_target_zone
                .as_deref()
                .ok_or(AuthorityError::BindingInvalid)?;
            let grant_record = self
                .persist_data_record(
                    request,
                    "CONSUME_ARTIFACT_GRANT",
                    DataOperation::ConsumeCrossDomainGrant,
                    format!("cross-domain-grants/{grant_id}"),
                    1,
                    json!({
                        "grant_id": grant_id,
                        "object_digest": output_digest,
                        "source_zone": source_zone,
                        "target_zone": target_zone,
                        "export_intent_id": artifact_authorization_id,
                    }),
                )
                .await?;
            mutation_evidence_ref(&grant_record)?;
            mutation_evidence_digest(&grant_record)?;
            Some(grant_record)
        } else {
            None
        };
        let artifact_authorization_request = ArtifactAuthorizationRequest {
            schema_version: "agenttrust.artifact-authorization.v1".into(),
            tenant_id: request.tenant_id,
            authorization_id: artifact_authorization_id,
            object_ref: object_ref.clone(),
            object_digest: output_digest.clone(),
            destination_digest: destination_digest.clone(),
            media_type: "application/json".into(),
            content_encoding: ContentEncoding::Identity,
            content_base64: STANDARD.encode(&output),
            label: output_label.clone(),
            label_digest: label_digest.clone(),
            policy_request: artifact_policy_request.clone(),
            decision_id: artifact_policy_evaluation.decision_id,
            dlp_scan_id: output_dlp.scan_id,
            dlp_receipt_digest: output_dlp.engine_receipt_digest.clone(),
            transform_id: None,
            transform_receipt_digest: None,
            cross_domain_grant_id: request.cross_domain_grant_id,
            redirect_target_digests: Vec::new(),
            requested_at: Utc::now(),
        };
        let artifact_authorization: ArtifactAuthorizationResult = self
            .post_tenant_json(
                &self.endpoints.artifact_authorizer,
                "/v1/internal/data/artifacts/authorize",
                request.tenant_id,
                &artifact_authorization_request,
                MAX_CONTROL_RESPONSE,
            )
            .await?;
        if artifact_authorization.schema_version != "agenttrust.artifact-authorization.v1"
            || artifact_authorization.authorization_id != artifact_authorization_id
            || !artifact_authorization.allowed
            || !artifact_authorization.durable_preflight_verified
            || artifact_authorization.label_digest != label_digest
            || artifact_authorization.decision_id != artifact_policy_evaluation.decision_id
            || !valid_shared_policy_decision(&artifact_authorization.decision)
            || artifact_authorization.decision != artifact_policy_evaluation.decision
            || artifact_authorization.decision_digest
                != canonical_digest(&artifact_authorization.decision)?
            || artifact_authorization.decision_digest != artifact_policy_evaluation.decision_digest
            || artifact_authorization.policy_request_digest
                != canonical_digest(&artifact_policy_request)?
            || artifact_authorization.policy_request_digest
                != artifact_policy_evaluation.request_digest
            || artifact_authorization.dlp_scan_id != output_dlp.scan_id
            || artifact_authorization.dlp_receipt_digest != output_dlp.engine_receipt_digest
            || artifact_authorization.transform_id.is_some()
            || artifact_authorization.transform_receipt_digest.is_some()
            || !artifact_authorization
                .object_authorization_ref
                .starts_with("object://")
            || !adapter_reference(&artifact_authorization.object_authorization_ref)
            || !lower_digest(&artifact_authorization.object_authorization_digest)
            || !artifact_authorization.worm_required
            || !artifact_authorization.durable_export_intent_required
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let export_payload = json!({
            "export_id": artifact_authorization_id,
            "object_ref": object_ref,
            "object_digest": output_digest,
            "label_digest": label_digest,
            "decision_id": artifact_policy_evaluation.decision_id,
            "decision_digest": artifact_authorization.decision_digest,
            "policy_request_digest": artifact_authorization.policy_request_digest,
            "dlp_scan_id": output_dlp.scan_id,
            "dlp_receipt_digest": output_dlp.engine_receipt_digest,
            "transform_id": Value::Null,
            "transform_receipt_digest": Value::Null,
            "grant_id": request.cross_domain_grant_id,
            "object_authorization_ref": artifact_authorization.object_authorization_ref,
            "object_authorization_digest": artifact_authorization.object_authorization_digest,
            "destination_kind": self.endpoints.artifact_store_destination_kind,
            "destination_digest": destination_digest,
            "expires_at": Utc::now() + chrono::Duration::minutes(10),
            "redirects_allowed": false,
        });
        let export_authorization_record = self
            .persist_data_record(
                request,
                "AUTHORIZE_EXPORT",
                DataOperation::AuthorizeExport,
                format!("export-intents/{artifact_authorization_id}"),
                0,
                export_payload,
            )
            .await?;
        let artifact_request = ArtifactWriteRequest {
            schema_version: "agenttrust.model-artifact-write-request.v1",
            tenant_id: request.tenant_id.to_string(),
            authorization_ref: &artifact_authorization.object_authorization_ref,
            authorization_digest: &artifact_authorization.object_authorization_digest,
            export_evidence_ref: mutation_evidence_ref(&export_authorization_record)?,
            export_evidence_digest: mutation_evidence_digest(&export_authorization_record)?,
            object_ref: &object_ref,
            object_digest: &output_digest,
            media_type: "application/json",
            content_base64: STANDARD.encode(&output),
            idempotency_key: &binding.idempotency_key,
            trace_id: &binding.trace_id,
        };
        let artifact: ArtifactWriteResponse = self
            .post_tenant_json(
                &self.endpoints.artifact_store,
                "/v1/model-artifacts",
                request.tenant_id,
                &artifact_request,
                MAX_CONTROL_RESPONSE,
            )
            .await?;
        let mut unsigned_artifact = artifact.clone();
        unsigned_artifact.receipt_digest.clear();
        if artifact.schema_version != "agenttrust.artifact-write-result.v1"
            || artifact.artifact_ref != object_ref
            || artifact.artifact_digest != output_digest
            || !lower_digest(&artifact.watermark_digest)
            || !lower_digest(&artifact.signature_digest)
            || !adapter_reference(&artifact.worm_receipt_ref)
            || !lower_digest(&artifact.worm_receipt_digest)
            || !adapter_reference(&artifact.receipt_ref)
            || artifact.receipt_digest != canonical_digest(&unsigned_artifact)?
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let complete_export_payload = json!({
            "export_id": artifact_authorization_id,
            "object_digest": output_digest,
            "artifact_ref": artifact.artifact_ref,
            "artifact_digest": artifact.artifact_digest,
            "watermark_digest": artifact.watermark_digest,
            "signature_digest": artifact.signature_digest,
            "worm_receipt_ref": artifact.worm_receipt_ref,
            "worm_receipt_digest": artifact.worm_receipt_digest,
            "completed_at": Utc::now(),
        });
        let export_completion_record = self
            .persist_data_record(
                request,
                "COMPLETE_EXPORT",
                DataOperation::CompleteExport,
                format!("export-intents/{artifact_authorization_id}"),
                export_authorization_record.resource_version,
                complete_export_payload,
            )
            .await?;
        let grant_consumption_evidence_ref = grant_consumption_record
            .as_ref()
            .map(mutation_evidence_ref)
            .transpose()?
            .map(str::to_owned);
        let grant_consumption_evidence_digest = grant_consumption_record
            .as_ref()
            .map(mutation_evidence_digest)
            .transpose()?
            .map(str::to_owned);
        let evidence_payload = ModelEvidencePayload {
            schema_version: "agenttrust.model-execution-evidence-payload.v1",
            tenant_id: request.tenant_id.to_string(),
            action_hash: &binding.action_hash,
            authorization_digest: &binding.authorization_digest,
            policy_decision_digest: &binding.policy_decision_digest,
            authorization_evidence_ref: &binding.authorization_evidence_ref,
            authorization_evidence_digest: &binding.authorization_evidence_digest,
            ledger_execution_id: binding.ledger_execution_id,
            ledger_event_id: binding.ledger_event_id,
            ledger_event_digest: &binding.ledger_event_digest,
            fence_digest: &binding.fence_digest,
            resource_version: &binding.resource_version,
            idempotency_key: &binding.idempotency_key,
            request_digest: canonical_digest(request)?,
            prompt_digest: digest(request.prompt_utf8.as_bytes()),
            provider_key: &plan.provider_key,
            provider_request_id: &outcome.provider_request_id,
            provider_manifest_digest: &plan.provider_manifest_digest,
            route_decision_digest: &plan.route_decision_digest,
            data_policy_version: &plan.data_policy_version,
            pre_transform_policy_decision_digest: &plan.pre_transform_policy_decision_digest,
            data_policy_decision_digest: &plan.data_policy_decision_digest,
            transformation_digest: &plan.transformation_digest,
            input_dlp_report_digest: &plan.dlp_report_digest,
            pre_transform_policy_evidence_ref: &plan.pre_transform_policy_evidence_ref,
            pre_transform_policy_evidence_digest: &plan.pre_transform_policy_evidence_digest,
            data_policy_evidence_ref: &plan.data_policy_evidence_ref,
            data_policy_evidence_digest: &plan.data_policy_evidence_digest,
            transform_evidence_ref: &plan.transform_evidence_ref,
            transform_evidence_digest: &plan.transform_evidence_digest,
            input_dlp_evidence_ref: &plan.input_dlp_evidence_ref,
            input_dlp_evidence_digest: &plan.input_dlp_evidence_digest,
            output_dlp_report_digest: &output_dlp.findings_digest,
            residency_policy_evidence_ref: &plan.data_policy_evidence_ref,
            residency_policy_evidence_digest: &plan.data_policy_evidence_digest,
            output_dlp_evidence_ref: mutation_evidence_ref(&output_dlp_record)?,
            output_dlp_evidence_digest: mutation_evidence_digest(&output_dlp_record)?,
            output_label_evidence_ref: mutation_evidence_ref(&output_label_record)?,
            output_label_evidence_digest: mutation_evidence_digest(&output_label_record)?,
            artifact_policy_evidence_ref: mutation_evidence_ref(&artifact_policy_record)?,
            artifact_policy_evidence_digest: mutation_evidence_digest(&artifact_policy_record)?,
            grant_consumption_evidence_ref: &grant_consumption_evidence_ref,
            grant_consumption_evidence_digest: &grant_consumption_evidence_digest,
            export_authorization_evidence_ref: mutation_evidence_ref(&export_authorization_record)?,
            export_authorization_evidence_digest: mutation_evidence_digest(
                &export_authorization_record,
            )?,
            export_completion_evidence_ref: mutation_evidence_ref(&export_completion_record)?,
            export_completion_evidence_digest: mutation_evidence_digest(&export_completion_record)?,
            artifact_store_receipt_ref: &artifact.receipt_ref,
            artifact_store_receipt_digest: &artifact.receipt_digest,
            artifact_ref: &artifact.artifact_ref,
            artifact_digest: &artifact.artifact_digest,
            output_digest: &output_digest,
            input_tokens: outcome.input_tokens,
            output_tokens: outcome.output_tokens,
            cost_microunits: outcome.cost_microunits,
            trace_id: &binding.trace_id,
        };
        let occurred_at = Utc::now();
        let authority_event_id = deterministic_uuid(&json!({
            "model_action_id": request.action_id,
            "event": "MODEL_EXECUTION_SUCCEEDED",
            "provider_request_id": outcome.provider_request_id,
            "payload_hash": canonical_digest(&evidence_payload)?,
        }))?;
        let evidence_request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: binding.tenant_id.clone(),
            task_id: request.canonical_action.task_id.clone(),
            authority_event_id: authority_event_id.to_string(),
            idempotency_key: IdempotencyKey(digest(
                format!("{}:MODEL_EXECUTION_SUCCEEDED", binding.idempotency_key).as_bytes(),
            )),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(authority_evidence_binding(binding)),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: binding.tenant_id.clone(),
                task_id: request.canonical_action.task_id.clone(),
                event_type: EvidenceEventType::StateTransition,
                actor_subject: request.canonical_action.agent.owner_subject.clone(),
                source_service: self.endpoints.evidence_source_service.clone(),
                trace_id: binding.trace_id.clone(),
                span_id: binding.ledger_event_id.to_string(),
                payload_hash: canonical_digest(&evidence_payload)?,
                safe_summary: "MODEL_EXECUTION_SUCCEEDED".into(),
                artifact_refs: vec![ArtifactRef(artifact.artifact_ref.clone())],
                occurred_at: occurred_at.to_owned(),
            },
            requested_at: occurred_at,
        };
        let evidence = self
            .append_evidence_event(
                &evidence_request,
                request.action_id,
                "MODEL_EXECUTION_SUCCEEDED",
            )
            .await?;
        Ok(CompletionEvidence {
            schema_version: COMPLETION_EVIDENCE_SCHEMA.into(),
            artifact_ref: artifact.artifact_ref,
            artifact_digest: artifact.artifact_digest,
            output_digest,
            evidence_ref: evidence.evidence_ref,
            evidence_digest: evidence.evidence_digest,
            residency_policy_evidence_ref: plan.data_policy_evidence_ref.clone(),
            residency_policy_evidence_digest: plan.data_policy_evidence_digest.clone(),
            output_dlp_report_digest: output_dlp.findings_digest,
            output_dlp_evidence_ref: mutation_evidence_ref(&output_dlp_record)?.to_owned(),
            output_dlp_evidence_digest: mutation_evidence_digest(&output_dlp_record)?.to_owned(),
            output_label_evidence_ref: mutation_evidence_ref(&output_label_record)?.to_owned(),
            output_label_evidence_digest: mutation_evidence_digest(&output_label_record)?
                .to_owned(),
            artifact_policy_evidence_ref: mutation_evidence_ref(&artifact_policy_record)?
                .to_owned(),
            artifact_policy_evidence_digest: mutation_evidence_digest(&artifact_policy_record)?
                .to_owned(),
            grant_consumption_evidence_ref,
            grant_consumption_evidence_digest,
            export_authorization_evidence_ref: mutation_evidence_ref(&export_authorization_record)?
                .to_owned(),
            export_authorization_evidence_digest: mutation_evidence_digest(
                &export_authorization_record,
            )?
            .to_owned(),
            export_completion_evidence_ref: mutation_evidence_ref(&export_completion_record)?
                .to_owned(),
            export_completion_evidence_digest: mutation_evidence_digest(&export_completion_record)?
                .to_owned(),
            artifact_store_receipt_ref: artifact.receipt_ref,
            artifact_store_receipt_digest: artifact.receipt_digest,
        })
    }

    async fn billing_evidence(
        &self,
        request: &BillingStatementRequest,
        binding: &ExecutionBinding,
        matched: bool,
        matched_requests: u64,
        total_metered_microunits: u64,
        total_billed_microunits: u64,
    ) -> Result<BillingEvidenceReceipt, AuthorityError> {
        let payload = BillingEvidenceRequest {
            schema_version: "agenttrust.model-billing-evidence-payload.v1",
            tenant_id: request.tenant_id.to_string(),
            action_hash: &binding.action_hash,
            authorization_digest: &binding.authorization_digest,
            policy_decision_digest: &binding.policy_decision_digest,
            authorization_evidence_ref: &binding.authorization_evidence_ref,
            authorization_evidence_digest: &binding.authorization_evidence_digest,
            ledger_execution_id: binding.ledger_execution_id,
            ledger_event_id: binding.ledger_event_id,
            ledger_event_digest: &binding.ledger_event_digest,
            fence_digest: &binding.fence_digest,
            resource_version: &binding.resource_version,
            idempotency_key: &binding.idempotency_key,
            provider_id: &request.provider_id,
            statement_period: &request.statement_period,
            statement_digest: &request.statement_digest,
            residency_policy_evidence_digest: &request.residency_policy_evidence_digest,
            matched,
            matched_requests,
            total_metered_microunits,
            total_billed_microunits,
            trace_id: &binding.trace_id,
        };
        let occurred_at = Utc::now();
        let authority_event_id = deterministic_uuid(&json!({
            "model_action_id": request.canonical_action.action_id.0,
            "event": "MODEL_BILLING_RECONCILIATION",
            "statement_digest": request.statement_digest,
            "payload_hash": canonical_digest(&payload)?,
        }))?;
        let evidence_request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: binding.tenant_id.clone(),
            task_id: request.canonical_action.task_id.clone(),
            authority_event_id: authority_event_id.to_string(),
            idempotency_key: IdempotencyKey(digest(
                format!("{}:MODEL_BILLING_RECONCILIATION", binding.idempotency_key).as_bytes(),
            )),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(authority_evidence_binding(binding)),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: binding.tenant_id.clone(),
                task_id: request.canonical_action.task_id.clone(),
                event_type: EvidenceEventType::Evaluation,
                actor_subject: request.canonical_action.agent.owner_subject.clone(),
                source_service: self.endpoints.evidence_source_service.clone(),
                trace_id: binding.trace_id.clone(),
                span_id: binding.ledger_event_id.to_string(),
                payload_hash: canonical_digest(&payload)?,
                safe_summary: if matched {
                    "MODEL_BILLING_RECONCILIATION_MATCHED".into()
                } else {
                    "MODEL_BILLING_RECONCILIATION_MISMATCH".into()
                },
                artifact_refs: Vec::new(),
                occurred_at: occurred_at.to_owned(),
            },
            requested_at: occurred_at,
        };
        let billing_action_id = Uuid::parse_str(&request.canonical_action.action_id.0)
            .map_err(|_| AuthorityError::BindingInvalid)?;
        let response = self
            .append_evidence_event(
                &evidence_request,
                billing_action_id,
                "MODEL_BILLING_RECONCILIATION",
            )
            .await?;
        Ok(BillingEvidenceReceipt {
            schema_version: "agenttrust.model-billing-evidence.v1".into(),
            evidence_ref: response.evidence_ref,
            evidence_digest: response.evidence_digest,
        })
    }

    async fn ready(&self) -> Result<(), AuthorityError> {
        let provider_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.model_provider_revisions r WHERE r.status='ACTIVE' \
             AND NOT EXISTS (SELECT 1 FROM public.model_provider_revocations x \
               WHERE x.provider_id=r.provider_id AND x.model_id=r.model_id \
               AND x.model_version=r.model_version AND x.provider_revision=r.revision)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if provider_count < 2 {
            return Err(AuthorityError::DependencyUnavailable);
        }
        self.dependency_ready(&self.endpoints.data_policy).await?;
        self.dependency_ready(&self.endpoints.dlp).await?;
        self.dependency_ready(&self.endpoints.sanitizer).await?;
        self.dependency_ready(&self.endpoints.artifact_authorizer)
            .await?;
        self.dependency_ready(&self.endpoints.data_mutation).await?;
        self.dependency_ready(&self.endpoints.data_read).await?;
        self.dependency_ready(&self.endpoints.artifact_store)
            .await?;
        self.dependency_ready(&self.endpoints.evidence).await
    }
}

fn verify_manifest(
    keyring: &ProviderKeyring,
    manifest: &SignedProviderManifest,
    source: &Value,
    stored_digest: &str,
) -> Result<(), AuthorityError> {
    let computed_digest = canonical_digest(source)?;
    let key = keyring
        .keys
        .get(&format!("MODEL_PROVIDER_MANIFEST:{}", manifest.key_id))
        .ok_or(AuthorityError::ProviderDenied)?;
    let unsigned = UnsignedManifest {
        schema_version: &manifest.schema_version,
        provider_id: &manifest.provider_id,
        model_id: &manifest.model_id,
        model_version: &manifest.model_version,
        revision: manifest.revision,
        region: &manifest.region,
        jurisdiction: &manifest.jurisdiction,
        deployment: &manifest.deployment,
        protocol: &manifest.protocol,
        capabilities: &manifest.capabilities,
        endpoint_profile: &manifest.endpoint_profile,
        endpoint_digest: &manifest.endpoint_digest,
        data_terms_version: &manifest.data_terms_version,
        maximum_context_bytes: manifest.maximum_context_bytes,
        maximum_output_bytes: manifest.maximum_output_bytes,
        cost_microunits_per_token: manifest.cost_microunits_per_token,
        issuer: &manifest.issuer,
        key_id: &manifest.key_id,
        key_usage: &manifest.key_usage,
    };
    let bytes = serde_jcs::to_vec(&unsigned).map_err(|_| AuthorityError::ProviderDenied)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(manifest.signature.as_bytes())
        .map_err(|_| AuthorityError::ProviderDenied)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| AuthorityError::ProviderDenied)?;
    if manifest.schema_version != "agenttrust.model-provider-manifest.v1"
        || manifest.key_usage != "MODEL_PROVIDER_MANIFEST"
        || computed_digest != stored_digest
        || !lower_digest(stored_digest)
        || !lower_digest(&manifest.endpoint_digest)
        || manifest.revision == 0
        || manifest.capabilities.is_empty()
        || manifest.capabilities.len() > 5
        || !matches!(
            manifest.deployment.as_str(),
            "PUBLIC_API" | "VPC" | "ON_PREM" | "LOCAL"
        )
        || !matches!(
            manifest.protocol.as_str(),
            "OPENAI_COMPATIBLE" | "LOCAL_INFERENCE"
        )
        || manifest.maximum_context_bytes == 0
        || manifest.maximum_context_bytes > 16_777_216
        || manifest.maximum_output_bytes == 0
        || manifest.maximum_output_bytes > 33_554_432
        || key.verify(&bytes, &signature).is_err()
    {
        return Err(AuthorityError::ProviderDenied);
    }
    Ok(())
}

fn verify_revocation(
    keyring: &ProviderKeyring,
    revocation: &SignedProviderRevocation,
    stored_digest: &str,
) -> Result<(), AuthorityError> {
    let key = keyring
        .keys
        .get(&format!("MODEL_PROVIDER_REVOCATION:{}", revocation.key_id))
        .ok_or(AuthorityError::ProviderDenied)?;
    let unsigned = UnsignedRevocation {
        schema_version: &revocation.schema_version,
        provider_id: &revocation.provider_id,
        model_id: &revocation.model_id,
        model_version: &revocation.model_version,
        provider_revision: revocation.provider_revision,
        provider_manifest_digest: &revocation.provider_manifest_digest,
        reason_code: &revocation.reason_code,
        revoked_at: revocation.revoked_at,
        issuer: &revocation.issuer,
        key_id: &revocation.key_id,
        key_usage: &revocation.key_usage,
    };
    let bytes = serde_jcs::to_vec(&unsigned).map_err(|_| AuthorityError::ProviderDenied)?;
    let full = serde_json::to_value(revocation).map_err(|_| AuthorityError::ProviderDenied)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(revocation.signature.as_bytes())
        .map_err(|_| AuthorityError::ProviderDenied)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| AuthorityError::ProviderDenied)?;
    if revocation.schema_version != "agenttrust.model-provider-revocation.v1"
        || revocation.key_usage != "MODEL_PROVIDER_REVOCATION"
        || revocation.provider_revision == 0
        || !lower_digest(&revocation.provider_manifest_digest)
        || !lower_digest(stored_digest)
        || canonical_digest(&full)? != stored_digest
        || revocation.reason_code.is_empty()
        || revocation.reason_code.len() > 128
        || !revocation
            .reason_code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || key.verify(&bytes, &signature).is_err()
    {
        return Err(AuthorityError::ProviderDenied);
    }
    Ok(())
}

fn provider_request_body(request: &ModelExecutionRequest, plan: &RoutePlan) -> Value {
    match (plan.protocol.as_str(), request.operation) {
        ("OPENAI_COMPATIBLE", ModelOperation::Generate) => json!({
            "model": plan.model_id,
            "messages": [{"role": "user", "content": plan.transformed_prompt_utf8}],
            "stream": false,
            "max_output_bytes": request.maximum_output_bytes,
            "metadata": {"idempotency_key": request.idempotency_key, "request_digest": digest(request.prompt_utf8.as_bytes())}
        }),
        ("OPENAI_COMPATIBLE", ModelOperation::Stream) => json!({
            "model": plan.model_id,
            "messages": [{"role": "user", "content": plan.transformed_prompt_utf8}],
            "stream": true,
            "stream_options": {"include_usage": true},
            "max_output_bytes": request.maximum_output_bytes,
            "metadata": {"idempotency_key": request.idempotency_key, "request_digest": digest(request.prompt_utf8.as_bytes())}
        }),
        ("OPENAI_COMPATIBLE", ModelOperation::Embeddings) => json!({
            "model": plan.model_id,
            "input": plan.transformed_prompt_utf8,
            "encoding_format": "float",
            "metadata": {"idempotency_key": request.idempotency_key, "request_digest": digest(request.prompt_utf8.as_bytes())}
        }),
        (_, operation) => json!({
            "schema_version": "agenttrust.local-model-request.v1",
            "model_id": plan.model_id,
            "model_version": plan.model_version,
            "operation": operation.as_str(),
            "prompt_utf8": plan.transformed_prompt_utf8,
            "maximum_output_bytes": request.maximum_output_bytes,
            "idempotency_key": request.idempotency_key,
            "request_digest": digest(request.prompt_utf8.as_bytes())
        }),
    }
}

fn parse_generate_response(
    bytes: &[u8],
    plan: &RoutePlan,
) -> Result<ProviderOutcome, AuthorityError> {
    let value: Value = strict_json(bytes, MAX_PROVIDER_RESPONSE)?;
    let (request_id, output, input_tokens, output_tokens, finish_reason) =
        if plan.protocol == "OPENAI_COMPATIBLE" {
            (
                string(&value, "/id", 512)?,
                string(&value, "/choices/0/message/content", 1_048_576)?,
                number(&value, "/usage/prompt_tokens")?,
                number(&value, "/usage/completion_tokens")?,
                string(&value, "/choices/0/finish_reason", 64)?,
            )
        } else {
            (
                string(&value, "/request_id", 512)?,
                string(&value, "/output_utf8", 1_048_576)?,
                number(&value, "/input_tokens")?,
                number(&value, "/output_tokens")?,
                string(&value, "/finish_reason", 64)?,
            )
        };
    provider_outcome(
        plan,
        request_id,
        Some(output),
        None,
        Vec::new(),
        finish_reason,
        input_tokens,
        output_tokens,
    )
}

fn parse_embedding_response(
    bytes: &[u8],
    plan: &RoutePlan,
) -> Result<ProviderOutcome, AuthorityError> {
    let value: Value = strict_json(bytes, MAX_PROVIDER_RESPONSE)?;
    let (request_id, embedding_pointer, input_tokens, output_tokens) =
        if plan.protocol == "OPENAI_COMPATIBLE" {
            (
                string(&value, "/id", 512)?,
                "/data/0/embedding",
                number(&value, "/usage/prompt_tokens")?,
                0,
            )
        } else {
            (
                string(&value, "/request_id", 512)?,
                "/embedding",
                number(&value, "/input_tokens")?,
                value
                    .pointer("/output_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
        };
    let values = value
        .pointer(embedding_pointer)
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= 65_536)
        .ok_or(AuthorityError::ProviderOutcomeUnknown)?;
    let embedding = values
        .iter()
        .map(|item| {
            item.as_f64()
                .filter(|number| number.is_finite())
                .map(|number| number as f32)
                .filter(|number| number.is_finite())
                .ok_or(AuthorityError::ProviderOutcomeUnknown)
        })
        .collect::<Result<Vec<_>, _>>()?;
    provider_outcome(
        plan,
        request_id,
        None,
        Some(embedding),
        Vec::new(),
        "stop".into(),
        input_tokens,
        output_tokens,
    )
}

fn parse_openai_sse(bytes: &[u8], plan: &RoutePlan) -> Result<ProviderOutcome, AuthorityError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AuthorityError::ProviderOutcomeUnknown)?;
    let mut chunks = Vec::new();
    let mut provider_request_id = None;
    let mut input_tokens = 0;
    let mut output_tokens = 0;
    let mut finish_reason = None;
    let mut done = false;
    for block in text.split("\n\n") {
        let block = block.trim_matches(['\r', '\n']);
        if block.is_empty() {
            continue;
        }
        let mut data = None;
        for line in block.lines() {
            let line = line.trim_end_matches('\r');
            if line.starts_with(':') || line.starts_with("event:") || line.starts_with("id:") {
                continue;
            }
            let value = line
                .strip_prefix("data: ")
                .ok_or(AuthorityError::ProviderOutcomeUnknown)?;
            if data.replace(value).is_some() {
                return Err(AuthorityError::ProviderOutcomeUnknown);
            }
        }
        let data = data.ok_or(AuthorityError::ProviderOutcomeUnknown)?;
        if data == "[DONE]" {
            done = true;
            continue;
        }
        if done {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let value: Value = strict_json(data.as_bytes(), 2 * 1_048_576)?;
        let current_id = string(&value, "/id", 512)?;
        if provider_request_id
            .as_ref()
            .is_some_and(|existing| existing != &current_id)
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        provider_request_id = Some(current_id);
        if let Some(content) = value
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
        {
            if content.is_empty() || content.len() > 1_048_576 || chunks.len() >= 10_000 {
                return Err(AuthorityError::ProviderOutcomeUnknown);
            }
            chunks.push(content.to_owned());
        }
        if let Some(reason) = value
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            && finish_reason.replace(reason.to_owned()).is_some()
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        if let Some(usage) = value.get("usage") {
            input_tokens = usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .ok_or(AuthorityError::ProviderOutcomeUnknown)?;
            output_tokens = usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .ok_or(AuthorityError::ProviderOutcomeUnknown)?;
        }
    }
    if !done || chunks.is_empty() {
        return Err(AuthorityError::ProviderOutcomeUnknown);
    }
    provider_outcome(
        plan,
        provider_request_id.ok_or(AuthorityError::ProviderOutcomeUnknown)?,
        None,
        None,
        chunks,
        finish_reason.ok_or(AuthorityError::ProviderOutcomeUnknown)?,
        input_tokens,
        output_tokens,
    )
}

fn parse_local_json_lines(
    bytes: &[u8],
    plan: &RoutePlan,
) -> Result<ProviderOutcome, AuthorityError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AuthorityError::ProviderOutcomeUnknown)?;
    let mut chunks = Vec::new();
    let mut request_id = None;
    let mut input_tokens = 0;
    let mut output_tokens = 0;
    let mut finish_reason = None;
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() || index >= 10_000 {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let value: Value = strict_json(line.as_bytes(), 2 * 1_048_576)?;
        let sequence = number(&value, "/sequence")?;
        if sequence
            != u64::try_from(index + 1).map_err(|_| AuthorityError::ProviderOutcomeUnknown)?
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let current_id = string(&value, "/request_id", 512)?;
        if request_id
            .as_ref()
            .is_some_and(|existing| existing != &current_id)
        {
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        request_id = Some(current_id);
        let chunk = string(&value, "/chunk_utf8", 1_048_576)?;
        chunks.push(chunk);
        if let Some(reason) = value.get("finish_reason").and_then(Value::as_str) {
            finish_reason = Some(reason.to_owned());
            input_tokens = number(&value, "/input_tokens")?;
            output_tokens = number(&value, "/output_tokens")?;
        }
    }
    provider_outcome(
        plan,
        request_id.ok_or(AuthorityError::ProviderOutcomeUnknown)?,
        None,
        None,
        chunks,
        finish_reason.ok_or(AuthorityError::ProviderOutcomeUnknown)?,
        input_tokens,
        output_tokens,
    )
}

#[allow(clippy::too_many_arguments)]
fn provider_outcome(
    plan: &RoutePlan,
    provider_request_id: String,
    output_utf8: Option<String>,
    embedding: Option<Vec<f32>>,
    stream_chunks: Vec<String>,
    finish_reason: String,
    input_tokens: u64,
    output_tokens: u64,
) -> Result<ProviderOutcome, AuthorityError> {
    let total = input_tokens
        .checked_add(output_tokens)
        .ok_or(AuthorityError::ProviderOutcomeUnknown)?;
    let cost = total
        .checked_mul(plan.cost_microunits_per_token)
        .ok_or(AuthorityError::ProviderOutcomeUnknown)?;
    if total == 0 || provider_request_id.is_empty() || finish_reason.is_empty() {
        return Err(AuthorityError::ProviderOutcomeUnknown);
    }
    Ok(ProviderOutcome {
        schema_version: EXTERNAL_OUTCOME_SCHEMA.into(),
        provider_request_id,
        output_utf8,
        embedding,
        stream_chunks,
        finish_reason,
        input_tokens,
        output_tokens,
        cost_microunits: cost,
    })
}

fn canonical_output_bytes(outcome: &ProviderOutcome) -> Result<Vec<u8>, AuthorityError> {
    let value = if let Some(output) = &outcome.output_utf8 {
        json!({"kind": "TEXT", "output_utf8": output})
    } else if let Some(embedding) = &outcome.embedding {
        json!({"kind": "EMBEDDING", "embedding": embedding})
    } else {
        json!({"kind": "STREAM", "chunks": outcome.stream_chunks, "finish_reason": outcome.finish_reason})
    };
    serde_jcs::to_vec(&value).map_err(|_| AuthorityError::ProviderOutcomeUnknown)
}

async fn bounded_json_response<T: DeserializeOwned>(
    response: reqwest::Response,
    maximum: usize,
) -> Result<T, AuthorityError> {
    if !response.status().is_success()
        || !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    {
        return Err(AuthorityError::DependencyUnavailable);
    }
    let bytes = bounded_bytes(response, maximum).await?;
    strict_json(&bytes, maximum)
}

async fn bounded_bytes(
    response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, AuthorityError> {
    read_bounded_body(response, maximum)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)
}

fn strict_json<T: DeserializeOwned>(raw: &[u8], maximum: usize) -> Result<T, AuthorityError> {
    let limits = ParseLimits {
        max_body_bytes: maximum,
        max_depth: 64,
        max_array_items: 100_000,
        max_string_bytes: 33_554_432,
        max_object_keys: 4096,
        max_number_chars: 128,
    };
    let value =
        parse_strict_json(raw, &limits).map_err(|_| AuthorityError::ProviderOutcomeUnknown)?;
    serde_json::from_value(value).map_err(|_| AuthorityError::ProviderOutcomeUnknown)
}

fn private_json<T: DeserializeOwned>(path: &Path) -> Result<T, AuthorityError> {
    crate::server::validate_private_file(path, 4 * 1_048_576)?;
    let bytes = std::fs::read(path).map_err(|_| AuthorityError::ConfigurationInvalid)?;
    strict_json(&bytes, 4 * 1_048_576).map_err(|_| AuthorityError::ConfigurationInvalid)
}

fn read_secret(
    path: &Path,
    minimum: usize,
    maximum: usize,
) -> Result<Zeroizing<String>, AuthorityError> {
    crate::server::validate_private_file(path, maximum as u64)?;
    let value = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|_| AuthorityError::ConfigurationInvalid)?,
    );
    if value.trim() != value.as_str()
        || !(minimum..=maximum).contains(&value.len())
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    Ok(value)
}

fn validate_endpoint(endpoint: &AdapterEndpoint) -> Result<(), AuthorityError> {
    validate_service_base(&endpoint.endpoint)?;
    crate::server::validate_private_file(&endpoint.token_file, 8192)
}

fn validate_provider_endpoint(profile: &ProviderEndpointRecord) -> Result<(), AuthorityError> {
    if profile.endpoint_profile.is_empty()
        || profile.endpoint_profile.len() > 128
        || profile.provider_key.is_empty()
        || profile.provider_key.len() > 768
        || !matches!(
            profile.protocol.as_str(),
            "OPENAI_COMPATIBLE" | "LOCAL_INFERENCE"
        )
        || profile.endpoint.scheme() != "https"
        || profile.endpoint.cannot_be_a_base()
        || profile.endpoint.host_str().is_none()
        || !profile.endpoint.username().is_empty()
        || profile.endpoint.password().is_some()
        || profile.endpoint.fragment().is_some()
        || profile.endpoint.query().is_some()
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    crate::server::validate_private_file(&profile.token_file, 8192)
}

fn validate_service_base(url: &Url) -> Result<(), AuthorityError> {
    if url.scheme() != "https"
        || url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.path() != "/"
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn service_url(base: &Url, path: &str) -> Result<Url, AuthorityError> {
    validate_service_base(base)?;
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("..")
        || path.contains('?')
        || path.contains('#')
    {
        return Err(AuthorityError::ConfigurationInvalid);
    }
    let mut result = base.clone();
    result.set_path(path);
    Ok(result)
}

fn string(value: &Value, pointer: &str, maximum: usize) -> Result<String, AuthorityError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .map(str::to_owned)
        .ok_or(AuthorityError::ProviderOutcomeUnknown)
}

fn number(value: &Value, pointer: &str) -> Result<u64, AuthorityError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or(AuthorityError::ProviderOutcomeUnknown)
}

fn provider_key(manifest: &SignedProviderManifest) -> String {
    format!(
        "{}:{}:{}",
        manifest.provider_id, manifest.model_id, manifest.model_version
    )
}

fn deployment_rank(deployment: &str) -> u8 {
    match deployment {
        "LOCAL" => 0,
        "ON_PREM" => 1,
        "VPC" => 2,
        _ => 3,
    }
}

fn model_destination_kind(deployment: &str) -> &'static str {
    match deployment {
        "LOCAL" => "model:Local",
        "ON_PREM" => "model:OnPrem",
        "VPC" => "model:VPC",
        _ => "model:PublicApi",
    }
}

fn deterministic_uuid<T: Serialize>(material: &T) -> Result<Uuid, AuthorityError> {
    let canonical = serde_jcs::to_vec(material).map_err(|_| AuthorityError::RequestInvalid)?;
    let raw = hex::decode(digest(&canonical)).map_err(|_| AuthorityError::RequestInvalid)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&raw[..16]);
    // RFC 4122 variant plus a deterministic, locally generated version-4-shaped identifier.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn valid_shared_policy_decision(value: &DataPolicyDecision) -> bool {
    value.schema_version.0 == "agenttrust.data-governance.v1"
        && identifier(&value.policy_version.0, 256)
        && !value.reason_codes.is_empty()
        && value.reason_codes.len() <= 32
        && value.reason_codes.iter().all(|item| identifier(item, 256))
        && value.required_transformations.len() <= 32
        && value
            .required_transformations
            .iter()
            .all(|item| identifier(item, 256))
        && value
            .required_transformations
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == value.required_transformations.len()
        && value.maximum_retention_seconds <= 630_720_000
}

fn dlp_denied_or_mislabeled(result: &DlpInspectionResult, label: &ModelDataLabel) -> bool {
    let count = |kind: &str| result.finding_counts.get(kind).copied().unwrap_or(0);
    result.blocking
        || count("SECRET") > 0
        || count("ENCODED_PAYLOAD") > 0
        || count("COMPRESSED_PAYLOAD") > 0
        || count("UNKNOWN") > 0
        || (count("PERSONAL_DATA") > 0 && !label.contains_personal_data)
        || (count("INDUSTRIAL_SENSITIVE") > 0
            && label.classification < agent_trust_contracts::DataClassification::Restricted)
}

fn mutation_evidence_ref(result: &DataMutationResult) -> Result<&str, AuthorityError> {
    result
        .evidence_ref
        .as_deref()
        .filter(|value| evidence_reference(value))
        .ok_or(AuthorityError::DependencyUnavailable)
}

fn mutation_evidence_digest(result: &DataMutationResult) -> Result<&str, AuthorityError> {
    result
        .evidence_digest
        .as_deref()
        .filter(|value| lower_digest(value))
        .ok_or(AuthorityError::DependencyUnavailable)
}

fn same_data_command_material(left: &DataCommandRequest, right: &DataCommandRequest) -> bool {
    left.schema_version == right.schema_version
        && left.tenant_id == right.tenant_id
        && left.task_id == right.task_id
        && left.resource == right.resource
        && left.operation == right.operation
        && left.expected_resource_version == right.expected_resource_version
        && stable_data_payload(left.operation, &left.payload)
            == stable_data_payload(right.operation, &right.payload)
}

fn stable_data_payload(operation: DataOperation, payload: &Value) -> Value {
    let mut stable = payload.clone();
    if let Some(object) = stable.as_object_mut() {
        match operation {
            DataOperation::RecordPolicyDecision => {
                object.remove("evaluated_at");
            }
            DataOperation::AuthorizeExport => {
                object.remove("expires_at");
            }
            DataOperation::CompleteExport => {
                object.remove("completed_at");
            }
            _ => {}
        }
    }
    stable
}

fn validate_completed_mutation(
    result: &DataMutationResult,
    command: &DataCommandRequest,
) -> Result<(), AuthorityError> {
    validate_completed_mutation_fields(
        result,
        command.command_id,
        command.operation,
        &command.resource,
    )
}

fn validate_completed_mutation_fields(
    result: &DataMutationResult,
    command_id: Uuid,
    operation: DataOperation,
    resource: &str,
) -> Result<(), AuthorityError> {
    let evidence_ref = result
        .evidence_ref
        .as_deref()
        .ok_or(AuthorityError::DependencyUnavailable)?;
    let evidence_digest = result
        .evidence_digest
        .as_deref()
        .ok_or(AuthorityError::DependencyUnavailable)?;
    if result.schema_version != "agenttrust.data-governance-mutation-result.v1"
        || result.command_id != command_id
        || result.operation != operation
        || result.resource != resource
        || result.resource_version == 0
        || result.state != "COMPLETED"
        || !lower_digest(&result.result_digest)
        || !result.evidence_outbox_ref.starts_with("evidence-outbox://")
        || !evidence_reference(evidence_ref)
        || !lower_digest(evidence_digest)
        || result.safe_receipts.len() > 8
    {
        return Err(AuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn authority_evidence_binding(binding: &ExecutionBinding) -> AuthorityEvidenceControlBinding {
    AuthorityEvidenceControlBinding {
        action_hash: ActionHash(binding.action_hash.clone()),
        ledger_execution_id: ExecutionId(binding.ledger_execution_id.to_string()),
        ledger_event_id: binding.ledger_event_id.to_string(),
        ledger_event_digest: binding.ledger_event_digest.clone(),
        fence_digest: binding.fence_digest.clone(),
        policy_decision_id: binding.policy_decision_id.clone(),
        policy_decision_digest: binding.policy_decision_digest.clone(),
        authorization_evidence_ref: binding.authorization_evidence_ref.clone(),
        authorization_evidence_digest: binding.authorization_evidence_digest.clone(),
    }
}

fn same_authority_evidence_material(
    existing: &AuthorityEvidenceEventRequest,
    proposed: &AuthorityEvidenceEventRequest,
) -> bool {
    existing.schema_version == proposed.schema_version
        && existing.tenant_id == proposed.tenant_id
        && existing.task_id == proposed.task_id
        && existing.authority_event_id == proposed.authority_event_id
        && existing.idempotency_key == proposed.idempotency_key
        && existing.source_kind == proposed.source_kind
        && existing.control_binding == proposed.control_binding
        && existing.event.schema_version == proposed.event.schema_version
        && existing.event.tenant_id == proposed.event.tenant_id
        && existing.event.task_id == proposed.event.task_id
        && existing.event.event_type == proposed.event.event_type
        && existing.event.actor_subject == proposed.event.actor_subject
        && existing.event.source_service == proposed.event.source_service
        && existing.event.trace_id == proposed.event.trace_id
        && existing.event.span_id == proposed.event.span_id
        && existing.event.payload_hash == proposed.event.payload_hash
        && existing.event.safe_summary == proposed.event.safe_summary
        && existing.event.artifact_refs == proposed.event.artifact_refs
}

fn verify_authority_receipt(
    keyring: &EvidenceKeyring,
    source_service: &str,
    request: &AuthorityEvidenceEventRequest,
    receipt: &SignedAuthorityEvidenceReceipt,
) -> Result<(), AuthorityError> {
    let key = keyring
        .keys
        .get(&receipt.key_id)
        .ok_or(AuthorityError::DependencyUnavailable)?;
    let expected_request_digest = request
        .request_digest()
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
    if receipt.tenant_id != request.tenant_id
        || receipt.task_id != request.task_id
        || receipt.authority_event_id != request.authority_event_id
        || receipt.idempotency_key != request.idempotency_key
        || receipt.source_kind != request.source_kind
        || receipt.request_digest != expected_request_digest
        || receipt.payload_digest != request.event.payload_hash
        || receipt.event.draft != request.event
        || receipt.event.draft.source_service != source_service
        || receipt.verify(key, Utc::now()).is_err()
    {
        return Err(AuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_control())
}

fn jurisdiction(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn adapter_reference(value: &str) -> bool {
    value.len() <= 2048
        && [
            "dlp://",
            "object://",
            "worm://",
            "legal-hold://",
            "evidence://",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
        && identifier(value, 2048)
}

fn evidence_reference(value: &str) -> bool {
    value.starts_with("evidence://") && identifier(value, 2048)
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod adapter_tests {
    use super::*;

    #[test]
    fn service_urls_cannot_escape_the_configured_origin() {
        let base = Url::parse("https://policy.example/").ok();
        assert!(
            base.as_ref()
                .is_some_and(|url| service_url(url, "/ready").is_ok())
        );
        assert!(
            base.as_ref()
                .is_some_and(|url| service_url(url, "//evil.example/x").is_err())
        );
        assert!(
            base.as_ref()
                .is_some_and(|url| service_url(url, "/../x").is_err())
        );
    }

    #[test]
    fn duplicate_provider_json_fails_closed() {
        let raw = br#"{"id":"one","id":"two"}"#;
        assert!(strict_json::<Value>(raw, 1024).is_err());
    }

    #[test]
    fn data_operations_use_exact_wire_values() {
        let cases = [
            (DataOperation::RegisterLabel, "\"REGISTER_LABEL\""),
            (
                DataOperation::RecordPolicyDecision,
                "\"RECORD_POLICY_DECISION\"",
            ),
            (DataOperation::RecordDlpScan, "\"RECORD_DLP_SCAN\""),
            (
                DataOperation::RecordTransformReceipt,
                "\"RECORD_TRANSFORM_RECEIPT\"",
            ),
            (
                DataOperation::ConsumeCrossDomainGrant,
                "\"CONSUME_CROSS_DOMAIN_GRANT\"",
            ),
            (DataOperation::AuthorizeExport, "\"AUTHORIZE_EXPORT\""),
            (DataOperation::CompleteExport, "\"COMPLETE_EXPORT\""),
        ];
        for (operation, expected) in cases {
            let encoded = serde_json::to_string(&operation).ok();
            assert_eq!(encoded.as_deref(), Some(expected));
        }
    }
}
