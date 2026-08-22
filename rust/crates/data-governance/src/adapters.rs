//! Fail-closed HTTPS adapters for the orchestrator, enterprise DLP, object/WORM, legal hold, and
//! Evidence authorities. Redirect following is disabled by the production client configuration.

use crate::authority::{
    AdapterReceipt, DataActionReceipt, DataAuthorityError, DataEffectReceipt,
    DataExecutionBinding, DataExecutorRequest, DataOperation, DataOrchestratorPort, DataRuntimePort,
    DATA_EVIDENCE_SCHEMA, adapter_reference, canonical_digest, canonical_uuid, digest,
    evidence_reference, identifier, valid_idempotency_key,
};
use crate::service::{
    ArtifactAuthorizationRequest, DataInspectionPort, EnterpriseDlpReceipt,
    ObjectAuthorizationReceipt,
};
use agent_trust_contracts::{
    ActionHash, AuthorityEvidenceControlBinding, AuthorityEvidenceEventRequest,
    AuthorityEvidenceSourceKind, EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft,
    EvidenceEventType, ExecutionId, IdempotencyKey, SignedAuthorityEvidenceReceipt, TaskId,
    TenantId, AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION,
};
use agent_trust_gateway::InboundEnvelope;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use nix::unistd::{Gid, Uid};
use reqwest::{Client, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AdapterEndpoint {
    pub endpoint: Url,
    pub token_file: PathBuf,
    pub readiness_schema: String,
}

impl AdapterEndpoint {
    pub fn validate(&self) -> Result<(), DataAuthorityError> {
        if self.endpoint.scheme() != "https"
            || self.endpoint.host_str().is_none()
            || self.endpoint.username() != ""
            || self.endpoint.password().is_some()
            || self.endpoint.path() != "/"
            || self.endpoint.query().is_some()
            || self.endpoint.fragment().is_some()
            || self.endpoint.port().is_none()
            || !self.token_file.is_absolute()
            || !identifier(&self.readiness_schema, 128)
        {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        validate_private_file(&self.token_file)
    }
}

#[derive(Debug, Clone)]
pub struct DataAdapterEndpoints {
    pub enterprise_dlp: AdapterEndpoint,
    pub object_worm: AdapterEndpoint,
    pub legal_hold: AdapterEndpoint,
    pub evidence: AdapterEndpoint,
}

#[derive(Clone)]
pub struct EvidenceReceiptVerification {
    source_service: String,
    issuer: String,
    verifying_keys: Arc<BTreeMap<String, VerifyingKey>>,
}

impl EvidenceReceiptVerification {
    pub fn new(
        source_service: String,
        issuer: String,
        verifying_keys: BTreeMap<String, VerifyingKey>,
    ) -> Result<Self, DataAuthorityError> {
        let san_value = source_service.strip_prefix("DNS:")
            .or_else(|| source_service.strip_prefix("URI:"));
        if san_value.is_none_or(str::is_empty)
            || !identifier(&source_service, 256)
            || !identifier(&issuer, 256)
            || verifying_keys.is_empty()
            || verifying_keys.len() > 1_024
            || verifying_keys.keys().any(|key_id| !identifier(key_id, 128))
        {
            return Err(DataAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            source_service,
            issuer,
            verifying_keys: Arc::new(verifying_keys),
        })
    }
}

#[derive(Clone)]
pub struct HttpDataOrchestrator {
    client: Client,
    endpoint: AdapterEndpoint,
}

impl HttpDataOrchestrator {
    pub fn new(client: Client, endpoint: AdapterEndpoint) -> Result<Self, DataAuthorityError> {
        endpoint.validate()?;
        Ok(Self { client, endpoint })
    }
}

#[derive(Clone)]
pub struct HttpDataRuntime {
    client: Client,
    endpoints: DataAdapterEndpoints,
    evidence_verification: EvidenceReceiptVerification,
}

impl HttpDataRuntime {
    pub fn new(
        client: Client,
        endpoints: DataAdapterEndpoints,
        evidence_verification: EvidenceReceiptVerification,
    ) -> Result<Self, DataAuthorityError> {
        endpoints.enterprise_dlp.validate()?;
        endpoints.object_worm.validate()?;
        endpoints.legal_hold.validate()?;
        endpoints.evidence.validate()?;
        Ok(Self { client, endpoints, evidence_verification })
    }

    async fn effect(
        &self,
        endpoint: &AdapterEndpoint,
        path: &str,
        adapter: &str,
        operation: &str,
        binding: &DataExecutionBinding,
        request: &DataExecutorRequest,
    ) -> Result<AdapterReceipt, DataAuthorityError> {
        let target = endpoint.endpoint.join(path)
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        let payload = json!({
            "schema_version": "agenttrust.data-adapter-effect.v1",
            "tenant_id": binding.tenant_id,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "ledger_event_id": binding.ledger_event_id,
            "ledger_event_digest": binding.ledger_event_digest,
            "fence_digest": binding.fence_digest,
            "resource_version": binding.resource_version,
            "idempotency_key": binding.idempotency_key,
            "policy_decision_id": binding.policy_decision_id,
            "policy_decision_digest": binding.policy_decision_digest,
            "authorization_evidence_ref": binding.authorization_evidence_ref,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "operation": request.command.operation,
            "resource": request.command.resource,
            "metadata": request.command.payload,
        });
        let request_digest = canonical_digest(&payload)?;
        let response = self.client.post(target)
            .bearer_auth(read_token(&endpoint.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &binding.tenant_id.0)
            .header("Idempotency-Key", &binding.idempotency_key)
            .header("X-AgentTrust-Action-Hash", &binding.action_hash)
            .header("X-AgentTrust-Ledger-Execution-Id", binding.ledger_execution_id.to_string())
            .header("X-AgentTrust-Ledger-Entry-Id", binding.ledger_event_id.to_string())
            .header("X-AgentTrust-Fence-Digest", &binding.fence_digest)
            .json(&payload)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        if response.status() == StatusCode::CONFLICT {
            return Err(DataAuthorityError::IdempotencyConflict);
        }
        let receipt: AdapterReceipt = bounded_json_response(response, 65_536).await?;
        let mut unsigned = receipt.clone();
        unsigned.receipt_digest.clear();
        let expected_receipt_digest = canonical_digest(&unsigned)?;
        if receipt.adapter != adapter
            || receipt.operation != operation
            || receipt.resource != request.command.resource
            || receipt.idempotency_key != binding.idempotency_key
            || receipt.request_digest != request_digest
            || receipt.receipt_digest != expected_receipt_digest
            || !adapter_reference(&receipt.reference)
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        Ok(receipt)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchestratorAcceptance {
    schema_version: String,
    action_id: String,
    task_id: String,
    accepted: bool,
    start_requested: bool,
    execution_pending: bool,
    ingress_digest: String,
    evidence_ref: String,
    evidence_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEvidencePayload {
    schema_version: String,
    event_id: Uuid,
    tenant_id: Uuid,
    task_id: Uuid,
    command_id: Uuid,
    operation: DataOperation,
    resource: String,
    resource_version: i64,
    action_hash: String,
    ledger_execution_id: Uuid,
    ledger_event_id: Uuid,
    ledger_event_digest: String,
    fence_digest: String,
    policy_decision_id: String,
    policy_decision_digest: String,
    authorization_evidence_ref: String,
    authorization_evidence_digest: String,
    trace_id: String,
    result_digest: String,
    safe_receipts: Vec<AdapterReceipt>,
    event_occurred_at: DateTime<Utc>,
    delivery_requested_at: DateTime<Utc>,
}

#[async_trait]
impl DataOrchestratorPort for HttpDataOrchestrator {
    async fn ready(&self) -> bool {
        endpoint_ready(&self.client, &self.endpoint).await
    }

    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<DataActionReceipt, DataAuthorityError> {
        let idempotency_key = envelope.idempotency_key.as_deref()
            .filter(|value| valid_idempotency_key(value))
            .ok_or(DataAuthorityError::RequestInvalid)?;
        let target = self.endpoint.endpoint.join("v1/actions")
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        let response = self.client.post(target)
            .bearer_auth(read_token(&self.endpoint.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", idempotency_key)
            .json(envelope)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        if response.status() == StatusCode::CONFLICT {
            return Err(DataAuthorityError::IdempotencyConflict);
        }
        let value: OrchestratorAcceptance = bounded_json_response(response, 65_536).await?;
        if value.schema_version != "agenttrust.action-acceptance.v1"
            || !value.accepted
            || !value.start_requested
            || !value.execution_pending
            || !Uuid::parse_str(&value.action_id).is_ok_and(|id| id.to_string() == value.action_id)
            || !Uuid::parse_str(&value.task_id).is_ok_and(|id| id.to_string() == value.task_id)
            || !digest(&value.ingress_digest)
            || !evidence_reference(&value.evidence_ref)
            || !digest(&value.evidence_digest)
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        Ok(DataActionReceipt {
            schema_version: crate::authority::DATA_ACTION_RECEIPT_SCHEMA.into(),
            action_id: value.action_id,
            task_id: value.task_id,
            accepted: true,
            execution_pending: true,
            ingress_digest: value.ingress_digest,
            ledger_evidence_ref: value.evidence_ref,
            ledger_evidence_digest: value.evidence_digest,
        })
    }
}

#[async_trait]
impl DataRuntimePort for HttpDataRuntime {
    async fn ready(&self) -> bool {
        let (dlp, object, hold, evidence) = tokio::join!(
            endpoint_ready(&self.client, &self.endpoints.enterprise_dlp),
            endpoint_ready(&self.client, &self.endpoints.object_worm),
            endpoint_ready(&self.client, &self.endpoints.legal_hold),
            endpoint_ready(&self.client, &self.endpoints.evidence),
        );
        dlp && object && hold && evidence
    }

    async fn execute_effects(
        &self,
        binding: &DataExecutionBinding,
        request: &DataExecutorRequest,
    ) -> Result<Option<DataEffectReceipt>, DataAuthorityError> {
        let receipts = match request.command.operation {
            DataOperation::RecordDlpScan => vec![self.effect(
                &self.endpoints.enterprise_dlp,
                "v1/dlp/receipts/verify",
                "ENTERPRISE_DLP",
                "VERIFY_DLP_RECEIPT",
                binding,
                request,
            ).await?],
            DataOperation::ResolveRetention => vec![self.effect(
                &self.endpoints.legal_hold,
                "v1/legal-holds/retention-check",
                "LEGAL_HOLD",
                "RESOLVE_RETENTION",
                binding,
                request,
            ).await?],
            DataOperation::PlaceLegalHold => vec![self.effect(
                &self.endpoints.legal_hold,
                "v1/legal-holds/place",
                "LEGAL_HOLD",
                "PLACE",
                binding,
                request,
            ).await?],
            DataOperation::ReleaseLegalHold => vec![self.effect(
                &self.endpoints.legal_hold,
                "v1/legal-holds/release",
                "LEGAL_HOLD",
                "RELEASE",
                binding,
                request,
            ).await?],
            DataOperation::AuthorizeExport => vec![
                self.effect(
                    &self.endpoints.enterprise_dlp,
                    "v1/dlp/authorize-export",
                    "ENTERPRISE_DLP",
                    "AUTHORIZE_EXPORT",
                    binding,
                    request,
                ).await?,
                self.effect(
                    &self.endpoints.object_worm,
                    "v1/objects/authorize-export",
                    "OBJECT_WORM",
                    "AUTHORIZE_EXPORT",
                    binding,
                    request,
                ).await?,
            ],
            DataOperation::CompleteExport => vec![self.effect(
                &self.endpoints.object_worm,
                "v1/objects/complete-export",
                "OBJECT_WORM",
                "COMPLETE_EXPORT",
                binding,
                request,
            ).await?],
            _ => return Ok(None),
        };
        let mut receipt = DataEffectReceipt {
            schema_version: "agenttrust.data-governance-effect-receipt.v1".into(),
            tenant_id: Uuid::parse_str(&binding.tenant_id.0)
                .map_err(|_| DataAuthorityError::RequestInvalid)?,
            action_hash: binding.action_hash.clone(),
            ledger_execution_id: binding.ledger_execution_id,
            idempotency_key: binding.idempotency_key.clone(),
            operation: request.command.operation,
            resource: request.command.resource.clone(),
            receipts,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = canonical_digest(&receipt)?;
        Ok(Some(receipt))
    }

    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<SignedAuthorityEvidenceReceipt, DataAuthorityError> {
        if !digest(payload_digest)
            || canonical_digest(payload)? != payload_digest
            || !valid_idempotency_key(idempotency_key)
            || idempotency_key.len() > 128
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        let evidence: AuthorityEvidencePayload = serde_json::from_value(payload.clone())
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        if evidence.schema_version != DATA_EVIDENCE_SCHEMA
            || evidence.event_id != event_id
            || evidence.tenant_id.to_string() != tenant.0
            || !canonical_uuid(&evidence.task_id.to_string())
            || !canonical_uuid(&evidence.command_id.to_string())
            || evidence.resource_version <= 0
            || !identifier(&evidence.resource, 1_024)
            || !digest(&evidence.action_hash)
            || !digest(&evidence.ledger_event_digest)
            || !digest(&evidence.fence_digest)
            || !identifier(&evidence.policy_decision_id, 256)
            || !digest(&evidence.policy_decision_digest)
            || !evidence_reference(&evidence.authorization_evidence_ref)
            || !digest(&evidence.authorization_evidence_digest)
            || !identifier(&evidence.trace_id, 256)
            || !digest(&evidence.result_digest)
            || evidence.safe_receipts.len() > 2
            || evidence.safe_receipts.iter().any(|receipt| {
                !identifier(&receipt.adapter, 128)
                    || !identifier(&receipt.operation, 128)
                    || !identifier(&receipt.resource, 1_024)
                    || !valid_idempotency_key(&receipt.idempotency_key)
                    || !digest(&receipt.request_digest)
                    || !digest(&receipt.receipt_digest)
                    || !adapter_reference(&receipt.reference)
            })
            || evidence.delivery_requested_at != evidence.event_occurred_at
            || evidence.delivery_requested_at > Utc::now() + chrono::Duration::minutes(1)
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId(evidence.task_id.to_string()),
            authority_event_id: event_id.to_string(),
            idempotency_key: IdempotencyKey(idempotency_key.into()),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(AuthorityEvidenceControlBinding {
                action_hash: ActionHash(evidence.action_hash),
                ledger_execution_id: ExecutionId(evidence.ledger_execution_id.to_string()),
                ledger_event_id: evidence.ledger_event_id.to_string(),
                ledger_event_digest: evidence.ledger_event_digest,
                fence_digest: evidence.fence_digest,
                policy_decision_id: evidence.policy_decision_id,
                policy_decision_digest: evidence.policy_decision_digest,
                authorization_evidence_ref: evidence.authorization_evidence_ref,
                authorization_evidence_digest: evidence.authorization_evidence_digest,
            }),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                task_id: TaskId(evidence.task_id.to_string()),
                event_type: EvidenceEventType::StateTransition,
                actor_subject: self.evidence_verification.source_service.clone(),
                source_service: self.evidence_verification.source_service.clone(),
                trace_id: evidence.trace_id,
                span_id: evidence.ledger_execution_id.to_string(),
                payload_hash: payload_digest.into(),
                safe_summary: format!(
                    "data-governance {} committed",
                    evidence.operation.as_str()
                ),
                artifact_refs: Vec::new(),
                occurred_at: evidence.event_occurred_at,
            },
            requested_at: evidence.delivery_requested_at,
        };
        let request_digest = request.request_digest()
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        let target = self.endpoints.evidence.endpoint.join("v1/evidence/authority-events")
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        let response = self.client.post(target)
            .bearer_auth(read_token(&self.endpoints.evidence.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", idempotency_key)
            .header("X-AgentTrust-Authority-Event-Id", event_id.to_string())
            .header("X-AgentTrust-Payload-Digest", payload_digest)
            .json(&request)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        if response.status() == StatusCode::CONFLICT {
            return Err(DataAuthorityError::IdempotencyConflict);
        }
        let receipt: SignedAuthorityEvidenceReceipt = bounded_json_response(response, 65_536).await?;
        let verifying_key = self.evidence_verification.verifying_keys.get(&receipt.key_id)
            .ok_or(DataAuthorityError::DependencyUnavailable)?;
        receipt.verify(verifying_key, Utc::now())
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        if receipt.issuer != self.evidence_verification.issuer
            || receipt.tenant_id != request.tenant_id
            || receipt.task_id != request.task_id
            || receipt.authority_event_id != request.authority_event_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.source_kind != request.source_kind
            || receipt.request_digest != request_digest
            || receipt.payload_digest != payload_digest
            || receipt.event.draft != request.event
            || !evidence_reference(&receipt.evidence_ref)
            || !digest(&receipt.evidence_digest)
        {
            return Err(DataAuthorityError::DependencyUnavailable);
        }
        Ok(receipt)
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DlpScanAdapterRequest<'a> {
    schema_version: &'static str,
    tenant_id: &'a str,
    scan_id: Uuid,
    content_digest: &'a str,
    media_type: &'a str,
    content_base64: String,
}

#[async_trait]
impl DataInspectionPort for HttpDataRuntime {
    async fn ready(&self) -> bool {
        endpoint_ready(&self.client, &self.endpoints.enterprise_dlp).await
            && endpoint_ready(&self.client, &self.endpoints.object_worm).await
    }

    async fn inspect(
        &self,
        tenant: &TenantId,
        scan_id: Uuid,
        content_digest: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<EnterpriseDlpReceipt, DataAuthorityError> {
        if bytes.is_empty()
            || bytes.len() > crate::MAX_INSPECTION_BYTES
            || !digest(content_digest)
            || !identifier(media_type, 128)
        {
            return Err(DataAuthorityError::RequestInvalid);
        }
        let target = self.endpoints.enterprise_dlp.endpoint.join("v1/dlp/scans")
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        let request = DlpScanAdapterRequest {
            schema_version: "agenttrust.enterprise-dlp-scan.v1",
            tenant_id: &tenant.0,
            scan_id,
            content_digest,
            media_type,
            content_base64: STANDARD.encode(bytes),
        };
        let response = self.client.post(target)
            .bearer_auth(read_token(&self.endpoints.enterprise_dlp.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", format!("dlp-scan-{scan_id}"))
            .json(&request)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        bounded_json_response(response, 262_144).await
    }

    async fn authorize_object(
        &self,
        tenant: &TenantId,
        request: &ArtifactAuthorizationRequest,
        decision_digest: &str,
        policy_request_digest: &str,
        dlp_receipt_digest: &str,
    ) -> Result<ObjectAuthorizationReceipt, DataAuthorityError> {
        if !digest(decision_digest)
            || !digest(policy_request_digest)
            || !digest(dlp_receipt_digest)
        {
            return Err(DataAuthorityError::RequestInvalid);
        }
        let target = self.endpoints.object_worm.endpoint.join("v1/objects/authorize")
            .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
        let payload = json!({
            "schema_version": "agenttrust.object-authorization.v1",
            "tenant_id": tenant,
            "authorization_id": request.authorization_id,
            "object_ref": request.object_ref,
            "object_digest": request.object_digest,
            "label_digest": request.label_digest,
            "decision_id": request.decision_id,
            "destination_digest": request.destination_digest,
            "decision_digest": decision_digest,
            "policy_request_digest": policy_request_digest,
            "dlp_scan_id": request.dlp_scan_id,
            "dlp_receipt_digest": dlp_receipt_digest,
            "transform_id": request.transform_id,
            "transform_receipt_digest": request.transform_receipt_digest,
            "cross_domain_grant_id": request.cross_domain_grant_id,
            "cross_domain_approval_id": request.policy_request.cross_domain_approval_id,
            "redirect_target_digests": request.redirect_target_digests,
        });
        let response = self.client.post(target)
            .bearer_auth(read_token(&self.endpoints.object_worm.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", format!("object-auth-{}", request.authorization_id))
            .json(&payload)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
        bounded_json_response(response, 65_536).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

async fn endpoint_ready(client: &Client, endpoint: &AdapterEndpoint) -> bool {
    let Ok(target) = endpoint.endpoint.join("ready") else {
        return false;
    };
    let Ok(token) = read_token(&endpoint.token_file) else {
        return false;
    };
    let Ok(response) = client.get(target)
        .bearer_auth(token)
        .timeout(Duration::from_secs(3))
        .send()
        .await else {
            return false;
        };
    bounded_json_response::<DependencyReadiness>(response, 4096)
        .await
        .is_ok_and(|value| {
            value.schema_version == endpoint.readiness_schema && value.ready
        })
}

async fn bounded_json_response<T: DeserializeOwned>(
    response: reqwest::Response,
    maximum: usize,
) -> Result<T, DataAuthorityError> {
    let maximum_u64 = u64::try_from(maximum)
        .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    let mut content_types = response
        .headers()
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter();
    let exact_json = content_types.next()
        .and_then(|value| value.to_str().ok()) == Some("application/json")
        && content_types.next().is_none();
    if !response.status().is_success()
        || response.content_length().is_some_and(|length| length > maximum_u64)
        || !exact_json
    {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    let bytes = response.bytes().await
        .map_err(|_| DataAuthorityError::DependencyUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DataAuthorityError::DependencyUnavailable);
    }
    crate::server::strict_json(&bytes)
        .map_err(|_| DataAuthorityError::DependencyUnavailable)
}

fn read_token(path: &PathBuf) -> Result<String, DataAuthorityError> {
    validate_private_file(path)?;
    let token = fs::read_to_string(path)
        .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    let token = token.trim();
    if !(16..=8192).contains(&token.len())
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(DataAuthorityError::ConfigurationInvalid);
    }
    Ok(token.into())
}

fn validate_private_file(path: &PathBuf) -> Result<(), DataAuthorityError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DataAuthorityError::ConfigurationInvalid)?;
    let mode = metadata.mode() & 0o777;
    let effective_uid = Uid::effective().as_raw();
    let effective_gid = Gid::effective().as_raw();
    let allowed = 0o400 | if metadata.gid() == effective_gid { 0o040 } else { 0 };
    let readable = (metadata.uid() == effective_uid && mode & 0o400 != 0)
        || (metadata.gid() == effective_gid && mode & 0o040 != 0);
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 8194
        || !readable
        || mode & !allowed != 0
    {
        return Err(DataAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}
