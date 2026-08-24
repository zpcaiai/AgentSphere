//! Fail-closed production adapters for Context Governance.
//!
//! All endpoints are HTTPS roots reached through the process-wide mTLS client. Tokens are read
//! from absolute private files for each request so rotation does not require a process restart.
//! Adapter responses are strictly decoded, request-bound, digest-bound, bounded, and never carry
//! document content back into the control plane.

use crate::authority::{
    AdapterReceipt, ContextAuthorityError, ContextEffectReceipt, ContextExecutionBinding,
    ContextExecutorRequest, ContextOperation, ContextOrchestratorPort, ContextRetrievalRequest,
    ContextRuntimePort, EvidenceDeliveryReceipt, RetrievalAuthorizationBinding,
    RetrievalDecision, VectorSearchHit, canonical_digest, digest, evidence_reference, identifier,
    index_reference, object_reference, valid_idempotency_key,
};
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ActionHash, ArtifactRef,
    AuthorityEvidenceControlBinding, AuthorityEvidenceEventRequest,
    AuthorityEvidenceSourceKind, EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft,
    EvidenceEventType, ExecutionId, IdempotencyKey, SignedAuthorityEvidenceReceipt, TaskId,
    TenantId,
};
use agent_trust_gateway::InboundEnvelope;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use nix::unistd::Uid;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

const MAX_DEPENDENCY_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone)]
pub struct AdapterEndpoint {
    pub endpoint: Url,
    pub token_file: PathBuf,
}

impl AdapterEndpoint {
    fn validate(&self) -> Result<(), ContextAuthorityError> {
        validate_https_root(&self.endpoint)?;
        if !self.token_file.is_absolute() {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        read_token(&self.token_file)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ContextAdapterEndpoints {
    pub object_store: AdapterEndpoint,
    pub vector_index: AdapterEndpoint,
    pub cache: AdapterEndpoint,
    pub supply_chain: AdapterEndpoint,
    pub legal_hold: AdapterEndpoint,
    pub poisoning: AdapterEndpoint,
    pub evidence: AdapterEndpoint,
}

#[derive(Clone)]
pub struct HttpContextRuntime {
    client: reqwest::Client,
    endpoints: ContextAdapterEndpoints,
    evidence_client_identity: String,
    evidence_keyring: ContextEvidenceKeyring,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyringDocument {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ContextEvidenceKeyring {
    keys: Arc<BTreeMap<String, VerifyingKey>>,
}

impl ContextEvidenceKeyring {
    pub fn from_json(raw: &[u8]) -> Result<Self, ContextAuthorityError> {
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        let document: EvidenceKeyringDocument =
            strict_json(raw).map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.ed25519-public-keyring.v1"
            || document.keys.is_empty()
            || document.keys.len() > 1_024
        {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for (key_id, encoded) in document.keys {
            if !identifier(&key_id, 128) {
                return Err(ContextAuthorityError::ConfigurationInvalid);
            }
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?
                .try_into()
                .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
            if keys.insert(key_id, key).is_some() {
                return Err(ContextAuthorityError::ConfigurationInvalid);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }
}

#[derive(Clone)]
pub struct HttpContextOrchestrator {
    client: reqwest::Client,
    endpoint: AdapterEndpoint,
}

impl HttpContextOrchestrator {
    pub fn new(
        client: reqwest::Client,
        endpoint: AdapterEndpoint,
    ) -> Result<Self, ContextAuthorityError> {
        endpoint.validate()?;
        Ok(Self { client, endpoint })
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

#[async_trait]
impl ContextOrchestratorPort for HttpContextOrchestrator {
    async fn ready(&self) -> bool {
        let Ok(target) = self.endpoint.endpoint.join("ready") else {
            return false;
        };
        let Ok(token) = read_token(&self.endpoint.token_file) else {
            return false;
        };
        let Ok(response) = self
            .client
            .get(target)
            .bearer_auth(token)
            .timeout(Duration::from_secs(3))
            .send()
            .await
        else {
            return false;
        };
        if !response.status().is_success()
            || response.content_length().is_some_and(|length| length > 4096)
        {
            return false;
        }
        let Ok(bytes) = read_bounded_body(response, 4_096).await else {
            return false;
        };
        strict_json::<DependencyReadiness>(&bytes).is_ok_and(|value| {
            value.schema_version == "agenttrust.orchestrator-readiness.v1" && value.ready
        })
    }

    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<crate::authority::ContextActionReceipt, ContextAuthorityError> {
        let idempotency_key = envelope
            .idempotency_key
            .as_deref()
            .filter(|value| valid_idempotency_key(value))
            .ok_or(ContextAuthorityError::RequestInvalid)?;
        let target = self
            .endpoint
            .endpoint
            .join("v1/actions")
            .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
        let response = self
            .client
            .post(target)
            .bearer_auth(read_token(&self.endpoint.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", idempotency_key)
            .json(envelope)
            .send()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(ContextAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response.content_length().is_some_and(|length| length > 65_536)
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        let value: OrchestratorAcceptance = strict_json(&bytes)
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if value.schema_version != "agenttrust.action-acceptance.v1"
            || !value.accepted
            || !value.start_requested
            || !value.execution_pending
            || !Uuid::parse_str(&value.action_id)
                .is_ok_and(|parsed| parsed.to_string() == value.action_id)
            || !Uuid::parse_str(&value.task_id)
                .is_ok_and(|parsed| parsed.to_string() == value.task_id)
            || !digest(&value.ingress_digest)
            || !evidence_reference(&value.evidence_ref)
            || !digest(&value.evidence_digest)
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        Ok(crate::authority::ContextActionReceipt {
            schema_version: crate::authority::CONTEXT_ACTION_RECEIPT_SCHEMA.into(),
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

impl HttpContextRuntime {
    pub fn new(
        client: reqwest::Client,
        endpoints: ContextAdapterEndpoints,
        evidence_client_identity: String,
        evidence_keyring: ContextEvidenceKeyring,
    ) -> Result<Self, ContextAuthorityError> {
        endpoints.object_store.validate()?;
        endpoints.vector_index.validate()?;
        endpoints.cache.validate()?;
        endpoints.supply_chain.validate()?;
        endpoints.legal_hold.validate()?;
        endpoints.poisoning.validate()?;
        endpoints.evidence.validate()?;
        if evidence_client_identity.len() > 512
            || !(evidence_client_identity.starts_with("DNS:")
                || evidence_client_identity.starts_with("URI:"))
            || evidence_client_identity.contains(char::is_whitespace)
        {
            return Err(ContextAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            client,
            endpoints,
            evidence_client_identity,
            evidence_keyring,
        })
    }

    async fn effect_call(
        &self,
        endpoint: &AdapterEndpoint,
        path: &str,
        adapter: &str,
        operation: &str,
        binding: &ContextExecutionBinding,
        resource: &str,
        payload: Value,
    ) -> Result<AdapterResponse, ContextAuthorityError> {
        let request = AdapterRequest {
            schema_version: "agenttrust.context-adapter-request.v1",
            tenant_id: parse_tenant(&binding.tenant_id)?,
            action_hash: &binding.action_hash,
            ledger_execution_id: binding.ledger_execution_id,
            ledger_event_id: binding.ledger_event_id,
            ledger_event_digest: &binding.ledger_event_digest,
            fence_digest: &binding.fence_digest,
            policy_decision_digest: &binding.policy_decision_digest,
            authorization_evidence_ref: &binding.authorization_evidence_ref,
            authorization_evidence_digest: &binding.authorization_evidence_digest,
            idempotency_key: &binding.idempotency_key,
            adapter,
            operation,
            resource,
            payload,
        };
        let request_digest = canonical_digest(&request)?;
        let response: AdapterResponse = self
            .post(endpoint, path, &binding.tenant_id, &binding.idempotency_key, &request)
            .await?;
        validate_adapter_response(
            &response,
            adapter,
            operation,
            resource,
            &binding.idempotency_key,
            &request_digest,
        )?;
        Ok(response)
    }

    async fn post<T: Serialize + ?Sized, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &AdapterEndpoint,
        path: &str,
        tenant: &TenantId,
        idempotency_key: &str,
        body: &T,
    ) -> Result<R, ContextAuthorityError> {
        let target = endpoint
            .endpoint
            .join(path)
            .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
        let response = self
            .client
            .post(target)
            .bearer_auth(read_token(&endpoint.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", idempotency_key)
            .json(body)
            .send()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_DEPENDENCY_RESPONSE_BYTES as u64)
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, MAX_DEPENDENCY_RESPONSE_BYTES)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > MAX_DEPENDENCY_RESPONSE_BYTES {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        strict_json(&bytes).map_err(|_| ContextAuthorityError::DependencyUnavailable)
    }

    async fn dependency_ready(&self, endpoint: &AdapterEndpoint) -> bool {
        let Ok(target) = endpoint.endpoint.join("ready") else {
            return false;
        };
        let Ok(token) = read_token(&endpoint.token_file) else {
            return false;
        };
        let Ok(response) = self
            .client
            .get(target)
            .bearer_auth(token)
            .timeout(Duration::from_secs(3))
            .send()
            .await
        else {
            return false;
        };
        if !response.status().is_success()
            || response.content_length().is_some_and(|length| length > 4096)
        {
            return false;
        }
        let Ok(bytes) = read_bounded_body(response, 4_096).await else {
            return false;
        };
        strict_json::<DependencyReadiness>(&bytes).is_ok_and(|value| {
            value.schema_version == "agenttrust.context-adapter-readiness.v1" && value.ready
        })
    }

    async fn poison_scan(
        &self,
        binding: &ContextExecutionBinding,
        resource: &str,
        object_ref: &str,
        content_digest: &str,
    ) -> Result<(AdapterReceipt, BTreeSet<String>), ContextAuthorityError> {
        let response = self
            .effect_call(
                &self.endpoints.poisoning,
                "v1/poisoning/scans",
                "POISONING",
                "SCAN",
                binding,
                resource,
                json!({
                    "object_ref": object_ref,
                    "content_digest": content_digest,
                    "detectors": [
                        "DIRECT_INSTRUCTION_INJECTION",
                        "INDIRECT_INSTRUCTION_INJECTION",
                        "ENCODING_CONFUSION",
                        "CROSS_TENANT_MARKER",
                        "SENSITIVE_DATA",
                        "ABNORMAL_REPETITION"
                    ]
                }),
            )
            .await?;
        Ok((response.receipt, response.findings))
    }

    async fn supply_chain_verify(
        &self,
        binding: &ContextExecutionBinding,
        resource: &str,
        artifact_digest: &str,
        receipt: &Value,
    ) -> Result<AdapterReceipt, ContextAuthorityError> {
        let response = self
            .effect_call(
                &self.endpoints.supply_chain,
                "v1/supply-chain/verifications",
                "SUPPLY_CHAIN",
                "VERIFY",
                binding,
                resource,
                json!({
                    "artifact_digest": artifact_digest,
                    "receipt": receipt,
                    "required_usage": "CONTEXT_ARTIFACT",
                    "require_transparency": true,
                    "require_non_revoked_signer": true
                }),
            )
            .await?;
        if response.verified != Some(true) {
            return Err(ContextAuthorityError::SupplyChainDenied);
        }
        Ok(response.receipt)
    }

    async fn object_promote(
        &self,
        binding: &ContextExecutionBinding,
        resource: &str,
        staging_ref: &str,
        content_digest: &str,
        quarantine: bool,
    ) -> Result<(AdapterReceipt, String), ContextAuthorityError> {
        let response = self
            .effect_call(
                &self.endpoints.object_store,
                "v1/objects/promotions",
                "OBJECT_STORE",
                "PROMOTE_IMMUTABLE",
                binding,
                resource,
                json!({
                    "staging_object_ref": staging_ref,
                    "content_digest": content_digest,
                    "destination_class": if quarantine { "QUARANTINE" } else { "GOVERNED" },
                    "retention_lock_required": true
                }),
            )
            .await?;
        let object_ref = response
            .object_ref
            .filter(|value| object_reference(value))
            .ok_or(ContextAuthorityError::DependencyUnavailable)?;
        Ok((response.receipt, object_ref))
    }

    async fn vector_upsert(
        &self,
        binding: &ContextExecutionBinding,
        resource: &str,
        object_ref: &str,
        content_digest: &str,
    ) -> Result<(AdapterReceipt, String), ContextAuthorityError> {
        let response = self
            .effect_call(
                &self.endpoints.vector_index,
                "v1/vector/upserts",
                "VECTOR_INDEX",
                "UPSERT",
                binding,
                resource,
                json!({
                    "object_ref": object_ref,
                    "content_digest": content_digest,
                    "metadata": {
                        "tenant_id": binding.tenant_id.0,
                        "resource": resource,
                        "action_hash": binding.action_hash
                    }
                }),
            )
            .await?;
        let index_ref = response
            .index_ref
            .filter(|value| index_reference(value))
            .ok_or(ContextAuthorityError::DependencyUnavailable)?;
        Ok((response.receipt, index_ref))
    }

    async fn purge_adapter(
        &self,
        endpoint: &AdapterEndpoint,
        path: &str,
        adapter: &str,
        operation: &str,
        binding: &ContextExecutionBinding,
        resource: &str,
        payload: Value,
    ) -> Result<AdapterReceipt, ContextAuthorityError> {
        self.effect_call(
            endpoint,
            path,
            adapter,
            operation,
            binding,
            resource,
            payload,
        )
        .await
        .map(|response| response.receipt)
    }
}

#[async_trait]
impl ContextRuntimePort for HttpContextRuntime {
    async fn ready(&self) -> bool {
        let checks = tokio::join!(
            self.dependency_ready(&self.endpoints.object_store),
            self.dependency_ready(&self.endpoints.vector_index),
            self.dependency_ready(&self.endpoints.cache),
            self.dependency_ready(&self.endpoints.supply_chain),
            self.dependency_ready(&self.endpoints.legal_hold),
            self.dependency_ready(&self.endpoints.poisoning),
            self.dependency_ready(&self.endpoints.evidence),
        );
        checks.0 && checks.1 && checks.2 && checks.3 && checks.4 && checks.5 && checks.6
    }

    async fn execute_effects(
        &self,
        binding: &ContextExecutionBinding,
        request: &ContextExecutorRequest,
    ) -> Result<Option<ContextEffectReceipt>, ContextAuthorityError> {
        if !request.command.operation.external_effects() {
            return Ok(None);
        }
        let payload = request
            .command
            .payload
            .as_object()
            .ok_or(ContextAuthorityError::RequestInvalid)?;
        let resource = request.command.resource.as_str();
        let mut receipts = Vec::new();
        let mut findings = BTreeSet::new();
        let mut object_ref = None;
        let mut index_ref = None;
        let mut legal_hold_blocked = false;
        match request.command.operation {
            ContextOperation::WriteMemory => {
                let staging = required_string(payload, "staging_object_ref")?;
                let content = required_string(payload, "content_digest")?;
                let (poison_receipt, observed) =
                    self.poison_scan(binding, resource, staging, content).await?;
                receipts.push(poison_receipt);
                findings = observed;
                let (object_receipt, promoted) = self
                    .object_promote(binding, resource, staging, content, !findings.is_empty())
                    .await?;
                receipts.push(object_receipt);
                object_ref = Some(promoted.clone());
                if findings.is_empty() {
                    let (vector_receipt, index) = self
                        .vector_upsert(binding, resource, &promoted, content)
                        .await?;
                    receipts.push(vector_receipt);
                    index_ref = Some(index);
                }
            }
            ContextOperation::PublishPrompt => {
                receipts.push(
                    self.supply_chain_verify(
                        binding,
                        resource,
                        required_string(payload, "artifact_digest")?,
                        payload
                            .get("supply_chain_receipt")
                            .ok_or(ContextAuthorityError::RequestInvalid)?,
                    )
                    .await?,
                );
                let staging = required_string(payload, "staging_object_ref")?;
                let content = required_string(payload, "content_digest")?;
                let (poison_receipt, observed) =
                    self.poison_scan(binding, resource, staging, content).await?;
                receipts.push(poison_receipt);
                findings = observed;
                let (object_receipt, promoted) = self
                    .object_promote(binding, resource, staging, content, !findings.is_empty())
                    .await?;
                receipts.push(object_receipt);
                object_ref = Some(promoted);
            }
            ContextOperation::PublishKnowledgeSnapshot => {
                receipts.push(
                    self.supply_chain_verify(
                        binding,
                        resource,
                        required_string(payload, "artifact_digest")?,
                        payload
                            .get("supply_chain_receipt")
                            .ok_or(ContextAuthorityError::RequestInvalid)?,
                    )
                    .await?,
                );
                let staging = required_string(payload, "staging_object_ref")?;
                let content = required_string(payload, "content_digest")?;
                let (poison_receipt, observed) =
                    self.poison_scan(binding, resource, staging, content).await?;
                receipts.push(poison_receipt);
                findings = observed;
                let (object_receipt, promoted) = self
                    .object_promote(binding, resource, staging, content, !findings.is_empty())
                    .await?;
                receipts.push(object_receipt);
                object_ref = Some(promoted.clone());
                if findings.is_empty() {
                    let (vector_receipt, index) = self
                        .vector_upsert(binding, resource, &promoted, content)
                        .await?;
                    receipts.push(vector_receipt);
                    index_ref = Some(index);
                }
            }
            ContextOperation::DeleteMemory | ContextOperation::DeleteKnowledgeSnapshot => {
                let hold = self
                    .effect_call(
                        &self.endpoints.legal_hold,
                        "v1/legal-holds/checks",
                        "LEGAL_HOLD",
                        "CHECK_DELETE",
                        binding,
                        resource,
                        json!({
                            "legal_hold_id": required_string(payload, "legal_hold_id")?,
                            "content_digest": required_string(payload, "content_digest")?
                        }),
                    )
                    .await?;
                legal_hold_blocked = hold.legal_hold_active == Some(true);
                receipts.push(hold.receipt);
                if !legal_hold_blocked {
                    receipts.push(
                        self.purge_adapter(
                            &self.endpoints.object_store,
                            "v1/objects/deletions",
                            "OBJECT_STORE",
                            "DELETE",
                            binding,
                            resource,
                            json!({
                                "object_ref": required_string(payload, "object_ref")?,
                                "content_digest": required_string(payload, "content_digest")?,
                                "verify_absent": true
                            }),
                        )
                        .await?,
                    );
                    receipts.push(
                        self.purge_adapter(
                            &self.endpoints.vector_index,
                            "v1/vector/deletions",
                            "VECTOR_INDEX",
                            "DELETE",
                            binding,
                            resource,
                            json!({
                                "index_ref": payload.get("index_ref").cloned().unwrap_or(Value::Null),
                                "verify_absent": true
                            }),
                        )
                        .await?,
                    );
                    receipts.push(
                        self.purge_adapter(
                            &self.endpoints.cache,
                            "v1/cache/purges",
                            "CACHE",
                            "PURGE",
                            binding,
                            resource,
                            json!({"verify_absent": true}),
                        )
                        .await?,
                    );
                }
            }
            ContextOperation::QuarantineResource => {
                receipts.push(
                    self.purge_adapter(
                        &self.endpoints.vector_index,
                        "v1/vector/deletions",
                        "VECTOR_INDEX",
                        "QUARANTINE_REMOVE",
                        binding,
                        resource,
                        json!({
                            "index_ref": payload.get("index_ref").cloned().unwrap_or(Value::Null),
                            "verify_absent": true
                        }),
                    )
                    .await?,
                );
                receipts.push(
                    self.purge_adapter(
                        &self.endpoints.cache,
                        "v1/cache/purges",
                        "CACHE",
                        "QUARANTINE_PURGE",
                        binding,
                        resource,
                        json!({"verify_absent": true}),
                    )
                    .await?,
                );
            }
            ContextOperation::ReleaseQuarantine => {
                let object = required_string(payload, "object_ref")?;
                let content = required_string(payload, "content_digest")?;
                let (poison_receipt, observed) =
                    self.poison_scan(binding, resource, object, content).await?;
                receipts.push(poison_receipt);
                findings = observed;
                if findings.is_empty() {
                    let (vector_receipt, index) =
                        self.vector_upsert(binding, resource, object, content).await?;
                    receipts.push(vector_receipt);
                    index_ref = Some(index);
                    receipts.push(
                        self.purge_adapter(
                            &self.endpoints.cache,
                            "v1/cache/purges",
                            "CACHE",
                            "PURGE_STALE_QUARANTINE",
                            binding,
                            resource,
                            json!({"verify_absent": true}),
                        )
                        .await?,
                    );
                }
            }
            ContextOperation::ActivatePrompt
            | ContextOperation::RollbackPrompt
            | ContextOperation::RegisterKnowledgeSource => {
                return Err(ContextAuthorityError::RequestInvalid);
            }
        }
        let mut receipt = ContextEffectReceipt {
            schema_version: "agenttrust.context-effect-receipt.v1".into(),
            tenant_id: request.command.tenant_id,
            action_hash: binding.action_hash.clone(),
            ledger_execution_id: binding.ledger_execution_id,
            idempotency_key: binding.idempotency_key.clone(),
            operation: request.command.operation,
            resource: request.command.resource.clone(),
            object_ref,
            index_ref,
            quarantine: !findings.is_empty(),
            legal_hold_blocked,
            poisoning_findings: findings,
            receipts,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = canonical_digest(&receipt)?;
        Ok(Some(receipt))
    }

    async fn search(
        &self,
        binding: &RetrievalAuthorizationBinding,
        request: &ContextRetrievalRequest,
        decision: &RetrievalDecision,
    ) -> Result<Vec<VectorSearchHit>, ContextAuthorityError> {
        if decision.authorized_resources.is_empty() {
            return Err(ContextAuthorityError::RequestInvalid);
        }
        let body = VectorSearchRequest {
            schema_version: "agenttrust.authorized-vector-search.v1",
            tenant_id: request.tenant_id,
            retrieval_id: request.retrieval_id,
            authorization_decision_id: decision.decision_id,
            authorization_request_digest: &decision.request_digest,
            policy_decision_id: &binding.policy_decision_id,
            policy_decision_digest: &binding.policy_decision_digest,
            policy_evidence_ref: &binding.policy_evidence_ref,
            policy_evidence_digest: &binding.policy_evidence_digest,
            query: &request.query,
            allowed_resources: &decision.authorized_resources,
            maximum_results: request.maximum_results,
        };
        let response: VectorSearchResponse = self
            .post(
                &self.endpoints.vector_index,
                "v1/vector/search",
                &binding.tenant_id,
                &request.retrieval_id.to_string(),
                &body,
            )
            .await?;
        if response.schema_version != "agenttrust.authorized-vector-search-result.v1"
            || response.retrieval_id != request.retrieval_id
            || response.authorization_decision_id != decision.decision_id
            || response.hits.len() > usize::from(request.maximum_results)
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        Ok(response.hits)
    }

    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<EvidenceDeliveryReceipt, ContextAuthorityError> {
        if !digest(payload_digest) || canonical_digest(payload)? != payload_digest {
            return Err(ContextAuthorityError::RequestInvalid);
        }
        let task_id = evidence_uuid_field(payload, "task_id")?;
        let occurred_at = evidence_time_field(payload, "occurred_at")?;
        let request = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId(task_id.to_string()),
            authority_event_id: event_id.to_string(),
            idempotency_key: IdempotencyKey(idempotency_key.into()),
            source_kind: AuthorityEvidenceSourceKind::GovernedAction,
            control_binding: Some(AuthorityEvidenceControlBinding {
                action_hash: ActionHash(evidence_digest_field(payload, "action_hash")?),
                ledger_execution_id: ExecutionId(
                    evidence_uuid_field(payload, "ledger_execution_id")?.to_string(),
                ),
                ledger_event_id: evidence_uuid_field(payload, "ledger_event_id")?.to_string(),
                ledger_event_digest: evidence_digest_field(payload, "ledger_event_digest")?,
                fence_digest: evidence_digest_field(payload, "fence_digest")?,
                policy_decision_id: evidence_string_field(payload, "policy_decision_id", 256)?
                    .into(),
                policy_decision_digest: evidence_digest_field(
                    payload,
                    "policy_decision_digest",
                )?,
                authorization_evidence_ref: evidence_string_field(
                    payload,
                    "authorization_evidence_ref",
                    2_048,
                )?
                .into(),
                authorization_evidence_digest: evidence_digest_field(
                    payload,
                    "authorization_evidence_digest",
                )?,
            }),
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                task_id: TaskId(task_id.to_string()),
                event_type: EvidenceEventType::StateTransition,
                actor_subject: evidence_string_field(payload, "actor_subject", 512)?.into(),
                source_service: self.evidence_client_identity.clone(),
                trace_id: evidence_string_field(payload, "trace_id", 256)?.into(),
                span_id: event_id.to_string(),
                payload_hash: payload_digest.into(),
                safe_summary: "Context governance mutation persisted".into(),
                artifact_refs: Vec::<ArtifactRef>::new(),
                occurred_at: occurred_at.clone(),
            },
            requested_at: occurred_at,
        };
        let request_digest = request
            .request_digest()
            .map_err(|_| ContextAuthorityError::RequestInvalid)?;
        let response = self
            .client
            .post(
                self.endpoints
                    .evidence
                    .endpoint
                    .join("v1/evidence/authority-events")
                    .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?,
            )
            .bearer_auth(read_token(&self.endpoints.evidence.token_file)?)
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", idempotency_key)
            .header("X-AgentTrust-Authority-Event-Id", event_id.to_string())
            .header("X-AgentTrust-Payload-Digest", payload_digest)
            .json(&request)
            .send()
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(ContextAuthorityError::IdempotencyConflict);
        }
        if !response.status().is_success()
            || response.content_length().is_some_and(|length| length > 65_536)
            || response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|value| {
                value.to_str().ok()
            }) != Some("application/json")
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        let receipt: SignedAuthorityEvidenceReceipt =
            strict_json(&bytes).map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        let key = self
            .evidence_keyring
            .key(&receipt.key_id)
            .ok_or(ContextAuthorityError::DependencyUnavailable)?;
        receipt
            .verify(key, Utc::now())
            .map_err(|_| ContextAuthorityError::DependencyUnavailable)?;
        if receipt.tenant_id != request.tenant_id
            || receipt.task_id != request.task_id
            || receipt.authority_event_id != request.authority_event_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.source_kind != request.source_kind
            || receipt.request_digest != request_digest
            || receipt.payload_digest != payload_digest
            || receipt.event.draft != request.event
        {
            return Err(ContextAuthorityError::DependencyUnavailable);
        }
        Ok(EvidenceDeliveryReceipt {
            schema_version: "agenttrust.context-evidence-delivery-receipt.v1".into(),
            evidence_ref: receipt.evidence_ref,
            evidence_digest: receipt.evidence_digest,
            payload_digest: receipt.payload_digest,
            idempotency_key: receipt.idempotency_key.0,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterRequest<'a> {
    schema_version: &'static str,
    tenant_id: Uuid,
    action_hash: &'a str,
    ledger_execution_id: Uuid,
    ledger_event_id: Uuid,
    ledger_event_digest: &'a str,
    fence_digest: &'a str,
    policy_decision_digest: &'a str,
    authorization_evidence_ref: &'a str,
    authorization_evidence_digest: &'a str,
    idempotency_key: &'a str,
    adapter: &'a str,
    operation: &'a str,
    resource: &'a str,
    payload: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterResponse {
    schema_version: String,
    succeeded: bool,
    receipt: AdapterReceipt,
    object_ref: Option<String>,
    index_ref: Option<String>,
    legal_hold_active: Option<bool>,
    verified: Option<bool>,
    #[serde(default)]
    findings: BTreeSet<String>,
    response_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct VectorSearchRequest<'a> {
    schema_version: &'static str,
    tenant_id: Uuid,
    retrieval_id: Uuid,
    authorization_decision_id: Uuid,
    authorization_request_digest: &'a str,
    policy_decision_id: &'a str,
    policy_decision_digest: &'a str,
    policy_evidence_ref: &'a str,
    policy_evidence_digest: &'a str,
    query: &'a str,
    allowed_resources: &'a BTreeSet<String>,
    maximum_results: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorSearchResponse {
    schema_version: String,
    retrieval_id: Uuid,
    authorization_decision_id: Uuid,
    hits: Vec<VectorSearchHit>,
}

fn evidence_string_field<'a>(
    payload: &'a Value,
    name: &str,
    maximum: usize,
) -> Result<&'a str, ContextAuthorityError> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or(ContextAuthorityError::RequestInvalid)
}

fn evidence_uuid_field(payload: &Value, name: &str) -> Result<Uuid, ContextAuthorityError> {
    let value = evidence_string_field(payload, name, 36)?;
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| !parsed.is_nil() && parsed.to_string() == value)
        .ok_or(ContextAuthorityError::RequestInvalid)
}

fn evidence_digest_field(
    payload: &Value,
    name: &str,
) -> Result<String, ContextAuthorityError> {
    let value = evidence_string_field(payload, name, 64)?;
    if !digest(value) {
        return Err(ContextAuthorityError::RequestInvalid);
    }
    Ok(value.into())
}

fn evidence_time_field(
    payload: &Value,
    name: &str,
) -> Result<DateTime<Utc>, ContextAuthorityError> {
    DateTime::parse_from_rfc3339(evidence_string_field(payload, name, 64)?)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ContextAuthorityError::RequestInvalid)
}

fn validate_adapter_response(
    response: &AdapterResponse,
    adapter: &str,
    operation: &str,
    resource: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<(), ContextAuthorityError> {
    let mut unsigned_response = response.clone();
    unsigned_response.response_digest.clear();
    let mut unsigned_receipt = response.receipt.clone();
    unsigned_receipt.receipt_digest.clear();
    if response.schema_version != "agenttrust.context-adapter-response.v1"
        || !response.succeeded
        || response.receipt.adapter != adapter
        || response.receipt.operation != operation
        || response.receipt.resource != resource
        || response.receipt.idempotency_key != idempotency_key
        || response.receipt.request_digest != request_digest
        || !digest(&response.receipt.receipt_digest)
        || canonical_digest(&unsigned_receipt)? != response.receipt.receipt_digest
        || !adapter_receipt_reference(&response.receipt.reference)
        || canonical_digest(&unsigned_response)? != response.response_digest
        || response
            .findings
            .iter()
            .any(|value| !identifier(value, 128))
    {
        return Err(ContextAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn required_string<'a>(
    value: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, ContextAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ContextAuthorityError::RequestInvalid)
}

fn parse_tenant(value: &TenantId) -> Result<Uuid, ContextAuthorityError> {
    Uuid::parse_str(&value.0)
        .ok()
        .filter(|parsed| parsed.to_string() == value.0)
        .ok_or(ContextAuthorityError::PrincipalDenied)
}

fn adapter_receipt_reference(value: &str) -> bool {
    value.starts_with("adapter-receipt://")
        && value.len() <= 2048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

fn validate_https_root(value: &Url) -> Result<(), ContextAuthorityError> {
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(ContextAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn read_token(path: &Path) -> Result<String, ContextAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 8194
    {
        return Err(ContextAuthorityError::ConfigurationInvalid);
    }
    let value =
        std::fs::read_to_string(path).map_err(|_| ContextAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(ContextAuthorityError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}

fn strict_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_must_be_https_roots() {
        assert!(
            validate_https_root(
                &Url::parse("https://context-object.internal/")
                    .unwrap_or_else(|error| panic!("url: {error}"))
            )
            .is_ok()
        );
        assert!(
            validate_https_root(
                &Url::parse("https://context-object.internal/v1")
                    .unwrap_or_else(|error| panic!("url: {error}"))
            )
            .is_err()
        );
        assert!(
            validate_https_root(
                &Url::parse("http://context-object.internal/")
                    .unwrap_or_else(|error| panic!("url: {error}"))
            )
            .is_err()
        );
    }
}
