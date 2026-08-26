//! Production PostgreSQL authority for audit ingestion, query, retention, Legal Hold, export,
//! deletion proofs, control catalog and evidence graph.

use super::{
    AUDIT_SCHEMA_VERSION, AuditError, AuditExportManifest, AuditExportPackage, AuditRecord,
    AuditRecordDraft, ControlDefinition, DeletionProof, EvidenceEdge, EvidenceNode, LegalHold,
    RetentionPolicy, manifest_hash, validate_draft,
};
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    DataClassification, IdempotencyKey, SchemaVersion, TaskId, TenantId, VerifiedHumanPrincipal,
};
use agent_trust_evidence_evaluator::artifact::{
    ARTIFACT_UPLOAD_SCHEMA_VERSION, ArtifactUploadRequest, WormArtifactPort, WormObjectReceipt,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

pub const AUDIT_APPEND_REQUEST_SCHEMA: &str = "agenttrust.audit-append-request.v1";
pub const AUDIT_APPEND_RESPONSE_SCHEMA: &str = "agenttrust.audit-append-response.v1";
pub const AUDIT_QUERY_REQUEST_SCHEMA: &str = "agenttrust.audit-query-request.v1";
pub const AUDIT_QUERY_RESPONSE_SCHEMA: &str = "agenttrust.audit-query-response.v1";
pub const AUTHORITATIVE_AUDIT_QUERY_REQUEST_SCHEMA: &str =
    "agenttrust.authoritative-audit-query-request.v1";
pub const AUTHORITATIVE_AUDIT_PAGE_SCHEMA: &str = "agenttrust.authoritative-audit-page.v1";
pub const AUDIT_QUERY_PRINCIPAL_EVIDENCE_SCHEMA: &str =
    "agenttrust.audit-query-principal-evidence.v1";
pub const AUDIT_MUTATION_RECEIPT_SCHEMA: &str = "agenttrust.audit-mutation-receipt.v1";
pub const AUDIT_EXPORT_REQUEST_SCHEMA: &str = "agenttrust.audit-export-request.v1";
pub const AUDIT_EXPORT_RESPONSE_SCHEMA: &str = "agenttrust.audit-export-response.v1";
pub const AUDIT_DELETION_REQUEST_SCHEMA: &str = "agenttrust.audit-deletion-request.v1";
pub const AUDIT_DELETION_RESPONSE_SCHEMA: &str = "agenttrust.audit-deletion-response.v1";
pub const RETENTION_DELETION_RECEIPT_SCHEMA: &str = "agenttrust.retention-deletion-receipt.v1";
pub const RETENTION_DELETION_READINESS_SCHEMA: &str = "agenttrust.retention-deletion-readiness.v1";
pub const AUDIT_READINESS_SCHEMA: &str = "agenttrust.audit-retention-readiness.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditAppendRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub records: Vec<AuditRecordDraft>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditMutationReceipt {
    pub schema_version: String,
    pub operation_id: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub request_digest: String,
    pub operation: String,
    pub resource_ref: String,
    pub result_digest: String,
    pub chain_head: String,
    pub issued_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl SignedAuditMutationReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| AuditError::Canonicalization)
    }

    fn sign(&mut self, key: &SigningKey) -> Result<(), AuditError> {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), AuditError> {
        if self.schema_version != AUDIT_MUTATION_RECEIPT_SCHEMA
            || canonical_uuid(&self.operation_id).is_err()
            || canonical_uuid(&self.tenant_id.0).is_err()
            || !valid_idempotency(&self.idempotency_key)
            || !lower_digest(&self.request_digest)
            || self.operation.is_empty()
            || self.operation.len() > 64
            || self.resource_ref.is_empty()
            || self.resource_ref.len() > 2_048
            || !lower_digest(&self.result_digest)
            || !lower_digest(&self.chain_head)
            || self.issuer.is_empty()
            || self.issuer.len() > 256
            || self.key_id.is_empty()
            || self.key_id.len() > 128
            || self.key_usage != "AUDIT_MUTATION_RECEIPT"
        {
            return Err(AuditError::SignatureInvalid);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.signature)
                .map_err(|_| AuditError::SignatureInvalid)?,
        )
        .map_err(|_| AuditError::SignatureInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| AuditError::SignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditAppendResponse {
    pub schema_version: String,
    pub records: Vec<AuditRecord>,
    pub receipt: SignedAuditMutationReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionAuditQuery {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub audit_task_id: TaskId,
    pub actor_subject: String,
    pub resource_prefix: String,
    pub maximum_classification: DataClassification,
    pub occurred_from: DateTime<Utc>,
    pub occurred_until: DateTime<Utc>,
    pub offset: u64,
    pub limit: u16,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionAuditQueryResponse {
    pub schema_version: String,
    pub records: Vec<AuditRecord>,
    pub next_offset: Option<u64>,
    pub receipt: SignedAuditMutationReceipt,
}

/// BFF-facing query contract. `resource` is the logical dashboard view while
/// `resource_prefix` is the independently authorized audit-record filter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeAuditQueryRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub audit_task_id: TaskId,
    pub actor_subject: String,
    pub resource: String,
    pub resource_prefix: String,
    pub maximum_classification: DataClassification,
    pub occurred_from: DateTime<Utc>,
    pub occurred_until: DateTime<Utc>,
    pub offset: u64,
    pub limit: u16,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeAuditPage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: TenantId,
    pub resource: String,
    pub items: Vec<AuditRecord>,
    pub next_offset: Option<u64>,
    pub receipt: SignedAuditMutationReceipt,
    pub data_digest: String,
}

impl AuthoritativeAuditPage {
    fn digest(&self) -> Result<String, AuditError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema_version: &'a str,
            authoritative: bool,
            tenant_id: &'a TenantId,
            resource: &'a str,
            items: &'a [AuditRecord],
            next_offset: Option<u64>,
            receipt: &'a SignedAuditMutationReceipt,
        }
        canonical_digest(&DigestMaterial {
            schema_version: &self.schema_version,
            authoritative: self.authoritative,
            tenant_id: &self.tenant_id,
            resource: &self.resource,
            items: &self.items,
            next_offset: self.next_offset,
            receipt: &self.receipt,
        })
    }

    pub fn verify_data_digest(&self) -> Result<(), AuditError> {
        if self.schema_version != AUTHORITATIVE_AUDIT_PAGE_SCHEMA
            || !self.authoritative
            || self.data_digest != self.digest()?
        {
            return Err(AuditError::IntegrityFailed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryPrincipalEvidence {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub audit_task_id: TaskId,
    pub actor_subject: String,
    pub client_identity: String,
    pub service_subject: String,
    pub scope: String,
    pub assertion_jti: String,
    pub assertion_digest: String,
    pub request_digest: String,
    pub response_digest: String,
    pub receipt_digest: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicyRequest {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub policy: RetentionPolicy,
    pub actor_subject: String,
    pub audit_task_id: TaskId,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldPlaceRequest {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub hold: LegalHold,
    pub audit_task_id: TaskId,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldReleaseRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub hold_id: String,
    pub idempotency_key: IdempotencyKey,
    pub released_by: String,
    pub reason_code: String,
    pub audit_task_id: TaskId,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditExportRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub audit_task_id: TaskId,
    pub actor_subject: String,
    pub maximum_classification: DataClassification,
    pub transformed: bool,
    pub retention_until: DateTime<Utc>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditExportResponse {
    pub schema_version: String,
    pub package: AuditExportPackage,
    pub worm_receipt: WormObjectReceipt,
    pub receipt: SignedAuditMutationReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditDeletionRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub audit_task_id: TaskId,
    pub actor_subject: String,
    pub policy_id: String,
    pub delete_before: DateTime<Utc>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionObjectDeletionReceipt {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub artifact_hash: String,
    pub object_ref: String,
    pub version_id: String,
    pub deletion_marker: String,
    pub deleted_at: DateTime<Utc>,
    pub proof_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditDeletionResponse {
    pub schema_version: String,
    pub proof: DeletionProof,
    pub object_receipts: Vec<RetentionObjectDeletionReceipt>,
    pub receipt: SignedAuditMutationReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlRegistrationRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub idempotency_key: IdempotencyKey,
    pub control: ControlDefinition,
    pub actor_subject: String,
    pub audit_task_id: TaskId,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceNodeRequest {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub node: EvidenceNode,
    pub actor_subject: String,
    pub audit_task_id: TaskId,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEdgeRequest {
    pub schema_version: String,
    pub idempotency_key: IdempotencyKey,
    pub edge: EvidenceEdge,
    pub actor_subject: String,
    pub audit_task_id: TaskId,
    pub requested_at: DateTime<Utc>,
}

#[async_trait]
pub trait RetentionDeletionPort: Send + Sync {
    async fn delete_expired_versions(
        &self,
        request: &AuditDeletionRequest,
        artifact_hashes: &[String],
    ) -> Result<Vec<RetentionObjectDeletionReceipt>, AuditError>;
    async fn ready(&self) -> bool;
}

#[derive(Clone)]
pub struct HttpRetentionDeletionClient {
    client: reqwest::Client,
    endpoint: Url,
    bearer: Arc<str>,
}

impl HttpRetentionDeletionClient {
    pub fn new(
        endpoint: &str,
        bearer: String,
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
    ) -> Result<Self, AuditError> {
        let endpoint = Url::parse(endpoint).map_err(|_| AuditError::ConfigurationInvalid)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || bearer.is_empty()
            || bearer.len() > 8_192
            || bearer.contains(char::is_whitespace)
        {
            return Err(AuditError::ConfigurationInvalid);
        }
        let ca = std::fs::read(ca_file).map_err(|_| AuditError::ConfigurationInvalid)?;
        let mut identity =
            std::fs::read(certificate_file).map_err(|_| AuditError::ConfigurationInvalid)?;
        identity
            .extend(std::fs::read(private_key_file).map_err(|_| AuditError::ConfigurationInvalid)?);
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca)
                    .map_err(|_| AuditError::ConfigurationInvalid)?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|_| AuditError::ConfigurationInvalid)?,
            )
            .build()
            .map_err(|_| AuditError::ConfigurationInvalid)?;
        Ok(Self {
            client,
            endpoint,
            bearer: bearer.into(),
        })
    }
}

#[async_trait]
impl RetentionDeletionPort for HttpRetentionDeletionClient {
    async fn delete_expired_versions(
        &self,
        request: &AuditDeletionRequest,
        artifact_hashes: &[String],
    ) -> Result<Vec<RetentionObjectDeletionReceipt>, AuditError> {
        if artifact_hashes.len() > 10_000
            || artifact_hashes.iter().any(|value| !lower_digest(value))
        {
            return Err(AuditError::DeletionFailed);
        }
        if artifact_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let response = self
            .client
            .post(
                self.endpoint
                    .join("v1/retention-deletions")
                    .map_err(|_| AuditError::ConfigurationInvalid)?,
            )
            .bearer_auth(self.bearer.as_ref())
            .header("x-agenttrust-tenant-id", &request.tenant_id.0)
            .header("idempotency-key", &request.idempotency_key.0)
            .json(&serde_json::json!({
                "schema_version": "agenttrust.retention-deletion-command.v1",
                "tenant_id": request.tenant_id,
                "policy_id": request.policy_id,
                "delete_before": request.delete_before,
                "artifact_hashes": artifact_hashes,
            }))
            .send()
            .await
            .map_err(|_| AuditError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response.content_length().unwrap_or(1_048_577) > 1_048_576
        {
            return Err(AuditError::DeletionFailed);
        }
        let body = read_bounded_body(response, 1_048_576)
            .await
            .map_err(|_| AuditError::DeletionFailed)?;
        let receipts = serde_json::from_slice::<Vec<RetentionObjectDeletionReceipt>>(&body)
            .map_err(|_| AuditError::DeletionFailed)?;
        let expected = artifact_hashes.iter().cloned().collect::<BTreeSet<_>>();
        let actual = receipts
            .iter()
            .map(|receipt| receipt.artifact_hash.clone())
            .collect::<BTreeSet<_>>();
        if receipts.len() != expected.len()
            || actual != expected
            || receipts.iter().any(|receipt| {
                receipt.schema_version != RETENTION_DELETION_RECEIPT_SCHEMA
                    || receipt.tenant_id != request.tenant_id
                    || !receipt.object_ref.starts_with("object-lock://")
                    || receipt.version_id.is_empty()
                    || receipt.deletion_marker.is_empty()
                    || receipt.deleted_at < request.requested_at
                    || receipt.deleted_at > Utc::now()
                    || receipt.proof_digest != deletion_receipt_digest(receipt).unwrap_or_default()
            })
        {
            return Err(AuditError::DeletionFailed);
        }
        Ok(receipts)
    }

    async fn ready(&self) -> bool {
        let url = match self.endpoint.join("ready") {
            Ok(value) => value,
            Err(_) => return false,
        };
        let response = match self
            .client
            .get(url)
            .bearer_auth(self.bearer.as_ref())
            .send()
            .await
        {
            Ok(value)
                if value.status().is_success()
                    && value.content_length().unwrap_or(4_097) <= 4_096 =>
            {
                value
            }
            _ => return false,
        };
        read_bounded_body(response, 4_096)
            .await
            .ok()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .is_some_and(|value| {
                value.get("schema_version").and_then(|value| value.as_str())
                    == Some(RETENTION_DELETION_READINESS_SCHEMA)
                    && value.get("ready").and_then(|value| value.as_bool()) == Some(true)
                    && value
                        .get("versioned_deletion_proof")
                        .and_then(|value| value.as_bool())
                        == Some(true)
            })
    }
}

#[derive(Clone)]
pub struct PostgresAuditAuthority {
    pool: PgPool,
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
    worm: Arc<dyn WormArtifactPort>,
    deletion: Arc<dyn RetentionDeletionPort>,
    maximum_export_bytes: usize,
    verifying_keys: BTreeMap<String, VerifyingKey>,
}

impl PostgresAuditAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
        worm: Arc<dyn WormArtifactPort>,
        deletion: Arc<dyn RetentionDeletionPort>,
        maximum_export_bytes: usize,
        verifying_keys: BTreeMap<String, VerifyingKey>,
    ) -> Result<Self, AuditError> {
        if issuer.is_empty()
            || issuer.len() > 256
            || key_id.is_empty()
            || key_id.len() > 128
            || !(1_048_576..=64 * 1024 * 1024).contains(&maximum_export_bytes)
            || verifying_keys.is_empty()
            || verifying_keys.len() > 1_024
            || verifying_keys
                .iter()
                .any(|(id, _)| id.is_empty() || id.len() > 128)
            || verifying_keys.get(&key_id) != Some(&signing_key.verifying_key())
        {
            return Err(AuditError::ConfigurationInvalid);
        }
        Ok(Self {
            pool,
            issuer,
            key_id,
            signing_key,
            worm,
            deletion,
            maximum_export_bytes,
            verifying_keys,
        })
    }

    pub async fn ready(&self) -> bool {
        let (database, worm, deletion) = self.readiness_components().await;
        database && worm && deletion
    }

    pub async fn readiness_components(&self) -> (bool, bool, bool) {
        let database = tokio::time::timeout(
            Duration::from_millis(750),
            sqlx::query_scalar::<_, bool>(
                "SELECT has_table_privilege(current_user,'audit_records','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_chain_heads','SELECT,INSERT,UPDATE') AND \
                 has_table_privilege(current_user,'audit_operation_replays','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'legal_holds','SELECT,INSERT,UPDATE') AND \
                 has_table_privilege(current_user,'audit_retention_policies','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_export_manifests','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_deletion_proofs','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_retention_outbox','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_human_assertion_uses','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_control_definitions','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_evidence_nodes','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'audit_evidence_edges','SELECT,INSERT')",
            )
            .fetch_one(&self.pool),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
        let (worm, deletion) = tokio::join!(self.worm.ready(), self.deletion.ready());
        (database, worm, deletion)
    }

    pub async fn append(
        &self,
        request: &AuditAppendRequest,
    ) -> Result<AuditAppendResponse, AuditError> {
        validate_append_request(request)?;
        let digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(&mut transaction, &format!("audit:{tenant}:default"))
            .await?;
        if let Some(response) = replay::<AuditAppendResponse>(
            &mut transaction,
            tenant,
            "APPEND",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(response);
        }
        let records = self
            .append_drafts(&mut transaction, tenant, &request.records)
            .await?;
        let chain_head = records
            .last()
            .map(|record| record.record_hash.clone())
            .ok_or(AuditError::RecordInvalid)?;
        let receipt = self.receipt(
            request.tenant_id.clone(),
            request.idempotency_key.clone(),
            digest.clone(),
            "APPEND",
            format!("audit://{}/records", request.tenant_id.0),
            canonical_digest(&records)?,
            chain_head,
        )?;
        let response = AuditAppendResponse {
            schema_version: AUDIT_APPEND_RESPONSE_SCHEMA.into(),
            records,
            receipt,
        };
        persist_replay(
            &mut transaction,
            tenant,
            "APPEND",
            &request.idempotency_key,
            &digest,
            &response,
        )
        .await?;
        self.outbox(
            &mut transaction,
            tenant,
            &request.records[0].task_id,
            "AUDIT_RECORDS_APPENDED",
            &response.receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(response)
    }

    pub async fn query(
        &self,
        request: &ProductionAuditQuery,
    ) -> Result<ProductionAuditQueryResponse, AuditError> {
        validate_query(request)?;
        let digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(&mut transaction, &format!("audit:{tenant}:default"))
            .await?;
        if let Some(response) = replay::<ProductionAuditQueryResponse>(
            &mut transaction,
            tenant,
            "QUERY",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(response);
        }
        let rows = sqlx::query(
            "SELECT record_payload FROM audit_records WHERE tenant_id=$1 AND occurred_at >= $2 \
             AND occurred_at <= $3 AND record_payload #>> '{draft,resource}' LIKE ($4 || '%') \
             AND CASE record_payload #>> '{draft,classification}' \
               WHEN 'PUBLIC' THEN 0 WHEN 'INTERNAL' THEN 1 WHEN 'CONFIDENTIAL' THEN 2 \
               WHEN 'RESTRICTED' THEN 3 WHEN 'REGULATED' THEN 4 ELSE 99 END <= $5 \
             ORDER BY sequence OFFSET $6 LIMIT $7",
        )
        .bind(tenant)
        .bind(request.occurred_from)
        .bind(request.occurred_until)
        .bind(escape_like_prefix(&request.resource_prefix))
        .bind(classification_rank(request.maximum_classification))
        .bind(i64::try_from(request.offset).map_err(|_| AuditError::QueryDenied)?)
        .bind(i64::from(request.limit) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let mut records = rows
            .into_iter()
            .map(|row| {
                serde_json::from_value::<AuditRecord>(
                    row.try_get("record_payload")
                        .map_err(|_| AuditError::PersistenceFailed)?,
                )
                .map_err(|_| AuditError::PersistenceFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = records.len() > usize::from(request.limit);
        records.truncate(usize::from(request.limit));
        let audit_record = self
            .append_drafts(
                &mut transaction,
                tenant,
                &[AuditRecordDraft {
                    schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
                    request_id: format!("authority:query:{}", request.idempotency_key.0),
                    tenant_id: request.tenant_id.clone(),
                    task_id: request.audit_task_id.clone(),
                    event_type: "AUDIT_QUERY".into(),
                    actor_subject: request.actor_subject.clone(),
                    resource: "audit://query".into(),
                    classification: DataClassification::Internal,
                    payload_hash: digest.clone(),
                    safe_summary: format!("audit query returned {} records", records.len()),
                    artifact_hashes: Vec::new(),
                    occurred_at: Utc::now(),
                }],
            )
            .await?
            .pop()
            .ok_or(AuditError::PersistenceFailed)?;
        let receipt = self.receipt(
            request.tenant_id.clone(),
            request.idempotency_key.clone(),
            digest.clone(),
            "QUERY",
            "audit://query".into(),
            canonical_digest(&records)?,
            audit_record.record_hash,
        )?;
        let response = ProductionAuditQueryResponse {
            schema_version: AUDIT_QUERY_RESPONSE_SCHEMA.into(),
            records,
            next_offset: has_more.then(|| request.offset + u64::from(request.limit)),
            receipt,
        };
        persist_replay(
            &mut transaction,
            tenant,
            "QUERY",
            &request.idempotency_key,
            &digest,
            &response,
        )
        .await?;
        self.outbox(
            &mut transaction,
            tenant,
            &request.audit_task_id,
            "AUDIT_QUERY_RECORDED",
            &response.receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(response)
    }

    pub async fn query_authoritative(
        &self,
        request: &AuthoritativeAuditQueryRequest,
        principal: &VerifiedHumanPrincipal,
    ) -> Result<AuthoritativeAuditPage, AuditError> {
        validate_authoritative_query(request, principal)?;
        let request_digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(&mut transaction, &format!("audit:{tenant}:default"))
            .await?;
        if let Some(response) = replay::<AuthoritativeAuditPage>(
            &mut transaction,
            tenant,
            "AUTHORITATIVE_QUERY",
            &request.idempotency_key,
            &request_digest,
        )
        .await?
        {
            response.verify_data_digest()?;
            verify_authoritative_query_use(
                &mut transaction,
                tenant,
                request,
                principal,
                &request_digest,
                &response,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(response);
        }

        let rows = sqlx::query(
            "SELECT record_payload FROM audit_records WHERE tenant_id=$1 AND occurred_at >= $2 \
             AND occurred_at <= $3 AND ($4='*' OR record_payload #>> '{draft,resource}' LIKE ($4 || '%')) \
             AND CASE record_payload #>> '{draft,classification}' \
               WHEN 'PUBLIC' THEN 0 WHEN 'INTERNAL' THEN 1 WHEN 'CONFIDENTIAL' THEN 2 \
               WHEN 'RESTRICTED' THEN 3 WHEN 'REGULATED' THEN 4 ELSE 99 END <= $5 \
             ORDER BY sequence OFFSET $6 LIMIT $7",
        )
        .bind(tenant)
        .bind(request.occurred_from)
        .bind(request.occurred_until)
        .bind(if request.resource_prefix == "*" {
            "*".to_string()
        } else {
            escape_like_prefix(&request.resource_prefix)
        })
        .bind(classification_rank(request.maximum_classification))
        .bind(i64::try_from(request.offset).map_err(|_| AuditError::QueryDenied)?)
        .bind(i64::from(request.limit) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let mut records = rows
            .into_iter()
            .map(|row| {
                serde_json::from_value::<AuditRecord>(
                    row.try_get("record_payload")
                        .map_err(|_| AuditError::PersistenceFailed)?,
                )
                .map_err(|_| AuditError::PersistenceFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = records.len() > usize::from(request.limit);
        records.truncate(usize::from(request.limit));
        let principal_binding_digest = canonical_digest(&serde_json::json!({
            "schema_version": AUDIT_QUERY_PRINCIPAL_EVIDENCE_SCHEMA,
            "tenant_id": request.tenant_id.clone(),
            "actor_subject": principal.subject.clone(),
            "client_identity": principal.client_identity.clone(),
            "service_subject": principal.service_subject.clone(),
            "scope": principal.scope.clone(),
            "assertion_jti": principal.jti.clone(),
            "assertion_digest": principal.assertion_digest.clone(),
            "request_digest": request_digest.clone(),
        }))?;
        let audit_record = self
            .append_drafts(
                &mut transaction,
                tenant,
                &[AuditRecordDraft {
                    schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
                    request_id: format!(
                        "authority:authoritative-query:{}",
                        request.idempotency_key.0
                    ),
                    tenant_id: request.tenant_id.clone(),
                    task_id: request.audit_task_id.clone(),
                    event_type: "AUTHORITATIVE_AUDIT_QUERY".into(),
                    actor_subject: principal.subject.clone(),
                    resource: format!("audit://authoritative-query/{}", request.resource),
                    classification: DataClassification::Internal,
                    payload_hash: principal_binding_digest,
                    safe_summary: format!(
                        "authoritative audit query returned {} records",
                        records.len()
                    ),
                    artifact_hashes: Vec::new(),
                    occurred_at: Utc::now(),
                }],
            )
            .await?
            .pop()
            .ok_or(AuditError::PersistenceFailed)?;
        let receipt = self.receipt(
            request.tenant_id.clone(),
            request.idempotency_key.clone(),
            request_digest.clone(),
            "AUTHORITATIVE_QUERY",
            "audit://authoritative-query".into(),
            canonical_digest(&records)?,
            audit_record.record_hash,
        )?;
        let mut response = AuthoritativeAuditPage {
            schema_version: AUTHORITATIVE_AUDIT_PAGE_SCHEMA.into(),
            authoritative: true,
            tenant_id: request.tenant_id.clone(),
            resource: request.resource.clone(),
            items: records,
            next_offset: has_more.then(|| request.offset + u64::from(request.limit)),
            receipt,
            data_digest: String::new(),
        };
        response.data_digest = response.digest()?;
        let receipt_digest = canonical_digest(&response.receipt)?;
        let evidence = AuditQueryPrincipalEvidence {
            schema_version: AUDIT_QUERY_PRINCIPAL_EVIDENCE_SCHEMA.into(),
            tenant_id: request.tenant_id.clone(),
            audit_task_id: request.audit_task_id.clone(),
            actor_subject: principal.subject.clone(),
            client_identity: principal.client_identity.clone(),
            service_subject: principal.service_subject.clone(),
            scope: principal.scope.clone(),
            assertion_jti: principal.jti.clone(),
            assertion_digest: principal.assertion_digest.clone(),
            request_digest: request_digest.clone(),
            response_digest: response.data_digest.clone(),
            receipt_digest: receipt_digest.clone(),
            recorded_at: Utc::now(),
        };
        sqlx::query(
            "INSERT INTO audit_human_assertion_uses \
             (tenant_id,assertion_jti,assertion_digest,request_digest,idempotency_key,operation,\
              actor_subject,client_identity,service_subject,scope,receipt_digest,expires_at,used_at) \
             VALUES($1,$2,$3,$4,$5,'AUTHORITATIVE_QUERY',$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(tenant)
        .bind(canonical_uuid(&principal.jti)?)
        .bind(&principal.assertion_digest)
        .bind(&request_digest)
        .bind(&request.idempotency_key.0)
        .bind(&principal.subject)
        .bind(&principal.client_identity)
        .bind(&principal.service_subject)
        .bind(&principal.scope)
        .bind(&receipt_digest)
        .bind(principal.expires_at)
        .bind(evidence.recorded_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::IdempotencyConflict)?;
        persist_replay(
            &mut transaction,
            tenant,
            "AUTHORITATIVE_QUERY",
            &request.idempotency_key,
            &request_digest,
            &response,
        )
        .await?;
        self.query_outbox(&mut transaction, tenant, &evidence)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(response)
    }

    pub async fn export(
        &self,
        request: &AuditExportRequest,
    ) -> Result<AuditExportResponse, AuditError> {
        validate_export_request(request)?;
        let request_digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(&mut transaction, &format!("audit:{tenant}:default"))
            .await?;
        if let Some(response) = replay::<AuditExportResponse>(
            &mut transaction,
            tenant,
            "EXPORT",
            &request.idempotency_key,
            &request_digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(response);
        }

        let export_id = Uuid::new_v4();
        self.append_drafts(
            &mut transaction,
            tenant,
            &[AuditRecordDraft {
                schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
                request_id: format!("authority:export:{}", request.idempotency_key.0),
                tenant_id: request.tenant_id.clone(),
                task_id: request.audit_task_id.clone(),
                event_type: "AUDIT_EXPORT".into(),
                actor_subject: request.actor_subject.clone(),
                resource: format!("audit-export://{}/{export_id}", request.tenant_id.0),
                classification: DataClassification::Internal,
                payload_hash: request_digest.clone(),
                safe_summary: "immutable audit export requested".into(),
                artifact_hashes: Vec::new(),
                occurred_at: Utc::now(),
            }],
        )
        .await?;
        let rows = sqlx::query(
            "SELECT record_payload FROM audit_records WHERE tenant_id=$1 ORDER BY sequence LIMIT 100001",
        )
        .bind(tenant)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        if rows.is_empty() || rows.len() > 100_000 {
            return Err(AuditError::CapacityExceeded);
        }
        let records = rows
            .into_iter()
            .map(|row| {
                serde_json::from_value::<AuditRecord>(
                    row.try_get("record_payload")
                        .map_err(|_| AuditError::PersistenceFailed)?,
                )
                .map_err(|_| AuditError::PersistenceFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_record_chain(&records, &request.tenant_id, &self.verifying_keys)?;
        if records
            .iter()
            .any(|record| record.draft.classification > request.maximum_classification)
        {
            return Err(AuditError::QueryDenied);
        }
        let record_hashes = records
            .iter()
            .map(|record| record.record_hash.clone())
            .collect::<Vec<_>>();
        let chain_head = record_hashes
            .last()
            .cloned()
            .ok_or(AuditError::IntegrityFailed)?;
        let mut manifest = AuditExportManifest {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            export_id: export_id.to_string(),
            tenant_id: request.tenant_id.clone(),
            record_hashes,
            chain_head: chain_head.clone(),
            transformed: false,
            transformation_hash: None,
            key_id: self.key_id.clone(),
            manifest_hash: String::new(),
            signature: String::new(),
            exported_at: Utc::now(),
        };
        manifest.manifest_hash = manifest_hash(&manifest)?;
        manifest.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(manifest.manifest_hash.as_bytes())
                .to_bytes(),
        );
        let package = AuditExportPackage { manifest, records };
        let package_bytes =
            serde_jcs::to_vec(&package).map_err(|_| AuditError::Canonicalization)?;
        if package_bytes.len() > self.maximum_export_bytes {
            return Err(AuditError::CapacityExceeded);
        }
        let artifact_request = ArtifactUploadRequest {
            schema_version: ARTIFACT_UPLOAD_SCHEMA_VERSION.into(),
            tenant_id: request.tenant_id.clone(),
            task_id: request.audit_task_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            media_type: "application/vnd.agenttrust.audit-export+json".into(),
            classification: enum_name(&request.maximum_classification)?,
            retention_until: request.retention_until,
            access_policy: "audit-retention-authority-only".into(),
            content_base64url: URL_SAFE_NO_PAD.encode(&package_bytes),
            requested_at: request.requested_at,
        };
        let decoded = artifact_request
            .validate_and_decode(self.maximum_export_bytes)
            .map_err(|_| AuditError::RequestInvalid)?;
        if decoded != package_bytes {
            return Err(AuditError::IntegrityFailed);
        }
        let package_digest = hex(Sha256::digest(&package_bytes));
        let worm_receipt = self
            .worm
            .put_immutable(&artifact_request, package_bytes)
            .await
            .map_err(|_| AuditError::DependencyUnavailable)?;
        worm_receipt
            .verify(&request.tenant_id, &package_digest, request.retention_until)
            .map_err(|_| AuditError::IntegrityFailed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&package.manifest.signature)
            .map_err(|_| AuditError::SignatureInvalid)?;
        sqlx::query(
            "INSERT INTO audit_export_manifests(tenant_id,export_id,manifest_digest,chain_head,object_ref,key_id,signature,created_at,request_digest,idempotency_key,package_payload,worm_receipt) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(tenant)
        .bind(export_id)
        .bind(&package.manifest.manifest_hash)
        .bind(&package.manifest.chain_head)
        .bind(&worm_receipt.object_ref)
        .bind(&package.manifest.key_id)
        .bind(signature)
        .bind(package.manifest.exported_at)
        .bind(&request_digest)
        .bind(&request.idempotency_key.0)
        .bind(serde_json::to_value(&package).map_err(|_| AuditError::Canonicalization)?)
        .bind(serde_json::to_value(&worm_receipt).map_err(|_| AuditError::Canonicalization)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let receipt = self.receipt(
            request.tenant_id.clone(),
            request.idempotency_key.clone(),
            request_digest.clone(),
            "EXPORT",
            worm_receipt.object_ref.clone(),
            package.manifest.manifest_hash.clone(),
            chain_head,
        )?;
        let response = AuditExportResponse {
            schema_version: AUDIT_EXPORT_RESPONSE_SCHEMA.into(),
            package,
            worm_receipt,
            receipt,
        };
        persist_replay(
            &mut transaction,
            tenant,
            "EXPORT",
            &request.idempotency_key,
            &request_digest,
            &response,
        )
        .await?;
        self.outbox(
            &mut transaction,
            tenant,
            &request.audit_task_id,
            "AUDIT_EXPORT_STORED",
            &response.receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(response)
    }

    pub async fn delete_with_proof(
        &self,
        request: &AuditDeletionRequest,
    ) -> Result<AuditDeletionResponse, AuditError> {
        validate_deletion_request(request)?;
        let request_digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(&mut transaction, &format!("audit:{tenant}:default"))
            .await?;
        if let Some(response) = replay::<AuditDeletionResponse>(
            &mut transaction,
            tenant,
            "DELETE",
            &request.idempotency_key,
            &request_digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(response);
        }

        let policy = sqlx::query(
            "SELECT retention_seconds,event_type,classification FROM audit_retention_policies \
             WHERE tenant_id=$1 AND policy_id=$2 AND effective_at <= $3 \
             ORDER BY effective_at DESC,policy_version DESC LIMIT 1 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.policy_id)
        .bind(request.requested_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?
        .ok_or(AuditError::RetentionPolicyMissing)?;
        let retention_seconds = policy
            .try_get::<i64, _>("retention_seconds")
            .map_err(|_| AuditError::PersistenceFailed)?;
        let eligible_before = request
            .requested_at
            .checked_sub_signed(chrono::Duration::seconds(retention_seconds))
            .ok_or(AuditError::RetentionPolicyInvalid)?;
        if request.delete_before > eligible_before {
            return Err(AuditError::RetentionPolicyInvalid);
        }
        let event_type = policy
            .try_get::<String, _>("event_type")
            .map_err(|_| AuditError::PersistenceFailed)?;
        let classification = policy
            .try_get::<String, _>("classification")
            .map_err(|_| AuditError::PersistenceFailed)?;
        let rows = sqlx::query(
            "SELECT record_payload FROM audit_records WHERE tenant_id=$1 ORDER BY sequence LIMIT 100001",
        )
        .bind(tenant)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        if rows.len() > 100_000 {
            return Err(AuditError::CapacityExceeded);
        }
        let records = rows
            .into_iter()
            .map(|row| {
                serde_json::from_value::<AuditRecord>(
                    row.try_get("record_payload")
                        .map_err(|_| AuditError::PersistenceFailed)?,
                )
                .map_err(|_| AuditError::PersistenceFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !records.is_empty() {
            validate_record_chain(&records, &request.tenant_id, &self.verifying_keys)?;
        }
        let hold_rows = sqlx::query(
            "SELECT hold_payload FROM legal_holds WHERE tenant_id=$1 AND released_at IS NULL \
             LIMIT 10001",
        )
        .bind(tenant)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        if hold_rows.len() > 10_000 {
            return Err(AuditError::CapacityExceeded);
        }
        let holds = hold_rows
            .into_iter()
            .map(|row| {
                serde_json::from_value::<LegalHold>(
                    row.try_get("hold_payload")
                        .map_err(|_| AuditError::PersistenceFailed)?,
                )
                .map_err(|_| AuditError::PersistenceFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let candidate_indexes = records
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.draft.occurred_at < request.delete_before
                    && record.draft.event_type == event_type
                    && enum_name(&record.draft.classification).ok().as_deref()
                        == Some(classification.as_str())
            })
            .map(|(index, _)| index)
            .collect::<BTreeSet<_>>();
        let held_indexes = candidate_indexes
            .iter()
            .copied()
            .filter(|index| {
                holds
                    .iter()
                    .any(|hold| hold_protects(hold, &records[*index]))
            })
            .collect::<BTreeSet<_>>();
        let candidate_hashes = candidate_indexes
            .difference(&held_indexes)
            .flat_map(|index| records[*index].draft.artifact_hashes.iter().cloned())
            .collect::<BTreeSet<_>>();
        let blocking_hashes = records
            .iter()
            .enumerate()
            .filter(|(index, _)| !candidate_indexes.contains(index) || held_indexes.contains(index))
            .flat_map(|(_, record)| record.draft.artifact_hashes.iter().cloned())
            .collect::<BTreeSet<_>>();
        let artifact_hashes = candidate_hashes
            .difference(&blocking_hashes)
            .cloned()
            .collect::<Vec<_>>();
        let mut protected_record_ids = held_indexes
            .iter()
            .map(|index| records[*index].record_id.clone())
            .collect::<BTreeSet<_>>();
        for index in candidate_indexes.difference(&held_indexes) {
            if records[*index]
                .draft
                .artifact_hashes
                .iter()
                .any(|hash| blocking_hashes.contains(hash))
            {
                protected_record_ids.insert(records[*index].record_id.clone());
            }
        }
        let object_receipts = self
            .deletion
            .delete_expired_versions(request, &artifact_hashes)
            .await?;
        let proof = DeletionProof {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            deletion_id: Uuid::new_v4().to_string(),
            tenant_id: request.tenant_id.clone(),
            policy_id: request.policy_id.clone(),
            deleted_payload_hashes: artifact_hashes,
            protected_record_ids: protected_record_ids.into_iter().collect(),
            executed_at: Utc::now(),
        };
        let proof_digest = canonical_digest(&proof)?;
        let mutation_record = self
            .append_drafts(
                &mut transaction,
                tenant,
                &[AuditRecordDraft {
                    schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
                    request_id: format!("authority:delete:{}", request.idempotency_key.0),
                    tenant_id: request.tenant_id.clone(),
                    task_id: request.audit_task_id.clone(),
                    event_type: "RETENTION_DELETION".into(),
                    actor_subject: request.actor_subject.clone(),
                    resource: format!(
                        "retention-deletion://{}/{}",
                        request.tenant_id.0, proof.deletion_id
                    ),
                    classification: DataClassification::Internal,
                    payload_hash: proof_digest.clone(),
                    safe_summary: format!(
                        "retention deletion produced {} object proofs and protected {} records",
                        object_receipts.len(),
                        proof.protected_record_ids.len()
                    ),
                    artifact_hashes: Vec::new(),
                    occurred_at: proof.executed_at,
                }],
            )
            .await?
            .pop()
            .ok_or(AuditError::PersistenceFailed)?;
        let deletion_id = canonical_uuid(&proof.deletion_id)?;
        sqlx::query(
            "INSERT INTO audit_deletion_proofs(tenant_id,deletion_id,policy_id,proof_payload,proof_digest,executed_at,request_digest,idempotency_key,object_receipts) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(tenant)
        .bind(deletion_id)
        .bind(&proof.policy_id)
        .bind(serde_json::to_value(&proof).map_err(|_| AuditError::Canonicalization)?)
        .bind(&proof_digest)
        .bind(proof.executed_at)
        .bind(&request_digest)
        .bind(&request.idempotency_key.0)
        .bind(serde_json::to_value(&object_receipts).map_err(|_| AuditError::Canonicalization)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let receipt = self.receipt(
            request.tenant_id.clone(),
            request.idempotency_key.clone(),
            request_digest.clone(),
            "DELETE",
            format!(
                "retention-deletion://{}/{}",
                request.tenant_id.0, proof.deletion_id
            ),
            proof_digest,
            mutation_record.record_hash,
        )?;
        let response = AuditDeletionResponse {
            schema_version: AUDIT_DELETION_RESPONSE_SCHEMA.into(),
            proof,
            object_receipts,
            receipt,
        };
        persist_replay(
            &mut transaction,
            tenant,
            "DELETE",
            &request.idempotency_key,
            &request_digest,
            &response,
        )
        .await?;
        self.outbox(
            &mut transaction,
            tenant,
            &request.audit_task_id,
            "RETENTION_DELETION_PROVED",
            &response.receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(response)
    }

    pub async fn register_retention_policy(
        &self,
        request: &RetentionPolicyRequest,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        validate_retention_request(request)?;
        let tenant_id = request.policy.tenant_id.clone();
        let digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&tenant_id.0)?;
        let mut transaction = self.begin(&tenant_id).await?;
        self.lock(
            &mut transaction,
            &format!("audit-retention:{tenant}:{}", request.policy.policy_id),
        )
        .await?;
        if let Some(receipt) = replay::<SignedAuditMutationReceipt>(
            &mut transaction,
            tenant,
            "RETENTION_POLICY",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(receipt);
        }
        let classification = enum_name(&request.policy.classification)?;
        sqlx::query(
            "INSERT INTO audit_retention_policies(tenant_id,policy_id,policy_version,retention_seconds,policy_digest,effective_at,event_type,classification,compliance_profile,anonymize_after_seconds) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(tenant)
        .bind(&request.policy.policy_id)
        .bind(&request.policy.policy_digest)
        .bind(i64::try_from(request.policy.retain_seconds).map_err(|_| AuditError::RetentionPolicyInvalid)?)
        .bind(&request.policy.policy_digest)
        .bind(request.requested_at)
        .bind(&request.policy.event_type)
        .bind(classification)
        .bind(&request.policy.compliance_profile)
        .bind(request.policy.anonymize_after_seconds.map(i64::try_from).transpose().map_err(|_| AuditError::RetentionPolicyInvalid)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let receipt = self
            .finish_mutation(
                &mut transaction,
                tenant,
                &tenant_id,
                &request.idempotency_key,
                &digest,
                "RETENTION_POLICY",
                format!(
                    "audit-retention://{}/{}",
                    tenant_id.0, request.policy.policy_id
                ),
                request.policy.policy_digest.clone(),
                &request.audit_task_id,
                &request.actor_subject,
                "RETENTION_POLICY_REGISTERED",
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(receipt)
    }

    pub async fn place_hold(
        &self,
        request: &LegalHoldPlaceRequest,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        validate_hold_request(request)?;
        let digest = canonical_digest(request)?;
        let tenant_id = request.hold.tenant_id.clone();
        let tenant = canonical_uuid(&tenant_id.0)?;
        let hold_id = canonical_uuid(&request.hold.hold_id)?;
        let mut transaction = self.begin(&tenant_id).await?;
        self.lock(&mut transaction, &format!("audit-hold:{tenant}:{hold_id}"))
            .await?;
        if let Some(receipt) = replay::<SignedAuditMutationReceipt>(
            &mut transaction,
            tenant,
            "LEGAL_HOLD_PLACE",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(receipt);
        }
        sqlx::query(
            "INSERT INTO legal_holds(tenant_id,hold_id,object_ref,reason,placed_by,placed_at,released_by,released_at,task_id,actor_subject,resource_prefix,starts_at,ends_at,hold_payload) \
             VALUES($1,$2,$3,$4,$5,$6,NULL,NULL,$7,$8,$9,$10,$11,$12)",
        )
        .bind(tenant)
        .bind(hold_id)
        .bind(hold_object_ref(&request.hold)?)
        .bind(&request.hold.reason_code)
        .bind(&request.hold.placed_by)
        .bind(request.requested_at)
        .bind(request.hold.task_id.as_ref().map(|value| canonical_uuid(&value.0)).transpose()?)
        .bind(&request.hold.actor_subject)
        .bind(&request.hold.resource_prefix)
        .bind(request.hold.starts_at)
        .bind(request.hold.ends_at)
        .bind(serde_json::to_value(&request.hold).map_err(|_| AuditError::Canonicalization)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::LegalHoldConflict)?;
        let receipt = self
            .finish_mutation(
                &mut transaction,
                tenant,
                &tenant_id,
                &request.idempotency_key,
                &digest,
                "LEGAL_HOLD_PLACE",
                format!("legal-hold://{}/{}", tenant_id.0, request.hold.hold_id),
                digest.clone(),
                &request.audit_task_id,
                &request.hold.placed_by,
                "LEGAL_HOLD_PLACED",
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(receipt)
    }

    pub async fn release_hold(
        &self,
        request: &LegalHoldReleaseRequest,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        validate_release(request)?;
        let digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let hold_id = canonical_uuid(&request.hold_id)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(&mut transaction, &format!("audit-hold:{tenant}:{hold_id}"))
            .await?;
        if let Some(receipt) = replay::<SignedAuditMutationReceipt>(
            &mut transaction,
            tenant,
            "LEGAL_HOLD_RELEASE",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(receipt);
        }
        let placed_by = sqlx::query_scalar::<_, String>(
            "SELECT placed_by FROM legal_holds WHERE tenant_id=$1 AND hold_id=$2 AND released_at IS NULL FOR UPDATE",
        )
        .bind(tenant)
        .bind(hold_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?
        .ok_or(AuditError::NotFound)?;
        if placed_by == request.released_by {
            return Err(AuditError::LegalHoldReleaseDenied);
        }
        let changed = sqlx::query(
            "UPDATE legal_holds SET released_by=$3,released_at=$4,release_reason=$5 \
             WHERE tenant_id=$1 AND hold_id=$2 AND released_at IS NULL",
        )
        .bind(tenant)
        .bind(hold_id)
        .bind(&request.released_by)
        .bind(request.requested_at)
        .bind(&request.reason_code)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?
        .rows_affected();
        if changed != 1 {
            return Err(AuditError::LegalHoldReleaseDenied);
        }
        let receipt = self
            .finish_mutation(
                &mut transaction,
                tenant,
                &request.tenant_id,
                &request.idempotency_key,
                &digest,
                "LEGAL_HOLD_RELEASE",
                format!("legal-hold://{}/{}", request.tenant_id.0, request.hold_id),
                digest.clone(),
                &request.audit_task_id,
                &request.released_by,
                "LEGAL_HOLD_RELEASED",
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(receipt)
    }

    pub async fn register_control(
        &self,
        request: &ControlRegistrationRequest,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        validate_control_request(request)?;
        let digest = canonical_digest(request)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self.begin(&request.tenant_id).await?;
        self.lock(
            &mut transaction,
            &format!("audit-control:{tenant}:{}", request.control.control_id),
        )
        .await?;
        if let Some(receipt) = replay::<SignedAuditMutationReceipt>(
            &mut transaction,
            tenant,
            "CONTROL_REGISTER",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(receipt);
        }
        sqlx::query(
            "INSERT INTO audit_control_definitions(tenant_id,control_id,control_digest,definition,created_at) VALUES($1,$2,$3,$4,$5)",
        )
        .bind(tenant)
        .bind(&request.control.control_id)
        .bind(&digest)
        .bind(serde_json::to_value(&request.control).map_err(|_| AuditError::Canonicalization)?)
        .bind(request.requested_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::ControlInvalid)?;
        let receipt = self
            .finish_mutation(
                &mut transaction,
                tenant,
                &request.tenant_id,
                &request.idempotency_key,
                &digest,
                "CONTROL_REGISTER",
                format!(
                    "control://{}/{}",
                    request.tenant_id.0, request.control.control_id
                ),
                digest.clone(),
                &request.audit_task_id,
                &request.actor_subject,
                "CONTROL_REGISTERED",
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(receipt)
    }

    pub async fn add_evidence_node(
        &self,
        request: &EvidenceNodeRequest,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        validate_node_request(request)?;
        let digest = canonical_digest(request)?;
        let tenant_id = request.node.tenant_id.clone();
        let tenant = canonical_uuid(&tenant_id.0)?;
        let mut transaction = self.begin(&tenant_id).await?;
        self.lock(
            &mut transaction,
            &format!("audit-node:{tenant}:{}", request.node.node_id),
        )
        .await?;
        if let Some(receipt) = replay::<SignedAuditMutationReceipt>(
            &mut transaction,
            tenant,
            "EVIDENCE_NODE",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(receipt);
        }
        sqlx::query(
            "INSERT INTO audit_evidence_nodes(tenant_id,node_id,node_type,node_digest,classification,node_payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant)
        .bind(&request.node.node_id)
        .bind(&request.node.node_type)
        .bind(&request.node.digest)
        .bind(enum_name(&request.node.classification)?)
        .bind(serde_json::to_value(&request.node).map_err(|_| AuditError::Canonicalization)?)
        .bind(request.requested_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::GraphInvalid)?;
        let receipt = self
            .finish_mutation(
                &mut transaction,
                tenant,
                &tenant_id,
                &request.idempotency_key,
                &digest,
                "EVIDENCE_NODE",
                format!("evidence-node://{}/{}", tenant_id.0, request.node.node_id),
                request.node.digest.clone(),
                &request.audit_task_id,
                &request.actor_subject,
                "EVIDENCE_NODE_ADDED",
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(receipt)
    }

    pub async fn add_evidence_edge(
        &self,
        request: &EvidenceEdgeRequest,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        validate_edge_request(request)?;
        let digest = canonical_digest(request)?;
        let tenant_id = request.edge.tenant_id.clone();
        let tenant = canonical_uuid(&tenant_id.0)?;
        let mut transaction = self.begin(&tenant_id).await?;
        self.lock(
            &mut transaction,
            &format!(
                "audit-edge:{tenant}:{}:{}:{}",
                request.edge.from_node, request.edge.relation, request.edge.to_node
            ),
        )
        .await?;
        if let Some(receipt) = replay::<SignedAuditMutationReceipt>(
            &mut transaction,
            tenant,
            "EVIDENCE_EDGE",
            &request.idempotency_key,
            &digest,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| AuditError::PersistenceFailed)?;
            return Ok(receipt);
        }
        let node_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_evidence_nodes WHERE tenant_id=$1 AND node_id = ANY($2)",
        )
        .bind(tenant)
        .bind(vec![
            request.edge.from_node.clone(),
            request.edge.to_node.clone(),
        ])
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let expected_nodes = if request.edge.from_node == request.edge.to_node {
            1
        } else {
            2
        };
        if node_count != expected_nodes {
            return Err(AuditError::GraphInvalid);
        }
        sqlx::query(
            "INSERT INTO audit_evidence_edges(tenant_id,from_node,relation,to_node,edge_digest,edge_payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant)
        .bind(&request.edge.from_node)
        .bind(&request.edge.relation)
        .bind(&request.edge.to_node)
        .bind(&digest)
        .bind(serde_json::to_value(&request.edge).map_err(|_| AuditError::Canonicalization)?)
        .bind(request.requested_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::GraphInvalid)?;
        let receipt = self
            .finish_mutation(
                &mut transaction,
                tenant,
                &tenant_id,
                &request.idempotency_key,
                &digest,
                "EVIDENCE_EDGE",
                format!(
                    "evidence-edge://{}/{}/{}/{}",
                    tenant_id.0,
                    request.edge.from_node,
                    request.edge.relation,
                    request.edge.to_node
                ),
                digest.clone(),
                &request.audit_task_id,
                &request.actor_subject,
                "EVIDENCE_EDGE_ADDED",
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(receipt)
    }

    async fn begin(&self, tenant: &TenantId) -> Result<Transaction<'_, Postgres>, AuditError> {
        canonical_uuid(&tenant.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(transaction)
    }

    async fn lock(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key: &str,
    ) -> Result<(), AuditError> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(key)
            .execute(&mut **transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(())
    }

    async fn append_drafts(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        drafts: &[AuditRecordDraft],
    ) -> Result<Vec<AuditRecord>, AuditError> {
        if drafts.is_empty() || drafts.len() > 1_000 {
            return Err(AuditError::CapacityExceeded);
        }
        for draft in drafts {
            validate_draft(draft)?;
            if draft.tenant_id.0 != tenant.to_string() {
                return Err(AuditError::TenantDenied);
            }
        }
        let mut request_ids = BTreeSet::new();
        if drafts
            .iter()
            .any(|draft| !request_ids.insert(draft.request_id.clone()))
        {
            return Err(AuditError::IdempotencyConflict);
        }
        let head = sqlx::query(
            "SELECT last_sequence,chain_hash FROM audit_chain_heads WHERE tenant_id=$1 AND stream_id='default' FOR UPDATE",
        )
        .bind(tenant)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let (mut sequence, mut previous) = match head {
            Some(row) => (
                u64::try_from(
                    row.try_get::<i64, _>("last_sequence")
                        .map_err(|_| AuditError::PersistenceFailed)?,
                )
                .map_err(|_| AuditError::IntegrityFailed)?
                    + 1,
                row.try_get("chain_hash")
                    .map_err(|_| AuditError::PersistenceFailed)?,
            ),
            None => (1, "0".repeat(64)),
        };
        let mut records = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let mut record = AuditRecord {
                schema_version: AUDIT_SCHEMA_VERSION.into(),
                record_id: Uuid::new_v4().to_string(),
                sequence,
                previous_hash: previous,
                record_hash: String::new(),
                key_id: self.key_id.clone(),
                signature: String::new(),
                draft: draft.clone(),
            };
            record.record_hash = hex(Sha256::digest(record.unsigned_bytes()?));
            record.signature = URL_SAFE_NO_PAD.encode(
                self.signing_key
                    .sign(record.record_hash.as_bytes())
                    .to_bytes(),
            );
            let record_id = canonical_uuid(&record.record_id)?;
            sqlx::query(
                "INSERT INTO audit_records(tenant_id,record_id,sequence,previous_hash,record_hash,key_id,signature,record_payload,occurred_at,request_id,request_digest) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(tenant)
            .bind(record_id)
            .bind(i64::try_from(sequence).map_err(|_| AuditError::CapacityExceeded)?)
            .bind(&record.previous_hash)
            .bind(&record.record_hash)
            .bind(&record.key_id)
            .bind(&record.signature)
            .bind(serde_json::to_value(&record).map_err(|_| AuditError::Canonicalization)?)
            .bind(record.draft.occurred_at)
            .bind(&record.draft.request_id)
            .bind(canonical_digest(&record.draft)?)
            .execute(&mut **transaction)
            .await
            .map_err(|_| AuditError::IdempotencyConflict)?;
            previous = record.record_hash.clone();
            sequence = sequence.saturating_add(1);
            records.push(record);
        }
        sqlx::query(
            "INSERT INTO audit_chain_heads(tenant_id,stream_id,last_sequence,chain_hash,key_id,updated_at) \
             VALUES($1,'default',$2,$3,$4,$5) ON CONFLICT(tenant_id,stream_id) DO UPDATE SET \
             last_sequence=EXCLUDED.last_sequence,chain_hash=EXCLUDED.chain_hash,key_id=EXCLUDED.key_id,updated_at=EXCLUDED.updated_at",
        )
        .bind(tenant)
        .bind(i64::try_from(sequence - 1).map_err(|_| AuditError::CapacityExceeded)?)
        .bind(&previous)
        .bind(&self.key_id)
        .bind(Utc::now())
        .execute(&mut **transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(records)
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt(
        &self,
        tenant_id: TenantId,
        idempotency_key: IdempotencyKey,
        request_digest: String,
        operation: &str,
        resource_ref: String,
        result_digest: String,
        chain_head: String,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        let mut receipt = SignedAuditMutationReceipt {
            schema_version: AUDIT_MUTATION_RECEIPT_SCHEMA.into(),
            operation_id: Uuid::new_v4().to_string(),
            tenant_id,
            idempotency_key,
            request_digest,
            operation: operation.into(),
            resource_ref,
            result_digest,
            chain_head,
            issued_at: Utc::now(),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            key_usage: "AUDIT_MUTATION_RECEIPT".into(),
            signature: String::new(),
        };
        receipt.sign(&self.signing_key)?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_mutation(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        tenant_id: &TenantId,
        idempotency_key: &IdempotencyKey,
        request_digest: &str,
        operation: &str,
        resource_ref: String,
        result_digest: String,
        audit_task_id: &TaskId,
        actor_subject: &str,
        event_type: &str,
    ) -> Result<SignedAuditMutationReceipt, AuditError> {
        let record = self
            .append_drafts(
                transaction,
                tenant,
                &[AuditRecordDraft {
                    schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
                    request_id: format!(
                        "authority:{}:{}",
                        operation.to_ascii_lowercase(),
                        idempotency_key.0
                    ),
                    tenant_id: tenant_id.clone(),
                    task_id: audit_task_id.clone(),
                    event_type: event_type.into(),
                    actor_subject: actor_subject.into(),
                    resource: resource_ref.clone(),
                    classification: DataClassification::Internal,
                    payload_hash: result_digest.clone(),
                    safe_summary: format!("{operation} recorded"),
                    artifact_hashes: Vec::new(),
                    occurred_at: Utc::now(),
                }],
            )
            .await?
            .pop()
            .ok_or(AuditError::PersistenceFailed)?;
        let receipt = self.receipt(
            tenant_id.clone(),
            idempotency_key.clone(),
            request_digest.into(),
            operation,
            resource_ref,
            result_digest,
            record.record_hash,
        )?;
        persist_replay(
            transaction,
            tenant,
            operation,
            idempotency_key,
            request_digest,
            &receipt,
        )
        .await?;
        self.outbox(transaction, tenant, audit_task_id, event_type, &receipt)
            .await?;
        Ok(receipt)
    }

    async fn outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        task: &TaskId,
        event_type: &str,
        receipt: &SignedAuditMutationReceipt,
    ) -> Result<(), AuditError> {
        sqlx::query(
            "INSERT INTO audit_retention_outbox(tenant_id,outbox_id,task_id,event_type,payload_digest,payload,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(canonical_uuid(&task.0)?)
        .bind(event_type)
        .bind(canonical_digest(receipt)?)
        .bind(serde_json::to_value(receipt).map_err(|_| AuditError::Canonicalization)?)
        .bind(Utc::now())
        .execute(&mut **transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(())
    }

    async fn query_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        evidence: &AuditQueryPrincipalEvidence,
    ) -> Result<(), AuditError> {
        sqlx::query(
            "INSERT INTO audit_retention_outbox(tenant_id,outbox_id,task_id,event_type,payload_digest,payload,created_at) \
             VALUES($1,$2,$3,'AUTHORITATIVE_AUDIT_QUERY_RECORDED',$4,$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(canonical_uuid(&evidence.audit_task_id.0)?)
        .bind(canonical_digest(evidence)?)
        .bind(serde_json::to_value(evidence).map_err(|_| AuditError::Canonicalization)?)
        .bind(evidence.recorded_at)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        Ok(())
    }
}

async fn verify_authoritative_query_use(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &AuthoritativeAuditQueryRequest,
    principal: &VerifiedHumanPrincipal,
    request_digest: &str,
    response: &AuthoritativeAuditPage,
) -> Result<(), AuditError> {
    let row = sqlx::query(
        "SELECT assertion_jti::text,assertion_digest,actor_subject,client_identity,service_subject,\
                scope,request_digest,receipt_digest FROM audit_human_assertion_uses \
         WHERE tenant_id=$1 AND operation='AUTHORITATIVE_QUERY' AND idempotency_key=$2 FOR SHARE",
    )
    .bind(tenant)
    .bind(&request.idempotency_key.0)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AuditError::PersistenceFailed)?
    .ok_or(AuditError::IntegrityFailed)?;
    if row
        .try_get::<String, _>("assertion_jti")
        .map_err(|_| AuditError::PersistenceFailed)?
        != principal.jti
        || row
            .try_get::<String, _>("assertion_digest")
            .map_err(|_| AuditError::PersistenceFailed)?
            != principal.assertion_digest
        || row
            .try_get::<String, _>("actor_subject")
            .map_err(|_| AuditError::PersistenceFailed)?
            != principal.subject
        || row
            .try_get::<String, _>("client_identity")
            .map_err(|_| AuditError::PersistenceFailed)?
            != principal.client_identity
        || row
            .try_get::<String, _>("service_subject")
            .map_err(|_| AuditError::PersistenceFailed)?
            != principal.service_subject
        || row
            .try_get::<String, _>("scope")
            .map_err(|_| AuditError::PersistenceFailed)?
            != principal.scope
        || principal.subject != request.actor_subject
        || row
            .try_get::<String, _>("request_digest")
            .map_err(|_| AuditError::PersistenceFailed)?
            != request_digest
        || row
            .try_get::<String, _>("receipt_digest")
            .map_err(|_| AuditError::PersistenceFailed)?
            != canonical_digest(&response.receipt)?
    {
        return Err(AuditError::IntegrityFailed);
    }
    Ok(())
}

async fn replay<T: for<'de> Deserialize<'de> + Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    operation: &str,
    key: &IdempotencyKey,
    digest: &str,
) -> Result<Option<T>, AuditError> {
    let row = sqlx::query(
        "SELECT request_digest,response_digest,response_body FROM audit_operation_replays \
         WHERE tenant_id=$1 AND operation=$2 AND idempotency_key=$3 FOR SHARE",
    )
    .bind(tenant)
    .bind(operation)
    .bind(&key.0)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AuditError::PersistenceFailed)?;
    match row {
        Some(row) => {
            if row
                .try_get::<String, _>("request_digest")
                .map_err(|_| AuditError::PersistenceFailed)?
                != digest
            {
                return Err(AuditError::IdempotencyConflict);
            }
            let response: T = serde_json::from_value(
                row.try_get("response_body")
                    .map_err(|_| AuditError::PersistenceFailed)?,
            )
            .map_err(|_| AuditError::PersistenceFailed)?;
            if row
                .try_get::<String, _>("response_digest")
                .map_err(|_| AuditError::PersistenceFailed)?
                != canonical_digest(&response)?
            {
                return Err(AuditError::IntegrityFailed);
            }
            Ok(Some(response))
        }
        None => Ok(None),
    }
}

async fn persist_replay<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    operation: &str,
    key: &IdempotencyKey,
    digest: &str,
    response: &T,
) -> Result<(), AuditError> {
    let body = serde_json::to_value(response).map_err(|_| AuditError::Canonicalization)?;
    sqlx::query(
        "INSERT INTO audit_operation_replays(tenant_id,operation,idempotency_key,request_digest,response_digest,response_body,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(tenant)
    .bind(operation)
    .bind(&key.0)
    .bind(digest)
    .bind(canonical_digest(response)?)
    .bind(body)
    .bind(Utc::now())
    .execute(&mut **transaction)
    .await
    .map_err(|_| AuditError::PersistenceFailed)?;
    Ok(())
}

fn validate_append_request(request: &AuditAppendRequest) -> Result<(), AuditError> {
    if request.schema_version != AUDIT_APPEND_REQUEST_SCHEMA
        || request.records.is_empty()
        || request.records.len() > 1_000
        || request.records.iter().any(|record| {
            record.tenant_id != request.tenant_id || record.request_id.starts_with("authority:")
        })
        || !valid_idempotency(&request.idempotency_key)
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::RequestInvalid);
    }
    Ok(())
}

fn validate_query(request: &ProductionAuditQuery) -> Result<(), AuditError> {
    if request.schema_version != AUDIT_QUERY_REQUEST_SCHEMA
        || !valid_idempotency(&request.idempotency_key)
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.resource_prefix.is_empty()
        || request.resource_prefix.len() > 2_048
        || request.occurred_from >= request.occurred_until
        || request.limit == 0
        || request.limit > 1_000
        || request.offset > 1_000_000
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::QueryDenied);
    }
    Ok(())
}

fn validate_authoritative_query(
    request: &AuthoritativeAuditQueryRequest,
    principal: &VerifiedHumanPrincipal,
) -> Result<(), AuditError> {
    let classification_ceiling = if principal.roles.contains("audit-regulated-reader") {
        Some(DataClassification::Regulated)
    } else if principal.roles.contains("audit-restricted-reader") {
        Some(DataClassification::Restricted)
    } else if principal.roles.contains("audit-confidential-reader") {
        Some(DataClassification::Confidential)
    } else if principal.roles.contains("audit-reader")
        || principal.roles.contains("compliance-auditor")
        || principal.roles.contains("security-auditor")
    {
        Some(DataClassification::Internal)
    } else {
        None
    };
    if request.schema_version != AUTHORITATIVE_AUDIT_QUERY_REQUEST_SCHEMA
        || request.tenant_id != principal.tenant_id
        || request.actor_subject != principal.subject
        || principal.scope != "audit:query"
        || !principal.strong_auth
        || classification_ceiling.is_none_or(|ceiling| request.maximum_classification > ceiling)
        || !valid_idempotency(&request.idempotency_key)
        || canonical_uuid(&request.tenant_id.0).is_err()
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.resource.is_empty()
        || request.resource.len() > 100
        || !request.resource.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            }
        })
        || request.resource_prefix.is_empty()
        || request.resource_prefix.len() > 2_048
        || request.resource_prefix.contains(['\0', '\r', '\n'])
        || request.occurred_from >= request.occurred_until
        || request.occurred_until > request.requested_at + chrono::Duration::minutes(1)
        || request.occurred_until - request.occurred_from > chrono::Duration::days(366)
        || request.limit == 0
        || request.limit > 100
        || request.offset > 1_000_000
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::QueryDenied);
    }
    Ok(())
}

fn validate_export_request(request: &AuditExportRequest) -> Result<(), AuditError> {
    if request.schema_version != AUDIT_EXPORT_REQUEST_SCHEMA
        || !valid_idempotency(&request.idempotency_key)
        || canonical_uuid(&request.tenant_id.0).is_err()
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || request.transformed
        || !valid_request_time(request.requested_at)
        || request.retention_until <= request.requested_at
        || request.retention_until > request.requested_at + chrono::Duration::days(365 * 25)
    {
        return Err(AuditError::RequestInvalid);
    }
    Ok(())
}

fn validate_deletion_request(request: &AuditDeletionRequest) -> Result<(), AuditError> {
    if request.schema_version != AUDIT_DELETION_REQUEST_SCHEMA
        || !valid_idempotency(&request.idempotency_key)
        || canonical_uuid(&request.tenant_id.0).is_err()
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || request.policy_id.is_empty()
        || request.policy_id.len() > 256
        || request.delete_before >= request.requested_at
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::RequestInvalid);
    }
    Ok(())
}

fn validate_retention_request(request: &RetentionPolicyRequest) -> Result<(), AuditError> {
    if request.schema_version != "agenttrust.retention-policy-request.v1"
        || request.policy.schema_version != AUDIT_SCHEMA_VERSION
        || !valid_idempotency(&request.idempotency_key)
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.policy.policy_id.is_empty()
        || request.policy.policy_id.len() > 256
        || request.policy.event_type.is_empty()
        || request.policy.event_type.len() > 128
        || request.policy.compliance_profile.is_empty()
        || request.policy.compliance_profile.len() > 128
        || request.policy.retain_seconds == 0
        || !lower_digest(&request.policy.policy_digest)
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::RetentionPolicyInvalid);
    }
    Ok(())
}

fn validate_hold(hold: &LegalHold) -> Result<(), AuditError> {
    if hold.schema_version != AUDIT_SCHEMA_VERSION
        || canonical_uuid(&hold.tenant_id.0).is_err()
        || canonical_uuid(&hold.hold_id).is_err()
        || hold.reason_code.is_empty()
        || hold.reason_code.len() > 256
        || hold.placed_by.is_empty()
        || hold.placed_by.len() > 512
        || hold.released_at.is_some()
        || hold.released_by.is_some()
        || hold
            .task_id
            .as_ref()
            .is_some_and(|task| canonical_uuid(&task.0).is_err())
        || hold
            .actor_subject
            .as_ref()
            .is_some_and(|actor| actor.is_empty() || actor.len() > 512)
        || hold
            .resource_prefix
            .as_ref()
            .is_some_and(|resource| resource.is_empty() || resource.len() > 2_048)
        || hold.ends_at.is_some_and(|end| end < hold.starts_at)
        || (hold.task_id.is_none()
            && hold.actor_subject.is_none()
            && hold.resource_prefix.is_none())
    {
        return Err(AuditError::LegalHoldInvalid);
    }
    Ok(())
}

fn validate_hold_request(request: &LegalHoldPlaceRequest) -> Result<(), AuditError> {
    validate_hold(&request.hold)?;
    if request.schema_version != "agenttrust.legal-hold-place-request.v1"
        || !valid_idempotency(&request.idempotency_key)
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::LegalHoldInvalid);
    }
    Ok(())
}

fn validate_release(request: &LegalHoldReleaseRequest) -> Result<(), AuditError> {
    if request.schema_version != "agenttrust.legal-hold-release-request.v1"
        || !valid_idempotency(&request.idempotency_key)
        || request.released_by.is_empty()
        || request.released_by.len() > 512
        || request.reason_code.is_empty()
        || request.reason_code.len() > 256
        || canonical_uuid(&request.tenant_id.0).is_err()
        || canonical_uuid(&request.hold_id).is_err()
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::LegalHoldReleaseDenied);
    }
    Ok(())
}

fn validate_control_request(request: &ControlRegistrationRequest) -> Result<(), AuditError> {
    if request.schema_version != "agenttrust.control-registration-request.v1"
        || request.control.schema_version != AUDIT_SCHEMA_VERSION
        || !valid_idempotency(&request.idempotency_key)
        || request.control.control_id.is_empty()
        || request.control.control_id.len() > 256
        || request.control.owner.is_empty()
        || request.control.requirement_ids.is_empty()
        || request.control.policy_refs.is_empty()
        || request.control.test_refs.is_empty()
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || canonical_uuid(&request.tenant_id.0).is_err()
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::ControlInvalid);
    }
    Ok(())
}

fn validate_node(node: &EvidenceNode) -> Result<(), AuditError> {
    if node.schema_version != AUDIT_SCHEMA_VERSION
        || node.node_id.is_empty()
        || node.node_id.len() > 512
        || node.node_type.is_empty()
        || node.node_type.len() > 128
        || canonical_uuid(&node.tenant_id.0).is_err()
        || !lower_digest(&node.digest)
    {
        return Err(AuditError::GraphInvalid);
    }
    Ok(())
}

fn validate_node_request(request: &EvidenceNodeRequest) -> Result<(), AuditError> {
    validate_node(&request.node)?;
    if request.schema_version != "agenttrust.evidence-node-request.v1"
        || !valid_idempotency(&request.idempotency_key)
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::GraphInvalid);
    }
    Ok(())
}

fn validate_record_chain(
    records: &[AuditRecord],
    tenant: &TenantId,
    keys: &BTreeMap<String, VerifyingKey>,
) -> Result<(), AuditError> {
    let mut previous = "0".repeat(64);
    for (index, record) in records.iter().enumerate() {
        if record.schema_version != AUDIT_SCHEMA_VERSION
            || &record.draft.tenant_id != tenant
            || record.sequence != index as u64 + 1
            || record.previous_hash != previous
            || record.record_hash != hex(Sha256::digest(record.unsigned_bytes()?))
            || !lower_digest(&record.record_hash)
        {
            return Err(AuditError::IntegrityFailed);
        }
        let key = keys
            .get(&record.key_id)
            .ok_or(AuditError::SignatureInvalid)?;
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&record.signature)
                .map_err(|_| AuditError::SignatureInvalid)?,
        )
        .map_err(|_| AuditError::SignatureInvalid)?;
        key.verify(record.record_hash.as_bytes(), &signature)
            .map_err(|_| AuditError::SignatureInvalid)?;
        previous = record.record_hash.clone();
    }
    Ok(())
}

fn hold_protects(hold: &LegalHold, record: &AuditRecord) -> bool {
    hold.released_at.is_none()
        && hold.tenant_id == record.draft.tenant_id
        && hold.starts_at <= record.draft.occurred_at
        && hold
            .ends_at
            .is_none_or(|end| record.draft.occurred_at <= end)
        && hold
            .task_id
            .as_ref()
            .is_none_or(|task| task == &record.draft.task_id)
        && hold
            .actor_subject
            .as_ref()
            .is_none_or(|actor| actor == &record.draft.actor_subject)
        && hold
            .resource_prefix
            .as_ref()
            .is_none_or(|prefix| record.draft.resource.starts_with(prefix))
}

fn validate_edge(edge: &EvidenceEdge) -> Result<(), AuditError> {
    if edge.schema_version != AUDIT_SCHEMA_VERSION
        || edge.from_node.is_empty()
        || edge.from_node.len() > 512
        || edge.relation.is_empty()
        || edge.relation.len() > 128
        || edge.to_node.is_empty()
        || edge.to_node.len() > 512
        || canonical_uuid(&edge.tenant_id.0).is_err()
    {
        return Err(AuditError::GraphInvalid);
    }
    Ok(())
}

fn validate_edge_request(request: &EvidenceEdgeRequest) -> Result<(), AuditError> {
    validate_edge(&request.edge)?;
    if request.schema_version != "agenttrust.evidence-edge-request.v1"
        || !valid_idempotency(&request.idempotency_key)
        || canonical_uuid(&request.audit_task_id.0).is_err()
        || request.actor_subject.is_empty()
        || request.actor_subject.len() > 512
        || !valid_request_time(request.requested_at)
    {
        return Err(AuditError::GraphInvalid);
    }
    Ok(())
}

fn hold_object_ref(hold: &LegalHold) -> Result<String, AuditError> {
    hold.task_id
        .as_ref()
        .map(|value| format!("task:{}", value.0))
        .or_else(|| {
            hold.actor_subject
                .as_ref()
                .map(|value| format!("actor:{value}"))
        })
        .or_else(|| hold.resource_prefix.clone())
        .ok_or(AuditError::LegalHoldInvalid)
}

fn enum_name<T: Serialize>(value: &T) -> Result<String, AuditError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(AuditError::Canonicalization)
}

fn classification_rank(value: DataClassification) -> i16 {
    match value {
        DataClassification::Public => 0,
        DataClassification::Internal => 1,
        DataClassification::Confidential => 2,
        DataClassification::Restricted => 3,
        DataClassification::Regulated => 4,
    }
}

fn escape_like_prefix(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn valid_idempotency(value: &IdempotencyKey) -> bool {
    !value.0.is_empty()
        && value.0.len() <= 128
        && value
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn valid_request_time(value: DateTime<Utc>) -> bool {
    let now = Utc::now();
    value >= now - chrono::Duration::minutes(5) && value <= now + chrono::Duration::minutes(1)
}

fn canonical_uuid(value: &str) -> Result<Uuid, AuditError> {
    let parsed = Uuid::parse_str(value).map_err(|_| AuditError::RequestInvalid)?;
    if parsed.to_string() != value {
        return Err(AuditError::RequestInvalid);
    }
    Ok(parsed)
}

fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, AuditError> {
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| AuditError::Canonicalization)?,
    )))
}

fn deletion_receipt_digest(receipt: &RetentionObjectDeletionReceipt) -> Result<String, AuditError> {
    let mut copy = receipt.clone();
    copy.proof_digest.clear();
    canonical_digest(&copy)
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(tenant: &TenantId) -> VerifiedHumanPrincipal {
        let now = Utc::now();
        VerifiedHumanPrincipal {
            tenant_id: tenant.clone(),
            subject: "auditor@example.test".into(),
            roles: BTreeSet::from(["audit-reader".into()]),
            project_ids: BTreeSet::new(),
            approval_ids: BTreeSet::new(),
            owned_resources: BTreeSet::new(),
            strong_auth: true,
            authentication_time: now - chrono::Duration::minutes(1),
            authentication_context: "urn:agenttrust:acr:mfa".into(),
            client_identity: "URI:spiffe://agenttrust/enterprise-bff".into(),
            service_subject: "enterprise-bff".into(),
            scope: "audit:query".into(),
            jti: Uuid::new_v4().to_string(),
            assertion_digest: "a".repeat(64),
            expires_at: now + chrono::Duration::minutes(4),
        }
    }

    fn authoritative_request(tenant: &TenantId) -> AuthoritativeAuditQueryRequest {
        let now = Utc::now();
        AuthoritativeAuditQueryRequest {
            schema_version: AUTHORITATIVE_AUDIT_QUERY_REQUEST_SCHEMA.into(),
            tenant_id: tenant.clone(),
            idempotency_key: IdempotencyKey(format!("audit-query:{}", Uuid::new_v4())),
            audit_task_id: TaskId::new(),
            actor_subject: "auditor@example.test".into(),
            resource: "summary".into(),
            resource_prefix: "*".into(),
            maximum_classification: DataClassification::Internal,
            occurred_from: now - chrono::Duration::days(30),
            occurred_until: now,
            offset: 0,
            limit: 50,
            requested_at: now,
        }
    }

    #[test]
    fn authoritative_query_binds_human_and_fails_closed_on_classification() {
        let tenant = TenantId::new();
        let principal = principal(&tenant);
        let mut request = authoritative_request(&tenant);
        assert!(validate_authoritative_query(&request, &principal).is_ok());

        request.maximum_classification = DataClassification::Confidential;
        assert_eq!(
            validate_authoritative_query(&request, &principal),
            Err(AuditError::QueryDenied)
        );
        request.maximum_classification = DataClassification::Internal;
        request.actor_subject = "different@example.test".into();
        assert_eq!(
            validate_authoritative_query(&request, &principal),
            Err(AuditError::QueryDenied)
        );
    }
}
