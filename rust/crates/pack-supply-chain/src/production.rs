//! Fail-closed Batch 20 production executor.
//!
//! The HTTP boundary accepts only requests already normalized to Canonical Action IR and bound
//! to a PEP authorization, transaction-ledger event, resource fence and authorization evidence.
//! External repository, signature, scanner, sandbox and revocation propagation are typed ports;
//! an ambiguous external outcome is persisted as `UNKNOWN` and is never replayed automatically.

use crate::{
    ArtifactManifest, ArtifactVerifier, DomainPackManifest, PackError, PackSdk, PermissionDiff,
};
use agent_trust_action_ir::{CanonicalAction, hash as action_hash};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const SUPPLY_EXECUTION_SCHEMA: &str = "agenttrust.supply-chain-execution.v1";
pub const SUPPLY_BINDING_SCHEMA: &str = "agenttrust.supply-chain-execution-binding.v1";
pub const SUPPLY_RECEIPT_SCHEMA: &str = "agenttrust.supply-chain-runtime-receipt.v1";
pub const SUPPLY_RESULT_SCHEMA: &str = "agenttrust.supply-chain-result.v1";
pub const SUPPLY_KEYRING_SCHEMA: &str = "agenttrust.supply-chain-receipt-keyring.v1";
pub const SUPPLY_RELEASES_SCHEMA: &str = "agenttrust.supply-chain-authoritative-releases.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupplyOperation {
    Publish,
    Validate,
    Approve,
    Activate,
    Rollback,
    Revoke,
    Quarantine,
    Recover,
}

impl SupplyOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Publish => "PUBLISH",
            Self::Validate => "VALIDATE",
            Self::Approve => "APPROVE",
            Self::Activate => "ACTIVATE",
            Self::Rollback => "ROLLBACK",
            Self::Revoke => "REVOKE",
            Self::Quarantine => "QUARANTINE",
            Self::Recover => "RECOVER",
        }
    }

    pub fn required_scope(self) -> &'static str {
        match self {
            Self::Publish | Self::Validate => "supply-chain:publish",
            Self::Approve => "supply-chain:approve",
            Self::Activate | Self::Rollback => "supply-chain:activate",
            Self::Revoke | Self::Quarantine => "supply-chain:revoke",
            Self::Recover => "supply-chain:recover",
        }
    }

    fn requires_external_effect(self) -> bool {
        matches!(
            self,
            Self::Publish
                | Self::Validate
                | Self::Activate
                | Self::Rollback
                | Self::Revoke
                | Self::Quarantine
                | Self::Recover
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainCommand {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub task_id: Uuid,
    pub operation: SupplyOperation,
    pub resource_key: String,
    pub expected_resource_version: u64,
    pub requested_at: DateTime<Utc>,
    pub safe_payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupplyExecutionBinding {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub authorization_id: Uuid,
    pub authorization_digest: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub resource_version: u64,
    pub idempotency_key: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyExecutionRequest {
    pub schema_version: String,
    pub actor_subject: String,
    pub canonical_action: CanonicalAction,
    pub command: SupplyChainCommand,
    pub binding: SupplyExecutionBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupplyRuntimeReceipt {
    pub schema_version: String,
    pub operation: SupplyOperation,
    pub resource_key: String,
    pub action_hash: String,
    pub request_digest: String,
    pub repository_receipt_digest: Option<String>,
    pub signature_receipt_digest: Option<String>,
    pub sbom_receipt_digest: Option<String>,
    pub vulnerability_receipt_digest: Option<String>,
    pub license_receipt_digest: Option<String>,
    pub sandbox_receipt_digest: Option<String>,
    pub revocation_receipt_digest: Option<String>,
    pub installation_receipt_digest: Option<String>,
    pub reconciliation_receipt_digest: Option<String>,
    pub external_effect_count: u32,
    pub production_access_detected: bool,
    pub completed_at: DateTime<Utc>,
    pub key_id: String,
    pub signature: String,
}

impl SupplyRuntimeReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, SupplyAuthorityError> {
        let mut value = self.clone();
        value.signature.clear();
        serde_jcs::to_vec(&value).map_err(|_| SupplyAuthorityError::RequestInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupplyMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub state: String,
    pub resource_key: String,
    pub resource_version: u64,
    pub result_digest: Option<String>,
    pub evidence_ref: Option<String>,
    pub evidence_digest: Option<String>,
    pub stable_error: Option<String>,
    pub effect_receipt: Option<SupplyRuntimeReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeRelease {
    pub pack_id: String,
    pub version: String,
    pub lifecycle_state: String,
    pub resource_version: u64,
    pub manifest_digest: String,
    pub permission_digest: String,
    pub dependency_lock_digest: String,
    pub artifact_digest: String,
    pub immutable_reference: String,
    pub sbom_digest: String,
    pub provenance_digest: String,
    pub signature_digest: String,
    pub license_report_digest: String,
    pub vulnerability_report_digest: String,
    pub maximum_vulnerability: String,
    pub artifact_status: String,
    pub receipt_refs: Vec<SupplyReceiptReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupplyReceiptReference {
    pub operation: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub result_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvidenceDelivery {
    pub evidence_ref: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeReleasePage {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub authoritative: bool,
    pub data_digest: String,
    pub items: Vec<AuthoritativeRelease>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptKeyringDocument {
    schema_version: String,
    keys: Vec<ReceiptKeyDocument>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptKeyDocument {
    key_id: String,
    usage: String,
    public_key: String,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

#[derive(Clone)]
pub struct SupplyReceiptKeyring {
    keys: Arc<BTreeMap<String, (VerifyingKey, DateTime<Utc>, DateTime<Utc>)>>,
}

impl SupplyReceiptKeyring {
    pub fn from_json(raw: &[u8], now: DateTime<Utc>) -> Result<Self, SupplyAuthorityError> {
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        let document: ReceiptKeyringDocument =
            serde_json::from_slice(raw).map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != SUPPLY_KEYRING_SCHEMA
            || document.keys.is_empty()
            || document.keys.len() > 256
        {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let decoded = URL_SAFE_NO_PAD
                .decode(entry.public_key)
                .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
            let bytes: [u8; 32] = decoded
                .try_into()
                .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| SupplyAuthorityError::ConfigurationInvalid)?;
            if entry.usage != "SUPPLY_CHAIN_RUNTIME_RECEIPT"
                || entry.revoked
                || entry.not_before > now
                || entry.expires_at <= now
                || !identifier(&entry.key_id, 256)
                || keys
                    .insert(entry.key_id, (key, entry.not_before, entry.expires_at))
                    .is_some()
            {
                return Err(SupplyAuthorityError::ConfigurationInvalid);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn verify(
        &self,
        receipt: &SupplyRuntimeReceipt,
        request: &SupplyExecutionRequest,
        request_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), SupplyAuthorityError> {
        let (key, not_before, expires_at) = self
            .keys
            .get(&receipt.key_id)
            .ok_or(SupplyAuthorityError::ReceiptInvalid)?;
        if receipt.schema_version != SUPPLY_RECEIPT_SCHEMA
            || receipt.operation != request.command.operation
            || receipt.resource_key != request.command.resource_key
            || receipt.action_hash != request.binding_action_hash()?
            || receipt.request_digest != request_digest
            || receipt.completed_at < request.command.requested_at
            || receipt.completed_at > now + Duration::minutes(1)
            || now < *not_before
            || now >= *expires_at
            || receipt.external_effect_count > 64
            || receipt.production_access_detected
        {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        if request.command.operation.requires_external_effect()
            && receipt.external_effect_count == 0
        {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        let required_receipts_present = match request.command.operation {
            SupplyOperation::Publish => {
                receipt.repository_receipt_digest.is_some()
                    && receipt.signature_receipt_digest.is_some()
                    && receipt.sbom_receipt_digest.is_some()
                    && receipt.vulnerability_receipt_digest.is_some()
                    && receipt.license_receipt_digest.is_some()
            }
            SupplyOperation::Validate => {
                receipt.sandbox_receipt_digest.is_some()
                    && receipt.vulnerability_receipt_digest.is_some()
                    && receipt.license_receipt_digest.is_some()
            }
            SupplyOperation::Approve => {
                receipt.external_effect_count == 0
                    && receipt.repository_receipt_digest.is_none()
                    && receipt.signature_receipt_digest.is_none()
                    && receipt.sbom_receipt_digest.is_none()
                    && receipt.vulnerability_receipt_digest.is_none()
                    && receipt.license_receipt_digest.is_none()
                    && receipt.sandbox_receipt_digest.is_none()
                    && receipt.revocation_receipt_digest.is_none()
                    && receipt.installation_receipt_digest.is_none()
                    && receipt.reconciliation_receipt_digest.is_none()
            }
            SupplyOperation::Activate | SupplyOperation::Rollback => {
                receipt.installation_receipt_digest.is_some()
            }
            SupplyOperation::Revoke | SupplyOperation::Quarantine => {
                receipt.revocation_receipt_digest.is_some()
            }
            SupplyOperation::Recover => receipt.reconciliation_receipt_digest.is_some(),
        };
        if !required_receipts_present {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        for digest_value in [
            receipt.repository_receipt_digest.as_deref(),
            receipt.signature_receipt_digest.as_deref(),
            receipt.sbom_receipt_digest.as_deref(),
            receipt.vulnerability_receipt_digest.as_deref(),
            receipt.license_receipt_digest.as_deref(),
            receipt.sandbox_receipt_digest.as_deref(),
            receipt.revocation_receipt_digest.as_deref(),
            receipt.installation_receipt_digest.as_deref(),
            receipt.reconciliation_receipt_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !digest(digest_value) {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&receipt.signature)
            .map_err(|_| SupplyAuthorityError::ReceiptInvalid)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| SupplyAuthorityError::ReceiptInvalid)?;
        key.verify(&receipt.signing_bytes()?, &signature)
            .map_err(|_| SupplyAuthorityError::ReceiptInvalid)
    }
}

impl SupplyExecutionRequest {
    fn binding_action_hash(&self) -> Result<String, SupplyAuthorityError> {
        action_hash(&self.canonical_action).map_err(|_| SupplyAuthorityError::RequestInvalid)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<String, SupplyAuthorityError> {
        let expected_current_state_version = self.command.expected_resource_version.to_string();
        let payload_resource = validate_supply_payload(
            self.command.operation,
            &self.command.safe_payload,
            self.command.requested_at,
        )?;
        if self.schema_version != SUPPLY_EXECUTION_SCHEMA
            || self.command.schema_version != "agenttrust.supply-chain-command.v1"
            || self.binding.schema_version != SUPPLY_BINDING_SCHEMA
            || self.command.tenant_id != self.binding.tenant_id
            || self.command.command_id.to_string() != self.canonical_action.action_id.0
            || self.command.task_id.to_string() != self.canonical_action.task_id.0
            || self.canonical_action.agent.tenant_id.0 != self.command.tenant_id.to_string()
            || self.canonical_action.resource.tenant_id.0 != self.command.tenant_id.to_string()
            || self.canonical_action.environment.tenant_id.0 != self.command.tenant_id.to_string()
            || self.canonical_action.environment.deployment != "production"
            || self.canonical_action.agent.owner_subject != self.actor_subject
            || self.canonical_action.intent.operation
                != self.command.operation.as_str().to_ascii_lowercase()
            || self.canonical_action.resource.locator != self.command.resource_key
            || self.canonical_action.current_state_version.as_deref()
                != Some(expected_current_state_version.as_str())
            || self.canonical_action.requested_at != self.command.requested_at
            || self.command.requested_at > now + Duration::minutes(1)
            || self.command.requested_at < now - Duration::minutes(10)
            || self.binding.resource_version
                != self.command.expected_resource_version.saturating_add(1)
            || !identifier(&self.actor_subject, 512)
            || !identifier(&self.binding.policy_decision_id, 256)
            || !identifier(&self.binding.trace_id, 256)
            || !identifier(&self.command.resource_key, 768)
            || self.command.resource_key != payload_resource
            || !idempotency_key(&self.binding.idempotency_key)
            || !reference(&self.binding.authorization_evidence_ref, 1024)
            || !digest(&self.binding.authorization_digest)
            || !digest(&self.binding.policy_decision_digest)
            || !digest(&self.binding.authorization_evidence_digest)
            || !digest(&self.binding.ledger_event_digest)
            || !digest(&self.binding.fence_digest)
            || json_limits(&self.command.safe_payload, 0).is_err()
        {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
        let action = self.binding_action_hash()?;
        if self.canonical_action.payload.type_id != "supply-chain.mutation.v1"
            || self.canonical_action.payload.schema_version != "1"
            || self
                .canonical_action
                .extensions
                .get("x-policy-decision-digest")
                != Some(&Value::String(self.binding.policy_decision_digest.clone()))
            || self
                .canonical_action
                .extensions
                .get("x-authorization-evidence-digest")
                != Some(&Value::String(
                    self.binding.authorization_evidence_digest.clone(),
                ))
            || self
                .canonical_action
                .extensions
                .get("x-ledger-event-digest")
                != Some(&Value::String(self.binding.ledger_event_digest.clone()))
            || self
                .canonical_action
                .extensions
                .get("x-execution-fence-digest")
                != Some(&Value::String(self.binding.fence_digest.clone()))
            || self
                .canonical_action
                .extensions
                .get("x-supply-command-digest")
                != Some(&Value::String(canonical_digest(
                    &self.command.safe_payload,
                )?))
        {
            return Err(SupplyAuthorityError::BindingInvalid);
        }
        Ok(action)
    }
}

#[async_trait]
pub trait SupplyChainRuntimePort: Send + Sync {
    async fn execute(
        &self,
        request: &SupplyExecutionRequest,
        _request_digest: &str,
        action_hash: &str,
    ) -> Result<SupplyRuntimeReceipt, SupplyAuthorityError>;

    async fn ready(&self) -> bool;

    async fn deliver_evidence(
        &self,
        tenant_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<AuthorityEvidenceDelivery, SupplyAuthorityError>;
}

#[derive(Debug, Clone)]
struct PendingEvidence {
    outbox_id: Uuid,
    idempotency_key: String,
    payload: Value,
    payload_digest: String,
}

#[async_trait]
pub trait PackRegistry: Send + Sync {
    async fn publish(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
    async fn approve(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
    async fn activate(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
    async fn revoke(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
}

#[async_trait]
pub trait PackInstaller: Send + Sync {
    async fn install(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
    async fn rollback(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
}

#[async_trait]
pub trait RevocationService: Send + Sync {
    async fn quarantine(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
    async fn revoke_release(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError>;
}

pub struct CompatibilityResolver;

impl CompatibilityResolver {
    pub fn check(
        required: &BTreeSet<String>,
        provided: &BTreeSet<String>,
    ) -> Result<(), SupplyAuthorityError> {
        if required.is_empty() || !required.is_subset(provided) {
            return Err(SupplyAuthorityError::PackInvalid);
        }
        Ok(())
    }
}

pub struct PackValidator;

impl PackValidator {
    pub fn validate(
        manifest: &DomainPackManifest,
        artifacts: &BTreeMap<String, ArtifactManifest>,
        verifier: &ArtifactVerifier,
        runtime_compatibility: &BTreeSet<String>,
    ) -> Result<(), SupplyAuthorityError> {
        PackSdk::validate(manifest).map_err(map_pack_error)?;
        verifier.verify_pack(manifest).map_err(map_pack_error)?;
        CompatibilityResolver::check(&manifest.compatibility, runtime_compatibility)?;
        if manifest.artifact_refs.len() != artifacts.len() {
            return Err(SupplyAuthorityError::PackInvalid);
        }
        for reference in &manifest.artifact_refs {
            let artifact = artifacts
                .get(reference)
                .ok_or(SupplyAuthorityError::PackInvalid)?;
            verifier.verify_artifact(artifact).map_err(map_pack_error)?;
            if reference != &format!("artifact:sha256:{}", artifact.digest) {
                return Err(SupplyAuthorityError::PackInvalid);
            }
        }
        Ok(())
    }
}

pub struct SupplyChainGate;

impl SupplyChainGate {
    pub fn admit(
        manifest: &DomainPackManifest,
        artifacts: &BTreeMap<String, ArtifactManifest>,
        verifier: &ArtifactVerifier,
        runtime_compatibility: &BTreeSet<String>,
        conformance_passed: bool,
        behavior_passed: bool,
        permission_expansion_approved: bool,
    ) -> Result<(), SupplyAuthorityError> {
        PackValidator::validate(manifest, artifacts, verifier, runtime_compatibility)?;
        if !conformance_passed
            || !behavior_passed
            || (!manifest.permissions.approval_scopes.is_empty() && !permission_expansion_approved)
        {
            return Err(SupplyAuthorityError::ApprovalDenied);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresSupplyChainStore {
    pool: PgPool,
}

impl PostgresSupplyChainStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn begin_tenant(
        &self,
        tenant: Uuid,
    ) -> Result<Transaction<'_, Postgres>, SupplyAuthorityError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM public.supply_chain_authority_commands WHERE false UNION ALL SELECT 1 LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .is_ok()
    }

    pub async fn authoritative_releases(
        &self,
        tenant: Uuid,
        limit: i64,
        cursor: Option<&str>,
    ) -> Result<AuthoritativeReleasePage, SupplyAuthorityError> {
        if !(1..=200).contains(&limit) {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
        let decoded = cursor.map(decode_release_cursor).transpose()?;
        let after_pack = decoded.as_ref().map(|value| value.0.as_str());
        let after_version = decoded.as_ref().map(|value| value.1.as_str());
        let mut tx = self.begin_tenant(tenant).await?;
        let rows=sqlx::query(
            "SELECT r.pack_id,r.version,r.lifecycle_state,r.resource_version,r.manifest_digest,
                    r.permission_digest,r.dependency_lock_digest,a.artifact_digest,a.immutable_reference,
                    a.sbom_digest,a.provenance_digest,a.signature_digest,a.license_report_digest,
                    a.vulnerability_report_digest,a.maximum_vulnerability,a.status AS artifact_status,
                    COALESCE((SELECT jsonb_agg(receipt.item ORDER BY receipt.created_at,receipt.command_id)
                      FROM (SELECT jsonb_build_object('operation',c.operation,
                             'evidence_ref',COALESCE((SELECT o.delivery_evidence_ref FROM public.supply_chain_evidence_outbox o WHERE o.tenant_id=c.tenant_id AND o.command_id=c.command_id AND o.delivered_at IS NOT NULL ORDER BY o.created_at DESC LIMIT 1),c.evidence_ref),
                             'evidence_digest',COALESCE((SELECT o.delivery_receipt_digest FROM public.supply_chain_evidence_outbox o WHERE o.tenant_id=c.tenant_id AND o.command_id=c.command_id AND o.delivered_at IS NOT NULL ORDER BY o.created_at DESC LIMIT 1),c.evidence_digest),
                             'result_digest',c.result_digest) AS item,c.created_at,c.command_id
                              FROM public.supply_chain_authority_commands c
                             WHERE c.tenant_id=r.tenant_id AND c.state='SUCCEEDED'
                               AND c.evidence_ref IS NOT NULL AND c.evidence_digest IS NOT NULL
                               AND c.result_digest IS NOT NULL
                               AND COALESCE(c.safe_request->>'pack_id',c.safe_request->'manifest'->>'pack_id')=r.pack_id
                               AND COALESCE(c.safe_request->>'version',c.safe_request->'manifest'->>'version')=r.version
                             ORDER BY c.created_at DESC,c.command_id DESC LIMIT 32) receipt),'[]'::jsonb) AS receipt_refs
               FROM public.supply_chain_pack_releases r
               JOIN public.supply_chain_artifact_revisions a
                 ON a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id
              WHERE r.tenant_id=$1 AND ($2::text IS NULL OR (r.pack_id,r.version)>($2,$3))
              ORDER BY r.pack_id,r.version LIMIT $4"
        ).bind(tenant).bind(after_pack).bind(after_version).bind(limit+1)
            .fetch_all(&mut *tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
        let mut items = rows
            .into_iter()
            .take(usize::try_from(limit).map_err(|_| SupplyAuthorityError::RequestInvalid)?)
            .map(authoritative_release_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            items
                .last()
                .map(|item| encode_release_cursor(&item.pack_id, &item.version))
                .transpose()?
        } else {
            None
        };
        // The digest covers the exact response object with only `data_digest` removed. Keep
        // this shape explicit so BFF/UI consumers can independently JCS-hash the received page.
        let digest_value = canonical_digest(&json!({
            "schema_version":SUPPLY_RELEASES_SCHEMA,
            "tenant_id":tenant,
            "authoritative":true,
            "items":&items,
            "next_cursor":&next_cursor,
        }))?;
        Ok(AuthoritativeReleasePage {
            schema_version: SUPPLY_RELEASES_SCHEMA.into(),
            tenant_id: tenant,
            authoritative: true,
            data_digest: digest_value,
            items: std::mem::take(&mut items),
            next_cursor,
        })
    }

    async fn prepare_and_claim(
        &self,
        request: &SupplyExecutionRequest,
        request_digest: &str,
        action_hash: &str,
        instance_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Option<SupplyMutationResult>, SupplyAuthorityError> {
        let mut tx = self.begin_tenant(request.command.tenant_id).await?;
        let canonical = serde_json::to_value(&request.canonical_action)
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
        let inserted=sqlx::query(
            "INSERT INTO public.supply_chain_authority_commands
             (tenant_id,command_id,task_id,action_id,action_hash,operation,resource_key,
              expected_resource_version,request_digest,idempotency_key,actor_subject,
              authorization_id,authorization_digest,policy_decision_id,policy_decision_digest,
              authorization_evidence_ref,authorization_evidence_digest,ledger_execution_id,
              ledger_event_id,ledger_event_digest,fence_digest,resource_version,canonical_action,
              safe_request,state)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,'PREPARED')
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(request.command.tenant_id)
        .bind(request.command.command_id)
        .bind(request.command.task_id)
        .bind(request.command.command_id)
        .bind(action_hash)
        .bind(request.command.operation.as_str())
        .bind(&request.command.resource_key)
        .bind(i64::try_from(request.command.expected_resource_version).map_err(|_| SupplyAuthorityError::RequestInvalid)?)
        .bind(request_digest)
        .bind(&request.binding.idempotency_key)
        .bind(&request.actor_subject)
        .bind(request.binding.authorization_id)
        .bind(&request.binding.authorization_digest)
        .bind(&request.binding.policy_decision_id)
        .bind(&request.binding.policy_decision_digest)
        .bind(&request.binding.authorization_evidence_ref)
        .bind(&request.binding.authorization_evidence_digest)
        .bind(request.binding.ledger_execution_id)
        .bind(request.binding.ledger_event_id)
        .bind(&request.binding.ledger_event_digest)
        .bind(&request.binding.fence_digest)
        .bind(i64::try_from(request.binding.resource_version).map_err(|_| SupplyAuthorityError::RequestInvalid)?)
        .bind(&canonical)
        .bind(&request.command.safe_payload)
        .execute(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
        let row = sqlx::query(
            "SELECT command_id,request_digest,action_hash,operation,resource_key,resource_version,
                    state,result_digest,evidence_ref,evidence_digest,stable_error,effect_receipt
             FROM public.supply_chain_authority_commands
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(request.command.tenant_id)
        .bind(&request.binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if row.get::<Uuid, _>("command_id") != request.command.command_id
            || row.get::<String, _>("request_digest") != request_digest
            || row.get::<String, _>("action_hash") != action_hash
            || row.get::<String, _>("operation") != request.command.operation.as_str()
            || row.get::<String, _>("resource_key") != request.command.resource_key
            || row.get::<i64, _>("resource_version")
                != i64::try_from(request.binding.resource_version)
                    .map_err(|_| SupplyAuthorityError::RequestInvalid)?
        {
            return Err(SupplyAuthorityError::IdempotencyConflict);
        }
        let state: String = row.get("state");
        if state != "PREPARED" {
            let result = result_from_row(&row)?;
            tx.commit()
                .await
                .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
            return Ok(Some(result));
        }
        if inserted == 1 {
            Self::preflight_external(&mut tx, request).await?;
        }
        let affected=sqlx::query(
            "UPDATE public.supply_chain_authority_commands
             SET state='EXECUTING',owner_instance_id=$3,lease_expires_at=now()+make_interval(secs=>$4),updated_at=now()
             WHERE tenant_id=$1 AND command_id=$2 AND state='PREPARED'",
        )
        .bind(request.command.tenant_id)
        .bind(request.command.command_id)
        .bind(instance_id)
        .bind(lease_seconds)
        .execute(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
        if affected != 1 {
            return Err(SupplyAuthorityError::StateConflict);
        }
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        Ok(None)
    }

    async fn verify_manifest_signature(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        manifest: &DomainPackManifest,
    ) -> Result<(), SupplyAuthorityError> {
        let row = sqlx::query(
            "SELECT k.public_key_spki,k.algorithm,p.status AS publisher_status,k.status AS key_status,
                    k.valid_from,k.valid_until
             FROM public.supply_chain_publisher_keys k
             JOIN public.supply_chain_publishers p ON p.publisher_id=k.publisher_id
             WHERE k.publisher_id=$1 AND k.key_id=$2",
        )
        .bind(&manifest.publisher_identity)
        .bind(&manifest.signature.key_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?
        .ok_or(SupplyAuthorityError::PublisherDenied)?;
        let public_key: Vec<u8> = row.get("public_key_spki");
        let bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| SupplyAuthorityError::PublisherDenied)?;
        let valid_from: DateTime<Utc> = row.get("valid_from");
        let valid_until: DateTime<Utc> = row.get("valid_until");
        if row.get::<String, _>("algorithm") != "ED25519"
            || row.get::<String, _>("publisher_status") != "ACTIVE"
            || row.get::<String, _>("key_status") != "ACTIVE"
            || valid_from > manifest.signature.signed_at
            || valid_until <= manifest.signature.signed_at
        {
            return Err(SupplyAuthorityError::PublisherDenied);
        }
        let publisher_subject = &manifest.publisher_identity;
        let key_subject = format!(
            "{}#{}",
            manifest.publisher_identity, manifest.signature.key_id
        );
        let revoked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM public.supply_chain_revocations
              WHERE tenant_id=$1 AND ((scope='PUBLISHER' AND subject_id=$2)
                   OR (scope='KEY' AND subject_id=$3)))",
        )
        .bind(tenant)
        .bind(publisher_subject)
        .bind(key_subject)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if revoked {
            return Err(SupplyAuthorityError::PublisherDenied);
        }
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| SupplyAuthorityError::PublisherDenied)?;
        let verifier = ArtifactVerifier::default();
        verifier.authorize_publisher(
            manifest.signature.key_id.clone(),
            manifest.publisher_identity.clone(),
            key,
        );
        verifier.verify_pack(manifest).map_err(map_pack_error)
    }

    async fn preflight_external(
        tx: &mut Transaction<'_, Postgres>,
        request: &SupplyExecutionRequest,
    ) -> Result<(), SupplyAuthorityError> {
        let tenant = request.command.tenant_id;
        let body = request
            .command
            .safe_payload
            .as_object()
            .ok_or(SupplyAuthorityError::RequestInvalid)?;
        let expected = i64::try_from(request.command.expected_resource_version)
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
        match request.command.operation {
            SupplyOperation::Publish => {
                let manifest: DomainPackManifest = serde_json::from_value(required_object_field(
                    &request.command.safe_payload,
                    "manifest",
                )?)
                .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
                Self::verify_manifest_signature(tx, tenant, &manifest).await?;
                let artifact_id = uuid_field(body, "artifact_id")?;
                let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_artifact_revisions WHERE tenant_id=$1 AND artifact_id=$2 UNION ALL SELECT 1 FROM public.supply_chain_pack_releases WHERE tenant_id=$1 AND pack_id=$3 AND version=$4)")
                    .bind(tenant).bind(artifact_id).bind(&manifest.pack_id).bind(&manifest.version)
                    .fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                if exists || expected != 0 {
                    return Err(SupplyAuthorityError::StateConflict);
                }
            }
            SupplyOperation::Validate => {
                let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_pack_releases WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND lifecycle_state='PUBLISHED' AND resource_version=$4)")
                    .bind(tenant).bind(string_field(body,"pack_id",256)?).bind(string_field(body,"version",128)?).bind(expected)
                    .fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                if !exists {
                    return Err(SupplyAuthorityError::StateConflict);
                }
            }
            SupplyOperation::Activate => {
                let pack_id = string_field(body, "pack_id", 256)?;
                let version = string_field(body, "version", 128)?;
                let environment = string_field(body, "environment", 64)?;
                let manifest_digest = string_field(body, "manifest_digest", 64)?;
                let approval_id = uuid_field(body, "approval_id")?;
                let releasable:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_pack_releases r JOIN public.supply_chain_artifact_revisions a ON a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id JOIN public.supply_chain_pack_approvals p ON p.tenant_id=r.tenant_id AND p.pack_id=r.pack_id AND p.version=r.version AND p.manifest_digest=r.manifest_digest WHERE r.tenant_id=$1 AND r.pack_id=$2 AND r.version=$3 AND r.manifest_digest=$4 AND r.lifecycle_state='APPROVED' AND a.status='VERIFIED' AND p.approval_id=$5 AND p.environment=$6 AND p.decision='APPROVED' AND p.expires_at>now())")
                    .bind(tenant).bind(&pack_id).bind(&version).bind(&manifest_digest).bind(approval_id).bind(&environment)
                    .fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                let installed:Option<i64>=sqlx::query_scalar("SELECT resource_version FROM public.supply_chain_installations WHERE tenant_id=$1 AND environment=$2 AND pack_id=$3")
                    .bind(tenant).bind(&environment).bind(&pack_id).fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                if !releasable
                    || installed.is_some_and(|version| version != expected)
                    || installed.is_none() && expected != 0
                {
                    return Err(SupplyAuthorityError::ApprovalDenied);
                }
            }
            SupplyOperation::Rollback => {
                let pack_id = string_field(body, "pack_id", 256)?;
                let environment = string_field(body, "environment", 64)?;
                let recoverable:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_installations i JOIN public.supply_chain_pack_releases r ON r.tenant_id=i.tenant_id AND r.pack_id=i.pack_id AND r.version=i.previous_version AND r.manifest_digest=i.previous_manifest_digest JOIN public.supply_chain_artifact_revisions a ON a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id WHERE i.tenant_id=$1 AND i.environment=$2 AND i.pack_id=$3 AND i.resource_version=$4 AND i.state IN ('ACTIVE','PAUSED') AND i.previous_version IS NOT NULL AND (i.previous_version,i.previous_manifest_digest)<>(i.version,i.manifest_digest) AND r.lifecycle_state IN ('APPROVED','ACTIVE','ROLLED_BACK') AND a.status='VERIFIED' AND EXISTS(SELECT 1 FROM public.supply_chain_pack_approvals p WHERE p.tenant_id=r.tenant_id AND p.pack_id=r.pack_id AND p.version=r.version AND p.manifest_digest=r.manifest_digest AND p.environment=i.environment AND p.decision='APPROVED' AND p.expires_at>now()))")
                    .bind(tenant).bind(&environment).bind(&pack_id).bind(expected).fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                if !recoverable {
                    return Err(SupplyAuthorityError::RecoveryDenied);
                }
            }
            SupplyOperation::Recover => {
                let state:Option<String>=sqlx::query_scalar("SELECT state FROM public.supply_chain_authority_commands WHERE tenant_id=$1 AND command_id=$2")
                    .bind(tenant).bind(uuid_field(body,"unknown_command_id")?).fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                if state.as_deref() != Some("UNKNOWN") {
                    return Err(SupplyAuthorityError::RecoveryDenied);
                }
            }
            SupplyOperation::Approve | SupplyOperation::Revoke | SupplyOperation::Quarantine => {}
        }
        Ok(())
    }

    async fn commit_success(
        &self,
        request: &SupplyExecutionRequest,
        _request_digest: &str,
        receipt: &SupplyRuntimeReceipt,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        let mut tx = self.begin_tenant(request.command.tenant_id).await?;
        if request.command.operation == SupplyOperation::Publish {
            let manifest: DomainPackManifest = serde_json::from_value(required_object_field(
                &request.command.safe_payload,
                "manifest",
            )?)
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            Self::verify_manifest_signature(&mut tx, request.command.tenant_id, &manifest).await?;
        }
        let row = sqlx::query(
            "SELECT state,owner_instance_id,lease_expires_at FROM public.supply_chain_authority_commands
             WHERE tenant_id=$1 AND command_id=$2 FOR UPDATE",
        )
        .bind(request.command.tenant_id)
        .bind(request.command.command_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        if row.get::<String, _>("state") != "EXECUTING"
            || row.get::<DateTime<Utc>, _>("lease_expires_at") <= Utc::now()
        {
            return Err(SupplyAuthorityError::OutcomeUnknown);
        }
        apply_mutation(&mut tx, request, receipt).await?;
        let receipt_value =
            serde_json::to_value(receipt).map_err(|_| SupplyAuthorityError::ReceiptInvalid)?;
        let result_digest = canonical_digest(&json!({
            "command_id": request.command.command_id,
            "operation": request.command.operation,
            "resource_key": request.command.resource_key,
            "resource_version": request.binding.resource_version,
            "effect_receipt": receipt_value,
        }))?;
        let event_id = Uuid::new_v4();
        // These timestamps are part of the durable outbox payload so retries produce the exact
        // same AuthorityEvidenceEventRequest digest at the Evidence Authority.
        let evidence_requested_at = Utc::now();
        let event_payload = json!({
            "schema_version": "agenttrust.supply-chain-evidence.v1",
            "event_id": event_id,
            "evidence_occurred_at": evidence_requested_at,
            "evidence_requested_at": evidence_requested_at,
            "command_id": request.command.command_id,
            "action_id": request.canonical_action.action_id.0,
            "action_hash": request.binding_action_hash()?,
            "operation": request.command.operation,
            "resource_key": request.command.resource_key,
            "result_digest": result_digest,
            "policy_decision_id": request.binding.policy_decision_id,
            "policy_decision_digest": request.binding.policy_decision_digest,
            "authorization_evidence_ref": request.binding.authorization_evidence_ref,
            "authorization_evidence_digest": request.binding.authorization_evidence_digest,
            "ledger_execution_id": request.binding.ledger_execution_id,
            "ledger_event_id": request.binding.ledger_event_id,
            "ledger_event_digest": request.binding.ledger_event_digest,
            "fence_digest": request.binding.fence_digest,
            "tenant_id": request.command.tenant_id,
            "task_id": request.command.task_id,
            "actor_subject": request.actor_subject,
            "trace_id": request.binding.trace_id,
            "runtime_receipt": receipt,
        });
        let payload_digest = canonical_digest(&event_payload)?;
        let previous = sqlx::query_scalar::<_, String>(
            "SELECT event_digest FROM public.supply_chain_evidence_events
             WHERE tenant_id=$1 ORDER BY created_at DESC,event_id DESC LIMIT 1",
        )
        .bind(request.command.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        let event_digest = sha256(
            format!(
                "{}:{}",
                previous.as_deref().unwrap_or("GENESIS"),
                payload_digest
            )
            .as_bytes(),
        );
        sqlx::query(
            "INSERT INTO public.supply_chain_evidence_events
             (tenant_id,event_id,command_id,action_id,execution_id,event_type,subject_digest,payload,
              payload_digest,previous_event_digest,event_digest,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())",
        )
        .bind(request.command.tenant_id)
        .bind(event_id)
        .bind(request.command.command_id)
        .bind(request.command.command_id)
        .bind(request.binding.ledger_execution_id)
        .bind(format!("SUPPLY_CHAIN_{}", request.command.operation.as_str()))
        .bind(sha256(request.command.resource_key.as_bytes()))
        .bind(&event_payload)
        .bind(&payload_digest)
        .bind(previous)
        .bind(&event_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::StateConflict)?;
        let evidence_ref = format!("evidence://supply-chain/{event_id}");
        let outbox_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO public.supply_chain_evidence_outbox
             (tenant_id,outbox_id,command_id,idempotency_key,destination,payload,payload_digest,created_at)
             VALUES ($1,$2,$3,$4,'EVIDENCE_AUTHORITY',$5,$6,now())",
        )
        .bind(request.command.tenant_id)
        .bind(outbox_id)
        .bind(request.command.command_id)
        .bind(format!("supply-evidence:{}", request.command.command_id))
        .bind(&event_payload)
        .bind(&payload_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::StateConflict)?;
        let affected = sqlx::query(
            "UPDATE public.supply_chain_authority_commands SET state='SUCCEEDED',effect_receipt=$3,
             result_digest=$4,evidence_ref=$5,evidence_digest=$6,updated_at=now()
             WHERE tenant_id=$1 AND command_id=$2 AND state='EXECUTING'",
        )
        .bind(request.command.tenant_id)
        .bind(request.command.command_id)
        .bind(&receipt_value)
        .bind(&result_digest)
        .bind(&evidence_ref)
        .bind(&event_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::StateConflict)?
        .rows_affected();
        if affected != 1 {
            return Err(SupplyAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::OutcomeUnknown)?;
        Ok(SupplyMutationResult {
            schema_version: SUPPLY_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            state: "SUCCEEDED".into(),
            resource_key: request.command.resource_key.clone(),
            resource_version: request.binding.resource_version,
            result_digest: Some(result_digest),
            evidence_ref: Some(evidence_ref),
            evidence_digest: Some(event_digest),
            stable_error: None,
            effect_receipt: Some(receipt.clone()),
        })
    }

    async fn finish_uncertain(
        &self,
        request: &SupplyExecutionRequest,
        state: &str,
        stable_error: &str,
    ) -> Result<(), SupplyAuthorityError> {
        if !matches!(state, "FAILED" | "UNKNOWN") || !identifier(stable_error, 128) {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
        let mut tx = self.begin_tenant(request.command.tenant_id).await?;
        let affected=sqlx::query(
            "UPDATE public.supply_chain_authority_commands SET state=$3,stable_error=$4,updated_at=now()
             WHERE tenant_id=$1 AND command_id=$2 AND state='EXECUTING'",
        )
        .bind(request.command.tenant_id)
        .bind(request.command.command_id)
        .bind(state)
        .bind(stable_error)
        .execute(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::OutcomeUnknown)?.rows_affected();
        if affected != 1 {
            return Err(SupplyAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::OutcomeUnknown)
    }

    pub async fn recover_expired(
        &self,
        tenant: Uuid,
        limit: i64,
    ) -> Result<u64, SupplyAuthorityError> {
        if !(1..=1000).contains(&limit) {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT tenant_id,command_id FROM public.supply_chain_authority_commands
             WHERE tenant_id=$1 AND state='EXECUTING' AND lease_expires_at<now()
             ORDER BY lease_expires_at LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(tenant)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        for row in &rows {
            sqlx::query(
                "UPDATE public.supply_chain_authority_commands
                 SET state='UNKNOWN',stable_error='SUPPLY_CHAIN_LEASE_EXPIRED',updated_at=now()
                 WHERE tenant_id=$1 AND command_id=$2 AND state='EXECUTING'",
            )
            .bind(row.get::<Uuid, _>("tenant_id"))
            .bind(row.get::<Uuid, _>("command_id"))
            .execute(&mut *tx)
            .await
            .map_err(|_| SupplyAuthorityError::OutcomeUnknown)?;
        }
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::OutcomeUnknown)?;
        u64::try_from(rows.len()).map_err(|_| SupplyAuthorityError::DependencyUnavailable)
    }

    async fn pending_evidence(
        &self,
        tenant: Uuid,
        limit: i64,
    ) -> Result<Vec<PendingEvidence>, SupplyAuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
        let mut tx = self.begin_tenant(tenant).await?;
        let rows=sqlx::query("SELECT outbox_id,idempotency_key,payload,payload_digest FROM public.supply_chain_evidence_outbox
            WHERE tenant_id=$1 AND delivered_at IS NULL ORDER BY created_at LIMIT $2")
            .bind(tenant).bind(limit).fetch_all(&mut *tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
        Ok(rows
            .into_iter()
            .map(|row| PendingEvidence {
                outbox_id: row.get("outbox_id"),
                idempotency_key: row.get("idempotency_key"),
                payload: row.get("payload"),
                payload_digest: row.get("payload_digest"),
            })
            .collect())
    }

    async fn mark_evidence_delivered(
        &self,
        tenant: Uuid,
        outbox_id: Uuid,
        payload_digest: &str,
        delivery: &AuthorityEvidenceDelivery,
    ) -> Result<(), SupplyAuthorityError> {
        if !digest(payload_digest)
            || !digest(&delivery.evidence_digest)
            || !reference(&delivery.evidence_ref, 2048)
        {
            return Err(SupplyAuthorityError::ReceiptInvalid);
        }
        let mut tx = self.begin_tenant(tenant).await?;
        let affected=sqlx::query("UPDATE public.supply_chain_evidence_outbox SET delivered_at=now(),delivery_receipt_digest=$4,delivery_evidence_ref=$5
            WHERE tenant_id=$1 AND outbox_id=$2 AND payload_digest=$3 AND delivered_at IS NULL")
            .bind(tenant).bind(outbox_id).bind(payload_digest).bind(&delivery.evidence_digest).bind(&delivery.evidence_ref).execute(&mut *tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?.rows_affected();
        if affected != 1 {
            return Err(SupplyAuthorityError::StateConflict);
        }
        tx.commit()
            .await
            .map_err(|_| SupplyAuthorityError::DependencyUnavailable)
    }
}

#[derive(Clone)]
pub struct SupplyChainAuthority {
    store: PostgresSupplyChainStore,
    runtime: Arc<dyn SupplyChainRuntimePort>,
    receipt_keyring: SupplyReceiptKeyring,
    instance_id: Uuid,
    lease_seconds: i64,
}

impl SupplyChainAuthority {
    pub fn new(
        store: PostgresSupplyChainStore,
        runtime: Arc<dyn SupplyChainRuntimePort>,
        receipt_keyring: SupplyReceiptKeyring,
        instance_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Self, SupplyAuthorityError> {
        if !(15..=300).contains(&lease_seconds) || instance_id.is_nil() {
            return Err(SupplyAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            runtime,
            receipt_keyring,
            instance_id,
            lease_seconds,
        })
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.runtime.ready().await
    }

    pub async fn execute(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        let now = Utc::now();
        let action_hash = request.validate(now)?;
        let request_digest = canonical_digest(&request)?;
        if let Some(result) = self
            .store
            .prepare_and_claim(
                &request,
                &request_digest,
                &action_hash,
                self.instance_id,
                self.lease_seconds,
            )
            .await?
        {
            return Ok(result);
        }
        let receipt = match self
            .runtime
            .execute(&request, &request_digest, &action_hash)
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                let state = if request.command.operation.requires_external_effect() {
                    "UNKNOWN"
                } else {
                    "FAILED"
                };
                let stable = if state == "UNKNOWN" {
                    "SUPPLY_CHAIN_EXTERNAL_OUTCOME_UNKNOWN"
                } else {
                    error.code()
                };
                self.store.finish_uncertain(&request, state, stable).await?;
                return Err(if state == "UNKNOWN" {
                    SupplyAuthorityError::OutcomeUnknown
                } else {
                    error
                });
            }
        };
        if let Err(error) =
            self.receipt_keyring
                .verify(&receipt, &request, &request_digest, Utc::now())
        {
            self.store
                .finish_uncertain(&request, "UNKNOWN", "SUPPLY_CHAIN_RECEIPT_INVALID")
                .await?;
            return Err(error);
        }
        let result = match self
            .store
            .commit_success(&request, &request_digest, &receipt)
            .await
        {
            Ok(result) => result,
            Err(_) => {
                // The runtime receipt proves an effect may already have happened. Any failure
                // while reconciling that receipt with the authoritative database is therefore
                // ambiguous; never expose it as a safe-to-retry validation/state error.
                let _ = self
                    .store
                    .finish_uncertain(&request, "UNKNOWN", "SUPPLY_CHAIN_COMMIT_OUTCOME_UNKNOWN")
                    .await;
                return Err(SupplyAuthorityError::OutcomeUnknown);
            }
        };
        let _ = self.flush_evidence(request.command.tenant_id, 32).await;
        Ok(result)
    }

    pub async fn recover_expired(
        &self,
        tenant: Uuid,
        limit: i64,
    ) -> Result<u64, SupplyAuthorityError> {
        self.store.recover_expired(tenant, limit).await
    }

    pub async fn authoritative_releases(
        &self,
        tenant: Uuid,
        limit: i64,
        cursor: Option<&str>,
    ) -> Result<AuthoritativeReleasePage, SupplyAuthorityError> {
        self.store
            .authoritative_releases(tenant, limit, cursor)
            .await
    }

    pub async fn flush_evidence(
        &self,
        tenant: Uuid,
        limit: i64,
    ) -> Result<u64, SupplyAuthorityError> {
        let pending = self.store.pending_evidence(tenant, limit).await?;
        let mut delivered = 0u64;
        for event in pending {
            let receipt = self
                .runtime
                .deliver_evidence(
                    tenant,
                    &event.idempotency_key,
                    &event.payload,
                    &event.payload_digest,
                )
                .await?;
            self.store
                .mark_evidence_delivered(tenant, event.outbox_id, &event.payload_digest, &receipt)
                .await?;
            delivered = delivered.saturating_add(1);
        }
        Ok(delivered)
    }
}

fn require_operation(
    request: &SupplyExecutionRequest,
    expected: SupplyOperation,
) -> Result<(), SupplyAuthorityError> {
    if request.command.operation != expected {
        return Err(SupplyAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_supply_payload(
    operation: SupplyOperation,
    value: &Value,
    requested_at: DateTime<Utc>,
) -> Result<String, SupplyAuthorityError> {
    let body = value
        .as_object()
        .ok_or(SupplyAuthorityError::RequestInvalid)?;
    match operation {
        SupplyOperation::Publish => {
            exact_keys(
                body,
                &[
                    "manifest",
                    "artifact_id",
                    "artifact_digest",
                    "immutable_reference",
                    "sbom_format",
                    "sbom_digest",
                    "component_count",
                    "provenance_digest",
                    "source_repository",
                    "source_commit",
                    "builder_identity",
                    "build_definition_digest",
                    "license_report_digest",
                    "vulnerability_report_digest",
                    "maximum_vulnerability",
                    "dependency_lock",
                ],
                &[],
            )?;
            let manifest: DomainPackManifest = serde_json::from_value(
                body.get("manifest")
                    .cloned()
                    .ok_or(SupplyAuthorityError::RequestInvalid)?,
            )
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            PackSdk::validate(&manifest).map_err(map_pack_error)?;
            let artifact_digest = string_field(body, "artifact_digest", 64)?;
            let immutable = string_field(body, "immutable_reference", 2048)?;
            let maximum = string_field(body, "maximum_vulnerability", 16)?;
            if artifact_digest != manifest.digest
                || !digest(&artifact_digest)
                || uuid_field(body, "artifact_id")?.is_nil()
                || !immutable.contains(&format!("sha256:{artifact_digest}"))
                || immutable.to_ascii_lowercase().contains("latest")
                || !matches!(
                    string_field(body, "sbom_format", 32)?.as_str(),
                    "SPDX_JSON" | "CYCLONEDX_JSON"
                )
                || i32_field(body, "component_count", 1, 1_000_000)?.is_negative()
                || !matches!(maximum.as_str(), "NONE" | "LOW" | "MEDIUM")
                || !https_reference(&string_field(body, "source_repository", 1024)?)
                || !identifier(&string_field(body, "source_commit", 128)?, 128)
                || !identifier(&string_field(body, "builder_identity", 1024)?, 1024)
            {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            for key in [
                "sbom_digest",
                "provenance_digest",
                "build_definition_digest",
                "license_report_digest",
                "vulnerability_report_digest",
            ] {
                if !digest(&string_field(body, key, 64)?) {
                    return Err(SupplyAuthorityError::RequestInvalid);
                }
            }
            validate_dependency_lock(
                body.get("dependency_lock")
                    .ok_or(SupplyAuthorityError::RequestInvalid)?,
            )?;
            Ok(format!(
                "pack-release:{}@{}",
                manifest.pack_id, manifest.version
            ))
        }
        SupplyOperation::Validate => {
            exact_keys(
                body,
                &[
                    "run_id",
                    "pack_id",
                    "version",
                    "sandbox_profile_digest",
                    "schema_report_digest",
                    "dependency_report_digest",
                    "vulnerability_report_digest",
                    "license_report_digest",
                    "behavior_report_digest",
                    "threat_report_digest",
                    "network_violation_count",
                    "conclusion",
                    "runner_identity",
                ],
                &[],
            )?;
            uuid_field(body, "run_id")?;
            let pack_id = string_field(body, "pack_id", 256)?;
            let version = string_field(body, "version", 128)?;
            for key in [
                "sandbox_profile_digest",
                "schema_report_digest",
                "dependency_report_digest",
                "vulnerability_report_digest",
                "license_report_digest",
                "behavior_report_digest",
                "threat_report_digest",
            ] {
                if !digest(&string_field(body, key, 64)?) {
                    return Err(SupplyAuthorityError::RequestInvalid);
                }
            }
            if !valid_semver_string(&version)
                || !matches!(
                    string_field(body, "conclusion", 16)?.as_str(),
                    "PASS" | "FAIL" | "INCONCLUSIVE"
                )
                || !identifier(&string_field(body, "runner_identity", 512)?, 512)
            {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            i32_field(body, "network_violation_count", 0, 1_000_000)?;
            Ok(format!("pack-release:{pack_id}@{version}"))
        }
        SupplyOperation::Approve => {
            exact_keys(
                body,
                &[
                    "approval_id",
                    "pack_id",
                    "version",
                    "manifest_digest",
                    "permission_diff",
                    "permission_expansion_reviewed",
                    "environment",
                    "approver_role",
                    "principal_assertion_digest",
                    "evidence_ref",
                    "evidence_digest",
                    "expires_at",
                ],
                &["previous_manifest_digest"],
            )?;
            uuid_field(body, "approval_id")?;
            let pack_id = string_field(body, "pack_id", 256)?;
            let version = string_field(body, "version", 128)?;
            serde_json::from_value::<PermissionDiff>(
                body.get("permission_diff")
                    .cloned()
                    .ok_or(SupplyAuthorityError::RequestInvalid)?,
            )
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            let expires = datetime_field(body, "expires_at")?;
            if !valid_semver_string(&version)
                || !digest(&string_field(body, "manifest_digest", 64)?)
                || optional_string_field(body, "previous_manifest_digest", 64)?
                    .is_some_and(|value| !digest(&value))
                || body
                    .get("permission_expansion_reviewed")
                    .and_then(Value::as_bool)
                    .is_none()
                || string_field(body, "environment", 64)? != "production"
                || !identifier(&string_field(body, "approver_role", 256)?, 256)
                || !digest(&string_field(body, "principal_assertion_digest", 64)?)
                || !reference(&string_field(body, "evidence_ref", 1024)?, 1024)
                || !digest(&string_field(body, "evidence_digest", 64)?)
                || expires <= requested_at
                || expires > requested_at + Duration::days(366)
            {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            Ok(format!("pack-release:{pack_id}@{version}"))
        }
        SupplyOperation::Activate => {
            exact_keys(
                body,
                &[
                    "pack_id",
                    "version",
                    "environment",
                    "manifest_digest",
                    "approval_id",
                ],
                &[],
            )?;
            let pack_id = string_field(body, "pack_id", 256)?;
            let version = string_field(body, "version", 128)?;
            let environment = string_field(body, "environment", 64)?;
            if !valid_semver_string(&version)
                || environment != "production"
                || !digest(&string_field(body, "manifest_digest", 64)?)
                || uuid_field(body, "approval_id")?.is_nil()
            {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            Ok(format!("pack-installation:{environment}:{pack_id}"))
        }
        SupplyOperation::Rollback => {
            exact_keys(body, &["pack_id", "environment"], &[])?;
            let pack_id = string_field(body, "pack_id", 256)?;
            let environment = string_field(body, "environment", 64)?;
            if environment != "production" {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            Ok(format!("pack-installation:{environment}:{pack_id}"))
        }
        SupplyOperation::Revoke | SupplyOperation::Quarantine => {
            exact_keys(
                body,
                &[
                    "revocation_id",
                    "scope",
                    "subject_id",
                    "reason_code",
                    "running_task_disposition",
                    "impact_digest",
                ],
                &[
                    "subject_digest",
                    "publisher_id",
                    "key_id",
                    "pack_id",
                    "version",
                ],
            )?;
            uuid_field(body, "revocation_id")?;
            let scope = string_field(body, "scope", 24)?;
            let subject = string_field(body, "subject_id", 640)?;
            if !matches!(
                string_field(body, "running_task_disposition", 20)?.as_str(),
                "PAUSE" | "KILL" | "ALLOW_TO_FINISH"
            ) || !identifier(&string_field(body, "reason_code", 128)?, 128)
                || !digest(&string_field(body, "impact_digest", 64)?)
                || optional_string_field(body, "subject_digest", 64)?
                    .is_some_and(|value| !digest(&value))
            {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            match scope.as_str() {
                "PUBLISHER" => {
                    let publisher = string_field(body, "publisher_id", 256)?;
                    if subject != publisher
                        || body.contains_key("key_id")
                        || body.contains_key("pack_id")
                        || body.contains_key("version")
                    {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                }
                "KEY" => {
                    let publisher = string_field(body, "publisher_id", 256)?;
                    let key = string_field(body, "key_id", 256)?;
                    if subject != format!("{publisher}#{key}")
                        || body.contains_key("pack_id")
                        || body.contains_key("version")
                    {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                }
                "ARTIFACT" => {
                    if !Uuid::parse_str(&subject).is_ok_and(|value| value.to_string() == subject)
                        || body.contains_key("publisher_id")
                        || body.contains_key("key_id")
                        || body.contains_key("pack_id")
                        || body.contains_key("version")
                    {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                }
                "PACK_RELEASE" => {
                    let pack = string_field(body, "pack_id", 256)?;
                    let version = string_field(body, "version", 128)?;
                    if subject != format!("{pack}@{version}")
                        || !valid_semver_string(&version)
                        || body.contains_key("publisher_id")
                        || body.contains_key("key_id")
                    {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                }
                _ => return Err(SupplyAuthorityError::RequestInvalid),
            }
            Ok(format!("supply-revocation:{scope}:{subject}"))
        }
        SupplyOperation::Recover => {
            exact_keys(body, &["unknown_command_id"], &[])?;
            let command = uuid_field(body, "unknown_command_id")?;
            Ok(format!("supply-command:{command}"))
        }
    }
}

#[async_trait]
impl PackRegistry for SupplyChainAuthority {
    async fn publish(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Publish)?;
        self.execute(request).await
    }
    async fn approve(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Approve)?;
        self.execute(request).await
    }
    async fn activate(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Activate)?;
        self.execute(request).await
    }
    async fn revoke(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Revoke)?;
        self.execute(request).await
    }
}

#[async_trait]
impl PackInstaller for SupplyChainAuthority {
    async fn install(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Activate)?;
        self.execute(request).await
    }
    async fn rollback(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Rollback)?;
        self.execute(request).await
    }
}

#[async_trait]
impl RevocationService for SupplyChainAuthority {
    async fn quarantine(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Quarantine)?;
        self.execute(request).await
    }
    async fn revoke_release(
        &self,
        request: SupplyExecutionRequest,
    ) -> Result<SupplyMutationResult, SupplyAuthorityError> {
        require_operation(&request, SupplyOperation::Revoke)?;
        self.execute(request).await
    }
}

async fn apply_mutation(
    tx: &mut Transaction<'_, Postgres>,
    request: &SupplyExecutionRequest,
    receipt: &SupplyRuntimeReceipt,
) -> Result<(), SupplyAuthorityError> {
    let tenant = request.command.tenant_id;
    let body = request
        .command
        .safe_payload
        .as_object()
        .ok_or(SupplyAuthorityError::RequestInvalid)?;
    match request.command.operation {
        SupplyOperation::Publish => {
            exact_keys(
                body,
                &[
                    "manifest",
                    "artifact_id",
                    "artifact_digest",
                    "immutable_reference",
                    "sbom_format",
                    "sbom_digest",
                    "component_count",
                    "provenance_digest",
                    "source_repository",
                    "source_commit",
                    "builder_identity",
                    "build_definition_digest",
                    "license_report_digest",
                    "vulnerability_report_digest",
                    "maximum_vulnerability",
                    "dependency_lock",
                ],
                &[],
            )?;
            let manifest: DomainPackManifest = serde_json::from_value(
                body.get("manifest")
                    .cloned()
                    .ok_or(SupplyAuthorityError::RequestInvalid)?,
            )
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            let artifact_id = uuid_field(body, "artifact_id")?;
            let artifact_digest = string_field(body, "artifact_digest", 64)?;
            if artifact_digest != manifest.digest
                || receipt.repository_receipt_digest.is_none()
                || receipt.signature_receipt_digest.is_none()
                || receipt.sbom_receipt_digest.is_none()
                || receipt.vulnerability_receipt_digest.is_none()
                || receipt.license_receipt_digest.is_none()
            {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
            let permission_digest = canonical_digest(&manifest.permissions)?;
            let manifest_value = serde_json::to_value(&manifest)
                .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            sqlx::query(
                "INSERT INTO public.supply_chain_artifact_revisions
                 (tenant_id,artifact_id,artifact_type,name,version,artifact_digest,immutable_reference,
                  publisher_id,publisher_key_id,sbom_format,sbom_digest,component_count,provenance_digest,
                  source_repository,source_commit,builder_identity,build_definition_digest,
                  signature_envelope,signature_digest,license_report_digest,vulnerability_report_digest,
                  maximum_vulnerability,compatibility,status)
                 VALUES ($1,$2,'DOMAIN_PACK',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,'VERIFIED')",
            )
            .bind(tenant).bind(artifact_id).bind(&manifest.pack_id).bind(&manifest.version)
            .bind(&manifest.digest).bind(string_field(body,"immutable_reference",2048)?)
            .bind(&manifest.publisher_identity).bind(&manifest.signature.key_id)
            .bind(string_field(body,"sbom_format",32)?).bind(string_field(body,"sbom_digest",64)?)
            .bind(i32_field(body,"component_count",1,1_000_000)?)
            .bind(string_field(body,"provenance_digest",64)?).bind(string_field(body,"source_repository",1024)?)
            .bind(string_field(body,"source_commit",128)?).bind(string_field(body,"builder_identity",1024)?)
            .bind(string_field(body,"build_definition_digest",64)?).bind(serde_json::to_value(&manifest.signature).map_err(|_| SupplyAuthorityError::RequestInvalid)?)
            .bind(canonical_digest(&manifest.signature)?).bind(string_field(body,"license_report_digest",64)?)
            .bind(string_field(body,"vulnerability_report_digest",64)?).bind(string_field(body,"maximum_vulnerability",16)?)
            .bind(serde_json::to_value(&manifest.compatibility).map_err(|_| SupplyAuthorityError::RequestInvalid)?)
            .execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?;
            let dependency_lock = body
                .get("dependency_lock")
                .cloned()
                .ok_or(SupplyAuthorityError::RequestInvalid)?;
            validate_dependency_lock(&dependency_lock)?;
            let dependency_digest = canonical_digest(&dependency_lock)?;
            sqlx::query(
                "INSERT INTO public.supply_chain_pack_releases
                 (tenant_id,pack_id,version,artifact_id,manifest,manifest_digest,permission_digest,
                  dependency_lock,dependency_lock_digest,lifecycle_state,resource_version)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'PUBLISHED',$10)",
            )
            .bind(tenant)
            .bind(&manifest.pack_id)
            .bind(&manifest.version)
            .bind(artifact_id)
            .bind(&manifest_value)
            .bind(&manifest.digest)
            .bind(permission_digest)
            .bind(dependency_lock)
            .bind(dependency_digest)
            .bind(
                i64::try_from(request.binding.resource_version)
                    .map_err(|_| SupplyAuthorityError::RequestInvalid)?,
            )
            .execute(&mut **tx)
            .await
            .map_err(|_| SupplyAuthorityError::StateConflict)?;
        }
        SupplyOperation::Validate => {
            exact_keys(
                body,
                &[
                    "run_id",
                    "pack_id",
                    "version",
                    "sandbox_profile_digest",
                    "schema_report_digest",
                    "dependency_report_digest",
                    "vulnerability_report_digest",
                    "license_report_digest",
                    "behavior_report_digest",
                    "threat_report_digest",
                    "network_violation_count",
                    "conclusion",
                    "runner_identity",
                ],
                &[],
            )?;
            if receipt.sandbox_receipt_digest.is_none()
                || receipt.vulnerability_receipt_digest.is_none()
                || receipt.license_receipt_digest.is_none()
            {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
            let conclusion = string_field(body, "conclusion", 16)?;
            if !matches!(conclusion.as_str(), "PASS" | "FAIL" | "INCONCLUSIVE") {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            sqlx::query(
                "INSERT INTO public.supply_chain_conformance_runs
                 (tenant_id,run_id,pack_id,version,sandbox_profile_digest,schema_report_digest,
                  dependency_report_digest,vulnerability_report_digest,license_report_digest,
                  behavior_report_digest,threat_report_digest,network_violation_count,conclusion,
                  runner_identity,completed_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            )
            .bind(tenant)
            .bind(uuid_field(body, "run_id")?)
            .bind(string_field(body, "pack_id", 256)?)
            .bind(string_field(body, "version", 128)?)
            .bind(string_field(body, "sandbox_profile_digest", 64)?)
            .bind(string_field(body, "schema_report_digest", 64)?)
            .bind(string_field(body, "dependency_report_digest", 64)?)
            .bind(string_field(body, "vulnerability_report_digest", 64)?)
            .bind(string_field(body, "license_report_digest", 64)?)
            .bind(string_field(body, "behavior_report_digest", 64)?)
            .bind(string_field(body, "threat_report_digest", 64)?)
            .bind(i32_field(body, "network_violation_count", 0, 1_000_000)?)
            .bind(&conclusion)
            .bind(string_field(body, "runner_identity", 512)?)
            .bind(request.command.requested_at)
            .execute(&mut **tx)
            .await
            .map_err(|_| SupplyAuthorityError::StateConflict)?;
            if conclusion == "PASS" {
                let affected=sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state='VALIDATED',resource_version=resource_version+1,updated_at=now() WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND lifecycle_state='PUBLISHED' AND resource_version=$4")
                    .bind(tenant).bind(string_field(body,"pack_id",256)?).bind(string_field(body,"version",128)?)
                    .bind(i64::try_from(request.command.expected_resource_version).map_err(|_|SupplyAuthorityError::RequestInvalid)?)
                    .execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
                if affected != 1 {
                    return Err(SupplyAuthorityError::StateConflict);
                }
            }
        }
        SupplyOperation::Approve => {
            exact_keys(
                body,
                &[
                    "approval_id",
                    "pack_id",
                    "version",
                    "manifest_digest",
                    "permission_diff",
                    "permission_expansion_reviewed",
                    "environment",
                    "approver_role",
                    "principal_assertion_digest",
                    "evidence_ref",
                    "evidence_digest",
                    "expires_at",
                ],
                &["previous_manifest_digest"],
            )?;
            let permission_diff: PermissionDiff = serde_json::from_value(
                body.get("permission_diff")
                    .cloned()
                    .ok_or(SupplyAuthorityError::RequestInvalid)?,
            )
            .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            let pack_id = string_field(body, "pack_id", 256)?;
            let version = string_field(body, "version", 128)?;
            let manifest_digest = string_field(body, "manifest_digest", 64)?;
            let environment = string_field(body, "environment", 64)?;
            let current_manifest_value:Value=sqlx::query_scalar("SELECT manifest FROM public.supply_chain_pack_releases
                WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND manifest_digest=$4 AND lifecycle_state='VALIDATED' AND resource_version=$5 FOR UPDATE")
                .bind(tenant).bind(&pack_id).bind(&version).bind(&manifest_digest)
                .bind(i64::try_from(request.command.expected_resource_version).map_err(|_|SupplyAuthorityError::RequestInvalid)?)
                .fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?.ok_or(SupplyAuthorityError::StateConflict)?;
            let current_manifest: DomainPackManifest =
                serde_json::from_value(current_manifest_value)
                    .map_err(|_| SupplyAuthorityError::StateConflict)?;
            let previous=sqlx::query("SELECT r.manifest_digest,r.manifest
                FROM public.supply_chain_pack_releases r
                JOIN public.supply_chain_pack_approvals a ON a.tenant_id=r.tenant_id AND a.pack_id=r.pack_id
                  AND a.version=r.version AND a.manifest_digest=r.manifest_digest
                WHERE r.tenant_id=$1 AND r.pack_id=$2 AND r.manifest_digest<>$3 AND a.environment=$4
                ORDER BY a.approved_at DESC,a.approval_id DESC LIMIT 1")
                .bind(tenant).bind(&pack_id).bind(&manifest_digest).bind(&environment)
                .fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
            let declared_previous = optional_string_field(body, "previous_manifest_digest", 64)?;
            let prior_permissions = if let Some(row) = previous {
                let prior_digest: String = row.get("manifest_digest");
                if declared_previous.as_deref() != Some(prior_digest.as_str()) {
                    return Err(SupplyAuthorityError::ApprovalDenied);
                }
                serde_json::from_value::<DomainPackManifest>(row.get("manifest"))
                    .map_err(|_| SupplyAuthorityError::StateConflict)?
                    .permissions
            } else {
                if declared_previous.is_some() {
                    return Err(SupplyAuthorityError::ApprovalDenied);
                }
                crate::PackPermissionDeclaration::default()
            };
            let computed_diff =
                PermissionDiff::compute(&prior_permissions, &current_manifest.permissions);
            let passed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_conformance_runs WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND conclusion='PASS')")
                .bind(tenant).bind(&pack_id).bind(&version).fetch_one(&mut **tx).await.map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
            if !passed
                || permission_diff != computed_diff
                || (computed_diff.expands_privilege()
                    && body.get("permission_expansion_reviewed") != Some(&Value::Bool(true)))
            {
                return Err(SupplyAuthorityError::ApprovalDenied);
            }
            let diff_value = serde_json::to_value(&permission_diff)
                .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
            sqlx::query("INSERT INTO public.supply_chain_pack_approvals
                (tenant_id,approval_id,pack_id,version,manifest_digest,previous_manifest_digest,
                 permission_diff,permission_diff_digest,environment,decision,approver_subject,approver_role,
                 principal_assertion_digest,evidence_ref,evidence_digest,approved_at,expires_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'APPROVED',$10,$11,$12,$13,$14,$15,$16)")
                .bind(tenant).bind(uuid_field(body,"approval_id")?).bind(&pack_id).bind(&version).bind(&manifest_digest)
                .bind(optional_string_field(body,"previous_manifest_digest",64)?).bind(&diff_value).bind(canonical_digest(&diff_value)?)
                .bind(&environment).bind(&request.actor_subject).bind(string_field(body,"approver_role",256)?)
                .bind(string_field(body,"principal_assertion_digest",64)?).bind(string_field(body,"evidence_ref",1024)?)
                .bind(string_field(body,"evidence_digest",64)?).bind(request.command.requested_at)
                .bind(datetime_field(body,"expires_at")?).execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?;
            let affected=sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state='APPROVED',resource_version=resource_version+1,updated_at=now() WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND manifest_digest=$4 AND lifecycle_state='VALIDATED' AND resource_version=$5")
                .bind(tenant).bind(pack_id).bind(version).bind(manifest_digest)
                .bind(i64::try_from(request.command.expected_resource_version).map_err(|_|SupplyAuthorityError::RequestInvalid)?)
                .execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
            if affected != 1 {
                return Err(SupplyAuthorityError::StateConflict);
            }
        }
        SupplyOperation::Activate => {
            exact_keys(
                body,
                &[
                    "pack_id",
                    "version",
                    "environment",
                    "manifest_digest",
                    "approval_id",
                ],
                &[],
            )?;
            if receipt.installation_receipt_digest.is_none() {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
            let pack_id = string_field(body, "pack_id", 256)?;
            let version = string_field(body, "version", 128)?;
            let environment = string_field(body, "environment", 64)?;
            let manifest_digest = string_field(body, "manifest_digest", 64)?;
            let approval_id = uuid_field(body, "approval_id")?;
            let approval: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_pack_approvals WHERE tenant_id=$1 AND approval_id=$2 AND pack_id=$3 AND version=$4 AND manifest_digest=$5 AND environment=$6 AND decision='APPROVED' AND expires_at>now())")
                .bind(tenant).bind(approval_id).bind(&pack_id).bind(&version).bind(&manifest_digest).bind(&environment)
                .fetch_one(&mut **tx).await.map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
            if !approval {
                return Err(SupplyAuthorityError::ApprovalDenied);
            }
            let installation_affected=sqlx::query("INSERT INTO public.supply_chain_installations
                (tenant_id,environment,pack_id,version,manifest_digest,approval_id,previous_version,
                 previous_manifest_digest,state,resource_version,activated_at,updated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,NULL,NULL,'ACTIVE',$7,now(),now())
                 ON CONFLICT (tenant_id,environment,pack_id) DO UPDATE SET
                 previous_version=supply_chain_installations.version,
                 previous_manifest_digest=supply_chain_installations.manifest_digest,
                 version=EXCLUDED.version,manifest_digest=EXCLUDED.manifest_digest,approval_id=EXCLUDED.approval_id,
                 state='ACTIVE',resource_version=supply_chain_installations.resource_version+1,activated_at=now(),updated_at=now()
                 WHERE supply_chain_installations.resource_version=$8")
                .bind(tenant).bind(&environment).bind(&pack_id).bind(&version).bind(&manifest_digest).bind(approval_id)
                .bind(i64::try_from(request.binding.resource_version).map_err(|_| SupplyAuthorityError::RequestInvalid)?)
                .bind(i64::try_from(request.command.expected_resource_version).map_err(|_|SupplyAuthorityError::RequestInvalid)?)
                .execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
            if installation_affected != 1 {
                return Err(SupplyAuthorityError::StateConflict);
            }
            let affected=sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state='ACTIVE',resource_version=resource_version+1,updated_at=now() WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND manifest_digest=$4 AND lifecycle_state='APPROVED'")
                .bind(tenant).bind(pack_id).bind(version).bind(manifest_digest).execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
            if affected != 1 {
                return Err(SupplyAuthorityError::StateConflict);
            }
        }
        SupplyOperation::Rollback => {
            exact_keys(body, &["pack_id", "environment"], &[])?;
            if receipt.installation_receipt_digest.is_none() {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
            let pack_id = string_field(body, "pack_id", 256)?;
            let environment = string_field(body, "environment", 64)?;
            let installation=sqlx::query("SELECT version,manifest_digest,previous_version,previous_manifest_digest
                FROM public.supply_chain_installations WHERE tenant_id=$1 AND environment=$2 AND pack_id=$3
                  AND state IN ('ACTIVE','PAUSED') AND resource_version=$4 FOR UPDATE")
                .bind(tenant).bind(&environment).bind(&pack_id)
                .bind(i64::try_from(request.command.expected_resource_version).map_err(|_|SupplyAuthorityError::RequestInvalid)?)
                .fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?.ok_or(SupplyAuthorityError::StateConflict)?;
            let current_version: String = installation.get("version");
            let current_manifest: String = installation.get("manifest_digest");
            let target_version: String = installation
                .get::<Option<String>, _>("previous_version")
                .ok_or(SupplyAuthorityError::RecoveryDenied)?;
            let target_manifest: String = installation
                .get::<Option<String>, _>("previous_manifest_digest")
                .ok_or(SupplyAuthorityError::RecoveryDenied)?;
            if target_version == current_version && target_manifest == current_manifest {
                return Err(SupplyAuthorityError::RecoveryDenied);
            }
            let target=sqlx::query("SELECT r.lifecycle_state,a.status AS artifact_status
                FROM public.supply_chain_pack_releases r JOIN public.supply_chain_artifact_revisions a
                  ON a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id
                WHERE r.tenant_id=$1 AND r.pack_id=$2 AND r.version=$3 AND r.manifest_digest=$4
                  AND r.lifecycle_state IN ('APPROVED','ACTIVE','ROLLED_BACK') AND a.status='VERIFIED' FOR UPDATE")
                .bind(tenant).bind(&pack_id).bind(&target_version).bind(&target_manifest)
                .fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?.ok_or(SupplyAuthorityError::RecoveryDenied)?;
            let approval_id:Uuid=sqlx::query_scalar("SELECT approval_id FROM public.supply_chain_pack_approvals
                WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND manifest_digest=$4 AND environment=$5
                  AND decision='APPROVED' AND expires_at>now() ORDER BY approved_at DESC LIMIT 1")
                .bind(tenant).bind(&pack_id).bind(&target_version).bind(&target_manifest).bind(&environment)
                .fetch_optional(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?.ok_or(SupplyAuthorityError::ApprovalDenied)?;
            if target.get::<String, _>("lifecycle_state") != "ACTIVE" {
                let release_affected=sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state='ACTIVE',resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND manifest_digest=$4 AND lifecycle_state IN ('APPROVED','ROLLED_BACK')")
                    .bind(tenant).bind(&pack_id).bind(&target_version).bind(&target_manifest).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?.rows_affected();
                if release_affected != 1 {
                    return Err(SupplyAuthorityError::StateConflict);
                }
            }
            let affected=sqlx::query("UPDATE public.supply_chain_installations SET version=$4,manifest_digest=$5,approval_id=$6,
                previous_version=$7,previous_manifest_digest=$8,state='ACTIVE',resource_version=resource_version+1,activated_at=now(),updated_at=now()
                WHERE tenant_id=$1 AND environment=$2 AND pack_id=$3 AND resource_version=$9 AND state IN ('ACTIVE','PAUSED')")
                .bind(tenant).bind(&environment).bind(&pack_id).bind(&target_version).bind(&target_manifest).bind(approval_id)
                .bind(&current_version).bind(&current_manifest).bind(i64::try_from(request.command.expected_resource_version).map_err(|_|SupplyAuthorityError::RequestInvalid)?)
                .execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?.rows_affected();
            if affected != 1 {
                return Err(SupplyAuthorityError::StateConflict);
            }
            // Keep catalog lifecycle distinct from installation state: the version being
            // replaced is no longer active, while an already quarantined version stays
            // quarantined and cannot be laundered through rollback.
            sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state='ROLLED_BACK',resource_version=resource_version+1,updated_at=now()
                WHERE tenant_id=$1 AND pack_id=$2 AND version=$3 AND manifest_digest=$4 AND lifecycle_state='ACTIVE'")
                .bind(tenant).bind(&pack_id).bind(&current_version).bind(&current_manifest)
                .execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
        }
        SupplyOperation::Revoke | SupplyOperation::Quarantine => {
            exact_keys(
                body,
                &[
                    "revocation_id",
                    "scope",
                    "subject_id",
                    "reason_code",
                    "running_task_disposition",
                    "impact_digest",
                ],
                &[
                    "subject_digest",
                    "publisher_id",
                    "key_id",
                    "pack_id",
                    "version",
                ],
            )?;
            if receipt.revocation_receipt_digest.is_none() {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
            let scope = string_field(body, "scope", 24)?;
            let subject_id = string_field(body, "subject_id", 1024)?;
            let disposition = string_field(body, "running_task_disposition", 20)?;
            if !matches!(
                scope.as_str(),
                "PUBLISHER" | "KEY" | "ARTIFACT" | "PACK_RELEASE"
            ) || !matches!(disposition.as_str(), "PAUSE" | "KILL" | "ALLOW_TO_FINISH")
            {
                return Err(SupplyAuthorityError::RequestInvalid);
            }
            let artifact_state = if request.command.operation == SupplyOperation::Revoke {
                "REVOKED"
            } else {
                "QUARANTINED"
            };
            let release_state = artifact_state;
            let installation_state = if request.command.operation == SupplyOperation::Revoke {
                "REVOKED"
            } else {
                "PAUSED"
            };
            match scope.as_str() {
                "PUBLISHER" => {
                    let publisher_id = string_field(body, "publisher_id", 256)?;
                    if subject_id != publisher_id {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_publishers WHERE publisher_id=$1)")
                        .bind(&publisher_id).fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                    if !exists {
                        return Err(SupplyAuthorityError::PublisherDenied);
                    }
                    propagate_publisher_safety(
                        tx,
                        tenant,
                        &publisher_id,
                        None,
                        artifact_state,
                        release_state,
                        installation_state,
                    )
                    .await?;
                }
                "KEY" => {
                    let publisher_id = string_field(body, "publisher_id", 256)?;
                    let key_id = string_field(body, "key_id", 256)?;
                    if subject_id != format!("{publisher_id}#{key_id}") {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_publisher_keys WHERE publisher_id=$1 AND key_id=$2)")
                        .bind(&publisher_id).bind(&key_id).fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                    if !exists {
                        return Err(SupplyAuthorityError::PublisherDenied);
                    }
                    propagate_publisher_safety(
                        tx,
                        tenant,
                        &publisher_id,
                        Some(&key_id),
                        artifact_state,
                        release_state,
                        installation_state,
                    )
                    .await?;
                }
                "ARTIFACT" => {
                    let artifact_id = Uuid::parse_str(&subject_id)
                        .ok()
                        .filter(|value| value.to_string() == subject_id)
                        .ok_or(SupplyAuthorityError::RequestInvalid)?;
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_artifact_revisions WHERE tenant_id=$1 AND artifact_id=$2)")
                        .bind(tenant).bind(artifact_id).fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                    if !exists {
                        return Err(SupplyAuthorityError::StateConflict);
                    }
                    propagate_artifact_safety(
                        tx,
                        tenant,
                        artifact_id,
                        artifact_state,
                        release_state,
                        installation_state,
                    )
                    .await?;
                }
                "PACK_RELEASE" => {
                    let pack_id = string_field(body, "pack_id", 256)?;
                    let version = string_field(body, "version", 128)?;
                    if subject_id != format!("{pack_id}@{version}") {
                        return Err(SupplyAuthorityError::RequestInvalid);
                    }
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_pack_releases WHERE tenant_id=$1 AND pack_id=$2 AND version=$3)")
                        .bind(tenant).bind(&pack_id).bind(&version).fetch_one(&mut **tx).await.map_err(|_|SupplyAuthorityError::DependencyUnavailable)?;
                    if !exists {
                        return Err(SupplyAuthorityError::StateConflict);
                    }
                    propagate_release_safety(
                        tx,
                        tenant,
                        &pack_id,
                        &version,
                        release_state,
                        installation_state,
                    )
                    .await?;
                }
                _ => return Err(SupplyAuthorityError::RequestInvalid),
            }
            sqlx::query("INSERT INTO public.supply_chain_revocations
                (tenant_id,revocation_id,scope,subject_id,subject_digest,reason_code,running_task_disposition,
                 impact_digest,actor_subject,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())")
                .bind(tenant).bind(uuid_field(body,"revocation_id")?).bind(&scope).bind(&subject_id)
                .bind(optional_string_field(body,"subject_digest",64)?).bind(string_field(body,"reason_code",128)?)
                .bind(disposition).bind(string_field(body,"impact_digest",64)?).bind(&request.actor_subject)
                .execute(&mut **tx).await.map_err(|_| SupplyAuthorityError::StateConflict)?;
        }
        SupplyOperation::Recover => {
            exact_keys(body, &["unknown_command_id"], &[])?;
            if receipt.reconciliation_receipt_digest.is_none() {
                return Err(SupplyAuthorityError::ReceiptInvalid);
            }
            let unknown_command_id = uuid_field(body, "unknown_command_id")?;
            let state: Option<String>=sqlx::query_scalar("SELECT state FROM public.supply_chain_authority_commands WHERE tenant_id=$1 AND command_id=$2")
                .bind(tenant).bind(unknown_command_id).fetch_optional(&mut **tx).await.map_err(|_| SupplyAuthorityError::DependencyUnavailable)?;
            if state.as_deref() != Some("UNKNOWN") {
                return Err(SupplyAuthorityError::RecoveryDenied);
            }
        }
    }
    Ok(())
}

async fn propagate_publisher_safety(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    publisher_id: &str,
    key_id: Option<&str>,
    artifact_state: &str,
    release_state: &str,
    installation_state: &str,
) -> Result<(), SupplyAuthorityError> {
    sqlx::query(
        "UPDATE public.supply_chain_artifact_revisions SET status=$4
        WHERE tenant_id=$1 AND publisher_id=$2 AND ($3::text IS NULL OR publisher_key_id=$3)
          AND (($4='REVOKED' AND status<>'REVOKED') OR ($4='QUARANTINED' AND status='VERIFIED'))",
    )
    .bind(tenant)
    .bind(publisher_id)
    .bind(key_id)
    .bind(artifact_state)
    .execute(&mut **tx)
    .await
    .map_err(|_| SupplyAuthorityError::StateConflict)?;
    sqlx::query("UPDATE public.supply_chain_pack_releases r SET lifecycle_state=$4,resource_version=r.resource_version+1,updated_at=now()
        FROM public.supply_chain_artifact_revisions a
        WHERE r.tenant_id=$1 AND a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id AND a.publisher_id=$2
          AND ($3::text IS NULL OR a.publisher_key_id=$3)
          AND (($4='REVOKED' AND r.lifecycle_state<>'REVOKED') OR ($4='QUARANTINED' AND r.lifecycle_state NOT IN ('QUARANTINED','REVOKED','ROLLED_BACK')))")
        .bind(tenant).bind(publisher_id).bind(key_id).bind(release_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    sqlx::query("UPDATE public.supply_chain_installations i SET state=$4,resource_version=i.resource_version+1,updated_at=now()
        WHERE i.tenant_id=$1 AND (($4='REVOKED' AND i.state<>'REVOKED') OR ($4='PAUSED' AND i.state='ACTIVE'))
          AND EXISTS(SELECT 1 FROM public.supply_chain_pack_releases r JOIN public.supply_chain_artifact_revisions a
              ON a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id
             WHERE r.tenant_id=i.tenant_id AND r.pack_id=i.pack_id AND r.version=i.version
               AND a.publisher_id=$2 AND ($3::text IS NULL OR a.publisher_key_id=$3))")
        .bind(tenant).bind(publisher_id).bind(key_id).bind(installation_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    Ok(())
}

async fn propagate_artifact_safety(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    artifact_id: Uuid,
    artifact_state: &str,
    release_state: &str,
    installation_state: &str,
) -> Result<(), SupplyAuthorityError> {
    sqlx::query("UPDATE public.supply_chain_artifact_revisions SET status=$3 WHERE tenant_id=$1 AND artifact_id=$2
          AND (($3='REVOKED' AND status<>'REVOKED') OR ($3='QUARANTINED' AND status='VERIFIED'))")
        .bind(tenant).bind(artifact_id).bind(artifact_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state=$3,resource_version=resource_version+1,updated_at=now()
        WHERE tenant_id=$1 AND artifact_id=$2
          AND (($3='REVOKED' AND lifecycle_state<>'REVOKED') OR ($3='QUARANTINED' AND lifecycle_state NOT IN ('QUARANTINED','REVOKED','ROLLED_BACK')))")
        .bind(tenant).bind(artifact_id).bind(release_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    sqlx::query("UPDATE public.supply_chain_installations i SET state=$3,resource_version=i.resource_version+1,updated_at=now()
        WHERE i.tenant_id=$1 AND (($3='REVOKED' AND i.state<>'REVOKED') OR ($3='PAUSED' AND i.state='ACTIVE'))
          AND EXISTS(SELECT 1 FROM public.supply_chain_pack_releases r WHERE r.tenant_id=i.tenant_id
              AND r.pack_id=i.pack_id AND r.version=i.version AND r.artifact_id=$2)")
        .bind(tenant).bind(artifact_id).bind(installation_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    Ok(())
}

async fn propagate_release_safety(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    pack_id: &str,
    version: &str,
    release_state: &str,
    installation_state: &str,
) -> Result<(), SupplyAuthorityError> {
    sqlx::query("UPDATE public.supply_chain_pack_releases SET lifecycle_state=$4,resource_version=resource_version+1,updated_at=now()
        WHERE tenant_id=$1 AND pack_id=$2 AND version=$3
          AND (($4='REVOKED' AND lifecycle_state<>'REVOKED') OR ($4='QUARANTINED' AND lifecycle_state NOT IN ('QUARANTINED','REVOKED','ROLLED_BACK')))")
        .bind(tenant).bind(pack_id).bind(version).bind(release_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    sqlx::query("UPDATE public.supply_chain_installations SET state=$4,resource_version=resource_version+1,updated_at=now()
        WHERE tenant_id=$1 AND pack_id=$2 AND version=$3
          AND (($4='REVOKED' AND state<>'REVOKED') OR ($4='PAUSED' AND state='ACTIVE'))")
        .bind(tenant).bind(pack_id).bind(version).bind(installation_state).execute(&mut **tx).await.map_err(|_|SupplyAuthorityError::StateConflict)?;
    Ok(())
}

fn result_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<SupplyMutationResult, SupplyAuthorityError> {
    let receipt = row
        .try_get::<Value, _>("effect_receipt")
        .ok()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| SupplyAuthorityError::StateConflict)?;
    Ok(SupplyMutationResult {
        schema_version: SUPPLY_RESULT_SCHEMA.into(),
        command_id: row.get("command_id"),
        state: row.get("state"),
        resource_key: row.get("resource_key"),
        resource_version: u64::try_from(row.get::<i64, _>("resource_version"))
            .map_err(|_| SupplyAuthorityError::StateConflict)?,
        result_digest: row.try_get("result_digest").ok(),
        evidence_ref: row.try_get("evidence_ref").ok(),
        evidence_digest: row.try_get("evidence_digest").ok(),
        stable_error: row.try_get("stable_error").ok(),
        effect_receipt: receipt,
    })
}

fn authoritative_release_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<AuthoritativeRelease, SupplyAuthorityError> {
    let receipt_refs: Vec<SupplyReceiptReference> =
        serde_json::from_value(row.get::<Value, _>("receipt_refs"))
            .map_err(|_| SupplyAuthorityError::StateConflict)?;
    Ok(AuthoritativeRelease {
        pack_id: row.get("pack_id"),
        version: row.get("version"),
        lifecycle_state: row.get("lifecycle_state"),
        resource_version: u64::try_from(row.get::<i64, _>("resource_version"))
            .map_err(|_| SupplyAuthorityError::StateConflict)?,
        manifest_digest: row.get("manifest_digest"),
        permission_digest: row.get("permission_digest"),
        dependency_lock_digest: row.get("dependency_lock_digest"),
        artifact_digest: row.get("artifact_digest"),
        immutable_reference: row.get("immutable_reference"),
        sbom_digest: row.get("sbom_digest"),
        provenance_digest: row.get("provenance_digest"),
        signature_digest: row.get("signature_digest"),
        license_report_digest: row.get("license_report_digest"),
        vulnerability_report_digest: row.get("vulnerability_report_digest"),
        maximum_vulnerability: row.get("maximum_vulnerability"),
        artifact_status: row.get("artifact_status"),
        receipt_refs,
    })
}

fn decode_release_cursor(value: &str) -> Result<(String, String), SupplyAuthorityError> {
    if value.is_empty() || value.len() > 2048 {
        return Err(SupplyAuthorityError::RequestInvalid);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SupplyAuthorityError::RequestInvalid)?;
    let fields: Vec<String> =
        serde_json::from_slice(&raw).map_err(|_| SupplyAuthorityError::RequestInvalid)?;
    if fields.len() != 2 || !identifier(&fields[0], 256) || !identifier(&fields[1], 128) {
        return Err(SupplyAuthorityError::RequestInvalid);
    }
    Ok((fields[0].clone(), fields[1].clone()))
}

fn encode_release_cursor(pack_id: &str, version: &str) -> Result<String, SupplyAuthorityError> {
    serde_jcs::to_vec(&[pack_id, version])
        .map(|raw| URL_SAFE_NO_PAD.encode(raw))
        .map_err(|_| SupplyAuthorityError::RequestInvalid)
}

fn required_object_field(value: &Value, key: &str) -> Result<Value, SupplyAuthorityError> {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .cloned()
        .ok_or(SupplyAuthorityError::RequestInvalid)
}

fn exact_keys(
    map: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), SupplyAuthorityError> {
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(SupplyAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_dependency_lock(value: &Value) -> Result<(), SupplyAuthorityError> {
    let entries = value
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= 1024)
        .ok_or(SupplyAuthorityError::RequestInvalid)?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or(SupplyAuthorityError::RequestInvalid)?;
        if object.len() != 4 {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
        let name = string_field(object, "name", 256)?;
        let version = string_field(object, "version", 128)?;
        let digest_value = string_field(object, "digest", 64)?;
        let reference_value = string_field(object, "immutable_reference", 2048)?;
        if !identifier(&name, 256)
            || !identifier(&version, 128)
            || !digest(&digest_value)
            || reference_value.to_ascii_lowercase().contains("latest")
            || !reference_value.contains(&format!("sha256:{digest_value}"))
            || !names.insert(name)
        {
            return Err(SupplyAuthorityError::RequestInvalid);
        }
    }
    Ok(())
}

fn string_field(
    map: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<String, SupplyAuthorityError> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        })
        .map(str::to_string)
        .ok_or(SupplyAuthorityError::RequestInvalid)
}

fn optional_string_field(
    map: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<Option<String>, SupplyAuthorityError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => string_field(map, key, maximum).map(Some),
    }
}

fn uuid_field(map: &Map<String, Value>, key: &str) -> Result<Uuid, SupplyAuthorityError> {
    string_field(map, key, 36).and_then(|value| {
        Uuid::parse_str(&value)
            .ok()
            .filter(|parsed| parsed.to_string() == value)
            .ok_or(SupplyAuthorityError::RequestInvalid)
    })
}

fn i32_field(
    map: &Map<String, Value>,
    key: &str,
    minimum: i32,
    maximum: i32,
) -> Result<i32, SupplyAuthorityError> {
    map.get(key)
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or(SupplyAuthorityError::RequestInvalid)
}

fn datetime_field(
    map: &Map<String, Value>,
    key: &str,
) -> Result<DateTime<Utc>, SupplyAuthorityError> {
    string_field(map, key, 64).and_then(|value| {
        DateTime::parse_from_rfc3339(&value)
            .map(|time| time.with_timezone(&Utc))
            .map_err(|_| SupplyAuthorityError::RequestInvalid)
    })
}

fn canonical_digest(value: &impl Serialize) -> Result<String, SupplyAuthorityError> {
    let raw = serde_jcs::to_vec(value).map_err(|_| SupplyAuthorityError::RequestInvalid)?;
    Ok(sha256(&raw))
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}
fn reference(value: &str, maximum: usize) -> bool {
    identifier(value, maximum) && !value.contains("..")
}
fn idempotency_key(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}
fn valid_semver_string(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}
fn https_reference(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
    })
}

fn json_limits(value: &Value, depth: usize) -> Result<usize, SupplyAuthorityError> {
    if depth > 32 {
        return Err(SupplyAuthorityError::RequestInvalid);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(1),
        Value::String(value) if value.len() <= 65_536 && !value.chars().any(char::is_control) => {
            Ok(value.len())
        }
        Value::String(_) => Err(SupplyAuthorityError::RequestInvalid),
        Value::Array(values) if values.len() <= 1024 => {
            values.iter().try_fold(0usize, |total, value| {
                json_limits(value, depth + 1).and_then(|size| {
                    total
                        .checked_add(size)
                        .ok_or(SupplyAuthorityError::RequestInvalid)
                })
            })
        }
        Value::Object(values) if values.len() <= 256 => {
            values.iter().try_fold(0usize, |total, (key, value)| {
                if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
                    return Err(SupplyAuthorityError::RequestInvalid);
                }
                json_limits(value, depth + 1).and_then(|size| {
                    total
                        .checked_add(key.len() + size)
                        .ok_or(SupplyAuthorityError::RequestInvalid)
                })
            })
        }
        _ => Err(SupplyAuthorityError::RequestInvalid),
    }
    .and_then(|size| {
        if size <= 1_048_576 {
            Ok(size)
        } else {
            Err(SupplyAuthorityError::RequestInvalid)
        }
    })
}

fn map_pack_error(error: PackError) -> SupplyAuthorityError {
    match error {
        PackError::PublisherUnauthorized => SupplyAuthorityError::PublisherDenied,
        PackError::SignatureInvalid => SupplyAuthorityError::SignatureInvalid,
        _ => SupplyAuthorityError::PackInvalid,
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SupplyAuthorityError {
    #[error("SUPPLY_CHAIN_REQUEST_INVALID")]
    RequestInvalid,
    #[error("SUPPLY_CHAIN_BINDING_INVALID")]
    BindingInvalid,
    #[error("SUPPLY_CHAIN_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("SUPPLY_CHAIN_PUBLISHER_DENIED")]
    PublisherDenied,
    #[error("SUPPLY_CHAIN_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("SUPPLY_CHAIN_PACK_INVALID")]
    PackInvalid,
    #[error("SUPPLY_CHAIN_RECEIPT_INVALID")]
    ReceiptInvalid,
    #[error("SUPPLY_CHAIN_APPROVAL_DENIED")]
    ApprovalDenied,
    #[error("SUPPLY_CHAIN_RECOVERY_DENIED")]
    RecoveryDenied,
    #[error("SUPPLY_CHAIN_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("SUPPLY_CHAIN_STATE_CONFLICT")]
    StateConflict,
    #[error("SUPPLY_CHAIN_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("SUPPLY_CHAIN_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("SUPPLY_CHAIN_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

impl SupplyAuthorityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::RequestInvalid => "SUPPLY_CHAIN_REQUEST_INVALID",
            Self::BindingInvalid => "SUPPLY_CHAIN_BINDING_INVALID",
            Self::PrincipalDenied => "SUPPLY_CHAIN_PRINCIPAL_DENIED",
            Self::PublisherDenied => "SUPPLY_CHAIN_PUBLISHER_DENIED",
            Self::SignatureInvalid => "SUPPLY_CHAIN_SIGNATURE_INVALID",
            Self::PackInvalid => "SUPPLY_CHAIN_PACK_INVALID",
            Self::ReceiptInvalid => "SUPPLY_CHAIN_RECEIPT_INVALID",
            Self::ApprovalDenied => "SUPPLY_CHAIN_APPROVAL_DENIED",
            Self::RecoveryDenied => "SUPPLY_CHAIN_RECOVERY_DENIED",
            Self::IdempotencyConflict => "SUPPLY_CHAIN_IDEMPOTENCY_CONFLICT",
            Self::StateConflict => "SUPPLY_CHAIN_STATE_CONFLICT",
            Self::DependencyUnavailable => "SUPPLY_CHAIN_DEPENDENCY_UNAVAILABLE",
            Self::OutcomeUnknown => "SUPPLY_CHAIN_OUTCOME_UNKNOWN",
            Self::ConfigurationInvalid => "SUPPLY_CHAIN_CONFIGURATION_INVALID",
        }
    }
}
