//! Review facts bound to the shared Evidence Authority receipt.

use super::{ApprovalError, ApprovalRequest};
use agent_trust_contracts::{
    APPROVAL_REVIEW_MAX_EVIDENCE_LIFETIME_SECONDS, AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE,
    AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION, AuthorityEvidenceSourceKind,
};
pub use agent_trust_contracts::{
    APPROVAL_REVIEW_EVIDENCE_ISSUE_SCHEMA_VERSION, APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION,
    APPROVAL_REVIEW_MATERIAL_SCHEMA_VERSION, ApprovalReviewEvidence,
    ApprovalReviewEvidenceIssueRequest, ApprovalReviewMaterial,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const APPROVAL_REVIEW_EVIDENCE_KEYRING_SCHEMA_VERSION: &str =
    "agenttrust.approval-review-evidence-keyring.v2";

const MAX_DOCUMENT_BYTES: usize = 1_048_576;
const MAX_KEYS: usize = 128;
const MAX_TENANTS_PER_KEY: usize = 1_024;

pub fn review_material_digest(material: &ApprovalReviewMaterial) -> Result<String, ApprovalError> {
    material
        .payload_digest()
        .map_err(|_| ApprovalError::RequestInvalid)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewEvidenceKeyringDocument {
    schema_version: String,
    keys: Vec<ReviewEvidenceVerificationKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewEvidenceVerificationKeyDocument {
    issuer: String,
    key_id: String,
    source_services: BTreeSet<String>,
    algorithm: String,
    usage: String,
    status: String,
    public_key: String,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct ReviewEvidenceVerificationKey {
    key: VerifyingKey,
    source_services: BTreeSet<String>,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    active: bool,
}

#[derive(Clone)]
pub struct ApprovalReviewEvidenceKeyring {
    keys: BTreeMap<(String, String), ReviewEvidenceVerificationKey>,
}

impl ApprovalReviewEvidenceKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ApprovalError> {
        let raw = std::fs::read(path).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &[u8]) -> Result<Self, ApprovalError> {
        if raw.is_empty() || raw.len() > MAX_DOCUMENT_BYTES {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let document: ReviewEvidenceKeyringDocument =
            serde_json::from_slice(raw).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        if document.schema_version != APPROVAL_REVIEW_EVIDENCE_KEYRING_SCHEMA_VERSION
            || document.keys.is_empty()
            || document.keys.len() > MAX_KEYS
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            if !identifier(&entry.issuer, 256)
                || !key_identifier(&entry.key_id)
                || entry.source_services.is_empty()
                || entry.source_services.len() > 128
                || entry.source_services.iter().any(|source| !source_identity(source))
                || entry.algorithm != "Ed25519"
                || entry.usage != AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE
                || !matches!(entry.status.as_str(), "ACTIVE" | "RETIRED")
                || entry.not_before >= entry.expires_at
                || entry.tenant_ids.is_empty()
                || entry.tenant_ids.len() > MAX_TENANTS_PER_KEY
                || entry.tenant_ids.iter().any(|tenant| !canonical_uuid(tenant))
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            let key_bytes = URL_SAFE_NO_PAD
                .decode(&entry.public_key)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let key_bytes: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let identity = (entry.issuer, entry.key_id);
            if keys
                .insert(
                    identity,
                    ReviewEvidenceVerificationKey {
                        key,
                        source_services: entry.source_services,
                        tenant_ids: entry.tenant_ids,
                        not_before: entry.not_before,
                        expires_at: entry.expires_at,
                        active: entry.status == "ACTIVE",
                    },
                )
                .is_some()
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
        }
        Ok(Self { keys })
    }

    pub fn covers_tenant_at(&self, tenant: &str, now: DateTime<Utc>) -> bool {
        self.keys.values().any(|verification| {
            verification.active
                && verification.tenant_ids.contains(tenant)
                && verification.not_before <= now
                && verification.expires_at
                    >= now
                        + Duration::seconds(APPROVAL_REVIEW_MAX_EVIDENCE_LIFETIME_SECONDS)
        })
    }

    pub fn verify_request(
        &self,
        request: &ApprovalRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        self.verify_at(request, now, true)
    }

    pub fn verify_historical_request(
        &self,
        request: &ApprovalRequest,
        case_created_at: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        self.verify_at(request, case_created_at, false)
    }

    fn verify_at(
        &self,
        request: &ApprovalRequest,
        verification_time: DateTime<Utc>,
        require_active: bool,
    ) -> Result<(), ApprovalError> {
        let evidence = &request.review_evidence;
        if evidence.schema_version != APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION
            || evidence.material.validate().is_err()
            || evidence.material != expected_material(request)
        {
            return Err(ApprovalError::RequestInvalid);
        }

        let authority_request = &evidence.authority_request;
        let receipt = &evidence.receipt;
        let verification = self
            .keys
            .get(&(receipt.issuer.clone(), receipt.key_id.clone()))
            .ok_or(ApprovalError::RequestInvalid)?;
        if (require_active && !verification.active)
            || !verification.tenant_ids.contains(&request.tenant_id.0)
            || !verification
                .source_services
                .contains(&authority_request.event.source_service)
            || verification.not_before > authority_request.event.occurred_at
            || verification.expires_at < receipt.persisted_at
        {
            return Err(ApprovalError::RequestInvalid);
        }

        receipt
            .verify(&verification.key, verification_time)
            .map_err(|_| ApprovalError::RequestInvalid)?;

        let issue = ApprovalReviewEvidenceIssueRequest {
            schema_version: APPROVAL_REVIEW_EVIDENCE_ISSUE_SCHEMA_VERSION.into(),
            request_id: authority_request.authority_event_id.clone(),
            idempotency_key: authority_request.idempotency_key.0.clone(),
            actor_subject: authority_request.event.actor_subject.clone(),
            source_service: authority_request.event.source_service.clone(),
            trace_id: authority_request.event.trace_id.clone(),
            material: evidence.material.clone(),
            requested_at: authority_request.requested_at,
        };
        let expected_authority_request = issue
            .to_authority_event(
                &authority_request.event.source_service,
                verification_time,
            )
            .map_err(|_| ApprovalError::RequestInvalid)?;
        let expected_request_digest = expected_authority_request
            .request_digest()
            .map_err(|_| ApprovalError::RequestInvalid)?;
        if authority_request != &expected_authority_request
            || receipt.schema_version != AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION
            || receipt.key_usage != AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE
            || receipt.tenant_id != authority_request.tenant_id
            || receipt.task_id != authority_request.task_id
            || receipt.authority_event_id != authority_request.authority_event_id
            || receipt.idempotency_key != authority_request.idempotency_key
            || receipt.source_kind != AuthorityEvidenceSourceKind::AuthenticatedEvent
            || receipt.source_kind != authority_request.source_kind
            || receipt.request_digest != expected_request_digest
            || receipt.payload_digest != authority_request.event.payload_hash
            || receipt.event.draft != authority_request.event
            || receipt.persisted_at < authority_request.requested_at
        {
            return Err(ApprovalError::RequestInvalid);
        }
        Ok(())
    }
}

fn expected_material(request: &ApprovalRequest) -> ApprovalReviewMaterial {
    ApprovalReviewMaterial {
        schema_version: APPROVAL_REVIEW_MATERIAL_SCHEMA_VERSION.into(),
        tenant_id: request.tenant_id.0.clone(),
        task_id: request.task_id.0.clone(),
        canonical_action_hash: request.action_hash.0.clone(),
        resource: request.resource.clone(),
        resource_version: request.resource_version.0.clone(),
        policy_version: request.policy_version.0.clone(),
        environment: request.environment.clone(),
        risk: request.risk,
        review_context: request.review_context.clone(),
        risk_package_ref: request.review_evidence.material.risk_package_ref.clone(),
        risk_package_digest: request.review_evidence.material.risk_package_digest.clone(),
        state_snapshot_ref: request.review_evidence.material.state_snapshot_ref.clone(),
        state_snapshot_digest: request.review_evidence.material.state_snapshot_digest.clone(),
    }
}

fn source_identity(value: &str) -> bool {
    value
        .strip_prefix("DNS:")
        .or_else(|| value.strip_prefix("URI:"))
        .is_some_and(|identity| !identity.is_empty() && identifier(value, 256))
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn key_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}
