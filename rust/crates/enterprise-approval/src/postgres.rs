//! Durable, tenant-isolated production approval state and atomic grant consumption.

use super::*;
use crate::evidence_delivery::{
    ApprovalEvidenceDeliveryError, ApprovalEvidencePublisher, EVIDENCE_REQUEST_TIMEOUT_SECONDS,
};
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ArtifactRef, AuthorityEvidenceEventRequest,
    AuthorityEvidenceSourceKind, EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft,
    EvidenceEventType, IdempotencyKey,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::path::Path;
use std::sync::Arc;

const MAX_TEXT_BYTES: usize = 2_048;
const MAX_APPROVAL_TTL_SECONDS: u64 = 604_800;
const MAX_AUTHORITATIVE_PAGE_SIZE: u16 = 100;
const AUTHORITATIVE_CURSOR_TTL_SECONDS: i64 = 900;
const DECISION_EVIDENCE_DELIVERY_BATCH_SIZE: usize = 32;
const DECISION_EVIDENCE_DELIVERY_LEASE_SECONDS: i64 = 60;
const DECISION_EVIDENCE_DELIVERY_MAX_BACKOFF_SECONDS: i64 = 900;
const DECISION_EVIDENCE_MAX_PENDING_AGE_SECONDS: i64 = 300;
const _: () =
    assert!(DECISION_EVIDENCE_DELIVERY_LEASE_SECONDS > EVIDENCE_REQUEST_TIMEOUT_SECONDS as i64);

pub const APPROVAL_CASE_VIEW_SCHEMA_VERSION: &str = "agenttrust.approval-case-view.v1";
pub const AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION: &str =
    "agenttrust.authoritative-approval-page.v1";
pub const APPROVAL_DECISION_RESULT_SCHEMA_VERSION: &str = "agenttrust.approval-decision-result.v1";
pub const APPROVAL_DECISION_EVIDENCE_SCHEMA_VERSION: &str =
    "agenttrust.approval-decision-evidence.v1";
pub const APPROVAL_DECISION_EVIDENCE_KEY_USAGE: &str = "APPROVAL_DECISION_EVIDENCE";
pub const APPROVAL_DECISION_REQUEST_BINDING_SCHEMA_VERSION: &str =
    "agenttrust.approval-decision-request-binding.v1";
pub const APPROVAL_DECISION_EVIDENCE_KEYRING_SCHEMA_VERSION: &str =
    "agenttrust.approval-decision-evidence-keyring.v1";
const AUTHORITATIVE_APPROVAL_CURSOR_SCHEMA_VERSION: &str =
    "agenttrust.authoritative-approval-cursor.v1";
const MAX_DECISION_EVIDENCE_KEYRING_BYTES: usize = 1_048_576;
const MAX_DECISION_EVIDENCE_KEYS: usize = 128;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalCaseDomain {
    Coding,
    Industrial,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalCaseViewStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCaseView {
    pub schema_version: String,
    pub case_id: String,
    pub domain: ApprovalCaseDomain,
    pub safe_summary: String,
    pub action_hash: String,
    pub resource: String,
    pub resource_version: String,
    pub policy_version: String,
    pub risk: RiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coding_details: Option<CodingApprovalReviewDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub industrial_details: Option<IndustrialApprovalReviewDetails>,
    pub evidence_refs: Vec<String>,
    pub status: ApprovalCaseViewStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeApprovalPage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: String,
    pub resource: String,
    pub items: Vec<ApprovalCaseView>,
    pub next_cursor: Option<String>,
    pub data_digest: String,
}

#[derive(Serialize)]
struct AuthoritativeApprovalPageMaterial<'a> {
    schema_version: &'a str,
    authoritative: bool,
    tenant_id: &'a str,
    resource: &'a str,
    items: &'a [ApprovalCaseView],
    next_cursor: &'a Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthoritativeApprovalCursor {
    schema_version: String,
    tenant_id: String,
    resource: String,
    created_at: DateTime<Utc>,
    case_id: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    issuer: String,
    key_id: String,
    signature: String,
}

impl AuthoritativeApprovalCursor {
    fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut material = self.clone();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| ApprovalError::RequestInvalid)
    }
}

/// The wire shape persisted before review_context became mandatory. These rows remain durable
/// audit records, but they cannot be rendered as an approval view because doing so would require
/// inventing the missing human-review facts. The authoritative inbox identifies this exact shape
/// and excludes it while continuing pagination; every other deserialization failure remains fatal.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyApprovalRequestV0 {
    tenant_id: TenantId,
    task_id: TaskId,
    step_id: StepId,
    action_hash: ActionHash,
    plan_hash: String,
    parameter_hash: String,
    resource: String,
    resource_version: ResourceVersion,
    policy_version: PolicyVersion,
    environment: String,
    risk: RiskLevel,
    requester_subject: String,
    agent_owner_subject: String,
    justification: String,
    requested_ttl_seconds: u64,
    requested_uses: u32,
}

impl LegacyApprovalRequestV0 {
    fn valid_for_authoritative_exclusion(&self, tenant: &TenantId) -> bool {
        self.tenant_id == *tenant
            && canonical_uuid(&self.tenant_id.0)
            && canonical_uuid(&self.task_id.0)
            && canonical_uuid(&self.step_id.0)
            && is_digest(&self.action_hash.0)
            && is_digest(&self.plan_hash)
            && is_digest(&self.parameter_hash)
            && bounded(&self.resource)
            && bounded(&self.resource_version.0)
            && bounded(&self.policy_version.0)
            && bounded(&self.environment)
            && matches!(
                self.risk,
                RiskLevel::Low | RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
            )
            && bounded(&self.requester_subject)
            && bounded(&self.agent_owner_subject)
            && valid_approval_human_text(&self.justification)
            && !self.justification.chars().any(char::is_control)
            && (1..=MAX_APPROVAL_TTL_SECONDS).contains(&self.requested_ttl_seconds)
            && self.requested_uses > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCaseCreateEnvelope {
    pub schema_version: String,
    pub request: ApprovalRequest,
    pub policy: ApprovalPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalDecision {
    Approve,
    Reject,
    PostReviewed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionEnvelope {
    pub schema_version: String,
    pub decision: ApprovalDecision,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionEvidenceReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub tenant_id: String,
    pub case_id: String,
    pub task_id: String,
    pub decision: ApprovalDecision,
    pub decision_reason_digest: String,
    pub request_digest: String,
    pub decision_digest: String,
    pub idempotency_key_digest: String,
    pub actor_subject: String,
    pub principal_assertion_jti: String,
    pub principal_assertion_request_digest: String,
    pub principal_assertion_digest: String,
    pub approval_case_digest: String,
    pub action_hash: String,
    pub step_id: String,
    pub plan_hash: String,
    pub parameter_hash: String,
    pub resource: String,
    pub resource_version: String,
    pub policy_version: String,
    pub environment: String,
    pub risk: RiskLevel,
    pub case_status: ApprovalStatus,
    pub decided_at: DateTime<Utc>,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub authority_request_digest: String,
    pub evidence_outbox_ref: String,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ApprovalDecisionEvidenceMaterial<'a> {
    schema_version: &'a str,
    tenant_id: &'a str,
    case_id: &'a str,
    task_id: &'a str,
    decision: ApprovalDecision,
    decision_reason_digest: &'a str,
    request_digest: &'a str,
    idempotency_key_digest: &'a str,
    actor_subject: &'a str,
    principal_assertion_jti: &'a str,
    principal_assertion_request_digest: &'a str,
    principal_assertion_digest: &'a str,
    approval_case_digest: &'a str,
    action_hash: &'a str,
    step_id: &'a str,
    plan_hash: &'a str,
    parameter_hash: &'a str,
    resource: &'a str,
    resource_version: &'a str,
    policy_version: &'a str,
    environment: &'a str,
    risk: RiskLevel,
    case_status: ApprovalStatus,
    decided_at: DateTime<Utc>,
}

impl ApprovalDecisionEvidenceReceipt {
    fn decision_material(&self) -> ApprovalDecisionEvidenceMaterial<'_> {
        ApprovalDecisionEvidenceMaterial {
            schema_version: APPROVAL_DECISION_EVIDENCE_SCHEMA_VERSION,
            tenant_id: &self.tenant_id,
            case_id: &self.case_id,
            task_id: &self.task_id,
            decision: self.decision,
            decision_reason_digest: &self.decision_reason_digest,
            request_digest: &self.request_digest,
            idempotency_key_digest: &self.idempotency_key_digest,
            actor_subject: &self.actor_subject,
            principal_assertion_jti: &self.principal_assertion_jti,
            principal_assertion_request_digest: &self.principal_assertion_request_digest,
            principal_assertion_digest: &self.principal_assertion_digest,
            approval_case_digest: &self.approval_case_digest,
            action_hash: &self.action_hash,
            step_id: &self.step_id,
            plan_hash: &self.plan_hash,
            parameter_hash: &self.parameter_hash,
            resource: &self.resource,
            resource_version: &self.resource_version,
            policy_version: &self.policy_version,
            environment: &self.environment,
            risk: self.risk,
            case_status: self.case_status,
            decided_at: self.decided_at,
        }
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut material = self.clone();
        material.evidence_digest.clear();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| ApprovalError::RequestInvalid)
    }

    fn expected_decision_digest(&self) -> Result<String, ApprovalError> {
        canonical_digest(&self.decision_material())
    }

    fn expected_evidence_ref(&self) -> String {
        format!(
            "urn:agenttrust:approval-decision:{}:{}:{}",
            self.tenant_id, self.case_id, self.receipt_id
        )
    }

    fn expected_evidence_outbox_ref(&self) -> String {
        format!(
            "outbox://approval-decision-evidence/{}/{}/sha256:{}",
            self.tenant_id, self.receipt_id, self.authority_request_digest
        )
    }

    fn expected_evidence_digest(&self) -> Result<String, ApprovalError> {
        Ok(hex(Sha256::digest(self.signing_bytes()?)))
    }

    pub fn verify(
        &self,
        issuer: &str,
        key_id: &str,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        if self.schema_version != APPROVAL_DECISION_EVIDENCE_SCHEMA_VERSION
            || self.issuer != issuer
            || self.key_id != key_id
            || self.key_usage != APPROVAL_DECISION_EVIDENCE_KEY_USAGE
            || !canonical_uuid(&self.receipt_id)
            || !canonical_uuid(&self.tenant_id)
            || !canonical_uuid(&self.case_id)
            || !canonical_uuid(&self.task_id)
            || !is_digest(&self.decision_reason_digest)
            || !is_digest(&self.request_digest)
            || !is_digest(&self.decision_digest)
            || !is_digest(&self.idempotency_key_digest)
            || !identifier(&self.actor_subject)
            || !canonical_uuid(&self.principal_assertion_jti)
            || !is_digest(&self.principal_assertion_request_digest)
            || !is_digest(&self.principal_assertion_digest)
            || !is_digest(&self.approval_case_digest)
            || !is_digest(&self.action_hash)
            || !canonical_uuid(&self.step_id)
            || !is_digest(&self.plan_hash)
            || !is_digest(&self.parameter_hash)
            || !bounded(&self.resource)
            || !bounded(&self.resource_version)
            || !bounded(&self.policy_version)
            || !bounded(&self.environment)
            || !decision_status_valid(self.decision, self.case_status)
            || self.decided_at > now + chrono::Duration::seconds(30)
            || self.decision_digest != self.expected_decision_digest()?
            || self.evidence_ref != self.expected_evidence_ref()
            || !is_digest(&self.authority_request_digest)
            || self.evidence_outbox_ref != self.expected_evidence_outbox_ref()
            || self.evidence_digest != self.expected_evidence_digest()?
        {
            return Err(ApprovalError::GrantInvalid);
        }
        let signature = decode_signature(&self.signature)?;
        key.verify(self.evidence_digest.as_bytes(), &signature)
            .map_err(|_| ApprovalError::GrantInvalid)
    }
}

fn decision_status_valid(decision: ApprovalDecision, status: ApprovalStatus) -> bool {
    match decision {
        ApprovalDecision::Reject => status == ApprovalStatus::Rejected,
        ApprovalDecision::PostReviewed => status == ApprovalStatus::Approved,
        ApprovalDecision::Approve => matches!(
            status,
            ApprovalStatus::Pending | ApprovalStatus::Approved | ApprovalStatus::PostReviewRequired
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionResult {
    pub schema_version: String,
    pub approval_case: ApprovalCase,
    pub evidence_receipt: ApprovalDecisionEvidenceReceipt,
}

#[derive(Serialize)]
struct ApprovalDecisionRequestBinding<'a> {
    schema_version: &'a str,
    case_id: &'a str,
    decision: &'a ApprovalDecisionEnvelope,
}

fn approval_decision_request_digest(
    case_id: &str,
    decision: &ApprovalDecisionEnvelope,
) -> Result<String, ApprovalError> {
    canonical_digest(&ApprovalDecisionRequestBinding {
        schema_version: APPROVAL_DECISION_REQUEST_BINDING_SCHEMA_VERSION,
        case_id,
        decision,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantIssueRequest {
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantRevocationRequest {
    pub schema_version: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantRevocationReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub tenant_id: String,
    pub grant_id: String,
    pub case_id: String,
    pub reason_digest: String,
    pub revoked_by: String,
    pub principal_assertion_jti: String,
    pub principal_assertion_digest: String,
    pub revoked_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl ApprovalGrantRevocationReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut material = self.clone();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| ApprovalError::GrantInvalid)
    }

    pub fn verify(
        &self,
        issuer: &str,
        key_id: &str,
        key: &VerifyingKey,
    ) -> Result<(), ApprovalError> {
        if self.schema_version != "agenttrust.approval-grant-revocation.v1"
            || self.issuer != issuer
            || self.key_id != key_id
            || !canonical_uuid(&self.receipt_id)
            || !canonical_uuid(&self.tenant_id)
            || !canonical_uuid(&self.grant_id)
            || !canonical_uuid(&self.case_id)
            || !is_digest(&self.reason_digest)
            || !identifier(&self.revoked_by)
            || !canonical_uuid(&self.principal_assertion_jti)
            || !is_digest(&self.principal_assertion_digest)
        {
            return Err(ApprovalError::GrantInvalid);
        }
        let signature = decode_signature(&self.signature)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ApprovalError::GrantInvalid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPrincipal {
    pub(crate) tenant_id: TenantId,
    pub(crate) subject: String,
    pub(crate) roles: BTreeSet<String>,
    pub(crate) owned_resources: BTreeSet<String>,
    pub(crate) strong_auth: bool,
    pub(crate) assertion_issuer: String,
    pub(crate) assertion_jti: String,
    pub(crate) assertion_request_digest: String,
    pub(crate) assertion_digest: String,
    pub(crate) assertion_document: Value,
    pub(crate) assertion_expires_at: DateTime<Utc>,
}

impl ApprovalPrincipal {
    fn identity(&self) -> ApproverIdentity {
        ApproverIdentity {
            tenant_id: self.tenant_id.clone(),
            subject: self.subject.clone(),
            roles: self.roles.clone(),
            owned_resources: self.owned_resources.clone(),
            delegated_until: None,
            strong_auth: self.strong_auth,
            active: true,
        }
    }
}

#[derive(Clone)]
pub struct ApprovalSigner {
    issuer: String,
    key_id: String,
    key: Arc<SigningKey>,
}

impl ApprovalSigner {
    pub fn new(issuer: String, key_id: String, key: SigningKey) -> Result<Self, ApprovalError> {
        if !identifier(&issuer) || !key_identifier(&key_id) {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        Ok(Self {
            issuer,
            key_id,
            key: Arc::new(key),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn sign_grant(&self, grant: &mut EnterpriseApprovalGrant) -> Result<(), ApprovalError> {
        grant.signature = URL_SAFE_NO_PAD.encode(self.key.sign(&grant.signing_bytes()?).to_bytes());
        Ok(())
    }

    fn sign_consumption(
        &self,
        receipt: &mut SignedApprovalConsumptionReceipt,
    ) -> Result<(), ApprovalError> {
        receipt.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&receipt.signing_bytes()?).to_bytes());
        Ok(())
    }

    fn sign_revocation(
        &self,
        receipt: &mut ApprovalGrantRevocationReceipt,
    ) -> Result<(), ApprovalError> {
        receipt.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&receipt.signing_bytes()?).to_bytes());
        Ok(())
    }

    fn sign_decision_evidence(
        &self,
        receipt: &mut ApprovalDecisionEvidenceReceipt,
    ) -> Result<(), ApprovalError> {
        receipt.evidence_digest = receipt.expected_evidence_digest()?;
        receipt.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(receipt.evidence_digest.as_bytes()).to_bytes());
        Ok(())
    }

    fn sign_authoritative_cursor(
        &self,
        cursor: &mut AuthoritativeApprovalCursor,
    ) -> Result<(), ApprovalError> {
        cursor.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&cursor.signing_bytes()?).to_bytes());
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionEvidenceKeyringDocument {
    schema_version: String,
    issuer: String,
    keys: Vec<ApprovalDecisionEvidenceVerificationKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionEvidenceVerificationKeyDocument {
    key_id: String,
    algorithm: String,
    public_key_base64url: String,
    status: String,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct ApprovalDecisionEvidenceVerificationKey {
    key: VerifyingKey,
    active: bool,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Public-only verification material for current and historical decision receipts.
///
/// Exactly one key is ACTIVE. Historical VERIFY_ONLY keys remain usable only for
/// receipts whose `decided_at` falls inside that key's validity interval; their
/// current wall-clock expiry does not invalidate an already persisted receipt.
#[derive(Clone)]
pub struct ApprovalDecisionEvidenceKeyring {
    issuer: String,
    active_key_id: String,
    keys: BTreeMap<String, ApprovalDecisionEvidenceVerificationKey>,
}

impl ApprovalDecisionEvidenceKeyring {
    pub fn from_file(path: &Path) -> Result<Self, ApprovalError> {
        let raw = std::fs::read(path).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &[u8]) -> Result<Self, ApprovalError> {
        if raw.is_empty() || raw.len() > MAX_DECISION_EVIDENCE_KEYRING_BYTES {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let document: ApprovalDecisionEvidenceKeyringDocument =
            serde_json::from_slice(raw).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        if document.schema_version != APPROVAL_DECISION_EVIDENCE_KEYRING_SCHEMA_VERSION
            || !identifier(&document.issuer)
            || document.keys.is_empty()
            || document.keys.len() > MAX_DECISION_EVIDENCE_KEYS
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        let mut active_key_id = None;
        for entry in document.keys {
            if !key_identifier(&entry.key_id)
                || entry.algorithm != "Ed25519"
                || !matches!(entry.status.as_str(), "ACTIVE" | "VERIFY_ONLY")
                || entry.not_before >= entry.expires_at
                || entry.public_key_base64url.len() != 43
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            let key_bytes = URL_SAFE_NO_PAD
                .decode(&entry.public_key_base64url)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let key_bytes: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            if URL_SAFE_NO_PAD.encode(key_bytes) != entry.public_key_base64url {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let active = entry.status == "ACTIVE";
            if active && active_key_id.replace(entry.key_id.clone()).is_some() {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            if keys
                .insert(
                    entry.key_id,
                    ApprovalDecisionEvidenceVerificationKey {
                        key,
                        active,
                        not_before: entry.not_before,
                        expires_at: entry.expires_at,
                    },
                )
                .is_some()
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
        }
        let active_key_id = active_key_id.ok_or(ApprovalError::ConfigurationInvalid)?;
        Ok(Self {
            issuer: document.issuer,
            active_key_id,
            keys,
        })
    }

    fn matches_signer(&self, signer: &ApprovalSigner) -> bool {
        self.issuer == signer.issuer()
            && self.active_key_id == signer.key_id()
            && self
                .keys
                .get(&self.active_key_id)
                .is_some_and(|verification| {
                    verification.active
                        && verification.key.to_bytes() == signer.verifying_key().to_bytes()
                })
    }

    fn covers_active_signer_at(&self, signer: &ApprovalSigner, at: DateTime<Utc>) -> bool {
        self.matches_signer(signer)
            && self
                .keys
                .get(&self.active_key_id)
                .is_some_and(|verification| {
                    verification.not_before <= at && verification.expires_at > at
                })
    }

    fn verify_receipt(
        &self,
        receipt: &ApprovalDecisionEvidenceReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        if receipt.issuer != self.issuer {
            return Err(ApprovalError::GrantInvalid);
        }
        let verification = self
            .keys
            .get(&receipt.key_id)
            .ok_or(ApprovalError::GrantInvalid)?;
        if verification.not_before > receipt.decided_at
            || verification.expires_at <= receipt.decided_at
        {
            return Err(ApprovalError::GrantInvalid);
        }
        receipt.verify(&self.issuer, &receipt.key_id, &verification.key, now)
    }
}

#[derive(Clone)]
pub struct PostgresApprovalStore {
    pool: PgPool,
    signer: ApprovalSigner,
    review_evidence_keyring: ApprovalReviewEvidenceKeyring,
    delivery_evidence_keyring: ApprovalReviewEvidenceKeyring,
    decision_evidence_keyring: ApprovalDecisionEvidenceKeyring,
    evidence_source_identity: String,
    evidence_publisher: Arc<ApprovalEvidencePublisher>,
}

struct PendingApprovalDecisionEvidence {
    tenant_id: TenantId,
    authority_event_id: String,
    request_digest: String,
    payload_digest: String,
    authority_request: AuthorityEvidenceEventRequest,
    delivery_attempts: i32,
}

impl PostgresApprovalStore {
    pub fn new(
        pool: PgPool,
        signer: ApprovalSigner,
        review_evidence_keyring: ApprovalReviewEvidenceKeyring,
        delivery_evidence_keyring: ApprovalReviewEvidenceKeyring,
        decision_evidence_keyring: ApprovalDecisionEvidenceKeyring,
        evidence_source_identity: String,
        evidence_publisher: Arc<ApprovalEvidencePublisher>,
    ) -> Result<Self, ApprovalError> {
        if !service_client_identity(&evidence_source_identity)
            || !decision_evidence_keyring.matches_signer(&signer)
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        Ok(Self {
            pool,
            signer,
            review_evidence_keyring,
            delivery_evidence_keyring,
            decision_evidence_keyring,
            evidence_source_identity,
            evidence_publisher,
        })
    }

    pub fn signer(&self) -> &ApprovalSigner {
        &self.signer
    }

    pub fn review_evidence_covers(&self, tenant: &TenantId, now: DateTime<Utc>) -> bool {
        self.review_evidence_keyring
            .covers_tenant_at(&tenant.0, now)
    }

    pub fn decision_evidence_delivery_covers(&self, tenant: &TenantId, now: DateTime<Utc>) -> bool {
        self.delivery_evidence_keyring.covers_source_tenant_at(
            &tenant.0,
            &self.evidence_source_identity,
            now,
        )
    }

    pub async fn ready(&self) -> bool {
        if !self
            .decision_evidence_keyring
            .covers_active_signer_at(&self.signer, Utc::now())
        {
            return false;
        }
        if !self.evidence_publisher.ready().await {
            return false;
        }
        sqlx::query(
            "SELECT NOT pg_is_in_recovery() \
             AND to_regclass('public.approval_cases') IS NOT NULL \
             AND to_regclass('public.approval_decisions') IS NOT NULL \
             AND to_regclass('public.approval_grants') IS NOT NULL \
             AND to_regclass('public.approval_notification_outbox') IS NOT NULL \
             AND to_regclass('public.approval_consumptions') IS NOT NULL \
             AND to_regclass('public.approval_mutation_receipts') IS NOT NULL \
             AND to_regclass('public.approval_principal_assertion_uses') IS NOT NULL \
             AND to_regclass('public.approval_events') IS NOT NULL \
             AND to_regclass('public.approval_decision_evidence_receipts') IS NOT NULL \
             AND to_regclass('public.approval_decision_evidence_outbox') IS NOT NULL \
             AND (SELECT count(*) = 10 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                  WHERE n.nspname='public' AND c.relname::text = ANY(ARRAY[\
                    'approval_cases','approval_decisions','approval_grants','approval_notification_outbox',\
                    'approval_consumptions','approval_mutation_receipts','approval_principal_assertion_uses','approval_events',\
                    'approval_decision_evidence_receipts','approval_decision_evidence_outbox'\
                  ]) AND c.relrowsecurity AND c.relforcerowsecurity) \
             AND (SELECT count(*) = 10 FROM pg_policies WHERE schemaname='public' \
                  AND tablename::text = ANY(ARRAY[\
                    'approval_cases','approval_decisions','approval_grants','approval_notification_outbox',\
                    'approval_consumptions','approval_mutation_receipts','approval_principal_assertion_uses','approval_events',\
                    'approval_decision_evidence_receipts','approval_decision_evidence_outbox'\
                  ]) AND policyname='tenant_isolation' AND roles=ARRAY['public']::name[]) AS ready",
        )
        .fetch_one(&self.pool)
        .await
        .ok()
        .and_then(|row| row.try_get::<bool, _>("ready").ok())
        .unwrap_or(false)
    }

    pub async fn decision_evidence_outbox_ready(
        &self,
        tenants: &BTreeSet<TenantId>,
        now: DateTime<Utc>,
    ) -> bool {
        if tenants.is_empty() {
            return false;
        }
        let stale_before = now
            .checked_sub_signed(chrono::Duration::seconds(
                DECISION_EVIDENCE_MAX_PENDING_AGE_SECONDS,
            ))
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        for tenant in tenants {
            let mut transaction = match self.begin_tenant(tenant).await {
                Ok(transaction) => transaction,
                Err(error) => {
                    decision_evidence_delivery_alert(
                        "READINESS_QUERY_FAILED",
                        Some(tenant),
                        None,
                        &error.to_string(),
                        None,
                    );
                    return false;
                }
            };
            let healthy = match sqlx::query(
                "SELECT NOT EXISTS (\
                   SELECT 1 FROM approval_decision_evidence_outbox \
                    WHERE tenant_id=$1::uuid AND delivered_at IS NULL \
                      AND (last_error_code IN ('CONFIGURATION_INVALID','RECEIPT_INVALID') \
                           OR created_at < $2)\
                 ) AS healthy",
            )
            .bind(&tenant.0)
            .bind(stale_before)
            .fetch_one(&mut *transaction)
            .await
            {
                Ok(row) => match row.try_get::<bool, _>("healthy") {
                    Ok(healthy) => healthy,
                    Err(_) => {
                        decision_evidence_delivery_alert(
                            "READINESS_RESULT_INVALID",
                            Some(tenant),
                            None,
                            "APPROVAL_DATABASE_UNAVAILABLE",
                            None,
                        );
                        return false;
                    }
                },
                Err(_) => {
                    decision_evidence_delivery_alert(
                        "READINESS_QUERY_FAILED",
                        Some(tenant),
                        None,
                        "APPROVAL_DATABASE_UNAVAILABLE",
                        None,
                    );
                    return false;
                }
            };
            if transaction.commit().await.is_err() {
                decision_evidence_delivery_alert(
                    "READINESS_COMMIT_FAILED",
                    Some(tenant),
                    None,
                    "APPROVAL_DATABASE_UNAVAILABLE",
                    None,
                );
                return false;
            }
            if !healthy {
                decision_evidence_delivery_alert(
                    "BACKLOG_UNHEALTHY",
                    Some(tenant),
                    None,
                    "FATAL_OR_STALE_BACKLOG",
                    None,
                );
                return false;
            }
        }
        true
    }

    /// Delivers at most one globally bounded batch. Every row is first leased
    /// in the same tenant/RLS scope. A network timeout or any response whose
    /// signed receipt cannot be proven exact remains pending with bounded
    /// exponential backoff; no uncertain outcome is promoted to DELIVERED.
    pub async fn deliver_decision_evidence_once(
        &self,
        tenants: &BTreeSet<TenantId>,
        worker_id: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, ApprovalError> {
        self.deliver_decision_evidence_once_from(tenants, worker_id, now, 0)
            .await
    }

    async fn deliver_decision_evidence_once_from(
        &self,
        tenants: &BTreeSet<TenantId>,
        worker_id: &str,
        now: DateTime<Utc>,
        start_index: usize,
    ) -> Result<usize, ApprovalError> {
        require_uuid(worker_id)?;
        if tenants.is_empty() {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut remaining = DECISION_EVIDENCE_DELIVERY_BATCH_SIZE;
        let mut delivered = 0_usize;
        let ordered_tenants = decision_evidence_tenant_order(tenants, start_index);
        let mut processed = 0_usize;
        while remaining > 0 {
            let mut progressed = false;
            for tenant in &ordered_tenants {
                if remaining == 0 {
                    break;
                }
                let claim_time = if processed == 0 { now } else { Utc::now() };
                let mut pending = self
                    .claim_decision_evidence(tenant, worker_id, 1, claim_time)
                    .await?;
                let Some(item) = pending.pop() else {
                    continue;
                };
                progressed = true;
                processed = processed.saturating_add(1);
                remaining = remaining.saturating_sub(1);
                let binding_valid = item.authority_request.tenant_id == item.tenant_id
                    && item.authority_request.authority_event_id == item.authority_event_id
                    && item.authority_request.event.payload_hash == item.payload_digest
                    && item
                        .authority_request
                        .request_digest()
                        .is_ok_and(|digest| digest == item.request_digest);
                let outcome = if binding_valid {
                    self.evidence_publisher
                        .publish(&item.authority_request)
                        .await
                } else {
                    Err(ApprovalEvidenceDeliveryError::ReceiptInvalid)
                };
                match outcome {
                    Ok(receipt) => {
                        if let Err(error) = self
                            .mark_decision_evidence_delivered(
                                &item,
                                worker_id,
                                &receipt,
                                Utc::now(),
                            )
                            .await
                        {
                            decision_evidence_delivery_alert(
                                "MARK_DELIVERED_FAILED",
                                Some(&item.tenant_id),
                                Some(&item.authority_event_id),
                                &error.to_string(),
                                Some(item.delivery_attempts),
                            );
                            return Err(error);
                        }
                        delivered = delivered.saturating_add(1);
                    }
                    Err(error) => {
                        let retry_code = error.retry_code();
                        if let Err(release_error) = self
                            .release_decision_evidence_for_retry(
                                &item,
                                worker_id,
                                retry_code,
                                Utc::now(),
                            )
                            .await
                        {
                            decision_evidence_delivery_alert(
                                "RELEASE_RETRY_FAILED",
                                Some(&item.tenant_id),
                                Some(&item.authority_event_id),
                                &release_error.to_string(),
                                Some(item.delivery_attempts),
                            );
                            return Err(release_error);
                        }
                        decision_evidence_delivery_alert(
                            "PUBLISH_RETRY",
                            Some(&item.tenant_id),
                            Some(&item.authority_event_id),
                            retry_code,
                            Some(item.delivery_attempts),
                        );
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(delivered)
    }

    pub async fn run_decision_evidence_delivery(
        self: Arc<Self>,
        tenants: BTreeSet<TenantId>,
        worker_id: String,
    ) -> Result<(), ApprovalError> {
        require_uuid(&worker_id)?;
        if tenants.is_empty() {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut start_index = 0_usize;
        loop {
            let delivered = match self
                .deliver_decision_evidence_once_from(&tenants, &worker_id, Utc::now(), start_index)
                .await
            {
                Ok(delivered) => delivered,
                Err(error) => {
                    decision_evidence_delivery_alert(
                        "BATCH_FAILED",
                        None,
                        None,
                        &error.to_string(),
                        None,
                    );
                    0
                }
            };
            start_index = (start_index + 1) % tenants.len();
            tokio::time::sleep(if delivered == 0 {
                std::time::Duration::from_secs(2)
            } else {
                std::time::Duration::from_millis(100)
            })
            .await;
        }
    }

    async fn claim_decision_evidence(
        &self,
        tenant: &TenantId,
        worker_id: &str,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<PendingApprovalDecisionEvidence>, ApprovalError> {
        if limit == 0 || limit > DECISION_EVIDENCE_DELIVERY_BATCH_SIZE {
            return Err(ApprovalError::RequestInvalid);
        }
        let limit = i64::try_from(limit).map_err(|_| ApprovalError::RequestInvalid)?;
        let lease_expires_at =
            now + chrono::Duration::seconds(DECISION_EVIDENCE_DELIVERY_LEASE_SECONDS);
        let mut transaction = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "WITH candidates AS MATERIALIZED (\
               SELECT tenant_id,authority_event_id \
                 FROM approval_decision_evidence_outbox \
                WHERE tenant_id=$1::uuid AND delivered_at IS NULL \
                  AND next_attempt_at <= $3 \
                  AND (lease_expires_at IS NULL OR lease_expires_at <= $3) \
                ORDER BY next_attempt_at,created_at,authority_event_id \
                FOR UPDATE SKIP LOCKED LIMIT $5\
             ) \
             UPDATE approval_decision_evidence_outbox o \
                SET lease_owner=$2::uuid,lease_expires_at=$4,\
                    delivery_attempts=o.delivery_attempts+1,last_attempt_at=$3,\
                    last_error_code=NULL \
               FROM candidates c \
              WHERE o.tenant_id=c.tenant_id AND o.authority_event_id=c.authority_event_id \
             RETURNING o.authority_event_id::text,o.request_digest::text,\
                       o.payload_digest::text,o.authority_request,o.delivery_attempts",
        )
        .bind(&tenant.0)
        .bind(worker_id)
        .bind(now)
        .bind(lease_expires_at)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(database)?;
        let mut pending = Vec::with_capacity(rows.len());
        for row in rows {
            let authority_request = serde_json::from_value::<AuthorityEvidenceEventRequest>(
                row.try_get("authority_request").map_err(database)?,
            )
            .map_err(|_| ApprovalError::DatabaseUnavailable)?;
            pending.push(PendingApprovalDecisionEvidence {
                tenant_id: tenant.clone(),
                authority_event_id: row.try_get("authority_event_id").map_err(database)?,
                request_digest: row.try_get("request_digest").map_err(database)?,
                payload_digest: row.try_get("payload_digest").map_err(database)?,
                authority_request,
                delivery_attempts: row.try_get("delivery_attempts").map_err(database)?,
            });
        }
        transaction.commit().await.map_err(database)?;
        Ok(pending)
    }

    async fn mark_decision_evidence_delivered(
        &self,
        pending: &PendingApprovalDecisionEvidence,
        worker_id: &str,
        receipt: &agent_trust_contracts::SignedAuthorityEvidenceReceipt,
        delivered_at: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        self.delivery_evidence_keyring.verify_authority_delivery(
            &pending.authority_request,
            receipt,
            delivered_at,
        )?;
        let receipt_value =
            serde_json::to_value(receipt).map_err(|_| ApprovalError::GrantInvalid)?;
        let mut transaction = self.begin_tenant(&pending.tenant_id).await?;
        let affected = sqlx::query(
            "UPDATE approval_decision_evidence_outbox \
                SET signed_authority_receipt=$6,delivered_at=$7,lease_owner=NULL,\
                    lease_expires_at=NULL,last_error_code=NULL,next_attempt_at=$7 \
              WHERE tenant_id=$1::uuid AND authority_event_id=$2::uuid \
                AND request_digest=$3 AND payload_digest=$4 AND lease_owner=$5::uuid \
                AND delivered_at IS NULL AND lease_expires_at > $7",
        )
        .bind(&pending.tenant_id.0)
        .bind(&pending.authority_event_id)
        .bind(&pending.request_digest)
        .bind(&pending.payload_digest)
        .bind(worker_id)
        .bind(receipt_value)
        .bind(delivered_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?
        .rows_affected();
        if affected != 1 {
            return Err(ApprovalError::ConcurrentMutation);
        }
        transaction.commit().await.map_err(database)?;
        Ok(())
    }

    async fn release_decision_evidence_for_retry(
        &self,
        pending: &PendingApprovalDecisionEvidence,
        worker_id: &str,
        failure_code: &str,
        failed_at: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        if !matches!(
            failure_code,
            "CONFIGURATION_INVALID" | "OUTCOME_UNKNOWN" | "RECEIPT_INVALID"
        ) {
            return Err(ApprovalError::RequestInvalid);
        }
        let next_attempt_at = failed_at
            + chrono::Duration::seconds(decision_evidence_retry_seconds(pending.delivery_attempts));
        let mut transaction = self.begin_tenant(&pending.tenant_id).await?;
        let affected = sqlx::query(
            "UPDATE approval_decision_evidence_outbox \
                SET lease_owner=NULL,lease_expires_at=NULL,last_error_code=$5,\
                    next_attempt_at=$6 \
              WHERE tenant_id=$1::uuid AND authority_event_id=$2::uuid \
                AND request_digest=$3 AND lease_owner=$4::uuid AND delivered_at IS NULL",
        )
        .bind(&pending.tenant_id.0)
        .bind(&pending.authority_event_id)
        .bind(&pending.request_digest)
        .bind(worker_id)
        .bind(failure_code)
        .bind(next_attempt_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?
        .rows_affected();
        if affected != 1 {
            return Err(ApprovalError::ConcurrentMutation);
        }
        transaction.commit().await.map_err(database)?;
        Ok(())
    }

    pub async fn create_case(
        &self,
        envelope: &ApprovalCaseCreateEnvelope,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalCase, ApprovalError> {
        validate_create(envelope)?;
        self.review_evidence_keyring
            .verify_request(&envelope.request, now)?;
        validate_principal(principal, now)?;
        require_same_tenant(&envelope.request.tenant_id, &principal.tenant_id)?;
        if envelope.request.requester_subject != principal.subject {
            return Err(ApprovalError::ScopeForbidden);
        }
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(envelope)?;
        let scope = "case:create";
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:request", now).await?;
        if let Some(replay) = replay::<ApprovalCase>(
            &mut transaction,
            &principal.tenant_id,
            scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            if replay.schema_version != APPROVAL_CASE_SCHEMA_VERSION
                || replay.request.tenant_id != principal.tenant_id
                || replay.request.requester_subject != principal.subject
            {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let ttl = i64::try_from(envelope.request.requested_ttl_seconds)
            .map_err(|_| ApprovalError::RequestInvalid)?;
        let case_id = Uuid::new_v4().to_string();
        let status = if envelope.policy.approval_type == ApprovalType::Emergency {
            ApprovalStatus::PostReviewRequired
        } else {
            ApprovalStatus::Pending
        };
        let post_review_due_at = (envelope.policy.approval_type == ApprovalType::Emergency)
            .then_some(now + chrono::Duration::hours(24));
        let case = ApprovalCase {
            schema_version: APPROVAL_CASE_SCHEMA_VERSION.into(),
            case_id: case_id.clone(),
            request: envelope.request.clone(),
            policy: envelope.policy.clone(),
            status,
            decisions: Vec::new(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl),
            post_review_due_at,
        };
        sqlx::query(
            "INSERT INTO approval_cases \
             (tenant_id,case_id,task_id,step_id,action_hash,plan_hash,parameter_hash,resource,\
              resource_version,policy_version,status,request,policy,created_at,expires_at,\
              post_review_due_at,request_digest,created_by,updated_at) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$14)",
        )
        .bind(&principal.tenant_id.0)
        .bind(&case.case_id)
        .bind(&case.request.task_id.0)
        .bind(&case.request.step_id.0)
        .bind(&case.request.action_hash.0)
        .bind(&case.request.plan_hash)
        .bind(&case.request.parameter_hash)
        .bind(&case.request.resource)
        .bind(&case.request.resource_version.0)
        .bind(&case.request.policy_version.0)
        .bind(status_text(case.status))
        .bind(serde_json::to_value(&case.request).map_err(|_| ApprovalError::RequestInvalid)?)
        .bind(serde_json::to_value(&case.policy).map_err(|_| ApprovalError::RequestInvalid)?)
        .bind(case.created_at)
        .bind(case.expires_at)
        .bind(case.post_review_due_at)
        .bind(&request_digest)
        .bind(&principal.subject)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        append_event(
            &mut transaction,
            &principal.tenant_id,
            "CASE_CREATED",
            &case.case_id,
            &principal.subject,
            &request_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            scope,
            idempotency_key,
            &request_digest,
            &case,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(case)
    }

    pub async fn get_case(
        &self,
        tenant: &TenantId,
        case_id: &str,
    ) -> Result<ApprovalCase, ApprovalError> {
        require_uuid(case_id)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let case = load_case(&mut transaction, tenant, case_id, false).await?;
        transaction.commit().await.map_err(database)?;
        Ok(case)
    }

    pub async fn list_authoritative_cases(
        &self,
        tenant: &TenantId,
        resource: &str,
        limit: u16,
        encoded_cursor: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<AuthoritativeApprovalPage, ApprovalError> {
        require_uuid(&tenant.0)?;
        if !dashboard_resource(resource) || limit == 0 || limit > MAX_AUTHORITATIVE_PAGE_SIZE {
            return Err(ApprovalError::RequestInvalid);
        }
        let cursor = encoded_cursor
            .map(|value| decode_authoritative_cursor(value, tenant, resource, &self.signer, now))
            .transpose()?;
        let cursor_created_at = cursor.as_ref().map(|value| value.created_at.to_owned());
        let cursor_case_id = cursor.as_ref().map(|value| value.case_id.as_str());
        let fetch_limit = i64::from(limit) + 1;
        let mut transaction = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT case_id::text,request,status,created_at,expires_at \
             FROM approval_cases \
             WHERE tenant_id=$1::uuid \
               AND ($2::timestamptz IS NULL OR created_at < $2 \
                    OR (created_at=$2 AND case_id < $3::uuid)) \
             ORDER BY created_at DESC,case_id DESC LIMIT $4",
        )
        .bind(&tenant.0)
        .bind(cursor_created_at)
        .bind(cursor_case_id)
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(database)?;

        let has_more = rows.len() > usize::from(limit);
        let mut results = Vec::with_capacity(rows.len().min(usize::from(limit)));
        let mut last_scanned = None;
        for row in rows.into_iter().take(usize::from(limit)) {
            let case_id = row.try_get::<String, _>("case_id").map_err(database)?;
            let stored_status =
                parse_status(&row.try_get::<String, _>("status").map_err(database)?)?;
            let created_at = row
                .try_get::<DateTime<Utc>, _>("created_at")
                .map_err(database)?;
            let expires_at = row
                .try_get::<DateTime<Utc>, _>("expires_at")
                .map_err(database)?;
            if !canonical_uuid(&case_id) {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            last_scanned = Some((created_at.to_owned(), case_id.clone()));
            let request = match parse_authoritative_request(
                row.try_get::<Value, _>("request").map_err(database)?,
                tenant,
            )? {
                Some(request) => request,
                // A legacy row has no safe domain review package. It stays in the immutable
                // database history, is never upgraded with fabricated content, and cannot block
                // newer reviewable cases from the bounded cursor scan.
                None => continue,
            };
            if request.tenant_id != *tenant {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            self.review_evidence_keyring
                .verify_historical_request(&request, created_at)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?;
            let domain = approval_case_domain(&request);
            let (coding_details, industrial_details) = match (&domain, &request.review_context) {
                (ApprovalCaseDomain::Coding, ApprovalReviewContext::Coding(details)) => {
                    (Some(details.clone()), None)
                }
                (ApprovalCaseDomain::Industrial, ApprovalReviewContext::Industrial(details)) => {
                    (None, Some(details.clone()))
                }
                _ => return Err(ApprovalError::DatabaseUnavailable),
            };
            let status = approval_case_view_status(stored_status, expires_at, now);
            let safe_summary = match domain {
                ApprovalCaseDomain::Coding => "Review governed coding action",
                ApprovalCaseDomain::Industrial => "Review supervised industrial action",
            }
            .to_string();
            let view = ApprovalCaseView {
                schema_version: APPROVAL_CASE_VIEW_SCHEMA_VERSION.into(),
                case_id: case_id.clone(),
                domain,
                safe_summary,
                action_hash: request.action_hash.0,
                resource: request.resource,
                resource_version: request.resource_version.0,
                policy_version: request.policy_version.0,
                risk: request.risk,
                coding_details,
                industrial_details,
                evidence_refs: request.review_evidence.evidence_refs(),
                status,
            };
            validate_case_view(&view)?;
            results.push((view, created_at, case_id));
        }
        transaction.commit().await.map_err(database)?;

        let next_cursor = if has_more {
            let (created_at, case_id) = last_scanned
                .as_ref()
                .ok_or(ApprovalError::DatabaseUnavailable)?;
            Some(encode_authoritative_cursor(
                tenant,
                resource,
                created_at.to_owned(),
                case_id,
                &self.signer,
                now,
            )?)
        } else {
            None
        };
        let items = results
            .into_iter()
            .map(|(view, _, _)| view)
            .collect::<Vec<_>>();
        let material = AuthoritativeApprovalPageMaterial {
            schema_version: AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION,
            authoritative: true,
            tenant_id: &tenant.0,
            resource,
            items: &items,
            next_cursor: &next_cursor,
        };
        let data_digest = canonical_digest(&material)?;
        Ok(AuthoritativeApprovalPage {
            schema_version: AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION.into(),
            authoritative: true,
            tenant_id: tenant.0.clone(),
            resource: resource.into(),
            items,
            next_cursor,
            data_digest,
        })
    }

    pub async fn decide(
        &self,
        case_id: &str,
        envelope: &ApprovalDecisionEnvelope,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalDecisionResult, ApprovalError> {
        require_uuid(case_id)?;
        if envelope.schema_version != APPROVAL_DECISION_SCHEMA_VERSION
            || !valid_approval_human_text(&envelope.reason)
        {
            return Err(ApprovalError::RequestInvalid);
        }
        validate_principal(principal, now)?;
        validate_idempotency_key(idempotency_key)?;
        let request_digest = approval_decision_request_digest(case_id, envelope)?;
        let scope = format!("case:decision:{case_id}:{}", principal.subject);
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:decide", now).await?;
        if let Some(replay) = replay::<ApprovalDecisionResult>(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            validate_decision_result_replay(
                &replay,
                case_id,
                envelope,
                principal,
                idempotency_key,
                &request_digest,
                &self.decision_evidence_keyring,
                now,
            )?;
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let mut case = load_case(&mut transaction, &principal.tenant_id, case_id, true).await?;
        if now >= case.expires_at {
            update_case_status(
                &mut transaction,
                &principal.tenant_id,
                case_id,
                ApprovalStatus::Expired,
                now,
            )
            .await?;
            transaction.commit().await.map_err(database)?;
            return Err(ApprovalError::Expired);
        }
        if case
            .decisions
            .iter()
            .any(|decision| decision.approver_subject == principal.subject)
        {
            return Err(ApprovalError::DuplicateApprover);
        }
        SoDEngine::validate(&case, &principal.identity(), now)?;
        let decision_text = match envelope.decision {
            ApprovalDecision::Approve => {
                if !matches!(
                    case.status,
                    ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired
                ) {
                    return Err(ApprovalError::LifecycleInvalid);
                }
                "APPROVE"
            }
            ApprovalDecision::Reject => {
                if !matches!(
                    case.status,
                    ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired
                ) {
                    return Err(ApprovalError::LifecycleInvalid);
                }
                "REJECT"
            }
            ApprovalDecision::PostReviewed => {
                if case.policy.approval_type != ApprovalType::Emergency
                    || case.status != ApprovalStatus::PostReviewRequired
                    || case
                        .post_review_due_at
                        .is_none_or(|deadline| now > deadline)
                    || !grant_exists(&mut transaction, &principal.tenant_id, case_id).await?
                {
                    return Err(ApprovalError::LifecycleInvalid);
                }
                "POST_REVIEWED"
            }
        };
        sqlx::query(
            "INSERT INTO approval_decisions \
             (tenant_id,case_id,approver_subject,decision,roles,reason,strong_auth,decided_at,\
              assertion_issuer,assertion_jti,assertion_request_digest,assertion_digest,assertion_expires_at) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10::uuid,$11,$12,$13)",
        )
        .bind(&principal.tenant_id.0)
        .bind(case_id)
        .bind(&principal.subject)
        .bind(decision_text)
        .bind(serde_json::to_value(&principal.roles).map_err(|_| ApprovalError::RequestInvalid)?)
        .bind(&envelope.reason)
        .bind(principal.strong_auth)
        .bind(now)
        .bind(&principal.assertion_issuer)
        .bind(&principal.assertion_jti)
        .bind(&principal.assertion_request_digest)
        .bind(&principal.assertion_digest)
        .bind(principal.assertion_expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_decision_insert)?;
        case.decisions.push(ApprovalDecisionRecord {
            approver_subject: principal.subject.clone(),
            roles: principal.roles.clone(),
            decision: decision_text.into(),
            reason: envelope.reason.clone(),
            decided_at: now,
            strong_auth: principal.strong_auth,
        });
        case.decisions.sort_by(|left, right| {
            left.decided_at
                .cmp(&right.decided_at)
                .then_with(|| left.approver_subject.cmp(&right.approver_subject))
        });
        let next_status = match envelope.decision {
            ApprovalDecision::Reject => ApprovalStatus::Rejected,
            ApprovalDecision::PostReviewed => ApprovalStatus::Approved,
            ApprovalDecision::Approve => {
                let approvals = case
                    .decisions
                    .iter()
                    .filter(|record| record.decision == "APPROVE")
                    .map(|record| &record.approver_subject)
                    .collect::<BTreeSet<_>>()
                    .len() as u32;
                if approvals >= case.policy.minimum_approvers {
                    if case.policy.approval_type == ApprovalType::Emergency {
                        ApprovalStatus::PostReviewRequired
                    } else {
                        ApprovalStatus::Approved
                    }
                } else {
                    case.status
                }
            }
        };
        update_case_status(
            &mut transaction,
            &principal.tenant_id,
            case_id,
            next_status,
            now,
        )
        .await?;
        case.status = next_status;
        append_event(
            &mut transaction,
            &principal.tenant_id,
            decision_text,
            case_id,
            &principal.subject,
            &request_digest,
            now,
        )
        .await?;
        let (evidence_receipt, authority_request) = self.decision_evidence_receipt(
            &case,
            envelope,
            principal,
            idempotency_key,
            &request_digest,
            now,
        )?;
        persist_decision_evidence(
            &mut transaction,
            &principal.tenant_id,
            &case,
            &evidence_receipt,
            &authority_request,
            now,
        )
        .await?;
        let result = ApprovalDecisionResult {
            schema_version: APPROVAL_DECISION_RESULT_SCHEMA_VERSION.into(),
            approval_case: case,
            evidence_receipt,
        };
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
            &result,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(result)
    }

    fn decision_evidence_receipt(
        &self,
        case: &ApprovalCase,
        envelope: &ApprovalDecisionEnvelope,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        request_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<
        (
            ApprovalDecisionEvidenceReceipt,
            AuthorityEvidenceEventRequest,
        ),
        ApprovalError,
    > {
        if !self
            .decision_evidence_keyring
            .covers_active_signer_at(&self.signer, now)
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut receipt = ApprovalDecisionEvidenceReceipt {
            schema_version: APPROVAL_DECISION_EVIDENCE_SCHEMA_VERSION.into(),
            receipt_id: Uuid::new_v4().to_string(),
            tenant_id: principal.tenant_id.0.clone(),
            case_id: case.case_id.clone(),
            task_id: case.request.task_id.0.clone(),
            decision: envelope.decision,
            decision_reason_digest: hex(Sha256::digest(envelope.reason.as_bytes())),
            request_digest: request_digest.into(),
            decision_digest: String::new(),
            idempotency_key_digest: hex(Sha256::digest(idempotency_key.as_bytes())),
            actor_subject: principal.subject.clone(),
            principal_assertion_jti: principal.assertion_jti.clone(),
            principal_assertion_request_digest: principal.assertion_request_digest.clone(),
            principal_assertion_digest: principal.assertion_digest.clone(),
            approval_case_digest: canonical_digest(case)?,
            action_hash: case.request.action_hash.0.clone(),
            step_id: case.request.step_id.0.clone(),
            plan_hash: case.request.plan_hash.clone(),
            parameter_hash: case.request.parameter_hash.clone(),
            resource: case.request.resource.clone(),
            resource_version: case.request.resource_version.0.clone(),
            policy_version: case.request.policy_version.0.clone(),
            environment: case.request.environment.clone(),
            risk: case.request.risk,
            case_status: case.status,
            decided_at: now,
            evidence_ref: String::new(),
            evidence_digest: String::new(),
            authority_request_digest: String::new(),
            evidence_outbox_ref: String::new(),
            issuer: self.signer.issuer().into(),
            key_id: self.signer.key_id().into(),
            key_usage: APPROVAL_DECISION_EVIDENCE_KEY_USAGE.into(),
            signature: String::new(),
        };
        receipt.decision_digest = receipt.expected_decision_digest()?;
        receipt.evidence_ref = receipt.expected_evidence_ref();
        let authority_request =
            decision_authority_evidence_request(&receipt, case, &self.evidence_source_identity)?;
        receipt.authority_request_digest = authority_request
            .request_digest()
            .map_err(|_| ApprovalError::RequestInvalid)?;
        receipt.evidence_outbox_ref = receipt.expected_evidence_outbox_ref();
        self.signer.sign_decision_evidence(&mut receipt)?;
        self.decision_evidence_keyring
            .verify_receipt(&receipt, now)?;
        Ok((receipt, authority_request))
    }

    pub async fn issue_grant(
        &self,
        case_id: &str,
        request: &ApprovalGrantIssueRequest,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<EnterpriseApprovalGrant, ApprovalError> {
        require_uuid(case_id)?;
        if request.schema_version != APPROVAL_SCHEMA_VERSION {
            return Err(ApprovalError::RequestInvalid);
        }
        validate_principal(principal, now)?;
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(&(case_id, request))?;
        let scope = format!("case:grant:{case_id}");
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:issue", now).await?;
        if let Some(replay) = replay::<EnterpriseApprovalGrant>(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            verify_grant_signature(
                &replay,
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
                now,
            )?;
            if replay.tenant_id != principal.tenant_id || replay.case_id != case_id {
                return Err(ApprovalError::GrantInvalid);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let case = load_case(&mut transaction, &principal.tenant_id, case_id, true).await?;
        if now >= case.expires_at {
            return Err(ApprovalError::Expired);
        }
        if !matches!(
            case.status,
            ApprovalStatus::Approved | ApprovalStatus::PostReviewRequired
        ) {
            return Err(ApprovalError::GrantNotReady);
        }
        let approvals = case
            .decisions
            .iter()
            .filter(|record| record.decision == "APPROVE")
            .map(|record| &record.approver_subject)
            .collect::<BTreeSet<_>>()
            .len() as u32;
        if approvals < case.policy.minimum_approvers
            || case.request.requested_uses != 1
            || case.policy.maximum_uses != 1
        {
            return Err(ApprovalError::GrantNotReady);
        }
        if let Some((existing, remaining_uses, revoked_at)) =
            load_grant_by_case(&mut transaction, &principal.tenant_id, case_id).await?
        {
            verify_grant_signature(
                &existing,
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
                now,
            )?;
            if existing.tenant_id != principal.tenant_id || existing.case_id != case_id {
                return Err(ApprovalError::GrantInvalid);
            }
            if revoked_at.is_some() {
                return Err(ApprovalError::Revoked);
            }
            if remaining_uses != 1 {
                return Err(ApprovalError::GrantReplayed);
            }
            save_replay(
                &mut transaction,
                &principal.tenant_id,
                &scope,
                idempotency_key,
                &request_digest,
                &existing,
                now,
            )
            .await?;
            transaction.commit().await.map_err(database)?;
            return Ok(existing);
        }
        let mut grant = make_grant(self.signer.issuer(), self.signer.key_id(), &case, now);
        self.signer.sign_grant(&mut grant)?;
        let grant_digest = canonical_digest(&grant)?;
        let lookup_digest = grant_lookup_digest_from_grant(&grant)?;
        sqlx::query(
            "INSERT INTO approval_grants \
             (tenant_id,grant_id,case_id,grant_hash,signed_grant,remaining_uses,revoked_at,expires_at,\
              binding_hash,task_id,step_id,action_hash,plan_hash,parameter_hash,resource,resource_version,\
              policy_version,environment,maximum_risk,issued_at,issued_by,key_id) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,1,NULL,$6,$7,$8::uuid,$9::uuid,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
        )
        .bind(&principal.tenant_id.0)
        .bind(&grant.grant_id.0)
        .bind(case_id)
        .bind(&grant_digest)
        .bind(serde_json::to_value(&grant).map_err(|_| ApprovalError::GrantInvalid)?)
        .bind(grant.expires_at)
        .bind(&lookup_digest)
        .bind(&grant.task_id.0)
        .bind(&grant.step_id.0)
        .bind(&grant.action_hash.0)
        .bind(&grant.plan_hash)
        .bind(&grant.parameter_hash)
        .bind(&grant.resource)
        .bind(&grant.resource_version.0)
        .bind(&grant.policy_version.0)
        .bind(&grant.environment)
        .bind(risk_text(grant.maximum_risk))
        .bind(grant.issued_at)
        .bind(&principal.subject)
        .bind(&grant.key_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_grant_insert)?;
        append_event(
            &mut transaction,
            &principal.tenant_id,
            "GRANT_ISSUED",
            &grant.grant_id.0,
            &principal.subject,
            &grant_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
            &grant,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(grant)
    }

    pub async fn revoke_grant(
        &self,
        grant_id: &str,
        request: &ApprovalGrantRevocationRequest,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalGrantRevocationReceipt, ApprovalError> {
        require_uuid(grant_id)?;
        if request.schema_version != APPROVAL_SCHEMA_VERSION
            || !valid_approval_human_text(&request.reason)
        {
            return Err(ApprovalError::RequestInvalid);
        }
        validate_principal(principal, now)?;
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(&(grant_id, request))?;
        let scope = format!("grant:revoke:{grant_id}");
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:revoke", now).await?;
        if let Some(replay) = replay::<ApprovalGrantRevocationReceipt>(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            replay.verify(
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
            )?;
            if replay.tenant_id != principal.tenant_id.0 || replay.grant_id != grant_id {
                return Err(ApprovalError::GrantInvalid);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let row = sqlx::query(
            "SELECT case_id::text,signed_grant,grant_hash,revocation_receipt FROM approval_grants \
             WHERE tenant_id=$1::uuid AND grant_id=$2::uuid FOR UPDATE",
        )
        .bind(&principal.tenant_id.0)
        .bind(grant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::GrantInvalid)?;
        let case_id = row.try_get::<String, _>("case_id").map_err(database)?;
        let signed_grant = row.try_get::<Value, _>("signed_grant").map_err(database)?;
        let grant_hash = row.try_get::<String, _>("grant_hash").map_err(database)?;
        let existing = row
            .try_get::<Option<Value>, _>("revocation_receipt")
            .map_err(database)?;
        let (receipt, newly_revoked) = if let Some(value) = existing {
            let receipt: ApprovalGrantRevocationReceipt =
                serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
            receipt.verify(
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
            )?;
            if receipt.tenant_id != principal.tenant_id.0
                || receipt.grant_id != grant_id
                || receipt.case_id != case_id
            {
                return Err(ApprovalError::GrantInvalid);
            }
            (receipt, false)
        } else {
            let grant: EnterpriseApprovalGrant = serde_json::from_value(signed_grant)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?;
            verify_grant_signature(
                &grant,
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
                now,
            )?;
            if grant.tenant_id != principal.tenant_id
                || grant.grant_id.0 != grant_id
                || grant.case_id != case_id
                || canonical_digest(&grant)? != grant_hash
            {
                return Err(ApprovalError::GrantInvalid);
            }
            let mut receipt = ApprovalGrantRevocationReceipt {
                schema_version: "agenttrust.approval-grant-revocation.v1".into(),
                receipt_id: Uuid::new_v4().to_string(),
                tenant_id: principal.tenant_id.0.clone(),
                grant_id: grant_id.into(),
                case_id: case_id.clone(),
                reason_digest: hex(Sha256::digest(request.reason.as_bytes())),
                revoked_by: principal.subject.clone(),
                principal_assertion_jti: principal.assertion_jti.clone(),
                principal_assertion_digest: principal.assertion_digest.clone(),
                revoked_at: now,
                issuer: self.signer.issuer().into(),
                key_id: self.signer.key_id().into(),
                signature: String::new(),
            };
            self.signer.sign_revocation(&mut receipt)?;
            sqlx::query(
                "UPDATE approval_grants SET remaining_uses=0,revoked_at=$3,revoked_by=$4,\
                 revocation_reason_digest=$5,revocation_receipt=$6 \
                 WHERE tenant_id=$1::uuid AND grant_id=$2::uuid",
            )
            .bind(&principal.tenant_id.0)
            .bind(grant_id)
            .bind(now)
            .bind(&principal.subject)
            .bind(&receipt.reason_digest)
            .bind(serde_json::to_value(&receipt).map_err(|_| ApprovalError::GrantInvalid)?)
            .execute(&mut *transaction)
            .await
            .map_err(database)?;
            update_case_status(
                &mut transaction,
                &principal.tenant_id,
                &case_id,
                ApprovalStatus::Revoked,
                now,
            )
            .await?;
            (receipt, true)
        };
        if newly_revoked {
            append_event(
                &mut transaction,
                &principal.tenant_id,
                "GRANT_REVOKED",
                grant_id,
                &principal.subject,
                &receipt.reason_digest,
                now,
            )
            .await?;
        }
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(receipt)
    }

    pub async fn consume_grant(
        &self,
        request: &ApprovalConsumptionRequest,
        tenant: &TenantId,
        subject: &str,
        client_identity: &str,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalGrantReceipt, ApprovalError> {
        validate_consumption(request)?;
        if request.tenant_id != tenant.0
            || !identifier(subject)
            || !service_client_identity(client_identity)
        {
            return Err(ApprovalError::ScopeForbidden);
        }
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(request)?;
        let scope = format!("grant:consume:{client_identity}:{subject}");
        let mut transaction = self.begin_tenant(tenant).await?;
        lock_idempotency(&mut transaction, tenant, &scope, idempotency_key).await?;
        if let Some(replay) = replay::<ApprovalGrantReceipt>(
            &mut transaction,
            tenant,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            verify_consumption_replay(
                &mut transaction,
                &self.signer,
                tenant,
                request,
                subject,
                client_identity,
                &replay,
            )
            .await?;
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let lookup_digest = grant_lookup_digest_from_request(request)?;
        let row = sqlx::query(
            "SELECT grant_id::text,case_id::text,signed_grant,grant_hash,remaining_uses,\
                    revoked_at,expires_at \
             FROM approval_grants WHERE tenant_id=$1::uuid AND binding_hash=$2 FOR UPDATE",
        )
        .bind(&tenant.0)
        .bind(&lookup_digest)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::GrantNotReady)?;
        let grant: EnterpriseApprovalGrant =
            serde_json::from_value(row.try_get::<Value, _>("signed_grant").map_err(database)?)
                .map_err(|_| ApprovalError::GrantInvalid)?;
        let grant_id = row.try_get::<String, _>("grant_id").map_err(database)?;
        let case_id = row.try_get::<String, _>("case_id").map_err(database)?;
        let remaining = row.try_get::<i32, _>("remaining_uses").map_err(database)?;
        let revoked_at = row
            .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
            .map_err(database)?;
        let expires_at = row
            .try_get::<DateTime<Utc>, _>("expires_at")
            .map_err(database)?;
        let grant_digest = row.try_get::<String, _>("grant_hash").map_err(database)?;
        verify_grant_signature(
            &grant,
            self.signer.issuer(),
            self.signer.key_id(),
            &self.signer.verifying_key(),
            now,
        )?;
        if revoked_at.is_some()
            || expires_at <= now
            || remaining != 1
            || canonical_digest(&grant)? != grant_digest
            || !consumption_matches_grant(request, &grant)
        {
            return Err(ApprovalError::GrantNotReady);
        }
        let case = load_case(&mut transaction, tenant, &case_id, true).await?;
        if matches!(
            case.status,
            ApprovalStatus::Rejected
                | ApprovalStatus::Revoked
                | ApprovalStatus::Expired
                | ApprovalStatus::Consumed
        ) {
            return Err(ApprovalError::GrantNotReady);
        }
        let updated = sqlx::query(
            "UPDATE approval_grants SET remaining_uses=0,last_consumed_at=$3 \
             WHERE tenant_id=$1::uuid AND grant_id=$2::uuid AND remaining_uses=1 AND revoked_at IS NULL",
        )
        .bind(&tenant.0)
        .bind(&grant_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(ApprovalError::ConcurrentMutation);
        }
        let mut signed = SignedApprovalConsumptionReceipt {
            schema_version: APPROVAL_CONSUMPTION_SCHEMA_VERSION.into(),
            receipt_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.0.clone(),
            grant_id: grant_id.clone(),
            case_id: case_id.clone(),
            request: request.clone(),
            grant: grant.clone(),
            request_digest: request_digest.clone(),
            grant_digest,
            idempotency_key_digest: hex(Sha256::digest(idempotency_key.as_bytes())),
            consumed_by: subject.into(),
            client_identity: client_identity.into(),
            consumed_at: now,
            remaining_uses: 0,
            issuer: self.signer.issuer().into(),
            key_id: self.signer.key_id().into(),
            signature: String::new(),
        };
        self.signer.sign_consumption(&mut signed)?;
        let payload_digest = hex(Sha256::digest(signed.signing_bytes()?));
        let consumption_ref = consumption_reference(&signed, &payload_digest)?;
        let wire = ApprovalGrantReceipt {
            schema_version: APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION.into(),
            grant,
            consumed_at: now,
            remaining_uses: 0,
            consumption_ref,
        };
        sqlx::query(
            "INSERT INTO approval_consumptions \
             (tenant_id,receipt_id,grant_id,case_id,idempotency_key,request_digest,\
              consumption_ref,signed_receipt,wire_receipt,consumed_by,client_identity,consumed_at) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(&tenant.0)
        .bind(&signed.receipt_id)
        .bind(&grant_id)
        .bind(&case_id)
        .bind(idempotency_key)
        .bind(&request_digest)
        .bind(&wire.consumption_ref)
        .bind(serde_json::to_value(&signed).map_err(|_| ApprovalError::GrantInvalid)?)
        .bind(serde_json::to_value(&wire).map_err(|_| ApprovalError::GrantInvalid)?)
        .bind(subject)
        .bind(client_identity)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_consumption_insert)?;
        if !wire.grant.break_glass {
            update_case_status(
                &mut transaction,
                tenant,
                &case_id,
                ApprovalStatus::Consumed,
                now,
            )
            .await?;
        }
        append_event(
            &mut transaction,
            tenant,
            "GRANT_CONSUMED",
            &signed.receipt_id,
            subject,
            &request_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            tenant,
            &scope,
            idempotency_key,
            &request_digest,
            &wire,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(wire)
    }

    pub async fn get_consumption_by_reference(
        &self,
        tenant: &TenantId,
        consumption_ref: &str,
    ) -> Result<SignedApprovalConsumptionReceipt, ApprovalError> {
        validate_consumption_reference(consumption_ref)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let value = sqlx::query_scalar::<_, Value>(
            "SELECT signed_receipt FROM approval_consumptions \
             WHERE tenant_id=$1::uuid AND consumption_ref=$2",
        )
        .bind(&tenant.0)
        .bind(consumption_ref)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::GrantInvalid)?;
        let receipt: SignedApprovalConsumptionReceipt =
            serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
        receipt.verify(
            self.signer.issuer(),
            self.signer.key_id(),
            &self.signer.verifying_key(),
        )?;
        let payload_digest = hex(Sha256::digest(receipt.signing_bytes()?));
        if consumption_reference(&receipt, &payload_digest)? != consumption_ref {
            return Err(ApprovalError::GrantInvalid);
        }
        transaction.commit().await.map_err(database)?;
        Ok(receipt)
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, ApprovalError> {
        require_uuid(&tenant.0)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .fetch_one(&mut *transaction)
            .await
            .map_err(database)?;
        Ok(transaction)
    }
}

async fn load_case(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
    lock: bool,
) -> Result<ApprovalCase, ApprovalError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT case_id::text,request,policy,status,created_at,expires_at,post_review_due_at \
         FROM approval_cases WHERE tenant_id=$1::uuid AND case_id=$2::uuid{suffix}"
    );
    let row = sqlx::query(&query)
        .bind(&tenant.0)
        .bind(case_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::CaseNotFound)?;
    let decisions = sqlx::query(
        "SELECT approver_subject,roles,decision,reason,decided_at,strong_auth \
         FROM approval_decisions WHERE tenant_id=$1::uuid AND case_id=$2::uuid \
         ORDER BY decided_at,approver_subject",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database)?
    .into_iter()
    .map(|decision| {
        Ok(ApprovalDecisionRecord {
            approver_subject: decision.try_get("approver_subject").map_err(database)?,
            roles: serde_json::from_value(decision.try_get("roles").map_err(database)?)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?,
            decision: decision.try_get("decision").map_err(database)?,
            reason: decision.try_get("reason").map_err(database)?,
            decided_at: decision.try_get("decided_at").map_err(database)?,
            strong_auth: decision.try_get("strong_auth").map_err(database)?,
        })
    })
    .collect::<Result<Vec<_>, ApprovalError>>()?;
    Ok(ApprovalCase {
        schema_version: APPROVAL_CASE_SCHEMA_VERSION.into(),
        case_id: row.try_get("case_id").map_err(database)?,
        request: serde_json::from_value(row.try_get("request").map_err(database)?)
            .map_err(|_| ApprovalError::DatabaseUnavailable)?,
        policy: serde_json::from_value(row.try_get("policy").map_err(database)?)
            .map_err(|_| ApprovalError::DatabaseUnavailable)?,
        status: parse_status(&row.try_get::<String, _>("status").map_err(database)?)?,
        decisions,
        created_at: row.try_get("created_at").map_err(database)?,
        expires_at: row.try_get("expires_at").map_err(database)?,
        post_review_due_at: row.try_get("post_review_due_at").map_err(database)?,
    })
}

async fn load_grant_by_case(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
) -> Result<Option<(EnterpriseApprovalGrant, i32, Option<DateTime<Utc>>)>, ApprovalError> {
    let row = sqlx::query(
        "SELECT signed_grant,remaining_uses,revoked_at FROM approval_grants \
         WHERE tenant_id=$1::uuid AND case_id=$2::uuid FOR UPDATE",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database)?;
    row.map(|row| {
        let grant =
            serde_json::from_value(row.try_get::<Value, _>("signed_grant").map_err(database)?)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?;
        Ok((
            grant,
            row.try_get("remaining_uses").map_err(database)?,
            row.try_get("revoked_at").map_err(database)?,
        ))
    })
    .transpose()
}

async fn verify_consumption_replay(
    transaction: &mut Transaction<'_, Postgres>,
    signer: &ApprovalSigner,
    tenant: &TenantId,
    request: &ApprovalConsumptionRequest,
    subject: &str,
    client_identity: &str,
    wire: &ApprovalGrantReceipt,
) -> Result<(), ApprovalError> {
    if wire.schema_version != APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION
        || wire.remaining_uses != 0
        || &wire.grant.tenant_id != tenant
        || !consumption_matches_grant(request, &wire.grant)
    {
        return Err(ApprovalError::GrantInvalid);
    }
    validate_consumption_reference(&wire.consumption_ref)?;
    verify_grant_signature(
        &wire.grant,
        signer.issuer(),
        signer.key_id(),
        &signer.verifying_key(),
        wire.consumed_at,
    )?;
    let value = sqlx::query_scalar::<_, Value>(
        "SELECT signed_receipt FROM approval_consumptions \
         WHERE tenant_id=$1::uuid AND consumption_ref=$2",
    )
    .bind(&tenant.0)
    .bind(&wire.consumption_ref)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database)?
    .ok_or(ApprovalError::GrantInvalid)?;
    let signed: SignedApprovalConsumptionReceipt =
        serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
    signed.verify(signer.issuer(), signer.key_id(), &signer.verifying_key())?;
    let payload_digest = hex(Sha256::digest(signed.signing_bytes()?));
    if &signed.request != request
        || &signed.grant != &wire.grant
        || signed.consumed_by != subject
        || signed.client_identity != client_identity
        || signed.consumed_at != wire.consumed_at
        || consumption_reference(&signed, &payload_digest)? != wire.consumption_ref
    {
        return Err(ApprovalError::GrantInvalid);
    }
    Ok(())
}

async fn grant_exists(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
) -> Result<bool, ApprovalError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM approval_grants \
         WHERE tenant_id=$1::uuid AND case_id=$2::uuid AND revoked_at IS NULL)",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database)
}

fn decision_authority_evidence_request(
    receipt: &ApprovalDecisionEvidenceReceipt,
    case: &ApprovalCase,
    evidence_source_identity: &str,
) -> Result<AuthorityEvidenceEventRequest, ApprovalError> {
    if !service_client_identity(evidence_source_identity) {
        return Err(ApprovalError::ConfigurationInvalid);
    }
    let request = AuthorityEvidenceEventRequest {
        schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
        tenant_id: case.request.tenant_id.clone(),
        task_id: case.request.task_id.clone(),
        authority_event_id: receipt.receipt_id.clone(),
        idempotency_key: IdempotencyKey(format!("approval-decision:{}", receipt.receipt_id)),
        source_kind: AuthorityEvidenceSourceKind::AuthenticatedEvent,
        control_binding: None,
        event: EvidenceEventDraft {
            schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
            tenant_id: case.request.tenant_id.clone(),
            task_id: case.request.task_id.clone(),
            event_type: EvidenceEventType::ApprovalDecision,
            actor_subject: receipt.actor_subject.clone(),
            source_service: evidence_source_identity.into(),
            trace_id: receipt.principal_assertion_jti.clone(),
            span_id: receipt.receipt_id.clone(),
            payload_hash: receipt.decision_digest.clone(),
            safe_summary: "Enterprise approval decision persisted".into(),
            artifact_refs: vec![ArtifactRef(receipt.evidence_ref.clone())],
            occurred_at: receipt.decided_at,
        },
        requested_at: receipt.decided_at,
    };
    request
        .request_digest()
        .map_err(|_| ApprovalError::RequestInvalid)?;
    Ok(request)
}

async fn persist_decision_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case: &ApprovalCase,
    receipt: &ApprovalDecisionEvidenceReceipt,
    authority_request: &AuthorityEvidenceEventRequest,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    let authority_request_digest = authority_request
        .request_digest()
        .map_err(|_| ApprovalError::RequestInvalid)?;
    let signed_receipt =
        serde_json::to_value(receipt).map_err(|_| ApprovalError::RequestInvalid)?;
    let request_value =
        serde_json::to_value(authority_request).map_err(|_| ApprovalError::RequestInvalid)?;
    sqlx::query(
        "INSERT INTO approval_decision_evidence_receipts \
         (tenant_id,receipt_id,case_id,approver_subject,decision,decision_digest,evidence_ref,\
          evidence_digest,signed_receipt,authority_request_digest,created_at) \
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(&tenant.0)
    .bind(&receipt.receipt_id)
    .bind(&case.case_id)
    .bind(&receipt.actor_subject)
    .bind(approval_decision_text(receipt.decision))
    .bind(&receipt.decision_digest)
    .bind(&receipt.evidence_ref)
    .bind(&receipt.evidence_digest)
    .bind(&signed_receipt)
    .bind(&authority_request_digest)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_decision_evidence_insert)?;
    sqlx::query(
        "INSERT INTO approval_decision_evidence_outbox \
         (tenant_id,authority_event_id,receipt_id,case_id,idempotency_key,request_digest,\
          payload_digest,evidence_ref,authority_request,created_at,next_attempt_at) \
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$10)",
    )
    .bind(&tenant.0)
    .bind(&authority_request.authority_event_id)
    .bind(&receipt.receipt_id)
    .bind(&case.case_id)
    .bind(&authority_request.idempotency_key.0)
    .bind(&authority_request_digest)
    .bind(&receipt.decision_digest)
    .bind(&receipt.evidence_ref)
    .bind(&request_value)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_decision_evidence_insert)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_decision_result_replay(
    result: &ApprovalDecisionResult,
    case_id: &str,
    envelope: &ApprovalDecisionEnvelope,
    principal: &ApprovalPrincipal,
    idempotency_key: &str,
    request_digest: &str,
    decision_evidence_keyring: &ApprovalDecisionEvidenceKeyring,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    let case = &result.approval_case;
    let receipt = &result.evidence_receipt;
    decision_evidence_keyring.verify_receipt(receipt, now)?;
    let matching_decision = case.decisions.iter().any(|decision| {
        decision.approver_subject == receipt.actor_subject
            && decision.decision == approval_decision_text(receipt.decision)
            && hex(Sha256::digest(decision.reason.as_bytes())) == receipt.decision_reason_digest
            && decision.decided_at == receipt.decided_at
            && decision.strong_auth
    });
    if result.schema_version != APPROVAL_DECISION_RESULT_SCHEMA_VERSION
        || case.schema_version != APPROVAL_CASE_SCHEMA_VERSION
        || case.case_id != case_id
        || case.request.tenant_id != principal.tenant_id
        || receipt.tenant_id != principal.tenant_id.0
        || receipt.case_id != case.case_id
        || receipt.task_id != case.request.task_id.0
        || receipt.decision != envelope.decision
        || receipt.request_digest != request_digest
        || receipt.idempotency_key_digest != hex(Sha256::digest(idempotency_key.as_bytes()))
        || !replay_principal_binding_matches(
            &receipt.actor_subject,
            &receipt.principal_assertion_request_digest,
            principal,
        )
        || receipt.approval_case_digest != canonical_digest(case)?
        || receipt.action_hash != case.request.action_hash.0
        || receipt.step_id != case.request.step_id.0
        || receipt.plan_hash != case.request.plan_hash
        || receipt.parameter_hash != case.request.parameter_hash
        || receipt.resource != case.request.resource
        || receipt.resource_version != case.request.resource_version.0
        || receipt.policy_version != case.request.policy_version.0
        || receipt.environment != case.request.environment
        || receipt.risk != case.request.risk
        || receipt.case_status != case.status
        || !matching_decision
    {
        return Err(ApprovalError::DatabaseUnavailable);
    }
    Ok(())
}

fn approval_decision_text(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Approve => "APPROVE",
        ApprovalDecision::Reject => "REJECT",
        ApprovalDecision::PostReviewed => "POST_REVIEWED",
    }
}

fn replay_principal_binding_matches(
    receipt_actor_subject: &str,
    receipt_assertion_request_digest: &str,
    principal: &ApprovalPrincipal,
) -> bool {
    receipt_actor_subject == principal.subject
        && receipt_assertion_request_digest == principal.assertion_request_digest
}

fn decision_evidence_tenant_order(
    tenants: &BTreeSet<TenantId>,
    start_index: usize,
) -> Vec<&TenantId> {
    if tenants.is_empty() {
        return Vec::new();
    }
    tenants
        .iter()
        .cycle()
        .skip(start_index % tenants.len())
        .take(tenants.len())
        .collect()
}

fn decision_evidence_retry_seconds(delivery_attempts: i32) -> i64 {
    let shift = u32::try_from(delivery_attempts.clamp(1, 20)).unwrap_or(20);
    1_i64
        .checked_shl(shift)
        .unwrap_or(DECISION_EVIDENCE_DELIVERY_MAX_BACKOFF_SECONDS)
        .min(DECISION_EVIDENCE_DELIVERY_MAX_BACKOFF_SECONDS)
}

fn decision_evidence_delivery_alert(
    stage: &str,
    tenant: Option<&TenantId>,
    authority_event_id: Option<&str>,
    code: &str,
    delivery_attempts: Option<i32>,
) {
    let severity = if code == "OUTCOME_UNKNOWN" {
        "WARN"
    } else {
        "ERROR"
    };
    eprintln!(
        "{}",
        serde_json::json!({
            "schema_version": "agenttrust.approval-evidence-delivery-alert.v1",
            "severity": severity,
            "stage": stage,
            "tenant_id": tenant.map(|value| value.0.as_str()),
            "authority_event_id": authority_event_id,
            "code": code,
            "delivery_attempts": delivery_attempts,
            "occurred_at": Utc::now(),
        })
    );
}

async fn update_case_status(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
    status: ApprovalStatus,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    let result = sqlx::query(
        "UPDATE approval_cases SET status=$3,updated_at=$4 \
         WHERE tenant_id=$1::uuid AND case_id=$2::uuid",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .bind(status_text(status))
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    if result.rows_affected() != 1 {
        return Err(ApprovalError::CaseNotFound);
    }
    Ok(())
}

async fn lock_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    scope: &str,
    key: &str,
) -> Result<(), ApprovalError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{}:{scope}:{key}", tenant.0))
        .fetch_one(&mut **transaction)
        .await
        .map_err(database)?;
    Ok(())
}

async fn register_principal_assertion(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &ApprovalPrincipal,
    scope: &str,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    sqlx::query(
        "INSERT INTO approval_principal_assertion_uses \
         (tenant_id,assertion_jti,issuer,subject,scope,request_digest,assertion_digest,signed_assertion,expires_at,first_used_at) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
    )
    .bind(&principal.tenant_id.0)
    .bind(&principal.assertion_jti)
    .bind(&principal.assertion_issuer)
    .bind(&principal.subject)
    .bind(scope)
    .bind(&principal.assertion_request_digest)
    .bind(&principal.assertion_digest)
    .bind(&principal.assertion_document)
    .bind(principal.assertion_expires_at)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    let row = sqlx::query(
        "SELECT issuer,subject,scope,request_digest,assertion_digest,signed_assertion,expires_at \
         FROM approval_principal_assertion_uses \
         WHERE tenant_id=$1::uuid AND assertion_jti=$2::uuid FOR UPDATE",
    )
    .bind(&principal.tenant_id.0)
    .bind(&principal.assertion_jti)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database)?;
    if row.try_get::<String, _>("issuer").map_err(database)? != principal.assertion_issuer
        || row.try_get::<String, _>("subject").map_err(database)? != principal.subject
        || row.try_get::<String, _>("scope").map_err(database)? != scope
        || row
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != principal.assertion_request_digest
        || row
            .try_get::<String, _>("assertion_digest")
            .map_err(database)?
            != principal.assertion_digest
        || row
            .try_get::<Value, _>("signed_assertion")
            .map_err(database)?
            != principal.assertion_document
        || row
            .try_get::<DateTime<Utc>, _>("expires_at")
            .map_err(database)?
            != principal.assertion_expires_at
    {
        return Err(ApprovalError::AuthenticationRequired);
    }
    Ok(())
}

async fn replay<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    operation: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<Option<T>, ApprovalError> {
    let row = sqlx::query(
        "SELECT request_digest,response_body FROM approval_mutation_receipts \
         WHERE tenant_id=$1::uuid AND operation=$2 AND idempotency_key=$3",
    )
    .bind(&tenant.0)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row
        .try_get::<String, _>("request_digest")
        .map_err(database)?
        != request_digest
    {
        return Err(ApprovalError::IdempotencyConflict);
    }
    let response = row.try_get::<Value, _>("response_body").map_err(database)?;
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| ApprovalError::DatabaseUnavailable)
}

async fn save_replay<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    operation: &str,
    idempotency_key: &str,
    request_digest: &str,
    response: &T,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    sqlx::query(
        "INSERT INTO approval_mutation_receipts \
         (tenant_id,operation,idempotency_key,request_digest,response_body,created_at) \
         VALUES ($1::uuid,$2,$3,$4,$5,$6)",
    )
    .bind(&tenant.0)
    .bind(operation)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(serde_json::to_value(response).map_err(|_| ApprovalError::RequestInvalid)?)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_idempotency_insert)?;
    Ok(())
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    event_type: &str,
    aggregate_id: &str,
    actor: &str,
    payload_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    sqlx::query(
        "INSERT INTO approval_events \
         (tenant_id,event_id,event_type,aggregate_id,actor_subject,payload_digest,occurred_at) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7)",
    )
    .bind(&tenant.0)
    .bind(Uuid::new_v4().to_string())
    .bind(event_type)
    .bind(aggregate_id)
    .bind(actor)
    .bind(payload_digest)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    Ok(())
}

fn validate_create(envelope: &ApprovalCaseCreateEnvelope) -> Result<(), ApprovalError> {
    if envelope.schema_version != APPROVAL_CASE_CREATE_SCHEMA_VERSION {
        return Err(ApprovalError::RequestInvalid);
    }
    validate_policy(&envelope.policy)?;
    validate_request(&envelope.request, &envelope.policy)?;
    require_uuid(&envelope.request.tenant_id.0)?;
    require_uuid(&envelope.request.task_id.0)?;
    require_uuid(&envelope.request.step_id.0)?;
    if envelope.request.requested_uses != 1
        || envelope.policy.maximum_uses != 1
        || envelope.policy.minimum_approvers > 64
        || envelope.policy.maximum_ttl_seconds > MAX_APPROVAL_TTL_SECONDS
        || envelope.policy.policy_id.len() > 256
        || envelope.policy.policy_version.len() > 256
        || envelope.policy.required_roles.len() > 64
        || envelope
            .policy
            .required_roles
            .iter()
            .any(|role| !identifier(role))
        || !is_digest(&envelope.request.action_hash.0)
        || !is_digest(&envelope.request.plan_hash)
        || !is_digest(&envelope.request.parameter_hash)
        || !bounded(&envelope.request.resource)
        || !bounded(&envelope.request.resource_version.0)
        || !bounded(&envelope.request.policy_version.0)
        || !bounded(&envelope.request.environment)
        || !identifier(&envelope.request.requester_subject)
        || !identifier(&envelope.request.agent_owner_subject)
        || !valid_approval_human_text(&envelope.request.justification)
    {
        return Err(ApprovalError::RequestInvalid);
    }
    if envelope.policy.approval_type == ApprovalType::Emergency
        && envelope.request.requested_ttl_seconds > 300
    {
        return Err(ApprovalError::BreakGlassDenied);
    }
    Ok(())
}

fn validate_principal(
    principal: &ApprovalPrincipal,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    let tenant = Uuid::parse_str(&principal.tenant_id.0)
        .map_err(|_| ApprovalError::AuthenticationRequired)?;
    let jti = Uuid::parse_str(&principal.assertion_jti)
        .map_err(|_| ApprovalError::AuthenticationRequired)?;
    if tenant.to_string() != principal.tenant_id.0
        || jti.to_string() != principal.assertion_jti
        || !identifier(&principal.subject)
        || !principal.strong_auth
        || principal.roles.is_empty()
        || principal.roles.len() > 64
        || principal.roles.iter().any(|role| !identifier(role))
        || principal.owned_resources.len() > 1_024
        || principal
            .owned_resources
            .iter()
            .any(|resource| !bounded(resource))
        || !identifier(&principal.assertion_issuer)
        || !is_digest(&principal.assertion_request_digest)
        || !is_digest(&principal.assertion_digest)
        || canonical_digest(&principal.assertion_document)? != principal.assertion_digest
        || principal.assertion_expires_at <= now
        || principal.assertion_expires_at > now + chrono::Duration::seconds(330)
    {
        return Err(ApprovalError::AuthenticationRequired);
    }
    Ok(())
}

fn validate_consumption(request: &ApprovalConsumptionRequest) -> Result<(), ApprovalError> {
    if request.schema_version != APPROVAL_GRANT_REQUEST_SCHEMA_VERSION
        || require_uuid(&request.tenant_id).is_err()
        || require_uuid(&request.task_id).is_err()
        || require_uuid(&request.step_id).is_err()
        || !is_digest(&request.action_hash)
        || !is_digest(&request.plan_hash)
        || !is_digest(&request.parameter_hash)
        || !bounded(&request.resource)
        || !bounded(&request.resource_version)
        || !bounded(&request.policy_version)
        || !bounded(&request.environment)
    {
        return Err(ApprovalError::RequestInvalid);
    }
    Ok(())
}

fn consumption_matches_grant(
    request: &ApprovalConsumptionRequest,
    grant: &EnterpriseApprovalGrant,
) -> bool {
    request.tenant_id == grant.tenant_id.0
        && request.task_id == grant.task_id.0
        && request.step_id == grant.step_id.0
        && request.action_hash == grant.action_hash.0
        && request.plan_hash == grant.plan_hash
        && request.parameter_hash == grant.parameter_hash
        && request.resource == grant.resource
        && request.resource_version == grant.resource_version.0
        && request.policy_version == grant.policy_version.0
        && request.environment == grant.environment
        && request.maximum_risk <= grant.maximum_risk
        && grant.maximum_uses == 1
}

#[derive(Serialize)]
struct GrantLookupBinding<'a> {
    tenant_id: &'a str,
    task_id: &'a str,
    step_id: &'a str,
    action_hash: &'a str,
    plan_hash: &'a str,
    parameter_hash: &'a str,
    resource: &'a str,
    resource_version: &'a str,
    policy_version: &'a str,
    environment: &'a str,
}

fn grant_lookup_digest_from_grant(
    grant: &EnterpriseApprovalGrant,
) -> Result<String, ApprovalError> {
    canonical_digest(&GrantLookupBinding {
        tenant_id: &grant.tenant_id.0,
        task_id: &grant.task_id.0,
        step_id: &grant.step_id.0,
        action_hash: &grant.action_hash.0,
        plan_hash: &grant.plan_hash,
        parameter_hash: &grant.parameter_hash,
        resource: &grant.resource,
        resource_version: &grant.resource_version.0,
        policy_version: &grant.policy_version.0,
        environment: &grant.environment,
    })
}

fn grant_lookup_digest_from_request(
    request: &ApprovalConsumptionRequest,
) -> Result<String, ApprovalError> {
    canonical_digest(&GrantLookupBinding {
        tenant_id: &request.tenant_id,
        task_id: &request.task_id,
        step_id: &request.step_id,
        action_hash: &request.action_hash,
        plan_hash: &request.plan_hash,
        parameter_hash: &request.parameter_hash,
        resource: &request.resource,
        resource_version: &request.resource_version,
        policy_version: &request.policy_version,
        environment: &request.environment,
    })
}

fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, ApprovalError> {
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| ApprovalError::RequestInvalid)?,
    )))
}

fn decode_signature(value: &str) -> Result<Signature, ApprovalError> {
    let raw = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApprovalError::GrantInvalid)?;
    if raw.len() != 64 || URL_SAFE_NO_PAD.encode(&raw) != value {
        return Err(ApprovalError::GrantInvalid);
    }
    Signature::from_slice(&raw).map_err(|_| ApprovalError::GrantInvalid)
}

fn consumption_reference(
    receipt: &SignedApprovalConsumptionReceipt,
    payload_digest: &str,
) -> Result<String, ApprovalError> {
    if !is_digest(payload_digest)
        || !key_identifier(&receipt.key_id)
        || decode_signature(&receipt.signature).is_err()
    {
        return Err(ApprovalError::GrantInvalid);
    }
    let value = format!(
        "urn:agenttrust:approval-consumption:{}:sha256:{}:kid:{}:sig:{}",
        receipt.receipt_id, payload_digest, receipt.key_id, receipt.signature
    );
    if value.len() > 2_048 {
        return Err(ApprovalError::GrantInvalid);
    }
    Ok(value)
}

fn validate_consumption_reference(value: &str) -> Result<(), ApprovalError> {
    let body = value
        .strip_prefix("urn:agenttrust:approval-consumption:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let (receipt_id, body) = body
        .split_once(":sha256:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let (payload_digest, body) = body
        .split_once(":kid:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let (key_id, signature) = body
        .split_once(":sig:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let receipt_uuid = Uuid::parse_str(receipt_id).map_err(|_| ApprovalError::GrantInvalid)?;
    if value.len() > 2_048
        || receipt_uuid.to_string() != receipt_id
        || !is_digest(payload_digest)
        || !key_identifier(key_id)
        || decode_signature(signature).is_err()
    {
        return Err(ApprovalError::GrantInvalid);
    }
    Ok(())
}

fn encode_authoritative_cursor(
    tenant: &TenantId,
    resource: &str,
    created_at: DateTime<Utc>,
    case_id: &str,
    signer: &ApprovalSigner,
    now: DateTime<Utc>,
) -> Result<String, ApprovalError> {
    if !canonical_uuid(&tenant.0) || !dashboard_resource(resource) || !canonical_uuid(case_id) {
        return Err(ApprovalError::RequestInvalid);
    }
    let mut cursor = AuthoritativeApprovalCursor {
        schema_version: AUTHORITATIVE_APPROVAL_CURSOR_SCHEMA_VERSION.into(),
        tenant_id: tenant.0.clone(),
        resource: resource.into(),
        created_at,
        case_id: case_id.into(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(AUTHORITATIVE_CURSOR_TTL_SECONDS),
        issuer: signer.issuer().into(),
        key_id: signer.key_id().into(),
        signature: String::new(),
    };
    signer.sign_authoritative_cursor(&mut cursor)?;
    let raw = serde_json::to_vec(&cursor).map_err(|_| ApprovalError::RequestInvalid)?;
    if raw.is_empty() || raw.len() > 4_096 {
        return Err(ApprovalError::RequestInvalid);
    }
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn decode_authoritative_cursor(
    encoded: &str,
    tenant: &TenantId,
    resource: &str,
    signer: &ApprovalSigner,
    now: DateTime<Utc>,
) -> Result<AuthoritativeApprovalCursor, ApprovalError> {
    if encoded.is_empty()
        || encoded.len() > 5_462
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ApprovalError::RequestInvalid);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApprovalError::RequestInvalid)?;
    if raw.is_empty() || raw.len() > 4_096 {
        return Err(ApprovalError::RequestInvalid);
    }
    let cursor: AuthoritativeApprovalCursor =
        serde_json::from_slice(&raw).map_err(|_| ApprovalError::RequestInvalid)?;
    if cursor.schema_version != AUTHORITATIVE_APPROVAL_CURSOR_SCHEMA_VERSION
        || cursor.tenant_id != tenant.0
        || cursor.resource != resource
        || cursor.issuer != signer.issuer()
        || cursor.key_id != signer.key_id()
        || !canonical_uuid(&cursor.case_id)
        || cursor.issued_at > now + chrono::Duration::seconds(30)
        || cursor.expires_at <= now
        || cursor.expires_at <= cursor.issued_at
        || cursor.expires_at
            > cursor.issued_at + chrono::Duration::seconds(AUTHORITATIVE_CURSOR_TTL_SECONDS)
    {
        return Err(ApprovalError::RequestInvalid);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&cursor.signature)
        .map_err(|_| ApprovalError::RequestInvalid)?;
    let signature = Signature::from_slice(&signature).map_err(|_| ApprovalError::RequestInvalid)?;
    signer
        .verifying_key()
        .verify(&cursor.signing_bytes()?, &signature)
        .map_err(|_| ApprovalError::RequestInvalid)?;
    Ok(cursor)
}

fn dashboard_resource(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn parse_authoritative_request(
    value: Value,
    tenant: &TenantId,
) -> Result<Option<ApprovalRequest>, ApprovalError> {
    match serde_json::from_value::<ApprovalRequest>(value.clone()) {
        Ok(request) => Ok(Some(request)),
        Err(_)
            if value.get("review_context").is_none() && value.get("review_evidence").is_none() =>
        {
            let legacy: LegacyApprovalRequestV0 =
                serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
            if !legacy.valid_for_authoritative_exclusion(tenant) {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            Ok(None)
        }
        Err(_) => Err(ApprovalError::DatabaseUnavailable),
    }
}

fn approval_case_domain(request: &ApprovalRequest) -> ApprovalCaseDomain {
    if request_is_industrial(request) {
        ApprovalCaseDomain::Industrial
    } else {
        ApprovalCaseDomain::Coding
    }
}

fn approval_case_view_status(
    stored: ApprovalStatus,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> ApprovalCaseViewStatus {
    if expires_at <= now && stored == ApprovalStatus::Pending {
        return ApprovalCaseViewStatus::Expired;
    }
    match stored {
        ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired => {
            ApprovalCaseViewStatus::Pending
        }
        ApprovalStatus::Approved | ApprovalStatus::Consumed => ApprovalCaseViewStatus::Approved,
        ApprovalStatus::Rejected => ApprovalCaseViewStatus::Rejected,
        ApprovalStatus::Expired => ApprovalCaseViewStatus::Expired,
        ApprovalStatus::Revoked => ApprovalCaseViewStatus::Revoked,
    }
}

fn validate_case_view(view: &ApprovalCaseView) -> Result<(), ApprovalError> {
    if view.schema_version != APPROVAL_CASE_VIEW_SCHEMA_VERSION
        || !canonical_uuid(&view.case_id)
        || view.safe_summary.is_empty()
        || view.safe_summary.len() > MAX_TEXT_BYTES
        || !is_digest(&view.action_hash)
        || !bounded(&view.resource)
        || !bounded(&view.resource_version)
        || !bounded(&view.policy_version)
        || match view.domain {
            ApprovalCaseDomain::Coding => {
                view.industrial_details.is_some()
                    || !view.coding_details.as_ref().is_some_and(|details| {
                        ApprovalReviewContext::Coding(details.clone()).valid()
                    })
            }
            ApprovalCaseDomain::Industrial => {
                view.coding_details.is_some()
                    || !view.industrial_details.as_ref().is_some_and(|details| {
                        ApprovalReviewContext::Industrial(details.clone()).valid()
                    })
            }
        }
        || view.evidence_refs.len() != 3
        || view
            .evidence_refs
            .iter()
            .any(|value| !evidence_reference(value))
        || view.evidence_refs.iter().collect::<BTreeSet<_>>().len() != view.evidence_refs.len()
    {
        return Err(ApprovalError::DatabaseUnavailable);
    }
    Ok(())
}

fn evidence_reference(value: &str) -> bool {
    let suffix = value
        .strip_prefix("evidence://")
        .or_else(|| value.strip_prefix("urn:agenttrust:evidence:"))
        .or_else(|| value.strip_prefix("urn:agenttrust:ledger-evidence:"));
    bounded(value)
        && suffix.is_some_and(|suffix| !suffix.is_empty())
        && !contains_secret_marker(value)
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        && !value.contains('?')
        && !value.contains('#')
}

fn require_same_tenant(left: &TenantId, right: &TenantId) -> Result<(), ApprovalError> {
    if left != right {
        Err(ApprovalError::ScopeForbidden)
    } else {
        Ok(())
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), ApprovalError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        Err(ApprovalError::IdempotencyInvalid)
    } else {
        Ok(())
    }
}

fn require_uuid(value: &str) -> Result<(), ApprovalError> {
    if canonical_uuid(value) {
        Ok(())
    } else {
        Err(ApprovalError::RequestInvalid)
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn service_client_identity(value: &str) -> bool {
    value.len() <= 512
        && (value.starts_with("DNS:") || value.starts_with("URI:"))
        && value.split_once(':').is_some_and(|(_, identity)| {
            !identity.is_empty() && identity.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

fn key_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn status_text(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "PENDING",
        ApprovalStatus::Approved => "APPROVED",
        ApprovalStatus::Rejected => "REJECTED",
        ApprovalStatus::Revoked => "REVOKED",
        ApprovalStatus::Expired => "EXPIRED",
        ApprovalStatus::Consumed => "CONSUMED",
        ApprovalStatus::PostReviewRequired => "POST_REVIEW_REQUIRED",
    }
}

fn parse_status(value: &str) -> Result<ApprovalStatus, ApprovalError> {
    match value {
        "PENDING" => Ok(ApprovalStatus::Pending),
        "APPROVED" => Ok(ApprovalStatus::Approved),
        "REJECTED" => Ok(ApprovalStatus::Rejected),
        "REVOKED" => Ok(ApprovalStatus::Revoked),
        "EXPIRED" => Ok(ApprovalStatus::Expired),
        "CONSUMED" => Ok(ApprovalStatus::Consumed),
        "POST_REVIEW_REQUIRED" => Ok(ApprovalStatus::PostReviewRequired),
        _ => Err(ApprovalError::DatabaseUnavailable),
    }
}

fn risk_text(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}

fn database(_: sqlx::Error) -> ApprovalError {
    ApprovalError::DatabaseUnavailable
}

fn map_decision_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::DuplicateApprover
    } else {
        database(error)
    }
}

fn map_decision_evidence_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::ConcurrentMutation
    } else {
        database(error)
    }
}

fn map_grant_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::ConcurrentMutation
    } else {
        database(error)
    }
}

fn map_idempotency_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::IdempotencyConflict
    } else {
        database(error)
    }
}

fn map_consumption_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::GrantReplayed
    } else {
        database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap_or_else(|_| panic!("test timestamp"))
            .with_timezone(&Utc)
    }

    fn test_principal() -> ApprovalPrincipal {
        ApprovalPrincipal {
            tenant_id: TenantId("01900000-0000-7000-8000-000000000001".into()),
            subject: "operator:one".into(),
            roles: BTreeSet::from(["approver".into()]),
            owned_resources: BTreeSet::new(),
            strong_auth: true,
            assertion_issuer: "enterprise-control".into(),
            assertion_jti: "01900000-0000-7000-8000-000000000002".into(),
            assertion_request_digest: "a".repeat(64),
            assertion_digest: "b".repeat(64),
            assertion_document: serde_json::json!({}),
            assertion_expires_at: instant("2030-01-01T00:00:00Z"),
        }
    }

    #[test]
    fn production_idempotency_keys_are_bounded_and_unambiguous() {
        assert!(validate_idempotency_key("execute:01900000-0000-7000-8000-000000000001").is_ok());
        assert!(validate_idempotency_key("contains a space").is_err());
        assert!(validate_idempotency_key(&"a".repeat(129)).is_err());
    }

    #[test]
    fn lookup_binding_does_not_weaken_any_resource_field() {
        let request = ApprovalConsumptionRequest {
            schema_version: APPROVAL_GRANT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: Uuid::new_v4().to_string(),
            task_id: Uuid::new_v4().to_string(),
            step_id: Uuid::new_v4().to_string(),
            action_hash: "a".repeat(64),
            plan_hash: "b".repeat(64),
            parameter_hash: "c".repeat(64),
            resource: "urn:resource:one".into(),
            resource_version: "version-1".into(),
            policy_version: "policy-1".into(),
            environment: "production".into(),
            maximum_risk: RiskLevel::High,
        };
        let original =
            grant_lookup_digest_from_request(&request).unwrap_or_else(|_| panic!("lookup digest"));
        let mut changed_resource_version = request.clone();
        changed_resource_version.resource_version = "version-2".into();
        let changed_resource_version = grant_lookup_digest_from_request(&changed_resource_version)
            .unwrap_or_else(|_| panic!("changed lookup digest"));
        let mut changed_plan = request;
        changed_plan.plan_hash = "d".repeat(64);
        let changed_plan = grant_lookup_digest_from_request(&changed_plan)
            .unwrap_or_else(|_| panic!("changed plan lookup digest"));
        assert_ne!(original, changed_resource_version);
        assert_ne!(original, changed_plan);
    }

    #[test]
    fn legacy_requests_are_excluded_without_fabricating_review_facts() {
        let tenant = TenantId("11111111-1111-4111-8111-111111111111".into());
        let legacy = serde_json::json!({
            "tenant_id": tenant.0.clone(),
            "task_id": "22222222-2222-4222-8222-222222222222",
            "step_id": "33333333-3333-4333-8333-333333333333",
            "action_hash": "a".repeat(64),
            "plan_hash": "b".repeat(64),
            "parameter_hash": "c".repeat(64),
            "resource": "repo:a",
            "resource_version": "v1",
            "policy_version": "policy-v1",
            "environment": "production",
            "risk": "HIGH",
            "requester_subject": "requester",
            "agent_owner_subject": "agent-owner",
            "justification": "legacy request",
            "requested_ttl_seconds": 300,
            "requested_uses": 1
        });
        assert!(matches!(
            parse_authoritative_request(legacy.clone(), &tenant),
            Ok(None)
        ));

        let mut unknown = legacy.clone();
        unknown
            .as_object_mut()
            .unwrap_or_else(|| panic!("legacy object"))
            .insert("raw_command".into(), serde_json::json!("unsafe"));
        assert_eq!(
            parse_authoritative_request(unknown, &tenant),
            Err(ApprovalError::DatabaseUnavailable)
        );

        let mut partial_upgrade = legacy;
        partial_upgrade
            .as_object_mut()
            .unwrap_or_else(|| panic!("partial object"))
            .insert(
                "review_context".into(),
                serde_json::json!({"domain": "CODING"}),
            );
        assert_eq!(
            parse_authoritative_request(partial_upgrade, &tenant),
            Err(ApprovalError::DatabaseUnavailable)
        );
    }

    #[test]
    fn decision_evidence_lease_covers_one_bounded_http_attempt_and_backoff_is_capped() {
        assert!(
            DECISION_EVIDENCE_DELIVERY_LEASE_SECONDS
                > i64::try_from(EVIDENCE_REQUEST_TIMEOUT_SECONDS)
                    .unwrap_or_else(|_| panic!("timeout fits i64"))
        );
        assert_eq!(decision_evidence_retry_seconds(1), 2);
        assert_eq!(decision_evidence_retry_seconds(2), 4);
        assert_eq!(
            decision_evidence_retry_seconds(20),
            DECISION_EVIDENCE_DELIVERY_MAX_BACKOFF_SECONDS
        );
    }

    #[test]
    fn tenant_delivery_order_rotates_even_when_the_first_tenant_has_a_full_batch() {
        let tenants = BTreeSet::from([
            TenantId("01900000-0000-7000-8000-000000000001".into()),
            TenantId("01900000-0000-7000-8000-000000000002".into()),
        ]);
        let first = decision_evidence_tenant_order(&tenants, 0);
        let second = decision_evidence_tenant_order(&tenants, 1);
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert_ne!(first[0], second[0]);
        assert_eq!(first[0], second[1]);
        assert_eq!(first[1], second[0]);
    }

    #[test]
    fn replay_accepts_a_fresh_assertion_jti_but_not_a_new_request_binding() {
        let original = test_principal();
        let mut retry = original.clone();
        retry.assertion_jti = "01900000-0000-7000-8000-000000000003".into();
        retry.assertion_digest = "c".repeat(64);
        assert_ne!(original.assertion_jti, retry.assertion_jti);
        assert_ne!(original.assertion_digest, retry.assertion_digest);
        assert!(replay_principal_binding_matches(
            &original.subject,
            &original.assertion_request_digest,
            &retry,
        ));
        retry.assertion_request_digest = "d".repeat(64);
        assert!(!replay_principal_binding_matches(
            &original.subject,
            &original.assertion_request_digest,
            &retry,
        ));
        assert!(!replay_principal_binding_matches(
            "operator:two",
            &original.assertion_request_digest,
            &original,
        ));
    }

    #[test]
    fn decision_receipt_key_validity_is_half_open_and_matches_the_signer() {
        let signer = ApprovalSigner::new(
            "approval-authority".into(),
            "decision-2026-01".into(),
            SigningKey::from_bytes(&[7_u8; 32]),
        )
        .unwrap_or_else(|_| panic!("test signer"));
        let keyring = ApprovalDecisionEvidenceKeyring::from_json(
            serde_json::to_string(&serde_json::json!({
                "schema_version": APPROVAL_DECISION_EVIDENCE_KEYRING_SCHEMA_VERSION,
                "issuer": "approval-authority",
                "keys": [{
                    "key_id": "decision-2026-01",
                    "algorithm": "Ed25519",
                    "public_key_base64url": URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes()),
                    "status": "ACTIVE",
                    "not_before": "2026-01-01T00:00:00Z",
                    "expires_at": "2027-01-01T00:00:00Z"
                }]
            }))
            .unwrap_or_else(|_| panic!("keyring JSON"))
            .as_bytes(),
        )
        .unwrap_or_else(|_| panic!("keyring"));
        assert!(keyring.covers_active_signer_at(&signer, instant("2026-01-01T00:00:00Z")));
        assert!(!keyring.covers_active_signer_at(&signer, instant("2027-01-01T00:00:00Z")));
    }

    #[test]
    fn signature_decoder_rejects_every_noncanonical_wire_alias() {
        let raw = [0_u8; 64];
        let canonical = URL_SAFE_NO_PAD.encode(raw);
        assert!(decode_signature(&canonical).is_ok());
        for replacement in b'A'..=b'z' {
            let mut alias = canonical.as_bytes().to_vec();
            let last = alias.len().saturating_sub(1);
            alias[last] = replacement;
            let Ok(alias) = String::from_utf8(alias) else {
                continue;
            };
            if alias != canonical
                && URL_SAFE_NO_PAD
                    .decode(&alias)
                    .is_ok_and(|decoded| decoded == raw)
            {
                assert!(decode_signature(&alias).is_err());
            }
        }
        assert!(decode_signature(&(canonical + "=")).is_err());
    }
}
