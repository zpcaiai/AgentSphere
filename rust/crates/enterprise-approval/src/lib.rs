//! Enterprise approval service with separation of duties and atomic grant consumption.

use agent_trust_contracts::{
    ActionHash, ApprovalId, ContractError, PolicyVersion, ResourceVersion, RiskLevel,
    SchemaVersion, StepId, TaskId, TenantId,
};
pub use agent_trust_contracts::{
    ApprovalConsumptionRequest, ApprovalGrantReceipt, ApprovalReviewContext,
    CodingApprovalReviewDetails, EnterpriseApprovalGrant, IndustrialApprovalReviewDetails,
    SignedApprovalConsumptionReceipt,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const APPROVAL_SCHEMA_VERSION: &str = "agenttrust.enterprise-approval.v1";
pub const APPROVAL_CASE_SCHEMA_VERSION: &str = "agenttrust.enterprise-approval-case.v2";
pub const APPROVAL_CASE_CREATE_SCHEMA_VERSION: &str = "agenttrust.approval-case-create.v2";
pub const APPROVAL_DECISION_SCHEMA_VERSION: &str = "agenttrust.approval-decision.v1";
pub const APPROVAL_GRANT_REQUEST_SCHEMA_VERSION: &str = "agenttrust.approval-grant-request.v1";
pub const APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION: &str = "agenttrust.approval-grant-receipt.v1";
pub const APPROVAL_CONSUMPTION_SCHEMA_VERSION: &str = "agenttrust.approval-consumption.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalType {
    Action,
    Scope,
    Escalation,
    Dual,
    Emergency,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Revoked,
    Expired,
    Consumed,
    PostReviewRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPolicy {
    pub policy_id: String,
    pub policy_version: String,
    pub approval_type: ApprovalType,
    pub minimum_approvers: u32,
    pub required_roles: BTreeSet<String>,
    pub prohibit_requester: bool,
    pub prohibit_agent_owner: bool,
    pub require_resource_owner: bool,
    pub maximum_ttl_seconds: u64,
    pub maximum_uses: u32,
    pub maximum_risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApproverIdentity {
    pub tenant_id: TenantId,
    pub subject: String,
    pub roles: BTreeSet<String>,
    pub owned_resources: BTreeSet<String>,
    pub delegated_until: Option<DateTime<Utc>>,
    pub strong_auth: bool,
    pub active: bool,
}

#[derive(Default)]
pub struct ApproverDirectory {
    identities: Mutex<BTreeMap<(TenantId, String), ApproverIdentity>>,
}
impl ApproverDirectory {
    pub fn upsert(&self, identity: ApproverIdentity) {
        self.identities.lock().insert(
            (identity.tenant_id.clone(), identity.subject.clone()),
            identity,
        );
    }
    pub fn resolve(
        &self,
        tenant: &TenantId,
        subject: &str,
    ) -> Result<ApproverIdentity, ApprovalError> {
        self.identities
            .lock()
            .get(&(tenant.clone(), subject.into()))
            .filter(|identity| identity.active)
            .cloned()
            .ok_or(ApprovalError::ApproverNotEligible)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub plan_hash: String,
    pub parameter_hash: String,
    pub resource: String,
    pub resource_version: ResourceVersion,
    pub policy_version: PolicyVersion,
    pub environment: String,
    pub risk: RiskLevel,
    pub review_context: ApprovalReviewContext,
    pub review_evidence: review_evidence::ApprovalReviewEvidence,
    pub requester_subject: String,
    pub agent_owner_subject: String,
    pub justification: String,
    pub requested_ttl_seconds: u64,
    pub requested_uses: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalDecisionRecord {
    pub approver_subject: String,
    pub roles: BTreeSet<String>,
    pub decision: String,
    pub reason: String,
    pub decided_at: DateTime<Utc>,
    pub strong_auth: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationKind {
    Pending,
    Approved,
    Rejected,
    Expiring,
    Escalated,
    PostReviewRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalNotification {
    pub schema_version: String,
    pub notification_id: String,
    pub tenant_id: TenantId,
    pub case_id: String,
    pub recipient_subject: String,
    pub kind: NotificationKind,
    pub safe_summary: String,
    pub evidence_refs: Vec<String>,
}

pub trait NotificationAdapter: Send + Sync {
    fn send(&self, notification: &ApprovalNotification) -> Result<String, ApprovalError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationDeliveryRecord {
    pub schema_version: String,
    pub notification_id: String,
    pub delivered: bool,
    pub provider_message_id: Option<String>,
    pub failure_code: Option<String>,
}

pub fn dispatch_notification(
    adapter: &dyn NotificationAdapter,
    notification: &ApprovalNotification,
) -> NotificationDeliveryRecord {
    match adapter.send(notification) {
        Ok(message_id) => NotificationDeliveryRecord {
            schema_version: APPROVAL_SCHEMA_VERSION.into(),
            notification_id: notification.notification_id.clone(),
            delivered: true,
            provider_message_id: Some(message_id),
            failure_code: None,
        },
        Err(_) => NotificationDeliveryRecord {
            schema_version: APPROVAL_SCHEMA_VERSION.into(),
            notification_id: notification.notification_id.clone(),
            delivered: false,
            provider_message_id: None,
            failure_code: Some("APPROVAL_NOTIFICATION_DELIVERY_FAILED".into()),
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCase {
    pub schema_version: String,
    pub case_id: String,
    pub request: ApprovalRequest,
    pub policy: ApprovalPolicy,
    pub status: ApprovalStatus,
    pub decisions: Vec<ApprovalDecisionRecord>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub post_review_due_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct ApprovalState {
    cases: BTreeMap<String, ApprovalCase>,
    grants: BTreeMap<String, EnterpriseApprovalGrant>,
    remaining_uses: BTreeMap<String, u32>,
    revoked_grants: BTreeSet<String>,
    ui_intents: BTreeSet<String>,
}

pub struct EnterpriseApprovalService {
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
    review_evidence_keyring: review_evidence::ApprovalReviewEvidenceKeyring,
    directory: ApproverDirectory,
    state: Mutex<ApprovalState>,
}

impl EnterpriseApprovalService {
    pub fn new(
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
        review_evidence_keyring: review_evidence::ApprovalReviewEvidenceKeyring,
    ) -> Result<Self, ApprovalError> {
        if issuer.is_empty() || key_id.is_empty() {
            Err(ApprovalError::ConfigurationInvalid)
        } else {
            Ok(Self {
                issuer,
                key_id,
                signing_key,
                review_evidence_keyring,
                directory: ApproverDirectory::default(),
                state: Mutex::new(ApprovalState::default()),
            })
        }
    }
    pub fn directory(&self) -> &ApproverDirectory {
        &self.directory
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    pub fn request(
        &self,
        request: ApprovalRequest,
        policy: ApprovalPolicy,
        now: DateTime<Utc>,
    ) -> Result<ApprovalCase, ApprovalError> {
        validate_policy(&policy)?;
        validate_request(&request, &policy)?;
        self.review_evidence_keyring.verify_request(&request, now)?;
        let ttl = request
            .requested_ttl_seconds
            .min(policy.maximum_ttl_seconds);
        let mut status = ApprovalStatus::Pending;
        let mut post_review_due_at = None;
        if policy.approval_type == ApprovalType::Emergency {
            if ttl > 300 || request.risk > policy.maximum_risk {
                return Err(ApprovalError::BreakGlassDenied);
            }
            status = ApprovalStatus::PostReviewRequired;
            post_review_due_at = Some(now + chrono::Duration::hours(24));
        }
        let case = ApprovalCase {
            schema_version: APPROVAL_CASE_SCHEMA_VERSION.into(),
            case_id: Uuid::new_v4().to_string(),
            request,
            policy,
            status,
            decisions: vec![],
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl as i64),
            post_review_due_at,
        };
        self.state
            .lock()
            .cases
            .insert(case.case_id.clone(), case.clone());
        Ok(case)
    }
    pub fn submit_ui_intent(
        &self,
        case_id: &str,
        user_session_id: &str,
    ) -> Result<(), ApprovalError> {
        if !self.state.lock().cases.contains_key(case_id) || user_session_id.is_empty() {
            return Err(ApprovalError::CaseNotFound);
        }
        self.state
            .lock()
            .ui_intents
            .insert(format!("{case_id}:{user_session_id}"));
        Ok(())
    }
    pub fn approve(
        &self,
        case_id: &str,
        approver_subject: &str,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<Option<EnterpriseApprovalGrant>, ApprovalError> {
        let mut state = self.state.lock();
        let case = state
            .cases
            .get_mut(case_id)
            .ok_or(ApprovalError::CaseNotFound)?;
        if now >= case.expires_at {
            case.status = ApprovalStatus::Expired;
            return Err(ApprovalError::Expired);
        }
        if !matches!(
            case.status,
            ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired
        ) {
            return Err(ApprovalError::LifecycleInvalid);
        }
        let approver = self
            .directory
            .resolve(&case.request.tenant_id, approver_subject)?;
        SoDEngine::validate(case, &approver, now)?;
        if case
            .decisions
            .iter()
            .any(|decision| decision.approver_subject == approver.subject)
        {
            return Err(ApprovalError::DuplicateApprover);
        }
        case.decisions.push(ApprovalDecisionRecord {
            approver_subject: approver.subject,
            roles: approver.roles,
            decision: "APPROVE".into(),
            reason,
            decided_at: now,
            strong_auth: approver.strong_auth,
        });
        let unique = case
            .decisions
            .iter()
            .filter(|decision| decision.decision == "APPROVE")
            .map(|decision| &decision.approver_subject)
            .collect::<BTreeSet<_>>()
            .len() as u32;
        if unique < case.policy.minimum_approvers {
            return Ok(None);
        }
        case.status = if case.policy.approval_type == ApprovalType::Emergency {
            ApprovalStatus::PostReviewRequired
        } else {
            ApprovalStatus::Approved
        };
        let case_clone = case.clone();
        let mut grant = make_grant(&self.issuer, &self.key_id, &case_clone, now);
        grant.signature =
            URL_SAFE_NO_PAD.encode(self.signing_key.sign(&grant.signing_bytes()?).to_bytes());
        state
            .remaining_uses
            .insert(grant.grant_id.0.clone(), grant.maximum_uses);
        state.grants.insert(grant.grant_id.0.clone(), grant.clone());
        Ok(Some(grant))
    }
    pub fn reject(
        &self,
        case_id: &str,
        approver_subject: &str,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        let mut state = self.state.lock();
        let case = state
            .cases
            .get_mut(case_id)
            .ok_or(ApprovalError::CaseNotFound)?;
        let approver = self
            .directory
            .resolve(&case.request.tenant_id, approver_subject)?;
        SoDEngine::validate(case, &approver, now)?;
        case.decisions.push(ApprovalDecisionRecord {
            approver_subject: approver.subject,
            roles: approver.roles,
            decision: "REJECT".into(),
            reason,
            decided_at: now,
            strong_auth: approver.strong_auth,
        });
        case.status = ApprovalStatus::Rejected;
        Ok(())
    }
    pub fn revoke_case(&self, case_id: &str) -> Result<(), ApprovalError> {
        let mut state = self.state.lock();
        let case = state
            .cases
            .get_mut(case_id)
            .ok_or(ApprovalError::CaseNotFound)?;
        case.status = ApprovalStatus::Revoked;
        let grants: Vec<String> = state
            .grants
            .values()
            .filter(|grant| grant.case_id == case_id)
            .map(|grant| grant.grant_id.0.clone())
            .collect();
        state.revoked_grants.extend(grants);
        Ok(())
    }
    pub fn revoke_task(&self, task_id: &TaskId) {
        let mut state = self.state.lock();
        let grants: Vec<String> = state
            .grants
            .values()
            .filter(|grant| &grant.task_id == task_id)
            .map(|grant| grant.grant_id.0.clone())
            .collect();
        state.revoked_grants.extend(grants);
    }
    pub fn audit_emergency(
        &self,
        case_id: &str,
        reviewer_subject: &str,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        let mut state = self.state.lock();
        let case = state
            .cases
            .get_mut(case_id)
            .ok_or(ApprovalError::CaseNotFound)?;
        if case.policy.approval_type != ApprovalType::Emergency
            || case.status != ApprovalStatus::PostReviewRequired
            || case.post_review_due_at.is_some_and(|due| now > due)
        {
            return Err(ApprovalError::LifecycleInvalid);
        }
        let reviewer = self
            .directory
            .resolve(&case.request.tenant_id, reviewer_subject)?;
        SoDEngine::validate(case, &reviewer, now)?;
        case.decisions.push(ApprovalDecisionRecord {
            approver_subject: reviewer.subject,
            roles: reviewer.roles,
            decision: "POST_REVIEWED".into(),
            reason,
            decided_at: now,
            strong_auth: reviewer.strong_auth,
        });
        case.status = ApprovalStatus::Approved;
        Ok(())
    }
    pub fn verify_and_consume(
        &self,
        grant: &EnterpriseApprovalGrant,
        binding: &ApprovalExecutionBinding,
        now: DateTime<Utc>,
    ) -> Result<u32, ApprovalError> {
        verify_grant_signature(
            grant,
            &self.issuer,
            &self.key_id,
            &self.signing_key.verifying_key(),
            now,
        )?;
        if !binding.matches(grant) {
            return Err(ApprovalError::BindingChanged);
        }
        let mut state = self.state.lock();
        if state.revoked_grants.contains(&grant.grant_id.0) {
            return Err(ApprovalError::Revoked);
        }
        let stored = state
            .grants
            .get(&grant.grant_id.0)
            .ok_or(ApprovalError::GrantInvalid)?;
        if stored != grant {
            return Err(ApprovalError::GrantInvalid);
        }
        let case = state
            .cases
            .get(&grant.case_id)
            .cloned()
            .ok_or(ApprovalError::CaseNotFound)?;
        if matches!(
            case.status,
            ApprovalStatus::Rejected | ApprovalStatus::Revoked | ApprovalStatus::Expired
        ) {
            return Err(ApprovalError::Revoked);
        }
        for subject in &grant.approver_subjects {
            let current = self.directory.resolve(&grant.tenant_id, subject)?;
            SoDEngine::validate(&case, &current, now)
                .map_err(|_| ApprovalError::ApproverRoleChanged)?;
        }
        let remaining = {
            let remaining = state
                .remaining_uses
                .get_mut(&grant.grant_id.0)
                .ok_or(ApprovalError::GrantInvalid)?;
            if *remaining == 0 {
                return Err(ApprovalError::GrantReplayed);
            }
            *remaining -= 1;
            *remaining
        };
        if remaining == 0
            && !grant.break_glass
            && let Some(case) = state.cases.get_mut(&grant.case_id)
        {
            case.status = ApprovalStatus::Consumed;
        }
        Ok(remaining)
    }
}

pub struct SoDEngine;
impl SoDEngine {
    pub fn validate(
        case: &ApprovalCase,
        approver: &ApproverIdentity,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalError> {
        let request = &case.request;
        let policy = &case.policy;
        if approver.tenant_id != request.tenant_id
            || !approver.active
            || !approver.strong_auth
            || approver.delegated_until.is_some_and(|expiry| expiry <= now)
            || (!policy.required_roles.is_empty()
                && policy.required_roles.is_disjoint(&approver.roles))
            || (policy.prohibit_requester && approver.subject == request.requester_subject)
            || (policy.prohibit_agent_owner && approver.subject == request.agent_owner_subject)
            || (policy.require_resource_owner
                && !approver.owned_resources.contains(&request.resource))
        {
            return Err(ApprovalError::ApproverNotEligible);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalExecutionBinding {
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub plan_hash: String,
    pub parameter_hash: String,
    pub resource: String,
    pub resource_version: ResourceVersion,
    pub policy_version: PolicyVersion,
    pub environment: String,
    pub risk: RiskLevel,
}
impl ApprovalExecutionBinding {
    fn matches(&self, grant: &EnterpriseApprovalGrant) -> bool {
        self.tenant_id == grant.tenant_id
            && self.task_id == grant.task_id
            && self.step_id == grant.step_id
            && self.action_hash == grant.action_hash
            && self.plan_hash == grant.plan_hash
            && self.parameter_hash == grant.parameter_hash
            && self.resource == grant.resource
            && self.resource_version == grant.resource_version
            && self.policy_version == grant.policy_version
            && self.environment == grant.environment
            && self.risk <= grant.maximum_risk
    }
}

fn make_grant(
    issuer: &str,
    key_id: &str,
    case: &ApprovalCase,
    now: DateTime<Utc>,
) -> EnterpriseApprovalGrant {
    EnterpriseApprovalGrant {
        schema_version: SchemaVersion(APPROVAL_SCHEMA_VERSION.into()),
        grant_id: ApprovalId::new(),
        case_id: case.case_id.clone(),
        tenant_id: case.request.tenant_id.clone(),
        task_id: case.request.task_id.clone(),
        step_id: case.request.step_id.clone(),
        action_hash: case.request.action_hash.clone(),
        plan_hash: case.request.plan_hash.clone(),
        parameter_hash: case.request.parameter_hash.clone(),
        resource: case.request.resource.clone(),
        resource_version: case.request.resource_version.clone(),
        policy_version: case.request.policy_version.clone(),
        environment: case.request.environment.clone(),
        maximum_risk: case.policy.maximum_risk,
        approver_subjects: case
            .decisions
            .iter()
            .filter(|decision| decision.decision == "APPROVE")
            .map(|decision| decision.approver_subject.clone())
            .collect(),
        issued_at: now,
        expires_at: case.expires_at,
        maximum_uses: case.request.requested_uses.min(case.policy.maximum_uses),
        break_glass: case.policy.approval_type == ApprovalType::Emergency,
        issuer: issuer.into(),
        key_id: key_id.into(),
        signature: String::new(),
    }
}
fn verify_grant_signature(
    grant: &EnterpriseApprovalGrant,
    issuer: &str,
    key_id: &str,
    key: &VerifyingKey,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    if grant.schema_version.0 != APPROVAL_SCHEMA_VERSION
        || grant.issuer != issuer
        || grant.key_id != key_id
        || now < grant.issued_at
        || now >= grant.expires_at
        || grant.maximum_uses == 0
    {
        return Err(ApprovalError::GrantInvalid);
    }
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&grant.signature)
            .map_err(|_| ApprovalError::GrantInvalid)?,
    )
    .map_err(|_| ApprovalError::GrantInvalid)?;
    key.verify(&grant.signing_bytes()?, &signature)
        .map_err(|_| ApprovalError::GrantInvalid)
}
fn validate_policy(policy: &ApprovalPolicy) -> Result<(), ApprovalError> {
    if policy.policy_id.is_empty()
        || policy.policy_version.is_empty()
        || policy.minimum_approvers == 0
        || policy.maximum_ttl_seconds == 0
        || policy.maximum_uses == 0
        || (policy.approval_type == ApprovalType::Dual && policy.minimum_approvers < 2)
    {
        Err(ApprovalError::PolicyInvalid)
    } else {
        Ok(())
    }
}
fn validate_request(
    request: &ApprovalRequest,
    policy: &ApprovalPolicy,
) -> Result<(), ApprovalError> {
    if request.action_hash.0.len() != 64
        || request.plan_hash.len() != 64
        || request.parameter_hash.len() != 64
        || request.resource.is_empty()
        || !request.review_context.valid()
        || request_is_industrial(request) != request.review_context.industrial()
        || request.requester_subject.is_empty()
        || request.agent_owner_subject.is_empty()
        || request.justification.is_empty()
        || request.requested_ttl_seconds == 0
        || request.requested_ttl_seconds > policy.maximum_ttl_seconds
        || request.requested_uses == 0
        || request.requested_uses > policy.maximum_uses
        || request.risk > policy.maximum_risk
    {
        Err(ApprovalError::RequestInvalid)
    } else {
        Ok(())
    }
}

pub(crate) fn request_is_industrial(request: &ApprovalRequest) -> bool {
    let resource = request.resource.to_ascii_lowercase();
    [
        "opcua:",
        "opc.tcp:",
        "mqtt:",
        "modbus:",
        "plc:",
        "scada:",
        "plant/",
        "urn:agenttrust:industrial:",
    ]
    .iter()
    .any(|prefix| resource.starts_with(prefix))
        || matches!(
            request.environment.as_str(),
            "industrial" | "physical-production"
        )
}

pub(crate) fn contains_secret_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "password",
        "passwd",
        "client_secret",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "private key",
        "-----begin",
        "cookie:",
        "set-cookie",
        "credential://",
        "vault-kv://",
        "secret://",
        "token=",
        "token:",
    ]
        .iter()
        .any(|marker| normalized.contains(marker))
}
pub fn binding_hash(binding: &ApprovalExecutionBinding) -> Result<String, ApprovalError> {
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(binding).map_err(|_| ApprovalError::BindingChanged)?,
    )))
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("APPROVAL_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("APPROVAL_POLICY_INVALID")]
    PolicyInvalid,
    #[error("APPROVAL_REQUEST_INVALID")]
    RequestInvalid,
    #[error("APPROVAL_CASE_NOT_FOUND")]
    CaseNotFound,
    #[error("APPROVAL_APPROVER_NOT_ELIGIBLE")]
    ApproverNotEligible,
    #[error("APPROVAL_DUPLICATE_APPROVER")]
    DuplicateApprover,
    #[error("APPROVAL_LIFECYCLE_INVALID")]
    LifecycleInvalid,
    #[error("APPROVAL_EXPIRED")]
    Expired,
    #[error("APPROVAL_REVOKED")]
    Revoked,
    #[error("APPROVAL_GRANT_INVALID")]
    GrantInvalid,
    #[error("APPROVAL_GRANT_REPLAYED")]
    GrantReplayed,
    #[error("APPROVAL_BINDING_CHANGED")]
    BindingChanged,
    #[error("APPROVAL_APPROVER_ROLE_CHANGED")]
    ApproverRoleChanged,
    #[error("APPROVAL_BREAK_GLASS_DENIED")]
    BreakGlassDenied,
    #[error("APPROVAL_NOTIFICATION_FAILED")]
    NotificationFailed,
    #[error("APPROVAL_DATABASE_UNAVAILABLE")]
    DatabaseUnavailable,
    #[error("APPROVAL_IDEMPOTENCY_KEY_INVALID")]
    IdempotencyInvalid,
    #[error("APPROVAL_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("APPROVAL_AUTHENTICATION_REQUIRED")]
    AuthenticationRequired,
    #[error("APPROVAL_SCOPE_FORBIDDEN")]
    ScopeForbidden,
    #[error("APPROVAL_GRANT_NOT_READY")]
    GrantNotReady,
    #[error("APPROVAL_CONCURRENT_MUTATION")]
    ConcurrentMutation,
}

impl From<ContractError> for ApprovalError {
    fn from(_: ContractError) -> Self {
        Self::GrantInvalid
    }
}

pub mod postgres;
pub mod principal;
pub mod review_evidence;
pub mod server;
pub use postgres::{
    APPROVAL_CASE_VIEW_SCHEMA_VERSION, AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION,
    ApprovalCaseCreateEnvelope, ApprovalCaseDomain, ApprovalCaseView, ApprovalCaseViewStatus,
    ApprovalDecision, ApprovalDecisionEnvelope, ApprovalGrantIssueRequest,
    ApprovalGrantRevocationReceipt, ApprovalGrantRevocationRequest, ApprovalPrincipal,
    ApprovalSigner, AuthoritativeApprovalPage, PostgresApprovalStore,
};
pub use principal::{
    APPROVAL_PRINCIPAL_ASSERTION_SCHEMA_VERSION, APPROVAL_PRINCIPAL_KEYRING_SCHEMA_VERSION,
    APPROVAL_PRINCIPAL_REQUEST_BINDING_SCHEMA_VERSION, ApprovalPrincipalAssertionKeyring,
    SignedApprovalPrincipalAssertion, approval_principal_request_digest,
};
pub use review_evidence::{
    APPROVAL_REVIEW_EVIDENCE_KEYRING_SCHEMA_VERSION,
    APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION, APPROVAL_REVIEW_EVIDENCE_ISSUE_SCHEMA_VERSION,
    APPROVAL_REVIEW_MATERIAL_SCHEMA_VERSION, ApprovalReviewEvidence,
    ApprovalReviewEvidenceIssueRequest, ApprovalReviewEvidenceKeyring, ApprovalReviewMaterial,
    review_material_digest,
};

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{
        AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION,
        AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE, AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION,
        AuthorityEvidenceSourceKind, EVIDENCE_EVENT_SCHEMA_VERSION, SignedAuthorityEvidenceReceipt,
        SignedEvidenceEvent,
    };
    use std::sync::Arc;

    struct FailingNotification;
    impl NotificationAdapter for FailingNotification {
        fn send(&self, _: &ApprovalNotification) -> Result<String, ApprovalError> {
            Err(ApprovalError::NotificationFailed)
        }
    }

    fn review_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[72u8; 32])
    }

    fn review_keyring(tenant: &TenantId, now: DateTime<Utc>) -> ApprovalReviewEvidenceKeyring {
        let signing = review_signing_key();
        let document = serde_json::json!({
            "schema_version": APPROVAL_REVIEW_EVIDENCE_KEYRING_SCHEMA_VERSION,
            "keys": [{
                "issuer": "evidence-authority",
                "key_id": "review-key",
                "source_services": ["URI:spiffe://agenttrust/domain-risk-authority"],
                "algorithm": "Ed25519",
                "usage": AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE,
                "status": "ACTIVE",
                "public_key": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                "tenant_ids": [tenant.0.clone()],
                "not_before": now - chrono::Duration::hours(1),
                "expires_at": now + chrono::Duration::days(1)
            }]
        });
        ApprovalReviewEvidenceKeyring::from_json(
            &serde_json::to_vec(&document).unwrap_or_else(|_| panic!("review keyring JSON")),
        )
        .unwrap_or_else(|_| panic!("review keyring"))
    }

    fn signed_review_evidence(
        material: ApprovalReviewMaterial,
        now: DateTime<Utc>,
    ) -> ApprovalReviewEvidence {
        let issue = ApprovalReviewEvidenceIssueRequest {
            schema_version: APPROVAL_REVIEW_EVIDENCE_ISSUE_SCHEMA_VERSION.into(),
            request_id: Uuid::new_v4().to_string(),
            idempotency_key: format!("approval-review:{}", Uuid::new_v4()),
            actor_subject: "review-fact-authority".into(),
            source_service: "URI:spiffe://agenttrust/domain-risk-authority".into(),
            trace_id: Uuid::new_v4().to_string(),
            material: material.clone(),
            requested_at: now,
        };
        let authority_request = issue
            .to_authority_event(&issue.source_service, now)
            .unwrap_or_else(|_| panic!("authority review event"));
        assert_eq!(
            authority_request.schema_version,
            AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION
        );
        let signing = review_signing_key();
        let mut event = SignedEvidenceEvent {
            schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
            event_id: authority_request.authority_event_id.clone(),
            sequence: 1,
            previous_hash: "0".repeat(64),
            event_hash: String::new(),
            key_id: "review-key".into(),
            signature: String::new(),
            draft: authority_request.event.clone(),
        };
        event.event_hash = event
            .expected_hash()
            .unwrap_or_else(|_| panic!("evidence event hash"));
        event.signature = URL_SAFE_NO_PAD.encode(
            signing
                .sign(event.event_hash.as_bytes())
                .to_bytes(),
        );
        let mut receipt = SignedAuthorityEvidenceReceipt {
            schema_version: AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION.into(),
            tenant_id: authority_request.tenant_id.clone(),
            task_id: authority_request.task_id.clone(),
            authority_event_id: authority_request.authority_event_id.clone(),
            idempotency_key: authority_request.idempotency_key.clone(),
            source_kind: AuthorityEvidenceSourceKind::AuthenticatedEvent,
            request_digest: authority_request
                .request_digest()
                .unwrap_or_else(|_| panic!("authority request digest")),
            payload_digest: authority_request.event.payload_hash.clone(),
            evidence_ref: String::new(),
            evidence_digest: String::new(),
            event,
            persisted_at: now,
            issuer: "evidence-authority".into(),
            key_id: "review-key".into(),
            key_usage: AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE.into(),
            signature: String::new(),
        };
        receipt.evidence_ref = receipt.expected_evidence_ref();
        receipt
            .sign(&signing)
            .unwrap_or_else(|_| panic!("shared authority receipt"));
        ApprovalReviewEvidence {
            schema_version: APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION.into(),
            material,
            authority_request,
            receipt,
        }
    }

    fn material_for_request(request: &ApprovalRequest) -> ApprovalReviewMaterial {
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

    fn setup(dual: bool) -> (Arc<EnterpriseApprovalService>, ApprovalCase) {
        let now = Utc::now();
        let tenant = TenantId::new();
        let keyring = review_keyring(&tenant, now);
        let service = Arc::new(
            EnterpriseApprovalService::new(
                "approval".into(),
                "key".into(),
                SigningKey::from_bytes(&[71u8; 32]),
                keyring,
            )
            .unwrap_or_else(|_| panic!("service")),
        );
        for subject in ["approver-1", "approver-2"] {
            service.directory().upsert(ApproverIdentity {
                tenant_id: tenant.clone(),
                subject: subject.into(),
                roles: BTreeSet::from(["production-approver".into()]),
                owned_resources: BTreeSet::from(["repo:a".into()]),
                delegated_until: None,
                strong_auth: true,
                active: true,
            });
        }
        let task_id = TaskId::new();
        let action_hash = ActionHash("a".repeat(64));
        let review_context = ApprovalReviewContext::Coding(CodingApprovalReviewDetails {
            diff_artifact_ref: format!("artifact://sha256/{}", "d".repeat(64)),
            command_summary: "Apply the reviewed repository patch".into(),
            network_scope: "egress:none".into(),
            rollback_summary: "Restore the reviewed parent revision".into(),
        });
        let material = ApprovalReviewMaterial {
            schema_version: APPROVAL_REVIEW_MATERIAL_SCHEMA_VERSION.into(),
            tenant_id: tenant.0.clone(),
            task_id: task_id.0.clone(),
            canonical_action_hash: action_hash.0.clone(),
            resource: "repo:a".into(),
            resource_version: "v1".into(),
            policy_version: "policy-v1".into(),
            environment: "production".into(),
            risk: RiskLevel::High,
            review_context: review_context.clone(),
            risk_package_ref: "urn:agenttrust:evidence:risk-package:test".into(),
            risk_package_digest: "e".repeat(64),
            state_snapshot_ref: "urn:agenttrust:evidence:state-snapshot:test".into(),
            state_snapshot_digest: "f".repeat(64),
        };
        let request = ApprovalRequest {
            tenant_id: tenant,
            task_id,
            step_id: StepId::new(),
            action_hash,
            plan_hash: "b".repeat(64),
            parameter_hash: "c".repeat(64),
            resource: "repo:a".into(),
            resource_version: ResourceVersion("v1".into()),
            policy_version: PolicyVersion("policy-v1".into()),
            environment: "production".into(),
            risk: RiskLevel::High,
            review_context,
            review_evidence: signed_review_evidence(material, now),
            requester_subject: "requester".into(),
            agent_owner_subject: "agent-owner".into(),
            justification: "apply reviewed patch".into(),
            requested_ttl_seconds: 300,
            requested_uses: 1,
        };
        let policy = ApprovalPolicy {
            policy_id: "production".into(),
            policy_version: "1".into(),
            approval_type: if dual {
                ApprovalType::Dual
            } else {
                ApprovalType::Action
            },
            minimum_approvers: if dual { 2 } else { 1 },
            required_roles: BTreeSet::from(["production-approver".into()]),
            prohibit_requester: true,
            prohibit_agent_owner: true,
            require_resource_owner: true,
            maximum_ttl_seconds: 600,
            maximum_uses: 1,
            maximum_risk: RiskLevel::High,
        };
        let case = service
            .request(request, policy, now)
            .unwrap_or_else(|_| panic!("case"));
        (service, case)
    }
    fn binding(case: &ApprovalCase) -> ApprovalExecutionBinding {
        ApprovalExecutionBinding {
            tenant_id: case.request.tenant_id.clone(),
            task_id: case.request.task_id.clone(),
            step_id: case.request.step_id.clone(),
            action_hash: case.request.action_hash.clone(),
            plan_hash: case.request.plan_hash.clone(),
            parameter_hash: case.request.parameter_hash.clone(),
            resource: case.request.resource.clone(),
            resource_version: case.request.resource_version.clone(),
            policy_version: case.request.policy_version.clone(),
            environment: case.request.environment.clone(),
            risk: case.request.risk,
        }
    }

    #[test]
    fn review_context_is_domain_bound_and_rejects_secret_like_values() {
        let (service, case) = setup(false);
        assert!(validate_request(&case.request, &case.policy).is_ok());

        let mut secret = case.request.clone();
        secret.review_context = ApprovalReviewContext::Coding(CodingApprovalReviewDetails {
            diff_artifact_ref: format!("artifact://sha256/{}", "d".repeat(64)),
            command_summary: "Authorization: Bearer must-not-enter-the-inbox".into(),
            network_scope: "egress:none".into(),
            rollback_summary: "Restore the reviewed parent revision".into(),
        });
        assert_eq!(
            validate_request(&secret, &case.policy),
            Err(ApprovalError::RequestInvalid)
        );

        let mut mismatched = case.request.clone();
        mismatched.resource = "opcua:plant/line-1/point-7".into();
        mismatched.environment = "industrial".into();
        assert_eq!(
            validate_request(&mismatched, &case.policy),
            Err(ApprovalError::RequestInvalid)
        );

        mismatched.review_context =
            ApprovalReviewContext::Industrial(IndustrialApprovalReviewDetails {
                current_value: "42.0 C".into(),
                target_value: "43.0 C".into(),
                allowed_range: "40.0 C to 45.0 C".into(),
                interlock_summary: "SIS permissive and operator supervision required".into(),
                physical_impact: "One degree setpoint increase on line 1".into(),
            });
        assert!(validate_request(&mismatched, &case.policy).is_ok());
        assert_eq!(
            service.review_evidence_keyring.verify_request(&mismatched, Utc::now()),
            Err(ApprovalError::RequestInvalid)
        );
        mismatched.review_evidence =
            signed_review_evidence(material_for_request(&mismatched), Utc::now());
        assert!(service.review_evidence_keyring
            .verify_request(&mismatched, Utc::now())
            .is_ok());

        let mut unknown = serde_json::to_value(&case.request.review_context)
            .unwrap_or_else(|_| panic!("review context JSON"));
        unknown
            .as_object_mut()
            .unwrap_or_else(|| panic!("review context object"))
            .insert("raw_command".into(), serde_json::json!("hidden"));
        assert!(serde_json::from_value::<ApprovalReviewContext>(unknown).is_err());
    }

    #[test]
    fn persisted_review_evidence_is_verified_at_case_creation_time() {
        let (service, case) = setup(false);
        let created_at = case.created_at;
        assert!(
            service
                .review_evidence_keyring
                .verify_historical_request(&case.request, created_at)
                .is_ok()
        );
        assert_eq!(
            service.review_evidence_keyring.verify_request(
                &case.request,
                created_at + chrono::Duration::hours(1),
            ),
            Err(ApprovalError::RequestInvalid)
        );
        assert!(
            service
                .review_evidence_keyring
                .verify_historical_request(&case.request, created_at)
                .is_ok(),
            "an immutable case must remain listable after the short-lived creation receipt expires"
        );
    }

    #[test]
    fn shared_authority_request_binds_exact_source_payload_and_artifacts() {
        let (service, case) = setup(false);
        let authority = &case.request.review_evidence.authority_request;
        assert_eq!(authority.source_kind, AuthorityEvidenceSourceKind::AuthenticatedEvent);
        assert!(authority.control_binding.is_none());
        assert_eq!(
            authority.event.event_type,
            agent_trust_contracts::EvidenceEventType::ApprovalReviewPrepared
        );
        assert_eq!(authority.event.artifact_refs.len(), 3);
        assert_eq!(
            authority.event.payload_hash,
            review_material_digest(&case.request.review_evidence.material)
                .unwrap_or_else(|_| panic!("review material digest"))
        );

        let mut source_drift = case.request.clone();
        source_drift
            .review_evidence
            .authority_request
            .event
            .source_service = "URI:spiffe://agenttrust/untrusted-requester".into();
        assert_eq!(
            service
                .review_evidence_keyring
                .verify_request(&source_drift, case.created_at),
            Err(ApprovalError::RequestInvalid)
        );

        let mut artifact_drift = case.request.clone();
        let _ = artifact_drift
            .review_evidence
            .authority_request
            .event
            .artifact_refs
            .pop();
        assert_eq!(
            service
                .review_evidence_keyring
                .verify_request(&artifact_drift, case.created_at),
            Err(ApprovalError::RequestInvalid)
        );
    }

    #[test]
    fn dual_approval_requires_distinct_subjects_and_ui_is_not_a_grant() {
        let (service, case) = setup(true);
        service
            .submit_ui_intent(&case.case_id, "session")
            .unwrap_or_else(|_| panic!("intent"));
        assert!(
            service
                .approve(&case.case_id, "approver-1", "ok".into(), Utc::now())
                .unwrap_or_else(|_| panic!("approve"))
                .is_none()
        );
        assert_eq!(
            service
                .approve(&case.case_id, "approver-1", "again".into(), Utc::now())
                .err(),
            Some(ApprovalError::DuplicateApprover)
        );
        assert!(
            service
                .approve(&case.case_id, "approver-2", "ok".into(), Utc::now())
                .unwrap_or_else(|_| panic!("approve"))
                .is_some()
        );
    }

    #[test]
    fn any_binding_change_invalidates_grant() {
        let (service, case) = setup(false);
        let grant = service
            .approve(&case.case_id, "approver-1", "ok".into(), Utc::now())
            .unwrap_or_else(|_| panic!("approve"))
            .unwrap_or_else(|| panic!("grant"));
        let mut changed = binding(&case);
        changed.resource_version = ResourceVersion("v2".into());
        assert_eq!(
            service.verify_and_consume(&grant, &changed, Utc::now()),
            Err(ApprovalError::BindingChanged)
        );
    }

    #[test]
    fn role_and_resource_ownership_are_rechecked_at_consumption() {
        let (service, case) = setup(false);
        let grant = service
            .approve(&case.case_id, "approver-1", "ok".into(), Utc::now())
            .unwrap_or_else(|_| panic!("approve"))
            .unwrap_or_else(|| panic!("grant"));
        service.directory().upsert(ApproverIdentity {
            tenant_id: case.request.tenant_id.clone(),
            subject: "approver-1".into(),
            roles: BTreeSet::from(["viewer".into()]),
            owned_resources: BTreeSet::new(),
            delegated_until: None,
            strong_auth: true,
            active: true,
        });
        assert_eq!(
            service.verify_and_consume(&grant, &binding(&case), Utc::now()),
            Err(ApprovalError::ApproverRoleChanged)
        );
    }

    #[test]
    fn notification_failure_is_recorded_and_never_becomes_approval() {
        let (service, case) = setup(false);
        let record = dispatch_notification(
            &FailingNotification,
            &ApprovalNotification {
                schema_version: APPROVAL_SCHEMA_VERSION.into(),
                notification_id: Uuid::new_v4().to_string(),
                tenant_id: case.request.tenant_id.clone(),
                case_id: case.case_id.clone(),
                recipient_subject: "approver-1".into(),
                kind: NotificationKind::Pending,
                safe_summary: "approval is pending".into(),
                evidence_refs: vec![],
            },
        );
        assert!(!record.delivered);
        assert!(record.provider_message_id.is_none());
        assert!(
            service
                .approve(&case.case_id, "approver-1", "explicit".into(), Utc::now())
                .unwrap_or_else(|_| panic!("explicit approval"))
                .is_some()
        );
    }

    #[test]
    fn grant_consumption_is_atomic_under_concurrency() {
        let (service, case) = setup(false);
        let grant = Arc::new(
            service
                .approve(&case.case_id, "approver-1", "ok".into(), Utc::now())
                .unwrap_or_else(|_| panic!("approve"))
                .unwrap_or_else(|| panic!("grant")),
        );
        let bind = Arc::new(binding(&case));
        let mut threads = Vec::new();
        for _ in 0..20 {
            let service = service.clone();
            let grant = grant.clone();
            let bind = bind.clone();
            threads.push(std::thread::spawn(move || {
                service
                    .verify_and_consume(&grant, &bind, Utc::now())
                    .is_ok()
            }));
        }
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap_or(false))
                .filter(|passed| *passed)
                .count(),
            1
        );
    }
}
