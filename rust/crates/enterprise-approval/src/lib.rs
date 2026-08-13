//! Enterprise approval service with separation of duties and atomic grant consumption.

use agent_trust_contracts::{
    ActionHash, ApprovalId, MinimalApprovalGrant, PolicyVersion, ResourceVersion, RiskLevel,
    SchemaVersion, StepId, TaskId, TenantId,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseApprovalGrant {
    pub schema_version: SchemaVersion,
    pub grant_id: ApprovalId,
    pub case_id: String,
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
    pub maximum_risk: RiskLevel,
    pub approver_subjects: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub maximum_uses: u32,
    pub break_glass: bool,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl EnterpriseApprovalGrant {
    fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| ApprovalError::GrantInvalid)
    }
    pub fn to_minimal_grant(&self) -> MinimalApprovalGrant {
        MinimalApprovalGrant {
            schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
            approval_id: self.grant_id.clone(),
            task_id: self.task_id.clone(),
            step_id: self.step_id.clone(),
            action_hash: self.action_hash.clone(),
            resource_version: self.resource_version.clone(),
            policy_version: self.policy_version.clone(),
            approver_subject: self.approver_subjects.join(","),
            approver_roles: vec!["enterprise-approved".into()],
            expires_at: self.expires_at,
            single_use: self.maximum_uses == 1,
        }
    }
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
    directory: ApproverDirectory,
    state: Mutex<ApprovalState>,
}

impl EnterpriseApprovalService {
    pub fn new(
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, ApprovalError> {
        if issuer.is_empty() || key_id.is_empty() {
            Err(ApprovalError::ConfigurationInvalid)
        } else {
            Ok(Self {
                issuer,
                key_id,
                signing_key,
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
            schema_version: APPROVAL_SCHEMA_VERSION.into(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct FailingNotification;
    impl NotificationAdapter for FailingNotification {
        fn send(&self, _: &ApprovalNotification) -> Result<String, ApprovalError> {
            Err(ApprovalError::NotificationFailed)
        }
    }

    fn setup(dual: bool) -> (Arc<EnterpriseApprovalService>, ApprovalCase) {
        let service = Arc::new(
            EnterpriseApprovalService::new(
                "approval".into(),
                "key".into(),
                SigningKey::from_bytes(&[71u8; 32]),
            )
            .unwrap_or_else(|_| panic!("service")),
        );
        let tenant = TenantId::new();
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
        let request = ApprovalRequest {
            tenant_id: tenant,
            task_id: TaskId::new(),
            step_id: StepId::new(),
            action_hash: ActionHash("a".repeat(64)),
            plan_hash: "b".repeat(64),
            parameter_hash: "c".repeat(64),
            resource: "repo:a".into(),
            resource_version: ResourceVersion("v1".into()),
            policy_version: PolicyVersion("policy-v1".into()),
            environment: "production".into(),
            risk: RiskLevel::High,
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
            .request(request, policy, Utc::now())
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
