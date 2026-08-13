//! Scope-reducing A2A delegation and authenticated AG-UI event replay.

use agent_trust_contracts::{
    AgentInstanceId, AuthorizationLease, DelegationEnvelope, EvaluationStatus, SchemaVersion,
    StepId, TaskId, TaskStatus, TenantId,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const A2A_SCHEMA_VERSION: &str = "agenttrust.a2a-agui.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentCardSnapshot {
    pub schema_version: String,
    pub agent_id: String,
    pub publisher_id: String,
    pub endpoint: String,
    pub capability_ids: BTreeSet<String>,
    pub card_hash: String,
    pub trust_level: String,
    pub verified: bool,
    pub observed_at: DateTime<Utc>,
}

pub struct AgentCardVerifier {
    approved_publishers: BTreeSet<String>,
    approved_endpoints: BTreeSet<String>,
}
impl AgentCardVerifier {
    pub fn new(
        approved_publishers: BTreeSet<String>,
        approved_endpoints: BTreeSet<String>,
    ) -> Self {
        Self {
            approved_publishers,
            approved_endpoints,
        }
    }
    pub fn verify(&self, mut card: AgentCardSnapshot) -> Result<AgentCardSnapshot, A2aError> {
        if card.schema_version != A2A_SCHEMA_VERSION
            || card.agent_id.is_empty()
            || card.capability_ids.is_empty()
            || card.card_hash.len() != 64
        {
            return Err(A2aError::AgentCardInvalid);
        }
        card.verified = self.approved_publishers.contains(&card.publisher_id)
            && self.approved_endpoints.contains(&card.endpoint);
        card.trust_level = if card.verified {
            "verified-card".into()
        } else {
            "untrusted-card".into()
        };
        Ok(card)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationToken {
    pub schema_version: SchemaVersion,
    pub token_id: String,
    pub tenant_id: TenantId,
    pub root_task_id: TaskId,
    pub parent_task_id: TaskId,
    pub parent_step_id: StepId,
    pub envelope: DelegationEnvelope,
    pub depth: u32,
    pub maximum_depth: u32,
    pub remaining_calls: u32,
    pub parent_token_id: Option<String>,
    pub revocation_epoch: u64,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl DelegationToken {
    fn signing_bytes(&self) -> Result<Vec<u8>, A2aError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| A2aError::TokenInvalid)
    }
}

#[derive(Default)]
struct DelegationState {
    revoked_tokens: BTreeSet<String>,
    revoked_tasks: BTreeSet<TaskId>,
    remaining_calls: BTreeMap<String, u32>,
    epoch_by_tenant: BTreeMap<TenantId, u64>,
}

pub struct DelegationLimiter {
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
    state: RwLock<DelegationState>,
}

impl DelegationLimiter {
    pub fn new(issuer: String, key_id: String, signing_key: SigningKey) -> Result<Self, A2aError> {
        if issuer.is_empty() || key_id.is_empty() {
            return Err(A2aError::ConfigurationInvalid);
        }
        Ok(Self {
            issuer,
            key_id,
            signing_key,
            state: RwLock::new(DelegationState::default()),
        })
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn issue_root(
        &self,
        tenant_id: TenantId,
        root_task_id: TaskId,
        parent_step_id: StepId,
        envelope: DelegationEnvelope,
        parent_lease: &AuthorizationLease,
        maximum_depth: u32,
        maximum_calls: u32,
    ) -> Result<DelegationToken, A2aError> {
        if maximum_depth == 0
            || maximum_calls == 0
            || !envelope.is_within(parent_lease)
            || envelope.parent_agent == envelope.child_agent
        {
            return Err(A2aError::ScopeExceeded);
        }
        self.sign_token(
            tenant_id,
            root_task_id.clone(),
            root_task_id,
            parent_step_id,
            envelope,
            1,
            maximum_depth,
            maximum_calls,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn issue_child(
        &self,
        parent: &DelegationToken,
        child_agent: AgentInstanceId,
        tools: BTreeSet<agent_trust_contracts::ToolRef>,
        resources: BTreeSet<String>,
        budget_ceiling_microunits: u64,
        expiry: DateTime<Utc>,
        maximum_calls: u32,
    ) -> Result<DelegationToken, A2aError> {
        self.verify(parent, Utc::now())?;
        if parent.depth >= parent.maximum_depth
            || maximum_calls == 0
            || maximum_calls > parent.remaining_calls
            || !tools.is_subset(&parent.envelope.delegated_tools)
            || !resources.is_subset(&parent.envelope.delegated_resources)
            || budget_ceiling_microunits > parent.envelope.budget_ceiling_microunits
            || expiry > parent.envelope.expiry
        {
            return Err(A2aError::ScopeExceeded);
        }
        let envelope = DelegationEnvelope {
            schema_version: parent.envelope.schema_version.clone(),
            parent_agent: parent.envelope.child_agent.clone(),
            child_agent,
            delegated_tools: tools,
            delegated_resources: resources,
            budget_ceiling_microunits,
            expiry,
        };
        self.sign_token(
            parent.tenant_id.clone(),
            parent.root_task_id.clone(),
            parent.parent_task_id.clone(),
            parent.parent_step_id.clone(),
            envelope,
            parent.depth + 1,
            parent.maximum_depth,
            maximum_calls,
            Some(parent.token_id.clone()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn sign_token(
        &self,
        tenant_id: TenantId,
        root_task_id: TaskId,
        parent_task_id: TaskId,
        parent_step_id: StepId,
        envelope: DelegationEnvelope,
        depth: u32,
        maximum_depth: u32,
        remaining_calls: u32,
        parent_token_id: Option<String>,
    ) -> Result<DelegationToken, A2aError> {
        let epoch = *self
            .state
            .read()
            .epoch_by_tenant
            .get(&tenant_id)
            .unwrap_or(&0);
        let mut token = DelegationToken {
            schema_version: SchemaVersion(A2A_SCHEMA_VERSION.into()),
            token_id: Uuid::new_v4().to_string(),
            tenant_id,
            root_task_id,
            parent_task_id,
            parent_step_id,
            envelope,
            depth,
            maximum_depth,
            remaining_calls,
            parent_token_id,
            revocation_epoch: epoch,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        token.signature =
            URL_SAFE_NO_PAD.encode(self.signing_key.sign(&token.signing_bytes()?).to_bytes());
        self.state
            .write()
            .remaining_calls
            .insert(token.token_id.clone(), remaining_calls);
        Ok(token)
    }
    pub fn verify(&self, token: &DelegationToken, now: DateTime<Utc>) -> Result<(), A2aError> {
        if token.issuer != self.issuer
            || token.key_id != self.key_id
            || token.depth == 0
            || token.depth > token.maximum_depth
            || now >= token.envelope.expiry
        {
            return Err(A2aError::TokenInvalid);
        }
        let state = self.state.read();
        if state.revoked_tokens.contains(&token.token_id)
            || state.revoked_tasks.contains(&token.root_task_id)
            || token.revocation_epoch < *state.epoch_by_tenant.get(&token.tenant_id).unwrap_or(&0)
        {
            return Err(A2aError::Revoked);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&token.signature)
                .map_err(|_| A2aError::TokenInvalid)?,
        )
        .map_err(|_| A2aError::TokenInvalid)?;
        self.signing_key
            .verifying_key()
            .verify(&token.signing_bytes()?, &signature)
            .map_err(|_| A2aError::TokenInvalid)
    }
    pub fn consume_call(
        &self,
        token: &DelegationToken,
        now: DateTime<Utc>,
    ) -> Result<u32, A2aError> {
        self.verify(token, now)?;
        let mut state = self.state.write();
        let remaining = state
            .remaining_calls
            .get_mut(&token.token_id)
            .ok_or(A2aError::Revoked)?;
        if *remaining == 0 {
            return Err(A2aError::BudgetExceeded);
        }
        *remaining -= 1;
        Ok(*remaining)
    }
    pub fn revoke_token(&self, token_id: String) {
        self.state.write().revoked_tokens.insert(token_id);
    }
    pub fn revoke_root_task(&self, task_id: TaskId) {
        self.state.write().revoked_tasks.insert(task_id);
    }
    pub fn bump_tenant_epoch(&self, tenant: &TenantId) {
        let mut state = self.state.write();
        *state.epoch_by_tenant.entry(tenant.clone()).or_insert(0) += 1;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgUiEventKind {
    Plan,
    ToolRequest,
    ApprovalRequired,
    ApprovalRecorded,
    ExecutionStatus,
    Artifact,
    Evaluation,
    Incident,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgUiEventEnvelope {
    pub schema_version: String,
    pub event_id: String,
    pub task_id: TaskId,
    pub sequence: u64,
    pub kind: AgUiEventKind,
    pub trace_id: String,
    pub safe_payload: Value,
    pub occurred_at: DateTime<Utc>,
    pub backend_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResumeToken {
    pub schema_version: String,
    pub task_id: TaskId,
    pub after_sequence: u64,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

pub struct AgUiStreamAdapter {
    key: SigningKey,
    maximum_events_per_task: usize,
    events: RwLock<BTreeMap<TaskId, Vec<AgUiEventEnvelope>>>,
}
impl AgUiStreamAdapter {
    pub fn new(key: SigningKey, maximum_events_per_task: usize) -> Result<Self, A2aError> {
        if maximum_events_per_task == 0 {
            Err(A2aError::ConfigurationInvalid)
        } else {
            Ok(Self {
                key,
                maximum_events_per_task,
                events: RwLock::new(BTreeMap::new()),
            })
        }
    }
    pub fn publish_backend(
        &self,
        task_id: TaskId,
        kind: AgUiEventKind,
        trace_id: String,
        safe_payload: Value,
    ) -> Result<AgUiEventEnvelope, A2aError> {
        if trace_id.is_empty() || safe_payload.to_string().len() > 64 * 1024 {
            return Err(A2aError::EventInvalid);
        }
        let mut events = self.events.write();
        let stream = events.entry(task_id.clone()).or_default();
        if stream.len() >= self.maximum_events_per_task {
            return Err(A2aError::CapacityExceeded);
        }
        let mut event = AgUiEventEnvelope {
            schema_version: A2A_SCHEMA_VERSION.into(),
            event_id: Uuid::new_v4().to_string(),
            task_id,
            sequence: stream.len() as u64 + 1,
            kind,
            trace_id,
            safe_payload,
            occurred_at: Utc::now(),
            backend_signature: String::new(),
        };
        event.backend_signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&event_bytes(&event)?).to_bytes());
        stream.push(event.clone());
        Ok(event)
    }
    pub fn resume_token(
        &self,
        task_id: TaskId,
        after_sequence: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<ResumeToken, A2aError> {
        let mut token = ResumeToken {
            schema_version: A2A_SCHEMA_VERSION.into(),
            task_id,
            after_sequence,
            expires_at,
            signature: String::new(),
        };
        token.signature = URL_SAFE_NO_PAD.encode(self.key.sign(&resume_bytes(&token)?).to_bytes());
        Ok(token)
    }
    pub fn resume(
        &self,
        token: &ResumeToken,
        now: DateTime<Utc>,
    ) -> Result<Vec<AgUiEventEnvelope>, A2aError> {
        if token.schema_version != A2A_SCHEMA_VERSION || now >= token.expires_at {
            return Err(A2aError::ResumeExpired);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&token.signature)
                .map_err(|_| A2aError::EventInvalid)?,
        )
        .map_err(|_| A2aError::EventInvalid)?;
        self.key
            .verifying_key()
            .verify(&resume_bytes(token)?, &signature)
            .map_err(|_| A2aError::EventInvalid)?;
        Ok(self
            .events
            .read()
            .get(&token.task_id)
            .map(|events| {
                events
                    .iter()
                    .filter(|event| event.sequence > token.after_sequence)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }
    pub fn accept_ui_event(&self, kind: AgUiEventKind) -> Result<(), A2aError> {
        if kind == AgUiEventKind::ApprovalRecorded {
            Err(A2aError::UiCannotAuthorize)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiApprovalIntent {
    pub schema_version: String,
    pub task_id: TaskId,
    pub action_hash: String,
    pub intent: String,
    pub user_session_id: String,
}

pub fn map_remote_status(remote: &str, evaluation: Option<EvaluationStatus>) -> TaskStatus {
    match remote {
        "submitted" => TaskStatus::Created,
        "working" => TaskStatus::Running,
        "cancelled" => TaskStatus::Cancelling,
        "completed" if evaluation == Some(EvaluationStatus::Pass) => TaskStatus::Completed,
        "completed" => TaskStatus::Verifying,
        _ => TaskStatus::NeedsHuman,
    }
}

fn event_bytes(event: &AgUiEventEnvelope) -> Result<Vec<u8>, A2aError> {
    let mut copy = event.clone();
    copy.backend_signature.clear();
    serde_jcs::to_vec(&copy).map_err(|_| A2aError::EventInvalid)
}
fn resume_bytes(token: &ResumeToken) -> Result<Vec<u8>, A2aError> {
    let mut copy = token.clone();
    copy.signature.clear();
    serde_jcs::to_vec(&copy).map_err(|_| A2aError::EventInvalid)
}
pub fn card_hash(value: &Value) -> Result<String, A2aError> {
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| A2aError::AgentCardInvalid)?,
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
pub enum A2aError {
    #[error("A2A_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("A2A_AGENT_CARD_INVALID")]
    AgentCardInvalid,
    #[error("A2A_SCOPE_EXCEEDED")]
    ScopeExceeded,
    #[error("A2A_TOKEN_INVALID")]
    TokenInvalid,
    #[error("A2A_REVOKED")]
    Revoked,
    #[error("A2A_BUDGET_EXCEEDED")]
    BudgetExceeded,
    #[error("AGUI_EVENT_INVALID")]
    EventInvalid,
    #[error("AGUI_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("AGUI_RESUME_EXPIRED")]
    ResumeExpired,
    #[error("AGUI_UI_CANNOT_AUTHORIZE")]
    UiCannotAuthorize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{LeaseId, ToolId, ToolRef, ToolVersion};

    fn setup() -> (DelegationLimiter, AuthorizationLease, DelegationEnvelope) {
        let limiter = DelegationLimiter::new(
            "delegation".into(),
            "key".into(),
            SigningKey::from_bytes(&[51u8; 32]),
        )
        .unwrap_or_else(|_| panic!("limiter"));
        let tool = ToolRef {
            tool_id: ToolId("coding.read".into()),
            tool_version: ToolVersion("1.0.0".into()),
        };
        let now = Utc::now();
        let lease = AuthorizationLease {
            schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
            lease_id: LeaseId::new(),
            task_id: TaskId::new(),
            goal_hash: "a".repeat(64),
            plan_hash: "b".repeat(64),
            policy_snapshot: "policy".into(),
            allowed_tools: BTreeSet::from([tool.clone()]),
            allowed_resources: BTreeSet::from(["repo:a".into()]),
            revocation_epoch: 0,
            valid_until: now + chrono::Duration::minutes(10),
        };
        let envelope = DelegationEnvelope {
            schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
            parent_agent: AgentInstanceId::new(),
            child_agent: AgentInstanceId::new(),
            delegated_tools: BTreeSet::from([tool]),
            delegated_resources: BTreeSet::from(["repo:a".into()]),
            budget_ceiling_microunits: 100,
            expiry: now + chrono::Duration::minutes(5),
        };
        (limiter, lease, envelope)
    }

    #[test]
    fn child_delegation_cannot_expand_scope_and_revocation_propagates() {
        let (limiter, lease, envelope) = setup();
        let root_task = lease.task_id.clone();
        let token = limiter
            .issue_root(
                TenantId::new(),
                root_task.clone(),
                StepId::new(),
                envelope,
                &lease,
                2,
                2,
            )
            .unwrap_or_else(|_| panic!("token"));
        assert!(
            limiter
                .issue_child(
                    &token,
                    AgentInstanceId::new(),
                    BTreeSet::new(),
                    BTreeSet::from(["repo:outside".into()]),
                    1,
                    Utc::now() + chrono::Duration::minutes(1),
                    1
                )
                .is_err()
        );
        limiter.revoke_root_task(root_task);
        assert_eq!(limiter.verify(&token, Utc::now()), Err(A2aError::Revoked));
    }

    #[test]
    fn ui_cannot_forge_approval_and_remote_completed_needs_evaluation() {
        let stream = AgUiStreamAdapter::new(SigningKey::from_bytes(&[52u8; 32]), 10)
            .unwrap_or_else(|_| panic!("stream"));
        assert_eq!(
            stream.accept_ui_event(AgUiEventKind::ApprovalRecorded),
            Err(A2aError::UiCannotAuthorize)
        );
        assert_eq!(map_remote_status("completed", None), TaskStatus::Verifying);
        assert_eq!(
            map_remote_status("completed", Some(EvaluationStatus::Pass)),
            TaskStatus::Completed
        );
    }

    #[test]
    fn resume_is_ordered_and_does_not_duplicate() {
        let stream = AgUiStreamAdapter::new(SigningKey::from_bytes(&[53u8; 32]), 10)
            .unwrap_or_else(|_| panic!("stream"));
        let task = TaskId::new();
        stream
            .publish_backend(
                task.clone(),
                AgUiEventKind::Plan,
                "trace".into(),
                serde_json::json!({"plan":"safe"}),
            )
            .unwrap_or_else(|_| panic!("event"));
        stream
            .publish_backend(
                task.clone(),
                AgUiEventKind::ExecutionStatus,
                "trace".into(),
                serde_json::json!({"status":"RUNNING"}),
            )
            .unwrap_or_else(|_| panic!("event"));
        let token = stream
            .resume_token(task, 1, Utc::now() + chrono::Duration::minutes(1))
            .unwrap_or_else(|_| panic!("token"));
        let events = stream
            .resume(&token, Utc::now())
            .unwrap_or_else(|_| panic!("resume"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 2);
    }
}
