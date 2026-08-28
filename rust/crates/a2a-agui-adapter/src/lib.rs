//! Scope-reducing A2A delegation and authenticated AG-UI event replay.

use agent_trust_contracts::{
    AgentInstanceId, AuthorizationLease, DelegationEnvelope, EvaluationStatus, SchemaVersion,
    StepId, TaskId, TaskStatus, TenantId,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const A2A_SCHEMA_VERSION: &str = "agenttrust.a2a-agui.v1";
pub const AGUI_SNAPSHOT_SCHEMA_VERSION: &str = "agenttrust.agui-safe-snapshot.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentCardSnapshot {
    pub schema_version: String,
    pub protocol_version: String,
    pub agent_id: String,
    pub publisher_id: String,
    pub endpoint: String,
    pub capability_ids: BTreeSet<String>,
    pub card_hash: String,
    pub trust_level: String,
    pub verified: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub publisher_key_id: String,
    pub signature: String,
}

impl AgentCardSnapshot {
    fn card_material(&self) -> Result<Vec<u8>, A2aError> {
        serde_jcs::to_vec(&(
            &self.schema_version,
            &self.protocol_version,
            &self.agent_id,
            &self.publisher_id,
            &self.endpoint,
            &self.capability_ids,
            &self.issued_at,
            &self.expires_at,
            &self.observed_at,
            &self.publisher_key_id,
        ))
        .map_err(|_| A2aError::AgentCardInvalid)
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, A2aError> {
        let mut copy = self.clone();
        copy.verified = false;
        copy.trust_level.clear();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| A2aError::AgentCardInvalid)
    }
}

pub struct AgentCardVerifier {
    approved_publishers: BTreeSet<String>,
    approved_endpoints: BTreeSet<String>,
    publisher_keys: BTreeMap<String, (String, VerifyingKey)>,
    require_verified: bool,
}
impl AgentCardVerifier {
    pub fn new(
        approved_publishers: BTreeSet<String>,
        approved_endpoints: BTreeSet<String>,
    ) -> Self {
        Self {
            approved_publishers,
            approved_endpoints,
            publisher_keys: BTreeMap::new(),
            require_verified: false,
        }
    }
    pub fn new_production(
        approved_publishers: BTreeSet<String>,
        approved_endpoints: BTreeSet<String>,
        publisher_keys: BTreeMap<String, (String, VerifyingKey)>,
    ) -> Result<Self, A2aError> {
        if publisher_keys.is_empty()
            || approved_endpoints.is_empty()
            || approved_endpoints
                .iter()
                .any(|endpoint| !secure_agent_endpoint(endpoint))
        {
            return Err(A2aError::ConfigurationInvalid);
        }
        Ok(Self {
            approved_publishers,
            approved_endpoints,
            publisher_keys,
            require_verified: true,
        })
    }
    pub fn verify(&self, mut card: AgentCardSnapshot) -> Result<AgentCardSnapshot, A2aError> {
        let now = Utc::now();
        if card.schema_version != A2A_SCHEMA_VERSION
            || !matches!(card.protocol_version.as_str(), "0.3.0" | "1.0")
            || card.agent_id.is_empty()
            || card.capability_ids.is_empty()
            || card.capability_ids.len() > 1024
            || card.issued_at > card.observed_at
            || card.observed_at > now + chrono::Duration::minutes(5)
            || card.observed_at >= card.expires_at
            || now >= card.expires_at
            || card.expires_at > card.issued_at + chrono::Duration::days(30)
            || card.card_hash != hex(Sha256::digest(card.card_material()?))
            || !secure_agent_endpoint(&card.endpoint)
        {
            return Err(A2aError::AgentCardInvalid);
        }
        let signature_valid = self
            .publisher_keys
            .get(&card.publisher_key_id)
            .filter(|(publisher, _)| publisher == &card.publisher_id)
            .and_then(|(_, key)| {
                let signature = URL_SAFE_NO_PAD
                    .decode(&card.signature)
                    .ok()
                    .and_then(|raw| Signature::from_slice(&raw).ok())?;
                key.verify(&card.signing_bytes().ok()?, &signature).ok()
            })
            .is_some();
        card.verified = signature_valid
            && self.approved_publishers.contains(&card.publisher_id)
            && self.approved_endpoints.contains(&card.endpoint);
        card.trust_level = if card.verified {
            "verified-card".into()
        } else {
            "untrusted-card".into()
        };
        if self.require_verified && !card.verified {
            return Err(A2aError::AgentCardInvalid);
        }
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

/// Atomic durable authority for delegation counters and revocation. Production callers must use
/// `DelegationLimiter::new_production`; process memory is not accepted as restart evidence.
pub trait DelegationStateStore: Send + Sync {
    fn current_epoch(&self, tenant_id: &TenantId) -> Result<u64, A2aError>;
    fn issue(&self, token: &DelegationToken) -> Result<(), A2aError>;
    /// Atomically reserves `child.remaining_calls` from the parent and stores the child.
    fn issue_child(
        &self,
        parent: &DelegationToken,
        child: &DelegationToken,
    ) -> Result<(), A2aError>;
    fn consume_call(&self, token: &DelegationToken) -> Result<u32, A2aError>;
    fn is_revoked(&self, token: &DelegationToken) -> Result<bool, A2aError>;
    fn revoke_token(&self, tenant_id: &TenantId, token_id: &str) -> Result<(), A2aError>;
    fn revoke_root_task(&self, tenant_id: &TenantId, task_id: &TaskId) -> Result<(), A2aError>;
    fn bump_tenant_epoch(&self, tenant_id: &TenantId) -> Result<u64, A2aError>;
}

pub struct DelegationLimiter {
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
    state: RwLock<DelegationState>,
    durable_state: Option<Arc<dyn DelegationStateStore>>,
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
            durable_state: None,
        })
    }
    pub fn new_production(
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
        durable_state: Arc<dyn DelegationStateStore>,
    ) -> Result<Self, A2aError> {
        let mut limiter = Self::new(issuer, key_id, signing_key)?;
        limiter.durable_state = Some(durable_state);
        Ok(limiter)
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
        let token = self.sign_token(
            tenant_id,
            root_task_id.clone(),
            root_task_id,
            parent_step_id,
            envelope,
            1,
            maximum_depth,
            maximum_calls,
            None,
        )?;
        if let Some(store) = &self.durable_state {
            store.issue(&token)?;
        }
        Ok(token)
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
        let token = self.sign_token(
            parent.tenant_id.clone(),
            parent.root_task_id.clone(),
            parent.parent_task_id.clone(),
            parent.parent_step_id.clone(),
            envelope,
            parent.depth + 1,
            parent.maximum_depth,
            maximum_calls,
            Some(parent.token_id.clone()),
        )?;
        if let Some(store) = &self.durable_state {
            store.issue_child(parent, &token)?;
        } else {
            let mut state = self.state.write();
            let remaining = state
                .remaining_calls
                .get(&parent.token_id)
                .copied()
                .ok_or(A2aError::Revoked)?;
            if remaining < maximum_calls {
                state.remaining_calls.remove(&token.token_id);
                return Err(A2aError::BudgetExceeded);
            }
            state
                .remaining_calls
                .insert(parent.token_id.clone(), remaining - maximum_calls);
        }
        Ok(token)
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
        let epoch = if let Some(store) = &self.durable_state {
            store.current_epoch(&tenant_id)?
        } else {
            *self
                .state
                .read()
                .epoch_by_tenant
                .get(&tenant_id)
                .unwrap_or(&0)
        };
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
        let durable_revoked = self
            .durable_state
            .as_ref()
            .map(|store| store.is_revoked(token))
            .transpose()?
            .unwrap_or(false);
        if durable_revoked
            || state.revoked_tokens.contains(&token.token_id)
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
        if let Some(store) = &self.durable_state {
            return store.consume_call(token);
        }
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
    pub fn revoke_token(&self, tenant_id: &TenantId, token_id: String) -> Result<(), A2aError> {
        if let Some(store) = &self.durable_state {
            store.revoke_token(tenant_id, &token_id)?;
        }
        self.state.write().revoked_tokens.insert(token_id);
        Ok(())
    }
    pub fn revoke_root_task(&self, tenant_id: &TenantId, task_id: TaskId) -> Result<(), A2aError> {
        if let Some(store) = &self.durable_state {
            store.revoke_root_task(tenant_id, &task_id)?;
        }
        self.state.write().revoked_tasks.insert(task_id);
        Ok(())
    }
    pub fn bump_tenant_epoch(&self, tenant: &TenantId) -> Result<u64, A2aError> {
        if let Some(store) = &self.durable_state {
            let epoch = store.bump_tenant_epoch(tenant)?;
            self.state
                .write()
                .epoch_by_tenant
                .insert(tenant.clone(), epoch);
            return Ok(epoch);
        }
        let mut state = self.state.write();
        let epoch = state.epoch_by_tenant.entry(tenant.clone()).or_insert(0);
        *epoch += 1;
        Ok(*epoch)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgUiEventKind {
    PlanUpdated,
    ToolRequested,
    ApprovalRequired,
    ApprovalRecorded,
    ExecutionStatus,
    ArtifactAvailable,
    EvaluationUpdated,
    Incident,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgUiEventEnvelope {
    pub schema_version: String,
    pub event_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub sequence: u64,
    pub kind: AgUiEventKind,
    pub trace_id: String,
    pub safe_payload: Value,
    pub occurred_at: DateTime<Utc>,
    pub backend_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResumeToken {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub after_sequence: u64,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

pub trait AgUiEventStore: Send + Sync {
    /// Atomically reserves a monotonically increasing sequence. Gaps are allowed after crashes;
    /// duplicate or decreasing sequences are forbidden.
    fn reserve_sequence(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        maximum_events: usize,
    ) -> Result<u64, A2aError>;
    fn append(&self, event: &AgUiEventEnvelope) -> Result<(), A2aError>;
    fn after(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        sequence: u64,
        maximum: usize,
    ) -> Result<Vec<AgUiEventEnvelope>, A2aError>;
    fn latest(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
    ) -> Result<Option<AgUiEventEnvelope>, A2aError>;
}

pub struct AgUiStreamAdapter {
    key: SigningKey,
    maximum_events_per_task: usize,
    events: RwLock<BTreeMap<(TenantId, TaskId), Vec<AgUiEventEnvelope>>>,
    durable_events: Option<Arc<dyn AgUiEventStore>>,
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
                durable_events: None,
            })
        }
    }
    pub fn new_production(
        key: SigningKey,
        maximum_events_per_task: usize,
        durable_events: Arc<dyn AgUiEventStore>,
    ) -> Result<Self, A2aError> {
        let mut stream = Self::new(key, maximum_events_per_task)?;
        stream.durable_events = Some(durable_events);
        Ok(stream)
    }
    pub fn publish_backend(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        kind: AgUiEventKind,
        trace_id: String,
        safe_payload: Value,
    ) -> Result<AgUiEventEnvelope, A2aError> {
        if trace_id.is_empty()
            || trace_id.len() > 256
            || !safe_payload_allowed(&safe_payload, 0)
            || serde_jcs::to_vec(&safe_payload)
                .map_err(|_| A2aError::EventInvalid)?
                .len()
                > 64 * 1024
        {
            return Err(A2aError::EventInvalid);
        }
        let mut events = self.events.write();
        let stream = events
            .entry((tenant_id.clone(), task_id.clone()))
            .or_default();
        let sequence = if let Some(store) = &self.durable_events {
            store.reserve_sequence(&tenant_id, &task_id, self.maximum_events_per_task)?
        } else {
            if stream.len() >= self.maximum_events_per_task {
                return Err(A2aError::CapacityExceeded);
            }
            stream.len() as u64 + 1
        };
        let mut event = AgUiEventEnvelope {
            schema_version: A2A_SCHEMA_VERSION.into(),
            event_id: Uuid::new_v4().to_string(),
            tenant_id,
            task_id,
            sequence,
            kind,
            trace_id,
            safe_payload,
            occurred_at: Utc::now(),
            backend_signature: String::new(),
        };
        event.backend_signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&event_bytes(&event)?).to_bytes());
        if let Some(store) = &self.durable_events {
            store.append(&event)?;
        }
        stream.push(event.clone());
        Ok(event)
    }
    pub fn resume_token(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        after_sequence: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<ResumeToken, A2aError> {
        let now = Utc::now();
        if expires_at <= now || expires_at > now + chrono::Duration::hours(24) {
            return Err(A2aError::EventInvalid);
        }
        let mut token = ResumeToken {
            schema_version: A2A_SCHEMA_VERSION.into(),
            tenant_id,
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
        let events = if let Some(store) = &self.durable_events {
            store.after(
                &token.tenant_id,
                &token.task_id,
                token.after_sequence,
                self.maximum_events_per_task,
            )?
        } else {
            self.events
                .read()
                .get(&(token.tenant_id.clone(), token.task_id.clone()))
                .map(|events| {
                    events
                        .iter()
                        .filter(|event| event.sequence > token.after_sequence)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };
        if events.len() > self.maximum_events_per_task {
            return Err(A2aError::CapacityExceeded);
        }
        let mut prior = token.after_sequence;
        for event in &events {
            self.verify_event(event)?;
            if event.tenant_id != token.tenant_id
                || event.task_id != token.task_id
                || event.sequence <= prior
            {
                return Err(A2aError::EventInvalid);
            }
            prior = event.sequence;
        }
        Ok(events)
    }
    pub fn verify_event(&self, event: &AgUiEventEnvelope) -> Result<(), A2aError> {
        if event.schema_version != A2A_SCHEMA_VERSION
            || event.sequence == 0
            || event.event_id.is_empty()
            || Uuid::parse_str(&event.event_id).is_err()
            || event.trace_id.is_empty()
            || event.trace_id.len() > 256
            || !safe_payload_allowed(&event.safe_payload, 0)
            || event.occurred_at > Utc::now() + chrono::Duration::minutes(5)
        {
            return Err(A2aError::EventInvalid);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&event.backend_signature)
                .map_err(|_| A2aError::EventInvalid)?,
        )
        .map_err(|_| A2aError::EventInvalid)?;
        self.key
            .verifying_key()
            .verify(&event_bytes(event)?, &signature)
            .map_err(|_| A2aError::EventInvalid)
    }
    pub fn safe_snapshot(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        status: String,
        evidence_digest: Option<String>,
        token_expires_at: DateTime<Utc>,
    ) -> Result<AgUiSafeSnapshot, A2aError> {
        let now = Utc::now();
        if status.is_empty()
            || status.len() > 64
            || !status
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || evidence_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
            || token_expires_at <= now
            || token_expires_at > now + chrono::Duration::hours(24)
        {
            return Err(A2aError::EventInvalid);
        }
        let latest = if let Some(store) = &self.durable_events {
            store.latest(&tenant_id, &task_id)?
        } else {
            self.events
                .read()
                .get(&(tenant_id.clone(), task_id.clone()))
                .and_then(|events| events.last().cloned())
        };
        if let Some(event) = &latest {
            self.verify_event(event)?;
        }
        let sequence = latest.as_ref().map_or(0, |event| event.sequence);
        let resume = self.resume_token(
            tenant_id.clone(),
            task_id.clone(),
            sequence,
            token_expires_at,
        )?;
        let token_bytes = serde_jcs::to_vec(&resume).map_err(|_| A2aError::EventInvalid)?;
        let mut safe_state = serde_json::json!({"status": status});
        if let Some(digest) = evidence_digest {
            safe_state
                .as_object_mut()
                .ok_or(A2aError::EventInvalid)?
                .insert("evidence_digest".into(), Value::String(digest));
        }
        if let Some(event) = &latest {
            safe_state
                .as_object_mut()
                .ok_or(A2aError::EventInvalid)?
                .insert(
                    "occurred_at".into(),
                    Value::String(event.occurred_at.to_rfc3339()),
                );
        }
        let mut snapshot = AgUiSafeSnapshot {
            schema_version: AGUI_SNAPSHOT_SCHEMA_VERSION.into(),
            tenant_id,
            task_id,
            sequence,
            safe_state,
            next_resume_token: URL_SAFE_NO_PAD.encode(token_bytes),
            generated_at: now,
            backend_signature: String::new(),
        };
        snapshot.backend_signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&snapshot_bytes(&snapshot)?).to_bytes());
        Ok(snapshot)
    }
    pub fn verify_snapshot(&self, snapshot: &AgUiSafeSnapshot) -> Result<(), A2aError> {
        if snapshot.schema_version != AGUI_SNAPSHOT_SCHEMA_VERSION
            || snapshot.generated_at > Utc::now() + chrono::Duration::minutes(5)
            || !safe_snapshot_state(&snapshot.safe_state)
        {
            return Err(A2aError::EventInvalid);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&snapshot.backend_signature)
                .map_err(|_| A2aError::EventInvalid)?,
        )
        .map_err(|_| A2aError::EventInvalid)?;
        self.key
            .verifying_key()
            .verify(&snapshot_bytes(snapshot)?, &signature)
            .map_err(|_| A2aError::EventInvalid)?;
        let token_bytes = URL_SAFE_NO_PAD
            .decode(&snapshot.next_resume_token)
            .map_err(|_| A2aError::EventInvalid)?;
        let token: ResumeToken =
            serde_json::from_slice(&token_bytes).map_err(|_| A2aError::EventInvalid)?;
        let token_signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&token.signature)
                .map_err(|_| A2aError::EventInvalid)?,
        )
        .map_err(|_| A2aError::EventInvalid)?;
        if token.schema_version != A2A_SCHEMA_VERSION
            || token.tenant_id != snapshot.tenant_id
            || token.task_id != snapshot.task_id
            || token.after_sequence != snapshot.sequence
            || token.expires_at <= snapshot.generated_at
        {
            return Err(A2aError::EventInvalid);
        }
        self.key
            .verifying_key()
            .verify(&resume_bytes(&token)?, &token_signature)
            .map_err(|_| A2aError::EventInvalid)
    }
    pub fn accept_ui_event(&self, kind: AgUiEventKind) -> Result<(), A2aError> {
        if kind == AgUiEventKind::ApprovalRecorded {
            Err(A2aError::UiCannotAuthorize)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgUiSafeSnapshot {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub sequence: u64,
    pub safe_state: Value,
    pub next_resume_token: String,
    pub generated_at: DateTime<Utc>,
    pub backend_signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum A2aTaskState {
    Submitted,
    Working,
    InputRequired,
    AuthRequired,
    Verifying,
    Completed,
    Cancelling,
    Cancelled,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct A2aTaskRecord {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub remote_task_id: String,
    pub agent_id: String,
    pub agent_card_hash: String,
    pub agent_endpoint: String,
    pub protocol_version: String,
    pub state: A2aTaskState,
    pub remote_status: String,
    pub evaluation_status: Option<EvaluationStatus>,
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
    pub backend_signature: String,
}

pub trait A2aTaskStore: Send + Sync {
    fn insert(&self, record: &A2aTaskRecord) -> Result<(), A2aError>;
    fn load(&self, tenant_id: &TenantId, task_id: &TaskId) -> Result<A2aTaskRecord, A2aError>;
    fn compare_and_set(
        &self,
        expected_revision: u64,
        record: &A2aTaskRecord,
    ) -> Result<(), A2aError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct A2aJsonRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct A2aJsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct A2aJsonRpcResponse {
    pub jsonrpc: String,
    pub id: String,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<A2aJsonRpcError>,
}

#[async_trait]
pub trait A2aJsonRpcTransport: Send + Sync {
    /// The implementation owns bounded HTTPS, peer authentication, redirect denial and response
    /// size limits. Ambiguous post-send failures must be returned as `RemoteOutcomeUnknown`.
    async fn exchange(
        &self,
        endpoint: &str,
        request: &A2aJsonRpcRequest,
    ) -> Result<A2aJsonRpcResponse, A2aError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteA2aTask {
    pub task_id: String,
    pub status: String,
}

pub struct NativeA2aClient<T: A2aJsonRpcTransport> {
    transport: Arc<T>,
}

impl<T: A2aJsonRpcTransport> NativeA2aClient<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self { transport }
    }

    pub async fn send_message(
        &self,
        card: &AgentCardSnapshot,
        params: Value,
    ) -> Result<RemoteA2aTask, A2aError> {
        if !card.verified
            || !params.is_object()
            || serde_jcs::to_vec(&params)
                .map_err(|_| A2aError::ProtocolInvalid)?
                .len()
                > 1_048_576
        {
            return Err(A2aError::ProtocolInvalid);
        }
        self.exchange_task(
            &card.endpoint,
            wire_method(&card.protocol_version, A2aWireOperation::Send)?,
            params,
        )
        .await
    }

    pub async fn status(
        &self,
        endpoint: &str,
        protocol_version: &str,
        remote_task_id: &str,
    ) -> Result<RemoteA2aTask, A2aError> {
        self.exchange_task(
            endpoint,
            wire_method(protocol_version, A2aWireOperation::Get)?,
            serde_json::json!({"id": remote_task_id}),
        )
        .await
    }

    pub async fn cancel(
        &self,
        endpoint: &str,
        protocol_version: &str,
        remote_task_id: &str,
    ) -> Result<RemoteA2aTask, A2aError> {
        self.exchange_task(
            endpoint,
            wire_method(protocol_version, A2aWireOperation::Cancel)?,
            serde_json::json!({"id": remote_task_id}),
        )
        .await
    }

    async fn exchange_task(
        &self,
        endpoint: &str,
        method: &str,
        params: Value,
    ) -> Result<RemoteA2aTask, A2aError> {
        if !secure_agent_endpoint(endpoint) {
            return Err(A2aError::ProtocolInvalid);
        }
        let request = A2aJsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Uuid::new_v4().to_string(),
            method: method.into(),
            params,
        };
        let response = self.transport.exchange(endpoint, &request).await?;
        if response.jsonrpc != "2.0"
            || response.id != request.id
            || response.result.is_some() == response.error.is_some()
        {
            return Err(A2aError::ProtocolInvalid);
        }
        let result = response.result.ok_or(A2aError::RemoteRejected)?;
        parse_remote_task(&result)
    }
}

#[derive(Clone, Copy)]
enum A2aWireOperation {
    Send,
    Get,
    Cancel,
}

fn wire_method(version: &str, operation: A2aWireOperation) -> Result<&'static str, A2aError> {
    match (version, operation) {
        ("0.3.0", A2aWireOperation::Send) => Ok("message/send"),
        ("0.3.0", A2aWireOperation::Get) => Ok("tasks/get"),
        ("0.3.0", A2aWireOperation::Cancel) => Ok("tasks/cancel"),
        ("1.0", A2aWireOperation::Send) => Ok("SendMessage"),
        ("1.0", A2aWireOperation::Get) => Ok("GetTask"),
        ("1.0", A2aWireOperation::Cancel) => Ok("CancelTask"),
        _ => Err(A2aError::ProtocolInvalid),
    }
}

fn parse_remote_task(value: &Value) -> Result<RemoteA2aTask, A2aError> {
    let task_id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(A2aError::ProtocolInvalid)?;
    let state = value
        .pointer("/status/state")
        .and_then(Value::as_str)
        .ok_or(A2aError::ProtocolInvalid)?;
    let status = normalize_remote_state(state).ok_or(A2aError::ProtocolInvalid)?;
    Ok(RemoteA2aTask {
        task_id: task_id.into(),
        status: status.into(),
    })
}

fn normalize_remote_state(state: &str) -> Option<&'static str> {
    match state {
        "submitted" | "TASK_STATE_SUBMITTED" => Some("submitted"),
        "working" | "TASK_STATE_WORKING" => Some("working"),
        "input-required" | "TASK_STATE_INPUT_REQUIRED" => Some("input-required"),
        "auth-required" | "TASK_STATE_AUTH_REQUIRED" => Some("auth-required"),
        "completed" | "TASK_STATE_COMPLETED" => Some("completed"),
        "canceled" | "cancelled" | "TASK_STATE_CANCELED" => Some("canceled"),
        "rejected" | "TASK_STATE_REJECTED" => Some("rejected"),
        "failed" | "TASK_STATE_FAILED" => Some("failed"),
        _ => None,
    }
}

pub struct A2aTaskAdapter {
    key: SigningKey,
    store: Arc<dyn A2aTaskStore>,
}

impl A2aTaskAdapter {
    pub fn new_production(key: SigningKey, store: Arc<dyn A2aTaskStore>) -> Self {
        Self { key, store }
    }
    pub fn submit(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        remote_task_id: String,
        card: &AgentCardSnapshot,
    ) -> Result<A2aTaskRecord, A2aError> {
        if remote_task_id.is_empty()
            || remote_task_id.len() > 512
            || !card.verified
            || !valid_digest(&card.card_hash)
        {
            return Err(A2aError::TaskInvalid);
        }
        let mut record = A2aTaskRecord {
            schema_version: A2A_SCHEMA_VERSION.into(),
            tenant_id,
            task_id,
            remote_task_id,
            agent_id: card.agent_id.clone(),
            agent_card_hash: card.card_hash.clone(),
            agent_endpoint: card.endpoint.clone(),
            protocol_version: card.protocol_version.clone(),
            state: A2aTaskState::Submitted,
            remote_status: "submitted".into(),
            evaluation_status: None,
            revision: 1,
            updated_at: Utc::now(),
            backend_signature: String::new(),
        };
        self.sign_task(&mut record)?;
        self.store.insert(&record)?;
        Ok(record)
    }
    pub async fn submit_remote<T: A2aJsonRpcTransport>(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        card: &AgentCardSnapshot,
        params: Value,
        client: &NativeA2aClient<T>,
    ) -> Result<A2aTaskRecord, A2aError> {
        let remote = client.send_message(card, params).await?;
        let record = self.submit(tenant_id, task_id, remote.task_id, card)?;
        if remote.status == "submitted" {
            Ok(record)
        } else {
            self.transition(&record.tenant_id, &record.task_id, &remote.status, None)
        }
    }
    pub fn status(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
    ) -> Result<A2aTaskRecord, A2aError> {
        let record = self.store.load(tenant_id, task_id)?;
        self.verify_task(&record)?;
        Ok(record)
    }
    pub fn cancel(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
    ) -> Result<A2aTaskRecord, A2aError> {
        let current = self.status(tenant_id, task_id)?;
        if matches!(
            current.state,
            A2aTaskState::Completed
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
                | A2aTaskState::Cancelling
        ) {
            return Err(A2aError::TaskTransitionInvalid);
        }
        let mut next = current.clone();
        next.state = A2aTaskState::Cancelling;
        next.revision = current
            .revision
            .checked_add(1)
            .ok_or(A2aError::TaskTransitionInvalid)?;
        next.updated_at = monotonic_update_time(current.updated_at.to_owned());
        next.backend_signature.clear();
        self.sign_task(&mut next)?;
        self.store.compare_and_set(current.revision, &next)?;
        Ok(next)
    }
    pub async fn cancel_remote<T: A2aJsonRpcTransport>(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        client: &NativeA2aClient<T>,
    ) -> Result<A2aTaskRecord, A2aError> {
        // Persist CANCELLING before the remote side effect. If the wire outcome is ambiguous, the
        // task remains CANCELLING and operators/pollers reconcile it through tasks/get/GetTask.
        let cancelling = self.cancel(tenant_id, task_id)?;
        let remote = client
            .cancel(
                &cancelling.agent_endpoint,
                &cancelling.protocol_version,
                &cancelling.remote_task_id,
            )
            .await?;
        if remote.task_id != cancelling.remote_task_id {
            return Err(A2aError::ProtocolInvalid);
        }
        self.transition(tenant_id, task_id, &remote.status, None)
    }
    pub async fn refresh_remote<T: A2aJsonRpcTransport>(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        evaluation: Option<EvaluationStatus>,
        client: &NativeA2aClient<T>,
    ) -> Result<A2aTaskRecord, A2aError> {
        let current = self.status(tenant_id, task_id)?;
        let remote = client
            .status(
                &current.agent_endpoint,
                &current.protocol_version,
                &current.remote_task_id,
            )
            .await?;
        if remote.task_id != current.remote_task_id {
            return Err(A2aError::ProtocolInvalid);
        }
        self.transition(tenant_id, task_id, &remote.status, evaluation)
    }
    pub fn record_remote_status(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        remote_status: &str,
        evaluation: Option<EvaluationStatus>,
    ) -> Result<A2aTaskRecord, A2aError> {
        self.transition(tenant_id, task_id, remote_status, evaluation)
    }
    fn transition(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        remote_status: &str,
        evaluation: Option<EvaluationStatus>,
    ) -> Result<A2aTaskRecord, A2aError> {
        let current = self.status(tenant_id, task_id)?;
        if matches!(
            current.state,
            A2aTaskState::Completed
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
        ) || !matches!(
            remote_status,
            "submitted"
                | "working"
                | "input-required"
                | "auth-required"
                | "completed"
                | "canceled"
                | "rejected"
                | "failed"
        ) {
            return Err(A2aError::TaskTransitionInvalid);
        }
        let state = if current.state == A2aTaskState::Cancelling
            && matches!(
                remote_status,
                "submitted" | "working" | "input-required" | "auth-required"
            ) {
            A2aTaskState::Cancelling
        } else {
            match remote_status {
                "submitted" => A2aTaskState::Submitted,
                "working" => A2aTaskState::Working,
                "input-required" => A2aTaskState::InputRequired,
                "auth-required" => A2aTaskState::AuthRequired,
                "completed" if evaluation == Some(EvaluationStatus::Pass) => {
                    A2aTaskState::Completed
                }
                "completed" => A2aTaskState::Verifying,
                "canceled" => A2aTaskState::Cancelled,
                "rejected" => A2aTaskState::Rejected,
                "failed" => A2aTaskState::Failed,
                _ => return Err(A2aError::TaskTransitionInvalid),
            }
        };
        if !valid_task_transition(current.state, state) {
            return Err(A2aError::TaskTransitionInvalid);
        }
        let mut next = current.clone();
        next.state = state;
        next.remote_status = remote_status.into();
        next.evaluation_status = evaluation;
        next.revision = current
            .revision
            .checked_add(1)
            .ok_or(A2aError::TaskTransitionInvalid)?;
        next.updated_at = monotonic_update_time(current.updated_at.to_owned());
        next.backend_signature.clear();
        self.sign_task(&mut next)?;
        self.store.compare_and_set(current.revision, &next)?;
        Ok(next)
    }
    fn sign_task(&self, record: &mut A2aTaskRecord) -> Result<(), A2aError> {
        let bytes = task_bytes(record)?;
        record.backend_signature = URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).to_bytes());
        Ok(())
    }
    fn verify_task(&self, record: &A2aTaskRecord) -> Result<(), A2aError> {
        if record.schema_version != A2A_SCHEMA_VERSION
            || record.revision == 0
            || record.remote_task_id.is_empty()
            || record.remote_task_id.len() > 512
            || record.agent_id.is_empty()
            || record.agent_id.len() > 256
            || !valid_digest(&record.agent_card_hash)
            || !secure_agent_endpoint(&record.agent_endpoint)
            || !matches!(record.protocol_version.as_str(), "0.3.0" | "1.0")
        {
            return Err(A2aError::TaskInvalid);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&record.backend_signature)
                .map_err(|_| A2aError::TaskInvalid)?,
        )
        .map_err(|_| A2aError::TaskInvalid)?;
        self.key
            .verifying_key()
            .verify(&task_bytes(record)?, &signature)
            .map_err(|_| A2aError::TaskInvalid)
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
        "canceled" => TaskStatus::Cancelling,
        "completed" if evaluation == Some(EvaluationStatus::Pass) => TaskStatus::Completed,
        "completed" => TaskStatus::Verifying,
        "input-required" | "auth-required" | "rejected" => TaskStatus::NeedsHuman,
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
fn task_bytes(record: &A2aTaskRecord) -> Result<Vec<u8>, A2aError> {
    let mut copy = record.clone();
    copy.backend_signature.clear();
    serde_jcs::to_vec(&copy).map_err(|_| A2aError::TaskInvalid)
}
fn monotonic_update_time(previous: DateTime<Utc>) -> DateTime<Utc> {
    let now = Utc::now();
    if now > previous {
        now
    } else {
        previous + chrono::Duration::microseconds(1)
    }
}
fn valid_task_transition(from: A2aTaskState, to: A2aTaskState) -> bool {
    match from {
        A2aTaskState::Submitted => matches!(
            to,
            A2aTaskState::Submitted
                | A2aTaskState::Working
                | A2aTaskState::InputRequired
                | A2aTaskState::AuthRequired
                | A2aTaskState::Verifying
                | A2aTaskState::Completed
                | A2aTaskState::Cancelling
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
        ),
        A2aTaskState::Working => matches!(
            to,
            A2aTaskState::Working
                | A2aTaskState::InputRequired
                | A2aTaskState::AuthRequired
                | A2aTaskState::Verifying
                | A2aTaskState::Completed
                | A2aTaskState::Cancelling
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
        ),
        A2aTaskState::InputRequired | A2aTaskState::AuthRequired => matches!(
            to,
            A2aTaskState::Working
                | A2aTaskState::InputRequired
                | A2aTaskState::AuthRequired
                | A2aTaskState::Verifying
                | A2aTaskState::Completed
                | A2aTaskState::Cancelling
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
        ),
        A2aTaskState::Verifying => matches!(
            to,
            A2aTaskState::Verifying
                | A2aTaskState::Completed
                | A2aTaskState::Cancelling
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
        ),
        A2aTaskState::Cancelling => matches!(
            to,
            A2aTaskState::Cancelling
                | A2aTaskState::Verifying
                | A2aTaskState::Completed
                | A2aTaskState::Cancelled
                | A2aTaskState::Rejected
                | A2aTaskState::Failed
        ),
        A2aTaskState::Completed
        | A2aTaskState::Cancelled
        | A2aTaskState::Rejected
        | A2aTaskState::Failed => false,
    }
}
fn snapshot_bytes(snapshot: &AgUiSafeSnapshot) -> Result<Vec<u8>, A2aError> {
    let mut copy = snapshot.clone();
    copy.backend_signature.clear();
    serde_jcs::to_vec(&copy).map_err(|_| A2aError::EventInvalid)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn secure_agent_endpoint(endpoint: &str) -> bool {
    let Ok(url) = Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| {
            !matches!(
                host.to_ascii_lowercase().as_str(),
                "localhost" | "127.0.0.1" | "::1" | "0.0.0.0" | "169.254.169.254"
            )
        })
}
fn safe_payload_allowed(value: &Value, depth: usize) -> bool {
    if depth > 16 || (depth == 0 && !value.is_object()) {
        return false;
    }
    match value {
        Value::Object(map) => map.iter().all(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            key.len() <= 128
                && ![
                    "authorization",
                    "bearer",
                    "credential",
                    "cookie",
                    "password",
                    "private_key",
                    "secret",
                    "api_key",
                    "access_token",
                    "refresh_token",
                    "session_token",
                ]
                .iter()
                .any(|marker| normalized == *marker)
                && safe_payload_allowed(value, depth + 1)
        }),
        Value::Array(values) => {
            values.len() <= 1024
                && values
                    .iter()
                    .all(|value| safe_payload_allowed(value, depth + 1))
        }
        Value::String(value) => value.len() <= 16 * 1024,
        Value::Number(_) | Value::Bool(_) | Value::Null => true,
    }
}
fn safe_snapshot_state(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    if map.is_empty()
        || map
            .keys()
            .any(|key| !matches!(key.as_str(), "status" | "evidence_digest" | "occurred_at"))
    {
        return false;
    }
    let status_ok = map
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| {
            !status.is_empty()
                && status.len() <= 64
                && status
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        });
    let digest_ok = map
        .get("evidence_digest")
        .is_none_or(|value| value.as_str().is_some_and(valid_digest));
    let time_ok = map.get("occurred_at").is_none_or(|value| {
        value
            .as_str()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .is_some()
    });
    status_ok && digest_ok && time_ok
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
    #[error("A2A_PERSISTENCE_UNAVAILABLE")]
    PersistenceUnavailable,
    #[error("A2A_TASK_INVALID")]
    TaskInvalid,
    #[error("A2A_TASK_TRANSITION_INVALID")]
    TaskTransitionInvalid,
    #[error("A2A_PROTOCOL_INVALID")]
    ProtocolInvalid,
    #[error("A2A_REMOTE_REJECTED")]
    RemoteRejected,
    #[error("A2A_REMOTE_OUTCOME_UNKNOWN")]
    RemoteOutcomeUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{LeaseId, ToolId, ToolRef, ToolVersion};

    #[derive(Default)]
    struct TaskStore {
        records: RwLock<BTreeMap<(TenantId, TaskId), A2aTaskRecord>>,
    }
    impl A2aTaskStore for TaskStore {
        fn insert(&self, record: &A2aTaskRecord) -> Result<(), A2aError> {
            let key = (record.tenant_id.clone(), record.task_id.clone());
            if self.records.write().insert(key, record.clone()).is_some() {
                return Err(A2aError::TaskTransitionInvalid);
            }
            Ok(())
        }
        fn load(&self, tenant_id: &TenantId, task_id: &TaskId) -> Result<A2aTaskRecord, A2aError> {
            self.records
                .read()
                .get(&(tenant_id.clone(), task_id.clone()))
                .cloned()
                .ok_or(A2aError::TaskInvalid)
        }
        fn compare_and_set(
            &self,
            expected_revision: u64,
            record: &A2aTaskRecord,
        ) -> Result<(), A2aError> {
            let key = (record.tenant_id.clone(), record.task_id.clone());
            let mut records = self.records.write();
            let current = records.get(&key).ok_or(A2aError::TaskInvalid)?;
            if current.revision != expected_revision {
                return Err(A2aError::TaskTransitionInvalid);
            }
            records.insert(key, record.clone());
            Ok(())
        }
    }

    struct Wire {
        methods: Mutex<Vec<String>>,
        status: String,
    }
    #[async_trait]
    impl A2aJsonRpcTransport for Wire {
        async fn exchange(
            &self,
            _: &str,
            request: &A2aJsonRpcRequest,
        ) -> Result<A2aJsonRpcResponse, A2aError> {
            self.methods.lock().push(request.method.clone());
            Ok(A2aJsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: Some(serde_json::json!({
                    "id": "remote-task",
                    "status": {"state": self.status.clone()}
                })),
                error: None,
            })
        }
    }

    fn verified_card() -> AgentCardSnapshot {
        let publisher = SigningKey::from_bytes(&[54u8; 32]);
        let now = Utc::now();
        let mut card = AgentCardSnapshot {
            schema_version: A2A_SCHEMA_VERSION.into(),
            protocol_version: "1.0".into(),
            agent_id: "remote-agent".into(),
            publisher_id: "publisher".into(),
            endpoint: "https://agent.example/a2a".into(),
            capability_ids: BTreeSet::from(["coding.read".into()]),
            card_hash: String::new(),
            trust_level: "untrusted-card".into(),
            verified: false,
            issued_at: now - chrono::Duration::minutes(1),
            expires_at: now + chrono::Duration::hours(1),
            observed_at: now,
            publisher_key_id: "publisher-key".into(),
            signature: String::new(),
        };
        card.card_hash = hex(Sha256::digest(
            card.card_material()
                .unwrap_or_else(|_| panic!("card material")),
        ));
        card.signature = URL_SAFE_NO_PAD.encode(
            publisher
                .sign(
                    &card
                        .signing_bytes()
                        .unwrap_or_else(|_| panic!("signing bytes")),
                )
                .to_bytes(),
        );
        let verifier = AgentCardVerifier::new_production(
            BTreeSet::from(["publisher".into()]),
            BTreeSet::from(["https://agent.example/a2a".into()]),
            BTreeMap::from([(
                "publisher-key".into(),
                ("publisher".into(), publisher.verifying_key()),
            )]),
        )
        .unwrap_or_else(|_| panic!("verifier"));
        verifier.verify(card).unwrap_or_else(|_| panic!("card"))
    }

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
        limiter
            .revoke_root_task(&token.tenant_id, root_task)
            .unwrap_or_else(|_| panic!("revoke"));
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
        assert!(valid_task_transition(
            A2aTaskState::InputRequired,
            A2aTaskState::Verifying
        ));
        assert!(valid_task_transition(
            A2aTaskState::Working,
            A2aTaskState::Completed
        ));
    }

    #[test]
    fn production_card_signature_and_expiry_are_fail_closed() {
        let card = verified_card();
        assert!(card.verified);
        let publisher = SigningKey::from_bytes(&[54u8; 32]);
        let verifier = AgentCardVerifier::new_production(
            BTreeSet::from(["publisher".into()]),
            BTreeSet::from(["https://agent.example/a2a".into()]),
            BTreeMap::from([(
                "publisher-key".into(),
                ("publisher".into(), publisher.verifying_key()),
            )]),
        )
        .unwrap_or_else(|_| panic!("verifier"));
        let mut tampered = card;
        tampered.capability_ids.insert("admin.write".into());
        assert_eq!(verifier.verify(tampered), Err(A2aError::AgentCardInvalid));
    }

    #[tokio::test]
    async fn native_a2a_status_is_persisted_and_completion_requires_evaluation() {
        let card = verified_card();
        let store = Arc::new(TaskStore::default());
        let adapter = A2aTaskAdapter::new_production(SigningKey::from_bytes(&[55u8; 32]), store);
        let wire = Arc::new(Wire {
            methods: Mutex::new(Vec::new()),
            status: "TASK_STATE_WORKING".into(),
        });
        let client = NativeA2aClient::new(wire.clone());
        let tenant = TenantId::new();
        let task = TaskId::new();
        let submitted = adapter
            .submit_remote(
                tenant.clone(),
                task.clone(),
                &card,
                serde_json::json!({"message":{"role":"user","parts":[{"kind":"text","text":"bounded"}]}}),
                &client,
            )
            .await
            .unwrap_or_else(|_| panic!("submit"));
        assert_eq!(submitted.state, A2aTaskState::Working);
        assert_eq!(
            wire.methods.lock().first().map(String::as_str),
            Some("SendMessage")
        );
        let verifying = adapter
            .record_remote_status(&tenant, &task, "completed", None)
            .unwrap_or_else(|_| panic!("status"));
        assert_eq!(verifying.state, A2aTaskState::Verifying);
        let completed = adapter
            .record_remote_status(&tenant, &task, "completed", Some(EvaluationStatus::Pass))
            .unwrap_or_else(|_| panic!("evaluation"));
        assert_eq!(completed.state, A2aTaskState::Completed);
    }

    #[test]
    fn resume_is_ordered_and_does_not_duplicate() {
        let stream = AgUiStreamAdapter::new(SigningKey::from_bytes(&[53u8; 32]), 10)
            .unwrap_or_else(|_| panic!("stream"));
        let tenant = TenantId::new();
        let task = TaskId::new();
        stream
            .publish_backend(
                tenant.clone(),
                task.clone(),
                AgUiEventKind::PlanUpdated,
                "trace".into(),
                serde_json::json!({"plan":"safe"}),
            )
            .unwrap_or_else(|_| panic!("event"));
        stream
            .publish_backend(
                tenant.clone(),
                task.clone(),
                AgUiEventKind::ExecutionStatus,
                "trace".into(),
                serde_json::json!({"status":"RUNNING"}),
            )
            .unwrap_or_else(|_| panic!("event"));
        let token = stream
            .resume_token(tenant, task, 1, Utc::now() + chrono::Duration::minutes(1))
            .unwrap_or_else(|_| panic!("token"));
        let events = stream
            .resume(&token, Utc::now())
            .unwrap_or_else(|_| panic!("resume"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 2);
    }

    #[test]
    fn safe_snapshot_binds_signed_resume_position() {
        let stream = AgUiStreamAdapter::new(SigningKey::from_bytes(&[56u8; 32]), 10)
            .unwrap_or_else(|_| panic!("stream"));
        let tenant = TenantId::new();
        let task = TaskId::new();
        stream
            .publish_backend(
                tenant.clone(),
                task.clone(),
                AgUiEventKind::ExecutionStatus,
                "trace".into(),
                serde_json::json!({"status":"RUNNING"}),
            )
            .unwrap_or_else(|_| panic!("event"));
        let snapshot = stream
            .safe_snapshot(
                tenant,
                task,
                "RUNNING".into(),
                Some("a".repeat(64)),
                Utc::now() + chrono::Duration::minutes(5),
            )
            .unwrap_or_else(|_| panic!("snapshot"));
        assert!(stream.verify_snapshot(&snapshot).is_ok());
        let mut tampered = snapshot;
        tampered.sequence += 1;
        assert_eq!(
            stream.verify_snapshot(&tampered),
            Err(A2aError::EventInvalid)
        );
    }
}
