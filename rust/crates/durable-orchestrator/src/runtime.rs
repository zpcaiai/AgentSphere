//! Stateless authoritative transitions used by the Temporal activity boundary.
//!
//! Temporal owns durable replay and the current state. This module owns the only
//! accepted state transitions. Caller supplied payloads are never interpreted as
//! authorization, ledger, evaluator, credential, or evidence facts; those facts
//! are resolved through [`TransitionFactResolver`] before this engine runs.

use crate::facts::{FactResolutionError, ProductionFactResolver, TransitionFactResolver};
use agent_trust_contracts::{
    ArtifactRef, CONTRACT_SCHEMA_VERSION, EvaluationResult, EvaluationStatus, ExecutionStatus,
    SchemaVersion, StateTransitionGuard, TaskStatus,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const TRANSITION_REQUEST_SCHEMA_VERSION: &str = "agenttrust.transition-request.v1";
pub const RUNTIME_STATE_SCHEMA_VERSION: &str = "agenttrust.orchestrator-state.v1";
pub const RUNTIME_COMMAND_SCHEMA_VERSION: &str = "agenttrust.orchestrator-command.v1";
const MAX_RUNTIME_EVENTS: usize = 1_024;
const MAX_ROUTINE_COMMANDS: usize = 10_000;
const MAX_PROCESSED_COMMANDS: usize = 10_257;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeCommandType {
    Start,
    Pause,
    Resume,
    Cancel,
    Kill,
    Checkpoint,
    Verify,
    Complete,
    NeedsHuman,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWorkflowCommand {
    pub schema_version: String,
    pub command_id: String,
    pub request_idempotency_key: String,
    pub tenant_id: String,
    pub task_id: String,
    pub command_type: RuntimeCommandType,
    pub expected_state_version: u64,
    pub payload_digest: String,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransitionEvent {
    pub schema_version: String,
    pub event_id: String,
    pub command_id: String,
    pub from: TaskStatus,
    pub to: TaskStatus,
    pub recovery_cursor: u64,
    pub evidence_digest: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeExecutionRecord {
    pub ledger_execution_id: String,
    pub fence_digest: String,
    pub outcome_digest: String,
    pub status: ExecutionStatus,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionMaterializationRef {
    pub schema_version: String,
    pub tenant_id: String,
    pub action_id: String,
    pub payload_hash: String,
    pub store: String,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWorkflowState {
    pub schema_version: String,
    pub tenant_id: String,
    pub task_id: String,
    pub action_id: String,
    pub status: TaskStatus,
    pub recovery_cursor: u64,
    pub terminal: bool,
    pub evidence_refs: BTreeSet<String>,
    pub ingress_digest: String,
    pub action_materialization: ActionMaterializationRef,
    #[serde(default)]
    pub has_side_effects: bool,
    #[serde(default)]
    pub execution: Option<RuntimeExecutionRecord>,
    #[serde(default)]
    pub processed_commands: BTreeSet<String>,
    #[serde(default)]
    pub processed_command_fingerprints: BTreeMap<String, String>,
    #[serde(default)]
    pub processed_idempotency_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub events: Vec<RuntimeTransitionEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransitionRequest {
    pub schema_version: String,
    pub current: RuntimeWorkflowState,
    pub command: RuntimeWorkflowCommand,
}

#[derive(Debug, Clone)]
pub struct ResolvedTransitionFacts {
    pub evidence_refs: BTreeSet<String>,
    pub ledger_status: Option<ExecutionStatus>,
    pub evaluation: Option<EvaluationResult>,
    pub compensation_verified: bool,
    pub credential_revoked: bool,
    pub supervisor_acknowledged: bool,
    pub execution: Option<RuntimeExecutionRecord>,
}

impl ResolvedTransitionFacts {
    pub fn validate(&self) -> Result<(), RuntimeTransitionError> {
        if self.evidence_refs.is_empty()
            || self
                .evidence_refs
                .iter()
                .any(|reference| reference.is_empty() || reference.len() > 2_048)
        {
            return Err(RuntimeTransitionError::FactsInvalid);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct AuthoritativeTransitionEngine<R = ProductionFactResolver> {
    resolver: R,
}

impl<R> AuthoritativeTransitionEngine<R>
where
    R: TransitionFactResolver,
{
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub async fn ready(&self) -> bool {
        self.resolver.ready().await
    }

    pub async fn apply(
        &self,
        request: RuntimeTransitionRequest,
    ) -> Result<RuntimeWorkflowState, RuntimeTransitionError> {
        validate_request(&request)?;
        let fingerprint = runtime_command_fingerprint(&request.command);
        if request
            .current
            .processed_commands
            .contains(&request.command.command_id)
        {
            return match request
                .current
                .processed_command_fingerprints
                .get(&request.command.command_id)
            {
                Some(existing) if existing == &fingerprint => Ok(request.current),
                _ => Err(RuntimeTransitionError::IdempotencyConflict),
            };
        }
        if let Some(existing) = request
            .current
            .processed_idempotency_keys
            .get(&request.command.request_idempotency_key)
        {
            return if existing == &fingerprint {
                Ok(request.current)
            } else {
                Err(RuntimeTransitionError::IdempotencyConflict)
            };
        }
        if request.command.expected_state_version != request.current.recovery_cursor {
            return Err(RuntimeTransitionError::ConcurrentCommand);
        }
        if request.current.terminal {
            return Err(RuntimeTransitionError::TerminalTask);
        }
        preflight_transition(&request.current, &request.command)?;
        let facts = self
            .resolver
            .resolve(&request.current, &request.command)
            .await?;
        apply_resolved_transition(request.current, request.command, facts)
    }
}

pub fn apply_resolved_transition(
    mut current: RuntimeWorkflowState,
    command: RuntimeWorkflowCommand,
    facts: ResolvedTransitionFacts,
) -> Result<RuntimeWorkflowState, RuntimeTransitionError> {
    facts.validate()?;
    let from = current.status;
    let path = transition_path(from, command.command_type)?;
    let mut previous = from;
    for next in path {
        let evaluation = if next == TaskStatus::Completed {
            facts.evaluation.as_ref()
        } else {
            None
        };
        if !StateTransitionGuard::allows(
            previous,
            next,
            evaluation,
            current.has_side_effects,
            facts.compensation_verified,
        ) {
            return Err(RuntimeTransitionError::TransitionDenied);
        }
        previous = next;
    }
    if matches!(
        command.command_type,
        RuntimeCommandType::Start | RuntimeCommandType::Resume
    ) && facts.credential_revoked
    {
        return Err(RuntimeTransitionError::AuthorizationInvalid);
    }
    if command.command_type == RuntimeCommandType::Kill
        && (!facts.credential_revoked || !facts.supervisor_acknowledged)
    {
        return Err(RuntimeTransitionError::ContainmentIncomplete);
    }
    if command.command_type == RuntimeCommandType::Complete {
        let evaluation = facts
            .evaluation
            .as_ref()
            .ok_or(RuntimeTransitionError::CompletionEvidenceMissing)?;
        if evaluation.status != EvaluationStatus::Pass
            || evaluation.hard_gate_results.is_empty()
            || !evaluation.hard_gate_results.values().all(|passed| *passed)
            || (current.has_side_effects && facts.ledger_status != Some(ExecutionStatus::Succeeded))
        {
            return Err(RuntimeTransitionError::CompletionEvidenceMissing);
        }
    }
    if command.command_type == RuntimeCommandType::NeedsHuman
        && !matches!(
            facts.ledger_status,
            Some(
                ExecutionStatus::Failed
                    | ExecutionStatus::TimedOut
                    | ExecutionStatus::Cancelled
                    | ExecutionStatus::Compensated
                    | ExecutionStatus::CompensationFailed
                    | ExecutionStatus::Unknown
            )
        )
    {
        return Err(RuntimeTransitionError::TransitionDenied);
    }
    current.status = previous;
    if facts.execution.is_some() {
        current.execution = facts.execution;
    }
    current.evidence_refs.extend(facts.evidence_refs);
    current.recovery_cursor = current.recovery_cursor.saturating_add(1);
    let fingerprint = runtime_command_fingerprint(&command);
    current
        .processed_commands
        .insert(command.command_id.clone());
    current
        .processed_command_fingerprints
        .insert(command.command_id.clone(), fingerprint.clone());
    current
        .processed_idempotency_keys
        .insert(command.request_idempotency_key.clone(), fingerprint);
    current.terminal = matches!(
        current.status,
        TaskStatus::Completed
            | TaskStatus::Killed
            | TaskStatus::Failed
            | TaskStatus::RolledBack
            | TaskStatus::Denied
    );
    if current.events.len() >= MAX_RUNTIME_EVENTS {
        current.events.remove(0);
    }
    let now = Utc::now();
    current.events.push(RuntimeTransitionEvent {
        schema_version: RUNTIME_STATE_SCHEMA_VERSION.into(),
        event_id: Uuid::new_v4().to_string(),
        command_id: command.command_id.clone(),
        from,
        to: current.status,
        recovery_cursor: current.recovery_cursor,
        evidence_digest: digest_evidence(&current.evidence_refs),
        occurred_at: now,
    });
    Ok(current)
}

fn preflight_transition(
    current: &RuntimeWorkflowState,
    command: &RuntimeWorkflowCommand,
) -> Result<(), RuntimeTransitionError> {
    transition_path(current.status, command.command_type)?;
    let processed = current.processed_commands.len();
    let lifecycle_control = matches!(
        command.command_type,
        RuntimeCommandType::Pause
            | RuntimeCommandType::Resume
            | RuntimeCommandType::Cancel
            | RuntimeCommandType::Verify
            | RuntimeCommandType::Complete
            | RuntimeCommandType::NeedsHuman
    );
    if (command.command_type != RuntimeCommandType::Kill
        && processed >= MAX_PROCESSED_COMMANDS - 1)
        || (!lifecycle_control
            && command.command_type != RuntimeCommandType::Kill
            && processed >= MAX_ROUTINE_COMMANDS)
        || current.processed_commands.len() >= MAX_PROCESSED_COMMANDS
        || current.processed_command_fingerprints.len() >= MAX_PROCESSED_COMMANDS
        || current.processed_idempotency_keys.len() >= MAX_PROCESSED_COMMANDS
    {
        return Err(RuntimeTransitionError::CapacityExceeded);
    }
    Ok(())
}

fn transition_path(
    from: TaskStatus,
    command: RuntimeCommandType,
) -> Result<Vec<TaskStatus>, RuntimeTransitionError> {
    use RuntimeCommandType as Command;
    use TaskStatus as Status;
    match (from, command) {
        (Status::Created, Command::Start) => Ok(vec![
            Status::Planned,
            Status::PolicyChecked,
            Status::Approved,
            Status::Running,
        ]),
        (Status::Paused, Command::Resume) => Ok(vec![Status::Running]),
        (Status::Running, Command::Pause) => Ok(vec![Status::PauseRequested, Status::Paused]),
        (Status::Running, Command::Cancel) => Ok(vec![Status::CancelRequested, Status::Cancelling]),
        (Status::Running | Status::Paused, Command::Kill) => {
            Ok(vec![Status::KillRequested, Status::Killed])
        }
        (Status::Running, Command::Verify) => Ok(vec![Status::Verifying]),
        (Status::Verifying, Command::Complete) => Ok(vec![Status::Completed]),
        (Status::Running | Status::Verifying, Command::NeedsHuman) => Ok(vec![Status::NeedsHuman]),
        (Status::Running | Status::Paused, Command::Checkpoint) => Ok(vec![]),
        _ => Err(RuntimeTransitionError::TransitionDenied),
    }
}

fn validate_request(request: &RuntimeTransitionRequest) -> Result<(), RuntimeTransitionError> {
    let state = &request.current;
    let command = &request.command;
    if request.schema_version != TRANSITION_REQUEST_SCHEMA_VERSION
        || state.schema_version != RUNTIME_STATE_SCHEMA_VERSION
        || command.schema_version != RUNTIME_COMMAND_SCHEMA_VERSION
        || state.tenant_id.is_empty()
        || state.task_id.is_empty()
        || state.action_id.is_empty()
        || state.tenant_id != command.tenant_id
        || state.task_id != command.task_id
        || command.command_id.is_empty()
        || command.command_id.len() > 256
        || command.request_idempotency_key.is_empty()
        || command.request_idempotency_key.len() > 256
        || !is_token(&command.command_id)
        || !is_token(&command.request_idempotency_key)
        || command.requested_by.is_empty()
        || command.requested_by.len() > 512
        || !is_digest(&state.ingress_digest)
        || state.action_materialization.schema_version != "agenttrust.action-materialization-ref.v1"
        || state.action_materialization.tenant_id != state.tenant_id
        || state.action_materialization.action_id != state.action_id
        || !is_digest(&state.action_materialization.payload_hash)
        || state.action_materialization.store != "ORCHESTRATOR_INGRESS_POSTGRESQL"
        || state.action_materialization.uri
            != format!(
                "orchestrator-ingress://{}/{}",
                state.tenant_id, state.action_id
            )
        || !is_digest(&command.payload_digest)
        || command.payload_digest != runtime_command_payload_digest(command.command_type)
        || command.requested_at > Utc::now() + Duration::minutes(5)
        || state.events.len() > MAX_RUNTIME_EVENTS
        || state.processed_commands.len() > MAX_PROCESSED_COMMANDS
        || state.processed_command_fingerprints.len() > MAX_PROCESSED_COMMANDS
        || state.processed_idempotency_keys.len() > MAX_PROCESSED_COMMANDS
        || state.processed_commands.len() != state.processed_command_fingerprints.len()
        || state.execution.as_ref().is_some_and(|execution| {
            execution.ledger_execution_id.is_empty()
                || execution.ledger_execution_id.len() > 256
                || !is_token(&execution.ledger_execution_id)
                || !is_digest(&execution.fence_digest)
                || !is_digest(&execution.outcome_digest)
                || execution.evidence_refs.is_empty()
                || execution.evidence_refs.iter().any(|value| value.is_empty())
        })
        || state.processed_commands.iter().any(|command_id| {
            !state
                .processed_command_fingerprints
                .contains_key(command_id)
        })
    {
        return Err(RuntimeTransitionError::RequestInvalid);
    }
    Ok(())
}

pub fn runtime_command_payload_digest(command_type: RuntimeCommandType) -> String {
    let name = match command_type {
        RuntimeCommandType::Start => "START",
        RuntimeCommandType::Pause => "PAUSE",
        RuntimeCommandType::Resume => "RESUME",
        RuntimeCommandType::Cancel => "CANCEL",
        RuntimeCommandType::Kill => "KILL",
        RuntimeCommandType::Checkpoint => "CHECKPOINT",
        RuntimeCommandType::Verify => "VERIFY",
        RuntimeCommandType::Complete => "COMPLETE",
        RuntimeCommandType::NeedsHuman => "NEEDS_HUMAN",
    };
    format!(
        "{:x}",
        Sha256::digest(format!(r#"{{"command_type":"{name}"}}"#).as_bytes())
    )
}

pub fn runtime_command_fingerprint(command: &RuntimeWorkflowCommand) -> String {
    let canonical = BTreeMap::from([
        ("command_id", command.command_id.clone()),
        (
            "command_type",
            command_type_name(command.command_type).into(),
        ),
        (
            "expected_state_version",
            command.expected_state_version.to_string(),
        ),
        ("payload_digest", command.payload_digest.clone()),
        (
            "request_idempotency_key",
            command.request_idempotency_key.clone(),
        ),
        ("requested_by", command.requested_by.clone()),
        ("schema_version", command.schema_version.clone()),
        ("task_id", command.task_id.clone()),
        ("tenant_id", command.tenant_id.clone()),
    ]);
    let encoded = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("{:x}", Sha256::digest(encoded))
}

fn command_type_name(command_type: RuntimeCommandType) -> &'static str {
    match command_type {
        RuntimeCommandType::Start => "START",
        RuntimeCommandType::Pause => "PAUSE",
        RuntimeCommandType::Resume => "RESUME",
        RuntimeCommandType::Cancel => "CANCEL",
        RuntimeCommandType::Kill => "KILL",
        RuntimeCommandType::Checkpoint => "CHECKPOINT",
        RuntimeCommandType::Verify => "VERIFY",
        RuntimeCommandType::Complete => "COMPLETE",
        RuntimeCommandType::NeedsHuman => "NEEDS_HUMAN",
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_token(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn digest_evidence(values: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

pub fn passed_evaluation(
    evidence_refs: &BTreeSet<String>,
    evaluator_id: String,
    evaluator_version: String,
    score_millionths: u32,
) -> EvaluationResult {
    EvaluationResult {
        schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
        status: EvaluationStatus::Pass,
        score_millionths,
        hard_gate_results: BTreeMap::from([("authoritative-evidence".into(), true)]),
        findings: Vec::new(),
        evidence_refs: evidence_refs.iter().cloned().map(ArtifactRef).collect(),
        evaluator_id,
        evaluator_version,
        evaluated_at: Utc::now(),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeTransitionError {
    #[error("ORCHESTRATOR_TRANSITION_REQUEST_INVALID")]
    RequestInvalid,
    #[error("ORCHESTRATOR_TRANSITION_FACTS_INVALID")]
    FactsInvalid,
    #[error("ORCHESTRATOR_CONCURRENT_COMMAND")]
    ConcurrentCommand,
    #[error("ORCHESTRATOR_COMMAND_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("ORCHESTRATOR_TERMINAL_TASK")]
    TerminalTask,
    #[error("ORCHESTRATOR_TRANSITION_DENIED")]
    TransitionDenied,
    #[error("ORCHESTRATOR_AUTHORIZATION_INVALID")]
    AuthorizationInvalid,
    #[error("ORCHESTRATOR_CONTAINMENT_INCOMPLETE")]
    ContainmentIncomplete,
    #[error("ORCHESTRATOR_COMPLETION_EVIDENCE_MISSING")]
    CompletionEvidenceMissing,
    #[error("ORCHESTRATOR_RUNTIME_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error(transparent)]
    FactResolution(#[from] FactResolutionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct FixedResolver {
        facts: ResolvedTransitionFacts,
    }

    #[derive(Clone)]
    struct CountingResolver(Arc<AtomicUsize>);

    #[async_trait]
    impl TransitionFactResolver for FixedResolver {
        async fn resolve(
            &self,
            _current: &RuntimeWorkflowState,
            _command: &RuntimeWorkflowCommand,
        ) -> Result<ResolvedTransitionFacts, FactResolutionError> {
            Ok(self.facts.clone())
        }

        async fn ready(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl TransitionFactResolver for CountingResolver {
        async fn resolve(
            &self,
            _current: &RuntimeWorkflowState,
            _command: &RuntimeWorkflowCommand,
        ) -> Result<ResolvedTransitionFacts, FactResolutionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(facts())
        }

        async fn ready(&self) -> bool {
            true
        }
    }

    fn state() -> RuntimeWorkflowState {
        RuntimeWorkflowState {
            schema_version: RUNTIME_STATE_SCHEMA_VERSION.into(),
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            task_id: "00000000-0000-4000-8000-000000000002".into(),
            action_id: "00000000-0000-4000-8000-000000000003".into(),
            status: TaskStatus::Created,
            recovery_cursor: 0,
            terminal: false,
            evidence_refs: BTreeSet::new(),
            ingress_digest: "a".repeat(64),
            action_materialization: ActionMaterializationRef {
                schema_version: "agenttrust.action-materialization-ref.v1".into(),
                tenant_id: "00000000-0000-4000-8000-000000000001".into(),
                action_id: "00000000-0000-4000-8000-000000000003".into(),
                payload_hash: "b".repeat(64),
                store: "ORCHESTRATOR_INGRESS_POSTGRESQL".into(),
                uri: "orchestrator-ingress://00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000003".into(),
            },
            has_side_effects: true,
            execution: None,
            processed_commands: BTreeSet::new(),
            processed_command_fingerprints: BTreeMap::new(),
            processed_idempotency_keys: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    fn command(
        state: &RuntimeWorkflowState,
        kind: RuntimeCommandType,
        id: &str,
    ) -> RuntimeWorkflowCommand {
        RuntimeWorkflowCommand {
            schema_version: RUNTIME_COMMAND_SCHEMA_VERSION.into(),
            command_id: id.into(),
            request_idempotency_key: format!("request:{id}"),
            tenant_id: state.tenant_id.clone(),
            task_id: state.task_id.clone(),
            command_type: kind,
            expected_state_version: state.recovery_cursor,
            payload_digest: runtime_command_payload_digest(kind),
            requested_by: "service:test".into(),
            requested_at: Utc::now(),
        }
    }

    fn facts() -> ResolvedTransitionFacts {
        ResolvedTransitionFacts {
            evidence_refs: BTreeSet::from(["evidence:test".into()]),
            ledger_status: Some(ExecutionStatus::Succeeded),
            evaluation: None,
            compensation_verified: false,
            credential_revoked: false,
            supervisor_acknowledged: false,
            execution: None,
        }
    }

    #[tokio::test]
    async fn start_to_evidence_gated_terminal_is_authoritative() {
        let resolver = FixedResolver { facts: facts() };
        let engine = AuthoritativeTransitionEngine::new(resolver.clone());
        let current = state();
        let current = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                command: command(&current, RuntimeCommandType::Start, "start"),
                current,
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        assert_eq!(current.status, TaskStatus::Running);

        let current = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                command: command(&current, RuntimeCommandType::Verify, "verify"),
                current,
            })
            .await
            .unwrap_or_else(|error| panic!("verify: {error}"));
        let mut terminal_facts = facts();
        terminal_facts.evaluation = Some(passed_evaluation(
            &terminal_facts.evidence_refs,
            "test-evaluator".into(),
            "1".into(),
            1_000_000,
        ));
        let terminal_engine = AuthoritativeTransitionEngine::new(FixedResolver {
            facts: terminal_facts,
        });
        let current = terminal_engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                command: command(&current, RuntimeCommandType::Complete, "complete"),
                current,
            })
            .await
            .unwrap_or_else(|error| panic!("complete: {error}"));
        assert_eq!(current.status, TaskStatus::Completed);
        assert!(current.terminal);
        assert_eq!(current.events.len(), 3);
        assert!(!current.evidence_refs.is_empty());
    }

    #[tokio::test]
    async fn kill_without_authoritative_containment_fails_closed() {
        let mut current = state();
        current.status = TaskStatus::Running;
        let engine = AuthoritativeTransitionEngine::new(FixedResolver { facts: facts() });
        let result = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                command: command(&current, RuntimeCommandType::Kill, "kill"),
                current,
            })
            .await;
        assert_eq!(result, Err(RuntimeTransitionError::ContainmentIncomplete));
    }

    #[tokio::test]
    async fn invalid_kill_is_rejected_before_authoritative_side_effects() {
        let current = state();
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = AuthoritativeTransitionEngine::new(CountingResolver(calls.clone()));
        let result = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                command: command(&current, RuntimeCommandType::Kill, "invalid-kill"),
                current,
            })
            .await;
        assert_eq!(result, Err(RuntimeTransitionError::TransitionDenied));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn compensated_execution_requires_authoritative_needs_human_transition() {
        let mut current = state();
        current.status = TaskStatus::Running;
        let needs_human = command(
            &current,
            RuntimeCommandType::NeedsHuman,
            "compensated-needs-human",
        );
        let mut resolved = facts();
        resolved.ledger_status = Some(ExecutionStatus::Compensated);
        resolved.execution = Some(RuntimeExecutionRecord {
            ledger_execution_id: "execution:compensated".into(),
            fence_digest: "c".repeat(64),
            outcome_digest: "d".repeat(64),
            status: ExecutionStatus::Compensated,
            evidence_refs: BTreeSet::from(["evidence:compensated".into()]),
        });
        let transitioned = apply_resolved_transition(current, needs_human, resolved)
            .unwrap_or_else(|error| panic!("needs human: {error}"));
        assert_eq!(transitioned.status, TaskStatus::NeedsHuman);
        assert_eq!(
            transitioned.execution.map(|value| value.status),
            Some(ExecutionStatus::Compensated)
        );
    }

    #[tokio::test]
    async fn stale_and_duplicate_commands_are_deterministic() {
        let engine = AuthoritativeTransitionEngine::new(FixedResolver { facts: facts() });
        let current = state();
        let start = command(&current, RuntimeCommandType::Start, "same-command");
        let transitioned = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                current,
                command: start,
            })
            .await
            .unwrap_or_else(|error| panic!("start: {error}"));
        let duplicate = command(
            &transitioned,
            RuntimeCommandType::Checkpoint,
            "same-command",
        );
        let replay = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                current: transitioned.clone(),
                command: duplicate,
            })
            .await;
        assert_eq!(replay, Err(RuntimeTransitionError::IdempotencyConflict));

        let exact = command(&state(), RuntimeCommandType::Start, "same-command");
        let replay = engine
            .apply(RuntimeTransitionRequest {
                schema_version: TRANSITION_REQUEST_SCHEMA_VERSION.into(),
                current: transitioned.clone(),
                command: exact,
            })
            .await
            .unwrap_or_else(|error| panic!("exact duplicate: {error}"));
        assert_eq!(replay, transitioned);
    }
}
