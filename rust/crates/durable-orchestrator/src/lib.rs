//! Authoritative durable Task/Step state machine and continuous authorization checkpoints.

pub mod facts;
pub mod runtime;

use agent_trust_contracts::{
    AuthorizationLease, EvaluationResult, ExecutionId, PlanManifest, SignedGoal, TaskId,
    TaskStatus, TenantId,
};
#[cfg(test)]
use agent_trust_contracts::{ExecutionStatus, StateTransitionGuard};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
#[cfg(test)]
use uuid::Uuid;

pub const ORCHESTRATOR_SCHEMA_VERSION: &str = "agenttrust.orchestrator.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepRuntimeRecord {
    pub schema_version: String,
    pub step_id: String,
    pub status: TaskStatus,
    pub stable_idempotency_key: String,
    pub ledger_execution_id: Option<ExecutionId>,
    pub attempt: u32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskRuntimeRecord {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub status: TaskStatus,
    pub goal_hash: String,
    pub plan_hash: String,
    pub policy_snapshot: Option<String>,
    pub authorization_lease: Option<AuthorizationLease>,
    pub authorization_epoch: u64,
    pub steps: BTreeMap<String, StepRuntimeRecord>,
    pub has_side_effects: bool,
    pub evidence_refs: BTreeSet<String>,
    pub processed_commands: BTreeSet<String>,
    pub last_evaluation: Option<EvaluationResult>,
    pub recovery_cursor: u64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowCommandKind {
    Plan { plan_hash: String },
    PolicyCheck { policy_snapshot: String },
    WaitForApproval,
    Approve { approval_id: String },
    Start,
    Pause,
    Resume,
    Cancel,
    BeginCancelling,
    Kill,
    ConfirmKilled,
    Verify,
    Complete,
    Fail,
    BeginCompensation,
    ConfirmRolledBack,
    NeedsHuman { reason_code: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowCommand {
    pub schema_version: String,
    pub command_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub expected_recovery_cursor: u64,
    pub kind: WorkflowCommandKind,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
}

#[cfg(test)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct WorkflowFacts {
    pub schema_version: String,
    pub ledger_status: Option<ExecutionStatus>,
    pub evaluation: Option<EvaluationResult>,
    pub compensation_verified: bool,
    pub evidence_refs: BTreeSet<String>,
    pub credential_revoked: bool,
    pub supervisor_acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCheckpoint {
    pub schema_version: String,
    pub task_id: TaskId,
    pub checkpoint: String,
    pub goal_hash: String,
    pub plan_hash: String,
    pub policy_snapshot: String,
    pub lease_id: String,
    pub risk_signal_digest: String,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowEvent {
    pub schema_version: String,
    pub event_id: String,
    pub task_id: TaskId,
    pub command_id: String,
    pub from: TaskStatus,
    pub to: TaskStatus,
    pub recovery_cursor: u64,
    pub evidence_digest: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrchestratorSnapshot {
    schema_version: String,
    tasks: Vec<TaskRuntimeRecord>,
    events: Vec<WorkflowEvent>,
}

pub struct TaskTransitionService {
    maximum_tasks: usize,
    maximum_events: usize,
    tasks: Mutex<BTreeMap<(TenantId, TaskId), TaskRuntimeRecord>>,
    events: Mutex<Vec<WorkflowEvent>>,
}

impl TaskTransitionService {
    pub fn new(maximum_tasks: usize, maximum_events: usize) -> Result<Self, OrchestratorError> {
        if maximum_tasks == 0 || maximum_events == 0 {
            return Err(OrchestratorError::ConfigurationInvalid);
        }
        Ok(Self {
            maximum_tasks,
            maximum_events,
            tasks: Mutex::new(BTreeMap::new()),
            events: Mutex::new(Vec::new()),
        })
    }

    pub fn create(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        goal: &SignedGoal,
        plan: &PlanManifest,
    ) -> Result<TaskRuntimeRecord, OrchestratorError> {
        if goal.goal_hash != plan.goal_hash
            || goal.goal_hash.len() != 64
            || plan.plan_hash.len() != 64
            || plan.valid_until <= Utc::now()
        {
            return Err(OrchestratorError::IntentInvalid);
        }
        let mut tasks = self.tasks.lock();
        if tasks.len() >= self.maximum_tasks {
            return Err(OrchestratorError::CapacityExceeded);
        }
        let key = (tenant_id.clone(), task_id.clone());
        if let Some(existing) = tasks.get(&key) {
            if existing.goal_hash == goal.goal_hash && existing.plan_hash == plan.plan_hash {
                return Ok(existing.clone());
            }
            return Err(OrchestratorError::IdempotencyConflict);
        }
        let now = Utc::now();
        let steps = plan
            .steps
            .iter()
            .map(|step| {
                let id = step.step_id.0.clone();
                (
                    id.clone(),
                    StepRuntimeRecord {
                        schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
                        step_id: id.clone(),
                        status: TaskStatus::Created,
                        stable_idempotency_key: format!("{}:{id}", task_id.0),
                        ledger_execution_id: None,
                        attempt: 0,
                        updated_at: now,
                    },
                )
            })
            .collect();
        let record = TaskRuntimeRecord {
            schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
            tenant_id,
            task_id,
            status: TaskStatus::Created,
            goal_hash: goal.goal_hash.clone(),
            plan_hash: plan.plan_hash.clone(),
            policy_snapshot: None,
            authorization_lease: None,
            authorization_epoch: 0,
            steps,
            has_side_effects: false,
            evidence_refs: BTreeSet::new(),
            processed_commands: BTreeSet::new(),
            last_evaluation: None,
            recovery_cursor: 0,
            updated_at: now,
        };
        tasks.insert(key, record.clone());
        Ok(record)
    }

    pub fn attach_lease(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        lease: AuthorizationLease,
    ) -> Result<(), OrchestratorError> {
        let mut tasks = self.tasks.lock();
        let record = tasks
            .get_mut(&(tenant.clone(), task.clone()))
            .ok_or(OrchestratorError::NotFound)?;
        if lease.task_id != *task
            || lease.goal_hash != record.goal_hash
            || lease.plan_hash != record.plan_hash
            || lease.valid_until <= Utc::now()
            || lease.revocation_epoch < record.authorization_epoch
        {
            return Err(OrchestratorError::AuthorizationInvalid);
        }
        record.policy_snapshot = Some(lease.policy_snapshot.clone());
        record.authorization_epoch = lease.revocation_epoch;
        record.authorization_lease = Some(lease);
        Ok(())
    }

    pub fn checkpoint(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        checkpoint: &str,
        risk_signal_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthorizationCheckpoint, OrchestratorError> {
        let tasks = self.tasks.lock();
        let record = tasks
            .get(&(tenant.clone(), task.clone()))
            .ok_or(OrchestratorError::NotFound)?;
        let lease = record
            .authorization_lease
            .as_ref()
            .ok_or(OrchestratorError::AuthorizationInvalid)?;
        if checkpoint.is_empty()
            || risk_signal_digest.len() != 64
            || now >= lease.valid_until
            || lease.revocation_epoch < record.authorization_epoch
            || lease.goal_hash != record.goal_hash
            || lease.plan_hash != record.plan_hash
        {
            return Err(OrchestratorError::AuthorizationInvalid);
        }
        Ok(AuthorizationCheckpoint {
            schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
            task_id: task.clone(),
            checkpoint: checkpoint.into(),
            goal_hash: record.goal_hash.clone(),
            plan_hash: record.plan_hash.clone(),
            policy_snapshot: lease.policy_snapshot.clone(),
            lease_id: lease.lease_id.0.clone(),
            risk_signal_digest: risk_signal_digest.into(),
            checked_at: now,
        })
    }

    pub fn revoke_lease(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        new_epoch: u64,
    ) -> Result<(), OrchestratorError> {
        let mut tasks = self.tasks.lock();
        let record = tasks
            .get_mut(&(tenant.clone(), task.clone()))
            .ok_or(OrchestratorError::NotFound)?;
        if new_epoch <= record.authorization_epoch {
            return Err(OrchestratorError::AuthorizationInvalid);
        }
        record.authorization_epoch = new_epoch;
        record.authorization_lease = None;
        Ok(())
    }

    #[cfg(test)]
    fn request_transition(
        &self,
        command: WorkflowCommand,
        facts: WorkflowFacts,
    ) -> Result<TaskRuntimeRecord, OrchestratorError> {
        validate_command(&command, &facts)?;
        let mut tasks = self.tasks.lock();
        let record = tasks
            .get_mut(&(command.tenant_id.clone(), command.task_id.clone()))
            .ok_or(OrchestratorError::NotFound)?;
        if record.processed_commands.contains(&command.command_id) {
            return Ok(record.clone());
        }
        if command.expected_recovery_cursor != record.recovery_cursor {
            return Err(OrchestratorError::ConcurrentCommand);
        }
        let mut events = self.events.lock();
        if events.len() >= self.maximum_events {
            return Err(OrchestratorError::CapacityExceeded);
        }
        let to = target_status(&command.kind);
        if requires_authorization(to) {
            let lease = record
                .authorization_lease
                .as_ref()
                .ok_or(OrchestratorError::AuthorizationInvalid)?;
            if Utc::now() >= lease.valid_until
                || lease.revocation_epoch < record.authorization_epoch
                || lease.plan_hash != record.plan_hash
            {
                return Err(OrchestratorError::AuthorizationInvalid);
            }
        }
        if to == TaskStatus::Completed
            && (facts.evidence_refs.is_empty()
                || record.has_side_effects
                    && facts.ledger_status != Some(ExecutionStatus::Succeeded))
        {
            return Err(OrchestratorError::CompletionEvidenceMissing);
        }
        if to == TaskStatus::Killed && (!facts.credential_revoked || !facts.supervisor_acknowledged)
        {
            return Err(OrchestratorError::ContainmentIncomplete);
        }
        if !StateTransitionGuard::allows(
            record.status,
            to,
            facts.evaluation.as_ref(),
            record.has_side_effects,
            facts.compensation_verified,
        ) {
            return Err(OrchestratorError::TransitionDenied);
        }
        let from = record.status;
        if let WorkflowCommandKind::Plan { plan_hash } = &command.kind
            && plan_hash != &record.plan_hash
        {
            record.plan_hash = plan_hash.clone();
            record.authorization_lease = None;
            record.authorization_epoch = record.authorization_epoch.saturating_add(1);
        }
        if let WorkflowCommandKind::PolicyCheck { policy_snapshot } = &command.kind {
            if policy_snapshot.is_empty() {
                return Err(OrchestratorError::AuthorizationInvalid);
            }
            record.policy_snapshot = Some(policy_snapshot.clone());
        }
        record.status = to;
        record.evidence_refs.extend(facts.evidence_refs.clone());
        record.last_evaluation = facts.evaluation;
        record.processed_commands.insert(command.command_id.clone());
        record.recovery_cursor = record.recovery_cursor.saturating_add(1);
        record.updated_at = Utc::now();
        let evidence_digest = digest_strings(&record.evidence_refs);
        let event = WorkflowEvent {
            schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
            event_id: Uuid::new_v4().to_string(),
            task_id: record.task_id.clone(),
            command_id: command.command_id,
            from,
            to,
            recovery_cursor: record.recovery_cursor,
            evidence_digest,
            occurred_at: record.updated_at,
        };
        let result = record.clone();
        events.push(event);
        Ok(result)
    }

    pub fn bind_execution(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        step_id: &str,
        execution_id: ExecutionId,
        has_side_effects: bool,
    ) -> Result<(), OrchestratorError> {
        let mut tasks = self.tasks.lock();
        let record = tasks
            .get_mut(&(tenant.clone(), task.clone()))
            .ok_or(OrchestratorError::NotFound)?;
        let step = record
            .steps
            .get_mut(step_id)
            .ok_or(OrchestratorError::NotFound)?;
        if let Some(existing) = &step.ledger_execution_id {
            if existing == &execution_id {
                return Ok(());
            }
            return Err(OrchestratorError::IdempotencyConflict);
        }
        step.ledger_execution_id = Some(execution_id);
        step.attempt = step.attempt.saturating_add(1);
        step.updated_at = Utc::now();
        record.has_side_effects |= has_side_effects;
        Ok(())
    }

    pub fn get(
        &self,
        tenant: &TenantId,
        task: &TaskId,
    ) -> Result<TaskRuntimeRecord, OrchestratorError> {
        self.tasks
            .lock()
            .get(&(tenant.clone(), task.clone()))
            .cloned()
            .ok_or(OrchestratorError::NotFound)
    }

    pub fn events_for(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        after_recovery_cursor: u64,
        limit: usize,
    ) -> Result<Vec<WorkflowEvent>, OrchestratorError> {
        if limit == 0 || limit > self.maximum_events {
            return Err(OrchestratorError::ConfigurationInvalid);
        }
        if !self
            .tasks
            .lock()
            .contains_key(&(tenant.clone(), task.clone()))
        {
            return Err(OrchestratorError::NotFound);
        }
        Ok(self
            .events
            .lock()
            .iter()
            .filter(|event| event.task_id == *task && event.recovery_cursor > after_recovery_cursor)
            .take(limit)
            .cloned()
            .collect())
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, OrchestratorError> {
        serde_json::to_vec(&OrchestratorSnapshot {
            schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
            tasks: self.tasks.lock().values().cloned().collect(),
            events: self.events.lock().clone(),
        })
        .map_err(|_| OrchestratorError::PersistenceFailed)
    }

    pub fn restore(
        bytes: &[u8],
        maximum_tasks: usize,
        maximum_events: usize,
    ) -> Result<Self, OrchestratorError> {
        let snapshot: OrchestratorSnapshot =
            serde_json::from_slice(bytes).map_err(|_| OrchestratorError::PersistenceFailed)?;
        if snapshot.schema_version != ORCHESTRATOR_SCHEMA_VERSION
            || snapshot.tasks.len() > maximum_tasks
            || snapshot.events.len() > maximum_events
        {
            return Err(OrchestratorError::PersistenceFailed);
        }
        let tasks = snapshot
            .tasks
            .into_iter()
            .map(|record| ((record.tenant_id.clone(), record.task_id.clone()), record))
            .collect();
        Ok(Self {
            maximum_tasks,
            maximum_events,
            tasks: Mutex::new(tasks),
            events: Mutex::new(snapshot.events),
        })
    }
}

#[cfg(test)]
fn validate_command(
    command: &WorkflowCommand,
    facts: &WorkflowFacts,
) -> Result<(), OrchestratorError> {
    if command.schema_version != ORCHESTRATOR_SCHEMA_VERSION
        || facts.schema_version != ORCHESTRATOR_SCHEMA_VERSION
        || command.command_id.is_empty()
        || command.requested_by.is_empty()
    {
        Err(OrchestratorError::CommandInvalid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn target_status(kind: &WorkflowCommandKind) -> TaskStatus {
    match kind {
        WorkflowCommandKind::Plan { .. } => TaskStatus::Planned,
        WorkflowCommandKind::PolicyCheck { .. } => TaskStatus::PolicyChecked,
        WorkflowCommandKind::WaitForApproval => TaskStatus::ApprovalPending,
        WorkflowCommandKind::Approve { .. } => TaskStatus::Approved,
        WorkflowCommandKind::Start | WorkflowCommandKind::Resume => TaskStatus::Running,
        WorkflowCommandKind::Pause => TaskStatus::PauseRequested,
        WorkflowCommandKind::Cancel => TaskStatus::CancelRequested,
        WorkflowCommandKind::BeginCancelling => TaskStatus::Cancelling,
        WorkflowCommandKind::Kill => TaskStatus::KillRequested,
        WorkflowCommandKind::ConfirmKilled => TaskStatus::Killed,
        WorkflowCommandKind::Verify => TaskStatus::Verifying,
        WorkflowCommandKind::Complete => TaskStatus::Completed,
        WorkflowCommandKind::Fail => TaskStatus::Failed,
        WorkflowCommandKind::BeginCompensation => TaskStatus::Compensating,
        WorkflowCommandKind::ConfirmRolledBack => TaskStatus::RolledBack,
        WorkflowCommandKind::NeedsHuman { .. } => TaskStatus::NeedsHuman,
    }
}

#[cfg(test)]
fn requires_authorization(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Approved | TaskStatus::Running | TaskStatus::Verifying
    )
}

#[cfg(test)]
fn digest_strings(values: &BTreeSet<String>) -> String {
    let joined = values.iter().cloned().collect::<Vec<_>>().join("\n");
    Sha256::digest(joined.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    #[error("ORCHESTRATOR_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("ORCHESTRATOR_INTENT_INVALID")]
    IntentInvalid,
    #[error("ORCHESTRATOR_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("ORCHESTRATOR_NOT_FOUND")]
    NotFound,
    #[error("ORCHESTRATOR_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("ORCHESTRATOR_AUTHORIZATION_INVALID")]
    AuthorizationInvalid,
    #[error("ORCHESTRATOR_COMMAND_INVALID")]
    CommandInvalid,
    #[error("ORCHESTRATOR_CONCURRENT_COMMAND")]
    ConcurrentCommand,
    #[error("ORCHESTRATOR_TRANSITION_DENIED")]
    TransitionDenied,
    #[error("ORCHESTRATOR_COMPLETION_EVIDENCE_MISSING")]
    CompletionEvidenceMissing,
    #[error("ORCHESTRATOR_CONTAINMENT_INCOMPLETE")]
    ContainmentIncomplete,
    #[error("ORCHESTRATOR_PERSISTENCE_FAILED")]
    PersistenceFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{
        ArtifactRef, CONTRACT_SCHEMA_VERSION, EvaluationStatus, GoalId, LeaseId, PlanId,
        PolicyVersion, RiskLevel, SchemaVersion,
    };
    use chrono::Duration;

    fn intent() -> (TenantId, TaskId, SignedGoal, PlanManifest) {
        let goal_hash = "a".repeat(64);
        let plan_hash = "b".repeat(64);
        (
            TenantId::new(),
            TaskId::new(),
            SignedGoal {
                schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
                goal_id: GoalId::new(),
                normalized_goal: "test goal".into(),
                goal_hash: goal_hash.clone(),
                constraints: BTreeMap::new(),
                approved_by: "user:1".into(),
                signed_at: Utc::now(),
                signer_key_id: "k1".into(),
                signature: "signed".into(),
            },
            PlanManifest {
                schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
                plan_id: PlanId::new(),
                goal_hash,
                plan_hash,
                steps: vec![],
                max_scope: vec!["repo://demo".into()],
                risk_budget: RiskLevel::Low,
                cost_budget_microunits: 100,
                valid_until: Utc::now() + Duration::hours(1),
            },
        )
    }

    fn lease(task: &TaskId, goal: &SignedGoal, plan: &PlanManifest) -> AuthorizationLease {
        AuthorizationLease {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            lease_id: LeaseId::new(),
            task_id: task.clone(),
            goal_hash: goal.goal_hash.clone(),
            plan_hash: plan.plan_hash.clone(),
            policy_snapshot: PolicyVersion("policy:v1".into()).0,
            allowed_tools: BTreeSet::new(),
            allowed_resources: BTreeSet::new(),
            revocation_epoch: 1,
            valid_until: Utc::now() + Duration::hours(1),
        }
    }

    fn facts() -> WorkflowFacts {
        WorkflowFacts {
            schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
            ledger_status: None,
            evaluation: None,
            compensation_verified: false,
            evidence_refs: BTreeSet::new(),
            credential_revoked: false,
            supervisor_acknowledged: false,
        }
    }

    fn command(
        tenant: &TenantId,
        task: &TaskId,
        cursor: u64,
        id: &str,
        kind: WorkflowCommandKind,
    ) -> WorkflowCommand {
        WorkflowCommand {
            schema_version: ORCHESTRATOR_SCHEMA_VERSION.into(),
            command_id: id.into(),
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            expected_recovery_cursor: cursor,
            kind,
            requested_by: "user:1".into(),
            requested_at: Utc::now(),
        }
    }

    #[test]
    fn concurrent_commands_and_restart_are_deterministic() {
        let service =
            TaskTransitionService::new(10, 100).unwrap_or_else(|error| panic!("new: {error}"));
        let (tenant, task, goal, plan) = intent();
        service
            .create(tenant.clone(), task.clone(), &goal, &plan)
            .unwrap_or_else(|error| panic!("create: {error}"));
        let first = service
            .request_transition(
                command(
                    &tenant,
                    &task,
                    0,
                    "plan",
                    WorkflowCommandKind::Plan {
                        plan_hash: plan.plan_hash.clone(),
                    },
                ),
                facts(),
            )
            .unwrap_or_else(|error| panic!("plan: {error}"));
        assert_eq!(first.status, TaskStatus::Planned);
        assert_eq!(
            service.request_transition(
                command(
                    &tenant,
                    &task,
                    0,
                    "stale",
                    WorkflowCommandKind::PolicyCheck {
                        policy_snapshot: "p1".into()
                    }
                ),
                facts()
            ),
            Err(OrchestratorError::ConcurrentCommand)
        );
        let bytes = service
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let recovered = TaskTransitionService::restore(&bytes, 10, 100)
            .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(
            recovered
                .get(&tenant, &task)
                .unwrap_or_else(|error| panic!("get: {error}"))
                .recovery_cursor,
            1
        );
    }

    #[test]
    fn completion_requires_evaluator_hard_gates_and_evidence() {
        let service =
            TaskTransitionService::new(10, 100).unwrap_or_else(|error| panic!("new: {error}"));
        let (tenant, task, goal, plan) = intent();
        service
            .create(tenant.clone(), task.clone(), &goal, &plan)
            .unwrap_or_else(|error| panic!("create: {error}"));
        service
            .attach_lease(&tenant, &task, lease(&task, &goal, &plan))
            .unwrap_or_else(|error| panic!("lease: {error}"));
        let sequence = [
            WorkflowCommandKind::Plan {
                plan_hash: plan.plan_hash.clone(),
            },
            WorkflowCommandKind::PolicyCheck {
                policy_snapshot: "policy:v1".into(),
            },
            WorkflowCommandKind::Approve {
                approval_id: "a1".into(),
            },
            WorkflowCommandKind::Start,
            WorkflowCommandKind::Verify,
        ];
        for (index, kind) in sequence.into_iter().enumerate() {
            service
                .request_transition(
                    command(&tenant, &task, index as u64, &format!("c{index}"), kind),
                    facts(),
                )
                .unwrap_or_else(|error| panic!("transition: {error}"));
        }
        let evaluation = EvaluationResult {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            status: EvaluationStatus::Pass,
            score_millionths: 1_000_000,
            hard_gate_results: BTreeMap::from([("evidence".into(), true)]),
            findings: vec![],
            evidence_refs: vec![ArtifactRef("artifact:1".into())],
            evaluator_id: "domain".into(),
            evaluator_version: "1.0.0".into(),
            evaluated_at: Utc::now(),
        };
        let mut complete_facts = facts();
        complete_facts.evaluation = Some(evaluation);
        assert_eq!(
            service.request_transition(
                command(&tenant, &task, 5, "complete", WorkflowCommandKind::Complete),
                complete_facts.clone()
            ),
            Err(OrchestratorError::CompletionEvidenceMissing)
        );
        complete_facts.evidence_refs.insert("artifact:1".into());
        let complete = service
            .request_transition(
                command(&tenant, &task, 5, "complete", WorkflowCommandKind::Complete),
                complete_facts,
            )
            .unwrap_or_else(|error| panic!("complete: {error}"));
        assert_eq!(complete.status, TaskStatus::Completed);
    }

    #[test]
    fn revoked_lease_cannot_resume() {
        let service =
            TaskTransitionService::new(10, 100).unwrap_or_else(|error| panic!("new: {error}"));
        let (tenant, task, goal, plan) = intent();
        service
            .create(tenant.clone(), task.clone(), &goal, &plan)
            .unwrap_or_else(|error| panic!("create: {error}"));
        service
            .attach_lease(&tenant, &task, lease(&task, &goal, &plan))
            .unwrap_or_else(|error| panic!("lease: {error}"));
        service
            .revoke_lease(&tenant, &task, 2)
            .unwrap_or_else(|error| panic!("revoke: {error}"));
        assert_eq!(
            service.checkpoint(&tenant, &task, "PRE_EXECUTION", &"c".repeat(64), Utc::now()),
            Err(OrchestratorError::AuthorizationInvalid)
        );
    }
}
