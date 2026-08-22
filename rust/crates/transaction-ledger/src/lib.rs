//! Durable idempotency reservations, fencing, compensation, outbox, and unknown-outcome recovery.

use agent_trust_contracts::{
    ActionHash, EffectClass, ExecutionId, ExecutionStatus, IdempotencyKey, ResourceVersion, StepId,
    TaskId, TenantId, ToolRef,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use thiserror::Error;
use uuid::Uuid;

pub const LEDGER_SCHEMA_VERSION: &str = "agenttrust.ledger.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIntent {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub action_hash: ActionHash,
    pub idempotency_key: IdempotencyKey,
    pub tool: ToolRef,
    pub effect_class: EffectClass,
    pub resource_version: Option<ResourceVersion>,
    pub canonical_arguments_hash: String,
    pub compensation_plan: Option<CompensationPlan>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionFence {
    pub tenant_id: TenantId,
    pub execution_id: ExecutionId,
    pub token: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Reservation {
    pub execution_id: ExecutionId,
    pub fence: ExecutionFence,
    pub existing: bool,
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionRecord {
    pub intent: ExecutionIntent,
    pub execution_id: ExecutionId,
    pub fence_token: u64,
    pub status: ExecutionStatus,
    pub attempt: u32,
    pub external_operation_id: Option<String>,
    pub result_ref: Option<String>,
    pub evidence_ref: Option<String>,
    pub last_error_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub manual_recovery: Option<ManualRecoveryCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboxEvent {
    pub event_id: String,
    pub execution_id: ExecutionId,
    pub event_type: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

/// Immutable digest-bound locator for a persisted ledger transition event. This is the fact
/// passed across the Tool Proxy boundary; it never substitutes for signed execution evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerEventFact {
    pub event_id: String,
    pub event_ref: String,
    pub event_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManualRecoveryCase {
    pub case_id: String,
    pub impact_scope: String,
    pub last_known_state: String,
    pub recommended_actions: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub opened_at: DateTime<Utc>,
}

#[async_trait]
pub trait ExecutionLedger: Send + Sync {
    async fn ready(&self) -> bool;
    async fn reserve(&self, intent: ExecutionIntent) -> Result<Reservation, LedgerError>;
    async fn mark_started(
        &self,
        fence: &ExecutionFence,
        external_operation_id: Option<String>,
    ) -> Result<(), LedgerError>;
    async fn mark_succeeded(
        &self,
        fence: &ExecutionFence,
        result_ref: String,
        evidence_ref: String,
    ) -> Result<(), LedgerError>;
    async fn mark_failed(
        &self,
        fence: &ExecutionFence,
        error_code: String,
    ) -> Result<(), LedgerError>;
    async fn mark_unknown(
        &self,
        fence: &ExecutionFence,
        error_code: String,
    ) -> Result<(), LedgerError>;
    async fn mark_manual_recovery(
        &self,
        fence: &ExecutionFence,
        case: ManualRecoveryCase,
    ) -> Result<(), LedgerError>;
    async fn get(
        &self,
        tenant_id: &TenantId,
        execution_id: &ExecutionId,
    ) -> Result<ExecutionRecord, LedgerError>;
    /// Durable locator for the latest ledger outbox event that represents this record.
    /// Callers use this as a ledger fact reference; it is not a substitute for signed
    /// execution evidence.
    async fn status_event_ref(
        &self,
        tenant_id: &TenantId,
        execution_id: &ExecutionId,
    ) -> Result<String, LedgerError> {
        Ok(self
            .status_event_fact(tenant_id, execution_id)
            .await?
            .event_ref)
    }
    async fn status_event_fact(
        &self,
        tenant_id: &TenantId,
        execution_id: &ExecutionId,
    ) -> Result<LedgerEventFact, LedgerError>;
    async fn stale_non_terminal(
        &self,
        tenant_id: &TenantId,
        before: DateTime<Utc>,
    ) -> Result<Vec<ExecutionRecord>, LedgerError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompensationStep {
    pub step_id: String,
    pub tool: ToolRef,
    pub arguments_hash: String,
    pub required_current_version: Option<ResourceVersion>,
    pub expected_current_value: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompensationPlan {
    pub plan_id: String,
    pub forward_action_hash: ActionHash,
    pub steps: Vec<CompensationStep>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompensationReceipt {
    pub plan_id: String,
    pub completed_steps: Vec<String>,
    pub already_completed_steps: Vec<String>,
}

#[async_trait]
pub trait CompensationExecutor: Send + Sync {
    async fn current_resource_version(
        &self,
        step: &CompensationStep,
    ) -> Result<Option<ResourceVersion>, LedgerError>;
    async fn execute(
        &self,
        step: &CompensationStep,
        compensation_idempotency_key: &str,
    ) -> Result<(), LedgerError>;
}

pub struct CompensationCoordinator<E: CompensationExecutor> {
    executor: Arc<E>,
    completed: Mutex<BTreeSet<(String, String)>>,
}

impl<E: CompensationExecutor> CompensationCoordinator<E> {
    pub fn new(executor: Arc<E>) -> Self {
        Self {
            executor,
            completed: Mutex::new(BTreeSet::new()),
        }
    }
    pub async fn execute(
        &self,
        plan: &CompensationPlan,
    ) -> Result<CompensationReceipt, LedgerError> {
        let mut completed_steps = Vec::new();
        let mut already_completed_steps = Vec::new();
        for step in plan.steps.iter().rev() {
            let key = (plan.plan_id.clone(), step.step_id.clone());
            if self.completed.lock().contains(&key) {
                already_completed_steps.push(step.step_id.clone());
                continue;
            }
            if let Some(required) = &step.required_current_version
                && self.executor.current_resource_version(step).await?.as_ref() != Some(required)
            {
                return Err(LedgerError::CompensationPreconditionFailed);
            }
            let idempotency = format!("comp:{}:{}", plan.plan_id, step.step_id);
            self.executor.execute(step, &idempotency).await?;
            self.completed.lock().insert(key);
            completed_steps.push(step.step_id.clone());
        }
        Ok(CompensationReceipt {
            plan_id: plan.plan_id.clone(),
            completed_steps,
            already_completed_steps,
        })
    }
}

#[derive(Default)]
struct MemoryState {
    by_execution: BTreeMap<ExecutionId, ExecutionRecord>,
    by_idempotency: BTreeMap<(TenantId, IdempotencyKey), ExecutionId>,
    outbox: Vec<OutboxEvent>,
}

pub struct InMemoryExecutionLedger {
    state: Mutex<MemoryState>,
    next_fence: AtomicU64,
}
impl Default for InMemoryExecutionLedger {
    fn default() -> Self {
        Self {
            state: Mutex::new(MemoryState::default()),
            next_fence: AtomicU64::new(1),
        }
    }
}

impl InMemoryExecutionLedger {
    pub fn outbox(&self) -> Vec<OutboxEvent> {
        self.state.lock().outbox.clone()
    }
    pub fn snapshot(&self) -> Result<Vec<u8>, LedgerError> {
        let state = self.state.lock();
        serde_json::to_vec(&(&state.by_execution, &state.outbox))
            .map_err(|_| LedgerError::StoreFailure)
    }
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, LedgerError> {
        let (by_execution, outbox): (BTreeMap<ExecutionId, ExecutionRecord>, Vec<OutboxEvent>) =
            serde_json::from_slice(bytes).map_err(|_| LedgerError::StoreFailure)?;
        let mut by_idempotency = BTreeMap::new();
        let mut max_fence = 0;
        for (id, record) in &by_execution {
            by_idempotency.insert(
                (
                    record.intent.tenant_id.clone(),
                    record.intent.idempotency_key.clone(),
                ),
                id.clone(),
            );
            max_fence = max_fence.max(record.fence_token);
        }
        Ok(Self {
            state: Mutex::new(MemoryState {
                by_execution,
                by_idempotency,
                outbox,
            }),
            next_fence: AtomicU64::new(max_fence + 1),
        })
    }

    fn transition(
        &self,
        fence: &ExecutionFence,
        allowed: &[ExecutionStatus],
        next: ExecutionStatus,
        update: impl FnOnce(&mut ExecutionRecord),
    ) -> Result<(), LedgerError> {
        let mut state = self.state.lock();
        let record = state
            .by_execution
            .get_mut(&fence.execution_id)
            .ok_or(LedgerError::NotFound)?;
        if record.intent.tenant_id != fence.tenant_id || record.fence_token != fence.token {
            return Err(LedgerError::StaleFence);
        }
        if !allowed.contains(&record.status) {
            return Err(LedgerError::TransitionInvalid);
        }
        record.status = next;
        record.updated_at = Utc::now();
        update(record);
        let event = OutboxEvent {
            event_id: Uuid::new_v4().to_string(),
            execution_id: fence.execution_id.clone(),
            event_type: format!("EXECUTION_{next:?}"),
            payload: serde_json::json!({"status":format!("{next:?}")}),
            created_at: Utc::now(),
            published_at: None,
        };
        state.outbox.push(event);
        Ok(())
    }
}

#[async_trait]
impl ExecutionLedger for InMemoryExecutionLedger {
    async fn ready(&self) -> bool {
        true
    }
    async fn reserve(&self, intent: ExecutionIntent) -> Result<Reservation, LedgerError> {
        validate_intent(&intent)?;
        let key = (intent.tenant_id.clone(), intent.idempotency_key.clone());
        let mut state = self.state.lock();
        if let Some(execution_id) = state.by_idempotency.get(&key).cloned() {
            let existing = state
                .by_execution
                .get(&execution_id)
                .ok_or(LedgerError::StoreFailure)?;
            if existing.intent.action_hash != intent.action_hash {
                return Err(LedgerError::IdempotencyConflict);
            }
            return Ok(Reservation {
                execution_id: execution_id.clone(),
                fence: ExecutionFence {
                    tenant_id: existing.intent.tenant_id.clone(),
                    execution_id,
                    token: existing.fence_token,
                },
                existing: true,
                status: existing.status,
            });
        }
        let execution_id = ExecutionId::new();
        let tenant_id = intent.tenant_id.clone();
        let fence_token = self.next_fence.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        let record = ExecutionRecord {
            intent,
            execution_id: execution_id.clone(),
            fence_token,
            status: ExecutionStatus::Prepared,
            attempt: 0,
            external_operation_id: None,
            result_ref: None,
            evidence_ref: None,
            last_error_code: None,
            created_at: now,
            updated_at: now,
            manual_recovery: None,
        };
        state.by_idempotency.insert(key, execution_id.clone());
        state.by_execution.insert(execution_id.clone(), record);
        state.outbox.push(OutboxEvent {
            event_id: Uuid::new_v4().to_string(),
            execution_id: execution_id.clone(),
            event_type: "EXECUTION_RESERVED".into(),
            payload: Value::Null,
            created_at: now,
            published_at: None,
        });
        Ok(Reservation {
            execution_id: execution_id.clone(),
            fence: ExecutionFence {
                tenant_id,
                execution_id,
                token: fence_token,
            },
            existing: false,
            status: ExecutionStatus::Prepared,
        })
    }
    async fn mark_started(
        &self,
        fence: &ExecutionFence,
        operation: Option<String>,
    ) -> Result<(), LedgerError> {
        self.transition(
            fence,
            &[ExecutionStatus::Prepared],
            ExecutionStatus::Running,
            |record| {
                record.attempt += 1;
                record.external_operation_id = operation;
            },
        )
    }
    async fn mark_succeeded(
        &self,
        fence: &ExecutionFence,
        result: String,
        evidence: String,
    ) -> Result<(), LedgerError> {
        self.transition(
            fence,
            &[ExecutionStatus::Running, ExecutionStatus::Unknown],
            ExecutionStatus::Succeeded,
            |record| {
                record.result_ref = Some(result);
                record.evidence_ref = Some(evidence);
            },
        )
    }
    async fn mark_failed(&self, fence: &ExecutionFence, error: String) -> Result<(), LedgerError> {
        self.transition(
            fence,
            &[ExecutionStatus::Prepared, ExecutionStatus::Running],
            ExecutionStatus::Failed,
            |record| record.last_error_code = Some(error),
        )
    }
    async fn mark_unknown(&self, fence: &ExecutionFence, error: String) -> Result<(), LedgerError> {
        self.transition(
            fence,
            &[ExecutionStatus::Running],
            ExecutionStatus::Unknown,
            |record| record.last_error_code = Some(error),
        )
    }
    async fn mark_manual_recovery(
        &self,
        fence: &ExecutionFence,
        case: ManualRecoveryCase,
    ) -> Result<(), LedgerError> {
        self.transition(
            fence,
            &[
                ExecutionStatus::Running,
                ExecutionStatus::Unknown,
                ExecutionStatus::CompensationFailed,
            ],
            ExecutionStatus::Unknown,
            |record| record.manual_recovery = Some(case),
        )
    }
    async fn get(
        &self,
        tenant_id: &TenantId,
        id: &ExecutionId,
    ) -> Result<ExecutionRecord, LedgerError> {
        let record = self
            .state
            .lock()
            .by_execution
            .get(id)
            .cloned()
            .ok_or(LedgerError::NotFound)?;
        if &record.intent.tenant_id != tenant_id {
            return Err(LedgerError::NotFound);
        }
        Ok(record)
    }
    async fn status_event_fact(
        &self,
        tenant_id: &TenantId,
        execution_id: &ExecutionId,
    ) -> Result<LedgerEventFact, LedgerError> {
        let state = self.state.lock();
        let record = state
            .by_execution
            .get(execution_id)
            .ok_or(LedgerError::NotFound)?;
        if &record.intent.tenant_id != tenant_id {
            return Err(LedgerError::NotFound);
        }
        let event = state
            .outbox
            .iter()
            .rev()
            .find(|event| &event.execution_id == execution_id)
            .ok_or(LedgerError::NotFound)?;
        ledger_event_fact(tenant_id, event)
    }
    async fn stale_non_terminal(
        &self,
        tenant_id: &TenantId,
        before: DateTime<Utc>,
    ) -> Result<Vec<ExecutionRecord>, LedgerError> {
        Ok(self
            .state
            .lock()
            .by_execution
            .values()
            .filter(|record| {
                &record.intent.tenant_id == tenant_id
                    && record.updated_at <= before
                    && matches!(
                        record.status,
                        ExecutionStatus::Running | ExecutionStatus::Unknown
                    )
            })
            .cloned()
            .collect())
    }
}

fn validate_intent(intent: &ExecutionIntent) -> Result<(), LedgerError> {
    if intent.schema_version != LEDGER_SCHEMA_VERSION
        || intent.idempotency_key.0.is_empty()
        || intent.idempotency_key.0.len() > 128
        || !intent
            .idempotency_key
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
    {
        return Err(LedgerError::IntentInvalid);
    }
    if [&intent.tenant_id.0, &intent.task_id.0, &intent.step_id.0]
        .iter()
        .any(|value| Uuid::parse_str(value).is_err())
    {
        return Err(LedgerError::IntentInvalid);
    }
    if intent.effect_class == EffectClass::Compensatable && intent.compensation_plan.is_none() {
        return Err(LedgerError::CompensationRequired);
    }
    if intent.effect_class != EffectClass::Pure && intent.resource_version.is_none() {
        return Err(LedgerError::IntentInvalid);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum RecoveryDecision {
    Succeeded {
        result_ref: String,
        evidence_ref: String,
    },
    Failed {
        error_code: String,
    },
    StillUnknown,
    ManualRecovery {
        reason: String,
    },
}

#[async_trait]
pub trait OutcomeResolver: Send + Sync {
    async fn resolve(&self, record: &ExecutionRecord) -> Result<RecoveryDecision, LedgerError>;
}

pub struct RecoveryScanner<L: ExecutionLedger, O: OutcomeResolver> {
    ledger: Arc<L>,
    resolver: Arc<O>,
}
impl<L: ExecutionLedger, O: OutcomeResolver> RecoveryScanner<L, O> {
    pub fn new(ledger: Arc<L>, resolver: Arc<O>) -> Self {
        Self { ledger, resolver }
    }
    pub async fn reconcile(
        &self,
        tenant_id: &TenantId,
        before: DateTime<Utc>,
    ) -> Result<usize, LedgerError> {
        let stale = self.ledger.stale_non_terminal(tenant_id, before).await?;
        let mut reconciled = 0;
        for record in stale {
            let fence = ExecutionFence {
                tenant_id: record.intent.tenant_id.clone(),
                execution_id: record.execution_id.clone(),
                token: record.fence_token,
            };
            match self.resolver.resolve(&record).await? {
                RecoveryDecision::Succeeded {
                    result_ref,
                    evidence_ref,
                } => {
                    self.ledger
                        .mark_succeeded(&fence, result_ref, evidence_ref)
                        .await?
                }
                RecoveryDecision::Failed { error_code }
                    if record.status == ExecutionStatus::Running =>
                {
                    self.ledger.mark_failed(&fence, error_code).await?
                }
                RecoveryDecision::ManualRecovery { reason } => {
                    self.ledger
                        .mark_manual_recovery(
                            &fence,
                            ManualRecoveryCase {
                                case_id: Uuid::new_v4().to_string(),
                                impact_scope: record.intent.tool.tool_id.0.clone(),
                                last_known_state: format!("{:?}", record.status),
                                recommended_actions: vec![reason],
                                evidence_refs: vec![],
                                opened_at: Utc::now(),
                            },
                        )
                        .await?
                }
                RecoveryDecision::StillUnknown | RecoveryDecision::Failed { .. } => continue,
            }
            reconciled += 1;
        }
        Ok(reconciled)
    }
}

pub struct PostgresExecutionLedger {
    pool: PgPool,
}
impl PostgresExecutionLedger {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ExecutionLedger for PostgresExecutionLedger {
    async fn ready(&self) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sqlx::query_scalar::<_, bool>(
                "SELECT \
                 has_table_privilege(current_user,'executions','SELECT') AND \
                 has_table_privilege(current_user,'executions','INSERT') AND \
                 has_table_privilege(current_user,'executions','UPDATE') AND \
                 has_table_privilege(current_user,'idempotency_records','INSERT') AND \
                 has_table_privilege(current_user,'execution_outbox','SELECT') AND \
                 has_table_privilege(current_user,'execution_outbox','INSERT') AND \
                 has_sequence_privilege(current_user,'execution_fence_seq','USAGE')",
            )
            .fetch_one(&self.pool),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false)
    }
    async fn reserve(&self, intent: ExecutionIntent) -> Result<Reservation, LedgerError> {
        validate_intent(&intent)?;
        let tenant_uuid =
            Uuid::parse_str(&intent.tenant_id.0).map_err(|_| LedgerError::IntentInvalid)?;
        let task_uuid =
            Uuid::parse_str(&intent.task_id.0).map_err(|_| LedgerError::IntentInvalid)?;
        let step_uuid =
            Uuid::parse_str(&intent.step_id.0).map_err(|_| LedgerError::IntentInvalid)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&intent.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "{}:{}",
                intent.tenant_id.0, intent.idempotency_key.0
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        if let Some(row) = sqlx::query("SELECT execution_id, action_hash, fence_token, status FROM executions WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE")
            .bind(tenant_uuid).bind(&intent.idempotency_key.0).fetch_optional(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)? {
            let stored_hash: String = row.try_get("action_hash").map_err(|_| LedgerError::StoreFailure)?;
            if stored_hash != intent.action_hash.0 { return Err(LedgerError::IdempotencyConflict); }
            let stored_execution_id: Uuid = row.try_get("execution_id").map_err(|_| LedgerError::StoreFailure)?;
            let execution_id = ExecutionId(stored_execution_id.to_string()); let token: i64 = row.try_get("fence_token").map_err(|_| LedgerError::StoreFailure)?;
            let status = parse_status(row.try_get::<String, _>("status").map_err(|_| LedgerError::StoreFailure)?.as_str())?;
            transaction.commit().await.map_err(|_| LedgerError::StoreFailure)?;
            return Ok(Reservation { execution_id: execution_id.clone(), fence: ExecutionFence { tenant_id: intent.tenant_id.clone(), execution_id, token: token as u64 }, existing: true, status });
        }
        let execution_uuid = Uuid::new_v4();
        let execution_id = ExecutionId(execution_uuid.to_string());
        let fence_token = sqlx::query_scalar::<_, i64>("SELECT nextval('execution_fence_seq')")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        let intent_json = serde_json::to_value(&intent).map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("INSERT INTO executions (execution_id, tenant_id, task_id, step_id, action_hash, idempotency_key, fence_token, status, intent, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'PREPARED',$8,now(),now())")
            .bind(execution_uuid).bind(tenant_uuid).bind(task_uuid).bind(step_uuid).bind(&intent.action_hash.0).bind(&intent.idempotency_key.0).bind(fence_token).bind(intent_json)
            .execute(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("INSERT INTO idempotency_records (tenant_id, idempotency_key, action_hash, execution_id) VALUES ($1,$2,$3,$4)")
            .bind(tenant_uuid)
            .bind(&intent.idempotency_key.0)
            .bind(&intent.action_hash.0)
            .bind(execution_uuid)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("INSERT INTO execution_outbox (event_id, tenant_id, execution_id, event_type, payload, created_at) VALUES ($1,$2,$3,'EXECUTION_RESERVED','{}'::jsonb,now())")
            .bind(Uuid::new_v4()).bind(tenant_uuid).bind(execution_uuid).execute(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)?;
        transaction
            .commit()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        Ok(Reservation {
            execution_id: execution_id.clone(),
            fence: ExecutionFence {
                tenant_id: intent.tenant_id,
                execution_id,
                token: fence_token as u64,
            },
            existing: false,
            status: ExecutionStatus::Prepared,
        })
    }
    async fn mark_started(
        &self,
        fence: &ExecutionFence,
        operation: Option<String>,
    ) -> Result<(), LedgerError> {
        pg_transition(
            &self.pool,
            fence,
            "PREPARED",
            "RUNNING",
            operation.as_deref(),
            None,
            None,
            None,
        )
        .await
    }
    async fn mark_succeeded(
        &self,
        fence: &ExecutionFence,
        result: String,
        evidence: String,
    ) -> Result<(), LedgerError> {
        pg_transition(
            &self.pool,
            fence,
            "RUNNING,UNKNOWN",
            "SUCCEEDED",
            None,
            None,
            Some(&result),
            Some(&evidence),
        )
        .await
    }
    async fn mark_failed(&self, fence: &ExecutionFence, error: String) -> Result<(), LedgerError> {
        pg_transition(
            &self.pool,
            fence,
            "PREPARED,RUNNING",
            "FAILED",
            None,
            Some(&error),
            None,
            None,
        )
        .await
    }
    async fn mark_unknown(&self, fence: &ExecutionFence, error: String) -> Result<(), LedgerError> {
        pg_transition(
            &self.pool,
            fence,
            "RUNNING",
            "UNKNOWN",
            None,
            Some(&error),
            None,
            None,
        )
        .await
    }
    async fn mark_manual_recovery(
        &self,
        fence: &ExecutionFence,
        case: ManualRecoveryCase,
    ) -> Result<(), LedgerError> {
        let value = serde_json::to_value(case).map_err(|_| LedgerError::StoreFailure)?;
        let execution_uuid =
            Uuid::parse_str(&fence.execution_id.0).map_err(|_| LedgerError::StoreFailure)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        let tenant_uuid =
            Uuid::parse_str(&fence.tenant_id.0).map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&fence.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        let changed = sqlx::query("UPDATE executions SET manual_recovery=$4, updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND fence_token=$3 AND status IN ('RUNNING','UNKNOWN','COMPENSATION_FAILED')")
            .bind(tenant_uuid).bind(execution_uuid).bind(fence.token as i64).bind(value.clone()).execute(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)?.rows_affected();
        if changed != 1 {
            return Err(LedgerError::StaleFence);
        }
        sqlx::query("INSERT INTO execution_outbox (event_id, tenant_id, execution_id, event_type, payload, created_at) VALUES ($1,$2,$3,'MANUAL_RECOVERY_REQUIRED',$4,now())")
            .bind(Uuid::new_v4())
            .bind(tenant_uuid)
            .bind(execution_uuid)
            .bind(value)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        transaction
            .commit()
            .await
            .map_err(|_| LedgerError::StoreFailure)
    }
    async fn get(
        &self,
        tenant_id: &TenantId,
        execution_id: &ExecutionId,
    ) -> Result<ExecutionRecord, LedgerError> {
        let tenant_uuid = Uuid::parse_str(&tenant_id.0).map_err(|_| LedgerError::NotFound)?;
        let execution_uuid = Uuid::parse_str(&execution_id.0).map_err(|_| LedgerError::NotFound)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        let row = sqlx::query("SELECT intent, execution_id, fence_token, status, attempt, external_operation_id, result_ref, evidence_ref, last_error_code, created_at, updated_at, manual_recovery FROM executions WHERE tenant_id=$1 AND execution_id=$2")
            .bind(tenant_uuid).bind(execution_uuid).fetch_optional(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)?.ok_or(LedgerError::NotFound)?;
        let record = row_to_record(row)?;
        transaction
            .commit()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        Ok(record)
    }
    async fn status_event_fact(
        &self,
        tenant_id: &TenantId,
        execution_id: &ExecutionId,
    ) -> Result<LedgerEventFact, LedgerError> {
        let tenant_uuid = Uuid::parse_str(&tenant_id.0).map_err(|_| LedgerError::NotFound)?;
        let execution_uuid = Uuid::parse_str(&execution_id.0).map_err(|_| LedgerError::NotFound)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        let row = sqlx::query(
            "SELECT event_id,event_type,payload,created_at FROM execution_outbox WHERE tenant_id=$1 AND execution_id=$2 ORDER BY created_at DESC,event_id DESC LIMIT 1",
        )
        .bind(tenant_uuid).bind(execution_uuid).fetch_optional(&mut *transaction).await
        .map_err(|_| LedgerError::StoreFailure)?.ok_or(LedgerError::NotFound)?;
        let event = OutboxEvent {
            event_id: row.try_get::<Uuid, _>("event_id").map_err(|_| LedgerError::StoreFailure)?.to_string(),
            execution_id: execution_id.clone(),
            event_type: row.try_get("event_type").map_err(|_| LedgerError::StoreFailure)?,
            payload: row.try_get("payload").map_err(|_| LedgerError::StoreFailure)?,
            created_at: row.try_get("created_at").map_err(|_| LedgerError::StoreFailure)?,
            published_at: None,
        };
        transaction
            .commit()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        ledger_event_fact(tenant_id, &event)
    }
    async fn stale_non_terminal(
        &self,
        tenant_id: &TenantId,
        before: DateTime<Utc>,
    ) -> Result<Vec<ExecutionRecord>, LedgerError> {
        let tenant_uuid = Uuid::parse_str(&tenant_id.0).map_err(|_| LedgerError::NotFound)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        let rows = sqlx::query("SELECT intent, execution_id, fence_token, status, attempt, external_operation_id, result_ref, evidence_ref, last_error_code, created_at, updated_at, manual_recovery FROM executions WHERE tenant_id=$1 AND status IN ('RUNNING','UNKNOWN') AND updated_at <= $2 ORDER BY updated_at LIMIT 100")
            .bind(tenant_uuid).bind(before).fetch_all(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)?;
        let records = rows.into_iter().map(row_to_record).collect();
        transaction
            .commit()
            .await
            .map_err(|_| LedgerError::StoreFailure)?;
        records
    }
}

#[derive(Serialize)]
struct LedgerEventDigestMaterial<'a> {
    schema_version: &'static str,
    tenant_id: &'a TenantId,
    event_id: &'a str,
    execution_id: &'a ExecutionId,
    event_type: &'a str,
    payload: &'a Value,
    created_at: DateTime<Utc>,
}

fn ledger_event_fact(
    tenant_id: &TenantId,
    event: &OutboxEvent,
) -> Result<LedgerEventFact, LedgerError> {
    let event_id = Uuid::parse_str(&event.event_id).map_err(|_| LedgerError::StoreFailure)?;
    if event_id.to_string() != event.event_id {
        return Err(LedgerError::StoreFailure);
    }
    let material = LedgerEventDigestMaterial {
        schema_version: "agenttrust.ledger-event-fact.v1",
        tenant_id,
        event_id: &event.event_id,
        execution_id: &event.execution_id,
        event_type: &event.event_type,
        payload: &event.payload,
        created_at: event.created_at.to_owned(),
    };
    let canonical = serde_jcs::to_vec(&material).map_err(|_| LedgerError::StoreFailure)?;
    Ok(LedgerEventFact {
        event_id: event.event_id.clone(),
        event_ref: format!("ledger-event:{}", event.event_id),
        event_digest: hex::encode(Sha256::digest(canonical)),
    })
}

// Keeping every optional mutation explicit makes terminal ledger transitions auditable at each
// call site; collapsing these fields into an untyped map would weaken the SQL binding contract.
#[allow(clippy::too_many_arguments)]
async fn pg_transition(
    pool: &PgPool,
    fence: &ExecutionFence,
    allowed_csv: &str,
    next: &str,
    external_operation_id: Option<&str>,
    error_code: Option<&str>,
    result: Option<&str>,
    evidence: Option<&str>,
) -> Result<(), LedgerError> {
    let allowed: Vec<&str> = allowed_csv.split(',').collect();
    let execution_uuid =
        Uuid::parse_str(&fence.execution_id.0).map_err(|_| LedgerError::StoreFailure)?;
    let tenant_uuid = Uuid::parse_str(&fence.tenant_id.0).map_err(|_| LedgerError::StoreFailure)?;
    let mut transaction = pool.begin().await.map_err(|_| LedgerError::StoreFailure)?;
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(&fence.tenant_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| LedgerError::StoreFailure)?;
    let changed = sqlx::query("UPDATE executions SET status=$4, external_operation_id=COALESCE($5,external_operation_id), last_error_code=COALESCE($6,last_error_code), result_ref=COALESCE($7,result_ref), evidence_ref=COALESCE($8,evidence_ref), attempt=CASE WHEN $4='RUNNING' THEN attempt+1 ELSE attempt END, updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND fence_token=$3 AND status = ANY($9)")
        .bind(tenant_uuid).bind(execution_uuid).bind(fence.token as i64).bind(next).bind(external_operation_id).bind(error_code).bind(result).bind(evidence).bind(&allowed)
        .execute(&mut *transaction).await.map_err(|_| LedgerError::StoreFailure)?.rows_affected();
    if changed != 1 {
        return Err(LedgerError::StaleFence);
    }
    sqlx::query("INSERT INTO execution_outbox (event_id, tenant_id, execution_id, event_type, payload, created_at) VALUES ($1,$2,$3,$4,$5,now())")
        .bind(Uuid::new_v4())
        .bind(tenant_uuid)
        .bind(execution_uuid)
        .bind(format!("EXECUTION_{next}"))
        .bind(serde_json::json!({"status": next, "external_operation_id": external_operation_id, "error_code": error_code, "result_ref": result, "evidence_ref": evidence}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| LedgerError::StoreFailure)?;
    transaction
        .commit()
        .await
        .map_err(|_| LedgerError::StoreFailure)
}

fn row_to_record(row: sqlx::postgres::PgRow) -> Result<ExecutionRecord, LedgerError> {
    let intent: ExecutionIntent = serde_json::from_value(
        row.try_get("intent")
            .map_err(|_| LedgerError::StoreFailure)?,
    )
    .map_err(|_| LedgerError::StoreFailure)?;
    Ok(ExecutionRecord {
        intent,
        execution_id: ExecutionId(
            row.try_get::<Uuid, _>("execution_id")
                .map_err(|_| LedgerError::StoreFailure)?
                .to_string(),
        ),
        fence_token: row
            .try_get::<i64, _>("fence_token")
            .map_err(|_| LedgerError::StoreFailure)? as u64,
        status: parse_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| LedgerError::StoreFailure)?,
        )?,
        attempt: row
            .try_get::<i32, _>("attempt")
            .map_err(|_| LedgerError::StoreFailure)? as u32,
        external_operation_id: row
            .try_get("external_operation_id")
            .map_err(|_| LedgerError::StoreFailure)?,
        result_ref: row
            .try_get("result_ref")
            .map_err(|_| LedgerError::StoreFailure)?,
        evidence_ref: row
            .try_get("evidence_ref")
            .map_err(|_| LedgerError::StoreFailure)?,
        last_error_code: row
            .try_get("last_error_code")
            .map_err(|_| LedgerError::StoreFailure)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| LedgerError::StoreFailure)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| LedgerError::StoreFailure)?,
        manual_recovery: row
            .try_get::<Option<Value>, _>("manual_recovery")
            .map_err(|_| LedgerError::StoreFailure)?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| LedgerError::StoreFailure)?,
    })
}

fn parse_status(value: &str) -> Result<ExecutionStatus, LedgerError> {
    match value {
        "PREPARED" => Ok(ExecutionStatus::Prepared),
        "RUNNING" => Ok(ExecutionStatus::Running),
        "SUCCEEDED" => Ok(ExecutionStatus::Succeeded),
        "FAILED" => Ok(ExecutionStatus::Failed),
        "TIMED_OUT" => Ok(ExecutionStatus::TimedOut),
        "CANCELLED" => Ok(ExecutionStatus::Cancelled),
        "KILLED" => Ok(ExecutionStatus::Killed),
        "COMPENSATING" => Ok(ExecutionStatus::Compensating),
        "COMPENSATED" => Ok(ExecutionStatus::Compensated),
        "COMPENSATION_FAILED" => Ok(ExecutionStatus::CompensationFailed),
        "UNKNOWN" => Ok(ExecutionStatus::Unknown),
        _ => Err(LedgerError::StoreFailure),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LedgerError {
    #[error("LEDGER_INTENT_INVALID")]
    IntentInvalid,
    #[error("LEDGER_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("LEDGER_COMPENSATION_REQUIRED")]
    CompensationRequired,
    #[error("LEDGER_COMPENSATION_PRECONDITION_FAILED")]
    CompensationPreconditionFailed,
    #[error("LEDGER_COMPENSATION_FAILED")]
    CompensationFailed,
    #[error("LEDGER_STALE_FENCE")]
    StaleFence,
    #[error("LEDGER_TRANSITION_INVALID")]
    TransitionInvalid,
    #[error("LEDGER_NOT_FOUND")]
    NotFound,
    #[error("LEDGER_STORE_FAILURE")]
    StoreFailure,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{ToolId, ToolVersion};

    fn intent(key: &str, hash: &str) -> ExecutionIntent {
        ExecutionIntent {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            action_hash: ActionHash(hash.into()),
            idempotency_key: IdempotencyKey(key.into()),
            tool: ToolRef {
                tool_id: ToolId("coding.run-tests".into()),
                tool_version: ToolVersion("1.0.0".into()),
            },
            effect_class: EffectClass::Idempotent,
            resource_version: Some(ResourceVersion("v1".into())),
            canonical_arguments_hash: "args".into(),
            compensation_plan: None,
            requested_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn concurrent_reservations_create_one_execution() {
        let ledger = Arc::new(InMemoryExecutionLedger::default());
        let base = intent("client:key", "hash");
        let mut tasks = vec![];
        for _ in 0..100 {
            let ledger = ledger.clone();
            let intent = base.clone();
            tasks.push(tokio::spawn(async move { ledger.reserve(intent).await }));
        }
        let mut ids = BTreeSet::new();
        let mut new_count = 0;
        for task in tasks {
            let reservation = task
                .await
                .unwrap_or_else(|_| panic!("join"))
                .unwrap_or_else(|_| panic!("reserve"));
            ids.insert(reservation.execution_id);
            if !reservation.existing {
                new_count += 1;
            }
        }
        assert_eq!(ids.len(), 1);
        assert_eq!(new_count, 1);
    }

    #[tokio::test]
    async fn same_key_different_action_conflicts() {
        let ledger = InMemoryExecutionLedger::default();
        let first = intent("client:key", "hash-a");
        let mut second = first.clone();
        second.action_hash = ActionHash("hash-b".into());
        assert!(ledger.reserve(first).await.is_ok());
        assert_eq!(
            ledger.reserve(second).await,
            Err(LedgerError::IdempotencyConflict)
        );
    }

    #[tokio::test]
    async fn prepared_reservation_can_terminally_record_pre_execution_denial() {
        let ledger = InMemoryExecutionLedger::default();
        let base = intent("client:denied", "hash-denied");
        let reservation = ledger
            .reserve(base.clone())
            .await
            .unwrap_or_else(|_| panic!("reserve"));
        ledger
            .mark_failed(&reservation.fence, "EXECUTION_AUTHORIZATION_DENIED".into())
            .await
            .unwrap_or_else(|_| panic!("deny"));
        let record = ledger
            .get(&base.tenant_id, &reservation.execution_id)
            .await
            .unwrap_or_else(|_| panic!("record"));
        assert_eq!(record.status, ExecutionStatus::Failed);
        assert_eq!(
            record.last_error_code.as_deref(),
            Some("EXECUTION_AUTHORIZATION_DENIED")
        );
    }

    #[tokio::test]
    async fn ledger_event_fact_is_stable_and_changes_with_the_persisted_transition() {
        let ledger = InMemoryExecutionLedger::default();
        let base = intent("client:event-fact", "hash-event-fact");
        let reservation = ledger
            .reserve(base.clone())
            .await
            .unwrap_or_else(|_| panic!("reserve"));
        let reserved = ledger
            .status_event_fact(&base.tenant_id, &reservation.execution_id)
            .await
            .unwrap_or_else(|_| panic!("reserved fact"));
        assert_eq!(reserved.event_digest.len(), 64);
        assert_eq!(reserved.event_ref, format!("ledger-event:{}", reserved.event_id));
        assert_eq!(
            ledger
                .status_event_fact(&base.tenant_id, &reservation.execution_id)
                .await
                .unwrap_or_else(|_| panic!("replay fact")),
            reserved
        );
        ledger
            .mark_started(&reservation.fence, None)
            .await
            .unwrap_or_else(|_| panic!("start"));
        let running = ledger
            .status_event_fact(&base.tenant_id, &reservation.execution_id)
            .await
            .unwrap_or_else(|_| panic!("running fact"));
        assert_ne!(running.event_id, reserved.event_id);
        assert_ne!(running.event_digest, reserved.event_digest);
    }

    struct Resolver;
    #[async_trait]
    impl OutcomeResolver for Resolver {
        async fn resolve(&self, _: &ExecutionRecord) -> Result<RecoveryDecision, LedgerError> {
            Ok(RecoveryDecision::Succeeded {
                result_ref: "result".into(),
                evidence_ref: "evidence".into(),
            })
        }
    }

    #[tokio::test]
    async fn unknown_outcome_survives_restart_and_reconciles_without_new_reservation() {
        let ledger = InMemoryExecutionLedger::default();
        let base = intent("client:key", "hash");
        let reservation = ledger
            .reserve(base.clone())
            .await
            .unwrap_or_else(|_| panic!("reserve"));
        ledger
            .mark_started(&reservation.fence, Some("external:1".into()))
            .await
            .unwrap_or_else(|_| panic!("start"));
        ledger
            .mark_unknown(&reservation.fence, "RESPONSE_LOST".into())
            .await
            .unwrap_or_else(|_| panic!("unknown"));
        let bytes = ledger.snapshot().unwrap_or_default();
        let restarted = Arc::new(
            InMemoryExecutionLedger::from_snapshot(&bytes).unwrap_or_else(|_| panic!("restore")),
        );
        let scanner = RecoveryScanner::new(restarted.clone(), Arc::new(Resolver));
        assert_eq!(
            scanner
                .reconcile(&base.tenant_id, Utc::now() + chrono::Duration::seconds(1),)
                .await,
            Ok(1)
        );
        assert_eq!(
            restarted
                .get(&base.tenant_id, &reservation.execution_id)
                .await
                .map(|record| record.status),
            Ok(ExecutionStatus::Succeeded)
        );
        assert!(
            restarted
                .reserve(base)
                .await
                .unwrap_or_else(|_| panic!("reserve"))
                .existing
        );
    }

    struct Compensation {
        version: ResourceVersion,
        calls: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl CompensationExecutor for Compensation {
        async fn current_resource_version(
            &self,
            _: &CompensationStep,
        ) -> Result<Option<ResourceVersion>, LedgerError> {
            Ok(Some(self.version.clone()))
        }
        async fn execute(&self, _: &CompensationStep, key: &str) -> Result<(), LedgerError> {
            self.calls.lock().push(key.into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn compensation_is_lifo_idempotent_and_version_guarded() {
        let executor = Arc::new(Compensation {
            version: ResourceVersion("v2".into()),
            calls: Mutex::new(vec![]),
        });
        let coordinator = CompensationCoordinator::new(executor.clone());
        let plan = CompensationPlan {
            plan_id: "plan".into(),
            forward_action_hash: ActionHash("hash".into()),
            steps: vec![
                CompensationStep {
                    step_id: "one".into(),
                    tool: intent("k", "h").tool,
                    arguments_hash: "a".into(),
                    required_current_version: Some(ResourceVersion("v2".into())),
                    expected_current_value: None,
                },
                CompensationStep {
                    step_id: "two".into(),
                    tool: intent("k2", "h2").tool,
                    arguments_hash: "b".into(),
                    required_current_version: Some(ResourceVersion("v2".into())),
                    expected_current_value: None,
                },
            ],
            created_at: Utc::now(),
        };
        let first = coordinator
            .execute(&plan)
            .await
            .unwrap_or_else(|_| panic!("compensate"));
        assert_eq!(first.completed_steps, vec!["two", "one"]);
        let second = coordinator
            .execute(&plan)
            .await
            .unwrap_or_else(|_| panic!("compensate"));
        assert_eq!(second.already_completed_steps.len(), 2);
        assert_eq!(executor.calls.lock().len(), 2);
        let stale = CompensationCoordinator::new(Arc::new(Compensation {
            version: ResourceVersion("v3".into()),
            calls: Mutex::new(vec![]),
        }));
        assert_eq!(
            stale.execute(&plan).await.err(),
            Some(LedgerError::CompensationPreconditionFailed)
        );
    }
}
