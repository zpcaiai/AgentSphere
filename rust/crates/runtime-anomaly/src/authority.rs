//! PostgreSQL-backed Runtime Anomaly and Continuous Authorization authority.
//!
//! Signed telemetry is an event input, never an implicit production action. The authority verifies
//! the source key and workload binding, persists the signal, deterministic finding, aggregate,
//! local lease revocation and Evidence outbox atomically. Any response with an external effect is
//! normalized into Canonical Action IR and admitted by the durable orchestrator. Only Tool Proxy
//! may invoke the executor with an exact PEP/ledger/fence/Evidence binding.

use crate::{
    ANOMALY_SCHEMA_VERSION, AuthorizationAdjustment, ContinuousAuthorizationController,
    RiskAggregate, RiskAggregator, RiskFinding, RiskSignal, RuleDetector, SemanticScore,
    SignalKind, TrajectoryState,
};
use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector, RiskContext,
    RiskLevel, SchemaVersion, StepId, TaskId, TenantId, ToolId, ToolRef, ToolVersion,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const SIGNED_SIGNAL_SCHEMA: &str = "agenttrust.signed-risk-signal.v1";
pub const SIGNAL_RECEIPT_SCHEMA: &str = "agenttrust.risk-signal-receipt.v1";
pub const ANOMALY_COMMAND_SCHEMA: &str = "agenttrust.runtime-anomaly-command.v1";
pub const ANOMALY_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.runtime-anomaly-executor-request.v1";
pub const ANOMALY_EXECUTION_BINDING_SCHEMA: &str =
    "agenttrust.runtime-anomaly-execution-binding.v1";
pub const ANOMALY_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.runtime-anomaly-action-receipt.v1";
pub const ANOMALY_MUTATION_RESULT_SCHEMA: &str = "agenttrust.runtime-anomaly-mutation-result.v1";
pub const ANOMALY_RESPONSE_RECEIPT_SCHEMA: &str = "agenttrust.runtime-response-receipt.v1";
pub const ANOMALY_EVIDENCE_RECEIPT_SCHEMA: &str = "agenttrust.runtime-anomaly-evidence-receipt.v1";
pub const ANOMALY_READINESS_SCHEMA: &str = "agenttrust.runtime-anomaly-readiness.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeAnomalyAuthorityError {
    #[error("RUNTIME_ANOMALY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("RUNTIME_ANOMALY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("RUNTIME_ANOMALY_SOURCE_DENIED")]
    SourceDenied,
    #[error("RUNTIME_ANOMALY_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("RUNTIME_ANOMALY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("RUNTIME_ANOMALY_STATE_CONFLICT")]
    StateConflict,
    #[error("RUNTIME_ANOMALY_NOT_FOUND")]
    NotFound,
    #[error("RUNTIME_ANOMALY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("RUNTIME_ANOMALY_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("RUNTIME_ANOMALY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeAnomalyOperation {
    RegisterSource,
    RevokeSource,
    StartTrajectory,
    UpdateBaseline,
    RecordFeedback,
    AcknowledgeCase,
    RecoverPausedTask,
    CompleteTrajectory,
    ApplyContinuousAuthorization,
}

impl RuntimeAnomalyOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RegisterSource => "REGISTER_SOURCE",
            Self::RevokeSource => "REVOKE_SOURCE",
            Self::StartTrajectory => "START_TRAJECTORY",
            Self::UpdateBaseline => "UPDATE_BASELINE",
            Self::RecordFeedback => "RECORD_FEEDBACK",
            Self::AcknowledgeCase => "ACKNOWLEDGE_CASE",
            Self::RecoverPausedTask => "RECOVER_PAUSED_TASK",
            Self::CompleteTrajectory => "COMPLETE_TRAJECTORY",
            Self::ApplyContinuousAuthorization => "APPLY_CONTINUOUS_AUTHORIZATION",
        }
    }

    fn risk(&self) -> RiskLevel {
        match self {
            Self::RecordFeedback | Self::AcknowledgeCase | Self::CompleteTrajectory => {
                RiskLevel::High
            }
            _ => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAnomalyCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub task_id: Uuid,
    pub resource: String,
    pub operation: RuntimeAnomalyOperation,
    pub expected_resource_version: u64,
    pub requested_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAnomalyExecutorRequest {
    pub schema_version: String,
    pub command: RuntimeAnomalyCommandRequest,
    pub actor_subject: String,
    pub actor_kind: String,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAnomalyExecutionBinding {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub resource_version: u64,
    pub idempotency_key: String,
    pub trace_id: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAnomalyActionReceipt {
    pub schema_version: String,
    pub action_id: String,
    pub task_id: String,
    pub accepted: bool,
    pub execution_pending: bool,
    pub ingress_digest: String,
    pub ledger_evidence_ref: String,
    pub ledger_evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAnomalyMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub operation: RuntimeAnomalyOperation,
    pub resource: String,
    pub resource_version: u64,
    pub task_execution_succeeded: bool,
    pub process_outcome: String,
    pub result_digest: String,
    pub evidence_outbox_ref: String,
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedRiskSignalEnvelope {
    pub schema_version: String,
    pub source_id: String,
    pub key_id: String,
    pub signal: RiskSignal,
    pub semantic_score: Option<SemanticScore>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalIngestReceipt {
    pub schema_version: String,
    pub event_id: String,
    pub task_id: String,
    pub payload_digest: String,
    pub duplicate: bool,
    pub finding_ids: Vec<String>,
    pub aggregate_id: Option<String>,
    pub response_action_id: Option<String>,
    pub local_authorization_status: String,
    pub revocation_epoch: u64,
    pub evidence_outbox_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeTrajectory {
    pub task_id: Uuid,
    pub agent_instance_id: Uuid,
    pub agent_type: String,
    pub domain: String,
    pub status: String,
    pub event_count: u64,
    pub revocation_epoch: u64,
    pub resource_version: u64,
    pub last_seen_at: DateTime<Utc>,
    pub latest_severity: Option<String>,
    pub open_case_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeTrajectoryPage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub authoritative: bool,
    pub items: Vec<AuthoritativeTrajectory>,
    pub next_after: Option<String>,
    pub data_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResponseReceipt {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub response_id: Uuid,
    pub task_id: Uuid,
    pub command_digest: String,
    pub adjustment: AuthorizationAdjustment,
    pub supervisor_receipt_digest: Option<String>,
    pub credential_receipt_digest: Option<String>,
    pub incident_receipt_digest: Option<String>,
    pub safe_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnomalyEvidenceReceipt {
    pub schema_version: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterSourcePayload {
    source_id: String,
    key_id: String,
    ed25519_public_key_base64: String,
    allowed_signal_kinds: Vec<String>,
    workload_identity: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeSourcePayload {
    source_id: String,
    reason_digest: String,
    replacement_source_id: Option<String>,
    approval_id: Uuid,
    approval_evidence_ref: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartTrajectoryPayload {
    agent_instance_id: Uuid,
    agent_type: String,
    domain: String,
    goal_hash: String,
    plan_hash: String,
    allowed_resource_prefixes: Vec<String>,
    allowed_network_destinations: Vec<String>,
    authorization_lease_id: Uuid,
    revocation_epoch: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselinePayload {
    baseline_id: Uuid,
    agent_type: String,
    domain: String,
    maximum_calls_per_minute: u32,
    maximum_distinct_resources: u32,
    maximum_destination_fanout: u32,
    sample_count: u64,
    threshold_version: String,
    approval_id: Uuid,
    approval_evidence_ref: String,
    baseline_digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedbackPayload {
    feedback_id: Uuid,
    finding_id: Uuid,
    label: String,
    annotation_digest: String,
    reviewer_subject: String,
    approval_id: Uuid,
    evidence_ref: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseTransitionPayload {
    case_id: Uuid,
    approval_id: Uuid,
    approval_evidence_ref: String,
    new_authorization_lease_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteTrajectoryPayload {
    completion_evidence_ref: String,
    completion_evidence_digest: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeAnomalyAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
    pub rule_version: String,
    pub rule_bundle_digest: String,
    pub maximum_signal_clock_skew_seconds: i64,
    pub maximum_signal_lookback: i64,
    pub slow_exfiltration_distinct_domains: usize,
    pub repeated_side_effect_limit: usize,
}

impl RuntimeAnomalyAuthorityConfig {
    pub fn validate(&self) -> Result<(), RuntimeAnomalyAuthorityError> {
        if canonical_uuid(&self.service_agent_id.0)
            && identifier(&self.organization_id, 256)
            && identifier(&self.agent_version, 128)
            && identifier(&self.region, 128)
            && identifier(&self.tool_id.0, 256)
            && identifier(&self.tool_version.0, 128)
            && identifier(&self.credential_profile, 128)
            && identifier(&self.service_subject, 256)
            && identifier(&self.rule_version, 128)
            && digest(&self.rule_bundle_digest)
            && (0..=300).contains(&self.maximum_signal_clock_skew_seconds)
            && (10..=4096).contains(&self.maximum_signal_lookback)
            && (2..=256).contains(&self.slow_exfiltration_distinct_domains)
            && (2..=256).contains(&self.repeated_side_effect_limit)
        {
            Ok(())
        } else {
            Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid)
        }
    }
}

#[async_trait]
pub trait RuntimeAnomalyOrchestratorPort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<RuntimeAnomalyActionReceipt, RuntimeAnomalyAuthorityError>;
}

#[async_trait]
pub trait RuntimeAnomalyEffectsPort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn apply_response(
        &self,
        binding: &RuntimeAnomalyExecutionBinding,
        command: &crate::ResponseCommand,
    ) -> Result<RuntimeResponseReceipt, RuntimeAnomalyAuthorityError>;
    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<AnomalyEvidenceReceipt, RuntimeAnomalyAuthorityError>;
}

#[derive(Clone)]
pub struct PostgresRuntimeAnomalyStore {
    pool: PgPool,
}

impl PostgresRuntimeAnomalyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM runtime_anomaly_trajectories WHERE false UNION ALL SELECT 1 LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .is_ok()
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, RuntimeAnomalyAuthorityError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(parse_tenant(tenant)?.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }
}

async fn load_source(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    source_id: &str,
) -> Result<SourceRecord, RuntimeAnomalyAuthorityError> {
    let row = sqlx::query(
        "SELECT key_id,ed25519_public_key,allowed_signal_kinds,workload_identity,status \
         FROM runtime_anomaly_signal_sources WHERE tenant_id=$1 AND source_id=$2 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(source_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
    .ok_or(RuntimeAnomalyAuthorityError::SourceDenied)?;
    Ok(SourceRecord {
        key_id: row.get("key_id"),
        public_key: row.get("ed25519_public_key"),
        allowed_signal_kinds: row.get("allowed_signal_kinds"),
        workload_identity: row.get("workload_identity"),
        status: row.get("status"),
    })
}

async fn load_trajectory(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    task_id: Uuid,
) -> Result<TrajectoryRecord, RuntimeAnomalyAuthorityError> {
    let row = sqlx::query(
        "SELECT agent_instance_id,agent_type,domain,goal_hash,plan_hash,\
                allowed_resource_prefixes,allowed_network_destinations,authorization_lease_id,\
                revocation_epoch,status,event_count,resource_version,started_at,last_seen_at \
         FROM runtime_anomaly_trajectories WHERE tenant_id=$1 AND task_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(task_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
    .ok_or(RuntimeAnomalyAuthorityError::NotFound)?;
    let prefixes: Vec<String> = row.get("allowed_resource_prefixes");
    let destinations: Vec<String> = row.get("allowed_network_destinations");
    Ok(TrajectoryRecord {
        state: TrajectoryState {
            schema_version: ANOMALY_SCHEMA_VERSION.into(),
            tenant_id: TenantId(tenant_id.to_string()),
            task_id: TaskId(task_id.to_string()),
            goal_hash: row.get("goal_hash"),
            plan_hash: row.get("plan_hash"),
            allowed_resource_prefixes: prefixes.into_iter().collect(),
            allowed_network_destinations: destinations.into_iter().collect(),
            event_count: usize::try_from(row.get::<i64, _>("event_count"))
                .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
            first_seen_at: row.get("started_at"),
            last_seen_at: row.get("last_seen_at"),
        },
        agent_instance_id: AgentInstanceId(row.get::<Uuid, _>("agent_instance_id").to_string()),
        revocation_epoch: u64::try_from(row.get::<i64, _>("revocation_epoch"))
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
        status: row.get("status"),
        resource_version: u64::try_from(row.get::<i64, _>("resource_version"))
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
    })
}

async fn load_recent_signals(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    task_id: Uuid,
    limit: i64,
) -> Result<Vec<RiskSignal>, RuntimeAnomalyAuthorityError> {
    let rows = sqlx::query(
        "SELECT event_id,agent_instance_id,signal_kind,action,resource,resource_class,\
                safe_features,confidence_millionths,source_version,occurred_at \
         FROM runtime_anomaly_signals WHERE tenant_id=$1 AND task_id=$2 \
         ORDER BY occurred_at DESC,event_id DESC LIMIT $3",
    )
    .bind(tenant_id)
    .bind(task_id)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    let mut signals = rows
        .into_iter()
        .map(|row| {
            Ok(RiskSignal {
                schema_version: ANOMALY_SCHEMA_VERSION.into(),
                event_id: row.get::<Uuid, _>("event_id").to_string(),
                tenant_id: TenantId(tenant_id.to_string()),
                task_id: TaskId(task_id.to_string()),
                agent_instance_id: AgentInstanceId(
                    row.get::<Uuid, _>("agent_instance_id").to_string(),
                ),
                kind: parse_signal_kind(row.get::<String, _>("signal_kind").as_str())?,
                action: row.get("action"),
                resource: row.get("resource"),
                resource_class: row.get("resource_class"),
                value: row.get("safe_features"),
                confidence_millionths: u32::try_from(row.get::<i32, _>("confidence_millionths"))
                    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
                source_version: row.get("source_version"),
                occurred_at: row.get("occurred_at"),
            })
        })
        .collect::<Result<Vec<_>, RuntimeAnomalyAuthorityError>>()?;
    signals.reverse();
    Ok(signals)
}

async fn persist_findings(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    task_id: Uuid,
    findings: &[RiskFinding],
) -> Result<Vec<String>, RuntimeAnomalyAuthorityError> {
    let mut ids = Vec::with_capacity(findings.len());
    for finding in findings.iter().take(4096) {
        let finding_id = parse_uuid(&finding.finding_id)?;
        let event_ids = finding
            .evidence_event_ids
            .iter()
            .map(|value| parse_uuid(value))
            .collect::<Result<Vec<_>, _>>()?;
        let finding_digest = canonical_digest(finding)?;
        sqlx::query(
            "INSERT INTO runtime_anomaly_findings \
             (tenant_id,finding_id,task_id,rule_id,rule_version,severity,deterministic,\
              confidence_millionths,evidence_event_ids,safe_reason,status,finding_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'OPEN',$11) ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(finding_id)
        .bind(task_id)
        .bind(&finding.rule_id)
        .bind(&finding.rule_version)
        .bind(risk_level_name(finding.severity))
        .bind(finding.deterministic)
        .bind(
            i32::try_from(finding.confidence_millionths)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
        )
        .bind(event_ids)
        .bind(&finding.safe_reason)
        .bind(finding_digest)
        .execute(&mut **tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        ids.push(finding.finding_id.clone());
    }
    Ok(ids)
}

async fn persist_aggregate(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    task_id: Uuid,
    aggregate: &RiskAggregate,
    finding_ids: &[String],
    rule_bundle_digest: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let aggregate_id = parse_uuid(&aggregate.aggregate_id)?;
    let finding_uuids = finding_ids
        .iter()
        .map(|value| parse_uuid(value))
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate_digest = canonical_digest(aggregate)?;
    let (model_id, model_version, semantic_score, reason_codes) = aggregate
        .semantic_score
        .as_ref()
        .map(|value| {
            (
                Some(value.model_id.clone()),
                Some(value.model_version.clone()),
                Some(i32::try_from(value.score_millionths).unwrap_or(1_000_000)),
                value.reason_codes.iter().cloned().collect::<Vec<_>>(),
            )
        })
        .unwrap_or((None, None, None, Vec::new()));
    sqlx::query(
        "INSERT INTO runtime_anomaly_aggregates \
         (tenant_id,aggregate_id,task_id,severity,score_millionths,finding_ids,semantic_model_id,\
          semantic_model_version,semantic_score_millionths,semantic_reason_codes,detector_degraded,\
          rule_bundle_digest,aggregate_digest,computed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(tenant_id)
    .bind(aggregate_id)
    .bind(task_id)
    .bind(risk_level_name(aggregate.severity))
    .bind(
        i32::try_from(aggregate.score_millionths)
            .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
    )
    .bind(finding_uuids)
    .bind(model_id)
    .bind(model_version)
    .bind(semantic_score)
    .bind(reason_codes)
    .bind(aggregate.detector_degraded)
    .bind(rule_bundle_digest)
    .bind(aggregate_digest)
    .bind(aggregate.computed_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    Ok(())
}

async fn persist_response(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    task_id: Uuid,
    aggregate: &RiskAggregate,
    response: &crate::ResponseCommand,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let signature = URL_SAFE_NO_PAD
        .decode(&response.signature)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    let command_digest = canonical_digest(response)?;
    sqlx::query(
        "INSERT INTO runtime_anomaly_response_commands \
         (tenant_id,response_id,task_id,aggregate_id,adjustment,new_revocation_epoch,reason_codes,\
          evidence_digest,recovery_conditions,command_digest,issuer,key_id,signature,state,issued_at,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'PENDING',$14,$15)",
    )
    .bind(tenant_id)
    .bind(parse_uuid(&response.response_id)?)
    .bind(task_id)
    .bind(parse_uuid(&aggregate.aggregate_id)?)
    .bind(adjustment_name(response.adjustment))
    .bind(i64::try_from(response.new_revocation_epoch)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
    .bind(response.reason_codes.iter().cloned().collect::<Vec<_>>())
    .bind(&response.evidence_digest)
    .bind(response.recovery_conditions.iter().cloned().collect::<Vec<_>>())
    .bind(command_digest)
    .bind(&response.issuer)
    .bind(&response.key_id)
    .bind(signature)
    .bind(response.issued_at)
    .bind(response.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    Ok(())
}

async fn persist_case(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    task_id: Uuid,
    aggregate: &RiskAggregate,
    response: &crate::ResponseCommand,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let status = match response.adjustment {
        AuthorizationAdjustment::Kill => "KILLED",
        AuthorizationAdjustment::Pause
        | AuthorizationAdjustment::RevokeLease
        | AuthorizationAdjustment::RevokeCredential => "PAUSED",
        _ => "OPEN",
    };
    sqlx::query(
        "INSERT INTO runtime_anomaly_cases \
         (tenant_id,case_id,task_id,aggregate_id,severity,status,recovery_conditions,response_epoch,resource_version) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(task_id)
    .bind(parse_uuid(&aggregate.aggregate_id)?)
    .bind(risk_level_name(aggregate.severity))
    .bind(status)
    .bind(response.recovery_conditions.iter().cloned().collect::<Vec<_>>())
    .bind(i64::try_from(response.new_revocation_epoch)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    Ok(())
}

async fn append_evidence_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    event_kind: &str,
    subject_id: &str,
    payload: &Value,
) -> Result<String, RuntimeAnomalyAuthorityError> {
    let payload_digest = canonical_digest(payload)?;
    let previous = sqlx::query_scalar::<_, String>(
        "SELECT event_digest FROM runtime_anomaly_evidence_events WHERE tenant_id=$1 \
         ORDER BY created_at DESC,event_id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    let event_id = Uuid::new_v4();
    let event_digest = canonical_digest(&json!({
        "tenant_id": tenant_id,
        "event_id": event_id,
        "event_kind": event_kind,
        "subject_id": subject_id,
        "payload_digest": payload_digest,
        "previous_event_digest": previous,
    }))?;
    sqlx::query(
        "INSERT INTO runtime_anomaly_evidence_events \
         (tenant_id,event_id,event_kind,subject_id,payload,payload_digest,previous_event_digest,event_digest) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tenant_id)
    .bind(event_id)
    .bind(event_kind)
    .bind(subject_id)
    .bind(payload)
    .bind(&payload_digest)
    .bind(previous)
    .bind(event_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    let outbox_id = Uuid::new_v4();
    let idempotency_key = format!("runtime-anomaly:evidence:{event_id}");
    sqlx::query(
        "INSERT INTO runtime_anomaly_evidence_outbox \
         (tenant_id,outbox_id,event_id,idempotency_key,payload,payload_digest,state) \
         VALUES ($1,$2,$3,$4,$5,$6,'PENDING')",
    )
    .bind(tenant_id)
    .bind(outbox_id)
    .bind(event_id)
    .bind(idempotency_key)
    .bind(payload)
    .bind(payload_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    Ok(format!("outbox://runtime-anomaly/{outbox_id}"))
}

async fn existing_signal_outbox(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    subject_id: &str,
) -> Result<String, RuntimeAnomalyAuthorityError> {
    let outbox_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT o.outbox_id FROM runtime_anomaly_evidence_events e \
         JOIN runtime_anomaly_evidence_outbox o ON o.tenant_id=e.tenant_id AND o.event_id=e.event_id \
         WHERE e.tenant_id=$1 AND e.event_kind='SIGNAL_INGESTED' AND e.subject_id=$2 \
         ORDER BY e.created_at LIMIT 1",
    )
    .bind(tenant_id)
    .bind(subject_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
    .ok_or(RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
    Ok(format!("outbox://runtime-anomaly/{outbox_id}"))
}

impl PostgresRuntimeAnomalyStore {
    async fn load_signal_evidence(
        &self,
        tenant: &TenantId,
        outbox_ref: &str,
    ) -> Result<Option<PendingSignalEvidence>, RuntimeAnomalyAuthorityError> {
        let outbox_id = outbox_ref
            .strip_prefix("outbox://runtime-anomaly/")
            .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)
            .and_then(parse_uuid)?;
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT event_id,outbox_id,idempotency_key,payload,payload_digest,state \
             FROM runtime_anomaly_evidence_outbox WHERE tenant_id=$1 AND outbox_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(outbox_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
        .ok_or(RuntimeAnomalyAuthorityError::NotFound)?;
        let state: String = row.get("state");
        if !matches!(state.as_str(), "PENDING" | "UNKNOWN" | "DELIVERED") {
            return Err(RuntimeAnomalyAuthorityError::StateConflict);
        }
        let pending = (state != "DELIVERED").then(|| PendingSignalEvidence {
            event_id: row.get("event_id"),
            outbox_id: row.get("outbox_id"),
            idempotency_key: row.get("idempotency_key"),
            payload: row.get("payload"),
            payload_digest: row.get("payload_digest"),
        });
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        Ok(pending)
    }

    async fn finalize_signal_evidence(
        &self,
        tenant: &TenantId,
        pending: PendingSignalEvidence,
        receipt: AnomalyEvidenceReceipt,
    ) -> Result<(), RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT state,payload_digest,evidence_ref,evidence_digest \
             FROM runtime_anomaly_evidence_outbox WHERE tenant_id=$1 AND outbox_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(pending.outbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        if row.get::<String, _>("payload_digest") != pending.payload_digest {
            return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
        }
        if row.get::<String, _>("state") == "DELIVERED" {
            if row.get::<Option<String>, _>("evidence_ref").as_deref()
                != Some(receipt.evidence_ref.as_str())
                || row.get::<Option<String>, _>("evidence_digest").as_deref()
                    != Some(receipt.evidence_digest.as_str())
            {
                return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
            }
        } else {
            sqlx::query(
                "UPDATE runtime_anomaly_evidence_outbox SET state='DELIVERED',evidence_ref=$3,\
                 evidence_digest=$4,delivered_at=now(),delivery_owner=NULL,delivery_lease_until=NULL \
                 WHERE tenant_id=$1 AND outbox_id=$2 AND state IN ('PENDING','UNKNOWN')",
            )
            .bind(tenant_uuid)
            .bind(pending.outbox_id)
            .bind(&receipt.evidence_ref)
            .bind(&receipt.evidence_digest)
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        }
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)
    }

    async fn pending_signal_evidence_refs(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<Vec<String>, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT o.outbox_id FROM runtime_anomaly_evidence_outbox o \
             JOIN runtime_anomaly_evidence_events e ON e.tenant_id=o.tenant_id AND e.event_id=o.event_id \
             WHERE o.tenant_id=$1 AND e.event_kind='SIGNAL_INGESTED' \
               AND o.state IN ('PENDING','UNKNOWN') ORDER BY o.created_at \
             FOR UPDATE OF o SKIP LOCKED LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        Ok(rows
            .into_iter()
            .map(|value| format!("outbox://runtime-anomaly/{value}"))
            .collect())
    }
}

#[derive(Clone)]
pub struct RuntimeAnomalyAuthority {
    store: PostgresRuntimeAnomalyStore,
    orchestrator: Arc<dyn RuntimeAnomalyOrchestratorPort>,
    effects: Arc<dyn RuntimeAnomalyEffectsPort>,
    config: RuntimeAnomalyAuthorityConfig,
    response_controller: Arc<ContinuousAuthorizationController>,
}

#[derive(Clone)]
pub struct RuntimeAnomalyExecutor {
    store: PostgresRuntimeAnomalyStore,
    effects: Arc<dyn RuntimeAnomalyEffectsPort>,
    execution_owner: Uuid,
    execution_lease_seconds: i64,
    response_verifying_key: VerifyingKey,
}

impl RuntimeAnomalyExecutor {
    pub fn new(
        store: PostgresRuntimeAnomalyStore,
        effects: Arc<dyn RuntimeAnomalyEffectsPort>,
        execution_owner: Uuid,
        execution_lease_seconds: i64,
        response_verifying_key: VerifyingKey,
    ) -> Result<Self, RuntimeAnomalyAuthorityError> {
        if execution_owner.is_nil() || !(15..=300).contains(&execution_lease_seconds) {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            effects,
            execution_owner,
            execution_lease_seconds,
            response_verifying_key,
        })
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.effects.ready().await
    }

    pub async fn execute(
        &self,
        binding: RuntimeAnomalyExecutionBinding,
        request: RuntimeAnomalyExecutorRequest,
    ) -> Result<RuntimeAnomalyMutationResult, RuntimeAnomalyAuthorityError> {
        validate_execution(&binding, &request)?;
        match self
            .store
            .claim_execution(
                &binding,
                &request,
                self.execution_owner,
                self.execution_lease_seconds,
            )
            .await?
        {
            ExecutionClaim::Completed(result) => Ok(result),
            ExecutionClaim::EvidencePending(pending) => {
                self.deliver_and_finalize(&binding.tenant_id, pending).await
            }
            ExecutionClaim::Claimed => {
                let effect_receipt = if request.command.operation
                    == RuntimeAnomalyOperation::ApplyContinuousAuthorization
                {
                    let response: crate::ResponseCommand =
                        serde_json::from_value(request.command.payload.clone())
                            .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
                    validate_response_command(
                        &binding,
                        &request,
                        &response,
                        &self.response_verifying_key,
                    )?;
                    let receipt = self.effects.apply_response(&binding, &response).await;
                    match receipt {
                        Ok(receipt) => {
                            validate_response_receipt(&binding, &response, &receipt)?;
                            Some(receipt)
                        }
                        Err(RuntimeAnomalyAuthorityError::OutcomeUnknown) => {
                            self.store.mark_execution_unknown(&binding).await?;
                            return Err(RuntimeAnomalyAuthorityError::OutcomeUnknown);
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    None
                };
                let pending = self
                    .store
                    .commit_mutation(&binding, &request, effect_receipt.as_ref())
                    .await?;
                self.deliver_and_finalize(&binding.tenant_id, pending).await
            }
        }
    }

    async fn deliver_and_finalize(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
    ) -> Result<RuntimeAnomalyMutationResult, RuntimeAnomalyAuthorityError> {
        let receipt = self
            .effects
            .publish_evidence(
                tenant,
                pending.event_id,
                &pending.idempotency_key,
                &pending.payload,
                &pending.payload_digest,
            )
            .await?;
        validate_evidence_receipt(&pending, &receipt)?;
        self.store.finalize_evidence(tenant, pending, receipt).await
    }

    pub async fn recover_pending_evidence(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<Vec<RuntimeAnomalyMutationResult>, RuntimeAnomalyAuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
        }
        let pending = self.store.pending_evidence(tenant, limit).await?;
        let mut results = Vec::with_capacity(pending.len());
        for item in pending {
            results.push(self.deliver_and_finalize(tenant, item).await?);
        }
        Ok(results)
    }
}

#[derive(Debug)]
enum ExecutionClaim {
    Completed(RuntimeAnomalyMutationResult),
    EvidencePending(PendingEvidence),
    Claimed,
}

#[derive(Debug, Clone)]
struct PendingEvidence {
    ledger_execution_id: Uuid,
    event_id: Uuid,
    outbox_id: Uuid,
    idempotency_key: String,
    payload: Value,
    payload_digest: String,
    result: RuntimeAnomalyMutationResult,
}

#[derive(Debug, Clone)]
struct PendingSignalEvidence {
    event_id: Uuid,
    outbox_id: Uuid,
    idempotency_key: String,
    payload: Value,
    payload_digest: String,
}

impl RuntimeAnomalyAuthority {
    pub fn new(
        store: PostgresRuntimeAnomalyStore,
        orchestrator: Arc<dyn RuntimeAnomalyOrchestratorPort>,
        effects: Arc<dyn RuntimeAnomalyEffectsPort>,
        config: RuntimeAnomalyAuthorityConfig,
        response_controller: Arc<ContinuousAuthorizationController>,
    ) -> Result<Self, RuntimeAnomalyAuthorityError> {
        config.validate()?;
        RuleDetector::new(
            config.rule_version.clone(),
            config.slow_exfiltration_distinct_domains,
            config.repeated_side_effect_limit,
        )
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        Ok(Self {
            store,
            orchestrator,
            effects,
            config,
            response_controller,
        })
    }

    pub async fn ready(&self) -> bool {
        let (store, orchestrator, effects) = tokio::join!(
            self.store.ready(),
            self.orchestrator.ready(),
            self.effects.ready(),
        );
        store && orchestrator && effects
    }

    pub async fn consume(
        &self,
        tenant: TenantId,
        workload_identity: &str,
        envelope: SignedRiskSignalEnvelope,
    ) -> Result<SignalIngestReceipt, RuntimeAnomalyAuthorityError> {
        validate_signed_envelope(&tenant, workload_identity, &envelope, &self.config)?;
        let persisted = self
            .store
            .persist_signal_decision(
                &tenant,
                workload_identity,
                &envelope,
                &self.config,
                &self.response_controller,
            )
            .await?;
        let mut result = persisted.receipt;
        if let Some(response_request) = persisted.response_request {
            let idempotency_key = format!(
                "runtime-anomaly:response:{}",
                response_request.command.command_id
            );
            let request_digest = canonical_digest(&response_request)?;
            let prepared = self
                .store
                .prepare_ingress(
                    &tenant,
                    &self.config.service_subject,
                    &response_request.command,
                    &request_digest,
                    &idempotency_key,
                    canonical_runtime_action(&response_request, &self.config, &idempotency_key)?,
                )
                .await?;
            let receipt = if let Some(receipt) = prepared.receipt {
                receipt
            } else {
                match self.orchestrator.submit(&tenant, &prepared.envelope).await {
                    Ok(receipt) => {
                        self.store
                            .complete_ingress(&tenant, &idempotency_key, &receipt)
                            .await?
                    }
                    Err(RuntimeAnomalyAuthorityError::OutcomeUnknown) => {
                        self.store
                            .mark_ingress_unknown(&tenant, &idempotency_key)
                            .await?;
                        return Err(RuntimeAnomalyAuthorityError::OutcomeUnknown);
                    }
                    Err(error) => return Err(error),
                }
            };
            result.response_action_id = Some(receipt.action_id);
        }
        self.deliver_signal_evidence(&tenant, &result.evidence_outbox_ref)
            .await?;
        Ok(result)
    }

    async fn deliver_signal_evidence(
        &self,
        tenant: &TenantId,
        outbox_ref: &str,
    ) -> Result<(), RuntimeAnomalyAuthorityError> {
        let Some(pending) = self.store.load_signal_evidence(tenant, outbox_ref).await? else {
            return Ok(());
        };
        let receipt = self
            .effects
            .publish_evidence(
                tenant,
                pending.event_id,
                &pending.idempotency_key,
                &pending.payload,
                &pending.payload_digest,
            )
            .await?;
        validate_signal_evidence_receipt(&pending, &receipt)?;
        self.store
            .finalize_signal_evidence(tenant, pending, receipt)
            .await
    }

    pub async fn recover_signal_evidence(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<usize, RuntimeAnomalyAuthorityError> {
        if !(1..=100).contains(&limit) {
            return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
        }
        let refs = self
            .store
            .pending_signal_evidence_refs(tenant, limit)
            .await?;
        let mut delivered = 0usize;
        for value in refs {
            self.deliver_signal_evidence(tenant, &value).await?;
            delivered = delivered.saturating_add(1);
        }
        Ok(delivered)
    }

    pub async fn submit_admin_action(
        &self,
        tenant: TenantId,
        actor_subject: String,
        request: RuntimeAnomalyCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<RuntimeAnomalyActionReceipt, RuntimeAnomalyAuthorityError> {
        validate_admin_command(
            &tenant,
            &actor_subject,
            &request,
            request_digest,
            idempotency_key,
        )?;
        if request.operation == RuntimeAnomalyOperation::ApplyContinuousAuthorization {
            return Err(RuntimeAnomalyAuthorityError::PrincipalDenied);
        }
        let executor_request = RuntimeAnomalyExecutorRequest {
            schema_version: ANOMALY_EXECUTOR_REQUEST_SCHEMA.into(),
            command: request.clone(),
            actor_subject: actor_subject.clone(),
            actor_kind: "HUMAN".into(),
            approval_ids: BTreeSet::new(),
        };
        let prepared = self
            .store
            .prepare_ingress(
                &tenant,
                &actor_subject,
                &request,
                request_digest,
                idempotency_key,
                canonical_runtime_action(&executor_request, &self.config, idempotency_key)?,
            )
            .await?;
        if let Some(receipt) = prepared.receipt {
            return Ok(receipt);
        }
        let receipt = self
            .orchestrator
            .submit(&tenant, &prepared.envelope)
            .await?;
        self.store
            .complete_ingress(&tenant, idempotency_key, &receipt)
            .await
    }

    pub async fn authoritative_trajectories(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativeTrajectoryPage, RuntimeAnomalyAuthorityError> {
        self.store
            .authoritative_trajectories(tenant, after, limit)
            .await
    }
}

#[derive(Debug)]
struct PreparedIngress {
    envelope: InboundEnvelope,
    receipt: Option<RuntimeAnomalyActionReceipt>,
}

#[derive(Debug)]
struct PersistedSignalDecision {
    receipt: SignalIngestReceipt,
    response_request: Option<RuntimeAnomalyExecutorRequest>,
}

#[derive(Debug)]
struct SourceRecord {
    key_id: String,
    public_key: Vec<u8>,
    allowed_signal_kinds: Vec<String>,
    workload_identity: String,
    status: String,
}

#[derive(Debug)]
struct TrajectoryRecord {
    state: TrajectoryState,
    agent_instance_id: AgentInstanceId,
    revocation_epoch: u64,
    status: String,
    resource_version: u64,
}

impl PostgresRuntimeAnomalyStore {
    #[allow(clippy::too_many_arguments)]
    async fn persist_signal_decision(
        &self,
        tenant: &TenantId,
        workload_identity: &str,
        envelope: &SignedRiskSignalEnvelope,
        config: &RuntimeAnomalyAuthorityConfig,
        controller: &ContinuousAuthorizationController,
    ) -> Result<PersistedSignalDecision, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let event_id = parse_uuid(&envelope.signal.event_id)?;
        let task_uuid = parse_uuid(&envelope.signal.task_id.0)?;
        let payload_digest = signed_envelope_digest(envelope)?;
        let mut tx = self.begin_tenant(tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{tenant_uuid}:{task_uuid}"))
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;

        let source = load_source(&mut tx, tenant_uuid, &envelope.source_id).await?;
        verify_source_and_signature(&source, workload_identity, envelope, &payload_digest)?;
        let mut trajectory = load_trajectory(&mut tx, tenant_uuid, task_uuid).await?;
        if trajectory.agent_instance_id != envelope.signal.agent_instance_id
            || !matches!(
                trajectory.status.as_str(),
                "ACTIVE" | "APPROVAL_REQUIRED" | "PAUSED"
            )
        {
            return Err(RuntimeAnomalyAuthorityError::StateConflict);
        }
        let now = Utc::now();
        let skew = Duration::seconds(config.maximum_signal_clock_skew_seconds);
        if envelope.signal.occurred_at > now + skew
            || envelope.signal.occurred_at < trajectory.state.first_seen_at - skew
        {
            return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
        }

        let signature = URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .map_err(|_| RuntimeAnomalyAuthorityError::SignatureInvalid)?;
        let inserted = sqlx::query(
            "INSERT INTO runtime_anomaly_signals \
             (tenant_id,event_id,task_id,agent_instance_id,source_id,signal_kind,action,resource,\
              resource_class,safe_features,confidence_millionths,source_version,occurred_at,\
              payload_digest,signature_key_id,signature) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) \
             ON CONFLICT (tenant_id,event_id) DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(event_id)
        .bind(task_uuid)
        .bind(parse_uuid(&envelope.signal.agent_instance_id.0)?)
        .bind(&envelope.source_id)
        .bind(signal_kind_name(envelope.signal.kind))
        .bind(&envelope.signal.action)
        .bind(&envelope.signal.resource)
        .bind(&envelope.signal.resource_class)
        .bind(&envelope.signal.value)
        .bind(
            i32::try_from(envelope.signal.confidence_millionths)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
        )
        .bind(&envelope.signal.source_version)
        .bind(envelope.signal.occurred_at)
        .bind(&payload_digest)
        .bind(&envelope.key_id)
        .bind(signature)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
        .rows_affected()
            == 1;

        if !inserted {
            let row = sqlx::query(
                "SELECT payload_digest FROM runtime_anomaly_signals \
                 WHERE tenant_id=$1 AND event_id=$2",
            )
            .bind(tenant_uuid)
            .bind(event_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            if row.get::<String, _>("payload_digest") != payload_digest {
                return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
            }
            let outbox =
                existing_signal_outbox(&mut tx, tenant_uuid, &envelope.signal.event_id).await?;
            tx.commit()
                .await
                .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            return Ok(PersistedSignalDecision {
                receipt: SignalIngestReceipt {
                    schema_version: SIGNAL_RECEIPT_SCHEMA.into(),
                    event_id: envelope.signal.event_id.clone(),
                    task_id: envelope.signal.task_id.0.clone(),
                    payload_digest,
                    duplicate: true,
                    finding_ids: Vec::new(),
                    aggregate_id: None,
                    response_action_id: None,
                    local_authorization_status: trajectory.status,
                    revocation_epoch: trajectory.revocation_epoch,
                    evidence_outbox_ref: outbox,
                },
                response_request: None,
            });
        }

        trajectory.state.event_count = trajectory.state.event_count.saturating_add(1);
        trajectory.state.last_seen_at = trajectory
            .state
            .last_seen_at
            .max(envelope.signal.occurred_at);
        sqlx::query(
            "UPDATE runtime_anomaly_trajectories SET event_count=$3,last_seen_at=$4,\
             resource_version=resource_version+1 WHERE tenant_id=$1 AND task_id=$2",
        )
        .bind(tenant_uuid)
        .bind(task_uuid)
        .bind(
            i64::try_from(trajectory.state.event_count)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
        )
        .bind(trajectory.state.last_seen_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        trajectory.resource_version = trajectory.resource_version.saturating_add(1);

        let signals = load_recent_signals(
            &mut tx,
            tenant_uuid,
            task_uuid,
            config.maximum_signal_lookback,
        )
        .await?;
        let detector = RuleDetector::new(
            config.rule_version.clone(),
            config.slow_exfiltration_distinct_domains,
            config.repeated_side_effect_limit,
        )
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let findings = detector.evaluate(&trajectory.state, &signals);
        let aggregate = RiskAggregator::update(
            &trajectory.state,
            findings.clone(),
            envelope.semantic_score.clone(),
            envelope.semantic_score.is_some(),
        );
        let finding_ids = persist_findings(&mut tx, tenant_uuid, task_uuid, &findings).await?;
        persist_aggregate(
            &mut tx,
            tenant_uuid,
            task_uuid,
            &aggregate,
            &finding_ids,
            &config.rule_bundle_digest,
        )
        .await?;

        let response = controller
            .adjust(&aggregate, trajectory.revocation_epoch)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let actionable = response.adjustment != AuthorizationAdjustment::NoChange;
        if actionable {
            let next_status = match response.adjustment {
                AuthorizationAdjustment::Kill => "KILLED",
                AuthorizationAdjustment::Pause
                | AuthorizationAdjustment::RevokeLease
                | AuthorizationAdjustment::RevokeCredential => "PAUSED",
                AuthorizationAdjustment::RequireApproval | AuthorizationAdjustment::ReduceScope => {
                    "APPROVAL_REQUIRED"
                }
                _ => trajectory.status.as_str(),
            };
            sqlx::query(
                "UPDATE runtime_anomaly_trajectories SET status=$3,revocation_epoch=$4,\
                 resource_version=resource_version+1 WHERE tenant_id=$1 AND task_id=$2",
            )
            .bind(tenant_uuid)
            .bind(task_uuid)
            .bind(next_status)
            .bind(
                i64::try_from(response.new_revocation_epoch)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            trajectory.status = next_status.into();
            trajectory.revocation_epoch = response.new_revocation_epoch;
            persist_response(&mut tx, tenant_uuid, task_uuid, &aggregate, &response).await?;
            persist_case(&mut tx, tenant_uuid, task_uuid, &aggregate, &response).await?;
        }

        let evidence_payload = json!({
            "schema_version": ANOMALY_SCHEMA_VERSION,
            "event_kind": "SIGNAL_INGESTED",
            "event_id": &envelope.signal.event_id,
            "task_id": &envelope.signal.task_id,
            "source_id": &envelope.source_id,
            "payload_digest": &payload_digest,
            "finding_ids": &finding_ids,
            "aggregate_id": &aggregate.aggregate_id,
            "response_id": actionable.then_some(response.response_id.clone()),
            "authorization_status": &trajectory.status,
            "revocation_epoch": trajectory.revocation_epoch,
            "rule_bundle_digest": &config.rule_bundle_digest,
            "detector_degraded": aggregate.detector_degraded,
            "evidence_occurred_at": envelope.signal.occurred_at,
        });
        let evidence_outbox_ref = append_evidence_event(
            &mut tx,
            tenant_uuid,
            "SIGNAL_INGESTED",
            &envelope.signal.event_id,
            &evidence_payload,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;

        let response_request = if actionable {
            Some(RuntimeAnomalyExecutorRequest {
                schema_version: ANOMALY_EXECUTOR_REQUEST_SCHEMA.into(),
                command: RuntimeAnomalyCommandRequest {
                    schema_version: ANOMALY_COMMAND_SCHEMA.into(),
                    tenant_id: tenant_uuid,
                    command_id: parse_uuid(&response.response_id)?,
                    task_id: task_uuid,
                    resource: format!("trajectory/{task_uuid}"),
                    operation: RuntimeAnomalyOperation::ApplyContinuousAuthorization,
                    expected_resource_version: trajectory.resource_version.saturating_add(1),
                    requested_at: response.issued_at,
                    payload: serde_json::to_value(&response)
                        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
                },
                actor_subject: config.service_subject.clone(),
                actor_kind: "SERVICE".into(),
                approval_ids: BTreeSet::new(),
            })
        } else {
            None
        };
        Ok(PersistedSignalDecision {
            receipt: SignalIngestReceipt {
                schema_version: SIGNAL_RECEIPT_SCHEMA.into(),
                event_id: envelope.signal.event_id.clone(),
                task_id: envelope.signal.task_id.0.clone(),
                payload_digest,
                duplicate: false,
                finding_ids,
                aggregate_id: Some(aggregate.aggregate_id),
                response_action_id: None,
                local_authorization_status: trajectory.status,
                revocation_epoch: trajectory.revocation_epoch,
                evidence_outbox_ref,
            },
            response_request,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_ingress(
        &self,
        tenant: &TenantId,
        actor_subject: &str,
        request: &RuntimeAnomalyCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        envelope: InboundEnvelope,
    ) -> Result<PreparedIngress, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let envelope_value = serde_json::to_value(&envelope)
            .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
        let admitted_hash = action_hash(&action)
            .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?
            .0;
        let mut tx = self.begin_tenant(tenant).await?;
        sqlx::query(
            "INSERT INTO runtime_anomaly_action_ingress \
             (tenant_id,idempotency_key,command_id,task_id,actor_subject,operation,resource,\
              request_digest,canonical_action_hash,canonical_envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED') ON CONFLICT DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .bind(request.command_id)
        .bind(request.task_id)
        .bind(actor_subject)
        .bind(request.operation.as_str())
        .bind(&request.resource)
        .bind(request_digest)
        .bind(&admitted_hash)
        .bind(&envelope_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::IdempotencyConflict)?;
        let row = sqlx::query(
            "SELECT command_id,task_id,actor_subject,operation,resource,request_digest,\
                    canonical_action_hash,canonical_envelope,state,orchestrator_receipt \
             FROM runtime_anomaly_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
        .ok_or(RuntimeAnomalyAuthorityError::IdempotencyConflict)?;
        let stored_envelope: InboundEnvelope =
            serde_json::from_value(row.get("canonical_envelope"))
                .map_err(|_| RuntimeAnomalyAuthorityError::IdempotencyConflict)?;
        let stored_action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&stored_envelope.payload)
                .map_err(|_| RuntimeAnomalyAuthorityError::IdempotencyConflict)?;
        let stored_hash = action_hash(&stored_action)
            .map_err(|_| RuntimeAnomalyAuthorityError::IdempotencyConflict)?
            .0;
        if row.get::<Uuid, _>("command_id") != request.command_id
            || row.get::<Uuid, _>("task_id") != request.task_id
            || row.get::<String, _>("actor_subject") != actor_subject
            || row.get::<String, _>("operation") != request.operation.as_str()
            || row.get::<String, _>("resource") != request.resource
            || row.get::<String, _>("request_digest") != request_digest
            || row.get::<String, _>("canonical_action_hash") != stored_hash
            || stored_hash != admitted_hash
            || stored_envelope.schema_version != GATEWAY_SCHEMA_VERSION
            || stored_envelope.content_type != "application/json"
            || stored_envelope.idempotency_key.as_deref() != Some(idempotency_key)
            || stored_envelope.tenant_context.tenant_id != *tenant
            || stored_envelope.identity_context.tenant_id != *tenant
            || stored_envelope.identity_context.owner_subject != actor_subject
            || stored_envelope.payload_hash != sha256(&stored_envelope.payload)
            || stored_action.action_id.0 != request.command_id.to_string()
            || stored_action.task_id.0 != request.task_id.to_string()
            || !matches!(
                row.get::<String, _>("state").as_str(),
                "PREPARED" | "ACCEPTED"
            )
        {
            return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("orchestrator_receipt")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        Ok(PreparedIngress {
            envelope: stored_envelope,
            receipt,
        })
    }

    async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &RuntimeAnomalyActionReceipt,
    ) -> Result<RuntimeAnomalyActionReceipt, RuntimeAnomalyAuthorityError> {
        validate_action_receipt(receipt)?;
        let tenant_uuid = parse_tenant(tenant)?;
        let receipt_value = serde_json::to_value(receipt)
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT command_id,task_id,state,orchestrator_receipt \
             FROM runtime_anomaly_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?
        .ok_or(RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("command_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("orchestrator_receipt") {
            if existing != receipt_value || row.get::<String, _>("state") != "ACCEPTED" {
                return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
            }
        } else {
            let updated = sqlx::query(
                "UPDATE runtime_anomaly_action_ingress SET state='ACCEPTED',\
                 orchestrator_receipt=$3,orchestrator_evidence_ref=$4,\
                 orchestrator_evidence_digest=$5,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&receipt_value)
            .bind(&receipt.ledger_evidence_ref)
            .bind(&receipt.ledger_evidence_digest)
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
            }
        }
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }

    async fn mark_ingress_unknown(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
    ) -> Result<(), RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        sqlx::query(
            "UPDATE runtime_anomaly_action_ingress SET state='UNKNOWN',updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)
    }

    async fn authoritative_trajectories(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativeTrajectoryPage, RuntimeAnomalyAuthorityError> {
        if !(1..=200).contains(&limit) || after.is_some_and(|value| !canonical_uuid(value)) {
            return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let after_uuid = after.map(parse_uuid).transpose()?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT t.task_id,t.agent_instance_id,t.agent_type,t.domain,t.status,t.event_count,\
                    t.revocation_epoch,t.resource_version,t.last_seen_at,\
                    (SELECT a.severity FROM runtime_anomaly_aggregates a \
                     WHERE a.tenant_id=t.tenant_id AND a.task_id=t.task_id \
                     ORDER BY a.computed_at DESC,a.aggregate_id DESC LIMIT 1) latest_severity,\
                    (SELECT count(*) FROM runtime_anomaly_cases c \
                     WHERE c.tenant_id=t.tenant_id AND c.task_id=t.task_id AND c.status<>'CLOSED') open_case_count \
             FROM runtime_anomaly_trajectories t WHERE t.tenant_id=$1 \
               AND ($2::uuid IS NULL OR t.task_id>$2) ORDER BY t.task_id LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(after_uuid)
        .bind(limit.saturating_add(1))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        let has_more = rows.len() > usize::try_from(limit).unwrap_or(0);
        let mut items = rows
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(0))
            .map(|row| {
                Ok(AuthoritativeTrajectory {
                    task_id: row.get("task_id"),
                    agent_instance_id: row.get("agent_instance_id"),
                    agent_type: row.get("agent_type"),
                    domain: row.get("domain"),
                    status: row.get("status"),
                    event_count: u64::try_from(row.get::<i64, _>("event_count"))
                        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
                    revocation_epoch: u64::try_from(row.get::<i64, _>("revocation_epoch"))
                        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
                    resource_version: u64::try_from(row.get::<i64, _>("resource_version"))
                        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
                    last_seen_at: row.get("last_seen_at"),
                    latest_severity: row.get("latest_severity"),
                    open_case_count: u64::try_from(row.get::<i64, _>("open_case_count"))
                        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?,
                })
            })
            .collect::<Result<Vec<_>, RuntimeAnomalyAuthorityError>>()?;
        let next_after = has_more
            .then(|| items.last().map(|value| value.task_id.to_string()))
            .flatten();
        let data_digest = canonical_digest(&json!({
            "schema_version": "agenttrust.authoritative-runtime-anomaly-page.v1",
            "tenant_id": tenant,
            "authoritative": true,
            "items": &items,
            "next_after": &next_after,
        }))?;
        Ok(AuthoritativeTrajectoryPage {
            schema_version: "agenttrust.authoritative-runtime-anomaly-page.v1".into(),
            tenant_id: tenant.clone(),
            authoritative: true,
            items: std::mem::take(&mut items),
            next_after,
            data_digest,
        })
    }

    async fn claim_execution(
        &self,
        binding: &RuntimeAnomalyExecutionBinding,
        request: &RuntimeAnomalyExecutorRequest,
        owner: Uuid,
        lease_seconds: i64,
    ) -> Result<ExecutionClaim, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let ingress = sqlx::query(
            "SELECT canonical_action_hash,state,command_id,task_id FROM runtime_anomaly_action_ingress \
             WHERE tenant_id=$1 AND command_id=$2 FOR SHARE",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
        .ok_or(RuntimeAnomalyAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("canonical_action_hash") != binding.action_hash
            || ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<Uuid, _>("task_id") != request.command.task_id
        {
            return Err(RuntimeAnomalyAuthorityError::PrincipalDenied);
        }
        sqlx::query(
            "INSERT INTO runtime_anomaly_authority_executions \
             (tenant_id,ledger_execution_id,command_id,action_hash,ledger_event_id,\
              ledger_event_digest,fence_digest,resource_version,policy_decision_id,\
              policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,\
              idempotency_key,trace_id,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'PREPARED') \
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(binding.ledger_execution_id)
        .bind(request.command.command_id)
        .bind(&binding.action_hash)
        .bind(binding.ledger_event_id)
        .bind(&binding.ledger_event_digest)
        .bind(&binding.fence_digest)
        .bind(
            i64::try_from(binding.resource_version)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
        )
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(&binding.idempotency_key)
        .bind(&binding.trace_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::IdempotencyConflict)?;
        let row = sqlx::query(
            "SELECT command_id,action_hash,ledger_event_id,ledger_event_digest,fence_digest,\
                    resource_version,policy_decision_id,policy_decision_digest,\
                    authorization_evidence_ref,authorization_evidence_digest,idempotency_key,\
                    trace_id,state,execution_owner,execution_lease_until,result \
             FROM runtime_anomaly_authority_executions \
             WHERE tenant_id=$1 AND ledger_execution_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(binding.ledger_execution_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        if row.get::<Uuid, _>("command_id") != request.command.command_id
            || row.get::<String, _>("action_hash") != binding.action_hash
            || row.get::<Uuid, _>("ledger_event_id") != binding.ledger_event_id
            || row.get::<String, _>("ledger_event_digest") != binding.ledger_event_digest
            || row.get::<String, _>("fence_digest") != binding.fence_digest
            || row.get::<i64, _>("resource_version")
                != i64::try_from(binding.resource_version)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?
            || row.get::<String, _>("policy_decision_id") != binding.policy_decision_id
            || row.get::<String, _>("policy_decision_digest") != binding.policy_decision_digest
            || row.get::<String, _>("authorization_evidence_ref")
                != binding.authorization_evidence_ref
            || row.get::<String, _>("authorization_evidence_digest")
                != binding.authorization_evidence_digest
            || row.get::<String, _>("idempotency_key") != binding.idempotency_key
            || row.get::<String, _>("trace_id") != binding.trace_id
        {
            return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
        }
        let state: String = row.get("state");
        if state == "SUCCEEDED" {
            let result: RuntimeAnomalyMutationResult = serde_json::from_value(
                row.get::<Option<Value>, _>("result")
                    .ok_or(RuntimeAnomalyAuthorityError::OutcomeUnknown)?,
            )
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
            tx.commit()
                .await
                .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            return Ok(ExecutionClaim::Completed(result));
        }
        if state == "MUTATED_PENDING_EVIDENCE" {
            let pending =
                load_pending_for_execution(&mut tx, tenant_uuid, binding.ledger_execution_id)
                    .await?;
            tx.commit()
                .await
                .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            return Ok(ExecutionClaim::EvidencePending(pending));
        }
        if state == "UNKNOWN" {
            return Err(RuntimeAnomalyAuthorityError::OutcomeUnknown);
        }
        let lease_until: Option<DateTime<Utc>> = row.get("execution_lease_until");
        let current_owner: Option<Uuid> = row.get("execution_owner");
        if lease_until.is_some_and(|value| value > Utc::now()) && current_owner != Some(owner) {
            return Err(RuntimeAnomalyAuthorityError::StateConflict);
        }
        let next_state =
            if request.command.operation == RuntimeAnomalyOperation::ApplyContinuousAuthorization {
                "RESPONSE_PENDING"
            } else {
                "PREPARED"
            };
        sqlx::query(
            "UPDATE runtime_anomaly_authority_executions SET state=$3,execution_owner=$4,\
             execution_lease_until=now()+make_interval(secs=>$5),updated_at=now() \
             WHERE tenant_id=$1 AND ledger_execution_id=$2",
        )
        .bind(tenant_uuid)
        .bind(binding.ledger_execution_id)
        .bind(next_state)
        .bind(owner)
        .bind(f64::from(i32::try_from(lease_seconds).map_err(|_| {
            RuntimeAnomalyAuthorityError::ConfigurationInvalid
        })?))
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        Ok(ExecutionClaim::Claimed)
    }

    async fn mark_execution_unknown(
        &self,
        binding: &RuntimeAnomalyExecutionBinding,
    ) -> Result<(), RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        sqlx::query(
            "UPDATE runtime_anomaly_authority_executions SET state='UNKNOWN',\
             execution_owner=NULL,execution_lease_until=NULL,updated_at=now() \
             WHERE tenant_id=$1 AND ledger_execution_id=$2 AND state='RESPONSE_PENDING'",
        )
        .bind(tenant_uuid)
        .bind(binding.ledger_execution_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)
    }

    async fn commit_mutation(
        &self,
        binding: &RuntimeAnomalyExecutionBinding,
        request: &RuntimeAnomalyExecutorRequest,
        response_receipt: Option<&RuntimeResponseReceipt>,
    ) -> Result<PendingEvidence, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let execution_state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM runtime_anomaly_authority_executions \
             WHERE tenant_id=$1 AND ledger_execution_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(binding.ledger_execution_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        let expected_state =
            if request.command.operation == RuntimeAnomalyOperation::ApplyContinuousAuthorization {
                "RESPONSE_PENDING"
            } else {
                "PREPARED"
            };
        if execution_state != expected_state {
            return Err(RuntimeAnomalyAuthorityError::StateConflict);
        }
        let resource_version = if let Some(receipt) = response_receipt {
            apply_response_receipt(&mut tx, tenant_uuid, binding, request, receipt).await?
        } else {
            apply_admin_mutation(&mut tx, tenant_uuid, request).await?
        };
        let process_outcome = response_receipt
            .map(|value| value.safe_status.clone())
            .unwrap_or_else(|| "ADMIN_MUTATION_APPLIED".into());
        let evidence_payload = json!({
            "schema_version": ANOMALY_SCHEMA_VERSION,
            "event_kind": if response_receipt.is_some() { "RESPONSE_APPLIED" } else { "ADMIN_MUTATION" },
            "command_id": request.command.command_id,
            "task_id": request.command.task_id,
            "operation": request.command.operation,
            "resource": request.command.resource,
            "resource_version": resource_version,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "ledger_event_id": binding.ledger_event_id,
            "ledger_event_digest": binding.ledger_event_digest,
            "fence_digest": binding.fence_digest,
            "policy_decision_id": binding.policy_decision_id,
            "policy_decision_digest": binding.policy_decision_digest,
            "authorization_evidence_ref": binding.authorization_evidence_ref,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "process_outcome": process_outcome,
            "evidence_occurred_at": request.command.requested_at,
        });
        let pending_ids = append_mutation_evidence(
            &mut tx,
            tenant_uuid,
            binding.ledger_execution_id,
            if response_receipt.is_some() {
                "RESPONSE_APPLIED"
            } else {
                "ADMIN_MUTATION"
            },
            &request.command.command_id.to_string(),
            &evidence_payload,
        )
        .await?;
        let evidence_outbox_ref = format!("outbox://runtime-anomaly/{}", pending_ids.1);
        let mut result = RuntimeAnomalyMutationResult {
            schema_version: ANOMALY_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            operation: request.command.operation.clone(),
            resource: request.command.resource.clone(),
            resource_version,
            task_execution_succeeded: true,
            process_outcome,
            result_digest: String::new(),
            evidence_outbox_ref,
            evidence_ref: None,
        };
        result.result_digest = canonical_digest(&result_without_digest(&result))?;
        let result_value = serde_json::to_value(&result)
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "UPDATE runtime_anomaly_authority_executions SET state='MUTATED_PENDING_EVIDENCE',\
             result=$3,result_digest=$4,execution_owner=NULL,execution_lease_until=NULL,updated_at=now() \
             WHERE tenant_id=$1 AND ledger_execution_id=$2",
        )
        .bind(tenant_uuid)
        .bind(binding.ledger_execution_id)
        .bind(&result_value)
        .bind(&result.result_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        Ok(PendingEvidence {
            ledger_execution_id: binding.ledger_execution_id,
            event_id: pending_ids.0,
            outbox_id: pending_ids.1,
            idempotency_key: pending_ids.2,
            payload: evidence_payload,
            payload_digest: pending_ids.3,
            result,
        })
    }

    async fn finalize_evidence(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
        receipt: AnomalyEvidenceReceipt,
    ) -> Result<RuntimeAnomalyMutationResult, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT state,payload_digest,evidence_ref,evidence_digest FROM runtime_anomaly_evidence_outbox \
             WHERE tenant_id=$1 AND outbox_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(pending.outbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        if row.get::<String, _>("payload_digest") != pending.payload_digest {
            return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
        }
        if row.get::<String, _>("state") == "DELIVERED" {
            if row.get::<Option<String>, _>("evidence_ref").as_deref()
                != Some(receipt.evidence_ref.as_str())
                || row.get::<Option<String>, _>("evidence_digest").as_deref()
                    != Some(receipt.evidence_digest.as_str())
            {
                return Err(RuntimeAnomalyAuthorityError::IdempotencyConflict);
            }
        } else {
            sqlx::query(
                "UPDATE runtime_anomaly_evidence_outbox SET state='DELIVERED',\
                 evidence_ref=$3,evidence_digest=$4,delivered_at=now(),delivery_owner=NULL,\
                 delivery_lease_until=NULL WHERE tenant_id=$1 AND outbox_id=$2",
            )
            .bind(tenant_uuid)
            .bind(pending.outbox_id)
            .bind(&receipt.evidence_ref)
            .bind(&receipt.evidence_digest)
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        }
        let mut result = pending.result;
        result.evidence_ref = Some(receipt.evidence_ref.clone());
        result.result_digest = canonical_digest(&result_without_digest(&result))?;
        let result_value = serde_json::to_value(&result)
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        let updated = sqlx::query(
            "UPDATE runtime_anomaly_authority_executions SET state='SUCCEEDED',result=$3,\
             result_digest=$4,evidence_ref=$5,evidence_digest=$6,updated_at=now() \
             WHERE tenant_id=$1 AND ledger_execution_id=$2 \
               AND state IN ('MUTATED_PENDING_EVIDENCE','SUCCEEDED')",
        )
        .bind(tenant_uuid)
        .bind(pending.ledger_execution_id)
        .bind(result_value)
        .bind(&result.result_digest)
        .bind(&receipt.evidence_ref)
        .bind(&receipt.evidence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        if updated.rows_affected() != 1 {
            return Err(RuntimeAnomalyAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        Ok(result)
    }

    async fn pending_evidence(
        &self,
        tenant: &TenantId,
        limit: i64,
    ) -> Result<Vec<PendingEvidence>, RuntimeAnomalyAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT e.ledger_execution_id,o.event_id,o.outbox_id,o.idempotency_key,o.payload,\
                    o.payload_digest,e.result FROM runtime_anomaly_authority_executions e \
             JOIN runtime_anomaly_evidence_outbox o ON o.tenant_id=e.tenant_id \
               AND o.idempotency_key='runtime-anomaly:execution:'||e.ledger_execution_id::text \
             WHERE e.tenant_id=$1 AND e.state='MUTATED_PENDING_EVIDENCE' \
               AND o.state IN ('PENDING','UNKNOWN') ORDER BY o.created_at FOR UPDATE SKIP LOCKED LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        let mut pending = Vec::with_capacity(rows.len());
        for row in rows {
            let result: RuntimeAnomalyMutationResult = serde_json::from_value(row.get("result"))
                .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
            pending.push(PendingEvidence {
                ledger_execution_id: row.get("ledger_execution_id"),
                event_id: row.get("event_id"),
                outbox_id: row.get("outbox_id"),
                idempotency_key: row.get("idempotency_key"),
                payload: row.get("payload"),
                payload_digest: row.get("payload_digest"),
                result,
            });
        }
        tx.commit()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        Ok(pending)
    }
}

async fn load_pending_for_execution(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    execution_id: Uuid,
) -> Result<PendingEvidence, RuntimeAnomalyAuthorityError> {
    let row = sqlx::query(
        "SELECT e.result,o.event_id,o.outbox_id,o.idempotency_key,o.payload,o.payload_digest \
         FROM runtime_anomaly_authority_executions e \
         JOIN runtime_anomaly_evidence_outbox o ON o.tenant_id=e.tenant_id \
           AND o.idempotency_key='runtime-anomaly:execution:'||e.ledger_execution_id::text \
         WHERE e.tenant_id=$1 AND e.ledger_execution_id=$2",
    )
    .bind(tenant_id)
    .bind(execution_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
    .ok_or(RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
    Ok(PendingEvidence {
        ledger_execution_id: execution_id,
        event_id: row.get("event_id"),
        outbox_id: row.get("outbox_id"),
        idempotency_key: row.get("idempotency_key"),
        payload: row.get("payload"),
        payload_digest: row.get("payload_digest"),
        result: serde_json::from_value(row.get("result"))
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?,
    })
}

async fn append_mutation_evidence(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    execution_id: Uuid,
    event_kind: &str,
    subject_id: &str,
    payload: &Value,
) -> Result<(Uuid, Uuid, String, String), RuntimeAnomalyAuthorityError> {
    let payload_digest = canonical_digest(payload)?;
    let previous = sqlx::query_scalar::<_, String>(
        "SELECT event_digest FROM runtime_anomaly_evidence_events WHERE tenant_id=$1 \
         ORDER BY created_at DESC,event_id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    let event_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let idempotency_key = format!("runtime-anomaly:execution:{execution_id}");
    let event_digest = canonical_digest(&json!({
        "tenant_id": tenant_id,
        "event_id": event_id,
        "event_kind": event_kind,
        "subject_id": subject_id,
        "payload_digest": payload_digest,
        "previous_event_digest": previous,
    }))?;
    sqlx::query(
        "INSERT INTO runtime_anomaly_evidence_events \
         (tenant_id,event_id,event_kind,subject_id,payload,payload_digest,previous_event_digest,event_digest) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tenant_id)
    .bind(event_id)
    .bind(event_kind)
    .bind(subject_id)
    .bind(payload)
    .bind(&payload_digest)
    .bind(previous)
    .bind(event_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    sqlx::query(
        "INSERT INTO runtime_anomaly_evidence_outbox \
         (tenant_id,outbox_id,event_id,idempotency_key,payload,payload_digest,state) \
         VALUES ($1,$2,$3,$4,$5,$6,'PENDING')",
    )
    .bind(tenant_id)
    .bind(outbox_id)
    .bind(event_id)
    .bind(&idempotency_key)
    .bind(payload)
    .bind(&payload_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    Ok((event_id, outbox_id, idempotency_key, payload_digest))
}

async fn apply_response_receipt(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    binding: &RuntimeAnomalyExecutionBinding,
    request: &RuntimeAnomalyExecutorRequest,
    receipt: &RuntimeResponseReceipt,
) -> Result<u64, RuntimeAnomalyAuthorityError> {
    let response: crate::ResponseCommand = serde_json::from_value(request.command.payload.clone())
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    let command_digest = canonical_digest(&response)?;
    let row = sqlx::query(
        "SELECT state,task_id,command_digest,new_revocation_epoch FROM runtime_anomaly_response_commands \
         WHERE tenant_id=$1 AND response_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(receipt.response_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
    .ok_or(RuntimeAnomalyAuthorityError::NotFound)?;
    if row.get::<Uuid, _>("task_id") != receipt.task_id
        || row.get::<String, _>("command_digest") != command_digest
        || row.get::<String, _>("state") != "PENDING"
    {
        return Err(RuntimeAnomalyAuthorityError::StateConflict);
    }
    sqlx::query(
        "UPDATE runtime_anomaly_response_commands SET state='APPLIED',applied_at=now(),\
         supervisor_receipt_digest=$3,credential_receipt_digest=$4,incident_receipt_digest=$5 \
         WHERE tenant_id=$1 AND response_id=$2 AND state='PENDING'",
    )
    .bind(tenant_id)
    .bind(receipt.response_id)
    .bind(&receipt.supervisor_receipt_digest)
    .bind(&receipt.credential_receipt_digest)
    .bind(&receipt.incident_receipt_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    let resource_version = sqlx::query_scalar::<_, i64>(
        "SELECT resource_version FROM runtime_anomaly_trajectories \
         WHERE tenant_id=$1 AND task_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(request.command.task_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    if u64::try_from(resource_version)
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
        != binding.resource_version
        || binding.resource_version != request.command.expected_resource_version
    {
        return Err(RuntimeAnomalyAuthorityError::StateConflict);
    }
    Ok(binding.resource_version)
}

async fn apply_admin_mutation(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    request: &RuntimeAnomalyExecutorRequest,
) -> Result<u64, RuntimeAnomalyAuthorityError> {
    let command = &request.command;
    match command.operation {
        RuntimeAnomalyOperation::RegisterSource => {
            if command.expected_resource_version != 0 {
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            }
            let payload: RegisterSourcePayload = decode_payload(&command.payload)?;
            validate_register_source(&payload, &command.resource)?;
            let public_key = URL_SAFE_NO_PAD
                .decode(&payload.ed25519_public_key_base64)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
            sqlx::query(
                "INSERT INTO runtime_anomaly_signal_sources \
                 (tenant_id,source_id,key_id,ed25519_public_key,allowed_signal_kinds,\
                  workload_identity,status,resource_version) \
                 VALUES ($1,$2,$3,$4,$5,$6,'ACTIVE',1)",
            )
            .bind(tenant_id)
            .bind(&payload.source_id)
            .bind(&payload.key_id)
            .bind(public_key)
            .bind(&payload.allowed_signal_kinds)
            .bind(&payload.workload_identity)
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::StateConflict)?;
            Ok(1)
        }
        RuntimeAnomalyOperation::RevokeSource => {
            let payload: RevokeSourcePayload = decode_payload(&command.payload)?;
            if command.resource != format!("source/{}", payload.source_id)
                || !digest(&payload.reason_digest)
                || !evidence_reference(&payload.approval_evidence_ref)
                || payload.approval_id.is_nil()
                || payload
                    .replacement_source_id
                    .as_ref()
                    .is_some_and(|value| value == &payload.source_id || !identifier(value, 128))
            {
                return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
            }
            if let Some(replacement) = &payload.replacement_source_id {
                let active = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM runtime_anomaly_signal_sources \
                     WHERE tenant_id=$1 AND source_id=$2 AND status='ACTIVE')",
                )
                .bind(tenant_id)
                .bind(replacement)
                .fetch_one(&mut **tx)
                .await
                .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
                if !active {
                    return Err(RuntimeAnomalyAuthorityError::StateConflict);
                }
            }
            let updated = sqlx::query(
                "UPDATE runtime_anomaly_signal_sources SET status='REVOKED',\
                 resource_version=resource_version+1,updated_at=now() \
                 WHERE tenant_id=$1 AND source_id=$2 AND status='ACTIVE' AND resource_version=$3",
            )
            .bind(tenant_id)
            .bind(&payload.source_id)
            .bind(
                i64::try_from(command.expected_resource_version)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
            )
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            if updated.rows_affected() != 1 {
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            }
            Ok(command.expected_resource_version.saturating_add(1))
        }
        RuntimeAnomalyOperation::StartTrajectory => {
            if command.expected_resource_version != 0
                || command.resource != format!("trajectory/{}", command.task_id)
            {
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            }
            let payload: StartTrajectoryPayload = decode_payload(&command.payload)?;
            validate_start_trajectory(&payload)?;
            sqlx::query(
                "INSERT INTO runtime_anomaly_trajectories \
                 (tenant_id,task_id,agent_instance_id,agent_type,domain,goal_hash,plan_hash,\
                  allowed_resource_prefixes,allowed_network_destinations,authorization_lease_id,\
                  revocation_epoch,status,event_count,resource_version,started_at,last_seen_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'ACTIVE',0,1,$12,$12)",
            )
            .bind(tenant_id)
            .bind(command.task_id)
            .bind(payload.agent_instance_id)
            .bind(payload.agent_type)
            .bind(payload.domain)
            .bind(payload.goal_hash)
            .bind(payload.plan_hash)
            .bind(payload.allowed_resource_prefixes)
            .bind(payload.allowed_network_destinations)
            .bind(payload.authorization_lease_id)
            .bind(
                i64::try_from(payload.revocation_epoch)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
            )
            .bind(command.requested_at)
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::StateConflict)?;
            Ok(1)
        }
        RuntimeAnomalyOperation::UpdateBaseline => {
            let payload: BaselinePayload = decode_payload(&command.payload)?;
            validate_baseline(&payload, &command.resource)?;
            let updated = if command.expected_resource_version == 0 {
                sqlx::query(
                    "INSERT INTO runtime_anomaly_baselines \
                     (tenant_id,baseline_id,agent_type,domain,maximum_calls_per_minute,\
                      maximum_distinct_resources,maximum_destination_fanout,sample_count,\
                      threshold_version,approval_id,approval_evidence_ref,baseline_digest,\
                      resource_version,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,'ACTIVE') \
                     ON CONFLICT DO NOTHING",
                )
                .bind(tenant_id)
                .bind(payload.baseline_id)
                .bind(payload.agent_type)
                .bind(payload.domain)
                .bind(i32::try_from(payload.maximum_calls_per_minute)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
                .bind(i32::try_from(payload.maximum_distinct_resources)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
                .bind(i32::try_from(payload.maximum_destination_fanout)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
                .bind(i64::try_from(payload.sample_count)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
                .bind(payload.threshold_version)
                .bind(payload.approval_id)
                .bind(payload.approval_evidence_ref)
                .bind(payload.baseline_digest)
                .execute(&mut **tx)
                .await
                .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
                .rows_affected()
            } else {
                // Baselines are versioned immutable records: a new threshold_version/baseline_id
                // is required. In-place loosening is never allowed through feedback.
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            };
            if updated != 1 {
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            }
            Ok(1)
        }
        RuntimeAnomalyOperation::RecordFeedback => {
            if command.expected_resource_version != 0 {
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            }
            let payload: FeedbackPayload = decode_payload(&command.payload)?;
            validate_feedback(&payload, &command.resource, &request.actor_subject)?;
            sqlx::query(
                "INSERT INTO runtime_anomaly_feedback \
                 (tenant_id,feedback_id,finding_id,label,annotation_digest,reviewer_subject,\
                  approval_id,evidence_ref) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(tenant_id)
            .bind(payload.feedback_id)
            .bind(payload.finding_id)
            .bind(payload.label)
            .bind(payload.annotation_digest)
            .bind(payload.reviewer_subject)
            .bind(payload.approval_id)
            .bind(payload.evidence_ref)
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::StateConflict)?;
            Ok(1)
        }
        RuntimeAnomalyOperation::AcknowledgeCase => {
            let payload: CaseTransitionPayload = decode_payload(&command.payload)?;
            validate_case_transition(&payload, &command.resource, false)?;
            let updated = sqlx::query(
                "UPDATE runtime_anomaly_cases SET status='CONTAINING',resource_version=resource_version+1 \
                 WHERE tenant_id=$1 AND case_id=$2 AND status='OPEN' AND resource_version=$3",
            )
            .bind(tenant_id)
            .bind(payload.case_id)
            .bind(i64::try_from(command.expected_resource_version)
                .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?)
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            ensure_one(updated.rows_affected())?;
            Ok(command.expected_resource_version.saturating_add(1))
        }
        RuntimeAnomalyOperation::RecoverPausedTask => {
            let payload: CaseTransitionPayload = decode_payload(&command.payload)?;
            validate_case_transition(&payload, &command.resource, true)?;
            let new_lease = payload
                .new_authorization_lease_id
                .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)?;
            let case = sqlx::query(
                "SELECT task_id,status FROM runtime_anomaly_cases \
                 WHERE tenant_id=$1 AND case_id=$2 FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(payload.case_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?
            .ok_or(RuntimeAnomalyAuthorityError::NotFound)?;
            let task_id: Uuid = case.get("task_id");
            if task_id != command.task_id
                || !matches!(
                    case.get::<String, _>("status").as_str(),
                    "PAUSED" | "CONTAINING"
                )
            {
                return Err(RuntimeAnomalyAuthorityError::StateConflict);
            }
            let updated = sqlx::query(
                "UPDATE runtime_anomaly_trajectories SET status='ACTIVE',authorization_lease_id=$3,\
                 revocation_epoch=revocation_epoch+1,resource_version=resource_version+1 \
                 WHERE tenant_id=$1 AND task_id=$2 AND status IN ('PAUSED','APPROVAL_REQUIRED') \
                   AND resource_version=$4",
            )
            .bind(tenant_id)
            .bind(task_id)
            .bind(new_lease)
            .bind(
                i64::try_from(command.expected_resource_version)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
            )
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            ensure_one(updated.rows_affected())?;
            sqlx::query(
                "UPDATE runtime_anomaly_cases SET status='RECOVERING',resource_version=resource_version+1 \
                 WHERE tenant_id=$1 AND case_id=$2",
            )
            .bind(tenant_id)
            .bind(payload.case_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            Ok(command.expected_resource_version.saturating_add(1))
        }
        RuntimeAnomalyOperation::CompleteTrajectory => {
            let payload: CompleteTrajectoryPayload = decode_payload(&command.payload)?;
            if command.resource != format!("trajectory/{}", command.task_id)
                || !evidence_reference(&payload.completion_evidence_ref)
                || !digest(&payload.completion_evidence_digest)
            {
                return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
            }
            let updated = sqlx::query(
                "UPDATE runtime_anomaly_trajectories SET status='COMPLETED',completed_at=now(),\
                 resource_version=resource_version+1 WHERE tenant_id=$1 AND task_id=$2 \
                 AND status='ACTIVE' AND resource_version=$3",
            )
            .bind(tenant_id)
            .bind(command.task_id)
            .bind(
                i64::try_from(command.expected_resource_version)
                    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?,
            )
            .execute(&mut **tx)
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
            ensure_one(updated.rows_affected())?;
            Ok(command.expected_resource_version.saturating_add(1))
        }
        RuntimeAnomalyOperation::ApplyContinuousAuthorization => {
            Err(RuntimeAnomalyAuthorityError::RequestInvalid)
        }
    }
}

fn validate_signed_envelope(
    tenant: &TenantId,
    workload_identity: &str,
    envelope: &SignedRiskSignalEnvelope,
    config: &RuntimeAnomalyAuthorityConfig,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    crate::validate_signal(&envelope.signal)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    if envelope.schema_version != SIGNED_SIGNAL_SCHEMA
        || envelope.signal.tenant_id != *tenant
        || !canonical_uuid(&envelope.signal.event_id)
        || !canonical_uuid(&envelope.signal.task_id.0)
        || !canonical_uuid(&envelope.signal.agent_instance_id.0)
        || !identifier(&envelope.source_id, 128)
        || !identifier(&envelope.key_id, 128)
        || !(workload_identity.starts_with("DNS:") || workload_identity.starts_with("URI:"))
        || envelope.signature.len() < 80
        || envelope.signature.len() > 128
        || envelope.signal.action.len() > 128
        || envelope.signal.resource.len() > 1024
        || envelope.signal.resource_class.len() > 128
        || envelope.signal.occurred_at < Utc::now() - Duration::days(30)
        || signed_envelope_bytes(envelope)?.len() > 1_048_576
        || !safe_json_document(&envelope.signal.value)
        || contains_secret_material(&envelope.signal.action)
        || contains_secret_material(&envelope.signal.resource)
        || contains_secret_material(&envelope.signal.value.to_string())
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    if let Some(score) = &envelope.semantic_score
        && (score.schema_version != ANOMALY_SCHEMA_VERSION
            || !identifier(&score.model_id, 128)
            || !identifier(&score.model_version, 128)
            || score.score_millionths > 1_000_000
            || score.confidence_millionths > 1_000_000
            || score.reason_codes.len() > 64
            || score
                .reason_codes
                .iter()
                .any(|value| !identifier(value, 128)))
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    config.validate()
}

fn verify_source_and_signature(
    source: &SourceRecord,
    workload_identity: &str,
    envelope: &SignedRiskSignalEnvelope,
    payload_digest: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if source.status != "ACTIVE"
        || source.key_id != envelope.key_id
        || source.workload_identity != workload_identity
        || !source
            .allowed_signal_kinds
            .iter()
            .any(|value| value == signal_kind_name(envelope.signal.kind))
        || source.public_key.len() != 32
    {
        return Err(RuntimeAnomalyAuthorityError::SourceDenied);
    }
    let key_bytes: [u8; 32] = source
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeAnomalyAuthorityError::SourceDenied)?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| RuntimeAnomalyAuthorityError::SourceDenied)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .map_err(|_| RuntimeAnomalyAuthorityError::SignatureInvalid)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| RuntimeAnomalyAuthorityError::SignatureInvalid)?;
    let bytes = signed_envelope_bytes(envelope)?;
    if sha256(&bytes) != payload_digest {
        return Err(RuntimeAnomalyAuthorityError::SignatureInvalid);
    }
    key.verify(&bytes, &signature)
        .map_err(|_| RuntimeAnomalyAuthorityError::SignatureInvalid)
}

fn signed_envelope_bytes(
    envelope: &SignedRiskSignalEnvelope,
) -> Result<Vec<u8>, RuntimeAnomalyAuthorityError> {
    serde_jcs::to_vec(&json!({
        "schema_version": envelope.schema_version,
        "source_id": envelope.source_id,
        "key_id": envelope.key_id,
        "signal": envelope.signal,
        "semantic_score": envelope.semantic_score,
    }))
    .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn signed_envelope_digest(
    envelope: &SignedRiskSignalEnvelope,
) -> Result<String, RuntimeAnomalyAuthorityError> {
    Ok(sha256(&signed_envelope_bytes(envelope)?))
}

fn validate_admin_command(
    tenant: &TenantId,
    actor_subject: &str,
    request: &RuntimeAnomalyCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if request.schema_version != ANOMALY_COMMAND_SCHEMA
        || request.tenant_id.to_string() != tenant.0
        || request.command_id.is_nil()
        || request.task_id.is_nil()
        || !identifier(actor_subject, 256)
        || !resource_identifier(&request.resource)
        || !digest(request_digest)
        || !(16..=256).contains(&idempotency_key.len())
        || !idempotency_key
            .bytes()
            .all(|value| value.is_ascii_graphic())
        || request.requested_at < Utc::now() - Duration::minutes(5)
        || request.requested_at > Utc::now() + Duration::minutes(2)
        || canonical_digest(request)? != request_digest
        || serde_jcs::to_vec(&request.payload)
            .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?
            .len()
            > 1_048_576
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    validate_operation_payload(request, actor_subject)
}

fn validate_operation_payload(
    request: &RuntimeAnomalyCommandRequest,
    actor_subject: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    match request.operation {
        RuntimeAnomalyOperation::RegisterSource => {
            let payload: RegisterSourcePayload = decode_payload(&request.payload)?;
            validate_register_source(&payload, &request.resource)
        }
        RuntimeAnomalyOperation::RevokeSource => {
            let payload: RevokeSourcePayload = decode_payload(&request.payload)?;
            if request.resource == format!("source/{}", payload.source_id)
                && digest(&payload.reason_digest)
                && !payload.approval_id.is_nil()
                && evidence_reference(&payload.approval_evidence_ref)
                && payload
                    .replacement_source_id
                    .as_ref()
                    .is_none_or(|value| value != &payload.source_id && identifier(value, 128))
            {
                Ok(())
            } else {
                Err(RuntimeAnomalyAuthorityError::RequestInvalid)
            }
        }
        RuntimeAnomalyOperation::StartTrajectory => {
            let payload: StartTrajectoryPayload = decode_payload(&request.payload)?;
            if request.resource == format!("trajectory/{}", request.task_id) {
                validate_start_trajectory(&payload)
            } else {
                Err(RuntimeAnomalyAuthorityError::RequestInvalid)
            }
        }
        RuntimeAnomalyOperation::UpdateBaseline => {
            let payload: BaselinePayload = decode_payload(&request.payload)?;
            validate_baseline(&payload, &request.resource)
        }
        RuntimeAnomalyOperation::RecordFeedback => {
            let payload: FeedbackPayload = decode_payload(&request.payload)?;
            validate_feedback(&payload, &request.resource, actor_subject)
        }
        RuntimeAnomalyOperation::AcknowledgeCase => {
            let payload: CaseTransitionPayload = decode_payload(&request.payload)?;
            validate_case_transition(&payload, &request.resource, false)
        }
        RuntimeAnomalyOperation::RecoverPausedTask => {
            let payload: CaseTransitionPayload = decode_payload(&request.payload)?;
            validate_case_transition(&payload, &request.resource, true)
        }
        RuntimeAnomalyOperation::CompleteTrajectory => {
            let payload: CompleteTrajectoryPayload = decode_payload(&request.payload)?;
            if request.resource == format!("trajectory/{}", request.task_id)
                && evidence_reference(&payload.completion_evidence_ref)
                && digest(&payload.completion_evidence_digest)
            {
                Ok(())
            } else {
                Err(RuntimeAnomalyAuthorityError::RequestInvalid)
            }
        }
        RuntimeAnomalyOperation::ApplyContinuousAuthorization => {
            Err(RuntimeAnomalyAuthorityError::PrincipalDenied)
        }
    }
}

fn validate_execution(
    binding: &RuntimeAnomalyExecutionBinding,
    request: &RuntimeAnomalyExecutorRequest,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if binding.schema_version != ANOMALY_EXECUTION_BINDING_SCHEMA
        || request.schema_version != ANOMALY_EXECUTOR_REQUEST_SCHEMA
        || request.command.schema_version != ANOMALY_COMMAND_SCHEMA
        || request.command.tenant_id.to_string() != binding.tenant_id.0
        || request.command.command_id.is_nil()
        || request.command.task_id.is_nil()
        || !digest(&binding.action_hash)
        || binding.ledger_execution_id.is_nil()
        || binding.ledger_event_id.is_nil()
        || !digest(&binding.ledger_event_digest)
        || !digest(&binding.fence_digest)
        || binding.resource_version != request.command.expected_resource_version
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !evidence_reference(&binding.authorization_evidence_ref)
        || !digest(&binding.authorization_evidence_digest)
        || !(16..=256).contains(&binding.idempotency_key.len())
        || !identifier(&binding.trace_id, 128)
        || !identifier(&request.actor_subject, 256)
        || !matches!(request.actor_kind.as_str(), "HUMAN" | "SERVICE")
        || request.approval_ids.len() > 16
        || request
            .approval_ids
            .iter()
            .any(|value| !canonical_uuid(value))
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    if request.command.operation == RuntimeAnomalyOperation::ApplyContinuousAuthorization {
        if request.actor_kind != "SERVICE" || !request.approval_ids.is_empty() {
            return Err(RuntimeAnomalyAuthorityError::PrincipalDenied);
        }
        Ok(())
    } else {
        validate_operation_payload(&request.command, &request.actor_subject)
    }
}

fn validate_response_command(
    binding: &RuntimeAnomalyExecutionBinding,
    request: &RuntimeAnomalyExecutorRequest,
    response: &crate::ResponseCommand,
    verifying_key: &VerifyingKey,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if response.schema_version != ANOMALY_SCHEMA_VERSION
        || response.response_id != request.command.command_id.to_string()
        || response.task_id.0 != request.command.task_id.to_string()
        || response.tenant_id != binding.tenant_id
        || response.adjustment == AuthorizationAdjustment::NoChange
        || !digest(&response.evidence_digest)
        || response.reason_codes.len() > 64
        || response.recovery_conditions.len() > 32
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    response
        .verify(verifying_key, Utc::now())
        .map_err(|_| RuntimeAnomalyAuthorityError::SignatureInvalid)
}

fn validate_response_receipt(
    binding: &RuntimeAnomalyExecutionBinding,
    response: &crate::ResponseCommand,
    receipt: &RuntimeResponseReceipt,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if receipt.schema_version != ANOMALY_RESPONSE_RECEIPT_SCHEMA
        || receipt.tenant_id.to_string() != binding.tenant_id.0
        || receipt.response_id.to_string() != response.response_id
        || receipt.task_id.to_string() != response.task_id.0
        || receipt.adjustment != response.adjustment
        || receipt.command_digest != canonical_digest(response)?
        || !identifier(&receipt.safe_status, 128)
        || receipt
            .supervisor_receipt_digest
            .as_ref()
            .is_some_and(|value| !digest(value))
        || receipt
            .credential_receipt_digest
            .as_ref()
            .is_some_and(|value| !digest(value))
        || receipt
            .incident_receipt_digest
            .as_ref()
            .is_some_and(|value| !digest(value))
    {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    let required_supervisor = matches!(
        response.adjustment,
        AuthorizationAdjustment::RequireApproval
            | AuthorizationAdjustment::ReduceScope
            | AuthorizationAdjustment::Pause
            | AuthorizationAdjustment::RevokeLease
            | AuthorizationAdjustment::RevokeCredential
            | AuthorizationAdjustment::Kill
    );
    let required_credential = response.adjustment == AuthorizationAdjustment::RevokeCredential;
    let required_incident = matches!(
        response.adjustment,
        AuthorizationAdjustment::Pause
            | AuthorizationAdjustment::RevokeLease
            | AuthorizationAdjustment::RevokeCredential
            | AuthorizationAdjustment::Kill
    );
    if required_supervisor != receipt.supervisor_receipt_digest.is_some()
        || required_credential != receipt.credential_receipt_digest.is_some()
        || required_incident != receipt.incident_receipt_digest.is_some()
    {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn validate_evidence_receipt(
    pending: &PendingEvidence,
    receipt: &AnomalyEvidenceReceipt,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if receipt.schema_version != ANOMALY_EVIDENCE_RECEIPT_SCHEMA
        || receipt.idempotency_key != pending.idempotency_key
        || !evidence_reference(&receipt.evidence_ref)
        || !digest(&receipt.evidence_digest)
    {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn validate_signal_evidence_receipt(
    pending: &PendingSignalEvidence,
    receipt: &AnomalyEvidenceReceipt,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if receipt.schema_version != ANOMALY_EVIDENCE_RECEIPT_SCHEMA
        || receipt.idempotency_key != pending.idempotency_key
        || !evidence_reference(&receipt.evidence_ref)
        || !digest(&receipt.evidence_digest)
    {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn validate_action_receipt(
    receipt: &RuntimeAnomalyActionReceipt,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if receipt.schema_version == ANOMALY_ACTION_RECEIPT_SCHEMA
        && receipt.accepted
        && receipt.execution_pending
        && canonical_uuid(&receipt.action_id)
        && canonical_uuid(&receipt.task_id)
        && digest(&receipt.ingress_digest)
        && evidence_reference(&receipt.ledger_evidence_ref)
        && digest(&receipt.ledger_evidence_digest)
    {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::DependencyUnavailable)
    }
}

fn canonical_runtime_action(
    request: &RuntimeAnomalyExecutorRequest,
    config: &RuntimeAnomalyAuthorityConfig,
    idempotency_key: &str,
) -> Result<InboundEnvelope, RuntimeAnomalyAuthorityError> {
    let now = Utc::now();
    let command = &request.command;
    let tenant = TenantId(command.tenant_id.to_string());
    let data = serde_json::to_value(request)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)?;
    let plan_hash = canonical_digest(&json!({
        "operation": command.operation,
        "resource": command.resource,
        "expected_resource_version": command.expected_resource_version,
        "payload": command.payload,
    }))?;
    let operation = command.operation.as_str().to_ascii_lowercase();
    let mut extensions = BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    extensions.insert(
        "x-required-control-path".into(),
        Value::String("CANONICAL_ACTION_IR->PEP->LEDGER->EVIDENCE".into()),
    );
    extensions.insert(
        "x-continuous-authorization".into(),
        Value::String("FAIL_CLOSED_LOCAL_LEASE_AND_GOVERNED_EXTERNAL_RESPONSE".into()),
    );
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(command.command_id.to_string()),
        task_id: TaskId(command.task_id.to_string()),
        step_id: StepId::new(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "runtime-anomaly-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: request.actor_subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-runtime-anomaly".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: format!("workload-identity://{}", request.actor_subject),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: canonical_digest(command)?,
            operation: operation.clone(),
            justification_code: "CONTINUOUS_AUTHORIZATION_AND_RUNTIME_SAFETY".into(),
            safe_summary: Some(format!(
                "{} {}",
                command.operation.as_str(),
                command.resource
            )),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "runtime.anomaly.command.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator: format!("runtime-anomaly/{}", command.resource),
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: false,
        },
        current_state_version: Some(command.expected_resource_version.to_string()),
        risk: RiskContext {
            declared_risk: command.operation.risk(),
            trajectory_risk_ref: Some(format!("runtime-anomaly://task/{}", command.task_id)),
            scope_delta: 0,
            automation_allowed: command.operation
                == RuntimeAnomalyOperation::ApplyContinuousAuthorization,
        },
        data: DataContext {
            classification: DataClassification::Restricted,
            jurisdiction: config.region.clone(),
            export_constraints: vec![
                "TENANT_BOUND".into(),
                "SAFE_FEATURES_ONLY".into(),
                "NO_RAW_SECRET_OR_PRIVATE_REASONING".into(),
            ],
        },
        expected_outcome: ExpectedOutcome {
            metric: "runtime_authorization_state_and_evidence_closed".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "runtime-anomaly/".into(),
            operations: vec![operation],
        }],
        requested_at: command.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("runtime.anomaly.command.v1", "1");
    let action = normalize(draft, &normalization)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    let payload =
        serde_json::to_vec(&action).map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    Ok(InboundEnvelope {
        request_id: Uuid::new_v4().to_string(),
        trace_context: TraceContext {
            trace_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
            invalid_input_replaced: false,
        },
        identity_context: IdentityContext {
            subject: config.service_subject.clone(),
            tenant_id: tenant.clone(),
            agent_instance_id: config.service_agent_id.clone(),
            owner_subject: request.actor_subject.clone(),
            trust_level: "attested".into(),
        },
        tenant_context: TenantContext {
            tenant_id: tenant,
            quota_profile: "runtime-anomaly-authority".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: Some(idempotency_key.into()),
        received_at: now,
        payload_hash: sha256(&payload),
        payload,
    })
}

fn validate_register_source(
    payload: &RegisterSourcePayload,
    resource: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let public_key = URL_SAFE_NO_PAD
        .decode(&payload.ed25519_public_key_base64)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    let allowed = payload.allowed_signal_kinds.iter().collect::<BTreeSet<_>>();
    if resource == format!("source/{}", payload.source_id)
        && identifier(&payload.source_id, 128)
        && identifier(&payload.key_id, 128)
        && public_key.len() == 32
        && (1..=16).contains(&payload.allowed_signal_kinds.len())
        && allowed.len() == payload.allowed_signal_kinds.len()
        && payload
            .allowed_signal_kinds
            .iter()
            .all(|value| parse_signal_kind(value).is_ok())
        && (payload.workload_identity.starts_with("DNS:")
            || payload.workload_identity.starts_with("URI:"))
        && payload.workload_identity.len() <= 512
    {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::RequestInvalid)
    }
}

fn validate_start_trajectory(
    payload: &StartTrajectoryPayload,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if !payload.agent_instance_id.is_nil()
        && identifier(&payload.agent_type, 128)
        && identifier(&payload.domain, 128)
        && digest(&payload.goal_hash)
        && digest(&payload.plan_hash)
        && !payload.authorization_lease_id.is_nil()
        && (1..=1024).contains(&payload.allowed_resource_prefixes.len())
        && payload.allowed_resource_prefixes.iter().all(|value| {
            !value.is_empty() && value.len() <= 1024 && !contains_secret_material(value)
        })
        && payload
            .allowed_resource_prefixes
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == payload.allowed_resource_prefixes.len()
        && payload.allowed_network_destinations.len() <= 1024
        && payload.allowed_network_destinations.iter().all(|value| {
            identifier(value, 253)
                && !value
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
        })
    {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::RequestInvalid)
    }
}

fn validate_baseline(
    payload: &BaselinePayload,
    resource: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if resource == format!("baseline/{}", payload.baseline_id)
        && !payload.baseline_id.is_nil()
        && identifier(&payload.agent_type, 128)
        && identifier(&payload.domain, 128)
        && payload.maximum_calls_per_minute > 0
        && payload.maximum_distinct_resources > 0
        && payload.maximum_destination_fanout > 0
        && payload.sample_count >= 10
        && identifier(&payload.threshold_version, 128)
        && !payload.approval_id.is_nil()
        && evidence_reference(&payload.approval_evidence_ref)
        && digest(&payload.baseline_digest)
    {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::RequestInvalid)
    }
}

fn validate_feedback(
    payload: &FeedbackPayload,
    resource: &str,
    actor_subject: &str,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if resource == format!("finding/{}", payload.finding_id)
        && !payload.feedback_id.is_nil()
        && !payload.finding_id.is_nil()
        && matches!(
            payload.label.as_str(),
            "TRUE_POSITIVE" | "FALSE_POSITIVE" | "FALSE_NEGATIVE" | "INCONCLUSIVE"
        )
        && digest(&payload.annotation_digest)
        && payload.reviewer_subject == actor_subject
        && !payload.approval_id.is_nil()
        && evidence_reference(&payload.evidence_ref)
    {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::RequestInvalid)
    }
}

fn validate_case_transition(
    payload: &CaseTransitionPayload,
    resource: &str,
    recovery: bool,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    if resource == format!("case/{}", payload.case_id)
        && !payload.case_id.is_nil()
        && !payload.approval_id.is_nil()
        && evidence_reference(&payload.approval_evidence_ref)
        && (recovery == payload.new_authorization_lease_id.is_some())
        && payload
            .new_authorization_lease_id
            .is_none_or(|value| !value.is_nil())
    {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::RequestInvalid)
    }
}

fn decode_payload<T: for<'de> Deserialize<'de>>(
    value: &Value,
) -> Result<T, RuntimeAnomalyAuthorityError> {
    serde_json::from_value(value.clone()).map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn result_without_digest(result: &RuntimeAnomalyMutationResult) -> Value {
    json!({
        "schema_version": result.schema_version,
        "command_id": result.command_id,
        "operation": result.operation,
        "resource": result.resource,
        "resource_version": result.resource_version,
        "task_execution_succeeded": result.task_execution_succeeded,
        "process_outcome": result.process_outcome,
        "evidence_outbox_ref": result.evidence_outbox_ref,
        "evidence_ref": result.evidence_ref,
    })
}

fn canonical_digest<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, RuntimeAnomalyAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_tenant(tenant: &TenantId) -> Result<Uuid, RuntimeAnomalyAuthorityError> {
    parse_uuid(&tenant.0)
}

fn parse_uuid(value: &str) -> Result<Uuid, RuntimeAnomalyAuthorityError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    Ok(parsed)
}

fn canonical_uuid(value: &str) -> bool {
    parse_uuid(value).is_ok()
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn resource_identifier(value: &str) -> bool {
    identifier(value, 1024) && value.contains('/') && !value.contains("..")
}

fn evidence_reference(value: &str) -> bool {
    value.starts_with("evidence://") && identifier(value, 1024)
}

fn safe_json(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    *nodes = nodes.saturating_add(1);
    if depth > 16 || *nodes > 4096 {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => value.len() <= 4096,
        Value::Array(values) => {
            values.len() <= 1024
                && values
                    .iter()
                    .all(|value| safe_json(value, depth + 1, nodes))
        }
        Value::Object(values) => {
            values.len() <= 1024
                && values
                    .iter()
                    .all(|(key, value)| identifier(key, 128) && safe_json(value, depth + 1, nodes))
        }
    }
}

fn safe_json_document(value: &Value) -> bool {
    let mut nodes = 0usize;
    safe_json(value, 0, &mut nodes)
}

fn contains_secret_material(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "authorization: bearer ",
        "password=",
        "secret=",
        "api_key=",
        "access_token=",
        "refresh_token=",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn signal_kind_name(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Tool => "TOOL",
        SignalKind::Resource => "RESOURCE",
        SignalKind::Network => "NETWORK",
        SignalKind::File => "FILE",
        SignalKind::Credential => "CREDENTIAL",
        SignalKind::PolicyDeny => "POLICY_DENY",
        SignalKind::Approval => "APPROVAL",
        SignalKind::Process => "PROCESS",
        SignalKind::Telemetry => "TELEMETRY",
        SignalKind::AuditControl => "AUDIT_CONTROL",
    }
}

fn parse_signal_kind(value: &str) -> Result<SignalKind, RuntimeAnomalyAuthorityError> {
    match value {
        "TOOL" => Ok(SignalKind::Tool),
        "RESOURCE" => Ok(SignalKind::Resource),
        "NETWORK" => Ok(SignalKind::Network),
        "FILE" => Ok(SignalKind::File),
        "CREDENTIAL" => Ok(SignalKind::Credential),
        "POLICY_DENY" => Ok(SignalKind::PolicyDeny),
        "APPROVAL" => Ok(SignalKind::Approval),
        "PROCESS" => Ok(SignalKind::Process),
        "TELEMETRY" => Ok(SignalKind::Telemetry),
        "AUDIT_CONTROL" => Ok(SignalKind::AuditControl),
        _ => Err(RuntimeAnomalyAuthorityError::RequestInvalid),
    }
}

fn risk_level_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}

fn adjustment_name(adjustment: AuthorizationAdjustment) -> &'static str {
    adjustment.as_str()
}

fn ensure_one(rows: u64) -> Result<(), RuntimeAnomalyAuthorityError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(RuntimeAnomalyAuthorityError::StateConflict)
    }
}
