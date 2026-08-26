//! PostgreSQL-backed Platform SRE authority.
//!
//! A human request cannot mutate SRE state.  The ingress binds a strong human assertion to a
//! Canonical Action IR envelope and submits it to the durable orchestrator.  Only the executor
//! route may apply a typed mutation, after verifying the exact admitted action, PEP decision,
//! transaction-ledger event, resource fence and authorization evidence.  Domain state and a
//! durable Evidence outbox record commit in one tenant-RLS transaction.

use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector, RiskContext,
    RiskLevel, SchemaVersion, StepId, TaskId, TenantId, ToolId, ToolRef, ToolVersion,
    VerifiedHumanPrincipal,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const SRE_COMMAND_SCHEMA: &str = "agenttrust.sre-command.v1";
pub const SRE_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.sre-executor-request.v1";
pub const SRE_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.sre-action-receipt.v1";
pub const SRE_MUTATION_RESULT_SCHEMA: &str = "agenttrust.sre-mutation-result.v1";
pub const SRE_EXTERNAL_RECEIPT_SCHEMA: &str = "agenttrust.sre-external-receipt.v1";
pub const SRE_ENGINE_REPORT_SCHEMA: &str = "agenttrust.sre-engine-report.v1";
pub const SRE_READINESS_SCHEMA: &str = "agenttrust.sre-readiness.v1";
pub const SRE_RESOURCE_PAGE_SCHEMA: &str = "agenttrust.sre-resource-page.v1";
pub const SRE_LIFECYCLE_EVIDENCE_SCHEMA: &str = "agenttrust.sre-lifecycle-evidence.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SreAuthorityError {
    #[error("SRE_AUTHORITY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("SRE_AUTHORITY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("SRE_AUTHORITY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("SRE_AUTHORITY_STATE_CONFLICT")]
    StateConflict,
    #[error("SRE_AUTHORITY_NOT_FOUND")]
    NotFound,
    #[error("SRE_AUTHORITY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("SRE_AUTHORITY_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("SRE_AUTHORITY_EXTERNAL_RECEIPT_INVALID")]
    ExternalReceiptInvalid,
    #[error("SRE_AUTHORITY_CERTIFICATION_BOUNDARY")]
    CertificationBoundary,
    #[error("SRE_AUTHORITY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SreOperation {
    ConfigureSlo,
    RecordSli,
    UpdateBurnAlert,
    LinkIncident,
    RegisterTopology,
    RecordZoneHealth,
    CreateBackup,
    VerifyRestore,
    PlanDr,
    Failover,
    Failback,
    PlanChaos,
    ExecuteChaos,
    PlanLoad,
    ExecuteLoad,
    PlanUpgrade,
    RecordCanary,
    RollbackUpgrade,
    RecordCostCapacity,
    RecordObservability,
}

impl SreOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigureSlo => "CONFIGURE_SLO",
            Self::RecordSli => "RECORD_SLI",
            Self::UpdateBurnAlert => "UPDATE_BURN_ALERT",
            Self::LinkIncident => "LINK_INCIDENT",
            Self::RegisterTopology => "REGISTER_TOPOLOGY",
            Self::RecordZoneHealth => "RECORD_ZONE_HEALTH",
            Self::CreateBackup => "CREATE_BACKUP",
            Self::VerifyRestore => "VERIFY_RESTORE",
            Self::PlanDr => "PLAN_DR",
            Self::Failover => "FAILOVER",
            Self::Failback => "FAILBACK",
            Self::PlanChaos => "PLAN_CHAOS",
            Self::ExecuteChaos => "EXECUTE_CHAOS",
            Self::PlanLoad => "PLAN_LOAD",
            Self::ExecuteLoad => "EXECUTE_LOAD",
            Self::PlanUpgrade => "PLAN_UPGRADE",
            Self::RecordCanary => "RECORD_CANARY",
            Self::RollbackUpgrade => "ROLLBACK_UPGRADE",
            Self::RecordCostCapacity => "RECORD_COST_CAPACITY",
            Self::RecordObservability => "RECORD_OBSERVABILITY",
        }
    }

    fn required_role(self) -> &'static str {
        match self {
            Self::ConfigureSlo | Self::RecordSli | Self::UpdateBurnAlert | Self::LinkIncident => {
                "sre-operator"
            }
            Self::RegisterTopology
            | Self::RecordZoneHealth
            | Self::RecordCostCapacity
            | Self::RecordObservability => "platform-operator",
            Self::CreateBackup | Self::VerifyRestore | Self::PlanDr => "recovery-operator",
            Self::Failover | Self::Failback => "recovery-commander",
            Self::PlanChaos | Self::ExecuteChaos => "chaos-operator",
            Self::PlanLoad | Self::ExecuteLoad => "capacity-operator",
            Self::PlanUpgrade | Self::RecordCanary | Self::RollbackUpgrade => "release-manager",
        }
    }

    fn risk(self) -> RiskLevel {
        match self {
            Self::RecordSli
            | Self::RecordZoneHealth
            | Self::RecordCostCapacity
            | Self::RecordObservability => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    fn minimum_approvals(self) -> usize {
        match self {
            Self::Failover
            | Self::Failback
            | Self::ExecuteChaos
            | Self::ExecuteLoad
            | Self::PlanUpgrade
            | Self::RollbackUpgrade => 2,
            Self::CreateBackup
            | Self::VerifyRestore
            | Self::RegisterTopology
            | Self::PlanChaos
            | Self::PlanLoad => 1,
            _ => 0,
        }
    }

    pub(crate) fn external_effect(self) -> bool {
        matches!(
            self,
            Self::RecordZoneHealth
                | Self::CreateBackup
                | Self::VerifyRestore
                | Self::Failover
                | Self::Failback
                | Self::ExecuteChaos
                | Self::ExecuteLoad
                | Self::RollbackUpgrade
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalEvidenceStatus {
    NotRun,
    Observed,
    Verified,
}

impl ExternalEvidenceStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "NOT_RUN",
            Self::Observed => "OBSERVED",
            Self::Verified => "VERIFIED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SreCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub task_id: Uuid,
    pub resource: String,
    pub operation: SreOperation,
    pub expected_resource_version: u64,
    pub requested_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SreExecutorRequest {
    pub schema_version: String,
    pub command: SreCommandRequest,
    pub actor_subject: String,
    pub principal_assertion_digest: String,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SreExecutionBinding {
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
pub struct SreActionReceipt {
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
pub struct SreExternalReceipt {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub operation: SreOperation,
    pub resource: String,
    pub idempotency_key: String,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub request_digest: String,
    pub result_digest: String,
    pub immutable_evidence_refs: BTreeSet<String>,
    pub immutable_evidence_digests: BTreeSet<String>,
    pub external_evidence_status: ExternalEvidenceStatus,
    pub production_evidence: bool,
    pub facts: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SreEvidenceDeliveryReceipt {
    pub schema_version: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub payload_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSreEngineReport {
    pub schema_version: String,
    pub report_id: Uuid,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub operation: SreOperation,
    pub resource: String,
    pub resource_version: u64,
    pub result_digest: String,
    pub external_evidence_status: ExternalEvidenceStatus,
    pub evidence_refs: BTreeSet<String>,
    pub evidence_digests: BTreeSet<String>,
    pub engine_report_only: bool,
    pub production_certification: bool,
    pub issued_at: DateTime<Utc>,
    pub key_id: String,
    pub signature: String,
}

impl SignedSreEngineReport {
    fn signing_bytes(&self) -> Result<Vec<u8>, SreAuthorityError> {
        let mut value = self.clone();
        value.signature.clear();
        serde_jcs::to_vec(&value).map_err(|_| SreAuthorityError::RequestInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SreMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub resource: String,
    pub operation: SreOperation,
    pub resource_version: u64,
    pub state: String,
    pub result_digest: String,
    pub evidence_outbox_ref: String,
    pub external_receipt: Option<SreExternalReceipt>,
    pub engine_report: SignedSreEngineReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SreResourceSummary {
    pub resource: String,
    pub resource_version: u64,
    pub action_hash: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SreResourcePage {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub authoritative: bool,
    pub items: Vec<SreResourceSummary>,
    pub next_after: Option<String>,
    pub data_digest: String,
}

#[derive(Debug, Clone)]
pub struct SreAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
}

impl SreAuthorityConfig {
    pub fn validate(&self) -> Result<(), SreAuthorityError> {
        if canonical_uuid(&self.service_agent_id.0)
            && identifier(&self.organization_id, 256)
            && identifier(&self.agent_version, 128)
            && identifier(&self.region, 128)
            && identifier(&self.tool_id.0, 256)
            && identifier(&self.tool_version.0, 128)
            && identifier(&self.credential_profile, 128)
            && identifier(&self.service_subject, 256)
        {
            Ok(())
        } else {
            Err(SreAuthorityError::ConfigurationInvalid)
        }
    }
}

#[async_trait]
pub trait SreOrchestratorPort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<SreActionReceipt, SreAuthorityError>;
}

#[async_trait]
pub trait SreEffectPort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn execute(
        &self,
        binding: &SreExecutionBinding,
        request: &SreExecutorRequest,
    ) -> Result<Option<SreExternalReceipt>, SreAuthorityError>;

    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<SreEvidenceDeliveryReceipt, SreAuthorityError>;
}

#[derive(Clone)]
pub struct PostgresSreAuthorityStore {
    pool: PgPool,
}

impl PostgresSreAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM sre_action_ingress WHERE false UNION ALL SELECT 1 LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .is_ok()
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, SreAuthorityError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(parse_tenant(tenant)?.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }

    pub async fn current_resource_version(
        &self,
        tenant: &TenantId,
        resource: &str,
    ) -> Result<u64, SreAuthorityError> {
        let mut tx = self.begin_tenant(tenant).await?;
        let version = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM sre_resource_versions WHERE tenant_id=$1 AND resource=$2",
        )
        .bind(parse_tenant(tenant)?)
        .bind(resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        u64::try_from(version).map_err(|_| SreAuthorityError::DependencyUnavailable)
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<SreResourcePage, SreAuthorityError> {
        if !(1..=200).contains(&limit) || after.is_some_and(|value| !resource_identifier(value)) {
            return Err(SreAuthorityError::RequestInvalid);
        }
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT resource,resource_version,action_hash,ledger_execution_id,ledger_event_id,\
                    ledger_event_digest,fence_digest,updated_at FROM sre_resource_versions \
             WHERE tenant_id=$1 AND ($2::text IS NULL OR resource>$2) ORDER BY resource LIMIT $3",
        )
        .bind(parse_tenant(tenant)?)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let mut items = Vec::new();
        for row in rows.iter().take(limit as usize) {
            items.push(SreResourceSummary {
                resource: row.get("resource"),
                resource_version: u64::try_from(row.get::<i64, _>("resource_version"))
                    .map_err(|_| SreAuthorityError::DependencyUnavailable)?,
                action_hash: row.get("action_hash"),
                ledger_execution_id: row.get("ledger_execution_id"),
                ledger_event_id: row.get("ledger_event_id"),
                ledger_event_digest: row.get("ledger_event_digest"),
                fence_digest: row.get("fence_digest"),
                updated_at: row.get("updated_at"),
            });
        }
        let next_after = (rows.len() > limit as usize)
            .then(|| items.last().map(|value| value.resource.clone()))
            .flatten();
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let data_digest = canonical_digest(&json!({
            "schema_version": SRE_RESOURCE_PAGE_SCHEMA,
            "tenant_id": tenant,
            "authoritative": true,
            "items": &items,
            "next_after": &next_after,
        }))?;
        Ok(SreResourcePage {
            schema_version: SRE_RESOURCE_PAGE_SCHEMA.into(),
            tenant_id: tenant.clone(),
            authoritative: true,
            items,
            next_after,
            data_digest,
        })
    }
}

async fn apply_operation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &SreExecutorRequest,
    external: Option<&SreExternalReceipt>,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let payload = request
        .command
        .payload
        .as_object()
        .ok_or(SreAuthorityError::RequestInvalid)?;
    match request.command.operation {
        SreOperation::ConfigureSlo => {
            let slo_id = uuid_value(payload, "slo_id")?;
            if request.command.expected_resource_version == 0 {
                sqlx::query(
                    "INSERT INTO sre_service_slos \
                     (tenant_id,slo_id,service,sli_kind,window_seconds,target_millionths,minimum_samples,\
                      fast_burn_threshold_millionths,slow_burn_threshold_millionths,release_blocking,status,resource_version) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                )
                .bind(tenant)
                .bind(slo_id)
                .bind(string_value(payload, "service")?)
                .bind(string_value(payload, "sli_kind")?)
                .bind(i64_value(payload, "window_seconds")?)
                .bind(i32_value(payload, "target_millionths")?)
                .bind(i64_value(payload, "minimum_samples")?)
                .bind(i32_value(payload, "fast_burn_threshold_millionths")?)
                .bind(i32_value(payload, "slow_burn_threshold_millionths")?)
                .bind(bool_value(payload, "release_blocking")?)
                .bind(string_value(payload, "status")?)
                .bind(next)
                .execute(&mut **tx)
                .await
                .map_err(|_| SreAuthorityError::StateConflict)?;
            } else {
                let updated = sqlx::query(
                    "UPDATE sre_service_slos SET service=$3,sli_kind=$4,window_seconds=$5,\
                     target_millionths=$6,minimum_samples=$7,fast_burn_threshold_millionths=$8,\
                     slow_burn_threshold_millionths=$9,release_blocking=$10,status=$11,\
                     resource_version=$12,updated_at=now() \
                     WHERE tenant_id=$1 AND slo_id=$2 AND resource_version=$13",
                )
                .bind(tenant)
                .bind(slo_id)
                .bind(string_value(payload, "service")?)
                .bind(string_value(payload, "sli_kind")?)
                .bind(i64_value(payload, "window_seconds")?)
                .bind(i32_value(payload, "target_millionths")?)
                .bind(i64_value(payload, "minimum_samples")?)
                .bind(i32_value(payload, "fast_burn_threshold_millionths")?)
                .bind(i32_value(payload, "slow_burn_threshold_millionths")?)
                .bind(bool_value(payload, "release_blocking")?)
                .bind(string_value(payload, "status")?)
                .bind(next)
                .bind(
                    i64::try_from(request.command.expected_resource_version)
                        .map_err(|_| SreAuthorityError::StateConflict)?,
                )
                .execute(&mut **tx)
                .await
                .map_err(|_| SreAuthorityError::StateConflict)?;
                require_one(updated.rows_affected())?;
            }
            Ok(string_value(payload, "status")?.into())
        }
        SreOperation::RecordSli => {
            let observation_id = uuid_value(payload, "observation_id")?;
            let slo_id = uuid_value(payload, "slo_id")?;
            let good = i64_value(payload, "good_events")?;
            let total = i64_value(payload, "total_events")?;
            let slo = sqlx::query(
                "SELECT target_millionths,fast_burn_threshold_millionths,\
                        slow_burn_threshold_millionths,minimum_samples,status \
                 FROM sre_service_slos WHERE tenant_id=$1 AND slo_id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(slo_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?
            .ok_or(SreAuthorityError::NotFound)?;
            if slo.get::<String, _>("status") != "ACTIVE"
                || total < slo.get::<i64, _>("minimum_samples")
            {
                return Err(SreAuthorityError::StateConflict);
            }
            sqlx::query(
                "INSERT INTO sre_sli_observations \
                 (tenant_id,observation_id,slo_id,release_digest,good_events,total_events,\
                  window_started_at,window_ended_at,trace_evidence_ref,metrics_evidence_ref,\
                  logs_evidence_ref,evidence_digest) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            )
            .bind(tenant)
            .bind(observation_id)
            .bind(slo_id)
            .bind(string_value(payload, "release_digest")?)
            .bind(good)
            .bind(total)
            .bind(time_value(payload, "window_started_at")?)
            .bind(time_value(payload, "window_ended_at")?)
            .bind(string_value(payload, "trace_evidence_ref")?)
            .bind(string_value(payload, "metrics_evidence_ref")?)
            .bind(string_value(payload, "logs_evidence_ref")?)
            .bind(string_value(payload, "evidence_digest")?)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            let target = u128::try_from(slo.get::<i32, _>("target_millionths"))
                .map_err(|_| SreAuthorityError::StateConflict)?;
            let achieved = if total == 0 {
                0
            } else {
                u128::try_from(good).map_err(|_| SreAuthorityError::StateConflict)? * 1_000_000
                    / u128::try_from(total).map_err(|_| SreAuthorityError::StateConflict)?
            };
            let error_budget = 1_000_000_u128.saturating_sub(target).max(1);
            let error_rate = 1_000_000_u128.saturating_sub(achieved);
            let burn = error_rate.saturating_mul(1_000_000) / error_budget;
            let slow = u128::try_from(slo.get::<i32, _>("slow_burn_threshold_millionths"))
                .map_err(|_| SreAuthorityError::StateConflict)?;
            let fast = u128::try_from(slo.get::<i32, _>("fast_burn_threshold_millionths"))
                .map_err(|_| SreAuthorityError::StateConflict)?;
            let alert_id = optional_uuid_value(payload, "alert_id")?;
            let outcome = if burn >= slow {
                let alert_id = alert_id.ok_or(SreAuthorityError::RequestInvalid)?;
                let severity = if burn >= fast { "CRITICAL" } else { "WARNING" };
                sqlx::query(
                    "INSERT INTO sre_burn_alerts \
                     (tenant_id,alert_id,slo_id,state,burn_rate_millionths,severity,\
                      opened_from_observation_id,resource_version) \
                     VALUES ($1,$2,$3,'OPEN',$4,$5,$6,1)",
                )
                .bind(tenant)
                .bind(alert_id)
                .bind(slo_id)
                .bind(i64::try_from(burn).map_err(|_| SreAuthorityError::StateConflict)?)
                .bind(severity)
                .bind(observation_id)
                .execute(&mut **tx)
                .await
                .map_err(|_| SreAuthorityError::StateConflict)?;
                format!("ALERT_{severity}")
            } else if alert_id.is_some() {
                return Err(SreAuthorityError::RequestInvalid);
            } else {
                "WITHIN_BUDGET".into()
            };
            let updated = sqlx::query(
                "UPDATE sre_service_slos SET resource_version=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND slo_id=$2 AND resource_version=$4",
            )
            .bind(tenant)
            .bind(slo_id)
            .bind(next)
            .bind(
                i64::try_from(request.command.expected_resource_version)
                    .map_err(|_| SreAuthorityError::StateConflict)?,
            )
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            require_one(updated.rows_affected())?;
            Ok(outcome)
        }
        SreOperation::UpdateBurnAlert => {
            let alert_id = uuid_value(payload, "alert_id")?;
            let current = sqlx::query(
                "SELECT state,resource_version FROM sre_burn_alerts \
                 WHERE tenant_id=$1 AND alert_id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(alert_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?
            .ok_or(SreAuthorityError::NotFound)?;
            let old: String = current.get("state");
            let new = string_value(payload, "state")?;
            if !matches!(
                (old.as_str(), new),
                ("OPEN", "ACKNOWLEDGED")
                    | ("ACKNOWLEDGED", "MITIGATING")
                    | ("ACKNOWLEDGED", "RESOLVED")
                    | ("MITIGATING", "RESOLVED")
            ) || current.get::<i64, _>("resource_version")
                != i64::try_from(request.command.expected_resource_version)
                    .map_err(|_| SreAuthorityError::StateConflict)?
            {
                return Err(SreAuthorityError::StateConflict);
            }
            let resolved_at = if new == "RESOLVED" {
                Some(time_value(payload, "resolved_at")?)
            } else {
                None
            };
            let updated = sqlx::query(
                "UPDATE sre_burn_alerts SET state=$3,owner_subject=$4,resolved_at=$5,\
                 resource_version=$6 WHERE tenant_id=$1 AND alert_id=$2 AND state=$7",
            )
            .bind(tenant)
            .bind(alert_id)
            .bind(new)
            .bind(string_value(payload, "owner_subject")?)
            .bind(resolved_at)
            .bind(next)
            .bind(old)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            require_one(updated.rows_affected())?;
            Ok(new.into())
        }
        SreOperation::LinkIncident => {
            let alert_id = uuid_value(payload, "alert_id")?;
            sqlx::query(
                "INSERT INTO sre_incident_links \
                 (tenant_id,link_id,alert_id,incident_id,incident_evidence_ref,linked_by) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "link_id")?)
            .bind(alert_id)
            .bind(uuid_value(payload, "incident_id")?)
            .bind(string_value(payload, "incident_evidence_ref")?)
            .bind(&request.actor_subject)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            let updated = sqlx::query(
                "UPDATE sre_burn_alerts SET resource_version=$3 \
                 WHERE tenant_id=$1 AND alert_id=$2 AND resource_version=$4",
            )
            .bind(tenant)
            .bind(alert_id)
            .bind(next)
            .bind(
                i64::try_from(request.command.expected_resource_version)
                    .map_err(|_| SreAuthorityError::StateConflict)?,
            )
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            require_one(updated.rows_affected())?;
            Ok("LINKED".into())
        }
        SreOperation::RegisterTopology => {
            let topology_id = uuid_value(payload, "topology_id")?;
            let zones = string_vec(payload, "zones")?;
            if request.command.expected_resource_version == 0 {
                sqlx::query(
                    "INSERT INTO sre_deployment_topologies \
                     (tenant_id,topology_id,deployment_mode,release_digest,topology_digest,zones,\
                      components,quorum_rules,disruption_budgets,immutable_image_digests,status,resource_version) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                )
                .bind(tenant)
                .bind(topology_id)
                .bind(string_value(payload, "deployment_mode")?)
                .bind(string_value(payload, "release_digest")?)
                .bind(string_value(payload, "topology_digest")?)
                .bind(zones)
                .bind(json_value(payload, "components")?)
                .bind(json_value(payload, "quorum_rules")?)
                .bind(json_value(payload, "disruption_budgets")?)
                .bind(json_value(payload, "immutable_image_digests")?)
                .bind(string_value(payload, "status")?)
                .bind(next)
                .execute(&mut **tx)
                .await
                .map_err(|_| SreAuthorityError::StateConflict)?;
            } else {
                let updated = sqlx::query(
                    "UPDATE sre_deployment_topologies SET deployment_mode=$3,release_digest=$4,\
                     topology_digest=$5,zones=$6,components=$7,quorum_rules=$8,disruption_budgets=$9,\
                     immutable_image_digests=$10,status=$11,resource_version=$12,updated_at=now() \
                     WHERE tenant_id=$1 AND topology_id=$2 AND resource_version=$13",
                )
                .bind(tenant)
                .bind(topology_id)
                .bind(string_value(payload, "deployment_mode")?)
                .bind(string_value(payload, "release_digest")?)
                .bind(string_value(payload, "topology_digest")?)
                .bind(zones)
                .bind(json_value(payload, "components")?)
                .bind(json_value(payload, "quorum_rules")?)
                .bind(json_value(payload, "disruption_budgets")?)
                .bind(json_value(payload, "immutable_image_digests")?)
                .bind(string_value(payload, "status")?)
                .bind(next)
                .bind(i64::try_from(request.command.expected_resource_version)
                    .map_err(|_| SreAuthorityError::StateConflict)?)
                .execute(&mut **tx)
                .await
                .map_err(|_| SreAuthorityError::StateConflict)?;
                require_one(updated.rows_affected())?;
            }
            Ok(string_value(payload, "status")?.into())
        }
        SreOperation::RecordZoneHealth => {
            let receipt = external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?;
            let observed = facts(receipt)?;
            let ready = i32_value(observed, "ready_replicas")?;
            let required = i32_value(observed, "required_replicas")?;
            let components = json_value(observed, "component_health")?;
            let dependencies = json_value(observed, "dependency_health")?;
            let healthy = ready >= required
                && components.as_object().is_some_and(|value| {
                    !value.is_empty() && value.values().all(|item| item == &Value::Bool(true))
                })
                && dependencies.as_object().is_some_and(|value| {
                    !value.is_empty() && value.values().all(|item| item == &Value::Bool(true))
                });
            sqlx::query(
                "INSERT INTO sre_zone_health_observations \
                 (tenant_id,observation_id,topology_id,zone,component_health,dependency_health,\
                  ready_replicas,required_replicas,topology_probe_digest,external_evidence_status,observed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "observation_id")?)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(string_value(payload, "zone")?)
            .bind(components)
            .bind(dependencies)
            .bind(ready)
            .bind(required)
            .bind(string_value(observed, "topology_probe_digest")?)
            .bind(receipt.external_evidence_status.as_str())
            .bind(time_value(observed, "observed_at")?)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            let status = if healthy { "HEALTHY" } else { "DEGRADED" };
            let updated = sqlx::query(
                "UPDATE sre_deployment_topologies SET status=$3,resource_version=$4,updated_at=now() \
                 WHERE tenant_id=$1 AND topology_id=$2 AND status<>'RETIRED' AND resource_version=$5",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(status)
            .bind(next)
            .bind(i64::try_from(request.command.expected_resource_version)
                .map_err(|_| SreAuthorityError::StateConflict)?)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            require_one(updated.rows_affected())?;
            Ok(status.into())
        }
        SreOperation::CreateBackup => {
            apply_backup(
                tx,
                tenant,
                request,
                payload,
                external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?,
                next,
            )
            .await
        }
        SreOperation::VerifyRestore => {
            apply_restore(
                tx,
                tenant,
                request,
                payload,
                external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?,
                next,
            )
            .await
        }
        SreOperation::PlanDr => {
            sqlx::query(
                "INSERT INTO sre_dr_plans \
                 (tenant_id,plan_id,topology_id,recovery_drill_id,source_zones,target_zones,\
                  maximum_rto_seconds,maximum_rpo_seconds,failover_steps,failback_steps,health_checks,\
                  status,resource_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'READY',$12)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "plan_id")?)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(uuid_value(payload, "recovery_drill_id")?)
            .bind(string_vec(payload, "source_zones")?)
            .bind(string_vec(payload, "target_zones")?)
            .bind(i64_value(payload, "maximum_rto_seconds")?)
            .bind(i64_value(payload, "maximum_rpo_seconds")?)
            .bind(json_value(payload, "failover_steps")?)
            .bind(json_value(payload, "failback_steps")?)
            .bind(json_value(payload, "health_checks")?)
            .bind(next)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            Ok("READY".into())
        }
        SreOperation::Failover | SreOperation::Failback => {
            apply_dr_event(
                tx,
                tenant,
                request,
                payload,
                external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?,
                next,
            )
            .await
        }
        SreOperation::PlanChaos => {
            sqlx::query(
                "INSERT INTO sre_chaos_campaigns \
                 (tenant_id,campaign_id,topology_id,environment_ref,fault_types,fault_budget_seconds,\
                  blast_radius,abort_conditions,cleanup_plan_digest,production_target_allowed,status,resource_version) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,false,'APPROVED',$10)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "campaign_id")?)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(string_value(payload, "environment_ref")?)
            .bind(string_vec(payload, "fault_types")?)
            .bind(i32_value(payload, "fault_budget_seconds")?)
            .bind(json_value(payload, "blast_radius")?)
            .bind(json_value(payload, "abort_conditions")?)
            .bind(string_value(payload, "cleanup_plan_digest")?)
            .bind(next)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            Ok("APPROVED".into())
        }
        SreOperation::ExecuteChaos => {
            apply_chaos_result(
                tx,
                tenant,
                request,
                payload,
                external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?,
                next,
            )
            .await
        }
        SreOperation::PlanLoad => {
            sqlx::query(
                "INSERT INTO sre_load_campaigns \
                 (tenant_id,campaign_id,topology_id,release_digest,workload_digest,duration_seconds,\
                  concurrency,maximum_requests,tenant_quota,stop_conditions,status,resource_version) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'APPROVED',$11)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "campaign_id")?)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(string_value(payload, "release_digest")?)
            .bind(string_value(payload, "workload_digest")?)
            .bind(i32_value(payload, "duration_seconds")?)
            .bind(i32_value(payload, "concurrency")?)
            .bind(i64_value(payload, "maximum_requests")?)
            .bind(json_value(payload, "tenant_quota")?)
            .bind(json_value(payload, "stop_conditions")?)
            .bind(next)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            Ok("APPROVED".into())
        }
        SreOperation::ExecuteLoad => {
            apply_load_result(
                tx,
                tenant,
                request,
                payload,
                external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?,
                next,
            )
            .await
        }
        SreOperation::PlanUpgrade => {
            sqlx::query(
                "INSERT INTO deployment_rollouts \
                 (tenant_id,rollout_id,topology_id,from_release_digest,to_release_digest,\
                  schema_compatible,api_compatible,policy_compatible,pack_compatible,migration_digest,\
                  rollback_digest,canary_steps,current_canary_percent,maximum_error_rate_millionths,\
                  status,resource_version) \
                 VALUES ($1,$2,$3,$4,$5,true,true,true,true,$6,$7,$8,0,$9,'PLANNED',$10)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "rollout_id")?)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(string_value(payload, "from_release_digest")?)
            .bind(string_value(payload, "to_release_digest")?)
            .bind(string_value(payload, "migration_digest")?)
            .bind(string_value(payload, "rollback_digest")?)
            .bind(i32_vec(payload, "canary_steps")?)
            .bind(i32_value(payload, "maximum_error_rate_millionths")?)
            .bind(next)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            Ok("PLANNED".into())
        }
        SreOperation::RecordCanary => apply_canary(tx, tenant, request, payload, next).await,
        SreOperation::RollbackUpgrade => {
            let receipt = external.ok_or(SreAuthorityError::ExternalReceiptInvalid)?;
            let facts = facts(receipt)?;
            let applied = string_value(facts, "rollback_artifact_digest")?;
            if applied != string_value(payload, "rollback_artifact_digest")? {
                return Err(SreAuthorityError::ExternalReceiptInvalid);
            }
            let succeeded = bool_value(facts, "succeeded")?;
            let status = if succeeded { "ROLLED_BACK" } else { "FAILED" };
            let updated = sqlx::query(
                "UPDATE deployment_rollouts SET status=$3,current_canary_percent=0,resource_version=$4,updated_at=now() \
                 WHERE tenant_id=$1 AND rollout_id=$2 AND resource_version=$5 \
                   AND status IN ('PLANNED','CANARY','ROLLING_BACK','FAILED')",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "rollout_id")?)
            .bind(status)
            .bind(next)
            .bind(i64::try_from(request.command.expected_resource_version)
                .map_err(|_| SreAuthorityError::StateConflict)?)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            require_one(updated.rows_affected())?;
            Ok(status.into())
        }
        SreOperation::RecordCostCapacity => {
            sqlx::query(
                "INSERT INTO sre_cost_capacity_observations \
                 (tenant_id,observation_id,topology_id,release_digest,period_started_at,period_ended_at,\
                  task_count,request_count,compute_microunits,storage_microunits,network_microunits,\
                  model_microunits,maximum_global_tasks,maximum_tasks_per_tenant,queue_capacity,\
                  connection_pool_capacity,evidence_buffer_capacity,source_digest) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "observation_id")?)
            .bind(uuid_value(payload, "topology_id")?)
            .bind(string_value(payload, "release_digest")?)
            .bind(time_value(payload, "period_started_at")?)
            .bind(time_value(payload, "period_ended_at")?)
            .bind(i64_value(payload, "task_count")?)
            .bind(i64_value(payload, "request_count")?)
            .bind(i64_value(payload, "compute_microunits")?)
            .bind(i64_value(payload, "storage_microunits")?)
            .bind(i64_value(payload, "network_microunits")?)
            .bind(i64_value(payload, "model_microunits")?)
            .bind(i64_value(payload, "maximum_global_tasks")?)
            .bind(i64_value(payload, "maximum_tasks_per_tenant")?)
            .bind(i64_value(payload, "queue_capacity")?)
            .bind(i64_value(payload, "connection_pool_capacity")?)
            .bind(i64_value(payload, "evidence_buffer_capacity")?)
            .bind(string_value(payload, "source_digest")?)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            Ok("RECORDED".into())
        }
        SreOperation::RecordObservability => {
            sqlx::query(
                "INSERT INTO sre_observability_evidence \
                 (tenant_id,evidence_id,resource,trace_id,trace_digest,log_digest,metrics_digest,\
                  redaction_policy_digest,immutable_refs,collected_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(tenant)
            .bind(uuid_value(payload, "evidence_id")?)
            .bind(&request.command.resource)
            .bind(string_value(payload, "trace_id")?)
            .bind(string_value(payload, "trace_digest")?)
            .bind(string_value(payload, "log_digest")?)
            .bind(string_value(payload, "metrics_digest")?)
            .bind(string_value(payload, "redaction_policy_digest")?)
            .bind(string_vec(payload, "immutable_refs")?)
            .bind(time_value(payload, "collected_at")?)
            .execute(&mut **tx)
            .await
            .map_err(|_| SreAuthorityError::StateConflict)?;
            Ok("RECORDED".into())
        }
    }
}

async fn apply_backup(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    _request: &SreExecutorRequest,
    payload: &Map<String, Value>,
    receipt: &SreExternalReceipt,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let value = facts(receipt)?;
    let backup_id = uuid_value(payload, "backup_id")?;
    let retention_until = time_value(value, "worm_retention_until")?;
    let minimum_retention = i64_value(payload, "minimum_worm_retention_seconds")?;
    if retention_until < Utc::now() + Duration::seconds(minimum_retention) {
        return Err(SreAuthorityError::ExternalReceiptInvalid);
    }
    sqlx::query(
        "INSERT INTO backup_manifests \
         (tenant_id,backup_id,topology_id,release_digest,scope_digest,database_lsn,\
          database_artifact_digest,object_manifest_digest,ledger_head_digest,worm_retention_until,\
          key_version,key_recovery_evidence_ref,record_counts,manifest_digest,signature_key_id,\
          signature,external_evidence_status,resource_version) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
    )
    .bind(tenant)
    .bind(backup_id)
    .bind(uuid_value(payload, "topology_id")?)
    .bind(string_value(payload, "release_digest")?)
    .bind(string_value(payload, "scope_digest")?)
    .bind(string_value(value, "database_lsn")?)
    .bind(string_value(value, "database_artifact_digest")?)
    .bind(string_value(value, "object_manifest_digest")?)
    .bind(string_value(value, "ledger_head_digest")?)
    .bind(retention_until)
    .bind(string_value(payload, "key_version")?)
    .bind(string_value(value, "key_recovery_evidence_ref")?)
    .bind(json_value(value, "record_counts")?)
    .bind(string_value(value, "manifest_digest")?)
    .bind(string_value(value, "signature_key_id")?)
    .bind(string_value(value, "signature")?)
    .bind(receipt.external_evidence_status.as_str())
    .bind(next)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    let artifacts = value
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or(SreAuthorityError::ExternalReceiptInvalid)?;
    for artifact in artifacts {
        let artifact = artifact
            .as_object()
            .ok_or(SreAuthorityError::ExternalReceiptInvalid)?;
        sqlx::query(
            "INSERT INTO sre_backup_artifacts \
             (tenant_id,artifact_id,backup_id,artifact_kind,immutable_ref,artifact_digest,size_bytes,\
              encryption_key_version,worm_locked,evidence_ref) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9)",
        )
        .bind(tenant)
        .bind(uuid_value(artifact, "artifact_id")?)
        .bind(backup_id)
        .bind(string_value(artifact, "artifact_kind")?)
        .bind(string_value(artifact, "immutable_ref")?)
        .bind(string_value(artifact, "artifact_digest")?)
        .bind(i64_value(artifact, "size_bytes")?)
        .bind(string_value(artifact, "encryption_key_version")?)
        .bind(string_value(artifact, "evidence_ref")?)
        .execute(&mut **tx)
        .await
        .map_err(|_| SreAuthorityError::StateConflict)?;
    }
    Ok("BACKUP_IMMUTABLE".into())
}

async fn apply_restore(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    _request: &SreExecutorRequest,
    payload: &Map<String, Value>,
    receipt: &SreExternalReceipt,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let value = facts(receipt)?;
    let expected_counts = json_value(value, "expected_record_counts")?;
    let restored_counts = json_value(value, "restored_record_counts")?;
    let rto = i64_value(value, "measured_rto_seconds")?;
    let rpo = i64_value(value, "measured_rpo_seconds")?;
    let integrity = bool_value(value, "object_integrity_passed")?;
    let ledger = bool_value(value, "ledger_reconciled")?;
    let key = bool_value(value, "key_recovery_passed")?;
    let passed = integrity
        && ledger
        && key
        && expected_counts == restored_counts
        && rto <= i64_value(payload, "maximum_rto_seconds")?
        && rpo <= i64_value(payload, "maximum_rpo_seconds")?;
    sqlx::query(
        "INSERT INTO recovery_drills \
         (tenant_id,drill_id,backup_id,topology_id,isolated_environment_ref,restore_target_digest,\
          expected_record_counts,restored_record_counts,object_integrity_passed,ledger_reconciled,\
          key_recovery_passed,measured_rto_seconds,measured_rpo_seconds,report_digest,command_digest,\
          external_evidence_status,passed,resource_version,started_at,completed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
    )
    .bind(tenant)
    .bind(uuid_value(payload, "drill_id")?)
    .bind(uuid_value(payload, "backup_id")?)
    .bind(uuid_value(payload, "topology_id")?)
    .bind(string_value(payload, "isolated_environment_ref")?)
    .bind(string_value(payload, "restore_target_digest")?)
    .bind(expected_counts)
    .bind(restored_counts)
    .bind(integrity)
    .bind(ledger)
    .bind(key)
    .bind(rto)
    .bind(rpo)
    .bind(string_value(value, "report_digest")?)
    .bind(string_value(value, "command_digest")?)
    .bind(receipt.external_evidence_status.as_str())
    .bind(passed)
    .bind(next)
    .bind(time_value(value, "started_at")?)
    .bind(time_value(value, "completed_at")?)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    Ok(if passed {
        "RESTORE_VERIFIED"
    } else {
        "RESTORE_FAILED"
    }
    .into())
}

async fn apply_dr_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &SreExecutorRequest,
    payload: &Map<String, Value>,
    receipt: &SreExternalReceipt,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let value = facts(receipt)?;
    let plan_id = uuid_value(payload, "plan_id")?;
    let plan = sqlx::query(
        "SELECT status,maximum_rto_seconds,maximum_rpo_seconds FROM sre_dr_plans \
         WHERE tenant_id=$1 AND plan_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(plan_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::DependencyUnavailable)?
    .ok_or(SreAuthorityError::NotFound)?;
    let expected_state = if request.command.operation == SreOperation::Failover {
        "READY"
    } else {
        "FAILED_OVER"
    };
    if plan.get::<String, _>("status") != expected_state {
        return Err(SreAuthorityError::StateConflict);
    }
    let rto = i64_value(value, "measured_rto_seconds")?;
    let rpo = i64_value(value, "measured_rpo_seconds")?;
    let adapter_succeeded = bool_value(value, "succeeded")?;
    let succeeded = adapter_succeeded
        && rto <= plan.get::<i64, _>("maximum_rto_seconds")
        && rpo <= plan.get::<i64, _>("maximum_rpo_seconds");
    let (phase, success_state) = if request.command.operation == SreOperation::Failover {
        ("FAILOVER", "FAILED_OVER")
    } else {
        ("FAILBACK", "COMPLETED")
    };
    let state = if succeeded { success_state } else { "FAILED" };
    sqlx::query(
        "INSERT INTO sre_dr_events \
         (tenant_id,event_id,plan_id,phase,from_state,to_state,adapter_receipt_digest,\
          health_evidence_ref,measured_rto_seconds,measured_rpo_seconds,external_evidence_status,succeeded) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(tenant)
    .bind(uuid_value(payload, "event_id")?)
    .bind(plan_id)
    .bind(phase)
    .bind(expected_state)
    .bind(state)
    .bind(string_value(value, "adapter_receipt_digest")?)
    .bind(string_value(value, "health_evidence_ref")?)
    .bind(rto)
    .bind(rpo)
    .bind(receipt.external_evidence_status.as_str())
    .bind(succeeded)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    let updated = sqlx::query(
        "UPDATE sre_dr_plans SET status=$3,resource_version=$4,updated_at=now() \
         WHERE tenant_id=$1 AND plan_id=$2 AND status=$5 AND resource_version=$6",
    )
    .bind(tenant)
    .bind(plan_id)
    .bind(state)
    .bind(next)
    .bind(expected_state)
    .bind(
        i64::try_from(request.command.expected_resource_version)
            .map_err(|_| SreAuthorityError::StateConflict)?,
    )
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    require_one(updated.rows_affected())?;
    Ok(state.into())
}

async fn apply_chaos_result(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &SreExecutorRequest,
    payload: &Map<String, Value>,
    receipt: &SreExternalReceipt,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let value = facts(receipt)?;
    let campaign_id = uuid_value(payload, "campaign_id")?;
    let campaign = sqlx::query(
        "SELECT status,production_target_allowed FROM sre_chaos_campaigns \
         WHERE tenant_id=$1 AND campaign_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(campaign_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::DependencyUnavailable)?
    .ok_or(SreAuthorityError::NotFound)?;
    if campaign.get::<String, _>("status") != "APPROVED"
        || campaign.get::<bool, _>("production_target_allowed")
    {
        return Err(SreAuthorityError::StateConflict);
    }
    let cleanup = bool_value(value, "cleanup_verified")?;
    let semantics = bool_value(value, "dependency_failure_semantics_verified")?;
    let emergency = bool_value(value, "emergency_stop_verified")?;
    let state = if cleanup && semantics && emergency {
        "COMPLETED"
    } else if !cleanup {
        "CLEANUP_FAILED"
    } else {
        "FAILED"
    };
    sqlx::query(
        "INSERT INTO sre_chaos_results \
         (tenant_id,result_id,campaign_id,fault_type,started_at,completed_at,safety_abort_triggered,\
          cleanup_verified,dependency_failure_semantics_verified,emergency_stop_verified,\
          production_evidence,command_digest,report_digest,evidence_refs) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(tenant)
    .bind(uuid_value(payload, "result_id")?)
    .bind(campaign_id)
    .bind(string_value(payload, "fault_type")?)
    .bind(time_value(value, "started_at")?)
    .bind(time_value(value, "completed_at")?)
    .bind(bool_value(value, "safety_abort_triggered")?)
    .bind(cleanup)
    .bind(semantics)
    .bind(emergency)
    .bind(receipt.production_evidence)
    .bind(string_value(value, "command_digest")?)
    .bind(string_value(value, "report_digest")?)
    .bind(string_vec(value, "evidence_refs")?)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    let updated = sqlx::query(
        "UPDATE sre_chaos_campaigns SET status=$3,resource_version=$4,updated_at=now() \
         WHERE tenant_id=$1 AND campaign_id=$2 AND status='APPROVED' AND resource_version=$5",
    )
    .bind(tenant)
    .bind(campaign_id)
    .bind(state)
    .bind(next)
    .bind(
        i64::try_from(request.command.expected_resource_version)
            .map_err(|_| SreAuthorityError::StateConflict)?,
    )
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    require_one(updated.rows_affected())?;
    Ok(state.into())
}

async fn apply_load_result(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &SreExecutorRequest,
    payload: &Map<String, Value>,
    receipt: &SreExternalReceipt,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let value = facts(receipt)?;
    let campaign_id = uuid_value(payload, "campaign_id")?;
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM sre_load_campaigns WHERE tenant_id=$1 AND campaign_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(campaign_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::DependencyUnavailable)?
    .ok_or(SreAuthorityError::NotFound)?;
    if status != "APPROVED" {
        return Err(SreAuthorityError::StateConflict);
    }
    let success = i32_value(value, "success_millionths")?;
    let isolated = bool_value(value, "noisy_neighbor_isolation_passed")?;
    let completed_state = if success >= 999_000 && isolated {
        "COMPLETED"
    } else {
        "FAILED"
    };
    sqlx::query(
        "INSERT INTO sre_load_results \
         (tenant_id,result_id,campaign_id,requests,success_millionths,p50_milliseconds,p95_milliseconds,\
          p99_milliseconds,throughput_millionths,backpressure_rejections,noisy_neighbor_isolation_passed,\
          production_evidence,report_digest,evidence_refs,started_at,completed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    )
    .bind(tenant)
    .bind(uuid_value(payload, "result_id")?)
    .bind(campaign_id)
    .bind(i64_value(value, "requests")?)
    .bind(success)
    .bind(i64_value(value, "p50_milliseconds")?)
    .bind(i64_value(value, "p95_milliseconds")?)
    .bind(i64_value(value, "p99_milliseconds")?)
    .bind(i64_value(value, "throughput_millionths")?)
    .bind(i64_value(value, "backpressure_rejections")?)
    .bind(isolated)
    .bind(receipt.production_evidence)
    .bind(string_value(value, "report_digest")?)
    .bind(string_vec(value, "evidence_refs")?)
    .bind(time_value(value, "started_at")?)
    .bind(time_value(value, "completed_at")?)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    let updated = sqlx::query(
        "UPDATE sre_load_campaigns SET status=$3,resource_version=$4,updated_at=now() \
         WHERE tenant_id=$1 AND campaign_id=$2 AND status='APPROVED' AND resource_version=$5",
    )
    .bind(tenant)
    .bind(campaign_id)
    .bind(completed_state)
    .bind(next)
    .bind(
        i64::try_from(request.command.expected_resource_version)
            .map_err(|_| SreAuthorityError::StateConflict)?,
    )
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    require_one(updated.rows_affected())?;
    Ok(completed_state.into())
}

async fn apply_canary(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &SreExecutorRequest,
    payload: &Map<String, Value>,
    next: i64,
) -> Result<String, SreAuthorityError> {
    let rollout_id = uuid_value(payload, "rollout_id")?;
    let rollout = sqlx::query(
        "SELECT status,maximum_error_rate_millionths,canary_steps,current_canary_percent \
         FROM deployment_rollouts WHERE tenant_id=$1 AND rollout_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(rollout_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::DependencyUnavailable)?
    .ok_or(SreAuthorityError::NotFound)?;
    if !matches!(
        rollout.get::<String, _>("status").as_str(),
        "PLANNED" | "CANARY"
    ) {
        return Err(SreAuthorityError::StateConflict);
    }
    let percent = i32_value(payload, "canary_percent")?;
    let steps: Vec<i32> = rollout.get("canary_steps");
    let current: i32 = rollout.get("current_canary_percent");
    if !steps.contains(&percent) || percent <= current {
        return Err(SreAuthorityError::StateConflict);
    }
    let regression = i32_value(payload, "error_rate_millionths")?
        > rollout.get::<i32, _>("maximum_error_rate_millionths")
        || i64_value(payload, "unsafe_allow_count")? > 0
        || i64_value(payload, "evidence_gap_count")? > 0;
    sqlx::query(
        "INSERT INTO sre_canary_observations \
         (tenant_id,observation_id,rollout_id,canary_percent,error_rate_millionths,unsafe_allow_count,\
          evidence_gap_count,rollback_triggered,metrics_digest,evidence_refs,observed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(tenant)
    .bind(uuid_value(payload, "observation_id")?)
    .bind(rollout_id)
    .bind(percent)
    .bind(i32_value(payload, "error_rate_millionths")?)
    .bind(i64_value(payload, "unsafe_allow_count")?)
    .bind(i64_value(payload, "evidence_gap_count")?)
    .bind(regression)
    .bind(string_value(payload, "metrics_digest")?)
    .bind(string_vec(payload, "evidence_refs")?)
    .bind(time_value(payload, "observed_at")?)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    let state = if regression {
        "ROLLING_BACK"
    } else if percent == 100 {
        "PROMOTED"
    } else {
        "CANARY"
    };
    let updated = sqlx::query(
        "UPDATE deployment_rollouts SET status=$3,current_canary_percent=$4,resource_version=$5,updated_at=now() \
         WHERE tenant_id=$1 AND rollout_id=$2 AND current_canary_percent=$6 AND resource_version=$7",
    )
    .bind(tenant)
    .bind(rollout_id)
    .bind(state)
    .bind(percent)
    .bind(next)
    .bind(current)
    .bind(i64::try_from(request.command.expected_resource_version)
        .map_err(|_| SreAuthorityError::StateConflict)?)
    .execute(&mut **tx)
    .await
    .map_err(|_| SreAuthorityError::StateConflict)?;
    require_one(updated.rows_affected())?;
    Ok(state.into())
}

fn external_fact_shape(operation: SreOperation, facts: &Value) -> bool {
    let Some(value) = facts.as_object() else {
        return false;
    };
    match operation {
        SreOperation::RecordZoneHealth => {
            exact_keys(
                value,
                &[
                    "component_health",
                    "dependency_health",
                    "ready_replicas",
                    "required_replicas",
                    "topology_probe_digest",
                    "probe_spec_digest",
                    "observed_at",
                ],
            ) && value
                .get("component_health")
                .and_then(Value::as_object)
                .is_some_and(|items| !items.is_empty() && items.values().all(Value::is_boolean))
                && value
                    .get("dependency_health")
                    .and_then(Value::as_object)
                    .is_some_and(|items| !items.is_empty() && items.values().all(Value::is_boolean))
                && u64_field(value, "ready_replicas")
                    .zip(u64_field(value, "required_replicas"))
                    .is_some_and(|(ready, required)| {
                        required > 0 && ready <= 1_000_000 && required <= 1_000_000
                    })
                && digest_field(value, "topology_probe_digest")
                && digest_field(value, "probe_spec_digest")
                && time_field(value, "observed_at")
        }
        SreOperation::CreateBackup => {
            exact_keys(
                value,
                &[
                    "database_lsn",
                    "database_artifact_digest",
                    "object_manifest_digest",
                    "ledger_head_digest",
                    "worm_retention_until",
                    "key_recovery_evidence_ref",
                    "record_counts",
                    "manifest_digest",
                    "signature_key_id",
                    "signature",
                    "artifacts",
                ],
            ) && identifier_field(value, "database_lsn", 256)
                && [
                    "database_artifact_digest",
                    "object_manifest_digest",
                    "ledger_head_digest",
                    "manifest_digest",
                ]
                .iter()
                .all(|field| digest_field(value, field))
                && time_field(value, "worm_retention_until")
                && evidence_reference_field(value, "key_recovery_evidence_ref")
                && value.get("record_counts").is_some_and(Value::is_object)
                && identifier_field(value, "signature_key_id", 128)
                && string_field(value, "signature")
                    .is_some_and(|item| (64..=1024).contains(&item.len()))
                && value
                    .get("artifacts")
                    .and_then(Value::as_array)
                    .is_some_and(|artifacts| {
                        artifacts.len() == 4
                            && artifacts.iter().all(|artifact| {
                                artifact.as_object().is_some_and(|item| {
                                    exact_keys(
                                        item,
                                        &[
                                            "artifact_id",
                                            "artifact_kind",
                                            "immutable_ref",
                                            "artifact_digest",
                                            "size_bytes",
                                            "encryption_key_version",
                                            "worm_locked",
                                            "evidence_ref",
                                        ],
                                    ) && uuid_field(item, "artifact_id")
                                        && matches!(
                                            string_field(item, "artifact_kind"),
                                            Some(
                                                "DATABASE"
                                                    | "OBJECT_MANIFEST"
                                                    | "LEDGER_HEAD"
                                                    | "KEY_RECOVERY"
                                            )
                                        )
                                        && resource_identifier(
                                            string_field(item, "immutable_ref").unwrap_or(""),
                                        )
                                        && digest_field(item, "artifact_digest")
                                        && u64_field(item, "size_bytes").is_some()
                                        && identifier_field(item, "encryption_key_version", 128)
                                        && item.get("worm_locked") == Some(&Value::Bool(true))
                                        && evidence_reference_field(item, "evidence_ref")
                                })
                            })
                            && artifacts
                                .iter()
                                .filter_map(|item| {
                                    item.get("artifact_kind").and_then(Value::as_str)
                                })
                                .collect::<BTreeSet<_>>()
                                .len()
                                == 4
                    })
        }
        SreOperation::VerifyRestore => {
            exact_keys(
                value,
                &[
                    "expected_record_counts",
                    "restored_record_counts",
                    "object_integrity_passed",
                    "ledger_reconciled",
                    "key_recovery_passed",
                    "measured_rto_seconds",
                    "measured_rpo_seconds",
                    "report_digest",
                    "command_digest",
                    "started_at",
                    "completed_at",
                ],
            ) && value
                .get("expected_record_counts")
                .is_some_and(Value::is_object)
                && value
                    .get("restored_record_counts")
                    .is_some_and(Value::is_object)
                && [
                    "object_integrity_passed",
                    "ledger_reconciled",
                    "key_recovery_passed",
                ]
                .iter()
                .all(|field| boolean_field(value, field))
                && u64_field(value, "measured_rto_seconds").is_some()
                && u64_field(value, "measured_rpo_seconds").is_some()
                && digest_field(value, "report_digest")
                && digest_field(value, "command_digest")
                && time_order(value, "started_at", "completed_at")
        }
        SreOperation::Failover | SreOperation::Failback => {
            exact_keys(
                value,
                &[
                    "adapter_receipt_digest",
                    "health_evidence_ref",
                    "measured_rto_seconds",
                    "measured_rpo_seconds",
                    "succeeded",
                ],
            ) && digest_field(value, "adapter_receipt_digest")
                && evidence_reference_field(value, "health_evidence_ref")
                && u64_field(value, "measured_rto_seconds").is_some()
                && u64_field(value, "measured_rpo_seconds").is_some()
                && boolean_field(value, "succeeded")
        }
        SreOperation::ExecuteChaos => {
            exact_keys(
                value,
                &[
                    "started_at",
                    "completed_at",
                    "safety_abort_triggered",
                    "cleanup_verified",
                    "dependency_failure_semantics_verified",
                    "emergency_stop_verified",
                    "command_digest",
                    "report_digest",
                    "evidence_refs",
                ],
            ) && time_order(value, "started_at", "completed_at")
                && [
                    "safety_abort_triggered",
                    "cleanup_verified",
                    "dependency_failure_semantics_verified",
                    "emergency_stop_verified",
                ]
                .iter()
                .all(|field| boolean_field(value, field))
                && digest_field(value, "command_digest")
                && digest_field(value, "report_digest")
                && string_array(value, "evidence_refs", 1, 128, evidence_reference)
        }
        SreOperation::ExecuteLoad => {
            exact_keys(
                value,
                &[
                    "requests",
                    "success_millionths",
                    "p50_milliseconds",
                    "p95_milliseconds",
                    "p99_milliseconds",
                    "throughput_millionths",
                    "backpressure_rejections",
                    "noisy_neighbor_isolation_passed",
                    "report_digest",
                    "evidence_refs",
                    "started_at",
                    "completed_at",
                ],
            ) && u64_range(value, "requests", 1, 10_000_000_000)
                && u64_range(value, "success_millionths", 0, 1_000_000)
                && u64_field(value, "p50_milliseconds")
                    .zip(u64_field(value, "p95_milliseconds"))
                    .zip(u64_field(value, "p99_milliseconds"))
                    .is_some_and(|((p50, p95), p99)| p50 <= p95 && p95 <= p99)
                && u64_field(value, "throughput_millionths").is_some()
                && u64_field(value, "backpressure_rejections").is_some()
                && boolean_field(value, "noisy_neighbor_isolation_passed")
                && digest_field(value, "report_digest")
                && string_array(value, "evidence_refs", 1, 128, evidence_reference)
                && time_order(value, "started_at", "completed_at")
        }
        SreOperation::RollbackUpgrade => {
            exact_keys(value, &["rollback_artifact_digest", "succeeded"])
                && digest_field(value, "rollback_artifact_digest")
                && boolean_field(value, "succeeded")
        }
        _ => false,
    }
}

fn facts(receipt: &SreExternalReceipt) -> Result<&Map<String, Value>, SreAuthorityError> {
    receipt
        .facts
        .as_object()
        .ok_or(SreAuthorityError::ExternalReceiptInvalid)
}

fn validate_zone_health_probe_binding(
    payload: &Map<String, Value>,
    observed: &Map<String, Value>,
) -> Result<(), SreAuthorityError> {
    let expected = string_field(payload, "probe_spec_digest")
        .ok_or(SreAuthorityError::RequestInvalid)?;
    let actual = string_field(observed, "probe_spec_digest")
        .ok_or(SreAuthorityError::ExternalReceiptInvalid)?;
    if actual != expected {
        return Err(SreAuthorityError::ExternalReceiptInvalid);
    }
    Ok(())
}

fn require_one(rows: u64) -> Result<(), SreAuthorityError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(SreAuthorityError::StateConflict)
    }
}

fn exact_keys(value: &Map<String, Value>, keys: &[&str]) -> bool {
    value.len() == keys.len() && keys.iter().all(|key| value.contains_key(*key))
}

fn string_field<'a>(value: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn string_value<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, SreAuthorityError> {
    string_field(value, field).ok_or(SreAuthorityError::RequestInvalid)
}

fn json_value(value: &Map<String, Value>, field: &str) -> Result<Value, SreAuthorityError> {
    value
        .get(field)
        .cloned()
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn bool_value(value: &Map<String, Value>, field: &str) -> Result<bool, SreAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn boolean_field(value: &Map<String, Value>, field: &str) -> bool {
    value.get(field).is_some_and(Value::is_boolean)
}

fn u64_field(value: &Map<String, Value>, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn u64_range(value: &Map<String, Value>, field: &str, minimum: u64, maximum: u64) -> bool {
    u64_field(value, field).is_some_and(|item| (minimum..=maximum).contains(&item))
}

fn i64_value(value: &Map<String, Value>, field: &str) -> Result<i64, SreAuthorityError> {
    u64_field(value, field)
        .and_then(|item| i64::try_from(item).ok())
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn i32_value(value: &Map<String, Value>, field: &str) -> Result<i32, SreAuthorityError> {
    u64_field(value, field)
        .and_then(|item| i32::try_from(item).ok())
        .ok_or(SreAuthorityError::RequestInvalid)
}

fn uuid_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(canonical_uuid)
}

fn uuid_value(value: &Map<String, Value>, field: &str) -> Result<Uuid, SreAuthorityError> {
    Uuid::parse_str(string_value(value, field)?).map_err(|_| SreAuthorityError::RequestInvalid)
}

fn optional_uuid_field_valid(value: &Map<String, Value>, field: &str) -> bool {
    matches!(value.get(field), Some(Value::Null)) || uuid_field(value, field)
}

fn optional_uuid_value(
    value: &Map<String, Value>,
    field: &str,
) -> Result<Option<Uuid>, SreAuthorityError> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(item)) => Uuid::parse_str(item)
            .map(Some)
            .map_err(|_| SreAuthorityError::RequestInvalid),
        _ => Err(SreAuthorityError::RequestInvalid),
    }
}

fn time_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(|item| item.parse::<DateTime<Utc>>().is_ok())
}

fn time_value(value: &Map<String, Value>, field: &str) -> Result<DateTime<Utc>, SreAuthorityError> {
    string_value(value, field)?
        .parse()
        .map_err(|_| SreAuthorityError::RequestInvalid)
}

fn time_order(value: &Map<String, Value>, start: &str, end: &str) -> bool {
    time_value(value, start)
        .ok()
        .zip(time_value(value, end).ok())
        .is_some_and(|(start, end)| end > start)
}

fn digest_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(digest)
}

fn evidence_reference_field(value: &Map<String, Value>, field: &str) -> bool {
    string_field(value, field).is_some_and(evidence_reference)
}

fn identifier_field(value: &Map<String, Value>, field: &str, maximum: usize) -> bool {
    string_field(value, field).is_some_and(|item| identifier(item, maximum))
}

fn evidence_status_field(value: &Map<String, Value>, field: &str) -> bool {
    matches!(
        string_field(value, field),
        Some("NOT_RUN" | "OBSERVED" | "VERIFIED")
    )
}

fn string_array(
    value: &Map<String, Value>,
    field: &str,
    minimum: usize,
    maximum: usize,
    validator: impl Fn(&str) -> bool,
) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            (minimum..=maximum).contains(&items.len())
                && items
                    .iter()
                    .all(|item| item.as_str().is_some_and(|value| validator(value)))
                && items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == items.len()
        })
}

fn string_vec(value: &Map<String, Value>, field: &str) -> Result<Vec<String>, SreAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or(SreAuthorityError::RequestInvalid)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or(SreAuthorityError::RequestInvalid)
        })
        .collect()
}

fn u64_array(
    value: &Map<String, Value>,
    field: &str,
    minimum_items: usize,
    maximum_items: usize,
    minimum: u64,
    maximum: u64,
) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            (minimum_items..=maximum_items).contains(&items.len())
                && items.iter().all(|item| {
                    item.as_u64()
                        .is_some_and(|item| (minimum..=maximum).contains(&item))
                })
                && items
                    .windows(2)
                    .all(|pair| pair[0].as_u64() < pair[1].as_u64())
        })
}

fn i32_vec(value: &Map<String, Value>, field: &str) -> Result<Vec<i32>, SreAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or(SreAuthorityError::RequestInvalid)?
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|item| i32::try_from(item).ok())
                .ok_or(SreAuthorityError::RequestInvalid)
        })
        .collect()
}

fn disjoint_string_arrays(value: &Map<String, Value>, left: &str, right: &str) -> bool {
    if !string_array(value, left, 1, 32, |item| identifier(item, 128))
        || !string_array(value, right, 1, 32, |item| identifier(item, 128))
    {
        return false;
    }
    let left = value
        .get(left)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let right = value
        .get(right)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    left.is_disjoint(&right)
}

fn allowed_fault(value: &str) -> bool {
    matches!(
        value,
        "PROCESS_KILL"
            | "LATENCY"
            | "PACKET_LOSS"
            | "NETWORK_PARTITION"
            | "DISK_FULL"
            | "CLOCK_DRIFT"
            | "CPU_EXHAUSTION"
            | "MEMORY_EXHAUSTION"
            | "CERTIFICATE_FAILURE"
            | "KEY_ROTATION_FAILURE"
            | "STORAGE_FAILURE"
            | "MESSAGE_BACKLOG"
    )
}

fn isolated_environment(value: &str) -> bool {
    resource_identifier(value)
        && !value
            .to_ascii_lowercase()
            .split(['/', ':', '-'])
            .any(|part| matches!(part, "prod" | "production"))
}

fn canonical_digest(value: &impl Serialize) -> Result<String, SreAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| SreAuthorityError::RequestInvalid)
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn parse_tenant(value: &TenantId) -> Result<Uuid, SreAuthorityError> {
    Uuid::parse_str(&value.0).map_err(|_| SreAuthorityError::RequestInvalid)
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn resource_identifier(value: &str) -> bool {
    identifier(value, 2_048) && !value.contains("..")
}

fn evidence_reference(value: &str) -> bool {
    (value.starts_with("evidence://") || value.starts_with("urn:agenttrust:evidence:"))
        && value.len() <= 2_048
        && !value.contains(['\0', '\r', '\n', ' ', '?', '#'])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(operation: SreOperation, payload: Value) -> SreCommandRequest {
        SreCommandRequest {
            schema_version: SRE_COMMAND_SCHEMA.into(),
            tenant_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            resource: "sre:test/resource".into(),
            operation,
            expected_resource_version: 0,
            requested_at: Utc::now(),
            payload,
        }
    }

    #[test]
    fn production_chaos_target_is_rejected_by_command_contract() {
        let request = command(
            SreOperation::PlanChaos,
            json!({
                "campaign_id": Uuid::new_v4(),
                "topology_id": Uuid::new_v4(),
                "environment_ref": "isolated-chaos-zone",
                "fault_types": ["NETWORK_PARTITION"],
                "fault_budget_seconds": 60,
                "blast_radius": {"maximum_pods": 1},
                "abort_conditions": ["emergency-stop-unavailable"],
                "cleanup_plan_digest": "a".repeat(64),
                "production_target_allowed": true,
            }),
        );
        assert!(!payload_shape(&request));
    }

    #[test]
    fn upgrade_contract_requires_every_compatibility_gate() {
        let request = command(
            SreOperation::PlanUpgrade,
            json!({
                "rollout_id": Uuid::new_v4(),
                "topology_id": Uuid::new_v4(),
                "from_release_digest": "a".repeat(64),
                "to_release_digest": "b".repeat(64),
                "schema_compatible": true,
                "api_compatible": false,
                "policy_compatible": true,
                "pack_compatible": true,
                "migration_digest": "c".repeat(64),
                "rollback_digest": "d".repeat(64),
                "canary_steps": [1,10,50,100],
                "maximum_error_rate_millionths": 1000,
            }),
        );
        assert!(!payload_shape(&request));
    }

    #[test]
    fn zone_health_receipt_requires_complete_facts_and_exact_probe_binding() {
        let probe_spec_digest = "a".repeat(64);
        let payload = json!({"probe_spec_digest": probe_spec_digest})
            .as_object()
            .cloned()
            .expect("payload object");
        let facts = json!({
            "component_health": {"control-plane": true},
            "dependency_health": {"postgres": true},
            "ready_replicas": 3,
            "required_replicas": 3,
            "topology_probe_digest": "b".repeat(64),
            "probe_spec_digest": "a".repeat(64),
            "observed_at": Utc::now(),
        });
        assert!(external_fact_shape(SreOperation::RecordZoneHealth, &facts));
        assert_eq!(
            validate_zone_health_probe_binding(
                &payload,
                facts.as_object().expect("facts object"),
            ),
            Ok(())
        );

        let mut mismatched = facts.as_object().cloned().expect("facts object");
        mismatched.insert("probe_spec_digest".into(), Value::String("c".repeat(64)));
        assert_eq!(
            validate_zone_health_probe_binding(&payload, &mismatched),
            Err(SreAuthorityError::ExternalReceiptInvalid)
        );
        mismatched.remove("dependency_health");
        assert!(!external_fact_shape(
            SreOperation::RecordZoneHealth,
            &Value::Object(mismatched)
        ));
    }

    #[test]
    fn local_engine_report_can_never_be_a_production_certificate() {
        let report = SignedSreEngineReport {
            schema_version: SRE_ENGINE_REPORT_SCHEMA.into(),
            report_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            operation: SreOperation::RecordSli,
            resource: "sre:slo/example".into(),
            resource_version: 1,
            result_digest: "a".repeat(64),
            external_evidence_status: ExternalEvidenceStatus::NotRun,
            evidence_refs: BTreeSet::from(["evidence://authorization/example".into()]),
            evidence_digests: BTreeSet::from(["b".repeat(64)]),
            engine_report_only: true,
            production_certification: false,
            issued_at: Utc::now(),
            key_id: "sre-engine-v1".into(),
            signature: String::new(),
        };
        assert!(report.engine_report_only);
        assert!(!report.production_certification);
        assert_eq!(
            report.external_evidence_status,
            ExternalEvidenceStatus::NotRun
        );
    }

    #[test]
    fn dependency_failure_matrix_keeps_ordinary_writes_closed() {
        for dependency in [
            crate::Dependency::Policy,
            crate::Dependency::Identity,
            crate::Dependency::Ledger,
        ] {
            let resolution = crate::DependencyFailureResolver::resolve(
                crate::ActionClass::OrdinaryWrite,
                BTreeSet::from([dependency]),
                true,
            );
            assert_eq!(resolution.mode, crate::FailureMode::FailClosed);
        }
    }
}

#[derive(Clone)]
pub struct SreIngressAuthority {
    store: PostgresSreAuthorityStore,
    orchestrator: Arc<dyn SreOrchestratorPort>,
    config: SreAuthorityConfig,
}

impl SreIngressAuthority {
    pub fn new(
        store: PostgresSreAuthorityStore,
        orchestrator: Arc<dyn SreOrchestratorPort>,
        config: SreAuthorityConfig,
    ) -> Result<Self, SreAuthorityError> {
        config.validate()?;
        Ok(Self {
            store,
            orchestrator,
            config,
        })
    }

    pub async fn submit(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: SreCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<SreActionReceipt, SreAuthorityError> {
        validate_command(principal, &request, request_digest, idempotency_key)?;
        let tenant = principal.tenant_id.clone();
        let current = self
            .store
            .current_resource_version(&tenant, &request.resource)
            .await?;
        if current != request.expected_resource_version {
            return Err(SreAuthorityError::StateConflict);
        }
        let envelope = canonical_sre_action(principal, &request, &self.config)?;
        let prepared = self
            .store
            .prepare_ingress(
                principal,
                &request,
                request_digest,
                idempotency_key,
                envelope,
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

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.orchestrator.ready().await
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        after: Option<&str>,
        limit: i64,
    ) -> Result<SreResourcePage, SreAuthorityError> {
        self.store.authoritative_page(tenant, after, limit).await
    }
}

#[derive(Debug)]
struct PreparedIngress {
    envelope: InboundEnvelope,
    receipt: Option<SreActionReceipt>,
}

impl PostgresSreAuthorityStore {
    async fn prepare_ingress(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: &SreCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        mut envelope: InboundEnvelope,
    ) -> Result<PreparedIngress, SreAuthorityError> {
        envelope.idempotency_key = Some(idempotency_key.to_string());
        let tenant = request.tenant_id;
        let envelope_value =
            serde_json::to_value(&envelope).map_err(|_| SreAuthorityError::RequestInvalid)?;
        let jti =
            Uuid::parse_str(&principal.jti).map_err(|_| SreAuthorityError::PrincipalDenied)?;
        let mut tx = self.begin_tenant(&principal.tenant_id).await?;
        sqlx::query(
            "INSERT INTO sre_principal_assertion_replay \
             (tenant_id,jti,assertion_digest,request_digest,expires_at) \
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,jti) DO NOTHING",
        )
        .bind(tenant)
        .bind(jti)
        .bind(&principal.assertion_digest)
        .bind(request_digest)
        .bind(principal.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let replay = sqlx::query(
            "SELECT assertion_digest,request_digest,expires_at FROM sre_principal_assertion_replay \
             WHERE tenant_id=$1 AND jti=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(jti)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if replay.get::<String, _>("assertion_digest") != principal.assertion_digest
            || replay.get::<String, _>("request_digest") != request_digest
            || replay.get::<DateTime<Utc>, _>("expires_at") != principal.expires_at
        {
            return Err(SreAuthorityError::IdempotencyConflict);
        }
        sqlx::query(
            "INSERT INTO sre_action_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,resource,operation,\
              principal_subject,principal_assertion_digest,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED') \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(request.command_id)
        .bind(request.task_id)
        .bind(&request.resource)
        .bind(request.operation.as_str())
        .bind(&principal.subject)
        .bind(&principal.assertion_digest)
        .bind(&envelope_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let row = sqlx::query(
            "SELECT request_digest,action_id,task_id,resource,operation,principal_subject,\
                    principal_assertion_digest,envelope,receipt FROM sre_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command_id
            || row.get::<Uuid, _>("task_id") != request.task_id
            || row.get::<String, _>("resource") != request.resource
            || row.get::<String, _>("operation") != request.operation.as_str()
            || row.get::<String, _>("principal_subject") != principal.subject
            || row.get::<String, _>("principal_assertion_digest") != principal.assertion_digest
            || row.get::<Value, _>("envelope") != envelope_value
        {
            return Err(SreAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("receipt")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        Ok(PreparedIngress { envelope, receipt })
    }

    async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &SreActionReceipt,
    ) -> Result<SreActionReceipt, SreAuthorityError> {
        if receipt.schema_version != SRE_ACTION_RECEIPT_SCHEMA
            || !receipt.accepted
            || !receipt.execution_pending
            || !canonical_uuid(&receipt.action_id)
            || !canonical_uuid(&receipt.task_id)
            || !digest(&receipt.ingress_digest)
            || !evidence_reference(&receipt.ledger_evidence_ref)
            || !digest(&receipt.ledger_evidence_digest)
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let value =
            serde_json::to_value(receipt).map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,state,receipt FROM sre_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("action_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(SreAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("receipt") {
            if existing != value {
                return Err(SreAuthorityError::IdempotencyConflict);
            }
        } else {
            let updated = sqlx::query(
                "UPDATE sre_action_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(SreAuthorityError::OutcomeUnknown);
            }
        }
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }
}

fn validate_command(
    principal: &VerifiedHumanPrincipal,
    request: &SreCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), SreAuthorityError> {
    let now = Utc::now();
    if request.schema_version != SRE_COMMAND_SCHEMA
        || request.tenant_id.to_string() != principal.tenant_id.0
        || request.command_id.is_nil()
        || request.task_id.is_nil()
        || !principal.strong_auth
        || !principal.roles.contains(request.operation.required_role())
        || principal.approval_ids.len() < request.operation.minimum_approvals()
        || !resource_identifier(&request.resource)
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || request.payload.as_object().is_none()
        || serde_json::to_vec(&request.payload).map_or(true, |value| value.len() > 1_048_576)
        || request.requested_at > now + Duration::minutes(1)
        || request.requested_at < now - Duration::hours(24)
        || !payload_shape(request)
        || !resource_matches_payload(request)
    {
        return Err(SreAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn payload_shape(request: &SreCommandRequest) -> bool {
    let Some(payload) = request.payload.as_object() else {
        return false;
    };
    match request.operation {
        SreOperation::ConfigureSlo => {
            exact_keys(
                payload,
                &[
                    "slo_id",
                    "service",
                    "sli_kind",
                    "window_seconds",
                    "target_millionths",
                    "minimum_samples",
                    "fast_burn_threshold_millionths",
                    "slow_burn_threshold_millionths",
                    "release_blocking",
                    "status",
                ],
            ) && uuid_field(payload, "slo_id")
                && identifier_field(payload, "service", 128)
                && matches!(
                    string_field(payload, "sli_kind"),
                    Some(
                        "AVAILABILITY"
                            | "AUTHORIZATION_LATENCY"
                            | "UNSAFE_ALLOW"
                            | "EVIDENCE_COMPLETENESS"
                            | "RECOVERY_TIME"
                            | "RECOVERY_POINT"
                            | "BACKPRESSURE_REJECTION"
                    )
                )
                && u64_range(payload, "window_seconds", 60, 2_592_000)
                && u64_range(payload, "target_millionths", 1, 1_000_000)
                && u64_range(payload, "minimum_samples", 1, 1_000_000_000)
                && u64_range(payload, "fast_burn_threshold_millionths", 1, 1_000_000_000)
                && u64_range(payload, "slow_burn_threshold_millionths", 1, 1_000_000_000)
                && boolean_field(payload, "release_blocking")
                && matches!(
                    string_field(payload, "status"),
                    Some("ACTIVE" | "PAUSED" | "RETIRED")
                )
        }
        SreOperation::RecordSli => {
            exact_keys(
                payload,
                &[
                    "observation_id",
                    "slo_id",
                    "release_digest",
                    "good_events",
                    "total_events",
                    "window_started_at",
                    "window_ended_at",
                    "trace_evidence_ref",
                    "metrics_evidence_ref",
                    "logs_evidence_ref",
                    "evidence_digest",
                    "alert_id",
                ],
            ) && uuid_field(payload, "observation_id")
                && uuid_field(payload, "slo_id")
                && digest_field(payload, "release_digest")
                && u64_field(payload, "good_events")
                    .zip(u64_field(payload, "total_events"))
                    .is_some_and(|(good, total)| good <= total)
                && time_order(payload, "window_started_at", "window_ended_at")
                && [
                    "trace_evidence_ref",
                    "metrics_evidence_ref",
                    "logs_evidence_ref",
                ]
                .iter()
                .all(|field| evidence_reference_field(payload, field))
                && digest_field(payload, "evidence_digest")
                && optional_uuid_field_valid(payload, "alert_id")
        }
        SreOperation::UpdateBurnAlert => {
            exact_keys(
                payload,
                &["alert_id", "state", "owner_subject", "resolved_at"],
            ) && uuid_field(payload, "alert_id")
                && matches!(
                    string_field(payload, "state"),
                    Some("ACKNOWLEDGED" | "MITIGATING" | "RESOLVED")
                )
                && identifier_field(payload, "owner_subject", 256)
                && if string_field(payload, "state") == Some("RESOLVED") {
                    time_field(payload, "resolved_at")
                } else {
                    payload.get("resolved_at") == Some(&Value::Null)
                }
        }
        SreOperation::LinkIncident => {
            exact_keys(
                payload,
                &[
                    "link_id",
                    "alert_id",
                    "incident_id",
                    "incident_evidence_ref",
                ],
            ) && ["link_id", "alert_id", "incident_id"]
                .iter()
                .all(|field| uuid_field(payload, field))
                && evidence_reference_field(payload, "incident_evidence_ref")
        }
        SreOperation::RegisterTopology => {
            exact_keys(
                payload,
                &[
                    "topology_id",
                    "deployment_mode",
                    "release_digest",
                    "topology_digest",
                    "zones",
                    "components",
                    "quorum_rules",
                    "disruption_budgets",
                    "immutable_image_digests",
                    "status",
                ],
            ) && uuid_field(payload, "topology_id")
                && matches!(
                    string_field(payload, "deployment_mode"),
                    Some("SAAS" | "PRIVATE" | "OFFLINE" | "EDGE_HYBRID")
                )
                && digest_field(payload, "release_digest")
                && digest_field(payload, "topology_digest")
                && string_array(payload, "zones", 1, 32, |value| identifier(value, 128))
                && [
                    "components",
                    "quorum_rules",
                    "disruption_budgets",
                    "immutable_image_digests",
                ]
                .iter()
                .all(|field| payload.get(*field).is_some_and(Value::is_object))
                && matches!(
                    string_field(payload, "status"),
                    Some("REGISTERED" | "HEALTHY" | "DEGRADED" | "FAILED" | "RETIRED")
                )
        }
        SreOperation::RecordZoneHealth => {
            exact_keys(
                payload,
                &["observation_id", "topology_id", "zone", "probe_spec_digest"],
            ) && uuid_field(payload, "observation_id")
                && uuid_field(payload, "topology_id")
                && identifier_field(payload, "zone", 128)
                && digest_field(payload, "probe_spec_digest")
        }
        SreOperation::CreateBackup => {
            exact_keys(
                payload,
                &[
                    "backup_id",
                    "topology_id",
                    "release_digest",
                    "scope",
                    "scope_digest",
                    "key_version",
                    "minimum_worm_retention_seconds",
                ],
            ) && uuid_field(payload, "backup_id")
                && uuid_field(payload, "topology_id")
                && digest_field(payload, "release_digest")
                && string_array(payload, "scope", 1, 64, |value| identifier(value, 128))
                && digest_field(payload, "scope_digest")
                && identifier_field(payload, "key_version", 128)
                && u64_range(
                    payload,
                    "minimum_worm_retention_seconds",
                    86_400,
                    315_360_000,
                )
        }
        SreOperation::VerifyRestore => {
            exact_keys(
                payload,
                &[
                    "drill_id",
                    "backup_id",
                    "topology_id",
                    "isolated_environment_ref",
                    "maximum_rto_seconds",
                    "maximum_rpo_seconds",
                    "restore_target_digest",
                ],
            ) && ["drill_id", "backup_id", "topology_id"]
                .iter()
                .all(|field| uuid_field(payload, field))
                && string_field(payload, "isolated_environment_ref")
                    .is_some_and(isolated_environment)
                && u64_range(payload, "maximum_rto_seconds", 1, 604_800)
                && u64_range(payload, "maximum_rpo_seconds", 0, 604_800)
                && digest_field(payload, "restore_target_digest")
        }
        SreOperation::PlanDr => {
            exact_keys(
                payload,
                &[
                    "plan_id",
                    "topology_id",
                    "recovery_drill_id",
                    "source_zones",
                    "target_zones",
                    "maximum_rto_seconds",
                    "maximum_rpo_seconds",
                    "failover_steps",
                    "failback_steps",
                    "health_checks",
                ],
            ) && ["plan_id", "topology_id", "recovery_drill_id"]
                .iter()
                .all(|field| uuid_field(payload, field))
                && disjoint_string_arrays(payload, "source_zones", "target_zones")
                && u64_range(payload, "maximum_rto_seconds", 1, 604_800)
                && u64_range(payload, "maximum_rpo_seconds", 0, 604_800)
                && ["failover_steps", "failback_steps", "health_checks"]
                    .iter()
                    .all(|field| {
                        payload
                            .get(*field)
                            .and_then(Value::as_array)
                            .is_some_and(|value| !value.is_empty() && value.len() <= 256)
                    })
        }
        SreOperation::Failover | SreOperation::Failback => {
            exact_keys(
                payload,
                &[
                    "event_id",
                    "plan_id",
                    "reason_digest",
                    "expected_health_digest",
                ],
            ) && uuid_field(payload, "event_id")
                && uuid_field(payload, "plan_id")
                && digest_field(payload, "reason_digest")
                && digest_field(payload, "expected_health_digest")
        }
        SreOperation::PlanChaos => {
            exact_keys(
                payload,
                &[
                    "campaign_id",
                    "topology_id",
                    "environment_ref",
                    "fault_types",
                    "fault_budget_seconds",
                    "blast_radius",
                    "abort_conditions",
                    "cleanup_plan_digest",
                    "production_target_allowed",
                ],
            ) && uuid_field(payload, "campaign_id")
                && uuid_field(payload, "topology_id")
                && string_field(payload, "environment_ref").is_some_and(isolated_environment)
                && string_array(payload, "fault_types", 1, 16, allowed_fault)
                && u64_range(payload, "fault_budget_seconds", 1, 3_600)
                && payload.get("blast_radius").is_some_and(Value::is_object)
                && payload
                    .get("abort_conditions")
                    .and_then(Value::as_array)
                    .is_some_and(|value| !value.is_empty() && value.len() <= 128)
                && digest_field(payload, "cleanup_plan_digest")
                && payload.get("production_target_allowed") == Some(&Value::Bool(false))
        }
        SreOperation::ExecuteChaos => {
            exact_keys(
                payload,
                &[
                    "result_id",
                    "campaign_id",
                    "fault_type",
                    "execution_authorization_digest",
                ],
            ) && uuid_field(payload, "result_id")
                && uuid_field(payload, "campaign_id")
                && string_field(payload, "fault_type").is_some_and(allowed_fault)
                && digest_field(payload, "execution_authorization_digest")
        }
        SreOperation::PlanLoad => {
            exact_keys(
                payload,
                &[
                    "campaign_id",
                    "topology_id",
                    "release_digest",
                    "workload_digest",
                    "duration_seconds",
                    "concurrency",
                    "maximum_requests",
                    "tenant_quota",
                    "stop_conditions",
                ],
            ) && uuid_field(payload, "campaign_id")
                && uuid_field(payload, "topology_id")
                && digest_field(payload, "release_digest")
                && digest_field(payload, "workload_digest")
                && u64_range(payload, "duration_seconds", 60, 604_800)
                && u64_range(payload, "concurrency", 1, 1_000_000)
                && u64_range(payload, "maximum_requests", 1, 10_000_000_000)
                && payload.get("tenant_quota").is_some_and(Value::is_object)
                && payload
                    .get("stop_conditions")
                    .and_then(Value::as_array)
                    .is_some_and(|value| !value.is_empty() && value.len() <= 128)
        }
        SreOperation::ExecuteLoad => {
            exact_keys(
                payload,
                &["result_id", "campaign_id", "execution_authorization_digest"],
            ) && uuid_field(payload, "result_id")
                && uuid_field(payload, "campaign_id")
                && digest_field(payload, "execution_authorization_digest")
        }
        SreOperation::PlanUpgrade => {
            exact_keys(
                payload,
                &[
                    "rollout_id",
                    "topology_id",
                    "from_release_digest",
                    "to_release_digest",
                    "schema_compatible",
                    "api_compatible",
                    "policy_compatible",
                    "pack_compatible",
                    "migration_digest",
                    "rollback_digest",
                    "canary_steps",
                    "maximum_error_rate_millionths",
                ],
            ) && uuid_field(payload, "rollout_id")
                && uuid_field(payload, "topology_id")
                && [
                    "from_release_digest",
                    "to_release_digest",
                    "migration_digest",
                    "rollback_digest",
                ]
                .iter()
                .all(|field| digest_field(payload, field))
                && string_field(payload, "from_release_digest")
                    != string_field(payload, "to_release_digest")
                && [
                    "schema_compatible",
                    "api_compatible",
                    "policy_compatible",
                    "pack_compatible",
                ]
                .iter()
                .all(|field| payload.get(*field) == Some(&Value::Bool(true)))
                && u64_array(payload, "canary_steps", 1, 20, 1, 100)
                && u64_range(payload, "maximum_error_rate_millionths", 0, 1_000_000)
        }
        SreOperation::RecordCanary => {
            exact_keys(
                payload,
                &[
                    "observation_id",
                    "rollout_id",
                    "canary_percent",
                    "error_rate_millionths",
                    "unsafe_allow_count",
                    "evidence_gap_count",
                    "metrics_digest",
                    "evidence_refs",
                    "observed_at",
                ],
            ) && uuid_field(payload, "observation_id")
                && uuid_field(payload, "rollout_id")
                && u64_range(payload, "canary_percent", 1, 100)
                && u64_range(payload, "error_rate_millionths", 0, 1_000_000)
                && u64_field(payload, "unsafe_allow_count").is_some()
                && u64_field(payload, "evidence_gap_count").is_some()
                && digest_field(payload, "metrics_digest")
                && string_array(payload, "evidence_refs", 1, 128, evidence_reference)
                && time_field(payload, "observed_at")
        }
        SreOperation::RollbackUpgrade => {
            exact_keys(
                payload,
                &["rollout_id", "reason_digest", "rollback_artifact_digest"],
            ) && uuid_field(payload, "rollout_id")
                && digest_field(payload, "reason_digest")
                && digest_field(payload, "rollback_artifact_digest")
        }
        SreOperation::RecordCostCapacity => {
            exact_keys(
                payload,
                &[
                    "observation_id",
                    "topology_id",
                    "release_digest",
                    "period_started_at",
                    "period_ended_at",
                    "task_count",
                    "request_count",
                    "compute_microunits",
                    "storage_microunits",
                    "network_microunits",
                    "model_microunits",
                    "maximum_global_tasks",
                    "maximum_tasks_per_tenant",
                    "queue_capacity",
                    "connection_pool_capacity",
                    "evidence_buffer_capacity",
                    "source_digest",
                ],
            ) && uuid_field(payload, "observation_id")
                && uuid_field(payload, "topology_id")
                && digest_field(payload, "release_digest")
                && time_order(payload, "period_started_at", "period_ended_at")
                && [
                    "task_count",
                    "request_count",
                    "compute_microunits",
                    "storage_microunits",
                    "network_microunits",
                    "model_microunits",
                ]
                .iter()
                .all(|field| u64_field(payload, field).is_some())
                && [
                    "maximum_global_tasks",
                    "maximum_tasks_per_tenant",
                    "queue_capacity",
                    "connection_pool_capacity",
                    "evidence_buffer_capacity",
                ]
                .iter()
                .all(|field| u64_range(payload, field, 1, i64::MAX as u64))
                && u64_field(payload, "maximum_tasks_per_tenant")
                    <= u64_field(payload, "maximum_global_tasks")
                && digest_field(payload, "source_digest")
        }
        SreOperation::RecordObservability => {
            exact_keys(
                payload,
                &[
                    "evidence_id",
                    "trace_id",
                    "trace_digest",
                    "log_digest",
                    "metrics_digest",
                    "redaction_policy_digest",
                    "immutable_refs",
                    "collected_at",
                ],
            ) && uuid_field(payload, "evidence_id")
                && identifier_field(payload, "trace_id", 128)
                && [
                    "trace_digest",
                    "log_digest",
                    "metrics_digest",
                    "redaction_policy_digest",
                ]
                .iter()
                .all(|field| digest_field(payload, field))
                && string_array(payload, "immutable_refs", 3, 128, evidence_reference)
                && time_field(payload, "collected_at")
        }
    }
}

fn resource_matches_payload(request: &SreCommandRequest) -> bool {
    let Some(payload) = request.payload.as_object() else {
        return false;
    };
    let (kind, identifier_field) = match request.operation {
        SreOperation::ConfigureSlo | SreOperation::RecordSli => ("slo", "slo_id"),
        SreOperation::UpdateBurnAlert | SreOperation::LinkIncident => ("alert", "alert_id"),
        SreOperation::RegisterTopology | SreOperation::RecordZoneHealth => {
            ("topology", "topology_id")
        }
        SreOperation::CreateBackup => ("backup", "backup_id"),
        SreOperation::VerifyRestore => ("restore", "drill_id"),
        SreOperation::PlanDr | SreOperation::Failover | SreOperation::Failback => ("dr", "plan_id"),
        SreOperation::PlanChaos | SreOperation::ExecuteChaos => ("chaos", "campaign_id"),
        SreOperation::PlanLoad | SreOperation::ExecuteLoad => ("load", "campaign_id"),
        SreOperation::PlanUpgrade | SreOperation::RecordCanary | SreOperation::RollbackUpgrade => {
            ("rollout", "rollout_id")
        }
        SreOperation::RecordCostCapacity => ("cost-capacity", "observation_id"),
        SreOperation::RecordObservability => ("observability", "evidence_id"),
    };
    string_field(payload, identifier_field)
        .is_some_and(|identifier| request.resource == format!("sre:{kind}/{identifier}"))
}

fn canonical_sre_action(
    principal: &VerifiedHumanPrincipal,
    request: &SreCommandRequest,
    config: &SreAuthorityConfig,
) -> Result<InboundEnvelope, SreAuthorityError> {
    let now = Utc::now();
    let tenant = principal.tenant_id.clone();
    let executor = SreExecutorRequest {
        schema_version: SRE_EXECUTOR_REQUEST_SCHEMA.into(),
        command: request.clone(),
        actor_subject: principal.subject.clone(),
        principal_assertion_digest: principal.assertion_digest.clone(),
        approval_ids: principal.approval_ids.clone(),
    };
    let data = serde_json::to_value(&executor)
        .map_err(|_| SreAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(SreAuthorityError::RequestInvalid)?;
    let plan_hash = canonical_digest(&json!({
        "operation": request.operation,
        "resource": request.resource,
        "expected_resource_version": request.expected_resource_version,
        "payload": request.payload,
    }))?;
    let mut extensions = BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    extensions.insert(
        "x-human-principal-assertion-digest".into(),
        Value::String(principal.assertion_digest.clone()),
    );
    extensions.insert(
        "x-required-control-path".into(),
        Value::String("CANONICAL_ACTION_IR->PEP->LEDGER->EVIDENCE".into()),
    );
    extensions.insert(
        "x-production-certification".into(),
        Value::String("NOT_ISSUED".into()),
    );
    let operation = request.operation.as_str().to_ascii_lowercase();
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(request.command_id.to_string()),
        task_id: TaskId(request.task_id.to_string()),
        step_id: StepId::new(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "platform-sre-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: principal.subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-platform-sre-engine".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: format!("human-assertion://{}", principal.jti),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: canonical_digest(request)?,
            operation: operation.clone(),
            justification_code: "PLATFORM_SRE_GOVERNANCE".into(),
            safe_summary: Some(format!(
                "{} {}",
                request.operation.as_str(),
                request.resource
            )),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "platform.sre.mutation.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator: format!("platform-sre/{}", request.resource),
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: matches!(
                request.operation,
                SreOperation::PlanChaos | SreOperation::ExecuteChaos
            ) && request.payload.get("production_target_allowed")
                != Some(&Value::Bool(true)),
        },
        current_state_version: Some(request.expected_resource_version.to_string()),
        risk: RiskContext {
            declared_risk: request.operation.risk(),
            trajectory_risk_ref: None,
            scope_delta: 1,
            automation_allowed: false,
        },
        data: DataContext {
            classification: DataClassification::Restricted,
            jurisdiction: config.region.clone(),
            export_constraints: vec!["TENANT_BOUND".into(), "SRE_EVIDENCE_IMMUTABLE".into()],
        },
        expected_outcome: ExpectedOutcome {
            metric: "sre_authority_state_persisted".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "platform-sre/".into(),
            operations: vec![operation],
        }],
        requested_at: request.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("platform.sre.mutation.v1", "1");
    let action = normalize(draft, &normalization).map_err(|_| SreAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| SreAuthorityError::RequestInvalid)?;
    let payload = serde_json::to_vec(&action).map_err(|_| SreAuthorityError::RequestInvalid)?;
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
            owner_subject: principal.subject.clone(),
            trust_level: "attested".into(),
        },
        tenant_context: TenantContext {
            tenant_id: tenant,
            quota_profile: "platform-sre-authority".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: None,
        received_at: now,
        payload_hash: sha256(&payload),
        payload,
    })
}

#[derive(Clone)]
pub struct SreExecutor {
    store: PostgresSreAuthorityStore,
    effects: Arc<dyn SreEffectPort>,
    report_key_id: String,
    report_signing_key: Arc<SigningKey>,
    execution_lease_seconds: i64,
}

impl SreExecutor {
    pub fn new(
        store: PostgresSreAuthorityStore,
        effects: Arc<dyn SreEffectPort>,
        report_key_id: String,
        report_signing_key: SigningKey,
        execution_lease_seconds: i64,
    ) -> Result<Self, SreAuthorityError> {
        if !identifier(&report_key_id, 128) || !(15..=300).contains(&execution_lease_seconds) {
            return Err(SreAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            effects,
            report_key_id,
            report_signing_key: Arc::new(report_signing_key),
            execution_lease_seconds,
        })
    }

    pub async fn execute(
        &self,
        binding: SreExecutionBinding,
        request: SreExecutorRequest,
    ) -> Result<SreMutationResult, SreAuthorityError> {
        validate_execution(&binding, &request)?;
        let claim = match self
            .store
            .claim_execution(&binding, &request, self.execution_lease_seconds)
            .await?
        {
            ExecutionClaim::Completed(result) => return Ok(result),
            ExecutionClaim::PendingEvidence(pending) => {
                return self.publish_and_finalize(&binding.tenant_id, pending).await;
            }
            ExecutionClaim::Claimed(value) => value,
        };
        let external = self.effects.execute(&binding, &request).await?;
        validate_external_receipt(&binding, &request, external.as_ref())?;
        let report = self.issue_engine_report(&binding, &request, external.as_ref())?;
        let pending = self
            .store
            .commit_mutation(&binding, &request, claim, external, report)
            .await?;
        self.publish_and_finalize(&binding.tenant_id, pending).await
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await && self.effects.ready().await
    }

    async fn publish_and_finalize(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
    ) -> Result<SreMutationResult, SreAuthorityError> {
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

    fn issue_engine_report(
        &self,
        binding: &SreExecutionBinding,
        request: &SreExecutorRequest,
        external: Option<&SreExternalReceipt>,
    ) -> Result<SignedSreEngineReport, SreAuthorityError> {
        let next = request
            .command
            .expected_resource_version
            .checked_add(1)
            .ok_or(SreAuthorityError::StateConflict)?;
        let result_digest = canonical_digest(&json!({
            "command": request.command,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "ledger_event_id": binding.ledger_event_id,
            "ledger_event_digest": binding.ledger_event_digest,
            "fence_digest": binding.fence_digest,
            "policy_decision_digest": binding.policy_decision_digest,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "external_result_digest": external.map(|value| value.result_digest.as_str()),
            "resource_version": next,
        }))?;
        let mut evidence_refs = BTreeSet::from([binding.authorization_evidence_ref.clone()]);
        let mut evidence_digests = BTreeSet::from([binding.authorization_evidence_digest.clone()]);
        let status = external
            .map(|value| value.external_evidence_status)
            .unwrap_or(ExternalEvidenceStatus::NotRun);
        if let Some(external) = external {
            evidence_refs.extend(external.immutable_evidence_refs.iter().cloned());
            evidence_digests.extend(external.immutable_evidence_digests.iter().cloned());
        }
        let mut report = SignedSreEngineReport {
            schema_version: SRE_ENGINE_REPORT_SCHEMA.into(),
            report_id: Uuid::new_v4(),
            tenant_id: request.command.tenant_id,
            command_id: request.command.command_id,
            operation: request.command.operation,
            resource: request.command.resource.clone(),
            resource_version: next,
            result_digest,
            external_evidence_status: status,
            evidence_refs,
            evidence_digests,
            engine_report_only: true,
            production_certification: false,
            issued_at: Utc::now(),
            key_id: self.report_key_id.clone(),
            signature: String::new(),
        };
        report.signature = URL_SAFE_NO_PAD.encode(
            self.report_signing_key
                .sign(&report.signing_bytes()?)
                .to_bytes(),
        );
        Ok(report)
    }
}

#[derive(Debug)]
enum ExecutionClaim {
    Completed(SreMutationResult),
    PendingEvidence(PendingEvidence),
    Claimed(Uuid),
}

#[derive(Debug, Clone)]
struct PendingEvidence {
    event_id: Uuid,
    idempotency_key: String,
    payload: Value,
    payload_digest: String,
    result: SreMutationResult,
}

fn validate_execution(
    binding: &SreExecutionBinding,
    request: &SreExecutorRequest,
) -> Result<(), SreAuthorityError> {
    if request.schema_version != SRE_EXECUTOR_REQUEST_SCHEMA
        || request.command.schema_version != SRE_COMMAND_SCHEMA
        || request.command.tenant_id.to_string() != binding.tenant_id.0
        || request.command.expected_resource_version != binding.resource_version
        || !resource_identifier(&request.command.resource)
        || !identifier(&request.actor_subject, 256)
        || !digest(&request.principal_assertion_digest)
        || request.approval_ids.len() < request.command.operation.minimum_approvals()
        || !digest(&binding.action_hash)
        || binding.ledger_execution_id.is_nil()
        || binding.ledger_event_id.is_nil()
        || !digest(&binding.ledger_event_digest)
        || !digest(&binding.fence_digest)
        || !valid_idempotency_key(&binding.idempotency_key)
        || !identifier(&binding.trace_id, 128)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !evidence_reference(&binding.authorization_evidence_ref)
        || !digest(&binding.authorization_evidence_digest)
        || !payload_shape(&request.command)
        || !resource_matches_payload(&request.command)
    {
        return Err(SreAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_external_receipt(
    binding: &SreExecutionBinding,
    request: &SreExecutorRequest,
    receipt: Option<&SreExternalReceipt>,
) -> Result<(), SreAuthorityError> {
    if !request.command.operation.external_effect() {
        return if receipt.is_none() {
            Ok(())
        } else {
            Err(SreAuthorityError::ExternalReceiptInvalid)
        };
    }
    let receipt = receipt.ok_or(SreAuthorityError::ExternalReceiptInvalid)?;
    if receipt.schema_version != SRE_EXTERNAL_RECEIPT_SCHEMA
        || receipt.tenant_id != request.command.tenant_id
        || receipt.operation != request.command.operation
        || receipt.resource != request.command.resource
        || receipt.idempotency_key != binding.idempotency_key
        || receipt.action_hash != binding.action_hash
        || receipt.ledger_execution_id != binding.ledger_execution_id
        || receipt.ledger_event_id != binding.ledger_event_id
        || receipt.ledger_event_digest != binding.ledger_event_digest
        || receipt.fence_digest != binding.fence_digest
        || receipt.policy_decision_digest != binding.policy_decision_digest
        || receipt.authorization_evidence_ref != binding.authorization_evidence_ref
        || receipt.authorization_evidence_digest != binding.authorization_evidence_digest
        || canonical_digest(request)? != receipt.request_digest
        || canonical_digest(&receipt.facts)? != receipt.result_digest
        || receipt.immutable_evidence_refs.is_empty()
        || receipt.immutable_evidence_refs.len() > 128
        || receipt
            .immutable_evidence_refs
            .iter()
            .any(|value| !evidence_reference(value))
        || receipt.immutable_evidence_digests.len() != receipt.immutable_evidence_refs.len()
        || receipt
            .immutable_evidence_digests
            .iter()
            .any(|value| !digest(value))
        || receipt.facts.as_object().is_none()
        || receipt.production_evidence
            && receipt.external_evidence_status != ExternalEvidenceStatus::Verified
        || !external_fact_shape(request.command.operation, &receipt.facts)
    {
        return Err(SreAuthorityError::ExternalReceiptInvalid);
    }
    if request.command.operation == SreOperation::RecordZoneHealth {
        validate_zone_health_probe_binding(
            request
                .command
                .payload
                .as_object()
                .ok_or(SreAuthorityError::RequestInvalid)?,
            receipt
                .facts
                .as_object()
                .ok_or(SreAuthorityError::ExternalReceiptInvalid)?,
        )?;
    }
    Ok(())
}

fn validate_evidence_receipt(
    pending: &PendingEvidence,
    receipt: &SreEvidenceDeliveryReceipt,
) -> Result<(), SreAuthorityError> {
    if receipt.schema_version != "agenttrust.sre-evidence-delivery-receipt.v1"
        || receipt.idempotency_key != pending.idempotency_key
        || !evidence_reference(&receipt.evidence_ref)
        || !digest(&receipt.evidence_digest)
        || receipt.payload_digest != pending.payload_digest
    {
        return Err(SreAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

impl PostgresSreAuthorityStore {
    async fn claim_execution(
        &self,
        binding: &SreExecutionBinding,
        request: &SreExecutorRequest,
        lease_seconds: i64,
    ) -> Result<ExecutionClaim, SreAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(request)?;
        let request_value =
            serde_json::to_value(request).map_err(|_| SreAuthorityError::RequestInvalid)?;
        let expected_version = i64::try_from(binding.resource_version)
            .map_err(|_| SreAuthorityError::RequestInvalid)?;
        let owner = Uuid::new_v4();
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let ingress = sqlx::query(
            "SELECT state,principal_subject,principal_assertion_digest,envelope \
             FROM sre_action_ingress WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?
        .ok_or(SreAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("principal_subject") != request.actor_subject
            || ingress.get::<String, _>("principal_assertion_digest")
                != request.principal_assertion_digest
        {
            return Err(SreAuthorityError::PrincipalDenied);
        }
        let envelope: InboundEnvelope = serde_json::from_value(ingress.get("envelope"))
            .map_err(|_| SreAuthorityError::PrincipalDenied)?;
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| SreAuthorityError::PrincipalDenied)?;
        let admitted_hash = action_hash(&action).map_err(|_| SreAuthorityError::PrincipalDenied)?;
        let expected_action_version = request.command.expected_resource_version.to_string();
        if admitted_hash.0 != binding.action_hash
            || action.action_id.0 != request.command.command_id.to_string()
            || action.task_id.0 != request.command.task_id.to_string()
            || action.current_state_version.as_deref() != Some(expected_action_version.as_str())
            || Value::Object(action.payload.data.clone()) != request_value
        {
            return Err(SreAuthorityError::PrincipalDenied);
        }
        sqlx::query(
            "INSERT INTO sre_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,action_hash,ledger_execution_id,\
              ledger_event_id,ledger_event_digest,fence_digest,resource,resource_version,trace_id,\
              policy_decision_id,policy_decision_digest,authorization_evidence_ref,\
              authorization_evidence_digest,request,state,execution_owner,lease_expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
                     'PREPARED',$18,now()+make_interval(secs=>$19)) \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(&request_digest)
        .bind(request.command.command_id)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(binding.ledger_event_id)
        .bind(&binding.ledger_event_digest)
        .bind(&binding.fence_digest)
        .bind(&request.command.resource)
        .bind(expected_version)
        .bind(&binding.trace_id)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(&request_value)
        .bind(owner)
        .bind(lease_seconds as f64)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::IdempotencyConflict)?;
        let row = sqlx::query(
            "SELECT request_digest,action_id,action_hash,ledger_execution_id,ledger_event_id,\
                    ledger_event_digest,fence_digest,resource,resource_version,trace_id,\
                    policy_decision_id,policy_decision_digest,authorization_evidence_ref,\
                    authorization_evidence_digest,request,state,safe_result,execution_owner,lease_expires_at \
             FROM sre_authority_executions WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Uuid, _>("action_id") != request.command.command_id
            || row.get::<String, _>("action_hash") != binding.action_hash
            || row.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
            || row.get::<Uuid, _>("ledger_event_id") != binding.ledger_event_id
            || row.get::<String, _>("ledger_event_digest") != binding.ledger_event_digest
            || row.get::<String, _>("fence_digest") != binding.fence_digest
            || row.get::<String, _>("resource") != request.command.resource
            || row.get::<i64, _>("resource_version") != expected_version
            || row.get::<String, _>("trace_id") != binding.trace_id
            || row.get::<String, _>("policy_decision_id") != binding.policy_decision_id
            || row.get::<String, _>("policy_decision_digest") != binding.policy_decision_digest
            || row.get::<String, _>("authorization_evidence_ref")
                != binding.authorization_evidence_ref
            || row.get::<String, _>("authorization_evidence_digest")
                != binding.authorization_evidence_digest
            || row.get::<Value, _>("request") != request_value
        {
            return Err(SreAuthorityError::IdempotencyConflict);
        }
        let mut state: String = row.get("state");
        if state == "SUCCEEDED" {
            let result = row
                .get::<Option<Value>, _>("safe_result")
                .ok_or(SreAuthorityError::OutcomeUnknown)
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|_| SreAuthorityError::OutcomeUnknown)
                })?;
            tx.commit()
                .await
                .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
            return Ok(ExecutionClaim::Completed(result));
        }
        if state == "MUTATED_PENDING_EVIDENCE" {
            let result = row
                .get::<Option<Value>, _>("safe_result")
                .ok_or(SreAuthorityError::OutcomeUnknown)
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|_| SreAuthorityError::OutcomeUnknown)
                })?;
            let outbox = sqlx::query(
                "SELECT event_id,payload,payload_digest FROM sre_evidence_outbox \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND delivered_at IS NULL",
            )
            .bind(tenant)
            .bind(&binding.idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?
            .ok_or(SreAuthorityError::OutcomeUnknown)?;
            let pending = PendingEvidence {
                event_id: outbox.get("event_id"),
                idempotency_key: binding.idempotency_key.clone(),
                payload: outbox.get("payload"),
                payload_digest: outbox.get("payload_digest"),
                result,
            };
            tx.commit()
                .await
                .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
            return Ok(ExecutionClaim::PendingEvidence(pending));
        }
        if matches!(state.as_str(), "FAILED" | "UNKNOWN") {
            return Err(SreAuthorityError::OutcomeUnknown);
        }
        let existing_owner: Uuid = row.get("execution_owner");
        let lease_expires_at: DateTime<Utc> = row.get("lease_expires_at");
        if existing_owner != owner {
            if lease_expires_at > Utc::now() {
                return Err(SreAuthorityError::OutcomeUnknown);
            }
            let claimed = sqlx::query(
                "UPDATE sre_authority_executions SET execution_owner=$3,\
                 lease_expires_at=now()+make_interval(secs=>$4),updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state IN ('PREPARED','SIDE_EFFECTS_PENDING') \
                   AND lease_expires_at<=now()",
            )
            .bind(tenant)
            .bind(&binding.idempotency_key)
            .bind(owner)
            .bind(lease_seconds as f64)
            .execute(&mut *tx)
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
            if claimed.rows_affected() != 1 {
                return Err(SreAuthorityError::OutcomeUnknown);
            }
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM sre_resource_versions \
             WHERE tenant_id=$1 AND resource=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current != expected_version {
            return Err(SreAuthorityError::StateConflict);
        }
        if request.command.operation.external_effect() && state == "PREPARED" {
            let updated = sqlx::query(
                "UPDATE sre_authority_executions SET state='SIDE_EFFECTS_PENDING',updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND execution_owner=$3 AND state='PREPARED'",
            )
            .bind(tenant)
            .bind(&binding.idempotency_key)
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
            if updated.rows_affected() != 1 {
                return Err(SreAuthorityError::OutcomeUnknown);
            }
            state = "SIDE_EFFECTS_PENDING".into();
        }
        if request.command.operation.external_effect() && state != "SIDE_EFFECTS_PENDING"
            || !request.command.operation.external_effect() && state != "PREPARED"
        {
            return Err(SreAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        Ok(ExecutionClaim::Claimed(owner))
    }

    async fn commit_mutation(
        &self,
        binding: &SreExecutionBinding,
        request: &SreExecutorRequest,
        owner: Uuid,
        external: Option<SreExternalReceipt>,
        report: SignedSreEngineReport,
    ) -> Result<PendingEvidence, SreAuthorityError> {
        let tenant = parse_tenant(&binding.tenant_id)?;
        let expected = i64::try_from(binding.resource_version)
            .map_err(|_| SreAuthorityError::RequestInvalid)?;
        let mut tx = self.begin_tenant(&binding.tenant_id).await?;
        let execution = sqlx::query(
            "SELECT state,execution_owner,lease_expires_at FROM sre_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        let expected_state = if request.command.operation.external_effect() {
            "SIDE_EFFECTS_PENDING"
        } else {
            "PREPARED"
        };
        if execution.get::<String, _>("state") != expected_state
            || execution.get::<Uuid, _>("execution_owner") != owner
            || execution.get::<DateTime<Utc>, _>("lease_expires_at") <= Utc::now()
        {
            return Err(SreAuthorityError::OutcomeUnknown);
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM sre_resource_versions \
             WHERE tenant_id=$1 AND resource=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(&request.command.resource)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current != expected {
            return Err(SreAuthorityError::StateConflict);
        }
        let next = current
            .checked_add(1)
            .ok_or(SreAuthorityError::StateConflict)?;
        let state = apply_operation(&mut tx, tenant, request, external.as_ref(), next).await?;
        sqlx::query(
            "INSERT INTO sre_resource_versions \
             (tenant_id,resource,resource_version,action_hash,ledger_execution_id,ledger_event_id,\
              ledger_event_digest,fence_digest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
             ON CONFLICT (tenant_id,resource) DO UPDATE SET \
              resource_version=EXCLUDED.resource_version,action_hash=EXCLUDED.action_hash,\
              ledger_execution_id=EXCLUDED.ledger_execution_id,ledger_event_id=EXCLUDED.ledger_event_id,\
              ledger_event_digest=EXCLUDED.ledger_event_digest,fence_digest=EXCLUDED.fence_digest,\
              updated_at=now()",
        )
        .bind(tenant)
        .bind(&request.command.resource)
        .bind(next)
        .bind(&binding.action_hash)
        .bind(binding.ledger_execution_id)
        .bind(binding.ledger_event_id)
        .bind(&binding.ledger_event_digest)
        .bind(&binding.fence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        let event_id = Uuid::new_v4();
        let event_payload = json!({
            "schema_version": SRE_LIFECYCLE_EVIDENCE_SCHEMA,
            "event_id": event_id,
            "tenant_id": tenant,
            "task_id": request.command.task_id,
            "command_id": request.command.command_id,
            "resource": request.command.resource,
            "operation": request.command.operation,
            "actor_subject": request.actor_subject,
            "principal_assertion_digest": request.principal_assertion_digest,
            "approval_ids": request.approval_ids,
            "action_hash": binding.action_hash,
            "ledger_execution_id": binding.ledger_execution_id,
            "ledger_event_id": binding.ledger_event_id,
            "ledger_event_digest": binding.ledger_event_digest,
            "fence_digest": binding.fence_digest,
            "policy_decision_id": binding.policy_decision_id,
            "policy_decision_digest": binding.policy_decision_digest,
            "authorization_evidence_ref": binding.authorization_evidence_ref,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "resource_version": next,
            "state": state,
            "external_receipt": external,
            "engine_report": report,
            "trace_id": binding.trace_id,
            "recorded_at": Utc::now(),
        });
        let event_digest = canonical_digest(&event_payload)?;
        let evidence_outbox_ref =
            format!("outbox://sre-evidence/{tenant}/{event_id}/sha256:{event_digest}");
        sqlx::query(
            "INSERT INTO sre_evidence_outbox \
             (tenant_id,event_id,idempotency_key,action_id,execution_id,payload,payload_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(&binding.idempotency_key)
        .bind(request.command.command_id)
        .bind(binding.ledger_execution_id)
        .bind(&event_payload)
        .bind(&event_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        let result_digest = canonical_digest(&json!({
            "state": state,
            "resource_version": next,
            "event_digest": event_digest,
            "engine_report_digest": report.result_digest,
            "external_result_digest": external.as_ref().map(|value| value.result_digest.as_str()),
        }))?;
        let result = SreMutationResult {
            schema_version: SRE_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            resource: request.command.resource.clone(),
            operation: request.command.operation,
            resource_version: u64::try_from(next).map_err(|_| SreAuthorityError::OutcomeUnknown)?,
            state,
            result_digest,
            evidence_outbox_ref: evidence_outbox_ref.clone(),
            external_receipt: external.clone(),
            engine_report: report,
        };
        let result_value =
            serde_json::to_value(&result).map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        let external_value = external
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        let changed = sqlx::query(
            "UPDATE sre_authority_executions SET state='MUTATED_PENDING_EVIDENCE',\
             external_receipt=$4,safe_result=$5,evidence_request=$6,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND execution_owner=$3 AND state=$7",
        )
        .bind(tenant)
        .bind(&binding.idempotency_key)
        .bind(owner)
        .bind(external_value)
        .bind(&result_value)
        .bind(&event_payload)
        .bind(expected_state)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        if changed.rows_affected() != 1 {
            return Err(SreAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        Ok(PendingEvidence {
            event_id,
            idempotency_key: binding.idempotency_key.clone(),
            payload: event_payload,
            payload_digest: event_digest,
            result,
        })
    }

    async fn finalize_evidence(
        &self,
        tenant: &TenantId,
        pending: PendingEvidence,
        receipt: SreEvidenceDeliveryReceipt,
    ) -> Result<SreMutationResult, SreAuthorityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let outbox = sqlx::query(
            "SELECT payload,payload_digest,delivered_at FROM sre_evidence_outbox \
             WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(pending.event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?
        .ok_or(SreAuthorityError::OutcomeUnknown)?;
        if outbox.get::<Value, _>("payload") != pending.payload
            || outbox.get::<String, _>("payload_digest") != pending.payload_digest
        {
            return Err(SreAuthorityError::OutcomeUnknown);
        }
        if outbox
            .get::<Option<DateTime<Utc>>, _>("delivered_at")
            .is_none()
        {
            let delivered = sqlx::query(
                "UPDATE sre_evidence_outbox SET delivered_at=now(),delivery_attempts=delivery_attempts+1 \
                 WHERE tenant_id=$1 AND event_id=$2 AND delivered_at IS NULL",
            )
            .bind(tenant_uuid)
            .bind(pending.event_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
            require_one(delivered.rows_affected())?;
        }
        let updated = sqlx::query(
            "UPDATE sre_authority_executions SET state='SUCCEEDED',evidence_ref=$3,\
             evidence_digest=$4,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='MUTATED_PENDING_EVIDENCE'",
        )
        .bind(tenant_uuid)
        .bind(&pending.idempotency_key)
        .bind(&receipt.evidence_ref)
        .bind(&receipt.evidence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        require_one(updated.rows_affected())?;
        tx.commit()
            .await
            .map_err(|_| SreAuthorityError::OutcomeUnknown)?;
        Ok(pending.result)
    }
}
