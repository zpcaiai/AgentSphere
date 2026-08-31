//! Durable production authority for Batch 15 model execution.
//!
//! The database stores only prompt/output digests and governed artifact references. A request is
//! durably prepared and budget-reserved before the selected provider is bound. Once the provider
//! invocation starts, every ambiguous failure becomes `UNKNOWN`; it is never retried against a
//! fallback provider. Tenant RLS is selected inside every transaction.

use agent_trust_action_ir::{CanonicalAction, hash as action_hash};
use agent_trust_contracts::{DataClassification, TenantId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub const EXECUTION_REQUEST_SCHEMA: &str = "agenttrust.model-execution-request.v1";
pub const EXECUTION_RESULT_SCHEMA: &str = "agenttrust.model-execution-result.v1";
pub const STREAM_EVENT_SCHEMA: &str = "agenttrust.model-stream-event.v1";
pub const ROUTE_PLAN_SCHEMA: &str = "agenttrust.model-route-plan.v1";
pub const EXTERNAL_OUTCOME_SCHEMA: &str = "agenttrust.model-provider-outcome.v1";
pub const COMPLETION_EVIDENCE_SCHEMA: &str = "agenttrust.model-completion-evidence.v1";
pub const READINESS_SCHEMA: &str = "agenttrust.model-gateway-readiness.v1";
pub const AUTHORITATIVE_EXECUTIONS_SCHEMA: &str = "agenttrust.authoritative-model-executions.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("MODEL_AUTHORITY_REQUEST_INVALID")]
    RequestInvalid,
    #[error("MODEL_AUTHORITY_BINDING_INVALID")]
    BindingInvalid,
    #[error("MODEL_AUTHORITY_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("MODEL_AUTHORITY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("MODEL_AUTHORITY_BUDGET_EXCEEDED")]
    BudgetExceeded,
    #[error("MODEL_AUTHORITY_NO_COMPLIANT_PROVIDER")]
    NoCompliantProvider,
    #[error("MODEL_AUTHORITY_PROVIDER_DENIED")]
    ProviderDenied,
    #[error("MODEL_AUTHORITY_PROVIDER_OUTCOME_UNKNOWN")]
    ProviderOutcomeUnknown,
    #[error("MODEL_AUTHORITY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("MODEL_AUTHORITY_STATE_CONFLICT")]
    StateConflict,
    #[error("MODEL_AUTHORITY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelOperation {
    Generate,
    Stream,
    Embeddings,
}

/// Batch 18 wire-compatible label. It is defined locally to keep the Batch 15 -> Batch 18
/// integration runtime-only while still requiring callers to supply the complete governed label.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelLabelConfidence {
    Unknown,
    Inferred,
    Deterministic,
    HumanVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelDataLineage {
    pub source_id: String,
    pub source_hash: String,
    pub transformation_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelDataLabel {
    pub schema_version: String,
    pub classification: DataClassification,
    pub domain_tags: BTreeSet<String>,
    pub jurisdictions: BTreeSet<String>,
    pub contains_secret: bool,
    pub contains_personal_data: bool,
    pub export_restricted: bool,
    pub retention_label: String,
    pub confidence: ModelLabelConfidence,
    pub lineage: ModelDataLineage,
}

impl ModelOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "GENERATE",
            Self::Stream => "STREAM",
            Self::Embeddings => "EMBEDDINGS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelExecutionRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub task_id: Uuid,
    pub action_id: Uuid,
    pub canonical_action: CanonicalAction,
    pub operation: ModelOperation,
    pub task_type: String,
    pub classification: DataClassification,
    pub data_label: ModelDataLabel,
    pub source_jurisdiction: String,
    pub deployment_profile: String,
    pub cross_domain_approval_id: Option<Uuid>,
    pub cross_domain_grant_id: Option<Uuid>,
    pub cross_domain_source_zone: Option<String>,
    pub cross_domain_target_zone: Option<String>,
    pub required_capabilities: BTreeSet<String>,
    pub allowed_provider_ids: BTreeSet<String>,
    pub maximum_latency_ms: u64,
    pub maximum_cost_microunits: u64,
    pub maximum_output_bytes: usize,
    pub prompt_utf8: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    pub tenant_id: TenantId,
    pub action_hash: String,
    pub authorization_id: Uuid,
    pub authorization_digest: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub ledger_execution_id: Uuid,
    pub ledger_event_id: Uuid,
    pub ledger_event_digest: String,
    pub fence_digest: String,
    pub resource_version: String,
    pub idempotency_key: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutePlan {
    pub schema_version: String,
    pub provider_key: String,
    pub provider_manifest_digest: String,
    pub endpoint_profile: String,
    pub model_id: String,
    pub model_version: String,
    pub provider_region: String,
    pub provider_jurisdiction: String,
    pub protocol: String,
    pub cost_microunits_per_token: u64,
    pub route_decision_digest: String,
    pub route_reasons: Vec<String>,
    pub data_policy_version: String,
    pub pre_transform_policy_decision_digest: String,
    pub pre_transform_policy_evidence_ref: String,
    pub pre_transform_policy_evidence_digest: String,
    pub data_policy_decision_digest: String,
    pub data_policy_evidence_ref: String,
    pub data_policy_evidence_digest: String,
    pub transformation_digest: String,
    pub transform_evidence_ref: Option<String>,
    pub transform_evidence_digest: Option<String>,
    pub dlp_report_digest: String,
    pub input_dlp_evidence_ref: String,
    pub input_dlp_evidence_digest: String,
    pub residency_policy_request_digest: String,
    pub transformed_prompt_utf8: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderOutcome {
    pub schema_version: String,
    pub provider_request_id: String,
    pub output_utf8: Option<String>,
    pub embedding: Option<Vec<f32>>,
    pub stream_chunks: Vec<String>,
    pub finish_reason: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microunits: u64,
    pub residency_attestation_ref: String,
    pub residency_attestation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompletionEvidence {
    pub schema_version: String,
    pub artifact_ref: String,
    pub artifact_digest: String,
    pub output_digest: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub residency_policy_evidence_ref: String,
    pub residency_policy_evidence_digest: String,
    pub residency_attestation_ref: String,
    pub residency_attestation_digest: String,
    pub output_dlp_report_digest: String,
    pub output_dlp_evidence_ref: String,
    pub output_dlp_evidence_digest: String,
    pub output_label_evidence_ref: String,
    pub output_label_evidence_digest: String,
    pub artifact_policy_evidence_ref: String,
    pub artifact_policy_evidence_digest: String,
    pub grant_consumption_evidence_ref: Option<String>,
    pub grant_consumption_evidence_digest: Option<String>,
    pub export_authorization_evidence_ref: String,
    pub export_authorization_evidence_digest: String,
    pub export_completion_evidence_ref: String,
    pub export_completion_evidence_digest: String,
    pub artifact_store_receipt_ref: String,
    pub artifact_store_receipt_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microunits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelExecutionResult {
    pub schema_version: String,
    pub request_id: Uuid,
    pub status: String,
    pub replayed: bool,
    pub output_utf8: Option<String>,
    pub embedding: Option<Vec<f32>>,
    pub artifact_ref: String,
    pub artifact_digest: String,
    pub untrusted_content: bool,
    pub provider_key: String,
    pub provider_request_id: String,
    pub usage: ModelUsage,
    pub output_digest: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamEvent {
    pub schema_version: String,
    pub request_id: Uuid,
    pub sequence: u64,
    pub chunk_utf8: String,
    pub release_mode: StreamReleaseMode,
    pub terminal: bool,
    pub finish_reason: Option<String>,
    pub usage: Option<ModelUsage>,
    pub artifact_ref: Option<String>,
    pub artifact_digest: Option<String>,
    pub evidence_ref: Option<String>,
    pub evidence_digest: Option<String>,
}

/// No provider chunk is released before output DLP, artifact authorization, WORM persistence and
/// signed Evidence complete. This intentionally favors confidentiality over token latency.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamReleaseMode {
    DlpVerifiedBuffered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelExecutionListQuery {
    pub tenant_id: Uuid,
    pub state: Option<String>,
    pub operation: Option<ModelOperation>,
    pub limit: u16,
    pub cursor_created_at: Option<DateTime<Utc>>,
    pub cursor_request_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeModelExecutionSummary {
    pub request_id: Uuid,
    pub task_id: Uuid,
    pub action_id: Uuid,
    pub action_hash: String,
    pub operation: ModelOperation,
    pub classification: String,
    pub source_jurisdiction: String,
    pub deployment_profile: String,
    pub state: String,
    pub provider_key: Option<String>,
    pub provider_request_id: Option<String>,
    pub usage: Option<ModelUsage>,
    pub output_digest: Option<String>,
    pub artifact_ref: Option<String>,
    pub artifact_digest: Option<String>,
    pub evidence_ref: Option<String>,
    pub evidence_digest: Option<String>,
    pub stable_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeModelExecutionCursor {
    pub created_at: DateTime<Utc>,
    pub request_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeModelExecutionsPage {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub authoritative: bool,
    pub items: Vec<AuthoritativeModelExecutionSummary>,
    pub next_cursor: Option<AuthoritativeModelExecutionCursor>,
    pub data_digest: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BillingLine {
    pub provider_key: String,
    pub provider_request_id: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub billed_microunits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderBillingAttestation {
    pub schema_version: String,
    pub provider_id: String,
    pub statement_period: String,
    pub statement_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}

impl ProviderBillingAttestation {
    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| AuthorityError::RequestInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BillingStatementRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub canonical_action: CanonicalAction,
    pub provider_id: String,
    pub statement_period: String,
    pub statement_digest: String,
    pub residency_policy_evidence_digest: String,
    pub lines: Vec<BillingLine>,
    pub provider_attestation: ProviderBillingAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BillingReconciliationResult {
    pub schema_version: String,
    pub matched: bool,
    pub matched_requests: u64,
    pub total_metered_microunits: u64,
    pub total_billed_microunits: u64,
    pub statement_digest: String,
    pub provider_attestation_digest: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BillingEvidenceReceipt {
    pub schema_version: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone)]
pub enum PrepareOutcome {
    New {
        request_id: Uuid,
        reservation_id: Uuid,
    },
    RetryPrepared {
        request_id: Uuid,
        reservation_id: Uuid,
    },
    Replay(Box<ModelExecutionResult>),
    Failed(String),
    Unknown,
}

#[async_trait]
pub trait ProductionModelRuntime: Send + Sync {
    /// Performs signed-manifest verification, tenant approval, exact Batch 18 policy/DLP durable
    /// recording, transformation and policy re-evaluation. It returns one immutable provider.
    async fn plan(
        &self,
        request: &ModelExecutionRequest,
        binding: &ExecutionBinding,
    ) -> Result<RoutePlan, AuthorityError>;

    /// Starts the single selected provider call. Any error returned after dispatch is ambiguous.
    async fn invoke(
        &self,
        request: &ModelExecutionRequest,
        binding: &ExecutionBinding,
        plan: &RoutePlan,
    ) -> Result<ProviderOutcome, AuthorityError>;

    /// DLP-inspects the output, durably authorizes export, writes it through the configured locked
    /// object/WORM port, durably completes export, and appends immutable Evidence. Raw output must
    /// not be logged or stored in DB.
    async fn complete(
        &self,
        request: &ModelExecutionRequest,
        binding: &ExecutionBinding,
        plan: &RoutePlan,
        outcome: &ProviderOutcome,
    ) -> Result<CompletionEvidence, AuthorityError>;

    async fn billing_evidence(
        &self,
        request: &BillingStatementRequest,
        binding: &ExecutionBinding,
        matched: bool,
        matched_requests: u64,
        total_metered_microunits: u64,
        total_billed_microunits: u64,
    ) -> Result<BillingEvidenceReceipt, AuthorityError>;

    /// Verifies the provider-authenticated statement before any preview or database transition.
    async fn verify_billing_statement(
        &self,
        request: &BillingStatementRequest,
        now: DateTime<Utc>,
    ) -> Result<(), AuthorityError>;

    async fn ready(&self) -> Result<(), AuthorityError>;
}

#[derive(Clone)]
pub struct PostgresModelAuthorityStore {
    pool: PgPool,
}

impl PostgresModelAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn tenant_transaction<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Result<Transaction<'a, Postgres>, AuthorityError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT pg_catalog.set_config('app.tenant_id',$1,true)")
            .bind(tenant_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        Ok(transaction)
    }

    pub async fn prepare(
        &self,
        request: &ModelExecutionRequest,
        binding: &ExecutionBinding,
        request_digest: &str,
        prompt_digest: &str,
    ) -> Result<PrepareOutcome, AuthorityError> {
        let mut transaction = self.tenant_transaction(request.tenant_id).await?;
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
            .bind(format!("{}:{}", request.tenant_id, request.idempotency_key))
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT request_id,state,request_digest,action_hash,authorization_digest,\
             policy_decision_id,policy_decision_digest,ledger_execution_id,ledger_event_digest,fence_digest,\
             safe_response,stable_error FROM public.model_gateway_requests \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(&request.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?
        {
            if row.try_get::<String, _>("request_digest").ok().as_deref()
                != Some(request_digest)
                || row.try_get::<String, _>("action_hash").ok().as_deref()
                    != Some(binding.action_hash.as_str())
                || row
                    .try_get::<String, _>("authorization_digest")
                    .ok()
                    .as_deref()
                    != Some(binding.authorization_digest.as_str())
                || row
                    .try_get::<String, _>("policy_decision_id")
                    .ok()
                    .as_deref()
                    != Some(binding.policy_decision_id.as_str())
                || row
                    .try_get::<String, _>("policy_decision_digest")
                    .ok()
                    .as_deref()
                    != Some(binding.policy_decision_digest.as_str())
                || row.try_get::<Uuid, _>("ledger_execution_id").ok()
                    != Some(binding.ledger_execution_id)
                || row
                    .try_get::<String, _>("ledger_event_digest")
                    .ok()
                    .as_deref()
                    != Some(binding.ledger_event_digest.as_str())
                || row.try_get::<String, _>("fence_digest").ok().as_deref()
                    != Some(binding.fence_digest.as_str())
            {
                return Err(AuthorityError::IdempotencyConflict);
            }
            let request_id: Uuid = row
                .try_get("request_id")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let state: String = row
                .try_get("state")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let result = match state.as_str() {
                "PREPARED" => PrepareOutcome::RetryPrepared {
                    request_id,
                    reservation_id: reservation_id(&mut transaction, request.tenant_id, request_id)
                        .await?,
                },
                "EXECUTING" | "UNKNOWN" => PrepareOutcome::Unknown,
                "FAILED" => PrepareOutcome::Failed(
                    row.try_get("stable_error")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?,
                ),
                "SUCCEEDED" => {
                    let value: Value = row
                        .try_get("safe_response")
                        .map_err(|_| AuthorityError::DependencyUnavailable)?;
                    let mut replay: ModelExecutionResult = serde_json::from_value(value)
                        .map_err(|_| AuthorityError::DependencyUnavailable)?;
                    replay.replayed = true;
                    PrepareOutcome::Replay(Box::new(replay))
                }
                _ => return Err(AuthorityError::DependencyUnavailable),
            };
            transaction
                .commit()
                .await
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            return Ok(result);
        }

        let account = sqlx::query(
            "SELECT limit_microunits,reserved_microunits,spent_microunits \
             FROM public.model_budget_accounts WHERE tenant_id=$1 FOR UPDATE",
        )
        .bind(request.tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?
        .ok_or(AuthorityError::BudgetExceeded)?;
        let limit: i64 = account
            .try_get("limit_microunits")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let reserved: i64 = account
            .try_get("reserved_microunits")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let spent: i64 = account
            .try_get("spent_microunits")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let requested = i64::try_from(request.maximum_cost_microunits)
            .map_err(|_| AuthorityError::BudgetExceeded)?;
        if reserved
            .checked_add(spent)
            .and_then(|used| used.checked_add(requested))
            .is_none_or(|total| total > limit)
        {
            return Err(AuthorityError::BudgetExceeded);
        }
        let request_id = Uuid::new_v4();
        let reservation_id = Uuid::new_v4();
        let request_inserted = sqlx::query(
            "INSERT INTO public.model_gateway_requests \
             (tenant_id,request_id,task_id,action_id,action_hash,request_digest,operation,\
              idempotency_key,authorization_id,authorization_digest,policy_decision_id,policy_decision_digest,\
              authorization_evidence_ref,authorization_evidence_digest,ledger_execution_id,\
              ledger_event_id,ledger_event_digest,fence_digest,resource_version,classification,\
              source_jurisdiction,deployment_profile,prompt_digest,maximum_cost_microunits,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,\
                     $20,$21,$22,$23,$24,'PREPARED')",
        )
        .bind(request.tenant_id)
        .bind(request_id)
        .bind(request.task_id)
        .bind(request.action_id)
        .bind(&binding.action_hash)
        .bind(request_digest)
        .bind(request.operation.as_str())
        .bind(&request.idempotency_key)
        .bind(binding.authorization_id)
        .bind(&binding.authorization_digest)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(binding.ledger_execution_id)
        .bind(binding.ledger_event_id)
        .bind(&binding.ledger_event_digest)
        .bind(&binding.fence_digest)
        .bind(&binding.resource_version)
        .bind(classification_name(request.classification))
        .bind(&request.source_jurisdiction)
        .bind(&request.deployment_profile)
        .bind(prompt_digest)
        .bind(requested)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if request_inserted.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        let reservation_inserted = sqlx::query(
            "INSERT INTO public.model_budget_reservations \
             (tenant_id,reservation_id,request_id,request_digest,idempotency_key,\
              reserved_microunits,state) VALUES ($1,$2,$3,$4,$5,$6,'RESERVED')",
        )
        .bind(request.tenant_id)
        .bind(reservation_id)
        .bind(request_id)
        .bind(request_digest)
        .bind(&request.idempotency_key)
        .bind(requested)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if reservation_inserted.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        let reserved_account = sqlx::query(
            "UPDATE public.model_budget_accounts SET reserved_microunits=reserved_microunits+$2,\
             account_version=account_version+1,updated_at=now() WHERE tenant_id=$1",
        )
        .bind(request.tenant_id)
        .bind(requested)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if reserved_account.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        Ok(PrepareOutcome::New {
            request_id,
            reservation_id,
        })
    }

    pub async fn claim(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        owner: Uuid,
        lease_seconds: i64,
        plan: &RoutePlan,
    ) -> Result<(), AuthorityError> {
        let mut transaction = self.tenant_transaction(tenant_id).await?;
        let result = sqlx::query(
            "UPDATE public.model_gateway_requests SET state='EXECUTING',owner_instance_id=$3,\
             lease_expires_at=now()+make_interval(secs=>$4),selected_provider_key=$5,\
             updated_at=now() WHERE tenant_id=$1 AND request_id=$2 AND state='PREPARED'",
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(owner)
        .bind(lease_seconds)
        .bind(&plan.provider_key)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if result.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    }

    pub async fn fail_before_provider(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        stable_error: &str,
    ) -> Result<(), AuthorityError> {
        if !stable_code(stable_error) {
            return Err(AuthorityError::RequestInvalid);
        }
        let mut transaction = self.tenant_transaction(tenant_id).await?;
        let row = sqlx::query(
            "SELECT reservation_id,reserved_microunits FROM public.model_budget_reservations \
             WHERE tenant_id=$1 AND request_id=$2 AND state='RESERVED' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let reservation_id: Uuid = row
            .try_get("reservation_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let reserved: i64 = row
            .try_get("reserved_microunits")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let changed = sqlx::query(
            "UPDATE public.model_gateway_requests SET state='FAILED',stable_error=$3,updated_at=now(),\
             completed_at=now() WHERE tenant_id=$1 AND request_id=$2 AND state='PREPARED'",
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(stable_error)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if changed.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        let denial = json!({
            "schema_version": "agenttrust.model-execution-denial.v1",
            "tenant_id": tenant_id,
            "request_id": request_id,
            "stable_error": stable_error
        });
        sqlx::query(
            "INSERT INTO public.model_evidence_outbox \
             (tenant_id,outbox_id,request_id,event_type,payload,payload_digest) \
             VALUES ($1,$2,$3,'MODEL_EXECUTION_DENIED',$4,$5)",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(request_id)
        .bind(&denial)
        .bind(canonical_digest(&denial)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "UPDATE public.model_budget_reservations SET actual_microunits=0,state='RELEASED',\
             finalized_at=now() WHERE tenant_id=$1 AND reservation_id=$2 AND state='RESERVED'",
        )
        .bind(tenant_id)
        .bind(reservation_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let released = sqlx::query(
            "UPDATE public.model_budget_accounts SET reserved_microunits=reserved_microunits-$2,\
             account_version=account_version+1,updated_at=now() \
             WHERE tenant_id=$1 AND reserved_microunits >= $2",
        )
        .bind(tenant_id)
        .bind(reserved)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if released.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn succeed(
        &self,
        request: &ModelExecutionRequest,
        binding: &ExecutionBinding,
        request_id: Uuid,
        reservation_id: Uuid,
        owner: Uuid,
        plan: &RoutePlan,
        outcome: &ProviderOutcome,
        completion: &CompletionEvidence,
        result: &ModelExecutionResult,
        chunks: &[ModelStreamEvent],
    ) -> Result<(), AuthorityError> {
        let mut transaction = self.tenant_transaction(request.tenant_id).await?;
        lock_running(
            &mut transaction,
            request.tenant_id,
            request_id,
            owner,
            &plan.provider_key,
            true,
        )
        .await?;
        let reserved: i64 = sqlx::query_scalar(
            "SELECT reserved_microunits FROM public.model_budget_reservations \
             WHERE tenant_id=$1 AND reservation_id=$2 AND state='RESERVED' FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(reservation_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let actual =
            i64::try_from(outcome.cost_microunits).map_err(|_| AuthorityError::BudgetExceeded)?;
        if actual > reserved {
            return Err(AuthorityError::BudgetExceeded);
        }
        let safe_response = sanitized_result(result)?;
        let updated = sqlx::query(
            "UPDATE public.model_gateway_requests SET state='SUCCEEDED',owner_instance_id=NULL,\
             lease_expires_at=NULL,provider_request_id=$4,output_digest=$5,output_artifact_ref=$6,\
             output_artifact_digest=$7,safe_response=$8,evidence_ref=$9,evidence_digest=$10,\
             updated_at=now(),completed_at=now() WHERE tenant_id=$1 AND request_id=$2 \
             AND owner_instance_id=$3 AND state='EXECUTING'",
        )
        .bind(request.tenant_id)
        .bind(request_id)
        .bind(owner)
        .bind(&outcome.provider_request_id)
        .bind(&completion.output_digest)
        .bind(&completion.artifact_ref)
        .bind(&completion.artifact_digest)
        .bind(safe_response)
        .bind(&completion.evidence_ref)
        .bind(&completion.evidence_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if updated.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        for event in chunks {
            let chunk = event.chunk_utf8.as_bytes();
            sqlx::query(
                "INSERT INTO public.model_stream_chunk_digests \
                 (tenant_id,request_id,sequence,chunk_digest,byte_count,terminal,finish_reason) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(request.tenant_id)
            .bind(request_id)
            .bind(i64::try_from(event.sequence).map_err(|_| AuthorityError::RequestInvalid)?)
            .bind(digest(chunk))
            .bind(i32::try_from(chunk.len()).map_err(|_| AuthorityError::RequestInvalid)?)
            .bind(event.terminal)
            .bind(&event.finish_reason)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        }
        sqlx::query(
            "INSERT INTO public.model_execution_evidence \
             (tenant_id,evidence_id,request_id,evidence_ref,evidence_digest,provider_key,\
              provider_request_id,provider_manifest_digest,route_decision_digest,\
              data_policy_version,pre_transform_policy_decision_digest,\
              data_policy_decision_digest,transformation_digest,input_tokens,output_tokens,\
              cost_microunits,prompt_digest,output_digest,residency_policy_evidence_ref,\
              residency_policy_evidence_digest,residency_attestation_ref,\
              residency_attestation_digest,input_dlp_report_digest,input_dlp_evidence_ref,\
              input_dlp_evidence_digest,transform_evidence_ref,transform_evidence_digest,\
              output_dlp_report_digest,output_dlp_evidence_ref,output_dlp_evidence_digest,\
              output_label_evidence_ref,output_label_evidence_digest,\
              artifact_policy_evidence_ref,artifact_policy_evidence_digest,\
              grant_consumption_evidence_ref,grant_consumption_evidence_digest,\
              export_authorization_evidence_ref,export_authorization_evidence_digest,\
              export_completion_evidence_ref,export_completion_evidence_digest,\
              artifact_store_receipt_ref,artifact_store_receipt_digest,trace_id,occurred_at) \
             SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,prompt_digest,$17,\
                    $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,\
                    $35,$36,$37,$38,$39,$40,$41,$42,now() \
             FROM public.model_gateway_requests \
             WHERE tenant_id=$1 AND request_id=$3",
        )
        .bind(request.tenant_id)
        .bind(Uuid::new_v4())
        .bind(request_id)
        .bind(&completion.evidence_ref)
        .bind(&completion.evidence_digest)
        .bind(&plan.provider_key)
        .bind(&outcome.provider_request_id)
        .bind(&plan.provider_manifest_digest)
        .bind(&plan.route_decision_digest)
        .bind(&plan.data_policy_version)
        .bind(&plan.pre_transform_policy_decision_digest)
        .bind(&plan.data_policy_decision_digest)
        .bind(&plan.transformation_digest)
        .bind(i64::try_from(outcome.input_tokens).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(i64::try_from(outcome.output_tokens).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(actual)
        .bind(&completion.output_digest)
        .bind(&completion.residency_policy_evidence_ref)
        .bind(&completion.residency_policy_evidence_digest)
        .bind(&completion.residency_attestation_ref)
        .bind(&completion.residency_attestation_digest)
        .bind(&plan.dlp_report_digest)
        .bind(&plan.input_dlp_evidence_ref)
        .bind(&plan.input_dlp_evidence_digest)
        .bind(&plan.transform_evidence_ref)
        .bind(&plan.transform_evidence_digest)
        .bind(&completion.output_dlp_report_digest)
        .bind(&completion.output_dlp_evidence_ref)
        .bind(&completion.output_dlp_evidence_digest)
        .bind(&completion.output_label_evidence_ref)
        .bind(&completion.output_label_evidence_digest)
        .bind(&completion.artifact_policy_evidence_ref)
        .bind(&completion.artifact_policy_evidence_digest)
        .bind(&completion.grant_consumption_evidence_ref)
        .bind(&completion.grant_consumption_evidence_digest)
        .bind(&completion.export_authorization_evidence_ref)
        .bind(&completion.export_authorization_evidence_digest)
        .bind(&completion.export_completion_evidence_ref)
        .bind(&completion.export_completion_evidence_digest)
        .bind(&completion.artifact_store_receipt_ref)
        .bind(&completion.artifact_store_receipt_digest)
        .bind(&binding.trace_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "INSERT INTO public.model_billing_usage_lines \
              (tenant_id,usage_id,request_id,provider_key,provider_request_id,input_tokens,\
              output_tokens,metered_microunits,residency_policy_evidence_digest,reconciliation_state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'PENDING')",
        )
        .bind(request.tenant_id)
        .bind(Uuid::new_v4())
        .bind(request_id)
        .bind(&plan.provider_key)
        .bind(&outcome.provider_request_id)
        .bind(i64::try_from(outcome.input_tokens).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(i64::try_from(outcome.output_tokens).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(actual)
        .bind(&plan.data_policy_evidence_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let outbox = json!({
            "schema_version": COMPLETION_EVIDENCE_SCHEMA,
            "request_id": request_id,
            "action_hash": binding.action_hash,
            "provider_key": plan.provider_key,
            "provider_manifest_digest": plan.provider_manifest_digest,
            "route_decision_digest": plan.route_decision_digest,
            "pre_transform_policy_decision_digest": plan.pre_transform_policy_decision_digest,
            "data_policy_decision_digest": plan.data_policy_decision_digest,
            "transformation_digest": plan.transformation_digest,
            "evidence_ref": completion.evidence_ref,
            "evidence_digest": completion.evidence_digest
        });
        sqlx::query(
            "INSERT INTO public.model_evidence_outbox \
             (tenant_id,outbox_id,request_id,event_type,payload,payload_digest) \
             VALUES ($1,$2,$3,'MODEL_EXECUTION_SUCCEEDED',$4,$5)",
        )
        .bind(request.tenant_id)
        .bind(Uuid::new_v4())
        .bind(request_id)
        .bind(&outbox)
        .bind(canonical_digest(&outbox)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let reservation_finalized = sqlx::query(
            "UPDATE public.model_budget_reservations SET actual_microunits=$3,state='FINALIZED',\
             provider_key=$4,provider_request_id=$5,finalized_at=now() \
             WHERE tenant_id=$1 AND reservation_id=$2 AND state='RESERVED'",
        )
        .bind(request.tenant_id)
        .bind(reservation_id)
        .bind(actual)
        .bind(&plan.provider_key)
        .bind(&outcome.provider_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if reservation_finalized.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        let budget_accounted = sqlx::query(
            "UPDATE public.model_budget_accounts SET reserved_microunits=reserved_microunits-$2,\
             spent_microunits=spent_microunits+$3,account_version=account_version+1,\
             updated_at=now() WHERE tenant_id=$1 AND reserved_microunits >= $2",
        )
        .bind(request.tenant_id)
        .bind(reserved)
        .bind(actual)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if budget_accounted.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    }

    pub async fn mark_unknown(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        owner: Uuid,
        stable_error: &str,
    ) -> Result<(), AuthorityError> {
        if !stable_code(stable_error) {
            return Err(AuthorityError::RequestInvalid);
        }
        let mut transaction = self.tenant_transaction(tenant_id).await?;
        lock_running(&mut transaction, tenant_id, request_id, owner, "", false).await?;
        let row = sqlx::query(
            "SELECT reservation_id,reserved_microunits FROM public.model_budget_reservations \
             WHERE tenant_id=$1 AND request_id=$2 AND state='RESERVED' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let reservation_id: Uuid = row
            .try_get("reservation_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let reserved: i64 = row
            .try_get("reserved_microunits")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "UPDATE public.model_gateway_requests SET state='UNKNOWN',owner_instance_id=NULL,\
             lease_expires_at=NULL,stable_error=$4,updated_at=now(),completed_at=now() \
             WHERE tenant_id=$1 AND request_id=$2 AND owner_instance_id=$3 AND state='EXECUTING'",
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(owner)
        .bind(stable_error)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "UPDATE public.model_budget_reservations SET actual_microunits=reserved_microunits,\
             state='UNKNOWN',finalized_at=now() WHERE tenant_id=$1 AND reservation_id=$2",
        )
        .bind(tenant_id)
        .bind(reservation_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let unknown = json!({
            "schema_version": "agenttrust.model-execution-unknown.v1",
            "tenant_id": tenant_id,
            "request_id": request_id,
            "stable_error": stable_error,
            "budget_accounted_microunits": reserved
        });
        sqlx::query(
            "INSERT INTO public.model_evidence_outbox \
             (tenant_id,outbox_id,request_id,event_type,payload,payload_digest) \
             VALUES ($1,$2,$3,'MODEL_EXECUTION_OUTCOME_UNKNOWN',$4,$5)",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(request_id)
        .bind(&unknown)
        .bind(canonical_digest(&unknown)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let accounted = sqlx::query(
            "UPDATE public.model_budget_accounts SET reserved_microunits=reserved_microunits-$2,\
             spent_microunits=spent_microunits+$2,account_version=account_version+1,updated_at=now() \
             WHERE tenant_id=$1 AND reserved_microunits >= $2",
        )
        .bind(tenant_id)
        .bind(reserved)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if accounted.rows_affected() != 1 {
            return Err(AuthorityError::StateConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)
    }

    pub async fn recover_expired(
        &self,
        tenant_id: Uuid,
        maximum: i64,
    ) -> Result<u64, AuthorityError> {
        if !(1..=1000).contains(&maximum) {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        let mut transaction = self.tenant_transaction(tenant_id).await?;
        let rows = sqlx::query(
            "SELECT request_id,owner_instance_id FROM public.model_gateway_requests \
             WHERE tenant_id=$1 AND state='EXECUTING' AND lease_expires_at <= now() \
             ORDER BY lease_expires_at LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(tenant_id)
        .bind(maximum)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        transaction
            .rollback()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let mut recovered = 0_u64;
        for row in rows {
            let request_id: Uuid = row
                .try_get("request_id")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let owner: Uuid = row
                .try_get("owner_instance_id")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            self.mark_unknown(
                tenant_id,
                request_id,
                owner,
                "MODEL_PROVIDER_OUTCOME_UNKNOWN_AFTER_LEASE_EXPIRY",
            )
            .await?;
            recovered += 1;
        }
        Ok(recovered)
    }

    pub async fn ready(&self) -> Result<(), AuthorityError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relkind='r' \
             AND c.relrowsecurity AND c.relforcerowsecurity AND c.relname=ANY(ARRAY[\
             'model_tenant_provider_approvals','model_budget_accounts','model_gateway_requests',\
             'model_budget_reservations','model_stream_chunk_digests','model_execution_evidence',\
             'model_billing_usage_lines','model_billing_reconciliations','model_evidence_outbox',\
             'model_authority_evidence_outbox','model_data_governance_outbox'])",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if count != 11 {
            return Err(AuthorityError::DependencyUnavailable);
        }
        let hardened_columns: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND (\
             (table_name='model_execution_evidence' AND column_name IN \
               ('residency_attestation_ref','residency_attestation_digest')) OR \
             (table_name='model_billing_reconciliations' AND column_name='provider_attestation_digest'))",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if hardened_columns != 3 {
            return Err(AuthorityError::DependencyUnavailable);
        }
        Ok(())
    }

    pub async fn list_executions(
        &self,
        query: &ModelExecutionListQuery,
    ) -> Result<AuthoritativeModelExecutionsPage, AuthorityError> {
        if !(1..=200).contains(&query.limit)
            || !query.state.as_deref().is_none_or(|value| {
                matches!(
                    value,
                    "PREPARED" | "EXECUTING" | "SUCCEEDED" | "FAILED" | "UNKNOWN"
                )
            })
            || query.cursor_created_at.is_some() != query.cursor_request_id.is_some()
        {
            return Err(AuthorityError::RequestInvalid);
        }
        let mut transaction = self.tenant_transaction(query.tenant_id).await?;
        let requested = i64::from(query.limit) + 1;
        let operation = query.operation.map(ModelOperation::as_str);
        let rows = sqlx::query(
            "SELECT r.request_id,r.task_id,r.action_id,r.action_hash,r.operation,r.classification,\
             r.source_jurisdiction,r.deployment_profile,r.state,r.selected_provider_key,\
             r.provider_request_id,r.output_digest,r.output_artifact_ref,r.output_artifact_digest,\
             r.evidence_ref,r.evidence_digest,r.stable_error,r.created_at,r.updated_at,r.completed_at,\
             u.input_tokens,u.output_tokens,u.metered_microunits \
             FROM public.model_gateway_requests r \
             LEFT JOIN public.model_billing_usage_lines u \
               ON u.tenant_id=r.tenant_id AND u.request_id=r.request_id \
             WHERE r.tenant_id=$1 AND ($2::varchar IS NULL OR r.state=$2) \
               AND ($3::varchar IS NULL OR r.operation=$3) \
               AND ($4::timestamptz IS NULL OR (r.created_at,r.request_id)<($4,$5)) \
             ORDER BY r.created_at DESC,r.request_id DESC LIMIT $6",
        )
        .bind(query.tenant_id)
        .bind(query.state.as_deref())
        .bind(operation)
        .bind(query.cursor_created_at.as_ref())
        .bind(query.cursor_request_id)
        .bind(requested)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let items = rows
            .iter()
            .take(usize::from(query.limit))
            .map(authoritative_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if rows.len() > usize::from(query.limit) {
            items.last().map(|item| AuthoritativeModelExecutionCursor {
                created_at: item.created_at.to_owned(),
                request_id: item.request_id,
            })
        } else {
            None
        };
        let mut page = AuthoritativeModelExecutionsPage {
            schema_version: AUTHORITATIVE_EXECUTIONS_SCHEMA.into(),
            tenant_id: query.tenant_id,
            authoritative: true,
            items,
            next_cursor,
            data_digest: String::new(),
            generated_at: Utc::now(),
        };
        let mut digest_material =
            serde_json::to_value(&page).map_err(|_| AuthorityError::DependencyUnavailable)?;
        digest_material
            .as_object_mut()
            .and_then(|object| object.remove("data_digest"))
            .ok_or(AuthorityError::DependencyUnavailable)?;
        page.data_digest = canonical_digest(&digest_material)?;
        Ok(page)
    }

    pub async fn preview_billing(
        &self,
        request: &BillingStatementRequest,
    ) -> Result<(bool, u64, u64, u64), AuthorityError> {
        let mut transaction = self.tenant_transaction(request.tenant_id).await?;
        let request_ids = request
            .lines
            .iter()
            .map(|line| line.provider_request_id.clone())
            .collect::<Vec<_>>();
        let rows = sqlx::query(
            "SELECT provider_key,provider_request_id,input_tokens,output_tokens,metered_microunits,\
                    residency_policy_evidence_digest \
             FROM public.model_billing_usage_lines WHERE tenant_id=$1 \
             AND provider_request_id=ANY($2)",
        )
        .bind(request.tenant_id)
        .bind(&request_ids)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let result = compare_billing_rows(
            &rows,
            &request.lines,
            &request.residency_policy_evidence_digest,
        )?;
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        Ok(result)
    }

    pub async fn reconcile_billing(
        &self,
        request: &BillingStatementRequest,
        binding: &ExecutionBinding,
        evidence: &BillingEvidenceReceipt,
    ) -> Result<BillingReconciliationResult, AuthorityError> {
        let request_digest = canonical_digest(request)?;
        let mut transaction = self.tenant_transaction(request.tenant_id).await?;
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
            .bind(format!(
                "billing:{}:{}",
                request.tenant_id, binding.idempotency_key
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT request_digest,safe_response FROM public.model_billing_reconciliations \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(&binding.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?
        {
            if row.try_get::<String, _>("request_digest").ok().as_deref()
                != Some(request_digest.as_str())
            {
                return Err(AuthorityError::IdempotencyConflict);
            }
            let value: Value = row
                .try_get("safe_response")
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            let result =
                serde_json::from_value(value).map_err(|_| AuthorityError::DependencyUnavailable)?;
            transaction
                .commit()
                .await
                .map_err(|_| AuthorityError::DependencyUnavailable)?;
            return Ok(result);
        }
        let request_ids = request
            .lines
            .iter()
            .map(|line| line.provider_request_id.clone())
            .collect::<Vec<_>>();
        let rows = sqlx::query(
            "SELECT provider_key,provider_request_id,input_tokens,output_tokens,metered_microunits,\
                    residency_policy_evidence_digest \
             FROM public.model_billing_usage_lines WHERE tenant_id=$1 \
             AND provider_request_id=ANY($2) FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(&request_ids)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let (matched, matched_requests, total_metered, total_billed) = compare_billing_rows(
            &rows,
            &request.lines,
            &request.residency_policy_evidence_digest,
        )?;
        let result = BillingReconciliationResult {
            schema_version: "agenttrust.model-billing-reconciliation.v1".into(),
            matched,
            matched_requests,
            total_metered_microunits: total_metered,
            total_billed_microunits: total_billed,
            statement_digest: request.statement_digest.clone(),
            provider_attestation_digest: canonical_digest(&request.provider_attestation)?,
            evidence_ref: evidence.evidence_ref.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
        };
        let safe_response =
            serde_json::to_value(&result).map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "INSERT INTO public.model_billing_reconciliations \
             (tenant_id,reconciliation_id,idempotency_key,request_digest,action_hash,authorization_id,\
              authorization_digest,policy_decision_id,policy_decision_digest,authorization_evidence_ref,\
              authorization_evidence_digest,ledger_execution_id,ledger_event_id,ledger_event_digest,\
              fence_digest,resource_version,provider_id,statement_period,statement_digest,\
              provider_attestation_digest,residency_policy_evidence_digest,matched_requests,total_metered_microunits,\
              total_billed_microunits,matched,trace_id,evidence_ref,evidence_digest,safe_response) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,\
                     $20,$21,$22,$23,$24,$25,$26,$27,$28,$29)",
        )
        .bind(request.tenant_id)
        .bind(Uuid::new_v4())
        .bind(&binding.idempotency_key)
        .bind(&request_digest)
        .bind(&binding.action_hash)
        .bind(binding.authorization_id)
        .bind(&binding.authorization_digest)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(binding.ledger_execution_id)
        .bind(binding.ledger_event_id)
        .bind(&binding.ledger_event_digest)
        .bind(&binding.fence_digest)
        .bind(&binding.resource_version)
        .bind(&request.provider_id)
        .bind(&request.statement_period)
        .bind(&request.statement_digest)
        .bind(canonical_digest(&request.provider_attestation)?)
        .bind(&request.residency_policy_evidence_digest)
        .bind(i64::try_from(matched_requests).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(i64::try_from(total_metered).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(i64::try_from(total_billed).map_err(|_| AuthorityError::RequestInvalid)?)
        .bind(matched)
        .bind(&binding.trace_id)
        .bind(&evidence.evidence_ref)
        .bind(&evidence.evidence_digest)
        .bind(safe_response)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        sqlx::query(
            "UPDATE public.model_billing_usage_lines SET provider_statement_digest=$3,\
             reconciliation_state=$4,reconciled_at=now() WHERE tenant_id=$1 \
             AND provider_request_id=ANY($2)",
        )
        .bind(request.tenant_id)
        .bind(&request_ids)
        .bind(&request.statement_digest)
        .bind(if matched { "MATCHED" } else { "MISMATCH" })
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        Ok(result)
    }
}

#[derive(Clone)]
pub struct ModelExecutionAuthority {
    store: PostgresModelAuthorityStore,
    runtime: Arc<dyn ProductionModelRuntime>,
    instance_id: Uuid,
    lease_seconds: i64,
}

impl ModelExecutionAuthority {
    pub fn new(
        store: PostgresModelAuthorityStore,
        runtime: Arc<dyn ProductionModelRuntime>,
        instance_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Self, AuthorityError> {
        if !(15..=300).contains(&lease_seconds) {
            return Err(AuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            runtime,
            instance_id,
            lease_seconds,
        })
    }

    pub async fn execute(
        &self,
        mut request: ModelExecutionRequest,
        binding: ExecutionBinding,
    ) -> Result<(ModelExecutionResult, Vec<ModelStreamEvent>), AuthorityError> {
        validate_request_binding(&request, &binding)?;
        let request_digest = canonical_digest(&request)?;
        let prompt_digest = digest(request.prompt_utf8.as_bytes());
        let outcome = self
            .store
            .prepare(&request, &binding, &request_digest, &prompt_digest)
            .await?;
        let (request_id, reservation_id) = match outcome {
            PrepareOutcome::New {
                request_id,
                reservation_id,
            }
            | PrepareOutcome::RetryPrepared {
                request_id,
                reservation_id,
            } => (request_id, reservation_id),
            PrepareOutcome::Replay(result) => return Ok((*result, Vec::new())),
            PrepareOutcome::Failed(_) => return Err(AuthorityError::StateConflict),
            PrepareOutcome::Unknown => return Err(AuthorityError::ProviderOutcomeUnknown),
        };
        let mut plan = match self.runtime.plan(&request, &binding).await {
            Ok(plan) => plan,
            Err(error) => {
                request.prompt_utf8.zeroize();
                self.store
                    .fail_before_provider(
                        request.tenant_id,
                        request_id,
                        stable_error_for_plan(&error),
                    )
                    .await?;
                return Err(error);
            }
        };
        if let Err(error) = validate_plan(&request, &plan) {
            request.prompt_utf8.zeroize();
            plan.transformed_prompt_utf8.zeroize();
            self.store
                .fail_before_provider(request.tenant_id, request_id, stable_error_for_plan(&error))
                .await?;
            return Err(error);
        }
        if let Err(error) = self
            .store
            .claim(
                request.tenant_id,
                request_id,
                self.instance_id,
                self.lease_seconds,
                &plan,
            )
            .await
        {
            request.prompt_utf8.zeroize();
            plan.transformed_prompt_utf8.zeroize();
            return Err(error);
        }
        let provider_outcome = match self.runtime.invoke(&request, &binding, &plan).await {
            Ok(value) => value,
            Err(_) => {
                request.prompt_utf8.zeroize();
                plan.transformed_prompt_utf8.zeroize();
                self.store
                    .mark_unknown(
                        request.tenant_id,
                        request_id,
                        self.instance_id,
                        "MODEL_PROVIDER_OUTCOME_UNKNOWN",
                    )
                    .await?;
                return Err(AuthorityError::ProviderOutcomeUnknown);
            }
        };
        if validate_provider_outcome(&request, &provider_outcome).is_err() {
            request.prompt_utf8.zeroize();
            plan.transformed_prompt_utf8.zeroize();
            self.store
                .mark_unknown(
                    request.tenant_id,
                    request_id,
                    self.instance_id,
                    "MODEL_PROVIDER_PROTOCOL_OUTCOME_UNKNOWN",
                )
                .await?;
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let completion = match self
            .runtime
            .complete(&request, &binding, &plan, &provider_outcome)
            .await
        {
            Ok(value) => value,
            Err(_) => {
                request.prompt_utf8.zeroize();
                plan.transformed_prompt_utf8.zeroize();
                self.store
                    .mark_unknown(
                        request.tenant_id,
                        request_id,
                        self.instance_id,
                        "MODEL_COMPLETION_EVIDENCE_UNKNOWN",
                    )
                    .await?;
                return Err(AuthorityError::ProviderOutcomeUnknown);
            }
        };
        if validate_completion(&completion).is_err() {
            request.prompt_utf8.zeroize();
            plan.transformed_prompt_utf8.zeroize();
            self.store
                .mark_unknown(
                    request.tenant_id,
                    request_id,
                    self.instance_id,
                    "MODEL_COMPLETION_EVIDENCE_INVALID",
                )
                .await?;
            return Err(AuthorityError::ProviderOutcomeUnknown);
        }
        let result = build_result(request_id, &plan, &provider_outcome, &completion);
        let chunks = build_stream_events(request_id, &provider_outcome, &completion)?;
        let persisted = self
            .store
            .succeed(
                &request,
                &binding,
                request_id,
                reservation_id,
                self.instance_id,
                &plan,
                &provider_outcome,
                &completion,
                &result,
                &chunks,
            )
            .await;
        request.prompt_utf8.zeroize();
        plan.transformed_prompt_utf8.zeroize();
        persisted?;
        Ok((result, chunks))
    }

    pub async fn ready(&self) -> Result<(), AuthorityError> {
        self.store.ready().await?;
        self.runtime.ready().await
    }

    pub async fn list_executions(
        &self,
        query: ModelExecutionListQuery,
    ) -> Result<AuthoritativeModelExecutionsPage, AuthorityError> {
        self.store.list_executions(&query).await
    }

    pub async fn recover_tenant(&self, tenant_id: Uuid) -> Result<u64, AuthorityError> {
        self.store.recover_expired(tenant_id, 100).await
    }

    pub async fn reconcile(
        &self,
        request: BillingStatementRequest,
        binding: ExecutionBinding,
    ) -> Result<BillingReconciliationResult, AuthorityError> {
        validate_billing_binding(&request, &binding)?;
        self.runtime
            .verify_billing_statement(&request, Utc::now())
            .await?;
        let preview = self.store.preview_billing(&request).await?;
        let evidence = self
            .runtime
            .billing_evidence(
                &request, &binding, preview.0, preview.1, preview.2, preview.3,
            )
            .await?;
        if evidence.schema_version != "agenttrust.model-billing-evidence.v1"
            || !evidence_reference(&evidence.evidence_ref, 512)
            || !digest_value(&evidence.evidence_digest)
        {
            return Err(AuthorityError::DependencyUnavailable);
        }
        self.store
            .reconcile_billing(&request, &binding, &evidence)
            .await
    }
}

async fn reservation_id(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    request_id: Uuid,
) -> Result<Uuid, AuthorityError> {
    sqlx::query_scalar(
        "SELECT reservation_id FROM public.model_budget_reservations \
         WHERE tenant_id=$1 AND request_id=$2 AND state='RESERVED'",
    )
    .bind(tenant_id)
    .bind(request_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| AuthorityError::DependencyUnavailable)
}

async fn lock_running(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    request_id: Uuid,
    owner: Uuid,
    provider_key: &str,
    require_live_lease: bool,
) -> Result<(), AuthorityError> {
    let row = sqlx::query(
        "SELECT selected_provider_key,lease_expires_at > now() AS lease_valid \
         FROM public.model_gateway_requests WHERE tenant_id=$1 AND request_id=$2 AND state='EXECUTING' \
         AND owner_instance_id=$3 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(request_id)
    .bind(owner)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AuthorityError::DependencyUnavailable)?
    .ok_or(AuthorityError::StateConflict)?;
    let selected: String = row
        .try_get("selected_provider_key")
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
    let lease_valid: bool = row
        .try_get("lease_valid")
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
    if (require_live_lease && !lease_valid)
        || (!provider_key.is_empty() && selected != provider_key)
    {
        return Err(AuthorityError::StateConflict);
    }
    Ok(())
}

fn stable_error_for_plan(error: &AuthorityError) -> &'static str {
    match error {
        AuthorityError::BudgetExceeded => "MODEL_BUDGET_EXCEEDED",
        AuthorityError::NoCompliantProvider => "MODEL_NO_COMPLIANT_PROVIDER",
        AuthorityError::ProviderDenied => "MODEL_PROVIDER_DENIED",
        AuthorityError::PrincipalDenied => "MODEL_PRINCIPAL_DENIED",
        AuthorityError::RequestInvalid | AuthorityError::BindingInvalid => "MODEL_REQUEST_INVALID",
        AuthorityError::DependencyUnavailable | AuthorityError::ConfigurationInvalid => {
            "MODEL_PLANNING_DEPENDENCY_UNAVAILABLE"
        }
        AuthorityError::IdempotencyConflict
        | AuthorityError::ProviderOutcomeUnknown
        | AuthorityError::StateConflict => "MODEL_PLANNING_STATE_CONFLICT",
    }
}

fn validate_billing_binding(
    request: &BillingStatementRequest,
    binding: &ExecutionBinding,
) -> Result<(), AuthorityError> {
    let computed =
        action_hash(&request.canonical_action).map_err(|_| AuthorityError::RequestInvalid)?;
    let material = BillingStatementDigestMaterial {
        schema_version: &request.schema_version,
        tenant_id: request.tenant_id,
        provider_id: &request.provider_id,
        statement_period: &request.statement_period,
        residency_policy_evidence_digest: &request.residency_policy_evidence_digest,
        lines: &request.lines,
    };
    if request.schema_version != "agenttrust.model-billing-statement.v1"
        || request.tenant_id.to_string() != binding.tenant_id.0
        || computed.0 != binding.action_hash
        || !digest_value(&binding.authorization_digest)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest_value(&binding.policy_decision_digest)
        || !evidence_reference(&binding.authorization_evidence_ref, 512)
        || !digest_value(&binding.authorization_evidence_digest)
        || !digest_value(&binding.ledger_event_digest)
        || !digest_value(&binding.fence_digest)
        || !idempotency(&binding.idempotency_key)
        || !identifier(&binding.trace_id, 128)
        || canonical_resource_version(&binding.resource_version).is_none()
        || !identifier(&request.provider_id, 128)
        || !identifier(&request.statement_period, 64)
        || !digest_value(&request.statement_digest)
        || !digest_value(&request.residency_policy_evidence_digest)
        || request.lines.is_empty()
        || request.lines.len() > 100_000
        || canonical_digest(&material)? != request.statement_digest
        || request.provider_attestation.schema_version
            != "agenttrust.model-provider-billing-attestation.v1"
        || request.provider_attestation.provider_id != request.provider_id
        || request.provider_attestation.statement_period != request.statement_period
        || request.provider_attestation.statement_digest != request.statement_digest
        || request.provider_attestation.key_usage != "MODEL_PROVIDER_BILLING"
        || !identifier(&request.provider_attestation.issuer, 256)
        || !identifier(&request.provider_attestation.key_id, 128)
        || request.provider_attestation.issued_at >= request.provider_attestation.expires_at
        || request.provider_attestation.signature.is_empty()
    {
        return Err(AuthorityError::BindingInvalid);
    }
    let mut provider_requests = BTreeSet::new();
    for line in &request.lines {
        if !line
            .provider_key
            .starts_with(&format!("{}:", request.provider_id))
            || !identifier(&line.provider_key, 768)
            || !identifier(&line.provider_request_id, 512)
            || !provider_requests.insert(line.provider_request_id.as_str())
            || line.input_tokens.checked_add(line.output_tokens).is_none()
            || line.billed_microunits > i64::MAX as u64
        {
            return Err(AuthorityError::RequestInvalid);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct BillingStatementDigestMaterial<'a> {
    schema_version: &'a str,
    tenant_id: Uuid,
    provider_id: &'a str,
    statement_period: &'a str,
    residency_policy_evidence_digest: &'a str,
    lines: &'a [BillingLine],
}

fn compare_billing_rows(
    rows: &[sqlx::postgres::PgRow],
    lines: &[BillingLine],
    residency_policy_evidence_digest: &str,
) -> Result<(bool, u64, u64, u64), AuthorityError> {
    let mut metered = std::collections::BTreeMap::new();
    let mut total_metered = 0_u64;
    for row in rows {
        let provider_request_id: String = row
            .try_get("provider_request_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let provider_key: String = row
            .try_get("provider_key")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let input_tokens = u64::try_from(
            row.try_get::<i64, _>("input_tokens")
                .map_err(|_| AuthorityError::DependencyUnavailable)?,
        )
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let output_tokens = u64::try_from(
            row.try_get::<i64, _>("output_tokens")
                .map_err(|_| AuthorityError::DependencyUnavailable)?,
        )
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let amount = u64::try_from(
            row.try_get::<i64, _>("metered_microunits")
                .map_err(|_| AuthorityError::DependencyUnavailable)?,
        )
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
        let policy_evidence_digest: String = row
            .try_get("residency_policy_evidence_digest")
            .map_err(|_| AuthorityError::DependencyUnavailable)?;
        total_metered = total_metered
            .checked_add(amount)
            .ok_or(AuthorityError::RequestInvalid)?;
        if metered
            .insert(
                provider_request_id,
                (
                    provider_key,
                    input_tokens,
                    output_tokens,
                    amount,
                    policy_evidence_digest,
                ),
            )
            .is_some()
        {
            return Err(AuthorityError::DependencyUnavailable);
        }
    }
    let mut total_billed = 0_u64;
    let mut matched = rows.len() == lines.len();
    for line in lines {
        total_billed = total_billed
            .checked_add(line.billed_microunits)
            .ok_or(AuthorityError::RequestInvalid)?;
        matched &= metered.get(&line.provider_request_id).is_some_and(
            |(provider_key, input_tokens, output_tokens, amount, policy_evidence_digest)| {
                provider_key == &line.provider_key
                    && input_tokens == &line.input_tokens
                    && output_tokens == &line.output_tokens
                    && amount == &line.billed_microunits
                    && policy_evidence_digest == residency_policy_evidence_digest
            },
        );
    }
    Ok((
        matched,
        u64::try_from(rows.len()).map_err(|_| AuthorityError::RequestInvalid)?,
        total_metered,
        total_billed,
    ))
}

fn authoritative_summary(
    row: &sqlx::postgres::PgRow,
) -> Result<AuthoritativeModelExecutionSummary, AuthorityError> {
    let operation = match row
        .try_get::<String, _>("operation")
        .map_err(|_| AuthorityError::DependencyUnavailable)?
        .as_str()
    {
        "GENERATE" => ModelOperation::Generate,
        "STREAM" => ModelOperation::Stream,
        "EMBEDDINGS" => ModelOperation::Embeddings,
        _ => return Err(AuthorityError::DependencyUnavailable),
    };
    let input_tokens = row
        .try_get::<Option<i64>, _>("input_tokens")
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
    let output_tokens = row
        .try_get::<Option<i64>, _>("output_tokens")
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
    let cost_microunits = row
        .try_get::<Option<i64>, _>("metered_microunits")
        .map_err(|_| AuthorityError::DependencyUnavailable)?;
    let usage = match (input_tokens, output_tokens, cost_microunits) {
        (Some(input), Some(output), Some(cost)) => Some(ModelUsage {
            input_tokens: u64::try_from(input)
                .map_err(|_| AuthorityError::DependencyUnavailable)?,
            output_tokens: u64::try_from(output)
                .map_err(|_| AuthorityError::DependencyUnavailable)?,
            cost_microunits: u64::try_from(cost)
                .map_err(|_| AuthorityError::DependencyUnavailable)?,
        }),
        (None, None, None) => None,
        _ => return Err(AuthorityError::DependencyUnavailable),
    };
    let summary = AuthoritativeModelExecutionSummary {
        request_id: row
            .try_get("request_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        task_id: row
            .try_get("task_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        action_id: row
            .try_get("action_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        action_hash: row
            .try_get("action_hash")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        operation,
        classification: row
            .try_get("classification")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        source_jurisdiction: row
            .try_get("source_jurisdiction")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        deployment_profile: row
            .try_get("deployment_profile")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        state: row
            .try_get("state")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        provider_key: row
            .try_get("selected_provider_key")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        provider_request_id: row
            .try_get("provider_request_id")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        usage,
        output_digest: row
            .try_get("output_digest")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        artifact_ref: row
            .try_get("output_artifact_ref")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        artifact_digest: row
            .try_get("output_artifact_digest")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        evidence_ref: row
            .try_get("evidence_ref")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        evidence_digest: row
            .try_get("evidence_digest")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        stable_error: row
            .try_get("stable_error")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
        completed_at: row
            .try_get("completed_at")
            .map_err(|_| AuthorityError::DependencyUnavailable)?,
    };
    if !digest_value(&summary.action_hash)
        || !matches!(
            summary.state.as_str(),
            "PREPARED" | "EXECUTING" | "SUCCEEDED" | "FAILED" | "UNKNOWN"
        )
        || summary
            .stable_error
            .as_deref()
            .is_some_and(|value| !stable_code(value))
    {
        return Err(AuthorityError::DependencyUnavailable);
    }
    Ok(summary)
}

fn validate_request_binding(
    request: &ModelExecutionRequest,
    binding: &ExecutionBinding,
) -> Result<(), AuthorityError> {
    let computed =
        action_hash(&request.canonical_action).map_err(|_| AuthorityError::RequestInvalid)?;
    if request.schema_version != EXECUTION_REQUEST_SCHEMA
        || request.tenant_id.to_string() != binding.tenant_id.0
        || request.task_id.to_string() != request.canonical_action.task_id.0
        || request.action_id.to_string() != request.canonical_action.action_id.0
        || computed.0 != binding.action_hash
        || request.idempotency_key != binding.idempotency_key
        || !digest_value(&binding.action_hash)
        || !digest_value(&binding.authorization_digest)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest_value(&binding.policy_decision_digest)
        || !digest_value(&binding.authorization_evidence_digest)
        || !digest_value(&binding.ledger_event_digest)
        || !digest_value(&binding.fence_digest)
        || !evidence_reference(&binding.authorization_evidence_ref, 512)
        || canonical_resource_version(&binding.resource_version).is_none()
        || !identifier(&binding.trace_id, 128)
        || !idempotency(&request.idempotency_key)
        || !identifier(&request.task_type, 128)
        || !valid_model_data_label(request)
        || !identifier(&request.source_jurisdiction, 128)
        || !identifier(&request.deployment_profile, 128)
        || request.cross_domain_approval_id.is_some() != request.cross_domain_grant_id.is_some()
        || request.cross_domain_grant_id.is_some() != request.cross_domain_source_zone.is_some()
        || request.cross_domain_grant_id.is_some() != request.cross_domain_target_zone.is_some()
        || request
            .cross_domain_source_zone
            .as_deref()
            .is_some_and(|value| !identifier(value, 256))
        || request
            .cross_domain_target_zone
            .as_deref()
            .is_some_and(|value| !identifier(value, 256))
        || request.required_capabilities.is_empty()
        || request.required_capabilities.len() > 5
        || request.allowed_provider_ids.is_empty()
        || request.allowed_provider_ids.len() > 100
        || !request.required_capabilities.iter().all(|value| {
            matches!(
                value.as_str(),
                "GENERATE" | "STREAM" | "EMBEDDINGS" | "TOOL_CALLING" | "STRUCTURED_OUTPUT"
            )
        })
        || request
            .allowed_provider_ids
            .iter()
            .any(|value| !identifier(value, 128))
        || !(1..=300_000).contains(&request.maximum_latency_ms)
        || request.maximum_cost_microunits == 0
        || request.maximum_cost_microunits > i64::MAX as u64
        || !(1..=1_048_576).contains(&request.maximum_output_bytes)
        || request.prompt_utf8.is_empty()
        || request.prompt_utf8.len() > 4_194_304
    {
        return Err(AuthorityError::BindingInvalid);
    }
    let expected = match request.operation {
        ModelOperation::Generate => "GENERATE",
        ModelOperation::Stream => "STREAM",
        ModelOperation::Embeddings => "EMBEDDINGS",
    };
    if !request.required_capabilities.contains(expected) {
        return Err(AuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_plan(request: &ModelExecutionRequest, plan: &RoutePlan) -> Result<(), AuthorityError> {
    let provider_id = plan
        .provider_key
        .split(':')
        .next()
        .ok_or(AuthorityError::NoCompliantProvider)?;
    if plan.schema_version != ROUTE_PLAN_SCHEMA
        || !request.allowed_provider_ids.contains(provider_id)
        || !identifier(&plan.provider_key, 768)
        || !identifier(&plan.endpoint_profile, 128)
        || !identifier(&plan.model_id, 256)
        || !identifier(&plan.model_version, 256)
        || !jurisdiction(&plan.provider_region)
        || !jurisdiction(&plan.provider_jurisdiction)
        || !matches!(
            plan.protocol.as_str(),
            "OPENAI_COMPATIBLE" | "LOCAL_INFERENCE"
        )
        || !digest_value(&plan.provider_manifest_digest)
        || !digest_value(&plan.route_decision_digest)
        || !digest_value(&plan.pre_transform_policy_decision_digest)
        || !evidence_reference(&plan.pre_transform_policy_evidence_ref, 2048)
        || !digest_value(&plan.pre_transform_policy_evidence_digest)
        || !digest_value(&plan.data_policy_decision_digest)
        || !evidence_reference(&plan.data_policy_evidence_ref, 2048)
        || !digest_value(&plan.data_policy_evidence_digest)
        || !digest_value(&plan.transformation_digest)
        || plan.transform_evidence_ref.is_some() != plan.transform_evidence_digest.is_some()
        || plan
            .transform_evidence_ref
            .as_deref()
            .is_some_and(|value| !evidence_reference(value, 2048))
        || plan
            .transform_evidence_digest
            .as_deref()
            .is_some_and(|value| !digest_value(value))
        || !digest_value(&plan.dlp_report_digest)
        || !evidence_reference(&plan.input_dlp_evidence_ref, 2048)
        || !digest_value(&plan.input_dlp_evidence_digest)
        || !digest_value(&plan.residency_policy_request_digest)
        || !identifier(&plan.data_policy_version, 256)
        || plan.route_reasons.is_empty()
        || plan.route_reasons.len() > 32
        || plan
            .route_reasons
            .iter()
            .any(|value| !identifier(value, 256))
        || plan.transformed_prompt_utf8.is_empty()
        || plan.transformed_prompt_utf8.len() > 4_194_304
    {
        return Err(AuthorityError::ProviderDenied);
    }
    Ok(())
}

fn validate_provider_outcome(
    request: &ModelExecutionRequest,
    outcome: &ProviderOutcome,
) -> Result<(), AuthorityError> {
    let output_bytes = outcome
        .output_utf8
        .as_ref()
        .map_or(0, |value| value.len())
        .saturating_add(outcome.stream_chunks.iter().map(String::len).sum::<usize>());
    if outcome.schema_version != EXTERNAL_OUTCOME_SCHEMA
        || !identifier(&outcome.provider_request_id, 512)
        || !identifier(&outcome.finish_reason, 64)
        || outcome.input_tokens.saturating_add(outcome.output_tokens) == 0
        || outcome.cost_microunits > request.maximum_cost_microunits
        || !adapter_reference(&outcome.residency_attestation_ref, 2048)
        || !digest_value(&outcome.residency_attestation_digest)
        || output_bytes > request.maximum_output_bytes
        || outcome.stream_chunks.len() > 10_000
        || outcome
            .stream_chunks
            .iter()
            .any(|chunk| chunk.is_empty() || chunk.len() > 1_048_576)
        || outcome.embedding.as_ref().is_some_and(|values| {
            values.is_empty()
                || values.len() > 65_536
                || values.iter().any(|value| !value.is_finite())
        })
        || match request.operation {
            ModelOperation::Generate => {
                outcome.output_utf8.is_none()
                    || !outcome.stream_chunks.is_empty()
                    || outcome.embedding.is_some()
            }
            ModelOperation::Stream => {
                outcome.stream_chunks.is_empty()
                    || outcome.output_utf8.is_some()
                    || outcome.embedding.is_some()
            }
            ModelOperation::Embeddings => {
                outcome.embedding.is_none()
                    || outcome.output_utf8.is_some()
                    || !outcome.stream_chunks.is_empty()
            }
        }
    {
        return Err(AuthorityError::ProviderOutcomeUnknown);
    }
    Ok(())
}

fn validate_completion(completion: &CompletionEvidence) -> Result<(), AuthorityError> {
    if completion.schema_version != COMPLETION_EVIDENCE_SCHEMA
        || !completion.artifact_ref.starts_with("artifact://sha256/")
        || completion.artifact_ref.len() != 82
        || !digest_value(&completion.artifact_digest)
        || !digest_value(&completion.output_digest)
        || completion.artifact_digest != completion.output_digest
        || completion.artifact_ref != format!("artifact://sha256/{}", completion.output_digest)
        || !evidence_reference(&completion.evidence_ref, 512)
        || !digest_value(&completion.evidence_digest)
        || !evidence_reference(&completion.residency_policy_evidence_ref, 2048)
        || !digest_value(&completion.residency_policy_evidence_digest)
        || !adapter_reference(&completion.residency_attestation_ref, 2048)
        || !digest_value(&completion.residency_attestation_digest)
        || !digest_value(&completion.output_dlp_report_digest)
        || !evidence_reference(&completion.output_dlp_evidence_ref, 2048)
        || !digest_value(&completion.output_dlp_evidence_digest)
        || !evidence_reference(&completion.output_label_evidence_ref, 2048)
        || !digest_value(&completion.output_label_evidence_digest)
        || !evidence_reference(&completion.artifact_policy_evidence_ref, 2048)
        || !digest_value(&completion.artifact_policy_evidence_digest)
        || completion.grant_consumption_evidence_ref.is_some()
            != completion.grant_consumption_evidence_digest.is_some()
        || completion
            .grant_consumption_evidence_ref
            .as_deref()
            .is_some_and(|value| !evidence_reference(value, 2048))
        || completion
            .grant_consumption_evidence_digest
            .as_deref()
            .is_some_and(|value| !digest_value(value))
        || !evidence_reference(&completion.export_authorization_evidence_ref, 2048)
        || !digest_value(&completion.export_authorization_evidence_digest)
        || !evidence_reference(&completion.export_completion_evidence_ref, 2048)
        || !digest_value(&completion.export_completion_evidence_digest)
        || !adapter_reference(&completion.artifact_store_receipt_ref, 2048)
        || !digest_value(&completion.artifact_store_receipt_digest)
    {
        return Err(AuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn valid_model_data_label(request: &ModelExecutionRequest) -> bool {
    let label = &request.data_label;
    label.schema_version == "agenttrust.data-governance.v1"
        && label.classification == request.classification
        && label.jurisdictions.contains(&request.source_jurisdiction)
        && !label.jurisdictions.is_empty()
        && label.jurisdictions.len() <= 32
        && label.jurisdictions.iter().all(|value| jurisdiction(value))
        && label.domain_tags.len() <= 64
        && label.domain_tags.iter().all(|value| identifier(value, 256))
        && identifier(&label.retention_label, 128)
        && identifier(&label.lineage.source_id, 512)
        && digest_value(&label.lineage.source_hash)
        && label.lineage.source_hash == digest(request.prompt_utf8.as_bytes())
        && label.lineage.transformation_hashes.len() <= 1024
        && label
            .lineage
            .transformation_hashes
            .iter()
            .all(|value| digest_value(value))
        && label
            .lineage
            .transformation_hashes
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == label.lineage.transformation_hashes.len()
        && !label.contains_secret
        && (!label.contains_personal_data
            || (request.classification == DataClassification::Regulated && label.export_restricted))
        && (!matches!(label.confidence, ModelLabelConfidence::Unknown)
            || matches!(
                request.classification,
                DataClassification::Restricted | DataClassification::Regulated
            ))
}

fn build_result(
    request_id: Uuid,
    plan: &RoutePlan,
    outcome: &ProviderOutcome,
    completion: &CompletionEvidence,
) -> ModelExecutionResult {
    ModelExecutionResult {
        schema_version: EXECUTION_RESULT_SCHEMA.into(),
        request_id,
        status: "SUCCEEDED".into(),
        replayed: false,
        output_utf8: outcome.output_utf8.clone(),
        embedding: outcome.embedding.clone(),
        artifact_ref: completion.artifact_ref.clone(),
        artifact_digest: completion.artifact_digest.clone(),
        untrusted_content: true,
        provider_key: plan.provider_key.clone(),
        provider_request_id: outcome.provider_request_id.clone(),
        usage: ModelUsage {
            input_tokens: outcome.input_tokens,
            output_tokens: outcome.output_tokens,
            cost_microunits: outcome.cost_microunits,
        },
        output_digest: completion.output_digest.clone(),
        evidence_ref: completion.evidence_ref.clone(),
        evidence_digest: completion.evidence_digest.clone(),
    }
}

fn build_stream_events(
    request_id: Uuid,
    outcome: &ProviderOutcome,
    completion: &CompletionEvidence,
) -> Result<Vec<ModelStreamEvent>, AuthorityError> {
    if outcome.stream_chunks.is_empty() {
        return Ok(Vec::new());
    }
    let last = outcome.stream_chunks.len();
    outcome
        .stream_chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let sequence = u64::try_from(index + 1).map_err(|_| AuthorityError::RequestInvalid)?;
            let terminal = index + 1 == last;
            Ok(ModelStreamEvent {
                schema_version: STREAM_EVENT_SCHEMA.into(),
                request_id,
                sequence,
                chunk_utf8: chunk.clone(),
                release_mode: StreamReleaseMode::DlpVerifiedBuffered,
                terminal,
                finish_reason: terminal.then(|| outcome.finish_reason.clone()),
                usage: terminal.then_some(ModelUsage {
                    input_tokens: outcome.input_tokens,
                    output_tokens: outcome.output_tokens,
                    cost_microunits: outcome.cost_microunits,
                }),
                artifact_ref: terminal.then(|| completion.artifact_ref.clone()),
                artifact_digest: terminal.then(|| completion.artifact_digest.clone()),
                evidence_ref: terminal.then(|| completion.evidence_ref.clone()),
                evidence_digest: terminal.then(|| completion.evidence_digest.clone()),
            })
        })
        .collect()
}

fn sanitized_result(result: &ModelExecutionResult) -> Result<Value, AuthorityError> {
    let mut safe = result.clone();
    safe.output_utf8 = None;
    safe.embedding = None;
    safe.replayed = true;
    serde_json::to_value(safe).map_err(|_| AuthorityError::DependencyUnavailable)
}

fn classification_name(value: DataClassification) -> &'static str {
    match value {
        DataClassification::Public => "PUBLIC",
        DataClassification::Internal => "INTERNAL",
        DataClassification::Confidential => "CONFIDENTIAL",
        DataClassification::Restricted => "RESTRICTED",
        DataClassification::Regulated => "REGULATED",
    }
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| digest(&bytes))
        .map_err(|_| AuthorityError::RequestInvalid)
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_value(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn evidence_reference(value: &str, maximum: usize) -> bool {
    value.starts_with("evidence://") && identifier(value, maximum)
}

fn adapter_reference(value: &str, maximum: usize) -> bool {
    [
        "dlp://",
        "object://",
        "worm://",
        "legal-hold://",
        "evidence://",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
        && identifier(value, maximum)
}

fn jurisdiction(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn idempotency(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn canonical_resource_version(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value && *parsed <= i64::MAX as u64)
}

fn stable_code(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod authority_tests {
    use super::*;

    #[test]
    fn stable_errors_and_digests_are_strict() {
        assert!(stable_code("MODEL_PROVIDER_OUTCOME_UNKNOWN"));
        assert!(!stable_code("provider failed: secret"));
        assert!(digest_value(&"a".repeat(64)));
        assert!(!digest_value(&"A".repeat(64)));
    }

    #[test]
    fn persisted_replay_never_contains_model_payload() {
        let result = ModelExecutionResult {
            schema_version: EXECUTION_RESULT_SCHEMA.into(),
            request_id: Uuid::nil(),
            status: "SUCCEEDED".into(),
            replayed: false,
            output_utf8: Some("sensitive".into()),
            embedding: Some(vec![1.0]),
            artifact_ref: format!("artifact://sha256/{}", "a".repeat(64)),
            artifact_digest: "a".repeat(64),
            untrusted_content: true,
            provider_key: "p:m:v".into(),
            provider_request_id: "request".into(),
            usage: ModelUsage {
                input_tokens: 1,
                output_tokens: 1,
                cost_microunits: 2,
            },
            output_digest: "b".repeat(64),
            evidence_ref: "evidence://request".into(),
            evidence_digest: "c".repeat(64),
        };
        let safe = sanitized_result(&result).unwrap_or(Value::Null);
        assert!(safe.get("output_utf8").is_some_and(Value::is_null));
        assert!(safe.get("embedding").is_some_and(Value::is_null));
    }

    #[test]
    fn stream_chunks_are_only_exposed_as_post_dlp_buffered_release() {
        let outcome = ProviderOutcome {
            schema_version: EXTERNAL_OUTCOME_SCHEMA.into(),
            provider_request_id: "provider-request".into(),
            output_utf8: None,
            embedding: None,
            stream_chunks: vec!["one".into(), "two".into()],
            finish_reason: "stop".into(),
            input_tokens: 2,
            output_tokens: 2,
            cost_microunits: 4,
            residency_attestation_ref: "evidence://provider/residency".into(),
            residency_attestation_digest: "a".repeat(64),
        };
        let completion = CompletionEvidence {
            schema_version: COMPLETION_EVIDENCE_SCHEMA.into(),
            artifact_ref: format!("artifact://sha256/{}", "b".repeat(64)),
            artifact_digest: "b".repeat(64),
            output_digest: "c".repeat(64),
            evidence_ref: "evidence://model/completion".into(),
            evidence_digest: "d".repeat(64),
            residency_policy_evidence_ref: "evidence://policy/residency".into(),
            residency_policy_evidence_digest: "e".repeat(64),
            residency_attestation_ref: "evidence://provider/residency".into(),
            residency_attestation_digest: "a".repeat(64),
            output_dlp_report_digest: "f".repeat(64),
            output_dlp_evidence_ref: "evidence://dlp/output".into(),
            output_dlp_evidence_digest: "1".repeat(64),
            output_label_evidence_ref: "evidence://label/output".into(),
            output_label_evidence_digest: "2".repeat(64),
            artifact_policy_evidence_ref: "evidence://artifact/policy".into(),
            artifact_policy_evidence_digest: "3".repeat(64),
            grant_consumption_evidence_ref: None,
            grant_consumption_evidence_digest: None,
            export_authorization_evidence_ref: "evidence://export/authorization".into(),
            export_authorization_evidence_digest: "4".repeat(64),
            export_completion_evidence_ref: "evidence://export/completion".into(),
            export_completion_evidence_digest: "5".repeat(64),
            artifact_store_receipt_ref: "evidence://artifact/store".into(),
            artifact_store_receipt_digest: "6".repeat(64),
        };
        let events = build_stream_events(Uuid::nil(), &outcome, &completion)
            .unwrap_or_else(|_| panic!("stream"));
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| { event.release_mode == StreamReleaseMode::DlpVerifiedBuffered })
        );
        assert!(events[0].evidence_ref.is_none());
        assert_eq!(
            events[1].evidence_digest.as_deref(),
            Some(completion.evidence_digest.as_str())
        );
    }
}
