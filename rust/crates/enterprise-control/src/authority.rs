//! Canonical enterprise mutation ingress and the fenced production executor.

use crate::principal::VerifiedHumanPrincipal;
use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector, RiskContext,
    RiskLevel, SchemaVersion, StepId, StrictJsonObject, TaskId, TenantId, ToolId, ToolRef,
    ToolVersion,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const ENTERPRISE_MUTATION_REQUEST_SCHEMA: &str = "agenttrust.enterprise-mutation-request.v1";
pub const ENTERPRISE_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.enterprise-action-receipt.v1";
pub const ENTERPRISE_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.enterprise-executor-request.v1";
pub const ENTERPRISE_EXECUTOR_RESULT_SCHEMA: &str = "agenttrust.enterprise-mutation-result.v1";

#[derive(Debug, Error)]
pub enum EnterpriseAuthorityError {
    #[error("ENTERPRISE_REQUEST_INVALID")]
    RequestInvalid,
    #[error("ENTERPRISE_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("ENTERPRISE_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("ENTERPRISE_STATE_CONFLICT")]
    StateConflict,
    #[error("ENTERPRISE_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("ENTERPRISE_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("ENTERPRISE_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMutationRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub admin_intent: EnterpriseAdminIntent,
    pub reason_digest: String,
    pub mutation: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseAdminIntent {
    pub schema_version: String,
    pub action_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Option<String>,
    pub operation: String,
    pub resource: String,
    pub requested_by: String,
    #[serde(default)]
    pub approval_ids: BTreeSet<String>,
    pub action_digest: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseActionReceipt {
    pub schema_version: String,
    pub action_id: String,
    pub task_id: String,
    pub accepted: bool,
    pub start_requested: bool,
    pub execution_pending: bool,
    pub ingress_digest: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone)]
pub struct EnterpriseAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
    pub assertion_scope: String,
}

impl EnterpriseAuthorityConfig {
    pub fn validate(&self) -> Result<(), EnterpriseAuthorityError> {
        if Uuid::parse_str(&self.service_agent_id.0)
            .is_ok_and(|value| value.to_string() == self.service_agent_id.0)
            && identifier(&self.organization_id, 256)
            && identifier(&self.agent_version, 128)
            && identifier(&self.region, 128)
            && identifier(&self.tool_id.0, 256)
            && identifier(&self.tool_version.0, 128)
            && identifier(&self.credential_profile, 128)
            && identifier(&self.service_subject, 256)
            && self.assertion_scope == "enterprise:mutate"
        {
            Ok(())
        } else {
            Err(EnterpriseAuthorityError::ConfigurationInvalid)
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedEnterpriseIngress {
    pub envelope: InboundEnvelope,
    pub receipt: Option<EnterpriseActionReceipt>,
}

#[async_trait]
pub trait EnterpriseOrchestratorPort: Send + Sync {
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<EnterpriseActionReceipt, EnterpriseAuthorityError>;
}

#[derive(Clone)]
pub struct EnterpriseIngressAuthority {
    store: PostgresEnterpriseAuthorityStore,
    orchestrator: Arc<dyn EnterpriseOrchestratorPort>,
    config: EnterpriseAuthorityConfig,
}

impl EnterpriseIngressAuthority {
    pub fn new(
        store: PostgresEnterpriseAuthorityStore,
        orchestrator: Arc<dyn EnterpriseOrchestratorPort>,
        config: EnterpriseAuthorityConfig,
    ) -> Result<Self, EnterpriseAuthorityError> {
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
        request: EnterpriseMutationRequest,
        request_digest: &str,
        idempotency_key: &str,
    ) -> Result<EnterpriseActionReceipt, EnterpriseAuthorityError> {
        validate_ingress_request(principal, &request, request_digest, idempotency_key)?;
        let tenant = TenantId(request.tenant_id.to_string());
        let current_version = self
            .store
            .current_resource_version(&tenant, &request.admin_intent.resource)
            .await?;
        let action =
            canonical_enterprise_action(principal, &request, &current_version, &self.config)?;
        let prepared = self
            .store
            .prepare_ingress(principal, &request, request_digest, idempotency_key, action)
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
        self.store.ready().await
    }
}

fn validate_ingress_request(
    principal: &VerifiedHumanPrincipal,
    request: &EnterpriseMutationRequest,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<(), EnterpriseAuthorityError> {
    let intent = &request.admin_intent;
    let required_role = required_role(&intent.operation)?;
    if request.schema_version != ENTERPRISE_MUTATION_REQUEST_SCHEMA
        || request.tenant_id.to_string() != principal.tenant_id.0
        || intent.tenant_id != request.tenant_id
        || intent.schema_version != "agenttrust.enterprise-control.v1"
        || intent.action_id.is_nil()
        || intent.requested_by != principal.subject
        || !principal.roles.contains(required_role)
        || intent.approval_ids.is_empty()
        || !intent.approval_ids.is_subset(&principal.approval_ids)
        || !digest(&intent.action_digest)
        || !digest(&request.reason_digest)
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || !resource_matches(&intent.operation, &intent.resource, &request.mutation)
        || intent.operation == "CREATE_TENANT"
            && intent.resource != format!("tenant:{}", request.tenant_id)
        || !principal_project_scope_matches(principal, &intent.operation, &request.mutation)
        || request.mutation.as_object().is_none()
        || serde_json::to_vec(&request.mutation).map_or(true, |value| value.len() > 262_144)
        || intent.requested_at > Utc::now() + Duration::minutes(5)
        || intent.requested_at < Utc::now() - Duration::hours(24)
        || intent
            .project_id
            .as_ref()
            .is_some_and(|project| !principal.project_ids.contains(project))
    {
        return Err(EnterpriseAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn principal_project_scope_matches(
    principal: &VerifiedHumanPrincipal,
    operation: &str,
    mutation: &Value,
) -> bool {
    let project = mutation
        .as_object()
        .and_then(|object| object.get("project_id"))
        .and_then(Value::as_str);
    match operation {
        "RECORD_COST" => project.is_some_and(|value| principal.project_ids.contains(value)),
        "ISSUE_API_KEY" => project.is_none_or(|value| principal.project_ids.contains(value)),
        _ => true,
    }
}

fn required_role(operation: &str) -> Result<&'static str, EnterpriseAuthorityError> {
    match operation {
        "CREATE_TENANT" | "CREATE_ORGANIZATION" => Ok("tenant-admin"),
        "CREATE_PROJECT" => Ok("project-admin"),
        "CREATE_INTEGRATION" => Ok("integration-admin"),
        "CONSUME_QUOTA" => Ok("quota-operator"),
        "RECORD_COST" => Ok("billing-operator"),
        "ISSUE_API_KEY" | "REVOKE_API_KEY" => Ok("credential-admin"),
        "SUBMIT_ADMIN_ACTION" => Ok("control-operator"),
        value
            if value.len() <= 100
                && value
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_uppercase())
                && value.bytes().all(|byte| {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                }) =>
        {
            Ok("control-operator")
        }
        _ => Err(EnterpriseAuthorityError::RequestInvalid),
    }
}

fn resource_matches(operation: &str, resource: &str, mutation: &Value) -> bool {
    let object = match mutation.as_object() {
        Some(value) => value,
        None => return false,
    };
    match operation {
        "CREATE_TENANT" => resource.starts_with("tenant:"),
        "CREATE_ORGANIZATION" => object
            .get("organization_id")
            .and_then(Value::as_str)
            .is_some_and(|id| resource == format!("organization:{id}")),
        "CREATE_PROJECT" => object
            .get("project_id")
            .and_then(Value::as_str)
            .is_some_and(|id| resource == format!("project:{id}")),
        "CREATE_INTEGRATION" => object
            .get("integration_id")
            .and_then(Value::as_str)
            .is_some_and(|id| resource == format!("integration:{id}")),
        "CONSUME_QUOTA" => object
            .get("quota_key")
            .and_then(Value::as_str)
            .is_some_and(|id| resource == format!("quota:{id}")),
        "RECORD_COST" => object
            .get("usage_id")
            .and_then(Value::as_str)
            .is_some_and(|id| resource == format!("cost:{id}")),
        "ISSUE_API_KEY" => resource == "api-key:new",
        "REVOKE_API_KEY" => object
            .get("api_key_id")
            .and_then(Value::as_str)
            .is_some_and(|id| resource == format!("api-key:{id}")),
        "SUBMIT_ADMIN_ACTION" => !resource.is_empty() && resource.len() <= 1_000,
        value if required_role(value).ok() == Some("control-operator") => {
            !resource.is_empty() && resource.len() <= 1_000
        }
        _ => false,
    }
}

fn canonical_enterprise_action(
    principal: &VerifiedHumanPrincipal,
    request: &EnterpriseMutationRequest,
    current_version: &str,
    config: &EnterpriseAuthorityConfig,
) -> Result<InboundEnvelope, EnterpriseAuthorityError> {
    let now = Utc::now();
    let tenant = TenantId(request.tenant_id.to_string());
    let task_id = TaskId::new();
    let step_id = StepId::new();
    let effective_operation = executor_operation(&request.admin_intent.operation);
    let operation = effective_operation.to_ascii_lowercase();
    let locator = format!("enterprise/{}", request.admin_intent.resource);
    let mut payload = Map::new();
    payload.insert(
        "schema_version".into(),
        Value::String(ENTERPRISE_EXECUTOR_REQUEST_SCHEMA.into()),
    );
    payload.insert(
        "action_id".into(),
        Value::String(request.admin_intent.action_id.to_string()),
    );
    payload.insert(
        "operation".into(),
        Value::String(effective_operation.into()),
    );
    payload.insert(
        "resource".into(),
        Value::String(request.admin_intent.resource.clone()),
    );
    payload.insert(
        "admin_action_digest".into(),
        Value::String(request.admin_intent.action_digest.clone()),
    );
    payload.insert(
        "reason_digest".into(),
        Value::String(request.reason_digest.clone()),
    );
    payload.insert(
        "requester_subject".into(),
        Value::String(principal.subject.clone()),
    );
    payload.insert(
        "approval_ids".into(),
        Value::Array(
            request
                .admin_intent
                .approval_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    let effective_mutation = if effective_operation == "SUBMIT_ADMIN_ACTION"
        && request.admin_intent.operation != "SUBMIT_ADMIN_ACTION"
    {
        json!({
            "admin_operation": request.admin_intent.operation,
            "admin_payload": request.mutation,
        })
    } else {
        request.mutation.clone()
    };
    payload.insert("mutation".into(), effective_mutation);
    let plan_hash = sha256(
        &serde_jcs::to_vec(&json!({
            "operation": effective_operation,
            "resource": request.admin_intent.resource,
            "current_state_version": current_version,
            "payload": &payload,
        }))
        .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?,
    );
    let mut extensions = std::collections::BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    extensions.insert(
        "x-human-principal-assertion-digest".into(),
        Value::String(principal.assertion_digest.clone()),
    );
    extensions.insert(
        "x-admin-action-digest".into(),
        Value::String(request.admin_intent.action_digest.clone()),
    );
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(request.admin_intent.action_id.to_string()),
        task_id: task_id.clone(),
        step_id,
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "enterprise-control-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: principal.subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-enterprise-control".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: format!("human-assertion://{}", principal.jti),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: request.admin_intent.action_digest.clone(),
            operation,
            justification_code: "ENTERPRISE_ADMIN".into(),
            safe_summary: Some(format!(
                "{} on {}",
                request.admin_intent.operation, request.admin_intent.resource
            )),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "enterprise.control.mutation.v1".into(),
            schema_version: "1".into(),
            data: payload,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator,
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: false,
        },
        current_state_version: Some(current_version.to_string()),
        risk: RiskContext {
            declared_risk: RiskLevel::High,
            trajectory_risk_ref: None,
            scope_delta: 1,
            automation_allowed: false,
        },
        data: DataContext {
            classification: DataClassification::Internal,
            jurisdiction: config.region.clone(),
            export_constraints: vec!["TENANT_BOUND".into()],
        },
        expected_outcome: ExpectedOutcome {
            metric: "enterprise_mutation_persisted".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "enterprise/".into(),
            operations: vec![effective_operation.to_ascii_lowercase()],
        }],
        requested_at: request.admin_intent.requested_at,
        extensions,
    };
    let action = normalize(draft, &NormalizationContext::default())
        .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    // Invoke the official hash here as an additional normalization invariant.  The durable
    // orchestrator re-normalizes and hashes the same canonical payload before PEP execution.
    action_hash(&action).map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    let payload =
        serde_json::to_vec(&action).map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    let payload_hash = sha256(&payload);
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
            quota_profile: "enterprise-control".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: None, // set by prepare_ingress before the exact envelope is persisted
        received_at: now,
        payload,
        payload_hash,
    })
}

fn executor_operation(operation: &str) -> &str {
    match operation {
        "CREATE_TENANT"
        | "CREATE_ORGANIZATION"
        | "CREATE_PROJECT"
        | "CREATE_INTEGRATION"
        | "CONSUME_QUOTA"
        | "RECORD_COST"
        | "ISSUE_API_KEY"
        | "REVOKE_API_KEY"
        | "SUBMIT_ADMIN_ACTION" => operation,
        _ => "SUBMIT_ADMIN_ACTION",
    }
}

#[derive(Clone)]
pub struct PostgresEnterpriseAuthorityStore {
    pool: PgPool,
}

impl PostgresEnterpriseAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    async fn tenant_transaction<'a>(
        &'a self,
        tenant: &TenantId,
    ) -> Result<(Uuid, Transaction<'a, Postgres>), EnterpriseAuthorityError> {
        let tenant_uuid = canonical_uuid(&tenant.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        Ok((tenant_uuid, transaction))
    }

    pub async fn current_resource_version(
        &self,
        tenant: &TenantId,
        resource: &str,
    ) -> Result<String, EnterpriseAuthorityError> {
        if !safe_resource(resource) {
            return Err(EnterpriseAuthorityError::RequestInvalid);
        }
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let value = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM enterprise_resource_versions \
             WHERE tenant_id=$1 AND resource=$2",
        )
        .bind(tenant_uuid)
        .bind(resource)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        transaction
            .commit()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        Ok(value.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_ingress(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: &EnterpriseMutationRequest,
        request_digest: &str,
        idempotency_key: &str,
        mut envelope: InboundEnvelope,
    ) -> Result<PreparedEnterpriseIngress, EnterpriseAuthorityError> {
        let tenant = &principal.tenant_id;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_key(&mut transaction, tenant, idempotency_key).await?;
        let existing = sqlx::query(
            "SELECT request_digest,envelope,receipt FROM enterprise_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        if let Some(row) = existing {
            if row.try_get::<String, _>("request_digest").ok().as_deref() != Some(request_digest) {
                return Err(EnterpriseAuthorityError::IdempotencyConflict);
            }
            let stored: Value = row
                .try_get("envelope")
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            let envelope: InboundEnvelope = serde_json::from_value(stored)
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            let receipt = row
                .try_get::<Option<Value>, _>("receipt")
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            transaction
                .commit()
                .await
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            return Ok(PreparedEnterpriseIngress { envelope, receipt });
        }
        let inserted = sqlx::query(
            "INSERT INTO enterprise_principal_assertion_replay \
             (tenant_id,jti,assertion_digest,request_digest,expires_at) \
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(canonical_uuid(&principal.jti)?)
        .bind(&principal.assertion_digest)
        .bind(request_digest)
        .bind(principal.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .rows_affected();
        if inserted != 1 {
            return Err(EnterpriseAuthorityError::PrincipalDenied);
        }
        envelope.idempotency_key = Some(idempotency_key.to_string());
        let envelope_value = serde_json::to_value(&envelope)
            .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
        let action_id = request.admin_intent.action_id;
        let task_id = envelope_action_id(&envelope, "task_id")?;
        let inserted = sqlx::query(
            "INSERT INTO enterprise_action_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,principal_subject,\
              principal_assertion_digest,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PREPARED')",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(action_id)
        .bind(task_id)
        .bind(&principal.subject)
        .bind(&principal.assertion_digest)
        .bind(envelope_value)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .rows_affected();
        if inserted != 1 {
            return Err(EnterpriseAuthorityError::IdempotencyConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        Ok(PreparedEnterpriseIngress {
            envelope,
            receipt: None,
        })
    }

    pub async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &EnterpriseActionReceipt,
    ) -> Result<EnterpriseActionReceipt, EnterpriseAuthorityError> {
        validate_action_receipt(receipt, tenant)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_key(&mut transaction, tenant, idempotency_key).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,receipt FROM enterprise_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .ok_or(EnterpriseAuthorityError::StateConflict)?;
        let action_id: Uuid = row
            .try_get("action_id")
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        let task_id: Uuid = row
            .try_get("task_id")
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        if action_id.to_string() != receipt.action_id || task_id.to_string() != receipt.task_id {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        if let Some(value) = row
            .try_get::<Option<Value>, _>("receipt")
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        {
            let stored: EnterpriseActionReceipt = serde_json::from_value(value)
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            if &stored != receipt {
                return Err(EnterpriseAuthorityError::StateConflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            return Ok(stored);
        }
        let value = serde_json::to_value(receipt)
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        let changed = sqlx::query(
            "UPDATE enterprise_action_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED' AND receipt IS NULL",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .bind(&value)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        append_outbox(
            &mut transaction,
            tenant_uuid,
            "ENTERPRISE_ACTION_ACCEPTED",
            &receipt.action_id,
            &value,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        Ok(receipt.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseExecutorRequest {
    pub schema_version: String,
    pub action_id: String,
    pub operation: String,
    pub resource: String,
    pub admin_action_digest: String,
    pub reason_digest: String,
    pub requester_subject: String,
    pub approval_ids: BTreeSet<String>,
    pub mutation: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseExecutionBinding {
    pub tenant_id: TenantId,
    pub action_hash: String,
    pub ledger_execution_id: String,
    pub fence_digest: String,
    pub resource_version: String,
    pub idempotency_key: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMutationResult {
    pub schema_version: String,
    pub action_id: String,
    pub state: String,
    pub resource: String,
    pub previous_resource_version: String,
    pub resource_version: String,
    pub credential_ref: Option<String>,
    pub safe_result: Value,
}

#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub api_key_id: Uuid,
    pub key_hash: String,
    pub credential_ref: String,
}

#[async_trait]
pub trait CredentialAuthorityPort: Send + Sync {
    async fn issue(
        &self,
        tenant: &TenantId,
        action_id: Uuid,
        scopes: &BTreeSet<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<IssuedCredential, EnterpriseAuthorityError>;
}

#[derive(Clone)]
pub struct EnterpriseExecutor {
    store: PostgresEnterpriseAuthorityStore,
    credentials: Arc<dyn CredentialAuthorityPort>,
}

impl EnterpriseExecutor {
    pub fn new(
        store: PostgresEnterpriseAuthorityStore,
        credentials: Arc<dyn CredentialAuthorityPort>,
    ) -> Self {
        Self { store, credentials }
    }

    pub async fn execute(
        &self,
        binding: EnterpriseExecutionBinding,
        request: EnterpriseExecutorRequest,
    ) -> Result<EnterpriseMutationResult, EnterpriseAuthorityError> {
        validate_executor_request(&binding, &request)?;
        match self.store.prepare_execution(&binding, &request).await? {
            PrepareExecutionOutcome::Replay(result) => return Ok(result),
            PrepareExecutionOutcome::Unknown => {
                return Err(EnterpriseAuthorityError::OutcomeUnknown);
            }
            PrepareExecutionOutcome::New | PrepareExecutionOutcome::RetryPrepared => {}
        }
        self.store.mark_execution_running(&binding).await?;
        let issued = if request.operation == "ISSUE_API_KEY" {
            let mutation = request
                .mutation
                .as_object()
                .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
            let scopes = string_set(mutation.get("scopes"), 64)?;
            let expires_at = mutation
                .get("expires_at")
                .and_then(Value::as_str)
                .ok_or(EnterpriseAuthorityError::RequestInvalid)?
                .parse::<DateTime<Utc>>()
                .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
            match self
                .credentials
                .issue(
                    &binding.tenant_id,
                    canonical_uuid(&request.action_id)?,
                    &scopes,
                    expires_at,
                )
                .await
            {
                Ok(value) => Some(value),
                Err(error) => {
                    self.store.mark_execution_unknown(&binding).await?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        match self
            .store
            .apply_execution(&binding, &request, issued.as_ref())
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if issued.is_some() => {
                // Vault has already accepted the credential write. No later database error is a
                // safely replayable deterministic failure.
                self.store.mark_execution_unknown(&binding).await?;
                Err(match error {
                    EnterpriseAuthorityError::DependencyUnavailable => error,
                    _ => EnterpriseAuthorityError::OutcomeUnknown,
                })
            }
            Err(
                EnterpriseAuthorityError::RequestInvalid
                | EnterpriseAuthorityError::PrincipalDenied
                | EnterpriseAuthorityError::StateConflict,
            ) => {
                self.store.mark_execution_failed(&binding).await?;
                Err(EnterpriseAuthorityError::StateConflict)
            }
            Err(error) => {
                self.store.mark_execution_unknown(&binding).await?;
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
pub enum PrepareExecutionOutcome {
    New,
    RetryPrepared,
    Replay(EnterpriseMutationResult),
    Unknown,
}

impl PostgresEnterpriseAuthorityStore {
    pub async fn prepare_execution(
        &self,
        binding: &EnterpriseExecutionBinding,
        request: &EnterpriseExecutorRequest,
    ) -> Result<PrepareExecutionOutcome, EnterpriseAuthorityError> {
        let request_digest =
            canonical_digest(&json!({"binding": binding_material(binding), "request": request}))?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&binding.tenant_id).await?;
        lock_key(
            &mut transaction,
            &binding.tenant_id,
            &binding.idempotency_key,
        )
        .await?;
        let row = sqlx::query(
            "SELECT request_digest,action_hash,ledger_execution_id,fence_digest,resource_version,\
             state,safe_result FROM enterprise_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        if let Some(row) = row {
            let exact = row.try_get::<String, _>("request_digest").ok().as_deref()
                == Some(request_digest.as_str())
                && row.try_get::<String, _>("action_hash").ok().as_deref()
                    == Some(binding.action_hash.as_str())
                && row
                    .try_get::<Uuid, _>("ledger_execution_id")
                    .ok()
                    .map(|id| id.to_string())
                    == Some(binding.ledger_execution_id.clone())
                && row.try_get::<String, _>("fence_digest").ok().as_deref()
                    == Some(binding.fence_digest.as_str())
                && row
                    .try_get::<i64, _>("resource_version")
                    .ok()
                    .map(|value| value.to_string())
                    == Some(binding.resource_version.clone());
            if !exact {
                return Err(EnterpriseAuthorityError::IdempotencyConflict);
            }
            let state: String = row
                .try_get("state")
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            let outcome = match state.as_str() {
                "PREPARED" => PrepareExecutionOutcome::RetryPrepared,
                "EXECUTING" | "UNKNOWN" => PrepareExecutionOutcome::Unknown,
                "SUCCEEDED" => {
                    let value: Value = row
                        .try_get("safe_result")
                        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
                    PrepareExecutionOutcome::Replay(
                        serde_json::from_value(value)
                            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?,
                    )
                }
                "FAILED" => return Err(EnterpriseAuthorityError::StateConflict),
                _ => return Err(EnterpriseAuthorityError::DependencyUnavailable),
            };
            transaction
                .commit()
                .await
                .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
            return Ok(outcome);
        }
        let inserted = sqlx::query(
            "INSERT INTO enterprise_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,action_hash,ledger_execution_id,\
              fence_digest,resource,resource_version,trace_id,request,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PREPARED')",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(request_digest)
        .bind(canonical_uuid(&request.action_id)?)
        .bind(&binding.action_hash)
        .bind(canonical_uuid(&binding.ledger_execution_id)?)
        .bind(&binding.fence_digest)
        .bind(&request.resource)
        .bind(parse_version(&binding.resource_version)?)
        .bind(&binding.trace_id)
        .bind(serde_json::to_value(request).map_err(|_| EnterpriseAuthorityError::RequestInvalid)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .rows_affected();
        if inserted != 1 {
            return Err(EnterpriseAuthorityError::IdempotencyConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        Ok(PrepareExecutionOutcome::New)
    }

    pub async fn mark_execution_running(
        &self,
        binding: &EnterpriseExecutionBinding,
    ) -> Result<(), EnterpriseAuthorityError> {
        self.transition_execution(binding, "PREPARED", "EXECUTING", None)
            .await
    }

    pub async fn mark_execution_unknown(
        &self,
        binding: &EnterpriseExecutionBinding,
    ) -> Result<(), EnterpriseAuthorityError> {
        self.transition_execution(binding, "EXECUTING", "UNKNOWN", None)
            .await
    }

    pub async fn mark_execution_failed(
        &self,
        binding: &EnterpriseExecutionBinding,
    ) -> Result<(), EnterpriseAuthorityError> {
        self.transition_execution(
            binding,
            "EXECUTING",
            "FAILED",
            Some("ENTERPRISE_MUTATION_REJECTED"),
        )
        .await
    }

    async fn transition_execution(
        &self,
        binding: &EnterpriseExecutionBinding,
        from: &str,
        to: &str,
        stable_error: Option<&str>,
    ) -> Result<(), EnterpriseAuthorityError> {
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&binding.tenant_id).await?;
        lock_key(
            &mut transaction,
            &binding.tenant_id,
            &binding.idempotency_key,
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE enterprise_authority_executions SET state=$3,stable_error=$4,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state=$5 \
             AND action_hash=$6 AND ledger_execution_id=$7 AND fence_digest=$8",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(to)
        .bind(stable_error)
        .bind(from)
        .bind(&binding.action_hash)
        .bind(canonical_uuid(&binding.ledger_execution_id)?)
        .bind(&binding.fence_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        append_outbox(
            &mut transaction,
            tenant_uuid,
            &format!("ENTERPRISE_EXECUTION_{to}"),
            &binding.ledger_execution_id,
            &json!({"state": to, "action_hash": binding.action_hash, "fence_digest": binding.fence_digest}),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)
    }

    pub async fn apply_execution(
        &self,
        binding: &EnterpriseExecutionBinding,
        request: &EnterpriseExecutorRequest,
        issued: Option<&IssuedCredential>,
    ) -> Result<EnterpriseMutationResult, EnterpriseAuthorityError> {
        let expected_version = parse_version(&binding.resource_version)?;
        let next_version = expected_version
            .checked_add(1)
            .ok_or(EnterpriseAuthorityError::StateConflict)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&binding.tenant_id).await?;
        lock_key(
            &mut transaction,
            &binding.tenant_id,
            &binding.idempotency_key,
        )
        .await?;
        lock_resource(&mut transaction, &binding.tenant_id, &request.resource).await?;
        let execution = sqlx::query(
            "SELECT state,request FROM enterprise_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .ok_or(EnterpriseAuthorityError::StateConflict)?;
        if execution.try_get::<String, _>("state").ok().as_deref() != Some("EXECUTING")
            || execution
                .try_get::<Value, _>("request")
                .ok()
                .and_then(|value| serde_json::from_value::<EnterpriseExecutorRequest>(value).ok())
                .as_ref()
                != Some(request)
        {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM enterprise_resource_versions \
             WHERE tenant_id=$1 AND resource=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.resource)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current != expected_version {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        let safe_result =
            apply_business_mutation(&mut transaction, tenant_uuid, request, issued).await?;
        let changed = if expected_version == 0 {
            sqlx::query(
                "INSERT INTO enterprise_resource_versions \
                 (tenant_id,resource,resource_version,action_hash,ledger_execution_id,fence_digest) \
                 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            )
            .bind(tenant_uuid)
            .bind(&request.resource)
            .bind(next_version)
            .bind(&binding.action_hash)
            .bind(canonical_uuid(&binding.ledger_execution_id)?)
            .bind(&binding.fence_digest)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE enterprise_resource_versions SET resource_version=$3,action_hash=$4,\
                 ledger_execution_id=$5,fence_digest=$6,updated_at=now() \
                 WHERE tenant_id=$1 AND resource=$2 AND resource_version=$7",
            )
            .bind(tenant_uuid)
            .bind(&request.resource)
            .bind(next_version)
            .bind(&binding.action_hash)
            .bind(canonical_uuid(&binding.ledger_execution_id)?)
            .bind(&binding.fence_digest)
            .bind(expected_version)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
            .rows_affected()
        };
        if changed != 1 {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        let result = EnterpriseMutationResult {
            schema_version: ENTERPRISE_EXECUTOR_RESULT_SCHEMA.into(),
            action_id: request.action_id.clone(),
            state: "SUCCEEDED".into(),
            resource: request.resource.clone(),
            previous_resource_version: expected_version.to_string(),
            resource_version: next_version.to_string(),
            credential_ref: issued.map(|value| value.credential_ref.clone()),
            safe_result,
        };
        let value = serde_json::to_value(&result)
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        let result_digest = canonical_digest(&value)?;
        let completed = sqlx::query(
            "UPDATE enterprise_authority_executions SET state='SUCCEEDED',safe_result=$3,\
             safe_result_digest=$4,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING' \
             AND action_hash=$5 AND ledger_execution_id=$6 AND fence_digest=$7",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(&value)
        .bind(&result_digest)
        .bind(&binding.action_hash)
        .bind(canonical_uuid(&binding.ledger_execution_id)?)
        .bind(&binding.fence_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
        .rows_affected();
        if completed != 1 {
            return Err(EnterpriseAuthorityError::StateConflict);
        }
        append_outbox(
            &mut transaction,
            tenant_uuid,
            "ENTERPRISE_EXECUTION_SUCCEEDED",
            &binding.ledger_execution_id,
            &json!({
                "schema_version": ENTERPRISE_EXECUTOR_RESULT_SCHEMA,
                "action_id": request.action_id,
                "action_hash": binding.action_hash,
                "ledger_execution_id": binding.ledger_execution_id,
                "fence_digest": binding.fence_digest,
                "result_digest": result_digest,
                "resource": request.resource,
                "resource_version": next_version.to_string(),
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
        Ok(result)
    }
}

async fn apply_business_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &EnterpriseExecutorRequest,
    issued: Option<&IssuedCredential>,
) -> Result<Value, EnterpriseAuthorityError> {
    let mutation = request
        .mutation
        .as_object()
        .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
    let affected = match request.operation.as_str() {
        "CREATE_TENANT" => {
            let quota = mutation
                .get("quota")
                .cloned()
                .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
            sqlx::query(
                "INSERT INTO enterprise_tenants \
                 (tenant_id,display_name,owner_subject,data_region,quota) VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(tenant)
            .bind(required_text(mutation, "display_name", 200)?)
            .bind(required_text(mutation, "owner_subject", 300)?)
            .bind(required_text(mutation, "data_region", 32)?)
            .bind(quota)
            .execute(&mut **transaction)
            .await
        }
        "CREATE_ORGANIZATION" => sqlx::query(
            "INSERT INTO enterprise_organizations \
             (tenant_id,organization_id,display_name,sponsor_subject) VALUES ($1,$2,$3,$4)",
        )
        .bind(tenant)
        .bind(required_text(mutation, "organization_id", 200)?)
        .bind(required_text(mutation, "display_name", 200)?)
        .bind(required_text(mutation, "sponsor_subject", 300)?)
        .execute(&mut **transaction)
        .await,
        "CREATE_PROJECT" => sqlx::query(
            "INSERT INTO enterprise_projects \
             (tenant_id,project_id,organization_id,owner_subject,environments) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(tenant)
        .bind(required_text(mutation, "project_id", 200)?)
        .bind(required_text(mutation, "organization_id", 200)?)
        .bind(required_text(mutation, "owner_subject", 300)?)
        .bind(mutation.get("environments").cloned().ok_or(EnterpriseAuthorityError::RequestInvalid)?)
        .execute(&mut **transaction)
        .await,
        "CREATE_INTEGRATION" => {
            let endpoint = required_text(mutation, "endpoint", 2_048)?;
            let secret_ref = required_text(mutation, "secret_ref", 1_000)?;
            let parsed = url::Url::parse(endpoint)
                .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || !valid_credential_ref(secret_ref)
            {
                return Err(EnterpriseAuthorityError::RequestInvalid);
            }
            sqlx::query(
                "INSERT INTO enterprise_integrations \
                 (tenant_id,integration_id,kind,endpoint,secret_ref,configuration_digest,active) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(tenant)
            .bind(canonical_uuid(required_text(mutation, "integration_id", 36)?)?)
            .bind(required_text(mutation, "kind", 32)?)
            .bind(endpoint)
            .bind(secret_ref)
            .bind(required_digest(mutation, "configuration_digest")?)
            .bind(mutation.get("active").and_then(Value::as_bool).unwrap_or(false))
            .execute(&mut **transaction)
            .await
        }
        "CONSUME_QUOTA" => {
            let amount = required_positive_i64(mutation, "amount")?;
            let limit = required_positive_i64(mutation, "limit")?;
            sqlx::query(
                "INSERT INTO enterprise_quota_usage \
                 (tenant_id,quota_key,window_started_at,used,limit_value) VALUES ($1,$2,$3,$4,$5) \
                 ON CONFLICT (tenant_id,quota_key,window_started_at) DO UPDATE \
                 SET used=enterprise_quota_usage.used+EXCLUDED.used,limit_value=EXCLUDED.limit_value \
                 WHERE enterprise_quota_usage.limit_value=EXCLUDED.limit_value \
                 AND enterprise_quota_usage.used+EXCLUDED.used<=EXCLUDED.limit_value",
            )
            .bind(tenant)
            .bind(required_text(mutation, "quota_key", 100)?)
            .bind(required_time(mutation, "window_started_at")?)
            .bind(amount)
            .bind(limit)
            .execute(&mut **transaction)
            .await
        }
        "RECORD_COST" => {
            let quantity = required_positive_i64(mutation, "quantity")?;
            let unit_cost = required_nonnegative_i64(mutation, "unit_cost_micros")?;
            let total = quantity
                .checked_mul(unit_cost)
                .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
            sqlx::query(
                "INSERT INTO enterprise_cost_usage \
                 (tenant_id,usage_id,project_id,meter,quantity,unit_cost_micros,total_cost_micros,\
                  source_digest,recorded_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(tenant)
            .bind(canonical_uuid(required_text(mutation, "usage_id", 36)?)?)
            .bind(required_text(mutation, "project_id", 200)?)
            .bind(required_text(mutation, "meter", 100)?)
            .bind(quantity)
            .bind(unit_cost)
            .bind(total)
            .bind(required_digest(mutation, "source_digest")?)
            .bind(required_time(mutation, "recorded_at")?)
            .execute(&mut **transaction)
            .await
        }
        "ISSUE_API_KEY" => {
            let issued = issued.ok_or(EnterpriseAuthorityError::OutcomeUnknown)?;
            let scopes = mutation
                .get("scopes")
                .cloned()
                .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
            sqlx::query(
                "INSERT INTO enterprise_api_keys \
                 (tenant_id,api_key_id,project_id,key_hash,credential_ref,scopes,created_by,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(tenant)
            .bind(issued.api_key_id)
            .bind(mutation.get("project_id").and_then(Value::as_str))
            .bind(&issued.key_hash)
            .bind(&issued.credential_ref)
            .bind(scopes)
            .bind(&request.requester_subject)
            .bind(required_time(mutation, "expires_at")?)
            .execute(&mut **transaction)
            .await
        }
        "REVOKE_API_KEY" => sqlx::query(
            "UPDATE enterprise_api_keys SET revoked_at=now(),revocation_reason=$3 \
             WHERE tenant_id=$1 AND api_key_id=$2 AND revoked_at IS NULL",
        )
        .bind(tenant)
        .bind(canonical_uuid(required_text(mutation, "api_key_id", 36)?)?)
        .bind(format!("digest:{}", request.reason_digest))
        .execute(&mut **transaction)
        .await,
        "SUBMIT_ADMIN_ACTION" => sqlx::query(
            "INSERT INTO enterprise_admin_actions \
             (tenant_id,action_id,requester_subject,operation,resource,action_digest,approvals,reason) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(tenant)
        .bind(canonical_uuid(&request.action_id)?)
        .bind(&request.requester_subject)
        .bind(
            mutation
                .get("admin_operation")
                .and_then(Value::as_str)
                .unwrap_or(&request.operation),
        )
        .bind(&request.resource)
        .bind(&request.admin_action_digest)
        .bind(json!(request.approval_ids))
        .bind(format!("digest:{}", request.reason_digest))
        .execute(&mut **transaction)
        .await,
        _ => return Err(EnterpriseAuthorityError::RequestInvalid),
    }
    .map_err(|_| EnterpriseAuthorityError::StateConflict)?
    .rows_affected();
    if affected != 1 {
        return Err(EnterpriseAuthorityError::StateConflict);
    }
    Ok(match (request.operation.as_str(), issued) {
        ("ISSUE_API_KEY", Some(value)) => json!({
            "api_key_id": value.api_key_id,
            "credential_ref": value.credential_ref,
            "raw_secret_returned": false,
        }),
        ("CONSUME_QUOTA", _) => json!({"accepted": true, "usage_result_deferred": true}),
        _ => json!({"accepted": true}),
    })
}

#[derive(Clone)]
pub struct VaultKvCredentialAuthority {
    client: reqwest::Client,
    base_url: url::Url,
    mount: String,
    path_prefix: String,
    token: Arc<Zeroizing<String>>,
    pepper: Arc<Zeroizing<Vec<u8>>>,
}

impl VaultKvCredentialAuthority {
    pub fn new(
        client: reqwest::Client,
        base_url: url::Url,
        mount: String,
        path_prefix: String,
        token: Zeroizing<String>,
        pepper: Zeroizing<Vec<u8>>,
    ) -> Result<Self, EnterpriseAuthorityError> {
        if base_url.scheme() != "https"
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
            || !path_segment(&mount)
            || path_prefix.is_empty()
            || path_prefix.len() > 128
            || path_prefix.split('/').any(|part| !path_segment(part))
            || token.len() < 16
            || token.len() > 8_192
            || token.bytes().any(|byte| !byte.is_ascii_graphic())
            || pepper.len() < 32
            || pepper.len() > 4_096
        {
            return Err(EnterpriseAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            client,
            base_url,
            mount,
            path_prefix,
            token: Arc::new(token),
            pepper: Arc::new(pepper),
        })
    }
}

#[derive(Serialize)]
struct VaultKvWrite<'a> {
    options: VaultCas,
    data: VaultCredentialData<'a>,
}

#[derive(Serialize)]
struct VaultCas {
    cas: u8,
}

#[derive(Serialize)]
struct VaultCredentialData<'a> {
    api_key: &'a str,
    tenant_id: &'a str,
    api_key_id: String,
    scopes: &'a BTreeSet<String>,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct VaultKvWriteResponse {
    data: VaultKvWriteMetadata,
}

#[derive(Deserialize)]
struct VaultKvWriteMetadata {
    version: u64,
    created_time: Option<String>,
    deletion_time: Option<String>,
    destroyed: Option<bool>,
}

#[async_trait]
impl CredentialAuthorityPort for VaultKvCredentialAuthority {
    async fn issue(
        &self,
        tenant: &TenantId,
        action_id: Uuid,
        scopes: &BTreeSet<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<IssuedCredential, EnterpriseAuthorityError> {
        if scopes.is_empty()
            || scopes.len() > 64
            || scopes.iter().any(|scope| !identifier(scope, 100))
            || expires_at <= Utc::now()
            || expires_at > Utc::now() + Duration::days(365)
        {
            return Err(EnterpriseAuthorityError::RequestInvalid);
        }
        canonical_uuid(&tenant.0)?;
        let mut random = [0_u8; 32];
        OsRng.fill_bytes(&mut random);
        let secret = Zeroizing::new(format!("atk_{}", URL_SAFE_NO_PAD.encode(random)));
        random.zeroize();
        let mut mac = Hmac::<Sha256>::new_from_slice(self.pepper.as_slice())
            .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
        mac.update(secret.as_bytes());
        let key_hash = hex::encode(mac.finalize().into_bytes());
        let relative = format!(
            "v1/{}/data/{}/{}/{}",
            self.mount, self.path_prefix, tenant.0, action_id
        );
        let url = self
            .base_url
            .join(&relative)
            .map_err(|_| EnterpriseAuthorityError::ConfigurationInvalid)?;
        if url.host_str() != self.base_url.host_str()
            || url.port_or_known_default() != self.base_url.port_or_known_default()
        {
            return Err(EnterpriseAuthorityError::ConfigurationInvalid);
        }
        let body = VaultKvWrite {
            options: VaultCas { cas: 0 },
            data: VaultCredentialData {
                api_key: secret.as_str(),
                tenant_id: &tenant.0,
                api_key_id: action_id.to_string(),
                scopes,
                expires_at,
            },
        };
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", self.token.as_str())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| EnterpriseAuthorityError::OutcomeUnknown)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return Err(EnterpriseAuthorityError::OutcomeUnknown);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| EnterpriseAuthorityError::OutcomeUnknown)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(EnterpriseAuthorityError::OutcomeUnknown);
        }
        let metadata: VaultKvWriteResponse =
            serde_json::from_slice(&bytes).map_err(|_| EnterpriseAuthorityError::OutcomeUnknown)?;
        if metadata.data.version == 0
            || metadata
                .data
                .created_time
                .as_deref()
                .is_none_or(str::is_empty)
            || metadata
                .data
                .deletion_time
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            || metadata.data.destroyed == Some(true)
        {
            return Err(EnterpriseAuthorityError::OutcomeUnknown);
        }
        Ok(IssuedCredential {
            api_key_id: action_id,
            key_hash,
            credential_ref: format!(
                "vault-kv://{}/{}/{}/{}#v{}",
                self.mount, self.path_prefix, tenant.0, action_id, metadata.data.version
            ),
        })
    }
}

fn validate_executor_request(
    binding: &EnterpriseExecutionBinding,
    request: &EnterpriseExecutorRequest,
) -> Result<(), EnterpriseAuthorityError> {
    required_role(&request.operation)?;
    if request.schema_version != ENTERPRISE_EXECUTOR_REQUEST_SCHEMA
        || !digest(&binding.action_hash)
        || !digest(&binding.fence_digest)
        || !digest(&request.admin_action_digest)
        || !digest(&request.reason_digest)
        || canonical_uuid(&binding.tenant_id.0).is_err()
        || canonical_uuid(&binding.ledger_execution_id).is_err()
        || canonical_uuid(&request.action_id).is_err()
        || !valid_idempotency_key(&binding.idempotency_key)
        || parse_version(&binding.resource_version).is_err()
        || !identifier(&binding.trace_id, 256)
        || !identifier(&request.requester_subject, 256)
        || request.approval_ids.len() > 1_024
        || request
            .approval_ids
            .iter()
            .any(|value| !identifier(value, 256))
        || !resource_matches(&request.operation, &request.resource, &request.mutation)
        || request.mutation.as_object().is_none()
    {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_action_receipt(
    receipt: &EnterpriseActionReceipt,
    tenant: &TenantId,
) -> Result<(), EnterpriseAuthorityError> {
    if receipt.schema_version != ENTERPRISE_ACTION_RECEIPT_SCHEMA
        || canonical_uuid(&receipt.action_id).is_err()
        || canonical_uuid(&receipt.task_id).is_err()
        || !receipt.accepted
        || !receipt.start_requested
        || !receipt.execution_pending
        || !digest(&receipt.ingress_digest)
        || !digest(&receipt.evidence_digest)
        || receipt.evidence_ref.len() > 2_048
        || !valid_acceptance_evidence_ref(&receipt.evidence_ref, tenant, &receipt.task_id)
    {
        return Err(EnterpriseAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn valid_acceptance_evidence_ref(value: &str, tenant: &TenantId, task_id: &str) -> bool {
    let Some(rest) = value.strip_prefix("orchestrator-event://") else {
        return false;
    };
    let mut parts = rest.split('/');
    let (Some(ref_tenant), Some(ref_task), Some(sequence), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    ref_tenant == tenant.0
        && ref_task == task_id
        && canonical_uuid(ref_tenant).is_ok()
        && canonical_uuid(ref_task).is_ok()
        && sequence
            .parse::<u64>()
            .is_ok_and(|parsed| parsed > 0 && parsed.to_string() == sequence)
}

fn binding_material(binding: &EnterpriseExecutionBinding) -> Value {
    json!({
        "tenant_id": binding.tenant_id,
        "action_hash": binding.action_hash,
        "ledger_execution_id": binding.ledger_execution_id,
        "fence_digest": binding.fence_digest,
        "resource_version": binding.resource_version,
        "idempotency_key": binding.idempotency_key,
        "trace_id": binding.trace_id,
    })
}

fn envelope_action_id(
    envelope: &InboundEnvelope,
    field: &str,
) -> Result<Uuid, EnterpriseAuthorityError> {
    let action: Value = serde_json::from_slice(&envelope.payload)
        .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    canonical_uuid(
        action
            .get(field)
            .and_then(Value::as_str)
            .ok_or(EnterpriseAuthorityError::RequestInvalid)?,
    )
}

async fn lock_key(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    key: &str,
) -> Result<(), EnterpriseAuthorityError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("enterprise-idempotency:{}:{key}", tenant.0))
        .execute(&mut **transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
    Ok(())
}

async fn lock_resource(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    resource: &str,
) -> Result<(), EnterpriseAuthorityError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("enterprise-resource:{}:{resource}", tenant.0))
        .execute(&mut **transaction)
        .await
        .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?;
    Ok(())
}

async fn append_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    event_type: &str,
    aggregate_id: &str,
    payload: &Value,
) -> Result<(), EnterpriseAuthorityError> {
    let digest = canonical_digest(payload)?;
    let inserted = sqlx::query(
        "INSERT INTO enterprise_authority_outbox \
         (tenant_id,event_id,event_type,aggregate_id,payload,payload_digest) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(event_type)
    .bind(aggregate_id)
    .bind(payload)
    .bind(digest)
    .execute(&mut **transaction)
    .await
    .map_err(|_| EnterpriseAuthorityError::DependencyUnavailable)?
    .rows_affected();
    if inserted != 1 {
        return Err(EnterpriseAuthorityError::DependencyUnavailable);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, EnterpriseAuthorityError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    Ok(sha256(&bytes))
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn canonical_uuid(value: &str) -> Result<Uuid, EnterpriseAuthorityError> {
    let parsed = Uuid::parse_str(value).map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(parsed)
}

fn parse_version(value: &str) -> Result<i64, EnterpriseAuthorityError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| EnterpriseAuthorityError::RequestInvalid)?;
    if parsed < 0 || parsed.to_string() != value {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(parsed)
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
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_credential_ref(value: &str) -> bool {
    let (body, versioned) = if let Some(body) = value.strip_prefix("credential://") {
        (body, false)
    } else if let Some(body) = value.strip_prefix("vault-kv://") {
        (body, true)
    } else {
        return false;
    };
    let (path, version) = body.rsplit_once("#v").unwrap_or((body, ""));
    !path.is_empty()
        && path.len() <= 900
        && path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        && if versioned {
            !version.is_empty()
                && version
                    .parse::<u64>()
                    .is_ok_and(|parsed| parsed > 0 && parsed.to_string() == version)
        } else {
            version.is_empty()
        }
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn safe_resource(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1_000 && !value.contains(['\0', '\r', '\n'])
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a str, EnterpriseAuthorityError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
    if value.is_empty() || value.len() > maximum || value.contains(['\0', '\r', '\n']) {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_digest<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, EnterpriseAuthorityError> {
    let value = required_text(object, field, 64)?;
    if !digest(value) {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_time(
    object: &Map<String, Value>,
    field: &str,
) -> Result<DateTime<Utc>, EnterpriseAuthorityError> {
    required_text(object, field, 64)?
        .parse::<DateTime<Utc>>()
        .map_err(|_| EnterpriseAuthorityError::RequestInvalid)
}

fn required_positive_i64(
    object: &Map<String, Value>,
    field: &str,
) -> Result<i64, EnterpriseAuthorityError> {
    let value = object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
    if value <= 0 {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn required_nonnegative_i64(
    object: &Map<String, Value>,
    field: &str,
) -> Result<i64, EnterpriseAuthorityError> {
    let value = object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
    if value < 0 {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(value)
}

fn string_set(
    value: Option<&Value>,
    maximum: usize,
) -> Result<BTreeSet<String>, EnterpriseAuthorityError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(EnterpriseAuthorityError::RequestInvalid)?;
    if values.is_empty() || values.len() > maximum {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    let set = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| identifier(value, 100))
                .map(str::to_string)
                .ok_or(EnterpriseAuthorityError::RequestInvalid)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if set.len() != values.len() {
        return Err(EnterpriseAuthorityError::RequestInvalid);
    }
    Ok(set)
}

#[cfg(test)]
mod production_contract_tests {
    use super::*;

    #[test]
    fn credential_handles_and_acceptance_evidence_are_exactly_bound() {
        let tenant = TenantId("11111111-1111-4111-8111-111111111111".into());
        let task = "22222222-2222-4222-8222-222222222222";
        assert!(valid_credential_ref("credential://integrations/siem/main"));
        assert!(valid_credential_ref(
            "vault-kv://enterprise/integrations/siem#v7"
        ));
        assert!(!valid_credential_ref("secret-value"));
        assert!(!valid_credential_ref("vault-kv://enterprise/siem#v0"));
        assert!(valid_acceptance_evidence_ref(
            &format!("orchestrator-event://{}/{task}/1", tenant.0),
            &tenant,
            task,
        ));
        assert!(!valid_acceptance_evidence_ref(
            &format!("orchestrator-event://{}/{task}/01", tenant.0),
            &tenant,
            task,
        ));
    }

    #[test]
    fn project_facts_come_only_from_verified_principal() {
        let principal = VerifiedHumanPrincipal {
            tenant_id: TenantId("11111111-1111-4111-8111-111111111111".into()),
            subject: "human:operator".into(),
            roles: BTreeSet::from(["billing-operator".into()]),
            project_ids: BTreeSet::from(["project-a".into()]),
            approval_ids: BTreeSet::from(["approval-a".into()]),
            owned_resources: BTreeSet::new(),
            jti: "33333333-3333-4333-8333-333333333333".into(),
            assertion_digest: "a".repeat(64),
            expires_at: Utc::now() + Duration::minutes(1),
            authentication_context: "urn:mfa".into(),
        };
        assert!(principal_project_scope_matches(
            &principal,
            "RECORD_COST",
            &json!({"project_id": "project-a"}),
        ));
        assert!(!principal_project_scope_matches(
            &principal,
            "RECORD_COST",
            &json!({"project_id": "project-b"}),
        ));
    }
}
