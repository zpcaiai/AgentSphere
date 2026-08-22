//! Durable production orchestration and the authoritative Registry HTTPS adapter.

use super::*;
use agent_trust_contracts::{StrictJsonObject, ToolRef};
use agent_trust_registry::{
    AUTHORITATIVE_TOOLS_SCHEMA_VERSION, AuthoritativeToolSummary, AuthoritativeToolsResponse,
    CapabilityDescriptor, CapabilityQuery, ManifestSignature, REGISTRY_SCHEMA_VERSION,
    RegistryError, RegistrySnapshot, canonical_registry_snapshot_hash, validate_schema_instance,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier};
use serde::de::DeserializeOwned;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};

pub const TOOL_PROXY_READINESS_SCHEMA_VERSION: &str = "agenttrust.tool-proxy-readiness.v1";
const MAX_VERIFIED_REGISTRY_BYTES: usize = 4 * 1_048_576;
const MAX_CACHED_REGISTRY_TENANTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationState {
    Prepared,
    Executing,
    Succeeded,
    Failed,
    Unknown,
}

impl InvocationState {
    fn parse(value: &str) -> Result<Self, ProductionProxyError> {
        match value {
            "PREPARED" => Ok(Self::Prepared),
            "EXECUTING" => Ok(Self::Executing),
            "SUCCEEDED" => Ok(Self::Succeeded),
            "FAILED" => Ok(Self::Failed),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(ProductionProxyError::StoreUnavailable),
        }
    }
}

#[derive(Debug)]
pub enum PrepareOutcome {
    New,
    RetryPrepared,
    ReplaySucceeded(SanitizedToolResult),
    ReplayFailed(String),
    Unknown,
}

#[derive(Clone)]
pub struct PostgresInvocationStore {
    pool: PgPool,
}

impl PostgresInvocationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn tenant_transaction<'a>(
        &'a self,
        tenant: &TenantId,
    ) -> Result<(Uuid, Transaction<'a, Postgres>), ProductionProxyError> {
        let tenant_uuid = parse_uuid(&tenant.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        Ok((tenant_uuid, transaction))
    }

    pub async fn prepare(
        &self,
        request: &AuthorizedToolRequest,
    ) -> Result<PrepareOutcome, ProductionProxyError> {
        validate_persistence_identity(request)?;
        let request_digest = canonical_digest(request)?;
        let authorization_digest = canonical_digest(&request.authorization)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_invocation(
            &mut transaction,
            &request.tenant_id,
            &request.idempotency_key,
        )
        .await?;
        let row = sqlx::query(
            "SELECT state,request_digest,authorization_id,authorization_digest,ledger_execution_id,\
             ledger_event_id,ledger_event_digest,fence_digest,safe_result,safe_result_digest,stable_error,credential_consumption_id,\
             credential_consumption_receipt_digest FROM tool_proxy_invocations \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        if let Some(row) = row {
            let matches = row.try_get::<String, _>("request_digest").ok().as_deref()
                == Some(request_digest.as_str())
                && row.try_get::<String, _>("authorization_id").ok().as_deref()
                    == Some(request.authorization.authorization_id.as_str())
                && row
                    .try_get::<String, _>("authorization_digest")
                    .ok()
                    .as_deref()
                    == Some(authorization_digest.as_str())
                && row
                    .try_get::<Uuid, _>("ledger_execution_id")
                    .ok()
                    .map(|id| id.to_string())
                    == Some(request.ledger_execution_id.0.clone())
                && row
                    .try_get::<Uuid, _>("ledger_event_id")
                    .ok()
                    .map(|id| id.to_string())
                    == Some(request.ledger_event_id.clone())
                && row
                    .try_get::<String, _>("ledger_event_digest")
                    .ok()
                    .as_deref()
                    == Some(request.ledger_event_digest.as_str())
                && row.try_get::<String, _>("fence_digest").ok().as_deref()
                    == Some(request.fence_digest.as_str());
            if !matches {
                return Err(ProductionProxyError::IdempotencyConflict);
            }
            let state = InvocationState::parse(
                &row.try_get::<String, _>("state")
                    .map_err(|_| ProductionProxyError::StoreUnavailable)?,
            )?;
            let outcome = match state {
                InvocationState::Prepared => PrepareOutcome::RetryPrepared,
                InvocationState::Executing | InvocationState::Unknown => PrepareOutcome::Unknown,
                InvocationState::Succeeded => {
                    let value: Value = row
                        .try_get("safe_result")
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                    let result: SanitizedToolResult = serde_json::from_value(value)
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                    let stored_result_digest: String = row
                        .try_get("safe_result_digest")
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                    let stored_consumption_id: Uuid = row
                        .try_get("credential_consumption_id")
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                    let stored_receipt_digest: String = row
                        .try_get("credential_consumption_receipt_digest")
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                    validate_replayed_result(
                        &result,
                        &stored_result_digest,
                        stored_consumption_id,
                        &stored_receipt_digest,
                    )?;
                    PrepareOutcome::ReplaySucceeded(result)
                }
                InvocationState::Failed => PrepareOutcome::ReplayFailed({
                    let code: String = row
                        .try_get("stable_error")
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                    validate_error_code(&code)?;
                    code
                }),
            };
            transaction
                .commit()
                .await
                .map_err(|_| ProductionProxyError::StoreUnavailable)?;
            return Ok(outcome);
        }
        sqlx::query(
            "INSERT INTO tool_proxy_invocations \
             (tenant_id,idempotency_key,request_digest,authorization_id,authorization_digest,\
              ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,action_hash,trace_id,tool_id,tool_version,\
              tool_snapshot_hash,registry_revision,credential_claims_digest,target_profile_hash,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'PREPARED')",
        )
        .bind(tenant_uuid)
        .bind(&request.idempotency_key.0)
        .bind(&request_digest)
        .bind(&request.authorization.authorization_id)
        .bind(&authorization_digest)
        .bind(parse_uuid(&request.ledger_execution_id.0)?)
        .bind(parse_uuid(&request.ledger_event_id)?)
        .bind(&request.ledger_event_digest)
        .bind(&request.fence_digest)
        .bind(&request.authorization.action_hash.0)
        .bind(&request.trace_id)
        .bind(&request.tool.tool_id.0)
        .bind(&request.tool.tool_version.0)
        .bind(&request.tool.snapshot_hash)
        .bind(i64::try_from(request.tool.registry_revision)
            .map_err(|_| ProductionProxyError::IdempotencyConflict)?)
        .bind(&request.authorization.workload_credential_claims_digest)
        .bind(sha256(request.target_profile.as_bytes()))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        Ok(PrepareOutcome::New)
    }

    pub async fn mark_executing(
        &self,
        tenant: &TenantId,
        key: &IdempotencyKey,
        execution_owner: &str,
        lease_for: Duration,
    ) -> Result<(), ProductionProxyError> {
        let owner_uuid = parse_uuid(execution_owner)?;
        if lease_for < Duration::from_secs(5) || lease_for > Duration::from_secs(3600) {
            return Err(ProductionProxyError::StoreUnavailable);
        }
        let lease_millis = i64::try_from(lease_for.as_millis())
            .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_invocation(&mut transaction, tenant, key).await?;
        let changed = sqlx::query(
            "UPDATE tool_proxy_invocations SET state='EXECUTING',execution_owner=$3,\
             execution_lease_until=now()+($4::bigint * interval '1 millisecond'),updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED' \
             AND execution_owner IS NULL AND execution_lease_until IS NULL",
        )
        .bind(tenant_uuid)
        .bind(&key.0)
        .bind(owner_uuid)
        .bind(lease_millis)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ProductionProxyError::StoreUnavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(ProductionProxyError::StateConflict);
        }
        let payload = serde_json::json!({
            "schema_version": PROXY_SCHEMA_VERSION,
            "state": "EXECUTING",
            "execution_owner_digest": sha256(execution_owner.as_bytes()),
        });
        record_safe_event(
            &mut transaction,
            tenant_uuid,
            key,
            "TOOL_EXECUTION_STARTED",
            &payload,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)
    }

    pub async fn mark_failed(
        &self,
        tenant: &TenantId,
        key: &IdempotencyKey,
        code: &str,
    ) -> Result<(), ProductionProxyError> {
        validate_error_code(code)?;
        self.transition_terminal(
            tenant,
            key,
            "PREPARED",
            "FAILED",
            None,
            code,
            "TOOL_EXECUTION_REJECTED",
        )
        .await
    }

    pub async fn mark_unknown(
        &self,
        tenant: &TenantId,
        key: &IdempotencyKey,
        execution_owner: &str,
        code: &str,
    ) -> Result<(), ProductionProxyError> {
        validate_error_code(code)?;
        self.transition_terminal(
            tenant,
            key,
            "EXECUTING",
            "UNKNOWN",
            Some(execution_owner),
            code,
            "TOOL_EXECUTION_UNKNOWN",
        )
        .await
    }

    async fn transition_terminal(
        &self,
        tenant: &TenantId,
        key: &IdempotencyKey,
        expected: &str,
        next: &str,
        execution_owner: Option<&str>,
        stable_error: &str,
        event_type: &str,
    ) -> Result<(), ProductionProxyError> {
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_invocation(&mut transaction, tenant, key).await?;
        let changed = if let Some(owner) = execution_owner {
            sqlx::query(
                "UPDATE tool_proxy_invocations SET state=$3,stable_error=$4,\
                 execution_lease_until=NULL,updated_at=now(),completed_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state=$5 AND execution_owner=$6",
            )
            .bind(tenant_uuid)
            .bind(&key.0)
            .bind(next)
            .bind(stable_error)
            .bind(expected)
            .bind(parse_uuid(owner)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE tool_proxy_invocations SET state=$3,stable_error=$4,\
                 updated_at=now(),completed_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state=$5 \
                 AND execution_owner IS NULL AND execution_lease_until IS NULL",
            )
            .bind(tenant_uuid)
            .bind(&key.0)
            .bind(next)
            .bind(stable_error)
            .bind(expected)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)?
            .rows_affected()
        };
        if changed != 1 {
            return Err(ProductionProxyError::StateConflict);
        }
        let payload = serde_json::json!({
            "schema_version": PROXY_SCHEMA_VERSION,
            "state": next,
            "error": stable_error,
        });
        record_safe_event(&mut transaction, tenant_uuid, key, event_type, &payload).await?;
        transaction
            .commit()
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)
    }

    pub async fn succeed(
        &self,
        tenant: &TenantId,
        key: &IdempotencyKey,
        execution_owner: &str,
        result: &SanitizedToolResult,
        audit: &ProxyAuditEvent,
    ) -> Result<(), ProductionProxyError> {
        let result_value =
            serde_json::to_value(result).map_err(|_| ProductionProxyError::StoreUnavailable)?;
        let audit_value =
            serde_json::to_value(audit).map_err(|_| ProductionProxyError::StoreUnavailable)?;
        let result_digest = canonical_digest(result)?;
        let receipt_digest = canonical_digest(&result.credential_consumption_receipt)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_invocation(&mut transaction, tenant, key).await?;
        let changed = sqlx::query(
            "UPDATE tool_proxy_invocations SET state='SUCCEEDED',safe_result=$3,\
             safe_result_digest=$4,credential_consumption_id=$5,\
             credential_consumption_receipt_digest=$6,execution_lease_until=NULL,\
             updated_at=now(),completed_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING' \
             AND execution_owner=$7",
        )
        .bind(tenant_uuid)
        .bind(&key.0)
        .bind(&result_value)
        .bind(&result_digest)
        .bind(parse_uuid(
            &result.credential_consumption_receipt.consumption_id,
        )?)
        .bind(&receipt_digest)
        .bind(parse_uuid(execution_owner)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ProductionProxyError::StoreUnavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(ProductionProxyError::StateConflict);
        }
        let details = serde_json::json!({
            "schema_version": PROXY_SCHEMA_VERSION,
            "state": "SUCCEEDED",
            "safe_result_digest": result_digest,
            "audit": audit_value,
        });
        record_safe_event(
            &mut transaction,
            tenant_uuid,
            key,
            "TOOL_EXECUTION_SUCCEEDED",
            &details,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)
    }

    pub async fn recover_expired_executing(
        &self,
        tenants: &BTreeSet<TenantId>,
    ) -> Result<u64, ProductionProxyError> {
        let mut recovered = 0_u64;
        for tenant in tenants {
            let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
            let rows = sqlx::query(
                "SELECT idempotency_key,execution_owner FROM tool_proxy_invocations \
                 WHERE tenant_id=$1 AND state='EXECUTING' AND execution_lease_until<=now() \
                 ORDER BY execution_lease_until LIMIT 100 FOR UPDATE SKIP LOCKED",
            )
            .bind(tenant_uuid)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| ProductionProxyError::StoreUnavailable)?;
            for row in rows {
                let key = IdempotencyKey(
                    row.try_get("idempotency_key")
                        .map_err(|_| ProductionProxyError::StoreUnavailable)?,
                );
                let owner: Uuid = row
                    .try_get("execution_owner")
                    .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                let changed = sqlx::query(
                    "UPDATE tool_proxy_invocations SET state='UNKNOWN',\
                     stable_error='PROXY_CRASH_RECOVERY_UNKNOWN',execution_lease_until=NULL,\
                     updated_at=now(),completed_at=now() \
                     WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING' \
                     AND execution_owner=$3 AND execution_lease_until<=now()",
                )
                .bind(tenant_uuid)
                .bind(&key.0)
                .bind(owner)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ProductionProxyError::StoreUnavailable)?
                .rows_affected();
                if changed == 1 {
                    let payload = serde_json::json!({
                        "schema_version": PROXY_SCHEMA_VERSION,
                        "state": "UNKNOWN",
                        "error": "PROXY_CRASH_RECOVERY_UNKNOWN",
                    });
                    record_safe_event(
                        &mut transaction,
                        tenant_uuid,
                        &key,
                        "TOOL_EXECUTION_UNKNOWN",
                        &payload,
                    )
                    .await?;
                    recovered = recovered.saturating_add(1);
                }
            }
            transaction
                .commit()
                .await
                .map_err(|_| ProductionProxyError::StoreUnavailable)?;
        }
        Ok(recovered)
    }

    pub async fn ready(&self, tenants: &BTreeSet<TenantId>) -> bool {
        if tenants.is_empty() {
            return false;
        }
        let check = async {
            for tenant in tenants {
                let (_, mut transaction) = self.tenant_transaction(tenant).await?;
                let posture: bool = sqlx::query_scalar(
                    "SELECT to_regclass('public.tool_proxy_invocations') IS NOT NULL \
                     AND to_regclass('public.tool_proxy_audit_events') IS NOT NULL \
                     AND to_regclass('public.tool_proxy_outbox') IS NOT NULL \
                     AND current_setting('row_security')='on' \
                     AND current_setting('app.tenant_id',true)=$1 \
                     AND (SELECT count(*)=3 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                          WHERE n.nspname='public' AND c.relname IN \
                          ('tool_proxy_invocations','tool_proxy_audit_events','tool_proxy_outbox') \
                          AND c.relrowsecurity AND c.relforcerowsecurity) \
                     AND EXISTS (SELECT 1 FROM information_schema.columns \
                          WHERE table_schema='public' AND table_name='tool_proxy_invocations' \
                          AND column_name='execution_owner') \
                     AND EXISTS (SELECT 1 FROM information_schema.columns \
                          WHERE table_schema='public' AND table_name='tool_proxy_invocations' \
                          AND column_name='execution_lease_until')",
                )
                .bind(&tenant.0)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ProductionProxyError::StoreUnavailable)?;
                if !posture {
                    return Ok::<bool, ProductionProxyError>(false);
                }
                transaction
                    .commit()
                    .await
                    .map_err(|_| ProductionProxyError::StoreUnavailable)?;
            }
            Ok(true)
        };
        tokio::time::timeout(Duration::from_secs(5), check)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }
}

fn validate_error_code(code: &str) -> Result<(), ProductionProxyError> {
    if code.is_empty()
        || code.len() > 128
        || !code.bytes().all(|byte| byte.is_ascii_graphic())
        || !code.starts_with("PROXY_")
    {
        return Err(ProductionProxyError::StoreUnavailable);
    }
    Ok(())
}

fn validate_replayed_result(
    result: &SanitizedToolResult,
    stored_result_digest: &str,
    stored_consumption_id: Uuid,
    stored_receipt_digest: &str,
) -> Result<(), ProductionProxyError> {
    if result.schema_version != PROXY_SCHEMA_VERSION
        || !lower_digest(stored_result_digest)
        || !lower_digest(stored_receipt_digest)
        || !lower_digest(&result.result_hash)
        || result.result_hash
            != sha256(
                serde_jcs::to_vec(&result.value)
                    .map_err(|_| ProductionProxyError::StoreUnavailable)?,
            )
        || canonical_digest(result)? != stored_result_digest
        || result.credential_consumption_receipt.consumption_id != stored_consumption_id.to_string()
        || canonical_digest(&result.credential_consumption_receipt)? != stored_receipt_digest
        || result.redacted_paths.len() > MAX_PROXY_REDACTIONS
        || result.redacted_paths.iter().any(|path| {
            path.is_empty()
                || path.len() > 2_048
                || !path.starts_with('$')
                || path.chars().any(char::is_control)
        })
        || serde_jcs::to_vec(result)
            .map_err(|_| ProductionProxyError::StoreUnavailable)?
            .len()
            > MAX_PROXY_RESPONSE_BYTES as usize
    {
        return Err(ProductionProxyError::StoreUnavailable);
    }
    if let Some(reference) = result.artifact_ref.as_deref() {
        validate_artifact_ref(reference).map_err(|_| ProductionProxyError::StoreUnavailable)?;
    }
    Ok(())
}

async fn record_safe_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    key: &IdempotencyKey,
    event_type: &str,
    details: &Value,
) -> Result<(), ProductionProxyError> {
    if !matches!(
        event_type,
        "TOOL_EXECUTION_STARTED"
            | "TOOL_EXECUTION_REJECTED"
            | "TOOL_EXECUTION_SUCCEEDED"
            | "TOOL_EXECUTION_UNKNOWN"
    ) {
        return Err(ProductionProxyError::StoreUnavailable);
    }
    let row = sqlx::query(
        "SELECT authorization_id,ledger_execution_id,fence_digest,action_hash,trace_id,\
         tool_id,tool_version,tool_snapshot_hash,registry_revision,credential_claims_digest,\
         target_profile_hash,state,execution_owner,safe_result_digest,stable_error,\
         credential_consumption_id,credential_consumption_receipt_digest \
         FROM tool_proxy_invocations WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(tenant_uuid)
    .bind(&key.0)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    let execution_owner: Option<Uuid> = row
        .try_get("execution_owner")
        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    let credential_consumption_id: Option<Uuid> = row
        .try_get("credential_consumption_id")
        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    let payload = serde_json::json!({
        "schema_version": PROXY_SCHEMA_VERSION,
        "event_type": event_type,
        "tenant_id": tenant_uuid.to_string(),
        "idempotency_key": &key.0,
        "authorization_id": row.try_get::<String, _>("authorization_id")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "ledger_execution_id": row.try_get::<Uuid, _>("ledger_execution_id")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?.to_string(),
        "fence_digest": row.try_get::<String, _>("fence_digest")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "action_hash": row.try_get::<String, _>("action_hash")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "trace_id": row.try_get::<String, _>("trace_id")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "tool_id": row.try_get::<String, _>("tool_id")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "tool_version": row.try_get::<String, _>("tool_version")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "tool_snapshot_hash": row.try_get::<String, _>("tool_snapshot_hash")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "registry_revision": row.try_get::<i64, _>("registry_revision")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "credential_claims_digest": row.try_get::<String, _>("credential_claims_digest")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "target_profile_hash": row.try_get::<String, _>("target_profile_hash")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "state": row.try_get::<String, _>("state")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "execution_owner": execution_owner.map(|owner| owner.to_string()),
        "safe_result_digest": row.try_get::<Option<String>, _>("safe_result_digest")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "stable_error": row.try_get::<Option<String>, _>("stable_error")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "credential_consumption_id": credential_consumption_id.map(|id| id.to_string()),
        "credential_consumption_receipt_digest": row
            .try_get::<Option<String>, _>("credential_consumption_receipt_digest")
            .map_err(|_| ProductionProxyError::StoreUnavailable)?,
        "details": details,
    });
    let payload_digest = canonical_digest(&payload)?;
    let event_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tool_proxy_audit_events \
         (event_id,tenant_id,idempotency_key,event_type,event_digest,payload) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(event_id)
    .bind(tenant_uuid)
    .bind(&key.0)
    .bind(event_type)
    .bind(&payload_digest)
    .bind(&payload)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    sqlx::query(
        "INSERT INTO tool_proxy_outbox \
         (outbox_id,tenant_id,idempotency_key,event_id,event_type,payload_digest,payload) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_uuid)
    .bind(&key.0)
    .bind(event_id)
    .bind(event_type)
    .bind(&payload_digest)
    .bind(&payload)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    Ok(())
}

#[derive(Debug)]
pub enum ProductionExecutionOutcome {
    Succeeded(SanitizedToolResult),
    Failed(String),
    Unknown,
}

pub struct ProductionToolProxyService<R: ToolRegistry> {
    proxy: Arc<ToolProxy<R>>,
    store: PostgresInvocationStore,
    execution_owner: String,
}

impl<R: ToolRegistry> ProductionToolProxyService<R> {
    pub fn new(
        proxy: Arc<ToolProxy<R>>,
        store: PostgresInvocationStore,
        execution_owner: String,
    ) -> Result<Self, ProductionProxyError> {
        parse_uuid(&execution_owner)?;
        Ok(Self {
            proxy,
            store,
            execution_owner,
        })
    }

    pub fn store(&self) -> &PostgresInvocationStore {
        &self.store
    }

    pub async fn execute(
        &self,
        request: AuthorizedToolRequest,
    ) -> Result<ProductionExecutionOutcome, ProductionProxyError> {
        match self.store.prepare(&request).await? {
            PrepareOutcome::ReplaySucceeded(result) => {
                return Ok(ProductionExecutionOutcome::Succeeded(result));
            }
            PrepareOutcome::ReplayFailed(code) => {
                return Ok(ProductionExecutionOutcome::Failed(code));
            }
            PrepareOutcome::Unknown => return Ok(ProductionExecutionOutcome::Unknown),
            PrepareOutcome::New | PrepareOutcome::RetryPrepared => {}
        }
        let prepared = match self.proxy.preflight(request.clone()).await {
            Ok(prepared) => prepared,
            Err(error) if deterministic_pre_side_effect(&error) => {
                let code = error.to_string();
                self.store
                    .mark_failed(&request.tenant_id, &request.idempotency_key, &code)
                    .await?;
                return Ok(ProductionExecutionOutcome::Failed(code));
            }
            Err(error) => return Err(ProductionProxyError::Dependency(error.to_string())),
        };
        self.store
            .mark_executing(
                &request.tenant_id,
                &request.idempotency_key,
                &self.execution_owner,
                prepared.timeout.saturating_add(Duration::from_secs(30)),
            )
            .await?;
        match self.proxy.run_prepared(prepared).await {
            Ok((result, audit)) => {
                self.store
                    .succeed(
                        &request.tenant_id,
                        &request.idempotency_key,
                        &self.execution_owner,
                        &result,
                        &audit,
                    )
                    .await?;
                Ok(ProductionExecutionOutcome::Succeeded(result))
            }
            Err(error) => {
                self.store
                    .mark_unknown(
                        &request.tenant_id,
                        &request.idempotency_key,
                        &self.execution_owner,
                        &error.to_string(),
                    )
                    .await?;
                Ok(ProductionExecutionOutcome::Unknown)
            }
        }
    }
}

fn deterministic_pre_side_effect(error: &ProxyError) -> bool {
    matches!(
        error,
        ProxyError::AuthorizationInvalid
            | ProxyError::AuthorizationReplayed
            | ProxyError::RegistryRevoked
            | ProxyError::ArgumentInvalid
            | ProxyError::CredentialScopeDenied
            | ProxyError::CredentialReceiptInvalid
            | ProxyError::ConnectorInvalid
            | ProxyError::TargetDenied
            | ProxyError::SsrfDenied
            | ProxyError::PathTraversal
    )
}

#[derive(Debug, Clone)]
pub struct RegistryVerificationKey {
    pub publisher_id: String,
    pub key_id: String,
    pub key: VerifyingKey,
}

#[derive(Clone)]
pub struct RegistrySnapshotKeyring {
    keys: Arc<BTreeMap<String, (String, VerifyingKey)>>,
}

impl RegistrySnapshotKeyring {
    pub fn new(entries: Vec<RegistryVerificationKey>) -> Result<Self, ProductionProxyError> {
        if entries.is_empty() || entries.len() > 128 {
            return Err(ProductionProxyError::RegistryTrustInvalid);
        }
        let mut keys = BTreeMap::new();
        for entry in entries {
            if !valid_identifier(&entry.publisher_id, 128)
                || !valid_identifier(&entry.key_id, 128)
                || keys
                    .insert(entry.key_id, (entry.publisher_id, entry.key))
                    .is_some()
            {
                return Err(ProductionProxyError::RegistryTrustInvalid);
            }
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    fn verify(&self, digest: &str, signature: &ManifestSignature) -> Result<(), RegistryError> {
        if !lower_digest(digest)
            || signature.algorithm != "Ed25519"
            || signature.signature.contains('=')
        {
            return Err(RegistryError::SignatureInvalid);
        }
        let (publisher, key) = self
            .keys
            .get(&signature.key_id)
            .ok_or(RegistryError::SignatureInvalid)?;
        if publisher != &signature.publisher_id {
            return Err(RegistryError::SignatureInvalid);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&signature.signature)
            .map_err(|_| RegistryError::SignatureInvalid)?;
        let signature = Signature::from_slice(&raw).map_err(|_| RegistryError::SignatureInvalid)?;
        key.verify(digest.as_bytes(), &signature)
            .map_err(|_| RegistryError::SignatureInvalid)
    }
}

pub struct SensitiveRegistryToken(String);

impl SensitiveRegistryToken {
    pub fn new(value: String) -> Result<Self, ProductionProxyError> {
        if value.is_empty()
            || value.len() > 8_192
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            Err(ProductionProxyError::RegistryTrustInvalid)
        } else {
            Ok(Self(value))
        }
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveRegistryToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveRegistryToken([REDACTED])")
    }
}

impl Drop for SensitiveRegistryToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct HttpsRegistryClient {
    endpoint: Url,
    client: reqwest::Client,
    token: SensitiveRegistryToken,
    keyring: RegistrySnapshotKeyring,
    verified: RwLock<BTreeMap<TenantId, VerifiedRegistryState>>,
}

#[derive(Clone)]
struct VerifiedRegistryState {
    response: AuthoritativeToolsResponse,
    tools: Vec<ResolvedToolSnapshot>,
}

impl HttpsRegistryClient {
    pub fn new(
        endpoint: Url,
        client: reqwest::Client,
        token: SensitiveRegistryToken,
        keyring: RegistrySnapshotKeyring,
    ) -> Result<Self, ProductionProxyError> {
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ProductionProxyError::RegistryTrustInvalid);
        }
        Ok(Self {
            endpoint,
            client,
            token,
            keyring,
            verified: RwLock::new(BTreeMap::new()),
        })
    }

    fn url(&self, segments: &[&str]) -> Result<Url, RegistryError> {
        let mut url = self.endpoint.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| RegistryError::UnavailableFailClosed)?;
            path.clear();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        tenant: &TenantId,
        url: Url,
    ) -> Result<T, RegistryError> {
        let mut response = self
            .client
            .get(url)
            .bearer_auth(self.token.expose())
            .header("Accept", "application/json")
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| RegistryError::UnavailableFailClosed)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 1_048_576)
        {
            return Err(RegistryError::UnavailableFailClosed);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        if !content_type {
            return Err(RegistryError::UnavailableFailClosed);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RegistryError::UnavailableFailClosed)?
        {
            if bytes.len().saturating_add(chunk.len()) > 1_048_576 {
                return Err(RegistryError::UnavailableFailClosed);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| RegistryError::SchemaInvalid)
    }

    async fn authoritative(
        &self,
        tenant: &TenantId,
    ) -> Result<VerifiedRegistryState, RegistryError> {
        let response: AuthoritativeToolsResponse = self
            .get_json(tenant, self.url(&["v1", "authoritative", "tools"])?)
            .await?;
        if response.schema_version != AUTHORITATIVE_TOOLS_SCHEMA_VERSION
            || !response.authoritative
            || response.tenant_id != *tenant
            || !response.complete
            || response.registry_revision == 0
            || response.tools.len() > 1_000
            || response.signed_at > Utc::now() + chrono::Duration::seconds(30)
        {
            return Err(RegistryError::SignatureInvalid);
        }
        self.keyring.verify(&response.digest, &response.signature)?;
        let ordered = response.tools.windows(2).all(|pair| {
            (&pair[0].tool_id, &pair[0].tool_version) < (&pair[1].tool_id, &pair[1].tool_version)
        });
        if !ordered
            || response.tools.iter().any(|tool| {
                !lower_digest(&tool.manifest_hash)
                    || !tool.implementation_digest.starts_with("sha256:")
                    || !lower_digest(tool.implementation_digest.trim_start_matches("sha256:"))
            })
        {
            return Err(RegistryError::SignatureInvalid);
        }
        if let Some(cached) = self.verified.read().get(tenant).cloned() {
            if response.registry_revision < cached.response.registry_revision
                || response.signed_at < cached.response.signed_at
                || response.registry_revision == cached.response.registry_revision
                    && response.digest != cached.response.digest
            {
                return Err(RegistryError::SignatureInvalid);
            }
            if response.registry_revision == cached.response.registry_revision
                && response.digest == cached.response.digest
                && response.signed_at == cached.response.signed_at
            {
                return Ok(cached);
            }
        }

        let mut tools = Vec::with_capacity(response.tools.len());
        let mut total_bytes = 0_usize;
        for summary in &response.tools {
            let snapshot: ResolvedToolSnapshot = self
                .get_json(
                    tenant,
                    self.url(&[
                        "v1",
                        "tools",
                        &summary.tool_id.0,
                        "versions",
                        &summary.tool_version.0,
                    ])?,
                )
                .await?;
            total_bytes = total_bytes.saturating_add(
                serde_jcs::to_vec(&snapshot)
                    .map_err(|_| RegistryError::SchemaInvalid)?
                    .len(),
            );
            if total_bytes > MAX_VERIFIED_REGISTRY_BYTES {
                return Err(RegistryError::UnavailableFailClosed);
            }
            validate_authoritative_snapshot(&response, summary, &snapshot)?;
            tools.push(snapshot);
        }
        let aggregate = RegistrySnapshot {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            revision: response.registry_revision,
            tools: tools.clone(),
            snapshot_hash: response.digest.clone(),
            signed_at: response.signed_at,
            signature: Some(response.signature.clone()),
        };
        if canonical_registry_snapshot_hash(&aggregate)? != response.digest {
            return Err(RegistryError::SignatureInvalid);
        }
        let state = VerifiedRegistryState { response, tools };
        let mut cache = self.verified.write();
        if !cache.contains_key(tenant) && cache.len() >= MAX_CACHED_REGISTRY_TENANTS {
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(tenant.clone(), state.clone());
        Ok(state)
    }

    pub async fn ready(&self, tenants: &BTreeSet<TenantId>) -> bool {
        if tenants.is_empty() {
            return false;
        }
        let check = async {
            for tenant in tenants {
                self.authoritative(tenant).await?;
            }
            Ok::<(), RegistryError>(())
        };
        tokio::time::timeout(Duration::from_secs(10), check)
            .await
            .ok()
            .is_some_and(Result::is_ok)
    }
}

fn validate_authoritative_snapshot(
    response: &AuthoritativeToolsResponse,
    summary: &AuthoritativeToolSummary,
    snapshot: &ResolvedToolSnapshot,
) -> Result<(), RegistryError> {
    let mut material = snapshot.clone();
    material.snapshot_hash.clear();
    material.resolved_at = DateTime::UNIX_EPOCH;
    let expected_hash =
        sha256(&serde_jcs::to_vec(&material).map_err(|_| RegistryError::SchemaInvalid)?);
    if snapshot.schema_version != REGISTRY_SCHEMA_VERSION
        || snapshot.tool_id != summary.tool_id
        || snapshot.tool_version != summary.tool_version
        || snapshot.snapshot_hash != expected_hash
        || snapshot.resolved_at != response.signed_at
        || snapshot.manifest_hash != summary.manifest_hash
        || snapshot.implementation.digest != summary.implementation_digest
        || snapshot.effect_class != summary.effect_class
        || snapshot.risk_level != summary.risk_level
    {
        return Err(RegistryError::SignatureInvalid);
    }
    Ok(())
}

#[async_trait]
impl ToolRegistry for HttpsRegistryClient {
    async fn resolve_exact(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, RegistryError> {
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let authoritative = self.authoritative(tenant).await?;
        authoritative
            .response
            .tools
            .iter()
            .find(|candidate| {
                candidate.tool_id == tool.tool_id && candidate.tool_version == tool.tool_version
            })
            .ok_or(RegistryError::VersionNotActive)?;
        authoritative
            .tools
            .into_iter()
            .find(|candidate| {
                candidate.tool_id == tool.tool_id && candidate.tool_version == tool.tool_version
            })
            .ok_or(RegistryError::SignatureInvalid)
    }

    async fn validate_arguments(
        &self,
        snapshot: &ResolvedToolSnapshot,
        args: &StrictJsonObject,
    ) -> Result<(), RegistryError> {
        validate_schema_instance(&snapshot.input_schema, &Value::Object(args.clone()), false)
    }

    async fn validate_output(
        &self,
        snapshot: &ResolvedToolSnapshot,
        output: &Value,
    ) -> Result<(), RegistryError> {
        validate_schema_instance(&snapshot.output_schema, output, true)
    }

    async fn discover_capabilities(
        &self,
        _query: CapabilityQuery,
    ) -> Result<Vec<CapabilityDescriptor>, RegistryError> {
        Err(RegistryError::UnavailableFailClosed)
    }

    async fn snapshot(
        &self,
        _tenant: &TenantId,
        _refs: &[ToolRef],
    ) -> Result<RegistrySnapshot, RegistryError> {
        Err(RegistryError::UnavailableFailClosed)
    }

    async fn is_revoked(&self, _tool: &ToolRef, _digest: &str) -> Result<bool, RegistryError> {
        // `resolve_exact` immediately fetched and verified the current complete
        // signed ACTIVE set. A second unscoped trait call cannot strengthen that
        // tenant-bound proof and would introduce a tenant-confusion risk.
        Ok(false)
    }
}

/// Intentionally unusable as a persistence sink. The production service calls
/// `run_prepared` and writes result, audit and outbox in one database transaction.
pub struct DeferredProductionAuditSink;

#[async_trait]
impl ProxyAuditSink for DeferredProductionAuditSink {
    async fn record(&self, _event: ProxyAuditEvent) -> Result<(), ProxyError> {
        Err(ProxyError::AuditFailed)
    }
}

#[derive(Debug, Error)]
pub enum ProductionProxyError {
    #[error("PROXY_STORE_UNAVAILABLE")]
    StoreUnavailable,
    #[error("PROXY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("PROXY_INVOCATION_STATE_CONFLICT")]
    StateConflict,
    #[error("PROXY_REGISTRY_TRUST_INVALID")]
    RegistryTrustInvalid,
    #[error("PROXY_DEPENDENCY_UNAVAILABLE")]
    Dependency(String),
}

fn validate_persistence_identity(
    request: &AuthorizedToolRequest,
) -> Result<(), ProductionProxyError> {
    parse_uuid(&request.tenant_id.0)?;
    parse_uuid(&request.ledger_execution_id.0)?;
    parse_uuid(&request.ledger_event_id)?;
    parse_uuid(&request.authorization.authorization_id)?;
    if request.idempotency_key.0.is_empty()
        || request.idempotency_key.0.len() > 128
        || !request
            .idempotency_key
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        || !lower_digest(&request.fence_digest)
        || !lower_digest(&request.ledger_event_digest)
        || !lower_digest(&request.authorization.action_hash.0)
        || !lower_digest(&request.tool.snapshot_hash)
        || !lower_digest(&request.authorization.workload_credential_claims_digest)
        || request.tool.registry_revision == 0
        || request.tool.registry_revision > i64::MAX as u64
        || request.trace_id.is_empty()
        || request.trace_id.len() > 128
        || !request
            .trace_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        || request.tool.tool_id.0.is_empty()
        || request.tool.tool_id.0.len() > 256
        || request.tool.tool_version.0.is_empty()
        || request.tool.tool_version.0.len() > 256
    {
        return Err(ProductionProxyError::IdempotencyConflict);
    }
    Ok(())
}

async fn lock_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    key: &IdempotencyKey,
) -> Result<(), ProductionProxyError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("tool-proxy:{}:{}", tenant.0, key.0))
        .execute(&mut **transaction)
        .await
        .map_err(|_| ProductionProxyError::StoreUnavailable)?;
    Ok(())
}

fn canonical_digest(value: &impl Serialize) -> Result<String, ProductionProxyError> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| ProductionProxyError::StoreUnavailable)
}

fn parse_uuid(value: &str) -> Result<Uuid, ProductionProxyError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(ProductionProxyError::StoreUnavailable)
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    hex_string(Sha256::digest(value.as_ref()))
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_tokens_are_redacted_and_endpoints_are_strict_https_roots() {
        let token = SensitiveRegistryToken::new("opaque-service-token".into())
            .unwrap_or_else(|error| panic!("token: {error}"));
        assert!(!format!("{token:?}").contains("opaque-service-token"));
        let keyring = RegistrySnapshotKeyring::new(vec![RegistryVerificationKey {
            publisher_id: "registry".into(),
            key_id: "key-1".into(),
            key: SigningKey::from_bytes(&[9_u8; 32]).verifying_key(),
        }])
        .unwrap_or_else(|error| panic!("keyring: {error}"));
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|error| panic!("client: {error}"));
        assert!(
            HttpsRegistryClient::new(
                Url::parse("http://registry.invalid/")
                    .unwrap_or_else(|error| panic!("url: {error}")),
                client.clone(),
                SensitiveRegistryToken::new("opaque".into())
                    .unwrap_or_else(|error| panic!("token: {error}")),
                keyring.clone(),
            )
            .is_err()
        );
        assert!(
            HttpsRegistryClient::new(
                Url::parse("https://registry.invalid/base")
                    .unwrap_or_else(|error| panic!("url: {error}")),
                client,
                SensitiveRegistryToken::new("opaque".into())
                    .unwrap_or_else(|error| panic!("token: {error}")),
                keyring,
            )
            .is_err()
        );
    }

    #[test]
    fn possible_side_effect_errors_are_not_classified_failed() {
        assert!(deterministic_pre_side_effect(&ProxyError::ArgumentInvalid));
        assert!(!deterministic_pre_side_effect(&ProxyError::Timeout));
        assert!(!deterministic_pre_side_effect(&ProxyError::ConnectorFailed));
        assert!(validate_error_code("PROXY_TIMEOUT").is_ok());
        assert!(validate_error_code("target said secret=opaque").is_err());
    }
}
