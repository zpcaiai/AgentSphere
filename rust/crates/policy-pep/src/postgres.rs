//! Tenant-isolated, crash-safe idempotent persistence for production PEP decisions.

use crate::authority::PepAuthorityError;
use agent_trust_contracts::{
    ExecutionAuthorization, PdpPolicyActivationAcknowledgement, PepPolicyActivationAcknowledgement,
    PolicyActivationRequest, PolicyDecision, PolicyEnvironment, TenantId,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

const CLAIM_LEASE_SECONDS: i32 = 15;

#[derive(Clone)]
pub struct PostgresPepStore {
    pool: PgPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePolicyBundle {
    pub activation_id: String,
    pub policy_id: String,
    pub environment: PolicyEnvironment,
    pub sequence: u64,
    pub bundle_digest: String,
    pub policy_version: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PolicyActivationClaimOwner(Uuid);

pub enum PolicyActivationClaimResult {
    Acquired(PolicyActivationClaimOwner),
    Replay(Box<PepPolicyActivationAcknowledgement>),
}

#[derive(Clone, PartialEq, Eq)]
pub struct PepClaimOwner(Uuid);

pub enum PepClaimResult<T, C> {
    Acquired { owner: PepClaimOwner, context: C },
    Replay(T),
}

pub struct GovernanceEvidenceRecord<'a> {
    pub evidence_id: &'a str,
    pub assertion_jti: &'a str,
    pub evidence_digest: &'a str,
    pub evidence_ref: &'a str,
    pub evidence_body: Value,
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingClaimState {
    Replay,
    Denied,
    InProgress,
    Recoverable,
}

impl PostgresPepStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT current_setting('row_security') = 'on' \
                 AND to_regclass('public.pep_authorization_requests') IS NOT NULL \
                 AND to_regclass('public.pep_policy_decisions') IS NOT NULL \
                 AND to_regclass('public.pep_execution_authorizations') IS NOT NULL \
                 AND to_regclass('public.pep_human_assertion_uses') IS NOT NULL \
                 AND to_regclass('public.pep_governance_evidence') IS NOT NULL \
                 AND to_regclass('public.pep_evidence_outbox') IS NOT NULL \
                 AND to_regclass('public.pep_policy_bundle_artifacts') IS NOT NULL \
                 AND to_regclass('public.pep_policy_activation_requests') IS NOT NULL \
                 AND to_regclass('public.pep_active_policy_bundles') IS NOT NULL \
                 AND to_regclass('public.pep_policy_activation_evidence') IS NOT NULL \
                 AND to_regclass('public.pep_policy_activation_outbox') IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false)
    }

    pub async fn active_policy_bundle(
        &self,
        tenant: &TenantId,
        environment: PolicyEnvironment,
    ) -> Result<ActivePolicyBundle, PepAuthorityError> {
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT activation_id::text,policy_id,environment,sequence,bundle_digest,policy_version \
             FROM pep_active_policy_bundles WHERE tenant_id=$1::uuid AND environment=$2 FOR SHARE",
        )
        .bind(&tenant.0)
        .bind(environment.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(PepAuthorityError::AuthorizationDenied)?;
        let record = ActivePolicyBundle {
            activation_id: row.try_get("activation_id").map_err(database)?,
            policy_id: row.try_get("policy_id").map_err(database)?,
            environment,
            sequence: u64::try_from(row.try_get::<i64, _>("sequence").map_err(database)?)
                .map_err(|_| PepAuthorityError::PersistenceUnavailable)?,
            bundle_digest: row.try_get("bundle_digest").map_err(database)?,
            policy_version: row.try_get("policy_version").map_err(database)?,
        };
        transaction.commit().await.map_err(database)?;
        Ok(record)
    }

    pub async fn begin_policy_activation(
        &self,
        request: &PolicyActivationRequest,
    ) -> Result<PolicyActivationClaimResult, PepAuthorityError> {
        request
            .validate()
            .map_err(|_| PepAuthorityError::RequestInvalid)?;
        let request_digest = canonical_digest(request)?;
        let bundle_body =
            serde_json::to_value(&request.bundle).map_err(|_| PepAuthorityError::RequestInvalid)?;
        let mut transaction = self.begin_tenant(&request.tenant_id).await?;
        advisory_lock(
            &mut transaction,
            &request.tenant_id,
            "POLICY_ACTIVATION",
            &request.idempotency_key,
        )
        .await?;
        let existing = sqlx::query(
            "SELECT activation_id::text,request_digest,state,response_body,response_digest,\
                    claim_expires_at > clock_timestamp() AS lease_live \
             FROM pep_policy_activation_requests \
             WHERE tenant_id=$1::uuid AND environment=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .bind(&request.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        if let Some(row) = existing {
            if row
                .try_get::<String, _>("activation_id")
                .map_err(database)?
                != request.activation_id
                || row
                    .try_get::<String, _>("request_digest")
                    .map_err(database)?
                    != request_digest
            {
                return Err(PepAuthorityError::IdempotencyConflict);
            }
            match row
                .try_get::<String, _>("state")
                .map_err(database)?
                .as_str()
            {
                "ACTIVE" => {
                    let acknowledgement: PepPolicyActivationAcknowledgement =
                        serde_json::from_value(
                            row.try_get::<Option<Value>, _>("response_body")
                                .map_err(database)?
                                .ok_or(PepAuthorityError::PersistenceUnavailable)?,
                        )
                        .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                    if canonical_digest(&acknowledgement)?
                        != row
                            .try_get::<Option<String>, _>("response_digest")
                            .map_err(database)?
                            .ok_or(PepAuthorityError::PersistenceUnavailable)?
                    {
                        return Err(PepAuthorityError::PersistenceUnavailable);
                    }
                    transaction.commit().await.map_err(database)?;
                    return Ok(PolicyActivationClaimResult::Replay(Box::new(acknowledgement)));
                }
                "PENDING" if row.try_get::<bool, _>("lease_live").map_err(database)? => {
                    return Err(PepAuthorityError::IdempotencyInProgress);
                }
                "PENDING" | "UNKNOWN" => {
                    let owner = PolicyActivationClaimOwner(Uuid::new_v4());
                    let updated = sqlx::query(
                        "UPDATE pep_policy_activation_requests SET state='PENDING',claim_owner=$4,\
                         claim_expires_at=clock_timestamp()+make_interval(secs=>$5::integer),updated_at=clock_timestamp() \
                         WHERE tenant_id=$1::uuid AND environment=$2 AND idempotency_key=$3 \
                           AND (state='UNKNOWN' OR claim_expires_at<=clock_timestamp())",
                    )
                    .bind(&request.tenant_id.0)
                    .bind(request.environment.as_str())
                    .bind(&request.idempotency_key)
                    .bind(owner.0)
                    .bind(CLAIM_LEASE_SECONDS)
                    .execute(&mut *transaction)
                    .await
                    .map_err(database)?;
                    if updated.rows_affected() != 1 {
                        return Err(PepAuthorityError::IdempotencyInProgress);
                    }
                    transaction.commit().await.map_err(database)?;
                    return Ok(PolicyActivationClaimResult::Acquired(owner));
                }
                _ => return Err(PepAuthorityError::AuthorizationDenied),
            }
        }

        let active = sqlx::query(
            "SELECT sequence,bundle_digest FROM pep_active_policy_bundles \
             WHERE tenant_id=$1::uuid AND environment=$2 FOR UPDATE",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        match active {
            Some(row) => {
                let active_sequence =
                    u64::try_from(row.try_get::<i64, _>("sequence").map_err(database)?)
                        .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                let active_digest = row
                    .try_get::<String, _>("bundle_digest")
                    .map_err(database)?;
                if active_sequence >= request.sequence
                    || request.previous_bundle_digest.as_deref() != Some(active_digest.as_str())
                {
                    return Err(PepAuthorityError::IdempotencyConflict);
                }
            }
            None if request.previous_bundle_digest.is_none() => {}
            None => return Err(PepAuthorityError::IdempotencyConflict),
        }
        sqlx::query(
            "INSERT INTO pep_policy_bundle_artifacts \
             (tenant_id,bundle_digest,bundle_id,policy_id,source_revision,policy_version,key_id,bundle_body,verified_at) \
             VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,clock_timestamp()) ON CONFLICT DO NOTHING",
        )
        .bind(&request.tenant_id.0)
        .bind(&request.bundle.bundle_digest)
        .bind(&request.bundle.bundle_id)
        .bind(&request.policy_id)
        .bind(i64::try_from(request.bundle.source_revision).map_err(|_| PepAuthorityError::RequestInvalid)?)
        .bind(&request.bundle.version)
        .bind(&request.bundle.key_id)
        .bind(&bundle_body)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let persisted_bundle = sqlx::query_scalar::<_, Value>(
            "SELECT bundle_body FROM pep_policy_bundle_artifacts \
             WHERE tenant_id=$1::uuid AND bundle_digest=$2 FOR SHARE",
        )
        .bind(&request.tenant_id.0)
        .bind(&request.bundle.bundle_digest)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database)?;
        if persisted_bundle != bundle_body {
            return Err(PepAuthorityError::IdempotencyConflict);
        }
        let owner = PolicyActivationClaimOwner(Uuid::new_v4());
        sqlx::query(
            "INSERT INTO pep_policy_activation_requests \
             (tenant_id,environment,idempotency_key,activation_id,request_digest,policy_id,sequence,\
              previous_bundle_digest,bundle_digest,request_body,state,claim_owner,claim_expires_at,created_at,updated_at) \
             VALUES ($1::uuid,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10,'PENDING',$11,\
                     clock_timestamp()+make_interval(secs=>$12::integer),clock_timestamp(),clock_timestamp())",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .bind(&request.idempotency_key)
        .bind(&request.activation_id)
        .bind(&request_digest)
        .bind(&request.policy_id)
        .bind(i64::try_from(request.sequence).map_err(|_| PepAuthorityError::RequestInvalid)?)
        .bind(&request.previous_bundle_digest)
        .bind(&request.bundle.bundle_digest)
        .bind(serde_json::to_value(request).map_err(|_| PepAuthorityError::RequestInvalid)?)
        .bind(owner.0)
        .bind(CLAIM_LEASE_SECONDS)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        Ok(PolicyActivationClaimResult::Acquired(owner))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn complete_policy_activation(
        &self,
        request: &PolicyActivationRequest,
        owner: &PolicyActivationClaimOwner,
        pdp_acknowledgement: &PdpPolicyActivationAcknowledgement,
        acknowledgement: &PepPolicyActivationAcknowledgement,
    ) -> Result<PepPolicyActivationAcknowledgement, PepAuthorityError> {
        let request_digest = canonical_digest(request)?;
        let pdp_ack_body = serde_json::to_value(pdp_acknowledgement)
            .map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let pdp_ack_digest = canonical_digest(pdp_acknowledgement)?;
        let response_body = serde_json::to_value(acknowledgement)
            .map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let response_digest = canonical_digest(acknowledgement)?;
        if acknowledgement.pdp_ack_digest != pdp_ack_digest {
            return Err(PepAuthorityError::ResponseInvalid);
        }
        let mut transaction = self.begin_tenant(&request.tenant_id).await?;
        advisory_lock(
            &mut transaction,
            &request.tenant_id,
            "POLICY_ACTIVATION",
            &request.idempotency_key,
        )
        .await?;
        let claim = sqlx::query(
            "SELECT request_digest,state,claim_owner FROM pep_policy_activation_requests \
             WHERE tenant_id=$1::uuid AND environment=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .bind(&request.idempotency_key)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database)?;
        if claim
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != request_digest
            || claim.try_get::<String, _>("state").map_err(database)? != "PENDING"
            || claim.try_get::<Uuid, _>("claim_owner").map_err(database)? != owner.0
        {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        let active = sqlx::query(
            "SELECT sequence,bundle_digest FROM pep_active_policy_bundles \
             WHERE tenant_id=$1::uuid AND environment=$2 FOR UPDATE",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        match active {
            Some(row) => {
                let active_sequence =
                    u64::try_from(row.try_get::<i64, _>("sequence").map_err(database)?)
                        .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                let active_digest = row
                    .try_get::<String, _>("bundle_digest")
                    .map_err(database)?;
                if active_sequence >= request.sequence
                    || request.previous_bundle_digest.as_deref() != Some(active_digest.as_str())
                {
                    return Err(PepAuthorityError::IdempotencyConflict);
                }
            }
            None if request.previous_bundle_digest.is_none() => {}
            None => return Err(PepAuthorityError::IdempotencyConflict),
        }
        let updated = sqlx::query(
            "UPDATE pep_policy_activation_requests SET state='ACTIVE',pdp_ack_digest=$4,pdp_ack_body=$5,\
             response_digest=$6,response_body=$7,completed_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE tenant_id=$1::uuid AND environment=$2 AND idempotency_key=$3 \
               AND state='PENDING' AND claim_owner=$8",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .bind(&request.idempotency_key)
        .bind(&pdp_ack_digest)
        .bind(&pdp_ack_body)
        .bind(&response_digest)
        .bind(&response_body)
        .bind(owner.0)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        sqlx::query(
            "INSERT INTO pep_active_policy_bundles \
             (tenant_id,environment,activation_id,policy_id,sequence,bundle_digest,policy_version,\
              pdp_ack_digest,activated_at) VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (tenant_id,environment) DO UPDATE SET \
              activation_id=EXCLUDED.activation_id,policy_id=EXCLUDED.policy_id,sequence=EXCLUDED.sequence,\
              bundle_digest=EXCLUDED.bundle_digest,policy_version=EXCLUDED.policy_version,\
              pdp_ack_digest=EXCLUDED.pdp_ack_digest,activated_at=EXCLUDED.activated_at",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .bind(&request.activation_id)
        .bind(&request.policy_id)
        .bind(i64::try_from(request.sequence).map_err(|_| PepAuthorityError::RequestInvalid)?)
        .bind(&request.bundle.bundle_digest)
        .bind(&request.bundle.version)
        .bind(&pdp_ack_digest)
        .bind(pdp_acknowledgement.activated_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let evidence_body = serde_json::json!({
            "schema_version": "agenttrust.pep-policy-activation-evidence.v1",
            "activation_id": request.activation_id,
            "tenant_id": request.tenant_id,
            "policy_id": request.policy_id,
            "environment": request.environment,
            "sequence": request.sequence,
            "bundle_digest": request.bundle.bundle_digest,
            "pdp_ack_digest": pdp_ack_digest,
            "evidence_ref": acknowledgement.evidence_ref,
            "evidence_digest": acknowledgement.evidence_digest,
            "recorded_at": acknowledgement.acknowledged_at,
        });
        sqlx::query(
            "INSERT INTO pep_policy_activation_evidence \
             (tenant_id,activation_id,evidence_ref,evidence_digest,pdp_ack_digest,pdp_ack_body,evidence_body,recorded_at) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)",
        )
        .bind(&request.tenant_id.0)
        .bind(&request.activation_id)
        .bind(&acknowledgement.evidence_ref)
        .bind(&acknowledgement.evidence_digest)
        .bind(&pdp_ack_digest)
        .bind(&pdp_ack_body)
        .bind(&evidence_body)
        .bind(acknowledgement.acknowledged_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let event_id = Uuid::new_v4();
        let mut event_body = serde_json::json!({
            "schema_version": "agenttrust.pep-policy-activation-outbox.v1",
            "event_id": event_id,
            "event_type": "PEP_POLICY_BUNDLE_ACTIVATED",
            "tenant_id": request.tenant_id,
            "activation_id": request.activation_id,
            "evidence_ref": acknowledgement.evidence_ref,
            "evidence_digest": acknowledgement.evidence_digest,
            "occurred_at": acknowledgement.acknowledged_at,
            "event_digest": ""
        });
        let event_digest = canonical_digest(&event_body)?;
        event_body["event_digest"] = Value::String(event_digest.clone());
        sqlx::query(
            "INSERT INTO pep_policy_activation_outbox \
             (tenant_id,event_id,activation_id,event_type,event_digest,event_body,occurred_at) \
             VALUES ($1::uuid,$2,$3::uuid,'PEP_POLICY_BUNDLE_ACTIVATED',$4,$5,$6)",
        )
        .bind(&request.tenant_id.0)
        .bind(event_id)
        .bind(&request.activation_id)
        .bind(&event_digest)
        .bind(&event_body)
        .bind(acknowledgement.acknowledged_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        Ok(acknowledgement.clone())
    }

    pub async fn mark_policy_activation_unknown(
        &self,
        request: &PolicyActivationRequest,
        owner: &PolicyActivationClaimOwner,
    ) -> Result<(), PepAuthorityError> {
        let request_digest = canonical_digest(request)?;
        let mut transaction = self.begin_tenant(&request.tenant_id).await?;
        advisory_lock(
            &mut transaction,
            &request.tenant_id,
            "POLICY_ACTIVATION",
            &request.idempotency_key,
        )
        .await?;
        let updated = sqlx::query(
            "UPDATE pep_policy_activation_requests SET state='UNKNOWN',updated_at=clock_timestamp() \
             WHERE tenant_id=$1::uuid AND environment=$2 AND idempotency_key=$3 AND request_digest=$4 \
               AND state='PENDING' AND claim_owner=$5",
        )
        .bind(&request.tenant_id.0)
        .bind(request.environment.as_str())
        .bind(&request.idempotency_key)
        .bind(&request_digest)
        .bind(owner.0)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        transaction.commit().await.map_err(database)?;
        Ok(())
    }

    /// Replays a terminal result without contacting dependencies. A non-terminal claim is
    /// reported explicitly so callers never race a request that may already have caused an
    /// external side effect.
    pub async fn replay<T: DeserializeOwned + Serialize>(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<Option<T>, PepAuthorityError> {
        validate_claim_key(tenant, stage, idempotency_key, request_digest)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT request_digest,result_status,response_digest,response_body,\
                    claim_expires_at > clock_timestamp() AS lease_live \
             FROM pep_authorization_requests \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 FOR SHARE",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(database)?;
            return Ok(None);
        };
        if row
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != request_digest
        {
            return Err(PepAuthorityError::IdempotencyConflict);
        }
        let status = row
            .try_get::<String, _>("result_status")
            .map_err(database)?;
        let lease_live = row.try_get::<bool, _>("lease_live").map_err(database)?;
        match classify_existing(&status, lease_live)? {
            ExistingClaimState::Replay => {
                let value = row
                    .try_get::<Option<Value>, _>("response_body")
                    .map_err(database)?
                    .ok_or(PepAuthorityError::PersistenceUnavailable)?;
                let response: T = serde_json::from_value(value)
                    .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                if canonical_digest(&response)?
                    != row
                        .try_get::<Option<String>, _>("response_digest")
                        .map_err(database)?
                        .ok_or(PepAuthorityError::PersistenceUnavailable)?
                {
                    return Err(PepAuthorityError::PersistenceUnavailable);
                }
                transaction.commit().await.map_err(database)?;
                Ok(Some(response))
            }
            ExistingClaimState::Denied => Err(PepAuthorityError::AuthorizationDenied),
            ExistingClaimState::InProgress => Err(PepAuthorityError::IdempotencyInProgress),
            ExistingClaimState::Recoverable => {
                transaction.commit().await.map_err(database)?;
                Ok(None)
            }
        }
    }

    /// Durably claims an idempotency key before any outbound side effect. An expired lease may
    /// be recovered only because every side-effecting authority request carries the same stable
    /// idempotency key and must return the exact persisted issuance.
    pub async fn begin_claim<T, C>(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
        claim_context: &C,
    ) -> Result<PepClaimResult<T, C>, PepAuthorityError>
    where
        T: DeserializeOwned + Serialize,
        C: Serialize + DeserializeOwned + Clone,
    {
        validate_claim_key(tenant, stage, idempotency_key, request_digest)?;
        let claim_context_body =
            serde_json::to_value(claim_context).map_err(|_| PepAuthorityError::ResponseInvalid)?;
        if !claim_context_body.is_object() {
            return Err(PepAuthorityError::ResponseInvalid);
        }
        let claim_context_digest = canonical_digest(claim_context)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        advisory_lock(&mut transaction, tenant, stage, idempotency_key).await?;
        let row = sqlx::query(
            "SELECT request_digest,result_status,response_digest,response_body,claim_context_digest,claim_context,\
                    claim_expires_at > clock_timestamp() AS lease_live \
             FROM pep_authorization_requests \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        if let Some(row) = row {
            let persisted_digest = row
                .try_get::<String, _>("request_digest")
                .map_err(database)?;
            if persisted_digest != request_digest {
                return Err(PepAuthorityError::IdempotencyConflict);
            }
            let status = row
                .try_get::<String, _>("result_status")
                .map_err(database)?;
            let lease_live = row.try_get::<bool, _>("lease_live").map_err(database)?;
            return match classify_existing(&status, lease_live)? {
                ExistingClaimState::Replay => {
                    let value = row
                        .try_get::<Option<Value>, _>("response_body")
                        .map_err(database)?
                        .ok_or(PepAuthorityError::PersistenceUnavailable)?;
                    let replay: T = serde_json::from_value(value)
                        .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                    if canonical_digest(&replay)?
                        != row
                            .try_get::<Option<String>, _>("response_digest")
                            .map_err(database)?
                            .ok_or(PepAuthorityError::PersistenceUnavailable)?
                    {
                        return Err(PepAuthorityError::PersistenceUnavailable);
                    }
                    transaction.commit().await.map_err(database)?;
                    Ok(PepClaimResult::Replay(replay))
                }
                ExistingClaimState::Denied => Err(PepAuthorityError::AuthorizationDenied),
                ExistingClaimState::InProgress => Err(PepAuthorityError::IdempotencyInProgress),
                ExistingClaimState::Recoverable => {
                    let persisted_context_digest = row
                        .try_get::<Option<String>, _>("claim_context_digest")
                        .map_err(database)?
                        .ok_or(PepAuthorityError::PersistenceUnavailable)?;
                    let context: C = serde_json::from_value(
                        row.try_get::<Option<Value>, _>("claim_context")
                            .map_err(database)?
                            .ok_or(PepAuthorityError::PersistenceUnavailable)?,
                    )
                    .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                    if canonical_digest(&context)? != persisted_context_digest {
                        return Err(PepAuthorityError::PersistenceUnavailable);
                    }
                    let owner = PepClaimOwner(Uuid::new_v4());
                    let updated = sqlx::query(
                        "UPDATE pep_authorization_requests \
                         SET claim_owner=$4,claim_expires_at=clock_timestamp()+make_interval(secs => $5::integer) \
                         WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 \
                           AND result_status='IN_PROGRESS' AND claim_expires_at <= clock_timestamp()",
                    )
                    .bind(&tenant.0)
                    .bind(stage)
                    .bind(idempotency_key)
                    .bind(owner.0)
                    .bind(CLAIM_LEASE_SECONDS)
                    .execute(&mut *transaction)
                    .await
                    .map_err(database)?;
                    if updated.rows_affected() != 1 {
                        return Err(PepAuthorityError::IdempotencyInProgress);
                    }
                    transaction.commit().await.map_err(database)?;
                    Ok(PepClaimResult::Acquired { owner, context })
                }
            };
        }

        let owner = PepClaimOwner(Uuid::new_v4());
        sqlx::query(
            "INSERT INTO pep_authorization_requests \
             (tenant_id,stage,idempotency_key,request_digest,result_status,claim_owner,claim_expires_at,claim_context_digest,claim_context,created_at) \
             VALUES ($1::uuid,$2,$3,$4,'IN_PROGRESS',$5,\
                     clock_timestamp()+make_interval(secs => $6::integer),$7,$8,clock_timestamp())",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(owner.0)
        .bind(CLAIM_LEASE_SECONDS)
        .bind(claim_context_digest)
        .bind(claim_context_body)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        Ok(PepClaimResult::Acquired {
            owner,
            context: claim_context.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn persist<T>(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
        owner: &PepClaimOwner,
        action_hash: &str,
        response: &T,
        decision: &PolicyDecision,
        authorization: Option<&ExecutionAuthorization>,
    ) -> Result<T, PepAuthorityError>
    where
        T: Serialize + DeserializeOwned + Clone,
    {
        self.complete(
            tenant,
            stage,
            idempotency_key,
            request_digest,
            owner,
            "SUCCEEDED",
            action_hash,
            response,
            decision,
            authorization,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn persist_denial(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
        owner: &PepClaimOwner,
        action_hash: &str,
        decision: &PolicyDecision,
    ) -> Result<(), PepAuthorityError> {
        let denial = serde_json::json!({
            "schema_version": "agenttrust.pep-denial.v1",
            "error": "PEP_AUTHORIZATION_DENIED"
        });
        self.complete(
            tenant,
            stage,
            idempotency_key,
            request_digest,
            owner,
            "DENIED",
            action_hash,
            &denial,
            decision,
            None,
        )
        .await
        .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn bind_human_assertion(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
        owner: &PepClaimOwner,
        assertion_jti: &str,
        assertion_digest: &str,
    ) -> Result<(), PepAuthorityError> {
        validate_claim_key(tenant, stage, idempotency_key, request_digest)?;
        if Uuid::parse_str(assertion_jti).is_err()
            || !digest(assertion_digest)
            || !matches!(stage, "GOVERNANCE_APPROVAL" | "GOVERNANCE_QUERY")
        {
            return Err(PepAuthorityError::RequestInvalid);
        }
        let mut transaction = self.begin_tenant(tenant).await?;
        advisory_lock(&mut transaction, tenant, stage, idempotency_key).await?;
        let claim = sqlx::query(
            "SELECT request_digest,result_status,claim_owner FROM pep_authorization_requests \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(PepAuthorityError::PersistenceUnavailable)?;
        if claim
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != request_digest
            || claim
                .try_get::<String, _>("result_status")
                .map_err(database)?
                != "IN_PROGRESS"
            || claim.try_get::<Uuid, _>("claim_owner").map_err(database)? != owner.0
        {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        sqlx::query(
            "INSERT INTO pep_human_assertion_uses \
             (tenant_id,assertion_jti,assertion_digest,stage,idempotency_key,request_digest,created_at) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,clock_timestamp()) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&tenant.0)
        .bind(assertion_jti)
        .bind(assertion_digest)
        .bind(stage)
        .bind(idempotency_key)
        .bind(request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let bindings = sqlx::query(
            "SELECT assertion_jti::text,assertion_digest,stage,idempotency_key,request_digest \
             FROM pep_human_assertion_uses \
             WHERE tenant_id=$1::uuid AND (assertion_jti=$2::uuid OR assertion_digest=$3) \
             FOR SHARE",
        )
        .bind(&tenant.0)
        .bind(assertion_jti)
        .bind(assertion_digest)
        .fetch_all(&mut *transaction)
        .await
        .map_err(database)?;
        if bindings.len() != 1
            || bindings[0]
                .try_get::<String, _>("assertion_jti")
                .map_err(database)?
                != assertion_jti
            || bindings[0]
                .try_get::<String, _>("assertion_digest")
                .map_err(database)?
                != assertion_digest
            || bindings[0]
                .try_get::<String, _>("stage")
                .map_err(database)?
                != stage
            || bindings[0]
                .try_get::<String, _>("idempotency_key")
                .map_err(database)?
                != idempotency_key
            || bindings[0]
                .try_get::<String, _>("request_digest")
                .map_err(database)?
                != request_digest
        {
            return Err(PepAuthorityError::IdempotencyConflict);
        }
        transaction.commit().await.map_err(database)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn persist_governance<T>(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
        owner: &PepClaimOwner,
        input_hash: &str,
        response: &T,
        decision: &PolicyDecision,
        evidence: GovernanceEvidenceRecord<'_>,
    ) -> Result<T, PepAuthorityError>
    where
        T: Serialize + DeserializeOwned + Clone,
    {
        validate_claim_key(tenant, stage, idempotency_key, request_digest)?;
        if !matches!(stage, "GOVERNANCE_APPROVAL" | "GOVERNANCE_QUERY")
            || !digest(input_hash)
            || !digest(evidence.evidence_digest)
            || Uuid::parse_str(evidence.evidence_id).is_err()
            || Uuid::parse_str(evidence.assertion_jti).is_err()
            || evidence.evidence_ref.is_empty()
            || evidence.evidence_ref.len() > 2_048
            || !evidence.evidence_body.is_object()
            || evidence
                .evidence_body
                .get("tenant_id")
                .and_then(Value::as_str)
                != Some(tenant.0.as_str())
            || evidence
                .evidence_body
                .get("evidence_id")
                .and_then(Value::as_str)
                != Some(evidence.evidence_id)
            || evidence
                .evidence_body
                .get("evidence_digest")
                .and_then(Value::as_str)
                != Some(evidence.evidence_digest)
            || evidence
                .evidence_body
                .get("evidence_ref")
                .and_then(Value::as_str)
                != Some(evidence.evidence_ref)
        {
            return Err(PepAuthorityError::ResponseInvalid);
        }
        let response_body =
            serde_json::to_value(response).map_err(|_| PepAuthorityError::ResponseInvalid)?;
        if !response_body.is_object() {
            return Err(PepAuthorityError::ResponseInvalid);
        }
        let response_digest = canonical_digest(response)?;
        let decision_body =
            serde_json::to_value(decision).map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let decision_digest = canonical_digest(decision)?;
        let event_id = Uuid::new_v4();
        let occurred_at = evidence.recorded_at;
        let mut outbox_body = serde_json::json!({
            "schema_version": "agenttrust.pep-evidence-outbox.v1",
            "event_id": event_id.to_string(),
            "event_type": "PEP_GOVERNANCE_DECISION_RECORDED",
            "tenant_id": &tenant.0,
            "evidence_id": evidence.evidence_id,
            "evidence_ref": evidence.evidence_ref,
            "evidence_digest": evidence.evidence_digest,
            "decision_id": &decision.decision_id,
            "decision_digest": decision_digest,
            "occurred_at": &occurred_at,
            "event_digest": ""
        });
        let event_digest = canonical_digest(&outbox_body)?;
        outbox_body["event_digest"] = Value::String(event_digest.clone());

        let mut transaction = self.begin_tenant(tenant).await?;
        advisory_lock(&mut transaction, tenant, stage, idempotency_key).await?;
        let claim = sqlx::query(
            "SELECT request_digest,result_status,claim_owner FROM pep_authorization_requests \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(PepAuthorityError::PersistenceUnavailable)?;
        if claim
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != request_digest
        {
            return Err(PepAuthorityError::IdempotencyConflict);
        }
        if claim
            .try_get::<String, _>("result_status")
            .map_err(database)?
            != "IN_PROGRESS"
            || claim.try_get::<Uuid, _>("claim_owner").map_err(database)? != owner.0
        {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        let assertion_use = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pep_human_assertion_uses \
             WHERE tenant_id=$1::uuid AND assertion_jti=$2::uuid \
               AND stage=$3 AND idempotency_key=$4 AND request_digest=$5",
        )
        .bind(&tenant.0)
        .bind(evidence.assertion_jti)
        .bind(stage)
        .bind(idempotency_key)
        .bind(request_digest)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database)?;
        if assertion_use != 1 {
            return Err(PepAuthorityError::PersistenceUnavailable);
        }

        sqlx::query(
            "INSERT INTO pep_policy_decisions \
             (tenant_id,decision_id,stage,action_hash,input_hash,policy_version,policy_bundle_hash,decision_body,evaluated_at,expires_at) \
             VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&tenant.0)
        .bind(&decision.decision_id)
        .bind(stage)
        .bind(input_hash)
        .bind(&decision.input_hash)
        .bind(&decision.policy_version.0)
        .bind(&decision.policy_bundle_hash)
        .bind(decision_body)
        .bind(decision.evaluated_at)
        .bind(decision.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;

        sqlx::query(
            "INSERT INTO pep_governance_evidence \
             (tenant_id,evidence_id,decision_id,stage,request_digest,assertion_jti,evidence_digest,evidence_ref,evidence_body,recorded_at) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,$7,$8,$9,$10)",
        )
        .bind(&tenant.0)
        .bind(evidence.evidence_id)
        .bind(&decision.decision_id)
        .bind(stage)
        .bind(request_digest)
        .bind(evidence.assertion_jti)
        .bind(evidence.evidence_digest)
        .bind(evidence.evidence_ref)
        .bind(evidence.evidence_body)
        .bind(occurred_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;

        sqlx::query(
            "INSERT INTO pep_evidence_outbox \
             (tenant_id,event_id,evidence_id,event_type,event_digest,event_body,occurred_at) \
             VALUES ($1::uuid,$2,$3::uuid,'PEP_GOVERNANCE_DECISION_RECORDED',$4,$5,$6)",
        )
        .bind(&tenant.0)
        .bind(event_id)
        .bind(evidence.evidence_id)
        .bind(event_digest)
        .bind(outbox_body)
        .bind(occurred_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;

        let updated = sqlx::query(
            "UPDATE pep_authorization_requests \
             SET result_status='SUCCEEDED',response_digest=$5,response_body=$6,completed_at=clock_timestamp() \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 \
               AND request_digest=$4 AND result_status='IN_PROGRESS' AND claim_owner=$7",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(response_digest)
        .bind(response_body)
        .bind(owner.0)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        transaction.commit().await.map_err(database)?;
        Ok(response.clone())
    }

    pub async fn load_governance_evidence(
        &self,
        tenant: &TenantId,
        evidence_id: &str,
    ) -> Result<Option<Value>, PepAuthorityError> {
        if Uuid::parse_str(evidence_id).is_err() {
            return Err(PepAuthorityError::RequestInvalid);
        }
        let mut transaction = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT evidence_digest,evidence_ref,evidence_body FROM pep_governance_evidence \
             WHERE tenant_id=$1::uuid AND evidence_id=$2::uuid",
        )
        .bind(&tenant.0)
        .bind(evidence_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let body = row.try_get::<Value, _>("evidence_body").map_err(database)?;
        let persisted_digest = row
            .try_get::<String, _>("evidence_digest")
            .map_err(database)?;
        let persisted_ref = row.try_get::<String, _>("evidence_ref").map_err(database)?;
        if body.get("evidence_digest").and_then(Value::as_str) != Some(persisted_digest.as_str())
            || body.get("evidence_ref").and_then(Value::as_str) != Some(persisted_ref.as_str())
        {
            return Err(PepAuthorityError::PersistenceUnavailable);
        }
        Ok(Some(body))
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete<T>(
        &self,
        tenant: &TenantId,
        stage: &str,
        idempotency_key: &str,
        request_digest: &str,
        owner: &PepClaimOwner,
        terminal_status: &str,
        action_hash: &str,
        response: &T,
        decision: &PolicyDecision,
        authorization: Option<&ExecutionAuthorization>,
    ) -> Result<T, PepAuthorityError>
    where
        T: Serialize + DeserializeOwned + Clone,
    {
        if !matches!(terminal_status, "SUCCEEDED" | "DENIED") || !digest(action_hash) {
            return Err(PepAuthorityError::PersistenceUnavailable);
        }
        if authorization.is_some_and(|authorization| {
            &authorization.tenant_id != tenant || authorization.action_hash.0 != action_hash
        }) {
            return Err(PepAuthorityError::ResponseInvalid);
        }
        let response_body =
            serde_json::to_value(response).map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let response_digest = canonical_digest(response)?;
        let decision_body =
            serde_json::to_value(decision).map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        advisory_lock(&mut transaction, tenant, stage, idempotency_key).await?;
        let claim = sqlx::query(
            "SELECT request_digest,result_status,claim_owner FROM pep_authorization_requests \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(PepAuthorityError::PersistenceUnavailable)?;
        if claim
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != request_digest
        {
            return Err(PepAuthorityError::IdempotencyConflict);
        }
        if claim
            .try_get::<String, _>("result_status")
            .map_err(database)?
            != "IN_PROGRESS"
            || claim.try_get::<Uuid, _>("claim_owner").map_err(database)? != owner.0
        {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }

        sqlx::query(
            "INSERT INTO pep_policy_decisions \
             (tenant_id,decision_id,stage,action_hash,input_hash,policy_version,policy_bundle_hash,decision_body,evaluated_at,expires_at) \
             VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&tenant.0)
        .bind(&decision.decision_id)
        .bind(stage)
        .bind(action_hash)
        .bind(&decision.input_hash)
        .bind(&decision.policy_version.0)
        .bind(&decision.policy_bundle_hash)
        .bind(decision_body)
        .bind(decision.evaluated_at)
        .bind(decision.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;

        if let Some(authorization) = authorization {
            let signed_authorization = serde_json::to_value(authorization)
                .map_err(|_| PepAuthorityError::ResponseInvalid)?;
            let authorization_digest = canonical_digest(authorization)?;
            sqlx::query(
                "INSERT INTO pep_execution_authorizations \
                 (tenant_id,authorization_id,ledger_execution_id,ledger_event_id,ledger_event_digest,action_hash,fence_digest,preapproval_digest,approval_consumption_ref,approval_receipt_digest,credential_id,credential_claims_digest,authorization_digest,signed_authorization,issued_at,expires_at) \
                 VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11::uuid,$12,$13,$14,$15,$16)",
            )
            .bind(&tenant.0)
            .bind(&authorization.authorization_id)
            .bind(&authorization.ledger_execution_id.0)
            .bind(&authorization.ledger_event_id)
            .bind(&authorization.ledger_event_digest)
            .bind(&authorization.action_hash.0)
            .bind(&authorization.fence_digest)
            .bind(&authorization.preapproval_digest)
            .bind(&authorization.approval_consumption_ref)
            .bind(&authorization.approval_receipt_digest)
            .bind(&authorization.workload_credential_id)
            .bind(&authorization.workload_credential_claims_digest)
            .bind(authorization_digest)
            .bind(signed_authorization)
            .bind(authorization.issued_at)
            .bind(authorization.expires_at)
            .execute(&mut *transaction)
            .await
            .map_err(map_authorization_conflict)?;
        }

        let updated = sqlx::query(
            "UPDATE pep_authorization_requests \
             SET result_status=$5,response_digest=$6,response_body=$7,completed_at=clock_timestamp() \
             WHERE tenant_id=$1::uuid AND stage=$2 AND idempotency_key=$3 \
               AND request_digest=$4 AND result_status='IN_PROGRESS' AND claim_owner=$8",
        )
        .bind(&tenant.0)
        .bind(stage)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(terminal_status)
        .bind(response_digest)
        .bind(response_body)
        .bind(owner.0)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(PepAuthorityError::IdempotencyIndeterminate);
        }
        transaction.commit().await.map_err(database)?;
        Ok(response.clone())
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, PepAuthorityError> {
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(database)?;
        Ok(transaction)
    }
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    stage: &str,
    idempotency_key: &str,
) -> Result<(), PepAuthorityError> {
    let lock_key = format!("{}:{stage}:{idempotency_key}", tenant.0);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(database)?;
    Ok(())
}

fn classify_existing(
    status: &str,
    lease_live: bool,
) -> Result<ExistingClaimState, PepAuthorityError> {
    match (status, lease_live) {
        ("SUCCEEDED", _) => Ok(ExistingClaimState::Replay),
        ("DENIED", _) => Ok(ExistingClaimState::Denied),
        ("IN_PROGRESS", true) => Ok(ExistingClaimState::InProgress),
        ("IN_PROGRESS", false) => Ok(ExistingClaimState::Recoverable),
        _ => Err(PepAuthorityError::PersistenceUnavailable),
    }
}

fn validate_claim_key(
    tenant: &TenantId,
    stage: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<(), PepAuthorityError> {
    if uuid::Uuid::parse_str(&tenant.0).is_err()
        || !matches!(
            stage,
            "PRE_APPROVAL" | "PRE_EXECUTION" | "GOVERNANCE_APPROVAL" | "GOVERNANCE_QUERY"
        )
        || idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || !idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        || !digest(request_digest)
    {
        return Err(PepAuthorityError::RequestInvalid);
    }
    Ok(())
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, PepAuthorityError> {
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| PepAuthorityError::RequestInvalid)?,
    )))
}

fn database(_: sqlx::Error) -> PepAuthorityError {
    PepAuthorityError::PersistenceUnavailable
}

fn map_authorization_conflict(error: sqlx::Error) -> PepAuthorityError {
    if error
        .as_database_error()
        .and_then(|value| value.code())
        .as_deref()
        == Some("23505")
    {
        PepAuthorityError::IdempotencyConflict
    } else {
        PepAuthorityError::PersistenceUnavailable
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_governance_claim_never_permits_a_concurrent_pdp_call() {
        assert_eq!(
            classify_existing("IN_PROGRESS", true),
            Ok(ExistingClaimState::InProgress)
        );
    }

    #[test]
    fn expired_claim_can_only_enter_idempotent_recovery() {
        assert_eq!(
            classify_existing("IN_PROGRESS", false),
            Ok(ExistingClaimState::Recoverable)
        );
    }

    #[test]
    fn governance_allow_and_deny_responses_replay_only_after_terminal_commit() {
        assert_eq!(
            classify_existing("SUCCEEDED", false),
            Ok(ExistingClaimState::Replay)
        );
        assert_eq!(
            classify_existing("DENIED", false),
            Ok(ExistingClaimState::Denied)
        );
    }
}
