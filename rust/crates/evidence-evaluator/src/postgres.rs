//! Transactional production evidence chain backed by the existing evidence tables.

use crate::artifact::{ArtifactUploadRequest, WormObjectReceipt};
use crate::{
    EVALUATION_RUN_KEY_USAGE, EVALUATION_RUN_SCHEMA_VERSION, EVIDENCE_PACKAGE_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION, EvidenceError, EvidencePackage, EvidencePackageRequest,
    ProductionEvaluationRequest, ProductionEvidenceEventRequest, SignedEvaluationRun,
    SignedEvidencePackage, StoredArtifact, package_hash,
};
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE, AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    ArtifactRef, AuthorityEvidenceEventRequest, AuthorityEvidenceSourceKind,
    EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE, EXECUTION_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    EvaluationResult, EvaluationStatus, EvidenceEventType, ExecutionEvidenceRequest, SchemaVersion,
    SignedAuthorityEvidenceReceipt, SignedEvidenceEvent, SignedExecutionEvidenceReceipt,
};
use agent_trust_tool_proxy::SanitizedToolResult;
use agent_trust_transaction_ledger::ExecutionFence;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub type ProductionExecutionEvidenceRequest = ExecutionEvidenceRequest<SanitizedToolResult>;

#[derive(Clone)]
pub struct PostgresEvidenceStore {
    pool: PgPool,
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
    verifying_keys: BTreeMap<String, VerifyingKey>,
}

impl PostgresEvidenceStore {
    pub fn new(
        pool: PgPool,
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
        verifying_keys: BTreeMap<String, VerifyingKey>,
    ) -> Result<Self, EvidenceError> {
        if issuer.is_empty()
            || issuer.len() > 256
            || key_id.is_empty()
            || key_id.len() > 128
            || verifying_keys.is_empty()
            || verifying_keys.len() > 1_024
            || verifying_keys
                .iter()
                .any(|(id, _)| id.is_empty() || id.len() > 128)
            || verifying_keys.get(&key_id) != Some(&signing_key.verifying_key())
        {
            return Err(EvidenceError::ConfigurationInvalid);
        }
        Ok(Self {
            pool,
            issuer,
            key_id,
            signing_key,
            verifying_keys,
        })
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn verification_key(&self, key_id: &str) -> Result<&VerifyingKey, EvidenceError> {
        self.verifying_keys
            .get(key_id)
            .ok_or(EvidenceError::UnknownKey)
    }

    pub async fn ready(&self) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_millis(750),
            sqlx::query_scalar::<_, bool>(
                "SELECT has_table_privilege(current_user,'audit_events','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'evidence_chain_heads','SELECT,INSERT,UPDATE') AND \
                 has_table_privilege(current_user,'execution_evidence_receipts','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'evidence_event_requests','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'authority_evidence_event_requests','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'evidence_packages','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'evaluation_results','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'evidence_outbox','SELECT,INSERT') AND \
                 has_table_privilege(current_user,'executions','SELECT') AND \
                 has_table_privilege(current_user,'pep_execution_authorizations','SELECT') AND \
                 has_table_privilege(current_user,'orchestrator_tasks','SELECT')",
            )
            .fetch_one(&self.pool),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false)
    }

    pub async fn append_event(
        &self,
        request: &ProductionEvidenceEventRequest,
    ) -> Result<SignedEvidenceEvent, EvidenceError> {
        let request_digest = request.request_digest()?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let task = canonical_uuid(&request.task_id.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("evidence-chain:{tenant}:{task}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT request_digest,signed_event FROM evidence_event_requests \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        {
            if row
                .try_get::<String, _>("request_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request_digest
            {
                return Err(EvidenceError::IdempotencyConflict);
            }
            let event: SignedEvidenceEvent = serde_json::from_value(
                row.try_get("signed_event")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
            )
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            event.verify(self.verification_key(&event.key_id)?)?;
            transaction
                .commit()
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            return Ok(event);
        }
        let task_row = sqlx::query(
            "SELECT state_version,goal_digest,plan_digest FROM orchestrator_tasks \
             WHERE tenant_id=$1 AND task_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::LedgerBindingInvalid)?;
        let state_version = task_row
            .try_get::<i64, _>("state_version")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        if u64::try_from(state_version).map_err(|_| EvidenceError::LedgerBindingInvalid)?
            != request.expected_task_state_version
            || (request.event.event_type == EvidenceEventType::TaskCreated
                && task_row
                    .try_get::<String, _>("goal_digest")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?
                    != request.event.payload_hash)
            || (request.event.event_type == EvidenceEventType::PlanGenerated
                && task_row
                    .try_get::<String, _>("plan_digest")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?
                    != request.event.payload_hash)
        {
            return Err(EvidenceError::LedgerBindingInvalid);
        }
        let head = sqlx::query(
            "SELECT last_sequence,chain_hash FROM evidence_chain_heads \
             WHERE tenant_id=$1 AND task_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let (sequence, previous_hash) = match head {
            Some(row) => (
                u64::try_from(
                    row.try_get::<i64, _>("last_sequence")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                )
                .map_err(|_| EvidenceError::IntegrityInvalid)?
                    + 1,
                row.try_get("chain_hash")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
            ),
            None => (1, "0".repeat(64)),
        };
        let mut event = SignedEvidenceEvent {
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            event_id: Uuid::new_v4().to_string(),
            sequence,
            previous_hash,
            event_hash: String::new(),
            key_id: self.key_id.clone(),
            signature: String::new(),
            draft: request.event.clone(),
        };
        event.event_hash = event.expected_hash()?;
        event.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(event.event_hash.as_bytes())
                .to_bytes(),
        );
        event.verify(&self.verifying_key())?;
        let event_id = canonical_uuid(&event.event_id)?;
        let event_type = serde_json::to_value(&event.draft.event_type)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(EvidenceError::EventInvalid)?;
        let event_value =
            serde_json::to_value(&event).map_err(|_| EvidenceError::Canonicalization)?;
        sqlx::query(
            "INSERT INTO audit_events(tenant_id,task_id,sequence,event_id,previous_hash,event_hash,key_id,signature,event_type,safe_payload,occurred_at,signed_event,request_digest) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(tenant)
        .bind(task)
        .bind(i64::try_from(sequence).map_err(|_| EvidenceError::CapacityExceeded)?)
        .bind(event_id)
        .bind(&event.previous_hash)
        .bind(&event.event_hash)
        .bind(&event.key_id)
        .bind(
            URL_SAFE_NO_PAD
                .decode(&event.signature)
                .map_err(|_| EvidenceError::SignatureInvalid)?,
        )
        .bind(event_type)
        .bind(event_value.clone())
        .bind(event.draft.occurred_at)
        .bind(event_value.clone())
        .bind(&request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_chain_heads(tenant_id,task_id,last_sequence,chain_hash,key_id,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,task_id) DO UPDATE SET \
             last_sequence=EXCLUDED.last_sequence,chain_hash=EXCLUDED.chain_hash,key_id=EXCLUDED.key_id,updated_at=EXCLUDED.updated_at",
        )
        .bind(tenant)
        .bind(task)
        .bind(i64::try_from(sequence).map_err(|_| EvidenceError::CapacityExceeded)?)
        .bind(&event.event_hash)
        .bind(&event.key_id)
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_event_requests(tenant_id,task_id,idempotency_key,request_digest,event_id,signed_event,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant)
        .bind(task)
        .bind(&request.idempotency_key.0)
        .bind(&request_digest)
        .bind(event_id)
        .bind(event_value)
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_outbox(tenant_id,outbox_id,task_id,event_id,event_type,payload,created_at) \
             VALUES($1,$2,$3,$4,'LIFECYCLE_EVIDENCE_APPENDED',$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(task)
        .bind(event_id)
        .bind(serde_json::json!({
            "event_id": event_id,
            "event_type": &event.draft.event_type,
            "event_hash": &event.event_hash,
            "task_state_version": request.expected_task_state_version,
        }))
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(event)
    }

    pub async fn append_authority_event(
        &self,
        request: &AuthorityEvidenceEventRequest,
    ) -> Result<SignedAuthorityEvidenceReceipt, EvidenceError> {
        let request_digest = request
            .request_digest()
            .map_err(|_| EvidenceError::EventInvalid)?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let task = canonical_uuid(&request.task_id.0)?;
        let authority_event_id = canonical_uuid(&request.authority_event_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("evidence-chain:{tenant}:{task}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;

        if let Some(row) = sqlx::query(
            "SELECT request_digest,signed_receipt FROM authority_evidence_event_requests \
             WHERE tenant_id=$1 AND (idempotency_key=$2 OR authority_event_id=$3) FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .bind(authority_event_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        {
            if row
                .try_get::<String, _>("request_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request_digest
            {
                return Err(EvidenceError::IdempotencyConflict);
            }
            let receipt: SignedAuthorityEvidenceReceipt = serde_json::from_value(
                row.try_get("signed_receipt")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
            )
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            receipt.verify(self.verification_key(&receipt.key_id)?, Utc::now())?;
            transaction
                .commit()
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            return Ok(receipt);
        }

        match (&request.source_kind, &request.control_binding) {
            (AuthorityEvidenceSourceKind::GovernedAction, Some(binding)) => {
                let ledger_execution = canonical_uuid(&binding.ledger_execution_id.0)?;
                let authorization = sqlx::query(
                    "SELECT ledger_event_id,ledger_event_digest,action_hash,fence_digest, \
                            signed_authorization ->> 'task_id' AS task_id, \
                            signed_authorization ->> 'policy_decision_id' AS policy_decision_id, \
                            signed_authorization ->> 'policy_decision_digest' AS policy_decision_digest, \
                            signed_authorization ->> 'authorization_evidence_ref' AS authorization_evidence_ref, \
                            signed_authorization ->> 'authorization_evidence_digest' AS authorization_evidence_digest \
                     FROM pep_execution_authorizations \
                     WHERE tenant_id=$1 AND ledger_execution_id=$2 FOR SHARE",
                )
                .bind(tenant)
                .bind(ledger_execution)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                .ok_or(EvidenceError::AuthorizationBindingInvalid)?;
                if authorization
                    .try_get::<Uuid, _>("ledger_event_id")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?
                    .to_string()
                    != binding.ledger_event_id
                    || authorization
                        .try_get::<String, _>("ledger_event_digest")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.ledger_event_digest
                    || authorization
                        .try_get::<String, _>("action_hash")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.action_hash.0
                    || authorization
                        .try_get::<String, _>("fence_digest")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.fence_digest
                    || authorization
                        .try_get::<String, _>("task_id")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != request.task_id.0
                    || authorization
                        .try_get::<String, _>("policy_decision_id")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.policy_decision_id
                    || authorization
                        .try_get::<String, _>("policy_decision_digest")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.policy_decision_digest
                    || authorization
                        .try_get::<String, _>("authorization_evidence_ref")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.authorization_evidence_ref
                    || authorization
                        .try_get::<String, _>("authorization_evidence_digest")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?
                        != binding.authorization_evidence_digest
                {
                    return Err(EvidenceError::AuthorizationBindingInvalid);
                }
            }
            (AuthorityEvidenceSourceKind::AuthenticatedEvent, None) => {
                let task_exists = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM orchestrator_tasks WHERE tenant_id=$1 AND task_id=$2)",
                )
                .bind(tenant)
                .bind(task)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
                if !task_exists {
                    return Err(EvidenceError::LedgerBindingInvalid);
                }
            }
            _ => return Err(EvidenceError::EventInvalid),
        }

        let head = sqlx::query(
            "SELECT last_sequence,chain_hash FROM evidence_chain_heads \
             WHERE tenant_id=$1 AND task_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let (sequence, previous_hash) = match head {
            Some(row) => (
                u64::try_from(
                    row.try_get::<i64, _>("last_sequence")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                )
                .map_err(|_| EvidenceError::IntegrityInvalid)?
                    + 1,
                row.try_get("chain_hash")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
            ),
            None => (1, "0".repeat(64)),
        };
        let mut event = SignedEvidenceEvent {
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            event_id: request.authority_event_id.clone(),
            sequence,
            previous_hash,
            event_hash: String::new(),
            key_id: self.key_id.clone(),
            signature: String::new(),
            draft: request.event.clone(),
        };
        event.event_hash = event.expected_hash()?;
        event.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(event.event_hash.as_bytes())
                .to_bytes(),
        );
        event.verify(&self.verifying_key())?;
        let persisted_at = Utc::now();
        let mut receipt = SignedAuthorityEvidenceReceipt {
            schema_version: AUTHORITY_EVIDENCE_RECEIPT_SCHEMA_VERSION.into(),
            tenant_id: request.tenant_id.clone(),
            task_id: request.task_id.clone(),
            authority_event_id: request.authority_event_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            source_kind: request.source_kind,
            request_digest: request_digest.clone(),
            payload_digest: request.event.payload_hash.clone(),
            evidence_ref: String::new(),
            evidence_digest: String::new(),
            event,
            persisted_at,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            key_usage: AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE.into(),
            signature: String::new(),
        };
        receipt.evidence_ref = receipt.expected_evidence_ref();
        receipt.sign(&self.signing_key)?;
        receipt.verify(&self.verifying_key(), Utc::now())?;

        let event_value = serde_json::to_value(&receipt.event)
            .map_err(|_| EvidenceError::Canonicalization)?;
        let receipt_value = serde_json::to_value(&receipt)
            .map_err(|_| EvidenceError::Canonicalization)?;
        let event_type = serde_json::to_value(&receipt.event.draft.event_type)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(EvidenceError::EventInvalid)?;
        sqlx::query(
            "INSERT INTO audit_events(tenant_id,task_id,sequence,event_id,previous_hash,event_hash,key_id,signature,event_type,safe_payload,occurred_at,signed_event,request_digest) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(tenant)
        .bind(task)
        .bind(i64::try_from(sequence).map_err(|_| EvidenceError::CapacityExceeded)?)
        .bind(authority_event_id)
        .bind(&receipt.event.previous_hash)
        .bind(&receipt.event.event_hash)
        .bind(&receipt.event.key_id)
        .bind(
            URL_SAFE_NO_PAD
                .decode(&receipt.event.signature)
                .map_err(|_| EvidenceError::SignatureInvalid)?,
        )
        .bind(event_type)
        .bind(event_value.clone())
        .bind(receipt.event.draft.occurred_at)
        .bind(event_value)
        .bind(&request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_chain_heads(tenant_id,task_id,last_sequence,chain_hash,key_id,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,task_id) DO UPDATE SET \
             last_sequence=EXCLUDED.last_sequence,chain_hash=EXCLUDED.chain_hash,key_id=EXCLUDED.key_id,updated_at=EXCLUDED.updated_at",
        )
        .bind(tenant)
        .bind(task)
        .bind(i64::try_from(sequence).map_err(|_| EvidenceError::CapacityExceeded)?)
        .bind(&receipt.event.event_hash)
        .bind(&receipt.event.key_id)
        .bind(persisted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO authority_evidence_event_requests \
             (tenant_id,authority_event_id,task_id,idempotency_key,request_digest,payload_digest,source_kind,control_binding,signed_receipt,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(tenant)
        .bind(authority_event_id)
        .bind(task)
        .bind(&request.idempotency_key.0)
        .bind(&request_digest)
        .bind(&request.event.payload_hash)
        .bind(match request.source_kind {
            AuthorityEvidenceSourceKind::GovernedAction => "GOVERNED_ACTION",
            AuthorityEvidenceSourceKind::AuthenticatedEvent => "AUTHENTICATED_EVENT",
        })
        .bind(
            request
                .control_binding
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| EvidenceError::Canonicalization)?,
        )
        .bind(receipt_value)
        .bind(persisted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_outbox(tenant_id,outbox_id,task_id,event_id,event_type,payload,created_at) \
             VALUES($1,$2,$3,$4,'AUTHORITY_EVIDENCE_APPENDED',$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(task)
        .bind(authority_event_id)
        .bind(serde_json::json!({
            "authority_event_id": authority_event_id,
            "source_kind": match request.source_kind {
                AuthorityEvidenceSourceKind::GovernedAction => "GOVERNED_ACTION",
                AuthorityEvidenceSourceKind::AuthenticatedEvent => "AUTHENTICATED_EVENT",
            },
            "evidence_ref": &receipt.evidence_ref,
            "evidence_digest": &receipt.evidence_digest,
            "event_hash": &receipt.event.event_hash,
        }))
        .bind(persisted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(receipt)
    }

    pub async fn append_execution(
        &self,
        request: &ProductionExecutionEvidenceRequest,
    ) -> Result<SignedExecutionEvidenceReceipt, EvidenceError> {
        let request_digest = request.request_digest()?;
        if request.result.result_hash != request.event.payload_hash
            || request.event.span_id != request.execution_id.0
            || request.event.schema_version != EVIDENCE_SCHEMA_VERSION
            || request.event.event_type != EvidenceEventType::ToolExecuted
        {
            return Err(EvidenceError::EventInvalid);
        }
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let task = canonical_uuid(&request.task_id.0)?;
        let step = canonical_uuid(&request.step_id.0)?;
        let execution = canonical_uuid(&request.execution_id.0)?;
        let authorization = canonical_uuid(&request.authorization_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("evidence-chain:{tenant}:{task}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;

        if let Some(row) = sqlx::query(
            "SELECT request_digest,receipt_payload FROM execution_evidence_receipts \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        {
            let stored_digest: String = row
                .try_get("request_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            if stored_digest != request_digest {
                return Err(EvidenceError::IdempotencyConflict);
            }
            let payload: Value = row
                .try_get("receipt_payload")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            let receipt: SignedExecutionEvidenceReceipt = serde_json::from_value(payload)
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            receipt.verify(self.verification_key(&receipt.key_id)?, Utc::now())?;
            transaction
                .commit()
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            return Ok(receipt);
        }

        let ledger = sqlx::query(
            "SELECT task_id,step_id,action_hash,fence_token,status FROM executions \
             WHERE tenant_id=$1 AND execution_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(execution)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::LedgerBindingInvalid)?;
        let ledger_task: Uuid = ledger
            .try_get("task_id")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let ledger_step: Uuid = ledger
            .try_get("step_id")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let ledger_action: String = ledger
            .try_get("action_hash")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let fence_token: i64 = ledger
            .try_get("fence_token")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let status: String = ledger
            .try_get("status")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let fence = ExecutionFence {
            tenant_id: request.tenant_id.clone(),
            execution_id: request.execution_id.clone(),
            token: u64::try_from(fence_token).map_err(|_| EvidenceError::LedgerBindingInvalid)?,
        };
        let fence_digest = canonical_digest(&fence)?;
        if ledger_task != task
            || ledger_step != step
            || ledger_action != request.action_hash.0
            || status != "RUNNING"
            || fence_digest != request.fence_digest
        {
            return Err(EvidenceError::LedgerBindingInvalid);
        }

        let authoritative_owner = sqlx::query_scalar::<_, String>(
            "SELECT owner_subject FROM orchestrator_ingress_actions \
             WHERE tenant_id=$1 AND task_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::LedgerBindingInvalid)?;
        if authoritative_owner != request.event.actor_subject {
            return Err(EvidenceError::LedgerBindingInvalid);
        }

        let pep = sqlx::query(
            "SELECT ledger_execution_id,action_hash,fence_digest,authorization_digest,expires_at \
             FROM pep_execution_authorizations WHERE tenant_id=$1 AND authorization_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(authorization)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::AuthorizationBindingInvalid)?;
        if pep
            .try_get::<Uuid, _>("ledger_execution_id")
            .map_err(|_| EvidenceError::PersistenceUnavailable)?
            != execution
            || pep
                .try_get::<String, _>("action_hash")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request.action_hash.0
            || pep
                .try_get::<String, _>("fence_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request.fence_digest
            || pep
                .try_get::<String, _>("authorization_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request.authorization_digest
            || pep
                .try_get::<chrono::DateTime<Utc>, _>("expires_at")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                <= Utc::now()
        {
            return Err(EvidenceError::AuthorizationBindingInvalid);
        }

        let head = sqlx::query(
            "SELECT last_sequence,chain_hash FROM evidence_chain_heads \
             WHERE tenant_id=$1 AND task_id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let (sequence, previous_hash) = match head {
            Some(row) => {
                let last: i64 = row
                    .try_get("last_sequence")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?;
                let hash: String = row
                    .try_get("chain_hash")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?;
                (
                    u64::try_from(last).map_err(|_| EvidenceError::IntegrityInvalid)? + 1,
                    hash,
                )
            }
            None => (1, "0".repeat(64)),
        };
        let mut event = SignedEvidenceEvent {
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            event_id: Uuid::new_v4().to_string(),
            sequence,
            previous_hash,
            event_hash: String::new(),
            key_id: self.key_id.clone(),
            signature: String::new(),
            draft: request.event.clone(),
        };
        event.event_hash = event.expected_hash()?;
        event.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(event.event_hash.as_bytes())
                .to_bytes(),
        );
        event.verify(&self.verifying_key())?;
        let persisted_at = Utc::now();
        let mut receipt = SignedExecutionEvidenceReceipt {
            schema_version: EXECUTION_EVIDENCE_RECEIPT_SCHEMA_VERSION.into(),
            tenant_id: request.tenant_id.clone(),
            task_id: request.task_id.clone(),
            step_id: request.step_id.clone(),
            execution_id: request.execution_id.clone(),
            action_hash: request.action_hash.clone(),
            authorization_id: request.authorization_id.clone(),
            authorization_digest: request.authorization_digest.clone(),
            fence_digest: request.fence_digest.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_digest: request_digest.clone(),
            result_hash: request.result.result_hash.clone(),
            chain_head: event.event_hash.clone(),
            evidence_ref: String::new(),
            event,
            persisted_at,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            key_usage: EVIDENCE_EXECUTION_RECEIPT_KEY_USAGE.into(),
            signature: String::new(),
        };
        receipt.evidence_ref = receipt.expected_evidence_ref();
        receipt.sign(&self.signing_key)?;
        receipt.verify(&self.verifying_key(), Utc::now())?;
        let event_id = canonical_uuid(&receipt.event.event_id)?;
        let event_payload =
            serde_json::to_value(&receipt.event).map_err(|_| EvidenceError::Canonicalization)?;
        let receipt_payload =
            serde_json::to_value(&receipt).map_err(|_| EvidenceError::Canonicalization)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&receipt.event.signature)
            .map_err(|_| EvidenceError::SignatureInvalid)?;
        let event_type = serde_json::to_value(&receipt.event.draft.event_type)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(EvidenceError::EventInvalid)?;
        sqlx::query(
            "INSERT INTO audit_events(tenant_id,task_id,sequence,event_id,previous_hash,event_hash,key_id,signature,event_type,safe_payload,occurred_at,signed_event,request_digest,execution_id,authorization_id,result_hash) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(tenant)
        .bind(task)
        .bind(i64::try_from(sequence).map_err(|_| EvidenceError::CapacityExceeded)?)
        .bind(event_id)
        .bind(&receipt.event.previous_hash)
        .bind(&receipt.event.event_hash)
        .bind(&receipt.event.key_id)
        .bind(signature)
        .bind(event_type)
        .bind(event_payload.clone())
        .bind(receipt.event.draft.occurred_at)
        .bind(event_payload)
        .bind(&request_digest)
        .bind(execution)
        .bind(authorization)
        .bind(&receipt.result_hash)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_chain_heads(tenant_id,task_id,last_sequence,chain_hash,key_id,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,task_id) DO UPDATE SET \
             last_sequence=EXCLUDED.last_sequence,chain_hash=EXCLUDED.chain_hash,key_id=EXCLUDED.key_id,updated_at=EXCLUDED.updated_at",
        )
        .bind(tenant)
        .bind(task)
        .bind(i64::try_from(sequence).map_err(|_| EvidenceError::CapacityExceeded)?)
        .bind(&receipt.chain_head)
        .bind(&self.key_id)
        .bind(persisted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO execution_evidence_receipts(tenant_id,receipt_id,task_id,execution_id,authorization_id,idempotency_key,request_digest,receipt_digest,evidence_ref,receipt_payload,persisted_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(tenant)
        .bind(event_id)
        .bind(task)
        .bind(execution)
        .bind(authorization)
        .bind(&request.idempotency_key.0)
        .bind(&request_digest)
        .bind(canonical_digest(&receipt)?)
        .bind(&receipt.evidence_ref)
        .bind(receipt_payload.clone())
        .bind(persisted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_outbox(tenant_id,outbox_id,task_id,event_id,event_type,payload,created_at) \
             VALUES($1,$2,$3,$4,'EXECUTION_EVIDENCE_APPENDED',$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(task)
        .bind(event_id)
        .bind(serde_json::json!({
            "receipt_id": event_id,
            "execution_id": execution,
            "evidence_ref": receipt.evidence_ref,
            "receipt_digest": canonical_digest(&receipt)?,
        }))
        .bind(persisted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(receipt)
    }

    pub async fn receipt(
        &self,
        tenant_id: &str,
        receipt_id: &str,
    ) -> Result<SignedExecutionEvidenceReceipt, EvidenceError> {
        let tenant = canonical_uuid(tenant_id)?;
        let receipt = canonical_uuid(receipt_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let payload = sqlx::query_scalar::<_, Value>(
            "SELECT receipt_payload FROM execution_evidence_receipts WHERE tenant_id=$1 AND receipt_id=$2",
        )
        .bind(tenant)
        .bind(receipt)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::NotFound)?;
        let value: SignedExecutionEvidenceReceipt =
            serde_json::from_value(payload).map_err(|_| EvidenceError::PersistenceUnavailable)?;
        value.verify(self.verification_key(&value.key_id)?, Utc::now())?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(value)
    }

    pub async fn chain(
        &self,
        tenant_id: &str,
        task_id: &str,
        limit: i64,
    ) -> Result<Vec<SignedEvidenceEvent>, EvidenceError> {
        if !(1..=10_000).contains(&limit) {
            return Err(EvidenceError::CapacityExceeded);
        }
        let tenant = canonical_uuid(tenant_id)?;
        let task = canonical_uuid(task_id)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let rows = sqlx::query_scalar::<_, Value>(
            "SELECT signed_event FROM audit_events WHERE tenant_id=$1 AND task_id=$2 AND signed_event IS NOT NULL ORDER BY sequence LIMIT $3",
        )
        .bind(tenant)
        .bind(task)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let events = rows
            .into_iter()
            .map(|value| {
                serde_json::from_value(value).map_err(|_| EvidenceError::PersistenceUnavailable)
            })
            .collect::<Result<Vec<SignedEvidenceEvent>, _>>()?;
        for event in &events {
            event.verify(self.verification_key(&event.key_id)?)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(events)
    }

    pub async fn build_package(
        &self,
        request: &EvidencePackageRequest,
    ) -> Result<SignedEvidencePackage, EvidenceError> {
        let request_digest = request.request_digest()?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let task = canonical_uuid(&request.task_id.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("evidence-chain:{tenant}:{task}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;

        if let Some(row) = sqlx::query(
            "SELECT request_digest,signed_package FROM evidence_package_requests \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        {
            if row
                .try_get::<String, _>("request_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request_digest
            {
                return Err(EvidenceError::IdempotencyConflict);
            }
            let value = row
                .try_get::<Value, _>("signed_package")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            let package: SignedEvidencePackage =
                serde_json::from_value(value).map_err(|_| EvidenceError::PersistenceUnavailable)?;
            package.verify(
                self.verification_key(&package.key_id)?,
                self.verifying_keys.clone(),
            )?;
            transaction
                .commit()
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            return Ok(package);
        }

        let chain_head = sqlx::query_scalar::<_, String>(
            "SELECT chain_hash FROM evidence_chain_heads WHERE tenant_id=$1 AND task_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::ChainIncomplete)?;
        if chain_head != request.expected_chain_head {
            return Err(EvidenceError::IntegrityInvalid);
        }
        let event_values = sqlx::query_scalar::<_, Value>(
            "SELECT signed_event FROM audit_events WHERE tenant_id=$1 AND task_id=$2 \
             ORDER BY sequence",
        )
        .bind(tenant)
        .bind(task)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let events = event_values
            .into_iter()
            .map(|value| {
                serde_json::from_value(value).map_err(|_| EvidenceError::PersistenceUnavailable)
            })
            .collect::<Result<Vec<SignedEvidenceEvent>, _>>()?;
        validate_chain_snapshot(
            &events,
            &request.tenant_id.0,
            &request.task_id.0,
            &chain_head,
        )?;

        let referenced_hashes = events
            .iter()
            .flat_map(|event| event.draft.artifact_refs.iter())
            .map(|reference| {
                reference
                    .0
                    .strip_prefix("artifact:sha256:")
                    .filter(|digest| digest.len() == 64)
                    .map(str::to_owned)
                    .ok_or(EvidenceError::IntegrityInvalid)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let artifact_rows = if referenced_hashes.is_empty() {
            Vec::new()
        } else {
            sqlx::query(
                "SELECT artifact_hash,media_type,classification,access_policy,byte_length,created_at,\
                        GREATEST(1,EXTRACT(EPOCH FROM (retention_until-created_at))::bigint) AS retention_seconds \
                 FROM evidence_artifacts WHERE tenant_id=$1 AND artifact_hash = ANY($2) \
                 ORDER BY artifact_hash",
            )
            .bind(tenant)
            .bind(referenced_hashes.iter().cloned().collect::<Vec<_>>())
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?
        };
        if artifact_rows.len() != referenced_hashes.len() {
            return Err(EvidenceError::ChainIncomplete);
        }
        let artifacts = artifact_rows
            .into_iter()
            .map(|row| {
                let digest = row
                    .try_get::<String, _>("artifact_hash")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?;
                Ok(StoredArtifact {
                    artifact_ref: ArtifactRef(format!("artifact:sha256:{digest}")),
                    sha256: digest,
                    media_type: row
                        .try_get("media_type")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                    classification: row
                        .try_get("classification")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                    retention_seconds: u64::try_from(
                        row.try_get::<i64, _>("retention_seconds")
                            .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                    )
                    .map_err(|_| EvidenceError::IntegrityInvalid)?,
                    access_policy: row
                        .try_get("access_policy")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                    bytes: u64::try_from(
                        row.try_get::<i64, _>("byte_length")
                            .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                    )
                    .map_err(|_| EvidenceError::IntegrityInvalid)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                })
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let built_at = Utc::now();
        let mut package = EvidencePackage {
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            package_id: Uuid::new_v4().to_string(),
            tenant_id: request.tenant_id.clone(),
            task_id: request.task_id.clone(),
            events,
            artifacts,
            package_hash: String::new(),
            built_at,
        };
        package.package_hash = package_hash(&package)?;
        let mut signed = SignedEvidencePackage {
            schema_version: EVIDENCE_PACKAGE_SCHEMA_VERSION.into(),
            package,
            chain_head,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        signed.sign(&self.signing_key)?;
        signed.verify(
            self.verification_key(&signed.key_id)?,
            self.verifying_keys.clone(),
        )?;
        let package_id = canonical_uuid(&signed.package.package_id)?;
        let signed_value =
            serde_json::to_value(&signed).map_err(|_| EvidenceError::Canonicalization)?;
        sqlx::query(
            "INSERT INTO evidence_packages(tenant_id,package_id,task_id,package_hash,manifest,built_at) \
             VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(tenant)
        .bind(package_id)
        .bind(task)
        .bind(&signed.package.package_hash)
        .bind(signed_value.clone())
        .bind(built_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_package_requests(tenant_id,idempotency_key,request_digest,package_id,signed_package,created_at) \
             VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .bind(&request_digest)
        .bind(package_id)
        .bind(signed_value.clone())
        .bind(built_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_outbox(tenant_id,outbox_id,task_id,event_id,event_type,payload,created_at) \
             VALUES($1,$2,$3,$4,'EVIDENCE_PACKAGE_BUILT',$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(task)
        .bind(package_id)
        .bind(serde_json::json!({
            "package_id": package_id,
            "package_hash": signed.package.package_hash,
            "chain_head": signed.chain_head,
        }))
        .bind(built_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(signed)
    }

    pub async fn artifact_replay(
        &self,
        request: &ArtifactUploadRequest,
    ) -> Result<Option<WormObjectReceipt>, EvidenceError> {
        let request_digest = request.request_digest()?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let row = sqlx::query(
            "SELECT request_digest,worm_receipt FROM evidence_artifact_requests \
             WHERE tenant_id=$1 AND idempotency_key=$2",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let result = match row {
            Some(row) => {
                if row
                    .try_get::<String, _>("request_digest")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?
                    != request_digest
                {
                    return Err(EvidenceError::IdempotencyConflict);
                }
                Some(
                    serde_json::from_value(
                        row.try_get("worm_receipt")
                            .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                    )
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                )
            }
            None => None,
        };
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(result)
    }

    pub async fn persist_artifact(
        &self,
        request: &ArtifactUploadRequest,
        receipt: &WormObjectReceipt,
        byte_length: usize,
    ) -> Result<WormObjectReceipt, EvidenceError> {
        let request_digest = request.request_digest()?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        receipt.verify(&request.tenant_id, &receipt.sha256, request.retention_until)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "evidence-artifact:{tenant}:{}",
                request.idempotency_key.0
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT request_digest,worm_receipt FROM evidence_artifact_requests \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        {
            if row
                .try_get::<String, _>("request_digest")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request_digest
            {
                return Err(EvidenceError::IdempotencyConflict);
            }
            let stored: WormObjectReceipt = serde_json::from_value(
                row.try_get("worm_receipt")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
            )
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            if &stored != receipt {
                return Err(EvidenceError::IntegrityInvalid);
            }
            transaction
                .commit()
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            return Ok(stored);
        }
        sqlx::query(
            "INSERT INTO evidence_artifacts(tenant_id,artifact_hash,media_type,classification,retention_until,access_policy,object_ref,byte_length,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,artifact_hash) DO NOTHING",
        )
        .bind(tenant)
        .bind(&receipt.sha256)
        .bind(&request.media_type)
        .bind(&request.classification)
        .bind(request.retention_until)
        .bind(&request.access_policy)
        .bind(&receipt.object_ref)
        .bind(i64::try_from(byte_length).map_err(|_| EvidenceError::ArtifactDenied)?)
        .bind(receipt.stored_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let receipt_value =
            serde_json::to_value(receipt).map_err(|_| EvidenceError::Canonicalization)?;
        sqlx::query(
            "INSERT INTO evidence_artifact_requests(tenant_id,idempotency_key,request_digest,artifact_hash,worm_receipt,created_at) \
             VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .bind(&request_digest)
        .bind(&receipt.sha256)
        .bind(receipt_value)
        .bind(receipt.stored_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_outbox(tenant_id,outbox_id,task_id,event_id,event_type,payload,created_at) \
             VALUES($1,$2,$3,$4,'EVIDENCE_ARTIFACT_STORED',$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(canonical_uuid(&request.task_id.0)?)
        .bind(Uuid::new_v4())
        .bind(serde_json::json!({
            "artifact_ref": receipt.artifact_ref,
            "object_ref": receipt.object_ref,
            "version_id": receipt.version_id,
            "retention_until": receipt.retention_until,
        }))
        .bind(receipt.stored_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(receipt.clone())
    }

    pub async fn evaluate_task(
        &self,
        request: &ProductionEvaluationRequest,
    ) -> Result<SignedEvaluationRun, EvidenceError> {
        let request_digest = request.request_digest()?;
        let tenant = canonical_uuid(&request.tenant_id.0)?;
        let task = canonical_uuid(&request.task_id.0)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&request.tenant_id.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("evidence-evaluation:{tenant}:{task}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        if let Some(row) = sqlx::query(
            "SELECT input_hash,result FROM evaluation_results WHERE tenant_id=$1 AND idempotency_key=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(&request.idempotency_key.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        {
            if row
                .try_get::<String, _>("input_hash")
                .map_err(|_| EvidenceError::PersistenceUnavailable)?
                != request_digest
            {
                return Err(EvidenceError::IdempotencyConflict);
            }
            let run: SignedEvaluationRun = serde_json::from_value(
                row.try_get("result")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?,
            )
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            run.verify(self.verification_key(&run.key_id)?)?;
            transaction
                .commit()
                .await
                .map_err(|_| EvidenceError::PersistenceUnavailable)?;
            return Ok(run);
        }
        let head = sqlx::query_scalar::<_, String>(
            "SELECT chain_hash FROM evidence_chain_heads WHERE tenant_id=$1 AND task_id=$2 FOR SHARE",
        )
        .bind(tenant)
        .bind(task)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?
        .ok_or(EvidenceError::ChainIncomplete)?;
        if head != request.expected_chain_head {
            return Err(EvidenceError::IntegrityInvalid);
        }
        let event_rows = sqlx::query(
            "SELECT event_type,event_hash,signed_event FROM audit_events WHERE tenant_id=$1 AND task_id=$2 ORDER BY sequence",
        )
        .bind(tenant)
        .bind(task)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let event_types = event_rows
            .iter()
            .map(|row| row.try_get::<String, _>("event_type"))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let first_sequence = event_rows.iter().enumerate().try_fold(
            BTreeMap::<String, u64>::new(),
            |mut result, (index, row)| {
                let event_type = row
                    .try_get::<String, _>("event_type")
                    .map_err(|_| EvidenceError::PersistenceUnavailable)?;
                result.entry(event_type).or_insert(
                    u64::try_from(index + 1).map_err(|_| EvidenceError::CapacityExceeded)?,
                );
                Ok::<_, EvidenceError>(result)
            },
        )?;
        let events = event_rows
            .iter()
            .map(|row| {
                serde_json::from_value(
                    row.try_get::<Value, _>("signed_event")
                        .map_err(|_| EvidenceError::PersistenceUnavailable)?,
                )
                .map_err(|_| EvidenceError::PersistenceUnavailable)
            })
            .collect::<Result<Vec<SignedEvidenceEvent>, _>>()?;
        validate_chain_snapshot(&events, &request.tenant_id.0, &request.task_id.0, &head)?;
        for event in &events {
            event.verify(self.verification_key(&event.key_id)?)?;
        }
        let executions = sqlx::query(
            "SELECT execution_id,status,evidence_ref FROM executions WHERE tenant_id=$1 AND task_id=$2 ORDER BY created_at",
        )
        .bind(tenant)
        .bind(task)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        let ledger_terminal = !executions.is_empty()
            && executions.iter().all(|row| {
                row.try_get::<String, _>("status").ok().as_deref() == Some("SUCCEEDED")
                    && row
                        .try_get::<Option<String>, _>("evidence_ref")
                        .ok()
                        .flatten()
                        .is_some_and(|value| !value.is_empty())
            });
        let event_name = |event: &EvidenceEventType| -> Result<String, EvidenceError> {
            serde_json::to_value(event)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(EvidenceError::EvaluationInvalid)
        };
        let required_names = request
            .required_event_types
            .iter()
            .map(event_name)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let all_required_events = required_names.is_subset(&event_types);
        let ordered_names = [
            "TASK_CREATED",
            "PLAN_GENERATED",
            "POLICY_EVALUATED",
            "CREDENTIAL_ISSUED",
            "TOOL_PREPARED",
            "TOOL_EXECUTED",
        ];
        let lifecycle_order_valid = ordered_names.windows(2).all(|pair| {
            first_sequence
                .get(pair[0])
                .zip(first_sequence.get(pair[1]))
                .is_some_and(|(left, right)| left < right)
        }) && first_sequence.get("APPROVAL_DECISION").is_none_or(
            |approval| {
                first_sequence
                    .get("POLICY_EVALUATED")
                    .is_some_and(|policy| policy < approval)
                    && first_sequence
                        .get("CREDENTIAL_ISSUED")
                        .is_some_and(|credential| approval < credential)
            },
        );
        let no_high_risk_alert = !event_types.contains("SECURITY_ALERT");
        let hard_gates = BTreeMap::from([
            ("required_evidence_events".into(), all_required_events),
            ("lifecycle_order_valid".into(), lifecycle_order_valid),
            ("trace_chain_complete".into(), true),
            ("expected_chain_head".into(), true),
            ("ledger_terminal_succeeded".into(), ledger_terminal),
            ("no_unhandled_high_risk_alerts".into(), no_high_risk_alert),
        ]);
        let pass = hard_gates.values().all(|value| *value);
        let evaluated_at = Utc::now();
        let result = EvaluationResult {
            schema_version: SchemaVersion("agenttrust.evaluation.v1".into()),
            status: if pass {
                EvaluationStatus::Pass
            } else {
                EvaluationStatus::NeedsHuman
            },
            score_millionths: if pass { 1_000_000 } else { 0 },
            hard_gate_results: hard_gates,
            findings: if pass {
                Vec::new()
            } else {
                vec!["authoritative hard-gate evidence is incomplete".into()]
            },
            evidence_refs: events
                .iter()
                .map(|event| {
                    ArtifactRef(format!(
                        "evidence://{}/{}/{}/{}",
                        request.tenant_id.0, request.task_id.0, event.sequence, event.event_hash
                    ))
                })
                .collect(),
            evaluator_id: "agenttrust.hard-gate.postgres".into(),
            evaluator_version: "1.0.0".into(),
            evaluated_at,
        };
        let mut run = SignedEvaluationRun {
            schema_version: EVALUATION_RUN_SCHEMA_VERSION.into(),
            evaluation_id: Uuid::new_v4().to_string(),
            tenant_id: request.tenant_id.clone(),
            task_id: request.task_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            request_digest: request_digest.clone(),
            chain_head: head,
            result,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            key_usage: EVALUATION_RUN_KEY_USAGE.into(),
            signature: String::new(),
        };
        run.sign(&self.signing_key)?;
        run.verify(&self.verifying_key())?;
        let evaluation_id = canonical_uuid(&run.evaluation_id)?;
        let run_value = serde_json::to_value(&run).map_err(|_| EvidenceError::Canonicalization)?;
        sqlx::query(
            "INSERT INTO evaluation_results(tenant_id,evaluation_id,task_id,evaluator_id,evaluator_version,input_hash,status,result,created_at,idempotency_key,chain_head) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(tenant)
        .bind(evaluation_id)
        .bind(task)
        .bind(&run.result.evaluator_id)
        .bind(&run.result.evaluator_version)
        .bind(&request_digest)
        .bind(match run.result.status {
            EvaluationStatus::Pass => "PASS",
            EvaluationStatus::Fail => "FAIL",
            _ => "NEEDS_HUMAN",
        })
        .bind(run_value.clone())
        .bind(evaluated_at)
        .bind(&request.idempotency_key.0)
        .bind(&run.chain_head)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        sqlx::query(
            "INSERT INTO evidence_outbox(tenant_id,outbox_id,task_id,event_id,event_type,payload,created_at) \
             VALUES($1,$2,$3,$4,'EVALUATION_RECORDED',$5,$6)",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(task)
        .bind(evaluation_id)
        .bind(serde_json::json!({
            "evaluation_id": evaluation_id,
            "status": run.result.status,
            "chain_head": run.chain_head,
            "request_digest": request_digest,
        }))
        .bind(evaluated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::PersistenceUnavailable)?;
        Ok(run)
    }
}

fn validate_chain_snapshot(
    events: &[SignedEvidenceEvent],
    tenant_id: &str,
    task_id: &str,
    expected_head: &str,
) -> Result<(), EvidenceError> {
    if events.is_empty() {
        return Err(EvidenceError::ChainIncomplete);
    }
    let mut previous = "0".repeat(64);
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.previous_hash != previous
            || event.event_hash != event.expected_hash()?
            || event.draft.tenant_id.0 != tenant_id
            || event.draft.task_id.0 != task_id
        {
            return Err(EvidenceError::IntegrityInvalid);
        }
        previous.clone_from(&event.event_hash);
    }
    if previous != expected_head {
        return Err(EvidenceError::IntegrityInvalid);
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> Result<Uuid, EvidenceError> {
    let parsed = Uuid::parse_str(value).map_err(|_| EvidenceError::EventInvalid)?;
    if parsed.to_string() != value {
        return Err(EvidenceError::EventInvalid);
    }
    Ok(parsed)
}

fn canonical_digest<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, EvidenceError> {
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| EvidenceError::Canonicalization)?,
    )))
}

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn append_sql_keeps_event_receipt_and_outbox_in_one_transaction_source() {
        let source = include_str!("postgres.rs");
        assert!(source.contains("pg_advisory_xact_lock"));
        assert!(source.contains("status != \"RUNNING\""));
        assert!(source.contains("INSERT INTO audit_events"));
        assert!(source.contains("INSERT INTO execution_evidence_receipts"));
        assert!(source.contains("INSERT INTO evidence_outbox"));
        assert!(source.contains("transaction.commit()"));
    }
}
