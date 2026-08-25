use super::*;
use agent_trust_contracts::{
    IdempotencyKey, SignedWorkloadCredentialBindingReceipt, TenantId,
    WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE,
    WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION,
    WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION, WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION,
    WorkloadCredentialBindingRequest, WorkloadCredentialClaims, WorkloadCredentialIssuance,
};
pub use agent_trust_contracts::{
    SignedWorkloadCredentialConsumptionReceipt, WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE,
    WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION,
    WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION, WorkloadCredentialConsumptionRequest,
};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::de::DeserializeOwned;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use zeroize::Zeroizing;

pub const CREDENTIAL_LIFECYCLE_SCHEMA_VERSION: &str = "agenttrust.credential-lifecycle.v1";
const EXPECTED_AUDIENCE: &str = "tool-proxy";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialLifecycleRequest {
    pub schema_version: String,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialLifecycleReceipt {
    pub schema_version: String,
    pub operation: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub tenant_id: TenantId,
    pub state: String,
    pub revocation_epoch: u64,
    pub event_ref: String,
    pub changed: bool,
}

/// Safe enterprise-console projection. Raw handles, handle hashes, claims and encrypted
/// idempotency payloads are deliberately absent from this type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeCredentialView {
    pub schema_version: String,
    pub credential_id: String,
    pub agent_instance_id: String,
    pub task_id: String,
    pub step_id: String,
    pub action_hash: String,
    pub audience: String,
    pub tool_id: String,
    pub credential_profile: String,
    pub resource: String,
    pub target_profile: String,
    pub claims_digest: String,
    pub binding_receipt_digest: String,
    pub status: String,
    pub remaining_uses: u32,
    pub revocation_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct CredentialAuthoritySigner {
    pub issuer: String,
    pub key_id: String,
    key: Arc<SigningKey>,
}

impl CredentialAuthoritySigner {
    pub fn new(issuer: String, key_id: String, key: SigningKey) -> Result<Self, IdentityError> {
        if !bounded_identifier(&issuer, 256) || !bounded_identifier(&key_id, 256) {
            return Err(IdentityError::SigningKeyInvalid);
        }
        Ok(Self {
            issuer,
            key_id,
            key: Arc::new(key),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

#[derive(Clone)]
pub struct IdentityResponseProtector {
    active_key_id: String,
    keys: BTreeMap<String, Arc<LessSafeKey>>,
}

struct ProtectedResponse {
    ciphertext: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    key_id: String,
    digest: String,
}

impl IdentityResponseProtector {
    pub fn new(
        active_key_id: String,
        material: BTreeMap<String, [u8; 32]>,
    ) -> Result<Self, IdentityError> {
        if !bounded_identifier(&active_key_id, 128)
            || material.is_empty()
            || material.len() > 8
            || !material.contains_key(&active_key_id)
        {
            return Err(IdentityError::ResponseProtectionInvalid);
        }
        let mut keys = BTreeMap::new();
        for (key_id, raw) in material {
            if !bounded_identifier(&key_id, 128) {
                return Err(IdentityError::ResponseProtectionInvalid);
            }
            let raw = Zeroizing::new(raw);
            let key = UnboundKey::new(&AES_256_GCM, &*raw)
                .map_err(|_| IdentityError::ResponseProtectionInvalid)?;
            keys.insert(key_id, Arc::new(LessSafeKey::new(key)));
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    fn seal<T: Serialize>(
        &self,
        request_digest: &str,
        response: &T,
    ) -> Result<ProtectedResponse, IdentityError> {
        let plaintext = serde_jcs::to_vec(response).map_err(|_| IdentityError::RequestInvalid)?;
        if plaintext.len() > 1_048_576 {
            return Err(IdentityError::ResponseProtectionInvalid);
        }
        let digest = sha256(&plaintext);
        let mut nonce = [0_u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| IdentityError::ResponseProtectionInvalid)?;
        let mut ciphertext = Zeroizing::new(plaintext);
        let aad = idempotency_aad(request_digest);
        self.keys
            .get(&self.active_key_id)
            .ok_or(IdentityError::ResponseProtectionInvalid)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_bytes()),
                &mut *ciphertext,
            )
            .map_err(|_| IdentityError::ResponseProtectionInvalid)?;
        Ok(ProtectedResponse {
            ciphertext: ciphertext.to_vec(),
            nonce,
            key_id: self.active_key_id.clone(),
            digest,
        })
    }

    fn open<T: DeserializeOwned>(
        &self,
        request_digest: &str,
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
        expected_digest: &str,
    ) -> Result<T, IdentityError> {
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| IdentityError::ResponseProtectionInvalid)?;
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        let aad = idempotency_aad(request_digest);
        let parsed = {
            let opened = self
                .keys
                .get(key_id)
                .ok_or(IdentityError::ResponseProtectionInvalid)?
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad.as_bytes()),
                    &mut *plaintext,
                )
                .map_err(|_| IdentityError::ResponseProtectionInvalid)?;
            if sha256(opened) != expected_digest {
                Err(IdentityError::ResponseProtectionInvalid)
            } else {
                serde_json::from_slice(opened).map_err(|_| IdentityError::ResponseProtectionInvalid)
            }
        };
        parsed
    }
}

#[derive(Clone)]
pub struct PostgresCredentialAuthority {
    pool: PgPool,
    signer: CredentialAuthoritySigner,
    protector: IdentityResponseProtector,
}

impl PostgresCredentialAuthority {
    pub fn new(
        pool: PgPool,
        signer: CredentialAuthoritySigner,
        protector: IdentityResponseProtector,
    ) -> Self {
        Self {
            pool,
            signer,
            protector,
        }
    }

    async fn tenant_transaction<'a>(
        &'a self,
        tenant: &TenantId,
    ) -> Result<(Uuid, Transaction<'a, Postgres>), IdentityError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok((tenant_uuid, transaction))
    }

    pub async fn list_authoritative_credentials(
        &self,
        tenant: &TenantId,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<Vec<AuthoritativeCredentialView>, IdentityError> {
        if !(1..=100).contains(&limit) {
            return Err(IdentityError::RequestInvalid);
        }
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let rows = sqlx::query(
            "SELECT credential_id,agent_instance_id,task_id,step_id,action_hash,audience,tool_id,\
                    credential_profile,resource,target_profile,claims_digest,binding_receipt_digest,\
                    remaining_uses,revocation_epoch,issued_at,expires_at,revoked_at \
             FROM credential_handles WHERE tenant_id=$1 \
             ORDER BY issued_at DESC,credential_id DESC LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let remaining_uses = row
                .try_get::<i32, _>("remaining_uses")
                .map_err(|_| IdentityError::StoreFailure)?;
            let revocation_epoch = row
                .try_get::<i64, _>("revocation_epoch")
                .map_err(|_| IdentityError::StoreFailure)?;
            let expires_at = row
                .try_get::<DateTime<Utc>, _>("expires_at")
                .map_err(|_| IdentityError::StoreFailure)?;
            let revoked_at = row
                .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
                .map_err(|_| IdentityError::StoreFailure)?;
            if remaining_uses < 0 || revocation_epoch < 0 {
                return Err(IdentityError::StoreFailure);
            }
            let status = if revoked_at.is_some() {
                "REVOKED"
            } else if remaining_uses == 0 {
                "CONSUMED"
            } else if expires_at <= now {
                "EXPIRED"
            } else {
                "ACTIVE"
            };
            result.push(AuthoritativeCredentialView {
                schema_version: "agenttrust.credential-view.v1".into(),
                credential_id: row
                    .try_get::<Uuid, _>("credential_id")
                    .map_err(|_| IdentityError::StoreFailure)?
                    .to_string(),
                agent_instance_id: row
                    .try_get::<Uuid, _>("agent_instance_id")
                    .map_err(|_| IdentityError::StoreFailure)?
                    .to_string(),
                task_id: row
                    .try_get::<Uuid, _>("task_id")
                    .map_err(|_| IdentityError::StoreFailure)?
                    .to_string(),
                step_id: row
                    .try_get::<Uuid, _>("step_id")
                    .map_err(|_| IdentityError::StoreFailure)?
                    .to_string(),
                action_hash: row
                    .try_get("action_hash")
                    .map_err(|_| IdentityError::StoreFailure)?,
                audience: row
                    .try_get("audience")
                    .map_err(|_| IdentityError::StoreFailure)?,
                tool_id: row
                    .try_get("tool_id")
                    .map_err(|_| IdentityError::StoreFailure)?,
                credential_profile: row
                    .try_get("credential_profile")
                    .map_err(|_| IdentityError::StoreFailure)?,
                resource: row
                    .try_get("resource")
                    .map_err(|_| IdentityError::StoreFailure)?,
                target_profile: row
                    .try_get("target_profile")
                    .map_err(|_| IdentityError::StoreFailure)?,
                claims_digest: row
                    .try_get("claims_digest")
                    .map_err(|_| IdentityError::StoreFailure)?,
                binding_receipt_digest: row
                    .try_get("binding_receipt_digest")
                    .map_err(|_| IdentityError::StoreFailure)?,
                status: status.into(),
                remaining_uses: u32::try_from(remaining_uses)
                    .map_err(|_| IdentityError::StoreFailure)?,
                revocation_epoch: u64::try_from(revocation_epoch)
                    .map_err(|_| IdentityError::StoreFailure)?,
                issued_at: row
                    .try_get("issued_at")
                    .map_err(|_| IdentityError::StoreFailure)?,
                expires_at,
                revoked_at,
            });
        }
        transaction
            .commit()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok(result)
    }

    pub async fn issue(
        &self,
        request: &WorkloadCredentialBindingRequest,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<WorkloadCredentialIssuance<CredentialHandle>, IdentityError> {
        request
            .validate()
            .map_err(|_| IdentityError::RequestInvalid)?;
        validate_binding_request(request)?;
        validate_actor(actor_subject)?;
        let request_digest = canonical_digest(request)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &request.tenant_id,
            &request.idempotency_key,
        )
        .await?;
        if let Some(response) = self
            .load_response(
                &mut transaction,
                tenant_uuid,
                &request.idempotency_key,
                "ISSUE",
                &request_digest,
            )
            .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
            return Ok(response);
        }
        require_signing_key(&mut transaction, tenant_uuid, &self.signer, true).await?;
        require_issue_allowed(&mut transaction, tenant_uuid, request).await?;

        let credential_id = Uuid::new_v4().to_string();
        let credential_handle = random_handle()?;
        let claims = WorkloadCredentialClaims {
            schema_version: WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION.into(),
            idempotency_key: request.idempotency_key.clone(),
            credential_id: credential_id.clone(),
            tenant_id: request.tenant_id.clone(),
            agent_instance_id: request.agent_instance_id.clone(),
            task_id: request.task_id.clone(),
            step_id: request.step_id.clone(),
            action_hash: request.action_hash.clone(),
            policy_decision_id: request.policy_decision_id.clone(),
            tool_id: request.tool_id.clone(),
            credential_profile: request.credential_profile.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            target_profile: request.target_profile.clone(),
            audience: request.audience.clone(),
            revocation_epoch: request.revocation_epoch,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(request.ttl_seconds as i64),
            max_uses: request.max_uses,
        };
        let mut receipt = SignedWorkloadCredentialBindingReceipt {
            schema_version: WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION.into(),
            credential_handle_sha256: sha256(credential_handle.as_bytes()),
            claims,
            claims_digest: String::new(),
            issuer: self.signer.issuer.clone(),
            key_id: self.signer.key_id.clone(),
            key_usage: WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE.into(),
            signature: String::new(),
        };
        receipt
            .sign(&self.signer.key)
            .map_err(|_| IdentityError::SigningKeyInvalid)?;
        let receipt_digest = canonical_digest(&receipt)?;
        let handle_sha256 = receipt.credential_handle_sha256.clone();
        let issuance = WorkloadCredentialIssuance {
            workload_credential: CredentialHandle(credential_handle),
            binding_receipt: receipt.clone(),
        };
        let claims_value =
            serde_json::to_value(&receipt.claims).map_err(|_| IdentityError::RequestInvalid)?;
        sqlx::query(
            "INSERT INTO credential_handles \
             (credential_id,tenant_id,agent_instance_id,task_id,step_id,action_hash,audience,scope_hash,\
              max_uses,remaining_uses,revocation_epoch,issued_at,expires_at,handle_sha256,\
              policy_decision_id,tool_id,credential_profile,operation,resource,target_profile,claims,\
              claims_digest,binding_receipt_digest,issuer,key_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,1,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)",
        )
        .bind(parse_uuid(&credential_id)?)
        .bind(tenant_uuid)
        .bind(parse_uuid(&request.agent_instance_id.0)?)
        .bind(parse_uuid(&request.task_id.0)?)
        .bind(parse_uuid(&request.step_id.0)?)
        .bind(&request.action_hash.0)
        .bind(&request.audience)
        .bind(&receipt.claims_digest)
        .bind(i64::try_from(request.revocation_epoch).map_err(|_| IdentityError::RequestInvalid)?)
        .bind(receipt.claims.issued_at)
        .bind(receipt.claims.expires_at)
        .bind(&handle_sha256)
        .bind(&request.policy_decision_id)
        .bind(&request.tool_id.0)
        .bind(&request.credential_profile)
        .bind(&request.operation)
        .bind(&request.resource)
        .bind(&request.target_profile)
        .bind(claims_value)
        .bind(&receipt.claims_digest)
        .bind(&receipt_digest)
        .bind(&self.signer.issuer)
        .bind(&self.signer.key_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?;
        let event_id = append_event(
            &mut transaction,
            tenant_uuid,
            "CREDENTIAL_ISSUED",
            Some(parse_uuid(&credential_id)?),
            Some(parse_uuid(&request.task_id.0)?),
            Some(parse_uuid(&request.agent_instance_id.0)?),
            &receipt.claims_digest,
            actor_subject,
            serde_json::json!({
                "credential_id":credential_id,
                "claims_digest":receipt.claims_digest,
                "revocation_epoch":request.revocation_epoch,
                "max_uses":1
            }),
        )
        .await?;
        append_outbox(
            &mut transaction,
            tenant_uuid,
            event_id,
            "CREDENTIAL_ISSUED",
            Some(parse_uuid(&receipt.claims.credential_id)?),
            &receipt.claims_digest,
        )
        .await?;
        self.store_response(
            &mut transaction,
            tenant_uuid,
            &request.idempotency_key,
            "ISSUE",
            &request_digest,
            &issuance,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok(issuance)
    }

    pub async fn consume(
        &self,
        request: &WorkloadCredentialConsumptionRequest,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<SignedWorkloadCredentialConsumptionReceipt, IdentityError> {
        request
            .validate()
            .map_err(|_| IdentityError::RequestInvalid)?;
        if !valid_handle(&request.credential_handle)
            || !canonical_uuid(&request.tenant_id.0)
            || !canonical_uuid(&request.agent_instance_id.0)
            || !canonical_uuid(&request.task_id.0)
            || !canonical_uuid(&request.step_id.0)
        {
            return Err(IdentityError::RequestInvalid);
        }
        validate_actor(actor_subject)?;
        let request_digest = canonical_digest(request)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &request.tenant_id,
            &request.idempotency_key,
        )
        .await?;
        if let Some(response) = self
            .load_response(
                &mut transaction,
                tenant_uuid,
                &request.idempotency_key,
                "CONSUME",
                &request_digest,
            )
            .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
            return Ok(response);
        }
        let handle_sha256 = sha256(request.credential_handle.as_bytes());
        let row = sqlx::query(
            "SELECT credential_id,claims,claims_digest,binding_receipt_digest,issuer,key_id,\
                    remaining_uses,revoked_at,expires_at \
             FROM credential_handles WHERE tenant_id=$1 AND handle_sha256=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&handle_sha256)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?
        .ok_or(IdentityError::CredentialNotFound)?;
        let claims: WorkloadCredentialClaims = serde_json::from_value(
            row.try_get("claims")
                .map_err(|_| IdentityError::StoreFailure)?,
        )
        .map_err(|_| IdentityError::StoreFailure)?;
        let stored_claims_digest: String = row
            .try_get("claims_digest")
            .map_err(|_| IdentityError::StoreFailure)?;
        let stored_receipt_digest: String = row
            .try_get("binding_receipt_digest")
            .map_err(|_| IdentityError::StoreFailure)?;
        if row
            .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
            .map_err(|_| IdentityError::StoreFailure)?
            .is_some()
        {
            return Err(IdentityError::Revoked);
        }
        let key = load_verification_key(
            &mut transaction,
            tenant_uuid,
            &request.binding_receipt.issuer,
            &request.binding_receipt.key_id,
        )
        .await?;
        let ttl_seconds = u64::try_from(
            (request.binding_receipt.claims.expires_at - request.binding_receipt.claims.issued_at)
                .num_seconds(),
        )
        .map_err(|_| IdentityError::RequestInvalid)?;
        let binding_request =
            binding_request_from_claims(&request.binding_receipt.claims, ttl_seconds);
        request
            .binding_receipt
            .verify(&key, &binding_request, &request.credential_handle, now)
            .map_err(|_| IdentityError::SignatureInvalid)?;
        if claims != request.binding_receipt.claims
            || request.claims_digest != stored_claims_digest
            || request.claims_digest != request.binding_receipt.claims_digest
            || canonical_digest(&request.binding_receipt)? != stored_receipt_digest
            || !consumption_scope_matches(request, &claims)
        {
            return Err(IdentityError::CredentialScopeInvalid);
        }
        require_consumption_allowed(&mut transaction, tenant_uuid, &claims, now).await?;
        let remaining_uses: i32 = row
            .try_get("remaining_uses")
            .map_err(|_| IdentityError::StoreFailure)?;
        if remaining_uses != 1 {
            return Err(IdentityError::UsageExceeded);
        }
        let credential_id: Uuid = row
            .try_get("credential_id")
            .map_err(|_| IdentityError::StoreFailure)?;
        let consumed = sqlx::query(
            "UPDATE credential_handles SET remaining_uses=remaining_uses-1 \
             WHERE tenant_id=$1 AND credential_id=$2 AND remaining_uses=1 AND revoked_at IS NULL",
        )
        .bind(tenant_uuid)
        .bind(credential_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?;
        if consumed.rows_affected() != 1 {
            return Err(IdentityError::UsageExceeded);
        }
        let scope_digest = request
            .scope_digest()
            .map_err(|_| IdentityError::RequestInvalid)?;
        let mut receipt = SignedWorkloadCredentialConsumptionReceipt {
            schema_version: WORKLOAD_CREDENTIAL_CONSUMPTION_RECEIPT_SCHEMA_VERSION.into(),
            idempotency_key: request.idempotency_key.clone(),
            consumption_id: Uuid::new_v4().to_string(),
            credential_id: credential_id.to_string(),
            tenant_id: request.tenant_id.clone(),
            action_hash: request.action_hash.clone(),
            audience: request.audience.clone(),
            revocation_epoch: request.revocation_epoch,
            claims_digest: request.claims_digest.clone(),
            scope_digest: scope_digest.clone(),
            consumed_at: now,
            remaining_uses: 0,
            issuer: self.signer.issuer.clone(),
            key_id: self.signer.key_id.clone(),
            key_usage: WORKLOAD_CREDENTIAL_CONSUMPTION_KEY_USAGE.into(),
            signature: String::new(),
        };
        require_signing_key(&mut transaction, tenant_uuid, &self.signer, true).await?;
        receipt
            .sign(&self.signer.key, request)
            .map_err(|_| IdentityError::SigningKeyInvalid)?;
        let event_id = append_event(
            &mut transaction,
            tenant_uuid,
            "CREDENTIAL_CONSUMED",
            Some(credential_id),
            Some(parse_uuid(&claims.task_id.0)?),
            Some(parse_uuid(&claims.agent_instance_id.0)?),
            &scope_digest,
            actor_subject,
            serde_json::json!({
                "credential_id":credential_id,
                "claims_digest":request.claims_digest,
                "scope_digest":scope_digest,
                "remaining_uses":0
            }),
        )
        .await?;
        append_outbox(
            &mut transaction,
            tenant_uuid,
            event_id,
            "CREDENTIAL_CONSUMED",
            Some(credential_id),
            &scope_digest,
        )
        .await?;
        self.store_response(
            &mut transaction,
            tenant_uuid,
            &request.idempotency_key,
            "CONSUME",
            &request_digest,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn revoke_credential(
        &self,
        tenant: &TenantId,
        credential_id: &str,
        request: &CredentialLifecycleRequest,
        idempotency_key: &IdempotencyKey,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialLifecycleReceipt, IdentityError> {
        validate_lifecycle_request(request, true)?;
        validate_actor(actor_subject)?;
        let credential_uuid = parse_uuid(credential_id)?;
        let digest = lifecycle_digest("REVOKE_CREDENTIAL", tenant, credential_id, request)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_idempotency(&mut transaction, tenant, idempotency_key).await?;
        if let Some(response) = self
            .load_response(
                &mut transaction,
                tenant_uuid,
                idempotency_key,
                "REVOKE_CREDENTIAL",
                &digest,
            )
            .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
            return Ok(response);
        }
        let row = sqlx::query(
            "SELECT claims_digest,task_id,agent_instance_id,revoked_at FROM credential_handles \
             WHERE tenant_id=$1 AND credential_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(credential_uuid)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?
        .ok_or(IdentityError::CredentialNotFound)?;
        let changed = row
            .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
            .map_err(|_| IdentityError::StoreFailure)?
            .is_none();
        let scope_digest: String = row
            .try_get("claims_digest")
            .map_err(|_| IdentityError::StoreFailure)?;
        if changed {
            sqlx::query(
                "UPDATE credential_handles SET revoked_at=$3,revoked_reason=$4 \
                 WHERE tenant_id=$1 AND credential_id=$2 AND revoked_at IS NULL",
            )
            .bind(tenant_uuid)
            .bind(credential_uuid)
            .bind(now)
            .bind(request.reason_code.as_deref())
            .execute(&mut *transaction)
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
            insert_revocation(
                &mut transaction,
                tenant_uuid,
                "credential",
                credential_id,
                request.reason_code.as_deref().unwrap_or_default(),
                now,
            )
            .await?;
        }
        let event_id = append_event(
            &mut transaction,
            tenant_uuid,
            "CREDENTIAL_REVOKED",
            Some(credential_uuid),
            row.try_get("task_id").map_err(|_| IdentityError::StoreFailure)?,
            row.try_get("agent_instance_id").map_err(|_| IdentityError::StoreFailure)?,
            &scope_digest,
            actor_subject,
            serde_json::json!({"credential_id":credential_id,"scope_digest":scope_digest,"changed":changed}),
        )
        .await?;
        append_outbox(
            &mut transaction,
            tenant_uuid,
            event_id,
            "CREDENTIAL_REVOKED",
            Some(credential_uuid),
            &scope_digest,
        )
        .await?;
        let epoch = current_epoch(&mut transaction, tenant_uuid).await?;
        let receipt = lifecycle_receipt(
            "REVOKE_CREDENTIAL",
            "credential",
            credential_id,
            tenant,
            "REVOKED",
            epoch,
            event_id,
            changed,
        );
        self.store_response(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "REVOKE_CREDENTIAL",
            &digest,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn set_task_state(
        &self,
        tenant: &TenantId,
        task_id: &str,
        operation: &str,
        request: &CredentialLifecycleRequest,
        idempotency_key: &IdempotencyKey,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialLifecycleReceipt, IdentityError> {
        let (target, event_type, reason_required, terminal) = match operation {
            "PAUSE_TASK" => ("PAUSED", "TASK_PAUSED", false, false),
            "UNFREEZE_TASK" => ("ACTIVE", "TASK_UNFROZEN", false, false),
            "REVOKE_TASK" => ("CANCELED", "TASK_CANCELED", true, true),
            "CANCEL_TASK" => ("CANCELED", "TASK_CANCELED", true, true),
            "KILL_TASK" => ("KILLED", "TASK_KILLED", true, true),
            _ => return Err(IdentityError::RequestInvalid),
        };
        validate_lifecycle_request(request, reason_required)?;
        validate_actor(actor_subject)?;
        let task_uuid = parse_uuid(task_id)?;
        let digest = lifecycle_digest(operation, tenant, task_id, request)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_idempotency(&mut transaction, tenant, idempotency_key).await?;
        if let Some(response) = self
            .load_response(
                &mut transaction,
                tenant_uuid,
                idempotency_key,
                operation,
                &digest,
            )
            .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
            return Ok(response);
        }
        advisory_lock(
            &mut transaction,
            &format!("identity:task:{}:{task_id}", tenant.0),
        )
        .await?;
        let previous = sqlx::query_scalar::<_, String>(
            "SELECT state FROM identity_task_lifecycle WHERE tenant_id=$1 AND task_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(task_uuid)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?
        .unwrap_or_else(|| "ACTIVE".into());
        if matches!(previous.as_str(), "CANCELED" | "KILLED") && previous != target {
            return Err(IdentityError::SubjectRevoked);
        }
        let changed = previous != target;
        if previous == "ACTIVE" && target == "ACTIVE" {
            // A missing row is already logically active; do not manufacture mutable state.
        } else {
            sqlx::query(
                "INSERT INTO identity_task_lifecycle \
                 (tenant_id,task_id,state,reason_code,updated_by,updated_at) VALUES ($1,$2,$3,$4,$5,$6) \
                 ON CONFLICT (tenant_id,task_id) DO UPDATE SET state=EXCLUDED.state,\
                   reason_code=EXCLUDED.reason_code,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at",
            )
            .bind(tenant_uuid)
            .bind(task_uuid)
            .bind(target)
            .bind(if terminal { request.reason_code.as_deref() } else { None })
            .bind(actor_subject)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        }
        if terminal {
            insert_revocation(
                &mut transaction,
                tenant_uuid,
                "task",
                task_id,
                request.reason_code.as_deref().unwrap_or_default(),
                now,
            )
            .await?;
            sqlx::query(
                "UPDATE credential_handles SET revoked_at=COALESCE(revoked_at,$3),\
                 revoked_reason=COALESCE(revoked_reason,$4) WHERE tenant_id=$1 AND task_id=$2",
            )
            .bind(tenant_uuid)
            .bind(task_uuid)
            .bind(now)
            .bind(request.reason_code.as_deref())
            .execute(&mut *transaction)
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        }
        let scope_digest = sha256(format!("task:{}:{task_id}", tenant.0).as_bytes());
        let event_id = append_event(
            &mut transaction,
            tenant_uuid,
            event_type,
            None,
            Some(task_uuid),
            None,
            &scope_digest,
            actor_subject,
            serde_json::json!({"task_id":task_id,"state":target,"changed":changed}),
        )
        .await?;
        append_outbox(
            &mut transaction,
            tenant_uuid,
            event_id,
            event_type,
            None,
            &scope_digest,
        )
        .await?;
        let epoch = current_epoch(&mut transaction, tenant_uuid).await?;
        let receipt = lifecycle_receipt(
            operation, "task", task_id, tenant, target, epoch, event_id, changed,
        );
        self.store_response(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            operation,
            &digest,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn revoke_agent_or_tenant(
        &self,
        tenant: &TenantId,
        subject_kind: &str,
        subject_id: &str,
        request: &CredentialLifecycleRequest,
        idempotency_key: &IdempotencyKey,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialLifecycleReceipt, IdentityError> {
        validate_lifecycle_request(request, true)?;
        validate_actor(actor_subject)?;
        let (operation, event_type, agent_uuid) = match subject_kind {
            "agent" => (
                "REVOKE_AGENT",
                "AGENT_REVOKED",
                Some(parse_uuid(subject_id)?),
            ),
            "tenant" if subject_id == tenant.0 => ("REVOKE_TENANT", "TENANT_REVOKED", None),
            _ => return Err(IdentityError::RequestInvalid),
        };
        let digest = lifecycle_digest(operation, tenant, subject_id, request)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        lock_idempotency(&mut transaction, tenant, idempotency_key).await?;
        if let Some(response) = self
            .load_response(
                &mut transaction,
                tenant_uuid,
                idempotency_key,
                operation,
                &digest,
            )
            .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
            return Ok(response);
        }
        if let Some(agent_uuid) = agent_uuid {
            let exists = sqlx::query_scalar::<_, Uuid>(
                "SELECT agent_instance_id FROM agent_principals \
                 WHERE tenant_id=$1 AND agent_instance_id=$2 FOR UPDATE",
            )
            .bind(tenant_uuid)
            .bind(agent_uuid)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| IdentityError::StoreFailure)?
            .is_some();
            if !exists {
                return Err(IdentityError::OwnershipUnknown);
            }
        }
        let changed = insert_revocation(
            &mut transaction,
            tenant_uuid,
            subject_kind,
            subject_id,
            request.reason_code.as_deref().unwrap_or_default(),
            now,
        )
        .await?;
        let epoch = if subject_kind == "tenant" && changed {
            sqlx::query_scalar::<_, i64>(
                "INSERT INTO identity_tenant_epochs(tenant_id,revocation_epoch) VALUES ($1,1) \
                 ON CONFLICT (tenant_id) DO UPDATE SET revocation_epoch=identity_tenant_epochs.revocation_epoch+1,updated_at=$2 \
                 RETURNING revocation_epoch",
            )
            .bind(tenant_uuid)
            .bind(now)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| IdentityError::StoreFailure)?
        } else {
            current_epoch(&mut transaction, tenant_uuid).await? as i64
        };
        let update = if let Some(agent_uuid) = agent_uuid {
            sqlx::query(
                "UPDATE credential_handles SET revoked_at=COALESCE(revoked_at,$3),\
                 revoked_reason=COALESCE(revoked_reason,$4) WHERE tenant_id=$1 AND agent_instance_id=$2",
            )
            .bind(tenant_uuid)
            .bind(agent_uuid)
            .bind(now)
            .bind(request.reason_code.as_deref())
            .execute(&mut *transaction)
            .await
        } else {
            sqlx::query(
                "UPDATE credential_handles SET revoked_at=COALESCE(revoked_at,$2),\
                 revoked_reason=COALESCE(revoked_reason,$3) WHERE tenant_id=$1",
            )
            .bind(tenant_uuid)
            .bind(now)
            .bind(request.reason_code.as_deref())
            .execute(&mut *transaction)
            .await
        };
        update.map_err(|_| IdentityError::StoreFailure)?;
        let scope_digest = sha256(format!("{subject_kind}:{}:{subject_id}", tenant.0).as_bytes());
        let event_id = append_event(
            &mut transaction,
            tenant_uuid,
            event_type,
            None,
            None,
            agent_uuid,
            &scope_digest,
            actor_subject,
            serde_json::json!({"subject_kind":subject_kind,"subject_id":subject_id,"changed":changed}),
        )
        .await?;
        append_outbox(
            &mut transaction,
            tenant_uuid,
            event_id,
            event_type,
            None,
            &scope_digest,
        )
        .await?;
        let receipt = lifecycle_receipt(
            operation,
            subject_kind,
            subject_id,
            tenant,
            "REVOKED",
            u64::try_from(epoch).map_err(|_| IdentityError::StoreFailure)?,
            event_id,
            changed,
        );
        self.store_response(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            operation,
            &digest,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn ready(&self, tenants: &BTreeSet<TenantId>) -> bool {
        let check = async {
            if tenants.is_empty() {
                return Err(IdentityError::ProductionTrustNotConfigured);
            }
            let rls = sqlx::query_scalar::<_, bool>(
                "SELECT count(*)=10 AND bool_and(c.relrowsecurity AND c.relforcerowsecurity) \
                 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                 WHERE n.nspname='public' AND c.relname=ANY($1::text[])",
            )
            .bind(vec![
                "agent_principals",
                "credential_profiles",
                "credential_handles",
                "identity_revocations",
                "identity_tenant_epochs",
                "identity_task_lifecycle",
                "identity_credential_signing_keys",
                "identity_credential_idempotency",
                "identity_credential_events",
                "identity_credential_outbox",
            ])
            .fetch_one(&self.pool)
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
            let privileges = sqlx::query_scalar::<_, bool>(
                "SELECT \
                 has_table_privilege('public.agent_principals','SELECT') AND \
                 has_table_privilege('public.credential_profiles','SELECT') AND \
                 has_table_privilege('public.credential_handles','SELECT,INSERT,UPDATE') AND \
                 has_table_privilege('public.identity_revocations','SELECT,INSERT') AND \
                 has_table_privilege('public.identity_tenant_epochs','SELECT,INSERT,UPDATE') AND \
                 has_table_privilege('public.identity_task_lifecycle','SELECT,INSERT,UPDATE') AND \
                 has_table_privilege('public.identity_credential_signing_keys','SELECT') AND \
                 has_table_privilege('public.identity_credential_idempotency','SELECT,INSERT') AND \
                 has_table_privilege('public.identity_credential_events','INSERT') AND \
                 has_table_privilege('public.identity_credential_outbox','INSERT') AND \
                 NOT has_table_privilege('public.agent_principals','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.credential_profiles','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.credential_handles','DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_revocations','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_tenant_epochs','DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_task_lifecycle','DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_credential_signing_keys','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_credential_idempotency','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_credential_events','SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                 NOT has_table_privilege('public.identity_credential_outbox','SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|_| IdentityError::StoreFailure)?;
            if !rls || !privileges {
                return Err(IdentityError::StoreFailure);
            }
            for tenant in tenants {
                let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
                require_signing_key(&mut transaction, tenant_uuid, &self.signer, true).await?;
                let unverifiable_live_credential = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM credential_handles credentials \
                     LEFT JOIN identity_credential_signing_keys signing_keys \
                       ON signing_keys.tenant_id=credentials.tenant_id \
                      AND signing_keys.issuer=credentials.issuer \
                      AND signing_keys.key_id=credentials.key_id \
                      AND signing_keys.algorithm='Ed25519' \
                      AND signing_keys.status IN ('ACTIVE','VERIFY_ONLY') \
                     WHERE credentials.tenant_id=$1 AND credentials.revoked_at IS NULL \
                       AND credentials.remaining_uses > 0 AND credentials.expires_at > now() \
                       AND signing_keys.key_id IS NULL)",
                )
                .bind(tenant_uuid)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
                if unverifiable_live_credential {
                    return Err(IdentityError::SigningKeyInvalid);
                }
                let missing_key = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM identity_credential_idempotency \
                     WHERE tenant_id=$1 AND response_ciphertext IS NOT NULL \
                       AND NOT encryption_key_id=ANY($2::text[]))",
                )
                .bind(tenant_uuid)
                .bind(self.protector.keys.keys().cloned().collect::<Vec<_>>())
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| IdentityError::StoreFailure)?;
                if missing_key {
                    return Err(IdentityError::ResponseProtectionInvalid);
                }
                transaction
                    .commit()
                    .await
                    .map_err(|_| IdentityError::StoreFailure)?;
            }
            Ok::<(), IdentityError>(())
        };
        tokio::time::timeout(Duration::from_secs(2), check)
            .await
            .ok()
            .and_then(Result::ok)
            .is_some()
    }

    async fn load_response<T: DeserializeOwned>(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant_uuid: Uuid,
        idempotency_key: &IdempotencyKey,
        operation: &str,
        request_digest: &str,
    ) -> Result<Option<T>, IdentityError> {
        let row = sqlx::query(
            "SELECT operation,request_digest,response_ciphertext,response_nonce,encryption_key_id,response_digest \
             FROM identity_credential_idempotency WHERE tenant_id=$1 AND idempotency_key=$2",
        )
        .bind(tenant_uuid)
        .bind(&idempotency_key.0)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_operation: String = row
            .try_get("operation")
            .map_err(|_| IdentityError::StoreFailure)?;
        let stored_digest: String = row
            .try_get("request_digest")
            .map_err(|_| IdentityError::StoreFailure)?;
        if stored_operation != operation || stored_digest != request_digest {
            return Err(IdentityError::IdempotencyConflict);
        }
        let key_id: Option<String> = row
            .try_get("encryption_key_id")
            .map_err(|_| IdentityError::StoreFailure)?;
        let nonce: Option<Vec<u8>> = row
            .try_get("response_nonce")
            .map_err(|_| IdentityError::StoreFailure)?;
        let ciphertext: Option<Vec<u8>> = row
            .try_get("response_ciphertext")
            .map_err(|_| IdentityError::StoreFailure)?;
        let (Some(key_id), Some(nonce), Some(ciphertext)) = (key_id, nonce, ciphertext) else {
            return Err(IdentityError::IdempotencyReplayExpired);
        };
        self.protector
            .open(
                request_digest,
                &key_id,
                &nonce,
                &ciphertext,
                &row.try_get::<String, _>("response_digest")
                    .map_err(|_| IdentityError::StoreFailure)?,
            )
            .map(Some)
    }

    async fn store_response<T: Serialize>(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant_uuid: Uuid,
        idempotency_key: &IdempotencyKey,
        operation: &str,
        request_digest: &str,
        response: &T,
    ) -> Result<(), IdentityError> {
        let protected = self.protector.seal(request_digest, response)?;
        sqlx::query(
            "INSERT INTO identity_credential_idempotency \
             (tenant_id,idempotency_key,operation,request_digest,response_ciphertext,response_nonce,\
              encryption_key_id,response_digest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(tenant_uuid)
        .bind(&idempotency_key.0)
        .bind(operation)
        .bind(request_digest)
        .bind(protected.ciphertext)
        .bind(protected.nonce.as_slice())
        .bind(protected.key_id)
        .bind(protected.digest)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505")
            {
                IdentityError::IdempotencyConflict
            } else {
                IdentityError::StoreFailure
            }
        })?;
        Ok(())
    }
}

fn validate_binding_request(
    request: &WorkloadCredentialBindingRequest,
) -> Result<(), IdentityError> {
    if request.schema_version != WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION
        || request.audience != EXPECTED_AUDIENCE
        || request.max_uses != 1
        || !valid_idempotency_key(&request.idempotency_key.0)
        || !canonical_uuid(&request.tenant_id.0)
        || !canonical_uuid(&request.agent_instance_id.0)
        || !canonical_uuid(&request.task_id.0)
        || !canonical_uuid(&request.step_id.0)
        || !lower_digest(&request.action_hash.0)
        || !bounded(&request.policy_decision_id, 256)
        || !bounded(&request.tool_id.0, 256)
        || !bounded(&request.credential_profile, 256)
        || !bounded(&request.operation, 256)
        || !bounded(&request.resource, 2_048)
        || !bounded(&request.target_profile, 256)
        || request.ttl_seconds == 0
        || request.ttl_seconds > 300
    {
        return Err(IdentityError::RequestInvalid);
    }
    Ok(())
}

async fn require_issue_allowed(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    request: &WorkloadCredentialBindingRequest,
) -> Result<(), IdentityError> {
    advisory_lock(
        transaction,
        &format!(
            "identity:task:{}:{}",
            request.tenant_id.0, request.task_id.0
        ),
    )
    .await?;
    sqlx::query(
        "INSERT INTO identity_tenant_epochs(tenant_id,revocation_epoch) VALUES ($1,0) \
         ON CONFLICT (tenant_id) DO NOTHING",
    )
    .bind(tenant_uuid)
    .execute(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    sqlx::query_scalar::<_, i64>(
        "SELECT revocation_epoch FROM identity_tenant_epochs WHERE tenant_id=$1 FOR SHARE",
    )
    .bind(tenant_uuid)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    let state = sqlx::query_scalar::<_, String>(
        "SELECT state FROM identity_task_lifecycle WHERE tenant_id=$1 AND task_id=$2",
    )
    .bind(tenant_uuid)
    .bind(parse_uuid(&request.task_id.0)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    match state.as_deref() {
        Some("PAUSED") => return Err(IdentityError::TaskFrozen),
        Some("CANCELED" | "KILLED") => return Err(IdentityError::SubjectRevoked),
        _ => {}
    }
    let revoked = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM identity_revocations WHERE tenant_id=$1 AND (\
           (subject_kind='tenant' AND subject_id=$2) OR \
           (subject_kind='agent' AND subject_id=$3) OR \
           (subject_kind='task' AND subject_id=$4)))",
    )
    .bind(tenant_uuid)
    .bind(&request.tenant_id.0)
    .bind(&request.agent_instance_id.0)
    .bind(&request.task_id.0)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    if revoked {
        return Err(IdentityError::SubjectRevoked);
    }
    let agent_epoch = sqlx::query_scalar::<_, i64>(
        "SELECT revocation_epoch FROM agent_principals \
         WHERE tenant_id=$1 AND agent_instance_id=$2 FOR SHARE",
    )
    .bind(tenant_uuid)
    .bind(parse_uuid(&request.agent_instance_id.0)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?
    .ok_or(IdentityError::OwnershipUnknown)?;
    if u64::try_from(agent_epoch).map_err(|_| IdentityError::StoreFailure)?
        != request.revocation_epoch
    {
        return Err(IdentityError::Revoked);
    }
    let profile_ready = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM credential_profiles WHERE tenant_id=$1 AND profile_id=$2)",
    )
    .bind(tenant_uuid)
    .bind(&request.credential_profile)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    if !profile_ready {
        return Err(IdentityError::OwnershipUnknown);
    }
    Ok(())
}

async fn require_consumption_allowed(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    claims: &WorkloadCredentialClaims,
    now: DateTime<Utc>,
) -> Result<(), IdentityError> {
    if now < claims.issued_at || now >= claims.expires_at || claims.max_uses != 1 {
        return Err(IdentityError::ExpiredOrNotYetValid);
    }
    let agent_epoch = sqlx::query_scalar::<_, i64>(
        "SELECT revocation_epoch FROM agent_principals \
         WHERE tenant_id=$1 AND agent_instance_id=$2 FOR SHARE",
    )
    .bind(tenant_uuid)
    .bind(parse_uuid(&claims.agent_instance_id.0)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?
    .ok_or(IdentityError::OwnershipUnknown)?;
    if u64::try_from(agent_epoch).map_err(|_| IdentityError::StoreFailure)?
        != claims.revocation_epoch
    {
        return Err(IdentityError::Revoked);
    }
    let revoked = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM identity_revocations WHERE tenant_id=$1 AND (\
           (subject_kind='tenant' AND subject_id=$2) OR \
           (subject_kind='agent' AND subject_id=$3) OR \
           (subject_kind='task' AND subject_id=$4) OR \
           (subject_kind='credential' AND subject_id=$5)))",
    )
    .bind(tenant_uuid)
    .bind(&claims.tenant_id.0)
    .bind(&claims.agent_instance_id.0)
    .bind(&claims.task_id.0)
    .bind(&claims.credential_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    let terminal = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM identity_task_lifecycle WHERE tenant_id=$1 AND task_id=$2 \
         AND state IN ('CANCELED','KILLED'))",
    )
    .bind(tenant_uuid)
    .bind(parse_uuid(&claims.task_id.0)?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    if revoked || terminal {
        return Err(IdentityError::Revoked);
    }
    Ok(())
}

fn binding_request_from_claims(
    claims: &WorkloadCredentialClaims,
    ttl_seconds: u64,
) -> WorkloadCredentialBindingRequest {
    WorkloadCredentialBindingRequest {
        schema_version: WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION.into(),
        idempotency_key: claims.idempotency_key.clone(),
        tenant_id: claims.tenant_id.clone(),
        agent_instance_id: claims.agent_instance_id.clone(),
        task_id: claims.task_id.clone(),
        step_id: claims.step_id.clone(),
        action_hash: claims.action_hash.clone(),
        policy_decision_id: claims.policy_decision_id.clone(),
        tool_id: claims.tool_id.clone(),
        credential_profile: claims.credential_profile.clone(),
        operation: claims.operation.clone(),
        resource: claims.resource.clone(),
        target_profile: claims.target_profile.clone(),
        audience: claims.audience.clone(),
        revocation_epoch: claims.revocation_epoch,
        ttl_seconds,
        max_uses: claims.max_uses,
    }
}

fn consumption_scope_matches(
    request: &WorkloadCredentialConsumptionRequest,
    claims: &WorkloadCredentialClaims,
) -> bool {
    request.tenant_id == claims.tenant_id
        && request.agent_instance_id == claims.agent_instance_id
        && request.task_id == claims.task_id
        && request.step_id == claims.step_id
        && request.action_hash == claims.action_hash
        && request.policy_decision_id == claims.policy_decision_id
        && request.tool_id == claims.tool_id
        && request.credential_profile == claims.credential_profile
        && request.operation == claims.operation
        && request.resource == claims.resource
        && request.target_profile == claims.target_profile
        && request.audience == claims.audience
        && request.revocation_epoch == claims.revocation_epoch
}

async fn require_signing_key(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    signer: &CredentialAuthoritySigner,
    active: bool,
) -> Result<(), IdentityError> {
    let row = sqlx::query(
        "SELECT algorithm,public_key,status FROM identity_credential_signing_keys \
         WHERE tenant_id=$1 AND issuer=$2 AND key_id=$3 FOR SHARE",
    )
    .bind(tenant_uuid)
    .bind(&signer.issuer)
    .bind(&signer.key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?
    .ok_or(IdentityError::SigningKeyInvalid)?;
    let status: String = row
        .try_get("status")
        .map_err(|_| IdentityError::StoreFailure)?;
    let public_key: Vec<u8> = row
        .try_get("public_key")
        .map_err(|_| IdentityError::StoreFailure)?;
    if row
        .try_get::<String, _>("algorithm")
        .map_err(|_| IdentityError::StoreFailure)?
        != "Ed25519"
        || public_key.as_slice() != signer.verifying_key().as_bytes()
        || (active && status != "ACTIVE")
        || (!active && !matches!(status.as_str(), "ACTIVE" | "VERIFY_ONLY"))
    {
        return Err(IdentityError::SigningKeyInvalid);
    }
    Ok(())
}

async fn load_verification_key(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    issuer: &str,
    key_id: &str,
) -> Result<VerifyingKey, IdentityError> {
    let raw = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT public_key FROM identity_credential_signing_keys WHERE tenant_id=$1 \
         AND issuer=$2 AND key_id=$3 AND algorithm='Ed25519' \
         AND status IN ('ACTIVE','VERIFY_ONLY') FOR SHARE",
    )
    .bind(tenant_uuid)
    .bind(issuer)
    .bind(key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?
    .ok_or(IdentityError::SigningKeyInvalid)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| IdentityError::SigningKeyInvalid)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| IdentityError::SigningKeyInvalid)
}

async fn current_epoch(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
) -> Result<u64, IdentityError> {
    let epoch = sqlx::query_scalar::<_, i64>(
        "SELECT revocation_epoch FROM identity_tenant_epochs WHERE tenant_id=$1",
    )
    .bind(tenant_uuid)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?
    .unwrap_or(0);
    u64::try_from(epoch).map_err(|_| IdentityError::StoreFailure)
}

async fn insert_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    subject_kind: &str,
    subject_id: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<bool, IdentityError> {
    let result = sqlx::query(
        "INSERT INTO identity_revocations \
         (revocation_id,tenant_id,subject_kind,subject_id,reason_code,revoked_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,subject_kind,subject_id) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_uuid)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(reason)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    Ok(result.rows_affected() == 1)
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    event_type: &str,
    credential_id: Option<Uuid>,
    task_id: Option<Uuid>,
    agent_instance_id: Option<Uuid>,
    scope_digest: &str,
    actor_subject: &str,
    payload: serde_json::Value,
) -> Result<Uuid, IdentityError> {
    let serialized = serde_jcs::to_vec(&payload).map_err(|_| IdentityError::RequestInvalid)?;
    if serialized.len() > 16_384
        || ["credential_handle", "bearer", "token", "secret"]
            .iter()
            .any(|forbidden| String::from_utf8_lossy(&serialized).contains(forbidden))
    {
        return Err(IdentityError::RequestInvalid);
    }
    let event_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identity_credential_events \
         (event_id,tenant_id,event_type,credential_id,task_id,agent_instance_id,scope_digest,actor_subject,event_payload) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(event_id)
    .bind(tenant_uuid)
    .bind(event_type)
    .bind(credential_id)
    .bind(task_id)
    .bind(agent_instance_id)
    .bind(scope_digest)
    .bind(actor_subject)
    .bind(payload)
    .execute(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    Ok(event_id)
}

async fn append_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    event_id: Uuid,
    event_type: &str,
    credential_id: Option<Uuid>,
    scope_digest: &str,
) -> Result<(), IdentityError> {
    sqlx::query(
        "INSERT INTO identity_credential_outbox \
         (outbox_id,tenant_id,event_id,event_type,credential_id,scope_digest,payload) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_uuid)
    .bind(event_id)
    .bind(event_type)
    .bind(credential_id)
    .bind(scope_digest)
    .bind(serde_json::json!({
        "event_id":event_id,
        "credential_id":credential_id,
        "scope_digest":scope_digest
    }))
    .execute(&mut **transaction)
    .await
    .map_err(|_| IdentityError::StoreFailure)?;
    Ok(())
}

async fn lock_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    key: &IdempotencyKey,
) -> Result<(), IdentityError> {
    if !valid_idempotency_key(&key.0) {
        return Err(IdentityError::IdempotencyInvalid);
    }
    advisory_lock(
        transaction,
        &format!("identity:idempotency:{}:{}", tenant.0, key.0),
    )
    .await
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    value: &str,
) -> Result<(), IdentityError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(value)
        .execute(&mut **transaction)
        .await
        .map_err(|_| IdentityError::StoreFailure)?;
    Ok(())
}

fn lifecycle_receipt(
    operation: &str,
    subject_kind: &str,
    subject_id: &str,
    tenant: &TenantId,
    state: &str,
    epoch: u64,
    event_id: Uuid,
    changed: bool,
) -> CredentialLifecycleReceipt {
    CredentialLifecycleReceipt {
        schema_version: CREDENTIAL_LIFECYCLE_SCHEMA_VERSION.into(),
        operation: operation.into(),
        subject_kind: subject_kind.into(),
        subject_id: subject_id.into(),
        tenant_id: tenant.clone(),
        state: state.into(),
        revocation_epoch: epoch,
        event_ref: format!("identity-event://{}/{event_id}", tenant.0),
        changed,
    }
}

fn lifecycle_digest(
    operation: &str,
    tenant: &TenantId,
    subject_id: &str,
    request: &CredentialLifecycleRequest,
) -> Result<String, IdentityError> {
    canonical_digest(&serde_json::json!({
        "operation":operation,
        "tenant_id":tenant,
        "subject_id":subject_id,
        "request":request,
    }))
}

fn validate_lifecycle_request(
    request: &CredentialLifecycleRequest,
    reason_required: bool,
) -> Result<(), IdentityError> {
    let reason_valid = request
        .reason_code
        .as_ref()
        .is_none_or(|reason| bounded_identifier(reason, 128));
    if request.schema_version != CREDENTIAL_LIFECYCLE_SCHEMA_VERSION
        || !reason_valid
        || reason_required != request.reason_code.is_some()
    {
        return Err(IdentityError::RequestInvalid);
    }
    Ok(())
}

fn validate_actor(actor: &str) -> Result<(), IdentityError> {
    if !bounded(actor, 256) {
        return Err(IdentityError::ManagementForbidden);
    }
    Ok(())
}

fn parse_tenant(tenant: &TenantId) -> Result<Uuid, IdentityError> {
    if !canonical_uuid(&tenant.0) {
        return Err(IdentityError::TenantMismatch);
    }
    parse_uuid(&tenant.0)
}

fn parse_uuid(value: &str) -> Result<Uuid, IdentityError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|uuid| uuid.to_string() == value)
        .ok_or(IdentityError::RequestInvalid)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, IdentityError> {
    Ok(sha256(
        &serde_jcs::to_vec(value).map_err(|_| IdentityError::RequestInvalid)?,
    ))
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn random_handle() -> Result<String, IdentityError> {
    let mut raw = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| IdentityError::ResponseProtectionInvalid)?;
    Ok(format!("wca_{}", URL_SAFE_NO_PAD.encode(raw)))
}

fn valid_handle(value: &str) -> bool {
    value.len() == 47
        && value.starts_with("wca_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn bounded_identifier(value: &str, maximum: usize) -> bool {
    bounded(value, maximum)
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn idempotency_aad(request_digest: &str) -> String {
    format!("agenttrust.identity-idempotency.v1:{request_digest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{ActionHash, AgentInstanceId, StepId, TaskId, ToolId};

    #[test]
    fn handles_and_protected_replay_are_secret_safe_and_exact() {
        let handle = random_handle().unwrap_or_else(|_| panic!("handle"));
        assert!(valid_handle(&handle));
        let protector = IdentityResponseProtector::new(
            "key-1".into(),
            BTreeMap::from([("key-1".into(), [7_u8; 32])]),
        )
        .unwrap_or_else(|_| panic!("protector"));
        let response = serde_json::json!({"credential_handle":handle});
        let protected = protector
            .seal(&"a".repeat(64), &response)
            .unwrap_or_else(|_| panic!("seal"));
        assert!(!String::from_utf8_lossy(&protected.ciphertext).contains("wca_"));
        let replay: serde_json::Value = protector
            .open(
                &"a".repeat(64),
                &protected.key_id,
                &protected.nonce,
                &protected.ciphertext,
                &protected.digest,
            )
            .unwrap_or_else(|_| panic!("open"));
        assert_eq!(replay, response);
    }

    #[test]
    fn consumption_debug_never_discloses_handle_or_binding_receipt() {
        let request = WorkloadCredentialConsumptionRequest {
            schema_version: WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION.into(),
            idempotency_key: IdempotencyKey("consume-1".into()),
            credential_handle: format!("wca_{}", "a".repeat(43)),
            binding_receipt: SignedWorkloadCredentialBindingReceipt {
                schema_version: WORKLOAD_CREDENTIAL_BINDING_RECEIPT_SCHEMA_VERSION.into(),
                credential_handle_sha256: sha256("secret-handle".as_bytes()),
                claims: WorkloadCredentialClaims {
                    schema_version: WORKLOAD_CREDENTIAL_CLAIMS_SCHEMA_VERSION.into(),
                    idempotency_key: IdempotencyKey("issue-1".into()),
                    credential_id: Uuid::new_v4().to_string(),
                    tenant_id: TenantId::new(),
                    agent_instance_id: AgentInstanceId::new(),
                    task_id: TaskId::new(),
                    step_id: StepId::new(),
                    action_hash: ActionHash("a".repeat(64)),
                    policy_decision_id: "policy".into(),
                    tool_id: ToolId("coding.repo-read".into()),
                    credential_profile: "repo-read".into(),
                    operation: "read".into(),
                    resource: "repo:a".into(),
                    target_profile: "repo-ro".into(),
                    audience: EXPECTED_AUDIENCE.into(),
                    revocation_epoch: 0,
                    issued_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::seconds(30),
                    max_uses: 1,
                },
                claims_digest: "b".repeat(64),
                issuer: "identity".into(),
                key_id: "key".into(),
                key_usage: WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE.into(),
                signature: "secret-signature".into(),
            },
            tenant_id: TenantId::new(),
            agent_instance_id: AgentInstanceId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            action_hash: ActionHash("a".repeat(64)),
            policy_decision_id: "policy".into(),
            tool_id: ToolId("coding.repo-read".into()),
            credential_profile: "repo-read".into(),
            operation: "read".into(),
            resource: "repo:a".into(),
            target_profile: "repo-ro".into(),
            audience: EXPECTED_AUDIENCE.into(),
            revocation_epoch: 0,
            claims_digest: "b".repeat(64),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-handle"));
        assert!(!debug.contains("secret-signature"));
    }
}
