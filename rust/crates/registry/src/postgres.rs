use super::*;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use uuid::Uuid;

const SNAPSHOT_SIGNATURE_ALGORITHM: &str = "Ed25519";

#[derive(Clone)]
pub struct RegistryPublisherSigner {
    pub publisher_id: String,
    pub key_id: String,
    signing_key: Arc<SigningKey>,
}

impl RegistryPublisherSigner {
    pub fn new(
        publisher_id: String,
        key_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, RegistryError> {
        if !valid_identifier(&publisher_id, 128) || !valid_identifier(&key_id, 128) {
            return Err(RegistryError::PublisherInvalid);
        }
        Ok(Self {
            publisher_id,
            key_id,
            signing_key: Arc::new(signing_key),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryActivationRequest {
    pub schema_version: String,
    pub expected_manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryActivationReceipt {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub operation: String,
    pub status: ToolVersionStatus,
    pub registry_revision: Option<u64>,
    pub manifest_hash: String,
    pub snapshot_hash: Option<String>,
    pub event_ref: String,
    pub idempotent: bool,
}

#[derive(Clone)]
pub struct PostgresRegistryStore {
    pool: PgPool,
    signer: Option<RegistryPublisherSigner>,
    tenant_scope: Option<TenantId>,
}

impl PostgresRegistryStore {
    /// Builds a read-only/draft-capable store. Production management composition
    /// must use `with_signer`; activation fails closed when no signer is present.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            signer: None,
            tenant_scope: None,
        }
    }

    pub fn with_signer(pool: PgPool, signer: RegistryPublisherSigner) -> Self {
        Self {
            pool,
            signer: Some(signer),
            tenant_scope: None,
        }
    }

    /// Produces a tenant-bound data-plane view so the legacy revocation method,
    /// whose trait signature predates tenant RLS, cannot query without context.
    pub fn for_tenant(&self, tenant: TenantId) -> Self {
        let mut scoped = self.clone();
        scoped.tenant_scope = Some(tenant);
        scoped
    }

    pub fn production_signer_configured(&self) -> bool {
        self.signer.is_some()
    }

    fn signer(&self) -> Result<&RegistryPublisherSigner, RegistryError> {
        self.signer
            .as_ref()
            .ok_or(RegistryError::PublisherNotConfigured)
    }

    async fn tenant_transaction<'a>(
        &'a self,
        tenant: &TenantId,
    ) -> Result<(Uuid, Transaction<'a, Postgres>), RegistryError> {
        let tenant_uuid = tenant_uuid(tenant)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok((tenant_uuid, transaction))
    }

    pub async fn register_publisher_key(
        &self,
        tenant: &TenantId,
        publisher_id: &str,
        key_id: &str,
        verifying_key: &VerifyingKey,
        actor_subject: &str,
    ) -> Result<(), RegistryError> {
        validate_actor(actor_subject)?;
        if !valid_identifier(publisher_id, 128) || !valid_identifier(key_id, 128) {
            return Err(RegistryError::PublisherInvalid);
        }
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:publisher:{}:{publisher_id}:{key_id}", tenant.0),
        )
        .await?;
        let existing = sqlx::query(
            "SELECT publisher_id,public_key,status FROM registry_publisher_keys \
             WHERE tenant_id=$1 AND key_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(key_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        if let Some(row) = existing {
            let stored_publisher: String = row
                .try_get("publisher_id")
                .map_err(|_| RegistryError::StoreFailure)?;
            let stored_key: Vec<u8> = row
                .try_get("public_key")
                .map_err(|_| RegistryError::StoreFailure)?;
            let status: String = row
                .try_get("status")
                .map_err(|_| RegistryError::StoreFailure)?;
            if stored_publisher != publisher_id
                || stored_key.as_slice() != verifying_key.as_bytes()
                || status != "ACTIVE"
            {
                return Err(RegistryError::PublisherConflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO registry_publisher_keys \
             (tenant_id,publisher_id,key_id,algorithm,public_key,status,created_by) \
             VALUES ($1,$2,$3,'Ed25519',$4,'ACTIVE',$5)",
        )
        .bind(tenant_uuid)
        .bind(publisher_id)
        .bind(key_id)
        .bind(verifying_key.as_bytes().as_slice())
        .bind(actor_subject)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        insert_event(
            &mut transaction,
            tenant_uuid,
            None,
            "PUBLISHER_KEY_REGISTERED",
            actor_subject,
            serde_json::json!({"publisher_id":publisher_id,"key_id":key_id,"algorithm":"Ed25519"}),
            None,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(())
    }

    pub async fn revoke_publisher_key(
        &self,
        tenant: &TenantId,
        publisher_id: &str,
        key_id: &str,
        actor_subject: &str,
    ) -> Result<(), RegistryError> {
        validate_actor(actor_subject)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:publisher:{}:{publisher_id}:{key_id}", tenant.0),
        )
        .await?;
        let in_use = sqlx::query_scalar::<_, bool>(
            "SELECT \
               EXISTS(SELECT 1 FROM tool_versions WHERE tenant_id=$1 AND status='ACTIVE' \
                 AND manifest #>> '{signature,publisher_id}'=$2 \
                 AND manifest #>> '{signature,key_id}'=$3) \
               OR EXISTS(SELECT 1 FROM registry_snapshots AS snapshot \
                 JOIN registry_tenant_revisions AS revision \
                   ON revision.tenant_id=snapshot.tenant_id AND revision.revision=snapshot.revision \
                 WHERE snapshot.tenant_id=$1 AND snapshot.publisher_id=$2 AND snapshot.key_id=$3)",
        )
        .bind(tenant_uuid)
        .bind(publisher_id)
        .bind(key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        if in_use {
            return Err(RegistryError::PublisherInUse);
        }
        let result = sqlx::query(
            "UPDATE registry_publisher_keys SET status='REVOKED',revoked_at=now(),revoked_by=$4 \
             WHERE tenant_id=$1 AND publisher_id=$2 AND key_id=$3 AND status='ACTIVE'",
        )
        .bind(tenant_uuid)
        .bind(publisher_id)
        .bind(key_id)
        .bind(actor_subject)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        if result.rows_affected() == 0 {
            let status = sqlx::query_scalar::<_, String>(
                "SELECT status FROM registry_publisher_keys \
                 WHERE tenant_id=$1 AND publisher_id=$2 AND key_id=$3",
            )
            .bind(tenant_uuid)
            .bind(publisher_id)
            .bind(key_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
            if status.as_deref() != Some("REVOKED") {
                return Err(RegistryError::PublisherInvalid);
            }
        } else {
            insert_event(
                &mut transaction,
                tenant_uuid,
                None,
                "PUBLISHER_KEY_REVOKED",
                actor_subject,
                serde_json::json!({"publisher_id":publisher_id,"key_id":key_id}),
                None,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(())
    }

    pub async fn insert_draft(
        &self,
        tenant: &TenantId,
        manifest: &ToolManifest,
    ) -> Result<(), RegistryError> {
        self.insert_draft_as(tenant, manifest, "system:registry-import")
            .await
    }

    pub async fn insert_draft_as(
        &self,
        tenant: &TenantId,
        manifest: &ToolManifest,
        actor_subject: &str,
    ) -> Result<(), RegistryError> {
        validate_actor(actor_subject)?;
        manifest
            .tool_ref()
            .validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        if manifest.status != ToolVersionStatus::Draft
            || manifest.signature.is_some()
            || manifest.allowed_tenants != BTreeSet::from([tenant.clone()])
        {
            return Err(RegistryError::SchemaInvalid);
        }
        let manifest_hash = canonical_manifest_hash(manifest)?;
        let schema_hash = canonical_schema_pair_hash(manifest)?;
        let value = serde_json::to_value(manifest).map_err(|_| RegistryError::SchemaInvalid)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_tool_lock(&mut transaction, tenant, &manifest.tool_ref()).await?;
        sqlx::query(
            "INSERT INTO tools (tenant_id,tool_id) VALUES ($1,$2) \
             ON CONFLICT (tenant_id,tool_id) DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(&manifest.tool_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let result = sqlx::query(
            "INSERT INTO tool_versions \
             (tenant_id,tool_id,tool_version,status,manifest,manifest_hash,schema_hash,\
              implementation_digest,effect_class,risk_level) \
             VALUES ($1,$2,$3,'DRAFT',$4,$5,$6,$7,$8,$9)",
        )
        .bind(tenant_uuid)
        .bind(&manifest.tool_id.0)
        .bind(&manifest.tool_version.0)
        .bind(value)
        .bind(&manifest_hash)
        .bind(&schema_hash)
        .bind(&manifest.implementation.digest)
        .bind(effect_class_db(manifest.effect_class))
        .bind(risk_level_db(manifest.risk_level))
        .execute(&mut *transaction)
        .await;
        if let Err(error) = result {
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505")
            {
                return Err(RegistryError::VersionConflict);
            }
            return Err(RegistryError::StoreFailure);
        }
        insert_event(
            &mut transaction,
            tenant_uuid,
            Some(&manifest.tool_ref()),
            "TOOL_DRAFT_CREATED",
            actor_subject,
            serde_json::json!({"manifest_hash":manifest_hash,"schema_hash":schema_hash}),
            None,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(())
    }

    pub async fn load(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ToolManifest, RegistryError> {
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, false)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        let manifest = manifest_from_row(&row)?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(manifest)
    }

    pub async fn validate_version(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        request: &RegistryActivationRequest,
        idempotency_key: &str,
        actor_subject: &str,
    ) -> Result<RegistryActivationReceipt, RegistryError> {
        validate_actor(actor_subject)?;
        validate_idempotency_key(idempotency_key)?;
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let request_digest = mutation_request_digest(tenant, tool, "VALIDATE", request)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:idempotency:{}:{idempotency_key}", tenant.0),
        )
        .await?;
        if let Some(receipt) = load_mutation_receipt(
            &mut transaction,
            tenant,
            tenant_uuid,
            tool,
            "VALIDATE",
            &request_digest,
            idempotency_key,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        advisory_tool_lock(&mut transaction, tenant, tool).await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, true)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        let status = row_status(&row)?;
        let stored_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if stored_hash != request.expected_manifest_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        if status == ToolVersionStatus::Validated {
            let event_id =
                lifecycle_event(&mut transaction, tenant_uuid, tool, "TOOL_VALIDATED").await?;
            let receipt = mutation_receipt(
                tenant,
                tool,
                "VALIDATE",
                ToolVersionStatus::Validated,
                stored_hash,
                None,
                None,
                event_id,
                true,
            );
            store_mutation_receipt(
                &mut transaction,
                tenant_uuid,
                "VALIDATE",
                &request_digest,
                idempotency_key,
                &receipt,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        if status != ToolVersionStatus::Draft {
            return Err(RegistryError::LifecycleInvalid);
        }
        let mut manifest = manifest_from_row(&row)?;
        manifest.status = ToolVersionStatus::Draft;
        validate_manifest_shape(&manifest)?;
        require_profiles_exist(&mut transaction, tenant_uuid, &manifest).await?;
        require_compensation_exists(&mut transaction, tenant_uuid, &manifest, false).await?;
        let manifest_hash = canonical_manifest_hash(&manifest)?;
        if manifest_hash != stored_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        let schema_hash = canonical_schema_pair_hash(&manifest)?;
        manifest.status = ToolVersionStatus::Validated;
        let manifest_value =
            serde_json::to_value(&manifest).map_err(|_| RegistryError::SchemaInvalid)?;
        sqlx::query(
            "UPDATE tool_versions SET status='VALIDATED',manifest=$4,schema_hash=$5 \
             WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status='DRAFT'",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .bind(manifest_value)
        .bind(&schema_hash)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let event_id = insert_event(
            &mut transaction,
            tenant_uuid,
            Some(tool),
            "TOOL_VALIDATED",
            actor_subject,
            serde_json::json!({"manifest_hash":manifest_hash,"schema_hash":schema_hash}),
            Some(idempotency_key),
        )
        .await?;
        let receipt = mutation_receipt(
            tenant,
            tool,
            "VALIDATE",
            ToolVersionStatus::Validated,
            manifest_hash,
            None,
            None,
            event_id,
            false,
        );
        store_mutation_receipt(
            &mut transaction,
            tenant_uuid,
            "VALIDATE",
            &request_digest,
            idempotency_key,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn sign_version(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        request: &RegistryActivationRequest,
        idempotency_key: &str,
        actor_subject: &str,
    ) -> Result<RegistryActivationReceipt, RegistryError> {
        validate_actor(actor_subject)?;
        validate_idempotency_key(idempotency_key)?;
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let request_digest = mutation_request_digest(tenant, tool, "SIGN", request)?;
        let signer = self.signer()?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:idempotency:{}:{idempotency_key}", tenant.0),
        )
        .await?;
        if let Some(receipt) = load_mutation_receipt(
            &mut transaction,
            tenant,
            tenant_uuid,
            tool,
            "SIGN",
            &request_digest,
            idempotency_key,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        advisory_tool_lock(&mut transaction, tenant, tool).await?;
        require_publisher_key(
            &mut transaction,
            tenant_uuid,
            &signer.publisher_id,
            &signer.key_id,
            &signer.verifying_key(),
        )
        .await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, true)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        let status = row_status(&row)?;
        let stored_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if stored_hash != request.expected_manifest_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        if status == ToolVersionStatus::Signed {
            let event_id =
                lifecycle_event(&mut transaction, tenant_uuid, tool, "TOOL_SIGNED").await?;
            let receipt = mutation_receipt(
                tenant,
                tool,
                "SIGN",
                ToolVersionStatus::Signed,
                stored_hash,
                None,
                None,
                event_id,
                true,
            );
            store_mutation_receipt(
                &mut transaction,
                tenant_uuid,
                "SIGN",
                &request_digest,
                idempotency_key,
                &receipt,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        if status != ToolVersionStatus::Validated {
            return Err(RegistryError::LifecycleInvalid);
        }
        let mut manifest = manifest_from_row(&row)?;
        manifest.status = ToolVersionStatus::Validated;
        manifest.signature = None;
        let manifest_hash = canonical_manifest_hash(&manifest)?;
        if manifest_hash != stored_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        let raw_signature = signer.signing_key.sign(manifest_hash.as_bytes()).to_bytes();
        manifest.signature = Some(ManifestSignature {
            publisher_id: signer.publisher_id.clone(),
            key_id: signer.key_id.clone(),
            algorithm: SNAPSHOT_SIGNATURE_ALGORITHM.into(),
            signature: URL_SAFE_NO_PAD.encode(raw_signature),
        });
        manifest.status = ToolVersionStatus::Signed;
        let manifest_value =
            serde_json::to_value(&manifest).map_err(|_| RegistryError::SchemaInvalid)?;
        sqlx::query(
            "INSERT INTO tool_signatures \
             (tenant_id,tool_id,tool_version,publisher_id,key_id,algorithm,signature) \
             VALUES ($1,$2,$3,$4,$5,'Ed25519',$6)",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .bind(&signer.publisher_id)
        .bind(&signer.key_id)
        .bind(raw_signature.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        sqlx::query(
            "UPDATE tool_versions SET status='SIGNED',manifest=$4 \
             WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status='VALIDATED'",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .bind(manifest_value)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let event_id = insert_event(
            &mut transaction,
            tenant_uuid,
            Some(tool),
            "TOOL_SIGNED",
            actor_subject,
            serde_json::json!({"manifest_hash":manifest_hash,"publisher_id":signer.publisher_id,"key_id":signer.key_id}),
            Some(idempotency_key),
        )
        .await?;
        let receipt = mutation_receipt(
            tenant,
            tool,
            "SIGN",
            ToolVersionStatus::Signed,
            manifest_hash,
            None,
            None,
            event_id,
            false,
        );
        store_mutation_receipt(
            &mut transaction,
            tenant_uuid,
            "SIGN",
            &request_digest,
            idempotency_key,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn activate(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        request: &RegistryActivationRequest,
        idempotency_key: &str,
        actor_subject: &str,
    ) -> Result<RegistryActivationReceipt, RegistryError> {
        validate_actor(actor_subject)?;
        validate_idempotency_key(idempotency_key)?;
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let request_digest = mutation_request_digest(tenant, tool, "ACTIVATE", request)?;
        let signer = self.signer()?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:idempotency:{}:{idempotency_key}", tenant.0),
        )
        .await?;
        if let Some(receipt) = load_mutation_receipt(
            &mut transaction,
            tenant,
            tenant_uuid,
            tool,
            "ACTIVATE",
            &request_digest,
            idempotency_key,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        advisory_tool_lock(&mut transaction, tenant, tool).await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, true)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        let status = row_status(&row)?;
        let stored_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if stored_hash != request.expected_manifest_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        if status == ToolVersionStatus::Active {
            let tool_revision = row_revision(&row)?;
            let revision_i64 = sqlx::query_scalar::<_, i64>(
                "SELECT revision FROM registry_tenant_revisions WHERE tenant_id=$1",
            )
            .bind(tenant_uuid)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
            let revision = u64::try_from(revision_i64).map_err(|_| RegistryError::StoreFailure)?;
            let snapshot =
                load_signed_snapshot(&mut transaction, tenant, tenant_uuid, revision).await?;
            if !snapshot.tools.iter().any(|candidate| {
                candidate.tool_id == tool.tool_id
                    && candidate.tool_version == tool.tool_version
                    && candidate.manifest_hash == stored_hash
                    && candidate.registry_revision == tool_revision
            }) {
                return Err(RegistryError::ManifestHashMismatch);
            }
            let event_id = insert_event(
                &mut transaction,
                tenant_uuid,
                Some(tool),
                "TOOL_ACTIVATION_CONFIRMED",
                actor_subject,
                serde_json::json!({
                    "manifest_hash":stored_hash,
                    "registry_revision":revision,
                    "snapshot_hash":snapshot.snapshot_hash
                }),
                Some(idempotency_key),
            )
            .await?;
            let receipt = activation_receipt(
                tenant,
                tool,
                revision,
                stored_hash,
                snapshot.snapshot_hash,
                event_id,
                true,
            );
            store_mutation_receipt(
                &mut transaction,
                tenant_uuid,
                "ACTIVATE",
                &request_digest,
                idempotency_key,
                &receipt,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        if status != ToolVersionStatus::Signed {
            return Err(RegistryError::LifecycleInvalid);
        }
        let mut manifest = manifest_from_row(&row)?;
        manifest.status = ToolVersionStatus::Signed;
        validate_manifest_shape(&manifest)?;
        require_profiles_exist(&mut transaction, tenant_uuid, &manifest).await?;
        require_compensation_exists(&mut transaction, tenant_uuid, &manifest, true).await?;
        verify_tool_signature(&mut transaction, tenant_uuid, &manifest, &stored_hash).await?;
        require_publisher_key(
            &mut transaction,
            tenant_uuid,
            &signer.publisher_id,
            &signer.key_id,
            &signer.verifying_key(),
        )
        .await?;
        let revision = allocate_revision(&mut transaction, tenant_uuid).await?;
        manifest.status = ToolVersionStatus::Active;
        let manifest_value =
            serde_json::to_value(&manifest).map_err(|_| RegistryError::SchemaInvalid)?;
        sqlx::query(
            "UPDATE tool_versions SET status='ACTIVE',manifest=$4,activated_at=now(),registry_revision=$5 \
             WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status='SIGNED'",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .bind(manifest_value)
        .bind(i64::try_from(revision).map_err(|_| RegistryError::StoreFailure)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let snapshot =
            publish_snapshot(&mut transaction, tenant, tenant_uuid, revision, signer).await?;
        let event_id = insert_event(
            &mut transaction,
            tenant_uuid,
            Some(tool),
            "TOOL_ACTIVATED",
            actor_subject,
            serde_json::json!({
                "manifest_hash":stored_hash,
                "registry_revision":revision,
                "snapshot_hash":snapshot.snapshot_hash
            }),
            Some(idempotency_key),
        )
        .await?;
        let receipt = activation_receipt(
            tenant,
            tool,
            revision,
            stored_hash,
            snapshot.snapshot_hash,
            event_id,
            false,
        );
        store_mutation_receipt(
            &mut transaction,
            tenant_uuid,
            "ACTIVATE",
            &request_digest,
            idempotency_key,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn deprecate(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        request: &RegistryActivationRequest,
        idempotency_key: &str,
        actor_subject: &str,
    ) -> Result<RegistryActivationReceipt, RegistryError> {
        self.transition_published(
            tenant,
            tool,
            ToolVersionStatus::Active,
            ToolVersionStatus::Deprecated,
            "TOOL_DEPRECATED",
            "DEPRECATE",
            request,
            idempotency_key,
            actor_subject,
        )
        .await
    }

    pub async fn revoke(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        request: &RegistryActivationRequest,
        idempotency_key: &str,
        actor_subject: &str,
    ) -> Result<RegistryActivationReceipt, RegistryError> {
        validate_actor(actor_subject)?;
        validate_idempotency_key(idempotency_key)?;
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let request_digest = mutation_request_digest(tenant, tool, "REVOKE", request)?;
        let signer = self.signer()?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:idempotency:{}:{idempotency_key}", tenant.0),
        )
        .await?;
        if let Some(receipt) = load_mutation_receipt(
            &mut transaction,
            tenant,
            tenant_uuid,
            tool,
            "REVOKE",
            &request_digest,
            idempotency_key,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        advisory_tool_lock(&mut transaction, tenant, tool).await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, true)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        let status = row_status(&row)?;
        let manifest_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if manifest_hash != request.expected_manifest_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        if status == ToolVersionStatus::Revoked {
            let (event_id, revision, snapshot_hash) =
                published_event_details(&mut transaction, tenant_uuid, tool, "TOOL_REVOKED")
                    .await?;
            let receipt = mutation_receipt(
                tenant,
                tool,
                "REVOKE",
                ToolVersionStatus::Revoked,
                manifest_hash,
                Some(revision),
                Some(snapshot_hash),
                event_id,
                true,
            );
            store_mutation_receipt(
                &mut transaction,
                tenant_uuid,
                "REVOKE",
                &request_digest,
                idempotency_key,
                &receipt,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        if !matches!(
            status,
            ToolVersionStatus::Active | ToolVersionStatus::Deprecated
        ) {
            return Err(RegistryError::LifecycleInvalid);
        }
        require_publisher_key(
            &mut transaction,
            tenant_uuid,
            &signer.publisher_id,
            &signer.key_id,
            &signer.verifying_key(),
        )
        .await?;
        let revision = allocate_revision(&mut transaction, tenant_uuid).await?;
        sqlx::query(
            "UPDATE tool_versions SET status='REVOKED',revoked_at=now() \
             WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status IN ('ACTIVE','DEPRECATED')",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let snapshot =
            publish_snapshot(&mut transaction, tenant, tenant_uuid, revision, signer).await?;
        let event_id = insert_event(
            &mut transaction,
            tenant_uuid,
            Some(tool),
            "TOOL_REVOKED",
            actor_subject,
            serde_json::json!({"manifest_hash":manifest_hash,"registry_revision":revision,"snapshot_hash":snapshot.snapshot_hash}),
            Some(idempotency_key),
        )
        .await?;
        let receipt = mutation_receipt(
            tenant,
            tool,
            "REVOKE",
            ToolVersionStatus::Revoked,
            manifest_hash,
            Some(revision),
            Some(snapshot.snapshot_hash),
            event_id,
            false,
        );
        store_mutation_receipt(
            &mut transaction,
            tenant_uuid,
            "REVOKE",
            &request_digest,
            idempotency_key,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    async fn transition_published(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        from: ToolVersionStatus,
        to: ToolVersionStatus,
        event_type: &str,
        operation: &str,
        request: &RegistryActivationRequest,
        idempotency_key: &str,
        actor_subject: &str,
    ) -> Result<RegistryActivationReceipt, RegistryError> {
        validate_actor(actor_subject)?;
        validate_idempotency_key(idempotency_key)?;
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let request_digest = mutation_request_digest(tenant, tool, operation, request)?;
        let signer = self.signer()?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        advisory_lock(
            &mut transaction,
            &format!("registry:idempotency:{}:{idempotency_key}", tenant.0),
        )
        .await?;
        if let Some(receipt) = load_mutation_receipt(
            &mut transaction,
            tenant,
            tenant_uuid,
            tool,
            operation,
            &request_digest,
            idempotency_key,
        )
        .await?
        {
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        advisory_tool_lock(&mut transaction, tenant, tool).await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, true)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        let status = row_status(&row)?;
        let manifest_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if manifest_hash != request.expected_manifest_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        if status == to {
            let (event_id, revision, snapshot_hash) =
                published_event_details(&mut transaction, tenant_uuid, tool, event_type).await?;
            let receipt = mutation_receipt(
                tenant,
                tool,
                operation,
                to,
                manifest_hash,
                Some(revision),
                Some(snapshot_hash),
                event_id,
                true,
            );
            store_mutation_receipt(
                &mut transaction,
                tenant_uuid,
                operation,
                &request_digest,
                idempotency_key,
                &receipt,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)?;
            return Ok(receipt);
        }
        if status != from {
            return Err(RegistryError::LifecycleInvalid);
        }
        require_publisher_key(
            &mut transaction,
            tenant_uuid,
            &signer.publisher_id,
            &signer.key_id,
            &signer.verifying_key(),
        )
        .await?;
        let revision = allocate_revision(&mut transaction, tenant_uuid).await?;
        let target = status_db(to);
        sqlx::query(
            "UPDATE tool_versions SET status=$4 \
             WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 AND status=$5",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .bind(target)
        .bind(status_db(from))
        .execute(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let snapshot =
            publish_snapshot(&mut transaction, tenant, tenant_uuid, revision, signer).await?;
        let event_id = insert_event(
            &mut transaction,
            tenant_uuid,
            Some(tool),
            event_type,
            actor_subject,
            serde_json::json!({"manifest_hash":manifest_hash,"registry_revision":revision,"snapshot_hash":snapshot.snapshot_hash}),
            Some(idempotency_key),
        )
        .await?;
        let receipt = mutation_receipt(
            tenant,
            tool,
            operation,
            to,
            manifest_hash,
            Some(revision),
            Some(snapshot.snapshot_hash),
            event_id,
            false,
        );
        store_mutation_receipt(
            &mut transaction,
            tenant_uuid,
            operation,
            &request_digest,
            idempotency_key,
            &receipt,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(receipt)
    }

    pub async fn ready(&self) -> bool {
        let check = async {
            let tables_ready = sqlx::query_scalar::<_, bool>(
                "SELECT count(*) = 13 AND bool_and(c.relrowsecurity AND c.relforcerowsecurity) \
                 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                 WHERE n.nspname='public' AND c.relname = ANY($1::text[])",
            )
            .bind(vec![
                "tools",
                "tool_versions",
                "tool_signatures",
                "registry_events",
                "registry_snapshots",
                "registry_publisher_keys",
                "registry_tenant_revisions",
                "registry_idempotency_records",
                "executor_profiles",
                "credential_profiles",
                "approval_profiles",
                "capabilities",
                "capability_versions",
            ])
            .fetch_one(&self.pool)
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
            let privileges_ready = sqlx::query_scalar::<_, bool>(
                "SELECT bool_and(has_table_privilege(format('public.%I',table_name),privilege_name)) \
                 FROM (VALUES \
                   ('tools','SELECT'),('tools','INSERT'), \
                   ('tool_versions','SELECT'),('tool_versions','INSERT'),('tool_versions','UPDATE'), \
                   ('tool_signatures','SELECT'),('tool_signatures','INSERT'), \
                   ('registry_events','SELECT'),('registry_events','INSERT'), \
                   ('registry_snapshots','SELECT'),('registry_snapshots','INSERT'), \
                   ('registry_publisher_keys','SELECT'),('registry_publisher_keys','INSERT'),('registry_publisher_keys','UPDATE'), \
                   ('registry_tenant_revisions','SELECT'),('registry_tenant_revisions','INSERT'),('registry_tenant_revisions','UPDATE'), \
                   ('registry_idempotency_records','SELECT'),('registry_idempotency_records','INSERT'), \
                   ('executor_profiles','SELECT'),('credential_profiles','SELECT'),('approval_profiles','SELECT'), \
                   ('capabilities','SELECT'),('capability_versions','SELECT') \
                 ) AS required(table_name,privilege_name)",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
            let least_privilege_ready = sqlx::query_scalar::<_, bool>(
                "SELECT \
                   NOT has_table_privilege('public.tools','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.tool_versions','DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.tool_signatures','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.registry_events','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.registry_snapshots','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.registry_publisher_keys','DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.registry_tenant_revisions','DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.registry_idempotency_records','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.executor_profiles','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.credential_profiles','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.approval_profiles','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.capabilities','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND \
                   NOT has_table_privilege('public.capability_versions','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
            Ok::<bool, RegistryError>(tables_ready && privileges_ready && least_privilege_ready)
        };
        tokio::time::timeout(Duration::from_millis(500), check)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }

    pub async fn publisher_ready(&self, tenant: &TenantId) -> bool {
        let check = async {
            let signer = self.signer()?;
            let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
            require_publisher_key(
                &mut transaction,
                tenant_uuid,
                &signer.publisher_id,
                &signer.key_id,
                &signer.verifying_key(),
            )
            .await?;
            verify_current_active_state(&mut transaction, tenant, tenant_uuid).await?;
            transaction
                .commit()
                .await
                .map_err(|_| RegistryError::StoreFailure)
        };
        tokio::time::timeout(Duration::from_millis(500), check)
            .await
            .ok()
            .and_then(Result::ok)
            .is_some()
    }
}

#[async_trait]
impl ToolRegistry for PostgresRegistryStore {
    async fn resolve_exact(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, RegistryError> {
        if self
            .tenant_scope
            .as_ref()
            .is_some_and(|scope| scope != tenant)
        {
            return Err(RegistryError::ToolNotFound);
        }
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let row = select_tool_row(&mut transaction, tenant_uuid, tool, false)
            .await?
            .ok_or(RegistryError::ToolNotFound)?;
        match row_status(&row)? {
            ToolVersionStatus::Revoked => return Err(RegistryError::ToolRevoked),
            ToolVersionStatus::Active => {}
            _ => return Err(RegistryError::VersionNotActive),
        }
        let tool_revision = row_revision(&row)?;
        let revision_i64 = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM registry_tenant_revisions WHERE tenant_id=$1",
        )
        .bind(tenant_uuid)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?
        .ok_or(RegistryError::VersionNotActive)?;
        let revision = u64::try_from(revision_i64).map_err(|_| RegistryError::StoreFailure)?;
        let stored_manifest_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        let stored_schema_hash: String = row
            .try_get("schema_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        let snapshot =
            load_signed_snapshot(&mut transaction, tenant, tenant_uuid, revision).await?;
        let resolved = snapshot
            .tools
            .iter()
            .find(|candidate| {
                candidate.tool_id == tool.tool_id && candidate.tool_version == tool.tool_version
            })
            .cloned()
            .ok_or(RegistryError::ManifestHashMismatch)?;
        if resolved.registry_revision != tool_revision
            || resolved.manifest_hash != stored_manifest_hash
            || resolved.schema_hash != stored_schema_hash
        {
            return Err(RegistryError::ManifestHashMismatch);
        }
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(resolved)
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
        query: CapabilityQuery,
    ) -> Result<Vec<CapabilityDescriptor>, RegistryError> {
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&query.tenant_id).await?;
        let rows = sqlx::query(
            "SELECT manifest FROM capability_versions \
             WHERE tenant_id=$1 AND status='ACTIVE' ORDER BY capability_id,capability_version",
        )
        .bind(tenant_uuid)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
        let mut result = Vec::new();
        for row in rows {
            let manifest: CapabilityManifest = serde_json::from_value(
                row.try_get("manifest")
                    .map_err(|_| RegistryError::StoreFailure)?,
            )
            .map_err(|_| RegistryError::SchemaInvalid)?;
            verify_capability_signature(&mut transaction, tenant_uuid, &manifest).await?;
            if manifest.schema_version == REGISTRY_SCHEMA_VERSION
                && (manifest.allowed_tenants.is_empty()
                    || manifest.allowed_tenants.contains(&query.tenant_id))
                && manifest.risk_summary <= query.maximum_risk
                && query
                    .protocol
                    .as_ref()
                    .is_none_or(|protocol| manifest.supported_protocols.contains(protocol))
            {
                result.push(CapabilityDescriptor {
                    manifest,
                    discovery_only: true,
                    authorization_required: true,
                });
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(result)
    }

    async fn snapshot(
        &self,
        tenant: &TenantId,
        refs: &[ToolRef],
    ) -> Result<RegistrySnapshot, RegistryError> {
        for tool in refs {
            tool.validate_exact()
                .map_err(|_| RegistryError::VersionRequired)?;
        }
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let revision_i64 = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM registry_tenant_revisions WHERE tenant_id=$1",
        )
        .bind(tenant_uuid)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?
        .ok_or(RegistryError::VersionNotActive)?;
        let revision = u64::try_from(revision_i64).map_err(|_| RegistryError::StoreFailure)?;
        let snapshot =
            load_signed_snapshot(&mut transaction, tenant, tenant_uuid, revision).await?;
        for tool in refs {
            if !snapshot.tools.iter().any(|candidate| {
                candidate.tool_id == tool.tool_id && candidate.tool_version == tool.tool_version
            }) {
                return Err(RegistryError::VersionNotActive);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(snapshot)
    }

    async fn is_revoked(&self, tool: &ToolRef, digest: &str) -> Result<bool, RegistryError> {
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let tenant = self
            .tenant_scope
            .as_ref()
            .ok_or(RegistryError::TenantRequired)?;
        self.is_revoked_for_tenant(tenant, tool, digest).await
    }
}

impl PostgresRegistryStore {
    pub async fn is_revoked_for_tenant(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
        digest: &str,
    ) -> Result<bool, RegistryError> {
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let row = sqlx::query(
            "SELECT status,implementation_digest FROM tool_versions \
             WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3",
        )
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?
        .ok_or(RegistryError::ToolNotFound)?;
        let status: String = row
            .try_get("status")
            .map_err(|_| RegistryError::StoreFailure)?;
        let implementation_digest: String = row
            .try_get("implementation_digest")
            .map_err(|_| RegistryError::StoreFailure)?;
        transaction
            .commit()
            .await
            .map_err(|_| RegistryError::StoreFailure)?;
        Ok(status != "ACTIVE" || implementation_digest != digest)
    }
}

fn tenant_uuid(tenant: &TenantId) -> Result<Uuid, RegistryError> {
    let parsed = Uuid::parse_str(&tenant.0).map_err(|_| RegistryError::SchemaInvalid)?;
    if parsed.to_string() != tenant.0 {
        return Err(RegistryError::SchemaInvalid);
    }
    Ok(parsed)
}

fn validate_actor(actor_subject: &str) -> Result<(), RegistryError> {
    if actor_subject.trim().is_empty() || actor_subject.len() > 256 {
        return Err(RegistryError::ManagementForbidden);
    }
    Ok(())
}

fn validate_idempotency_key(key: &str) -> Result<(), RegistryError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/".contains(&byte))
    {
        return Err(RegistryError::IdempotencyInvalid);
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn effect_class_db(effect: EffectClass) -> &'static str {
    match effect {
        EffectClass::Pure => "PURE",
        EffectClass::Idempotent => "IDEMPOTENT",
        EffectClass::Compensatable => "COMPENSATABLE",
        EffectClass::Irreversible => "IRREVERSIBLE",
    }
}

fn risk_level_db(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}

fn status_db(status: ToolVersionStatus) -> &'static str {
    match status {
        ToolVersionStatus::Draft => "DRAFT",
        ToolVersionStatus::Validated => "VALIDATED",
        ToolVersionStatus::Signed => "SIGNED",
        ToolVersionStatus::Active => "ACTIVE",
        ToolVersionStatus::Deprecated => "DEPRECATED",
        ToolVersionStatus::Revoked => "REVOKED",
    }
}

fn parse_status(status: &str) -> Result<ToolVersionStatus, RegistryError> {
    match status {
        "DRAFT" => Ok(ToolVersionStatus::Draft),
        "VALIDATED" => Ok(ToolVersionStatus::Validated),
        "SIGNED" => Ok(ToolVersionStatus::Signed),
        "ACTIVE" => Ok(ToolVersionStatus::Active),
        "DEPRECATED" => Ok(ToolVersionStatus::Deprecated),
        "REVOKED" => Ok(ToolVersionStatus::Revoked),
        _ => Err(RegistryError::StoreFailure),
    }
}

fn row_status(row: &sqlx::postgres::PgRow) -> Result<ToolVersionStatus, RegistryError> {
    parse_status(
        &row.try_get::<String, _>("status")
            .map_err(|_| RegistryError::StoreFailure)?,
    )
}

fn row_revision(row: &sqlx::postgres::PgRow) -> Result<u64, RegistryError> {
    let revision = row
        .try_get::<Option<i64>, _>("registry_revision")
        .map_err(|_| RegistryError::StoreFailure)?
        .ok_or(RegistryError::ManifestHashMismatch)?;
    u64::try_from(revision).map_err(|_| RegistryError::StoreFailure)
}

fn manifest_from_row(row: &sqlx::postgres::PgRow) -> Result<ToolManifest, RegistryError> {
    let mut manifest: ToolManifest = serde_json::from_value(
        row.try_get("manifest")
            .map_err(|_| RegistryError::StoreFailure)?,
    )
    .map_err(|_| RegistryError::SchemaInvalid)?;
    manifest.status = row_status(row)?;
    Ok(manifest)
}

async fn select_tool_row(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    tool: &ToolRef,
    for_update: bool,
) -> Result<Option<sqlx::postgres::PgRow>, RegistryError> {
    let sql = if for_update {
        "SELECT status,manifest,manifest_hash,COALESCE(schema_hash,'') AS schema_hash,registry_revision \
         FROM tool_versions WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3 FOR UPDATE"
    } else {
        "SELECT status,manifest,manifest_hash,COALESCE(schema_hash,'') AS schema_hash,registry_revision \
         FROM tool_versions WHERE tenant_id=$1 AND tool_id=$2 AND tool_version=$3"
    };
    sqlx::query(sql)
        .bind(tenant_uuid)
        .bind(&tool.tool_id.0)
        .bind(&tool.tool_version.0)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    lock_key: &str,
) -> Result<(), RegistryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RegistryError::StoreFailure)?;
    Ok(())
}

async fn advisory_tool_lock(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    tool: &ToolRef,
) -> Result<(), RegistryError> {
    advisory_lock(
        transaction,
        &format!(
            "registry:tool:{}:{}:{}",
            tenant.0, tool.tool_id.0, tool.tool_version.0
        ),
    )
    .await
}

async fn require_compensation_exists(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    manifest: &ToolManifest,
    require_active: bool,
) -> Result<(), RegistryError> {
    let Some(binding) = &manifest.compensation else {
        return Ok(());
    };
    if binding.tool == manifest.tool_ref() {
        return Ok(());
    }
    let exists = if require_active {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM tool_versions WHERE tenant_id=$1 \
             AND tool_id=$2 AND tool_version=$3 AND status='ACTIVE')",
        )
        .bind(tenant_uuid)
        .bind(&binding.tool.tool_id.0)
        .bind(&binding.tool.tool_version.0)
        .fetch_one(&mut **transaction)
        .await
    } else {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM tool_versions WHERE tenant_id=$1 \
             AND tool_id=$2 AND tool_version=$3)",
        )
        .bind(tenant_uuid)
        .bind(&binding.tool.tool_id.0)
        .bind(&binding.tool.tool_version.0)
        .fetch_one(&mut **transaction)
        .await
    }
    .map_err(|_| RegistryError::StoreFailure)?;
    if !exists {
        return Err(RegistryError::CompensationInvalid);
    }
    Ok(())
}

async fn require_profiles_exist(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    manifest: &ToolManifest,
) -> Result<(), RegistryError> {
    let ready = sqlx::query_scalar::<_, bool>(
        "SELECT \
           EXISTS(SELECT 1 FROM executor_profiles WHERE tenant_id=$1 AND profile_id=$2) AND \
           ($3 = 'none' OR EXISTS(SELECT 1 FROM credential_profiles WHERE tenant_id=$1 AND profile_id=$3)) AND \
           ($4 = 'none' OR EXISTS(SELECT 1 FROM approval_profiles WHERE tenant_id=$1 AND profile_id=$4))",
    )
    .bind(tenant_uuid)
    .bind(&manifest.executor_profile)
    .bind(&manifest.credential_profile)
    .bind(&manifest.approval_profile)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    if !ready {
        return Err(RegistryError::ProfileNotFound);
    }
    Ok(())
}

async fn require_publisher_key(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    publisher_id: &str,
    key_id: &str,
    expected: &VerifyingKey,
) -> Result<(), RegistryError> {
    let row = sqlx::query(
        "SELECT algorithm,public_key,status FROM registry_publisher_keys \
         WHERE tenant_id=$1 AND publisher_id=$2 AND key_id=$3",
    )
    .bind(tenant_uuid)
    .bind(publisher_id)
    .bind(key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?
    .ok_or(RegistryError::PublisherInvalid)?;
    let algorithm: String = row
        .try_get("algorithm")
        .map_err(|_| RegistryError::StoreFailure)?;
    let public_key: Vec<u8> = row
        .try_get("public_key")
        .map_err(|_| RegistryError::StoreFailure)?;
    let status: String = row
        .try_get("status")
        .map_err(|_| RegistryError::StoreFailure)?;
    if algorithm != SNAPSHOT_SIGNATURE_ALGORITHM
        || status != "ACTIVE"
        || public_key.as_slice() != expected.as_bytes()
    {
        return Err(RegistryError::PublisherInvalid);
    }
    Ok(())
}

async fn load_publisher_key(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    signature: &ManifestSignature,
) -> Result<VerifyingKey, RegistryError> {
    if signature.algorithm != SNAPSHOT_SIGNATURE_ALGORITHM {
        return Err(RegistryError::SignatureInvalid);
    }
    let raw = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT public_key FROM registry_publisher_keys WHERE tenant_id=$1 \
         AND publisher_id=$2 AND key_id=$3 AND algorithm='Ed25519' AND status='ACTIVE'",
    )
    .bind(tenant_uuid)
    .bind(&signature.publisher_id)
    .bind(&signature.key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?
    .ok_or(RegistryError::SignatureInvalid)?;
    let key_bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::SignatureInvalid)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| RegistryError::SignatureInvalid)
}

async fn verify_tool_signature(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    manifest: &ToolManifest,
    manifest_hash: &str,
) -> Result<(), RegistryError> {
    let signature = manifest
        .signature
        .as_ref()
        .ok_or(RegistryError::SignatureInvalid)?;
    let key = load_publisher_key(transaction, tenant_uuid, signature).await?;
    let raw_signature = URL_SAFE_NO_PAD
        .decode(&signature.signature)
        .map_err(|_| RegistryError::SignatureInvalid)?;
    let persisted_signature = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT signature FROM tool_signatures WHERE tenant_id=$1 AND tool_id=$2 \
         AND tool_version=$3 AND publisher_id=$4 AND key_id=$5 AND algorithm='Ed25519'",
    )
    .bind(tenant_uuid)
    .bind(&manifest.tool_id.0)
    .bind(&manifest.tool_version.0)
    .bind(&signature.publisher_id)
    .bind(&signature.key_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?
    .ok_or(RegistryError::SignatureInvalid)?;
    if persisted_signature != raw_signature {
        return Err(RegistryError::SignatureInvalid);
    }
    let signature =
        Signature::from_slice(&raw_signature).map_err(|_| RegistryError::SignatureInvalid)?;
    key.verify(manifest_hash.as_bytes(), &signature)
        .map_err(|_| RegistryError::SignatureInvalid)
}

async fn allocate_revision(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
) -> Result<u64, RegistryError> {
    let revision = sqlx::query_scalar::<_, i64>(
        "INSERT INTO registry_tenant_revisions (tenant_id,revision) VALUES ($1,1) \
         ON CONFLICT (tenant_id) DO UPDATE \
         SET revision=registry_tenant_revisions.revision+1,updated_at=now() \
         RETURNING revision",
    )
    .bind(tenant_uuid)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    u64::try_from(revision).map_err(|_| RegistryError::StoreFailure)
}

async fn publish_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    tenant_uuid: Uuid,
    revision: u64,
    signer: &RegistryPublisherSigner,
) -> Result<RegistrySnapshot, RegistryError> {
    require_publisher_key(
        transaction,
        tenant_uuid,
        &signer.publisher_id,
        &signer.key_id,
        &signer.verifying_key(),
    )
    .await?;
    let rows = sqlx::query(
        "SELECT status,manifest,manifest_hash,COALESCE(schema_hash,'') AS schema_hash,registry_revision \
         FROM tool_versions WHERE tenant_id=$1 AND status='ACTIVE' ORDER BY tool_id,tool_version FOR SHARE",
    )
    .bind(tenant_uuid)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    if rows.len() > 1_000 {
        return Err(RegistryError::UnavailableFailClosed);
    }
    let active_refs = rows
        .iter()
        .map(manifest_from_row)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|manifest| manifest.tool_ref())
        .collect::<BTreeSet<_>>();
    let signed_at = DateTime::<Utc>::from_timestamp_micros(Utc::now().timestamp_micros())
        .ok_or(RegistryError::StoreFailure)?;
    let mut tools = Vec::with_capacity(rows.len());
    for row in rows {
        let mut manifest = manifest_from_row(&row)?;
        manifest.status = ToolVersionStatus::Active;
        let manifest_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        let schema_hash: String = row
            .try_get("schema_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if canonical_manifest_hash(&manifest)? != manifest_hash
            || canonical_schema_pair_hash(&manifest)? != schema_hash
        {
            return Err(RegistryError::ManifestHashMismatch);
        }
        require_profiles_exist(transaction, tenant_uuid, &manifest).await?;
        verify_tool_signature(transaction, tenant_uuid, &manifest, &manifest_hash).await?;
        let compensation_active = manifest
            .compensation
            .as_ref()
            .is_none_or(|binding| active_refs.contains(&binding.tool));
        let mut resolved =
            resolved_snapshot_from_active_manifest(tenant, &manifest, compensation_active)?;
        resolved.registry_revision = row_revision(&row)?;
        resolved.resolved_at = signed_at;
        resolved.snapshot_hash = snapshot_hash(&resolved)?;
        tools.push(resolved);
    }
    let mut snapshot = RegistrySnapshot {
        schema_version: REGISTRY_SCHEMA_VERSION.into(),
        tenant_id: tenant.clone(),
        revision,
        tools,
        snapshot_hash: String::new(),
        signed_at,
        signature: None,
    };
    snapshot.snapshot_hash = canonical_registry_snapshot_hash(&snapshot)?;
    let raw_signature = signer
        .signing_key
        .sign(snapshot.snapshot_hash.as_bytes())
        .to_bytes();
    snapshot.signature = Some(ManifestSignature {
        publisher_id: signer.publisher_id.clone(),
        key_id: signer.key_id.clone(),
        algorithm: SNAPSHOT_SIGNATURE_ALGORITHM.into(),
        signature: URL_SAFE_NO_PAD.encode(raw_signature),
    });
    let snapshot_value =
        serde_json::to_value(&snapshot).map_err(|_| RegistryError::SchemaInvalid)?;
    sqlx::query(
        "INSERT INTO registry_snapshots \
         (tenant_id,revision,snapshot,snapshot_hash,signature,publisher_id,key_id,algorithm,signed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'Ed25519',$8)",
    )
    .bind(tenant_uuid)
    .bind(i64::try_from(revision).map_err(|_| RegistryError::StoreFailure)?)
    .bind(snapshot_value)
    .bind(&snapshot.snapshot_hash)
    .bind(raw_signature.as_slice())
    .bind(&signer.publisher_id)
    .bind(&signer.key_id)
    .bind(snapshot.signed_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    Ok(snapshot)
}

async fn verify_current_active_state(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    tenant_uuid: Uuid,
) -> Result<(), RegistryError> {
    let revision = sqlx::query_scalar::<_, i64>(
        "SELECT revision FROM registry_tenant_revisions WHERE tenant_id=$1",
    )
    .bind(tenant_uuid)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    let rows = sqlx::query(
        "SELECT status,manifest,manifest_hash,COALESCE(schema_hash,'') AS schema_hash,registry_revision \
         FROM tool_versions WHERE tenant_id=$1 AND status='ACTIVE' ORDER BY tool_id,tool_version",
    )
    .bind(tenant_uuid)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    if rows.len() > 1_000 {
        return Err(RegistryError::UnavailableFailClosed);
    }
    let Some(revision) = revision else {
        return if rows.is_empty() {
            Ok(())
        } else {
            Err(RegistryError::ManifestHashMismatch)
        };
    };
    let revision = u64::try_from(revision).map_err(|_| RegistryError::StoreFailure)?;
    let snapshot = load_signed_snapshot(transaction, tenant, tenant_uuid, revision).await?;
    if snapshot.tools.len() != rows.len() {
        return Err(RegistryError::ManifestHashMismatch);
    }
    for row in rows {
        let manifest = manifest_from_row(&row)?;
        let manifest_hash: String = row
            .try_get("manifest_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        let schema_hash: String = row
            .try_get("schema_hash")
            .map_err(|_| RegistryError::StoreFailure)?;
        if canonical_manifest_hash(&manifest)? != manifest_hash
            || canonical_schema_pair_hash(&manifest)? != schema_hash
        {
            return Err(RegistryError::ManifestHashMismatch);
        }
        require_profiles_exist(transaction, tenant_uuid, &manifest).await?;
        verify_tool_signature(transaction, tenant_uuid, &manifest, &manifest_hash).await?;
        let expected_revision = row_revision(&row)?;
        if !snapshot.tools.iter().any(|tool| {
            tool.tool_id == manifest.tool_id
                && tool.tool_version == manifest.tool_version
                && tool.manifest_hash == manifest_hash
                && tool.schema_hash == schema_hash
                && tool.registry_revision == expected_revision
        }) {
            return Err(RegistryError::ManifestHashMismatch);
        }
    }
    Ok(())
}

async fn load_signed_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    tenant_uuid: Uuid,
    revision: u64,
) -> Result<RegistrySnapshot, RegistryError> {
    let row = sqlx::query(
        "SELECT snapshot,snapshot_hash,signature,publisher_id,key_id,algorithm,signed_at \
         FROM registry_snapshots WHERE tenant_id=$1 AND revision=$2",
    )
    .bind(tenant_uuid)
    .bind(i64::try_from(revision).map_err(|_| RegistryError::StoreFailure)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?
    .ok_or(RegistryError::ManifestHashMismatch)?;
    let snapshot: RegistrySnapshot = serde_json::from_value(
        row.try_get("snapshot")
            .map_err(|_| RegistryError::StoreFailure)?,
    )
    .map_err(|_| RegistryError::SchemaInvalid)?;
    let stored_hash: String = row
        .try_get("snapshot_hash")
        .map_err(|_| RegistryError::StoreFailure)?;
    let stored_signature: Vec<u8> = row
        .try_get("signature")
        .map_err(|_| RegistryError::StoreFailure)?;
    let publisher_id: String = row
        .try_get("publisher_id")
        .map_err(|_| RegistryError::StoreFailure)?;
    let key_id: String = row
        .try_get("key_id")
        .map_err(|_| RegistryError::StoreFailure)?;
    let algorithm: String = row
        .try_get("algorithm")
        .map_err(|_| RegistryError::StoreFailure)?;
    let signed_at: DateTime<Utc> = row
        .try_get("signed_at")
        .map_err(|_| RegistryError::StoreFailure)?;
    let signature = snapshot
        .signature
        .as_ref()
        .ok_or(RegistryError::SignatureInvalid)?;
    if snapshot.schema_version != REGISTRY_SCHEMA_VERSION
        || snapshot.tenant_id != *tenant
        || snapshot.revision != revision
        || snapshot.signed_at != signed_at
        || snapshot.snapshot_hash != stored_hash
        || signature.publisher_id != publisher_id
        || signature.key_id != key_id
        || signature.algorithm != algorithm
        || canonical_registry_snapshot_hash(&snapshot)? != stored_hash
    {
        return Err(RegistryError::ManifestHashMismatch);
    }
    let decoded_signature = URL_SAFE_NO_PAD
        .decode(&signature.signature)
        .map_err(|_| RegistryError::SignatureInvalid)?;
    if decoded_signature != stored_signature {
        return Err(RegistryError::SignatureInvalid);
    }
    let key = load_publisher_key(transaction, tenant_uuid, signature).await?;
    let signature =
        Signature::from_slice(&stored_signature).map_err(|_| RegistryError::SignatureInvalid)?;
    key.verify(stored_hash.as_bytes(), &signature)
        .map_err(|_| RegistryError::SignatureInvalid)?;
    Ok(snapshot)
}

async fn verify_capability_signature(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    manifest: &CapabilityManifest,
) -> Result<(), RegistryError> {
    if manifest.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(RegistryError::SchemaInvalid);
    }
    let key = load_publisher_key(transaction, tenant_uuid, &manifest.signature).await?;
    let mut material = manifest.clone();
    material.signature.signature.clear();
    let hash = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&material).map_err(|_| RegistryError::ManifestHashMismatch)?,
    ));
    let raw = URL_SAFE_NO_PAD
        .decode(&manifest.signature.signature)
        .map_err(|_| RegistryError::SignatureInvalid)?;
    let signature = Signature::from_slice(&raw).map_err(|_| RegistryError::SignatureInvalid)?;
    key.verify(hash.as_bytes(), &signature)
        .map_err(|_| RegistryError::SignatureInvalid)
}

async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    tool: Option<&ToolRef>,
    event_type: &str,
    actor_subject: &str,
    payload: Value,
    idempotency_key: Option<&str>,
) -> Result<Uuid, RegistryError> {
    let event_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO registry_events \
         (event_id,tenant_id,tool_id,tool_version,event_type,actor_subject,event_payload,idempotency_key) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(event_id)
    .bind(tenant_uuid)
    .bind(tool.map(|value| value.tool_id.0.as_str()))
    .bind(tool.map(|value| value.tool_version.0.as_str()))
    .bind(event_type)
    .bind(actor_subject)
    .bind(payload)
    .bind(idempotency_key)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    Ok(event_id)
}

fn mutation_request_digest(
    tenant: &TenantId,
    tool: &ToolRef,
    operation: &str,
    request: &RegistryActivationRequest,
) -> Result<String, RegistryError> {
    if request.schema_version != REGISTRY_SCHEMA_VERSION
        || !is_sha256_hex(&request.expected_manifest_hash)
        || !matches!(
            operation,
            "VALIDATE" | "SIGN" | "ACTIVATE" | "DEPRECATE" | "REVOKE"
        )
    {
        return Err(RegistryError::SchemaInvalid);
    }
    let material = serde_json::json!({
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "tenant_id": &tenant.0,
        "tool_id": &tool.tool_id.0,
        "tool_version": &tool.tool_version.0,
        "operation": operation,
        "expected_manifest_hash": &request.expected_manifest_hash,
    });
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&material).map_err(|_| RegistryError::ManifestHashMismatch)?,
    )))
}

async fn load_mutation_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    tenant_uuid: Uuid,
    tool: &ToolRef,
    operation: &str,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<Option<RegistryActivationReceipt>, RegistryError> {
    let row = sqlx::query(
        "SELECT operation,request_digest,response_receipt \
         FROM registry_idempotency_records WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(tenant_uuid)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_operation: String = row
        .try_get("operation")
        .map_err(|_| RegistryError::StoreFailure)?;
    let stored_digest: String = row
        .try_get("request_digest")
        .map_err(|_| RegistryError::StoreFailure)?;
    if stored_operation != operation || stored_digest != request_digest {
        return Err(RegistryError::IdempotencyConflict);
    }
    let receipt: RegistryActivationReceipt = serde_json::from_value(
        row.try_get("response_receipt")
            .map_err(|_| RegistryError::StoreFailure)?,
    )
    .map_err(|_| RegistryError::StoreFailure)?;
    if receipt.schema_version != REGISTRY_SCHEMA_VERSION
        || receipt.tenant_id != *tenant
        || receipt.tool_id != tool.tool_id
        || receipt.tool_version != tool.tool_version
        || receipt.operation != operation
    {
        return Err(RegistryError::StoreFailure);
    }
    Ok(Some(receipt))
}

async fn store_mutation_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    operation: &str,
    request_digest: &str,
    idempotency_key: &str,
    receipt: &RegistryActivationReceipt,
) -> Result<(), RegistryError> {
    let receipt_value = serde_json::to_value(receipt).map_err(|_| RegistryError::StoreFailure)?;
    sqlx::query(
        "INSERT INTO registry_idempotency_records \
         (tenant_id,idempotency_key,operation,request_digest,response_receipt) \
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(tenant_uuid)
    .bind(idempotency_key)
    .bind(operation)
    .bind(request_digest)
    .bind(receipt_value)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .and_then(|database| database.code())
            .as_deref()
            == Some("23505")
        {
            RegistryError::IdempotencyConflict
        } else {
            RegistryError::StoreFailure
        }
    })?;
    Ok(())
}

async fn lifecycle_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    tool: &ToolRef,
    event_type: &str,
) -> Result<Uuid, RegistryError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT event_id FROM registry_events WHERE tenant_id=$1 AND tool_id=$2 \
         AND tool_version=$3 AND event_type=$4 ORDER BY created_at LIMIT 1",
    )
    .bind(tenant_uuid)
    .bind(&tool.tool_id.0)
    .bind(&tool.tool_version.0)
    .bind(event_type)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?
    .ok_or(RegistryError::StoreFailure)
}

async fn published_event_details(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    tool: &ToolRef,
    event_type: &str,
) -> Result<(Uuid, u64, String), RegistryError> {
    let row = sqlx::query(
        "SELECT event_id,event_payload FROM registry_events WHERE tenant_id=$1 AND tool_id=$2 \
         AND tool_version=$3 AND event_type=$4 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_uuid)
    .bind(&tool.tool_id.0)
    .bind(&tool.tool_version.0)
    .bind(event_type)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| RegistryError::StoreFailure)?
    .ok_or(RegistryError::StoreFailure)?;
    let event_id: Uuid = row
        .try_get("event_id")
        .map_err(|_| RegistryError::StoreFailure)?;
    let payload: Value = row
        .try_get("event_payload")
        .map_err(|_| RegistryError::StoreFailure)?;
    let revision = payload
        .get("registry_revision")
        .and_then(Value::as_u64)
        .ok_or(RegistryError::StoreFailure)?;
    let snapshot_hash = payload
        .get("snapshot_hash")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_hex(value))
        .ok_or(RegistryError::StoreFailure)?;
    Ok((event_id, revision, snapshot_hash.into()))
}

fn activation_receipt(
    tenant: &TenantId,
    tool: &ToolRef,
    revision: u64,
    manifest_hash: String,
    snapshot_hash: String,
    event_id: Uuid,
    idempotent: bool,
) -> RegistryActivationReceipt {
    mutation_receipt(
        tenant,
        tool,
        "ACTIVATE",
        ToolVersionStatus::Active,
        manifest_hash,
        Some(revision),
        Some(snapshot_hash),
        event_id,
        idempotent,
    )
}

#[allow(clippy::too_many_arguments)]
fn mutation_receipt(
    tenant: &TenantId,
    tool: &ToolRef,
    operation: &str,
    status: ToolVersionStatus,
    manifest_hash: String,
    registry_revision: Option<u64>,
    snapshot_hash: Option<String>,
    event_id: Uuid,
    idempotent: bool,
) -> RegistryActivationReceipt {
    RegistryActivationReceipt {
        schema_version: REGISTRY_SCHEMA_VERSION.into(),
        tenant_id: tenant.clone(),
        tool_id: tool.tool_id.clone(),
        tool_version: tool.tool_version.clone(),
        operation: operation.into(),
        status,
        registry_revision,
        manifest_hash,
        snapshot_hash,
        event_ref: format!("registry-event://{}/{event_id}", tenant.0),
        idempotent,
    }
}
