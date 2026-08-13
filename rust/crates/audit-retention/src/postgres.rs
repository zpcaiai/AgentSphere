use super::{
    AUDIT_SCHEMA_VERSION, AuditError, AuditExportPackage, AuditRecord, IntegrityVerifier, LegalHold,
};
use agent_trust_contracts::TenantId;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresAuditRepository {
    pool: PgPool,
}

impl PostgresAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn append(&self, records: &[AuditRecord]) -> Result<(), AuditError> {
        if records.is_empty()
            || records.iter().any(|record| {
                record.schema_version != AUDIT_SCHEMA_VERSION
                    || record.draft.tenant_id != records[0].draft.tenant_id
            })
        {
            return Err(AuditError::RecordInvalid);
        }
        let tenant_uuid = Uuid::parse_str(&records[0].draft.tenant_id.0)
            .map_err(|_| AuditError::PersistenceFailed)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant_uuid.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("audit-chain:{tenant_uuid}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;

        let existing_rows = sqlx::query(
            "SELECT record_id, record_hash FROM audit_records WHERE tenant_id=$1 AND record_id = ANY($2)",
        )
        .bind(tenant_uuid)
        .bind(
            records
                .iter()
                .map(|record| Uuid::parse_str(&record.record_id))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AuditError::PersistenceFailed)?,
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        if !existing_rows.is_empty() {
            let all_match = existing_rows.len() == records.len()
                && records.iter().all(|record| {
                    existing_rows.iter().any(|row| {
                        row.try_get::<Uuid, _>("record_id")
                            .ok()
                            .is_some_and(|id| id.to_string() == record.record_id)
                            && row
                                .try_get::<String, _>("record_hash")
                                .ok()
                                .is_some_and(|hash| hash == record.record_hash)
                    })
                });
            if all_match {
                transaction
                    .commit()
                    .await
                    .map_err(|_| AuditError::PersistenceFailed)?;
                return Ok(());
            }
            return Err(AuditError::IdempotencyConflict);
        }

        let head = sqlx::query(
            "SELECT last_sequence, chain_hash FROM audit_chain_heads WHERE tenant_id=$1 AND stream_id='default' FOR UPDATE",
        )
        .bind(tenant_uuid)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let (mut expected_sequence, mut expected_previous) = match head {
            Some(row) => (
                row.try_get::<i64, _>("last_sequence")
                    .map_err(|_| AuditError::PersistenceFailed)? as u64
                    + 1,
                row.try_get::<String, _>("chain_hash")
                    .map_err(|_| AuditError::PersistenceFailed)?,
            ),
            None => (1, "0".repeat(64)),
        };
        for record in records {
            let computed_hash = hex(Sha256::digest(record.unsigned_bytes()?));
            if record.sequence != expected_sequence
                || record.previous_hash != expected_previous
                || record.record_hash != computed_hash
            {
                return Err(AuditError::IntegrityFailed);
            }
            let record_id =
                Uuid::parse_str(&record.record_id).map_err(|_| AuditError::PersistenceFailed)?;
            let payload =
                serde_json::to_value(record).map_err(|_| AuditError::PersistenceFailed)?;
            sqlx::query(
                "INSERT INTO audit_records(tenant_id,record_id,sequence,previous_hash,record_hash,key_id,signature,record_payload,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(tenant_uuid)
            .bind(record_id)
            .bind(record.sequence as i64)
            .bind(&record.previous_hash)
            .bind(&record.record_hash)
            .bind(&record.key_id)
            .bind(&record.signature)
            .bind(payload)
            .bind(record.draft.occurred_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
            expected_sequence = expected_sequence.saturating_add(1);
            expected_previous = record.record_hash.clone();
        }
        sqlx::query(
            "INSERT INTO audit_chain_heads(tenant_id,stream_id,last_sequence,chain_hash,key_id) VALUES($1,'default',$2,$3,$4) ON CONFLICT(tenant_id,stream_id) DO UPDATE SET last_sequence=EXCLUDED.last_sequence,chain_hash=EXCLUDED.chain_hash,key_id=EXCLUDED.key_id,updated_at=now()",
        )
        .bind(tenant_uuid)
        .bind((expected_sequence - 1) as i64)
        .bind(expected_previous)
        .bind(&records[records.len() - 1].key_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)
    }

    pub async fn load_tenant(
        &self,
        tenant: &TenantId,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        if offset < 0 || !(1..=10_000).contains(&limit) {
            return Err(AuditError::QueryDenied);
        }
        let tenant_uuid = Uuid::parse_str(&tenant.0).map_err(|_| AuditError::PersistenceFailed)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant_uuid.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        let rows = sqlx::query(
            "SELECT record_payload FROM audit_records WHERE tenant_id=$1 ORDER BY sequence OFFSET $2 LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(offset)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        let result = rows
            .into_iter()
            .map(|row| {
                let value = row
                    .try_get::<serde_json::Value, _>("record_payload")
                    .map_err(|_| AuditError::PersistenceFailed)?;
                serde_json::from_value(value).map_err(|_| AuditError::PersistenceFailed)
            })
            .collect();
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        result
    }

    pub async fn persist_export(
        &self,
        package: &AuditExportPackage,
        object_ref: &str,
        verifier: &IntegrityVerifier,
    ) -> Result<(), AuditError> {
        if object_ref.is_empty() || !object_ref.starts_with("object://") {
            return Err(AuditError::RecordInvalid);
        }
        verifier.verify(package)?;
        let tenant = Uuid::parse_str(&package.manifest.tenant_id.0)
            .map_err(|_| AuditError::PersistenceFailed)?;
        let export_id = Uuid::parse_str(&package.manifest.export_id)
            .map_err(|_| AuditError::PersistenceFailed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&package.manifest.signature)
            .map_err(|_| AuditError::SignatureInvalid)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query(
            "INSERT INTO audit_export_manifests(tenant_id,export_id,manifest_digest,chain_head,object_ref,key_id,signature,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,export_id) DO NOTHING",
        )
        .bind(tenant)
        .bind(export_id)
        .bind(&package.manifest.manifest_hash)
        .bind(&package.manifest.chain_head)
        .bind(object_ref)
        .bind(&package.manifest.key_id)
        .bind(signature)
        .bind(package.manifest.exported_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)
    }

    pub async fn persist_hold(&self, hold: &LegalHold) -> Result<(), AuditError> {
        let tenant =
            Uuid::parse_str(&hold.tenant_id.0).map_err(|_| AuditError::PersistenceFailed)?;
        let hold_id = Uuid::parse_str(&hold.hold_id).map_err(|_| AuditError::PersistenceFailed)?;
        let object_ref = hold
            .task_id
            .as_ref()
            .map(|task| format!("task:{}", task.0))
            .or_else(|| hold.resource_prefix.clone())
            .or_else(|| {
                hold.actor_subject
                    .as_ref()
                    .map(|actor| format!("actor:{actor}"))
            })
            .ok_or(AuditError::LegalHoldInvalid)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuditError::PersistenceFailed)?;
        sqlx::query(
            "INSERT INTO legal_holds(tenant_id,hold_id,object_ref,reason,placed_by,released_by,placed_at,released_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,hold_id) DO UPDATE SET released_by=EXCLUDED.released_by,released_at=EXCLUDED.released_at WHERE legal_holds.object_ref=EXCLUDED.object_ref AND legal_holds.reason=EXCLUDED.reason AND legal_holds.placed_by=EXCLUDED.placed_by",
        )
        .bind(tenant)
        .bind(hold_id)
        .bind(object_ref)
        .bind(&hold.reason_code)
        .bind(&hold.placed_by)
        .bind(&hold.released_by)
        .bind(hold.starts_at)
        .bind(hold.released_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuditError::PersistenceFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditError::PersistenceFailed)
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
