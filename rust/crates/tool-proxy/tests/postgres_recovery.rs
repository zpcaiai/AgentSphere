//! Dedicated PostgreSQL concurrency/restart conformance.
//!
//! Run only against a disposable database with the production migration applied:
//! `AGENT_TRUST_TOOL_PROXY_TEST_DATABASE_URL=... cargo test -p agent-trust-tool-proxy
//! --test postgres_recovery -- --ignored --exact concurrent_owner_fence_and_expired_recovery`.

use agent_trust_contracts::{IdempotencyKey, TenantId};
use agent_trust_tool_proxy::production::PostgresInvocationStore;
use sqlx::Row;
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance with Tool Proxy migration and app grants"]
async fn concurrent_owner_fence_and_expired_recovery() {
    let database_url = std::env::var("AGENT_TRUST_TOOL_PROXY_TEST_DATABASE_URL")
        .unwrap_or_else(|_| panic!("AGENT_TRUST_TOOL_PROXY_TEST_DATABASE_URL is required"));
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .unwrap_or_else(|error| panic!("database connection failed: {error}"));
    let store = PostgresInvocationStore::new(pool.clone());
    let tenant = TenantId(Uuid::new_v4().to_string());
    let key = IdempotencyKey(format!("tool-proxy-concurrency:{}", Uuid::new_v4()));
    insert_prepared(&pool, &tenant, &key).await;

    let owner_a = Uuid::new_v4().to_string();
    let owner_b = Uuid::new_v4().to_string();
    let (first, second) = tokio::join!(
        store.mark_executing(&tenant, &key, &owner_a, Duration::from_secs(5)),
        store.mark_executing(&tenant, &key, &owner_b, Duration::from_secs(5)),
    );
    assert_eq!((first.is_ok() as usize) + (second.is_ok() as usize), 1);

    tokio::time::sleep(Duration::from_millis(5_200)).await;
    let tenants = BTreeSet::from([tenant.clone()]);
    assert_eq!(
        store
            .recover_expired_executing(&tenants)
            .await
            .unwrap_or_else(|error| panic!("recovery failed: {error}")),
        1
    );
    let mut transaction = pool
        .begin()
        .await
        .unwrap_or_else(|error| panic!("transaction failed: {error}"));
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(&tenant.0)
        .execute(&mut *transaction)
        .await
        .unwrap_or_else(|error| panic!("tenant context failed: {error}"));
    let row = sqlx::query(
        "SELECT state,stable_error,execution_lease_until,completed_at FROM tool_proxy_invocations \
         WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(Uuid::parse_str(&tenant.0).unwrap_or_else(|error| panic!("tenant: {error}")))
    .bind(&key.0)
    .fetch_one(&mut *transaction)
    .await
    .unwrap_or_else(|error| panic!("state query failed: {error}"));
    assert_eq!(row.get::<String, _>("state"), "UNKNOWN");
    assert_eq!(
        row.get::<String, _>("stable_error"),
        "PROXY_CRASH_RECOVERY_UNKNOWN"
    );
    assert!(
        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("execution_lease_until")
            .is_none()
    );
    assert!(
        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at")
            .is_some()
    );
}

async fn insert_prepared(pool: &sqlx::PgPool, tenant: &TenantId, key: &IdempotencyKey) {
    let tenant_uuid =
        Uuid::parse_str(&tenant.0).unwrap_or_else(|error| panic!("tenant UUID failed: {error}"));
    let mut transaction = pool
        .begin()
        .await
        .unwrap_or_else(|error| panic!("transaction failed: {error}"));
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(&tenant.0)
        .execute(&mut *transaction)
        .await
        .unwrap_or_else(|error| panic!("tenant context failed: {error}"));
    sqlx::query(
        "INSERT INTO tool_proxy_invocations \
         (tenant_id,idempotency_key,request_digest,authorization_id,authorization_digest,\
          ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,action_hash,trace_id,tool_id,tool_version,\
          tool_snapshot_hash,registry_revision,credential_claims_digest,target_profile_hash,state) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,$15,$16,'PREPARED')",
    )
    .bind(tenant_uuid)
    .bind(&key.0)
    .bind("1".repeat(64))
    .bind(Uuid::new_v4().to_string())
    .bind("2".repeat(64))
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind("8".repeat(64))
    .bind("3".repeat(64))
    .bind("4".repeat(64))
    .bind(format!("trace-{}", Uuid::new_v4()))
    .bind("http.test")
    .bind("1.0.0")
    .bind("5".repeat(64))
    .bind("6".repeat(64))
    .bind("7".repeat(64))
    .execute(&mut *transaction)
    .await
    .unwrap_or_else(|error| panic!("prepared insert failed: {error}"));
    transaction
        .commit()
        .await
        .unwrap_or_else(|error| panic!("commit failed: {error}"));
}
