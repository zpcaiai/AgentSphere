use agent_trust_audit_retention::{
    AUDIT_SCHEMA_VERSION, AuditIngest, AuditRecordDraft, postgres::PostgresAuditRepository,
};
use agent_trust_contracts::*;
use agent_trust_registry::*;
use agent_trust_transaction_ledger::*;
use chrono::Utc;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{collections::BTreeSet, sync::Arc};
use tokio::task::JoinSet;
use uuid::Uuid;

async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("AGENT_TRUST_TEST_DATABASE_URL").ok()?;
    Some(
        PgPoolOptions::new()
            .max_connections(20)
            .connect(&url)
            .await
            .unwrap_or_else(|_| panic!("postgres test connection")),
    )
}

fn draft_manifest(tenant: &TenantId) -> ToolManifest {
    ToolManifest {
        schema_version: REGISTRY_SCHEMA_VERSION.into(),
        tool_id: ToolId(format!("coding.pg-test-{}", Uuid::new_v4())),
        tool_version: ToolVersion("1.0.0".into()),
        status: ToolVersionStatus::Draft,
        domain: "coding".into(),
        display_name: "Postgres test".into(),
        description: "Persistence conformance test".into(),
        input_schema: serde_json::json!({"type":"object","additionalProperties":false}),
        output_schema: serde_json::json!({"type":"object","additionalProperties":false}),
        effect_class: EffectClass::Pure,
        risk_level: RiskLevel::Low,
        executor_profile: "coding-read".into(),
        credential_profile: "none".into(),
        approval_profile: "none".into(),
        compensation: None,
        limits: ToolLimits {
            timeout_ms: 1000,
            max_result_bytes: 1024,
        },
        network_profile_ref: "none".into(),
        filesystem_profile_ref: "repo-ro".into(),
        implementation: ToolImplementation {
            kind: ImplementationKind::InternalService,
            digest: format!("sha256:{}", "a".repeat(64)),
            executor_id: "pg-test".into(),
        },
        allowed_tenants: BTreeSet::from([tenant.clone()]),
        signature: None,
    }
}

fn intent(tenant: TenantId, key: String) -> ExecutionIntent {
    ExecutionIntent {
        schema_version: LEDGER_SCHEMA_VERSION.into(),
        tenant_id: tenant,
        task_id: TaskId::new(),
        step_id: StepId::new(),
        action_hash: ActionHash("f".repeat(64)),
        idempotency_key: IdempotencyKey(key),
        tool: ToolRef {
            tool_id: ToolId("coding.pg-test".into()),
            tool_version: ToolVersion("1.0.0".into()),
        },
        effect_class: EffectClass::Pure,
        resource_version: None,
        canonical_arguments_hash: "e".repeat(64),
        compensation_plan: None,
        requested_at: Utc::now(),
    }
}

#[tokio::test]
async fn postgres_registry_and_ledger_are_durable_and_concurrency_safe() {
    let Some(pool) = test_pool().await else {
        eprintln!("SKIP: AGENT_TRUST_TEST_DATABASE_URL is not configured");
        return;
    };
    let unprotected_tenant_tables: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I', namespace.nspname, class.relname)
          FROM pg_class AS class
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = class.oid
         WHERE namespace.nspname = 'public'
           AND class.relkind IN ('r', 'p')
           AND attribute.attname = 'tenant_id'
           AND NOT attribute.attisdropped
           AND (NOT class.relrowsecurity OR NOT class.relforcerowsecurity)
         ORDER BY namespace.nspname, class.relname
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_else(|error| panic!("inspect tenant RLS: {error}"));
    assert!(
        unprotected_tenant_tables.is_empty(),
        "tenant tables without ENABLE and FORCE RLS: {unprotected_tenant_tables:?}"
    );
    let tenant = TenantId::new();
    let registry = PostgresRegistryStore::new(pool.clone());
    let manifest = draft_manifest(&tenant);
    let tool = manifest.tool_ref();
    registry
        .insert_draft(&tenant, &manifest)
        .await
        .unwrap_or_else(|error| panic!("insert registry draft: {error:?}"));
    let loaded = registry
        .load(&tenant, &tool)
        .await
        .unwrap_or_else(|error| panic!("load registry draft: {error:?}"));
    assert_eq!(loaded, manifest);

    let ledger = Arc::new(PostgresExecutionLedger::new(pool.clone()));
    let ledger_intent = intent(tenant.clone(), format!("pg:{}", Uuid::new_v4()));
    let mut tasks = JoinSet::new();
    for _ in 0..20 {
        let ledger = ledger.clone();
        let candidate = ledger_intent.clone();
        tasks.spawn(async move { ledger.reserve(candidate).await });
    }
    let mut reservations = Vec::new();
    while let Some(result) = tasks.join_next().await {
        reservations.push(
            result
                .unwrap_or_else(|_| panic!("reservation task"))
                .unwrap_or_else(|_| panic!("postgres reservation")),
        );
    }
    let execution_id = reservations[0].execution_id.clone();
    assert!(
        reservations
            .iter()
            .all(|reservation| reservation.execution_id == execution_id)
    );
    assert_eq!(
        reservations
            .iter()
            .filter(|reservation| !reservation.existing)
            .count(),
        1
    );

    let fence = reservations[0].fence.clone();
    ledger
        .mark_started(&fence, Some("provider-operation-1".into()))
        .await
        .unwrap_or_else(|_| panic!("postgres start"));
    ledger
        .mark_succeeded(&fence, "result:1".into(), "evidence:1".into())
        .await
        .unwrap_or_else(|_| panic!("postgres success"));
    assert_eq!(
        ledger
            .get(&tenant, &execution_id)
            .await
            .map(|record| record.status),
        Ok(ExecutionStatus::Succeeded)
    );
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM execution_outbox WHERE execution_id=$1")
            .bind(Uuid::parse_str(&execution_id.0).unwrap_or_else(|_| panic!("execution uuid")))
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|_| panic!("outbox count"));
    assert_eq!(outbox_count, 3);

    let audit_key = ed25519_dalek::SigningKey::from_bytes(&[73_u8; 32]);
    let audit = AuditIngest::new("audit-test-key".into(), audit_key, 100)
        .unwrap_or_else(|error| panic!("audit service: {error}"));
    let request_id = format!("pg-audit:{}", Uuid::new_v4());
    let records = audit
        .append_batch(vec![AuditRecordDraft {
            schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
            request_id,
            tenant_id: ledger_intent.tenant_id.clone(),
            task_id: ledger_intent.task_id.clone(),
            event_type: "POSTGRES_INTEGRATION_TEST".into(),
            actor_subject: "test:integration".into(),
            resource: "postgres://audit-records".into(),
            classification: DataClassification::Internal,
            payload_hash: "a".repeat(64),
            safe_summary: "persistence conformance".into(),
            artifact_hashes: vec!["b".repeat(64)],
            occurred_at: Utc::now(),
        }])
        .unwrap_or_else(|error| panic!("audit append: {error}"));
    let audit_repository = PostgresAuditRepository::new(pool.clone());
    audit_repository
        .append(&records)
        .await
        .unwrap_or_else(|error| panic!("audit persist: {error}"));
    audit_repository
        .append(&records)
        .await
        .unwrap_or_else(|error| panic!("audit idempotent retry: {error}"));
    let loaded = audit_repository
        .load_tenant(&ledger_intent.tenant_id, 0, 10_000)
        .await
        .unwrap_or_else(|error| panic!("audit load: {error}"));
    assert!(
        loaded
            .iter()
            .any(|record| record.record_id == records[0].record_id)
    );
}
