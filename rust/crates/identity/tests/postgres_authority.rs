//! Real-PostgreSQL concurrency and restart-recovery contract.
//!
//! This test intentionally does not substitute an in-memory store. It runs only when the
//! dedicated, fully migrated `AGENT_TRUST_IDENTITY_TEST_DATABASE_URL` environment is supplied;
//! absence is reported as external evidence NOT_RUN by the production gate, never as a pass.

use agent_trust_contracts::{
    ActionHash, AgentInstanceId, IdempotencyKey, StepId, TaskId, TenantId, ToolId,
    WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION,
    WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION, WorkloadCredentialBindingRequest,
    WorkloadCredentialConsumptionRequest,
};
use agent_trust_identity::{
    CredentialAuthoritySigner, IdentityError, IdentityResponseProtector,
    PostgresCredentialAuthority,
};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn postgres_issue_restarts_exactly_and_consume_has_one_concurrent_winner() {
    let Some(database_url) = std::env::var("AGENT_TRUST_IDENTITY_TEST_DATABASE_URL").ok() else {
        eprintln!("NOT_RUN_EXTERNAL_POSTGRES: AGENT_TRUST_IDENTITY_TEST_DATABASE_URL is absent");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .unwrap_or_else(|error| panic!("dedicated PostgreSQL unavailable: {error}"));
    let tenant = TenantId(Uuid::new_v4().to_string());
    let agent = AgentInstanceId(Uuid::new_v4().to_string());
    let task = TaskId(Uuid::new_v4().to_string());
    let step = StepId(Uuid::new_v4().to_string());
    let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
    let signer = CredentialAuthoritySigner::new(
        "identity-test".into(),
        Uuid::new_v4().to_string(),
        signing_key.clone(),
    )
    .unwrap_or_else(|error| panic!("test signer: {error}"));
    let protector = IdentityResponseProtector::new(
        "test-envelope-1".into(),
        BTreeMap::from([("test-envelope-1".into(), [41_u8; 32])]),
    )
    .unwrap_or_else(|error| panic!("test protector: {error}"));
    seed_references(&pool, &tenant, &agent, &signer, &signing_key).await;
    let authority = Arc::new(PostgresCredentialAuthority::new(
        pool.clone(),
        signer.clone(),
        protector.clone(),
    ));
    let binding = WorkloadCredentialBindingRequest {
        schema_version: WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION.into(),
        idempotency_key: IdempotencyKey(Uuid::new_v4().to_string()),
        tenant_id: tenant.clone(),
        agent_instance_id: agent.clone(),
        task_id: task.clone(),
        step_id: step.clone(),
        action_hash: ActionHash("a".repeat(64)),
        policy_decision_id: "policy-test".into(),
        tool_id: ToolId("test.tool".into()),
        credential_profile: "test-profile".into(),
        operation: "read".into(),
        resource: "repo:test".into(),
        target_profile: "test-target".into(),
        audience: "tool-proxy".into(),
        revocation_epoch: 0,
        ttl_seconds: 60,
        max_uses: 1,
    };
    let now = Utc::now();
    let first_now = now;
    let second_now = now;
    let first = {
        let authority = authority.clone();
        let request = binding.clone();
        tokio::spawn(async move { authority.issue(&request, "test-pep", first_now).await })
    };
    let second = {
        let authority = authority.clone();
        let request = binding.clone();
        tokio::spawn(async move { authority.issue(&request, "test-pep", second_now).await })
    };
    let issuance_a = first
        .await
        .unwrap_or_else(|error| panic!("issue join: {error}"))
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let issuance_b = second
        .await
        .unwrap_or_else(|error| panic!("issue join: {error}"))
        .unwrap_or_else(|error| panic!("issue replay: {error}"));
    assert_eq!(issuance_a, issuance_b);

    let restarted = PostgresCredentialAuthority::new(pool.clone(), signer, protector);
    let issuance_after_restart = restarted
        .issue(&binding, "test-pep", Utc::now())
        .await
        .unwrap_or_else(|error| panic!("restart replay: {error}"));
    assert_eq!(issuance_a, issuance_after_restart);

    let consumption = WorkloadCredentialConsumptionRequest {
        schema_version: WORKLOAD_CREDENTIAL_CONSUMPTION_REQUEST_SCHEMA_VERSION.into(),
        idempotency_key: IdempotencyKey(Uuid::new_v4().to_string()),
        credential_handle: issuance_a.workload_credential.0.clone(),
        binding_receipt: issuance_a.binding_receipt.clone(),
        tenant_id: tenant,
        agent_instance_id: agent,
        task_id: task,
        step_id: step,
        action_hash: binding.action_hash.clone(),
        policy_decision_id: binding.policy_decision_id.clone(),
        tool_id: binding.tool_id.clone(),
        credential_profile: binding.credential_profile.clone(),
        operation: binding.operation.clone(),
        resource: binding.resource.clone(),
        target_profile: binding.target_profile.clone(),
        audience: binding.audience.clone(),
        revocation_epoch: binding.revocation_epoch,
        claims_digest: issuance_a.binding_receipt.claims_digest.clone(),
    };
    let mut other_consumption = consumption.clone();
    other_consumption.idempotency_key = IdempotencyKey(Uuid::new_v4().to_string());
    let first_use = {
        let authority = authority.clone();
        tokio::spawn(async move {
            authority
                .consume(&consumption, "test-tool-proxy", Utc::now())
                .await
        })
    };
    let second_use = tokio::spawn(async move {
        restarted
            .consume(&other_consumption, "test-tool-proxy", Utc::now())
            .await
    });
    let outcomes = [
        first_use
            .await
            .unwrap_or_else(|error| panic!("consume join: {error}")),
        second_use
            .await
            .unwrap_or_else(|error| panic!("consume join: {error}")),
    ];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(IdentityError::UsageExceeded)))
            .count(),
        1
    );
}

async fn seed_references(
    pool: &sqlx::PgPool,
    tenant: &TenantId,
    agent: &AgentInstanceId,
    signer: &CredentialAuthoritySigner,
    signing_key: &SigningKey,
) {
    let mut transaction = pool
        .begin()
        .await
        .unwrap_or_else(|error| panic!("seed transaction: {error}"));
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(&tenant.0)
        .execute(&mut *transaction)
        .await
        .unwrap_or_else(|error| panic!("seed tenant: {error}"));
    sqlx::query(
        "INSERT INTO agent_principals \
         (agent_instance_id,tenant_id,owner_subject,organization_id,trust_level,revocation_epoch) \
         VALUES ($1,$2,'test-owner','test-org','verified',0)",
    )
    .bind(Uuid::parse_str(&agent.0).unwrap_or_else(|_| panic!("agent uuid")))
    .bind(Uuid::parse_str(&tenant.0).unwrap_or_else(|_| panic!("tenant uuid")))
    .execute(&mut *transaction)
    .await
    .unwrap_or_else(|error| panic!("seed principal: {error}"));
    sqlx::query(
        "INSERT INTO credential_profiles(tenant_id,profile_id,definition) \
         VALUES ($1,'test-profile','{}'::jsonb)",
    )
    .bind(Uuid::parse_str(&tenant.0).unwrap_or_else(|_| panic!("tenant uuid")))
    .execute(&mut *transaction)
    .await
    .unwrap_or_else(|error| panic!("seed profile: {error}"));
    sqlx::query(
        "INSERT INTO identity_credential_signing_keys \
         (tenant_id,issuer,key_id,algorithm,public_key,status,created_by) \
         VALUES ($1,$2,$3,'Ed25519',$4,'ACTIVE','test-bootstrap')",
    )
    .bind(Uuid::parse_str(&tenant.0).unwrap_or_else(|_| panic!("tenant uuid")))
    .bind(&signer.issuer)
    .bind(&signer.key_id)
    .bind(signing_key.verifying_key().as_bytes().as_slice())
    .execute(&mut *transaction)
    .await
    .unwrap_or_else(|error| panic!("seed signer: {error}"));
    transaction
        .commit()
        .await
        .unwrap_or_else(|error| panic!("seed commit: {error}"));
}
