//! Real PostgreSQL concurrency, restart and fail-closed state test.
//!
//! This test runs only when a dedicated fully migrated database is supplied. Absence is emitted as
//! NOT_RUN_EXTERNAL_POSTGRES and must never be represented as production evidence.

use agent_trust_agent_registry_posture::production::{
    AgentBomDocument, BomComponent, CursorCodec, GovernanceContext, LifecycleConvergenceInput,
    OwnershipConfirmationRequest, OwnershipRole, PostgresAgentRegistryAuthority,
    ProductionLifecyclePort, RegistrationRequest, expected_confirmation_digest,
};
use agent_trust_agent_registry_posture::{LifecycleState, RegistryError};
use agent_trust_contracts::TenantId;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
struct LifecyclePort {
    fail: bool,
}

#[async_trait]
impl ProductionLifecyclePort for LifecyclePort {
    async fn ready(&self) -> bool {
        !self.fail
    }

    async fn converge(
        &self,
        _: &LifecycleConvergenceInput,
    ) -> Result<BTreeSet<String>, RegistryError> {
        if self.fail {
            Err(RegistryError::PropagationFailed)
        } else {
            Ok(BTreeSet::from([
                "evidence://test/identity".into(),
                "evidence://test/authorization".into(),
                "evidence://test/pack".into(),
            ]))
        }
    }
}

fn authority(pool: sqlx::PgPool, fail: bool) -> PostgresAgentRegistryAuthority {
    PostgresAgentRegistryAuthority::new(
        pool,
        Arc::new(LifecyclePort { fail }),
        CursorCodec::new(vec![37_u8; 32], Duration::minutes(15))
            .unwrap_or_else(|error| panic!("cursor: {error}")),
    )
}

fn governance() -> GovernanceContext {
    GovernanceContext {
        schema_version: "agenttrust.governed-authority-context.v1".into(),
        action_hash: "d".repeat(64),
        policy_decision_id: "policy-decision:test".into(),
        policy_decision_digest: "e".repeat(64),
        execution_id: Uuid::new_v4().to_string(),
        ledger_entry_id: Uuid::new_v4().to_string(),
        ledger_entry_digest: "f".repeat(64),
        authorization_evidence_ref: "evidence://test/authorization".into(),
    }
}

fn registration(tenant: &TenantId, agent_id: &str) -> RegistrationRequest {
    let mut bom = AgentBomDocument {
        schema_version: "agenttrust.agent-bom.v1".into(),
        tenant_id: tenant.clone(),
        agent_id: agent_id.into(),
        components: vec![BomComponent {
            kind: "PACK".into(),
            name: "coding".into(),
            version: "1.0.0".into(),
            digest: "a".repeat(64),
            supply_chain_digest: Some("b".repeat(64)),
        }],
        bom_digest: String::new(),
        generated_at: Utc::now(),
    };
    bom.bom_digest = bom
        .expected_digest()
        .unwrap_or_else(|error| panic!("bom digest: {error}"));
    RegistrationRequest {
        schema_version: "agenttrust.agent-registration-request.v1".into(),
        tenant_id: tenant.clone(),
        agent_id: agent_id.into(),
        display_name: "PostgreSQL Test Agent".into(),
        owner_subject: "owner:test".into(),
        sponsor_subject: "sponsor:test".into(),
        ownership_review_due_at: Utc::now() + Duration::days(30),
        environment: "STAGING".into(),
        agent_type: "CODING".into(),
        endpoints: BTreeSet::from(["https://agent.test.invalid".into()]),
        identity_refs: BTreeSet::from([Uuid::new_v4().to_string()]),
        tool_refs: BTreeSet::from(["coding.repo_read@1.0.0".into()]),
        pack_refs: BTreeSet::from(["coding@1.0.0".into()]),
        requested_permissions: BTreeSet::from(["repo:read".into()]),
        approved_permissions: BTreeSet::from(["repo:read".into()]),
        bom,
        last_activity_at: Utc::now(),
        provenance_ref: "registration://test/harness".into(),
        provenance_digest: "c".repeat(64),
        governance: governance(),
    }
}

#[tokio::test]
async fn registration_replays_across_concurrency_and_restart_with_tenant_isolation() {
    let Some(database_url) = std::env::var("AGENT_TRUST_AGENT_REGISTRY_TEST_DATABASE_URL").ok()
    else {
        eprintln!(
            "NOT_RUN_EXTERNAL_POSTGRES: AGENT_TRUST_AGENT_REGISTRY_TEST_DATABASE_URL is absent"
        );
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .unwrap_or_else(|error| panic!("dedicated PostgreSQL unavailable: {error}"));
    let tenant = TenantId(Uuid::new_v4().to_string());
    let other = TenantId(Uuid::new_v4().to_string());
    let request = registration(&tenant, &format!("agent-{}", Uuid::new_v4()));
    let authority_instance = Arc::new(authority(pool.clone(), false));
    let first = {
        let authority = authority_instance.clone();
        let request = request.clone();
        tokio::spawn(async move {
            authority
                .register(&request, "registration:1", "registrar:test", Utc::now())
                .await
        })
    };
    let second = {
        let authority = authority_instance.clone();
        let request = request.clone();
        tokio::spawn(async move {
            authority
                .register(&request, "registration:1", "registrar:test", Utc::now())
                .await
        })
    };
    let a = first
        .await
        .unwrap_or_else(|error| panic!("join: {error}"))
        .unwrap_or_else(|error| panic!("register: {error}"));
    let b = second
        .await
        .unwrap_or_else(|error| panic!("join: {error}"))
        .unwrap_or_else(|error| panic!("replay: {error}"));
    assert_eq!(a, b);
    let mut evidence = pool
        .begin()
        .await
        .unwrap_or_else(|error| panic!("evidence transaction: {error}"));
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(&tenant.0)
        .execute(&mut *evidence)
        .await
        .unwrap_or_else(|error| panic!("tenant scope: {error}"));
    let audit = sqlx::query(
        "SELECT count(*) OVER () AS audit_count,action_hash,governance_digest \
         FROM agent_registry_audit_events WHERE tenant_id=$1 AND resource_id=$2",
    )
    .bind(Uuid::parse_str(&tenant.0).unwrap_or_else(|error| panic!("tenant uuid: {error}")))
    .bind(&request.agent_id)
    .fetch_one(&mut *evidence)
    .await
    .unwrap_or_else(|error| panic!("audit row: {error}"));
    let audit_count: i64 = audit
        .try_get("audit_count")
        .unwrap_or_else(|error| panic!("audit count: {error}"));
    let audit_action_hash: String = audit
        .try_get("action_hash")
        .unwrap_or_else(|error| panic!("audit action hash: {error}"));
    let audit_governance_digest: String = audit
        .try_get("governance_digest")
        .unwrap_or_else(|error| panic!("audit governance digest: {error}"));
    assert_eq!(audit_count, 1);
    assert_eq!(audit_action_hash, request.governance.action_hash);
    assert_eq!(audit_governance_digest, a.governance_digest);
    let outbox_governance: String = sqlx::query_scalar(
        "SELECT payload->>'governance_digest' FROM agent_registry_outbox WHERE tenant_id=$1",
    )
    .bind(Uuid::parse_str(&tenant.0).unwrap_or_else(|error| panic!("tenant uuid: {error}")))
    .fetch_one(&mut *evidence)
    .await
    .unwrap_or_else(|error| panic!("outbox row: {error}"));
    assert_eq!(outbox_governance, a.governance_digest);
    evidence
        .commit()
        .await
        .unwrap_or_else(|error| panic!("evidence commit: {error}"));
    let restarted = authority(pool.clone(), false);
    let page = restarted
        .list_agents(&tenant, "summary", None, 10, Utc::now())
        .await
        .unwrap_or_else(|error| panic!("restart list: {error}"));
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].ownership_status, "PENDING");
    assert!(
        restarted
            .list_agents(&other, "summary", None, 10, Utc::now())
            .await
            .unwrap_or_else(|error| panic!("other tenant: {error}"))
            .items
            .is_empty()
    );
    let mut conflict = request.clone();
    conflict.display_name = "Conflicting body".into();
    assert_eq!(
        restarted
            .register(&conflict, "registration:1", "registrar:test", Utc::now())
            .await,
        Err(RegistryError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn failed_lifecycle_port_does_not_change_authoritative_state() {
    let Some(database_url) = std::env::var("AGENT_TRUST_AGENT_REGISTRY_TEST_DATABASE_URL").ok()
    else {
        eprintln!(
            "NOT_RUN_EXTERNAL_POSTGRES: AGENT_TRUST_AGENT_REGISTRY_TEST_DATABASE_URL is absent"
        );
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap_or_else(|error| panic!("dedicated PostgreSQL unavailable: {error}"));
    let tenant = TenantId(Uuid::new_v4().to_string());
    let agent_id = format!("agent-{}", Uuid::new_v4());
    let request = registration(&tenant, &agent_id);
    let active = authority(pool.clone(), false);
    active
        .register(&request, "registration:2", "registrar:test", Utc::now())
        .await
        .unwrap_or_else(|error| panic!("register: {error}"));
    for (role, subject, key) in [
        (OwnershipRole::Owner, "owner:test", "owner-confirm:2"),
        (OwnershipRole::Sponsor, "sponsor:test", "sponsor-confirm:2"),
    ] {
        let mut confirmation = OwnershipConfirmationRequest {
            schema_version: "agenttrust.ownership-confirmation.v1".into(),
            tenant_id: tenant.clone(),
            agent_id: agent_id.clone(),
            ownership_version: 1,
            role,
            subject: subject.into(),
            confirmation_digest: String::new(),
            governance: governance(),
        };
        confirmation.confirmation_digest = expected_confirmation_digest(&confirmation)
            .unwrap_or_else(|error| panic!("confirmation digest: {error}"));
        active
            .confirm_ownership(&confirmation, key, subject, Utc::now())
            .await
            .unwrap_or_else(|error| panic!("confirm: {error}"));
    }
    active
        .transition_lifecycle(
            &agent_trust_agent_registry_posture::production::LifecycleRequest {
                schema_version: "agenttrust.agent-lifecycle-request.v1".into(),
                tenant_id: tenant.clone(),
                agent_id: agent_id.clone(),
                target: LifecycleState::Active,
                reason_code: "APPROVED".into(),
                governance: governance(),
            },
            "activate:2",
            "lifecycle:test",
            Utc::now(),
        )
        .await
        .unwrap_or_else(|error| panic!("activate: {error}"));
    let failing = authority(pool, true);
    let result = failing
        .transition_lifecycle(
            &agent_trust_agent_registry_posture::production::LifecycleRequest {
                schema_version: "agenttrust.agent-lifecycle-request.v1".into(),
                tenant_id: tenant.clone(),
                agent_id: agent_id.clone(),
                target: LifecycleState::Revoked,
                reason_code: "SECURITY".into(),
                governance: governance(),
            },
            "revoke:2",
            "lifecycle:test",
            Utc::now(),
        )
        .await;
    assert_eq!(result, Err(RegistryError::PropagationFailed));
    let page = failing
        .list_agents(&tenant, "summary", None, 10, Utc::now())
        .await
        .unwrap_or_else(|error| panic!("list: {error}"));
    assert_eq!(page.items[0].lifecycle, LifecycleState::Active);
}
