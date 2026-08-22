use agent_trust_pack_marketplace::authority::{
    AUTHORITATIVE_PACK_PAGE_SCHEMA, MARKETPLACE_ACTION_RECEIPT_SCHEMA, MARKETPLACE_COMMAND_SCHEMA,
    MARKETPLACE_EXECUTOR_REQUEST_SCHEMA, MARKETPLACE_MUTATION_RESULT_SCHEMA,
    MARKETPLACE_READINESS_SCHEMA,
};
use agent_trust_pack_marketplace::server::{
    PACKS_EXECUTE_SCOPE, PACKS_MUTATE_SCOPE, PACKS_READ_SCOPE,
};

#[test]
fn public_assets_match_runtime_constants() {
    let command = include_str!("../../../../schemas/marketplace/command.schema.json");
    let api = include_str!("../../../../schemas/marketplace/api.schema.json");
    let readiness = include_str!("../../../../schemas/marketplace/readiness.schema.json");
    let tokens = include_str!("../../../../schemas/marketplace/token-bindings.schema.json");
    let openapi = include_str!("../../../../schemas/openapi/pack-marketplace-v1.yaml");
    for expected in [
        MARKETPLACE_COMMAND_SCHEMA,
        MARKETPLACE_EXECUTOR_REQUEST_SCHEMA,
        MARKETPLACE_ACTION_RECEIPT_SCHEMA,
        MARKETPLACE_MUTATION_RESULT_SCHEMA,
        AUTHORITATIVE_PACK_PAGE_SCHEMA,
        MARKETPLACE_READINESS_SCHEMA,
        PACKS_MUTATE_SCOPE,
        PACKS_EXECUTE_SCOPE,
        PACKS_READ_SCOPE,
    ] {
        assert!(
            command.contains(expected)
                || api.contains(expected)
                || readiness.contains(expected)
                || tokens.contains(expected)
                || openapi.contains(expected),
            "missing public contract {expected}"
        );
    }
}

#[test]
fn production_migration_forces_tenant_rls_and_governance_bindings() {
    let migration = include_str!(
        "../../../../migrations/pack-marketplace/0036_01_09_production_pack_marketplace.sql"
    );
    for required in [
        "FORCE ROW LEVEL SECURITY",
        "marketplace_principal_assertion_replay",
        "marketplace_action_ingress",
        "marketplace_authority_executions",
        "policy_decision_digest",
        "ledger_entry_digest",
        "authorization_evidence_ref",
        "marketplace_evidence_events",
        "marketplace_evidence_outbox",
        "MARKETPLACE_RESOURCE_FENCE_INVALID",
        "REVOKE ALL",
    ] {
        assert!(
            migration.contains(required),
            "missing migration gate {required}"
        );
    }
}

#[test]
fn production_role_posture_is_exact_and_keeps_evidence_insert_only() {
    let binary = include_str!("../src/bin/agenttrust-pack-marketplace-service.rs");
    let docs = include_str!("../PRODUCTION.md");
    for required in [
        "base_table_grant_count",
        "evidence_table_grant_count",
        "update_column_grant_count",
        "unexpected_table_grant",
        "cross_domain_table_grant",
        "unexpected_update_column",
        "!= 26",
        "!= 2",
        "!= 54",
    ] {
        assert!(binary.contains(required), "missing role gate {required}");
    }
    assert!(docs.contains("only `INSERT` (never `SELECT`)"));
}

#[test]
fn lifecycle_contract_keeps_install_activation_and_authorization_separate() {
    let command = include_str!("../../../../schemas/marketplace/command.schema.json");
    let docs = include_str!("../PRODUCTION.md");
    for operation in [
        "ONBOARD_PUBLISHER",
        "VERIFY_PUBLISHER_KEY",
        "SET_PUBLISHER_TRUST",
        "CONFIGURE_TENANT_CATALOG",
        "SUBMIT_RELEASE",
        "REVIEW_RELEASE",
        "REQUEST_INSTALLATION",
        "APPROVE_INSTALLATION",
        "INSTALL",
        "ACTIVATE",
        "PLAN_UPGRADE",
        "RECORD_CANARY",
        "UPGRADE",
        "ROLLBACK",
        "DEACTIVATE",
        "REVOKE_RELEASE",
    ] {
        assert!(command.contains(operation), "missing operation {operation}");
    }
    assert!(docs.contains("Installation is always"));
    assert!(docs.contains("never issues a credential"));
}
