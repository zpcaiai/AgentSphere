use serde_json::Value;
use std::collections::BTreeSet;

const AUTHORITY: &str = include_str!("../src/authority.rs");
const SERVER: &str = include_str!("../src/server.rs");
const SERVICE: &str = include_str!("../src/bin/agenttrust-platform-sre-service.rs");
const MIGRATION: &str =
    include_str!("../../../../migrations/platform-sre/0036_01_13_production_platform_sre.sql");
const OPENAPI: &str = include_str!("../../../../schemas/openapi/platform-sre-v1.yaml");
const COMMAND_SCHEMA: &str =
    include_str!("../../../../schemas/platform-sre/sre-command.schema.json");
const ENGINE_SCHEMA: &str =
    include_str!("../../../../schemas/platform-sre/sre-engine-report.schema.json");
const DOCKERFILE: &str = include_str!("../../../../Dockerfile.platform-sre");
const STACK: &str = include_str!("../../../../deploy/kubernetes/production-stack.yaml.tmpl");

fn expected_operations() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "CONFIGURE_SLO",
        "RECORD_SLI",
        "UPDATE_BURN_ALERT",
        "LINK_INCIDENT",
        "REGISTER_TOPOLOGY",
        "RECORD_ZONE_HEALTH",
        "CREATE_BACKUP",
        "VERIFY_RESTORE",
        "PLAN_DR",
        "FAILOVER",
        "FAILBACK",
        "PLAN_CHAOS",
        "EXECUTE_CHAOS",
        "PLAN_LOAD",
        "EXECUTE_LOAD",
        "PLAN_UPGRADE",
        "RECORD_CANARY",
        "ROLLBACK_UPGRADE",
        "RECORD_COST_CAPACITY",
        "RECORD_OBSERVABILITY",
    ])
}

#[test]
fn command_schema_and_authority_cover_the_same_production_operations() {
    let schema: Value = serde_json::from_str(COMMAND_SCHEMA)
        .unwrap_or_else(|error| panic!("command schema JSON invalid: {error}"));
    let observed = schema["properties"]["operation"]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("operation enum missing"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("operation is not a string"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(observed, expected_operations());
    for operation in expected_operations() {
        assert!(AUTHORITY.contains(&format!("\"{operation}\"")));
    }
}

#[test]
fn every_mutation_is_bound_to_canonical_pep_ledger_fence_and_evidence() {
    for required in [
        "CANONICAL_ACTION_IR->PEP->LEDGER->EVIDENCE",
        "ledger_execution_id",
        "ledger_event_id",
        "ledger_event_digest",
        "fence_digest",
        "policy_decision_digest",
        "authorization_evidence_ref",
        "authorization_evidence_digest",
        "MUTATED_PENDING_EVIDENCE",
        "publish_evidence",
        "finalize_evidence",
    ] {
        assert!(
            AUTHORITY.contains(required),
            "missing authority binding {required}"
        );
    }
    for header in [
        "x-agenttrust-action-hash",
        "x-agenttrust-ledger-execution-id",
        "x-agenttrust-ledger-entry-id",
        "x-agenttrust-ledger-entry-digest",
        "x-agenttrust-fence-digest",
        "x-agenttrust-resource-version",
        "x-agenttrust-policy-decision-id",
        "x-agenttrust-policy-decision-digest",
        "x-agenttrust-authorization-evidence-ref",
        "x-agenttrust-authorization-evidence-digest",
    ] {
        assert!(SERVER.contains(header), "missing executor header {header}");
    }
}

#[test]
fn database_contract_forces_tenant_rls_immutability_and_restart_states() {
    let tenant_tables = [
        "sre_service_slos",
        "sre_sli_observations",
        "sre_burn_alerts",
        "sre_incident_links",
        "sre_deployment_topologies",
        "sre_zone_health_observations",
        "backup_manifests",
        "sre_backup_artifacts",
        "recovery_drills",
        "sre_dr_plans",
        "sre_dr_events",
        "sre_chaos_campaigns",
        "sre_chaos_results",
        "sre_load_campaigns",
        "sre_load_results",
        "deployment_rollouts",
        "sre_canary_observations",
        "sre_cost_capacity_observations",
        "sre_observability_evidence",
        "sre_resource_versions",
        "sre_action_ingress",
        "sre_principal_assertion_replay",
        "sre_authority_executions",
        "sre_evidence_outbox",
    ];
    for table in tenant_tables {
        assert!(
            MIGRATION.contains(&format!("'{table}'")),
            "RLS inventory missing {table}"
        );
        assert!(
            SERVICE.contains(&format!("\"{table}\"")),
            "DB grant inventory missing {table}"
        );
    }
    for state in [
        "PREPARED",
        "SIDE_EFFECTS_PENDING",
        "MUTATED_PENDING_EVIDENCE",
        "SUCCEEDED",
        "FAILED",
        "UNKNOWN",
    ] {
        assert!(MIGRATION.contains(state));
    }
    assert!(MIGRATION.contains("FORCE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("SRE_EXECUTION_BINDING_IMMUTABLE"));
    assert!(MIGRATION.contains("SRE_RESOURCE_FENCE_INVALID"));
    assert!(MIGRATION.contains("SRE_IMMUTABLE_RECORD"));
    assert!(MIGRATION.contains("REVOKE ALL"));
}

#[test]
fn signed_engine_report_is_structurally_not_a_production_certificate() {
    let schema: Value = serde_json::from_str(ENGINE_SCHEMA)
        .unwrap_or_else(|error| panic!("engine schema JSON invalid: {error}"));
    assert_eq!(schema["properties"]["engine_report_only"]["const"], true);
    assert_eq!(
        schema["properties"]["production_certification"]["const"],
        false
    );
    assert!(AUTHORITY.contains("engine_report_only: true"));
    assert!(AUTHORITY.contains("production_certification: false"));
}

#[test]
fn adapters_and_transport_fail_closed() {
    for required in [
        "min_tls_version(reqwest::tls::Version::TLS_1_3)",
        "redirect(reqwest::redirect::Policy::none())",
        "verify-full",
        "PLATFORM_SRE_DATABASE_CROSS_DOMAIN_GRANT",
        "PLATFORM_SRE_DATABASE_COLUMN_GRANTS_INVALID",
        "PLATFORM_SRE_DEPENDENCY_CREDENTIAL_REUSE_DENIED",
    ] {
        assert!(SERVICE.contains(required));
    }
    for adapter in [
        "Backup",
        "Recovery",
        "DisasterRecovery",
        "Chaos",
        "Load",
        "Upgrade",
        "Evidence",
    ] {
        assert!(SERVER.contains(&format!("SreAdapterKind::{adapter}")));
    }
    assert!(SERVER.contains("TLS13"));
    assert!(SERVER.contains("exact_certificate_identity"));
    assert!(SERVER.contains("identities.len() == 1"));
    assert!(SERVER.contains("v1/evidence/authority-events"));
    assert!(SERVER.contains("AuthorityEvidenceSourceKind::GovernedAction"));
    assert!(SERVER.contains("SignedAuthorityEvidenceReceipt"));
    assert!(SERVER.contains("receipt.verify(key, Utc::now())"));
    assert!(SERVER.contains("X-AgentTrust-Authority-Event-Id"));
    assert!(SERVER.contains("X-AgentTrust-Payload-Digest"));
    assert!(SERVICE.contains("AGENT_TRUST_SRE_EVIDENCE_CLIENT_IDENTITY"));
    assert!(SERVICE.contains("AGENT_TRUST_SRE_EVIDENCE_KEYRING_FILE"));
}

#[test]
fn public_openapi_and_container_are_production_scoped() {
    for path in [
        "/v1/sre/actions",
        "/v1/sre/executions",
        "/v1/authoritative/sre/resources",
    ] {
        assert!(OPENAPI.contains(path));
    }
    assert!(OPENAPI.contains("mutualTLS"));
    assert!(OPENAPI.contains("bearerAuth"));
    assert!(DOCKERFILE.contains("cargo build --locked --release -p agent-trust-platform-sre"));
    assert!(DOCKERFILE.contains("USER nonroot:nonroot"));
}

#[test]
fn management_routes_match_production_probes() {
    for marker in [
        ".route(\"/live\", get(management_health))",
        ".route(\"/ready\", get(management_ready))",
    ] {
        assert!(SERVER.contains(marker), "missing management route {marker}");
    }
    assert!(SERVER.contains("\"schema_version\": \"agenttrust.sre-liveness.v1\""));
    assert!(STACK.contains("livenessProbe: {httpGet: {path: /live, port: management}"));
    assert!(STACK.contains("readinessProbe: {httpGet: {path: /ready, port: management}"));
}
