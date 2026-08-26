use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"))
        .to_path_buf()
}

#[test]
fn production_contract_assets_are_versioned_and_parseable() {
    for relative in [
        "schemas/agent-registry/agent-bom.schema.json",
        "schemas/agent-registry/api.schema.json",
        "schemas/agent-registry/token-bindings.schema.json",
    ] {
        let value: Value = serde_json::from_slice(
            &fs::read(root().join(relative))
                .unwrap_or_else(|error| panic!("read {relative}: {error}")),
        )
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"));
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
    }
    let openapi = fs::read_to_string(root().join("schemas/openapi/agent-registry-v1.yaml"))
        .unwrap_or_else(|error| panic!("openapi: {error}"));
    for route in [
        "/v1/authoritative/agents",
        "/v1/agents/registrations",
        "/v1/discovery/observations",
        "/v1/relationships/graph",
        "/v1/posture/evaluations",
        "/v1/agents/{agent_id}/lifecycle",
    ] {
        assert!(openapi.contains(route), "missing route {route}");
    }
    assert!(openapi.contains("Discovery responses are immutable untrusted facts"));
    assert!(openapi.contains("Canonical Action IR, PEP decision, execution, ledger and evidence"));
}

#[test]
fn migration_forces_rls_and_immutability_without_creating_a_login_role() {
    let sql = fs::read_to_string(
        root().join("migrations/agent-registry/0036_01_08_production_agent_registry.sql"),
    )
    .unwrap_or_else(|error| panic!("migration: {error}"));
    for table in [
        "agent_assets",
        "agent_discovery_facts",
        "agent_posture_findings",
        "agent_registry_idempotency",
        "agent_registry_audit_events",
        "agent_registry_outbox",
    ] {
        assert!(sql.contains(table));
    }
    assert!(sql.contains("FORCE ROW LEVEL SECURITY"));
    assert!(sql.contains("reject_agent_registry_immutable_record"));
    assert!(sql.contains("UNTRUSTED_OBSERVATION"));
    assert!(sql.contains("reconciled_agent_id IS NULL"));
    for governance_column in [
        "governance_digest",
        "action_hash",
        "policy_decision_id",
        "policy_decision_digest",
        "execution_id",
        "ledger_entry_id",
        "ledger_entry_digest",
        "authorization_evidence_ref",
    ] {
        assert!(sql.contains(governance_column));
    }
    assert!(!sql.contains("CREATE ROLE"));
    assert!(!sql.contains("CREATE USER"));
}

#[test]
fn every_authoritative_write_is_governed_and_audited_with_outbox_binding() {
    let schema: Value = serde_json::from_slice(
        &fs::read(root().join("schemas/agent-registry/api.schema.json"))
            .unwrap_or_else(|error| panic!("schema: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse schema: {error}"));
    for definition in [
        "registration_request",
        "ownership_assignment",
        "ownership_confirmation",
        "discovery_ingest",
        "bom_update",
        "relationship_request",
        "posture_evaluation",
        "lifecycle_request",
    ] {
        let required = schema
            .pointer(&format!("/$defs/{definition}/required"))
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("required array for {definition}"));
        assert!(
            required
                .iter()
                .any(|item| item.as_str() == Some("governance"))
        );
    }

    let source =
        fs::read_to_string(root().join("rust/crates/agent-registry-posture/src/production.rs"))
            .unwrap_or_else(|error| panic!("source: {error}"));
    for binding in [
        "action_hash",
        "policy_decision_id",
        "policy_decision_digest",
        "execution_id",
        "ledger_entry_id",
        "ledger_entry_digest",
        "authorization_evidence_ref",
    ] {
        assert!(
            source.contains(&format!("\"{binding}\":&governance."))
                || source.contains(&format!("\"{binding}\":governance."))
        );
    }
    assert!(source.contains("let outbox_payload_digest = canonical_digest(&outbox_payload)"));
}

#[test]
fn production_binary_never_constructs_in_memory_registry() {
    let binary =
        fs::read_to_string(root().join(
            "rust/crates/agent-registry-posture/src/bin/agenttrust-agent-registry-service.rs",
        ))
        .unwrap_or_else(|error| panic!("binary: {error}"));
    assert!(binary.contains("PostgresAgentRegistryAuthority::new"));
    assert!(!binary.contains("AgentRegistry::new"));
    assert!(binary.contains("verify_database_posture"));
}

#[test]
fn discovery_write_source_has_no_asset_insert_or_activation() {
    let source =
        fs::read_to_string(root().join("rust/crates/agent-registry-posture/src/production.rs"))
            .unwrap_or_else(|error| panic!("source: {error}"));
    let start = source
        .find("pub async fn ingest_discovery")
        .unwrap_or_else(|| panic!("ingest method"));
    let end = source[start..]
        .find("pub async fn assign_ownership")
        .map(|offset| start + offset)
        .unwrap_or(source.len());
    let method = &source[start..end];
    assert!(method.contains("INSERT INTO agent_discovery_facts"));
    assert!(method.contains("UNTRUSTED_OBSERVATION"));
    assert!(!method.contains("INSERT INTO agent_assets"));
    assert!(!method.contains("UPDATE agent_assets"));
    assert!(!method.contains("ACTIVE"));
}

#[test]
fn lifecycle_converges_before_authoritative_state_update() {
    let source =
        fs::read_to_string(root().join("rust/crates/agent-registry-posture/src/production.rs"))
            .unwrap_or_else(|error| panic!("source: {error}"));
    let start = source
        .find("pub async fn transition_lifecycle")
        .unwrap_or_else(|| panic!("transition method"));
    let end = source[start..]
        .find("pub async fn evaluate_posture")
        .map(|offset| start + offset)
        .unwrap_or(source.len());
    let method = &source[start..end];
    let convergence = method
        .find(".converge(")
        .unwrap_or_else(|| panic!("external convergence"));
    let state_update = method
        .find("UPDATE agent_assets SET lifecycle")
        .unwrap_or_else(|| panic!("state update"));
    assert!(convergence < state_update);
    assert!(method.contains("store_replay"));
    assert!(method.contains("append_audit"));
}
