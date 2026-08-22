use serde_json::Value;
use std::path::PathBuf;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("repository root unavailable"))
        .to_path_buf()
}

#[test]
fn public_policy_schemas_match_wire_versions_and_closed_objects() {
    let root = repository_root();
    for (path, version) in [
        (
            "schemas/policy-admin/policy-token-bindings.schema.json",
            "agenttrust.policy-admin-token-bindings.v1",
        ),
        (
            "schemas/policy-admin/policy-readiness.schema.json",
            "agenttrust.policy-admin-readiness.v1",
        ),
        (
            "schemas/policy-admin/policy-bundle.schema.json",
            "agenttrust.signed-policy-bundle.v1",
        ),
    ] {
        let raw =
            std::fs::read(root.join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"));
        let schema: Value =
            serde_json::from_slice(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"));
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["schema_version"]["const"], version);
    }
    let command: Value = serde_json::from_slice(
        &std::fs::read(root.join("schemas/policy-admin/policy-command.schema.json"))
            .unwrap_or_else(|error| panic!("read command schema: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse command schema: {error}"));
    assert_eq!(command["oneOf"].as_array().map(Vec::len), Some(12));
    assert_eq!(
        command["$defs"]["base"]["properties"]["schema_version"]["const"],
        "agenttrust.policy-command.v1"
    );
}

#[test]
fn openapi_declares_separate_human_executor_and_query_scopes() {
    let path = repository_root().join("schemas/openapi/policy-administration-v1.yaml");
    let document = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    for invariant in [
        "/v1/policies/actions:",
        "/v1/policies/executions:",
        "/v1/authoritative/policies:",
        "x-required-scope: policy:mutate",
        "x-required-scope: policy:execute",
        "x-required-scope: policy:query",
        "Canonical Action IR",
        "SHADOW_EVALUATE",
        "IMPACT_ANALYZE",
        "CREATE_EXCEPTION",
        "/simulations:",
        "/impact-reports:",
        "/exceptions:",
        "authoritative-PDP activation acknowledgement",
        "Promotion network uncertainty remains UNKNOWN",
    ] {
        assert!(document.contains(invariant), "missing {invariant}");
    }
}

#[test]
fn migration_forces_rls_and_immutable_policy_artifacts() {
    let path = repository_root()
        .join("migrations/policy-admin/0036_01_10_production_policy_administration.sql");
    let migration = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    for invariant in [
        "FORCE ROW LEVEL SECURITY",
        "POLICY_SOURCE_ARTIFACT_IMMUTABLE",
        "POLICY_BUNDLE_ARTIFACT_IMMUTABLE",
        "POLICY_RESOURCE_FENCE_INVALID",
        "policy_principal_assertion_replay",
        "policy_evidence_outbox",
        "policy_impact_reports",
        "policy_activation_intents",
        "policy_promotions_single_unresolved_idx",
        "pep-policy-activation-ack.v1",
        "POLICY_EXCEPTION_TRANSITION_INVALID",
        "REVOKE ALL",
    ] {
        assert!(migration.contains(invariant), "missing {invariant}");
    }
}
