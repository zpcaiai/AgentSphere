use serde_json::Value;
use std::collections::BTreeSet;

#[test]
fn workload_credential_schema_is_strict_and_matches_shared_surface() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../schemas/identity/workload-credential.schema.json"
    ))
    .unwrap_or_else(|error| panic!("workload credential schema: {error}"));
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("$defs"));
    for name in [
        "bindingRequest",
        "bindingReceipt",
        "issuance",
        "consumptionRequest",
        "consumptionReceipt",
        "lifecycleRequest",
        "lifecycleReceipt",
    ] {
        assert_eq!(
            definitions[name].get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{name} must reject unknown fields"
        );
    }
    let binding_receipt_properties = definitions["bindingReceipt"]["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("binding receipt properties"));
    assert!(binding_receipt_properties.contains_key("credential_handle_sha256"));
    assert!(!binding_receipt_properties.contains_key("credential_handle"));
    let consumption_required = definitions["consumptionRequest"]["required"]
        .as_array()
        .unwrap_or_else(|| panic!("consumption required"))
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        consumption_required,
        BTreeSet::from([
            "action_hash",
            "agent_instance_id",
            "audience",
            "binding_receipt",
            "claims_digest",
            "credential_handle",
            "credential_profile",
            "idempotency_key",
            "operation",
            "policy_decision_id",
            "resource",
            "revocation_epoch",
            "schema_version",
            "step_id",
            "target_profile",
            "task_id",
            "tenant_id",
            "tool_id",
        ])
    );
}

#[test]
fn openapi_uses_matchit_safe_paths_and_exact_security_bindings() {
    let openapi = include_str!("../../../../schemas/openapi/identity-credential-v1.yaml");
    for route in [
        "/v1/credentials/issue",
        "/v1/credentials/consume",
        "/v1/credentials/{credential_id}/revoke",
        "/v1/tasks/{task_id}/pause",
        "/v1/tasks/{task_id}/unfreeze",
        "/v1/tasks/{task_id}/revoke",
        "/v1/tasks/{task_id}/cancel",
        "/v1/tasks/{task_id}/kill",
        "/v1/agents/{agent_id}/revoke",
        "/v1/tenants/{tenant_id}/revoke",
    ] {
        assert!(openapi.contains(route), "missing route {route}");
    }
    assert!(!openapi.contains("{credential_id}:"));
    assert!(!openapi.contains("{task_id}:"));
    assert!(openapi.contains("bearerFormat: opaque-service-token"));
    assert!(openapi.contains("mutualTLS: []"));
    assert!(openapi.contains("Idempotency-Key"));
}
