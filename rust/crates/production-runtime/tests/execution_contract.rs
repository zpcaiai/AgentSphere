use agent_trust_contracts::ExecutionStatus;
use agent_trust_production_runtime::execution::{
    ActionMaterializationRef, EXECUTION_OUTCOME_SCHEMA, EXECUTION_REQUEST_SCHEMA, ExecutionOutcome,
    ExecutionRequest, validate_request,
};
use uuid::Uuid;

fn request() -> ExecutionRequest {
    let tenant = Uuid::new_v4().to_string();
    let action = Uuid::new_v4().to_string();
    ExecutionRequest {
        schema_version: EXECUTION_REQUEST_SCHEMA.into(),
        tenant_id: tenant.clone(),
        task_id: Uuid::new_v4().to_string(),
        action_id: action.clone(),
        ingress_digest: "a".repeat(64),
        idempotency_key: "execute:contract".into(),
        action_materialization: ActionMaterializationRef {
            schema_version: "agenttrust.action-materialization-ref.v1".into(),
            tenant_id: tenant.clone(),
            action_id: action.clone(),
            payload_hash: "b".repeat(64),
            store: "ORCHESTRATOR_INGRESS_POSTGRESQL".into(),
            uri: format!("orchestrator-ingress://{tenant}/{action}"),
        },
    }
}

#[test]
fn worker_wire_contract_has_exact_request_fields() {
    let value = serde_json::to_value(request())
        .unwrap_or_else(|error| panic!("serialize request: {error}"));
    let keys = value
        .as_object()
        .unwrap_or_else(|| panic!("serialized request was not an object"))
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "action_id",
            "action_materialization",
            "idempotency_key",
            "ingress_digest",
            "schema_version",
            "task_id",
            "tenant_id"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn unknown_outcome_remains_a_process_outcome() {
    let request = request();
    assert!(validate_request(&request).is_ok());
    let outcome = ExecutionOutcome {
        schema_version: EXECUTION_OUTCOME_SCHEMA.into(),
        tenant_id: request.tenant_id.clone(),
        task_id: request.task_id.clone(),
        action_id: request.action_id.clone(),
        ingress_digest: request.ingress_digest.clone(),
        idempotency_key: request.idempotency_key.clone(),
        ledger_execution_id: Uuid::new_v4().to_string(),
        fence_digest: "c".repeat(64),
        status: ExecutionStatus::Unknown,
        outcome_digest: "d".repeat(64),
        evidence_refs: vec![format!("ledger-event:{}", Uuid::new_v4())],
        action_materialization: request.action_materialization,
    };
    let value =
        serde_json::to_value(outcome).unwrap_or_else(|error| panic!("serialize outcome: {error}"));
    assert_eq!(value["status"], "UNKNOWN");
}
