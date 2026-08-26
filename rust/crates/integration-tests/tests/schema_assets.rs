use std::{
    fs,
    path::{Path, PathBuf},
};

fn json_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).unwrap_or_else(|_| panic!("read schema directory"));
    for entry in entries {
        let path = entry.unwrap_or_else(|_| panic!("read schema entry")).path();
        if path.is_dir() {
            json_files(&path, files);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push(path);
        }
    }
}

#[test]
fn every_json_schema_compiles_under_draft_2020_12() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    json_files(&root.join("schemas"), &mut files);
    files.sort();
    assert!(!files.is_empty());
    let schemas: Vec<(PathBuf, serde_json::Value)> = files
        .into_iter()
        .map(|file| {
            let bytes = fs::read(&file).unwrap_or_else(|_| panic!("read {}", file.display()));
            let schema = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| panic!("parse {}", file.display()));
            (file, schema)
        })
        .collect();
    let mut registry = jsonschema::Registry::new();
    for (_, schema) in &schemas {
        if let Some(identifier) = schema.get("$id").and_then(serde_json::Value::as_str) {
            registry = registry
                .add(identifier, schema)
                .unwrap_or_else(|error| panic!("register {identifier}: {error}"));
        }
    }
    let registry = registry
        .prepare()
        .unwrap_or_else(|error| panic!("prepare schema registry: {error}"));
    for (file, schema) in &schemas {
        jsonschema::options()
            .with_registry(&registry)
            .build(schema)
            .unwrap_or_else(|error| panic!("compile {}: {error}", file.display()));
    }
    let validate = |schema_suffix: &str, instance_relative: &str| {
        let (schema_path, schema) = schemas
            .iter()
            .find(|(path, _)| path.ends_with(schema_suffix))
            .unwrap_or_else(|| panic!("schema {schema_suffix}"));
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(schema)
            .unwrap_or_else(|error| panic!("compile {}: {error}", schema_path.display()));
        let instance_path = root.join(instance_relative);
        let instance: serde_json::Value = serde_json::from_slice(
            &fs::read(&instance_path)
                .unwrap_or_else(|_| panic!("read {}", instance_path.display())),
        )
        .unwrap_or_else(|_| panic!("parse {}", instance_path.display()));
        assert!(
            validator.is_valid(&instance),
            "invalid instance {}: {:?}",
            instance_path.display(),
            validator.iter_errors(&instance).collect::<Vec<_>>()
        );
    };
    for config in [
        "config/gateway.example.json",
        "config/gateway.production.example.json",
    ] {
        validate("execution/gateway-config.schema.json", config);
    }
    validate(
        "runtime/production-runtime-config.schema.json",
        "config/production-runtime.example.json",
    );
    for (schema, report) in [
        (
            "execution/linux-isolation-report.schema.json",
            "evidence/external-gates/linux-isolation-baseline.json",
        ),
        (
            "release/external-gate-report.schema.json",
            "evidence/external-gates/enterprise-iam-not-run.json",
        ),
        (
            "release/external-gate-report.schema.json",
            "evidence/external-gates/temporal-local-protocol.json",
        ),
        (
            "release/external-gate-report.schema.json",
            "evidence/external-gates/object-store-local-s3.json",
        ),
        (
            "release/external-gate-report.schema.json",
            "evidence/external-gates/model-provider-live-catalog.json",
        ),
        (
            "release/external-gate-report.schema.json",
            "evidence/external-gates/model-generation-live-failed.json",
        ),
        (
            "sre/postgres-failover-report.schema.json",
            "evidence/external-gates/postgres-single-host-failover.json",
        ),
        (
            "sre/backup-restore-drill.schema.json",
            "evidence/external-gates/backup-restore-local-drill.json",
        ),
        (
            "sre/http-load-report.schema.json",
            "evidence/external-gates/gateway-local-load.json",
        ),
        (
            "sre/kubernetes-recovery-drill.schema.json",
            "evidence/external-gates/kubernetes-local-recovery.json",
        ),
        (
            "release/external-condition-matrix.schema.json",
            "evidence/production-closure/external-condition-matrix.json",
        ),
    ] {
        validate(schema, report);
    }
}

#[test]
fn platform_sre_zone_health_contract_rejects_client_facts_and_malformed_receipts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let read_schema = |relative: &str| {
        let path = root.join(relative);
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(&path).unwrap_or_else(|_| panic!("read {}", path.display())),
        )
        .unwrap_or_else(|_| panic!("parse {}", path.display()))
    };
    let command_schema = read_schema("schemas/platform-sre/sre-command.schema.json");
    let command_validator = jsonschema::validator_for(&command_schema)
        .unwrap_or_else(|error| panic!("compile command schema: {error}"));
    let valid_command = serde_json::json!({
        "schema_version": "agenttrust.sre-command.v1",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "command_id": "22222222-2222-4222-8222-222222222222",
        "task_id": "33333333-3333-4333-8333-333333333333",
        "resource": "sre:topology/44444444-4444-4444-8444-444444444444",
        "operation": "RECORD_ZONE_HEALTH",
        "expected_resource_version": 7,
        "requested_at": "2026-08-26T00:00:00Z",
        "payload": {
            "observation_id": "44444444-4444-4444-8444-444444444444",
            "topology_id": "55555555-5555-4555-8555-555555555555",
            "zone": "cn-east-1a",
            "probe_spec_digest": "a".repeat(64)
        }
    });
    assert!(command_validator.is_valid(&valid_command));
    let mut client_facts = valid_command.clone();
    client_facts["payload"]["component_health"] = serde_json::json!({"api": true});
    assert!(!command_validator.is_valid(&client_facts));
    let mut missing_probe_spec = valid_command;
    missing_probe_spec["payload"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("payload object"))
        .remove("probe_spec_digest");
    assert!(!command_validator.is_valid(&missing_probe_spec));

    let receipt_schema =
        read_schema("schemas/platform-sre/sre-external-receipt.schema.json");
    let receipt_validator = jsonschema::validator_for(&receipt_schema)
        .unwrap_or_else(|error| panic!("compile receipt schema: {error}"));
    let valid_receipt = serde_json::json!({
        "schema_version": "agenttrust.sre-external-receipt.v1",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "operation": "RECORD_ZONE_HEALTH",
        "resource": "sre:topology/44444444-4444-4444-8444-444444444444",
        "idempotency_key": "zone-health-0001",
        "action_hash": "b".repeat(64),
        "ledger_execution_id": "66666666-6666-4666-8666-666666666666",
        "ledger_event_id": "77777777-7777-4777-8777-777777777777",
        "ledger_event_digest": "c".repeat(64),
        "fence_digest": "d".repeat(64),
        "policy_decision_digest": "e".repeat(64),
        "authorization_evidence_ref": "evidence://authorization/zone-health-0001",
        "authorization_evidence_digest": "f".repeat(64),
        "request_digest": "1".repeat(64),
        "result_digest": "2".repeat(64),
        "immutable_evidence_refs": ["evidence://probe/zone-health-0001"],
        "immutable_evidence_digests": ["3".repeat(64)],
        "external_evidence_status": "OBSERVED",
        "production_evidence": false,
        "facts": {
            "component_health": {"api": true},
            "dependency_health": {"postgres": true},
            "ready_replicas": 3,
            "required_replicas": 3,
            "topology_probe_digest": "4".repeat(64),
            "probe_spec_digest": "a".repeat(64),
            "observed_at": "2026-08-26T00:00:01Z"
        }
    });
    assert!(receipt_validator.is_valid(&valid_receipt));
    let mut missing_fact = valid_receipt.clone();
    missing_fact["facts"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("facts object"))
        .remove("probe_spec_digest");
    assert!(!receipt_validator.is_valid(&missing_fact));
    let mut extra_fact = valid_receipt.clone();
    extra_fact["facts"]["untrusted_client_status"] = serde_json::json!(true);
    assert!(!receipt_validator.is_valid(&extra_fact));
    let mut invalid_health = valid_receipt.clone();
    invalid_health["facts"]["component_health"]["api"] = serde_json::json!("healthy");
    assert!(!receipt_validator.is_valid(&invalid_health));
    let mut false_production_claim = valid_receipt;
    false_production_claim["production_evidence"] = serde_json::json!(true);
    assert!(!receipt_validator.is_valid(&false_production_claim));
}

#[test]
fn all_batch_status_files_match_the_implementation_evidence_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for (package, batches) in [
        ("agent-trust-control-plane-batches-01-09-v2", 1..10),
        ("agent-trust-control-plane-batches-10-18-v2", 10..19),
        ("agent-trust-control-plane-batches-19-27-v2", 19..28),
        ("agent-trust-control-plane-batches-28-36-v2", 28..37),
    ] {
        let schema_path = root
            .join("skills")
            .join(package)
            .join("IMPLEMENTATION_EVIDENCE_SCHEMA.json");
        let schema: serde_json::Value = serde_json::from_slice(
            &fs::read(&schema_path).unwrap_or_else(|_| panic!("read {}", schema_path.display())),
        )
        .unwrap_or_else(|_| panic!("parse {}", schema_path.display()));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("compile {}: {error}", schema_path.display()));
        for batch in batches {
            let status_path = root.join(format!(
                "evidence/batch-{batch:02}/IMPLEMENTATION_STATUS.json"
            ));
            let status: serde_json::Value = serde_json::from_slice(
                &fs::read(&status_path)
                    .unwrap_or_else(|_| panic!("read {}", status_path.display())),
            )
            .unwrap_or_else(|_| panic!("parse {}", status_path.display()));
            assert!(
                validator.is_valid(&status),
                "invalid status {}: {:?}",
                status_path.display(),
                validator.iter_errors(&status).collect::<Vec<_>>()
            );
        }
    }
}
