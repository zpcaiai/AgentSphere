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
