use serde_json::Value;

const MIGRATION: &str = include_str!(
    "../../../../migrations/security-evaluation/0036_01_12_production_security_evaluation.sql"
);
const OPENAPI: &str = include_str!("../../../../schemas/openapi/security-evaluation-v1.yaml");
const COMMAND_SCHEMA: &str = include_str!(
    "../../../../schemas/security-evaluation/security-evaluation-command-v1.schema.json"
);
const SCENARIO_SCHEMA: &str =
    include_str!("../../../../schemas/security-evaluation/attack-scenario-v1.schema.json");
const DATASET_SCHEMA: &str =
    include_str!("../../../../schemas/security-evaluation/attack-dataset-manifest-v1.schema.json");
const REPORT_SCHEMA: &str = include_str!(
    "../../../../schemas/security-evaluation/security-evaluation-report-v1.schema.json"
);
const RUNNER_SCHEMA: &str =
    include_str!("../../../../schemas/security-evaluation/isolated-runner-receipt-v1.schema.json");
const AUTHORITY: &str = include_str!("../src/authority.rs");
const SERVER: &str = include_str!("../src/server.rs");
const BINARY: &str = include_str!("../src/bin/agenttrust-security-evaluation-authority.rs");
const DOCKERFILE: &str = include_str!("../Dockerfile");

#[test]
fn json_contracts_are_strict_and_parseable() {
    for source in [
        COMMAND_SCHEMA,
        SCENARIO_SCHEMA,
        DATASET_SCHEMA,
        REPORT_SCHEMA,
        RUNNER_SCHEMA,
    ] {
        let schema: Value =
            serde_json::from_str(source).unwrap_or_else(|error| panic!("schema: {error}"));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        assert!(schema.get("required").is_some());
    }
    assert!(REPORT_SCHEMA.contains("\"production_certified\": {\"const\": false}"));
    assert!(RUNNER_SCHEMA.contains("\"production_access_detected\": {\"const\": false}"));
    assert!(RUNNER_SCHEMA.contains("\"physical_side_effect_detected\": {\"const\": false}"));
}

#[test]
fn public_executor_contract_requires_the_whole_control_path() {
    for header in [
        "X-AgentTrust-Action-Hash",
        "X-AgentTrust-Ledger-Execution-Id",
        "X-AgentTrust-Ledger-Entry-Id",
        "X-AgentTrust-Ledger-Entry-Digest",
        "X-AgentTrust-Fence-Digest",
        "X-AgentTrust-Resource-Version",
        "X-AgentTrust-Policy-Decision-Id",
        "X-AgentTrust-Policy-Decision-Digest",
        "X-AgentTrust-Authorization-Evidence-Ref",
        "X-AgentTrust-Authorization-Evidence-Digest",
    ] {
        assert!(OPENAPI.contains(header), "missing {header}");
        assert!(
            SERVER
                .to_ascii_lowercase()
                .contains(&header.to_ascii_lowercase())
        );
    }
    assert!(AUTHORITY.contains("CANONICAL_ACTION_IR->PEP->LEDGER->FENCE->EVIDENCE"));
    assert!(AUTHORITY.contains("security_eval_evidence_events"));
    assert!(AUTHORITY.contains("security_eval_evidence_outbox"));
}

#[test]
fn migration_forces_rls_and_immutable_evidence_for_every_runtime_table() {
    let tables = [
        "security_eval_datasets",
        "security_eval_dataset_versions",
        "attack_scenarios",
        "security_campaigns",
        "security_eval_campaign_scenarios",
        "security_eval_scenario_results",
        "security_findings",
        "security_eval_remediations",
        "security_eval_retests",
        "security_eval_baselines",
        "security_eval_reports",
        "security_eval_kill_switches",
        "security_eval_resource_versions",
        "security_eval_action_ingress",
        "security_eval_authority_executions",
        "security_eval_evidence_events",
        "security_eval_evidence_outbox",
    ];
    for table in tables {
        assert!(MIGRATION.contains(table), "missing {table}");
    }
    assert!(MIGRATION.contains("ALTER TABLE %I FORCE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("current_setting(''app.tenant_id'',true)"));
    assert!(MIGRATION.contains("SECURITY_EVAL_IMMUTABLE_RECORD"));
    assert!(MIGRATION.contains("SECURITY_EVAL_RESOURCE_FENCE_INVALID"));
    assert!(MIGRATION.contains("SECURITY_EVAL_HIGH_RISK_REGRESSION_NOT_BLOCKED"));
    assert!(MIGRATION.contains("NOT production_access_allowed"));
    assert!(MIGRATION.contains("NOT physical_effects_allowed"));
}

#[test]
fn attack_catalog_covers_protocol_context_identity_sandbox_and_domains() {
    for threat in [
        "PROMPT_INJECTION",
        "TOOL_ABUSE",
        "CREDENTIAL_MOVEMENT",
        "MEMORY_POISONING",
        "MCP_DECLARATION_MISMATCH",
        "A2A_CASCADE",
        "IDENTITY_SPOOFING",
        "APPROVAL_BYPASS",
        "SANDBOX_ESCAPE",
        "SLOW_EXFILTRATION",
        "CONTEXT_POISONING",
    ] {
        assert!(DATASET_SCHEMA.contains(threat), "missing {threat}");
    }
    for domain in [
        "CODING",
        "INDUSTRIAL",
        "ENERGY",
        "MEDICAL",
        "SENSITIVE_INTERACTION",
    ] {
        assert!(DATASET_SCHEMA.contains(domain), "missing {domain}");
        assert!(AUTHORITY.contains(&format!("\"{domain}\"")));
    }
}

#[test]
fn restart_failure_and_budget_paths_fail_closed_in_source() {
    for invariant in [
        "LEASE_EXPIRED",
        "RUNNER_OUTCOME_UNKNOWN",
        "RUNNER_PREFLIGHT_DENIED",
        "RUNNER_RECEIPT_INVALID",
        "KillSwitchTripped",
        "BudgetExhausted",
    ] {
        assert!(AUTHORITY.contains(invariant), "missing {invariant}");
    }
    assert!(AUTHORITY.contains("if state == \"SUCCEEDED\""));
    assert!(AUTHORITY.contains("return Ok(ExecutionClaim::Replay(result))"));
    assert!(AUTHORITY.contains("production_certified: false"));
    assert!(AUTHORITY.contains("recorded_at"));
    assert!(AUTHORITY.contains("payload_digest: row.get(\"payload_digest\")"));
    assert!(SERVER.contains("v1/evidence/authority-events"));
    assert!(SERVER.contains("AuthorityEvidenceControlBinding"));
    assert!(SERVER.contains("SignedAuthorityEvidenceReceipt"));
    assert!(SERVER.contains("receipt.verify(key, Utc::now())"));
    assert!(BINARY.contains("AGENT_TRUST_SECURITY_EVAL_EVIDENCE_CLIENT_IDENTITY"));
    assert!(BINARY.contains("AGENT_TRUST_SECURITY_EVAL_EVIDENCE_KEYRING_FILE"));
}

#[test]
fn startup_and_image_posture_are_fail_closed() {
    for invariant in [
        "Uid::effective().is_root()",
        "PgSslMode::VerifyFull",
        "rolbypassrls",
        "relforcerowsecurity",
        "SECURITY_EVAL_DATABASE_GRANTS_INVALID",
        "metadata.file_type().is_symlink()",
        "metadata.mode() & 0o077",
    ] {
        assert!(BINARY.contains(invariant), "missing {invariant}");
    }
    assert!(DOCKERFILE.contains("ARG RUST_BUILDER_IMAGE"));
    assert!(DOCKERFILE.contains("ARG RUNTIME_BASE_IMAGE"));
    assert!(DOCKERFILE.contains("cargo build --locked --release"));
    assert!(DOCKERFILE.contains("USER 65532:65532"));
}
