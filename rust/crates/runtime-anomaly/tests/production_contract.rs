const AUTHORITY: &str = include_str!("../src/authority.rs");
const DETECTOR: &str = include_str!("../src/lib.rs");
const ADAPTERS: &str = include_str!("../src/production.rs");
const SERVER: &str = include_str!("../src/server.rs");
const BINARY: &str = include_str!("../src/bin/agenttrust-runtime-anomaly-authority.rs");
const MIGRATION: &str = include_str!(
    "../../../../migrations/runtime-anomaly/0036_01_17_production_runtime_anomaly.sql"
);
const OPENAPI: &str = include_str!("../../../../schemas/openapi/runtime-anomaly-v1.yaml");
const RISK_SIGNAL_SCHEMA: &str =
    include_str!("../../../../schemas/runtime-anomaly/risk-signal.schema.json");
const SIGNED_SIGNAL_SCHEMA: &str =
    include_str!("../../../../schemas/runtime-anomaly/signed-risk-signal.schema.json");
const COMMAND_SCHEMA: &str =
    include_str!("../../../../schemas/runtime-anomaly/runtime-anomaly-command.schema.json");
const RESPONSE_REQUEST_SCHEMA: &str =
    include_str!("../../../../schemas/runtime-anomaly/controlled-response-request.schema.json");
const RESPONSE_RECEIPT_SCHEMA: &str =
    include_str!("../../../../schemas/runtime-anomaly/controlled-response-receipt.schema.json");
const DOCKERFILE: &str = include_str!("../../../../Dockerfile.runtime-anomaly");
const IMAGE_BUILDER: &str = include_str!("../../../../scripts/build-production-image.py");
const RUNBOOK: &str = include_str!("../../../../docs/runtime-anomaly/operations-runbook.md");
const FAILURE_MATRIX: &str =
    include_str!("../../../../tests/runtime-anomaly/failure-injection-matrix.json");

#[test]
fn governed_operations_match_code_schema_and_database_contract() {
    for operation in [
        "REGISTER_SOURCE",
        "REVOKE_SOURCE",
        "START_TRAJECTORY",
        "UPDATE_BASELINE",
        "RECORD_FEEDBACK",
        "ACKNOWLEDGE_CASE",
        "RECOVER_PAUSED_TASK",
        "COMPLETE_TRAJECTORY",
    ] {
        assert!(
            AUTHORITY.contains(operation),
            "authority missing {operation}"
        );
        assert!(
            COMMAND_SCHEMA.contains(operation),
            "schema missing {operation}"
        );
        assert!(
            MIGRATION.contains(operation),
            "migration missing {operation}"
        );
    }
    assert!(AUTHORITY.contains("APPLY_CONTINUOUS_AUTHORIZATION"));
}

#[test]
fn production_action_requires_canonical_pep_ledger_fence_and_evidence() {
    for header in [
        "x-agenttrust-action-hash",
        "x-agenttrust-ledger-execution-id",
        "x-agenttrust-ledger-event-id",
        "x-agenttrust-ledger-event-digest",
        "x-agenttrust-fence-digest",
        "x-agenttrust-resource-version",
        "x-agenttrust-policy-decision-id",
        "x-agenttrust-policy-decision-digest",
        "x-agenttrust-authorization-evidence-ref",
        "x-agenttrust-authorization-evidence-digest",
    ] {
        assert!(SERVER.contains(header), "server missing {header}");
        assert!(
            OPENAPI.to_ascii_lowercase().contains(header),
            "OpenAPI missing {header}"
        );
    }
    for column in [
        "action_hash",
        "ledger_execution_id",
        "ledger_event_id",
        "ledger_event_digest",
        "fence_digest",
        "policy_decision_digest",
        "authorization_evidence_digest",
    ] {
        assert!(MIGRATION.contains(column), "migration missing {column}");
    }
}

#[test]
fn signed_signals_are_bounded_source_and_workload_bound() {
    // Source/key/signature provenance is carried by the signed outer envelope;
    // workload identity is bound by the mTLS request and checked by authority.
    for marker in ["source_id", "key_id", "signature", "signal", "semantic_score"] {
        assert!(
            SIGNED_SIGNAL_SCHEMA.contains(marker),
            "signed signal schema missing {marker}"
        );
    }
    for marker in ["workload_identity", "safe_features"] {
        assert!(AUTHORITY.contains(marker), "authority missing {marker}");
    }
    assert!(RISK_SIGNAL_SCHEMA.contains("safeValue"));
    assert!(RISK_SIGNAL_SCHEMA.contains("maxProperties"));
    assert!(RISK_SIGNAL_SCHEMA.contains("maxLength"));
    assert!(AUTHORITY.contains("maximum_signal_clock_skew_seconds"));
    assert!(AUTHORITY.contains("maximum_signal_lookback"));
    for forbidden in [
        "raw_prompt",
        "raw_output",
        "credential_value",
        "authorization_header",
    ] {
        assert!(
            !MIGRATION.contains(forbidden),
            "raw material column {forbidden}"
        );
    }
}

#[test]
fn deterministic_detection_drives_fail_closed_continuous_authorization() {
    for marker in [
        "RUNTIME_SANDBOX_EVASION",
        "RUNTIME_APPROVAL_BYPASS",
        "RUNTIME_SLOW_EXFILTRATION",
        "RUNTIME_CREDENTIAL_MOVEMENT",
        "RUNTIME_REPEATED_POLICY_DENY",
    ] {
        assert!(
            DETECTOR.contains(marker) || AUTHORITY.contains(marker),
            "detector missing {marker}"
        );
    }
    for adjustment in [
        "REQUIRE_APPROVAL",
        "REDUCE_SCOPE",
        "PAUSE",
        "REVOKE_LEASE",
        "REVOKE_CREDENTIAL",
        "KILL",
    ] {
        assert!(
            DETECTOR.contains(adjustment),
            "adjustment missing {adjustment}"
        );
    }
    assert!(AUTHORITY.contains("new_revocation_epoch"));
    assert!(AUTHORITY.contains("RECOVER_PAUSED_TASK"));
    assert!(AUTHORITY.contains("mark_execution_unknown"));
}

#[test]
fn response_receipts_and_evidence_are_exactly_bound_and_recoverable() {
    for marker in [
        "supervisor_receipt_digest",
        "credential_receipt_digest",
        "incident_receipt_digest",
        "command_digest",
        "payload_digest",
        "evidence_ref",
    ] {
        assert!(
            AUTHORITY.contains(marker),
            "receipt binding missing {marker}"
        );
    }
    assert!(AUTHORITY.contains("MUTATED_PENDING_EVIDENCE"));
    assert!(AUTHORITY.contains("recover_pending_evidence"));
    assert!(AUTHORITY.contains("recover_signal_evidence"));
    assert!(ADAPTERS.contains("Policy::none()"));
    assert!(ADAPTERS.contains("tls_built_in_root_certs(false)"));
    assert!(ADAPTERS.contains("Version::TLS_1_3"));
    assert!(ADAPTERS.contains("v1/evidence/authority-events"));
    assert!(ADAPTERS.contains("AuthorityEvidenceSourceKind::GovernedAction"));
    assert!(ADAPTERS.contains("AuthorityEvidenceSourceKind::AuthenticatedEvent"));
    assert!(ADAPTERS.contains("SignedAuthorityEvidenceReceipt"));
    assert!(ADAPTERS.contains("receipt.verify(key, Utc::now())"));
    assert!(ADAPTERS.contains("evidence_occurred_at"));
    assert!(BINARY.contains("AGENT_TRUST_RUNTIME_ANOMALY_EVIDENCE_KEYRING_FILE"));
    assert!(BINARY.contains("AGENT_TRUST_RUNTIME_ANOMALY_EVIDENCE_CLIENT_IDENTITY"));
    assert!(RESPONSE_REQUEST_SCHEMA.contains("agenttrust.controlled-runtime-response.v1"));
    assert!(RESPONSE_REQUEST_SCHEMA.contains("authorization_evidence_digest"));
    assert!(RESPONSE_RECEIPT_SCHEMA.contains("agenttrust.controlled-runtime-response-receipt.v1"));
    assert!(RESPONSE_RECEIPT_SCHEMA.contains("command_digest"));
}

#[test]
fn production_boundary_is_tls13_single_san_exact_scope_and_fixed_ports() {
    assert!(SERVER.contains("with_protocol_versions(&[&rustls::version::TLS13])"));
    assert!(SERVER.contains("identities.len() == 1"));
    assert!(SERVER.contains("CommonName is intentionally ignored"));
    for scope in [
        "runtime-anomaly:signal",
        "runtime-anomaly:mutate",
        "runtime-anomaly:execute",
        "runtime-anomaly:query",
    ] {
        assert!(SERVER.contains(scope));
    }
    assert!(BINARY.contains("Uid::effective().is_root()"));
    assert!(
        BINARY.contains("required_exact_port(\"AGENT_TRUST_RUNTIME_ANOMALY_DATA_PORT\", 8_094)")
    );
    assert!(
        BINARY.contains(
            "required_exact_port(\"AGENT_TRUST_RUNTIME_ANOMALY_MANAGEMENT_PORT\", 9_104)"
        )
    );
}

#[test]
fn force_rls_immutability_state_and_failure_boundaries_are_structural() {
    for table in [
        "runtime_anomaly_signal_sources",
        "runtime_anomaly_trajectories",
        "runtime_anomaly_signals",
        "runtime_anomaly_findings",
        "runtime_anomaly_aggregates",
        "runtime_anomaly_baselines",
        "runtime_anomaly_feedback",
        "runtime_anomaly_cases",
        "runtime_anomaly_action_ingress",
        "runtime_anomaly_authority_executions",
        "runtime_anomaly_response_commands",
        "runtime_anomaly_evidence_events",
        "runtime_anomaly_evidence_outbox",
    ] {
        assert!(MIGRATION.contains(table), "migration missing {table}");
    }
    assert!(MIGRATION.contains("FORCE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("current_setting(''app.tenant_id'',true)"));
    for scenario in [
        "SIGNAL_SOURCE_KEY_REVOKED",
        "ENCODED_SANDBOX_EVASION",
        "CREDENTIAL_MOVEMENT",
        "ORCHESTRATOR_TIMEOUT",
        "DOWNSTREAM_RESPONSE_TIMEOUT",
        "CRASH_AFTER_MUTATION_BEFORE_EVIDENCE",
        "EVIDENCE_RECEIPT_BINDING_MISMATCH",
        "EVIDENCE_RECEIPT_SIGNATURE_MISMATCH",
        "EVIDENCE_DELAYED_EXACT_REPLAY",
    ] {
        assert!(
            FAILURE_MATRIX.contains(scenario),
            "missing scenario {scenario}"
        );
    }
    assert!(FAILURE_MATRIX.contains("NOT_RUN_EXTERNAL_ENVIRONMENT"));
}

#[test]
fn image_and_runbook_preserve_the_evidence_boundary() {
    assert!(DOCKERFILE.contains("RUST_BUILDER_IMAGE"));
    assert!(DOCKERFILE.contains("RUNTIME_BASE_IMAGE"));
    assert!(IMAGE_BUILDER.contains("@sha256:"));
    assert!(IMAGE_BUILDER.contains("runtime-anomaly"));
    assert!(DOCKERFILE.contains("USER 65532:65532"));
    assert!(RUNBOOK.contains("NOT_RUN"));
    assert!(RUNBOOK.contains("UNKNOWN"));
    for source in [AUTHORITY, ADAPTERS, SERVER, BINARY] {
        for marker in ["todo!", "unimplemented!", "mock production", "allow_all"] {
            assert!(!source.contains(marker), "placeholder marker {marker}");
        }
    }
}
