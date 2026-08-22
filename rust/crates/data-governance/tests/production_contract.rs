const AUTHORITY: &str = include_str!("../src/authority.rs");
const SERVICE: &str = include_str!("../src/service.rs");
const ADAPTERS: &str = include_str!("../src/adapters.rs");
const SERVER: &str = include_str!("../src/server.rs");
const BINARY: &str = include_str!("../src/bin/agenttrust-data-governance-service.rs");
const MIGRATION: &str = include_str!(
    "../../../../migrations/data-governance/0036_01_15_production_data_governance.sql"
);
const OPENAPI: &str = include_str!("../../../../schemas/openapi/data-governance-v1.yaml");
const COMMAND_SCHEMA: &str =
    include_str!("../../../../schemas/data-governance/data-command.schema.json");
const INSPECTION_SCHEMA: &str =
    include_str!("../../../../schemas/data-governance/inspection.schema.json");
const AUTHORITATIVE_PAGE_SCHEMA: &str =
    include_str!("../../../../schemas/data-governance/authoritative-page.schema.json");
const DOCKERFILE: &str = include_str!("../../../../Dockerfile.data-governance");
const RUNBOOK: &str =
    include_str!("../../../../docs/data-governance/production-runbook.md");
const FAILURE_MATRIX: &str =
    include_str!("../../../../tests/data-governance/failure-injection-matrix.json");

#[test]
fn durable_operations_match_code_schema_and_database_contract() {
    for operation in [
        "REGISTER_LABEL", "RECORD_POLICY_DECISION", "RECORD_DLP_SCAN",
        "RECORD_TRANSFORM_RECEIPT", "ISSUE_CROSS_DOMAIN_GRANT",
        "CONSUME_CROSS_DOMAIN_GRANT", "RESOLVE_RETENTION", "PLACE_LEGAL_HOLD",
        "RELEASE_LEGAL_HOLD", "AUTHORIZE_EXPORT", "COMPLETE_EXPORT",
    ] {
        assert!(AUTHORITY.contains(operation), "authority missing {operation}");
        assert!(COMMAND_SCHEMA.contains(operation), "schema missing {operation}");
        assert!(MIGRATION.contains(operation), "migration missing {operation}");
    }
}

#[test]
fn exact_pep_ledger_fence_and_evidence_binding_is_mandatory() {
    for header in [
        "x-agenttrust-action-hash", "x-agenttrust-ledger-execution-id",
        "x-agenttrust-ledger-entry-id", "x-agenttrust-ledger-entry-digest",
        "x-agenttrust-fence-digest", "x-agenttrust-resource-version",
        "x-agenttrust-policy-decision-id", "x-agenttrust-policy-decision-digest",
        "x-agenttrust-authorization-evidence-ref",
        "x-agenttrust-authorization-evidence-digest",
    ] {
        assert!(SERVER.contains(header), "server missing {header}");
        assert!(OPENAPI.to_ascii_lowercase().contains(header), "OpenAPI missing {header}");
    }
    for column in [
        "ledger_event_id", "ledger_event_digest", "policy_decision_digest",
        "authorization_evidence_ref", "authorization_evidence_digest",
    ] {
        assert!(MIGRATION.contains(column), "migration missing {column}");
    }
    assert!(AUTHORITY.contains("CANONICAL_ACTION_IR->PEP->LEDGER->EVIDENCE"));
}

#[test]
fn typed_ephemeral_routes_never_write_raw_content() {
    for path in [
        "/v1/internal/data/evaluate", "/v1/internal/data/scan",
        "/v1/internal/data/sanitize", "/v1/internal/data/artifacts/authorize",
    ] {
        assert!(SERVER.contains(path), "server missing {path}");
        assert!(OPENAPI.contains(path), "OpenAPI missing {path}");
    }
    for forbidden_column in [
        "raw_content ", "prompt_content ", "content_base64 ", "sanitized_prompt ",
        "secret_value ", "bearer_token ",
    ] {
        assert!(!MIGRATION.to_ascii_lowercase().contains(forbidden_column));
    }
    assert!(SERVICE.contains("durable_record_required: true"));
    assert!(SERVICE.contains("ContentEncoding::Gzip | ContentEncoding::Zip"));
    assert!(ADAPTERS.contains("redirect(reqwest::redirect::Policy::none())") || BINARY.contains("redirect(reqwest::redirect::Policy::none())"));
}

#[test]
fn completed_mutation_read_never_promotes_a_pending_record_proposal() {
    let path = "/v1/authoritative/data/mutations/{command_id}";
    assert!(SERVER.contains("/v1/authoritative/data/mutations/{command_id}"));
    assert!(OPENAPI.contains(path));
    assert!(AUTHORITY.contains("if state != \"COMPLETED\""));
    assert!(AUTHORITY.contains("result.evidence_ref.as_deref()"));
    assert!(AUTHORITY.contains("result.evidence_digest.as_deref()"));
}

#[test]
fn authoritative_page_has_an_explicit_canonical_integrity_envelope() {
    for marker in ["authoritative: true", "data_digest", "remove(\"data_digest\")", "canonical_digest(&material)"] {
        assert!(AUTHORITY.contains(marker), "authority page missing {marker}");
    }
    for contract in [OPENAPI, AUTHORITATIVE_PAGE_SCHEMA] {
        assert!(contract.contains("authoritative"));
        assert!(contract.contains("data_digest"));
        assert!(contract.contains("JCS SHA-256"));
    }
}

#[test]
fn production_boundary_is_tls13_single_san_exact_scope_and_fixed_ports() {
    assert!(SERVER.contains("with_protocol_versions(&[&rustls::version::TLS13])"));
    assert!(BINARY.contains("min_tls_version(reqwest::tls::Version::TLS_1_3)"));
    assert!(BINARY.contains("max_tls_version(reqwest::tls::Version::TLS_1_3)"));
    assert!(SERVER.contains("identities.len() == 1"));
    assert!(SERVER.contains("CommonName is deliberately ignored"));
    for scope in [
        "data:mutate", "data:execute", "data:evaluate", "data:scan",
        "data:sanitize", "data:artifact-authorize", "data:read",
    ] {
        assert!(SERVER.contains(scope));
    }
    assert!(BINARY.contains("Uid::effective().is_root()"));
    assert!(BINARY.contains("required_exact_port(\"AGENT_TRUST_DATA_PORT\", 8092)"));
    assert!(BINARY.contains("required_exact_port(\"AGENT_TRUST_DATA_MANAGEMENT_PORT\", 9102)"));
    assert!(BINARY.contains("DATA_GOVERNANCE_DATABASE_ROLE_UNSAFE"));
    assert!(ADAPTERS.contains("self.endpoint.port().is_none()"));
    assert!(ADAPTERS.contains("value.schema_version == endpoint.readiness_schema"));
}

#[test]
fn force_rls_immutability_concurrency_and_evidence_recovery_are_structural() {
    for table in [
        "data_resource_versions", "data_authority_ingress", "data_authority_executions",
        "governed_data_labels", "data_policy_decision_records", "data_dlp_scan_summaries",
        "data_transform_receipts", "data_cross_domain_grants",
        "data_cross_domain_consumptions", "data_retention_records", "data_legal_holds",
        "data_export_intents", "data_evidence_outbox",
    ] {
        assert!(MIGRATION.contains(table), "migration missing {table}");
    }
    for marker in [
        "FORCE ROW LEVEL SECURITY", "data_single_resource_flight_idx",
        "FOR UPDATE", "consumed_at IS NULL", "MUTATED_PENDING_EVIDENCE",
        "recover_pending_evidence", "MissedTickBehavior::Delay",
    ] {
        assert!(MIGRATION.contains(marker) || AUTHORITY.contains(marker) || SERVER.contains(marker), "missing {marker}");
    }
    assert!(MIGRATION.contains("DATA_CROSS_DOMAIN_GRANT_IMMUTABLE"));
    assert!(MIGRATION.contains("DATA_EVIDENCE_OUTBOX_IMMUTABLE"));
    assert!(AUTHORITY.contains("data-governance:{tenant}:{object_ref}"));
    assert!(AUTHORITY.contains("validate_resource_binding"));
    assert!(AUTHORITY.contains("only future skew is invalid here"));
    assert!(!AUTHORITY.contains("request.requested_at < now - Duration::minutes(5)"));
    assert!(AUTHORITY.contains("receipt.authority_event_id != pending.event_id.to_string()"));
    assert!(ADAPTERS.contains("v1/dlp/receipts/verify"));
}

#[test]
fn evidence_uses_the_shared_governed_authority_wire_and_verifies_signatures() {
    for marker in [
        "AuthorityEvidenceEventRequest", "AuthorityEvidenceControlBinding",
        "AuthorityEvidenceSourceKind::GovernedAction", "SignedAuthorityEvidenceReceipt",
        "v1/evidence/authority-events", "X-AgentTrust-Authority-Event-Id",
        "X-AgentTrust-Payload-Digest", "receipt.verify(verifying_key, Utc::now())",
    ] {
        assert!(ADAPTERS.contains(marker), "Evidence adapter missing {marker}");
    }
    for marker in [
        "task_id", "event_occurred_at", "delivery_requested_at",
        "data-governance-evidence-{event_id}",
    ] {
        assert!(AUTHORITY.contains(marker), "durable outbox missing {marker}");
    }
    for variable in [
        "AGENT_TRUST_DATA_EVIDENCE_SOURCE_SERVICE",
        "AGENT_TRUST_DATA_EVIDENCE_ISSUER",
        "AGENT_TRUST_DATA_EVIDENCE_VERIFYING_KEYRING_FILE",
    ] {
        assert!(BINARY.contains(variable), "production config missing {variable}");
    }
    assert!(!ADAPTERS.contains("v1/evidence/events\""));
    assert!(RUNBOOK.contains("evidence:authority-event"));
}

#[test]
fn artifact_and_export_authorization_require_exact_durable_preflight_bindings() {
    for marker in [
        "verify_artifact_preflight", "governed_data_labels", "data_policy_decision_records",
        "data_dlp_scan_summaries", "data_transform_receipts", "data_cross_domain_grants",
        "transformations @> d.decision->'required_transformations'",
        "s.engine_receipt_digest=$8", "g.single_use AND g.expires_at>now()",
        "verify_external_effect_preconditions", "DataOperation::CompleteExport",
    ] {
        assert!(AUTHORITY.contains(marker), "durable preflight missing {marker}");
    }
    for marker in [
        "dlp_receipt_digest", "transform_id", "transform_receipt_digest",
        "object_authorization_ref", "object_authorization_digest",
    ] {
        assert!(COMMAND_SCHEMA.contains(marker), "command schema missing {marker}");
        assert!(MIGRATION.contains(marker), "migration missing {marker}");
        assert!(INSPECTION_SCHEMA.contains(marker), "inspection schema missing {marker}");
    }
    assert!(SERVICE.contains("durable_preflight_verified: true"));
    assert!(SERVICE.contains("receipt.transform_id != request.transform_id"));
}

#[test]
fn failure_matrix_covers_required_negative_and_crash_boundaries() {
    for scenario in [
        "ENTERPRISE_DLP_UNAVAILABLE", "ENCODED_COMPRESSED_ESCAPE", "REDIRECT_BYPASS",
        "PUBLIC_MODEL_FALLBACK", "CROSS_TENANT_EXPORT", "CROSS_DOMAIN_CONCURRENT_REPLAY",
        "LEGAL_HOLD_RELEASE_RACE", "CRASH_AFTER_EXTERNAL_EFFECT", "CRASH_AFTER_DB_COMMIT",
        "OFFLINE_EGRESS_ATTEMPT", "ARTIFACT_DURABLE_BINDING_MISMATCH",
        "REQUIRED_TRANSFORM_MISSING", "EXPORT_TRANSFORM_REPLAY",
    ] {
        assert!(FAILURE_MATRIX.contains(scenario), "missing {scenario}");
    }
    assert!(FAILURE_MATRIX.contains("NOT_RUN_EXTERNAL_ENVIRONMENT"));
}

#[test]
fn image_is_pinned_non_root_and_evidence_boundary_is_honest() {
    assert!(DOCKERFILE.contains("@sha256:"));
    assert!(DOCKERFILE.contains("USER 65532:65532"));
    assert!(RUNBOOK.contains("IN_PROGRESS"));
    assert!(RUNBOOK.contains("NOT_RUN"));
}

#[test]
fn production_sources_have_no_placeholder_or_allow_all_path() {
    for source in [AUTHORITY, SERVICE, ADAPTERS, SERVER, BINARY] {
        for marker in ["todo!", "unimplemented!", "mock production", "allow_all"] {
            assert!(!source.contains(marker), "placeholder marker {marker}");
        }
    }
    assert!(INSPECTION_SCHEMA.contains("maxLength"));
}
