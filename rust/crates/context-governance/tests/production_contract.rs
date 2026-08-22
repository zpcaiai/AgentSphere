use std::collections::BTreeSet;

const AUTHORITY: &str = include_str!("../src/authority.rs");
const ADAPTERS: &str = include_str!("../src/adapters.rs");
const SERVER: &str = include_str!("../src/server.rs");
const BINARY: &str = include_str!("../src/bin/agenttrust-context-governance-service.rs");
const MIGRATION: &str = include_str!(
    "../../../../migrations/context-governance/0036_01_11_production_context_governance.sql"
);
const OPENAPI: &str = include_str!("../../../../schemas/openapi/context-governance-v1.yaml");
const COMMAND_SCHEMA: &str =
    include_str!("../../../../schemas/context/context-command.schema.json");
const DOCKERFILE: &str = include_str!("../Dockerfile");
const RUNBOOK: &str = include_str!("../PRODUCTION.md");
const FAILURE_MATRIX: &str =
    include_str!("../../../../tests/context-security/failure-injection-matrix.json");

#[test]
fn lifecycle_operations_match_code_schema_openapi_and_database_contract() {
    let operations = [
        "WRITE_MEMORY",
        "DELETE_MEMORY",
        "PUBLISH_PROMPT",
        "ACTIVATE_PROMPT",
        "ROLLBACK_PROMPT",
        "REGISTER_KNOWLEDGE_SOURCE",
        "PUBLISH_KNOWLEDGE_SNAPSHOT",
        "DELETE_KNOWLEDGE_SNAPSHOT",
        "QUARANTINE_RESOURCE",
        "RELEASE_QUARANTINE",
    ];
    for operation in operations {
        assert!(AUTHORITY.contains(operation), "authority missing {operation}");
        assert!(COMMAND_SCHEMA.contains(operation), "schema missing {operation}");
        assert!(MIGRATION.contains(operation), "migration missing {operation}");
    }
    for path in [
        "/v1/context/actions",
        "/v1/context/executions",
        "/v1/context/retrievals",
        "/v1/authoritative/context/resources",
    ] {
        assert!(OPENAPI.contains(path), "OpenAPI missing {path}");
        assert!(SERVER.contains(path), "server missing {path}");
    }
}

#[test]
fn executor_requires_complete_authorization_ledger_and_evidence_binding() {
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
        assert!(SERVER.contains(header), "server missing {header}");
        assert!(
            OPENAPI.to_ascii_lowercase().contains(header),
            "OpenAPI missing {header}"
        );
    }
    for column in [
        "ledger_event_id",
        "ledger_event_digest",
        "policy_decision_digest",
        "authorization_evidence_ref",
        "authorization_evidence_digest",
    ] {
        assert!(MIGRATION.contains(column), "migration missing {column}");
    }
}

#[test]
fn authorization_is_structurally_before_similarity_and_vector_scope_is_explicit() {
    let authorize = match AUTHORITY.find("authorize_retrieval(&binding, &request).await") {
        Some(offset) => offset,
        None => panic!("authorization call missing"),
    };
    let search = match AUTHORITY.find("self.runtime.search(&binding, &request, &decision).await") {
        Some(offset) => offset,
        None => panic!("similarity call missing"),
    };
    assert!(authorize < search);
    assert!(ADAPTERS.contains("allowed_resources: &decision.authorized_resources"));
    assert!(AUTHORITY.contains("decision.authorized_resources.is_empty()"));
    assert!(MIGRATION.contains("context_retrieval_decisions"));
    assert!(MIGRATION.contains("context_retrieval_immutable_guard"));
    assert!(MIGRATION.contains("UNIQUE (tenant_id, retrieval_id)"));
    assert!(MIGRATION.contains("context_single_resource_flight_idx"));
}

#[test]
fn deletion_quarantine_and_failure_recovery_are_durable() {
    for marker in [
        "LEGAL_HOLD",
        "OBJECT_STORE",
        "VECTOR_INDEX",
        "CACHE",
        "POISONING",
        "SUPPLY_CHAIN",
    ] {
        assert!(ADAPTERS.contains(marker), "missing adapter {marker}");
    }
    for marker in [
        "MUTATED_PENDING_EVIDENCE",
        "pending_evidence",
        "recover_pending_evidence",
        "context_evidence_outbox",
        "cache_purged",
        "legal_hold_blocked",
    ] {
        assert!(AUTHORITY.contains(marker) || MIGRATION.contains(marker), "missing {marker}");
    }
    assert!(ADAPTERS.contains("verify_absent"));
    assert!(SERVER.contains("MissedTickBehavior::Delay"));
    assert!(ADAPTERS.contains("v1/evidence/authority-events"));
    assert!(ADAPTERS.contains("AuthorityEvidenceControlBinding"));
    assert!(ADAPTERS.contains("SignedAuthorityEvidenceReceipt"));
    assert!(ADAPTERS.contains("receipt.verify(key, Utc::now())"));
    assert!(BINARY.contains("AGENT_TRUST_CONTEXT_EVIDENCE_CLIENT_IDENTITY"));
    assert!(BINARY.contains("AGENT_TRUST_CONTEXT_EVIDENCE_KEYRING_FILE"));
}

#[test]
fn failure_injection_matrix_covers_external_effect_and_outbox_crash_boundaries() {
    for scenario in [
        "VECTOR_PARTIAL_WRITE",
        "OBJECT_INDEX_INCONSISTENCY",
        "DELETION_EVENT_LOSS",
        "POISONING_DETECTOR_UNAVAILABLE",
        "PROMPT_REGISTRY_ROLLBACK_CRASH",
        "EVIDENCE_RECEIPT_SIGNATURE_MISMATCH",
        "DELAYED_EVIDENCE_REPLAY",
    ] {
        assert!(FAILURE_MATRIX.contains(scenario), "missing {scenario}");
    }
    for invariant in [
        "SAME_IDEMPOTENCY_KEY_AND_REQUEST_DIGEST",
        "ADAPTER_RECEIPTS_REPLAY_EXACTLY",
        "SAME_OUTBOX_EVENT_ID_AND_PAYLOAD_DIGEST",
        "NO_OBJECT_PROMOTION_OR_VECTOR_UPSERT",
        "TARGET_VERSION_AND_FENCE_UNCHANGED",
    ] {
        assert!(FAILURE_MATRIX.contains(invariant), "missing {invariant}");
    }
    assert!(FAILURE_MATRIX.contains("MUTATED_PENDING_EVIDENCE"));
    assert!(FAILURE_MATRIX.contains("REPLAY_ORIGINAL_EVENT_TIME_AND_REQUEST_DIGEST"));
    assert!(FAILURE_MATRIX.matches("SIDE_EFFECTS_PENDING").count() >= 4);
}

#[test]
fn production_boundary_is_tls13_single_san_and_exact_token_scope() {
    assert!(SERVER.contains("with_protocol_versions(&[&rustls::version::TLS13])"));
    assert!(SERVER.contains("identities.len() == 1"));
    assert!(SERVER.contains("CommonName is deliberately ignored"));
    let scopes = [
        "context:mutate",
        "context:execute",
        "context:retrieve",
        "context:read",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(scopes.len(), 4);
    for scope in scopes {
        assert!(SERVER.contains(scope));
        assert!(OPENAPI.contains("mutualTls"));
    }
    assert!(BINARY.contains("AGENT_TRUST_PROFILE"));
    assert!(BINARY.contains("Uid::effective().is_root()"));
    assert!(BINARY.contains("CONTEXT_DATABASE_ROLE_UNSAFE"));
    assert!(BINARY.contains("cross_domain_table_grant"));
    assert!(BINARY.contains("unexpected_update_column"));
}

#[test]
fn migration_forces_rls_and_image_is_pinned_non_root() {
    for table in [
        "governed_memory_entries",
        "prompt_versions",
        "knowledge_snapshots",
        "context_knowledge_sources",
        "context_deletion_tombstones",
        "context_quarantine_records",
        "context_resource_versions",
        "context_action_ingress",
        "context_authority_executions",
        "context_retrieval_decisions",
        "context_evidence_outbox",
    ] {
        assert!(MIGRATION.contains(table), "migration missing {table}");
    }
    assert!(MIGRATION.contains("FORCE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("current_setting(''app.tenant_id'', true)"));
    assert!(DOCKERFILE.contains("@sha256:"));
    assert!(DOCKERFILE.contains("USER 65532:65532"));
    assert!(RUNBOOK.contains("NOT_RUN"));
}

#[test]
fn production_sources_have_no_placeholder_paths() {
    for source in [AUTHORITY, ADAPTERS, SERVER, BINARY] {
        for marker in ["todo!", "unimplemented!", "TODO", "mock production", "allow_all"] {
            assert!(!source.contains(marker), "placeholder marker {marker}");
        }
    }
}
