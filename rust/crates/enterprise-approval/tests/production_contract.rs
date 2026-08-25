use agent_trust_enterprise_approval::{
    APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION, APPROVAL_GRANT_REQUEST_SCHEMA_VERSION,
    ApprovalConsumptionRequest, SignedApprovalPrincipalAssertion,
    approval_principal_request_digest,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

fn must<T, E: std::fmt::Debug>(value: Result<T, E>, context: &str) -> T {
    match value {
        Ok(result) => result,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

fn must_str<'a>(value: &'a serde_json::Value, context: &str) -> &'a str {
    match value.as_str() {
        Some(result) => result,
        None => panic!("{context}: expected JSON string"),
    }
}

const MIGRATION: &str =
    include_str!("../../../../migrations/enterprise-approval/0036_01_02_production_approval.sql");
const REVIEW_EVIDENCE_MIGRATION: &str = include_str!(
    "../../../../migrations/enterprise-approval/0036_01_25_approval_review_evidence_v2.sql"
);
const DECISION_EVIDENCE_MIGRATION: &str = include_str!(
    "../../../../migrations/enterprise-approval/0036_01_26_approval_decision_evidence.sql"
);
const OPENAPI: &str = include_str!("../../../../schemas/openapi/approval-v1.yaml");
const DECISION_EVIDENCE_SCHEMA: &str =
    include_str!("../../../../schemas/approval/decision-evidence.schema.json");
const DECISION_RESULT_SCHEMA: &str =
    include_str!("../../../../schemas/approval/decision-result.schema.json");
const DECISION_KEYRING_SCHEMA: &str =
    include_str!("../../../../schemas/approval/decision-evidence-keyring.schema.json");
const DECISION_REQUEST_BINDING_SCHEMA: &str =
    include_str!("../../../../schemas/approval/decision-request-binding.schema.json");
const TOKEN_BINDINGS_SCHEMA: &str =
    include_str!("../../../../schemas/approval/token-bindings.schema.json");
const PRINCIPAL_ASSERTION_SCHEMA: &str =
    include_str!("../../../../schemas/approval/principal-assertion.schema.json");
const PRINCIPAL_KEYRING_SCHEMA: &str =
    include_str!("../../../../schemas/approval/principal-keyring.schema.json");
const PRINCIPAL_GOLDEN_VECTOR: &str =
    include_str!("../../../../schemas/approval/principal-assertion.golden.json");
const REVIEW_EVIDENCE_KEYRING_SCHEMA: &str =
    include_str!("../../../../schemas/approval/review-evidence-keyring.schema.json");
const EXECUTION_CLIENT: &str = include_str!("../../production-runtime/src/execution.rs");
const APPROVAL_SERVER: &str = include_str!("../src/server.rs");
const APPROVAL_STORE: &str = include_str!("../src/postgres.rs");
const APPROVAL_PRINCIPAL_SOURCE: &str = include_str!("../src/principal.rs");
const APPROVAL_REVIEW_EVIDENCE_SOURCE: &str = include_str!("../src/review_evidence.rs");
const APPROVAL_EVIDENCE_DELIVERY_SOURCE: &str = include_str!("../src/evidence_delivery.rs");
const APPROVAL_BINARY: &str = include_str!("../src/bin/agenttrust-approval-service.rs");

#[test]
fn consume_request_rejects_wire_extensions() {
    let value = json!({
        "schema_version": APPROVAL_GRANT_REQUEST_SCHEMA_VERSION,
        "tenant_id": "01900000-0000-7000-8000-000000000001",
        "task_id": "01900000-0000-7000-8000-000000000002",
        "step_id": "01900000-0000-7000-8000-000000000003",
        "action_hash": "a".repeat(64),
        "plan_hash": "b".repeat(64),
        "parameter_hash": "c".repeat(64),
        "resource": "urn:agenttrust:resource:one",
        "resource_version": "version-1",
        "policy_version": "policy-1",
        "environment": "production",
        "maximum_risk": "HIGH",
        "untrusted_extension": true
    });
    assert!(serde_json::from_value::<ApprovalConsumptionRequest>(value).is_err());
}

#[test]
fn execution_client_and_service_share_the_consume_wire_versions() {
    assert!(EXECUTION_CLIENT.contains("agenttrust.approval-grant-request.v1"));
    assert!(EXECUTION_CLIENT.contains("agenttrust.approval-grant-receipt.v1"));
    assert_eq!(
        APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION,
        "agenttrust.approval-grant-receipt.v1"
    );
    for field in [
        "tenant_id",
        "task_id",
        "step_id",
        "action_hash",
        "plan_hash",
        "parameter_hash",
        "resource_version",
        "policy_version",
        "environment",
        "maximum_risk",
    ] {
        assert!(OPENAPI.contains(field));
        let field_declaration = format!("pub {field}:");
        assert!(EXECUTION_CLIENT.contains(field_declaration.as_str()));
    }
}

#[test]
fn migration_closes_replay_and_tenant_boundaries() {
    for invariant in [
        "FORCE ROW LEVEL SECURITY",
        "approval_mutation_receipts",
        "approval_principal_assertion_uses",
        "UNIQUE (tenant_id, idempotency_key)",
        "UNIQUE (tenant_id, grant_id)",
        "approval_grants_binding_unique",
        "remaining_uses IN (0,1)",
        "reject_immutable_approval_mutation",
        "TO PUBLIC",
        "assertion_request_digest",
        "signed_assertion jsonb NOT NULL",
        "approval_decisions_assertion_use_fk",
        "enforce_approval_case_immutable_binding",
        "enforce_approval_grant_immutable_binding",
        "approval_notifications_immutable_payload",
    ] {
        assert!(MIGRATION.contains(invariant), "missing {invariant}");
    }
}

#[test]
fn openapi_documents_atomic_signed_consumption() {
    for invariant in [
        "/v1/approvals/grants/consume:",
        "additionalProperties: false",
        "remaining_uses: { type: integer, const: 0 }",
        "agenttrust.approval-consumption.v1",
        "type: mutualTLS",
        "Idempotency-Key",
        "x-agenttrust-principal-assertion",
        "/ready:",
        "opaque-service-token",
    ] {
        assert!(OPENAPI.contains(invariant), "missing {invariant}");
    }
}

#[test]
fn token_binding_contract_has_no_production_bypass() {
    for invariant in [
        "agenttrust.approval-token-bindings.v1",
        "^(DNS|URI):.+$",
        "approvals:consume",
        "approvals:verify",
        "^[0-9a-f]{64}$",
        "\"additionalProperties\": false",
    ] {
        assert!(
            TOKEN_BINDINGS_SCHEMA.contains(invariant),
            "missing {invariant}"
        );
    }
    for forbidden in ["\"roles\"", "\"owned_resources\"", "\"strong_auth\""] {
        assert!(
            !TOKEN_BINDINGS_SCHEMA.contains(forbidden),
            "service token must not carry human attribute {forbidden}"
        );
    }
}

#[test]
fn human_mutations_require_independently_signed_request_bound_principals() {
    assert_eq!(
        OPENAPI
            .matches("$ref: '#/components/parameters/PrincipalAssertion'")
            .count(),
        4,
        "exactly four human mutation operations require the assertion header"
    );
    assert_eq!(
        APPROVAL_SERVER.matches("required_human_principal").count(),
        5,
        "four handler calls plus the verifier definition are required"
    );
    for invariant in [
        "agenttrust.signed-approval-principal-assertion.v1",
        "request_digest",
        "client_identity",
        "strong_auth",
        "approvals:decide",
        "additionalProperties",
    ] {
        assert!(
            PRINCIPAL_ASSERTION_SCHEMA.contains(invariant),
            "missing assertion invariant {invariant}"
        );
    }
    for invariant in [
        "agenttrust.approval-principal-keyring.v1",
        "Ed25519",
        "APPROVAL_PRINCIPAL_ASSERTION",
        "tenant_ids",
        "not_before",
        "expires_at",
    ] {
        assert!(
            PRINCIPAL_KEYRING_SCHEMA.contains(invariant),
            "missing keyring invariant {invariant}"
        );
    }
    for invariant in [
        "required_human_principal(",
        "verify_encoded(",
        "to_header_value",
        "agenttrust.approval-principal-request-binding.v1",
        "x-agenttrust-principal-assertion",
    ] {
        assert!(
            APPROVAL_SERVER.contains(invariant) || APPROVAL_PRINCIPAL_SOURCE.contains(invariant),
            "missing server gate {invariant}"
        );
    }
    for invariant in [
        "AGENT_TRUST_APPROVAL_PRINCIPAL_KEYS_FILE",
        "AGENT_TRUST_APPROVAL_PRINCIPAL_AUDIENCE",
        "AGENT_TRUST_APPROVAL_DATABASE_PASSWORD_FILE",
    ] {
        assert!(
            APPROVAL_BINARY.contains(invariant),
            "missing config gate {invariant}"
        );
    }
}

#[test]
fn final_pep_fetches_only_by_the_exact_opaque_reference() {
    for invariant in [
        "/v1/approvals/consumptions/{consumption_ref}:",
        "name: consumption_ref",
        "approvals:verify",
    ] {
        assert!(OPENAPI.contains(invariant), "missing {invariant}");
    }
    for invariant in [
        "UNIQUE (tenant_id, consumption_ref)",
        "consumption_ref LIKE 'urn:agenttrust:approval-consumption:%'",
    ] {
        assert!(MIGRATION.contains(invariant), "missing {invariant}");
    }
}

#[test]
fn authoritative_approval_inbox_is_bounded_tenant_safe_and_cursor_signed() {
    for invariant in [
        "/v1/authoritative/approvals:",
        "x-required-service-scope: approvals:read",
        "agenttrust.authoritative-approval-page.v1",
        "agenttrust.approval-case-view.v1",
        "maximum: 100",
        "data_digest",
        "safe_summary",
        "evidence_refs",
        "next_cursor",
        "coding_details",
        "industrial_details",
        "signed-authority-evidence-receipt.schema.json",
        "APPROVAL_REVIEW_PREPARED",
    ] {
        assert!(OPENAPI.contains(invariant), "missing {invariant}");
    }
    for invariant in [
        "list_authoritative_cases(",
        "MAX_AUTHORITATIVE_PAGE_SIZE",
        "sign_authoritative_cursor",
        "decode_authoritative_cursor(",
        "Review governed coding action",
        "Review supervised industrial action",
        "verify_historical_request(&request, created_at)",
        ".evidence_refs()",
        "canonical_digest(&material)",
    ] {
        assert!(APPROVAL_STORE.contains(invariant), "missing {invariant}");
    }
    assert!(
        MIGRATION.contains("approval_cases_authoritative_page_idx"),
        "authoritative cursor query requires its tenant/order index"
    );
}

#[test]
fn authoritative_review_facts_are_signed_exact_and_migrated_atomically() {
    for invariant in [
        "agenttrust.approval-review-evidence-keyring.v2",
        "AUTHORITY_EVIDENCE_RECEIPT",
        "additionalProperties",
        "tenant_ids",
        "source_services",
        "not_before",
        "expires_at",
    ] {
        assert!(
            REVIEW_EVIDENCE_KEYRING_SCHEMA.contains(invariant),
            "missing review evidence keyring invariant {invariant}"
        );
    }
    for invariant in [
        "#[serde(deny_unknown_fields)]",
        "verify_request(",
        "verify_historical_request(",
        "review_material_digest",
        "risk_package_ref",
        "state_snapshot_ref",
        "SignedAuthorityEvidenceReceipt",
        "AuthorityEvidenceEventRequest",
        "to_authority_event",
    ] {
        assert!(
            APPROVAL_REVIEW_EVIDENCE_SOURCE.contains(invariant),
            "missing signed review invariant {invariant}"
        );
    }
    for invariant in [
        "APPROVAL_V2_LEGACY_MUTABLE_STATE_MUST_BE_DRAINED",
        "agenttrust.signed-authority-evidence-receipt.v1",
        "APPROVAL_REVIEW_PREPARED",
        "review_context",
        "review_evidence",
    ] {
        assert!(
            REVIEW_EVIDENCE_MIGRATION.contains(invariant),
            "missing atomic v2 migration invariant {invariant}"
        );
    }
    for invariant in ["AGENT_TRUST_APPROVAL_REVIEW_EVIDENCE_KEYRING_FILE"] {
        assert!(
            APPROVAL_BINARY.contains(invariant),
            "missing review evidence startup gate {invariant}"
        );
    }
    assert!(
        APPROVAL_STORE.contains("review_evidence_covers"),
        "readiness must require active review-evidence key coverage"
    );
}

#[test]
fn approval_decisions_commit_an_immutable_signed_receipt_and_outbox_atomically() {
    assert_eq!(OPENAPI.matches("x-agenttrust-max-utf8-bytes: 4096").count(), 4);
    assert!(DECISION_REQUEST_BINDING_SCHEMA.contains(
        "\"x-agenttrust-max-utf8-bytes\": 4096"
    ));
    assert!(APPROVAL_STORE.contains("!valid_approval_human_text(&envelope.reason)"));
    for invariant in [
        "agenttrust.approval-decision-result.v1",
        "agenttrust.approval-decision-evidence.v1",
        "principal_assertion_request_digest",
        "approval_case_digest",
        "authority_request_digest",
        "evidence_outbox_ref",
        "APPROVAL_DECISION_EVIDENCE",
    ] {
        assert!(OPENAPI.contains(invariant), "missing OpenAPI {invariant}");
        assert!(
            DECISION_EVIDENCE_SCHEMA.contains(invariant)
                || DECISION_RESULT_SCHEMA.contains(invariant),
            "missing JSON Schema {invariant}"
        );
    }
    assert!(OPENAPI.contains("$ref: '#/components/schemas/ApprovalDecisionResult'"));
    assert!(DECISION_EVIDENCE_SCHEMA.contains(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ));
    assert!(!DECISION_EVIDENCE_SCHEMA.contains("[1-5][0-9a-f]{3}"));

    for invariant in [
        "approval_decision_evidence_receipts",
        "approval_decision_evidence_outbox",
        "CREATE CONSTRAINT TRIGGER approval_decision_requires_evidence",
        "DEFERRABLE INITIALLY DEFERRED",
        "FORCE ROW LEVEL SECURITY",
        "lease_owner",
        "signed_authority_receipt ?& ARRAY[",
        "signed_authority_receipt - ARRAY[",
        "IS DISTINCT FROM",
    ] {
        assert!(
            DECISION_EVIDENCE_MIGRATION.contains(invariant),
            "missing decision migration invariant {invariant}"
        );
    }
    assert!(!DECISION_EVIDENCE_MIGRATION.contains("jsonb_object_length"));
    assert!(APPROVAL_STORE.contains("FOR UPDATE SKIP LOCKED"));
    assert!(APPROVAL_STORE.contains(".bind(&receipt.decision_digest)"));
}

#[test]
fn decision_receipt_rotation_and_delivery_are_real_fail_closed_runtime_paths() {
    for invariant in [
        "agenttrust.approval-decision-evidence-keyring.v1",
        "ACTIVE",
        "VERIFY_ONLY",
        "Ed25519",
        "half-open interval [not_before, expires_at)",
    ] {
        assert!(
            DECISION_KEYRING_SCHEMA.contains(invariant),
            "missing decision keyring invariant {invariant}"
        );
    }
    for variable in [
        "AGENT_TRUST_APPROVAL_DECISION_EVIDENCE_KEYRING_FILE",
        "AGENT_TRUST_APPROVAL_EVIDENCE_RECEIPT_KEYRING_FILE",
        "AGENT_TRUST_APPROVAL_EVIDENCE_SOURCE_IDENTITY",
        "AGENT_TRUST_APPROVAL_EVIDENCE_ENDPOINT",
        "AGENT_TRUST_APPROVAL_EVIDENCE_TOKEN_FILE",
        "AGENT_TRUST_APPROVAL_EVIDENCE_CA_FILE",
        "AGENT_TRUST_APPROVAL_EVIDENCE_CLIENT_CERTIFICATE_FILE",
        "AGENT_TRUST_APPROVAL_EVIDENCE_CLIENT_PRIVATE_KEY_FILE",
        "AGENT_TRUST_APPROVAL_EVIDENCE_READINESS_SCHEMA",
    ] {
        assert!(APPROVAL_BINARY.contains(variable), "missing startup {variable}");
    }
    assert!(APPROVAL_BINARY.contains(
        "ApprovalApiState::production(store.clone(), authorizer, principal_keyring)"
    ));
    assert!(!APPROVAL_BINARY.contains(
        "decision_evidence_outbox_ready(&delivery_tenants"
    ));
    assert!(APPROVAL_BINARY.contains("validate_certificate_identity_file("));
    for invariant in [
        "delivery_evidence_keyring",
        "covers_source_tenant_at",
        "verify_authority_delivery",
        "claim_decision_evidence(tenant, worker_id, 1",
        "start_index = (start_index + 1) % tenants.len()",
        "OUTCOME_UNKNOWN",
        "decision_evidence_outbox_ready",
        "last_error_code IN ('CONFIGURATION_INVALID','RECEIPT_INVALID')",
        "agenttrust.approval-evidence-delivery-alert.v1",
        "MARK_DELIVERED_FAILED",
        "RELEASE_RETRY_FAILED",
        "BATCH_FAILED",
    ] {
        assert!(
            APPROVAL_STORE.contains(invariant)
                || APPROVAL_REVIEW_EVIDENCE_SOURCE.contains(invariant)
                || APPROVAL_EVIDENCE_DELIVERY_SOURCE.contains(invariant),
            "missing delivery invariant {invariant}"
        );
    }
    assert!(!APPROVAL_STORE.contains(".await\n                .unwrap_or(0)"));
    for invariant in [
        ".min_tls_version(reqwest::tls::Version::TLS_1_3)",
        ".tls_built_in_root_certs(false)",
        ".redirect(Policy::none())",
        "x-agenttrust-authority-event-id",
        "x-agenttrust-payload-digest",
        "database_ready",
        "worm_ready",
        "canonical_ed25519_signature",
    ] {
        assert!(
            APPROVAL_EVIDENCE_DELIVERY_SOURCE.contains(invariant),
            "missing publisher invariant {invariant}"
        );
    }
    for column in [
        "delivery_attempts",
        "next_attempt_at",
        "lease_owner",
        "lease_expires_at",
        "last_attempt_at",
        "last_error_code",
        "signed_authority_receipt",
        "delivered_at",
    ] {
        let privilege = format!(
            "has_column_privilege(current_user,'public.approval_decision_evidence_outbox','{column}','UPDATE')"
        );
        assert!(
            APPROVAL_BINARY.contains(&privilege),
            "startup misses mutable delivery column {column}"
        );
    }
}

#[test]
fn principal_assertion_golden_vector_is_cross_language_stable() {
    let vector: serde_json::Value = must(
        serde_json::from_str(PRINCIPAL_GOLDEN_VECTOR),
        "golden vector must parse",
    );
    let request = &vector["request"];
    let digest = must(
        approval_principal_request_digest(
            must_str(&request["method"], "request method"),
            must_str(&request["path"], "request path"),
            must_str(&request["tenant_id"], "request tenant"),
            must_str(&request["client_identity"], "request client identity"),
            must_str(&request["service_subject"], "request service subject"),
            must_str(&request["scope"], "request scope"),
            must_str(&request["idempotency_key"], "request idempotency key"),
            &request["body"],
        ),
        "principal request digest must be computable",
    );
    assert_eq!(
        digest,
        must_str(&vector["request_digest"], "request digest")
    );

    let assertion: SignedApprovalPrincipalAssertion = must(
        serde_json::from_value(vector["signed_assertion"].clone()),
        "signed assertion must parse",
    );
    assert_eq!(
        must(
            String::from_utf8(must(assertion.signing_bytes(), "signing bytes")),
            "signing bytes must be UTF-8",
        ),
        must_str(&vector["assertion_signing_jcs"], "assertion signing JCS")
    );
    assert_eq!(
        must(assertion.to_header_value(), "assertion header must encode"),
        must_str(&vector["header_value_base64url"], "assertion header")
    );

    let seed = must(
        URL_SAFE_NO_PAD.decode(must_str(
            &vector["private_seed_base64url_test_only"],
            "test seed",
        )),
        "test seed must decode",
    );
    let seed_bytes: [u8; 32] = must(seed.try_into(), "test seed must contain 32 bytes");
    let signing = SigningKey::from_bytes(&seed_bytes);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
        must_str(&vector["public_key_base64url"], "public key")
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(
            signing
                .sign(&must(assertion.signing_bytes(), "signing bytes"))
                .to_bytes(),
        ),
        must_str(&vector["signature_base64url"], "signature")
    );
    let canonical = must(serde_jcs::to_vec(&assertion), "assertion must canonicalize");
    assert_eq!(
        hex::encode(Sha256::digest(canonical)),
        must_str(&vector["assertion_digest"], "assertion digest")
    );
}
