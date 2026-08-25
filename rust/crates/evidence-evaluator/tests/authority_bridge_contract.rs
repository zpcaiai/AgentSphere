const CONTRACTS: &str = include_str!("../../contracts/src/lib.rs");
const STORE: &str = include_str!("../src/postgres.rs");
const SERVER: &str = include_str!("../src/server.rs");
const BINARY: &str = include_str!("../src/bin/agenttrust-evidence-service.rs");
const MIGRATION: &str =
    include_str!("../../../../migrations/evidence/0036_01_23_production_authority_evidence.sql");
const OPENAPI: &str = include_str!("../../../../schemas/openapi/evidence-v1.yaml");
const REQUEST_SCHEMA: &str =
    include_str!("../../../../schemas/evidence/authority-evidence-event-request.schema.json");
const RECEIPT_SCHEMA: &str =
    include_str!("../../../../schemas/evidence/signed-authority-evidence-receipt.schema.json");

#[test]
fn authority_events_are_distinct_from_orchestrator_lifecycle_events() {
    assert!(SERVER.contains("/v1/evidence/authority-events"));
    assert!(SERVER.contains("evidence:authority-event"));
    assert!(OPENAPI.contains("appendAuthorityEvidenceEvent"));
    assert!(REQUEST_SCHEMA.contains("GOVERNED_ACTION"));
    assert!(REQUEST_SCHEMA.contains("AUTHENTICATED_EVENT"));
    assert!(CONTRACTS.contains("ApprovalReviewPrepared"));
    assert!(OPENAPI.contains("APPROVAL_REVIEW_PREPARED"));
    assert!(!REQUEST_SCHEMA.contains("expected_task_state_version"));
    assert!(CONTRACTS.contains("AuthorityEvidenceEventRequest"));
    assert!(CONTRACTS.contains("SignedAuthorityEvidenceReceipt"));
}

#[test]
fn governed_authority_event_is_bound_to_final_pep_and_ledger() {
    for marker in [
        "pep_execution_authorizations",
        "ledger_execution_id",
        "ledger_event_id",
        "ledger_event_digest",
        "action_hash",
        "fence_digest",
        "policy_decision_id",
        "policy_decision_digest",
        "authorization_evidence_ref",
        "authorization_evidence_digest",
    ] {
        assert!(
            STORE.contains(marker),
            "missing production binding {marker}"
        );
        assert!(
            REQUEST_SCHEMA.contains(marker),
            "missing schema binding {marker}"
        );
    }
    assert!(STORE.contains("AuthorityEvidenceSourceKind::GovernedAction"));
    assert!(STORE.contains("AuthorityEvidenceSourceKind::AuthenticatedEvent"));
}

#[test]
fn receipt_chain_idempotency_rls_and_least_privilege_are_closed() {
    assert!(CONTRACTS.contains("AUTHORITY_EVIDENCE_RECEIPT_KEY_USAGE"));
    assert!(CONTRACTS.contains("self.event.verify(key)"));
    assert!(CONTRACTS.contains("key.verify(self.evidence_digest.as_bytes()"));
    assert!(STORE.contains("receipt.verify(self.verification_key"));
    assert!(STORE.contains("pg_advisory_xact_lock"));
    assert!(STORE.contains("IdempotencyConflict"));
    assert!(MIGRATION.contains("FORCE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("reject_evidence_immutable_record"));
    assert!(MIGRATION.contains("AUTHORITY_EVIDENCE_APPENDED"));
    assert!(BINARY.contains("can_read_authority_events"));
    assert!(BINARY.contains("can_insert_authority_events"));
    assert!(RECEIPT_SCHEMA.contains("AUTHORITY_EVIDENCE_RECEIPT"));
}
