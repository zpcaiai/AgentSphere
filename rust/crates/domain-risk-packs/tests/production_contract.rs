use agent_trust_domain_risk_packs::{coding, energy, industrial, medical, sensitive};

#[test]
fn all_domain_manifests_are_content_addressed_and_default_deny_secrets() {
    let manifests = [
        coding::manifest(),
        industrial::manifest(),
        energy::manifest(),
        medical::manifest(),
        sensitive::manifest(),
    ];
    for manifest in manifests {
        assert!(manifest.policy_bundle_ref.starts_with("policy:sha256:"));
        assert!(manifest.evaluator_ref.starts_with("evaluator:sha256:"));
        assert!(manifest
            .artifact_refs
            .iter()
            .all(|reference| reference.starts_with("artifact:sha256:")));
        assert!(manifest.permissions.secret_scopes.is_empty());
        assert!(manifest
            .compatibility
            .contains("agenttrust.domain-execution.v1"));
    }
}

#[test]
fn physical_migrations_require_distinct_experts_and_consume_supervision() {
    let industrial = include_str!(
        "../../../../migrations/domain-packs/0036_01_19_production_industrial_pack.sql"
    );
    let energy = include_str!(
        "../../../../migrations/domain-packs/0036_01_20_production_energy_pack.sql"
    );
    for migration in [industrial, energy] {
        assert!(migration.contains("count(DISTINCT reviewer_subject)"));
        assert!(migration.contains("reviewer_subject<>supervision.supervisor_subject"));
        assert!(migration.contains("consumed_by_execution_id=NEW.execution_id"));
        assert!(migration.contains("FORCE ROW LEVEL SECURITY"));
    }
}

#[test]
fn domain_runtime_has_authoritative_wire_and_shared_evidence_bridge() {
    let server = include_str!("../server.rs");
    let authority = include_str!("../authority.rs");
    let openapi = include_str!("../../../../schemas/openapi/domain-runtime-v1.yaml");
    let dockerfile = include_str!("../../../../Dockerfile.domain-runtime");
    assert!(server.contains("/v1/authoritative/domain-runtime/executions"));
    assert!(server.contains("/v1/domain-runtime/executions"));
    assert!(authority.contains("TypedDomainEffectReceipt"));
    assert!(authority.contains("TypedDomainEvaluatorResult"));
    assert!(authority.contains("\"schema_version\":DOMAIN_STATE_SCHEMA"));
    assert!(server.contains("v1/evidence/authority-events"));
    assert!(server.contains("SignedAuthorityEvidenceReceipt"));
    assert!(!server.contains("expected_task_state_version"));
    assert!(authority.contains("evidence_requested_at"));
    assert!(openapi.contains(":8094"));
    assert!(dockerfile.contains("EXPOSE 8094 9104"));
}

#[test]
fn review_evidence_producer_is_executable_bounded_and_scope_separated() {
    let server = include_str!("../server.rs");
    let binary = include_str!("../src/bin/agenttrust-domain-runtime-authority.rs");
    let contracts = include_str!("../../contracts/src/lib.rs");
    let openapi = include_str!("../../../../schemas/openapi/domain-runtime-v1.yaml");
    let token_schema =
        include_str!("../../../../schemas/domain-packs/domain-runtime-token-bindings.schema.json");

    for source in [server, openapi, token_schema] {
        assert!(source.contains("domain-runtime:approval-review-evidence"));
    }
    for marker in [
        "/v1/domain-runtime/approval-review-evidence",
        "issue_approval_review_evidence",
        "v1/evidence/authority-events",
        "verify_for_source_kind",
        "AuthorityEvidenceSourceKind::AuthenticatedEvent",
        "read_bounded_body(response,262_144)",
        "X-AgentTrust-Authority-Event-Id",
        "X-AgentTrust-Payload-Digest",
    ] {
        assert!(server.contains(marker), "producer marker missing: {marker}");
    }
    assert!(contracts.contains("pub struct ApprovalReviewEvidenceIssueRequest"));
    assert!(contracts.contains("pub struct ApprovalReviewEvidence"));
    assert!(server.contains("issue.to_authority_event(&self.evidence_client_identity"));
    assert!(binary.contains("router(authority.clone(),tokens,runtime)"));
    assert!(!server.contains("SigningKey"));
}

#[test]
fn domain_management_routes_match_production_probes() {
    let server = include_str!("../server.rs");
    let stack = include_str!("../../../../deploy/kubernetes/production-stack.yaml.tmpl");
    assert!(server.contains("route(\"/live\",get(management_live))"));
    assert!(server.contains("route(\"/ready\",get(management_ready))"));
    assert!(server.contains("\"schema_version\":DOMAIN_READINESS_SCHEMA,\"live\":true"));
    assert!(stack.contains(
        "livenessProbe: {httpGet: {path: /live, port: management}"
    ));
    assert!(stack.contains(
        "readinessProbe: {httpGet: {path: /ready, port: management}"
    ));
}
