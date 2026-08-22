#[test]
fn production_assets_keep_authority_fail_closed() {
    let migration = include_str!(
        "../../../../migrations/pack-supply-chain/0036_01_16_production_pack_supply_chain.sql"
    );
    let openapi = include_str!("../../../../schemas/openapi/pack-supply-chain-v1.yaml");
    let dockerfile = include_str!("../../../../Dockerfile.pack-supply-chain");

    assert!(migration.contains("FORCE ROW LEVEL SECURITY"));
    assert!(migration.contains("SUPPLY_CHAIN_RELEASE_TRANSITION_INVALID"));
    assert!(migration.contains("supply_single_pack_flight_idx"));
    assert!(migration.contains("delivery_evidence_ref"));
    assert!(openapi.contains(":8093"));
    assert!(openapi.contains("/v1/authoritative/supply-chain/releases"));
    assert!(openapi.contains("X-AgentTrust-Fence-Digest"));
    assert!(dockerfile.contains("USER 65532:65532"));
    assert!(dockerfile.contains("EXPOSE 8093 9103"));

    let server = include_str!("../src/server.rs");
    let authority = include_str!("../src/production.rs");
    assert!(server.contains("v1/evidence/authority-events"));
    assert!(server.contains("SignedAuthorityEvidenceReceipt"));
    assert!(!server.contains("expected_task_state_version"));
    assert!(authority.contains("evidence_requested_at"));
    assert!(authority.contains("installation_receipt_digest"));
    assert!(authority.contains("reconciliation_receipt_digest"));
    assert!(authority.contains("\"schema_version\":SUPPLY_RELEASES_SCHEMA"));
}
