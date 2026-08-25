//! Domain risk packs built on the shared Batch 20 SDK.

pub mod authority;
pub mod coding;
pub mod energy;
pub mod industrial;
pub mod medical;
pub mod production;
pub mod sensitive;
pub mod server;

use agent_trust_contracts::EffectClass;
use agent_trust_pack_supply_chain::{
    DomainPackManifest, PACK_SCHEMA_VERSION, PackPermissionDeclaration, PackToolDefinition,
    SignatureEnvelope,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const DOMAIN_PACKS_SCHEMA_VERSION: &str = "agenttrust.domain-risk-packs.v1";

pub fn unsigned_pack_manifest(
    pack_id: &str,
    description: &str,
    tools: Vec<PackToolDefinition>,
    data_classes: BTreeSet<String>,
    threat_scenarios: BTreeSet<String>,
) -> DomainPackManifest {
    let tool_ids = tools.iter().map(|tool| tool.tool_id.clone()).collect();
    let compensation_refs = tools
        .iter()
        .filter_map(|tool| tool.compensation_ref.clone())
        .collect();
    DomainPackManifest {
        schema_version: PACK_SCHEMA_VERSION.into(),
        pack_id: pack_id.into(),
        version: "1.0.0".into(),
        digest: String::new(),
        publisher_identity: "publisher:agent-trust-platform".into(),
        description: description.into(),
        permissions: PackPermissionDeclaration {
            tools: tool_ids,
            network_destinations: BTreeSet::new(),
            data_classes,
            secret_scopes: BTreeSet::new(),
            executors: BTreeSet::from([format!("{pack_id}-executor-v1")]),
            approval_scopes: tools
                .iter()
                .filter(|tool| tool.approval_required)
                .map(|tool| tool.tool_id.clone())
                .collect(),
        },
        tools,
        policy_bundle_ref: immutable_ref("policy", pack_id, "v1"),
        evaluator_ref: immutable_ref("evaluator", pack_id, "v1"),
        compensation_refs,
        threat_scenario_refs: threat_scenarios,
        artifact_refs: BTreeSet::from([immutable_ref("artifact", pack_id, "v1")]),
        compatibility: BTreeSet::from([
            "agenttrust.contracts.v1".into(),
            "agenttrust.domain-execution.v1".into(),
        ]),
        signature: SignatureEnvelope {
            key_id: String::new(),
            publisher_identity: String::new(),
            subject_digest: String::new(),
            signature: String::new(),
            signed_at: Utc::now(),
        },
    }
}

fn immutable_ref(kind: &str, pack_id: &str, component: &str) -> String {
    let digest = Sha256::digest(format!("agenttrust:{kind}:{pack_id}:{component}").as_bytes());
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{kind}:sha256:{encoded}")
}

pub fn tool(
    tool_id: &str,
    effect_class: EffectClass,
    approval_required: bool,
    compensation_ref: Option<&str>,
    irreversible_reason: Option<&str>,
    executor: &str,
) -> PackToolDefinition {
    PackToolDefinition {
        tool_id: tool_id.into(),
        effect_class,
        approval_required,
        compensation_ref: compensation_ref.map(str::to_string),
        irreversible_reason: irreversible_reason.map(str::to_string),
        executor_template: executor.into(),
    }
}
