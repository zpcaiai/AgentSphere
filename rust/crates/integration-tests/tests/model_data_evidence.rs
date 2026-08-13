use agent_trust_contracts::{DataClassification, PolicyVersion, TaskId, TenantId};
use agent_trust_data_governance::{DataPolicyPortImpl, DeploymentMode, DeploymentPolicy};
use agent_trust_evidence_evaluator::{
    ArtifactStore, AuditSink, EvidenceBuilder, EvidenceChainVerifier, EvidenceEventDraft,
    EvidenceEventType, InMemoryArtifactStore, InMemoryAuditChain,
};
use agent_trust_model_gateway::{
    BudgetManager, DeploymentKind, DeterministicRoutePlanner, MODEL_SCHEMA_VERSION,
    ModelCapability, ModelError, ModelGateway, ModelProviderAdapter, ModelRequestEnvelope,
    ProviderProfile, ProviderRegistry, ProviderRequest, ProviderResponse,
};
use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

struct LocalAdapter {
    key: String,
}
#[async_trait]
impl ModelProviderAdapter for LocalAdapter {
    fn provider_key(&self) -> &str {
        &self.key
    }
    async fn generate(&self, _: ProviderRequest) -> Result<ProviderResponse, ModelError> {
        Ok(ProviderResponse {
            provider_request_id: "local-request-1".into(),
            output: b"bounded local result".to_vec(),
            input_tokens: 3,
            output_tokens: 3,
            finish_reason: "stop".into(),
        })
    }
}

#[tokio::test]
async fn restricted_model_output_becomes_offline_verifiable_evidence() {
    let tenant = TenantId::new();
    let task = TaskId::new();
    let data_policy = Arc::new(
        DataPolicyPortImpl::new(PolicyVersion("data-policy-v1".into()))
            .unwrap_or_else(|_| panic!("data policy")),
    );
    data_policy
        .deployments()
        .register(DeploymentPolicy {
            profile_id: "private".into(),
            mode: DeploymentMode::OnPrem,
            allowed_external_endpoints: BTreeSet::new(),
            telemetry_export: false,
            update_channel: "offline-bundle".into(),
            maximum_classification: DataClassification::Regulated,
        })
        .unwrap_or_else(|_| panic!("deployment"));

    let registry = Arc::new(ProviderRegistry::default());
    let provider = ProviderProfile {
        schema_version: MODEL_SCHEMA_VERSION.into(),
        provider_id: "local".into(),
        model_id: "approved-model".into(),
        model_version: "1".into(),
        region: "cn".into(),
        jurisdiction: "CN".into(),
        deployment: DeploymentKind::Local,
        capabilities: BTreeSet::from([ModelCapability::Generate]),
        endpoint_digest: format!("sha256:{}", "a".repeat(64)),
        data_terms_version: "1".into(),
        approved_tenants: BTreeSet::from([tenant.clone()]),
        approved: true,
        revoked: false,
        maximum_context_bytes: 4096,
        maximum_output_bytes: 4096,
        cost_microunits_per_token: 2,
    };
    registry
        .approve(provider.clone())
        .unwrap_or_else(|_| panic!("provider"));
    let budget = Arc::new(BudgetManager::default());
    budget.set_limit(tenant.clone(), 1_000_000);
    let gateway = ModelGateway::new(
        data_policy,
        registry,
        Arc::new(DeterministicRoutePlanner),
        budget,
        vec![Arc::new(LocalAdapter {
            key: provider.key(),
        })],
    )
    .unwrap_or_else(|_| panic!("gateway"));
    let result = gateway
        .generate(ModelRequestEnvelope {
            schema_version: MODEL_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            task_type: "evidence-test".into(),
            classification: DataClassification::Restricted,
            source_jurisdiction: "CN".into(),
            deployment_profile: "private".into(),
            required_capabilities: BTreeSet::from([ModelCapability::Generate]),
            allowed_provider_ids: BTreeSet::from(["local".into()]),
            maximum_latency_ms: 1000,
            maximum_cost_microunits: 1000,
            maximum_output_bytes: 1024,
            prompt: b"safe internal input".to_vec(),
            idempotency_key: "model-data-evidence-1".into(),
        })
        .await
        .unwrap_or_else(|_| panic!("model call"));

    let artifact_store = InMemoryArtifactStore::new(4096, 8);
    let artifact = artifact_store
        .put(
            result.output,
            "text/plain".into(),
            "RESTRICTED".into(),
            3600,
            "task-owner".into(),
        )
        .await
        .unwrap_or_else(|_| panic!("artifact"));
    let audit = Arc::new(
        InMemoryAuditChain::new("audit-key".into(), SigningKey::from_bytes(&[81u8; 32]), 16)
            .unwrap_or_else(|_| panic!("audit")),
    );
    audit
        .append(EvidenceEventDraft {
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            event_type: EvidenceEventType::ToolExecuted,
            actor_subject: "model-gateway".into(),
            source_service: "model-gateway".into(),
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            payload_hash: result.evidence.output_hash,
            safe_summary: "local model output stored".into(),
            artifact_refs: vec![artifact.artifact_ref.clone()],
            occurred_at: Utc::now(),
        })
        .await
        .unwrap_or_else(|_| panic!("event"));
    let package = EvidenceBuilder::new(audit.clone())
        .build(tenant, task, vec![artifact])
        .await
        .unwrap_or_else(|_| panic!("package"));
    let report = EvidenceChainVerifier::new(BTreeMap::from([(
        "audit-key".into(),
        audit.verifying_key(),
    )]))
    .verify(&package);
    assert!(report.valid);
    assert_eq!(report.verified_events, 1);
    assert_eq!(report.verified_artifacts, 1);
}
