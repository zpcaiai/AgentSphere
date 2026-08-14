use agent_trust_action_ir::{
    ActionDraft, NormalizationContext, RegistryPolicySnapshot, RuntimeContext,
    TrajectoryRiskSnapshot, TypedPayload, hash, normalize, to_policy_input,
};
use agent_trust_contracts::*;
use agent_trust_identity::{
    CredentialRequest, CredentialService, IDENTITY_SCHEMA_VERSION, RevocationService,
};
use agent_trust_policy_pep::{
    EnforcementOutcome, EnforcementRequest, EnforcementStage, MinimalApprovalKernel,
    POLICY_SCHEMA_VERSION, PolicyDecisionPointPort, PolicyEnforcementPoint, PolicyError,
    policy_input_hash,
};
use agent_trust_registry::*;
use agent_trust_tool_proxy::*;
use agent_trust_transaction_ledger::*;
use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use parking_lot::RwLock;
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;

struct AllowPdp;
#[async_trait]
impl PolicyDecisionPointPort for AllowPdp {
    async fn evaluate(
        &self,
        input: &agent_trust_action_ir::PolicyInput,
        _: EnforcementStage,
    ) -> Result<PolicyDecision, PolicyError> {
        Ok(PolicyDecision {
            schema_version: SchemaVersion(POLICY_SCHEMA_VERSION.into()),
            decision_id: "industrial-allow".into(),
            decision: Decision::Allow,
            reason_codes: vec!["SIMULATOR_RANGE_AND_INTERLOCK_PASS".into()],
            policy_version: PolicyVersion("industrial-p1".into()),
            policy_bundle_hash: "e".repeat(64),
            input_hash: policy_input_hash(input)?,
            evaluated_at: Utc::now() - chrono::Duration::seconds(1),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            obligations: vec![
                Obligation::RequireFreshResourceState,
                Obligation::RequireResourceVersion,
                Obligation::MaxExecutionTime { milliseconds: 3000 },
            ],
            risk_summary: RiskLevel::High,
        })
    }
}

#[derive(Default)]
struct Simulator {
    writes: RwLock<u32>,
}
#[async_trait]
impl IndustrialBackend for Simulator {
    async fn compare_and_set(
        &self,
        _: &str,
        write: IndustrialWrite,
        _: &[u8],
    ) -> Result<Value, ProxyError> {
        if write.expected_current_value.as_i64() != Some(70) || write.resource_version != "v1" {
            return Err(ProxyError::ConnectorFailed);
        }
        *self.writes.write() += 1;
        Ok(serde_json::json!({"verified_value":write.value,"resource_version":"v2"}))
    }
}

#[derive(Default)]
struct Audit {
    events: RwLock<Vec<ProxyAuditEvent>>,
}
#[async_trait]
impl ProxyAuditSink for Audit {
    async fn record(&self, event: ProxyAuditEvent) -> Result<(), ProxyError> {
        self.events.write().push(event);
        Ok(())
    }
}

fn install_tool(registry: &InMemoryToolRegistry, tenant: &TenantId) -> ToolRef {
    let signer = SigningKey::from_bytes(&[21u8; 32]);
    registry.add_publisher_key("publisher", signer.verifying_key());
    let tool_ref = ToolRef {
        tool_id: ToolId("industrial.commit-setpoint".into()),
        tool_version: ToolVersion("1.0.0".into()),
    };
    let manifest = ToolManifest {
        schema_version: REGISTRY_SCHEMA_VERSION.into(),
        tool_id: tool_ref.tool_id.clone(),
        tool_version: tool_ref.tool_version.clone(),
        status: ToolVersionStatus::Draft,
        domain: "industrial".into(),
        display_name: "Commit setpoint".into(),
        description: "Simulator CAS".into(),
        input_schema: serde_json::json!({"type":"object","additionalProperties":false,"required":["asset_id","tag","value","expected_current_value","resource_version"],"properties":{"asset_id":{"type":"string"},"tag":{"type":"string"},"value":{"type":"number"},"expected_current_value":{"type":"number"},"resource_version":{"type":"string"}}}),
        output_schema: serde_json::json!({"type":"object","additionalProperties":false,"required":["verified_value","resource_version"],"properties":{"verified_value":{"type":"number"},"resource_version":{"type":"string"}}}),
        effect_class: EffectClass::Compensatable,
        risk_level: RiskLevel::High,
        executor_profile: "industrial-simulator".into(),
        credential_profile: "simulator-setpoint".into(),
        approval_profile: "industrial-write".into(),
        compensation: Some(CompensationBinding {
            tool: tool_ref.clone(),
            precondition_kind: "expected_current_value".into(),
        }),
        limits: ToolLimits {
            timeout_ms: 5000,
            max_result_bytes: 65536,
        },
        network_profile_ref: "industrial-gateway-only".into(),
        filesystem_profile_ref: "none".into(),
        implementation: ToolImplementation {
            kind: ImplementationKind::IndustrialGateway,
            digest: format!("sha256:{}", "c".repeat(64)),
            executor_id: "simulator-gateway".into(),
        },
        allowed_tenants: BTreeSet::from([tenant.clone()]),
        signature: None,
    };
    registry
        .create_draft(manifest)
        .unwrap_or_else(|_| panic!("draft"));
    registry
        .validate_version(&tool_ref)
        .unwrap_or_else(|_| panic!("validate"));
    registry
        .sign_version(&tool_ref, "publisher".into(), "publisher".into(), &signer)
        .unwrap_or_else(|_| panic!("sign"));
    registry
        .activate(&tool_ref)
        .unwrap_or_else(|_| panic!("activate"));
    tool_ref
}

#[tokio::test]
async fn industrial_prepare_authorize_proxy_execute_and_ledger_finalize() {
    let tenant = TenantId::new();
    let registry = Arc::new(InMemoryToolRegistry::new());
    let tool_ref = install_tool(&registry, &tenant);
    let snapshot = registry
        .resolve_exact(&tenant, &tool_ref)
        .await
        .unwrap_or_else(|_| panic!("snapshot"));
    let task_id = TaskId::new();
    let step_id = StepId::new();
    let agent_id = AgentInstanceId::new();
    let arguments = Map::from_iter([
        ("asset_id".into(), Value::String("asset-1".into())),
        ("tag".into(), Value::String("setpoint".into())),
        ("value".into(), Value::from(75)),
        ("expected_current_value".into(), Value::from(70)),
        ("resource_version".into(), Value::String("v1".into())),
    ]);
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId::new(),
        task_id: task_id.clone(),
        step_id: step_id.clone(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "industrial".into(),
            agent_instance_id: agent_id.clone(),
            organization_id: "org".into(),
            tenant_id: tenant.clone(),
            owner_subject: "operator".into(),
            model_provider: "test".into(),
            model_id: "sim".into(),
            agent_version: "1".into(),
            deployment_environment: "development".into(),
            trust_level: "verified".into(),
            auth_context_ref: "auth".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        },
        intent: Intent {
            goal_hash: "a".repeat(64),
            operation: "write".into(),
            justification_code: "OPERATOR_REQUEST".into(),
            safe_summary: None,
        },
        tool: tool_ref.clone(),
        payload: TypedPayload {
            type_id: "industrial.setpoint.v1".into(),
            schema_version: "1".into(),
            data: arguments.clone(),
        },
        resource: ResourceSelector {
            scheme: "opcua".into(),
            tenant_id: tenant.clone(),
            locator: "plant/asset-1/setpoint".into(),
            version: Some(ResourceVersion("v1".into())),
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "development".into(),
            region: "local".into(),
            zone: None,
            simulation: false,
        },
        current_state_version: Some("v1".into()),
        risk: RiskContext {
            declared_risk: RiskLevel::High,
            trajectory_risk_ref: Some("risk:1".into()),
            scope_delta: 0,
            automation_allowed: false,
        },
        data: DataContext {
            classification: DataClassification::Internal,
            jurisdiction: "CN".into(),
            export_constraints: vec![],
        },
        expected_outcome: ExpectedOutcome {
            metric: "verified_value".into(),
            operator: "eq".into(),
            target: Value::from(75),
        },
        credential_refs: vec![agent_trust_action_ir::CredentialRef {
            profile: "simulator-setpoint".into(),
            resource_prefix: "plant/asset-1".into(),
            operations: vec!["write".into()],
        }],
        requested_at: Utc::now(),
        extensions: BTreeMap::new(),
    };
    let action =
        normalize(draft, &NormalizationContext::default()).unwrap_or_else(|_| panic!("normalize"));
    let action_hash = hash(&action).unwrap_or_else(|_| panic!("hash"));
    let registry_input = RegistryPolicySnapshot {
        snapshot_hash: snapshot.snapshot_hash.clone(),
        tool_id: snapshot.tool_id.0.clone(),
        tool_version: snapshot.tool_version.0.clone(),
        risk: snapshot.risk_level,
        effect: snapshot.effect_class,
        implementation_digest: snapshot.implementation.digest.clone(),
    };
    let policy_input = to_policy_input(
        &action,
        &registry_input,
        &RuntimeContext {
            identity_subject: "operator".into(),
            prior_approvals: vec![],
            budget_remaining_microunits: 1_000_000,
        },
        &TrajectoryRiskSnapshot {
            version: "1".into(),
            accumulated_resources: vec![action.resource.locator.clone()],
            anomaly_score_millionths: 0,
        },
    )
    .unwrap_or_else(|_| panic!("policy input"));
    let grant = MinimalApprovalGrant {
        schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
        approval_id: ApprovalId::new(),
        task_id: task_id.clone(),
        step_id: step_id.clone(),
        action_hash: action_hash.clone(),
        resource_version: ResourceVersion("v1".into()),
        policy_version: PolicyVersion("industrial-p1".into()),
        approver_subject: "operator-2".into(),
        approver_roles: vec!["industrial-approver".into()],
        expires_at: Utc::now() + chrono::Duration::minutes(5),
        single_use: true,
    };
    let pep_key = SigningKey::from_bytes(&[22u8; 32]);
    let pep = PolicyEnforcementPoint::new(
        registry.clone(),
        Arc::new(AllowPdp),
        Arc::new(MinimalApprovalKernel::default()),
        "pep".into(),
        "pep-key".into(),
        pep_key,
        BTreeSet::from(["e".repeat(64)]),
    );
    let authorization = match pep
        .enforce(EnforcementRequest {
            stage: EnforcementStage::PreExecution,
            action: action.clone(),
            action_hash: action_hash.clone(),
            tool: snapshot.clone(),
            policy_input,
            approval: Some(grant),
            idempotency_key: Some("industrial:operation-1".into()),
            identity_uses_dev_verifier: false,
            resource_state_fresh: true,
            now: Utc::now(),
        })
        .await
        .unwrap_or_else(|_| panic!("pep"))
    {
        EnforcementOutcome::ExecutionAuthorized { authorization, .. } => authorization,
        _ => panic!("authorization required"),
    };
    let authorization = *authorization;

    let ledger = InMemoryExecutionLedger::default();
    let compensation = CompensationPlan {
        plan_id: Uuid::new_v4().to_string(),
        forward_action_hash: action_hash.clone(),
        steps: vec![CompensationStep {
            step_id: "restore".into(),
            tool: tool_ref,
            arguments_hash: "restore-args".into(),
            required_current_version: Some(ResourceVersion("v2".into())),
            expected_current_value: Some(Value::from(75)),
        }],
        created_at: Utc::now(),
    };
    let reservation = ledger
        .reserve(ExecutionIntent {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id,
            step_id,
            action_hash: action_hash.clone(),
            idempotency_key: IdempotencyKey("industrial:operation-1".into()),
            tool: action.tool.clone(),
            effect_class: EffectClass::Compensatable,
            resource_version: Some(ResourceVersion("v1".into())),
            canonical_arguments_hash: "args".into(),
            compensation_plan: Some(compensation),
            requested_at: Utc::now(),
        })
        .await
        .unwrap_or_else(|_| panic!("reserve"));
    ledger
        .mark_started(&reservation.fence, Some("simulator:operation-1".into()))
        .await
        .unwrap_or_else(|_| panic!("start"));

    let credentials = Arc::new(CredentialService::new(RevocationService::default()));
    let credential = credentials
        .issue(
            CredentialRequest {
                schema_version: SchemaVersion(IDENTITY_SCHEMA_VERSION.into()),
                tenant_id: tenant.clone(),
                agent_instance_id: agent_id,
                task_id: action.task_id.clone(),
                step_id: action.step_id.clone(),
                action_hash: action_hash.clone(),
                audience: "tool-proxy".into(),
                resources: BTreeSet::from(["plant/asset-1/setpoint".into()]),
                operations: BTreeSet::from(["commit_setpoint".into()]),
                tool_id: action.tool.tool_id.0.clone(),
                ttl_seconds: 60,
                max_uses: 1,
            },
            Utc::now(),
        )
        .unwrap_or_else(|_| panic!("credential"));
    let secrets = Arc::new(InMemoryTargetSecretProvider::default());
    secrets.insert(
        tenant.clone(),
        "simulator-setpoint".into(),
        "simulator-1".into(),
        b"simulator-secret".to_vec(),
    );
    let auth_verifier = Arc::new(ProxyAuthorizationVerifier::default());
    auth_verifier.add_key("pep-key".into(), "pep".into(), pep.verifying_key());
    let simulator = Arc::new(Simulator::default());
    let connector = Arc::new(IndustrialConnector::new(
        "industrial-simulator".into(),
        BTreeMap::from([(
            "simulator-1".into(),
            BTreeSet::from([("asset-1".into(), "setpoint".into())]),
        )]),
        simulator.clone(),
    ));
    let audit = Arc::new(Audit::default());
    let proxy = ToolProxy::new(
        registry,
        auth_verifier,
        credentials,
        secrets,
        vec![connector],
        audit.clone(),
    )
    .unwrap_or_else(|_| panic!("proxy"));
    let result = proxy
        .execute(AuthorizedToolRequest {
            authorization,
            tool: snapshot,
            tenant_id: tenant.clone(),
            workload_credential: credential,
            operation: "commit_setpoint".into(),
            resource: "plant/asset-1/setpoint".into(),
            target_profile: "simulator-1".into(),
            arguments,
            trace_id: "trace-1".into(),
        })
        .await
        .unwrap_or_else(|_| panic!("proxy execute"));
    ledger
        .mark_succeeded(
            &reservation.fence,
            result.result_hash,
            "evidence:industrial-1".into(),
        )
        .await
        .unwrap_or_else(|_| panic!("success"));
    assert_eq!(*simulator.writes.read(), 1);
    assert_eq!(audit.events.read().len(), 1);
    assert_eq!(
        ledger
            .get(&tenant, &reservation.execution_id)
            .await
            .map(|record| record.status),
        Ok(ExecutionStatus::Succeeded)
    );
}
