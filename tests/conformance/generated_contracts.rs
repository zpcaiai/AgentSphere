include!("../../generated/rust/contracts.rs");

fn main() {
    let tool = ToolRef {
        tool_id: "coding.test".into(),
        tool_version: "1.0.0".into(),
    };
    let plan = PlanManifest {
        schema_version: "agenttrust.contracts.v1".into(),
        plan_id: "plan-1".into(),
        goal_hash: "a".repeat(64),
        plan_hash: "b".repeat(64),
        steps: vec![PlanStep {
            step_id: "step-1".into(),
            sequence: 1,
            intent: "run tests".into(),
            dependencies: vec![],
            tool: Some(tool.clone()),
            resource_scope: vec!["repo:example".into()],
            risk: RiskLevel::Low,
        }],
        max_scope: vec!["repo:example".into()],
        risk_budget: RiskLevel::Low,
        cost_budget_microunits: 100,
        valid_until: "2026-08-05T11:00:00Z".into(),
    };
    assert_eq!(plan.steps[0].tool.as_ref(), Some(&tool));
}
