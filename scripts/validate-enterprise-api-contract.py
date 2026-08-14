#!/usr/bin/env python3
"""Fail a build when OpenAPI, Java handlers, and the generated browser client drift."""

from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
openapi = (root / "schemas/openapi/control-plane-v1.yaml").read_text(encoding="utf-8")
java_controller = "\n".join(
    (root / f"java/enterprise-control-api/src/main/java/com/agenttrust/control/{name}").read_text(encoding="utf-8")
    for name in ("EnterpriseController.java", "SessionController.java")
)
java_models = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AdminModels.java").read_text(encoding="utf-8")
typescript_client = (root / "web/control-console/src/api-client.ts").read_text(encoding="utf-8")
typescript_models = (root / "web/control-console/src/enterprise-api-types.ts").read_text(encoding="utf-8")
generated = (root / "web/control-console/src/generated/control-plane-v1.d.ts").read_text(encoding="utf-8")
package_json = (root / "web/control-console/package.json").read_text(encoding="utf-8")

# Every public operation has a concrete server handler and a browser-client entry point.
operations = {
    "getConsoleSession": ("session(", "session(", "ConsoleSession"),
    "logoutConsoleSession": ("logout(", "logout(", None),
    "createTenant": ("createTenant(", "createTenant(", "TenantRequest"),
    "createOrganization": ("createOrganization(", "createOrganization(", "OrganizationRequest"),
    "createProject": ("createProject(", "createProject(", "ProjectRequest"),
    "createIntegration": ("createIntegration(", "createIntegration(", "IntegrationRequest"),
    "consumeTenantQuota": ("consumeQuota(", "consumeQuota(", "QuotaConsumeRequest"),
    "recordTenantCost": ("recordCost(", "recordCost(", "CostUsageRequest"),
    "issueApiKey": ("issueApiKey(", "issueApiKey(", "ApiKeyIssueRequest"),
    "revokeApiKey": ("revokeApiKey(", "revokeApiKey(", "AdminAction"),
    "submitTaskCommand": ("submitTaskCommand(", "submitTaskCommand(", "TaskCommand"),
    "listAgentInventory": ("listAgentInventory(", "listAgents(", "AuthorityPayload"),
    "simulatePolicyBundle": ("simulatePolicyBundle(", "simulatePolicy(", "PolicySimulationRequest"),
    "promotePolicyBundle": ("promotePolicyBundle(", "promotePolicy(", "PolicyPromotionRequest"),
    "submitApprovalIntent": ("submitApprovalIntent(", "submitApprovalIntent(", "ApprovalIntent"),
    "resumeTaskEvents": ("resumeAguiEvents(", "AgUiResumeClient", "AguiResumeResponse"),
    "getTaskSafeSnapshot": ("safeAguiSnapshot(", "AgUiResumeClient", "AguiSafeSnapshot"),
    "getEnterpriseDashboard": ("dashboard(", "dashboard(", "EnterpriseDashboard"),
    "submitAdminIntent": ("submitIntent(", "submitAdminIntent(", "AdminAction"),
}

declared = re.findall(r"^\s+operationId: ([A-Za-z0-9]+)$", openapi, flags=re.MULTILINE)
assert len(declared) == len(set(declared)), "duplicate OpenAPI operationId"
assert set(declared) == set(operations), (
    f"operation drift missing={sorted(set(operations) - set(declared))} "
    f"extra={sorted(set(declared) - set(operations))}"
)

shared_agui = (root / "web/shared/agui-client.ts").read_text(encoding="utf-8")
for operation, (java_method, typescript_method, schema) in operations.items():
    assert java_method in java_controller, f"Java handler missing: {operation}"
    assert typescript_method in typescript_client or typescript_method in shared_agui, (
        f"TypeScript client missing: {operation}"
    )
    if schema is not None:
        assert f"        {schema}:" in generated, f"generated schema missing: {schema}"
    assert f'operations["{operation}"]' in generated, f"generated operation missing: {operation}"

for java_type in (
    "TenantRequest", "OrganizationRequest", "ProjectRequest", "IntegrationRequest",
    "QuotaConsumeRequest", "CostUsageRequest", "ApiKeyIssueRequest", "TaskCommand",
    "PolicySimulationRequest", "PolicyPromotionRequest", "ApprovalIntent", "AdminIntent",
):
    assert f"record {java_type}" in java_models, f"Java model missing: {java_type}"

for generated_type in (
    "TenantRequest", "OrganizationRequest", "ProjectRequest", "IntegrationRequest",
    "QuotaConsumeRequest", "QuotaUsage", "CostUsageRequest", "ApiKeyIssueRequest",
    "ApiKeyIssueResponse", "TaskCommand", "PolicySimulationRequest", "PolicyPromotionRequest",
):
    assert f'Schemas["{generated_type}"]' in typescript_models, (
        f"browser model does not consume generated contract: {generated_type}"
    )

# Explicit session/JWT alternatives and CSRF parameters are mandatory at every browser operation.
operation_blocks = re.split(r"(?=^\s+operationId: )", openapi, flags=re.MULTILINE)
by_operation = {}
for index, block in enumerate(operation_blocks[1:], start=1):
    operation = re.match(r"\s+operationId: ([A-Za-z0-9]+)", block)
    if operation:
        # Security and parameters precede operationId, so include the preceding method prefix.
        prefix = operation_blocks[index - 1].rsplit("\n  /", 1)[-1]
        by_operation[operation.group(1)] = prefix + block.split("\n  /", 1)[0]

for operation in operations:
    block = by_operation[operation]
    assert "enterpriseJwt: []" in block and "oidcSession: []" in block, (
        f"browser authentication alternatives missing: {operation}"
    )

for operation in set(operations) - {"getConsoleSession", "listAgentInventory", "resumeTaskEvents", "getTaskSafeSnapshot", "getEnterpriseDashboard"}:
    assert "#/components/parameters/CsrfToken" in by_operation[operation], (
        f"CSRF contract missing: {operation}"
    )

assert '"generate:api"' in package_json and "openapi-typescript" in package_json
assert "name: Idempotency-Key" in openapi and "name: X-XSRF-TOKEN" in openapi
assert "one_time_secret" in openapi and "oneTimeSecret" in java_models
assert "Cache-Control" in java_controller and "csrfToken.getToken()" in java_controller
assert "CookieCsrfTokenRepository" in (
    root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/SecurityConfiguration.java"
).read_text(encoding="utf-8")
assert "name: SESSION" in openapi and "name: JSESSIONID" not in openapi

# Signed resume and snapshot data must derive from the dedicated authoritative transition
# surface.  Mixing submitted commands or rejection audits into a bounded page can evict the
# current transition and make a BFF sign stale task state.
orchestrator_contract = (root / "schemas/openapi/orchestrator-v1.yaml").read_text(encoding="utf-8")
orchestrator_api = (root / "python/durable_worker/orchestrator_api.py").read_text(encoding="utf-8")
agui_service = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AguiResumeService.java").read_text(encoding="utf-8")
agui_client = (root / "web/shared/agui-client.ts").read_text(encoding="utf-8")
for marker in (
    "/v1/tasks/transitions:", "operationId: authoritativeTaskTransitions",
    "agenttrust.authoritative-task-transitions.v1",
):
    assert marker in orchestrator_contract, f"authoritative task transition contract missing: {marker}"
assert "async def task_transitions(" in orchestrator_api
assert "_validated_authoritative_transitions(state)" in orchestrator_api
assert '"/v1/tasks/transitions"' in orchestrator_api
assert '"agenttrust.authoritative-task-transitions.v1"' in agui_service
assert "authorities.taskTransitions" in agui_service
assert "recoverFromSafeSnapshot" in agui_client and "resetFromSafeSnapshot" in agui_client
for schema_file in ("agui-event.schema.json", "agui-safe-snapshot.schema.json"):
    assert (root / "schemas/a2a" / schema_file).is_file(), f"A2A schema missing: {schema_file}"

print(f"enterprise API parity OK: {len(operations)} public operations, generated browser models consumed")
