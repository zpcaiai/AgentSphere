#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
openapi = (root / "schemas/openapi/control-plane-v1.yaml").read_text()
java_models = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AdminModels.java").read_text()
typescript = (root / "web/control-console/src/enterprise-api-types.ts").read_text()

operations = {
    "createTenant": ("TenantRequest", "TenantRequest"),
    "createOrganization": ("OrganizationRequest", "OrganizationRequest"),
    "createProject": ("ProjectRequest", "ProjectRequest"),
    "createIntegration": ("IntegrationRequest", "IntegrationRequest"),
    "consumeTenantQuota": ("QuotaConsumeRequest", "QuotaConsumeRequest"),
    "recordTenantCost": ("CostUsageRequest", "CostUsageRequest"),
    "issueApiKey": ("ApiKeyIssueRequest", "ApiKeyIssueRequest"),
    "revokeApiKey": ("AdminIntent", "AdminIntent"),
}

for operation, (java_type, typescript_type) in operations.items():
    assert f"operationId: {operation}" in openapi, operation
    assert f"record {java_type}" in java_models, java_type
    assert f"interface {typescript_type}" in typescript or typescript_type == "AdminIntent", typescript_type

assert "required: [schema_version, action_id, tenant_id," in openapi
assert "name: X-XSRF-TOKEN" in openapi
assert "Cache-Control" in (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/EnterpriseController.java").read_text()
assert "one_time_secret" in openapi and "oneTimeSecret" in java_models and "one_time_secret" in typescript
print(f"enterprise API parity OK: {len(operations)} governed operations")
