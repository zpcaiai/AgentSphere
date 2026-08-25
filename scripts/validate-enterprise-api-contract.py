#!/usr/bin/env python3
"""Fail a build when OpenAPI, Java handlers, and the generated browser client drift."""

from pathlib import Path
import json
import re

root = Path(__file__).resolve().parents[1]
openapi = (root / "schemas/openapi/control-plane-v1.yaml").read_text(encoding="utf-8")
java_controller = "\n".join(
    (root / f"java/enterprise-control-api/src/main/java/com/agenttrust/control/{name}").read_text(encoding="utf-8")
    for name in ("EnterpriseController.java", "SessionController.java")
)
java_models = "\n".join(
    (root / f"java/enterprise-control-api/src/main/java/com/agenttrust/control/{name}").read_text(encoding="utf-8")
    for name in ("AdminModels.java", "IncidentModels.java", "MarketplaceModels.java")
)
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
    "listAgentInventory": ("listAgentInventory(", "listAgents(", "AgentInventoryPage"),
    "listPolicies": ("listPolicies(", "listPolicies(", "PolicyPage"),
    "listPolicySources": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "listPolicyAnalyses": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "listPolicyReviews": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "listPolicySimulations": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "listPolicyImpactReports": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "listPolicyPromotions": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "listPolicyExceptions": ("listPolicyArtifacts(", "listPolicyArtifacts(", "PolicyArtifactPage"),
    "submitPolicyAction": ("submitPolicyAction(", "submitPolicyAction(", "PolicyCommand"),
    "listIncidents": ("listIncidents(", "listIncidents(", "IncidentPage"),
    "getIncident": ("getIncident(", "getIncident(", "Incident"),
    "submitIncidentAction": ("submitIncidentAction(", "submitIncidentAction(", "IncidentCommand"),
    "listPacks": ("listPacks(", "listPacks(", "PackPage"),
    "submitPackAction": ("submitPackAction(", "submitPackAction(", "MarketplaceCommand"),
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
pep_governance = (root / "rust/crates/policy-pep/src/governance.rs").read_text(
    encoding="utf-8"
)
pep_governance_schema = json.loads(
    (root / "schemas/pep/governance-authorization.schema.json").read_text(encoding="utf-8")
)
for operation, (java_method, typescript_method, schema) in operations.items():
    assert java_method in java_controller, f"Java handler missing: {operation}"
    assert typescript_method in typescript_client or typescript_method in shared_agui, (
        f"TypeScript client missing: {operation}"
    )
    if schema is not None:
        assert f"        {schema}:" in generated, f"generated schema missing: {schema}"
    assert f'operations["{operation}"]' in generated, f"generated operation missing: {operation}"

pep_approval = pep_governance_schema["$defs"]["approvalAction"]["properties"]
assert pep_approval["reason"]["maxLength"] == 2000
assert pep_approval["reason"]["x-agenttrust-max-utf8-bytes"] == 4096
assert pep_approval["reason"]["pattern"] == r"^[^\u0000]*$"
assert pep_approval["observed_resource_version"]["maxLength"] == 512
assert pep_approval["observed_resource_version"]["pattern"] == r"^[^\u0000\r\n]*$"
for marker in ("valid_approval_reason", "value.chars().count() <= 2_000",
               "value.len() <= 4_096", "valid_approval_resource_version",
               "fresh_human_principal_key_status(key.status)"):
    assert marker in pep_governance, f"PEP approval Unicode contract missing {marker}"

for java_type in (
    "TenantRequest", "OrganizationRequest", "ProjectRequest", "IntegrationRequest",
    "QuotaConsumeRequest", "CostUsageRequest", "ApiKeyIssueRequest", "TaskCommand",
    "PolicyCommandRequest", "PolicyActionReceipt", "ApprovalIntent", "AdminIntent",
    "IncidentCommandRequest", "MarketplaceCommandRequest",
):
    assert f"record {java_type}" in java_models, f"Java model missing: {java_type}"

for generated_type in (
    "TenantRequest", "OrganizationRequest", "ProjectRequest", "IntegrationRequest",
    "QuotaConsumeRequest", "QuotaUsage", "CostUsageRequest", "ApiKeyIssueRequest",
    "AgentInventoryItem", "AgentInventoryPage", "EnterpriseActionReceipt", "TaskCommand",
    "PolicyCommand", "PolicyActionReceipt", "PolicyPage", "PolicyArtifactPage",
    "Incident", "IncidentPage", "IncidentCommand", "IncidentActionReceipt",
    "PackRelease", "PackInstallation", "PackPage", "MarketplaceTypedCommand",
    "MarketplaceCommand", "MarketplaceActionReceipt", "ApprovalIntentReceipt",
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

for operation in set(operations) - {
    "getConsoleSession", "listAgentInventory", "listPolicies", "listPolicySources",
    "listPolicyAnalyses", "listPolicyReviews", "listPolicySimulations",
    "listPolicyImpactReports", "listPolicyPromotions", "listPolicyExceptions",
    "listIncidents", "getIncident", "listPacks", "resumeTaskEvents",
    "getTaskSafeSnapshot", "getEnterpriseDashboard",
}:
    assert "#/components/parameters/CsrfToken" in by_operation[operation], (
        f"CSRF contract missing: {operation}"
    )

approval_intent_operation = by_operation["submitApprovalIntent"]
for status in ("400", "401", "403", "409", "413", "415", "429", "500", "503"):
    assert f"'{status}':" in approval_intent_operation, (
        f"approval safe-error response missing: {status}"
    )
assert approval_intent_operation.count("#/components/schemas/SafeError") == 9

assert '"generate:api"' in package_json and "openapi-typescript" in package_json
assert "name: Idempotency-Key" in openapi and "name: X-XSRF-TOKEN" in openapi
assert "one_time_secret" not in openapi and "oneTimeSecret" not in java_models
assert "one_time_secret" not in generated and "one_time_secret" not in typescript_client
assert "agenttrust.enterprise-action-receipt.v1" in openapi
assert "Cache-Control" in java_controller and "csrfToken.getToken()" in java_controller
assert "CookieCsrfTokenRepository" in (
    root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/SecurityConfiguration.java"
).read_text(encoding="utf-8")
assert "name: SESSION" in openapi and "name: JSESSIONID" not in openapi

# Incident and Pack writes must preserve the exact Rust authority scopes and terminate at the
# Canonical Action ingress. Browser code never receives service bearer tokens or a human signer.
application_yml = (root / "java/enterprise-control-api/src/main/resources/application.yml").read_text(encoding="utf-8")
token_properties = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthorityTokenProperties.java").read_text(encoding="utf-8")
incident_gateway = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/IncidentAuthorityGateway.java").read_text(encoding="utf-8")
pack_gateway = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/PackMarketplaceGateway.java").read_text(encoding="utf-8")
readiness = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthorityReadinessConfiguration.java").read_text(encoding="utf-8")
bff = (root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthoritativeBff.java").read_text(encoding="utf-8")
console_state = (root / "web/control-console/src/control-state.ts").read_text(encoding="utf-8")
console_router = (root / "web/control-console/src/router.ts").read_text(encoding="utf-8")
for marker in (
    "AGENT_TRUST_INCIDENT_READ_TOKEN_FILE", "AGENT_TRUST_INCIDENT_MUTATE_TOKEN_FILE",
    "AGENT_TRUST_PACK_MARKETPLACE_READ_TOKEN_FILE", "AGENT_TRUST_PACK_MARKETPLACE_MUTATE_TOKEN_FILE",
):
    assert marker in application_yml, f"authority token file binding missing: {marker}"
for marker in ('"incidents.mutate"', '"packs.mutate"'):
    assert marker in token_properties, f"operation token allowlist missing: {marker}"
for source, markers in (
    (incident_gateway, ('"incident:mutate"', '"/v1/incidents/actions"',
        'tokens.operationToken(MUTATE_OPERATION_TOKEN)', 'assertions.sign(',
        'tokens.readToken(READ_AUTHORITY)', 'decode(response, 202)')),
    (pack_gateway, ('"packs:mutate"', '"/v1/packs/actions"',
        'tokens.operationToken(MUTATE_OPERATION_TOKEN)', 'assertions.sign(',
        'tokens.readToken(READ_AUTHORITY)', 'decode(response, 202)')),
):
    for marker in markers:
        assert marker in source, f"authority ingress invariant missing: {marker}"
for marker in ("agenttrust.incident-release-readiness.v1",
               "agenttrust.pack-marketplace-readiness.v1"):
    assert marker in readiness, f"readiness contract missing: {marker}"

production_authority_pages = {
    "models": ("MODELS", "/v1/authoritative/models/executions",
               "agenttrust.authoritative-model-executions.v1",
               "AGENT_TRUST_MODEL_GATEWAY_READ_TOKEN_FILE"),
    "data": ("DATA", "/v1/authoritative/data/resources",
             "agenttrust.authoritative-data-page.v1",
             "AGENT_TRUST_DATA_GOVERNANCE_READ_TOKEN_FILE"),
    "context": ("CONTEXT", "/v1/authoritative/context/resources",
                "agenttrust.authoritative-context-page.v1",
                "AGENT_TRUST_CONTEXT_GOVERNANCE_READ_TOKEN_FILE"),
    "anomalies": ("ANOMALIES", "/v1/authoritative/runtime-anomaly/trajectories",
                  "agenttrust.authoritative-runtime-anomaly-page.v1",
                  "AGENT_TRUST_RUNTIME_ANOMALY_READ_TOKEN_FILE"),
    "security_evaluations": (
        "SECURITY_EVALUATIONS", "/v1/authoritative/security-evaluations/campaigns",
        "agenttrust.authoritative-security-eval-campaign-page.v1",
        "AGENT_TRUST_SECURITY_EVALUATION_READ_TOKEN_FILE"),
    "supply_chain": ("SUPPLY_CHAIN", "/v1/authoritative/supply-chain/releases",
                     "agenttrust.supply-chain-authoritative-releases.v1",
                     "AGENT_TRUST_PACK_SUPPLY_CHAIN_READ_TOKEN_FILE"),
    "domain_packs": ("DOMAIN_PACKS", "/v1/authoritative/domain-runtime/executions",
                     "agenttrust.domain-runtime-authoritative-state.v1",
                     "AGENT_TRUST_DOMAIN_RUNTIME_READ_TOKEN_FILE"),
    "sre": ("SRE", "/v1/authoritative/sre/resources",
            "agenttrust.sre-resource-page.v1", "AGENT_TRUST_SRE_READ_TOKEN_FILE"),
}
for authority, (section, path, schema, token_env) in production_authority_pages.items():
    assert f'"{authority}"' in token_properties, f"authority token scope missing: {authority}"
    assert path in bff and schema in bff, f"BFF authority page contract missing: {authority}"
    assert f'"{section}"' in console_state, f"console module missing: {section}"
    assert token_env in application_yml, f"BFF token-file binding missing: {token_env}"
    assert section in openapi and section in generated, f"generated dashboard section missing: {section}"
for marker in (
    'material.remove("data_digest")', "MessageDigest.isEqual(expected, supplied)",
    "SENSITIVE_BROWSER_DATA_SEGMENTS", "safeBrowserAuthorityData",
):
    assert marker in bff, f"BFF fail-closed page validation missing: {marker}"

# The eight production runtime authorities are one contract across Rust, standalone/inline JSON
# Schema, OpenAPI, the BFF, and the browser.  Validate ports as well as paths: accepting an
# arbitrary container port while the Service/Docker contract is fixed produces a deployment that
# can be healthy in-process but permanently unreachable from the control plane.
production_runtime_contracts = {
    "models": {
        "section": "MODELS", "path": "/v1/authoritative/models/executions",
        "page_schema": "agenttrust.authoritative-model-executions.v1",
        "cursor": "next_cursor", "readiness": "agenttrust.model-gateway-readiness.v1",
        "openapi": "model-gateway-v1.yaml", "page_contract": "model-gateway/authoritative-executions.schema.json",
        "server": "model-gateway/src/server.rs", "authority": "model-gateway/src/authority.rs",
        "binary": "model-gateway/src/bin/agenttrust-model-gateway-service.rs",
        "dockerfile": "Dockerfile.model-gateway", "data_port": 8091, "management_port": 9101,
        "port_markers": ('exact_port("AGENT_TRUST_MODEL_PORT", 8091)',
                         'exact_port("AGENT_TRUST_MODEL_MANAGEMENT_PORT", 9101)'),
        "readiness_fields": {"schema_version", "ready", "database_ready",
            "provider_registry_ready", "data_governance_authority_ready",
            "artifact_store_ready", "evidence_ready"},
    },
    "data": {
        "section": "DATA", "path": "/v1/authoritative/data/resources",
        "page_schema": "agenttrust.authoritative-data-page.v1", "cursor": "next_after",
        "readiness": "agenttrust.data-governance-readiness.v1",
        "openapi": "data-governance-v1.yaml", "page_contract": "data-governance/authoritative-page.schema.json",
        "server": "data-governance/src/server.rs", "authority": "data-governance/src/authority.rs",
        "binary": "data-governance/src/bin/agenttrust-data-governance-service.rs",
        "dockerfile": "Dockerfile.data-governance", "data_port": 8092, "management_port": 9102,
        "port_markers": ('required_exact_port("AGENT_TRUST_DATA_PORT", 8092)',
                         'required_exact_port("AGENT_TRUST_DATA_MANAGEMENT_PORT", 9102)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "orchestrator_ready",
            "enterprise_dlp_ready", "object_worm_ready", "legal_hold_ready", "evidence_ready"},
    },
    "context": {
        "section": "CONTEXT", "path": "/v1/authoritative/context/resources",
        "page_schema": "agenttrust.authoritative-context-page.v1", "cursor": "next_after",
        "readiness": "agenttrust.context-readiness.v1", "openapi": "context-governance-v1.yaml",
        "page_contract": None, "server": "context-governance/src/server.rs",
        "authority": "context-governance/src/authority.rs",
        "binary": "context-governance/src/bin/agenttrust-context-governance-service.rs",
        "dockerfile": "Dockerfile.context-governance", "data_port": 8095, "management_port": 9105,
        "port_markers": ('required_i64("AGENT_TRUST_CONTEXT_PORT", 8_095, 8_095)',
                         'required_i64("AGENT_TRUST_CONTEXT_MANAGEMENT_PORT", 9_105, 9_105)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "orchestrator_ready",
            "object_store_ready", "vector_index_ready", "cache_ready", "supply_chain_ready",
            "legal_hold_ready", "poisoning_detector_ready", "evidence_ready"},
    },
    "anomalies": {
        "section": "ANOMALIES", "path": "/v1/authoritative/runtime-anomaly/trajectories",
        "page_schema": "agenttrust.authoritative-runtime-anomaly-page.v1", "cursor": "next_after",
        "readiness": "agenttrust.runtime-anomaly-readiness.v1", "openapi": "runtime-anomaly-v1.yaml",
        "page_contract": "runtime-anomaly/authoritative-trajectory-page.schema.json",
        "server": "runtime-anomaly/src/server.rs", "authority": "runtime-anomaly/src/authority.rs",
        "binary": "runtime-anomaly/src/bin/agenttrust-runtime-anomaly-authority.rs",
        "dockerfile": "Dockerfile.runtime-anomaly", "data_port": 8094, "management_port": 9104,
        "port_markers": ('required_exact_port("AGENT_TRUST_RUNTIME_ANOMALY_DATA_PORT", 8_094)',
                         'required_exact_port("AGENT_TRUST_RUNTIME_ANOMALY_MANAGEMENT_PORT", 9_104)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "orchestrator_ready",
            "response_dependencies_ready", "evidence_authority_ready", "deterministic_rules_ready",
            "semantic_detector_required", "production_certification"},
    },
    "security_evaluations": {
        "section": "SECURITY_EVALUATIONS",
        "path": "/v1/authoritative/security-evaluations/campaigns",
        "page_schema": "agenttrust.authoritative-security-eval-campaign-page.v1",
        "cursor": "next_after_campaign_id", "readiness": "agenttrust.security-eval-readiness.v1",
        "openapi": "security-evaluation-v1.yaml", "page_contract": None,
        "server": "security-evaluation-lab/src/server.rs",
        "authority": "security-evaluation-lab/src/authority.rs",
        "binary": "security-evaluation-lab/src/bin/agenttrust-security-evaluation-authority.rs",
        "dockerfile": "Dockerfile.security-evaluation", "data_port": 8096, "management_port": 9106,
        "port_markers": ('required_u16("AGENT_TRUST_SECURITY_EVAL_DATA_PORT", 8_096, 8_096)',
                         'required_u16("AGENT_TRUST_SECURITY_EVAL_MANAGEMENT_PORT", 9_106, 9_106)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "orchestrator_ready",
            "isolated_runner_ready", "evidence_authority_ready", "dataset_keyring_ready",
            "report_signer_ready", "production_certification"},
    },
    "supply_chain": {
        "section": "SUPPLY_CHAIN", "path": "/v1/authoritative/supply-chain/releases",
        "page_schema": "agenttrust.supply-chain-authoritative-releases.v1", "cursor": "next_cursor",
        "readiness": "agenttrust.supply-chain-readiness.v1", "openapi": "pack-supply-chain-v1.yaml",
        "page_contract": "domain-pack/authoritative-releases.schema.json",
        "server": "pack-supply-chain/src/server.rs", "authority": "pack-supply-chain/src/production.rs",
        "binary": "pack-supply-chain/src/bin/agenttrust-pack-supply-chain-authority.rs",
        "dockerfile": "Dockerfile.pack-supply-chain", "data_port": 8093, "management_port": 9103,
        "port_markers": ('required_i64("AGENT_TRUST_SUPPLY_PORT",8093,8093)',
                         'required_i64("AGENT_TRUST_SUPPLY_MANAGEMENT_PORT",9103,9103)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "repository_ready",
            "signer_ready", "scanner_ready", "sandbox_ready", "revocation_ready", "evidence_ready"},
    },
    "domain_packs": {
        "section": "DOMAIN_PACKS", "path": "/v1/authoritative/domain-runtime/executions",
        "page_schema": "agenttrust.domain-runtime-authoritative-state.v1", "cursor": "next_cursor",
        "readiness": "agenttrust.domain-runtime-readiness.v1", "openapi": "domain-runtime-v1.yaml",
        "page_contract": "domain-packs/authoritative-domain-state.schema.json",
        "server": "domain-risk-packs/server.rs", "authority": "domain-risk-packs/authority.rs",
        "binary": "domain-risk-packs/src/bin/agenttrust-domain-runtime-authority.rs",
        "dockerfile": "Dockerfile.domain-runtime", "data_port": 8094, "management_port": 9104,
        "port_markers": ('required_i64("AGENT_TRUST_DOMAIN_PORT",8094,8094)',
                         'required_i64("AGENT_TRUST_DOMAIN_MANAGEMENT_PORT",9104,9104)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "executor_ready",
            "evidence_ready"},
    },
    "sre": {
        "section": "SRE", "path": "/v1/authoritative/sre/resources",
        "page_schema": "agenttrust.sre-resource-page.v1", "cursor": "next_after",
        "readiness": "agenttrust.sre-readiness.v1", "openapi": "platform-sre-v1.yaml",
        "page_contract": None, "server": "platform-sre/src/server.rs",
        "authority": "platform-sre/src/authority.rs",
        "binary": "platform-sre/src/bin/agenttrust-platform-sre-service.rs",
        "dockerfile": "Dockerfile.platform-sre", "data_port": 8097, "management_port": 9107,
        "port_markers": ('required_i64("AGENT_TRUST_SRE_PORT", 8_097, 8_097)',
                         'required_i64("AGENT_TRUST_SRE_MANAGEMENT_PORT", 9_107, 9_107)'),
        "readiness_fields": {"schema_version", "ready", "database_ready", "orchestrator_ready",
            "effect_adapters_ready", "production_certification"},
    },
}

def java_map_entries(source: str, declaration: str) -> dict[str, str]:
    start = source.index(declaration)
    end = source.index(");", start)
    return dict(re.findall(r'Map\.entry\("([a-z_]+)",\s*"([^"]+)"\)', source[start:end]))

def rust_readiness_field_sets(source: str) -> list[set[str]]:
    candidates = []
    for marker in re.finditer(r'"schema_version"\s*:\s*[A-Z_]+', source):
        block = source[marker.start():marker.start() + 2_500].split("})))", 1)[0]
        fields = set(re.findall(r'"([a-z_]+)"\s*:', block))
        if "ready" in fields:
            candidates.append(fields)
    return candidates

bff_paths = java_map_entries(bff, "AUTHORITY_DASHBOARD_PATHS =")
bff_schemas = java_map_entries(bff, "STANDARD_PAGE_SCHEMAS =")
bff_cursors = java_map_entries(bff, "STANDARD_PAGE_CURSORS =")
expected_sections = {value[0] for value in production_authority_pages.values()}
section_block = re.search(r"SERVICE_SECTIONS\s*=\s*\[(.*?)\]\s*as const", console_state, re.DOTALL)
assert section_block is not None, "console service section declaration missing"
actual_sections = set(re.findall(r'"([A-Z_]+)"', section_block.group(1)))
assert len(actual_sections) == 21 and expected_sections <= actual_sections, (
    "console production authority section set drift"
)
router_block = re.search(
    r"const modules = new Set\(\[(.*?)\]\);", console_router, re.DOTALL
)
assert router_block is not None, "console module route allowlist missing"
actual_routes = set(re.findall(r'"([a-z_]+)"', router_block.group(1)))
expected_routes = {section.lower() for section in actual_sections} | {"overview", "admin"}
assert actual_routes == expected_routes, (
    f"console module route drift missing={sorted(expected_routes - actual_routes)} "
    f"extra={sorted(actual_routes - expected_routes)}"
)

# Batch 17 approval review facts form one strict v2 contract. Requester text is never rendered
# unless an independently signed authority attestation binds it to the exact Canonical Action,
# risk package and state snapshot. Legacy mutable rows must be drained before the atomic rollout.
approval_openapi = (root / "schemas/openapi/approval-v1.yaml").read_text(encoding="utf-8")
approval_schema = json.loads(
    (root / "schemas/approval/approval-case.schema.json").read_text(encoding="utf-8")
)
decision_request_binding_schema = json.loads(
    (root / "schemas/approval/decision-request-binding.schema.json").read_text(
        encoding="utf-8"
    )
)
review_keyring_schema = json.loads(
    (root / "schemas/approval/review-evidence-keyring.schema.json").read_text(encoding="utf-8")
)
review_issue_schema = json.loads(
    (root / "schemas/approval/review-evidence-issue.schema.json").read_text(encoding="utf-8")
)
approval_rust = (root / "rust/crates/enterprise-approval/src/lib.rs").read_text(encoding="utf-8")
approval_store = (root / "rust/crates/enterprise-approval/src/postgres.rs").read_text(encoding="utf-8")
review_evidence_rust = (
    root / "rust/crates/enterprise-approval/src/review_evidence.rs"
).read_text(encoding="utf-8")
review_shared_contracts = (
    root / "rust/crates/contracts/src/lib.rs"
).read_text(encoding="utf-8")
domain_review_producer = (
    root / "rust/crates/domain-risk-packs/server.rs"
).read_text(encoding="utf-8")
domain_review_binary = (
    root / "rust/crates/domain-risk-packs/src/bin/agenttrust-domain-runtime-authority.rs"
).read_text(encoding="utf-8")
domain_review_openapi = (
    root / "schemas/openapi/domain-runtime-v1.yaml"
).read_text(encoding="utf-8")
domain_token_schema = json.loads(
    (root / "schemas/domain-packs/domain-runtime-token-bindings.schema.json").read_text(
        encoding="utf-8"
    )
)
approval_gateway = (
    root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/GovernedAuthorityGateway.java"
).read_text(encoding="utf-8")
approval_decision_verifier = (
    root
    / "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalDecisionEvidenceVerifier.java"
).read_text(encoding="utf-8")
approval_signature_verifier = (
    root
    / "java/enterprise-control-api/src/main/java/com/agenttrust/control/ApprovalAuthoritySignatureVerifier.java"
).read_text(encoding="utf-8")
approval_repository = (
    root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/EnterpriseRepository.java"
).read_text(encoding="utf-8")
approval_service = (
    root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/EnterpriseService.java"
).read_text(encoding="utf-8")
approval_intent_migration = (
    root / "migrations/enterprise-control/0036_01_27_approval_intent_receipt.sql"
).read_text(encoding="utf-8")
approval_json = (
    root / "java/enterprise-control-api/src/main/java/com/agenttrust/control/AuthorityJson.java"
).read_text(encoding="utf-8")
approval_browser = (root / "web/approval-console/src/approval-state.ts").read_text(encoding="utf-8")
approval_view = (root / "web/approval-console/src/ApprovalConsole.vue").read_text(encoding="utf-8")
approval_tests = (root / "web/approval-console/src/approval-state.test.ts").read_text(encoding="utf-8")
approval_request_fields = {
    "tenant_id", "task_id", "step_id", "action_hash", "plan_hash", "parameter_hash",
    "resource", "resource_version", "policy_version", "environment", "risk",
    "review_context", "review_evidence", "requester_subject", "agent_owner_subject",
    "justification", "requested_ttl_seconds", "requested_uses",
}
assert set(approval_schema["properties"]["request"]["required"]) == approval_request_fields
assert set(approval_schema["properties"]["request"]["properties"]) == approval_request_fields
assert approval_schema["properties"]["request"]["additionalProperties"] is False
assert approval_schema["properties"]["schema_version"]["const"] == (
    "agenttrust.enterprise-approval-case.v2"
)
assert approval_schema["properties"]["request"]["properties"]["justification"][
    "x-agenttrust-max-utf8-bytes"
] == 4096
assert decision_request_binding_schema["properties"]["decision"]["properties"][
    "reason"
]["x-agenttrust-max-utf8-bytes"] == 4096
assert approval_openapi.count("x-agenttrust-max-utf8-bytes: 4096") == 4
assert review_keyring_schema["properties"]["schema_version"]["const"] == (
    "agenttrust.approval-review-evidence-keyring.v2"
)
assert review_keyring_schema["properties"]["keys"]["items"]["properties"]["usage"]["const"] == (
    "AUTHORITY_EVIDENCE_RECEIPT"
)
assert set(review_issue_schema["required"]) == {
    "schema_version", "request_id", "idempotency_key", "actor_subject", "source_service",
    "trace_id", "material", "requested_at",
}
for marker in (
    "agenttrust.approval-case-create.v2", "agenttrust.enterprise-approval-case.v2",
    "agenttrust.approval-review-evidence-binding.v1", "agenttrust.approval-review-material.v1",
    "signed-authority-evidence-receipt.schema.json", "canonical_action_hash",
    "authority_request", "APPROVAL_REVIEW_PREPARED",
    "risk_package_ref", "risk_package_digest", "state_snapshot_ref", "state_snapshot_digest",
):
    assert marker in approval_openapi, f"approval v2 OpenAPI marker missing: {marker}"
for marker in ("deny_unknown_fields", "review_context", "review_evidence"):
    assert marker in approval_rust, f"strict Rust approval request marker missing: {marker}"
for marker in (
    "verify_request(&envelope.request, now)", "verify_historical_request(&request, created_at)",
    "LegacyApprovalRequestV0", "parse_authoritative_request", ".evidence_refs()",
):
    assert marker in approval_store, f"approval persistence compatibility marker missing: {marker}"
for marker in (
    "ApprovalReviewEvidenceKeyring", "ApprovalReviewMaterial", "review_material_digest",
    "AuthorityEvidenceSourceKind::AuthenticatedEvent", "risk_package_ref", "state_snapshot_ref",
    "VerifyingKey", "to_authority_event",
):
    assert marker in review_evidence_rust, f"review evidence verifier missing: {marker}"
for marker in (
    "pub struct ApprovalReviewEvidenceIssueRequest", "pub struct ApprovalReviewMaterial",
    "pub struct ApprovalReviewEvidence", "AuthorityEvidenceEventRequest",
    "SignedAuthorityEvidenceReceipt", "EvidenceEventType::ApprovalReviewPrepared",
):
    assert marker in review_shared_contracts, f"shared review contract missing: {marker}"
for forbidden in ("bind_and_sign", "SigningKey", "private_key", "evidence:authority-event"):
    assert forbidden not in review_evidence_rust, f"approval review verifier owns issuer material: {forbidden}"
for marker in (
    "/v1/domain-runtime/approval-review-evidence", "issue_approval_review_evidence",
    "v1/evidence/authority-events", "issue.to_authority_event(&self.evidence_client_identity",
    "verify_for_source_kind", "AuthorityEvidenceSourceKind::AuthenticatedEvent",
    "read_bounded_body(response,262_144)", "X-AgentTrust-Authority-Event-Id",
    "X-AgentTrust-Payload-Digest",
):
    assert marker in domain_review_producer, f"executable review producer missing: {marker}"
for marker in (
    "/v1/domain-runtime/approval-review-evidence",
    "domain-runtime:approval-review-evidence",
    "review-evidence-issue.schema.json",
):
    assert marker in domain_review_openapi, f"review producer OpenAPI drift: {marker}"
assert "router(authority.clone(),tokens,runtime)" in domain_review_binary
assert "domain-runtime:approval-review-evidence" in (
    domain_token_schema["properties"]["bindings"]["items"]["properties"]["scope"]["enum"]
)
assert "SigningKey" not in domain_review_producer
for marker in (
    '"review_context", "review_evidence"', "agenttrust.enterprise-approval-case.v2",
    "signedApprovalReviewEvidence",
):
    assert marker in approval_gateway, f"Java approval v2 binding missing: {marker}"
for marker in (
    "agenttrust.approval-decision-result.v1",
    "agenttrust.approval-decision-evidence.v1",
    "agenttrust.approval-decision-request-binding.v1",
    "APPROVAL_DECISION_EVIDENCE",
    "authority_request_digest",
    "approval_case_digest",
    "signatures.verifyFresh(",
    "signatures.verifyPersisted(",
    "requirePersistedReplay(",
):
    assert marker in approval_decision_verifier, (
        f"Java approval decision receipt verification missing: {marker}"
    )
for marker in (
    "agenttrust.approval-decision-evidence-keyring.v1",
    "ACTIVE", "VERIFY_ONLY", "Signature.getInstance(\"Ed25519\")",
    "!persistedReplay && !\"ACTIVE\".equals(selected.status())",
):
    assert marker in approval_signature_verifier, (
        f"Java approval authority keyring missing: {marker}"
    )
for marker in (
    "response_payload::text", "response_payload=CAST(? AS jsonb)",
    "pep_policy_digest", "pep_evidence_ref",
):
    assert marker in approval_repository, f"approval replay payload persistence missing: {marker}"
for marker in (
    "pep_policy_digest", "pep_evidence_ref",
    "enterprise_approval_intent_pep_evidence_check", "NOT VALID",
    "'{evidence_receipt,actor_subject}' = actor_subject",
    "'{evidence_receipt,decision_reason_digest}'",
    "= reason_digest::text",
):
    assert marker in approval_intent_migration, (
        f"approval PEP evidence migration binding missing: {marker}"
    )
assert re.search(
    r"enterprise_approval_intent_pep_evidence_check.*?CHECK\s*\(\s*COALESCE\s*\(",
    approval_intent_migration,
    flags=re.DOTALL,
), "approval PEP evidence CHECK must fail closed on SQL NULL"
for marker in ("var pepDecision = pep.authorizeApproval", "intent, pepDecision"):
    assert marker in approval_service, f"approval PEP evidence persistence missing: {marker}"
assert "x-agenttrust-max-utf8-bytes: 4096" in openapi
assert "new TextEncoder().encode(value.reason).byteLength > 4_096" in typescript_client
assert "reason.getBytes(StandardCharsets.UTF_8).length > 4_096" in java_models
assert "markApprovalEvidencePending" not in approval_gateway
for marker in (
    "ApprovalIntentReceipt", "agenttrust.approval-intent-receipt.v1",
    "CONTROL_APPROVAL_RECEIPT_INVALID", "agenttrust.safe-error.v1",
    "SAFE_ERROR_FIELDS", "UTC_INSTANT",
):
    assert marker in openapi or marker in typescript_client or marker in generated, (
        f"browser approval receipt closure missing: {marker}"
    )
assert "        SafeError:" in generated
for marker in (
    "Character::isISOControl", "AUTHORITY_EVIDENCE_RECEIPT", "expectedReference",
    "agenttrust.signed-authority-evidence-receipt.v1",
):
    assert marker in approval_json, f"Java review evidence guard missing: {marker}"
for field in (
    "diff_artifact_ref", "command_summary", "network_scope", "rollback_summary",
    "current_value", "target_value", "allowed_range", "interlock_summary", "physical_impact",
):
    for source in (approval_openapi, approval_browser, approval_view):
        assert field in source, f"approval review field drift: {field}"
for marker in ("raw_command", "production-secret", "evidence_refs.length !== 3"):
    assert marker in approval_tests or marker in approval_browser, (
        f"approval browser negative contract missing: {marker}"
    )
deployment = (root / "deploy/kubernetes/production-stack.yaml.tmpl").read_text(encoding="utf-8")
approval_deployment = deployment.split(
    "kind: Deployment\nmetadata:\n  name: agenttrust-approval", 1
)[1].split("---", 1)[0]
assert "strategy: {type: Recreate}" in approval_deployment
assert "AGENT_TRUST_APPROVAL_REVIEW_EVIDENCE_KEYRING_FILE" in approval_deployment
assert "name: AGENT_TRUST_APPROVAL_EVIDENCE_PRIVATE_KEY," not in approval_deployment
assert "name: AGENT_TRUST_APPROVAL_EVIDENCE_TOKEN," not in approval_deployment
assert "enterprise-approval/0036_01_25_approval_review_evidence_v2.sql" in (
    root / "migrations/manifest.txt"
).read_text(encoding="utf-8")

contracts_rust = (root / "rust/crates/contracts/src/lib.rs").read_text(encoding="utf-8")
execution_openapi = (root / "schemas/openapi/execution-v1.yaml").read_text(encoding="utf-8")
evaluation_schema = json.loads(
    (root / "schemas/evidence/evaluation-request.schema.json").read_text(encoding="utf-8")
)
authority_event_schema = json.loads(
    (root / "schemas/evidence/authority-evidence-event-request.schema.json").read_text(
        encoding="utf-8"
    )
)
evidence_openapi = (root / "schemas/openapi/evidence-v1.yaml").read_text(encoding="utf-8")
assert "ApprovalReviewPrepared" in contracts_rust
for source in (approval_openapi, execution_openapi, json.dumps(evaluation_schema), evidence_openapi):
    assert "APPROVAL_REVIEW_PREPARED" in source, "shared EvidenceEventType drift"
expected_evidence_event_types = {
    "TASK_CREATED", "PLAN_GENERATED", "POLICY_EVALUATED", "APPROVAL_DECISION",
    "APPROVAL_REVIEW_PREPARED", "CREDENTIAL_ISSUED", "TOOL_PREPARED", "TOOL_EXECUTED",
    "COMPENSATION", "EVALUATION", "SECURITY_ALERT", "STATE_TRANSITION", "AUDIT_QUERY",
    "AUDIT_EXPORT", "LEGAL_HOLD", "RETENTION_DELETION",
}
event_enum_match = re.search(
    r"event_type:\s*\{enum:\s*\[([^\]]+)\]\}", execution_openapi
)
assert event_enum_match is not None
assert {value.strip() for value in event_enum_match.group(1).split(",")} == (
    expected_evidence_event_types
)
assert set(evaluation_schema["properties"]["required_event_types"]["items"]["enum"]) == (
    expected_evidence_event_types
)
assert authority_event_schema["properties"]["event"]["allOf"][0]["$ref"].endswith(
    "execution-v1.yaml#/components/schemas/EvidenceEventDraft"
)

for authority, contract in production_runtime_contracts.items():
    service_openapi = (root / "schemas/openapi" / contract["openapi"]).read_text(encoding="utf-8")
    server_source = (root / "rust/crates" / contract["server"]).read_text(encoding="utf-8")
    authority_source = (root / "rust/crates" / contract["authority"]).read_text(encoding="utf-8")
    binary_source = (root / "rust/crates" / contract["binary"]).read_text(encoding="utf-8")
    dockerfile = (root / contract["dockerfile"]).read_text(encoding="utf-8")
    contract_text = service_openapi
    if contract["page_contract"] is not None:
        contract_text += (root / "schemas" / contract["page_contract"]).read_text(encoding="utf-8")
    assert contract["path"] in server_source and contract["path"] in service_openapi
    assert contract["page_schema"] in authority_source and contract["page_schema"] in contract_text
    assert contract["cursor"] in authority_source and contract["cursor"] in contract_text
    assert bff_paths.get(authority) == contract["path"], f"BFF route drift: {authority}"
    assert bff_schemas.get(authority) == contract["page_schema"], f"BFF page schema drift: {authority}"
    assert bff_cursors.get(authority) == contract["cursor"], f"BFF cursor drift: {authority}"
    assert f':{contract["data_port"]}' in service_openapi, f"OpenAPI data port drift: {authority}"
    readiness_operation = service_openapi.split("\n  /ready:\n", 1)[1].split("\n  /", 1)[0]
    assert "security:" in readiness_operation and "mutual" in readiness_operation
    assert "bearer" not in readiness_operation.lower(), f"readiness bearer drift: {authority}"
    readiness_contract = readiness_operation
    readiness_ref = re.search(r"\$ref:\s*['\"]?([^'\"\s}]+)", readiness_operation)
    if readiness_ref is not None and readiness_ref.group(1).startswith("../"):
        readiness_contract += (root / "schemas/openapi" / readiness_ref.group(1)).resolve().read_text(
            encoding="utf-8"
        )
    elif readiness_ref is not None and readiness_ref.group(1).startswith("#/"):
        readiness_contract += service_openapi
    assert contract["readiness"] in readiness_contract, f"OpenAPI readiness schema drift: {authority}"
    for field in contract["readiness_fields"]:
        assert field in readiness_contract, f"OpenAPI readiness field drift: {authority}: {field}"
    assert f'EXPOSE {contract["data_port"]} {contract["management_port"]}' in dockerfile
    for marker in contract["port_markers"]:
        assert marker in binary_source, f"fixed runtime port missing: {authority}: {marker}"
    ready_handler = re.search(
        r"async fn data_ready\b(.*?)(?=\n(?:async fn |#\[derive|struct ))",
        server_source, re.DOTALL,
    )
    assert ready_handler is not None, f"data readiness handler missing: {authority}"
    assert ".authorize(" not in ready_handler.group(1) and "exact_tenant" not in ready_handler.group(1), (
        f"BFF-incompatible tenant bearer requirement on readiness: {authority}"
    )
    readiness_entry = re.search(
        rf'Map\.entry\("{re.escape(contract["readiness"])}",\s*Set\.of\((.*?)\)\)',
        readiness, re.DOTALL,
    )
    assert readiness_entry is not None, f"BFF readiness schema missing: {authority}"
    readiness_fields = set(re.findall(r'"([a-z_]+)"', readiness_entry.group(1)))
    assert readiness_fields == contract["readiness_fields"], f"BFF readiness field drift: {authority}"
    assert contract["readiness_fields"] in rust_readiness_field_sets(server_source), (
        f"Rust readiness field drift: {authority}"
    )
for browser_file in (typescript_client,
    (root / "web/control-console/src/components/IncidentConsole.vue").read_text(encoding="utf-8"),
    (root / "web/control-console/src/components/PackMarketplace.vue").read_text(encoding="utf-8")):
    assert "X-AgentTrust-Human-Assertion" not in browser_file
    assert not re.search(r"[\"']Authorization[\"']\s*:", browser_file)
    assert "Bearer " not in browser_file

incident_schema = json.loads((root / "schemas/incidents/incident-command.schema.json").read_text(encoding="utf-8"))
marketplace_schema = json.loads((root / "schemas/marketplace/command.schema.json").read_text(encoding="utf-8"))
incident_operations = set(incident_schema["properties"]["operation"]["enum"]) - {"DETECT"}
marketplace_kinds = {
    value["properties"]["kind"]["const"]
    for value in marketplace_schema["$defs"].values()
    if isinstance(value, dict) and "kind" in value.get("properties", {})
}
assert len(incident_operations) == 14, "human Incident operation count drift"
assert len(marketplace_kinds) == 16, "typed Marketplace command count drift"
incident_browser = (root / "web/control-console/src/incident-command.ts").read_text(encoding="utf-8")
marketplace_browser = (root / "web/control-console/src/marketplace-command.ts").read_text(encoding="utf-8")
for operation in incident_operations:
    for source in (openapi, generated, incident_gateway, incident_browser):
        assert f'"{operation}"' in source or operation in source, f"Incident operation missing: {operation}"
for kind in marketplace_kinds:
    for source in (openapi, generated, pack_gateway, marketplace_browser):
        assert f'"{kind}"' in source or kind in source, f"Marketplace kind missing: {kind}"

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
