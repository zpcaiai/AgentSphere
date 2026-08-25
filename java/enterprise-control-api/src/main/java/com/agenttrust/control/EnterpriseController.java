package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.CostUsageRequest;
import com.agenttrust.control.AdminModels.DashboardResponse;
import com.agenttrust.control.AdminModels.EnterpriseActionReceipt;
import com.agenttrust.control.AdminModels.IntegrationRequest;
import com.agenttrust.control.AdminModels.OrganizationRequest;
import com.agenttrust.control.AdminModels.ProjectRequest;
import com.agenttrust.control.AdminModels.QuotaConsumeRequest;
import com.agenttrust.control.AdminModels.TenantRequest;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.agenttrust.control.AdminModels.ApprovalIntentReceipt;
import com.agenttrust.control.AdminModels.PolicyCommandRequest;
import com.agenttrust.control.AdminModels.TaskCommand;
import com.agenttrust.control.IncidentModels.IncidentCommandRequest;
import com.agenttrust.control.MarketplaceModels.MarketplaceCommandRequest;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/tenants/{tenantId}")
public final class EnterpriseController {
    private final EnterpriseService service;
    private final AuthoritativeBff bff;
    private final GovernedAuthorityGateway authorities;
    private final PolicyAuthorityGateway policyAuthority;
    private final IncidentAuthorityGateway incidentAuthority;
    private final PackMarketplaceGateway packMarketplace;
    private final AguiResumeService agui;
    private final AuthenticatedPrincipalResolver principals;

    public EnterpriseController(EnterpriseService service, AuthoritativeBff bff,
                                GovernedAuthorityGateway authorities,
                                PolicyAuthorityGateway policyAuthority,
                                IncidentAuthorityGateway incidentAuthority,
                                PackMarketplaceGateway packMarketplace,
                                AguiResumeService agui,
                                AuthenticatedPrincipalResolver principals) {
        this.service = service;
        this.bff = bff;
        this.authorities = authorities;
        this.policyAuthority = policyAuthority;
        this.incidentAuthority = incidentAuthority;
        this.packMarketplace = packMarketplace;
        this.agui = agui;
        this.principals = principals;
    }

    @PostMapping
    ResponseEntity<EnterpriseActionReceipt> createTenant(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedTenantRequest request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.createTenant(principals.resolve(authentication, tenantId),
            request.tenant(), request.intent(), request.reason(), key));
    }

    @PostMapping("/organizations")
    ResponseEntity<EnterpriseActionReceipt> createOrganization(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedOrganizationRequest request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.createOrganization(
            principals.resolve(authentication, tenantId), request.organization(), request.intent(),
            request.reason(), key));
    }

    @PostMapping("/projects")
    ResponseEntity<EnterpriseActionReceipt> createProject(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedProjectRequest request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.createProject(principals.resolve(authentication, tenantId),
            request.project(), request.intent(), request.reason(), key));
    }

    @PostMapping("/integrations")
    ResponseEntity<EnterpriseActionReceipt> createIntegration(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedIntegrationRequest request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.createIntegration(
            principals.resolve(authentication, tenantId), request.integration(), request.intent(),
            request.reason(), key));
    }

    @PostMapping("/quota/consume")
    ResponseEntity<EnterpriseActionReceipt> consumeQuota(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedQuotaRequest request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.consumeQuota(principals.resolve(authentication, tenantId),
            request.quota(), request.intent(), request.reason(), key));
    }

    @PostMapping("/costs")
    ResponseEntity<EnterpriseActionReceipt> recordCost(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedCostRequest request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.recordCost(principals.resolve(authentication, tenantId),
            request.cost(), request.intent(), request.reason(), key));
    }

    @PostMapping("/api-keys")
    ResponseEntity<EnterpriseActionReceipt> issueApiKey(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedApiKeyIssueRequest request) {
        requireIdempotencyKey(key);
        EnterpriseActionReceipt receipt = service.issueApiKey(
            principals.resolve(authentication, tenantId), request.apiKey(), request.intent(),
            request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .location(taskLocation(tenantId, receipt))
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body(receipt);
    }

    @PostMapping("/api-keys/{apiKeyId}/revoke")
    ResponseEntity<EnterpriseActionReceipt> revokeApiKey(Authentication authentication,
        @PathVariable UUID tenantId, @PathVariable UUID apiKeyId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedAdminIntent request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.revokeApiKey(principals.resolve(authentication, tenantId),
            apiKeyId, request.intent(), request.reason(), key));
    }

    @GetMapping("/dashboard")
    DashboardResponse dashboard(Authentication authentication, @PathVariable UUID tenantId,
        @RequestParam(defaultValue = "summary") String resource,
        @RequestParam(defaultValue = "50") int limit) {
        return bff.dashboard(principals.resolve(authentication, tenantId), resource, limit);
    }

    @GetMapping("/agents")
    JsonNode listAgentInventory(Authentication authentication, @PathVariable UUID tenantId,
                                @RequestParam(required = false) String cursor,
                                @RequestParam(defaultValue = "50") int limit) {
        return authorities.listAgents(principals.resolve(authentication, tenantId), cursor, limit);
    }

    @PostMapping("/tasks/{taskId}/commands")
    ResponseEntity<Void> submitTaskCommand(Authentication authentication,
        @PathVariable UUID tenantId, @PathVariable String taskId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedTaskCommand request) {
        requireIdempotencyKey(key);
        authorities.submitTaskCommand(principals.resolve(authentication, tenantId), taskId, request.command(),
            request.intent(), request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @GetMapping("/policies")
    JsonNode listPolicies(Authentication authentication, @PathVariable UUID tenantId,
        @RequestParam(name = "after_policy_id", required = false) String afterPolicyId,
        @RequestParam(defaultValue = "50") int limit) {
        return policyAuthority.listPolicies(principals.resolve(authentication, tenantId),
            afterPolicyId, limit);
    }

    @GetMapping("/policies/{policyId}/{artifactPath:sources|analyses|reviews|simulations|impact-reports|promotions|exceptions}")
    JsonNode listPolicyArtifacts(Authentication authentication, @PathVariable UUID tenantId,
        @PathVariable String policyId, @PathVariable String artifactPath,
        @RequestParam(defaultValue = "50") int limit) {
        return policyAuthority.listArtifacts(principals.resolve(authentication, tenantId), policyId,
            PolicyAuthorityGateway.ArtifactType.fromPath(artifactPath), limit);
    }

    @PostMapping("/policies/actions")
    ResponseEntity<JsonNode> submitPolicyAction(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody PolicyCommandRequest request) {
        requireIdempotencyKey(key);
        JsonNode receipt = policyAuthority.submitAction(
            principals.resolve(authentication, tenantId), request, key);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .location(URI.create("/v1/tenants/" + tenantId + "/tasks/"
                + receipt.path("task_id").textValue() + "/agui/snapshot"))
            .header("Cache-Control", "no-store").header("Pragma", "no-cache").body(receipt);
    }

    @GetMapping("/incidents")
    ResponseEntity<JsonNode> listIncidents(Authentication authentication, @PathVariable UUID tenantId,
        @RequestParam(name = "after_incident_id", required = false) String afterIncidentId,
        @RequestParam(defaultValue = "50") int limit) {
        return noStore(incidentAuthority.list(principals.resolve(authentication, tenantId),
            afterIncidentId, limit));
    }

    @GetMapping("/incidents/{incidentId}")
    ResponseEntity<JsonNode> getIncident(Authentication authentication, @PathVariable UUID tenantId,
        @PathVariable UUID incidentId) {
        return noStore(incidentAuthority.detail(
            principals.resolve(authentication, tenantId), incidentId));
    }

    @PostMapping("/incidents/actions")
    ResponseEntity<JsonNode> submitIncidentAction(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody IncidentCommandRequest request) {
        requireIdempotencyKey(key);
        JsonNode receipt = incidentAuthority.submit(
            principals.resolve(authentication, tenantId), request, key);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .location(URI.create("/v1/tenants/" + tenantId + "/tasks/"
                + receipt.path("task_id").textValue() + "/agui/snapshot"))
            .header("Cache-Control", "no-store").header("Pragma", "no-cache").body(receipt);
    }

    @GetMapping("/packs")
    ResponseEntity<JsonNode> listPacks(Authentication authentication, @PathVariable UUID tenantId,
        @RequestParam(required = false) String query,
        @RequestParam(name = "after_pack_id", required = false) String afterPackId,
        @RequestParam(defaultValue = "50") int limit) {
        return noStore(packMarketplace.list(principals.resolve(authentication, tenantId), query,
            afterPackId, limit));
    }

    @PostMapping("/packs/actions")
    ResponseEntity<JsonNode> submitPackAction(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody MarketplaceCommandRequest request) {
        requireIdempotencyKey(key);
        JsonNode receipt = packMarketplace.submit(
            principals.resolve(authentication, tenantId), request, key);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .location(URI.create("/v1/tenants/" + tenantId + "/tasks/"
                + receipt.path("task_id").textValue() + "/agui/snapshot"))
            .header("Cache-Control", "no-store").header("Pragma", "no-cache").body(receipt);
    }

    @PostMapping("/approvals/{caseId}/intents")
    ResponseEntity<ApprovalIntentReceipt> submitApprovalIntent(Authentication authentication,
        @PathVariable UUID tenantId, @PathVariable UUID caseId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody ApprovalIntentEnvelope request) {
        requireIdempotencyKey(key);
        ApprovalIntentReceipt receipt = authorities.submitApprovalIntent(
            principals.resolve(authentication, tenantId), caseId,
            request.approvalIntent(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .header("Cache-Control", "no-store").header("Pragma", "no-cache").body(receipt);
    }

    @GetMapping("/tasks/{taskId}/agui/events")
    JsonNode resumeAguiEvents(Authentication authentication, @PathVariable UUID tenantId,
        @PathVariable String taskId, @RequestParam(name = "resume_token", required = false)
        String resumeToken, @RequestParam(defaultValue = "100") int limit) {
        return agui.resume(principals.resolve(authentication, tenantId), taskId, resumeToken, limit);
    }

    @GetMapping("/tasks/{taskId}/agui/snapshot")
    JsonNode safeAguiSnapshot(Authentication authentication, @PathVariable UUID tenantId,
                             @PathVariable String taskId) {
        return agui.snapshot(principals.resolve(authentication, tenantId), taskId);
    }

    @PostMapping("/admin/actions")
    ResponseEntity<EnterpriseActionReceipt> submitIntent(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedAdminIntent request) {
        requireIdempotencyKey(key);
        return accepted(tenantId, service.submitIntent(principals.resolve(authentication, tenantId),
            request.intent(), request.reason(), key));
    }

    private static ResponseEntity<EnterpriseActionReceipt> accepted(
        UUID tenantId, EnterpriseActionReceipt receipt
    ) {
        return ResponseEntity.status(HttpStatus.ACCEPTED)
            .location(taskLocation(tenantId, receipt))
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body(receipt);
    }

    private static ResponseEntity<JsonNode> noStore(JsonNode body) {
        return ResponseEntity.ok().header("Cache-Control", "no-store")
            .header("Pragma", "no-cache").body(body);
    }

    private static URI taskLocation(UUID tenantId, EnterpriseActionReceipt receipt) {
        return URI.create("/v1/tenants/" + tenantId + "/tasks/" + receipt.taskId()
            + "/agui/snapshot");
    }

    private static void requireIdempotencyKey(String key) {
        if (key == null || !key.matches("[A-Za-z0-9._:-]{16,128}")) {
            throw new ControlDeniedException("CONTROL_IDEMPOTENCY_KEY_INVALID");
        }
    }

    public record GovernedOrganizationRequest(@jakarta.validation.constraints.NotNull @Valid OrganizationRequest organization,
                                               @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                               @jakarta.validation.constraints.NotBlank
                                               @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedTenantRequest(@jakarta.validation.constraints.NotNull @Valid TenantRequest tenant,
                                        @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                        @jakarta.validation.constraints.NotBlank
                                        @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedProjectRequest(@jakarta.validation.constraints.NotNull @Valid ProjectRequest project,
                                         @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                         @jakarta.validation.constraints.NotBlank
                                         @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedIntegrationRequest(@jakarta.validation.constraints.NotNull @Valid IntegrationRequest integration,
                                             @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                             @jakarta.validation.constraints.NotBlank
                                             @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedQuotaRequest(@jakarta.validation.constraints.NotNull @Valid QuotaConsumeRequest quota,
                                       @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                       @jakarta.validation.constraints.NotBlank
                                       @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedCostRequest(@jakarta.validation.constraints.NotNull @Valid CostUsageRequest cost,
                                      @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                      @jakarta.validation.constraints.NotBlank
                                      @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedApiKeyIssueRequest(@jakarta.validation.constraints.NotNull @Valid ApiKeyIssueRequest apiKey,
                                             @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                             @jakarta.validation.constraints.NotBlank
                                             @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedAdminIntent(@jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                      @jakarta.validation.constraints.NotBlank
                                      @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record GovernedTaskCommand(@jakarta.validation.constraints.NotNull @Valid TaskCommand command,
                                      @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
                                      @jakarta.validation.constraints.NotBlank
                                      @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record ApprovalIntentEnvelope(
        @com.fasterxml.jackson.annotation.JsonProperty("approval_intent")
        @jakarta.validation.constraints.NotNull @Valid ApprovalIntent approvalIntent) {}
}
