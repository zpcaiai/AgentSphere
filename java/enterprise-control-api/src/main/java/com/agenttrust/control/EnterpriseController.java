package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.ApiKeyIssueResponse;
import com.agenttrust.control.AdminModels.CostUsageRequest;
import com.agenttrust.control.AdminModels.DashboardResponse;
import com.agenttrust.control.AdminModels.IntegrationRequest;
import com.agenttrust.control.AdminModels.OrganizationRequest;
import com.agenttrust.control.AdminModels.ProjectRequest;
import com.agenttrust.control.AdminModels.QuotaConsumeRequest;
import com.agenttrust.control.AdminModels.QuotaUsageResponse;
import com.agenttrust.control.AdminModels.TenantRequest;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.agenttrust.control.AdminModels.PolicyPromotionRequest;
import com.agenttrust.control.AdminModels.PolicySimulationRequest;
import com.agenttrust.control.AdminModels.TaskCommand;
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
    private final AguiResumeService agui;
    private final AuthenticatedPrincipalResolver principals;

    public EnterpriseController(EnterpriseService service, AuthoritativeBff bff,
                                GovernedAuthorityGateway authorities,
                                AguiResumeService agui,
                                AuthenticatedPrincipalResolver principals) {
        this.service = service;
        this.bff = bff;
        this.authorities = authorities;
        this.agui = agui;
        this.principals = principals;
    }

    @PostMapping
    ResponseEntity<Void> createTenant(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedTenantRequest request) {
        requireIdempotencyKey(key);
        service.createTenant(principals.resolve(authentication, tenantId), request.tenant(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId)).build();
    }

    @PostMapping("/organizations")
    ResponseEntity<Void> createOrganization(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedOrganizationRequest request) {
        requireIdempotencyKey(key);
        service.createOrganization(principals.resolve(authentication, tenantId), request.organization(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId
            + "/organizations/" + request.organization().organizationId())).build();
    }

    @PostMapping("/projects")
    ResponseEntity<Void> createProject(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedProjectRequest request) {
        requireIdempotencyKey(key);
        service.createProject(principals.resolve(authentication, tenantId), request.project(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId
            + "/projects/" + request.project().projectId())).build();
    }

    @PostMapping("/integrations")
    ResponseEntity<Void> createIntegration(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedIntegrationRequest request) {
        requireIdempotencyKey(key);
        service.createIntegration(principals.resolve(authentication, tenantId), request.integration(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId
            + "/integrations/" + request.integration().integrationId())).build();
    }

    @PostMapping("/quota/consume")
    QuotaUsageResponse consumeQuota(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedQuotaRequest request) {
        requireIdempotencyKey(key);
        return service.consumeQuota(principals.resolve(authentication, tenantId), request.quota(), request.intent(), request.reason(), key);
    }

    @PostMapping("/costs")
    ResponseEntity<Void> recordCost(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedCostRequest request) {
        requireIdempotencyKey(key);
        service.recordCost(principals.resolve(authentication, tenantId), request.cost(), request.intent(), request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @PostMapping("/api-keys")
    ResponseEntity<ApiKeyIssueResponse> issueApiKey(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedApiKeyIssueRequest request) {
        requireIdempotencyKey(key);
        return ResponseEntity.status(HttpStatus.CREATED)
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body(service.issueApiKey(principals.resolve(authentication, tenantId), request.apiKey(),
                request.intent(), request.reason(), key));
    }

    @PostMapping("/api-keys/{apiKeyId}/revoke")
    ResponseEntity<Void> revokeApiKey(Authentication authentication,
        @PathVariable UUID tenantId, @PathVariable UUID apiKeyId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedAdminIntent request) {
        requireIdempotencyKey(key);
        service.revokeApiKey(principals.resolve(authentication, tenantId), apiKeyId, request.intent(), request.reason(), key);
        return ResponseEntity.noContent().build();
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

    @PostMapping("/policies/{bundleId}/simulate")
    JsonNode simulatePolicyBundle(Authentication authentication, @PathVariable UUID tenantId,
        @PathVariable String bundleId, @Valid @RequestBody PolicySimulationRequest request) {
        return authorities.simulatePolicy(principals.resolve(authentication, tenantId), bundleId, request);
    }

    @PostMapping("/policies/{bundleId}/promotions")
    ResponseEntity<Void> promotePolicyBundle(Authentication authentication,
        @PathVariable UUID tenantId, @PathVariable String bundleId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedPolicyPromotion request) {
        requireIdempotencyKey(key);
        authorities.promotePolicy(principals.resolve(authentication, tenantId), bundleId, request.promotion(),
            request.intent(), request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @PostMapping("/approvals/{caseId}/intents")
    ResponseEntity<Void> submitApprovalIntent(Authentication authentication,
        @PathVariable UUID tenantId, @PathVariable UUID caseId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody ApprovalIntentEnvelope request) {
        requireIdempotencyKey(key);
        authorities.submitApprovalIntent(principals.resolve(authentication, tenantId), caseId,
            request.approvalIntent(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
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
    ResponseEntity<Void> submitIntent(Authentication authentication,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedAdminIntent request) {
        requireIdempotencyKey(key);
        service.submitIntent(principals.resolve(authentication, tenantId), request.intent(), request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    private static void requireIdempotencyKey(String key) {
        if (key == null || key.length() < 16 || key.length() > 128) {
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
    public record GovernedPolicyPromotion(
        @jakarta.validation.constraints.NotNull @Valid PolicyPromotionRequest promotion,
        @jakarta.validation.constraints.NotNull @Valid AdminIntent intent,
        @jakarta.validation.constraints.NotBlank
        @jakarta.validation.constraints.Size(max = 2000) String reason) {}
    public record ApprovalIntentEnvelope(
        @com.fasterxml.jackson.annotation.JsonProperty("approval_intent")
        @jakarta.validation.constraints.NotNull @Valid ApprovalIntent approvalIntent) {}
}
