package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.ApiKeyIssueResponse;
import com.agenttrust.control.AdminModels.CostUsageRequest;
import com.agenttrust.control.AdminModels.DashboardResponse;
import com.agenttrust.control.AdminModels.IntegrationRequest;
import com.agenttrust.control.AdminModels.OrganizationRequest;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.ProjectRequest;
import com.agenttrust.control.AdminModels.QuotaConsumeRequest;
import com.agenttrust.control.AdminModels.QuotaUsageResponse;
import com.agenttrust.control.AdminModels.TenantRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
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

    public EnterpriseController(EnterpriseService service, AuthoritativeBff bff) {
        this.service = service;
        this.bff = bff;
    }

    @PostMapping
    ResponseEntity<Void> createTenant(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedTenantRequest request) {
        requireIdempotencyKey(key);
        service.createTenant(principal(jwt, tenantId), request.tenant(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId)).build();
    }

    @PostMapping("/organizations")
    ResponseEntity<Void> createOrganization(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedOrganizationRequest request) {
        requireIdempotencyKey(key);
        service.createOrganization(principal(jwt, tenantId), request.organization(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId
            + "/organizations/" + request.organization().organizationId())).build();
    }

    @PostMapping("/projects")
    ResponseEntity<Void> createProject(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedProjectRequest request) {
        requireIdempotencyKey(key);
        service.createProject(principal(jwt, tenantId), request.project(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId
            + "/projects/" + request.project().projectId())).build();
    }

    @PostMapping("/integrations")
    ResponseEntity<Void> createIntegration(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedIntegrationRequest request) {
        requireIdempotencyKey(key);
        service.createIntegration(principal(jwt, tenantId), request.integration(), request.intent(), request.reason(), key);
        return ResponseEntity.created(URI.create("/v1/tenants/" + tenantId
            + "/integrations/" + request.integration().integrationId())).build();
    }

    @PostMapping("/quota/consume")
    QuotaUsageResponse consumeQuota(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedQuotaRequest request) {
        requireIdempotencyKey(key);
        return service.consumeQuota(principal(jwt, tenantId), request.quota(), request.intent(), request.reason(), key);
    }

    @PostMapping("/costs")
    ResponseEntity<Void> recordCost(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedCostRequest request) {
        requireIdempotencyKey(key);
        service.recordCost(principal(jwt, tenantId), request.cost(), request.intent(), request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @PostMapping("/api-keys")
    ResponseEntity<ApiKeyIssueResponse> issueApiKey(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedApiKeyIssueRequest request) {
        requireIdempotencyKey(key);
        return ResponseEntity.status(HttpStatus.CREATED)
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body(service.issueApiKey(principal(jwt, tenantId), request.apiKey(),
                request.intent(), request.reason(), key));
    }

    @PostMapping("/api-keys/{apiKeyId}/revoke")
    ResponseEntity<Void> revokeApiKey(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @PathVariable UUID apiKeyId,
        @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedAdminIntent request) {
        requireIdempotencyKey(key);
        service.revokeApiKey(principal(jwt, tenantId), apiKeyId, request.intent(), request.reason(), key);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/dashboard")
    DashboardResponse dashboard(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID tenantId,
        @RequestParam(defaultValue = "summary") String resource,
        @RequestParam(defaultValue = "50") int limit) {
        return bff.dashboard(principal(jwt, tenantId), resource, limit);
    }

    @PostMapping("/admin/actions")
    ResponseEntity<Void> submitIntent(@AuthenticationPrincipal Jwt jwt,
        @PathVariable UUID tenantId, @RequestHeader("Idempotency-Key") String key,
        @Valid @RequestBody GovernedAdminIntent request) {
        requireIdempotencyKey(key);
        service.submitIntent(principal(jwt, tenantId), request.intent(), request.reason(), key);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    private static PrincipalContext principal(Jwt jwt, UUID pathTenant) {
        UUID tokenTenant;
        try { tokenTenant = UUID.fromString(jwt.getClaimAsString("tenant_id")); }
        catch (RuntimeException error) {
            throw new ControlDeniedException("CONTROL_TENANT_CLAIM_INVALID", error);
        }
        if (!pathTenant.equals(tokenTenant)) {
            throw new ControlDeniedException("CONTROL_CROSS_TENANT_DENIED");
        }
        List<String> roles = jwt.getClaimAsStringList("roles");
        List<String> projects = jwt.getClaimAsStringList("project_ids");
        return new PrincipalContext(jwt.getSubject(), tokenTenant,
            Set.copyOf(roles == null ? List.of() : roles),
            Set.copyOf(projects == null ? List.of() : projects));
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
}
