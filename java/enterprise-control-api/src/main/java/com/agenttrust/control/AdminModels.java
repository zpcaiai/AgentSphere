package com.agenttrust.control;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class AdminModels {
    private AdminModels() {}

    public record PrincipalContext(String subject, UUID tenantId, Set<String> roles, Set<String> projectIds) {
        public PrincipalContext {
            roles = Set.copyOf(roles);
            projectIds = Set.copyOf(projectIds);
        }
    }

    public record OrganizationRequest(@NotBlank @Size(max = 200) String organizationId,
                                      @NotBlank @Size(max = 200) String displayName,
                                      @NotBlank @Size(max = 300) String sponsorSubject) {}

    public record QuotaSpec(@Positive int maximumActiveTasks,
                            @Positive int maximumExportRecords,
                            @Positive int maximumWebhooks,
                            @Positive int maximumApiRequestsPerMinute) {}

    public record TenantRequest(@NotBlank @Size(max = 200) String displayName,
                                @NotBlank @Size(max = 300) String ownerSubject,
                                @NotBlank @Pattern(regexp = "^[A-Z]{2}(-[A-Z0-9]{1,8})?$") String dataRegion,
                                @NotNull @jakarta.validation.Valid QuotaSpec quota) {}

    public record ProjectRequest(@NotBlank @Size(max = 200) String projectId,
                                 @NotBlank @Size(max = 200) String organizationId,
                                 @NotBlank @Size(max = 300) String ownerSubject,
                                 @NotEmpty @Size(max = 20)
                                 Set<@Pattern(regexp = "^[a-z][a-z0-9-]{0,62}$") String> environments) {
        public ProjectRequest { environments = Set.copyOf(environments); }
    }

    public record IntegrationRequest(@NotNull UUID integrationId,
                                     @NotBlank @Pattern(regexp = "^(IAM|NOTIFICATION|TICKETING|SIEM|WEBHOOK)$")
                                     String kind,
                                     @NotNull URI endpoint,
                                     @NotBlank @Size(max = 1000) String secretRef,
                                     @NotBlank @Pattern(regexp = "^[a-f0-9]{64}$") String configurationDigest,
                                     boolean active) {}

    public record QuotaConsumeRequest(@NotBlank @Size(max = 100) String quotaKey,
                                      @NotNull Instant windowStartedAt,
                                      @Positive long amount,
                                      @Positive long limit) {}

    public record QuotaUsageResponse(String schemaVersion, UUID tenantId, String quotaKey,
                                     Instant windowStartedAt, long used, long limit) {}

    public record CostUsageRequest(@NotNull UUID usageId,
                                   @NotBlank @Size(max = 200) String projectId,
                                   @NotBlank @Size(max = 100) String meter,
                                   @Positive long quantity,
                                   @PositiveOrZero long unitCostMicros,
                                   @NotBlank @Pattern(regexp = "^[a-f0-9]{64}$") String sourceDigest,
                                   @NotNull Instant recordedAt) {}

    public record ApiKeyIssueRequest(String projectId,
                                     @NotEmpty @Size(max = 64)
                                     Set<@Pattern(regexp = "^[a-z][a-z0-9:_-]{0,99}$") String> scopes,
                                     @NotNull Instant expiresAt) {
        public ApiKeyIssueRequest { scopes = Set.copyOf(scopes); }
    }

    public record ApiKeyIssueResponse(String schemaVersion, UUID apiKeyId, String oneTimeSecret,
                                      Instant createdAt, Instant expiresAt, Set<String> scopes) {}

    public record AdminIntent(@JsonProperty("schema_version") @NotBlank String schemaVersion,
                              @NotNull UUID actionId,
                              @NotNull UUID tenantId,
                              String projectId,
                              @NotBlank @Size(max = 100) String operation,
                              @NotBlank @Size(max = 1000) String resource,
                              @NotBlank @Size(max = 300) String requestedBy,
                              @Size(max = 16) Set<String> approvalIds,
                              @NotBlank @Pattern(regexp = "^[a-f0-9]{64}$") String actionDigest,
                              @NotNull Instant requestedAt) {
        public AdminIntent { approvalIds = approvalIds == null ? Set.of() : Set.copyOf(approvalIds); }
    }

    public record AuthorizationDecision(String decision, @JsonProperty("policy_digest") String policyDigest,
                                        @JsonProperty("evidence_ref") String evidenceRef,
                                        @JsonProperty("reason_codes") List<String> reasonCodes) {
        public boolean allowed() {
            return "ALLOW".equals(decision)
                && policyDigest != null && policyDigest.matches("[a-f0-9]{64}")
                && evidenceRef != null && !evidenceRef.isBlank();
        }
    }

    public record AuthorityView(@JsonProperty("schema_version") String schemaVersion,
                                String section, boolean authoritative, boolean available,
                                Object data, String dataDigest, String safeErrorCode, Instant fetchedAt) {}

    public record DashboardResponse(@JsonProperty("schema_version") String schemaVersion,
                                    UUID tenantId, Map<String, AuthorityView> sections,
                                    boolean complete, Set<String> unavailableSections, Instant generatedAt) {}
}
