package com.agenttrust.control;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

public final class AdminModels {
    private AdminModels() {}

    public record PrincipalContext(String subject, UUID tenantId, Set<String> roles,
                                   Set<String> projectIds, Set<String> approvalIds,
                                   Set<String> ownedResources, boolean strongAuth,
                                   Instant authenticationTime, String authenticationContext) {
        public PrincipalContext {
            roles = immutableSortedSet(roles);
            projectIds = immutableSortedSet(projectIds);
            approvalIds = immutableSortedSet(approvalIds);
            ownedResources = immutableSortedSet(ownedResources);
        }

        /** Compatibility constructor for non-approval unit fixtures; never asserts strong auth. */
        public PrincipalContext(String subject, UUID tenantId, Set<String> roles,
                                Set<String> projectIds, Set<String> approvalIds) {
            this(subject, tenantId, roles, projectIds, approvalIds, Set.of(), false, null, null);
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
        public ProjectRequest { environments = immutableSortedSet(environments); }
    }

    public record IntegrationRequest(@NotNull UUID integrationId,
                                     @NotBlank @Pattern(regexp = "^(IAM|NOTIFICATION|TICKETING|SIEM|WEBHOOK)$")
                                     String kind,
                                     @NotNull URI endpoint,
                                     @NotBlank @Size(max = 1000)
                                     @Pattern(regexp = "^(credential://[A-Za-z0-9._:/-]{1,900}|vault-kv://[A-Za-z0-9._/-]{1,900}#v[1-9][0-9]*)$")
                                     String secretRef,
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
        public ApiKeyIssueRequest { scopes = immutableSortedSet(scopes); }
    }

    /**
     * Durable acceptance from the enterprise action authority.  This is deliberately not a
     * business-operation result: {@code executionPending} remains true until the authoritative
     * task reaches a separately observed terminal state.
     */
    public record EnterpriseActionReceipt(
        @JsonProperty("schema_version") String schemaVersion,
        @JsonProperty("action_id") UUID actionId,
        @JsonProperty("task_id") UUID taskId,
        boolean accepted,
        @JsonProperty("start_requested") boolean startRequested,
        @JsonProperty("execution_pending") boolean executionPending,
        @JsonProperty("ingress_digest") String ingressDigest,
        @JsonProperty("evidence_ref") String evidenceRef,
        @JsonProperty("evidence_digest") String evidenceDigest) {}

    public record TaskCommand(@JsonProperty("schema_version") @NotBlank String schemaVersion,
                              @NotBlank @Size(max = 128) String commandId,
                              @NotBlank @Pattern(regexp = "^(START|PAUSE|RESUME|CANCEL|KILL|CHECKPOINT)$")
                              String commandType,
                              @PositiveOrZero long expectedStateVersion,
                              @NotBlank @Pattern(regexp = "^[a-f0-9]{64}$") String payloadDigest) {}

    /** Exact browser-to-Policy-Authority lifecycle command. Payload shape is operation-specific. */
    public record PolicyCommandRequest(
        @JsonProperty("schema_version")
        @NotBlank @Pattern(regexp = "^agenttrust\\.policy-command\\.v1$") String schemaVersion,
        @NotNull UUID tenantId,
        @NotNull UUID commandId,
        @NotBlank @Pattern(regexp = "^[A-Za-z0-9._:/-]{1,256}$") String policyId,
        @NotBlank @Pattern(regexp = "^(CREATE_DRAFT|VALIDATE|SIMULATE|SHADOW_EVALUATE|"
            + "IMPACT_ANALYZE|APPROVE|SIGN|PROMOTE|ROLLBACK|DEPRECATE|CREATE_EXCEPTION|"
            + "REVOKE_EXCEPTION)$") String operation,
        @PositiveOrZero long expectedResourceVersion,
        @NotNull JsonNode payload,
        @NotNull Instant requestedAt) {}

    /**
     * Durable Policy workflow admission. This is never a lifecycle mutation success result:
     * {@code executionPending} must remain true in the only accepted BFF response.
     */
    public record PolicyActionReceipt(
        @JsonProperty("schema_version") String schemaVersion,
        @JsonProperty("action_id") UUID actionId,
        @JsonProperty("task_id") UUID taskId,
        boolean accepted,
        @JsonProperty("execution_pending") boolean executionPending,
        @JsonProperty("ingress_digest") String ingressDigest,
        @JsonProperty("ledger_evidence_ref") String ledgerEvidenceRef,
        @JsonProperty("ledger_evidence_digest") String ledgerEvidenceDigest) {}

    public record ApprovalIntent(
        @JsonProperty("schema_version") @NotBlank String schemaVersion,
        @NotNull UUID caseId,
        @NotBlank @Pattern(regexp = "^(APPROVE|REJECT)$") String decision,
        @NotBlank String reason,
        @NotBlank @Pattern(regexp = "^[a-f0-9]{64}$") String observedActionHash,
        @NotBlank String observedResourceVersion) {
        public ApprovalIntent {
            if (reason != null
                && (reason.codePointCount(0, reason.length()) > 2_000
                    || reason.indexOf('\0') >= 0
                    || reason.getBytes(StandardCharsets.UTF_8).length > 4_096)) {
                throw new IllegalArgumentException("CONTROL_APPROVAL_REASON_TOO_LARGE");
            }
            if (observedResourceVersion != null
                && (observedResourceVersion.codePointCount(
                    0, observedResourceVersion.length()) > 512
                    || observedResourceVersion.indexOf('\0') >= 0
                    || observedResourceVersion.indexOf('\r') >= 0
                    || observedResourceVersion.indexOf('\n') >= 0)) {
                throw new IllegalArgumentException(
                    "CONTROL_APPROVAL_RESOURCE_VERSION_INVALID");
            }
        }
    }

    /**
     * Browser-safe projection of one independently signed Approval authority decision receipt.
     * The principal assertion, human reason and mutable full Approval case deliberately remain
     * server-side.
     */
    public record ApprovalIntentReceipt(
        @JsonProperty("schema_version") String schemaVersion,
        @JsonProperty("tenant_id") UUID tenantId,
        @JsonProperty("case_id") UUID caseId,
        String decision,
        @JsonProperty("action_hash") String actionHash,
        @JsonProperty("resource_version") String resourceVersion,
        @JsonProperty("case_status") String caseStatus,
        @JsonProperty("decided_at") Instant decidedAt,
        @JsonProperty("evidence_ref") String evidenceRef,
        @JsonProperty("evidence_digest") String evidenceDigest,
        @JsonProperty("authority_issuer") String authorityIssuer,
        @JsonProperty("authority_key_id") String authorityKeyId) {}

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
        public AdminIntent {
            approvalIds = approvalIds == null ? Set.of() : immutableSortedSet(approvalIds);
        }
    }

    public record AuthorizationDecision(String decision, @JsonProperty("policy_digest") String policyDigest,
                                        @JsonProperty("evidence_ref") String evidenceRef,
                                        @JsonProperty("reason_codes") List<String> reasonCodes) {
        public boolean allowed() {
            return "ALLOW".equals(decision)
                && policyDigest != null && policyDigest.matches("[a-f0-9]{64}")
                && evidenceRef != null
                && evidenceRef.getBytes(StandardCharsets.UTF_8).length <= 2_048
                && evidenceRef.matches("[A-Za-z][A-Za-z0-9+.-]*:[^\\s]{1,2031}");
        }
    }

    public record AuthorityView(@JsonProperty("schema_version") String schemaVersion,
                                String section, boolean authoritative, boolean available,
                                Object data, String dataDigest, String safeErrorCode, Instant fetchedAt) {}

    public record DashboardResponse(@JsonProperty("schema_version") String schemaVersion,
                                    UUID tenantId, Map<String, AuthorityView> sections,
                                    boolean complete, Set<String> unavailableSections, Instant generatedAt) {}

    private static <T extends Comparable<? super T>> Set<T> immutableSortedSet(Set<T> values) {
        return Collections.unmodifiableSortedSet(new TreeSet<>(values));
    }
}
