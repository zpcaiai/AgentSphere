package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.CostUsageRequest;
import com.agenttrust.control.AdminModels.EnterpriseActionReceipt;
import com.agenttrust.control.AdminModels.IntegrationRequest;
import com.agenttrust.control.AdminModels.OrganizationRequest;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.ProjectRequest;
import com.agenttrust.control.AdminModels.QuotaConsumeRequest;
import com.agenttrust.control.AdminModels.TenantRequest;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public final class EnterpriseService {
    private final EnterpriseRepository repository;
    private final PepAuthorizationClient pep;
    private final TransactionTemplate transactions;
    private final EnterpriseMutationGateway enterpriseMutations;
    private final CanonicalDigest canonicalDigest;

    public EnterpriseService(EnterpriseRepository repository, PepAuthorizationClient pep,
                             TransactionTemplate transactions,
                             EnterpriseMutationGateway enterpriseMutations,
                             CanonicalDigest canonicalDigest) {
        this.repository = repository;
        this.pep = pep;
        this.transactions = transactions;
        this.enterpriseMutations = enterpriseMutations;
        this.canonicalDigest = canonicalDigest;
    }

    public EnterpriseActionReceipt createTenant(PrincipalContext principal, TenantRequest request,
                                                AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_TENANT", "tenant:" + principal.tenantId());
        requireContext(principal, intent, Set.of("tenant-admin"), true);
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt createOrganization(PrincipalContext principal,
                                                       OrganizationRequest request,
                                                       AdminIntent intent, String reason,
                                                       String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_ORGANIZATION", "organization:" + request.organizationId());
        requireContext(principal, intent, Set.of("tenant-admin"), true);
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt createProject(PrincipalContext principal, ProjectRequest request,
                                                 AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_PROJECT", "project:" + request.projectId());
        requireContext(principal, intent, Set.of("project-admin"), true);
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt createIntegration(PrincipalContext principal,
                                                      IntegrationRequest request,
                                                      AdminIntent intent, String reason,
                                                      String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_INTEGRATION", "integration:" + request.integrationId());
        requireContext(principal, intent, Set.of("integration-admin"), true);
        if (request.integrationId() == null || request.endpoint().getHost() == null
            || !"https".equalsIgnoreCase(request.endpoint().getScheme())
            || request.endpoint().getUserInfo() != null) {
            throw new ControlDeniedException("CONTROL_INTEGRATION_INVALID");
        }
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt consumeQuota(PrincipalContext principal,
                                                QuotaConsumeRequest request,
                                                AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CONSUME_QUOTA", "quota:" + request.quotaKey());
        requireContext(principal, intent, Set.of("quota-operator"), true);
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt recordCost(PrincipalContext principal, CostUsageRequest request,
                                              AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "RECORD_COST", "cost:" + request.usageId());
        requireContext(principal, intent, Set.of("billing-operator"), true);
        if (request.usageId() == null || !principal.projectIds().contains(request.projectId())) {
            throw new ControlDeniedException("CONTROL_COST_DENIED");
        }
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt issueApiKey(PrincipalContext principal,
                                               ApiKeyIssueRequest request,
                                               AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "ISSUE_API_KEY", "api-key:new");
        requireContext(principal, intent, Set.of("credential-admin"), true);
        if (request.projectId() != null && !principal.projectIds().contains(request.projectId())) {
            throw new ControlDeniedException("CONTROL_API_KEY_DENIED");
        }
        Instant now = Instant.now();
        if (!request.expiresAt().isAfter(now)
            || request.expiresAt().isAfter(now.plus(365, ChronoUnit.DAYS))) {
            throw new ControlDeniedException("CONTROL_API_KEY_EXPIRY_INVALID");
        }
        requireActionDigest(intent, reason, request);
        return submitEnterpriseMutation(principal, intent, reason, key, request);
    }

    public EnterpriseActionReceipt revokeApiKey(PrincipalContext principal, UUID apiKeyId,
                                                AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "REVOKE_API_KEY", "api-key:" + apiKeyId);
        requireContext(principal, intent, Set.of("credential-admin"), true);
        requireActionDigest(intent, reason, apiKeyId);
        return submitEnterpriseMutation(principal, intent, reason, key,
            Map.of("api_key_id", apiKeyId.toString()));
    }

    public EnterpriseActionReceipt submitIntent(PrincipalContext principal, AdminIntent intent,
                                                String reason, String key) {
        requireReason(reason);
        requireContext(principal, intent, Set.of("control-operator"), true);
        requireActionDigest(intent, reason, null);
        return submitEnterpriseMutation(principal, intent, reason, key, Map.of());
    }

    private EnterpriseActionReceipt submitEnterpriseMutation(
        PrincipalContext principal, AdminIntent intent, String reason, String key,
        Object mutation
    ) {
        if (enterpriseMutations == null) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_AUTHORITY_UNAVAILABLE");
        }
        return enterpriseMutations.submit(principal, intent, reason, key, mutation);
    }

    public RemoteAuthorization authorizeRemoteAction(PrincipalContext principal, AdminIntent intent,
                                                       String reason, String key, Object payload,
                                                       String operation, String resource,
                                                       Set<String> requiredRoles) {
        requireReason(reason);
        requireOperation(intent, operation, resource);
        requireContext(principal, intent, requiredRoles, true);
        requireActionDigest(intent, reason, payload);
        String digest = requestDigest(intent, reason, payload);
        var reservation = transactions.execute(status -> {
            repository.enterTenant(principal.tenantId());
            return repository.reserveRemoteAction(principal.tenantId(), key, digest,
                intent, payload);
        });
        if (reservation == null) {
            throw new ConflictException("CONTROL_TRANSACTION_FAILED");
        }
        return new RemoteAuthorization(principal.tenantId(), key, reservation.dispatch(),
            reservation.completed(), reservation.attempt(), reservation.responsePayload(),
            reservation.evidenceRef());
    }

    public void completeRemoteAction(RemoteAuthorization authorization, Object response,
                                     String evidenceRef) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishRemoteAction(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "COMPLETED", response, evidenceRef);
        });
    }

    public void markRemoteUnknown(RemoteAuthorization authorization, String reasonCode) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishRemoteAction(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "UNKNOWN", Map.of("safe_error_code", reasonCode), null);
        });
    }

    public void markRemoteFailed(RemoteAuthorization authorization, String reasonCode) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishRemoteAction(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "FAILED", Map.of("safe_error_code", reasonCode), null);
        });
    }

    public ApprovalAuthorization authorizeApprovalIntent(PrincipalContext principal,
                                                           ApprovalIntent intent, String key) {
        if (!"agenttrust.approval-intent.v1".equals(intent.schemaVersion())
            || !principal.roles().contains("approver")) {
            throw new ControlDeniedException("CONTROL_APPROVAL_DENIED");
        }
        var decision = pep.authorizeApproval(principal, intent, key);
        String digest = canonicalDigest.digest(Map.of("tenant_id", principal.tenantId(),
            "actor", principal.subject(), "approval_intent", intent));
        var reservation = transactions.execute(status -> {
            repository.enterTenant(principal.tenantId());
            return repository.reserveApprovalIntent(principal.tenantId(), key, digest,
                principal.subject(), intent);
        });
        if (reservation == null) {
            throw new ConflictException("CONTROL_TRANSACTION_FAILED");
        }
        return new ApprovalAuthorization(principal.tenantId(), key, reservation.dispatch(),
            reservation.completed(), reservation.attempt(), decision.evidenceRef(),
            reservation.evidenceRef());
    }

    public void completeApprovalIntent(ApprovalAuthorization authorization, String evidenceRef) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishApprovalIntent(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "COMPLETED", evidenceRef);
        });
    }

    public void markApprovalUnknown(ApprovalAuthorization authorization) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishApprovalIntent(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "UNKNOWN", authorization.pepEvidenceRef(),
                "CONTROL_APPROVAL_OUTCOME_UNKNOWN");
        });
    }

    /**
     * The Approval authority currently returns a case snapshot, not an immutable Evidence receipt.
     * Keep the remote outcome retryable and do not substitute the earlier PEP decision evidence.
     */
    public void markApprovalEvidencePending(ApprovalAuthorization authorization) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishApprovalIntent(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "UNKNOWN", null,
                "CONTROL_APPROVAL_EVIDENCE_PENDING");
        });
    }

    public void markApprovalFailed(ApprovalAuthorization authorization, String reasonCode) {
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(authorization.tenantId());
            repository.finishApprovalIntent(authorization.tenantId(), authorization.key(),
                authorization.attempt(), "FAILED", null, reasonCode);
        });
    }

    public record RemoteAuthorization(UUID tenantId, String key, boolean dispatch,
                                      boolean completed, int attempt,
                                      com.fasterxml.jackson.databind.JsonNode completedResponse,
                                      String completedEvidenceRef) {}
    public record ApprovalAuthorization(UUID tenantId, String key, boolean dispatch,
                                        boolean completed, int attempt, String pepEvidenceRef,
                                        String completedEvidenceRef) {}

    private String requestDigest(AdminIntent intent, String reason, Object request) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("intent", intent);
        values.put("reason", reason);
        values.put("request", request);
        return canonicalDigest.digest(values);
    }

    void requireActionDigest(AdminIntent intent, String reason, Object request) {
        byte[] expected = canonicalDigest.actionDigest(intent, reason, request)
            .getBytes(StandardCharsets.US_ASCII);
        byte[] supplied = intent.actionDigest().getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new ControlDeniedException("CONTROL_ACTION_DIGEST_MISMATCH");
        }
    }

    static void requireOperation(AdminIntent intent, String operation, String resource) {
        if (!operation.equals(intent.operation()) || !resource.equals(intent.resource())) {
            throw new ControlDeniedException("CONTROL_ACTION_BINDING_INVALID");
        }
    }

    static void requireContext(PrincipalContext principal, AdminIntent intent,
                               Set<String> roles, boolean separation) {
        Instant now = Instant.now();
        if (!"agenttrust.enterprise-control.v1".equals(intent.schemaVersion())
            || intent.actionId() == null || intent.requestedAt() == null
            || intent.actionId().getMostSignificantBits() == 0L
                && intent.actionId().getLeastSignificantBits() == 0L
            || intent.requestedAt().isAfter(now.plus(5, ChronoUnit.MINUTES))
            || intent.requestedAt().isBefore(now.minus(24, ChronoUnit.HOURS))
            || intent.actionDigest() == null || !intent.actionDigest().matches("[a-f0-9]{64}")
            || !principal.tenantId().equals(intent.tenantId())
            || !principal.subject().equals(intent.requestedBy())
            || !principal.roles().containsAll(roles)
            || intent.projectId() != null && !principal.projectIds().contains(intent.projectId())
            || !principal.approvalIds().containsAll(intent.approvalIds())
            || separation && (!principal.strongAuth() || intent.approvalIds().isEmpty())) {
            throw new ControlDeniedException("CONTROL_ADMIN_DENIED");
        }
    }

    private static void requireReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 2000) {
            throw new ControlDeniedException("CONTROL_REASON_REQUIRED");
        }
    }
}
