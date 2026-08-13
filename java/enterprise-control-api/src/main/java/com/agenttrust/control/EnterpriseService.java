package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.ApiKeyIssueResponse;
import com.agenttrust.control.AdminModels.CostUsageRequest;
import com.agenttrust.control.AdminModels.IntegrationRequest;
import com.agenttrust.control.AdminModels.OrganizationRequest;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.ProjectRequest;
import com.agenttrust.control.AdminModels.QuotaConsumeRequest;
import com.agenttrust.control.AdminModels.QuotaUsageResponse;
import com.agenttrust.control.AdminModels.TenantRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public final class EnterpriseService {
    private final EnterpriseRepository repository;
    private final PepAuthorizationClient pep;
    private final TransactionTemplate transactions;
    private final ApiKeyManager apiKeys;
    private final CanonicalDigest canonicalDigest;

    public EnterpriseService(EnterpriseRepository repository, PepAuthorizationClient pep,
                             TransactionTemplate transactions, ApiKeyManager apiKeys,
                             CanonicalDigest canonicalDigest) {
        this.repository = repository;
        this.pep = pep;
        this.transactions = transactions;
        this.apiKeys = apiKeys;
        this.canonicalDigest = canonicalDigest;
    }

    public void createTenant(PrincipalContext principal, TenantRequest request,
                             AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_TENANT", "tenant:" + principal.tenantId());
        requireContext(principal, intent, Set.of("tenant-admin"), true);
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            if (repository.createTenant(principal.tenantId(), request) != 1) {
                throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 201);
        });
    }

    public void createOrganization(PrincipalContext principal, OrganizationRequest request,
                                   AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_ORGANIZATION", "organization:" + request.organizationId());
        requireContext(principal, intent, Set.of("tenant-admin"), true);
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            if (repository.createOrganization(principal.tenantId(), request) != 1) {
                throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 201);
        });
    }

    public void createProject(PrincipalContext principal, ProjectRequest request,
                              AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_PROJECT", "project:" + request.projectId());
        requireContext(principal, intent, Set.of("project-admin"), true);
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            if (repository.createProject(principal.tenantId(), request) != 1) {
                throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 201);
        });
    }

    public void createIntegration(PrincipalContext principal, IntegrationRequest request,
                                  AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CREATE_INTEGRATION", "integration:" + request.integrationId());
        requireContext(principal, intent, Set.of("integration-admin"), true);
        if (request.integrationId() == null || request.endpoint().getHost() == null
            || !"https".equalsIgnoreCase(request.endpoint().getScheme())
            || request.endpoint().getUserInfo() != null) {
            throw new ControlDeniedException("CONTROL_INTEGRATION_INVALID");
        }
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            if (repository.createIntegration(principal.tenantId(), request) != 1) {
                throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 201);
        });
    }

    public QuotaUsageResponse consumeQuota(PrincipalContext principal, QuotaConsumeRequest request,
                                           AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "CONSUME_QUOTA", "quota:" + request.quotaKey());
        requireContext(principal, intent, Set.of("quota-operator"), true);
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        QuotaUsageResponse response = transactions.execute(status -> {
            repository.enterTenant(principal.tenantId());
            var reservation = repository.reserveIdempotency(principal.tenantId(), key, requestDigest);
            if (reservation.replay()) {
                if (reservation.responseStatus() != 200 || reservation.responsePayload() == null
                    || !reservation.responsePayload().path("used").canConvertToLong()) {
                    throw new ConflictException("CONTROL_IDEMPOTENCY_RESPONSE_INVALID");
                }
                return new QuotaUsageResponse("agenttrust.quota-usage.v1", principal.tenantId(),
                    request.quotaKey(), request.windowStartedAt(),
                    reservation.responsePayload().path("used").longValue(), request.limit());
            }
            long current = repository.consumeQuota(principal.tenantId(), request);
            writeAudit(intent, decision, reason);
            var result = new QuotaUsageResponse("agenttrust.quota-usage.v1", principal.tenantId(),
                request.quotaKey(), request.windowStartedAt(), current, request.limit());
            repository.completeIdempotency(principal.tenantId(), key, 200, result);
            return result;
        });
        if (response == null) {
            throw new ConflictException("CONTROL_TRANSACTION_FAILED");
        }
        return response;
    }

    public void recordCost(PrincipalContext principal, CostUsageRequest request,
                           AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "RECORD_COST", "cost:" + request.usageId());
        requireContext(principal, intent, Set.of("billing-operator"), true);
        if (request.usageId() == null || !principal.projectIds().contains(request.projectId())) {
            throw new ControlDeniedException("CONTROL_COST_DENIED");
        }
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            if (repository.recordCost(principal.tenantId(), request) != 1) {
                throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 202);
        });
    }

    public ApiKeyIssueResponse issueApiKey(PrincipalContext principal, ApiKeyIssueRequest request,
                                           AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "ISSUE_API_KEY", "api-key:new");
        requireContext(principal, intent, Set.of("credential-admin"), true);
        if (request.projectId() != null && !principal.projectIds().contains(request.projectId())) {
            throw new ControlDeniedException("CONTROL_API_KEY_DENIED");
        }
        requireActionDigest(intent, reason, request);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, request);
        ApiKeyIssueResponse response = transactions.execute(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                throw new ConflictException("CONTROL_API_KEY_SECRET_ALREADY_ISSUED");
            }
            var issued = apiKeys.issue(request);
            if (repository.createApiKey(principal.tenantId(), issued.response().apiKeyId(), request,
                issued.keyHash(), principal.subject(), issued.response().createdAt()) != 1) {
                throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
            }
            writeAudit(intent, decision, reason);
            repository.completeIdempotency(principal.tenantId(), key, 201,
                Map.of("api_key_id", issued.response().apiKeyId().toString(),
                    "secret_recoverable", false));
            return issued.response();
        });
        if (response == null) {
            throw new ConflictException("CONTROL_TRANSACTION_FAILED");
        }
        return response;
    }

    public void revokeApiKey(PrincipalContext principal, UUID apiKeyId, AdminIntent intent,
                             String reason, String key) {
        requireReason(reason);
        requireOperation(intent, "REVOKE_API_KEY", "api-key:" + apiKeyId);
        requireContext(principal, intent, Set.of("credential-admin"), true);
        requireActionDigest(intent, reason, apiKeyId);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, apiKeyId);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            if (repository.revokeApiKey(principal.tenantId(), apiKeyId, reason) != 1) {
                throw new ControlDeniedException("CONTROL_API_KEY_DENIED");
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 204);
        });
    }

    public void submitIntent(PrincipalContext principal, AdminIntent intent, String reason, String key) {
        requireReason(reason);
        requireContext(principal, intent, Set.of("control-operator"), true);
        requireActionDigest(intent, reason, null);
        var decision = pep.authorize(principal, intent, key);
        String requestDigest = requestDigest(intent, reason, null);
        transactions.executeWithoutResult(status -> {
            repository.enterTenant(principal.tenantId());
            if (repository.reserveIdempotency(principal.tenantId(), key, requestDigest).replay()) {
                return;
            }
            writeAudit(intent, decision, reason);
            completeVoid(principal, key, 202);
        });
    }

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

    private void completeVoid(PrincipalContext principal, String key, int status) {
        repository.completeIdempotency(principal.tenantId(), key, status,
            Map.of("completed", true));
    }

    private void writeAudit(AdminIntent intent, AdminModels.AuthorizationDecision decision,
                            String reason) {
        if (repository.writeAudit(intent, decision.policyDigest(), decision.evidenceRef(), reason) != 1) {
            throw new ConflictException("CONTROL_AUDIT_CONFLICT");
        }
    }

    static void requireOperation(AdminIntent intent, String operation, String resource) {
        if (!operation.equals(intent.operation()) || !resource.equals(intent.resource())) {
            throw new ControlDeniedException("CONTROL_ACTION_BINDING_INVALID");
        }
    }

    static void requireContext(PrincipalContext principal, AdminIntent intent,
                               Set<String> roles, boolean separation) {
        if (!"agenttrust.enterprise-control.v1".equals(intent.schemaVersion())
            || intent.actionId() == null || intent.requestedAt() == null
            || intent.actionDigest() == null || !intent.actionDigest().matches("[a-f0-9]{64}")
            || !principal.tenantId().equals(intent.tenantId())
            || !principal.subject().equals(intent.requestedBy())
            || !principal.roles().containsAll(roles)
            || intent.projectId() != null && !principal.projectIds().contains(intent.projectId())
            || separation && intent.approvalIds().isEmpty()) {
            throw new ControlDeniedException("CONTROL_ADMIN_DENIED");
        }
    }

    private static void requireReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 2000) {
            throw new ControlDeniedException("CONTROL_REASON_REQUIRED");
        }
    }
}
