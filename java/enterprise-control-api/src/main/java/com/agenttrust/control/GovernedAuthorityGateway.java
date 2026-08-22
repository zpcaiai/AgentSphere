package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.TaskCommand;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Tenant-bound BFF command gateway. Remote writes are first authorized and persisted by
 * EnterpriseService; an uncertain transport outcome remains UNKNOWN and is safe to retry with the
 * same downstream idempotency key.
 */
@Component
public final class GovernedAuthorityGateway {
    private static final Set<String> COMMAND_RECEIPT_FIELDS = Set.of(
        "schema_version", "accepted", "command_id", "evidence_ref",
        "evidence_digest", "execution_pending");
    private static final Pattern COMMAND_EVIDENCE_REFERENCE = Pattern.compile(
        "^orchestrator-event://([0-9a-f-]{36})/([0-9a-f-]{36})/([1-9][0-9]{0,18})$");
    private static final Pattern UUID_TEXT = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");
    private static final Set<String> APPROVAL_CASE_FIELDS = Set.of(
        "schema_version", "case_id", "request", "policy", "status", "decisions",
        "created_at", "expires_at", "post_review_due_at");
    private static final Set<String> APPROVAL_REQUEST_FIELDS = Set.of(
        "tenant_id", "task_id", "step_id", "action_hash", "plan_hash", "parameter_hash",
        "resource", "resource_version", "policy_version", "environment", "risk",
        "requester_subject", "agent_owner_subject", "justification",
        "requested_ttl_seconds", "requested_uses");
    private static final Set<String> APPROVAL_POLICY_FIELDS = Set.of(
        "policy_id", "policy_version", "approval_type", "minimum_approvers",
        "required_roles", "prohibit_requester", "prohibit_agent_owner",
        "require_resource_owner", "maximum_ttl_seconds", "maximum_uses", "maximum_risk");
    private static final Set<String> APPROVAL_DECISION_FIELDS = Set.of(
        "approver_subject", "roles", "decision", "reason", "decided_at", "strong_auth");
    private static final Set<String> APPROVAL_CASE_STATUSES = Set.of(
        "PENDING", "APPROVED", "REJECTED", "REVOKED", "EXPIRED", "CONSUMED",
        "POST_REVIEW_REQUIRED");
    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final AuthorityScopeTokenProvider authorityTokens;
    private final ApprovalScopeTokenProvider approvalTokens;
    private final ApprovalPrincipalAssertionSigner approvalAssertions;
    private final EnterpriseService service;
    private final AuthoritativeBff responseValidator;
    private final PepAuthorizationClient pep;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;

    public GovernedAuthorityGateway(ControlProperties properties, SecureRestClientFactory clients,
                                    AuthorityScopeTokenProvider authorityTokens,
                                    ApprovalScopeTokenProvider approvalTokens,
                                    ApprovalPrincipalAssertionSigner approvalAssertions,
                                    EnterpriseService service, AuthoritativeBff responseValidator,
                                    PepAuthorizationClient pep,
                                    CanonicalDigest canonical, ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.authorityTokens = authorityTokens;
        this.approvalTokens = approvalTokens;
        this.approvalAssertions = approvalAssertions;
        this.service = service;
        this.responseValidator = responseValidator;
        this.pep = pep;
        this.canonical = canonical;
        this.mapper = mapper;
    }

    public JsonNode listAgents(PrincipalContext principal, String cursor, int limit) {
        requireLimit(limit);
        if (cursor != null && !cursor.matches("[A-Za-z0-9_-]{1,5462}")) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
        pep.authorizeQuery(principal, "LIST_AGENT_INVENTORY", "agents:inventory");
        JsonNode page = get(principal, "agents", builder -> {
            var value = builder.path("/v1/authoritative/agents").queryParam("limit", limit);
            if (cursor != null && !cursor.isBlank()) {
                value.queryParam("cursor", cursor);
            }
            return value.build();
        });
        responseValidator.requireAgentPage(page, principal, "summary", limit);
        return page;
    }

    public void submitTaskCommand(PrincipalContext principal, String taskId, TaskCommand command,
                                  AdminIntent intent, String reason, String key) {
        UUID boundTaskId = requireTaskIdentifier(taskId);
        var authorization = service.authorizeRemoteAction(principal, intent, reason, key, command,
            "TASK_" + command.commandType(), "task:" + taskId, Set.of("task-operator"));
        if (authorization.completed()) {
            requireCompletedCommandReplay(authorization, command.commandId(), principal.tenantId(),
                boundTaskId);
            return;
        }
        requireDispatchLease(authorization.dispatch());
        try {
            JsonNode response = post(principal, "tasks", "/v1/tasks/" + taskId + "/commands",
                command, key, "tasks.command");
            String evidence = requiredCommandAcceptanceEvidence(response, command.commandId(),
                principal.tenantId(), boundTaskId);
            service.completeRemoteAction(authorization, response, evidence);
        } catch (ControlDeniedException | ConflictException error) {
            markRemoteFailed(authorization, "CONTROL_TASK_COMMAND_REJECTED", error);
        } catch (CapacityException error) {
            markRemoteRetryable(authorization, "CONTROL_TASK_COMMAND_CAPACITY", error);
        } catch (RuntimeException error) {
            markRemoteUnknown(authorization, "CONTROL_TASK_COMMAND_OUTCOME_UNKNOWN", error);
        }
    }

    public void submitApprovalIntent(PrincipalContext principal, java.util.UUID caseId,
                                     ApprovalIntent approval, String key) {
        if (!caseId.equals(approval.caseId())) {
            throw new ControlDeniedException("CONTROL_APPROVAL_BINDING_MISMATCH");
        }
        String path = approvalDecisionPath(caseId);
        Map<String, Object> decision = approvalDecisionBody(approval);
        var signedPrincipal = approvalAssertions.sign(principal, "POST", path,
            ApprovalScopeTokenProvider.Scope.DECIDE, key, decision);
        var authorization = service.authorizeApprovalIntent(principal, approval, key);
        if (authorization.completed()) {
            // Legacy completed rows have no independently verified Approval evidence receipt.
            throw new ControlUnavailableException("CONTROL_APPROVAL_REPLAY_EVIDENCE_UNVERIFIED");
        }
        requireDispatchLease(authorization.dispatch());
        JsonNode response;
        try {
            JsonNode before = approvalGet(principal, approvalCasePath(caseId));
            ApprovalCaseBinding binding = requireApprovalCaseBinding(before, principal.tenantId(),
                caseId, approval.observedActionHash(), approval.observedResourceVersion(),
                APPROVAL_CASE_STATUSES);
            if (containsApprover(before.path("decisions"), principal.subject())) {
                // The earlier authority response may have been lost after its transaction
                // committed. Re-validate the exact persisted decision and do not submit a
                // second human mutation. It still is not an immutable Evidence receipt, so the
                // local state remains UNKNOWN below.
                requireApprovalDecisionResult(before, binding, principal, approval);
                response = before;
            } else {
                if (!"PENDING".equals(before.path("status").textValue())) {
                    throw new ConflictException("CONTROL_APPROVAL_CASE_NOT_PENDING");
                }
                response = approvalPost(principal, path, decision, key,
                    signedPrincipal.headerValue());
                requireApprovalDecisionResult(response, binding, principal, approval);
            }
        } catch (ControlDeniedException | ConflictException error) {
            try {
                service.markApprovalFailed(authorization, "CONTROL_APPROVAL_REJECTED");
            } catch (RuntimeException suppressed) {
                error.addSuppressed(suppressed);
            }
            throw error;
        } catch (CapacityException error) {
            try {
                service.markApprovalUnknown(authorization);
            } catch (RuntimeException suppressed) {
                error.addSuppressed(suppressed);
            }
            throw error;
        } catch (RuntimeException error) {
            try {
                service.markApprovalUnknown(authorization);
            } catch (RuntimeException suppressed) {
                error.addSuppressed(suppressed);
            }
            throw new ControlUnavailableException("CONTROL_APPROVAL_OUTCOME_UNKNOWN", error);
        }
        try {
            service.markApprovalEvidencePending(authorization);
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_OUTCOME_UNKNOWN", error);
        }
        // A mutable case snapshot is not an immutable Evidence authority receipt. The decision was
        // accepted remotely, but UI success remains fail-closed until that receipt is integrated.
        throw new ControlUnavailableException("CONTROL_APPROVAL_EVIDENCE_PENDING");
    }

    static String approvalCasePath(UUID caseId) {
        return "/v1/approvals/cases/" + caseId;
    }

    static String approvalDecisionPath(UUID caseId) {
        return approvalCasePath(caseId) + "/decisions";
    }

    static Map<String, Object> approvalDecisionBody(ApprovalIntent approval) {
        Map<String, Object> decision = new LinkedHashMap<>();
        decision.put("schema_version", "agenttrust.approval-decision.v1");
        decision.put("decision", approval.decision());
        decision.put("reason", approval.reason());
        return java.util.Collections.unmodifiableMap(decision);
    }

    private JsonNode approvalGet(PrincipalContext principal, String path) {
        try {
            return approvalAuthenticated(principal, ApprovalScopeTokenProvider.Scope.READ)
                .get().uri(path).exchange((ignored, response) -> decode(response));
        } catch (ControlDeniedException | ConflictException | CapacityException
                 | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private JsonNode approvalPost(PrincipalContext principal, String path, Object body,
                                  String idempotencyKey, String principalAssertion) {
        try {
            return approvalAuthenticated(principal, ApprovalScopeTokenProvider.Scope.DECIDE)
                .post().uri(path).contentType(MediaType.APPLICATION_JSON)
                .header("Idempotency-Key", idempotencyKey)
                .header("x-agenttrust-principal-assertion", principalAssertion)
                .body(body).exchange((ignored, response) -> decode(response));
        } catch (ControlDeniedException | ConflictException | CapacityException
                 | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private RestClient approvalAuthenticated(PrincipalContext principal,
                                             ApprovalScopeTokenProvider.Scope scope) {
        URI endpoint = properties.authorityEndpoints().get("approvals");
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_AUTHORITY_UNCONFIGURED");
        }
        String tenant = principal.tenantId().toString();
        return clients.client(endpoint).mutate().defaultHeaders(headers -> {
            headers.setBearerAuth(approvalTokens.token(scope));
            // New canonical spelling plus the migration alias; both values are byte-identical.
            headers.set("X-AgentTrust-Tenant-Id", tenant);
            headers.set("X-Tenant-Id", tenant);
            headers.set("X-Actor-Subject", principal.subject());
            headers.set("X-Actor-Roles", String.join(",", principal.roles()));
        }).build();
    }

    private ApprovalCaseBinding requireApprovalCaseBinding(
        JsonNode value, UUID tenantId, UUID caseId, String actionHash, String resourceVersion,
        Set<String> acceptedStatuses
    ) {
        requireApprovalCaseShape(value);
        JsonNode request = value.path("request");
        String status = value.path("status").textValue();
        if (!caseId.toString().equals(value.path("case_id").textValue())
            || !tenantId.toString().equals(request.path("tenant_id").textValue())
            || !actionHash.equals(request.path("action_hash").textValue())
            || !resourceVersion.equals(request.path("resource_version").textValue())
            || !acceptedStatuses.contains(status)) {
            throw new ControlDeniedException("CONTROL_APPROVAL_BINDING_MISMATCH");
        }
        return new ApprovalCaseBinding(tenantId, caseId, actionHash, resourceVersion,
            canonical.digest(request), canonical.digest(value.path("policy")));
    }

    private void requireApprovalDecisionResult(JsonNode response, ApprovalCaseBinding before,
                                               PrincipalContext principal,
                                               ApprovalIntent approval) {
        Set<String> statuses = "REJECT".equals(approval.decision())
            ? Set.of("REJECTED")
            : Set.of("PENDING", "APPROVED", "POST_REVIEW_REQUIRED", "CONSUMED", "REVOKED",
                "EXPIRED");
        ApprovalCaseBinding after;
        try {
            after = requireApprovalCaseBinding(response, before.tenantId(), before.caseId(),
                before.actionHash(), before.resourceVersion(), statuses);
        } catch (ControlDeniedException error) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_RESPONSE_BINDING_INVALID",
                error);
        }
        if (!before.requestDigest().equals(after.requestDigest())
            || !before.policyDigest().equals(after.policyDigest())) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_RESPONSE_BINDING_INVALID");
        }
        int matched = 0;
        for (JsonNode decision : response.path("decisions")) {
            if (principal.subject().equals(decision.path("approver_subject").asText())) {
                Set<String> roles = new java.util.TreeSet<>();
                decision.path("roles").forEach(item -> roles.add(item.asText()));
                if (!approval.decision().equals(decision.path("decision").asText())
                    || !approval.reason().equals(decision.path("reason").asText())
                    || !decision.path("strong_auth").asBoolean(false)
                    || !roles.equals(principal.roles())) {
                    throw new ControlUnavailableException(
                        "CONTROL_APPROVAL_RESPONSE_BINDING_INVALID");
                }
                matched++;
            }
        }
        if (matched != 1) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_RESPONSE_BINDING_INVALID");
        }
    }

    private static boolean containsApprover(JsonNode decisions, String subject) {
        for (JsonNode decision : decisions) {
            if (subject.equals(decision.path("approver_subject").asText())) {
                return true;
            }
        }
        return false;
    }

    private static void requireApprovalCaseShape(JsonNode value) {
        if (value == null || !value.isObject() || !hasExactFields(value, APPROVAL_CASE_FIELDS)
            || !"agenttrust.enterprise-approval.v1".equals(text(value, "schema_version", 128))
            || !canonicalUuid(text(value, "case_id", 36))
            || !value.path("request").isObject()
            || !hasExactFields(value.path("request"), APPROVAL_REQUEST_FIELDS)
            || !value.path("policy").isObject()
            || !hasExactFields(value.path("policy"), APPROVAL_POLICY_FIELDS)
            || !value.path("decisions").isArray() || value.path("decisions").size() > 64) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
        }
        JsonNode request = value.path("request");
        if (!canonicalUuid(text(request, "tenant_id", 36))
            || !canonicalUuid(text(request, "task_id", 36))
            || !canonicalUuid(text(request, "step_id", 36))
            || !digest(request, "action_hash") || !digest(request, "plan_hash")
            || !digest(request, "parameter_hash")
            || invalidBoundedText(request, "resource", 2048)
            || invalidBoundedText(request, "resource_version", 2048)
            || invalidBoundedText(request, "policy_version", 2048)
            || invalidBoundedText(request, "environment", 2048)
            || !Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL")
                .contains(text(request, "risk", 16))
            || invalidBoundedText(request, "requester_subject", 256)
            || invalidBoundedText(request, "agent_owner_subject", 256)
            || invalidBoundedText(request, "justification", 4096)
            || !positiveInteger(request.path("requested_ttl_seconds"), 604_800)
            || !request.path("requested_uses").isIntegralNumber()
            || request.path("requested_uses").longValue() != 1) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
        }
        JsonNode policy = value.path("policy");
        if (invalidBoundedText(policy, "policy_id", 256)
            || invalidBoundedText(policy, "policy_version", 256)
            || !Set.of("ACTION", "SCOPE", "ESCALATION", "DUAL", "EMERGENCY")
                .contains(text(policy, "approval_type", 32))
            || !positiveInteger(policy.path("minimum_approvers"), 64)
            || !stringArray(policy.path("required_roles"), 64, 256)
            || !policy.path("prohibit_requester").isBoolean()
            || !policy.path("prohibit_agent_owner").isBoolean()
            || !policy.path("require_resource_owner").isBoolean()
            || !positiveInteger(policy.path("maximum_ttl_seconds"), 604_800)
            || !policy.path("maximum_uses").isIntegralNumber()
            || policy.path("maximum_uses").longValue() != 1
            || !Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL")
                .contains(text(policy, "maximum_risk", 16))) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
        }
        for (JsonNode decision : value.path("decisions")) {
            if (!decision.isObject() || !hasExactFields(decision, APPROVAL_DECISION_FIELDS)
                || invalidBoundedText(decision, "approver_subject", 256)
                || !stringArray(decision.path("roles"), 64, 256)
                || !Set.of("APPROVE", "REJECT", "POST_REVIEWED")
                    .contains(text(decision, "decision", 32))
                || invalidBoundedText(decision, "reason", 4096)
                || !dateTime(decision.path("decided_at"))
                || !decision.path("strong_auth").isBoolean()
                || !decision.path("strong_auth").booleanValue()) {
                throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
            }
        }
        String status = text(value, "status", 32);
        if (!APPROVAL_CASE_STATUSES.contains(status)
            || !dateTime(value.path("created_at")) || !dateTime(value.path("expires_at"))
            || !(value.path("post_review_due_at").isNull()
                || dateTime(value.path("post_review_due_at")))) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
        }
        Instant created = Instant.parse(value.path("created_at").textValue());
        Instant expires = Instant.parse(value.path("expires_at").textValue());
        if (!created.isBefore(expires) || ("PENDING".equals(status) && !Instant.now().isBefore(expires))) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
        }
    }

    private static String text(JsonNode object, String field, int maximum) {
        JsonNode value = object.path(field);
        if (!value.isTextual() || value.textValue().isBlank()
            || value.textValue().length() > maximum
            || containsControl(value.textValue())) {
            throw new ControlUnavailableException("CONTROL_APPROVAL_CASE_INVALID");
        }
        return value.textValue();
    }

    private static boolean invalidBoundedText(JsonNode object, String field, int maximum) {
        try {
            text(object, field, maximum);
            return false;
        } catch (ControlUnavailableException error) {
            return true;
        }
    }

    private static boolean containsControl(String value) {
        return value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }

    private static boolean digest(JsonNode object, String field) {
        JsonNode value = object.path(field);
        return value.isTextual() && SHA256.matcher(value.textValue()).matches();
    }

    private static boolean canonicalUuid(String value) {
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private static boolean positiveInteger(JsonNode value, long maximum) {
        return value.isIntegralNumber() && value.canConvertToLong()
            && value.longValue() >= 1 && value.longValue() <= maximum;
    }

    private static boolean stringArray(JsonNode value, int maximumItems, int maximumLength) {
        if (!value.isArray() || value.size() > maximumItems) {
            return false;
        }
        Set<String> unique = new HashSet<>();
        for (JsonNode item : value) {
            if (!item.isTextual() || item.textValue().isBlank()
                || item.textValue().length() > maximumLength
                || containsControl(item.textValue()) || !unique.add(item.textValue())) {
                return false;
            }
        }
        return true;
    }

    private static boolean dateTime(JsonNode value) {
        if (!value.isTextual()) {
            return false;
        }
        try {
            Instant.parse(value.textValue());
            return true;
        } catch (RuntimeException error) {
            return false;
        }
    }

    private record ApprovalCaseBinding(UUID tenantId, UUID caseId, String actionHash,
                                       String resourceVersion, String requestDigest,
                                       String policyDigest) {}

    public JsonNode taskTransitions(PrincipalContext principal, String taskId, int limit) {
        requireIdentifier(taskId);
        if (limit < 1 || limit > 1000) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
        pep.authorizeQuery(principal, "RESUME_TASK_EVENTS", "task:" + taskId);
        return post(principal, "tasks", "/v1/tasks/transitions",
            Map.of("tenant_id", principal.tenantId().toString(), "owner", principal.subject(),
                "task_id", taskId, "limit", limit), null, "tasks.transitions");
    }

    private void markRemoteUnknown(EnterpriseService.RemoteAuthorization authorization,
                                   String code, RuntimeException error) {
        try {
            service.markRemoteUnknown(authorization, code);
        } catch (RuntimeException suppressed) {
            error.addSuppressed(suppressed);
        }
        throw new ControlUnavailableException(code, error);
    }

    private void markRemoteFailed(EnterpriseService.RemoteAuthorization authorization,
                                  String code, RuntimeException error) {
        try {
            service.markRemoteFailed(authorization, code);
        } catch (RuntimeException suppressed) {
            error.addSuppressed(suppressed);
        }
        throw error;
    }

    private void markRemoteRetryable(EnterpriseService.RemoteAuthorization authorization,
                                     String code, RuntimeException error) {
        try {
            service.markRemoteUnknown(authorization, code);
        } catch (RuntimeException suppressed) {
            error.addSuppressed(suppressed);
        }
        throw error;
    }

    private JsonNode post(PrincipalContext principal, String authority, String path, Object body,
                          String idempotencyKey, String tokenOperation) {
        try {
            RestClient.RequestBodySpec request = authenticated(authority, principal,
                authorityTokens.operationToken(tokenOperation)).post().uri(path)
                    .contentType(MediaType.APPLICATION_JSON);
            if (idempotencyKey != null) {
                request = request.header("Idempotency-Key", idempotencyKey);
            }
            return request.body(body).exchange((ignored, response) -> decode(response));
        } catch (ControlDeniedException | ConflictException | CapacityException
                 | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private JsonNode get(PrincipalContext principal, String authority,
                         java.util.function.Function<org.springframework.web.util.UriBuilder,
                         URI> uri) {
        try {
            return authenticated(authority, principal, authorityTokens.readToken(authority))
                .get().uri(uri)
                .exchange((ignored, response) -> decode(response));
        } catch (ControlDeniedException | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private RestClient authenticated(String authority, PrincipalContext principal, String token) {
        URI endpoint = properties.authorityEndpoints().get(authority);
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_UNCONFIGURED");
        }
        String tenant = principal.tenantId().toString();
        return clients.client(endpoint).mutate().defaultHeaders(headers -> {
            headers.setBearerAuth(token);
            headers.set("X-AgentTrust-Tenant-Id", tenant);
            headers.set("X-Tenant-Id", tenant);
            headers.set("X-Actor-Subject", principal.subject());
            headers.set("X-Actor-Roles", String.join(",", new java.util.TreeSet<>(principal.roles())));
        }).build();
    }

    private JsonNode decode(org.springframework.http.client.ClientHttpResponse response)
        throws IOException {
        int status = response.getStatusCode().value();
        if (status == 401 || status == 403 || status == 400 || status == 404 || status == 422) {
            throw new ControlDeniedException("CONTROL_AUTHORITY_REJECTED");
        }
        if (status == 409) {
            throw new ConflictException("CONTROL_AUTHORITY_CONFLICT");
        }
        if (status == 429) {
            throw new CapacityException("CONTROL_AUTHORITY_CAPACITY");
        }
        if (status < 200 || status >= 300 || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(
                response.getHeaders().getContentType())) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_UNAVAILABLE");
        }
        byte[] bytes = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (bytes.length == 0 || bytes.length > properties.maximumAuthorityResponseBytes()) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_RESPONSE_INVALID");
        }
        try {
            JsonNode value = mapper.readTree(bytes);
            if (value == null || !value.isObject()) {
                throw new ControlUnavailableException("CONTROL_AUTHORITY_RESPONSE_INVALID");
            }
            return value;
        } catch (java.io.IOException error) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_RESPONSE_INVALID", error);
        }
    }

    static String requiredCommandAcceptanceEvidence(JsonNode response, String expectedCommandId,
                                                    UUID expectedTenantId, UUID expectedTaskId) {
        if (response == null || !response.isObject() || response.size() != COMMAND_RECEIPT_FIELDS.size()
            || !hasExactFields(response, COMMAND_RECEIPT_FIELDS)
            || !response.path("schema_version").isTextual()
            || !"agenttrust.command-receipt.v1".equals(response.path("schema_version").textValue())
            || !response.path("accepted").isBoolean() || !response.path("accepted").booleanValue()
            || !response.path("command_id").isTextual()
            || !expectedCommandId.equals(response.path("command_id").textValue())
            || !response.path("execution_pending").isBoolean()
            || !response.path("execution_pending").booleanValue()
            || !response.path("evidence_ref").isTextual()
            || !response.path("evidence_digest").isTextual()
            || !SHA256.matcher(response.path("evidence_digest").textValue()).matches()) {
            throw new ControlUnavailableException("CONTROL_TASK_COMMAND_RECEIPT_INVALID");
        }
        String reference = response.path("evidence_ref").textValue();
        var match = COMMAND_EVIDENCE_REFERENCE.matcher(reference);
        if (reference.length() > 2048 || !match.matches()) {
            throw new ControlUnavailableException("CONTROL_TASK_COMMAND_RECEIPT_INVALID");
        }
        try {
            if (!UUID.fromString(match.group(1)).toString().equals(match.group(1))
                || !UUID.fromString(match.group(2)).toString().equals(match.group(2))
                || !expectedTenantId.toString().equals(match.group(1))
                || !expectedTaskId.toString().equals(match.group(2))
                || Long.parseLong(match.group(3)) < 1) {
                throw new ControlUnavailableException("CONTROL_TASK_COMMAND_RECEIPT_INVALID");
            }
        } catch (IllegalArgumentException error) {
            throw new ControlUnavailableException("CONTROL_TASK_COMMAND_RECEIPT_INVALID", error);
        }
        return reference;
    }

    static void requireCompletedCommandReplay(
        EnterpriseService.RemoteAuthorization authorization, String expectedCommandId,
        UUID expectedTenantId, UUID expectedTaskId
    ) {
        if (authorization == null || !authorization.completed()) {
            throw new ControlUnavailableException("CONTROL_TASK_COMMAND_REPLAY_INVALID");
        }
        String evidence = requiredCommandAcceptanceEvidence(authorization.completedResponse(),
            expectedCommandId, expectedTenantId, expectedTaskId);
        if (!evidence.equals(authorization.completedEvidenceRef())) {
            throw new ControlUnavailableException("CONTROL_TASK_COMMAND_REPLAY_INVALID");
        }
    }

    private static boolean hasExactFields(JsonNode object, Set<String> expected) {
        Set<String> actual = new HashSet<>();
        object.fieldNames().forEachRemaining(actual::add);
        return actual.equals(expected);
    }

    private static void requireDispatchLease(boolean dispatch) {
        if (!dispatch) {
            throw new ControlUnavailableException("CONTROL_REMOTE_ACTION_IN_PROGRESS");
        }
    }

    private void requireLimit(int limit) {
        if (limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
    }

    private static void requireIdentifier(String value) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9:_-]{0,199}")) {
            throw new ControlDeniedException("CONTROL_RESOURCE_IDENTIFIER_INVALID");
        }
    }

    private static UUID requireTaskIdentifier(String value) {
        try {
            if (value == null || !UUID_TEXT.matcher(value).matches()) {
                throw new IllegalArgumentException("invalid task id");
            }
            UUID taskId = UUID.fromString(value);
            if (taskId.getMostSignificantBits() == 0L && taskId.getLeastSignificantBits() == 0L) {
                throw new IllegalArgumentException("zero task id");
            }
            return taskId;
        } catch (RuntimeException error) {
            throw new ControlDeniedException("CONTROL_RESOURCE_IDENTIFIER_INVALID", error);
        }
    }
}
