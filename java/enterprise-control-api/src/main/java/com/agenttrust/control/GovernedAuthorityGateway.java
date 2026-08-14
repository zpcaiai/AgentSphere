package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.agenttrust.control.AdminModels.PolicyPromotionRequest;
import com.agenttrust.control.AdminModels.PolicySimulationRequest;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.TaskCommand;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.io.IOException;
import java.util.HashSet;
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
    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final ServiceTokenProvider serviceToken;
    private final EnterpriseService service;
    private final PepAuthorizationClient pep;
    private final ObjectMapper mapper;

    public GovernedAuthorityGateway(ControlProperties properties, SecureRestClientFactory clients,
                                    ServiceTokenProvider serviceToken, EnterpriseService service,
                                    PepAuthorizationClient pep, ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.serviceToken = serviceToken;
        this.service = service;
        this.pep = pep;
        this.mapper = mapper;
    }

    public JsonNode listAgents(PrincipalContext principal, String cursor, int limit) {
        requireLimit(limit);
        pep.authorizeQuery(principal, "LIST_AGENT_INVENTORY", "agents:inventory");
        return get(principal, "agents", builder -> {
            var value = builder.path("/v1/authoritative/agents").queryParam("limit", limit);
            if (cursor != null && !cursor.isBlank()) {
                value.queryParam("cursor", cursor);
            }
            return value.build();
        });
    }

    public JsonNode simulatePolicy(PrincipalContext principal, String bundleId,
                                   PolicySimulationRequest simulation) {
        requireIdentifier(bundleId);
        pep.authorizeQuery(principal, "SIMULATE_POLICY", "policy:" + bundleId);
        return post(principal, "policies", "/v1/policies/" + bundleId + "/simulate",
            simulation, null);
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
                command, key);
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

    public void promotePolicy(PrincipalContext principal, String bundleId,
                              PolicyPromotionRequest promotion, AdminIntent intent,
                              String reason, String key) {
        requireIdentifier(bundleId);
        var authorization = service.authorizeRemoteAction(principal, intent, reason, key, promotion,
            "PROMOTE_POLICY", "policy:" + bundleId, Set.of("policy-admin"));
        if (authorization.completed()) {
            String evidence = requiredEvidence(authorization.completedResponse(),
                "CONTROL_POLICY_PROMOTION_REPLAY_INVALID");
            if (!evidence.equals(authorization.completedEvidenceRef())) {
                throw new ControlUnavailableException("CONTROL_POLICY_PROMOTION_REPLAY_INVALID");
            }
            return;
        }
        requireDispatchLease(authorization.dispatch());
        try {
            JsonNode response = post(principal, "policies",
                "/v1/policies/" + bundleId + "/promotions", promotion, key);
            String evidence = requiredEvidence(response, "CONTROL_POLICY_PROMOTION_EVIDENCE_MISSING");
            service.completeRemoteAction(authorization, response, evidence);
        } catch (ControlDeniedException | ConflictException error) {
            markRemoteFailed(authorization, "CONTROL_POLICY_PROMOTION_REJECTED", error);
        } catch (CapacityException error) {
            markRemoteRetryable(authorization, "CONTROL_POLICY_PROMOTION_CAPACITY", error);
        } catch (RuntimeException error) {
            markRemoteUnknown(authorization, "CONTROL_POLICY_PROMOTION_OUTCOME_UNKNOWN", error);
        }
    }

    public void submitApprovalIntent(PrincipalContext principal, java.util.UUID caseId,
                                     ApprovalIntent approval, String key) {
        if (!caseId.equals(approval.caseId())) {
            throw new ControlDeniedException("CONTROL_APPROVAL_BINDING_MISMATCH");
        }
        var authorization = service.authorizeApprovalIntent(principal, approval, key);
        if (authorization.completed()) {
            requireEvidenceReference(authorization.completedEvidenceRef(),
                "CONTROL_APPROVAL_REPLAY_INVALID");
            return;
        }
        requireDispatchLease(authorization.dispatch());
        try {
            JsonNode response = post(principal, "approvals",
                "/v1/approvals/" + caseId + "/intents",
                Map.of("approval_intent", approval), key);
            if (!response.path("event_verified").asBoolean(false)) {
                throw new ControlDeniedException("CONTROL_APPROVAL_EVENT_UNVERIFIED");
            }
            service.completeApprovalIntent(authorization,
                requiredEvidence(response, "CONTROL_APPROVAL_EVIDENCE_MISSING"));
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
    }

    public JsonNode taskTransitions(PrincipalContext principal, String taskId, int limit) {
        requireIdentifier(taskId);
        if (limit < 1 || limit > 1000) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
        pep.authorizeQuery(principal, "RESUME_TASK_EVENTS", "task:" + taskId);
        return post(principal, "tasks", "/v1/tasks/transitions",
            Map.of("tenant_id", principal.tenantId().toString(), "owner", principal.subject(),
                "task_id", taskId, "limit", limit), null);
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
                          String idempotencyKey) {
        try {
            RestClient.RequestBodySpec request = authenticated(authority, principal).post().uri(path)
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
            return authenticated(authority, principal).get().uri(uri)
                .exchange((ignored, response) -> decode(response));
        } catch (ControlDeniedException | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private RestClient authenticated(String authority, PrincipalContext principal) {
        URI endpoint = properties.authorityEndpoints().get(authority);
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_AUTHORITY_UNCONFIGURED");
        }
        return clients.client(endpoint).mutate().defaultHeaders(headers -> {
            headers.setBearerAuth(serviceToken.token());
            headers.set("X-Tenant-Id", principal.tenantId().toString());
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
        if (status < 200 || status >= 300) {
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

    private static String requiredEvidence(JsonNode response, String code) {
        if (response == null || !response.isObject()) {
            throw new ControlUnavailableException(code);
        }
        return requireEvidenceReference(response.path("evidence_ref").asText(""), code);
    }

    private static String requireEvidenceReference(String value, String code) {
        if (value == null || value.isBlank() || value.length() > 2048) {
            throw new ControlUnavailableException(code);
        }
        return value;
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
