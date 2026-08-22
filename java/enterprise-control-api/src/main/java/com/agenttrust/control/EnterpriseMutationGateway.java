package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.EnterpriseActionReceipt;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * The only production egress for enterprise mutations.  It binds the verified browser principal
 * to one exact request and returns only the durable action acceptance receipt.  It never interprets
 * an HTTP success as completion of the enterprise mutation.
 */
@Component
public final class EnterpriseMutationGateway {
    static final String PATH = "/v1/enterprise/actions";
    static final String SCOPE = "enterprise:mutate";
    private static final Set<String> RECEIPT_FIELDS = Set.of(
        "schema_version", "action_id", "task_id", "accepted", "start_requested",
        "execution_pending", "ingress_digest", "evidence_ref", "evidence_digest");
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final AuthorityScopeTokenProvider tokens;
    private final HumanPrincipalAssertionSigner assertions;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;

    public EnterpriseMutationGateway(ControlProperties properties, SecureRestClientFactory clients,
                                     AuthorityScopeTokenProvider tokens,
                                     HumanPrincipalAssertionSigner assertions,
                                     CanonicalDigest canonical, ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.tokens = tokens;
        this.assertions = assertions;
        this.canonical = canonical;
        this.mapper = mapper;
    }

    public EnterpriseActionReceipt submit(PrincipalContext principal, AdminIntent intent,
                                          String reason, String idempotencyKey, Object mutation) {
        EnterpriseMutationRequest body = new EnterpriseMutationRequest(
            "agenttrust.enterprise-mutation-request.v1", principal.tenantId(), intent,
            canonical.digest(Map.of("reason", reason)), mutation == null ? Map.of() : mutation);
        var assertion = assertions.sign(principal, "POST", PATH, SCOPE, idempotencyKey, body, true);
        URI endpoint = properties.authorityEndpoints().get("enterprise");
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_AUTHORITY_UNCONFIGURED");
        }
        try {
            JsonNode response = clients.client(endpoint).post().uri(PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + tokens.operationToken("enterprise.mutate"))
                .header("X-AgentTrust-Tenant-Id", principal.tenantId().toString())
                .header("Idempotency-Key", idempotencyKey)
                .header("X-AgentTrust-Human-Assertion", assertion.headerValue())
                .body(body)
                .exchange((ignored, raw) -> decode(raw));
            return requireReceipt(response, intent.actionId(), principal.tenantId());
        } catch (ControlDeniedException | ConflictException | CapacityException
                 | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private JsonNode decode(org.springframework.http.client.ClientHttpResponse response)
        throws IOException {
        int status = response.getStatusCode().value();
        if (status == 400 || status == 401 || status == 403 || status == 404 || status == 422) {
            throw new ControlDeniedException("CONTROL_ENTERPRISE_AUTHORITY_REJECTED");
        }
        if (status == 409) {
            throw new ConflictException("CONTROL_ENTERPRISE_AUTHORITY_CONFLICT");
        }
        if (status == 429) {
            throw new CapacityException("CONTROL_ENTERPRISE_AUTHORITY_CAPACITY");
        }
        if (status != 202 || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(
                response.getHeaders().getContentType())) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_AUTHORITY_UNAVAILABLE");
        }
        byte[] bytes = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (bytes.length == 0 || bytes.length > properties.maximumAuthorityResponseBytes()) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_RECEIPT_INVALID");
        }
        JsonNode value = mapper.readTree(bytes);
        if (value == null || !value.isObject()) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_RECEIPT_INVALID");
        }
        return value;
    }

    static EnterpriseActionReceipt requireReceipt(JsonNode value, UUID expectedActionId,
                                                   UUID expectedTenantId) {
        Set<String> actual = new HashSet<>();
        if (value != null && value.isObject()) {
            value.fieldNames().forEachRemaining(actual::add);
        }
        if (!actual.equals(RECEIPT_FIELDS)
            || !"agenttrust.enterprise-action-receipt.v1".equals(
                value.path("schema_version").textValue())
            || !value.path("accepted").isBoolean() || !value.path("accepted").booleanValue()
            || !value.path("start_requested").isBoolean()
            || !value.path("start_requested").booleanValue()
            || !value.path("execution_pending").isBoolean()
            || !value.path("execution_pending").booleanValue()
            || !SHA256.matcher(value.path("ingress_digest").asText("")).matches()
            || !SHA256.matcher(value.path("evidence_digest").asText("")).matches()) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_RECEIPT_INVALID");
        }
        try {
            UUID actionId = UUID.fromString(value.path("action_id").textValue());
            UUID taskId = UUID.fromString(value.path("task_id").textValue());
            if (!AuthorityJson.uuid(actionId.toString()) || !actionId.equals(expectedActionId)
                || !AuthorityJson.uuid(taskId.toString())
                || !AuthorityJson.orchestratorEventReference(
                    value.path("evidence_ref"), expectedTenantId, taskId)) {
                throw new IllegalArgumentException("receipt binding mismatch");
            }
            return new EnterpriseActionReceipt(
                value.path("schema_version").textValue(), actionId, taskId, true, true, true,
                value.path("ingress_digest").textValue(), value.path("evidence_ref").textValue(),
                value.path("evidence_digest").textValue());
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_ENTERPRISE_RECEIPT_INVALID", error);
        }
    }

    public record EnterpriseMutationRequest(
        @JsonProperty("schema_version") String schemaVersion,
        @JsonProperty("tenant_id") UUID tenantId,
        @JsonProperty("admin_intent") AdminIntent adminIntent,
        @JsonProperty("reason_digest") String reasonDigest,
        Object mutation) {}
}
