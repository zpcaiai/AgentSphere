package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AuthorizationDecision;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public final class PepAuthorizationClient {
    private final RestClient client;
    private final PepScopeTokenProvider pepTokens;
    private final HumanPrincipalAssertionSigner humanAssertions;
    private final ObjectMapper mapper;

    public PepAuthorizationClient(ControlProperties properties, SecureRestClientFactory clients,
                                  PepScopeTokenProvider pepTokens,
                                  HumanPrincipalAssertionSigner humanAssertions,
                                  ObjectMapper mapper) {
        this.pepTokens = pepTokens;
        this.humanAssertions = humanAssertions;
        this.mapper = mapper;
        this.client = clients.client(properties.pepEndpoint());
    }

    public AuthorizationDecision authorizeApproval(PrincipalContext principal, ApprovalIntent intent,
                                                    String idempotencyKey) {
        return decision("/v1/authorize/approval", PepScopeTokenProvider.Scope.APPROVAL,
            principal, intent, idempotencyKey);
    }

    public AuthorizationDecision authorizeQuery(PrincipalContext principal, String operation,
                                                 String resource) {
        String idempotencyKey = "query-" + UUID.randomUUID();
        return decision("/v1/authorize/query", PepScopeTokenProvider.Scope.QUERY, principal,
            Map.of("schema_version", "agenttrust.query-authorization.v1",
                "operation", operation, "resource", resource), idempotencyKey);
    }

    private AuthorizationDecision decision(String path, PepScopeTokenProvider.Scope scope,
                                           PrincipalContext principal, Object action,
                                           String idempotencyKey) {
        try {
            if (idempotencyKey == null
                || !idempotencyKey.matches("[A-Za-z0-9._:-]{1,128}")) {
                throw new ControlDeniedException("CONTROL_IDEMPOTENCY_KEY_INVALID");
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("schema_version", "agenttrust.authorization-request.v1");
            body.put("principal", principal);
            body.put("action", action);
            var assertion = humanAssertions.sign(principal, "POST", path, scope.value(),
                idempotencyKey, body, scope == PepScopeTokenProvider.Scope.APPROVAL);
            var decision = boundedDecision(client.post().uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + pepTokens.token(scope))
                .header("X-AgentTrust-Tenant-Id", principal.tenantId().toString())
                .header("Idempotency-Key", idempotencyKey)
                .header("X-AgentTrust-Human-Assertion", assertion.headerValue())
                .body(body));
            if (decision == null || !decision.allowed()) {
                throw new ControlDeniedException("CONTROL_PEP_DENIED");
            }
            return decision;
        } catch (ControlDeniedException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_PEP_UNAVAILABLE", error);
        }
    }

    private AuthorizationDecision boundedDecision(RestClient.RequestHeadersSpec<?> request) {
        return request.exchange((ignored, response) -> {
            int status = response.getStatusCode().value();
            if (status == 401 || status == 403 || status == 400 || status == 422) {
                throw new ControlDeniedException("CONTROL_PEP_DENIED");
            }
            if (status < 200 || status >= 300) {
                throw new ControlUnavailableException("CONTROL_PEP_UNAVAILABLE");
            }
            byte[] body = response.getBody().readNBytes(65_537);
            if (body.length == 0 || body.length > 65_536) {
                throw new IOException("CONTROL_PEP_RESPONSE_INVALID");
            }
            return mapper.readValue(body, AuthorizationDecision.class);
        });
    }
}
