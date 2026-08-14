package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.AuthorizationDecision;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public final class PepAuthorizationClient {
    private final RestClient client;
    private final ServiceTokenProvider serviceToken;
    private final ObjectMapper mapper;

    public PepAuthorizationClient(ControlProperties properties, SecureRestClientFactory clients,
                                  ServiceTokenProvider serviceToken, ObjectMapper mapper) {
        this.serviceToken = serviceToken;
        this.mapper = mapper;
        this.client = clients.client(properties.pepEndpoint());
    }

    public AuthorizationDecision authorize(PrincipalContext principal, AdminIntent intent, String idempotencyKey) {
        try {
            var decision = boundedDecision(client.post()
                .uri("/v1/authorize/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + serviceToken.token())
                .header("Idempotency-Key", idempotencyKey)
                .body(Map.of("schema_version", "agenttrust.admin-authorization.v1",
                    "principal", principal, "action", intent)));
            if (decision == null || !decision.allowed()) {
                throw new ControlDeniedException("CONTROL_ADMIN_DENIED");
            }
            return decision;
        } catch (ControlDeniedException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_PEP_UNAVAILABLE", error);
        }
    }

    public AuthorizationDecision authorizeApproval(PrincipalContext principal, ApprovalIntent intent,
                                                    String idempotencyKey) {
        return decision("/v1/authorize/approval", principal, intent, idempotencyKey);
    }

    public AuthorizationDecision authorizeQuery(PrincipalContext principal, String operation,
                                                 String resource) {
        return decision("/v1/authorize/query", principal,
            Map.of("schema_version", "agenttrust.query-authorization.v1",
                "operation", operation, "resource", resource), null);
    }

    private AuthorizationDecision decision(String path, PrincipalContext principal, Object action,
                                           String idempotencyKey) {
        try {
            var request = client.post().uri(path).contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + serviceToken.token());
            if (idempotencyKey != null) {
                request = request.header("Idempotency-Key", idempotencyKey);
            }
            var decision = boundedDecision(request.body(Map.of("schema_version",
                "agenttrust.authorization-request.v1", "principal", principal,
                "action", action)));
            if (decision == null || !decision.allowed()) {
                throw new ControlDeniedException("CONTROL_ADMIN_DENIED");
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
                throw new ControlDeniedException("CONTROL_ADMIN_DENIED");
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
