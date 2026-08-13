package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.AuthorizationDecision;
import com.agenttrust.control.AdminModels.PrincipalContext;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public final class PepAuthorizationClient {
    private final RestClient client;
    private final String serviceToken;

    public PepAuthorizationClient(ControlProperties properties, RestClient.Builder builder) {
        this.serviceToken = properties.serviceToken();
        this.client = builder.baseUrl(properties.pepEndpoint().toString()).build();
    }

    public AuthorizationDecision authorize(PrincipalContext principal, AdminIntent intent, String idempotencyKey) {
        try {
            var decision = client.post()
                .uri("/v1/authorize/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + serviceToken)
                .header("Idempotency-Key", idempotencyKey)
                .body(Map.of("schema_version", "agenttrust.admin-authorization.v1",
                    "principal", principal, "action", intent))
                .retrieve()
                .body(AuthorizationDecision.class);
            if (decision == null || !decision.allowed()) {
                throw new ControlDeniedException("CONTROL_ADMIN_DENIED");
            }
            return decision;
        } catch (ControlDeniedException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlDeniedException("CONTROL_PEP_UNAVAILABLE", error);
        }
    }
}
