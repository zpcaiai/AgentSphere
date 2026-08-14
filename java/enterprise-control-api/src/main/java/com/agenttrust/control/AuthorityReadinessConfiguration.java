package com.agenttrust.control;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpResponse;

/** Dependency-aware readiness. Liveness deliberately remains process-local. */
@Configuration
public class AuthorityReadinessConfiguration {
    private static final int MAXIMUM_READINESS_BYTES = 65_536;

    @Bean(name = "pep")
    HealthIndicator pepReadiness(ControlProperties properties, SecureRestClientFactory clients,
                                 ServiceTokenProvider token, ObjectMapper mapper) {
        return () -> dependencyHealth(() -> requireReady(clients, token, mapper,
            properties.pepEndpoint()));
    }

    @Bean(name = "jwks")
    HealthIndicator jwksReadiness(ControlProperties properties, SecureRestClientFactory clients,
                                  ObjectMapper mapper) {
        return () -> dependencyHealth(() -> {
            JsonNode body = clients.client(properties.jwksEndpoint()).get()
                .uri(properties.jwksEndpoint()).exchange((ignored, response) ->
                    readSuccessJson(response, mapper));
            if (body == null || !body.path("keys").isArray() || body.path("keys").isEmpty()) {
                throw new IOException("CONTROL_JWKS_EMPTY");
            }
        });
    }

    @Bean(name = "authorities")
    HealthIndicator authorityReadiness(ControlProperties properties,
                                       SecureRestClientFactory clients,
                                       ServiceTokenProvider token, ObjectMapper mapper) {
        return () -> dependencyHealth(() -> {
            var checks = new ArrayList<Callable<Void>>();
            for (Map.Entry<String, URI> entry : properties.authorityEndpoints().entrySet()) {
                checks.add(() -> {
                    requireReady(clients, token, mapper, entry.getValue());
                    return null;
                });
            }
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                var results = executor.invokeAll(checks,
                    properties.authorityTimeoutMillis() + 500L, TimeUnit.MILLISECONDS);
                for (var result : results) {
                    if (result.isCancelled()) {
                        throw new IOException("CONTROL_AUTHORITY_READINESS_TIMEOUT");
                    }
                    result.get();
                }
            }
        });
    }

    private static Health dependencyHealth(CheckedProbe probe) {
        try {
            probe.check();
            return Health.up().build();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return Health.down().withDetail("code", "CONTROL_READINESS_INTERRUPTED").build();
        } catch (Exception error) {
            return Health.down().withDetail("code", "CONTROL_DEPENDENCY_UNAVAILABLE").build();
        }
    }

    private static void requireReady(SecureRestClientFactory clients, ServiceTokenProvider token,
                                     ObjectMapper mapper, URI endpoint) {
        JsonNode body = clients.client(endpoint).get().uri("/ready")
            .headers(headers -> headers.setBearerAuth(token.token()))
            .exchange((ignored, response) -> readSuccessJson(response, mapper));
        if (body == null || !(body.path("ready").asBoolean(false)
            || "UP".equalsIgnoreCase(body.path("status").asText())
            || "READY".equalsIgnoreCase(body.path("status").asText()))) {
            throw new ControlUnavailableException("CONTROL_DEPENDENCY_NOT_READY");
        }
    }

    private static JsonNode readSuccessJson(ClientHttpResponse response, ObjectMapper mapper)
        throws IOException {
        int status = response.getStatusCode().value();
        if (status < 200 || status >= 300) {
            throw new IOException("CONTROL_READINESS_HTTP_STATUS");
        }
        byte[] body = response.getBody().readNBytes(MAXIMUM_READINESS_BYTES + 1);
        if (body.length == 0 || body.length > MAXIMUM_READINESS_BYTES) {
            throw new IOException("CONTROL_READINESS_RESPONSE_INVALID");
        }
        JsonNode value = mapper.readTree(body);
        if (value == null || !value.isObject()) {
            throw new IOException("CONTROL_READINESS_RESPONSE_INVALID");
        }
        return value;
    }

    @FunctionalInterface
    private interface CheckedProbe {
        void check() throws Exception;
    }
}
