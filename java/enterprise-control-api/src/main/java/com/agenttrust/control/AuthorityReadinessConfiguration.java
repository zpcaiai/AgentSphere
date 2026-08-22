package com.agenttrust.control;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;

/** Dependency-aware readiness. Liveness deliberately remains process-local. */
@Configuration
public class AuthorityReadinessConfiguration {
    private static final int MAXIMUM_READINESS_BYTES = 65_536;
    private static final Set<String> BASIC_READINESS_FIELDS =
        Set.of("schema_version", "ready");
    private static final Map<String, Set<String>> READINESS_FIELDS = Map.ofEntries(
        Map.entry("agenttrust.agent-registry-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "lifecycle_dependencies_ready")),
        Map.entry("agenttrust.evidence-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "worm_ready")),
        Map.entry("agenttrust.audit-retention-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "worm_ready",
                "deletion_gateway_ready", "human_principal_keys_ready")),
        Map.entry("agenttrust.incident-release-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "orchestrator_ready",
                "containment_replay_ready", "release_signer_ready")),
        Map.entry("agenttrust.pack-marketplace-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "release_gate_keyring_ready")),
        Map.entry("agenttrust.policy-admin-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "signing_key_ready",
                "pep_activation_ready")),
        Map.entry("agenttrust.model-gateway-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "provider_registry_ready",
                "data_governance_authority_ready", "artifact_store_ready", "evidence_ready")),
        Map.entry("agenttrust.data-governance-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "orchestrator_ready",
                "enterprise_dlp_ready", "object_worm_ready", "legal_hold_ready", "evidence_ready")),
        Map.entry("agenttrust.context-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "orchestrator_ready",
                "object_store_ready", "vector_index_ready", "cache_ready", "supply_chain_ready",
                "legal_hold_ready", "poisoning_detector_ready", "evidence_ready")),
        Map.entry("agenttrust.runtime-anomaly-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "orchestrator_ready",
                "response_dependencies_ready", "evidence_authority_ready",
                "deterministic_rules_ready", "semantic_detector_required", "production_certification")),
        Map.entry("agenttrust.security-eval-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "orchestrator_ready",
                "isolated_runner_ready", "evidence_authority_ready", "dataset_keyring_ready",
                "report_signer_ready", "production_certification")),
        Map.entry("agenttrust.supply-chain-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "repository_ready", "signer_ready",
                "scanner_ready", "sandbox_ready", "revocation_ready", "evidence_ready")),
        Map.entry("agenttrust.domain-runtime-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "executor_ready", "evidence_ready")),
        Map.entry("agenttrust.sre-readiness.v1",
            Set.of("schema_version", "ready", "database_ready", "orchestrator_ready",
                "effect_adapters_ready", "production_certification"))
    );

    @Bean(name = "pep")
    HealthIndicator pepReadiness(ControlProperties properties, SecureRestClientFactory clients,
                                 ObjectMapper mapper) {
        return () -> dependencyHealth(() -> requireReady(clients, mapper,
            properties.pepEndpoint(), properties.pepReadinessSchema()));
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
                                       ObjectMapper mapper) {
        return () -> dependencyHealth(() -> {
            var checks = new ArrayList<Callable<Void>>();
            for (Map.Entry<String, URI> entry : properties.authorityEndpoints().entrySet()) {
                checks.add(() -> {
                    requireReady(clients, mapper, entry.getValue(),
                        properties.authorityReadinessSchemas().get(entry.getKey()));
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

    private static void requireReady(SecureRestClientFactory clients, ObjectMapper mapper,
                                     URI endpoint, String expectedSchema) {
        JsonNode body = clients.client(endpoint).get().uri("/ready")
            .exchange((ignored, response) -> readSuccessJson(response, mapper));
        if (!validReadiness(body, expectedSchema)) {
            throw new ControlUnavailableException("CONTROL_DEPENDENCY_NOT_READY");
        }
    }

    static boolean validReadiness(JsonNode body, String expectedSchema) {
        if (body == null || !body.isObject() || expectedSchema == null) {
            return false;
        }
        Set<String> fields = new HashSet<>();
        body.fieldNames().forEachRemaining(fields::add);
        Set<String> expectedFields = READINESS_FIELDS.getOrDefault(
            expectedSchema, BASIC_READINESS_FIELDS);
        if (!fields.equals(expectedFields)
            || !expectedSchema.equals(body.path("schema_version").textValue())
            || !body.path("ready").isBoolean() || !body.path("ready").booleanValue()) {
            return false;
        }
        return fields.stream()
            .filter(field -> !field.equals("schema_version"))
            .allMatch(field -> body.path(field).isBoolean());
    }

    private static JsonNode readSuccessJson(ClientHttpResponse response, ObjectMapper mapper)
        throws IOException {
        int status = response.getStatusCode().value();
        if (status < 200 || status >= 300 || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(
                response.getHeaders().getContentType())) {
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
