package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AuthorityView;
import com.agenttrust.control.AdminModels.DashboardResponse;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.springframework.stereotype.Component;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Component
public final class AuthoritativeBff {
    private final ControlProperties properties;
    private final RestClient.Builder clients;
    private final ObjectMapper mapper;

    public AuthoritativeBff(ControlProperties properties, RestClient.Builder clients,
                            ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.mapper = mapper;
    }

    public DashboardResponse dashboard(PrincipalContext principal, String resource, int limit) {
        if (resource == null || resource.isBlank() || limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
        Map<String, AuthorityView> sections = new TreeMap<>();
        Set<String> unavailable = new TreeSet<>();
        properties.authorityEndpoints().forEach((name, endpoint) -> {
            String section = name.toUpperCase(java.util.Locale.ROOT);
            try {
                var requestFactory = new SimpleClientHttpRequestFactory();
                var timeout = Duration.ofMillis(properties.authorityTimeoutMillis());
                requestFactory.setConnectTimeout(timeout);
                requestFactory.setReadTimeout(timeout);
                JsonNode data = clients.clone().requestFactory(requestFactory)
                    .baseUrl(endpoint.toString()).build().get()
                    .uri(uri -> uri.path("/v1/authoritative/{resource}")
                        .queryParam("limit", limit).build(resource))
                    .header("Authorization", "Bearer " + properties.serviceToken())
                    .header("X-Tenant-Id", principal.tenantId().toString())
                    .retrieve().body(JsonNode.class);
                if (data == null || !data.path("authoritative").asBoolean(false)) {
                    throw new IllegalStateException("NOT_AUTHORITATIVE");
                }
                sections.put(section, new AuthorityView("agenttrust.authority-view.v1", section,
                    true, true, data,
                    sha256(mapper.writeValueAsBytes(data)), null, Instant.now()));
            } catch (Exception error) {
                unavailable.add(section);
                sections.put(section, new AuthorityView("agenttrust.authority-view.v1", section,
                    true, false, null,
                    "0".repeat(64), "AUTHORITATIVE_SOURCE_UNAVAILABLE", Instant.now()));
            }
        });
        return new DashboardResponse("agenttrust.enterprise-dashboard.v1", principal.tenantId(),
            Map.copyOf(sections), unavailable.isEmpty(), Set.copyOf(unavailable), Instant.now());
    }

    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA256_UNAVAILABLE", error);
        }
    }
}
