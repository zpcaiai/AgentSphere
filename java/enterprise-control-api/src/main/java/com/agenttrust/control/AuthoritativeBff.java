package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AuthorityView;
import com.agenttrust.control.AdminModels.DashboardResponse;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public final class AuthoritativeBff {
    private static final Map<String, String> AUTHORITY_DASHBOARD_PATHS = Map.ofEntries(
        Map.entry("agents", "/v1/authoritative/agents"),
        Map.entry("tasks", "/v1/authoritative/tasks"),
        Map.entry("approvals", "/v1/authoritative/approvals"),
        Map.entry("evidence", "/v1/authoritative/evidence"),
        Map.entry("incidents", "/v1/authoritative/incidents"),
        Map.entry("policies", "/v1/authoritative/policies"),
        Map.entry("tools", "/v1/authoritative/tools"),
        Map.entry("credentials", "/v1/authoritative/credentials"),
        Map.entry("packs", "/v1/authoritative/packs"),
        Map.entry("trace", "/v1/authoritative/trace"),
        Map.entry("compliance", "/v1/authoritative/compliance"),
        Map.entry("audit", "/v1/authoritative/audit"),
        Map.entry("sre", "/v1/authoritative/sre"),
        Map.entry("deployments", "/v1/authoritative/deployments"));
    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final ServiceTokenProvider serviceToken;
    private final PepAuthorizationClient pep;
    private final ObjectMapper mapper;

    public AuthoritativeBff(ControlProperties properties, SecureRestClientFactory clients,
                            ServiceTokenProvider serviceToken, PepAuthorizationClient pep,
                            ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.serviceToken = serviceToken;
        this.pep = pep;
        this.mapper = mapper;
    }

    public DashboardResponse dashboard(PrincipalContext principal, String resource, int limit) {
        if (resource == null || !resource.matches("[a-z][a-z0-9_-]{0,99}")
            || limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
        pep.authorizeQuery(principal, "VIEW_ENTERPRISE_DASHBOARD", "dashboard:" + resource);
        Map<String, AuthorityView> sections = new TreeMap<>();
        Set<String> unavailable = new TreeSet<>();
        AUTHORITY_DASHBOARD_PATHS.forEach((name, path) -> {
            String section = name.toUpperCase(java.util.Locale.ROOT);
            try {
                var endpoint = properties.authorityEndpoints().get(name);
                if (endpoint == null) {
                    throw new IllegalStateException("AUTHORITY_ENDPOINT_UNCONFIGURED");
                }
                JsonNode data = clients.client(endpoint).get()
                    .uri(uri -> uri.path(path).queryParam("resource", resource)
                        .queryParam("limit", limit).build())
                    .header("Authorization", "Bearer " + serviceToken.token())
                    .header("X-Tenant-Id", principal.tenantId().toString())
                    .header("X-Actor-Subject", principal.subject())
                    .header("X-Actor-Roles", String.join(",", new TreeSet<>(principal.roles())))
                    .exchange((ignored, response) -> decodeAuthority(response));
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

    static String dashboardPath(String authority) {
        String path = AUTHORITY_DASHBOARD_PATHS.get(authority);
        if (path == null) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_ROUTE_UNSUPPORTED");
        }
        return path;
    }

    static Set<String> dashboardAuthorities() {
        return AUTHORITY_DASHBOARD_PATHS.keySet();
    }

    private JsonNode decodeAuthority(org.springframework.http.client.ClientHttpResponse response)
        throws IOException {
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IOException("AUTHORITY_RESPONSE_REJECTED");
        }
        byte[] body = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (body.length == 0 || body.length > properties.maximumAuthorityResponseBytes()) {
            throw new IOException("AUTHORITY_RESPONSE_INVALID");
        }
        JsonNode value = mapper.readTree(body);
        if (value == null || !value.isObject()) {
            throw new IOException("AUTHORITY_RESPONSE_INVALID");
        }
        return value;
    }

    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA256_UNAVAILABLE", error);
        }
    }
}
