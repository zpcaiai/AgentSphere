package com.agenttrust.control;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "agenttrust.control")
public record ControlProperties(
    @NotEmpty List<String> consoleOrigins,
    URI iamIssuer,
    @NotBlank String iamAudience,
    URI iamAuthorizationEndpoint,
    URI iamTokenEndpoint,
    URI iamUserInfoEndpoint,
    URI pepEndpoint,
    @NotBlank String pepReadinessSchema,
    URI jwksEndpoint,
    Map<String, URI> authorityEndpoints,
    Map<String, String> authorityReadinessSchemas,
    int maximumPageSize,
    int authorityTimeoutMillis,
    int maximumAuthorityResponseBytes,
    Path aguiSigningKeyFile,
    Path aguiResumeHmacKeyFile,
    int aguiResumeTtlSeconds,
    Path outboundKeyStore,
    Path outboundKeyStorePasswordFile,
    Path outboundTrustStore,
    Path outboundTrustStorePasswordFile,
    boolean outboundMtlsRequired,
    @NotBlank String expectedDatabaseRole,
    boolean databaseTlsRequired
) {
    /**
     * Complete production authority inventory. Readiness must never silently omit a dashboard
     * section (or the enterprise mutation ingress) because an endpoint was absent from a partial
     * map override.
     */
    static final Set<String> REQUIRED_AUTHORITY_ENDPOINTS = Set.of(
        "enterprise", "agents", "tasks", "approvals", "evidence", "incidents", "policies",
        "tools", "credentials", "packs", "trace", "compliance", "audit", "models", "data",
        "context", "anomalies", "security_evaluations", "supply_chain", "domain_packs", "sre",
        "deployments");

    public ControlProperties {
        consoleOrigins = List.copyOf(consoleOrigins);
        authorityEndpoints = Map.copyOf(authorityEndpoints);
        authorityReadinessSchemas = Map.copyOf(authorityReadinessSchemas);
        if (!secureIdentityUri(iamIssuer)
            || !secureIdentityUri(iamAuthorizationEndpoint)
            || !secureIdentityUri(iamTokenEndpoint)
            || !secureIdentityUri(iamUserInfoEndpoint)
            || !iamAudience.matches("[A-Za-z0-9][A-Za-z0-9:._/-]{0,199}")) {
            throw new IllegalArgumentException("CONTROL_IAM_CONFIGURATION_INVALID");
        }
        if (!secureServiceUri(pepEndpoint) || !readinessSchema(pepReadinessSchema)) {
            throw new IllegalArgumentException("CONTROL_PEP_ENDPOINT_MUST_USE_HTTPS");
        }
        if (!secureJwksUri(jwksEndpoint)) {
            throw new IllegalArgumentException("CONTROL_JWKS_ENDPOINT_INVALID");
        }
        if (consoleOrigins.isEmpty() || consoleOrigins.stream().anyMatch(origin -> {
            try {
                URI uri = URI.create(origin);
                return !secureServiceUri(uri) || uri.getPort() == 0
                    || uri.getPath() != null && !uri.getPath().isEmpty() && !"/".equals(uri.getPath());
            } catch (IllegalArgumentException error) {
                return true;
            }
        })) {
            throw new IllegalArgumentException("CONTROL_CONSOLE_ORIGIN_INVALID");
        }
        if (!authorityEndpoints.keySet().equals(REQUIRED_AUTHORITY_ENDPOINTS)
            || authorityEndpoints.keySet().stream()
            .anyMatch(name -> !name.matches("[a-z][a-z0-9_-]{0,63}"))
            || authorityEndpoints.values().stream().anyMatch(uri -> !secureServiceUri(uri))) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_ENDPOINT_INVENTORY_INVALID");
        }
        if (!authorityReadinessSchemas.keySet().equals(authorityEndpoints.keySet())
            || authorityReadinessSchemas.values().stream()
                .anyMatch(schema -> !readinessSchema(schema))) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_READINESS_SCHEMA_INVALID");
        }
        if (maximumPageSize < 1 || maximumPageSize > 100
            || authorityTimeoutMillis < 100 || authorityTimeoutMillis > 30_000
            || maximumAuthorityResponseBytes < 1024
            || maximumAuthorityResponseBytes > 8 * 1024 * 1024
            || aguiResumeTtlSeconds < 30 || aguiResumeTtlSeconds > 3600) {
            throw new IllegalArgumentException("CONTROL_BOUNDS_INVALID");
        }
        if (invalidAbsolute(aguiSigningKeyFile) || invalidAbsolute(aguiResumeHmacKeyFile)) {
            throw new IllegalArgumentException("CONTROL_AGUI_SIGNING_KEY_INVALID");
        }
        if (outboundMtlsRequired && (invalidAbsolute(outboundKeyStore)
            || invalidAbsolute(outboundKeyStorePasswordFile)
            || invalidAbsolute(outboundTrustStore)
            || invalidAbsolute(outboundTrustStorePasswordFile))) {
            throw new IllegalArgumentException("CONTROL_OUTBOUND_MTLS_CONFIG_INVALID");
        }
        if (!expectedDatabaseRole.matches("[a-z_][a-z0-9_]{0,62}")) {
            throw new IllegalArgumentException("CONTROL_DATABASE_ROLE_INVALID");
        }
    }

    private static boolean invalidAbsolute(Path value) {
        return value == null || !value.isAbsolute();
    }

    private static boolean secureServiceUri(URI uri) {
        return uri != null && uri.isAbsolute() && "https".equalsIgnoreCase(uri.getScheme())
            && uri.getHost() != null && !uri.getHost().isBlank() && uri.getUserInfo() == null
            && uri.getQuery() == null && uri.getFragment() == null
            && (uri.getPath() == null || uri.getPath().isEmpty() || "/".equals(uri.getPath()));
    }

    private static boolean readinessSchema(String value) {
        return value != null && value.matches("agenttrust\\.[a-z0-9.-]{1,120}\\.v[1-9][0-9]*");
    }

    private static boolean secureJwksUri(URI uri) {
        return uri != null && uri.isAbsolute() && "https".equalsIgnoreCase(uri.getScheme())
            && uri.getHost() != null && !uri.getHost().isBlank() && uri.getUserInfo() == null
            && uri.getQuery() == null && uri.getFragment() == null
            && uri.getPath() != null && uri.getPath().startsWith("/")
            && !uri.getPath().endsWith("/");
    }

    private static boolean secureIdentityUri(URI uri) {
        return uri != null && uri.isAbsolute() && "https".equalsIgnoreCase(uri.getScheme())
            && uri.getHost() != null && !uri.getHost().isBlank() && uri.getUserInfo() == null
            && uri.getQuery() == null && uri.getFragment() == null;
    }
}
