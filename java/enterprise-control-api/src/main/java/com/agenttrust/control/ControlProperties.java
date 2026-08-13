package com.agenttrust.control;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "agenttrust.control")
public record ControlProperties(
    @NotEmpty List<String> consoleOrigins,
    @NotBlank String serviceToken,
    @NotBlank String apiKeyPepper,
    URI pepEndpoint,
    Map<String, URI> authorityEndpoints,
    int maximumPageSize,
    int authorityTimeoutMillis,
    boolean databaseTlsRequired
) {
    public ControlProperties {
        consoleOrigins = List.copyOf(consoleOrigins);
        authorityEndpoints = Map.copyOf(authorityEndpoints);
        if (pepEndpoint == null || !"https".equalsIgnoreCase(pepEndpoint.getScheme())) {
            throw new IllegalArgumentException("CONTROL_PEP_ENDPOINT_MUST_USE_HTTPS");
        }
        if (apiKeyPepper.length() < 32) {
            throw new IllegalArgumentException("CONTROL_API_KEY_PEPPER_TOO_SHORT");
        }
        if (authorityEndpoints.isEmpty() || authorityEndpoints.values().stream()
            .anyMatch(uri -> !"https".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_ENDPOINT_MUST_USE_HTTPS");
        }
        if (maximumPageSize < 1 || maximumPageSize > 100
            || authorityTimeoutMillis < 100 || authorityTimeoutMillis > 30_000) {
            throw new IllegalArgumentException("CONTROL_BOUNDS_INVALID");
        }
    }
}
