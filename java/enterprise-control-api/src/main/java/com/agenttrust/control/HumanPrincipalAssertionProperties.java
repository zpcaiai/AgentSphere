package com.agenttrust.control;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.nio.file.Path;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Trust configuration for short-lived request-bound human assertions sent to authorities. */
@Validated
@ConfigurationProperties(prefix = "agenttrust.control.human-assertion")
public record HumanPrincipalAssertionProperties(
    Path signingKeyFile,
    SigningKeyFormat signingKeyFormat,
    @NotBlank String issuer,
    @NotBlank String audience,
    @NotBlank String keyId,
    @NotBlank String clientIdentity,
    @NotBlank String serviceSubject,
    int assertionTtlSeconds,
    @NotEmpty Set<String> acceptedAuthenticationContexts,
    int maximumAuthenticationAgeSeconds
) {
    private static final String IDENTIFIER = "[A-Za-z0-9_.:/@-]+";

    public HumanPrincipalAssertionProperties {
        if (signingKeyFile == null || !signingKeyFile.isAbsolute() || signingKeyFormat == null) {
            throw new IllegalArgumentException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
        }
        if (!identifier(issuer, 256) || audience == null || audience.isBlank()
            || audience.length() > 256 || unsafe(audience)
            || keyId == null || !keyId.matches("[A-Za-z0-9_.-]{1,128}")) {
            throw new IllegalArgumentException("CONTROL_HUMAN_ASSERTION_TRUST_INVALID");
        }
        if (clientIdentity == null || clientIdentity.length() > 512
            || !(clientIdentity.startsWith("DNS:") || clientIdentity.startsWith("URI:"))
            || clientIdentity.substring(clientIdentity.indexOf(':') + 1).isEmpty()
            || clientIdentity.chars().anyMatch(value -> value <= 32 || value > 126)
            || !identifier(serviceSubject, 256)) {
            throw new IllegalArgumentException("CONTROL_HUMAN_ASSERTION_IDENTITY_INVALID");
        }
        if (assertionTtlSeconds < 1 || assertionTtlSeconds > 300
            || maximumAuthenticationAgeSeconds < 30
            || maximumAuthenticationAgeSeconds > 86_400) {
            throw new IllegalArgumentException("CONTROL_HUMAN_ASSERTION_BOUNDS_INVALID");
        }
        if (acceptedAuthenticationContexts == null || acceptedAuthenticationContexts.isEmpty()
            || acceptedAuthenticationContexts.size() > 64
            || acceptedAuthenticationContexts.stream().anyMatch(value -> !identifier(value, 256))) {
            throw new IllegalArgumentException("CONTROL_HUMAN_ASSERTION_ACR_INVALID");
        }
        acceptedAuthenticationContexts = Set.copyOf(acceptedAuthenticationContexts);
    }

    private static boolean identifier(String value, int maximum) {
        return value != null && !value.isBlank() && value.length() <= maximum
            && value.matches(IDENTIFIER);
    }

    private static boolean unsafe(String value) {
        return value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }

    public enum SigningKeyFormat {
        RAW_BASE64URL,
        PKCS8_PEM
    }
}
