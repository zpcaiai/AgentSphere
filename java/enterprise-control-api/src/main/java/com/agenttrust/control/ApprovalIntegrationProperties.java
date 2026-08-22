package com.agenttrust.control;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Fail-closed production configuration for the enterprise Approval authority integration. */
@Validated
@ConfigurationProperties(prefix = "agenttrust.control.approval")
public record ApprovalIntegrationProperties(
    Path readTokenFile,
    Path requestTokenFile,
    Path decideTokenFile,
    Path issueTokenFile,
    Path revokeTokenFile,
    Path principalSigningKeyFile,
    PrincipalSigningKeyFormat principalSigningKeyFormat,
    @NotBlank String principalIssuer,
    @NotBlank String principalAudience,
    @NotBlank String principalKeyId,
    @NotBlank String clientIdentity,
    @NotBlank String serviceSubject,
    int assertionTtlSeconds,
    @NotEmpty Set<String> acceptedStrongAuthAcrs,
    int maximumAuthenticationAgeSeconds
) {
    private static final String IDENTIFIER = "[A-Za-z0-9_.:/@-]+";

    public ApprovalIntegrationProperties {
        List<Path> tokenPaths = List.of(readTokenFile, requestTokenFile, decideTokenFile,
            issueTokenFile, revokeTokenFile);
        if (tokenPaths.stream().anyMatch(path -> path == null || !path.isAbsolute())
            || new HashSet<>(tokenPaths).size() != tokenPaths.size()) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_TOKEN_FILES_INVALID");
        }
        if (principalSigningKeyFile == null || !principalSigningKeyFile.isAbsolute()
            || tokenPaths.contains(principalSigningKeyFile) || principalSigningKeyFormat == null) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
        }
        if (!boundedIdentifier(principalIssuer, 256)
            || principalAudience == null || principalAudience.isBlank()
            || principalAudience.length() > 256 || containsUnsafe(principalAudience)
            || principalKeyId == null
            || !principalKeyId.matches("[A-Za-z0-9_.-]{1,128}")) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_PRINCIPAL_CONFIGURATION_INVALID");
        }
        if (clientIdentity == null || clientIdentity.length() > 512
            || !(clientIdentity.startsWith("DNS:") || clientIdentity.startsWith("URI:"))
            || clientIdentity.substring(clientIdentity.indexOf(':') + 1).isEmpty()
            || clientIdentity.chars().anyMatch(value -> value <= 32 || value > 126)
            || !boundedIdentifier(serviceSubject, 256)) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_CLIENT_IDENTITY_INVALID");
        }
        if (assertionTtlSeconds < 1 || assertionTtlSeconds > 300
            || maximumAuthenticationAgeSeconds < 30
            || maximumAuthenticationAgeSeconds > 86_400) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_AUTHENTICATION_BOUNDS_INVALID");
        }
        if (acceptedStrongAuthAcrs == null || acceptedStrongAuthAcrs.isEmpty()
            || acceptedStrongAuthAcrs.size() > 64
            || acceptedStrongAuthAcrs.stream().anyMatch(value -> !boundedIdentifier(value, 256))) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_ACR_ALLOWLIST_INVALID");
        }
        acceptedStrongAuthAcrs = Set.copyOf(acceptedStrongAuthAcrs);
    }

    private static boolean boundedIdentifier(String value, int maximum) {
        return value != null && !value.isBlank() && value.length() <= maximum
            && value.matches(IDENTIFIER);
    }

    private static boolean containsUnsafe(String value) {
        return value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }

    public enum PrincipalSigningKeyFormat {
        RAW_BASE64URL,
        PKCS8_PEM
    }
}
