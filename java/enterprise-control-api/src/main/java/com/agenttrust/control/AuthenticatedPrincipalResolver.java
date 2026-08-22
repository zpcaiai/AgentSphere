package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PrincipalContext;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/** Normalizes resource-server JWT and server-side OIDC session claims through one boundary. */
@Component
public final class AuthenticatedPrincipalResolver {
    private final ApprovalIntegrationProperties approvalProperties;
    private final Clock clock;

    public AuthenticatedPrincipalResolver(ApprovalIntegrationProperties approvalProperties) {
        this(approvalProperties, Clock.systemUTC());
    }

    private AuthenticatedPrincipalResolver(ApprovalIntegrationProperties approvalProperties,
                                           Clock clock) {
        this.approvalProperties = approvalProperties;
        this.clock = clock;
    }

    static AuthenticatedPrincipalResolver forTest(ApprovalIntegrationProperties properties,
                                                  Clock clock) {
        return new AuthenticatedPrincipalResolver(properties, clock);
    }

    public PrincipalContext resolve(Authentication authentication, UUID pathTenant) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ControlDeniedException("CONTROL_UNAUTHENTICATED");
        }
        Map<String, Object> claims;
        String subject;
        if (authentication instanceof JwtAuthenticationToken jwt) {
            claims = jwt.getToken().getClaims();
            subject = jwt.getToken().getSubject();
        } else if (authentication instanceof OAuth2AuthenticationToken oidc
            && oidc.getPrincipal() instanceof OidcUser user) {
            claims = user.getClaims();
            subject = user.getSubject();
        } else {
            throw new ControlDeniedException("CONTROL_AUTHENTICATION_TYPE_DENIED");
        }
        UUID tokenTenant;
        try {
            tokenTenant = UUID.fromString(stringClaim(claims, "tenant_id"));
        } catch (RuntimeException error) {
            throw new ControlDeniedException("CONTROL_TENANT_CLAIM_INVALID", error);
        }
        if (tokenTenant.getMostSignificantBits() == 0L && tokenTenant.getLeastSignificantBits() == 0L) {
            throw new ControlDeniedException("CONTROL_TENANT_CLAIM_INVALID");
        }
        if (pathTenant != null && !pathTenant.equals(tokenTenant)) {
            throw new ControlDeniedException("CONTROL_CROSS_TENANT_DENIED");
        }
        Set<String> roles = stringSet(claims.get("roles"), 64, 100);
        Set<String> projects = stringSet(claims.get("project_ids"), 1000, 200);
        Set<String> approvals = stringSet(claims.get("approval_ids"), 16, 200);
        Set<String> ownedResources = stringSet(claims.get("owned_resources"), 1024, 2048);
        String authenticationContext = stringClaim(claims, "acr");
        Instant authenticationTime = authenticationTime(claims.get("auth_time"));
        boolean strongAuth = strongAuth(authenticationContext, authenticationTime);
        if (subject == null || !subject.matches("[A-Za-z0-9][A-Za-z0-9:@._/-]{0,299}")
            || roles.isEmpty()
            || roles.stream().anyMatch(value -> !value.matches("[a-z][a-z0-9:_-]{0,99}"))
            || projects.stream().anyMatch(value -> !value.matches("[A-Za-z0-9][A-Za-z0-9:_-]{0,199}"))
            || ownedResources.stream().anyMatch(AuthenticatedPrincipalResolver::unsafeResource)) {
            throw new ControlDeniedException("CONTROL_PRINCIPAL_CLAIMS_INVALID");
        }
        return new PrincipalContext(subject, tokenTenant, roles, projects, approvals,
            ownedResources, strongAuth, authenticationTime, authenticationContext);
    }

    private boolean strongAuth(String authenticationContext, Instant authenticationTime) {
        if (authenticationContext == null || authenticationTime == null
            || !approvalProperties.acceptedStrongAuthAcrs().contains(authenticationContext)) {
            return false;
        }
        Instant now = clock.instant();
        return !authenticationTime.isAfter(now.plusSeconds(30))
            && !authenticationTime.isBefore(
                now.minusSeconds(approvalProperties.maximumAuthenticationAgeSeconds()));
    }

    private static Instant authenticationTime(Object raw) {
        if (raw instanceof Instant value) {
            return value;
        }
        if (raw instanceof Number value) {
            double epoch = value.doubleValue();
            if (!Double.isFinite(epoch) || epoch != Math.rint(epoch)
                || epoch < 0 || epoch > 253_402_300_799d) {
                return null;
            }
            try {
                return Instant.ofEpochSecond(value.longValue());
            } catch (RuntimeException ignored) {
                return null;
            }
        }
        return null;
    }

    private static boolean unsafeResource(String value) {
        return value.isBlank() || value.indexOf('\0') >= 0
            || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }

    private static String stringClaim(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        return value instanceof String text ? text : null;
    }

    private static Set<String> stringSet(Object raw, int maximum, int maximumLength) {
        if (raw == null) {
            return Set.of();
        }
        if (!(raw instanceof Collection<?> values) || values.size() > maximum) {
            throw new ControlDeniedException("CONTROL_PRINCIPAL_CLAIMS_INVALID");
        }
        Set<String> result = values.stream().filter(String.class::isInstance)
            .map(String.class::cast).filter(value -> value.length() <= maximumLength)
            .collect(Collectors.toUnmodifiableSet());
        if (result.size() != values.size()) {
            throw new ControlDeniedException("CONTROL_PRINCIPAL_CLAIMS_INVALID");
        }
        return result;
    }
}
