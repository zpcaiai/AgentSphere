package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PrincipalContext;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/** Normalizes resource-server JWT and server-side OIDC session claims through one boundary. */
@Component
public final class AuthenticatedPrincipalResolver {
    public PrincipalContext resolve(Authentication authentication, UUID pathTenant) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ControlDeniedException("CONTROL_UNAUTHENTICATED");
        }
        Map<String, Object> claims;
        String subject;
        if (authentication instanceof JwtAuthenticationToken jwt) {
            claims = jwt.getToken().getClaims();
            subject = jwt.getToken().getSubject();
        } else if (authentication instanceof OAuth2AuthenticationToken oidc) {
            claims = oidc.getPrincipal().getAttributes();
            subject = stringClaim(claims, "sub");
        } else {
            throw new ControlDeniedException("CONTROL_AUTHENTICATION_TYPE_DENIED");
        }
        UUID tokenTenant;
        try {
            tokenTenant = UUID.fromString(stringClaim(claims, "tenant_id"));
        } catch (RuntimeException error) {
            throw new ControlDeniedException("CONTROL_TENANT_CLAIM_INVALID", error);
        }
        if (pathTenant != null && !pathTenant.equals(tokenTenant)) {
            throw new ControlDeniedException("CONTROL_CROSS_TENANT_DENIED");
        }
        Set<String> roles = stringSet(claims.get("roles"), 64, 100);
        Set<String> projects = stringSet(claims.get("project_ids"), 1000, 200);
        Set<String> approvals = stringSet(claims.get("approval_ids"), 16, 200);
        if (subject == null || !subject.matches("[A-Za-z0-9][A-Za-z0-9:@._/-]{0,299}")
            || roles.stream().anyMatch(value -> !value.matches("[a-z][a-z0-9:_-]{0,99}"))
            || projects.stream().anyMatch(value -> !value.matches("[A-Za-z0-9][A-Za-z0-9:_-]{0,199}"))) {
            throw new ControlDeniedException("CONTROL_PRINCIPAL_CLAIMS_INVALID");
        }
        return new PrincipalContext(subject, tokenTenant, roles, projects, approvals);
    }

    private static String stringClaim(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        return value instanceof String text ? text : null;
    }

    private static Set<String> stringSet(Object raw, int maximum, int maximumLength) {
        if (!(raw instanceof Collection<?> values) || values.size() > maximum) {
            return Set.of();
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
