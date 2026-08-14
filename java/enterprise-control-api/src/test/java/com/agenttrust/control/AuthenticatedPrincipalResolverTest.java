package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class AuthenticatedPrincipalResolverTest {
    private final AuthenticatedPrincipalResolver resolver = new AuthenticatedPrincipalResolver();

    @Test
    void trustedClaimsAreBoundToPathTenantAndApprovalSet() {
        UUID tenant = UUID.randomUUID();
        Jwt token = Jwt.withTokenValue("opaque-for-unit-test")
            .header("alg", "EdDSA")
            .subject("admin:1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .claim("tenant_id", tenant.toString())
            .claim("roles", List.of("tenant-admin"))
            .claim("project_ids", List.of("project:1"))
            .claim("approval_ids", List.of("approval:1"))
            .build();
        var principal = resolver.resolve(new JwtAuthenticationToken(token,
            List.of(new SimpleGrantedAuthority("ROLE_USER"))), tenant);
        assertEquals(tenant, principal.tenantId());
        assertEquals("admin:1", principal.subject());
        assertEquals(java.util.Set.of("approval:1"), principal.approvalIds());
    }

    @Test
    void crossTenantAndMalformedCollectionFailClosed() {
        UUID tenant = UUID.randomUUID();
        Jwt token = Jwt.withTokenValue("opaque-for-unit-test")
            .header("alg", "EdDSA")
            .subject("admin:1")
            .claim("tenant_id", tenant.toString())
            .claim("roles", List.of("tenant-admin", 42))
            .claim("project_ids", List.of())
            .claim("approval_ids", List.of())
            .build();
        var authentication = new JwtAuthenticationToken(token,
            List.of(new SimpleGrantedAuthority("ROLE_USER")));
        assertThrows(ControlDeniedException.class,
            () -> resolver.resolve(authentication, UUID.randomUUID()));
        assertThrows(ControlDeniedException.class,
            () -> resolver.resolve(authentication, tenant));
    }
}
