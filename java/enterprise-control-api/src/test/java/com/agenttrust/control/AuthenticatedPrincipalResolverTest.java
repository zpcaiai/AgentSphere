package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class AuthenticatedPrincipalResolverTest {
    private static final Instant NOW = Instant.parse("2030-01-02T03:04:05Z");
    private final AuthenticatedPrincipalResolver resolver = AuthenticatedPrincipalResolver.forTest(
        ApprovalTestProperties.create(Path.of("/tmp/agenttrust-test-principal.seed")),
        Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void trustedClaimsAreBoundToPathTenantAndApprovalSet() {
        UUID tenant = UUID.randomUUID();
        Jwt token = Jwt.withTokenValue("opaque-for-unit-test")
            .header("alg", "EdDSA")
            .subject("admin:1")
            .issuedAt(NOW)
            .expiresAt(NOW.plusSeconds(60))
            .claim("tenant_id", tenant.toString())
            .claim("roles", List.of("tenant-admin"))
            .claim("project_ids", List.of("project:1"))
            .claim("approval_ids", List.of("approval:1"))
            .claim("owned_resources", List.of("urn:agenttrust:resource:one"))
            .claim("acr", "urn:agenttrust:acr:mfa")
            .claim("auth_time", NOW.minusSeconds(60).getEpochSecond())
            .build();
        var principal = resolver.resolve(new JwtAuthenticationToken(token,
            List.of(new SimpleGrantedAuthority("ROLE_USER"))), tenant);
        assertEquals(tenant, principal.tenantId());
        assertEquals("admin:1", principal.subject());
        assertEquals(java.util.Set.of("approval:1"), principal.approvalIds());
        assertEquals(java.util.Set.of("urn:agenttrust:resource:one"), principal.ownedResources());
        assertEquals(true, principal.strongAuth());
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

    @Test
    void rolesNeverImplyOwnershipOrStrongAuthentication() {
        UUID tenant = UUID.randomUUID();
        Jwt token = Jwt.withTokenValue("opaque-for-unit-test")
            .header("alg", "EdDSA")
            .subject("admin:1")
            .claim("tenant_id", tenant.toString())
            .claim("roles", List.of("approver"))
            .claim("project_ids", List.of())
            .claim("approval_ids", List.of())
            .claim("acr", "urn:agenttrust:acr:mfa")
            .claim("auth_time", NOW.minusSeconds(901).getEpochSecond())
            .build();
        var principal = resolver.resolve(new JwtAuthenticationToken(token,
            List.of(new SimpleGrantedAuthority("ROLE_USER"))), tenant);
        assertEquals(false, principal.strongAuth());
        assertEquals(java.util.Set.of(), principal.ownedResources());
    }

    @Test
    void nilTenantClaimIsNeverAnAuthoritativeTenant() {
        UUID nil = new UUID(0L, 0L);
        Jwt token = Jwt.withTokenValue("opaque-for-unit-test")
            .header("alg", "EdDSA")
            .subject("admin:1")
            .claim("tenant_id", nil.toString())
            .claim("roles", List.of("tenant-admin"))
            .build();
        assertThrows(ControlDeniedException.class,
            () -> resolver.resolve(new JwtAuthenticationToken(token), nil));
    }
}
