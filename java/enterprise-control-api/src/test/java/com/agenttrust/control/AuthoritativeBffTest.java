package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthoritativeBffTest {
    private static final Set<String> EXPECTED_AUTHORITIES = Set.of(
        "agents", "tasks", "approvals", "evidence", "incidents", "policies", "tools",
        "credentials", "packs", "trace", "compliance", "audit", "sre", "deployments");

    @Test
    void dashboardUsesOneExplicitCollectionRoutePerAuthority() {
        assertEquals(EXPECTED_AUTHORITIES, AuthoritativeBff.dashboardAuthorities());
        Set<String> paths = new HashSet<>();
        for (String authority : EXPECTED_AUTHORITIES) {
            String path = AuthoritativeBff.dashboardPath(authority);
            assertEquals("/v1/authoritative/" + authority, path);
            paths.add(path);
        }
        assertEquals(EXPECTED_AUTHORITIES.size(), paths.size());
        assertFalse(paths.contains("/v1/authoritative/summary"));
    }

    @Test
    void unknownAuthorityCannotBecomeAPath() {
        assertThrows(IllegalArgumentException.class,
            () -> AuthoritativeBff.dashboardPath("../../metadata"));
    }
}
