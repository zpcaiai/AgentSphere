package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CanonicalDigestTest {
    @Test
    void mapAndSetOrderDoNotChangeIdempotencyDigest() {
        var digest = new CanonicalDigest(new ObjectMapper());
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("operation", "CREATE_PROJECT");
        first.put("roles", Set.of("project-admin", "auditor"));
        Map<String, Object> second = new LinkedHashMap<>();
        second.put("roles", Set.of("auditor", "project-admin"));
        second.put("operation", "CREATE_PROJECT");
        assertEquals(digest.digest(first), digest.digest(second));
    }

    @Test
    void actionDigestMatchesTheBrowserCanonicalizationGoldenVector() {
        var mapper = new ObjectMapper();
        mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        var digest = new CanonicalDigest(mapper);
        var intent = new AdminModels.AdminIntent(
            "agenttrust.enterprise-control.v1",
            UUID.fromString("22222222-2222-4222-8222-222222222222"),
            UUID.fromString("11111111-1111-4111-8111-111111111111"),
            null,
            "CREATE_ORGANIZATION",
            "organization:one",
            "subject:1",
            Set.of("b", "a"),
            "0".repeat(64),
            Instant.parse("2026-08-13T01:02:03Z"));
        var request = new AdminModels.OrganizationRequest("one", "One", "subject:sponsor");

        assertEquals("741c60e6c35aace23c59fad505a6daed5ba4c4252b8a2776a830acbe3fa77c4e",
            digest.actionDigest(intent, "reason", request));
    }
}
