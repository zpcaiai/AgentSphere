package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
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
}
