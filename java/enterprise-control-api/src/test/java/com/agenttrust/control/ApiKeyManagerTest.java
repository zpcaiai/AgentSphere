package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ApiKeyManagerTest {
    private static ApiKeyManager manager() {
        var properties = new ControlProperties(List.of("https://console.example.invalid"),
            "service-token", "p".repeat(32), URI.create("https://pep.example.invalid"),
            Map.of("tasks", URI.create("https://tasks.example.invalid")), 100, 3_000, true);
        return new ApiKeyManager(properties);
    }

    @Test
    void generatedSecretIsOneTimeAndStoredAsHmacOnly() {
        var issued = manager().issue(new ApiKeyIssueRequest("project:1", Set.of("tasks:read"),
            Instant.now().plus(1, ChronoUnit.DAYS)));
        assertTrue(issued.response().oneTimeSecret().startsWith("atk_"));
        assertEquals(64, issued.keyHash().length());
        assertNotEquals(issued.response().oneTimeSecret(), issued.keyHash());
    }

    @Test
    void excessiveExpiryFailsClosed() {
        var request = new ApiKeyIssueRequest(null, Set.of("tasks:read"),
            Instant.now().plus(366, ChronoUnit.DAYS));
        assertThrows(ControlDeniedException.class, () -> manager().issue(request));
    }
}
