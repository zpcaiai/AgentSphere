package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ApiKeyManagerTest {
    private static ApiKeyManager manager() {
        var properties = new ControlProperties(List.of("https://console.example.invalid"),
            Path.of("/tmp/agenttrust-test-token"), "p".repeat(32),
            URI.create("https://idp.example.invalid/tenant"), "agenttrust-control",
            URI.create("https://idp.example.invalid/oauth2/authorize"),
            URI.create("https://idp.example.invalid/oauth2/token"),
            URI.create("https://idp.example.invalid/oauth2/userinfo"),
            URI.create("https://pep.example.invalid"),
            URI.create("https://idp.example.invalid/.well-known/jwks.json"),
            Map.of("tasks", URI.create("https://tasks.example.invalid")), 100, 3_000,
            1_048_576, Path.of("/tmp/agui-signing-key.pem"),
            Path.of("/tmp/agui-resume-hmac-key"), 300,
            Path.of("/tmp/client.p12"), Path.of("/tmp/client.pass"),
            Path.of("/tmp/trust.p12"), Path.of("/tmp/trust.pass"), true,
            "agenttrust_enterprise_app", true);
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
