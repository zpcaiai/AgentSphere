package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ApprovalScopeTokenProviderTest {
    @TempDir Path temporary;

    @Test
    void scopesUseDistinctRotatableOpaqueCredentials() throws Exception {
        Path key = temporary.resolve("principal.seed");
        var properties = ApprovalTestProperties.create(key);
        write(properties.readTokenFile(), "read-token-value-0001");
        write(properties.requestTokenFile(), "request-token-value-0002");
        write(properties.decideTokenFile(), "decide-token-value-0003");
        write(properties.issueTokenFile(), "issue-token-value-0004");
        write(properties.revokeTokenFile(), "revoke-token-value-0005");

        var provider = new ApprovalScopeTokenProvider(properties);
        assertEquals("decide-token-value-0003",
            provider.token(ApprovalScopeTokenProvider.Scope.DECIDE));

        write(properties.decideTokenFile(), "read-token-value-0001");
        assertThrows(IllegalStateException.class,
            () -> provider.token(ApprovalScopeTokenProvider.Scope.DECIDE));
    }

    private static void write(Path path, String value) throws Exception {
        Files.writeString(path, value + "\n", StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ));
    }
}
