package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthorityScopeTokenProviderTest {
    @TempDir Path directory;

    @Test
    void exactScopesRotateAndRejectRawTokenReuse() throws Exception {
        Map<String, Path> reads = new HashMap<>();
        Map<String, Path> operations = new HashMap<>();
        int index = 0;
        for (String scope : AuthorityTokenProperties.READ_AUTHORITIES) {
            reads.put(scope, secret("read-" + scope, token(index++)));
        }
        for (String scope : AuthorityTokenProperties.OPERATIONS) {
            operations.put(scope, secret("operation-" + scope, token(index++)));
        }
        var provider = new AuthorityScopeTokenProvider(
            new AuthorityTokenProperties(reads, operations));
        assertEquals(Files.readString(reads.get("credentials"), StandardCharsets.US_ASCII),
            provider.readToken("credentials"));
        assertEquals(Files.readString(operations.get("tasks.command"), StandardCharsets.US_ASCII),
            provider.operationToken("tasks.command"));

        Files.writeString(operations.get("tasks.command"),
            Files.readString(reads.get("credentials"), StandardCharsets.US_ASCII),
            StandardCharsets.US_ASCII);
        assertThrows(IllegalStateException.class,
            () -> provider.operationToken("tasks.command"));
    }

    @Test
    void missingScopeFailsConfiguration() {
        assertThrows(IllegalArgumentException.class,
            () -> new AuthorityTokenProperties(Map.of(), Map.of()));
    }

    private Path secret(String name, String value) throws Exception {
        Path path = directory.resolve(name.replace('.', '-'));
        Files.writeString(path, value, StandardCharsets.US_ASCII);
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Windows test workers do not expose POSIX permissions.
        }
        return path;
    }

    private static String token(int index) {
        return "authority-token-" + String.format("%04d", index) + "-unique";
    }
}
