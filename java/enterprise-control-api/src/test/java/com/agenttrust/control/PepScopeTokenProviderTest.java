package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PepScopeTokenProviderTest {
    @TempDir Path directory;

    @Test
    void scopesAreDistinctAndRotationIsObserved() throws Exception {
        Path approval = secret("approval", "pep-approval-token-0002");
        Path query = secret("query", "pep-query-token-0003");
        var provider = new PepScopeTokenProvider(
            new PepTokenProperties(approval, query));
        assertEquals("pep-query-token-0003",
            provider.token(PepScopeTokenProvider.Scope.QUERY));

        Files.writeString(query, "pep-approval-token-0002", StandardCharsets.US_ASCII);
        assertThrows(IllegalStateException.class,
            () -> provider.token(PepScopeTokenProvider.Scope.QUERY));
    }

    private Path secret(String name, String value) throws Exception {
        Path path = directory.resolve(name);
        Files.writeString(path, value, StandardCharsets.US_ASCII);
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Windows test workers do not expose POSIX permissions.
        }
        return path;
    }
}
