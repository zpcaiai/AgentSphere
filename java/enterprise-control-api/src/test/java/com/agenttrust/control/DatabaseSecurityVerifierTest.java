package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DatabaseSecurityVerifierTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void requiresVerifyFullAndExplicitRootCertificate() throws IOException {
        Path root = temporaryDirectory.resolve("database-ca.pem");
        Files.writeString(root, "test-ca");
        String valid = "jdbc:postgresql://database.internal:5432/agenttrust"
            + "?sslmode=verify-full&sslrootcert=" + root
            + "&options=-csearch_path%3Dpg_catalog%2Cpublic";

        assertTrue(DatabaseSecurityVerifier.verifyFullJdbcUrl(valid));
        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(valid.replace(
            "verify-full", "require")));
        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(
            "jdbc:postgresql://database.internal:5432/agenttrust?sslmode=verify-full"));
    }

    @Test
    void rejectsDuplicateOrCustomTlsVerifiers() throws IOException {
        Path root = temporaryDirectory.resolve("database-ca.pem");
        Files.writeString(root, "test-ca");
        String prefix = "jdbc:postgresql://database.internal:5432/agenttrust"
            + "?sslmode=verify-full&sslrootcert=" + root
            + "&options=-csearch_path%3Dpg_catalog%2Cpublic";

        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(prefix
            + "&sslmode=disable"));
        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(prefix
            + "&sslhostnameverifier=com.example.AcceptAll"));
        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(prefix
            + "&sslfactory=com.example.UnsafeFactory"));
        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(prefix
            + "&OPTIONS=-csearch_path%3Devil%2Cpublic"));
        assertFalse(DatabaseSecurityVerifier.verifyFullJdbcUrl(prefix.replace(
            "-csearch_path%3Dpg_catalog%2Cpublic", "-csearch_path%3Dpublic")));
    }
}
