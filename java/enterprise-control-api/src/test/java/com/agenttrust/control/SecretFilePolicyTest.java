package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecretFilePolicyTest {
    @TempDir
    Path directory;

    @Test
    void acceptsPrivateRegularFileAndRejectsGroupWrite() throws IOException {
        Path secret = directory.resolve("secret");
        Files.writeString(secret, "0123456789abcdef");
        try {
            Files.setPosixFilePermissions(secret, PosixFilePermissions.fromString("rw-------"));
            assertDoesNotThrow(() -> SecretFilePolicy.requireReadable(secret, 16, 32));
            Files.setPosixFilePermissions(secret, PosixFilePermissions.fromString("rw-rw----"));
            assertThrows(IOException.class,
                () -> SecretFilePolicy.requireReadable(secret, 16, 32));
        } catch (UnsupportedOperationException ignored) {
            assertDoesNotThrow(() -> SecretFilePolicy.requireReadable(secret, 16, 32));
        }
    }

    @Test
    void rejectsSymbolicLinkEvenWhenTargetIsPrivate() throws IOException {
        Path target = directory.resolve("target");
        Path link = directory.resolve("link");
        Files.writeString(target, "0123456789abcdef");
        try {
            Files.createSymbolicLink(link, target);
            assertThrows(IOException.class,
                () -> SecretFilePolicy.requireReadable(link, 16, 32));
        } catch (UnsupportedOperationException ignored) {
            // The production Linux filesystem supports symlinks; some development hosts do not.
        }
    }
}
