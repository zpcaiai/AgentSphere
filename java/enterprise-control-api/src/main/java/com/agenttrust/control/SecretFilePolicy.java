package com.agenttrust.control;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/** Shared fail-closed policy for CSI/Vault mounted secret files. */
final class SecretFilePolicy {
    private SecretFilePolicy() {}

    static void requireReadable(Path path, long minimumBytes, long maximumBytes)
        throws IOException {
        if (path == null || !path.isAbsolute() || Files.isSymbolicLink(path)
            || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
            || !Files.isReadable(path)) {
            throw new IOException("CONTROL_SECRET_FILE_INVALID");
        }
        long size = Files.size(path);
        if (size < minimumBytes || size > maximumBytes) {
            throw new IOException("CONTROL_SECRET_FILE_INVALID");
        }
        requireSafePermissions(path);
    }

    private static void requireSafePermissions(Path path) throws IOException {
        try {
            PosixFileAttributes attributes = Files.readAttributes(path,
                PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Set<PosixFilePermission> permissions = attributes.permissions();
            if (permissions.contains(PosixFilePermission.OWNER_EXECUTE)
                || permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                || permissions.contains(PosixFilePermission.OTHERS_READ)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)
                || !(permissions.contains(PosixFilePermission.OWNER_READ)
                    || permissions.contains(PosixFilePermission.GROUP_READ))) {
                throw new IOException("CONTROL_SECRET_FILE_PERMISSIONS_INVALID");
            }
            if (permissions.contains(PosixFilePermission.GROUP_READ)) {
                Path process = Path.of("/proc/self");
                if (!Files.isDirectory(process)
                    || !attributes.group().equals(Files.readAttributes(process,
                        PosixFileAttributes.class).group())) {
                    throw new IOException("CONTROL_SECRET_FILE_GROUP_INVALID");
                }
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX development hosts still get no-follow, regular-file, size and readable
            // checks. Production admission requires Linux with RuntimeDefault seccomp.
        }
    }
}
