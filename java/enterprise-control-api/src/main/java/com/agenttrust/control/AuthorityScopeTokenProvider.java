package com.agenttrust.control;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/** Reads all authority credentials on each use and rejects reuse after a CSI rotation. */
@Component
public final class AuthorityScopeTokenProvider {
    private static final int MAXIMUM_TOKEN_BYTES = 8192;
    private final Map<String, Path> readPaths;
    private final Map<String, Path> operationPaths;

    public AuthorityScopeTokenProvider(AuthorityTokenProperties properties) {
        this.readPaths = properties.readTokenFiles();
        this.operationPaths = properties.operationTokenFiles();
        snapshot();
    }

    public String readToken(String authority) {
        if (!AuthorityTokenProperties.READ_AUTHORITIES.contains(authority)) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_READ_SCOPE_INVALID");
        }
        return snapshot().get("read:" + authority);
    }

    public String operationToken(String operation) {
        if (!AuthorityTokenProperties.OPERATIONS.contains(operation)) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_OPERATION_SCOPE_INVALID");
        }
        return snapshot().get("operation:" + operation);
    }

    private Map<String, String> snapshot() {
        Map<String, String> values = new HashMap<>();
        readPaths.forEach((scope, path) -> values.put("read:" + scope, read(path)));
        operationPaths.forEach((scope, path) -> values.put("operation:" + scope, read(path)));
        Set<String> digests = new HashSet<>();
        values.values().forEach(value -> digests.add(sha256(value)));
        if (digests.size() != values.size()) {
            throw new IllegalStateException("CONTROL_AUTHORITY_TOKEN_REUSE_DENIED");
        }
        return Map.copyOf(values);
    }

    private static String read(Path path) {
        try {
            SecretFilePolicy.requireReadable(path, 16, MAXIMUM_TOKEN_BYTES + 2L);
            byte[] raw = Files.readAllBytes(path);
            int length = raw.length;
            if (length > 0 && raw[length - 1] == '\n') {
                length--;
                if (length > 0 && raw[length - 1] == '\r') {
                    length--;
                }
            }
            if (length < 16 || length > MAXIMUM_TOKEN_BYTES) {
                throw new IllegalStateException("CONTROL_AUTHORITY_TOKEN_FILE_INVALID");
            }
            for (int index = 0; index < length; index++) {
                int value = Byte.toUnsignedInt(raw[index]);
                if (value < 33 || value > 126) {
                    throw new IllegalStateException("CONTROL_AUTHORITY_TOKEN_FILE_INVALID");
                }
            }
            if (length != raw.length && length + 1 != raw.length && length + 2 != raw.length) {
                throw new IllegalStateException("CONTROL_AUTHORITY_TOKEN_FILE_INVALID");
            }
            return new String(raw, 0, length, StandardCharsets.US_ASCII);
        } catch (IOException error) {
            throw new IllegalStateException("CONTROL_AUTHORITY_TOKEN_FILE_UNAVAILABLE", error);
        }
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("CONTROL_SHA256_UNAVAILABLE", error);
        }
    }
}
