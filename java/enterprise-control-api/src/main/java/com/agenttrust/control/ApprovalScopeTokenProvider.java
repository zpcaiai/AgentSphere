package com.agenttrust.control;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/** Rotatable, least-privilege opaque service credentials for each Approval operation. */
@Component
public final class ApprovalScopeTokenProvider {
    private static final int MAXIMUM_TOKEN_BYTES = 8192;
    private final Map<Scope, Path> paths;

    public ApprovalScopeTokenProvider(ApprovalIntegrationProperties properties) {
        EnumMap<Scope, Path> configured = new EnumMap<>(Scope.class);
        configured.put(Scope.READ, properties.readTokenFile());
        configured.put(Scope.REQUEST, properties.requestTokenFile());
        configured.put(Scope.DECIDE, properties.decideTokenFile());
        configured.put(Scope.ISSUE, properties.issueTokenFile());
        configured.put(Scope.REVOKE, properties.revokeTokenFile());
        this.paths = Map.copyOf(configured);
        snapshot();
    }

    public String token(Scope scope) {
        if (scope == null) {
            throw new IllegalArgumentException("CONTROL_APPROVAL_SCOPE_INVALID");
        }
        return snapshot().get(scope);
    }

    private Map<Scope, String> snapshot() {
        EnumMap<Scope, String> values = new EnumMap<>(Scope.class);
        paths.forEach((scope, path) -> values.put(scope, read(path)));
        Set<String> digests = new HashSet<>();
        values.values().forEach(value -> digests.add(sha256(value)));
        if (digests.size() != Scope.values().length) {
            throw new IllegalStateException("CONTROL_APPROVAL_SCOPE_TOKEN_REUSE_DENIED");
        }
        return values;
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
                throw new IllegalStateException("CONTROL_APPROVAL_TOKEN_FILE_INVALID");
            }
            for (int index = 0; index < length; index++) {
                int value = Byte.toUnsignedInt(raw[index]);
                if (value < 33 || value > 126) {
                    throw new IllegalStateException("CONTROL_APPROVAL_TOKEN_FILE_INVALID");
                }
            }
            if (length != raw.length && length + 1 != raw.length && length + 2 != raw.length) {
                throw new IllegalStateException("CONTROL_APPROVAL_TOKEN_FILE_INVALID");
            }
            return new String(raw, 0, length, StandardCharsets.US_ASCII);
        } catch (IOException error) {
            throw new IllegalStateException("CONTROL_APPROVAL_TOKEN_FILE_UNAVAILABLE", error);
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

    public enum Scope {
        READ("approvals:read"),
        REQUEST("approvals:request"),
        DECIDE("approvals:decide"),
        ISSUE("approvals:issue"),
        REVOKE("approvals:revoke");

        private final String value;

        Scope(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }
}
