package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.stereotype.Component;

/** Creates short-lived Ed25519 assertions bound to one exact Approval mutation request. */
@Component
public final class ApprovalPrincipalAssertionSigner {
    private static final String ASSERTION_SCHEMA =
        "agenttrust.signed-approval-principal-assertion.v1";
    private static final String REQUEST_BINDING_SCHEMA =
        "agenttrust.approval-principal-request-binding.v1";
    private static final byte[] ED25519_PKCS8_SEED_PREFIX = HexFormat.of().parseHex(
        "302e020100300506032b657004220420");
    private final ApprovalIntegrationProperties properties;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final Supplier<UUID> jtiSupplier;

    public ApprovalPrincipalAssertionSigner(ApprovalIntegrationProperties properties,
                                            CanonicalDigest canonical, ObjectMapper mapper) {
        this(properties, canonical, mapper, Clock.systemUTC(), UUID::randomUUID);
    }

    private ApprovalPrincipalAssertionSigner(ApprovalIntegrationProperties properties,
                                             CanonicalDigest canonical, ObjectMapper mapper,
                                             Clock clock, Supplier<UUID> jtiSupplier) {
        this.properties = properties;
        this.canonical = canonical;
        this.mapper = mapper;
        this.clock = clock;
        this.jtiSupplier = jtiSupplier;
        loadSigningKey();
    }

    static ApprovalPrincipalAssertionSigner forTest(ApprovalIntegrationProperties properties,
                                                     CanonicalDigest canonical,
                                                     ObjectMapper mapper, Clock clock,
                                                     Supplier<UUID> jtiSupplier) {
        return new ApprovalPrincipalAssertionSigner(properties, canonical, mapper, clock,
            jtiSupplier);
    }

    public SignedHeader sign(PrincipalContext principal, String method, String path,
                             ApprovalScopeTokenProvider.Scope scope, String idempotencyKey,
                             Object body) {
        Instant issuedAt = clock.instant();
        requirePrincipal(principal, issuedAt);
        if (!"POST".equals(method) || path == null || !path.startsWith("/")
            || path.length() > 2048 || containsAny(path, '\0', '\r', '\n', '?', '#')
            || scope == null || scope == ApprovalScopeTokenProvider.Scope.READ
            || idempotencyKey == null || idempotencyKey.isEmpty()
            || idempotencyKey.length() > 128
            || !idempotencyKey.matches("[A-Za-z0-9_.:/-]+")) {
            throw new ControlDeniedException("CONTROL_APPROVAL_ASSERTION_BINDING_INVALID");
        }

        Map<String, Object> requestBinding = new LinkedHashMap<>();
        requestBinding.put("schema_version", REQUEST_BINDING_SCHEMA);
        requestBinding.put("method", method);
        requestBinding.put("path", path);
        requestBinding.put("tenant_id", principal.tenantId().toString());
        requestBinding.put("client_identity", properties.clientIdentity());
        requestBinding.put("service_subject", properties.serviceSubject());
        requestBinding.put("scope", scope.value());
        requestBinding.put("idempotency_key", idempotencyKey);
        requestBinding.put("body", body);
        String requestDigest = canonical.digest(requestBinding);

        Map<String, Object> assertion = assertion(principal, issuedAt, requestDigest, scope,
            jtiSupplier.get());
        byte[] signingBytes = canonical.canonicalBytes(assertion);
        if (signingBytes.length > 32_600) {
            throw new ControlDeniedException("CONTROL_APPROVAL_ASSERTION_TOO_LARGE");
        }
        byte[] signature = sign(loadSigningKey(), signingBytes);
        String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        if (encodedSignature.length() != 86) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNATURE_INVALID");
        }
        assertion.put("signature", encodedSignature);
        try {
            byte[] document = mapper.writeValueAsBytes(assertion);
            if (document.length == 0 || document.length > 32_768) {
                throw new IllegalStateException("CONTROL_APPROVAL_ASSERTION_INVALID");
            }
            String header = Base64.getUrlEncoder().withoutPadding().encodeToString(document);
            return new SignedHeader(header, requestDigest, canonical.digest(assertion),
                assertion.get("jti").toString());
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("CONTROL_APPROVAL_ASSERTION_INVALID", error);
        }
    }

    private Map<String, Object> assertion(PrincipalContext principal, Instant issuedAt,
                                          String requestDigest,
                                          ApprovalScopeTokenProvider.Scope scope, UUID jti) {
        if (jti == null || jti.getMostSignificantBits() == 0L && jti.getLeastSignificantBits() == 0L) {
            throw new IllegalStateException("CONTROL_APPROVAL_ASSERTION_JTI_INVALID");
        }
        List<String> roles = new ArrayList<>(principal.roles());
        List<String> resources = new ArrayList<>(principal.ownedResources());
        Map<String, Object> assertion = new LinkedHashMap<>();
        assertion.put("schema_version", ASSERTION_SCHEMA);
        assertion.put("tenant_id", principal.tenantId().toString());
        assertion.put("subject", principal.subject());
        assertion.put("roles", roles);
        assertion.put("owned_resources", resources);
        assertion.put("strong_auth", true);
        assertion.put("issuer", properties.principalIssuer());
        assertion.put("audience", properties.principalAudience());
        assertion.put("issued_at", issuedAt.toString());
        assertion.put("expires_at",
            issuedAt.plusSeconds(properties.assertionTtlSeconds()).toString());
        assertion.put("jti", jti.toString());
        assertion.put("request_digest", requestDigest);
        assertion.put("client_identity", properties.clientIdentity());
        assertion.put("scope", scope.value());
        assertion.put("key_id", properties.principalKeyId());
        assertion.put("signature", "");
        return assertion;
    }

    private void requirePrincipal(PrincipalContext principal, Instant now) {
        if (principal == null || principal.tenantId() == null || !principal.strongAuth()
            || principal.subject() == null
            || !principal.subject().matches("[A-Za-z0-9_.:/@-]{1,256}")
            || principal.roles().isEmpty() || principal.roles().size() > 64
            || principal.roles().stream()
                .anyMatch(role -> !role.matches("[A-Za-z0-9_.:/@-]{1,256}"))
            || principal.ownedResources().size() > 1024
            || principal.ownedResources().stream().anyMatch(value -> value.isBlank()
                || value.length() > 2048 || containsAny(value, '\0', '\r', '\n'))
            || principal.authenticationTime() == null
            || principal.authenticationContext() == null
            || !properties.acceptedStrongAuthAcrs().contains(principal.authenticationContext())
            || principal.authenticationTime().isAfter(now.plusSeconds(30))
            || principal.authenticationTime().isBefore(
                now.minusSeconds(properties.maximumAuthenticationAgeSeconds()))) {
            throw new ControlDeniedException("CONTROL_APPROVAL_STRONG_AUTH_REQUIRED");
        }
    }

    private PrivateKey loadSigningKey() {
        Path path = properties.principalSigningKeyFile();
        try {
            SecretFilePolicy.requireReadable(path, 32, 16_384);
            byte[] file = Files.readAllBytes(path);
            try {
                byte[] pkcs8 = switch (properties.principalSigningKeyFormat()) {
                    case RAW_BASE64URL -> rawSeedPkcs8(file);
                    case PKCS8_PEM -> pemPkcs8(file);
                };
                try {
                    PrivateKey key = KeyFactory.getInstance("Ed25519")
                        .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                    if (!("EdDSA".equals(key.getAlgorithm())
                        || "Ed25519".equals(key.getAlgorithm()))) {
                        throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
                    }
                    return key;
                } finally {
                    java.util.Arrays.fill(pkcs8, (byte) 0);
                }
            } finally {
                java.util.Arrays.fill(file, (byte) 0);
            }
        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_UNAVAILABLE", error);
        }
    }

    private static byte[] rawSeedPkcs8(byte[] file) {
        String encoded = strictAsciiSecret(file);
        if (!encoded.matches("[A-Za-z0-9_-]{43}")) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
        }
        byte[] seed;
        try {
            seed = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID", error);
        }
        if (seed.length != 32) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
        }
        byte[] pkcs8 = new byte[ED25519_PKCS8_SEED_PREFIX.length + seed.length];
        System.arraycopy(ED25519_PKCS8_SEED_PREFIX, 0, pkcs8, 0,
            ED25519_PKCS8_SEED_PREFIX.length);
        System.arraycopy(seed, 0, pkcs8, ED25519_PKCS8_SEED_PREFIX.length, seed.length);
        java.util.Arrays.fill(seed, (byte) 0);
        return pkcs8;
    }

    private static byte[] pemPkcs8(byte[] file) {
        String value = new String(file, StandardCharsets.US_ASCII).replace("\r\n", "\n");
        if (value.indexOf('\r') >= 0) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
        }
        String begin = "-----BEGIN PRIVATE KEY-----\n";
        String end = "\n-----END PRIVATE KEY-----";
        if (!value.startsWith(begin) || !(value.endsWith(end) || value.endsWith(end + "\n"))) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
        }
        int endIndex = value.endsWith("\n") ? value.length() - end.length() - 1
            : value.length() - end.length();
        String body = value.substring(begin.length(), endIndex).replace("\n", "");
        if (body.isEmpty() || !body.matches("[A-Za-z0-9+/]+={0,2}")) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
        }
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID", error);
        }
    }

    private static String strictAsciiSecret(byte[] file) {
        int length = file.length;
        if (length > 0 && file[length - 1] == '\n') {
            length--;
            if (length > 0 && file[length - 1] == '\r') {
                length--;
            }
        }
        for (int index = 0; index < length; index++) {
            int value = Byte.toUnsignedInt(file[index]);
            if (value < 33 || value > 126) {
                throw new IllegalStateException("CONTROL_APPROVAL_SIGNING_KEY_INVALID");
            }
        }
        return new String(file, 0, length, StandardCharsets.US_ASCII);
    }

    private static byte[] sign(PrivateKey key, byte[] bytes) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(bytes);
            return signer.sign();
        } catch (Exception error) {
            throw new IllegalStateException("CONTROL_APPROVAL_SIGNATURE_FAILED", error);
        }
    }

    private static boolean containsAny(String value, char... needles) {
        for (char needle : needles) {
            if (value.indexOf(needle) >= 0) {
                return true;
            }
        }
        return false;
    }

    public record SignedHeader(String headerValue, String requestDigest, String assertionDigest,
                               String jti) {}
}
