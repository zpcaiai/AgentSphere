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
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.stereotype.Component;

/** Signs one exact authority request with bounded claims from the verified OIDC session. */
@Component
public final class HumanPrincipalAssertionSigner {
    private static final String ASSERTION_SCHEMA =
        "agenttrust.signed-human-principal-assertion.v1";
    private static final String REQUEST_BINDING_SCHEMA =
        "agenttrust.human-principal-request-binding.v1";
    private static final String KEY_USAGE = "HUMAN_PRINCIPAL_ASSERTION";
    private static final byte[] ED25519_PKCS8_SEED_PREFIX = HexFormat.of().parseHex(
        "302e020100300506032b657004220420");
    private final HumanPrincipalAssertionProperties properties;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final Supplier<UUID> jtiSupplier;

    public HumanPrincipalAssertionSigner(HumanPrincipalAssertionProperties properties,
                                         CanonicalDigest canonical, ObjectMapper mapper) {
        this(properties, canonical, mapper, Clock.systemUTC(), UUID::randomUUID);
    }

    private HumanPrincipalAssertionSigner(HumanPrincipalAssertionProperties properties,
                                          CanonicalDigest canonical, ObjectMapper mapper,
                                          Clock clock, Supplier<UUID> jtiSupplier) {
        this.properties = properties;
        this.canonical = canonical;
        this.mapper = mapper;
        this.clock = clock;
        this.jtiSupplier = jtiSupplier;
        loadSigningKey();
    }

    static HumanPrincipalAssertionSigner forTest(HumanPrincipalAssertionProperties properties,
                                                  CanonicalDigest canonical, ObjectMapper mapper,
                                                  Clock clock, Supplier<UUID> jtiSupplier) {
        return new HumanPrincipalAssertionSigner(properties, canonical, mapper, clock, jtiSupplier);
    }

    public SignedHeader sign(PrincipalContext principal, String method, String path, String scope,
                             String idempotencyKey, Object body, boolean requireStrongAuth) {
        Instant issuedAt = clock.instant();
        requirePrincipal(principal, issuedAt, requireStrongAuth);
        requireBinding(method, path, scope, idempotencyKey);

        Map<String, Object> requestBinding = new LinkedHashMap<>();
        requestBinding.put("schema_version", REQUEST_BINDING_SCHEMA);
        requestBinding.put("method", method);
        requestBinding.put("path", path);
        requestBinding.put("tenant_id", principal.tenantId().toString());
        requestBinding.put("client_identity", properties.clientIdentity());
        requestBinding.put("service_subject", properties.serviceSubject());
        requestBinding.put("scope", scope);
        requestBinding.put("idempotency_key", idempotencyKey);
        requestBinding.put("body", body);
        String requestDigest = canonical.digest(requestBinding);

        UUID jti = jtiSupplier.get();
        if (jti == null || jti.getMostSignificantBits() == 0L && jti.getLeastSignificantBits() == 0L) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_JTI_INVALID");
        }
        Map<String, Object> assertion = new LinkedHashMap<>();
        assertion.put("schema_version", ASSERTION_SCHEMA);
        assertion.put("tenant_id", principal.tenantId().toString());
        assertion.put("subject", principal.subject());
        // The shared Rust contract deserializes these uniqueness-constrained claims into
        // BTreeSet before reconstructing the Ed25519 signing bytes. Sort explicitly so the Java
        // signer emits those exact cross-language canonical bytes for every Set implementation.
        assertion.put("roles", new ArrayList<>(new TreeSet<>(principal.roles())));
        assertion.put("project_ids", new ArrayList<>(new TreeSet<>(principal.projectIds())));
        assertion.put("approval_ids", new ArrayList<>(new TreeSet<>(principal.approvalIds())));
        assertion.put("owned_resources", new ArrayList<>(new TreeSet<>(principal.ownedResources())));
        assertion.put("strong_auth", principal.strongAuth());
        assertion.put("authentication_time", principal.authenticationTime().toString());
        assertion.put("authentication_context", principal.authenticationContext());
        assertion.put("issuer", properties.issuer());
        assertion.put("audience", properties.audience());
        assertion.put("issued_at", issuedAt.toString());
        assertion.put("expires_at", issuedAt.plusSeconds(properties.assertionTtlSeconds()).toString());
        assertion.put("jti", jti.toString());
        assertion.put("request_digest", requestDigest);
        assertion.put("client_identity", properties.clientIdentity());
        assertion.put("service_subject", properties.serviceSubject());
        assertion.put("scope", scope);
        assertion.put("key_id", properties.keyId());
        assertion.put("key_usage", KEY_USAGE);
        assertion.put("signature", "");
        byte[] signingBytes = canonical.canonicalBytes(assertion);
        if (signingBytes.length == 0 || signingBytes.length > 65_536) {
            throw new ControlDeniedException("CONTROL_HUMAN_ASSERTION_TOO_LARGE");
        }
        String signature = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(sign(loadSigningKey(), signingBytes));
        if (!signature.matches("[A-Za-z0-9_-]{86}")) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_SIGNATURE_INVALID");
        }
        assertion.put("signature", signature);
        try {
            byte[] document = mapper.writeValueAsBytes(assertion);
            if (document.length == 0 || document.length > 65_536) {
                throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_INVALID");
            }
            return new SignedHeader(
                Base64.getUrlEncoder().withoutPadding().encodeToString(document),
                requestDigest, canonical.digest(assertion), jti.toString());
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_INVALID", error);
        }
    }

    private void requirePrincipal(PrincipalContext principal, Instant now,
                                  boolean requireStrongAuth) {
        if (principal == null || principal.tenantId() == null || principal.subject() == null
            || !principal.subject().matches("[A-Za-z0-9_.:/@-]{1,256}")
            || requireStrongAuth && !principal.strongAuth()
            || principal.roles().isEmpty() || principal.roles().size() > 64
            || principal.roles().stream().anyMatch(value -> !identifier(value, 256))
            || principal.projectIds().size() > 1024
            || principal.projectIds().stream().anyMatch(value -> !identifier(value, 256))
            || principal.approvalIds().size() > 1024
            || principal.approvalIds().stream().anyMatch(value -> !identifier(value, 256))
            || principal.ownedResources().size() > 1024
            || principal.ownedResources().stream().anyMatch(value -> value.isBlank()
                || value.length() > 2048 || unsafe(value))
            || principal.authenticationTime() == null || principal.authenticationContext() == null
            || !properties.acceptedAuthenticationContexts()
                .contains(principal.authenticationContext())
            || principal.authenticationTime().isAfter(now.plusSeconds(30))
            || principal.authenticationTime().isBefore(
                now.minusSeconds(properties.maximumAuthenticationAgeSeconds()))) {
            throw new ControlDeniedException("CONTROL_HUMAN_ASSERTION_PRINCIPAL_INVALID");
        }
    }

    private static void requireBinding(String method, String path, String scope,
                                       String idempotencyKey) {
        if (!"POST".equals(method) || path == null || !path.startsWith("/")
            || path.length() > 2048 || unsafe(path) || path.contains("?") || path.contains("#")
            || path.contains("\\") || java.util.Arrays.asList(path.split("/")).contains("..")
            || scope == null || !scope.matches("[A-Za-z0-9_.:-]{1,128}")
            || idempotencyKey == null
            || !idempotencyKey.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new ControlDeniedException("CONTROL_HUMAN_ASSERTION_BINDING_INVALID");
        }
    }

    private PrivateKey loadSigningKey() {
        Path path = properties.signingKeyFile();
        try {
            SecretFilePolicy.requireReadable(path, 32, 16_384);
            byte[] file = Files.readAllBytes(path);
            try {
                byte[] pkcs8 = switch (properties.signingKeyFormat()) {
                    case RAW_BASE64URL -> rawSeedPkcs8(file);
                    case PKCS8_PEM -> pemPkcs8(file);
                };
                try {
                    PrivateKey key = KeyFactory.getInstance("Ed25519")
                        .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                    if (!"EdDSA".equalsIgnoreCase(key.getAlgorithm())
                        && !"Ed25519".equalsIgnoreCase(key.getAlgorithm())) {
                        throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
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
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_UNAVAILABLE", error);
        }
    }

    private static byte[] rawSeedPkcs8(byte[] file) {
        String encoded = strictAscii(file);
        if (!encoded.matches("[A-Za-z0-9_-]{43}")) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
        }
        byte[] seed;
        try {
            seed = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID", error);
        }
        if (seed.length != 32) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
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
        String begin = "-----BEGIN PRIVATE KEY-----\n";
        String end = "\n-----END PRIVATE KEY-----";
        if (value.indexOf('\r') >= 0 || !value.startsWith(begin)
            || !(value.endsWith(end) || value.endsWith(end + "\n"))) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
        }
        int endIndex = value.endsWith("\n") ? value.length() - end.length() - 1
            : value.length() - end.length();
        String body = value.substring(begin.length(), endIndex).replace("\n", "");
        if (body.isEmpty() || !body.matches("[A-Za-z0-9+/]+={0,2}")) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
        }
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID", error);
        }
    }

    private static String strictAscii(byte[] file) {
        int length = file.length;
        if (length > 0 && file[length - 1] == '\n') {
            length--;
            if (length > 0 && file[length - 1] == '\r') length--;
        }
        for (int index = 0; index < length; index++) {
            int value = Byte.toUnsignedInt(file[index]);
            if (value < 33 || value > 126) {
                throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_KEY_INVALID");
            }
        }
        return new String(file, 0, length, StandardCharsets.US_ASCII);
    }

    private static byte[] sign(PrivateKey key, byte[] value) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(value);
            return signer.sign();
        } catch (Exception error) {
            throw new IllegalStateException("CONTROL_HUMAN_ASSERTION_SIGNING_FAILED", error);
        }
    }

    private static boolean identifier(String value, int maximum) {
        return value != null && value.matches("[A-Za-z0-9_.:/@-]{1," + maximum + "}");
    }

    private static boolean unsafe(String value) {
        return value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }

    public record SignedHeader(String headerValue, String requestDigest,
                               String assertionDigest, String jti) {}
}
