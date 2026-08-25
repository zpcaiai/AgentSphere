package com.agenttrust.control;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonFactoryBuilder;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/** Verifies Approval evidence with a rotating, public-only Ed25519 authority keyring. */
@Component
public final class ApprovalAuthoritySignatureVerifier {
    private static final String KEYRING_SCHEMA =
        "agenttrust.approval-decision-evidence-keyring.v1";
    private static final Set<String> KEYRING_FIELDS = Set.of(
        "schema_version", "issuer", "keys");
    private static final Set<String> KEY_FIELDS = Set.of(
        "key_id", "algorithm", "public_key_base64url", "status", "not_before",
        "expires_at");
    private static final byte[] ED25519_X509_PUBLIC_PREFIX = HexFormat.of().parseHex(
        "302a300506032b6570032100");
    private final ApprovalIntegrationProperties properties;
    private final ObjectMapper mapper;
    private final Clock clock;

    public ApprovalAuthoritySignatureVerifier(ApprovalIntegrationProperties properties) {
        this(properties, Clock.systemUTC());
    }

    ApprovalAuthoritySignatureVerifier(ApprovalIntegrationProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        JsonFactory factory = new JsonFactoryBuilder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(8).maxNumberLength(64).maxStringLength(16_384).build())
            .build();
        this.mapper = new ObjectMapper(factory);
        loadKeyring(clock.instant());
    }

    public void verifyFresh(String issuer, String keyId, Instant decidedAt,
                            String evidenceDigest, String encodedSignature) {
        verify(issuer, keyId, decidedAt, evidenceDigest, encodedSignature, false);
    }

    public void verifyPersisted(String issuer, String keyId, Instant decidedAt,
                                String evidenceDigest, String encodedSignature) {
        verify(issuer, keyId, decidedAt, evidenceDigest, encodedSignature, true);
    }

    private void verify(String issuer, String keyId, Instant decidedAt, String evidenceDigest,
                        String encodedSignature, boolean persistedReplay) {
        if (!AuthorityJson.identifier(issuer, 256)
            || keyId == null || !keyId.matches("[A-Za-z0-9_.-]{1,128}")
            || decidedAt == null
            || evidenceDigest == null || !evidenceDigest.matches("[a-f0-9]{64}")
            || encodedSignature == null || !encodedSignature.matches("[A-Za-z0-9_-]{86}")) {
            throw invalidEvidence(null);
        }
        try {
            Keyring keyring = loadKeyring(clock.instant());
            VerificationKey selected = keyring.keys().get(keyId);
            if (!keyring.issuer().equals(issuer) || selected == null
                || !persistedReplay && !"ACTIVE".equals(selected.status())
                || decidedAt.isBefore(selected.notBefore())
                || !decidedAt.isBefore(selected.expiresAt())) {
                throw invalidEvidence(null);
            }
            byte[] signatureBytes = Base64.getUrlDecoder().decode(encodedSignature);
            if (signatureBytes.length != 64 || !Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signatureBytes).equals(encodedSignature)) {
                throw invalidEvidence(null);
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(selected.publicKey());
            verifier.update(evidenceDigest.getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signatureBytes)) {
                throw invalidEvidence(null);
            }
        } catch (ControlUnavailableException error) {
            throw error;
        } catch (Exception error) {
            throw invalidEvidence(error);
        }
    }

    private Keyring loadKeyring(Instant now) {
        byte[] document = null;
        try {
            SecretFilePolicy.requireReadable(properties.authorityVerificationKeyringFile(),
                2, 1_048_576);
            document = Files.readAllBytes(properties.authorityVerificationKeyringFile());
            JsonNode root = mapper.readTree(document);
            if (!AuthorityJson.exact(root, KEYRING_FIELDS)
                || !KEYRING_SCHEMA.equals(root.path("schema_version").asText())
                || !AuthorityJson.identifier(root.path("issuer"), 256)
                || !root.path("keys").isArray() || root.path("keys").isEmpty()
                || root.path("keys").size() > 128) {
                throw invalidKeyring(null);
            }
            Map<String, VerificationKey> keys = new HashMap<>();
            int active = 0;
            for (JsonNode value : root.path("keys")) {
                if (!AuthorityJson.exact(value, KEY_FIELDS)
                    || !value.path("key_id").isTextual()
                    || !value.path("key_id").asText().matches("[A-Za-z0-9_.-]{1,128}")
                    || !"Ed25519".equals(value.path("algorithm").asText())
                    || !value.path("public_key_base64url").isTextual()
                    || !value.path("public_key_base64url").asText()
                        .matches("[A-Za-z0-9_-]{43}")
                    || !Set.of("ACTIVE", "VERIFY_ONLY")
                        .contains(value.path("status").asText())
                    || !AuthorityJson.instant(value.path("not_before"))
                    || !AuthorityJson.instant(value.path("expires_at"))) {
                    throw invalidKeyring(null);
                }
                Instant notBefore = Instant.parse(value.path("not_before").asText());
                Instant expiresAt = Instant.parse(value.path("expires_at").asText());
                if (!notBefore.isBefore(expiresAt)) {
                    throw invalidKeyring(null);
                }
                String status = value.path("status").asText();
                if ("ACTIVE".equals(status)) {
                    active++;
                    if (now.isBefore(notBefore) || !now.isBefore(expiresAt)) {
                        throw invalidKeyring(null);
                    }
                }
                String keyId = value.path("key_id").asText();
                VerificationKey prior = keys.put(keyId, new VerificationKey(
                    publicKey(value.path("public_key_base64url").asText()), notBefore,
                    expiresAt, status));
                if (prior != null) {
                    throw invalidKeyring(null);
                }
            }
            if (active != 1) {
                throw invalidKeyring(null);
            }
            return new Keyring(root.path("issuer").asText(), Map.copyOf(keys));
        } catch (IllegalStateException error) {
            throw error;
        } catch (IOException | RuntimeException error) {
            throw invalidKeyring(error);
        } finally {
            if (document != null) {
                java.util.Arrays.fill(document, (byte) 0);
            }
        }
    }

    private static PublicKey publicKey(String encoded) {
        byte[] rawKey = null;
        byte[] encodedKey = null;
        try {
            rawKey = Base64.getUrlDecoder().decode(encoded);
            if (rawKey.length != 32 || !Base64.getUrlEncoder().withoutPadding()
                .encodeToString(rawKey).equals(encoded)) {
                throw invalidKeyring(null);
            }
            encodedKey = new byte[ED25519_X509_PUBLIC_PREFIX.length + rawKey.length];
            System.arraycopy(ED25519_X509_PUBLIC_PREFIX, 0, encodedKey, 0,
                ED25519_X509_PUBLIC_PREFIX.length);
            System.arraycopy(rawKey, 0, encodedKey, ED25519_X509_PUBLIC_PREFIX.length,
                rawKey.length);
            PublicKey key = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(encodedKey));
            if (!("EdDSA".equalsIgnoreCase(key.getAlgorithm())
                || "Ed25519".equalsIgnoreCase(key.getAlgorithm()))) {
                throw invalidKeyring(null);
            }
            return key;
        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception error) {
            throw invalidKeyring(error);
        } finally {
            if (rawKey != null) {
                java.util.Arrays.fill(rawKey, (byte) 0);
            }
            if (encodedKey != null) {
                java.util.Arrays.fill(encodedKey, (byte) 0);
            }
        }
    }

    private static IllegalStateException invalidKeyring(Exception cause) {
        return cause == null
            ? new IllegalStateException("CONTROL_APPROVAL_AUTHORITY_KEYRING_INVALID")
            : new IllegalStateException("CONTROL_APPROVAL_AUTHORITY_KEYRING_INVALID", cause);
    }

    private static ControlUnavailableException invalidEvidence(Exception cause) {
        return cause == null
            ? new ControlUnavailableException("CONTROL_APPROVAL_EVIDENCE_INVALID")
            : new ControlUnavailableException("CONTROL_APPROVAL_EVIDENCE_INVALID", cause);
    }

    private record VerificationKey(PublicKey publicKey, Instant notBefore, Instant expiresAt,
                                   String status) {}
    private record Keyring(String issuer, Map<String, VerificationKey> keys) {}
}
