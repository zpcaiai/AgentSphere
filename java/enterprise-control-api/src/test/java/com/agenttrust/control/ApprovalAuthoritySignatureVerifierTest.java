package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ApprovalAuthoritySignatureVerifierTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-08-24T05:00:00Z");
    @TempDir Path temporary;

    @Test
    void verifiesActiveAndHistoricalVerifyOnlyKeysWithinTheirReceiptWindows() throws Exception {
        KeyPair active = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair historical = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair verifyOnlyCurrent = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Path principalKey = temporary.resolve("principal.seed");
        writeKeyring(principalKey, List.of(
            entry("approval-key-2", active, "ACTIVE", "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z"),
            entry("approval-key-1", historical, "VERIFY_ONLY", "2025-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z"),
            entry("approval-key-legacy-current", verifyOnlyCurrent, "VERIFY_ONLY",
                "2025-01-01T00:00:00Z", "2027-01-01T00:00:00Z")));
        var verifier = new ApprovalAuthoritySignatureVerifier(
            ApprovalTestProperties.create(principalKey),
            Clock.fixed(NOW, ZoneOffset.UTC));
        String digest = "a".repeat(64);

        assertDoesNotThrow(() -> verifier.verifyFresh("agenttrust-approval", "approval-key-2", NOW,
            digest, sign(active, digest)));
        Instant historicalDecision = Instant.parse("2025-06-01T00:00:00Z");
        assertDoesNotThrow(() -> verifier.verifyPersisted("agenttrust-approval", "approval-key-1",
            historicalDecision, digest, sign(historical, digest)));
        Instant notBefore = Instant.parse("2025-01-01T00:00:00Z");
        assertDoesNotThrow(() -> verifier.verifyPersisted("agenttrust-approval", "approval-key-1",
            notBefore, digest, sign(historical, digest)));
        Instant expiresAt = Instant.parse("2026-01-01T00:00:00Z");
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "agenttrust-approval", "approval-key-1", historicalDecision, digest,
            sign(historical, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyPersisted(
            "agenttrust-approval", "approval-key-1", expiresAt, digest,
            sign(historical, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyPersisted(
            "agenttrust-approval", "approval-key-1", NOW, digest, sign(historical, digest)));
        assertDoesNotThrow(() -> verifier.verifyPersisted("agenttrust-approval",
            "approval-key-legacy-current", NOW, digest, sign(verifyOnlyCurrent, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "agenttrust-approval", "approval-key-legacy-current", NOW, digest,
            sign(verifyOnlyCurrent, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "other-issuer", "approval-key-2", NOW, digest, sign(active, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "agenttrust-approval", "other-key", NOW, digest, sign(active, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "agenttrust-approval", "approval-key-2", NOW, "b".repeat(64),
            sign(active, digest)));
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "agenttrust-approval", "approval-key-2", NOW, digest, "A".repeat(86)));
        String canonicalSignature = sign(active, digest);
        assertThrows(ControlUnavailableException.class, () -> verifier.verifyFresh(
            "agenttrust-approval", "approval-key-2", NOW, digest,
            nonCanonicalAlias(canonicalSignature)));
    }

    @Test
    void startupRejectsKeyringsWithoutExactlyOneCurrentlyValidActiveKey() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Path principalKey = temporary.resolve("principal.seed");
        writeKeyring(principalKey, List.of(entry("approval-key-1", pair, "VERIFY_ONLY",
            "2025-01-01T00:00:00Z", "2027-01-01T00:00:00Z")));

        assertThrows(IllegalStateException.class, () -> new ApprovalAuthoritySignatureVerifier(
            ApprovalTestProperties.create(principalKey), Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    private void writeKeyring(Path principalKey, List<Map<String, String>> keys) throws Exception {
        Path keyring = ApprovalTestProperties.create(principalKey)
            .authorityVerificationKeyringFile();
        Files.writeString(keyring, MAPPER.writeValueAsString(Map.of(
            "schema_version", "agenttrust.approval-decision-evidence-keyring.v1",
            "issuer", "agenttrust-approval", "keys", keys)), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(keyring, Set.of(PosixFilePermission.OWNER_READ));
    }

    private static Map<String, String> entry(String keyId, KeyPair pair, String status,
                                              String notBefore, String expiresAt) {
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        return Map.of("key_id", keyId, "algorithm", "Ed25519",
            "public_key_base64url",
            Base64.getUrlEncoder().withoutPadding().encodeToString(raw),
            "status", status, "not_before", notBefore, "expires_at", expiresAt);
    }

    private static String sign(KeyPair pair, String digest) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(digest.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }

    private static String nonCanonicalAlias(String canonical) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int last = alphabet.indexOf(canonical.charAt(canonical.length() - 1));
        if (last < 0 || last % 4 != 0) {
            throw new AssertionError("canonical base64url signature expected");
        }
        return canonical.substring(0, canonical.length() - 1) + alphabet.charAt(last + 1);
    }
}
