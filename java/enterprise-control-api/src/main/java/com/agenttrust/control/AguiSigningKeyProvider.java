package com.agenttrust.control;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/** Reloads event and resume-token key material per operation to support mounted-secret rotation. */
@Component
public final class AguiSigningKeyProvider {
    private static final int MAXIMUM_KEY_BYTES = 16 * 1024;
    private final Path signingKey;
    private final Path resumeHmacKey;

    public AguiSigningKeyProvider(ControlProperties properties) {
        signingKey = properties.aguiSigningKeyFile();
        resumeHmacKey = properties.aguiResumeHmacKeyFile();
        privateKey();
        hmacKey();
    }

    public String signEvent(byte[] canonicalEvent) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey());
            signature.update(canonicalEvent);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
        } catch (java.security.GeneralSecurityException error) {
            throw new IllegalStateException("CONTROL_AGUI_SIGNATURE_FAILED", error);
        }
    }

    public byte[] tokenMac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey(), "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (java.security.GeneralSecurityException error) {
            throw new IllegalStateException("CONTROL_AGUI_TOKEN_FAILED", error);
        }
    }

    private PrivateKey privateKey() {
        try {
            byte[] file = readBounded(signingKey, 64, MAXIMUM_KEY_BYTES);
            String pem = new String(file, StandardCharsets.US_ASCII).trim();
            if (!pem.startsWith("-----BEGIN PRIVATE KEY-----")
                || !pem.endsWith("-----END PRIVATE KEY-----")) {
                throw new IllegalStateException("CONTROL_AGUI_SIGNING_KEY_INVALID");
            }
            String encoded = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(encoded);
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IOException | java.security.GeneralSecurityException | IllegalArgumentException error) {
            throw new IllegalStateException("CONTROL_AGUI_SIGNING_KEY_INVALID", error);
        }
    }

    private byte[] hmacKey() {
        try {
            byte[] value = readBounded(resumeHmacKey, 32, 512);
            if (value[value.length - 1] == '\n') {
                value = java.util.Arrays.copyOf(value, value.length - 1);
            }
            if (value.length < 32) {
                throw new IllegalStateException("CONTROL_AGUI_HMAC_KEY_INVALID");
            }
            return value;
        } catch (IOException error) {
            throw new IllegalStateException("CONTROL_AGUI_HMAC_KEY_INVALID", error);
        }
    }

    private static byte[] readBounded(Path path, int minimum, int maximum) throws IOException {
        SecretFilePolicy.requireReadable(path, minimum, maximum);
        return Files.readAllBytes(path);
    }
}
