package com.agenttrust.control;

import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.ApiKeyIssueResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public final class ApiKeyManager {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final byte[] pepper;

    public ApiKeyManager(ControlProperties properties) {
        this.pepper = properties.apiKeyPepper().getBytes(StandardCharsets.UTF_8).clone();
    }

    Issued issue(ApiKeyIssueRequest request) {
        Instant now = Instant.now();
        if (!request.expiresAt().isAfter(now)
            || request.expiresAt().isAfter(now.plus(365, ChronoUnit.DAYS))) {
            throw new ControlDeniedException("CONTROL_API_KEY_EXPIRY_INVALID");
        }
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        String secret = "atk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        UUID apiKeyId = UUID.randomUUID();
        var response = new ApiKeyIssueResponse("agenttrust.api-key.v1", apiKeyId, secret,
            now, request.expiresAt(), request.scopes());
        return new Issued(response, hmac(secret));
    }

    String hmac(String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(secret.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("CONTROL_HMAC_UNAVAILABLE", error);
        }
    }

    record Issued(ApiKeyIssueResponse response, String keyHash) {}
}
