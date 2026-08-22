package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ApprovalPrincipalAssertionSignerTest {
    @TempDir Path temporary;

    @Test
    void matchesRustEd25519AndRfc8785GoldenVector() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode golden = mapper.readTree(Files.readAllBytes(repositoryFile(
            "schemas/approval/principal-assertion.golden.json")));
        Path signingKey = temporary.resolve("principal.seed");
        Files.writeString(signingKey,
            golden.path("private_seed_base64url_test_only").textValue() + "\n",
            StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(signingKey, Set.of(PosixFilePermission.OWNER_READ));

        Instant issuedAt = Instant.parse("2030-01-02T03:04:05Z");
        CanonicalDigest canonical = new CanonicalDigest(mapper);
        var signer = ApprovalPrincipalAssertionSigner.forTest(
            ApprovalTestProperties.create(signingKey), canonical, mapper,
            Clock.fixed(issuedAt, ZoneOffset.UTC),
            () -> UUID.fromString("01900000-0000-7000-8000-000000000005"));
        var principal = new PrincipalContext(
            "human-approver@example.test",
            UUID.fromString("01900000-0000-7000-8000-000000000001"),
            Set.of("production-approver", "change-manager"), Set.of(), Set.of(),
            Set.of("urn:agenttrust:resource:payments-api"), true, issuedAt,
            "urn:agenttrust:acr:mfa");
        JsonNode request = golden.path("request");
        @SuppressWarnings("unchecked")
        Map<String, Object> body = mapper.convertValue(request.path("body"), Map.class);
        var signed = signer.sign(principal, request.path("method").textValue(),
            request.path("path").textValue(), ApprovalScopeTokenProvider.Scope.DECIDE,
            request.path("idempotency_key").textValue(), body);

        assertEquals(golden.path("request_digest").textValue(), signed.requestDigest());
        assertEquals(golden.path("assertion_digest").textValue(), signed.assertionDigest());
        assertEquals(golden.path("header_value_base64url").textValue(), signed.headerValue());
        JsonNode decoded = mapper.readTree(Base64.getUrlDecoder().decode(signed.headerValue()));
        assertEquals(golden.path("signed_assertion"), decoded);
    }

    private static Path repositoryFile(String relative) {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null) {
            Path candidate = current.resolve(relative);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("TEST_REPOSITORY_FILE_NOT_FOUND");
    }
}
