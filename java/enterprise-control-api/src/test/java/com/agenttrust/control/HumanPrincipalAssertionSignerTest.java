package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HumanPrincipalAssertionSignerTest {
    @TempDir Path temporary;

    @Test
    void bindsEveryAuthoritativePrincipalClaimAndExactRequestBody() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Instant now = Instant.parse("2030-01-02T03:04:05Z");
        HumanPrincipalAssertionSigner signer = signer(mapper, now);
        PrincipalContext principal = principal(now, true);
        Map<String, Object> body = Map.of(
            "schema_version", "agenttrust.enterprise-mutation.v1",
            "operation", "UPDATE_QUOTA",
            "project_id", "project-7",
            "approval_ids", Set.of("approval-2", "approval-1"));

        var signed = signer.sign(principal, "POST", "/v1/enterprise/actions",
            "enterprise:mutate", "mutation:01900000-0000-7000-8000-000000000008",
            body, true);
        JsonNode assertion = mapper.readTree(Base64.getUrlDecoder().decode(signed.headerValue()));

        assertEquals("agenttrust.signed-human-principal-assertion.v1",
            assertion.path("schema_version").textValue());
        assertEquals("01900000-0000-7000-8000-000000000001",
            assertion.path("tenant_id").textValue());
        assertEquals("human@example.test", assertion.path("subject").textValue());
        assertEquals("quota-manager", assertion.path("roles").get(0).textValue());
        assertEquals("tenant-admin", assertion.path("roles").get(1).textValue());
        assertEquals("project-7", assertion.path("project_ids").get(0).textValue());
        assertEquals("approval-1", assertion.path("approval_ids").get(0).textValue());
        assertEquals("approval-2", assertion.path("approval_ids").get(1).textValue());
        assertEquals("enterprise:mutate", assertion.path("scope").textValue());
        assertEquals(signed.requestDigest(), assertion.path("request_digest").textValue());
        assertEquals(86, assertion.path("signature").textValue().length());

        var altered = signer.sign(principal, "POST", "/v1/enterprise/actions",
            "enterprise:mutate", "mutation:01900000-0000-7000-8000-000000000008",
            Map.of("schema_version", "agenttrust.enterprise-mutation.v1",
                "operation", "UPDATE_QUOTA", "project_id", "project-8",
                "approval_ids", Set.of("approval-2", "approval-1")), true);
        assertNotEquals(signed.requestDigest(), altered.requestDigest());
    }

    @Test
    void strongMutationRejectsWeakOrStalePrincipal() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Instant now = Instant.parse("2030-01-02T03:04:05Z");
        HumanPrincipalAssertionSigner signer = signer(mapper, now);
        assertThrows(ControlDeniedException.class, () -> signer.sign(
            principal(now, false), "POST", "/v1/enterprise/actions", "enterprise:mutate",
            "mutation:01900000-0000-7000-8000-000000000008", Map.of(), true));
        assertThrows(ControlDeniedException.class, () -> signer.sign(
            principal(now.minusSeconds(901), true), "POST", "/v1/enterprise/actions",
            "enterprise:mutate", "mutation:01900000-0000-7000-8000-000000000008",
            Map.of(), true));
    }

    private HumanPrincipalAssertionSigner signer(ObjectMapper mapper, Instant now)
        throws Exception {
        Path key = temporary.resolve("human-principal.seed");
        Files.writeString(key, "W1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1s\n",
            StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(key, Set.of(PosixFilePermission.OWNER_READ));
        HumanPrincipalAssertionProperties properties = new HumanPrincipalAssertionProperties(
            key.toAbsolutePath(),
            HumanPrincipalAssertionProperties.SigningKeyFormat.RAW_BASE64URL,
            "enterprise-idp", "agenttrust-governance", "human-assertion-key-1",
            "URI:spiffe://agenttrust/enterprise-bff", "enterprise-bff", 300,
            Set.of("urn:agenttrust:acr:mfa"), 900);
        return HumanPrincipalAssertionSigner.forTest(properties, new CanonicalDigest(mapper),
            mapper, Clock.fixed(now, ZoneOffset.UTC),
            () -> UUID.fromString("01900000-0000-7000-8000-000000000009"));
    }

    private static PrincipalContext principal(Instant authenticationTime, boolean strongAuth) {
        return new PrincipalContext("human@example.test",
            UUID.fromString("01900000-0000-7000-8000-000000000001"),
            new LinkedHashSet<>(List.of("tenant-admin", "quota-manager")), Set.of("project-7"),
            new LinkedHashSet<>(List.of("approval-2", "approval-1")),
            Set.of("tenant:current"), strongAuth,
            authenticationTime, "urn:agenttrust:acr:mfa");
    }
}
