package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AguiSigningKeyProviderTest {
    @TempDir Path directory;

    @Test
    void mountedEd25519KeySignsBrowserVerifiableEvent() throws Exception {
        var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pair.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
        Path privateKey = secret("agui.pem", pem.getBytes(StandardCharsets.US_ASCII));
        Path hmacKey = secret("resume.key", "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        Path token = secret("service.token", "0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        var properties = new ControlProperties(List.of("https://console.example.invalid"), token,
            "p".repeat(32), URI.create("https://idp.example.invalid/tenant"),
            "agenttrust-control", URI.create("https://idp.example.invalid/oauth2/authorize"),
            URI.create("https://idp.example.invalid/oauth2/token"),
            URI.create("https://idp.example.invalid/oauth2/userinfo"),
            URI.create("https://pep.example.invalid"),
            URI.create("https://idp.example.invalid/.well-known/jwks.json"),
            Map.of("tasks", URI.create("https://tasks.example.invalid")), 100, 3_000,
            1_048_576, privateKey, hmacKey, 300, Path.of("/tmp/client.p12"),
            Path.of("/tmp/client.pass"), Path.of("/tmp/trust.p12"),
            Path.of("/tmp/trust.pass"), true, "agenttrust_enterprise_app", true);
        byte[] event = "{\"event_id\":\"1\"}".getBytes(StandardCharsets.UTF_8);
        byte[] signed = Base64.getUrlDecoder().decode(
            new AguiSigningKeyProvider(properties).signEvent(event));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(pair.getPublic());
        verifier.update(event);
        assertTrue(verifier.verify(signed));
    }

    private Path secret(String name, byte[] value) throws Exception {
        Path path = directory.resolve(name);
        Files.write(path, value);
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Windows test workers do not expose POSIX permissions.
        }
        return path;
    }
}
