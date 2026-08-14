package com.agenttrust.control;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Builds bounded TLS 1.3 clients with deployment-owned PKCS12 workload identity. */
@Component
public final class SecureRestClientFactory {
    private final ControlProperties properties;
    private final RestClient.Builder builder;
    private volatile ClientState state;

    public SecureRestClientFactory(ControlProperties properties, RestClient.Builder builder) {
        this.properties = properties;
        this.builder = builder;
        this.state = new ClientState(fingerprint(properties), buildClient(properties));
    }

    public RestClient client(java.net.URI endpoint) {
        if (endpoint == null || !"https".equalsIgnoreCase(endpoint.getScheme())
            || endpoint.getHost() == null || endpoint.getUserInfo() != null
            || endpoint.getQuery() != null || endpoint.getFragment() != null) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_ENDPOINT_MUST_USE_HTTPS");
        }
        return builder.clone().requestFactory(rotatingRequestFactory())
            .baseUrl(endpoint.toString()).build();
    }

    ClientHttpRequestFactory requestFactory() {
        var requestFactory = new JdkClientHttpRequestFactory(currentClient());
        requestFactory.setReadTimeout(Duration.ofMillis(properties.authorityTimeoutMillis()));
        return requestFactory;
    }

    /**
     * Resolve the underlying TLS client for every request. Secret-store rotations therefore take
     * effect for long-lived RestClient, RestTemplate, OAuth token, user-info, and JWKS clients
     * without accepting a plaintext fallback or requiring a process restart.
     */
    ClientHttpRequestFactory rotatingRequestFactory() {
        return (uri, method) -> requestFactory().createRequest(uri, method);
    }

    private HttpClient currentClient() {
        String current = fingerprint(properties);
        ClientState observed = state;
        if (MessageDigestSupport.equal(current, observed.fingerprint())) {
            return observed.client();
        }
        synchronized (this) {
            observed = state;
            if (!MessageDigestSupport.equal(current, observed.fingerprint())) {
                observed = new ClientState(current, buildClient(properties));
                state = observed;
            }
            return observed.client();
        }
    }

    private static HttpClient buildClient(ControlProperties properties) {
        try {
            var http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(properties.authorityTimeoutMillis()))
                .followRedirects(HttpClient.Redirect.NEVER);
            if (properties.outboundMtlsRequired()) {
                http.sslContext(sslContext(properties));
            }
            var parameters = new SSLParameters();
            parameters.setProtocols(new String[] {"TLSv1.3"});
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            http.sslParameters(parameters);
            return http.build();
        } catch (GeneralSecurityException | IOException error) {
            throw new IllegalStateException("CONTROL_OUTBOUND_MTLS_CONFIG_INVALID", error);
        }
    }

    private static SSLContext sslContext(ControlProperties properties)
        throws GeneralSecurityException, IOException {
        char[] keyPassword = readPassword(properties.outboundKeyStorePasswordFile());
        char[] trustPassword = readPassword(properties.outboundTrustStorePasswordFile());
        try {
            KeyStore keys = loadStore(properties.outboundKeyStore(), keyPassword);
            KeyStore trust = loadStore(properties.outboundTrustStore(), trustPassword);
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keys, keyPassword);
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            return context;
        } finally {
            java.util.Arrays.fill(keyPassword, '\0');
            java.util.Arrays.fill(trustPassword, '\0');
        }
    }

    private static KeyStore loadStore(Path path, char[] password)
        throws GeneralSecurityException, IOException {
        SecretFilePolicy.requireReadable(path, 1, 4 * 1024 * 1024);
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(path)) {
            store.load(input, password);
        }
        return store;
    }

    private static char[] readPassword(Path path) throws IOException {
        SecretFilePolicy.requireReadable(path, 8, 4096);
        String value = Files.readString(path, StandardCharsets.UTF_8).trim();
        if (value.length() < 8 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IOException("CONTROL_OUTBOUND_PASSWORD_FILE_INVALID");
        }
        return value.toCharArray();
    }

    private static String fingerprint(ControlProperties properties) {
        if (!properties.outboundMtlsRequired()) {
            return "TLS_SYSTEM_TRUST";
        }
        try {
            StringBuilder value = new StringBuilder();
            for (Path path : new Path[] {properties.outboundKeyStore(),
                properties.outboundKeyStorePasswordFile(), properties.outboundTrustStore(),
                properties.outboundTrustStorePasswordFile()}) {
                if (!Files.isRegularFile(path)) {
                    throw new IOException("CONTROL_OUTBOUND_MTLS_FILE_UNAVAILABLE");
                }
                value.append(path).append(':').append(Files.size(path)).append(':')
                    .append(Files.getLastModifiedTime(path).toMillis()).append(';');
            }
            return value.toString();
        } catch (IOException error) {
            throw new IllegalStateException("CONTROL_OUTBOUND_MTLS_CONFIG_INVALID", error);
        }
    }

    private record ClientState(String fingerprint, HttpClient client) {}

    /** Keeps comparison constant-time even though the fingerprint contains metadata only. */
    private static final class MessageDigestSupport {
        private MessageDigestSupport() {}

        static boolean equal(String first, String second) {
            return java.security.MessageDigest.isEqual(first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
        }
    }
}
