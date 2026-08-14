package com.agenttrust.control;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Component;

/** Reads the service credential for every request so a CSI/Vault rotation needs no restart. */
@Component
public final class ServiceTokenProvider {
    private static final int MAXIMUM_TOKEN_BYTES = 8192;
    private final Path path;

    public ServiceTokenProvider(ControlProperties properties) {
        this.path = properties.serviceTokenFile();
        token();
    }

    public String token() {
        try {
            SecretFilePolicy.requireReadable(path, 16, MAXIMUM_TOKEN_BYTES);
            String value = Files.readString(path, StandardCharsets.UTF_8).trim();
            if (value.length() < 16 || value.indexOf('\0') >= 0
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
                throw new IllegalStateException("CONTROL_SERVICE_TOKEN_FILE_INVALID");
            }
            return value;
        } catch (IOException error) {
            throw new IllegalStateException("CONTROL_SERVICE_TOKEN_FILE_UNAVAILABLE", error);
        }
    }

}
