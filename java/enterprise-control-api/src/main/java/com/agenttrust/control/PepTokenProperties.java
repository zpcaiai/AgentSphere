package com.agenttrust.control;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Independent service credentials for each enterprise PEP operation. */
@ConfigurationProperties(prefix = "agenttrust.control.pep-tokens")
public record PepTokenProperties(
    Path approvalTokenFile,
    Path queryTokenFile
) {
    public PepTokenProperties {
        List<Path> paths = List.of(approvalTokenFile, queryTokenFile);
        if (paths.stream().anyMatch(path -> path == null || !path.isAbsolute())
            || new HashSet<>(paths).size() != paths.size()) {
            throw new IllegalArgumentException("CONTROL_PEP_TOKEN_FILES_INVALID");
        }
    }
}
