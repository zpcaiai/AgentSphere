package com.agenttrust.control;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Exact, least-privilege token-file configuration for non-Approval authorities. */
@ConfigurationProperties(prefix = "agenttrust.control.authority-tokens")
public record AuthorityTokenProperties(
    Map<String, Path> readTokenFiles,
    Map<String, Path> operationTokenFiles
) {
    static final Set<String> READ_AUTHORITIES = Set.of(
        "agents", "tasks", "evidence", "incidents", "policies", "tools",
        "credentials", "packs", "trace", "compliance", "audit", "models", "data",
        "context", "anomalies", "security_evaluations", "supply_chain", "domain_packs",
        "sre", "deployments");
    static final Set<String> OPERATIONS = Set.of(
        "enterprise.mutate", "policies.mutate", "incidents.mutate", "packs.mutate", "tasks.command",
        "tasks.transitions");

    public AuthorityTokenProperties {
        if (readTokenFiles == null || operationTokenFiles == null
            || !readTokenFiles.keySet().equals(READ_AUTHORITIES)
            || !operationTokenFiles.keySet().equals(OPERATIONS)) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_TOKEN_SCOPE_INVALID");
        }
        readTokenFiles = Map.copyOf(readTokenFiles);
        operationTokenFiles = Map.copyOf(operationTokenFiles);
        Set<Path> paths = new HashSet<>();
        readTokenFiles.values().forEach(path -> requirePath(path, paths));
        operationTokenFiles.values().forEach(path -> requirePath(path, paths));
    }

    private static void requirePath(Path path, Set<Path> paths) {
        if (path == null || !path.isAbsolute() || !paths.add(path.normalize())) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_TOKEN_FILE_INVALID");
        }
    }
}
