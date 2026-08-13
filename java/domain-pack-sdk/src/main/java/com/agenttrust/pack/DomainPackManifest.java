package com.agenttrust.pack;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public record DomainPackManifest(
    String schemaVersion,
    String packId,
    String version,
    String digest,
    String publisherIdentity,
    Set<String> permissions,
    List<ToolDefinition> tools,
    String policyBundleRef,
    String evaluatorRef,
    Set<String> threatScenarioRefs
) {
    private static final Pattern DIGEST = Pattern.compile("^[a-f0-9]{64}$");
    private static final Pattern IDENTIFIER = Pattern.compile("^[a-z][a-z0-9.-]{1,127}$");

    public DomainPackManifest {
        permissions = Set.copyOf(permissions);
        tools = List.copyOf(tools);
        threatScenarioRefs = Set.copyOf(threatScenarioRefs);
    }

    public void validate() {
        if (!"agenttrust.domain-pack.v1".equals(schemaVersion)
            || !IDENTIFIER.matcher(packId).matches()
            || version == null || version.isBlank()
            || !DIGEST.matcher(digest).matches()
            || publisherIdentity == null || publisherIdentity.isBlank()
            || permissions.isEmpty() || tools.isEmpty()
            || policyBundleRef == null || policyBundleRef.isBlank()
            || evaluatorRef == null || evaluatorRef.isBlank()
            || threatScenarioRefs.isEmpty()) {
            throw new IllegalArgumentException("DOMAIN_PACK_MANIFEST_INVALID");
        }
        Set<String> ids = new java.util.HashSet<>();
        for (ToolDefinition tool : tools) {
            tool.validate();
            if (!ids.add(tool.toolId()) || !permissions.contains(tool.toolId())) {
                throw new IllegalArgumentException("DOMAIN_PACK_TOOL_PERMISSION_INVALID");
            }
        }
    }

    public record ToolDefinition(String toolId, EffectClass effectClass,
                                 boolean approvalRequired, String compensationRef,
                                 String executorEndpoint) {
        void validate() {
            URI endpoint;
            try { endpoint = URI.create(executorEndpoint); }
            catch (RuntimeException error) {
                throw new IllegalArgumentException("DOMAIN_PACK_EXECUTOR_INVALID", error);
            }
            if (toolId == null || toolId.isBlank() || effectClass == null
                || !"https".equalsIgnoreCase(endpoint.getScheme())
                || effectClass == EffectClass.IRREVERSIBLE && !approvalRequired
                || effectClass == EffectClass.COMPENSATABLE
                    && (compensationRef == null || compensationRef.isBlank())) {
                throw new IllegalArgumentException("DOMAIN_PACK_TOOL_INVALID");
            }
        }
    }

    public enum EffectClass { PURE, IDEMPOTENT, COMPENSATABLE, IRREVERSIBLE }
}
