package com.agenttrust.control;

import java.nio.file.Path;
import java.util.Set;

final class ApprovalTestProperties {
    private ApprovalTestProperties() {}

    static ApprovalIntegrationProperties create(Path signingKey) {
        Path root = signingKey.toAbsolutePath().getParent();
        return new ApprovalIntegrationProperties(
            root.resolve("approval-read.token"),
            root.resolve("approval-request.token"),
            root.resolve("approval-decide.token"),
            root.resolve("approval-issue.token"),
            root.resolve("approval-revoke.token"),
            signingKey.toAbsolutePath(),
            ApprovalIntegrationProperties.PrincipalSigningKeyFormat.RAW_BASE64URL,
            "enterprise-idp", "agenttrust-approval", "idp-key-1",
            "URI:spiffe://agenttrust/approval-bff", "approval-bff", 300,
            Set.of("urn:agenttrust:acr:mfa"), 900);
    }
}
