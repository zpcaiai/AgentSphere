package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ApprovalControlContractTest {
    @Test
    void javaBffAndGeneratedWebContractTrackApprovalAuthorityV1() throws Exception {
        String approval = Files.readString(repositoryFile("schemas/openapi/approval-v1.yaml"));
        String control = Files.readString(repositoryFile("schemas/openapi/control-plane-v1.yaml"));
        String generated = Files.readString(repositoryFile(
            "web/control-console/src/generated/control-plane-v1.d.ts"));
        String configuration = Files.readString(repositoryFile(
            "java/enterprise-control-api/src/main/resources/application.yml"));

        assertTrue(approval.contains("/v1/approvals/cases/{case_id}/decisions:"));
        assertTrue(approval.contains("x-required-service-scope: approvals:decide"));
        assertTrue(approval.contains("name: x-agenttrust-principal-assertion"));
        assertTrue(approval.contains("agenttrust.approval-case-create.v2"));
        assertTrue(approval.contains("agenttrust.enterprise-approval-case.v2"));
        for (String field : new String[] {"review_context", "review_evidence",
            "canonical_action_hash", "risk_package_ref", "state_snapshot_ref",
            "authority_request", "agenttrust.signed-authority-evidence-receipt.v1",
            "APPROVAL_REVIEW_PREPARED", "AUTHORITY_EVIDENCE_RECEIPT"}) {
            assertTrue(approval.contains(field));
        }
        assertTrue(control.contains("CONTROL_APPROVAL_EVIDENCE_PENDING"));
        for (String field : new String[] {"owned_resources", "strong_auth",
            "authentication_time", "authentication_context"}) {
            assertTrue(control.contains(field));
            assertTrue(generated.contains(field));
        }
        for (String scope : new String[] {"READ", "REQUEST", "DECIDE", "ISSUE", "REVOKE"}) {
            assertTrue(configuration.contains(
                "AGENT_TRUST_APPROVAL_" + scope + "_TOKEN_FILE"));
        }
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
