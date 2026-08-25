package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ApprovalControlContractTest {
    @Test
    void javaBffAndGeneratedWebContractTrackApprovalAuthorityV1() throws Exception {
        String approval = Files.readString(repositoryFile("schemas/openapi/approval-v1.yaml"));
        String control = Files.readString(repositoryFile("schemas/openapi/control-plane-v1.yaml"));
        String generated = Files.readString(repositoryFile(
            "web/control-console/src/generated/control-plane-v1.d.ts"));
        String signedEvidenceReceipt = Files.readString(repositoryFile(
            "schemas/evidence/signed-authority-evidence-receipt.schema.json"));
        String configuration = Files.readString(repositoryFile(
            "java/enterprise-control-api/src/main/resources/application.yml"));

        assertTrue(approval.contains("/v1/approvals/cases/{case_id}/decisions:"));
        assertTrue(approval.contains("x-required-service-scope: approvals:decide"));
        assertTrue(approval.contains("name: x-agenttrust-principal-assertion"));
        assertTrue(approval.contains("agenttrust.approval-case-create.v2"));
        assertTrue(approval.contains("agenttrust.enterprise-approval-case.v2"));
        for (String field : new String[] {"review_context", "review_evidence",
            "canonical_action_hash", "risk_package_ref", "state_snapshot_ref",
            "authority_request", "APPROVAL_REVIEW_PREPARED"}) {
            assertTrue(approval.contains(field));
        }
        assertTrue(approval.contains("signed-authority-evidence-receipt.schema.json"));
        assertTrue(signedEvidenceReceipt.contains(
            "agenttrust.signed-authority-evidence-receipt.v1"));
        assertTrue(signedEvidenceReceipt.contains("AUTHORITY_EVIDENCE_RECEIPT"));
        assertTrue(control.contains("agenttrust.approval-intent-receipt.v1"));
        assertTrue(generated.contains("ApprovalIntentReceipt"));
        for (String field : new String[] {"action_hash", "resource_version", "case_status",
            "evidence_ref", "evidence_digest", "authority_issuer", "authority_key_id"}) {
            assertTrue(control.contains(field));
            assertTrue(generated.contains(field));
        }
        assertFalse(control.contains("CONTROL_APPROVAL_EVIDENCE_PENDING"));
        for (String field : new String[] {"owned_resources", "strong_auth",
            "authentication_time", "authentication_context"}) {
            assertTrue(control.contains(field));
            assertTrue(generated.contains(field));
        }
        for (String scope : new String[] {"READ", "REQUEST", "DECIDE", "ISSUE", "REVOKE"}) {
            assertTrue(configuration.contains(
                "AGENT_TRUST_APPROVAL_" + scope + "_TOKEN_FILE"));
        }
        assertTrue(configuration.contains(
            "AGENT_TRUST_APPROVAL_AUTHORITY_VERIFICATION_KEYRING_FILE"));
        assertTrue(control.contains("x-agenttrust-max-utf8-bytes: 4096"));
        assertTrue(generated.contains("Human reason encoded as at most 4096 UTF-8 bytes"));
    }

    @Test
    void approvalReasonUsesTheAuthorityUtf8ByteLimit() {
        assertDoesNotThrow(() -> new AdminModels.ApprovalIntent(
            "agenttrust.approval-intent.v1",
            UUID.fromString("01900000-0000-7000-8000-000000000001"), "APPROVE",
            "😀".repeat(1_001), "a".repeat(64), "resource-v1"));
        assertThrows(IllegalArgumentException.class, () -> new AdminModels.ApprovalIntent(
            "agenttrust.approval-intent.v1",
            UUID.fromString("01900000-0000-7000-8000-000000000001"), "APPROVE",
            "界".repeat(1_366), "a".repeat(64), "resource-v1"));
        assertThrows(IllegalArgumentException.class, () -> new AdminModels.ApprovalIntent(
            "agenttrust.approval-intent.v1",
            UUID.fromString("01900000-0000-7000-8000-000000000001"), "APPROVE",
            "bad\0reason", "a".repeat(64), "resource-v1"));
        assertThrows(IllegalArgumentException.class, () -> new AdminModels.ApprovalIntent(
            "agenttrust.approval-intent.v1",
            UUID.fromString("01900000-0000-7000-8000-000000000001"), "APPROVE",
            "reviewed", "a".repeat(64), "😀".repeat(513)));
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
