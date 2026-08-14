package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class GovernedAuthorityGatewayTest {
    private static final UUID TENANT_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID TASK_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final String COMMAND_ID = "command-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void exactCommandAcceptanceReceiptReturnsRemoteEvidence() {
        ObjectNode receipt = receipt();
        assertEquals("orchestrator-event://" + TENANT_ID + "/" + TASK_ID + "/17",
            GovernedAuthorityGateway.requiredCommandAcceptanceEvidence(
                receipt, COMMAND_ID, TENANT_ID, TASK_ID));
    }

    @Test
    void receiptMustContainOnlyTheVersionedExactFields() {
        ObjectNode receipt = receipt();
        receipt.put("pep_evidence_ref", "must-not-be-substituted");
        assertInvalid(receipt);

        receipt = receipt();
        receipt.remove("evidence_digest");
        assertInvalid(receipt);

        receipt = receipt();
        receipt.put("accepted", "true");
        assertInvalid(receipt);
    }

    @Test
    void receiptMustBindCommandTenantTaskAndPendingExecution() {
        ObjectNode receipt = receipt();
        receipt.put("command_id", "other-command");
        assertInvalid(receipt);

        receipt = receipt();
        receipt.put("execution_pending", false);
        assertInvalid(receipt);

        receipt = receipt();
        receipt.put("evidence_ref",
            "orchestrator-event://33333333-3333-4333-8333-333333333333/" + TASK_ID + "/17");
        assertInvalid(receipt);
    }

    @Test
    void receiptRequiresCanonicalEvidenceReferenceAndLowercaseSha256() {
        ObjectNode receipt = receipt();
        receipt.put("evidence_ref", "ledger:command-1");
        assertInvalid(receipt);

        receipt = receipt();
        receipt.put("evidence_digest", "A".repeat(64));
        assertInvalid(receipt);

        receipt = receipt();
        receipt.put("schema_version", "agenttrust.command-receipt.v2");
        assertInvalid(receipt);
    }

    @Test
    void completedReplayUsesThePersistedReceiptAndRemoteEvidenceOnly() {
        String evidence = "orchestrator-event://" + TENANT_ID + "/" + TASK_ID + "/17";
        var completed = new EnterpriseService.RemoteAuthorization(TENANT_ID, "idempotency-key-1",
            false, true, 1, receipt(), evidence);
        assertDoesNotThrow(() -> GovernedAuthorityGateway.requireCompletedCommandReplay(
            completed, COMMAND_ID, TENANT_ID, TASK_ID));

        var pepSubstitution = new EnterpriseService.RemoteAuthorization(TENANT_ID,
            "idempotency-key-1", false, true, 1, receipt(), "pep-evidence://decision");
        assertThrows(ControlUnavailableException.class,
            () -> GovernedAuthorityGateway.requireCompletedCommandReplay(
                pepSubstitution, COMMAND_ID, TENANT_ID, TASK_ID));
    }

    private static void assertInvalid(ObjectNode receipt) {
        assertThrows(ControlUnavailableException.class,
            () -> GovernedAuthorityGateway.requiredCommandAcceptanceEvidence(
                receipt, COMMAND_ID, TENANT_ID, TASK_ID));
    }

    private static ObjectNode receipt() {
        ObjectNode value = MAPPER.createObjectNode();
        value.put("schema_version", "agenttrust.command-receipt.v1");
        value.put("accepted", true);
        value.put("command_id", COMMAND_ID);
        value.put("evidence_ref",
            "orchestrator-event://" + TENANT_ID + "/" + TASK_ID + "/17");
        value.put("evidence_digest", "a".repeat(64));
        value.put("execution_pending", true);
        return value;
    }
}
