package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class EnterpriseMutationGatewayTest {
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID ACTION = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID TASK = UUID.fromString("33333333-3333-4333-8333-333333333333");

    @Test
    void acceptanceIsBoundAndCannotMasqueradeAsExecutionSuccess() throws Exception {
        var receipt = new ObjectMapper().readTree("""
            {"schema_version":"agenttrust.enterprise-action-receipt.v1",
             "action_id":"22222222-2222-4222-8222-222222222222",
             "task_id":"33333333-3333-4333-8333-333333333333",
             "accepted":true,"start_requested":true,"execution_pending":true,
             "ingress_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "evidence_ref":"orchestrator-event://11111111-1111-4111-8111-111111111111/33333333-3333-4333-8333-333333333333/1",
             "evidence_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
            """);
        var parsed = EnterpriseMutationGateway.requireReceipt(receipt, ACTION, TENANT);
        assertEquals(TASK, parsed.taskId());
        assertEquals(true, parsed.executionPending());
    }

    @Test
    void rawSecretOrFalsePendingReceiptFailsClosed() throws Exception {
        var value = new ObjectMapper().readTree("""
            {"schema_version":"agenttrust.enterprise-action-receipt.v1",
             "action_id":"22222222-2222-4222-8222-222222222222",
             "task_id":"33333333-3333-4333-8333-333333333333",
             "accepted":true,"start_requested":true,"execution_pending":false,
             "ingress_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "evidence_ref":"orchestrator-event://11111111-1111-4111-8111-111111111111/33333333-3333-4333-8333-333333333333/1",
             "evidence_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "one_time_secret":"atk_forbidden"}
            """);
        assertThrows(ControlUnavailableException.class,
            () -> EnterpriseMutationGateway.requireReceipt(value, ACTION, TENANT));
    }
}
