package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.reflect.Proxy;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

class EnterpriseApprovalPersistenceTest {
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID CASE = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PEP_POLICY_DIGEST = "c".repeat(64);
    private static final String PEP_EVIDENCE_REF = "urn:agenttrust:pep-evidence:approval-one";

    @Test
    void completedReservationReturnsTheExactPersistedAuthorityEnvelope() {
        ObjectNode response = authorityResponse();
        String digest = "a".repeat(64);
        String evidence = "urn:agenttrust:approval-decision:" + TENANT + ":" + CASE
            + ":33333333-3333-4333-8333-333333333333";
        ReplayJdbc jdbc = new ReplayJdbc(digest, response.toString(), evidence);
        EnterpriseRepository repository = new EnterpriseRepository(jdbc, MAPPER);
        var intent = new AdminModels.ApprovalIntent("agenttrust.approval-intent.v1", CASE,
            "APPROVE", "exact reason", "b".repeat(64), "resource-v7");

        EnterpriseRepository.ApprovalReservation reservation = repository.reserveApprovalIntent(
            TENANT, "approval-key-1", digest, "approver:one", intent, pepDecision());

        assertTrue(reservation.completed());
        assertFalse(reservation.dispatch());
        assertEquals(response, reservation.responsePayload());
        assertEquals(evidence, reservation.evidenceRef());
        assertEquals(PEP_POLICY_DIGEST, reservation.pepPolicyDigest());
        assertEquals(PEP_EVIDENCE_REF, reservation.pepEvidenceRef());
    }

    @Test
    void replayRejectsAChangedPepEvidenceBinding() {
        String digest = "a".repeat(64);
        ReplayJdbc jdbc = new ReplayJdbc(digest, authorityResponse().toString(),
            "urn:agenttrust:approval-decision:" + TENANT + ":" + CASE
                + ":33333333-3333-4333-8333-333333333333");
        EnterpriseRepository repository = new EnterpriseRepository(jdbc, MAPPER);
        var intent = new AdminModels.ApprovalIntent("agenttrust.approval-intent.v1", CASE,
            "APPROVE", "exact reason", "b".repeat(64), "resource-v7");
        var changedPep = new AdminModels.AuthorizationDecision("ALLOW", PEP_POLICY_DIGEST,
            "urn:agenttrust:pep-evidence:changed", List.of("APPROVAL_AUTHORIZED"));

        assertThrows(ConflictException.class, () -> repository.reserveApprovalIntent(
            TENANT, "approval-key-1", digest, "approver:one", intent, changedPep));
    }

    @Test
    void legacyReplayWithoutPepEvidenceFailsClosed() {
        String digest = "a".repeat(64);
        ReplayJdbc jdbc = new ReplayJdbc(digest, authorityResponse().toString(),
            "urn:agenttrust:approval-decision:" + TENANT + ":" + CASE
                + ":33333333-3333-4333-8333-333333333333", null, null);
        EnterpriseRepository repository = new EnterpriseRepository(jdbc, MAPPER);
        var intent = new AdminModels.ApprovalIntent("agenttrust.approval-intent.v1", CASE,
            "APPROVE", "exact reason", "b".repeat(64), "resource-v7");

        assertThrows(ConflictException.class, () -> repository.reserveApprovalIntent(
            TENANT, "approval-key-1", digest, "approver:one", intent, pepDecision()));
    }

    @Test
    void serviceCompletionWritesFullResponseAndReceiptReferenceAtomically() {
        CaptureJdbc jdbc = new CaptureJdbc();
        EnterpriseRepository repository = new EnterpriseRepository(jdbc, MAPPER);
        EnterpriseService service = new EnterpriseService(repository, null,
            new TransactionTemplate(new DirectTransactions()), null, null);
        ObjectNode response = authorityResponse();
        String evidence = response.path("evidence_receipt").path("evidence_ref").asText();
        var authorization = new EnterpriseService.ApprovalAuthorization(TENANT,
            "approval-key-1", true, false, 3, PEP_POLICY_DIGEST, PEP_EVIDENCE_REF,
            null, null);

        service.completeApprovalIntent(authorization, response, evidence);

        assertEquals(1, jdbc.updates().size());
        CapturedUpdate update = jdbc.updates().getFirst();
        assertTrue(update.sql().contains("response_payload=CAST(? AS jsonb)"));
        assertEquals("COMPLETED", update.arguments()[0]);
        assertEquals(response, read((String) update.arguments()[1]));
        assertEquals(evidence, update.arguments()[2]);
        assertEquals(TENANT, update.arguments()[5]);
        assertEquals("approval-key-1", update.arguments()[6]);
        assertEquals(3, update.arguments()[7]);
    }

    @Test
    void repositoryWillNotCreateCompletedStateWithoutResponseAndEvidence() {
        CaptureJdbc jdbc = new CaptureJdbc();
        EnterpriseRepository repository = new EnterpriseRepository(jdbc, MAPPER);

        assertThrows(ConflictException.class, () -> repository.finishApprovalIntent(TENANT,
            "approval-key-1", 1, "COMPLETED", null, "evidence://missing-response"));
        assertThrows(ConflictException.class, () -> repository.finishApprovalIntent(TENANT,
            "approval-key-1", 1, "COMPLETED", authorityResponse(), null));
        assertTrue(jdbc.updates().isEmpty());
    }

    private static ObjectNode authorityResponse() {
        ObjectNode result = MAPPER.createObjectNode();
        result.put("schema_version", "agenttrust.approval-decision-result.v1");
        result.putObject("approval_case").put("case_id", CASE.toString());
        result.putObject("evidence_receipt").put("evidence_ref",
            "urn:agenttrust:approval-decision:" + TENANT + ":" + CASE
                + ":33333333-3333-4333-8333-333333333333");
        return result;
    }

    private static AdminModels.AuthorizationDecision pepDecision() {
        return new AdminModels.AuthorizationDecision("ALLOW", PEP_POLICY_DIGEST,
            PEP_EVIDENCE_REF, List.of("APPROVAL_AUTHORIZED"));
    }

    private static ObjectNode read(String value) {
        try {
            return (ObjectNode) MAPPER.readTree(value);
        } catch (java.io.IOException error) {
            throw new AssertionError(error);
        }
    }

    private static ResultSet resultSet(String... values) {
        return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(),
            new Class<?>[] {ResultSet.class}, (ignored, method, arguments) -> {
                if ("getString".equals(method.getName())) {
                    return values[(Integer) arguments[0] - 1];
                }
                if ("getInt".equals(method.getName())) {
                    return Integer.parseInt(values[(Integer) arguments[0] - 1]);
                }
                if ("wasNull".equals(method.getName()) || "isClosed".equals(method.getName())) {
                    return false;
                }
                if ("toString".equals(method.getName())) {
                    return "ApprovalReservationResultSet";
                }
                Class<?> type = method.getReturnType();
                if (type == boolean.class) {
                    return false;
                }
                if (type == int.class) {
                    return 0;
                }
                if (type == long.class) {
                    return 0L;
                }
                return null;
            });
    }

    private static final class ReplayJdbc extends JdbcTemplate {
        private final String digest;
        private final String response;
        private final String evidence;
        private final String storedPepPolicy;
        private final String storedPepEvidence;

        private ReplayJdbc(String digest, String response, String evidence) {
            this(digest, response, evidence, PEP_POLICY_DIGEST, PEP_EVIDENCE_REF);
        }

        private ReplayJdbc(String digest, String response, String evidence,
                           String storedPepPolicy, String storedPepEvidence) {
            this.digest = digest;
            this.response = response;
            this.evidence = evidence;
            this.storedPepPolicy = storedPepPolicy;
            this.storedPepEvidence = storedPepEvidence;
        }

        @Override
        public int update(String sql, Object... arguments) {
            assertTrue(sql.startsWith("INSERT INTO enterprise_approval_intents"));
            assertTrue(sql.contains("pep_policy_digest, pep_evidence_ref"));
            assertEquals(PEP_POLICY_DIGEST, arguments[9]);
            assertTrue(((String) arguments[10]).startsWith("urn:agenttrust:pep-evidence:"));
            return 0;
        }

        @Override
        public <T> T queryForObject(String sql, RowMapper<T> mapper, Object... arguments) {
            assertTrue(sql.contains("response_payload::text"));
            try {
                return mapper.mapRow(resultSet(digest, "COMPLETED", response, evidence,
                    storedPepPolicy, storedPepEvidence, "4"), 0);
            } catch (java.sql.SQLException error) {
                throw new AssertionError(error);
            }
        }
    }

    private static final class CaptureJdbc extends JdbcTemplate {
        private final List<CapturedUpdate> updates = new ArrayList<>();

        @Override
        public <T> T queryForObject(String sql, Class<T> requiredType, Object... arguments) {
            assertTrue(sql.startsWith("SELECT set_config"));
            return requiredType.cast(arguments[0]);
        }

        @Override
        public int update(String sql, Object... arguments) {
            updates.add(new CapturedUpdate(sql, arguments.clone()));
            return 1;
        }

        private List<CapturedUpdate> updates() {
            return List.copyOf(updates);
        }
    }

    private static final class DirectTransactions implements PlatformTransactionManager {
        @Override
        public TransactionStatus getTransaction(TransactionDefinition definition) {
            return new SimpleTransactionStatus();
        }

        @Override
        public void commit(TransactionStatus status) {}

        @Override
        public void rollback(TransactionStatus status) {}
    }

    private record CapturedUpdate(String sql, Object[] arguments) {}
}
