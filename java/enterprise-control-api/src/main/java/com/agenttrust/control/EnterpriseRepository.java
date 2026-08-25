package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.agenttrust.control.AdminModels.AuthorizationDecision;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public final class EnterpriseRepository {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public EnterpriseRepository(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public void enterTenant(UUID tenantId) {
        jdbc.queryForObject("SELECT set_config('app.tenant_id', ?, true)", String.class, tenantId.toString());
    }

    public RemoteReservation reserveRemoteAction(UUID tenantId, String key, String requestDigest,
                                                   AdminIntent intent, Object safePayload) {
        int inserted = jdbc.update("INSERT INTO enterprise_remote_actions(tenant_id, action_id, idempotency_key, request_digest, operation, resource, request_payload, status, attempts, next_attempt_at, created_at, updated_at) VALUES (?,?,?,?,?,?,CAST(? AS jsonb),'DISPATCHED',1,now() + interval '2 minutes',now(),now()) ON CONFLICT DO NOTHING",
            tenantId, intent.actionId(), key, requestDigest, intent.operation(), intent.resource(),
            json(safePayload));
        RemoteActionRow row = jdbc.queryForObject("SELECT request_digest, status, response_payload::text, evidence_ref, attempts FROM enterprise_remote_actions WHERE tenant_id=? AND idempotency_key=? FOR UPDATE",
            (result, ignored) -> new RemoteActionRow(result.getString(1), result.getString(2),
                parseJson(result.getString(3)), result.getString(4), result.getInt(5)), tenantId, key);
        if (row == null || !requestDigest.equals(row.requestDigest()) || "FAILED".equals(row.status())) {
            throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
        }
        if (inserted == 1) {
            return new RemoteReservation(true, true, false, 1, null, null);
        }
        if ("COMPLETED".equals(row.status())) {
            return new RemoteReservation(false, false, true, row.attempt(),
                row.responsePayload(), row.evidenceRef());
        }
        int claimed = jdbc.update("UPDATE enterprise_remote_actions SET status='DISPATCHED', attempts=attempts+1, next_attempt_at=now() + interval '2 minutes', last_error_code=NULL, updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND (status IN ('PENDING','UNKNOWN') OR (status='DISPATCHED' AND next_attempt_at <= now()))",
            tenantId, key);
        return new RemoteReservation(false, claimed == 1, false,
            claimed == 1 ? row.attempt() + 1 : row.attempt(), null, row.evidenceRef());
    }

    public void finishRemoteAction(UUID tenantId, String key, int attempt, String status,
                                   Object response, String evidenceRef) {
        String lastErrorCode = response instanceof java.util.Map<?, ?> values
            && values.get("safe_error_code") instanceof String code ? code : null;
        if (!Set.of("COMPLETED", "UNKNOWN", "FAILED").contains(status)
            || jdbc.update("UPDATE enterprise_remote_actions SET status=?, response_payload=CAST(? AS jsonb), evidence_ref=?, last_error_code=?, next_attempt_at=CASE WHEN ?='UNKNOWN' THEN now() ELSE NULL END, updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND status='DISPATCHED' AND attempts=?",
                status, json(response), evidenceRef, lastErrorCode, status, tenantId, key,
                attempt) != 1) {
            throw new ConflictException("CONTROL_REMOTE_ACTION_STATE_CONFLICT");
        }
    }

    public ApprovalReservation reserveApprovalIntent(UUID tenantId, String key, String digest,
                                                       String actor, ApprovalIntent intent,
                                                       AuthorizationDecision pepDecision) {
        if (pepDecision == null || !pepDecision.allowed()) {
            throw new ControlDeniedException("CONTROL_PEP_DECISION_INVALID");
        }
        int inserted = jdbc.update("INSERT INTO enterprise_approval_intents(tenant_id, idempotency_key, intent_digest, case_id, actor_subject, decision, observed_action_hash, observed_resource_version, reason_digest, pep_policy_digest, pep_evidence_ref, status, attempts, next_attempt_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,'DISPATCHED',1,now() + interval '2 minutes',now(),now()) ON CONFLICT DO NOTHING",
            tenantId, key, digest, intent.caseId(), actor, intent.decision(),
            intent.observedActionHash(), intent.observedResourceVersion(), sha256(intent.reason()),
            pepDecision.policyDigest(), pepDecision.evidenceRef());
        ApprovalRow row = jdbc.queryForObject("SELECT intent_digest, status, response_payload::text, evidence_ref, pep_policy_digest, pep_evidence_ref, attempts FROM enterprise_approval_intents WHERE tenant_id=? AND idempotency_key=? FOR UPDATE",
            (result, ignored) -> new ApprovalRow(result.getString(1), result.getString(2),
                parseJson(result.getString(3)), result.getString(4), result.getString(5),
                result.getString(6), result.getInt(7)),
            tenantId, key);
        if (row == null || !digest.equals(row.intentDigest()) || "FAILED".equals(row.status())
            || !pepDecision.policyDigest().equals(row.pepPolicyDigest())
            || !pepDecision.evidenceRef().equals(row.pepEvidenceRef())) {
            throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
        }
        if (inserted == 1) {
            return new ApprovalReservation(true, false, 1, row.pepPolicyDigest(),
                row.pepEvidenceRef(), null, null);
        }
        if ("COMPLETED".equals(row.status())) {
            return new ApprovalReservation(false, true, row.attempt(), row.pepPolicyDigest(),
                row.pepEvidenceRef(), row.responsePayload(), row.evidenceRef());
        }
        int claimed = jdbc.update("UPDATE enterprise_approval_intents SET status='DISPATCHED', attempts=attempts+1, next_attempt_at=now() + interval '2 minutes', last_error_code=NULL, updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND (status IN ('PENDING','UNKNOWN') OR (status='DISPATCHED' AND next_attempt_at <= now()))",
            tenantId, key);
        return new ApprovalReservation(claimed == 1, false,
            claimed == 1 ? row.attempt() + 1 : row.attempt(), row.pepPolicyDigest(),
            row.pepEvidenceRef(), null, null);
    }

    public void finishApprovalIntent(UUID tenantId, String key, int attempt, String status,
                                     Object response, String evidenceRef) {
        finishApprovalIntent(tenantId, key, attempt, status, response, evidenceRef, null);
    }

    public void finishApprovalIntent(UUID tenantId, String key, int attempt, String status,
                                     Object response, String evidenceRef,
                                     String lastErrorCode) {
        boolean completed = "COMPLETED".equals(status);
        if (!Set.of("COMPLETED", "UNKNOWN", "FAILED").contains(status)
            || completed != (response != null && evidenceRef != null && !evidenceRef.isBlank())
            || !completed && evidenceRef != null
            || jdbc.update("UPDATE enterprise_approval_intents SET status=?, response_payload=CAST(? AS jsonb), evidence_ref=?, last_error_code=?, next_attempt_at=CASE WHEN ?='UNKNOWN' THEN now() ELSE NULL END, updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND status='DISPATCHED' AND attempts=?",
                status, response == null ? null : json(response), evidenceRef, lastErrorCode,
                status, tenantId, key, attempt) != 1) {
            throw new ConflictException("CONTROL_APPROVAL_INTENT_STATE_CONFLICT");
        }
    }

    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException error) { throw new IllegalStateException("CONTROL_CANONICALIZATION_FAILED", error); }
    }

    private JsonNode parseJson(String value) {
        if (value == null) {
            return null;
        }
        try {
            return mapper.readTree(value);
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("CONTROL_PERSISTED_JSON_INVALID", error);
        }
    }

    public record RemoteReservation(boolean created, boolean dispatch, boolean completed,
                                    int attempt, JsonNode responsePayload, String evidenceRef) {}
    public record ApprovalReservation(boolean dispatch, boolean completed, int attempt,
                                      String pepPolicyDigest, String pepEvidenceRef,
                                      JsonNode responsePayload, String evidenceRef) {}
    private record RemoteActionRow(String requestDigest, String status, JsonNode responsePayload,
                                   String evidenceRef, int attempt) {}
    private record ApprovalRow(String intentDigest, String status, JsonNode responsePayload,
                               String evidenceRef, String pepPolicyDigest, String pepEvidenceRef,
                               int attempt) {}

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA256_UNAVAILABLE", error);
        }
    }
}
