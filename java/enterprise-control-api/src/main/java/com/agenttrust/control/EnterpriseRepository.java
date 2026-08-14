package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.ApiKeyIssueRequest;
import com.agenttrust.control.AdminModels.CostUsageRequest;
import com.agenttrust.control.AdminModels.IntegrationRequest;
import com.agenttrust.control.AdminModels.OrganizationRequest;
import com.agenttrust.control.AdminModels.ProjectRequest;
import com.agenttrust.control.AdminModels.QuotaConsumeRequest;
import com.agenttrust.control.AdminModels.TenantRequest;
import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.time.Instant;
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

    public IdempotencyReservation reserveIdempotency(UUID tenantId, String key, String digest) {
        int inserted = jdbc.update("INSERT INTO enterprise_request_idempotency(tenant_id, idempotency_key, request_digest, state) VALUES (?,?,?,'IN_PROGRESS') ON CONFLICT DO NOTHING",
            tenantId, key, digest);
        if (inserted == 1) {
            return new IdempotencyReservation(false, 0, null);
        }
        IdempotencyRow row = jdbc.queryForObject("SELECT request_digest, state, response_status, response_payload::text FROM enterprise_request_idempotency WHERE tenant_id=? AND idempotency_key=? FOR UPDATE",
            (result, ignored) -> new IdempotencyRow(result.getString(1), result.getString(2),
                result.getObject(3, Integer.class), parseJson(result.getString(4))), tenantId, key);
        if (row == null || !digest.equals(row.requestDigest()) || !"COMPLETED".equals(row.state())
            || row.responseStatus() == null) {
            throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
        }
        return new IdempotencyReservation(true, row.responseStatus(), row.responsePayload());
    }

    public void completeIdempotency(UUID tenantId, String key, int status, Object response) {
        if (jdbc.update("UPDATE enterprise_request_idempotency SET state='COMPLETED', response_status=?, response_payload=CAST(? AS jsonb), updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND state='IN_PROGRESS'",
            status, json(response), tenantId, key) != 1) {
            throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
        }
    }

    public int createOrganization(UUID tenantId, OrganizationRequest request) {
        return jdbc.update("INSERT INTO enterprise_organizations(tenant_id, organization_id, display_name, sponsor_subject) VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
            tenantId, request.organizationId(), request.displayName(), request.sponsorSubject());
    }

    public int createTenant(UUID tenantId, TenantRequest request) {
        return jdbc.update("INSERT INTO enterprise_tenants(tenant_id, display_name, owner_subject, data_region, quota) VALUES (?,?,?,?,CAST(? AS jsonb)) ON CONFLICT DO NOTHING",
            tenantId, request.displayName(), request.ownerSubject(), request.dataRegion(), json(request.quota()));
    }

    public int createProject(UUID tenantId, ProjectRequest request) {
        return jdbc.update("INSERT INTO enterprise_projects(tenant_id, project_id, organization_id, owner_subject, environments) VALUES (?,?,?,?,CAST(? AS jsonb)) ON CONFLICT DO NOTHING",
            tenantId, request.projectId(), request.organizationId(), request.ownerSubject(), json(request.environments()));
    }

    public int createIntegration(UUID tenantId, IntegrationRequest request) {
        return jdbc.update("INSERT INTO enterprise_integrations(tenant_id, integration_id, kind, endpoint, secret_ref, configuration_digest, active) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            tenantId, request.integrationId(), request.kind(), request.endpoint().toString(),
            request.secretRef(), request.configurationDigest(), request.active());
    }

    public long consumeQuota(UUID tenantId, QuotaConsumeRequest request) {
        List<Long> rows = jdbc.query("INSERT INTO enterprise_quota_usage(tenant_id, quota_key, window_started_at, used, limit_value) VALUES (?,?,?,?,?) ON CONFLICT (tenant_id, quota_key, window_started_at) DO UPDATE SET used = enterprise_quota_usage.used + EXCLUDED.used WHERE enterprise_quota_usage.limit_value = EXCLUDED.limit_value AND enterprise_quota_usage.used <= enterprise_quota_usage.limit_value - EXCLUDED.used RETURNING used",
            (result, row) -> result.getLong(1), tenantId, request.quotaKey(),
            request.windowStartedAt(), request.amount(), request.limit());
        if (rows.size() != 1) {
            throw new CapacityException("CONTROL_QUOTA_EXCEEDED");
        }
        return rows.getFirst();
    }

    public int recordCost(UUID tenantId, CostUsageRequest request) {
        long total;
        try {
            total = Math.multiplyExact(request.quantity(), request.unitCostMicros());
        } catch (ArithmeticException error) {
            throw new ControlDeniedException("CONTROL_COST_INVALID", error);
        }
        return jdbc.update("INSERT INTO enterprise_cost_usage(tenant_id, usage_id, project_id, meter, quantity, unit_cost_micros, total_cost_micros, source_digest, recorded_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            tenantId, request.usageId(), request.projectId(), request.meter(), request.quantity(),
            request.unitCostMicros(), total, request.sourceDigest(), request.recordedAt());
    }

    public int createApiKey(UUID tenantId, UUID apiKeyId, ApiKeyIssueRequest request,
                            String keyHash, String createdBy, Instant createdAt) {
        return jdbc.update("INSERT INTO enterprise_api_keys(tenant_id, api_key_id, project_id, key_hash, scopes, created_by, created_at, expires_at) VALUES (?,?,?,?,CAST(? AS jsonb),?,?,?) ON CONFLICT DO NOTHING",
            tenantId, apiKeyId, request.projectId(), keyHash, json(request.scopes()), createdBy,
            createdAt, request.expiresAt());
    }

    public int revokeApiKey(UUID tenantId, UUID apiKeyId, String reason) {
        return jdbc.update("UPDATE enterprise_api_keys SET revoked_at = now(), revocation_reason = ? WHERE tenant_id = ? AND api_key_id = ? AND revoked_at IS NULL",
            reason, tenantId, apiKeyId);
    }

    public int writeAudit(AdminIntent intent, String policyDigest, String evidenceRef, String reason) {
        String resultDigest = sha256(policyDigest + "\n" + evidenceRef);
        return jdbc.update("INSERT INTO enterprise_admin_actions(tenant_id, action_id, requester_subject, operation, resource, action_digest, approvals, result_digest, reason) VALUES (?,?,?,?,?,?,CAST(? AS jsonb),?,?) ON CONFLICT DO NOTHING",
            intent.tenantId(), intent.actionId(), intent.requestedBy(), intent.operation(), intent.resource(),
            intent.actionDigest(), json(intent.approvalIds()), resultDigest, reason);
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
                                                       String actor, ApprovalIntent intent) {
        int inserted = jdbc.update("INSERT INTO enterprise_approval_intents(tenant_id, idempotency_key, intent_digest, case_id, actor_subject, decision, observed_action_hash, observed_resource_version, reason_digest, status, attempts, next_attempt_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,'DISPATCHED',1,now() + interval '2 minutes',now(),now()) ON CONFLICT DO NOTHING",
            tenantId, key, digest, intent.caseId(), actor, intent.decision(),
            intent.observedActionHash(), intent.observedResourceVersion(), sha256(intent.reason()));
        ApprovalRow row = jdbc.queryForObject("SELECT intent_digest, status, evidence_ref, attempts FROM enterprise_approval_intents WHERE tenant_id=? AND idempotency_key=? FOR UPDATE",
            (result, ignored) -> new ApprovalRow(result.getString(1), result.getString(2),
                result.getString(3), result.getInt(4)),
            tenantId, key);
        if (row == null || !digest.equals(row.intentDigest()) || "FAILED".equals(row.status())) {
            throw new ConflictException("CONTROL_IDEMPOTENCY_CONFLICT");
        }
        if (inserted == 1) {
            return new ApprovalReservation(true, false, 1, null);
        }
        if ("COMPLETED".equals(row.status())) {
            return new ApprovalReservation(false, true, row.attempt(), row.evidenceRef());
        }
        int claimed = jdbc.update("UPDATE enterprise_approval_intents SET status='DISPATCHED', attempts=attempts+1, next_attempt_at=now() + interval '2 minutes', last_error_code=NULL, updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND (status IN ('PENDING','UNKNOWN') OR (status='DISPATCHED' AND next_attempt_at <= now()))",
            tenantId, key);
        return new ApprovalReservation(claimed == 1, false,
            claimed == 1 ? row.attempt() + 1 : row.attempt(), null);
    }

    public void finishApprovalIntent(UUID tenantId, String key, int attempt, String status,
                                     String evidenceRef) {
        finishApprovalIntent(tenantId, key, attempt, status, evidenceRef, null);
    }

    public void finishApprovalIntent(UUID tenantId, String key, int attempt, String status,
                                     String evidenceRef, String lastErrorCode) {
        if (!Set.of("COMPLETED", "UNKNOWN", "FAILED").contains(status)
            || jdbc.update("UPDATE enterprise_approval_intents SET status=?, evidence_ref=?, last_error_code=?, next_attempt_at=CASE WHEN ?='UNKNOWN' THEN now() ELSE NULL END, updated_at=now() WHERE tenant_id=? AND idempotency_key=? AND status='DISPATCHED' AND attempts=?",
                status, evidenceRef, lastErrorCode, status, tenantId, key, attempt) != 1) {
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

    public record IdempotencyReservation(boolean replay, int responseStatus, JsonNode responsePayload) {}
    public record RemoteReservation(boolean created, boolean dispatch, boolean completed,
                                    int attempt, JsonNode responsePayload, String evidenceRef) {}
    public record ApprovalReservation(boolean dispatch, boolean completed, int attempt,
                                      String evidenceRef) {}
    private record IdempotencyRow(String requestDigest, String state, Integer responseStatus,
                                  JsonNode responsePayload) {}
    private record RemoteActionRow(String requestDigest, String status, JsonNode responsePayload,
                                   String evidenceRef, int attempt) {}
    private record ApprovalRow(String intentDigest, String status, String evidenceRef, int attempt) {}

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA256_UNAVAILABLE", error);
        }
    }
}
