package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.IncidentModels.IncidentCommandRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Tenant-bound Incident, Replay, and Release Gate BFF. Writes terminate only at the authority's
 * Canonical Action ingress; a 202 response is admission evidence and never execution success.
 */
@Component
public final class IncidentAuthorityGateway {
    static final String MUTATE_OPERATION_TOKEN = "incidents.mutate";
    static final String MUTATE_SCOPE = "incident:mutate";
    static final String ACTION_PATH = "/v1/incidents/actions";
    private static final String READ_AUTHORITY = "incidents";
    private static final Set<String> OPERATIONS = Set.of(
        "TRIAGE", "CONTAIN", "INVESTIGATE", "PRESERVE_EVIDENCE", "PLAN_REPLAY",
        "COMPLETE_REPLAY", "PUBLISH_ROOT_CAUSE", "BEGIN_REMEDIATION",
        "TRIGGER_RECERTIFICATION", "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY",
        "ROLLBACK_RELEASE", "CLOSE");
    private static final Set<String> RELEASE_OPERATIONS = Set.of(
        "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE");
    private static final Set<String> STATUSES = Set.of(
        "DETECTED", "TRIAGED", "CONTAINED", "INVESTIGATING", "REMEDIATING",
        "RECERTIFYING", "CLOSED");
    private static final Set<String> SEVERITIES = Set.of("P0", "P1", "P2", "P3");
    private static final Set<String> PAGE_FIELDS = Set.of(
        "schema_version", "tenant_id", "items", "next_after_incident_id");
    private static final Set<String> INCIDENT_FIELDS = Set.of(
        "incident_id", "correlation_key", "severity", "status", "task_id", "owner",
        "safe_summary", "scope", "evidence_refs", "legal_hold_id", "resource_version",
        "created_at", "updated_at", "timeline");
    private static final Set<String> TIMELINE_FIELDS = Set.of(
        "event_id", "sequence", "event_type", "from_status", "to_status", "actor_subject",
        "reason_code", "payload_digest", "action_hash", "ledger_execution_id", "fence_digest",
        "policy_decision_digest", "authorization_evidence_ref",
        "authorization_evidence_digest", "occurred_at");
    private static final Set<String> RECEIPT_FIELDS = Set.of(
        "schema_version", "action_id", "task_id", "accepted", "execution_pending",
        "ingress_digest", "ledger_evidence_ref", "ledger_evidence_digest");

    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final AuthorityScopeTokenProvider tokens;
    private final HumanPrincipalAssertionSigner assertions;
    private final PepAuthorizationClient pep;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;

    public IncidentAuthorityGateway(ControlProperties properties,
                                    SecureRestClientFactory clients,
                                    AuthorityScopeTokenProvider tokens,
                                    HumanPrincipalAssertionSigner assertions,
                                    PepAuthorizationClient pep, CanonicalDigest canonical,
                                    ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.tokens = tokens;
        this.assertions = assertions;
        this.pep = pep;
        this.canonical = canonical;
        this.mapper = mapper;
    }

    public JsonNode list(PrincipalContext principal, String afterIncidentId, int limit) {
        requireLimit(limit);
        if (afterIncidentId != null && !AuthorityJson.uuid(afterIncidentId)) {
            throw new ControlDeniedException("CONTROL_INCIDENT_QUERY_INVALID");
        }
        pep.authorizeQuery(principal, "LIST_INCIDENTS", "incidents:timeline");
        JsonNode value = get(principal, builder -> {
            var uri = builder.path("/v1/authoritative/incidents").queryParam("limit", limit);
            if (afterIncidentId != null) {
                uri.queryParam("after_incident_id", afterIncidentId);
            }
            return uri.build();
        });
        requirePage(value, principal.tenantId(), afterIncidentId, limit);
        return value;
    }

    public JsonNode detail(PrincipalContext principal, UUID incidentId) {
        if (incidentId == null || !AuthorityJson.uuid(incidentId.toString())) {
            throw new ControlDeniedException("CONTROL_INCIDENT_QUERY_INVALID");
        }
        pep.authorizeQuery(principal, "READ_INCIDENT_TIMELINE", "incident:" + incidentId);
        JsonNode value = get(principal, builder -> builder
            .path("/v1/authoritative/incidents/{incidentId}").build(incidentId));
        requireIncident(value, incidentId.toString());
        return value;
    }

    public JsonNode submit(PrincipalContext principal, IncidentCommandRequest command,
                           String idempotencyKey) {
        requireCommand(principal, command, idempotencyKey, mapper, canonical);
        var signed = assertions.sign(principal, "POST", ACTION_PATH, MUTATE_SCOPE,
            idempotencyKey, command, true);
        JsonNode receipt;
        try {
            receipt = authenticated(principal, tokens.operationToken(MUTATE_OPERATION_TOKEN))
                .post().uri(ACTION_PATH).contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("Idempotency-Key", idempotencyKey)
                .header("X-AgentTrust-Human-Assertion", signed.headerValue())
                .body(command).exchange((ignored, response) -> decode(response, 202));
        } catch (ControlDeniedException | ConflictException | CapacityException
                 | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_UNAVAILABLE", error);
        }
        requireReceipt(receipt, command.commandId(), command.taskId(), principal.tenantId());
        return receipt;
    }

    private JsonNode get(PrincipalContext principal,
                         java.util.function.Function<org.springframework.web.util.UriBuilder,
                         URI> uri) {
        try {
            return authenticated(principal, tokens.readToken(READ_AUTHORITY)).get().uri(uri)
                .accept(MediaType.APPLICATION_JSON)
                .exchange((ignored, response) -> decode(response, 200));
        } catch (ControlDeniedException | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private RestClient authenticated(PrincipalContext principal, String token) {
        URI endpoint = properties.authorityEndpoints().get(READ_AUTHORITY);
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_UNCONFIGURED");
        }
        return clients.client(endpoint).mutate().defaultHeaders(headers -> {
            headers.setBearerAuth(token);
            headers.set("X-AgentTrust-Tenant-Id", principal.tenantId().toString());
        }).build();
    }

    private JsonNode decode(org.springframework.http.client.ClientHttpResponse response,
                            int expectedStatus) throws IOException {
        int status = response.getStatusCode().value();
        if (status == 400 || status == 401 || status == 403 || status == 404 || status == 422) {
            throw new ControlDeniedException("CONTROL_INCIDENT_AUTHORITY_REJECTED");
        }
        if (status == 409) {
            throw new ConflictException("CONTROL_INCIDENT_AUTHORITY_CONFLICT");
        }
        if (status == 429) {
            throw new CapacityException("CONTROL_INCIDENT_AUTHORITY_CAPACITY");
        }
        if (status != expectedStatus || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(response.getHeaders().getContentType())) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID");
        }
        byte[] bytes = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (bytes.length == 0 || bytes.length > properties.maximumAuthorityResponseBytes()) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID");
        }
        try {
            JsonNode value = mapper.readTree(bytes);
            if (value == null || !value.isObject()) {
                throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID");
            }
            return value;
        } catch (IOException error) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID", error);
        }
    }

    static void requirePage(JsonNode value, UUID tenantId, String afterIncidentId, int limit) {
        if (!AuthorityJson.exact(value, PAGE_FIELDS)
            || !"agenttrust.authoritative-incident-page.v1".equals(
                value.path("schema_version").textValue())
            || !tenantId.toString().equals(value.path("tenant_id").textValue())
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !(value.path("next_after_incident_id").isNull()
                || AuthorityJson.uuid(value.path("next_after_incident_id")))) {
            invalidResponse();
        }
        String previous = afterIncidentId;
        for (JsonNode item : value.path("items")) {
            requireIncident(item, null);
            String current = item.path("incident_id").textValue();
            if (previous != null && current.compareTo(previous) <= 0) {
                invalidResponse();
            }
            previous = current;
        }
        JsonNode next = value.path("next_after_incident_id");
        if (!next.isNull() && (value.path("items").size() != limit || previous == null
            || !previous.equals(next.textValue()))) {
            invalidResponse();
        }
    }

    static void requireIncident(JsonNode value, String expectedIncidentId) {
        if (!AuthorityJson.exact(value, INCIDENT_FIELDS)
            || !AuthorityJson.uuid(value.path("incident_id"))
            || expectedIncidentId != null
                && !expectedIncidentId.equals(value.path("incident_id").textValue())
            || !AuthorityJson.text(value.path("correlation_key"), 256)
            || !SEVERITIES.contains(value.path("severity").textValue())
            || !STATUSES.contains(value.path("status").textValue())
            || !AuthorityJson.uuid(value.path("task_id"))
            || !AuthorityJson.identifier(value.path("owner"), 256)
            || !AuthorityJson.text(value.path("safe_summary"), 512)
            || !AuthorityJson.stringSet(value.path("scope"), 1, 256, 1024,
                item -> AuthorityJson.resource(item, 1024))
            || !AuthorityJson.stringSet(value.path("evidence_refs"), 1, 256, 2048,
                IncidentAuthorityGateway::incidentEvidenceReference)
            || !AuthorityJson.identifier(value.path("legal_hold_id"), 256)
            || !AuthorityJson.integer(value.path("resource_version"), 1, Long.MAX_VALUE)
            || !AuthorityJson.instant(value.path("created_at"))
            || !AuthorityJson.instant(value.path("updated_at"))
            || Instant.parse(value.path("updated_at").textValue()).isBefore(
                Instant.parse(value.path("created_at").textValue()))
            || !value.path("timeline").isArray() || value.path("timeline").size() > 100_000) {
            invalidResponse();
        }
        long sequence = 0;
        Instant occurred = null;
        String previousState = null;
        for (JsonNode event : value.path("timeline")) {
            if (!AuthorityJson.exact(event, TIMELINE_FIELDS)
                || !AuthorityJson.uuid(event.path("event_id"))
                || !AuthorityJson.integer(event.path("sequence"), 1, Long.MAX_VALUE)
                || event.path("sequence").longValue() != sequence + 1
                || !OPERATIONS_WITH_DETECT.contains(event.path("event_type").textValue())
                || !nullableStatus(event.path("from_status"))
                || !nullableStatus(event.path("to_status"))
                || !AuthorityJson.identifier(event.path("actor_subject"), 256)
                || !AuthorityJson.identifier(event.path("reason_code"), 256)
                || !AuthorityJson.digest(event.path("payload_digest"))
                || !AuthorityJson.digest(event.path("action_hash"))
                || !AuthorityJson.uuid(event.path("ledger_execution_id"))
                || !AuthorityJson.digest(event.path("fence_digest"))
                || !AuthorityJson.digest(event.path("policy_decision_digest"))
                || !incidentEvidenceReference(event.path("authorization_evidence_ref").textValue())
                || !AuthorityJson.digest(event.path("authorization_evidence_digest"))
                || !AuthorityJson.instant(event.path("occurred_at"))) {
                invalidResponse();
            }
            String from = event.path("from_status").isNull() ? null
                : event.path("from_status").textValue();
            if (sequence > 0 && from != null && previousState != null && !from.equals(previousState)) {
                invalidResponse();
            }
            Instant eventTime = Instant.parse(event.path("occurred_at").textValue());
            if (occurred != null && eventTime.isBefore(occurred)) {
                invalidResponse();
            }
            sequence += 1;
            occurred = eventTime;
            previousState = event.path("to_status").isNull() ? previousState
                : event.path("to_status").textValue();
        }
        if (!value.path("timeline").isEmpty()
            && !value.path("status").textValue().equals(previousState)) {
            invalidResponse();
        }
    }

    private static final Set<String> OPERATIONS_WITH_DETECT = Set.of(
        "DETECT", "TRIAGE", "CONTAIN", "INVESTIGATE", "PRESERVE_EVIDENCE",
        "PLAN_REPLAY", "COMPLETE_REPLAY", "PUBLISH_ROOT_CAUSE", "BEGIN_REMEDIATION",
        "TRIGGER_RECERTIFICATION", "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY",
        "ROLLBACK_RELEASE", "CLOSE");

    static void requireReceipt(JsonNode value, UUID commandId, UUID taskId, UUID tenantId) {
        if (!AuthorityJson.exact(value, RECEIPT_FIELDS)
            || !"agenttrust.incident-action-receipt.v1".equals(
                value.path("schema_version").textValue())
            || !commandId.toString().equals(value.path("action_id").textValue())
            || !taskId.toString().equals(value.path("task_id").textValue())
            || !value.path("accepted").isBoolean() || !value.path("accepted").booleanValue()
            || !value.path("execution_pending").isBoolean()
            || !value.path("execution_pending").booleanValue()
            || !AuthorityJson.digest(value.path("ingress_digest"))
            || !AuthorityJson.orchestratorEventReference(
                value.path("ledger_evidence_ref"), tenantId, taskId)
            || !AuthorityJson.digest(value.path("ledger_evidence_digest"))) {
            throw new ControlUnavailableException("CONTROL_INCIDENT_ACTION_RECEIPT_INVALID");
        }
    }

    static void requireCommand(PrincipalContext principal, IncidentCommandRequest command,
                               String idempotencyKey, ObjectMapper mapper,
                               CanonicalDigest canonical) {
        Instant now = Instant.now();
        if (principal == null || command == null || idempotencyKey == null
            || !idempotencyKey.matches("[A-Za-z0-9._:/-]{16,128}")
            || !"agenttrust.incident-command.v1".equals(command.schemaVersion())
            || !principal.tenantId().equals(command.tenantId())
            || !AuthorityJson.uuid(command.commandId().toString())
            || !AuthorityJson.uuid(command.taskId().toString())
            || !OPERATIONS.contains(command.operation()) || command.expectedResourceVersion() < 0
            || command.payload() == null || !command.payload().isObject()
            || command.requestedAt() == null || command.requestedAt().isAfter(now.plusSeconds(60))
            || command.requestedAt().isBefore(now.minus(Duration.ofHours(24)))
            || RELEASE_OPERATIONS.contains(command.operation()) != command.resourceId().startsWith("release:")
            || !validResource(command.resourceId(), command.operation())
            || !principal.strongAuth() || !principal.roles().contains(requiredRole(command.operation()))
            || !payloadShape(command, principal, canonical)) {
            throw new ControlDeniedException("CONTROL_INCIDENT_COMMAND_INVALID");
        }
        try {
            if (mapper.writeValueAsBytes(command).length > 1_048_576) {
                throw new ControlDeniedException("CONTROL_INCIDENT_COMMAND_INVALID");
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
            throw new ControlDeniedException("CONTROL_INCIDENT_COMMAND_INVALID", error);
        }
    }

    private static boolean validResource(String resource, String operation) {
        if (RELEASE_OPERATIONS.contains(operation)) {
            return resource.startsWith("release:") && resource.length() <= 1024
                && AuthorityJson.resource(resource.substring(8), 1016);
        }
        return resource.startsWith("incident:")
            && AuthorityJson.uuid(resource.substring("incident:".length()));
    }

    private static boolean payloadShape(IncidentCommandRequest request,
                                        PrincipalContext principal, CanonicalDigest canonical) {
        JsonNode value = request.payload();
        return switch (request.operation()) {
            case "TRIAGE" -> AuthorityJson.exact(value, Set.of("owner", "severity", "reason_code"))
                && AuthorityJson.identifier(value.path("owner"), 256)
                && SEVERITIES.contains(value.path("severity").textValue())
                && AuthorityJson.identifier(value.path("reason_code"), 128);
            case "CONTAIN" -> validContain(value, principal);
            case "INVESTIGATE", "BEGIN_REMEDIATION" -> AuthorityJson.exact(value,
                Set.of("reason_code")) && AuthorityJson.identifier(value.path("reason_code"), 128);
            case "PRESERVE_EVIDENCE" -> validPreservation(value);
            case "PLAN_REPLAY" -> validReplayPlan(value, principal);
            case "COMPLETE_REPLAY" -> validReplayResult(value, principal);
            case "PUBLISH_ROOT_CAUSE" -> validRootCause(value, canonical);
            case "TRIGGER_RECERTIFICATION" -> AuthorityJson.exact(value,
                Set.of("root_cause_digest", "release_digest", "campaigns"))
                && AuthorityJson.digest(value.path("root_cause_digest"))
                && AuthorityJson.digest(value.path("release_digest"))
                && AuthorityJson.stringSet(value.path("campaigns"), 1, 64, 128,
                    item -> AuthorityJson.identifier(item, 128))
                && !principal.approvalIds().isEmpty();
            case "EVALUATE_RELEASE" -> validReleaseGate(value, principal, canonical);
            case "START_CANARY" -> AuthorityJson.exact(value,
                Set.of("certificate_id", "release_digest", "canary_plan_digest", "percentage"))
                && AuthorityJson.uuid(value.path("certificate_id"))
                && AuthorityJson.digest(value.path("release_digest"))
                && AuthorityJson.digest(value.path("canary_plan_digest"))
                && AuthorityJson.integer(value.path("percentage"), 1, 10)
                && principal.approvalIds().size() >= 2;
            case "RECORD_CANARY" -> AuthorityJson.exact(value,
                Set.of("certificate_id", "release_digest", "metrics_digest", "passed",
                    "rollback_required"))
                && AuthorityJson.uuid(value.path("certificate_id"))
                && AuthorityJson.digest(value.path("release_digest"))
                && AuthorityJson.digest(value.path("metrics_digest"))
                && AuthorityJson.booleanValue(value.path("passed"))
                && AuthorityJson.booleanValue(value.path("rollback_required"))
                && (value.path("passed").booleanValue()
                    || value.path("rollback_required").booleanValue())
                && principal.approvalIds().size() >= 2;
            case "ROLLBACK_RELEASE" -> AuthorityJson.exact(value,
                Set.of("release_digest", "target_release_digest", "reason_digest"))
                && AuthorityJson.digest(value.path("release_digest"))
                && AuthorityJson.digest(value.path("target_release_digest"))
                && AuthorityJson.digest(value.path("reason_digest"))
                && principal.approvalIds().size() >= 2;
            case "CLOSE" -> AuthorityJson.exact(value,
                Set.of("root_cause_digest", "recertification_evidence_ref",
                    "recertification_evidence_digest"))
                && AuthorityJson.digest(value.path("root_cause_digest"))
                && incidentEvidenceReference(value.path("recertification_evidence_ref").textValue())
                && AuthorityJson.digest(value.path("recertification_evidence_digest"))
                && !principal.approvalIds().isEmpty();
            default -> false;
        };
    }

    private static boolean validContain(JsonNode value, PrincipalContext principal) {
        if (!AuthorityJson.exact(value, Set.of("reason_code", "targets", "break_glass"))
            || !AuthorityJson.identifier(value.path("reason_code"), 128)) {
            return false;
        }
        JsonNode targets = value.path("targets");
        if (!AuthorityJson.exact(targets, Set.of("kill_task", "revoke_credentials",
            "isolate_integrations", "freeze_artifacts"))
            || !targets.path("kill_task").isBoolean() || !targets.path("kill_task").booleanValue()
            || !targets.path("revoke_credentials").isBoolean()
            || !targets.path("revoke_credentials").booleanValue()
            || !targets.path("freeze_artifacts").isBoolean()
            || !targets.path("freeze_artifacts").booleanValue()
            || !AuthorityJson.stringSet(targets.path("isolate_integrations"), 1, 256, 1024,
                item -> AuthorityJson.resource(item, 1024))) {
            return false;
        }
        if (!principal.approvalIds().isEmpty()) {
            return value.path("break_glass").isNull();
        }
        JsonNode breakGlass = value.path("break_glass");
        if (!AuthorityJson.exact(breakGlass, Set.of("break_glass_id", "expires_at",
            "review_due_at", "compensating_controls", "reason_digest"))
            || !AuthorityJson.uuid(breakGlass.path("break_glass_id"))
            || !AuthorityJson.digest(breakGlass.path("reason_digest"))
            || !AuthorityJson.stringSet(breakGlass.path("compensating_controls"), 1, 32, 128,
                item -> AuthorityJson.identifier(item, 128))
            || !AuthorityJson.instant(breakGlass.path("expires_at"))
            || !AuthorityJson.instant(breakGlass.path("review_due_at"))) {
            return false;
        }
        Instant now = Instant.now();
        Instant expires = Instant.parse(breakGlass.path("expires_at").textValue());
        Instant review = Instant.parse(breakGlass.path("review_due_at").textValue());
        return expires.isAfter(now) && !expires.isAfter(now.plus(Duration.ofMinutes(15)))
            && !review.isBefore(expires) && !review.isAfter(now.plus(Duration.ofHours(24)));
    }

    private static boolean validPreservation(JsonNode value) {
        Set<String> fields = Set.of("chain_head_digest", "snapshot_digest", "process_digest",
            "network_digest", "configuration_digest", "version_digest", "legal_hold_id");
        if (!AuthorityJson.exact(value, fields)
            || !AuthorityJson.identifier(value.path("legal_hold_id"), 256)) {
            return false;
        }
        return fields.stream().filter(field -> field.endsWith("_digest"))
            .allMatch(field -> AuthorityJson.digest(value.path(field)));
    }

    private static boolean validReplayPlan(JsonNode value, PrincipalContext principal) {
        if (!AuthorityJson.exact(value, Set.of("replay_id", "mode", "input_digest",
            "source_snapshot_digest", "expected_result_digest", "resource_refs",
            "credential_profile", "fresh_lease_id", "fresh_lease_digest",
            "authorization_lease_expires_at"))
            || !AuthorityJson.uuid(value.path("replay_id"))
            || !AuthorityJson.digest(value.path("input_digest"))
            || !AuthorityJson.digest(value.path("source_snapshot_digest"))
            || !AuthorityJson.digest(value.path("expected_result_digest"))) {
            return false;
        }
        return switch (value.path("mode").textValue()) {
            case "LOGICAL" -> value.path("resource_refs").isArray()
                && value.path("resource_refs").isEmpty()
                && value.path("credential_profile").isNull()
                && value.path("fresh_lease_id").isNull()
                && value.path("fresh_lease_digest").isNull()
                && value.path("authorization_lease_expires_at").isNull();
            case "SANDBOX" -> "test-only".equals(value.path("credential_profile").textValue())
                && AuthorityJson.stringSet(value.path("resource_refs"), 1, 256, 1024,
                    item -> item.startsWith("sandbox://") && AuthorityJson.resource(item, 1024))
                && value.path("fresh_lease_id").isNull()
                && value.path("fresh_lease_digest").isNull()
                && value.path("authorization_lease_expires_at").isNull();
            case "LIVE" -> AuthorityJson.identifier(value.path("credential_profile"), 128)
                && !"test-only".equals(value.path("credential_profile").textValue())
                && AuthorityJson.uuid(value.path("fresh_lease_id"))
                && AuthorityJson.digest(value.path("fresh_lease_digest"))
                && AuthorityJson.instant(value.path("authorization_lease_expires_at"))
                && Instant.parse(value.path("authorization_lease_expires_at").textValue())
                    .isAfter(Instant.now())
                && !Instant.parse(value.path("authorization_lease_expires_at").textValue())
                    .isAfter(Instant.now().plus(Duration.ofHours(1)))
                && AuthorityJson.stringSet(value.path("resource_refs"), 1, 256, 1024,
                    item -> AuthorityJson.resource(item, 1024))
                && principal.approvalIds().size() >= 2;
            default -> false;
        };
    }

    private static boolean validReplayResult(JsonNode value, PrincipalContext principal) {
        return AuthorityJson.exact(value, Set.of("replay_id", "mode", "plan_digest"))
            && AuthorityJson.uuid(value.path("replay_id"))
            && Set.of("LOGICAL", "SANDBOX", "LIVE").contains(value.path("mode").textValue())
            && AuthorityJson.digest(value.path("plan_digest"))
            && (!"LIVE".equals(value.path("mode").textValue())
                || principal.approvalIds().size() >= 2);
    }

    private static boolean validRootCause(JsonNode value, CanonicalDigest canonical) {
        if (!AuthorityJson.exact(value, Set.of("report_id", "report_digest", "findings",
            "remediations")) || !AuthorityJson.uuid(value.path("report_id"))
            || !AuthorityJson.digest(value.path("report_digest"))
            || !value.path("findings").isArray() || value.path("findings").isEmpty()
            || value.path("findings").size() > 256 || !value.path("remediations").isArray()
            || value.path("remediations").isEmpty() || value.path("remediations").size() > 512) {
            return false;
        }
        Set<String> findings = new HashSet<>();
        for (JsonNode finding : value.path("findings")) {
            if (!AuthorityJson.exact(finding, Set.of("finding_id", "category", "trigger",
                "system_defect", "detection_gap", "recovery_gap", "evidence_refs"))
                || !AuthorityJson.identifier(finding.path("finding_id"), 128)
                || !Set.of("TRIGGER", "SYSTEM_DEFECT", "DETECTION_GAP", "RECOVERY_PROBLEM")
                    .contains(finding.path("category").textValue())
                || !AuthorityJson.identifier(finding.path("trigger"), 512)
                || !AuthorityJson.identifier(finding.path("system_defect"), 512)
                || !AuthorityJson.identifier(finding.path("detection_gap"), 512)
                || !AuthorityJson.identifier(finding.path("recovery_gap"), 512)
                || !AuthorityJson.stringSet(finding.path("evidence_refs"), 1, 256, 2048,
                    IncidentAuthorityGateway::incidentEvidenceReference)
                || !findings.add(finding.path("finding_id").textValue())) {
                return false;
            }
        }
        Set<String> covered = new HashSet<>();
        for (JsonNode remediation : value.path("remediations")) {
            if (!AuthorityJson.exact(remediation, Set.of("remediation_id", "finding_id",
                "policy_ref", "test_ref", "owner", "due_at"))
                || !AuthorityJson.identifier(remediation.path("remediation_id"), 128)
                || !AuthorityJson.identifier(remediation.path("finding_id"), 128)
                || !AuthorityJson.text(remediation.path("policy_ref"), 1024)
                || !AuthorityJson.resource(remediation.path("policy_ref").textValue(), 1024)
                || !AuthorityJson.text(remediation.path("test_ref"), 1024)
                || !AuthorityJson.resource(remediation.path("test_ref").textValue(), 1024)
                || !AuthorityJson.identifier(remediation.path("owner"), 256)
                || !AuthorityJson.instant(remediation.path("due_at"))) {
                return false;
            }
            covered.add(remediation.path("finding_id").textValue());
        }
        ObjectNode material = canonicalObject(value, "findings", "remediations");
        return covered.containsAll(findings)
            && value.path("report_digest").textValue().equals(canonical.digest(material));
    }

    private static boolean validReleaseGate(JsonNode value, PrincipalContext principal,
                                            CanonicalDigest canonical) {
        if (principal.approvalIds().size() < 2 || !AuthorityJson.exact(value,
            Set.of("release_digest", "definition", "evidence", "rollback_artifact_digest",
                "canary_plan_digest", "valid_until"))
            || !AuthorityJson.digest(value.path("release_digest"))
            || !AuthorityJson.digest(value.path("rollback_artifact_digest"))
            || !AuthorityJson.digest(value.path("canary_plan_digest"))
            || !AuthorityJson.instant(value.path("valid_until"))) {
            return false;
        }
        JsonNode definition = value.path("definition");
        if (!AuthorityJson.exact(definition, Set.of("gate_id", "version", "definition_digest",
            "required_controls", "maximum_evidence_age_seconds"))
            || !AuthorityJson.identifier(definition.path("gate_id"), 128)
            || !AuthorityJson.identifier(definition.path("version"), 64)
            || !AuthorityJson.digest(definition.path("definition_digest"))
            || !AuthorityJson.stringSet(definition.path("required_controls"), 10, 128, 128,
                item -> AuthorityJson.identifier(item, 128))
            || !AuthorityJson.integer(definition.path("maximum_evidence_age_seconds"), 60,
                2_592_000)) {
            return false;
        }
        Set<String> required = stringValues(definition.path("required_controls"));
        Set<String> baseline = Set.of("CONTRACT", "IDENTITY", "POLICY", "SANDBOX",
            "IDEMPOTENCY", "ROLLBACK", "TRACE", "THREAT", "COMPLIANCE", "DOMAIN_EVALUATOR");
        ObjectNode definitionMaterial = canonicalObject(definition, "gate_id", "version",
            "required_controls", "maximum_evidence_age_seconds");
        if (!required.containsAll(baseline)
            || !definition.path("definition_digest").textValue()
                .equals(canonical.digest(definitionMaterial))
            || !value.path("evidence").isArray()
            || value.path("evidence").size() != required.size()) {
            return false;
        }
        Set<String> observed = new HashSet<>();
        Instant now = Instant.now();
        long maximumAge = definition.path("maximum_evidence_age_seconds").longValue();
        for (JsonNode evidence : value.path("evidence")) {
            if (!AuthorityJson.exact(evidence, Set.of("control_id", "evidence_ref",
                "evidence_digest", "release_digest", "passed", "collected_at"))
                || !AuthorityJson.identifier(evidence.path("control_id"), 128)
                || !incidentEvidenceReference(evidence.path("evidence_ref").textValue())
                || !AuthorityJson.digest(evidence.path("evidence_digest"))
                || !value.path("release_digest").textValue()
                    .equals(evidence.path("release_digest").textValue())
                || !evidence.path("passed").isBoolean() || !evidence.path("passed").booleanValue()
                || !AuthorityJson.instant(evidence.path("collected_at"))
                || !observed.add(evidence.path("control_id").textValue())) {
                return false;
            }
            Instant collected = Instant.parse(evidence.path("collected_at").textValue());
            if (collected.isAfter(now) || collected.isBefore(now.minusSeconds(maximumAge))) {
                return false;
            }
        }
        Instant expiry = Instant.parse(value.path("valid_until").textValue());
        return observed.equals(required) && expiry.isAfter(now)
            && !expiry.isAfter(now.plus(Duration.ofDays(7)));
    }

    private static ObjectNode canonicalObject(JsonNode source, String... fields) {
        ObjectNode value = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode();
        for (String field : fields) {
            value.set(field, source.path(field));
        }
        return value;
    }

    private static Set<String> stringValues(JsonNode value) {
        Set<String> result = new HashSet<>();
        value.forEach(item -> result.add(item.textValue()));
        return result;
    }

    private static String requiredRole(String operation) {
        return switch (operation) {
            case "TRIAGE", "INVESTIGATE", "PRESERVE_EVIDENCE", "PLAN_REPLAY",
                "COMPLETE_REPLAY" -> "incident-responder";
            case "CONTAIN", "PUBLISH_ROOT_CAUSE", "BEGIN_REMEDIATION",
                "TRIGGER_RECERTIFICATION", "CLOSE" -> "incident-commander";
            default -> "release-manager";
        };
    }

    private void requireLimit(int limit) {
        if (limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_INCIDENT_QUERY_INVALID");
        }
    }

    private static boolean nullableStatus(JsonNode value) {
        return value != null && (value.isNull()
            || value.isTextual() && (STATUSES.contains(value.textValue())
                || Set.of("GATE_PASSED", "CANARY_RUNNING", "CANARY_PASSED",
                    "ROLLBACK_REQUIRED", "ROLLED_BACK").contains(value.textValue())));
    }

    private static boolean incidentEvidenceReference(String value) {
        return value != null && value.length() <= 2048
            && (value.startsWith("evidence://")
                || value.startsWith("urn:agenttrust:evidence:")
                || value.startsWith("urn:agenttrust:ledger-evidence:"))
            && !value.matches(".*[\\s?#].*");
    }

    private static void invalidResponse() {
        throw new ControlUnavailableException("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID");
    }
}
