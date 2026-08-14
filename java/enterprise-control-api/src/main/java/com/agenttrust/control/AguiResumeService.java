package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** Produces bounded, signed and statelessly resumable AG-UI pages from authoritative transitions. */
@Service
public final class AguiResumeService {
    private static final String EVENT_SCHEMA = "agenttrust.a2a-agui.v1";
    private static final String TOKEN_SCHEMA = "agenttrust.agui-resume.v1";
    private final GovernedAuthorityGateway authorities;
    private final AguiSigningKeyProvider keys;
    private final ControlProperties properties;
    private final ObjectMapper mapper;

    public AguiResumeService(GovernedAuthorityGateway authorities, AguiSigningKeyProvider keys,
                             ControlProperties properties, ObjectMapper mapper) {
        this.authorities = authorities;
        this.keys = keys;
        this.properties = properties;
        this.mapper = mapper;
    }

    public JsonNode resume(PrincipalContext principal, String taskId, String encodedToken, int limit) {
        if (limit < 1 || limit > Math.min(100, properties.maximumPageSize())) {
            throw new ControlDeniedException("CONTROL_AGUI_LIMIT_INVALID");
        }
        long after = encodedToken == null || encodedToken.isBlank()
            ? 0 : decodeToken(encodedToken, principal, taskId);
        JsonNode authoritative = authorities.taskTransitions(principal, taskId, 1000);
        TreeMap<Long, JsonNode> transitions = transitions(authoritative);
        validateAuthoritativeState(authoritative, principal, taskId, transitions);
        long expected = after + 1;
        if ((after == 0 && !transitions.isEmpty() && transitions.firstKey() > 1)
            || after > 0 && transitions.floorKey(after) == null
            || !transitions.tailMap(after, false).isEmpty()
                && transitions.tailMap(after, false).firstKey() != expected) {
            return snapshotRequired();
        }
        ArrayNode events = mapper.createArrayNode();
        long cursor = after;
        for (Map.Entry<Long, JsonNode> entry : transitions.tailMap(after, false).entrySet()) {
            if (events.size() >= limit) {
                break;
            }
            if (entry.getKey() != cursor + 1) {
                return snapshotRequired();
            }
            events.add(toSignedEvent(principal, taskId, entry.getValue(), entry.getKey()));
            cursor = entry.getKey();
        }
        ObjectNode response = mapper.createObjectNode();
        response.set("events", events);
        response.put("next_resume_token", encodeToken(principal, taskId, cursor));
        response.put("safe_snapshot_required", false);
        return response;
    }

    /**
     * Re-anchors a client whose event cursor fell behind the bounded transition ring.  The
     * snapshot contains only safelisted status data and a fresh tenant/task-bound resume token;
     * the Ed25519 signature covers both so a browser cannot advance its reducer from an
     * untrusted cursor.
     */
    public JsonNode snapshot(PrincipalContext principal, String taskId) {
        JsonNode authoritative = authorities.taskTransitions(principal, taskId, 1000);
        TreeMap<Long, JsonNode> transitions = transitions(authoritative);
        validateAuthoritativeState(authoritative, principal, taskId, transitions);
        long cursor = authoritative.path("recovery_cursor").longValue();
        ObjectNode safeState = mapper.createObjectNode();
        safeState.put("status", authoritative.path("status").textValue());
        if (!authoritative.path("evidence_digest").isNull()) {
            safeState.put("evidence_digest", authoritative.path("evidence_digest").textValue());
        }
        if (!authoritative.path("occurred_at").isNull()) {
            safeState.put("occurred_at", authoritative.path("occurred_at").textValue());
        }
        ObjectNode snapshot = mapper.createObjectNode();
        snapshot.put("schema_version", "agenttrust.agui-safe-snapshot.v1");
        snapshot.put("tenant_id", principal.tenantId().toString());
        snapshot.put("task_id", taskId);
        snapshot.put("sequence", cursor);
        snapshot.set("safe_state", safeState);
        snapshot.put("next_resume_token", encodeToken(principal, taskId, cursor));
        snapshot.put("generated_at", Instant.now().toString());
        snapshot.put("backend_signature", "");
        snapshot.put("backend_signature", keys.signEvent(canonicalBytes(snapshot)));
        return snapshot;
    }

    private TreeMap<Long, JsonNode> transitions(JsonNode source) {
        JsonNode values = source.path("transitions");
        if (!values.isArray() || values.size() > 1000) {
            throw new ControlUnavailableException("CONTROL_AGUI_SOURCE_INVALID");
        }
        TreeMap<Long, JsonNode> transitions = new TreeMap<>();
        for (JsonNode candidate : values) {
            if (!candidate.isObject() || !candidate.path("recovery_cursor").canConvertToLong()) {
                throw new ControlUnavailableException("CONTROL_AGUI_SOURCE_INVALID");
            }
            long sequence = candidate.path("recovery_cursor").longValue();
            validateTransition(candidate, sequence);
            if (transitions.putIfAbsent(sequence, candidate) != null) {
                throw new ControlUnavailableException("CONTROL_AGUI_SEQUENCE_DUPLICATE");
            }
        }
        return transitions;
    }

    private void validateAuthoritativeState(JsonNode source, PrincipalContext principal,
                                            String taskId,
                                            TreeMap<Long, JsonNode> transitions) {
        long cursor = source.path("recovery_cursor").longValue();
        String status = source.path("status").textValue();
        JsonNode evidenceDigest = source.path("evidence_digest");
        JsonNode occurredAt = source.path("occurred_at");
        boolean expectedTerminal = "COMPLETED".equals(status) || "KILLED".equals(status)
            || "FAILED".equals(status) || "ROLLED_BACK".equals(status)
            || "DENIED".equals(status);
        if (!source.isObject()
            || !"agenttrust.authoritative-task-transitions.v1".equals(
                source.path("schema_version").textValue())
            || !principal.tenantId().toString().equals(source.path("tenant_id").textValue())
            || !taskId.equals(source.path("task_id").textValue())
            || !source.path("recovery_cursor").canConvertToLong()
            || source.path("recovery_cursor").longValue() < 0
            || source.path("recovery_cursor").longValue() > 1_000_000
            || !source.path("terminal").isBoolean()
            || !isStatus(source.path("status").textValue())
            || source.path("terminal").booleanValue() != expectedTerminal
            || cursor == 0
                && (!transitions.isEmpty() || !"CREATED".equals(status)
                    || !evidenceDigest.isNull()
                    || !occurredAt.isNull())
            || cursor > 0
                && (transitions.isEmpty()
                    || transitions.lastKey() != cursor
                    || !status.equals(transitions.lastEntry().getValue().path("to").textValue())
                    || !evidenceDigest.isTextual()
                    || !evidenceDigest.textValue().equals(
                        transitions.lastEntry().getValue().path("evidence_digest").textValue())
                    || !occurredAt.isTextual()
                    || !occurredAt.textValue().equals(
                        transitions.lastEntry().getValue().path("occurred_at").textValue()))
            || !evidenceDigest.isNull()
                && (!evidenceDigest.isTextual()
                    || !evidenceDigest.textValue().matches("[a-f0-9]{64}"))
            || !occurredAt.isNull()
                && (!occurredAt.isTextual() || !validInstant(occurredAt.textValue()))) {
            throw new ControlUnavailableException("CONTROL_AGUI_SOURCE_INVALID");
        }
    }

    private ObjectNode toSignedEvent(PrincipalContext principal, String taskId, JsonNode source,
                                     long sequence) {
        ObjectNode safePayload = mapper.createObjectNode();
        safePayload.put("from", source.path("from").textValue());
        safePayload.put("to", source.path("to").textValue());
        safePayload.put("recovery_cursor", sequence);
        safePayload.put("evidence_digest", source.path("evidence_digest").textValue());
        ObjectNode event = mapper.createObjectNode();
        event.put("schema_version", EVENT_SCHEMA);
        event.put("event_id", source.path("event_id").textValue());
        event.put("tenant_id", principal.tenantId().toString());
        event.put("task_id", taskId);
        event.put("sequence", sequence);
        event.put("trace_id", source.path("command_id").textValue());
        event.put("kind", "EXECUTION_STATUS");
        event.set("safe_payload", safePayload);
        event.put("occurred_at", source.path("occurred_at").textValue());
        event.put("backend_signature", "");
        event.put("backend_signature", keys.signEvent(canonicalBytes(event)));
        return event;
    }

    private void validateTransition(JsonNode value, long sequence) {
        if (sequence < 1 || sequence > 1_000_000
            || !isIdentifier(value.path("event_id").textValue(), 200)
            || !isIdentifier(value.path("command_id").textValue(), 256)
            || !isStatus(value.path("from").textValue()) || !isStatus(value.path("to").textValue())
            || !value.path("evidence_digest").asText("").matches("[a-f0-9]{64}")) {
            throw new ControlUnavailableException("CONTROL_AGUI_SOURCE_INVALID");
        }
        try {
            Instant occurred = Instant.parse(value.path("occurred_at").textValue());
            if (occurred.isAfter(Instant.now().plus(5, ChronoUnit.MINUTES))) {
                throw new ControlUnavailableException("CONTROL_AGUI_SOURCE_INVALID");
            }
            UUID.fromString(value.path("event_id").textValue());
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_AGUI_SOURCE_INVALID", error);
        }
    }

    private String encodeToken(PrincipalContext principal, String taskId, long after) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("schema_version", TOKEN_SCHEMA);
        payload.put("tenant_id", principal.tenantId().toString());
        payload.put("task_id", taskId);
        payload.put("after_sequence", after);
        payload.put("expires_at_epoch_seconds",
            Instant.now().plusSeconds(properties.aguiResumeTtlSeconds()).getEpochSecond());
        byte[] canonical = canonicalBytes(payload);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(canonical) + "." + encoder.encodeToString(keys.tokenMac(canonical));
    }

    private long decodeToken(String encoded, PrincipalContext principal, String taskId) {
        if (encoded.length() > 2048 || encoded.chars().filter(value -> value == '.').count() != 1) {
            throw new ControlDeniedException("CONTROL_AGUI_TOKEN_INVALID");
        }
        try {
            String[] parts = encoded.split("\\.", -1);
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[0]);
            byte[] supplied = Base64.getUrlDecoder().decode(parts[1]);
            if (!MessageDigest.isEqual(keys.tokenMac(payloadBytes), supplied)) {
                throw new ControlDeniedException("CONTROL_AGUI_TOKEN_INVALID");
            }
            JsonNode payload = mapper.readTree(payloadBytes);
            if (!payload.isObject() || payload.size() != 5
                || !TOKEN_SCHEMA.equals(payload.path("schema_version").textValue())
                || !principal.tenantId().toString().equals(payload.path("tenant_id").textValue())
                || !taskId.equals(payload.path("task_id").textValue())
                || !payload.path("after_sequence").canConvertToLong()
                || !payload.path("expires_at_epoch_seconds").canConvertToLong()
                || payload.path("expires_at_epoch_seconds").longValue() <= Instant.now().getEpochSecond()) {
                throw new ControlDeniedException("CONTROL_AGUI_TOKEN_INVALID");
            }
            long after = payload.path("after_sequence").longValue();
            if (after < 0 || after > 1_000_000) {
                throw new ControlDeniedException("CONTROL_AGUI_TOKEN_INVALID");
            }
            return after;
        } catch (ControlDeniedException error) {
            throw error;
        } catch (RuntimeException | java.io.IOException error) {
            throw new ControlDeniedException("CONTROL_AGUI_TOKEN_INVALID", error);
        }
    }

    private byte[] canonicalBytes(JsonNode value) {
        try {
            return mapper.writeValueAsBytes(canonicalize(value));
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("CONTROL_AGUI_CANONICALIZATION_FAILED", error);
        }
    }

    private JsonNode canonicalize(JsonNode value) {
        if (value.isObject()) {
            ObjectNode result = mapper.createObjectNode();
            TreeMap<String, JsonNode> fields = new TreeMap<>();
            value.properties().forEach(entry -> fields.put(entry.getKey(), canonicalize(entry.getValue())));
            fields.forEach(result::set);
            return result;
        }
        if (value.isArray()) {
            ArrayNode result = mapper.createArrayNode();
            value.forEach(item -> result.add(canonicalize(item)));
            return result;
        }
        return value;
    }

    private ObjectNode snapshotRequired() {
        ObjectNode response = mapper.createObjectNode();
        response.set("events", mapper.createArrayNode());
        response.put("next_resume_token", "");
        response.put("safe_snapshot_required", true);
        return response;
    }

    private static boolean isIdentifier(String value, int maximum) {
        return value != null && !value.isBlank() && value.length() <= maximum
            && value.matches("[A-Za-z0-9][A-Za-z0-9:._-]*");
    }

    private static boolean isStatus(String value) {
        return value != null && value.matches("[A-Z][A-Z0-9_]{0,63}");
    }

    private static boolean validInstant(String value) {
        try {
            Instant.parse(value);
            return true;
        } catch (RuntimeException error) {
            return false;
        }
    }
}
