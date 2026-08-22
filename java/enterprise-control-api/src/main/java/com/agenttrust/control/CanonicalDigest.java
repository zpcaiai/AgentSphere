package com.agenttrust.control;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.springframework.stereotype.Component;

@Component
public final class CanonicalDigest {
    private final ObjectMapper mapper;

    public CanonicalDigest(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public String digest(Map<String, Object> values) {
        return digest((Object) values);
    }

    public String digest(Object value) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(canonicalBytes(value)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("CONTROL_CANONICALIZATION_FAILED", error);
        }
    }

    /**
     * RFC 8785-compatible bytes for the bounded control-plane contracts. Those contracts permit
     * strings, booleans, nulls, integral values, arrays and objects only; object members are sorted
     * lexicographically and array order is preserved.
     */
    public byte[] canonicalBytes(Object value) {
        try {
            JsonNode canonical = canonicalizeValue(value);
            return mapper.writeValueAsString(canonical).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("CONTROL_CANONICALIZATION_FAILED", error);
        }
    }

    public String canonicalJson(Object value) {
        return new String(canonicalBytes(value), StandardCharsets.UTF_8);
    }

    public String actionDigest(AdminModels.AdminIntent intent, String reason, Object request) {
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("schema_version", intent.schemaVersion());
        action.put("action_id", intent.actionId());
        action.put("tenant_id", intent.tenantId());
        action.put("project_id", intent.projectId());
        action.put("operation", intent.operation());
        action.put("resource", intent.resource());
        action.put("requested_by", intent.requestedBy());
        action.put("approval_ids", intent.approvalIds());
        action.put("requested_at_epoch_ms", intent.requestedAt().toEpochMilli());
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("action", action);
        binding.put("reason", reason);
        binding.put("request", request);
        return digest(binding);
    }

    private JsonNode canonicalizeValue(Object value) {
        if (value instanceof JsonNode node) {
            return canonicalize(node);
        }
        if (value instanceof Map<?, ?> map) {
            ObjectNode result = mapper.createObjectNode();
            Map<String, JsonNode> fields = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new IllegalStateException("CONTROL_CANONICALIZATION_KEY_INVALID");
                }
                fields.put(key, canonicalizeValue(entry.getValue()));
            }
            fields.forEach(result::set);
            return result;
        }
        if (value instanceof Set<?> set) {
            List<JsonNode> values = new ArrayList<>();
            set.forEach(item -> values.add(canonicalizeValue(item)));
            values.sort(Comparator.comparing(JsonNode::toString));
            ArrayNode result = mapper.createArrayNode();
            values.forEach(result::add);
            return result;
        }
        if (value instanceof Iterable<?> iterable) {
            ArrayNode result = mapper.createArrayNode();
            iterable.forEach(item -> result.add(canonicalizeValue(item)));
            return result;
        }
        return canonicalize(mapper.valueToTree(value));
    }

    private JsonNode canonicalize(JsonNode value) {
        if (value.isObject()) {
            ObjectNode result = mapper.createObjectNode();
            Map<String, JsonNode> fields = new TreeMap<>();
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
}
