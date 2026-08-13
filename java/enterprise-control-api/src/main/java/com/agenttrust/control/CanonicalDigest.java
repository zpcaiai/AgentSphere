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
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Component;

@Component
public final class CanonicalDigest {
    private final ObjectMapper mapper;

    public CanonicalDigest(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public String digest(Map<String, Object> values) {
        try {
            JsonNode canonical = canonicalize(mapper.valueToTree(values));
            byte[] bytes = mapper.writeValueAsString(canonical).getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (JsonProcessingException | NoSuchAlgorithmException error) {
            throw new IllegalStateException("CONTROL_CANONICALIZATION_FAILED", error);
        }
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

    private JsonNode canonicalize(JsonNode value) {
        if (value.isObject()) {
            ObjectNode result = mapper.createObjectNode();
            Map<String, JsonNode> fields = new TreeMap<>();
            value.properties().forEach(entry -> fields.put(entry.getKey(), canonicalize(entry.getValue())));
            fields.forEach(result::set);
            return result;
        }
        if (value.isArray()) {
            var values = new ArrayList<JsonNode>();
            value.forEach(item -> values.add(canonicalize(item)));
            values.sort(Comparator.comparing(JsonNode::toString));
            ArrayNode result = mapper.createArrayNode();
            values.forEach(result::add);
            return result;
        }
        return value;
    }
}
