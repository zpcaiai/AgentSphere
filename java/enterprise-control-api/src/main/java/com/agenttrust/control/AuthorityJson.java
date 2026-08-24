package com.agenttrust.control;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Shared strict JSON predicates for tenant authority gateways. */
final class AuthorityJson {
    private static final java.util.regex.Pattern SHA256 =
        java.util.regex.Pattern.compile("^[a-f0-9]{64}$");
    private static final Pattern ORCHESTRATOR_EVENT = Pattern.compile(
        "^orchestrator-event://([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/"
            + "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/"
            + "([1-9][0-9]{0,18})$");

    private AuthorityJson() {}

    static boolean exact(JsonNode value, Set<String> expected) {
        if (value == null || !value.isObject() || value.size() != expected.size()) {
            return false;
        }
        Set<String> actual = new HashSet<>();
        value.fieldNames().forEachRemaining(actual::add);
        return actual.equals(expected);
    }

    static boolean text(JsonNode value, int maximum) {
        return value != null && value.isTextual() && !value.textValue().isBlank()
            && value.textValue().length() <= maximum && !control(value.textValue());
    }

    static boolean nullableText(JsonNode value, int maximum) {
        return value != null && (value.isNull() || text(value, maximum));
    }

    static boolean identifier(JsonNode value, int maximum) {
        return text(value, maximum) && value.textValue().matches(
            "[A-Za-z0-9._:/@-]{1," + maximum + "}");
    }

    static boolean identifier(String value, int maximum) {
        return value != null && !value.isEmpty() && value.length() <= maximum && !control(value)
            && value.matches("[A-Za-z0-9._:/@-]{1," + maximum + "}");
    }

    static boolean resource(String value, int maximum) {
        return identifier(value, maximum) && !value.contains("..");
    }

    static boolean digest(JsonNode value) {
        return value != null && value.isTextual() && SHA256.matcher(value.textValue()).matches();
    }

    static boolean digestOrNull(JsonNode value) {
        return value != null && (value.isNull() || digest(value));
    }

    static boolean uuid(JsonNode value) {
        return value != null && value.isTextual() && uuid(value.textValue());
    }

    static boolean uuid(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.toString().equals(value)
                && (parsed.getMostSignificantBits() != 0L || parsed.getLeastSignificantBits() != 0L);
        } catch (RuntimeException error) {
            return false;
        }
    }

    static boolean instant(JsonNode value) {
        if (value == null || !value.isTextual() || value.textValue().length() > 64) {
            return false;
        }
        try {
            Instant.parse(value.textValue());
            return true;
        } catch (RuntimeException error) {
            return false;
        }
    }

    static boolean integer(JsonNode value, long minimum, long maximum) {
        return value != null && value.isIntegralNumber() && value.canConvertToLong()
            && value.longValue() >= minimum && value.longValue() <= maximum;
    }

    static boolean booleanValue(JsonNode value) {
        return value != null && value.isBoolean();
    }

    static boolean stringSet(JsonNode value, int minimum, int maximum, int maximumLength) {
        if (value == null || !value.isArray() || value.size() < minimum
            || value.size() > maximum) {
            return false;
        }
        Set<String> unique = new HashSet<>();
        for (JsonNode item : value) {
            if (!text(item, maximumLength) || !unique.add(item.textValue())) {
                return false;
            }
        }
        return true;
    }

    static boolean stringSet(JsonNode value, int minimum, int maximum, int maximumLength,
                             java.util.function.Predicate<String> predicate) {
        if (!stringSet(value, minimum, maximum, maximumLength)) {
            return false;
        }
        for (JsonNode item : value) {
            if (!predicate.test(item.textValue())) {
                return false;
            }
        }
        return true;
    }

    static boolean evidenceReference(JsonNode value) {
        return text(value, 2048)
            && (value.textValue().startsWith("evidence://")
                || value.textValue().startsWith("urn:agenttrust:evidence:")
                || value.textValue().startsWith("urn:agenttrust:"))
            && !value.textValue().matches(".*[ ?#].*");
    }

    static boolean approvalEvidenceReference(JsonNode value) {
        return text(value, 2048)
            && value.textValue().matches(
                "^(evidence://|urn:agenttrust:(evidence|ledger-evidence):)[^\\s?#]+$")
            && !containsSecretMarker(value.textValue());
    }

    static boolean codingApprovalDetails(JsonNode details) {
        return exact(details, Set.of("diff_artifact_ref", "command_summary", "network_scope",
                "rollback_summary"))
            && details.path("diff_artifact_ref").isTextual()
            && details.path("diff_artifact_ref").textValue()
                .matches("^artifact://sha256/[a-f0-9]{64}$")
            && safeReviewText(details.path("command_summary"), 2048)
            && safeReviewText(details.path("network_scope"), 1024)
            && safeReviewText(details.path("rollback_summary"), 2048);
    }

    static boolean industrialApprovalDetails(JsonNode details) {
        return exact(details, Set.of("current_value", "target_value", "allowed_range",
                "interlock_summary", "physical_impact"))
            && safeReviewText(details.path("current_value"), 512)
            && safeReviewText(details.path("target_value"), 512)
            && safeReviewText(details.path("allowed_range"), 512)
            && safeReviewText(details.path("interlock_summary"), 2048)
            && safeReviewText(details.path("physical_impact"), 2048);
    }

    static boolean approvalReviewContext(JsonNode context, boolean industrial) {
        if (!exact(context, Set.of("domain", "details"))) {
            return false;
        }
        return industrial
            ? "INDUSTRIAL".equals(context.path("domain").asText())
                && industrialApprovalDetails(context.path("details"))
            : "CODING".equals(context.path("domain").asText())
                && codingApprovalDetails(context.path("details"));
    }

    static boolean signedApprovalReviewEvidence(JsonNode evidence, JsonNode request,
                                                JsonNode caseCreatedAt,
                                                CanonicalDigest canonical) {
        if (!exact(evidence, Set.of("schema_version", "material", "authority_request", "receipt"))
            || !"agenttrust.approval-review-evidence-binding.v1"
                .equals(evidence.path("schema_version").asText())
            || !approvalReviewMaterial(evidence.path("material"), request)) {
            return false;
        }
        JsonNode material = evidence.path("material");
        JsonNode authority = evidence.path("authority_request");
        JsonNode receipt = evidence.path("receipt");
        if (!exact(authority, Set.of("schema_version", "tenant_id", "task_id",
                "authority_event_id", "idempotency_key", "source_kind", "control_binding",
                "event", "requested_at"))
            || !"agenttrust.authority-evidence-event-request.v1"
                .equals(authority.path("schema_version").asText())
            || !authority.path("tenant_id").equals(request.path("tenant_id"))
            || !authority.path("task_id").equals(request.path("task_id"))
            || !uuid(authority.path("authority_event_id"))
            || !authority.path("idempotency_key").asText()
                .matches("^[A-Za-z0-9._:-]{1,128}$")
            || !"AUTHENTICATED_EVENT".equals(authority.path("source_kind").asText())
            || !authority.path("control_binding").isNull()
            || !instant(authority.path("requested_at"))
            || !approvalReviewEvent(authority.path("event"), authority, material, canonical)) {
            return false;
        }
        return signedAuthorityEvidenceReceipt(receipt, authority, material, caseCreatedAt,
            canonical);
    }

    private static boolean approvalReviewMaterial(JsonNode material, JsonNode request) {
        Set<String> fields = Set.of("schema_version", "tenant_id", "task_id",
            "canonical_action_hash", "resource", "resource_version", "policy_version",
            "environment", "risk", "review_context", "risk_package_ref",
            "risk_package_digest", "state_snapshot_ref", "state_snapshot_digest");
        return exact(material, fields)
            && "agenttrust.approval-review-material.v1"
                .equals(material.path("schema_version").asText())
            && material.path("tenant_id").equals(request.path("tenant_id"))
            && material.path("task_id").equals(request.path("task_id"))
            && material.path("canonical_action_hash").equals(request.path("action_hash"))
            && material.path("resource").equals(request.path("resource"))
            && material.path("resource_version").equals(request.path("resource_version"))
            && material.path("policy_version").equals(request.path("policy_version"))
            && material.path("environment").equals(request.path("environment"))
            && material.path("risk").equals(request.path("risk"))
            && material.path("review_context").equals(request.path("review_context"))
            && approvalEvidenceReference(material.path("risk_package_ref"))
            && digest(material.path("risk_package_digest"))
            && approvalEvidenceReference(material.path("state_snapshot_ref"))
            && digest(material.path("state_snapshot_digest"))
            && !material.path("risk_package_ref").equals(material.path("state_snapshot_ref"));
    }

    private static boolean approvalReviewEvent(JsonNode event, JsonNode authority,
                                               JsonNode material, CanonicalDigest canonical) {
        if (!exact(event, Set.of("schema_version", "tenant_id", "task_id", "event_type",
                "actor_subject", "source_service", "trace_id", "span_id", "payload_hash",
                "safe_summary", "artifact_refs", "occurred_at"))
            || !"agenttrust.evidence.v1".equals(event.path("schema_version").asText())
            || !event.path("tenant_id").equals(authority.path("tenant_id"))
            || !event.path("task_id").equals(authority.path("task_id"))
            || !"APPROVAL_REVIEW_PREPARED".equals(event.path("event_type").asText())
            || !identifier(event.path("actor_subject"), 512)
            || !identifier(event.path("source_service"), 256)
            || !(event.path("source_service").asText().startsWith("DNS:")
                || event.path("source_service").asText().startsWith("URI:"))
            || !identifier(event.path("trace_id"), 256)
            || !event.path("span_id").equals(authority.path("authority_event_id"))
            || !digest(event.path("payload_hash"))
            || !canonical.digest(material).equals(event.path("payload_hash").asText())
            || !instant(event.path("occurred_at"))
            || !event.path("occurred_at").equals(authority.path("requested_at"))) {
            return false;
        }
        boolean industrial = "INDUSTRIAL".equals(material.path("review_context").path("domain").asText());
        String expectedSummary = industrial
            ? "Approval industrial review facts prepared" : "Approval coding review facts prepared";
        List<String> expectedArtifacts = industrial
            ? List.of(material.path("risk_package_ref").asText(),
                material.path("state_snapshot_ref").asText())
            : List.of(material.path("review_context").path("details")
                    .path("diff_artifact_ref").asText(),
                material.path("risk_package_ref").asText(),
                material.path("state_snapshot_ref").asText());
        JsonNode artifacts = event.path("artifact_refs");
        if (!expectedSummary.equals(event.path("safe_summary").asText())
            || !artifacts.isArray() || artifacts.size() != expectedArtifacts.size()) {
            return false;
        }
        for (int index = 0; index < expectedArtifacts.size(); index++) {
            if (!artifacts.path(index).isTextual()
                || !expectedArtifacts.get(index).equals(artifacts.path(index).asText())) {
                return false;
            }
        }
        return true;
    }

    private static boolean signedAuthorityEvidenceReceipt(JsonNode receipt, JsonNode authority,
                                                          JsonNode material,
                                                          JsonNode caseCreatedAt,
                                                          CanonicalDigest canonical) {
        if (!exact(receipt, Set.of("schema_version", "tenant_id", "task_id",
                "authority_event_id", "idempotency_key", "source_kind", "request_digest",
                "payload_digest", "evidence_ref", "evidence_digest", "event", "persisted_at",
                "issuer", "key_id", "key_usage", "signature"))
            || !"agenttrust.signed-authority-evidence-receipt.v1"
                .equals(receipt.path("schema_version").asText())
            || !receipt.path("tenant_id").equals(authority.path("tenant_id"))
            || !receipt.path("task_id").equals(authority.path("task_id"))
            || !receipt.path("authority_event_id").equals(authority.path("authority_event_id"))
            || !receipt.path("idempotency_key").equals(authority.path("idempotency_key"))
            || !"AUTHENTICATED_EVENT".equals(receipt.path("source_kind").asText())
            || !digest(receipt.path("request_digest"))
            || !canonical.digest(authority).equals(receipt.path("request_digest").asText())
            || !receipt.path("payload_digest").equals(authority.path("event").path("payload_hash"))
            || !receipt.path("payload_digest").asText().equals(canonical.digest(material))
            || !approvalEvidenceReference(receipt.path("evidence_ref"))
            || !digest(receipt.path("evidence_digest"))
            || !instant(receipt.path("persisted_at")) || !instant(caseCreatedAt)
            || !identifier(receipt.path("issuer"), 256)
            || !receipt.path("key_id").asText().matches("^[A-Za-z0-9_.:-]{1,128}$")
            || !"AUTHORITY_EVIDENCE_RECEIPT".equals(receipt.path("key_usage").asText())
            || !receipt.path("signature").asText().matches("^[A-Za-z0-9_-]{86}$")
            || !receipt.path("key_id").equals(receipt.path("event").path("key_id"))
            || !signedEvidenceEvent(receipt.path("event"), authority, canonical)) {
            return false;
        }
        JsonNode signedEvent = receipt.path("event");
        String expectedReference = "evidence://authority-event/"
            + receipt.path("tenant_id").asText() + "/" + receipt.path("task_id").asText()
            + "/" + receipt.path("authority_event_id").asText() + "/"
            + signedEvent.path("event_hash").asText();
        ObjectNode unsignedReceipt = ((ObjectNode) receipt).deepCopy();
        unsignedReceipt.put("evidence_digest", "");
        unsignedReceipt.put("signature", "");
        Instant occurredAt = Instant.parse(authority.path("event").path("occurred_at").asText());
        Instant persistedAt = Instant.parse(receipt.path("persisted_at").asText());
        Instant createdAt = Instant.parse(caseCreatedAt.asText());
        return expectedReference.equals(receipt.path("evidence_ref").asText())
            && canonical.digest(unsignedReceipt).equals(receipt.path("evidence_digest").asText())
            && !occurredAt.isAfter(createdAt.plusSeconds(30))
            && !occurredAt.isBefore(createdAt.minusSeconds(900))
            && !persistedAt.isBefore(occurredAt) && !persistedAt.isAfter(createdAt);
    }

    private static boolean signedEvidenceEvent(JsonNode event, JsonNode authority,
                                               CanonicalDigest canonical) {
        if (!exact(event, Set.of("schema_version", "event_id", "sequence", "previous_hash",
                "event_hash", "key_id", "signature", "draft"))
            || !"agenttrust.evidence.v1".equals(event.path("schema_version").asText())
            || !event.path("event_id").equals(authority.path("authority_event_id"))
            || !integer(event.path("sequence"), 1, Long.MAX_VALUE)
            || !digest(event.path("previous_hash")) || !digest(event.path("event_hash"))
            || !event.path("key_id").asText().matches("^[A-Za-z0-9_.:-]{1,128}$")
            || !event.path("signature").asText().matches("^[A-Za-z0-9_-]{86}$")
            || !event.path("draft").equals(authority.path("event"))) {
            return false;
        }
        ObjectNode unsignedEvent = ((ObjectNode) event).deepCopy();
        unsignedEvent.put("event_hash", "");
        unsignedEvent.put("signature", "");
        return canonical.digest(unsignedEvent).equals(event.path("event_hash").asText());
    }

    static boolean industrialApprovalResource(String resource, String environment) {
        if (resource == null || environment == null) {
            return false;
        }
        String normalized = resource.toLowerCase(java.util.Locale.ROOT);
        return Set.of("opcua:", "opc.tcp:", "mqtt:", "modbus:", "plc:", "scada:",
                "plant/", "urn:agenttrust:industrial:")
            .stream().anyMatch(normalized::startsWith)
            || Set.of("industrial", "physical-production").contains(environment);
    }

    static boolean safeReviewText(JsonNode value, int maximum) {
        if (!text(value, maximum)) {
            return false;
        }
        if (containsSecretMarker(value.textValue())) {
            return false;
        }
        return java.util.Arrays.stream(value.textValue().split("[^A-Za-z0-9_-]+"))
            .noneMatch(fragment -> fragment.length() >= 32
                && fragment.chars().anyMatch(Character::isAlphabetic)
                && fragment.chars().anyMatch(Character::isDigit));
    }

    private static boolean containsSecretMarker(String value) {
        String normalized = value.toLowerCase(java.util.Locale.ROOT);
        for (String marker : Set.of("authorization:", "bearer ", "password", "passwd",
            "client_secret", "api_key", "api-key", "apikey", "x-api-key", "private key",
            "-----begin", "cookie:", "set-cookie", "credential://", "vault-kv://",
            "secret://", "token=", "token:")) {
            if (normalized.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    /** Exact durable-command evidence binding returned by the orchestrator action ingress. */
    static boolean orchestratorEventReference(JsonNode value, UUID tenantId, UUID taskId) {
        if (!text(value, 2048) || tenantId == null || taskId == null) {
            return false;
        }
        var match = ORCHESTRATOR_EVENT.matcher(value.textValue());
        if (!match.matches() || !tenantId.toString().equals(match.group(1))
            || !taskId.toString().equals(match.group(2))) {
            return false;
        }
        try {
            return Long.parseLong(match.group(3)) > 0;
        } catch (NumberFormatException error) {
            return false;
        }
    }

    static boolean control(String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }
}
