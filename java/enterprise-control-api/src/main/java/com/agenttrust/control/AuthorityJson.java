package com.agenttrust.control;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.HashSet;
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
        return value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0
            || value.indexOf('\n') >= 0;
    }
}
