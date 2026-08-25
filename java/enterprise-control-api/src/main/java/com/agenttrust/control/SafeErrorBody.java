package com.agenttrust.control;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.regex.Pattern;

/** Public error shape that never contains exception, principal, policy, or authority details. */
@JsonPropertyOrder({"schema_version", "code", "trace_id", "occurred_at"})
record SafeErrorBody(
    @JsonProperty("schema_version") String schemaVersion,
    @JsonProperty("code") String code,
    @JsonProperty("trace_id") String traceId,
    @JsonProperty("occurred_at") String occurredAt
) {
    static final String SCHEMA_VERSION = "agenttrust.safe-error.v1";
    private static final Pattern SAFE_CODE = Pattern.compile("CONTROL_[A-Z0-9_]{3,120}");

    static boolean validCode(String code) {
        return code != null && SAFE_CODE.matcher(code).matches();
    }
}
