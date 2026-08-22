package com.agenttrust.control;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import java.time.Instant;
import java.util.UUID;

public final class IncidentModels {
    private IncidentModels() {}

    /** Browser-to-Incident Authority governance command; DETECT remains machine-only. */
    public record IncidentCommandRequest(
        @JsonProperty("schema_version")
        @NotBlank @Pattern(regexp = "^agenttrust\\.incident-command\\.v1$") String schemaVersion,
        @NotNull UUID tenantId,
        @NotNull UUID commandId,
        @NotBlank @Pattern(regexp = "^(incident:[0-9a-f-]{36}|release:[A-Za-z0-9][A-Za-z0-9._:/-]*)$")
        String resourceId,
        @NotNull UUID taskId,
        @NotBlank @Pattern(regexp = "^(TRIAGE|CONTAIN|INVESTIGATE|PRESERVE_EVIDENCE|"
            + "PLAN_REPLAY|COMPLETE_REPLAY|PUBLISH_ROOT_CAUSE|BEGIN_REMEDIATION|"
            + "TRIGGER_RECERTIFICATION|EVALUATE_RELEASE|START_CANARY|RECORD_CANARY|"
            + "ROLLBACK_RELEASE|CLOSE)$") String operation,
        @PositiveOrZero long expectedResourceVersion,
        @NotNull Instant requestedAt,
        @NotNull JsonNode payload) {}
}
