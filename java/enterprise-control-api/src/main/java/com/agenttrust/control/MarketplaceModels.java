package com.agenttrust.control;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import java.time.Instant;
import java.util.UUID;

public final class MarketplaceModels {
    private MarketplaceModels() {}

    /** Strict wrapper around one typed Pack Marketplace lifecycle command. */
    public record MarketplaceCommandRequest(
        @JsonProperty("schema_version")
        @NotBlank @Pattern(regexp = "^agenttrust\\.marketplace-command\\.v1$") String schemaVersion,
        @NotNull UUID tenantId,
        @NotNull UUID commandId,
        @NotBlank @Pattern(regexp = "^[A-Za-z0-9._:/-]{1,256}$") String resourceId,
        @PositiveOrZero long expectedResourceVersion,
        @NotNull JsonNode command,
        @NotNull Instant requestedAt) {}
}
