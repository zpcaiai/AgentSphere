package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.MarketplaceModels.MarketplaceCommandRequest;
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
import java.util.regex.Pattern;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Exact BFF for the 16 typed Pack Marketplace lifecycle commands. */
@Component
public final class PackMarketplaceGateway {
    static final String MUTATE_OPERATION_TOKEN = "packs.mutate";
    static final String MUTATE_SCOPE = "packs:mutate";
    static final String ACTION_PATH = "/v1/packs/actions";
    private static final String READ_AUTHORITY = "packs";
    private static final Pattern SEMVER = Pattern.compile(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$");
    private static final Set<String> KINDS = Set.of(
        "ONBOARD_PUBLISHER", "VERIFY_PUBLISHER_KEY", "SET_PUBLISHER_TRUST",
        "CONFIGURE_TENANT_CATALOG", "SUBMIT_RELEASE", "REVIEW_RELEASE",
        "REQUEST_INSTALLATION", "APPROVE_INSTALLATION", "INSTALL", "ACTIVATE",
        "PLAN_UPGRADE", "RECORD_CANARY", "UPGRADE", "ROLLBACK", "DEACTIVATE",
        "REVOKE_RELEASE");
    private static final Set<String> PAGE_FIELDS = Set.of(
        "schema_version", "authoritative", "tenant_id", "releases", "installations",
        "next_after_pack_id", "data_digest");
    private static final Set<String> RELEASE_FIELDS = Set.of(
        "release_id", "pack_id", "version", "pack_digest", "publisher_id", "visibility",
        "entitlement", "allowed_regions", "risk_rating", "compatibility",
        "certificate_digest", "review_status", "updated_at");
    private static final Set<String> INSTALLATION_FIELDS = Set.of(
        "installation_id", "release_id", "pack_id", "version", "environment", "state",
        "permission_expansion", "previous_installation_id", "updated_at");
    private static final Set<String> RECEIPT_FIELDS = Set.of(
        "schema_version", "action_id", "task_id", "accepted", "execution_pending",
        "ingress_digest", "ledger_evidence_ref", "ledger_evidence_digest");
    private static final Set<String> RISKS = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");
    private static final Set<String> ENVIRONMENTS = Set.of(
        "development", "staging", "canary", "production");

    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final AuthorityScopeTokenProvider tokens;
    private final HumanPrincipalAssertionSigner assertions;
    private final PepAuthorizationClient pep;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;

    public PackMarketplaceGateway(ControlProperties properties, SecureRestClientFactory clients,
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

    public JsonNode list(PrincipalContext principal, String query, String afterPackId, int limit) {
        requireLimit(limit);
        if (query != null && (query.length() > 128 || AuthorityJson.control(query))
            || afterPackId != null && !AuthorityJson.identifier(afterPackId, 128)) {
            throw new ControlDeniedException("CONTROL_PACK_QUERY_INVALID");
        }
        pep.authorizeQuery(principal, "LIST_PACK_MARKETPLACE", "packs:catalog");
        JsonNode value = get(principal, builder -> {
            var uri = builder.path("/v1/authoritative/packs").queryParam("limit", limit);
            if (query != null && !query.isBlank()) uri.queryParam("query", query);
            if (afterPackId != null) uri.queryParam("after_pack_id", afterPackId);
            return uri.build();
        });
        requirePage(value, principal.tenantId(), afterPackId, limit, canonical);
        return value;
    }

    public JsonNode submit(PrincipalContext principal, MarketplaceCommandRequest command,
                           String idempotencyKey) {
        requireCommand(principal, command, idempotencyKey, mapper);
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
            throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_UNAVAILABLE", error);
        }
        requireReceipt(receipt, command.commandId(), principal.tenantId());
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
            throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private RestClient authenticated(PrincipalContext principal, String token) {
        URI endpoint = properties.authorityEndpoints().get(READ_AUTHORITY);
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_UNCONFIGURED");
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
            throw new ControlDeniedException("CONTROL_PACK_AUTHORITY_REJECTED");
        }
        if (status == 409) throw new ConflictException("CONTROL_PACK_AUTHORITY_CONFLICT");
        if (status == 429) throw new CapacityException("CONTROL_PACK_AUTHORITY_CAPACITY");
        if (status != expectedStatus || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(response.getHeaders().getContentType())) {
            throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID");
        }
        byte[] bytes = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (bytes.length == 0 || bytes.length > properties.maximumAuthorityResponseBytes()) {
            throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID");
        }
        try {
            JsonNode value = mapper.readTree(bytes);
            if (value == null || !value.isObject()) {
                throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID");
            }
            return value;
        } catch (IOException error) {
            throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID", error);
        }
    }

    static void requirePage(JsonNode value, UUID tenantId, String afterPackId, int limit,
                            CanonicalDigest canonical) {
        if (!AuthorityJson.exact(value, PAGE_FIELDS)
            || !"agenttrust.authoritative-pack-page.v1".equals(
                value.path("schema_version").textValue())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !tenantId.toString().equals(value.path("tenant_id").textValue())
            || !value.path("releases").isArray() || value.path("releases").size() > limit
            || !value.path("installations").isArray()
            || value.path("installations").size() > limit
            || !(value.path("next_after_pack_id").isNull()
                || AuthorityJson.identifier(value.path("next_after_pack_id"), 128))
            || !AuthorityJson.digest(value.path("data_digest"))) {
            invalidResponse();
        }
        String previousPack = afterPackId;
        String previousVersion = null;
        for (JsonNode release : value.path("releases")) {
            requireRelease(release);
            String pack = release.path("pack_id").textValue();
            String version = release.path("version").textValue();
            if (previousPack != null && (pack.compareTo(previousPack) < 0
                || pack.equals(previousPack) && previousVersion != null
                    && version.compareTo(previousVersion) <= 0)) {
                invalidResponse();
            }
            if (!pack.equals(previousPack)) previousVersion = null;
            previousPack = pack;
            previousVersion = version;
        }
        Instant previousUpdate = null;
        for (JsonNode installation : value.path("installations")) {
            requireInstallation(installation);
            Instant updated = Instant.parse(installation.path("updated_at").textValue());
            if (previousUpdate != null && updated.isAfter(previousUpdate)) invalidResponse();
            previousUpdate = updated;
        }
        JsonNode next = value.path("next_after_pack_id");
        if (!next.isNull() && (value.path("releases").size() != limit || previousPack == null
            || !previousPack.equals(next.textValue()))) {
            invalidResponse();
        }
        ObjectNode material = value.deepCopy();
        String supplied = material.remove("data_digest").textValue();
        if (!supplied.equals(canonical.digest(material))) invalidResponse();
    }

    private static void requireRelease(JsonNode value) {
        if (!AuthorityJson.exact(value, RELEASE_FIELDS)
            || !AuthorityJson.uuid(value.path("release_id"))
            || !AuthorityJson.identifier(value.path("pack_id"), 128)
            || !semver(value.path("version")) || !AuthorityJson.digest(value.path("pack_digest"))
            || !AuthorityJson.identifier(value.path("publisher_id"), 128)
            || !Set.of("PRIVATE", "TENANT").contains(value.path("visibility").textValue())
            || !AuthorityJson.identifier(value.path("entitlement"), 128)
            || !AuthorityJson.stringSet(value.path("allowed_regions"), 1, 64, 128,
                item -> AuthorityJson.identifier(item, 128))
            || !RISKS.contains(value.path("risk_rating").textValue())
            || !AuthorityJson.stringSet(value.path("compatibility"), 1, 256, 2048)
            || !AuthorityJson.digest(value.path("certificate_digest"))
            || !Set.of("SUBMITTED", "PUBLISHED", "REJECTED", "REVOKED")
                .contains(value.path("review_status").textValue())
            || !AuthorityJson.instant(value.path("updated_at"))) {
            invalidResponse();
        }
    }

    private static void requireInstallation(JsonNode value) {
        if (!AuthorityJson.exact(value, INSTALLATION_FIELDS)
            || !AuthorityJson.uuid(value.path("installation_id"))
            || !AuthorityJson.uuid(value.path("release_id"))
            || !AuthorityJson.identifier(value.path("pack_id"), 128)
            || !semver(value.path("version"))
            || !ENVIRONMENTS.contains(value.path("environment").textValue())
            || !Set.of("PENDING_APPROVAL", "APPROVED", "REJECTED", "INSTALLED", "ACTIVE",
                "INACTIVE", "ROLLED_BACK", "REVOKED").contains(value.path("state").textValue())
            || !AuthorityJson.booleanValue(value.path("permission_expansion"))
            || !(value.path("previous_installation_id").isNull()
                || AuthorityJson.uuid(value.path("previous_installation_id")))
            || !AuthorityJson.instant(value.path("updated_at"))) {
            invalidResponse();
        }
    }

    static void requireReceipt(JsonNode value, UUID commandId, UUID tenantId) {
        UUID taskId = AuthorityJson.uuid(value == null ? null : value.path("task_id"))
            ? UUID.fromString(value.path("task_id").textValue()) : null;
        if (!AuthorityJson.exact(value, RECEIPT_FIELDS)
            || !"agenttrust.marketplace-action-receipt.v1".equals(
                value.path("schema_version").textValue())
            || !commandId.toString().equals(value.path("action_id").textValue())
            || taskId == null
            || !value.path("accepted").isBoolean() || !value.path("accepted").booleanValue()
            || !value.path("execution_pending").isBoolean()
            || !value.path("execution_pending").booleanValue()
            || !AuthorityJson.digest(value.path("ingress_digest"))
            || !AuthorityJson.orchestratorEventReference(
                value.path("ledger_evidence_ref"), tenantId, taskId)
            || !AuthorityJson.digest(value.path("ledger_evidence_digest"))) {
            throw new ControlUnavailableException("CONTROL_PACK_ACTION_RECEIPT_INVALID");
        }
    }

    static void requireCommand(PrincipalContext principal, MarketplaceCommandRequest request,
                               String idempotencyKey, ObjectMapper mapper) {
        Instant now = Instant.now();
        JsonNode command = request == null ? null : request.command();
        if (principal == null || request == null || idempotencyKey == null
            || !idempotencyKey.matches("[A-Za-z0-9._:/-]{16,128}")
            || !"agenttrust.marketplace-command.v1".equals(request.schemaVersion())
            || !principal.tenantId().equals(request.tenantId())
            || !AuthorityJson.uuid(request.commandId().toString())
            || !AuthorityJson.identifier(request.resourceId(), 256)
            || request.expectedResourceVersion() < 0 || command == null || !command.isObject()
            || !KINDS.contains(command.path("kind").textValue())
            || request.requestedAt() == null
            || request.requestedAt().isAfter(now.plus(Duration.ofMinutes(5)))
            || request.requestedAt().isBefore(now.minus(Duration.ofHours(24)))
            || !principal.strongAuth()
            || !principal.roles().contains(requiredRole(command.path("kind").textValue()))
            || !commandShape(request)) {
            throw new ControlDeniedException("CONTROL_PACK_COMMAND_INVALID");
        }
        try {
            if (mapper.writeValueAsBytes(request).length > 1_048_576) {
                throw new ControlDeniedException("CONTROL_PACK_COMMAND_INVALID");
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
            throw new ControlDeniedException("CONTROL_PACK_COMMAND_INVALID", error);
        }
    }

    private static boolean commandShape(MarketplaceCommandRequest request) {
        JsonNode value = request.command();
        String kind = value.path("kind").textValue();
        return switch (kind) {
            case "ONBOARD_PUBLISHER" -> exactAndResource(value, request, Set.of("kind",
                "publisher_id", "publisher_subject", "identity_digest", "responsibility_contact",
                "home_region"), "publisher_id")
                && AuthorityJson.identifier(value.path("publisher_id"), 128)
                && AuthorityJson.identifier(value.path("publisher_subject"), 256)
                && AuthorityJson.digest(value.path("identity_digest"))
                && email(value.path("responsibility_contact"))
                && AuthorityJson.identifier(value.path("home_region"), 128);
            case "VERIFY_PUBLISHER_KEY" -> validPublisherKey(value, request);
            case "SET_PUBLISHER_TRUST" -> exactAndResource(value, request,
                Set.of("kind", "publisher_id", "trust", "reason_digest"), "publisher_id")
                && AuthorityJson.identifier(value.path("publisher_id"), 128)
                && Set.of("SUSPENDED", "REVOKED").contains(value.path("trust").textValue())
                && AuthorityJson.digest(value.path("reason_digest"));
            case "CONFIGURE_TENANT_CATALOG" -> "tenant-catalog".equals(request.resourceId())
                && AuthorityJson.exact(value, Set.of("kind", "control_plane_version", "region",
                    "entitlements", "allowed_compatibility", "minimum_publisher_trust",
                    "maximum_risk"))
                && semver(value.path("control_plane_version"))
                && AuthorityJson.identifier(value.path("region"), 128)
                && AuthorityJson.stringSet(value.path("entitlements"), 1, 256, 256)
                && AuthorityJson.stringSet(value.path("allowed_compatibility"), 1, 256, 256)
                && "VERIFIED".equals(value.path("minimum_publisher_trust").textValue())
                && RISKS.contains(value.path("maximum_risk").textValue());
            case "SUBMIT_RELEASE" -> validSubmitRelease(value, request);
            case "REVIEW_RELEASE" -> exactUuidResource(value, request,
                Set.of("kind", "release_id", "decision", "review_digest"), "release_id")
                && Set.of("APPROVE", "REJECT").contains(value.path("decision").textValue())
                && AuthorityJson.digest(value.path("review_digest"));
            case "REQUEST_INSTALLATION" -> exactUuidResource(value, request,
                Set.of("kind", "installation_id", "release_id", "environment",
                    "request_reason_digest"), "installation_id")
                && AuthorityJson.uuid(value.path("release_id"))
                && ENVIRONMENTS.contains(value.path("environment").textValue())
                && AuthorityJson.digest(value.path("request_reason_digest"));
            case "APPROVE_INSTALLATION" -> exactUuidResource(value, request,
                Set.of("kind", "installation_id", "decision", "approval_digest"),
                "installation_id")
                && Set.of("APPROVE", "REJECT").contains(value.path("decision").textValue())
                && AuthorityJson.digest(value.path("approval_digest"));
            case "INSTALL" -> exactUuidResource(value, request,
                Set.of("kind", "installation_id", "artifact_receipt_digest"),
                "installation_id") && AuthorityJson.digest(value.path("artifact_receipt_digest"));
            case "ACTIVATE" -> exactUuidResource(value, request,
                Set.of("kind", "installation_id", "production_certificate_digest"),
                "installation_id")
                && AuthorityJson.digestOrNull(value.path("production_certificate_digest"));
            case "PLAN_UPGRADE" -> validPlanUpgrade(value, request);
            case "RECORD_CANARY" -> exactUuidResource(value, request,
                Set.of("kind", "plan_id", "passed", "observed_samples", "evidence_ref",
                    "evidence_digest"), "plan_id")
                && AuthorityJson.booleanValue(value.path("passed"))
                && AuthorityJson.integer(value.path("observed_samples"), 1, 10_000_000)
                && marketplaceEvidenceReference(value.path("evidence_ref"))
                && AuthorityJson.digest(value.path("evidence_digest"));
            case "UPGRADE" -> exactUuidResource(value, request,
                Set.of("kind", "plan_id", "production_certificate_digest"), "plan_id")
                && AuthorityJson.digestOrNull(value.path("production_certificate_digest"));
            case "ROLLBACK", "DEACTIVATE" -> exactUuidResource(value, request,
                Set.of("kind", "installation_id", "reason_digest"), "installation_id")
                && AuthorityJson.digest(value.path("reason_digest"));
            case "REVOKE_RELEASE" -> exactUuidResource(value, request,
                Set.of("kind", "release_id", "reason_code", "reason_digest",
                    "running_task_response"), "release_id")
                && AuthorityJson.identifier(value.path("reason_code"), 128)
                && AuthorityJson.digest(value.path("reason_digest"))
                && Set.of("PAUSE", "KILL", "ALLOW_TO_FINISH")
                    .contains(value.path("running_task_response").textValue());
            default -> false;
        };
    }

    private static boolean validPublisherKey(JsonNode value,
                                             MarketplaceCommandRequest request) {
        if (!exactAndResource(value, request, Set.of("kind", "publisher_id", "key_id",
            "algorithm", "public_key", "key_fingerprint", "not_before", "expires_at",
            "review_digest"), "publisher_id")
            || !AuthorityJson.identifier(value.path("publisher_id"), 128)
            || !AuthorityJson.identifier(value.path("key_id"), 128)
            || !"Ed25519".equals(value.path("algorithm").textValue())
            || !AuthorityJson.text(value.path("public_key"), 128)
            || !value.path("public_key").textValue().matches("[A-Za-z0-9_-]{43}")
            || !AuthorityJson.digest(value.path("key_fingerprint"))
            || !AuthorityJson.digest(value.path("review_digest"))
            || !AuthorityJson.instant(value.path("not_before"))
            || !AuthorityJson.instant(value.path("expires_at"))) {
            return false;
        }
        Instant start = Instant.parse(value.path("not_before").textValue());
        Instant end = Instant.parse(value.path("expires_at").textValue());
        return start.isBefore(end) && !end.isAfter(Instant.now().plus(Duration.ofDays(730)));
    }

    private static boolean validSubmitRelease(JsonNode value,
                                              MarketplaceCommandRequest request) {
        return exactUuidResource(value, request, Set.of("kind", "release_id", "manifest",
            "release_certificate", "visibility", "entitlement", "allowed_regions",
            "risk_rating", "minimum_publisher_trust", "minimum_control_plane_version"),
            "release_id")
            && validManifest(value.path("manifest"))
            && validReleaseCertificate(value.path("release_certificate"),
                value.path("manifest").path("digest").textValue())
            && Set.of("PRIVATE", "TENANT").contains(value.path("visibility").textValue())
            && AuthorityJson.identifier(value.path("entitlement"), 128)
            && AuthorityJson.stringSet(value.path("allowed_regions"), 1, 64, 128,
                item -> AuthorityJson.identifier(item, 128))
            && RISKS.contains(value.path("risk_rating").textValue())
            && "VERIFIED".equals(value.path("minimum_publisher_trust").textValue())
            && semver(value.path("minimum_control_plane_version"));
    }

    private static boolean validManifest(JsonNode value) {
        if (!AuthorityJson.exact(value, Set.of("schema_version", "pack_id", "version", "digest",
            "publisher_identity", "description", "permissions", "tools", "policy_bundle_ref",
            "evaluator_ref", "compensation_refs", "threat_scenario_refs", "artifact_refs",
            "compatibility", "signature"))
            || !"agenttrust.domain-pack.v1".equals(value.path("schema_version").textValue())
            || !AuthorityJson.identifier(value.path("pack_id"), 128)
            || !semver(value.path("version")) || !AuthorityJson.digest(value.path("digest"))
            || !AuthorityJson.identifier(value.path("publisher_identity"), 128)
            || !AuthorityJson.text(value.path("description"), 4096)
            || !AuthorityJson.text(value.path("policy_bundle_ref"), 2048)
            || !AuthorityJson.text(value.path("evaluator_ref"), 2048)
            || !AuthorityJson.stringSet(value.path("compensation_refs"), 0, 256, 2048)
            || !AuthorityJson.stringSet(value.path("threat_scenario_refs"), 1, 256, 2048)
            || !AuthorityJson.stringSet(value.path("artifact_refs"), 1, 256, 2048,
                item -> item.matches("^(?!.*:latest$).{1,1980}sha256:[a-f0-9]{64}$"))
            || !AuthorityJson.stringSet(value.path("compatibility"), 1, 256, 2048)
            || !validPermissions(value.path("permissions"))
            || !value.path("tools").isArray() || value.path("tools").isEmpty()
            || value.path("tools").size() > 256
            || !validPublisherSignature(value.path("signature"), value)) {
            return false;
        }
        Set<String> tools = new HashSet<>();
        for (JsonNode tool : value.path("tools")) {
            if (!AuthorityJson.exact(tool, Set.of("tool_id", "effect_class", "approval_required",
                "compensation_ref", "irreversible_reason", "executor_template"))
                || !AuthorityJson.text(tool.path("tool_id"), 256)
                || !Set.of("PURE", "IDEMPOTENT", "COMPENSATABLE", "IRREVERSIBLE")
                    .contains(tool.path("effect_class").textValue())
                || !AuthorityJson.booleanValue(tool.path("approval_required"))
                || !AuthorityJson.nullableText(tool.path("compensation_ref"), 2048)
                || !AuthorityJson.nullableText(tool.path("irreversible_reason"), 2048)
                || !AuthorityJson.text(tool.path("executor_template"), 2048)
                || tool.path("executor_template").textValue().matches(".*(/bin/sh|bash -c).*")
                || !validToolSafety(tool) || !tools.add(tool.path("tool_id").textValue())) {
                return false;
            }
        }
        return true;
    }

    private static boolean validToolSafety(JsonNode tool) {
        String effect = tool.path("effect_class").textValue();
        return switch (effect) {
            case "PURE", "IDEMPOTENT" -> tool.path("compensation_ref").isNull()
                && tool.path("irreversible_reason").isNull();
            case "COMPENSATABLE" -> AuthorityJson.text(tool.path("compensation_ref"), 2048)
                && tool.path("irreversible_reason").isNull();
            case "IRREVERSIBLE" -> tool.path("compensation_ref").isNull()
                && AuthorityJson.text(tool.path("irreversible_reason"), 2048)
                && tool.path("approval_required").booleanValue();
            default -> false;
        };
    }

    private static boolean validPermissions(JsonNode value) {
        if (!AuthorityJson.exact(value, Set.of("tools", "network_destinations", "data_classes",
            "secret_scopes", "executors", "approval_scopes"))) return false;
        for (String field : Set.of("tools", "network_destinations", "data_classes",
            "secret_scopes", "executors", "approval_scopes")) {
            if (!AuthorityJson.stringSet(value.path(field), 0, 256, 2048)) return false;
        }
        return true;
    }

    private static boolean validPublisherSignature(JsonNode signature, JsonNode manifest) {
        return AuthorityJson.exact(signature, Set.of("key_id", "publisher_identity",
            "subject_digest", "signature", "signed_at"))
            && AuthorityJson.identifier(signature.path("key_id"), 128)
            && manifest.path("publisher_identity").textValue()
                .equals(signature.path("publisher_identity").textValue())
            && manifest.path("digest").textValue().equals(signature.path("subject_digest").textValue())
            && signature.path("signature").isTextual()
            && signature.path("signature").textValue().matches("[A-Za-z0-9_-]{86}")
            && AuthorityJson.instant(signature.path("signed_at"));
    }

    private static boolean validReleaseCertificate(JsonNode value, String releaseDigest) {
        if (!AuthorityJson.exact(value, Set.of("schema_version", "certificate_id",
            "release_digest", "gate_id", "gate_version", "definition_digest",
            "evidence_digests", "valid_from", "valid_until", "engine_certificate_only",
            "production_closure", "key_id", "signature"))
            || !"agenttrust.incident-release.v1".equals(value.path("schema_version").textValue())
            || !AuthorityJson.uuid(value.path("certificate_id"))
            || !releaseDigest.equals(value.path("release_digest").textValue())
            || !AuthorityJson.identifier(value.path("gate_id"), 256)
            || !AuthorityJson.text(value.path("gate_version"), 128)
            || !AuthorityJson.digest(value.path("definition_digest"))
            || !value.path("evidence_digests").isObject()
            || value.path("evidence_digests").isEmpty()
            || value.path("evidence_digests").size() > 256
            || !AuthorityJson.instant(value.path("valid_from"))
            || !AuthorityJson.instant(value.path("valid_until"))
            || !value.path("engine_certificate_only").isBoolean()
            || !value.path("engine_certificate_only").booleanValue()
            || !value.path("production_closure").isBoolean()
            || value.path("production_closure").booleanValue()
            || !AuthorityJson.identifier(value.path("key_id"), 256)
            || !value.path("signature").isTextual()
            || !value.path("signature").textValue().matches("[A-Za-z0-9_-]{86}")) {
            return false;
        }
        var fields = value.path("evidence_digests").properties().iterator();
        Set<String> controls = new HashSet<>();
        while (fields.hasNext()) {
            var field = fields.next();
            if (!AuthorityJson.identifier(field.getKey(), 128) || !AuthorityJson.digest(field.getValue())
                || !controls.add(field.getKey())) return false;
        }
        return Instant.parse(value.path("valid_from").textValue())
            .isBefore(Instant.parse(value.path("valid_until").textValue()));
    }

    private static boolean validPlanUpgrade(JsonNode value, MarketplaceCommandRequest request) {
        return exactUuidResource(value, request, Set.of("kind", "plan_id",
            "current_installation_id", "target_installation_id", "migration_digest",
            "rollback_digest", "canary_percent"), "plan_id")
            && AuthorityJson.uuid(value.path("current_installation_id"))
            && AuthorityJson.uuid(value.path("target_installation_id"))
            && !value.path("current_installation_id").textValue()
                .equals(value.path("target_installation_id").textValue())
            && AuthorityJson.digest(value.path("migration_digest"))
            && AuthorityJson.digest(value.path("rollback_digest"))
            && AuthorityJson.integer(value.path("canary_percent"), 1, 50);
    }

    private static boolean exactAndResource(JsonNode value, MarketplaceCommandRequest request,
                                            Set<String> fields, String resourceField) {
        return AuthorityJson.exact(value, fields)
            && request.resourceId().equals(value.path(resourceField).textValue());
    }

    private static boolean exactUuidResource(JsonNode value, MarketplaceCommandRequest request,
                                             Set<String> fields, String resourceField) {
        return exactAndResource(value, request, fields, resourceField)
            && AuthorityJson.uuid(value.path(resourceField));
    }

    private static String requiredRole(String kind) {
        return switch (kind) {
            case "ONBOARD_PUBLISHER", "SET_PUBLISHER_TRUST" -> "marketplace-publisher-admin";
            case "VERIFY_PUBLISHER_KEY" -> "marketplace-publisher-reviewer";
            case "CONFIGURE_TENANT_CATALOG" -> "marketplace-admin";
            case "SUBMIT_RELEASE" -> "marketplace-publisher";
            case "REVIEW_RELEASE" -> "marketplace-release-reviewer";
            case "REQUEST_INSTALLATION", "INSTALL" -> "marketplace-installer";
            case "APPROVE_INSTALLATION" -> "marketplace-install-reviewer";
            case "RECORD_CANARY" -> "marketplace-canary-controller";
            case "REVOKE_RELEASE" -> "marketplace-security-admin";
            default -> "marketplace-operator";
        };
    }

    private void requireLimit(int limit) {
        if (limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_PACK_QUERY_INVALID");
        }
    }

    private static boolean semver(JsonNode value) {
        return value != null && value.isTextual() && SEMVER.matcher(value.textValue()).matches();
    }

    private static boolean email(JsonNode value) {
        return AuthorityJson.text(value, 320)
            && value.textValue().matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");
    }

    private static boolean marketplaceEvidenceReference(JsonNode value) {
        return AuthorityJson.text(value, 2048) && value.textValue().startsWith("urn:agenttrust:")
            && !value.textValue().matches(".*[\\s?#].*");
    }

    private static void invalidResponse() {
        throw new ControlUnavailableException("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID");
    }
}
