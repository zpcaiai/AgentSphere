package com.agenttrust.control;

import com.agenttrust.control.AdminModels.PolicyCommandRequest;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Exact, tenant-bound Policy Administration BFF. Lifecycle commands are forwarded only to the
 * Canonical Action ingress; this component has no Policy database or executor capability.
 */
@Component
public final class PolicyAuthorityGateway {
    static final String MUTATE_OPERATION_TOKEN = "policies.mutate";
    static final String MUTATE_SCOPE = "policy:mutate";
    static final String ACTION_PATH = "/v1/policies/actions";
    private static final String READ_AUTHORITY = "policies";
    private static final Pattern POLICY_ID = Pattern.compile("^[A-Za-z0-9._:/-]{1,256}$");
    private static final Pattern IDENTIFIER = Pattern.compile("^[A-Za-z0-9._:/@-]{1,256}$");
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");
    private static final Pattern IDEMPOTENCY = Pattern.compile("^[A-Za-z0-9._:-]{16,128}$");
    private static final Set<String> OPERATIONS = Set.of(
        "CREATE_DRAFT", "VALIDATE", "SIMULATE", "SHADOW_EVALUATE", "IMPACT_ANALYZE",
        "APPROVE", "SIGN", "PROMOTE", "ROLLBACK", "DEPRECATE", "CREATE_EXCEPTION",
        "REVOKE_EXCEPTION");
    private static final Set<String> POLICY_PAGE_FIELDS = Set.of(
        "schema_version", "tenant_id", "items", "next_after_policy_id");
    private static final Set<String> POLICY_FIELDS = Set.of(
        "policy_id", "revision", "lifecycle_state", "source_digest", "author_subject",
        "active_bundle_digest", "active_environment", "resource_version", "updated_at");
    private static final Set<String> ARTIFACT_PAGE_FIELDS = Set.of(
        "schema_version", "tenant_id", "policy_id", "artifact_type", "items");
    private static final Set<String> SOURCE_FIELDS = Set.of(
        "schema_version", "source_id", "tenant_id", "version", "rules", "default_decision",
        "author", "source_digest", "created_at");
    private static final Set<String> RULE_FIELDS = Set.of(
        "rule_id", "subject_pattern", "tool_pattern", "resource_pattern", "decision",
        "maximum_risk", "reason_code");
    private static final Set<String> ANALYSIS_FIELDS = Set.of(
        "schema_version", "policy_id", "revision", "source_digest", "valid", "findings",
        "analyzed_at");
    private static final Set<String> FINDING_FIELDS = Set.of(
        "code", "rule_ids", "blocking");
    private static final Set<String> REVIEW_FIELDS = Set.of(
        "review_id", "revision", "reviewer_subject", "decision", "review_digest",
        "reviewed_at");
    private static final Set<String> SIMULATION_FIELDS = Set.of(
        "simulation_id", "revision", "run_kind", "baseline_bundle_digest",
        "candidate_source_digest", "corpus_digest", "evaluated_actions", "difference_count",
        "side_effect_count", "impact_report_digest", "impact_report", "run_by", "created_at");
    private static final Set<String> SIMULATION_REPORT_FIELDS = Set.of(
        "schema_version", "old_bundle_digest", "new_bundle_digest", "evaluated_actions",
        "differences", "side_effect_count", "generated_at");
    private static final Set<String> DIFFERENCE_FIELDS = Set.of(
        "action_id", "agent_id", "tool", "resource", "risk", "old_decision",
        "new_decision");
    private static final Set<String> IMPACT_FIELDS = Set.of(
        "schema_version", "impact_report_id", "tenant_id", "policy_id", "revision",
        "simulation_id", "simulation_digest", "evaluated_actions", "difference_count",
        "affected_agents", "affected_tools", "affected_resources", "maximum_risk",
        "generated_at", "impact_report_digest");
    private static final Set<String> PROMOTION_FIELDS = Set.of(
        "environment", "sequence", "bundle_digest", "previous_bundle_digest", "rollback_of",
        "promoted_by", "state", "promotion_digest", "promoted_at", "completed_at");
    private static final Set<String> EXCEPTION_FIELDS = Set.of(
        "exception_id", "policy_id", "scope_digest", "owner_subject", "approval_ids",
        "reason_digest", "compensating_controls", "issued_by", "expires_at", "revoked_at",
        "expired_at", "state", "created_at");
    private static final Set<String> RECEIPT_FIELDS = Set.of(
        "schema_version", "action_id", "task_id", "accepted", "execution_pending",
        "ingress_digest", "ledger_evidence_ref", "ledger_evidence_digest");
    private static final Set<String> SOURCE_DECISIONS = Set.of(
        "DENY", "KILL", "PAUSE", "REQUIRE_APPROVAL");
    private static final Set<String> RULE_DECISIONS = Set.of(
        "ALLOW", "DENY", "KILL", "PAUSE", "REQUIRE_APPROVAL");
    private static final Set<String> RISKS = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");
    private static final Set<String> ENVIRONMENTS = Set.of("DEV", "STAGING", "CANARY", "PRODUCTION");
    private static final Set<String> LIFECYCLE_STATES = Set.of(
        "DRAFT", "VALIDATED", "REVIEW", "SIGNED", "DEPRECATED");

    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final AuthorityScopeTokenProvider tokens;
    private final HumanPrincipalAssertionSigner assertions;
    private final PepAuthorizationClient pep;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;

    public PolicyAuthorityGateway(ControlProperties properties, SecureRestClientFactory clients,
                                  AuthorityScopeTokenProvider tokens,
                                  HumanPrincipalAssertionSigner assertions,
                                  PepAuthorizationClient pep,
                                  CanonicalDigest canonical, ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.tokens = tokens;
        this.assertions = assertions;
        this.pep = pep;
        this.canonical = canonical;
        this.mapper = mapper;
    }

    public JsonNode listPolicies(PrincipalContext principal, String afterPolicyId, int limit) {
        requireLimit(limit);
        if (afterPolicyId != null && !POLICY_ID.matcher(afterPolicyId).matches()) {
            throw new ControlDeniedException("CONTROL_POLICY_QUERY_INVALID");
        }
        pep.authorizeQuery(principal, "LIST_POLICIES", "policies:inventory");
        JsonNode page = get(principal, builder -> {
            var uri = builder.path("/v1/authoritative/policies").queryParam("limit", limit);
            if (afterPolicyId != null) {
                uri.queryParam("after_policy_id", afterPolicyId);
            }
            return uri.build();
        });
        requirePolicyPage(page, principal.tenantId(), afterPolicyId, limit);
        return page;
    }

    public JsonNode listArtifacts(PrincipalContext principal, String policyId,
                                  ArtifactType artifactType, int limit) {
        requirePolicyId(policyId);
        requireLimit(limit);
        if (artifactType == null) {
            throw new ControlDeniedException("CONTROL_POLICY_QUERY_INVALID");
        }
        pep.authorizeQuery(principal, "READ_POLICY_ARTIFACTS", "policy:" + policyId);
        JsonNode page = get(principal, builder -> builder
            .path("/v1/authoritative/policies/{policyId}/{artifactPath}")
            .queryParam("limit", limit).build(policyId, artifactType.path()));
        requireArtifactPage(page, principal.tenantId(), policyId, artifactType, limit, canonical);
        return page;
    }

    public JsonNode submitAction(PrincipalContext principal, PolicyCommandRequest command,
                                 String idempotencyKey) {
        requireCommand(principal, command, idempotencyKey, mapper);
        HumanPrincipalAssertionSigner.SignedHeader signed = assertions.sign(
            principal, "POST", ACTION_PATH, MUTATE_SCOPE, idempotencyKey, command, true);
        RestClient client = authenticated(principal, tokens.operationToken(MUTATE_OPERATION_TOKEN));
        JsonNode receipt;
        try {
            receipt = client.post().uri(ACTION_PATH).contentType(MediaType.APPLICATION_JSON)
                .header("Idempotency-Key", idempotencyKey)
                .header("X-AgentTrust-Human-Assertion", signed.headerValue())
                .body(command).exchange((ignored, response) -> decode(response, 202));
        } catch (ControlDeniedException | ConflictException | CapacityException
                 | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_UNAVAILABLE", error);
        }
        requireActionReceipt(receipt, command.commandId(), principal.tenantId());
        return receipt;
    }

    private JsonNode get(PrincipalContext principal,
                         java.util.function.Function<org.springframework.web.util.UriBuilder,
                         URI> uri) {
        try {
            return authenticated(principal, tokens.readToken(READ_AUTHORITY))
                .get().uri(uri).exchange((ignored, response) -> decode(response, 200));
        } catch (ControlDeniedException | ControlUnavailableException error) {
            throw error;
        } catch (RuntimeException error) {
            throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_UNAVAILABLE", error);
        }
    }

    private RestClient authenticated(PrincipalContext principal, String token) {
        URI endpoint = properties.authorityEndpoints().get(READ_AUTHORITY);
        if (endpoint == null) {
            throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_UNCONFIGURED");
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
            throw new ControlDeniedException("CONTROL_POLICY_AUTHORITY_REJECTED");
        }
        if (status == 409) {
            throw new ConflictException("CONTROL_POLICY_AUTHORITY_CONFLICT");
        }
        if (status == 429) {
            throw new CapacityException("CONTROL_POLICY_AUTHORITY_CAPACITY");
        }
        if (status != expectedStatus
            || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(response.getHeaders().getContentType())) {
            throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID");
        }
        byte[] bytes = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (bytes.length == 0 || bytes.length > properties.maximumAuthorityResponseBytes()) {
            throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID");
        }
        try {
            JsonNode value = mapper.readTree(bytes);
            if (value == null || !value.isObject()) {
                throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID");
            }
            return value;
        } catch (IOException error) {
            throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID", error);
        }
    }

    static void requirePolicyPage(JsonNode value, UUID tenantId, String afterPolicyId, int limit) {
        if (!exact(value, POLICY_PAGE_FIELDS)
            || !"agenttrust.authoritative-policy-page.v1".equals(text(value, "schema_version", 128))
            || !tenantId.toString().equals(text(value, "tenant_id", 36))
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !(value.path("next_after_policy_id").isNull()
                || policyId(value.path("next_after_policy_id").textValue()))) {
            invalidPage();
        }
        String previous = afterPolicyId;
        for (JsonNode item : value.path("items")) {
            if (!exact(item, POLICY_FIELDS)) {
                invalidPage();
            }
            String current = text(item, "policy_id", 256);
            if (!policyId(current) || previous != null && current.compareTo(previous) <= 0
                || !positive(item.path("revision"), Long.MAX_VALUE)
                || !LIFECYCLE_STATES.contains(text(item, "lifecycle_state", 32))
                || !digest(item.path("source_digest"))
                || !identifier(text(item, "author_subject", 256))
                || !(item.path("active_bundle_digest").isNull()
                    || digest(item.path("active_bundle_digest")))
                || !(item.path("active_environment").isNull()
                    || ENVIRONMENTS.contains(item.path("active_environment").textValue()))
                || !positive(item.path("resource_version"), Long.MAX_VALUE)
                || !dateTime(item.path("updated_at"))) {
                invalidPage();
            }
            previous = current;
        }
        JsonNode next = value.path("next_after_policy_id");
        if (!next.isNull() && (value.path("items").size() != limit
            || previous == null || !previous.equals(next.textValue()))) {
            invalidPage();
        }
    }

    static void requireArtifactPage(JsonNode value, UUID tenantId, String policyId,
                                    ArtifactType kind, int limit, CanonicalDigest canonical) {
        if (!exact(value, ARTIFACT_PAGE_FIELDS)
            || !"agenttrust.authoritative-policy-artifact-page.v1".equals(
                text(value, "schema_version", 128))
            || !tenantId.toString().equals(text(value, "tenant_id", 36))
            || !policyId.equals(text(value, "policy_id", 256))
            || !kind.wireName().equals(text(value, "artifact_type", 32))
            || !value.path("items").isArray() || value.path("items").size() > limit) {
            invalidPage();
        }
        for (JsonNode item : value.path("items")) {
            switch (kind) {
                case SOURCES -> requireSource(item, tenantId, policyId, canonical);
                case ANALYSES -> requireAnalysis(item, policyId);
                case REVIEWS -> requireReview(item);
                case SIMULATIONS -> requireSimulation(item, canonical);
                case IMPACT_REPORTS -> requireImpact(item, tenantId, policyId, canonical);
                case PROMOTIONS -> requirePromotion(item, tenantId, policyId, canonical);
                case EXCEPTIONS -> requireException(item, policyId);
            }
        }
    }

    static void requireActionReceipt(JsonNode value, UUID commandId, UUID tenantId) {
        UUID taskId = AuthorityJson.uuid(value == null ? null : value.path("task_id"))
            ? UUID.fromString(value.path("task_id").textValue()) : null;
        if (!exact(value, RECEIPT_FIELDS)
            || !"agenttrust.policy-action-receipt.v1".equals(text(value, "schema_version", 128))
            || !commandId.toString().equals(text(value, "action_id", 36))
            || taskId == null
            || !value.path("accepted").isBoolean() || !value.path("accepted").booleanValue()
            || !value.path("execution_pending").isBoolean()
            || !value.path("execution_pending").booleanValue()
            || !digest(value.path("ingress_digest"))
            || !AuthorityJson.orchestratorEventReference(
                value.path("ledger_evidence_ref"), tenantId, taskId)
            || !digest(value.path("ledger_evidence_digest"))) {
            throw new ControlUnavailableException("CONTROL_POLICY_ACTION_RECEIPT_INVALID");
        }
    }

    static void requireCommand(PrincipalContext principal, PolicyCommandRequest command,
                               String key, ObjectMapper mapper) {
        if (principal == null || command == null || !IDEMPOTENCY.matcher(key == null ? "" : key).matches()
            || !"agenttrust.policy-command.v1".equals(command.schemaVersion())
            || !principal.tenantId().equals(command.tenantId())
            || command.commandId().getMostSignificantBits() == 0L
                && command.commandId().getLeastSignificantBits() == 0L
            || !policyId(command.policyId()) || !OPERATIONS.contains(command.operation())
            || command.expectedResourceVersion() < 0 || command.payload() == null
            || !command.payload().isObject() || command.requestedAt() == null
            || command.requestedAt().isAfter(Instant.now().plus(Duration.ofMinutes(5)))
            || command.requestedAt().isBefore(Instant.now().minus(Duration.ofHours(24)))
            || !principal.strongAuth() || !principal.roles().contains(requiredRole(command.operation()))
            || !payloadShape(command, principal, new CanonicalDigest(mapper))) {
            throw new ControlDeniedException("CONTROL_POLICY_COMMAND_INVALID");
        }
        try {
            if (mapper.writeValueAsBytes(command).length > 1_048_576) {
                throw new ControlDeniedException("CONTROL_POLICY_COMMAND_INVALID");
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
            throw new ControlDeniedException("CONTROL_POLICY_COMMAND_INVALID", error);
        }
    }

    private static boolean payloadShape(PolicyCommandRequest command, PrincipalContext principal,
                                        CanonicalDigest canonical) {
        JsonNode payload = command.payload();
        return switch (command.operation()) {
            case "CREATE_DRAFT" -> exact(payload, Set.of("source"))
                && validSourceForCommand(payload.path("source"), command, principal, canonical);
            case "VALIDATE", "SIGN" -> payload.isEmpty();
            case "SIMULATE", "SHADOW_EVALUATE" -> exact(payload,
                Set.of("baseline_bundle_digest", "actions"))
                && digest(payload.path("baseline_bundle_digest"))
                && policyActions(payload.path("actions"), command.tenantId());
            case "IMPACT_ANALYZE" -> exact(payload, Set.of("simulation_id"))
                && canonicalUuid(payload.path("simulation_id").textValue());
            case "APPROVE" -> exact(payload, Set.of("decision", "review_digest"))
                && "APPROVE".equals(payload.path("decision").textValue())
                && digest(payload.path("review_digest"));
            case "PROMOTE" -> exact(payload,
                Set.of("bundle_digest", "impact_report_digest", "environment"))
                && digest(payload.path("bundle_digest"))
                && digest(payload.path("impact_report_digest"))
                && ENVIRONMENTS.contains(payload.path("environment").textValue());
            case "ROLLBACK" -> exact(payload,
                Set.of("target_bundle_digest", "reason_digest", "environment"))
                && digest(payload.path("target_bundle_digest"))
                && digest(payload.path("reason_digest"))
                && ENVIRONMENTS.contains(payload.path("environment").textValue());
            case "DEPRECATE" -> exact(payload, Set.of("bundle_digest", "reason_digest"))
                && digest(payload.path("bundle_digest")) && digest(payload.path("reason_digest"));
            case "CREATE_EXCEPTION" -> validCreateException(payload, principal);
            case "REVOKE_EXCEPTION" -> exact(payload, Set.of("exception_id", "reason_digest"))
                && canonicalUuid(payload.path("exception_id").textValue())
                && digest(payload.path("reason_digest"));
            default -> false;
        };
    }

    private static boolean validSourceForCommand(JsonNode source, PolicyCommandRequest command,
                                                 PrincipalContext principal,
                                                 CanonicalDigest canonical) {
        if (!(exact(source, SOURCE_FIELDS)
            && "agenttrust.policy-admin.v1".equals(source.path("schema_version").textValue())
            && command.policyId().equals(source.path("source_id").textValue())
            && command.tenantId().toString().equals(source.path("tenant_id").textValue())
            && principal.subject().equals(source.path("author").textValue())
            && textValue(source.path("version"), 128) && digest(source.path("source_digest"))
            && SOURCE_DECISIONS.contains(source.path("default_decision").textValue())
            && dateTime(source.path("created_at")) && rules(source.path("rules")))) {
            return false;
        }
        ObjectNode digestInput = source.deepCopy();
        String supplied = digestInput.path("source_digest").textValue();
        digestInput.put("source_digest", "");
        return supplied.equals(canonical.digest(digestInput));
    }

    private static boolean policyActions(JsonNode value, UUID tenantId) {
        if (!value.isArray() || value.isEmpty() || value.size() > 10_000) {
            return false;
        }
        for (JsonNode action : value) {
            if (!exact(action, Set.of("action_id", "tenant_id", "agent_id", "subject", "tool",
                "resource", "risk"))
                || !textValue(action.path("action_id"), 256)
                || !tenantId.toString().equals(action.path("tenant_id").textValue())
                || !textValue(action.path("agent_id"), 256)
                || !textValue(action.path("subject"), 1024)
                || !textValue(action.path("tool"), 1024)
                || !textValue(action.path("resource"), 2048)
                || !RISKS.contains(action.path("risk").textValue())) {
                return false;
            }
        }
        return true;
    }

    private static boolean validCreateException(JsonNode payload, PrincipalContext principal) {
        if (!exact(payload, Set.of("exception_id", "owner_subject", "scope", "reason_digest",
            "compensating_controls", "approval_ids", "expires_at"))
            || !canonicalUuid(payload.path("exception_id").textValue())
            || !identifier(payload.path("owner_subject").textValue())
            || principal.subject().equals(payload.path("owner_subject").textValue())
            || !stringSet(payload.path("scope"), 1, 128, 2048)
            || !digest(payload.path("reason_digest"))
            || !stringSet(payload.path("compensating_controls"), 1, 64, 256)
            || !stringSet(payload.path("approval_ids"), 2, 64, 256)
            || !dateTime(payload.path("expires_at"))) {
            return false;
        }
        Set<String> approvals = new HashSet<>();
        payload.path("approval_ids").forEach(item -> approvals.add(item.textValue()));
        Instant expiry = Instant.parse(payload.path("expires_at").textValue());
        return principal.approvalIds().containsAll(approvals) && expiry.isAfter(Instant.now())
            && expiry.isBefore(Instant.now().plus(Duration.ofDays(30)).plusSeconds(1));
    }

    private static String requiredRole(String operation) {
        return switch (operation) {
            case "CREATE_DRAFT", "VALIDATE", "SIMULATE", "SHADOW_EVALUATE", "IMPACT_ANALYZE"
                -> "policy-author";
            case "APPROVE" -> "policy-reviewer";
            default -> "policy-admin";
        };
    }

    private static void requireSource(JsonNode value, UUID tenantId, String policyId,
                                      CanonicalDigest canonical) {
        if (!exact(value, SOURCE_FIELDS)
            || !"agenttrust.policy-admin.v1".equals(value.path("schema_version").textValue())
            || !policyId.equals(value.path("source_id").textValue())
            || !tenantId.toString().equals(value.path("tenant_id").textValue())
            || !textValue(value.path("version"), 128) || !rules(value.path("rules"))
            || !SOURCE_DECISIONS.contains(value.path("default_decision").textValue())
            || !identifier(value.path("author").textValue()) || !digest(value.path("source_digest"))
            || !dateTime(value.path("created_at"))) {
            invalidPage();
        }
        ObjectNode digestInput = value.deepCopy();
        String supplied = digestInput.path("source_digest").textValue();
        digestInput.put("source_digest", "");
        if (!supplied.equals(canonical.digest(digestInput))) {
            invalidPage();
        }
    }

    private static boolean rules(JsonNode value) {
        if (!value.isArray() || value.isEmpty() || value.size() > 10_000) {
            return false;
        }
        for (JsonNode rule : value) {
            if (!exact(rule, RULE_FIELDS) || !textValue(rule.path("rule_id"), 256)
                || !textValue(rule.path("subject_pattern"), 1024)
                || !textValue(rule.path("tool_pattern"), 1024)
                || !textValue(rule.path("resource_pattern"), 2048)
                || !RULE_DECISIONS.contains(rule.path("decision").textValue())
                || !RISKS.contains(rule.path("maximum_risk").textValue())
                || !rule.path("reason_code").isTextual()
                || !rule.path("reason_code").textValue().matches("[A-Z][A-Z0-9_]{2,127}")) {
                return false;
            }
        }
        return true;
    }

    private static void requireAnalysis(JsonNode value, String policyId) {
        if (!exact(value, ANALYSIS_FIELDS)
            || !"agenttrust.policy-static-analysis.v1".equals(value.path("schema_version").textValue())
            || !policyId.equals(value.path("policy_id").textValue())
            || !positive(value.path("revision"), Long.MAX_VALUE)
            || !digest(value.path("source_digest")) || !value.path("valid").isBoolean()
            || !value.path("findings").isArray() || value.path("findings").size() > 20_000
            || !dateTime(value.path("analyzed_at"))) {
            invalidPage();
        }
        boolean blocking = false;
        for (JsonNode finding : value.path("findings")) {
            if (!exact(finding, FINDING_FIELDS) || !textValue(finding.path("code"), 128)
                || !stringSet(finding.path("rule_ids"), 0, 10_000, 256)
                || !finding.path("blocking").isBoolean()) {
                invalidPage();
            }
            blocking |= finding.path("blocking").booleanValue();
        }
        if (value.path("valid").booleanValue() == blocking) {
            invalidPage();
        }
    }

    private static void requireReview(JsonNode value) {
        if (!exact(value, REVIEW_FIELDS) || !canonicalUuid(value.path("review_id").textValue())
            || !positive(value.path("revision"), Long.MAX_VALUE)
            || !identifier(value.path("reviewer_subject").textValue())
            || !Set.of("APPROVE", "REJECT").contains(value.path("decision").textValue())
            || !digest(value.path("review_digest")) || !dateTime(value.path("reviewed_at"))) {
            invalidPage();
        }
    }

    private static void requireSimulation(JsonNode value, CanonicalDigest canonical) {
        if (!exact(value, SIMULATION_FIELDS)
            || !canonicalUuid(value.path("simulation_id").textValue())
            || !positive(value.path("revision"), Long.MAX_VALUE)
            || !Set.of("SIMULATION", "SHADOW").contains(value.path("run_kind").textValue())
            || !digest(value.path("baseline_bundle_digest"))
            || !digest(value.path("candidate_source_digest")) || !digest(value.path("corpus_digest"))
            || !positive(value.path("evaluated_actions"), 10_000)
            || !nonNegative(value.path("difference_count"), 10_000)
            || value.path("difference_count").longValue() > value.path("evaluated_actions").longValue()
            || !value.path("side_effect_count").isIntegralNumber()
            || value.path("side_effect_count").longValue() != 0
            || !digest(value.path("impact_report_digest"))
            || !identifier(value.path("run_by").textValue()) || !dateTime(value.path("created_at"))) {
            invalidPage();
        }
        JsonNode report = value.path("impact_report");
        if (!exact(report, SIMULATION_REPORT_FIELDS)
            || !"agenttrust.policy-admin.v1".equals(report.path("schema_version").textValue())
            || !value.path("baseline_bundle_digest").textValue().equals(
                report.path("old_bundle_digest").textValue())
            || !value.path("candidate_source_digest").textValue().equals(
                report.path("new_bundle_digest").textValue())
            || report.path("evaluated_actions").longValue()
                != value.path("evaluated_actions").longValue()
            || report.path("side_effect_count").longValue() != 0
            || !report.path("differences").isArray()
            || report.path("differences").size() != value.path("difference_count").intValue()
            || !dateTime(report.path("generated_at"))) {
            invalidPage();
        }
        for (JsonNode difference : report.path("differences")) {
            if (!exact(difference, DIFFERENCE_FIELDS)
                || !textValue(difference.path("action_id"), 256)
                || !textValue(difference.path("agent_id"), 256)
                || !textValue(difference.path("tool"), 1024)
                || !textValue(difference.path("resource"), 2048)
                || !RISKS.contains(difference.path("risk").textValue())
                || !RULE_DECISIONS.contains(difference.path("old_decision").textValue())
                || !RULE_DECISIONS.contains(difference.path("new_decision").textValue())) {
                invalidPage();
            }
        }
        if (!value.path("impact_report_digest").textValue().equals(canonical.digest(report))) {
            invalidPage();
        }
    }

    private static void requireImpact(JsonNode value, UUID tenantId, String policyId,
                                      CanonicalDigest canonical) {
        if (!exact(value, IMPACT_FIELDS)
            || !"agenttrust.policy-impact-report.v1".equals(value.path("schema_version").textValue())
            || !canonicalUuid(value.path("impact_report_id").textValue())
            || !tenantId.toString().equals(value.path("tenant_id").textValue())
            || !policyId.equals(value.path("policy_id").textValue())
            || !positive(value.path("revision"), Long.MAX_VALUE)
            || !canonicalUuid(value.path("simulation_id").textValue())
            || !digest(value.path("simulation_digest"))
            || !positive(value.path("evaluated_actions"), 10_000)
            || !nonNegative(value.path("difference_count"), 10_000)
            || value.path("difference_count").longValue() > value.path("evaluated_actions").longValue()
            || !stringSet(value.path("affected_agents"), 0, 10_000, 256)
            || !stringSet(value.path("affected_tools"), 0, 10_000, 1024)
            || !stringSet(value.path("affected_resources"), 0, 10_000, 2048)
            || !RISKS.contains(value.path("maximum_risk").textValue())
            || !dateTime(value.path("generated_at")) || !digest(value.path("impact_report_digest"))) {
            invalidPage();
        }
        ObjectNode digestInput = value.deepCopy();
        String supplied = digestInput.remove("impact_report_digest").textValue();
        if (!supplied.equals(canonical.digest(digestInput))) {
            invalidPage();
        }
    }

    private static void requirePromotion(JsonNode value, UUID tenantId, String policyId,
                                         CanonicalDigest canonical) {
        if (!exact(value, PROMOTION_FIELDS)
            || !ENVIRONMENTS.contains(value.path("environment").textValue())
            || !positive(value.path("sequence"), Long.MAX_VALUE)
            || !digest(value.path("bundle_digest"))
            || !(value.path("previous_bundle_digest").isNull()
                || digest(value.path("previous_bundle_digest")))
            || !(value.path("rollback_of").isNull()
                || positive(value.path("rollback_of"), Long.MAX_VALUE))
            || !identifier(value.path("promoted_by").textValue())
            || !Set.of("ACTIVE", "SUPERSEDED", "ROLLED_BACK").contains(
                value.path("state").textValue())
            || !digest(value.path("promotion_digest")) || !dateTime(value.path("promoted_at"))
            || !(value.path("completed_at").isNull() || dateTime(value.path("completed_at")))
            || ("ACTIVE".equals(value.path("state").textValue())) != value.path("completed_at").isNull()) {
            invalidPage();
        }
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("tenant_id", tenantId.toString());
        binding.put("policy_id", policyId);
        binding.put("environment", value.path("environment").textValue());
        binding.put("sequence", value.path("sequence").longValue());
        binding.put("bundle_digest", value.path("bundle_digest").textValue());
        binding.put("rollback_of", value.path("rollback_of").isNull()
            ? null : value.path("rollback_of").longValue());
        if (!value.path("promotion_digest").textValue().equals(canonical.digest(binding))) {
            invalidPage();
        }
    }

    private static void requireException(JsonNode value, String policyId) {
        if (!exact(value, EXCEPTION_FIELDS)
            || !canonicalUuid(value.path("exception_id").textValue())
            || !policyId.equals(value.path("policy_id").textValue())
            || !digest(value.path("scope_digest"))
            || !identifier(value.path("owner_subject").textValue())
            || !stringSet(value.path("approval_ids"), 2, 64, 256)
            || !digest(value.path("reason_digest"))
            || !stringSet(value.path("compensating_controls"), 1, 64, 256)
            || !identifier(value.path("issued_by").textValue())
            || !dateTime(value.path("expires_at"))
            || !(value.path("revoked_at").isNull() || dateTime(value.path("revoked_at")))
            || !(value.path("expired_at").isNull() || dateTime(value.path("expired_at")))
            || !Set.of("ACTIVE", "REVOKED", "EXPIRED").contains(value.path("state").textValue())
            || !dateTime(value.path("created_at"))) {
            invalidPage();
        }
        Instant created = Instant.parse(value.path("created_at").textValue());
        Instant expires = Instant.parse(value.path("expires_at").textValue());
        String state = value.path("state").textValue();
        if (!created.isBefore(expires) || expires.isAfter(created.plus(Duration.ofDays(30)))
            || "ACTIVE".equals(state) && (!value.path("revoked_at").isNull()
                || !value.path("expired_at").isNull())
            || "REVOKED".equals(state) && (value.path("revoked_at").isNull()
                || !value.path("expired_at").isNull())
            || "EXPIRED".equals(state) && !value.path("revoked_at").isNull()) {
            invalidPage();
        }
    }

    private void requireLimit(int limit) {
        if (limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_POLICY_QUERY_INVALID");
        }
    }

    private static void requirePolicyId(String value) {
        if (!policyId(value)) {
            throw new ControlDeniedException("CONTROL_POLICY_QUERY_INVALID");
        }
    }

    private static boolean exact(JsonNode value, Set<String> expected) {
        if (value == null || !value.isObject() || value.size() != expected.size()) {
            return false;
        }
        Set<String> actual = new HashSet<>();
        value.fieldNames().forEachRemaining(actual::add);
        return actual.equals(expected);
    }

    private static String text(JsonNode object, String field, int maximum) {
        JsonNode value = object.path(field);
        if (!textValue(value, maximum)) {
            invalidPage();
        }
        return value.textValue();
    }

    private static boolean textValue(JsonNode value, int maximum) {
        return value != null && value.isTextual() && !value.textValue().isBlank()
            && value.textValue().length() <= maximum && !containsControl(value.textValue());
    }

    private static boolean identifier(String value) {
        return value != null && IDENTIFIER.matcher(value).matches();
    }

    private static boolean policyId(String value) {
        return value != null && POLICY_ID.matcher(value).matches();
    }

    private static boolean digest(JsonNode value) {
        return value != null && value.isTextual() && SHA256.matcher(value.textValue()).matches();
    }

    private static boolean positive(JsonNode value, long maximum) {
        return value != null && value.isIntegralNumber() && value.canConvertToLong()
            && value.longValue() >= 1 && value.longValue() <= maximum;
    }

    private static boolean nonNegative(JsonNode value, long maximum) {
        return value != null && value.isIntegralNumber() && value.canConvertToLong()
            && value.longValue() >= 0 && value.longValue() <= maximum;
    }

    private static boolean stringSet(JsonNode value, int minimum, int maximum, int maxLength) {
        if (value == null || !value.isArray() || value.size() < minimum || value.size() > maximum) {
            return false;
        }
        Set<String> unique = new HashSet<>();
        for (JsonNode item : value) {
            if (!textValue(item, maxLength) || !unique.add(item.textValue())) {
                return false;
            }
        }
        return true;
    }

    private static boolean dateTime(JsonNode value) {
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

    private static boolean canonicalUuid(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.toString().equals(value)
                && (parsed.getMostSignificantBits() != 0L || parsed.getLeastSignificantBits() != 0L);
        } catch (RuntimeException error) {
            return false;
        }
    }

    private static boolean containsControl(String value) {
        return value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }

    private static void invalidPage() {
        throw new ControlUnavailableException("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID");
    }

    public enum ArtifactType {
        SOURCES("sources"),
        ANALYSES("analyses"),
        REVIEWS("reviews"),
        SIMULATIONS("simulations"),
        IMPACT_REPORTS("impact-reports"),
        PROMOTIONS("promotions"),
        EXCEPTIONS("exceptions");

        private final String path;

        ArtifactType(String path) {
            this.path = path;
        }

        public String path() {
            return path;
        }

        public String wireName() {
            return name();
        }

        public static ArtifactType fromPath(String value) {
            for (ArtifactType item : values()) {
                if (item.path.equals(value)) {
                    return item;
                }
            }
            throw new ControlDeniedException("CONTROL_POLICY_QUERY_INVALID");
        }
    }
}
