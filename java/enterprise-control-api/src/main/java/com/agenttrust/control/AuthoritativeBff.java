package com.agenttrust.control;

import com.agenttrust.control.AdminModels.AuthorityView;
import com.agenttrust.control.AdminModels.DashboardResponse;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public final class AuthoritativeBff {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthoritativeBff.class);
    private static final Map<String, String> AUTHORITY_DASHBOARD_PATHS = Map.ofEntries(
        Map.entry("agents", "/v1/authoritative/agents"),
        Map.entry("tasks", "/v1/authoritative/tasks"),
        Map.entry("approvals", "/v1/authoritative/approvals"),
        Map.entry("evidence", "/v1/authoritative/evidence"),
        Map.entry("incidents", "/v1/authoritative/incidents"),
        Map.entry("policies", "/v1/authoritative/policies"),
        Map.entry("tools", "/v1/authoritative/tools"),
        Map.entry("credentials", "/v1/authoritative/credentials"),
        Map.entry("packs", "/v1/authoritative/packs"),
        Map.entry("trace", "/v1/authoritative/trace"),
        Map.entry("compliance", "/v1/authoritative/compliance"),
        Map.entry("audit", "/v1/authoritative/audit"),
        Map.entry("models", "/v1/authoritative/models/executions"),
        Map.entry("data", "/v1/authoritative/data/resources"),
        Map.entry("context", "/v1/authoritative/context/resources"),
        Map.entry("anomalies", "/v1/authoritative/runtime-anomaly/trajectories"),
        Map.entry("security_evaluations", "/v1/authoritative/security-evaluations/campaigns"),
        Map.entry("supply_chain", "/v1/authoritative/supply-chain/releases"),
        Map.entry("domain_packs", "/v1/authoritative/domain-runtime/executions"),
        Map.entry("sre", "/v1/authoritative/sre/resources"),
        Map.entry("deployments", "/v1/authoritative/deployments"));
    private static final Set<String> TENANT_QUERY_AUTHORITIES = Set.of(
        "models", "supply_chain", "domain_packs");
    private static final Set<String> NO_RESOURCE_QUERY_AUTHORITIES = Set.of(
        "policies", "incidents", "packs");
    private static final Map<String, String> STANDARD_PAGE_SCHEMAS = Map.ofEntries(
        Map.entry("models", "agenttrust.authoritative-model-executions.v1"),
        Map.entry("data", "agenttrust.authoritative-data-page.v1"),
        Map.entry("context", "agenttrust.authoritative-context-page.v1"),
        Map.entry("anomalies", "agenttrust.authoritative-runtime-anomaly-page.v1"),
        Map.entry("security_evaluations", "agenttrust.authoritative-security-eval-campaign-page.v1"),
        Map.entry("supply_chain", "agenttrust.supply-chain-authoritative-releases.v1"),
        Map.entry("domain_packs", "agenttrust.domain-runtime-authoritative-state.v1"),
        Map.entry("sre", "agenttrust.sre-resource-page.v1"));
    private static final Map<String, String> STANDARD_PAGE_CURSORS = Map.ofEntries(
        Map.entry("models", "next_cursor"),
        Map.entry("data", "next_after"),
        Map.entry("context", "next_after"),
        Map.entry("anomalies", "next_after"),
        Map.entry("security_evaluations", "next_after_campaign_id"),
        Map.entry("supply_chain", "next_cursor"),
        Map.entry("domain_packs", "next_cursor"),
        Map.entry("sre", "next_after"));
    private static final Set<String> SENSITIVE_BROWSER_DATA_SEGMENTS = Set.of(
        "api_key", "authorization", "content", "cookie", "credential", "key_material",
        "password", "payload", "private", "private_key", "prompt", "raw", "secret", "token");
    private static final Set<String> SAFE_BROWSER_METADATA_SUFFIXES = Set.of(
        "_count", "_digest", "_hash", "_id", "_length", "_profile", "_ref", "_size_bytes",
        "_status", "_type", "_version");
    private final ControlProperties properties;
    private final SecureRestClientFactory clients;
    private final AuthorityScopeTokenProvider authorityTokens;
    private final ApprovalScopeTokenProvider approvalTokens;
    private final PepAuthorizationClient pep;
    private final HumanPrincipalAssertionSigner humanAssertions;
    private final CanonicalDigest canonical;
    private final ObjectMapper mapper;

    public AuthoritativeBff(ControlProperties properties, SecureRestClientFactory clients,
                            AuthorityScopeTokenProvider authorityTokens,
                            ApprovalScopeTokenProvider approvalTokens,
                            PepAuthorizationClient pep,
                            HumanPrincipalAssertionSigner humanAssertions,
                            CanonicalDigest canonical,
                            ObjectMapper mapper) {
        this.properties = properties;
        this.clients = clients;
        this.authorityTokens = authorityTokens;
        this.approvalTokens = approvalTokens;
        this.pep = pep;
        this.humanAssertions = humanAssertions;
        this.canonical = canonical;
        this.mapper = mapper;
    }

    public DashboardResponse dashboard(PrincipalContext principal, String resource, int limit) {
        if (resource == null || !resource.matches("[a-z][a-z0-9_-]{0,99}")
            || limit < 1 || limit > properties.maximumPageSize()) {
            throw new ControlDeniedException("CONTROL_QUERY_DENIED");
        }
        pep.authorizeQuery(principal, "VIEW_ENTERPRISE_DASHBOARD", "dashboard:" + resource);
        Map<String, AuthorityView> sections = new TreeMap<>();
        Set<String> unavailable = new TreeSet<>();
        AUTHORITY_DASHBOARD_PATHS.forEach((name, path) -> {
            String section = name.toUpperCase(java.util.Locale.ROOT);
            UUID traceId = UUID.randomUUID();
            try {
                var endpoint = properties.authorityEndpoints().get(name);
                if (endpoint == null) {
                    throw new IllegalStateException("AUTHORITY_ENDPOINT_UNCONFIGURED");
                }
                String tenant = principal.tenantId().toString();
                String token = "approvals".equals(name)
                    ? approvalTokens.token(ApprovalScopeTokenProvider.Scope.READ)
                    : authorityTokens.readToken(name);
                JsonNode data = "audit".equals(name)
                    ? queryAuditAuthority(endpoint, token, principal, resource, limit, traceId)
                    : clients.client(endpoint).get()
                        .uri(uri -> {
                            uri.path(path);
                            if (TENANT_QUERY_AUTHORITIES.contains(name)) {
                                uri.queryParam("tenant_id", tenant);
                            } else if (!STANDARD_PAGE_SCHEMAS.containsKey(name)
                                && !NO_RESOURCE_QUERY_AUTHORITIES.contains(name)) {
                                uri.queryParam("resource", resource);
                            }
                            return uri.queryParam("limit", limit).build();
                        })
                        .header("Authorization", "Bearer " + token)
                        .header("X-AgentTrust-Tenant-Id", tenant)
                        .header("X-Tenant-Id", tenant)
                        .header("X-Actor-Subject", principal.subject())
                        .header("X-Actor-Roles", String.join(",", new TreeSet<>(principal.roles())))
                        .header("X-AgentTrust-Trace-Id", traceId.toString())
                        .exchange((ignored, response) -> decodeAuthority(response));
                requireDashboardAuthority(name, data, principal, resource, limit);
                sections.put(section, new AuthorityView("agenttrust.authority-view.v1", section,
                    true, true, data,
                    canonical.digest(data), null, Instant.now()));
            } catch (Exception error) {
                LOGGER.warn("authoritative source unavailable authority={} trace_id={} error_type={}",
                    name, traceId, error.getClass().getSimpleName());
                unavailable.add(section);
                sections.put(section, new AuthorityView("agenttrust.authority-view.v1", section,
                    true, false, null,
                    "0".repeat(64), "AUTHORITATIVE_SOURCE_UNAVAILABLE", Instant.now()));
            }
        });
        return new DashboardResponse("agenttrust.enterprise-dashboard.v1", principal.tenantId(),
            Map.copyOf(sections), unavailable.isEmpty(), Set.copyOf(unavailable), Instant.now());
    }

    static String dashboardPath(String authority) {
        String path = AUTHORITY_DASHBOARD_PATHS.get(authority);
        if (path == null) {
            throw new IllegalArgumentException("CONTROL_AUTHORITY_ROUTE_UNSUPPORTED");
        }
        return path;
    }

    static Set<String> dashboardAuthorities() {
        return AUTHORITY_DASHBOARD_PATHS.keySet();
    }

    void requireDashboardAuthority(String name, JsonNode data, PrincipalContext principal,
                                   String resource, int limit) {
        if (data == null || !data.isObject()) {
            throw new IllegalStateException("NOT_AUTHORITATIVE");
        }
        if ("approvals".equals(name)) {
            requireApprovalPage(data, principal, resource, limit);
        } else if ("agents".equals(name)) {
            requireAgentPage(data, principal, resource, limit);
        } else if ("tasks".equals(name)) {
            requireTaskPage(data, principal, resource, limit);
        } else if ("credentials".equals(name)) {
            requireCredentialPage(data, principal, resource, limit);
        } else if ("tools".equals(name)) {
            requireToolInventory(data, principal);
        } else if ("audit".equals(name)) {
            requireAuditPage(data, principal, resource, limit);
        } else if ("policies".equals(name)) {
            PolicyAuthorityGateway.requirePolicyPage(data, principal.tenantId(), null, limit);
        } else if ("incidents".equals(name)) {
            IncidentAuthorityGateway.requirePage(data, principal.tenantId(), null, limit);
        } else if ("packs".equals(name)) {
            PackMarketplaceGateway.requirePage(data, principal.tenantId(), null, limit, canonical);
        } else if (STANDARD_PAGE_SCHEMAS.containsKey(name)) {
            requireStandardAuthorityPage(name, data, principal, limit);
        } else if (!data.path("authoritative").isBoolean()
            || !data.path("authoritative").booleanValue()) {
            throw new IllegalStateException("NOT_AUTHORITATIVE");
        }
        if (!safeBrowserAuthorityData(data, 0, new int[] {50_000}, false)) {
            throw new IllegalStateException("AUTHORITY_BROWSER_PROJECTION_UNSAFE");
        }
    }

    void requireStandardAuthorityPage(String authority, JsonNode value,
                                      PrincipalContext principal, int limit) {
        String expectedSchema = STANDARD_PAGE_SCHEMAS.get(authority);
        String cursorField = STANDARD_PAGE_CURSORS.get(authority);
        Set<String> fields = "models".equals(authority)
            ? Set.of("schema_version", "tenant_id", "authoritative", "items", cursorField,
                "data_digest", "generated_at")
            : Set.of("schema_version", "tenant_id", "authoritative", "items", cursorField,
                "data_digest");
        JsonNode cursor = value.path(cursorField);
        if (!value.isObject() || !exactFields(value, fields)
            || !expectedSchema.equals(value.path("schema_version").asText())
            || !principal.tenantId().toString().equals(value.path("tenant_id").asText())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !standardCursorValid(authority, cursor) || !digest(value.path("data_digest"))
            || "models".equals(authority) && !instant(value.path("generated_at"))
            || !safeBrowserAuthorityData(value.path("items"), 0, new int[] {50_000}, false)) {
            throw new IllegalStateException("STANDARD_AUTHORITY_PAGE_INVALID");
        }
        ObjectNode material = value.deepCopy();
        material.remove("data_digest");
        byte[] expected = canonical.digest(material).getBytes(StandardCharsets.US_ASCII);
        byte[] supplied = value.path("data_digest").textValue()
            .getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new IllegalStateException("STANDARD_AUTHORITY_PAGE_DIGEST_INVALID");
        }
    }

    private static boolean safeBrowserAuthorityData(JsonNode value, int depth, int[] budget,
                                                    boolean dynamicMetadataKeys) {
        if (depth > 16 || --budget[0] < 0) {
            return false;
        }
        if (value.isObject()) {
            var fields = value.properties().iterator();
            while (fields.hasNext()) {
                var field = fields.next();
                String key = field.getKey();
                if (key.isBlank() || key.length() > 128
                    || (!dynamicMetadataKeys && forbiddenBrowserDataField(key))
                    || dynamicMetadataKeys && !(field.getValue().isIntegralNumber()
                        || field.getValue().isBoolean() || field.getValue().isNull())
                    || key.chars().anyMatch(Character::isISOControl)
                    || !safeBrowserAuthorityData(field.getValue(), depth + 1, budget,
                        "metrics".equals(key))) {
                    return false;
                }
            }
            return true;
        }
        if (value.isArray()) {
            if (value.size() > 1_000) {
                return false;
            }
            for (JsonNode item : value) {
                if (!safeBrowserAuthorityData(item, depth + 1, budget, false)) {
                    return false;
                }
            }
            return true;
        }
        if (value.isTextual()) {
            return value.textValue().length() <= 8_192
                && value.textValue().chars().noneMatch(Character::isISOControl);
        }
        return value.isNull() || value.isBoolean()
            || value.isIntegralNumber() && value.canConvertToLong();
    }

    private static boolean forbiddenBrowserDataField(String key) {
        String normalized = key.toLowerCase(java.util.Locale.ROOT);
        if (SAFE_BROWSER_METADATA_SUFFIXES.stream().anyMatch(normalized::endsWith)) {
            return false;
        }
        return SENSITIVE_BROWSER_DATA_SEGMENTS.stream().anyMatch(segment ->
            normalized.equals(segment) || normalized.startsWith(segment + "_")
                || normalized.endsWith("_" + segment)
                || normalized.contains("_" + segment + "_"));
    }

    static boolean standardCursorValid(String authority, JsonNode cursor) {
        if (cursor.isNull()) {
            return true;
        }
        if ("models".equals(authority)) {
            return cursor.isObject()
                && exactFields(cursor, Set.of("created_at", "request_id"))
                && instant(cursor.path("created_at")) && uuid(cursor.path("request_id"));
        }
        if ("anomalies".equals(authority) || "security_evaluations".equals(authority)) {
            return uuid(cursor);
        }
        if ("supply_chain".equals(authority)) {
            return cursor.isTextual() && cursor.textValue().matches("[A-Za-z0-9_-]{1,2048}");
        }
        if ("domain_packs".equals(authority)) {
            return cursor.isTextual() && cursor.textValue().matches("[A-Za-z0-9_-]{1,512}");
        }
        if ("context".equals(authority)) {
            if (!cursor.isTextual()) {
                return false;
            }
            String value = cursor.textValue();
            int separator = value.indexOf(':');
            return value.length() >= 3 && value.length() <= 1_024
                && separator > 0 && separator < value.length() - 1
                && !value.contains("?") && !value.contains("#")
                && value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e);
        }
        if ("sre".equals(authority)) {
            return cursor.isTextual() && cursor.textValue().matches(
                "sre:(slo|alert|topology|backup|restore|dr|chaos|load|rollout|"
                    + "cost-capacity|observability)/[0-9a-f]{8}-[0-9a-f]{4}-"
                    + "[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
        }
        if (!cursor.isTextual() || cursor.textValue().length() > 1_024
            || cursor.textValue().isBlank()) {
            return false;
        }
        String value = cursor.textValue();
        return !value.startsWith("/") && !value.contains("..") && !value.contains("//")
            && value.chars().noneMatch(character -> Character.isWhitespace(character)
                || Character.isISOControl(character));
    }

    private JsonNode decodeAuthority(org.springframework.http.client.ClientHttpResponse response)
        throws IOException {
        if (!response.getStatusCode().is2xxSuccessful()
            || response.getHeaders().getContentType() == null
            || !MediaType.APPLICATION_JSON.isCompatibleWith(
                response.getHeaders().getContentType())) {
            throw new IOException("AUTHORITY_RESPONSE_REJECTED");
        }
        byte[] body = response.getBody().readNBytes(properties.maximumAuthorityResponseBytes() + 1);
        if (body.length == 0 || body.length > properties.maximumAuthorityResponseBytes()) {
            throw new IOException("AUTHORITY_RESPONSE_INVALID");
        }
        JsonNode value = mapper.readTree(body);
        if (value == null || !value.isObject()) {
            throw new IOException("AUTHORITY_RESPONSE_INVALID");
        }
        return value;
    }

    private JsonNode queryAuditAuthority(java.net.URI endpoint, String token,
                                         PrincipalContext principal, String resource, int limit,
                                         UUID traceId) {
        Instant requestedAt = Instant.now();
        String idempotencyKey = "audit-query:" + UUID.randomUUID();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schema_version", "agenttrust.authoritative-audit-query-request.v1");
        body.put("tenant_id", principal.tenantId().toString());
        body.put("idempotency_key", idempotencyKey);
        body.put("audit_task_id", UUID.randomUUID().toString());
        body.put("actor_subject", principal.subject());
        body.put("resource", resource);
        body.put("resource_prefix", "*");
        body.put("maximum_classification", "INTERNAL");
        body.put("occurred_from", requestedAt.minus(Duration.ofDays(30)).toString());
        body.put("occurred_until", requestedAt.toString());
        body.put("offset", 0);
        body.put("limit", limit);
        body.put("requested_at", requestedAt.toString());
        Map<String, Object> immutableBody = java.util.Collections.unmodifiableMap(body);
        var assertion = humanAssertions.sign(principal, "POST", "/v1/authoritative/audit",
            "audit:query", idempotencyKey, immutableBody, true);
        String tenant = principal.tenantId().toString();
        JsonNode response = clients.client(endpoint).post()
            .uri("/v1/authoritative/audit")
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + token)
            .header("X-AgentTrust-Tenant-Id", tenant)
            .header("Idempotency-Key", idempotencyKey)
            .header("X-AgentTrust-Trace-Id", traceId.toString())
            .header("X-AgentTrust-Human-Assertion", assertion.headerValue())
            .body(immutableBody)
            .exchange((ignored, httpResponse) -> decodeAuthority(httpResponse));
        JsonNode receipt = response.path("receipt");
        if (!receipt.isObject()
            || !idempotencyKey.equals(receipt.path("idempotency_key").asText())
            || !principal.tenantId().toString().equals(receipt.path("tenant_id").asText())
            || !MessageDigest.isEqual(canonical.digest(immutableBody)
                    .getBytes(StandardCharsets.US_ASCII),
                receipt.path("request_digest").asText().getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("AUDIT_AUTHORITY_REQUEST_BINDING_INVALID");
        }
        return response;
    }

    void requireAuditPage(JsonNode value, PrincipalContext principal, String resource, int limit) {
        Set<String> fields = Set.of("schema_version", "authoritative", "tenant_id", "resource",
            "items", "next_offset", "receipt", "data_digest");
        if (!value.isObject() || !exactFields(value, fields)
            || !"agenttrust.authoritative-audit-page.v1"
                .equals(value.path("schema_version").asText())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !principal.tenantId().toString().equals(value.path("tenant_id").asText())
            || !resource.equals(value.path("resource").asText())
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !(value.path("next_offset").isNull()
                || value.path("next_offset").canConvertToLong()
                    && value.path("next_offset").longValue() == limit)
            || !digest(value.path("data_digest"))) {
            throw new IllegalStateException("AUDIT_AUTHORITY_PAGE_INVALID");
        }
        for (JsonNode item : value.path("items")) {
            requireAuditRecord(item, principal);
        }
        JsonNode receipt = value.path("receipt");
        requireAuditReceipt(receipt, principal, value.path("items"));
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("schema_version", value.path("schema_version"));
        material.put("authoritative", value.path("authoritative"));
        material.put("tenant_id", value.path("tenant_id"));
        material.put("resource", value.path("resource"));
        material.put("items", value.path("items"));
        material.put("next_offset", value.path("next_offset"));
        material.put("receipt", receipt);
        byte[] expected = canonical.digest(material).getBytes(StandardCharsets.US_ASCII);
        byte[] supplied = value.path("data_digest").textValue()
            .getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new IllegalStateException("AUDIT_AUTHORITY_PAGE_DIGEST_INVALID");
        }
    }

    void requireAuditReceipt(JsonNode receipt, PrincipalContext principal, JsonNode items) {
        Set<String> fields = Set.of("schema_version", "operation_id", "tenant_id",
            "idempotency_key", "request_digest", "operation", "resource_ref", "result_digest",
            "chain_head", "issued_at", "issuer", "key_id", "key_usage", "signature");
        if (!receipt.isObject() || !exactFields(receipt, fields)
            || !"agenttrust.audit-mutation-receipt.v1"
                .equals(receipt.path("schema_version").asText())
            || !uuid(receipt.path("operation_id"))
            || !principal.tenantId().toString().equals(receipt.path("tenant_id").asText())
            || !receipt.path("idempotency_key").isTextual()
            || !receipt.path("idempotency_key").textValue()
                .matches("[A-Za-z0-9._:/-]{1,128}")
            || !digest(receipt.path("request_digest"))
            || !"AUTHORITATIVE_QUERY".equals(receipt.path("operation").asText())
            || !"audit://authoritative-query".equals(receipt.path("resource_ref").asText())
            || !digest(receipt.path("result_digest"))
            || !MessageDigest.isEqual(canonical.digest(items).getBytes(StandardCharsets.US_ASCII),
                receipt.path("result_digest").textValue().getBytes(StandardCharsets.US_ASCII))
            || !digest(receipt.path("chain_head")) || !instant(receipt.path("issued_at"))
            || invalidText(receipt.path("issuer"), 256)
            || invalidText(receipt.path("key_id"), 128)
            || !"AUDIT_MUTATION_RECEIPT".equals(receipt.path("key_usage").asText())
            || !receipt.path("signature").isTextual()
            || !receipt.path("signature").textValue().matches("[A-Za-z0-9_-]{86}")) {
            throw new IllegalStateException("AUDIT_AUTHORITY_RECEIPT_INVALID");
        }
    }

    static void requireAuditRecord(JsonNode item, PrincipalContext principal) {
        Set<String> fields = Set.of("schema_version", "record_id", "sequence", "previous_hash",
            "record_hash", "key_id", "signature", "draft");
        if (!item.isObject() || !exactFields(item, fields)
            || !"agenttrust.audit-retention.v1".equals(item.path("schema_version").asText())
            || !uuid(item.path("record_id")) || !item.path("sequence").canConvertToLong()
            || item.path("sequence").longValue() < 1 || !digest(item.path("previous_hash"))
            || !digest(item.path("record_hash")) || invalidText(item.path("key_id"), 128)
            || !item.path("signature").isTextual()
            || !item.path("signature").textValue().matches("[A-Za-z0-9_-]{86}")) {
            throw new IllegalStateException("AUDIT_AUTHORITY_RECORD_INVALID");
        }
        JsonNode draft = item.path("draft");
        Set<String> draftFields = Set.of("schema_version", "request_id", "tenant_id", "task_id",
            "event_type", "actor_subject", "resource", "classification", "payload_hash",
            "safe_summary", "artifact_hashes", "occurred_at");
        if (!draft.isObject() || !exactFields(draft, draftFields)
            || !"agenttrust.audit-retention.v1".equals(draft.path("schema_version").asText())
            || invalidText(draft.path("request_id"), 256)
            || !principal.tenantId().toString().equals(draft.path("tenant_id").asText())
            || !uuid(draft.path("task_id")) || invalidText(draft.path("event_type"), 128)
            || invalidText(draft.path("actor_subject"), 512)
            || invalidText(draft.path("resource"), 2048)
            || !Set.of("PUBLIC", "INTERNAL").contains(draft.path("classification").asText())
            || !digest(draft.path("payload_hash"))
            || invalidText(draft.path("safe_summary"), 4096)
            || !draft.path("artifact_hashes").isArray()
            || draft.path("artifact_hashes").size() > 10_000
            || !instant(draft.path("occurred_at"))) {
            throw new IllegalStateException("AUDIT_AUTHORITY_RECORD_INVALID");
        }
        Set<String> artifacts = new HashSet<>();
        for (JsonNode artifact : draft.path("artifact_hashes")) {
            if (!digest(artifact) || !artifacts.add(artifact.textValue())) {
                throw new IllegalStateException("AUDIT_AUTHORITY_RECORD_INVALID");
            }
        }
    }

    private void requireApprovalPage(JsonNode value, PrincipalContext principal, String resource,
                                     int limit) {
        Set<String> fields = Set.of("schema_version", "authoritative", "tenant_id", "resource",
            "items", "next_cursor", "data_digest");
        if (!value.isObject() || !exactFields(value, fields)
            || !"agenttrust.authoritative-approval-page.v1"
                .equals(value.path("schema_version").asText())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !principal.tenantId().toString().equals(value.path("tenant_id").asText())
            || !resource.equals(value.path("resource").asText())
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !(value.path("next_cursor").isNull()
                || value.path("next_cursor").isTextual()
                    && value.path("next_cursor").textValue().matches("[A-Za-z0-9_-]{1,5462}"))
            || !value.path("data_digest").isTextual()
            || !value.path("data_digest").textValue().matches("[a-f0-9]{64}")) {
            throw new IllegalStateException("APPROVAL_AUTHORITY_PAGE_INVALID");
        }
        for (JsonNode item : value.path("items")) {
            requireApprovalCaseView(item);
        }
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("schema_version", value.path("schema_version"));
        material.put("authoritative", value.path("authoritative"));
        material.put("tenant_id", value.path("tenant_id"));
        material.put("resource", value.path("resource"));
        material.put("items", value.path("items"));
        material.put("next_cursor", value.path("next_cursor"));
        byte[] expected = canonical.digest(material).getBytes(StandardCharsets.US_ASCII);
        byte[] supplied = value.path("data_digest").textValue()
            .getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new IllegalStateException("APPROVAL_AUTHORITY_DIGEST_INVALID");
        }
    }

    private void requireTaskPage(JsonNode value, PrincipalContext principal, String resource,
                                 int limit) {
        JsonNode items = requireCommonPage(value, "agenttrust.authoritative-task-page.v1",
            principal, resource, limit, "TASK_AUTHORITY_PAGE_INVALID");
        Set<String> statuses = Set.of("CREATED", "PLANNED", "POLICY_CHECKED",
            "APPROVAL_PENDING", "APPROVED", "RUNNING", "PAUSE_REQUESTED", "PAUSED",
            "CANCEL_REQUESTED", "CANCELLING", "KILL_REQUESTED", "KILLED", "VERIFYING",
            "COMPLETED", "DENIED", "FAILED", "EVALUATION_FAILED", "COMPENSATING",
            "ROLLED_BACK", "NEEDS_HUMAN", "MANUAL_RECOVERY_REQUIRED");
        Set<String> fields = Set.of("schema_version", "action_id", "task_id", "status",
            "recovery_cursor", "terminal");
        for (JsonNode item : items) {
            if (!item.isObject() || !exactFields(item, fields)
                || !"agenttrust.task-view.v1".equals(item.path("schema_version").asText())
                || !uuid(item.path("action_id")) || !uuid(item.path("task_id"))
                || !statuses.contains(item.path("status").asText())
                || !item.path("recovery_cursor").canConvertToLong()
                || item.path("recovery_cursor").longValue() < 0
                || !item.path("terminal").isBoolean()) {
                throw new IllegalStateException("TASK_AUTHORITY_VIEW_INVALID");
            }
        }
    }

    void requireAgentPage(JsonNode value, PrincipalContext principal, String resource, int limit) {
        Set<String> fields = Set.of("schema_version", "authoritative", "tenant_id", "resource",
            "items", "next_cursor", "data_digest");
        if (!value.isObject() || !exactFields(value, fields)
            || !"agenttrust.authoritative-agent-page.v1"
                .equals(value.path("schema_version").asText())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !principal.tenantId().toString().equals(value.path("tenant_id").asText())
            || !resource.equals(value.path("resource").asText())
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !(value.path("next_cursor").isNull()
                || value.path("next_cursor").isTextual()
                    && value.path("next_cursor").textValue().matches("[A-Za-z0-9_-]{1,5462}"))
            || !digest(value.path("data_digest"))) {
            throw new IllegalStateException("AGENT_AUTHORITY_PAGE_INVALID");
        }
        Set<String> itemFields = Set.of("schema_version", "agent_id", "display_name",
            "owner_subject", "sponsor_subject", "ownership_status", "environment", "lifecycle",
            "agent_type", "bom_digest", "endpoint_count", "identity_count", "tool_count",
            "pack_count", "open_findings", "highest_risk", "last_activity_at", "registered_at",
            "updated_at");
        for (JsonNode item : value.path("items")) {
            if (!item.isObject() || !exactFields(item, itemFields)
                || !"agenttrust.agent-inventory-item.v1"
                    .equals(item.path("schema_version").asText())
                || invalidIdentifier(item.path("agent_id"), 256)
                || invalidText(item.path("display_name"), 256)
                || invalidText(item.path("owner_subject"), 512)
                || invalidText(item.path("sponsor_subject"), 512)
                || !Set.of("PENDING", "CONFIRMED")
                    .contains(item.path("ownership_status").asText())
                || !Set.of("DEVELOPMENT", "STAGING", "PRODUCTION")
                    .contains(item.path("environment").asText())
                || !Set.of("DRAFT", "ACTIVE", "SUSPENDED", "RETIRED", "REVOKED")
                    .contains(item.path("lifecycle").asText())
                || invalidIdentifier(item.path("agent_type"), 128)
                || !digest(item.path("bom_digest"))
                || !boundedInteger(item.path("endpoint_count"), 1, 100)
                || !boundedInteger(item.path("identity_count"), 1, 1_000)
                || !boundedInteger(item.path("tool_count"), 0, 1_000)
                || !boundedInteger(item.path("pack_count"), 0, 1_000)
                || !boundedInteger(item.path("open_findings"), 0, Integer.MAX_VALUE)
                || !(item.path("highest_risk").isNull()
                    || Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL")
                        .contains(item.path("highest_risk").asText()))
                || !instant(item.path("last_activity_at"))
                || !instant(item.path("registered_at"))
                || !instant(item.path("updated_at"))) {
                throw new IllegalStateException("AGENT_AUTHORITY_ITEM_INVALID");
            }
        }
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("schema_version", value.path("schema_version"));
        material.put("authoritative", value.path("authoritative"));
        material.put("tenant_id", value.path("tenant_id"));
        material.put("resource", value.path("resource"));
        material.put("items", value.path("items"));
        material.put("next_cursor", value.path("next_cursor"));
        if (!MessageDigest.isEqual(canonical.digest(material).getBytes(StandardCharsets.US_ASCII),
            value.path("data_digest").textValue().getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("AGENT_AUTHORITY_DIGEST_INVALID");
        }
    }

    private void requireCredentialPage(JsonNode value, PrincipalContext principal,
                                       String resource, int limit) {
        JsonNode items = requireCommonPage(value,
            "agenttrust.authoritative-credential-page.v1", principal, resource, limit,
            "CREDENTIAL_AUTHORITY_PAGE_INVALID");
        Set<String> fields = Set.of("schema_version", "credential_id", "agent_instance_id",
            "task_id", "step_id", "action_hash", "audience", "tool_id",
            "credential_profile", "resource", "target_profile", "claims_digest",
            "binding_receipt_digest", "status", "remaining_uses", "revocation_epoch",
            "issued_at", "expires_at", "revoked_at");
        for (JsonNode item : items) {
            if (!item.isObject() || !exactFields(item, fields)
                || !"agenttrust.credential-view.v1".equals(item.path("schema_version").asText())
                || !uuid(item.path("credential_id")) || !uuid(item.path("agent_instance_id"))
                || !uuid(item.path("task_id")) || !uuid(item.path("step_id"))
                || !digest(item.path("action_hash")) || !digest(item.path("claims_digest"))
                || !digest(item.path("binding_receipt_digest"))
                || !"tool-proxy".equals(item.path("audience").asText())
                || invalidText(item.path("tool_id"), 256)
                || invalidText(item.path("credential_profile"), 256)
                || invalidText(item.path("resource"), 2048)
                || invalidText(item.path("target_profile"), 256)
                || !Set.of("ACTIVE", "CONSUMED", "EXPIRED", "REVOKED")
                    .contains(item.path("status").asText())
                || !item.path("remaining_uses").canConvertToInt()
                || item.path("remaining_uses").intValue() < 0
                || item.path("remaining_uses").intValue() > 1
                || !item.path("revocation_epoch").canConvertToLong()
                || item.path("revocation_epoch").longValue() < 0
                || !instant(item.path("issued_at")) || !instant(item.path("expires_at"))
                || !(item.path("revoked_at").isNull() || instant(item.path("revoked_at")))) {
                throw new IllegalStateException("CREDENTIAL_AUTHORITY_VIEW_INVALID");
            }
        }
    }

    private void requireToolInventory(JsonNode value, PrincipalContext principal) {
        Set<String> fields = Set.of("schema_version", "authoritative", "tenant_id", "complete",
            "registry_revision", "digest", "signed_at", "signature", "tools");
        if (!value.isObject() || !exactFields(value, fields)
            || !"agenttrust.authoritative-tools.v1".equals(value.path("schema_version").asText())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !principal.tenantId().toString().equals(value.path("tenant_id").asText())
            || !value.path("complete").isBoolean() || !value.path("complete").booleanValue()
            || !value.path("registry_revision").canConvertToLong()
            || value.path("registry_revision").longValue() < 1
            || !digest(value.path("digest")) || !instant(value.path("signed_at"))
            || !validManifestSignature(value.path("signature"))
            || !value.path("tools").isArray() || value.path("tools").size() > 1000) {
            throw new IllegalStateException("TOOL_AUTHORITY_INVENTORY_INVALID");
        }
        Set<String> toolFields = Set.of("tool_id", "tool_version", "effect_class", "risk_level",
            "manifest_hash", "implementation_digest");
        for (JsonNode tool : value.path("tools")) {
            if (!tool.isObject() || !exactFields(tool, toolFields)
                || invalidText(tool.path("tool_id"), 256)
                || !tool.path("tool_version").isTextual()
                || !tool.path("tool_version").textValue().matches(
                    "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?")
                || !Set.of("PURE", "IDEMPOTENT", "COMPENSATABLE", "IRREVERSIBLE")
                    .contains(tool.path("effect_class").asText())
                || !Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL")
                    .contains(tool.path("risk_level").asText())
                || !digest(tool.path("manifest_hash"))
                || !digest(tool.path("implementation_digest"))) {
                throw new IllegalStateException("TOOL_AUTHORITY_ITEM_INVALID");
            }
        }
    }

    private JsonNode requireCommonPage(JsonNode value, String schema, PrincipalContext principal,
                                       String resource, int limit, String error) {
        Set<String> fields = Set.of("schema_version", "authoritative", "tenant_id", "resource",
            "items", "next_cursor", "data_digest");
        if (!value.isObject() || !exactFields(value, fields)
            || !schema.equals(value.path("schema_version").asText())
            || !value.path("authoritative").isBoolean()
            || !value.path("authoritative").booleanValue()
            || !principal.tenantId().toString().equals(value.path("tenant_id").asText())
            || !resource.equals(value.path("resource").asText())
            || !value.path("items").isArray() || value.path("items").size() > limit
            || !value.path("next_cursor").isNull() || !digest(value.path("data_digest"))) {
            throw new IllegalStateException(error);
        }
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("schema_version", value.path("schema_version"));
        material.put("authoritative", value.path("authoritative"));
        material.put("tenant_id", value.path("tenant_id"));
        material.put("resource", value.path("resource"));
        material.put("items", value.path("items"));
        material.put("next_cursor", value.path("next_cursor"));
        byte[] expected = canonical.digest(material).getBytes(StandardCharsets.US_ASCII);
        byte[] supplied = value.path("data_digest").textValue()
            .getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, supplied)) {
            throw new IllegalStateException(error);
        }
        return value.path("items");
    }

    private static void requireApprovalCaseView(JsonNode item) {
        Set<String> fields = Set.of("schema_version", "case_id", "domain", "safe_summary",
            "action_hash", "resource", "resource_version", "policy_version", "risk",
            "evidence_refs", "status");
        if (!item.isObject() || !exactFields(item, fields)
            || !"agenttrust.approval-case-view.v1".equals(item.path("schema_version").asText())
            || !item.path("case_id").isTextual()
            || !item.path("case_id").textValue().matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            || !Set.of("CODING", "INDUSTRIAL").contains(item.path("domain").asText())
            || invalidText(item.path("safe_summary"), 2000)
            || !item.path("action_hash").isTextual()
            || !item.path("action_hash").textValue().matches("[a-f0-9]{64}")
            || invalidText(item.path("resource"), 2048)
            || invalidText(item.path("resource_version"), 2048)
            || invalidText(item.path("policy_version"), 2048)
            || !Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL").contains(item.path("risk").asText())
            || !item.path("evidence_refs").isArray() || item.path("evidence_refs").size() > 100
            || !Set.of("PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED")
                .contains(item.path("status").asText())) {
            throw new IllegalStateException("APPROVAL_AUTHORITY_CASE_VIEW_INVALID");
        }
        Set<String> evidence = new HashSet<>();
        for (JsonNode reference : item.path("evidence_refs")) {
            if (invalidText(reference, 2048) || !evidence.add(reference.textValue())) {
                throw new IllegalStateException("APPROVAL_AUTHORITY_CASE_VIEW_INVALID");
            }
        }
    }

    private static boolean invalidText(JsonNode value, int maximum) {
        return !value.isTextual() || value.textValue().isBlank()
            || value.textValue().length() > maximum || value.textValue().indexOf('\0') >= 0
            || value.textValue().indexOf('\r') >= 0 || value.textValue().indexOf('\n') >= 0;
    }

    private static boolean invalidIdentifier(JsonNode value, int maximum) {
        return invalidText(value, maximum)
            || !value.textValue().matches("[A-Za-z0-9][A-Za-z0-9._:-]{0," + (maximum - 1) + "}");
    }

    private static boolean boundedInteger(JsonNode value, int minimum, int maximum) {
        return value.isIntegralNumber() && value.canConvertToInt()
            && value.intValue() >= minimum && value.intValue() <= maximum;
    }

    private static boolean uuid(JsonNode value) {
        return value.isTextual() && value.textValue().matches(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    private static boolean digest(JsonNode value) {
        return value.isTextual() && value.textValue().matches("[a-f0-9]{64}");
    }

    private static boolean instant(JsonNode value) {
        if (!value.isTextual()) {
            return false;
        }
        try {
            Instant.parse(value.textValue());
            return true;
        } catch (RuntimeException error) {
            return false;
        }
    }

    private static boolean validManifestSignature(JsonNode value) {
        Set<String> fields = Set.of("publisher_id", "key_id", "algorithm", "signature");
        return value.isObject() && exactFields(value, fields)
            && !invalidText(value.path("publisher_id"), 256)
            && !invalidText(value.path("key_id"), 256)
            && "Ed25519".equals(value.path("algorithm").asText())
            && value.path("signature").isTextual()
            && value.path("signature").textValue().matches("[A-Za-z0-9_-]{86}");
    }

    private static boolean exactFields(JsonNode value, Set<String> expected) {
        Set<String> actual = new HashSet<>();
        value.fieldNames().forEachRemaining(actual::add);
        return actual.equals(expected);
    }
}
