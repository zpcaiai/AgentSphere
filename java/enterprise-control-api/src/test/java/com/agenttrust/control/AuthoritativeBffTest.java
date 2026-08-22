package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthoritativeBffTest {
    private static final Map<String, String> EXPECTED_ROUTES = Map.ofEntries(
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
        Map.entry("security_evaluations",
            "/v1/authoritative/security-evaluations/campaigns"),
        Map.entry("supply_chain", "/v1/authoritative/supply-chain/releases"),
        Map.entry("domain_packs", "/v1/authoritative/domain-runtime/executions"),
        Map.entry("sre", "/v1/authoritative/sre/resources"),
        Map.entry("deployments", "/v1/authoritative/deployments"));

    @Test
    void dashboardUsesOneExplicitCollectionRoutePerAuthority() {
        assertEquals(EXPECTED_ROUTES.keySet(), AuthoritativeBff.dashboardAuthorities());
        Set<String> paths = new HashSet<>();
        for (Map.Entry<String, String> route : EXPECTED_ROUTES.entrySet()) {
            String authority = route.getKey();
            String path = AuthoritativeBff.dashboardPath(authority);
            assertEquals(route.getValue(), path);
            paths.add(path);
        }
        assertEquals(EXPECTED_ROUTES.size(), paths.size());
        assertFalse(paths.contains("/v1/authoritative/summary"));
    }

    @Test
    void standardAuthorityPageRequiresTenantExactShapeAndRecomputableDigest() {
        ObjectMapper mapper = new ObjectMapper();
        CanonicalDigest canonical = new CanonicalDigest(mapper);
        AuthoritativeBff bff = new AuthoritativeBff(null, null, null, null, null, null,
            canonical, mapper);
        UUID tenant = UUID.fromString("01900000-0000-7000-8000-000000000001");
        PrincipalContext principal = new PrincipalContext("reader@example.test", tenant,
            Set.of("data-reader"), Set.of(), Set.of(), Set.of(), true,
            Instant.parse("2030-01-02T03:03:05Z"), "urn:agenttrust:acr:mfa");
        ObjectNode page = mapper.createObjectNode();
        page.put("schema_version", "agenttrust.authoritative-data-page.v1");
        page.put("tenant_id", tenant.toString());
        page.put("authoritative", true);
        page.set("items", mapper.createArrayNode());
        page.putNull("next_after");
        page.put("data_digest", canonical.digest(page));

        assertDoesNotThrow(() -> bff.requireStandardAuthorityPage("data", page, principal, 50));
        page.withArray("items").addObject().put("prompt_digest", "d".repeat(64));
        ObjectNode metadataMaterial = page.deepCopy();
        metadataMaterial.remove("data_digest");
        page.put("data_digest", canonical.digest(metadataMaterial));
        assertDoesNotThrow(() -> bff.requireStandardAuthorityPage("data", page, principal, 50));
        ObjectNode first = (ObjectNode) page.withArray("items").get(0);
        first.putObject("metrics").put("secret", "must-never-reach-browser");
        ObjectNode unsafeMetricMaterial = page.deepCopy();
        unsafeMetricMaterial.remove("data_digest");
        page.put("data_digest", canonical.digest(unsafeMetricMaterial));
        assertThrows(IllegalStateException.class,
            () -> bff.requireStandardAuthorityPage("data", page, principal, 50));
        first.remove("metrics");
        first.put("content_base64", "must-never-reach-browser");
        ObjectNode forbiddenMaterial = page.deepCopy();
        forbiddenMaterial.remove("data_digest");
        page.put("data_digest", canonical.digest(forbiddenMaterial));
        assertThrows(IllegalStateException.class,
            () -> bff.requireStandardAuthorityPage("data", page, principal, 50));
        page.withArray("items").removeAll();
        page.put("data_digest", "c".repeat(64));
        assertThrows(IllegalStateException.class,
            () -> bff.requireStandardAuthorityPage("data", page, principal, 50));
    }

    @Test
    void unknownAuthorityCannotBecomeAPath() {
        assertThrows(IllegalArgumentException.class,
            () -> AuthoritativeBff.dashboardPath("../../metadata"));
    }

    @Test
    void standardAuthorityCursorsUseTheirExactPublicContracts() {
        ObjectMapper mapper = new ObjectMapper();
        assertTrue(AuthoritativeBff.standardCursorValid("context",
            mapper.getNodeFactory().textNode("memory:team//release/../approved")));
        assertFalse(AuthoritativeBff.standardCursorValid("context",
            mapper.getNodeFactory().textNode("memory:unsafe?query")));
        assertTrue(AuthoritativeBff.standardCursorValid("supply_chain",
            mapper.getNodeFactory().textNode("a".repeat(2_048))));
        assertFalse(AuthoritativeBff.standardCursorValid("supply_chain",
            mapper.getNodeFactory().textNode("a".repeat(2_049))));
        assertTrue(AuthoritativeBff.standardCursorValid("domain_packs",
            mapper.getNodeFactory().textNode("a".repeat(512))));
        assertFalse(AuthoritativeBff.standardCursorValid("domain_packs",
            mapper.getNodeFactory().textNode("a".repeat(513))));
        assertTrue(AuthoritativeBff.standardCursorValid("sre", mapper.getNodeFactory().textNode(
            "sre:backup/01900000-0000-7000-8000-000000000001")));
        assertFalse(AuthoritativeBff.standardCursorValid("sre", mapper.getNodeFactory().textNode(
            "sre:unknown/01900000-0000-7000-8000-000000000001")));
    }

    @Test
    void authoritativeAuditPageIsTenantRequestAndDigestBound() {
        ObjectMapper mapper = new ObjectMapper();
        CanonicalDigest canonical = new CanonicalDigest(mapper);
        AuthoritativeBff bff = new AuthoritativeBff(null, null, null, null, null, null,
            canonical, mapper);
        UUID tenant = UUID.fromString("01900000-0000-7000-8000-000000000001");
        PrincipalContext principal = new PrincipalContext("auditor@example.test", tenant,
            Set.of("audit-reader"), Set.of(), Set.of(), Set.of(), true,
            Instant.parse("2030-01-02T03:03:05Z"), "urn:agenttrust:acr:mfa");
        ArrayNode items = mapper.createArrayNode();
        ObjectNode receipt = mapper.createObjectNode();
        receipt.put("schema_version", "agenttrust.audit-mutation-receipt.v1");
        receipt.put("operation_id", "01900000-0000-7000-8000-000000000002");
        receipt.put("tenant_id", tenant.toString());
        receipt.put("idempotency_key",
            "audit-query:01900000-0000-7000-8000-000000000003");
        receipt.put("request_digest", "a".repeat(64));
        receipt.put("operation", "AUTHORITATIVE_QUERY");
        receipt.put("resource_ref", "audit://authoritative-query");
        receipt.put("result_digest", canonical.digest(items));
        receipt.put("chain_head", "b".repeat(64));
        receipt.put("issued_at", "2030-01-02T03:04:05Z");
        receipt.put("issuer", "agenttrust-audit-retention");
        receipt.put("key_id", "audit-key-1");
        receipt.put("key_usage", "AUDIT_MUTATION_RECEIPT");
        receipt.put("signature", "A".repeat(86));
        ObjectNode page = mapper.createObjectNode();
        page.put("schema_version", "agenttrust.authoritative-audit-page.v1");
        page.put("authoritative", true);
        page.put("tenant_id", tenant.toString());
        page.put("resource", "summary");
        page.set("items", items);
        page.putNull("next_offset");
        page.set("receipt", receipt);
        Map<String, Object> digestMaterial = new LinkedHashMap<>();
        digestMaterial.put("schema_version", page.path("schema_version"));
        digestMaterial.put("authoritative", page.path("authoritative"));
        digestMaterial.put("tenant_id", page.path("tenant_id"));
        digestMaterial.put("resource", page.path("resource"));
        digestMaterial.put("items", page.path("items"));
        digestMaterial.put("next_offset", page.path("next_offset"));
        digestMaterial.put("receipt", receipt);
        page.put("data_digest", canonical.digest(digestMaterial));

        assertDoesNotThrow(() -> bff.requireAuditPage(page, principal, "summary", 50));
        page.put("data_digest", "c".repeat(64));
        assertThrows(IllegalStateException.class,
            () -> bff.requireAuditPage(page, principal, "summary", 50));
    }

    @Test
    void authoritativeAgentPageIsExactTenantBoundAndDigestBound() {
        ObjectMapper mapper = new ObjectMapper();
        CanonicalDigest canonical = new CanonicalDigest(mapper);
        AuthoritativeBff bff = new AuthoritativeBff(null, null, null, null, null, null,
            canonical, mapper);
        UUID tenant = UUID.fromString("01900000-0000-7000-8000-000000000001");
        PrincipalContext principal = new PrincipalContext("reader@example.test", tenant,
            Set.of("agent-reader"), Set.of(), Set.of(), Set.of(), true,
            Instant.parse("2030-01-02T03:03:05Z"), "urn:agenttrust:acr:mfa");
        ObjectNode item = mapper.createObjectNode();
        item.put("schema_version", "agenttrust.agent-inventory-item.v1");
        item.put("agent_id", "agent:one");
        item.put("display_name", "Agent One");
        item.put("owner_subject", "subject:owner");
        item.put("sponsor_subject", "subject:sponsor");
        item.put("ownership_status", "CONFIRMED");
        item.put("environment", "PRODUCTION");
        item.put("lifecycle", "ACTIVE");
        item.put("agent_type", "coding-agent");
        item.put("bom_digest", "a".repeat(64));
        item.put("endpoint_count", 1);
        item.put("identity_count", 1);
        item.put("tool_count", 2);
        item.put("pack_count", 1);
        item.put("open_findings", 0);
        item.putNull("highest_risk");
        item.put("last_activity_at", "2030-01-02T03:04:05Z");
        item.put("registered_at", "2030-01-01T03:04:05Z");
        item.put("updated_at", "2030-01-02T03:04:05Z");
        ArrayNode items = mapper.createArrayNode().add(item);
        ObjectNode page = mapper.createObjectNode();
        page.put("schema_version", "agenttrust.authoritative-agent-page.v1");
        page.put("authoritative", true);
        page.put("tenant_id", tenant.toString());
        page.put("resource", "summary");
        page.set("items", items);
        page.putNull("next_cursor");
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("schema_version", page.path("schema_version"));
        material.put("authoritative", page.path("authoritative"));
        material.put("tenant_id", page.path("tenant_id"));
        material.put("resource", page.path("resource"));
        material.put("items", page.path("items"));
        material.put("next_cursor", page.path("next_cursor"));
        page.put("data_digest", canonical.digest(material));

        assertDoesNotThrow(() -> bff.requireAgentPage(page, principal, "summary", 50));
        page.put("tenant_id", "01900000-0000-7000-8000-000000000099");
        assertThrows(IllegalStateException.class,
            () -> bff.requireAgentPage(page, principal, "summary", 50));
    }

    @Test
    void dashboardUsesThePolicyAuthorityExactPageWithoutInventingAFlag() {
        ObjectMapper mapper = new ObjectMapper();
        CanonicalDigest canonical = new CanonicalDigest(mapper);
        AuthoritativeBff bff = new AuthoritativeBff(null, null, null, null, null, null,
            canonical, mapper);
        UUID tenant = UUID.fromString("01900000-0000-7000-8000-000000000001");
        PrincipalContext principal = new PrincipalContext("reader@example.test", tenant,
            Set.of("policy-reader"), Set.of(), Set.of(), Set.of(), true,
            Instant.parse("2030-01-02T03:03:05Z"), "urn:agenttrust:acr:mfa");
        ObjectNode page = mapper.createObjectNode();
        page.put("schema_version", "agenttrust.authoritative-policy-page.v1");
        page.put("tenant_id", tenant.toString());
        page.set("items", mapper.createArrayNode());
        page.putNull("next_after_policy_id");

        assertDoesNotThrow(() -> bff.requireDashboardAuthority(
            "policies", page, principal, "summary", 50));
        page.put("authoritative", true);
        assertThrows(ControlUnavailableException.class, () -> bff.requireDashboardAuthority(
            "policies", page, principal, "summary", 50));
    }
}
