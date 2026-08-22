package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.agenttrust.control.AdminModels.PolicyCommandRequest;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PolicyAuthorityGatewayTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final CanonicalDigest CANONICAL = new CanonicalDigest(MAPPER);
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID COMMAND = UUID.fromString("22222222-2222-4222-8222-222222222222");

    @Test
    void actionReceiptIsExactBoundAndStillPending() {
        ObjectNode receipt = receipt();
        assertDoesNotThrow(() -> PolicyAuthorityGateway.requireActionReceipt(
            receipt, COMMAND, TENANT));

        ObjectNode crossTenant = receipt();
        crossTenant.put("ledger_evidence_ref",
            "orchestrator-event://44444444-4444-4444-8444-444444444444/"
                + "33333333-3333-4333-8333-333333333333/1");
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requireActionReceipt(crossTenant, COMMAND, TENANT));

        receipt.put("execution_pending", false);
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requireActionReceipt(receipt, COMMAND, TENANT));

        ObjectNode extended = receipt();
        extended.put("lifecycle_succeeded", true);
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requireActionReceipt(extended, COMMAND, TENANT));
    }

    @Test
    void policyPageRejectsForgedTenantUnknownFieldsAndInvalidKeyset() {
        ObjectNode page = policyPage();
        assertDoesNotThrow(() -> PolicyAuthorityGateway.requirePolicyPage(page, TENANT, null, 50));

        page.put("tenant_id", "33333333-3333-4333-8333-333333333333");
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requirePolicyPage(page, TENANT, null, 50));

        page = policyPage();
        page.put("safe_success", true);
        ObjectNode finalPage = page;
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requirePolicyPage(finalPage, TENANT, null, 50));
    }

    @Test
    void sourceArtifactVerifiesEmbeddedTenantAndCanonicalDigest() {
        ObjectNode source = source();
        ObjectNode page = artifactPage("SOURCES", source);
        assertDoesNotThrow(() -> PolicyAuthorityGateway.requireArtifactPage(page, TENANT,
            "policy-one", PolicyAuthorityGateway.ArtifactType.SOURCES, 50, CANONICAL));

        source.put("author", "subject:forged");
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requireArtifactPage(page, TENANT, "policy-one",
                PolicyAuthorityGateway.ArtifactType.SOURCES, 50, CANONICAL));
    }

    @Test
    void promotionArtifactVerifiesCanonicalTenantPolicyBinding() {
        ObjectNode promotion = MAPPER.createObjectNode();
        promotion.put("environment", "DEV");
        promotion.put("sequence", 1);
        promotion.put("bundle_digest", "b".repeat(64));
        promotion.putNull("previous_bundle_digest");
        promotion.putNull("rollback_of");
        promotion.put("promoted_by", "subject:admin");
        promotion.put("state", "ACTIVE");
        // Map.of cannot represent JSON null; build the exact canonical nullable binding.
        java.util.Map<String, Object> binding = new java.util.LinkedHashMap<>();
        binding.put("tenant_id", TENANT.toString());
        binding.put("policy_id", "policy-one");
        binding.put("environment", "DEV");
        binding.put("sequence", 1L);
        binding.put("bundle_digest", "b".repeat(64));
        binding.put("rollback_of", null);
        promotion.put("promotion_digest", CANONICAL.digest(binding));
        promotion.put("promoted_at", "2030-01-01T00:00:00Z");
        promotion.putNull("completed_at");
        ObjectNode page = artifactPage("PROMOTIONS", promotion);
        assertDoesNotThrow(() -> PolicyAuthorityGateway.requireArtifactPage(page, TENANT,
            "policy-one", PolicyAuthorityGateway.ArtifactType.PROMOTIONS, 50, CANONICAL));

        promotion.put("promotion_digest", "c".repeat(64));
        assertThrows(ControlUnavailableException.class,
            () -> PolicyAuthorityGateway.requireArtifactPage(page, TENANT, "policy-one",
                PolicyAuthorityGateway.ArtifactType.PROMOTIONS, 50, CANONICAL));
    }

    @Test
    void commandRequiresStrongRoleTenantExactPayloadAndBoundApprovals() {
        PrincipalContext principal = new PrincipalContext("subject:author", TENANT,
            Set.of("policy-author"), Set.of(), Set.of("approval:one", "approval:two"), Set.of(),
            true, Instant.now(), "urn:agenttrust:acr:mfa");
        ObjectNode payload = MAPPER.createObjectNode();
        payload.set("source", source());
        PolicyCommandRequest request = new PolicyCommandRequest("agenttrust.policy-command.v1",
            TENANT, COMMAND, "policy-one", "CREATE_DRAFT", 0, payload, Instant.now());
        assertDoesNotThrow(() -> PolicyAuthorityGateway.requireCommand(
            principal, request, COMMAND.toString(), MAPPER));

        payload.put("bypass_review", true);
        assertThrows(ControlDeniedException.class, () -> PolicyAuthorityGateway.requireCommand(
            principal, request, COMMAND.toString(), MAPPER));
    }

    private static ObjectNode receipt() {
        ObjectNode value = MAPPER.createObjectNode();
        value.put("schema_version", "agenttrust.policy-action-receipt.v1");
        value.put("action_id", COMMAND.toString());
        value.put("task_id", "33333333-3333-4333-8333-333333333333");
        value.put("accepted", true);
        value.put("execution_pending", true);
        value.put("ingress_digest", "a".repeat(64));
        value.put("ledger_evidence_ref", "orchestrator-event://" + TENANT
            + "/33333333-3333-4333-8333-333333333333/1");
        value.put("ledger_evidence_digest", "b".repeat(64));
        return value;
    }

    private static ObjectNode policyPage() {
        ObjectNode item = MAPPER.createObjectNode();
        item.put("policy_id", "policy-one");
        item.put("revision", 1);
        item.put("lifecycle_state", "DRAFT");
        item.put("source_digest", "a".repeat(64));
        item.put("author_subject", "subject:author");
        item.putNull("active_bundle_digest");
        item.putNull("active_environment");
        item.put("resource_version", 1);
        item.put("updated_at", "2030-01-01T00:00:00Z");
        ObjectNode value = MAPPER.createObjectNode();
        value.put("schema_version", "agenttrust.authoritative-policy-page.v1");
        value.put("tenant_id", TENANT.toString());
        value.set("items", MAPPER.createArrayNode().add(item));
        value.putNull("next_after_policy_id");
        return value;
    }

    private static ObjectNode artifactPage(String type, ObjectNode item) {
        ObjectNode value = MAPPER.createObjectNode();
        value.put("schema_version", "agenttrust.authoritative-policy-artifact-page.v1");
        value.put("tenant_id", TENANT.toString());
        value.put("policy_id", "policy-one");
        value.put("artifact_type", type);
        value.set("items", MAPPER.createArrayNode().add(item));
        return value;
    }

    private static ObjectNode source() {
        ObjectNode rule = MAPPER.createObjectNode();
        rule.put("rule_id", "deny-write");
        rule.put("subject_pattern", "*");
        rule.put("tool_pattern", "tool:write");
        rule.put("resource_pattern", "repo:*");
        rule.put("decision", "DENY");
        rule.put("maximum_risk", "CRITICAL");
        rule.put("reason_code", "POLICY_DENY_WRITE");
        ArrayNode rules = MAPPER.createArrayNode().add(rule);
        ObjectNode value = MAPPER.createObjectNode();
        value.put("schema_version", "agenttrust.policy-admin.v1");
        value.put("source_id", "policy-one");
        value.put("tenant_id", TENANT.toString());
        value.put("version", "1");
        value.set("rules", rules);
        value.put("default_decision", "DENY");
        value.put("author", "subject:author");
        value.put("source_digest", "");
        value.put("created_at", "2030-01-01T00:00:00Z");
        value.put("source_digest", CANONICAL.digest(value));
        return value;
    }
}
