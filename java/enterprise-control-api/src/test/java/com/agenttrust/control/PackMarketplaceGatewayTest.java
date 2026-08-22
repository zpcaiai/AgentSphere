package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.MarketplaceModels.MarketplaceCommandRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PackMarketplaceGatewayTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final CanonicalDigest CANONICAL = new CanonicalDigest(MAPPER);
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID COMMAND = UUID.fromString("22222222-2222-4222-8222-222222222222");

    @Test
    void catalogRequiresExactTenantLifecycleAndCanonicalDigest() {
        ObjectNode validPage = page();
        assertDoesNotThrow(() -> PackMarketplaceGateway.requirePage(validPage, TENANT, null, 50,
            CANONICAL));

        ObjectNode forged = page();
        ((ObjectNode) forged.path("installations").path(0)).put("state", "ACTIVE_AND_AUTHORIZED");
        assertThrows(ControlUnavailableException.class,
            () -> PackMarketplaceGateway.requirePage(forged, TENANT, null, 50, CANONICAL));

        ObjectNode wrongDigest = page();
        wrongDigest.put("data_digest", "f".repeat(64));
        assertThrows(ControlUnavailableException.class,
            () -> PackMarketplaceGateway.requirePage(wrongDigest, TENANT, null, 50, CANONICAL));
    }

    @Test
    void typedCommandRequiresStrongExactRoleAndResourceBinding() {
        PrincipalContext principal = new PrincipalContext("subject:market-admin", TENANT,
            Set.of("marketplace-admin"), Set.of(), Set.of(), Set.of(), true, Instant.now(),
            "urn:agenttrust:acr:mfa");
        ObjectNode command = MAPPER.createObjectNode();
        command.put("kind", "CONFIGURE_TENANT_CATALOG");
        command.put("control_plane_version", "1.2.3");
        command.put("region", "cn-east-1");
        command.putArray("entitlements").add("energy");
        command.putArray("allowed_compatibility").add("agenttrust-1");
        command.put("minimum_publisher_trust", "VERIFIED");
        command.put("maximum_risk", "HIGH");
        MarketplaceCommandRequest request = new MarketplaceCommandRequest(
            "agenttrust.marketplace-command.v1", TENANT, COMMAND, "tenant-catalog", 0,
            command, Instant.now());
        assertDoesNotThrow(() -> PackMarketplaceGateway.requireCommand(
            principal, request, COMMAND.toString(), MAPPER));

        command.put("auto_activate_production", true);
        assertThrows(ControlDeniedException.class,
            () -> PackMarketplaceGateway.requireCommand(principal, request, COMMAND.toString(),
                MAPPER));
    }

    @Test
    void receiptMeansAdmissionOnly() {
        ObjectNode receipt = MAPPER.createObjectNode();
        receipt.put("schema_version", "agenttrust.marketplace-action-receipt.v1");
        receipt.put("action_id", COMMAND.toString());
        receipt.put("task_id", "33333333-3333-4333-8333-333333333333");
        receipt.put("accepted", true);
        receipt.put("execution_pending", true);
        receipt.put("ingress_digest", "a".repeat(64));
        receipt.put("ledger_evidence_ref", "orchestrator-event://" + TENANT
            + "/33333333-3333-4333-8333-333333333333/1");
        receipt.put("ledger_evidence_digest", "b".repeat(64));
        assertDoesNotThrow(() -> PackMarketplaceGateway.requireReceipt(receipt, COMMAND, TENANT));
        receipt.put("ledger_evidence_ref",
            "orchestrator-event://44444444-4444-4444-8444-444444444444/"
                + "33333333-3333-4333-8333-333333333333/1");
        assertThrows(ControlUnavailableException.class,
            () -> PackMarketplaceGateway.requireReceipt(receipt, COMMAND, TENANT));
        receipt.put("ledger_evidence_ref", "orchestrator-event://" + TENANT
            + "/33333333-3333-4333-8333-333333333333/1");
        receipt.put("activated", true);
        assertThrows(ControlUnavailableException.class,
            () -> PackMarketplaceGateway.requireReceipt(receipt, COMMAND, TENANT));
    }

    @Test
    void allSixteenTypedLifecycleCommandsHaveAnExactResourceBinding() {
        PrincipalContext principal = new PrincipalContext("subject:market-admin", TENANT,
            Set.of("marketplace-publisher-admin", "marketplace-publisher-reviewer",
                "marketplace-admin", "marketplace-publisher", "marketplace-release-reviewer",
                "marketplace-installer", "marketplace-install-reviewer",
                "marketplace-canary-controller", "marketplace-security-admin",
                "marketplace-operator"), Set.of(), Set.of("approval:one", "approval:two"),
            Set.of(), true, Instant.now(), "urn:agenttrust:acr:mfa");
        for (String kind : Set.of("ONBOARD_PUBLISHER", "VERIFY_PUBLISHER_KEY",
            "SET_PUBLISHER_TRUST", "CONFIGURE_TENANT_CATALOG", "SUBMIT_RELEASE",
            "REVIEW_RELEASE", "REQUEST_INSTALLATION", "APPROVE_INSTALLATION", "INSTALL",
            "ACTIVATE", "PLAN_UPGRADE", "RECORD_CANARY", "UPGRADE", "ROLLBACK",
            "DEACTIVATE", "REVOKE_RELEASE")) {
            ObjectNode command = command(kind);
            MarketplaceCommandRequest request = new MarketplaceCommandRequest(
                "agenttrust.marketplace-command.v1", TENANT, COMMAND, resource(command), 0,
                command, Instant.now());
            assertDoesNotThrow(() -> PackMarketplaceGateway.requireCommand(
                principal, request, COMMAND.toString(), MAPPER), kind);
        }
    }

    private static ObjectNode command(String kind) {
        String digest = "a".repeat(64);
        String release = "44444444-4444-4444-8444-444444444444";
        String installation = "55555555-5555-4555-8555-555555555555";
        String plan = "66666666-6666-4666-8666-666666666666";
        ObjectNode value = MAPPER.createObjectNode(); value.put("kind", kind);
        switch (kind) {
            case "ONBOARD_PUBLISHER" -> {
                value.put("publisher_id", "publisher:one");
                value.put("publisher_subject", "subject:publisher");
                value.put("identity_digest", digest);
                value.put("responsibility_contact", "owner@example.com");
                value.put("home_region", "cn-east-1");
            }
            case "VERIFY_PUBLISHER_KEY" -> {
                value.put("publisher_id", "publisher:one"); value.put("key_id", "key:one");
                value.put("algorithm", "Ed25519"); value.put("public_key", "A".repeat(43));
                value.put("key_fingerprint", digest);
                value.put("not_before", Instant.now().minusSeconds(10).toString());
                value.put("expires_at", Instant.now().plusSeconds(3600).toString());
                value.put("review_digest", digest);
            }
            case "SET_PUBLISHER_TRUST" -> {
                value.put("publisher_id", "publisher:one"); value.put("trust", "SUSPENDED");
                value.put("reason_digest", digest);
            }
            case "CONFIGURE_TENANT_CATALOG" -> {
                value.put("control_plane_version", "1.0.0"); value.put("region", "cn-east-1");
                value.putArray("entitlements").add("energy");
                value.putArray("allowed_compatibility").add("agenttrust-1");
                value.put("minimum_publisher_trust", "VERIFIED"); value.put("maximum_risk", "HIGH");
            }
            case "SUBMIT_RELEASE" -> submitRelease(value, digest, release);
            case "REVIEW_RELEASE" -> {
                value.put("release_id", release); value.put("decision", "REJECT");
                value.put("review_digest", digest);
            }
            case "REQUEST_INSTALLATION" -> {
                value.put("installation_id", installation); value.put("release_id", release);
                value.put("environment", "staging"); value.put("request_reason_digest", digest);
            }
            case "APPROVE_INSTALLATION" -> {
                value.put("installation_id", installation); value.put("decision", "REJECT");
                value.put("approval_digest", digest);
            }
            case "INSTALL" -> {
                value.put("installation_id", installation); value.put("artifact_receipt_digest", digest);
            }
            case "ACTIVATE" -> {
                value.put("installation_id", installation); value.putNull("production_certificate_digest");
            }
            case "PLAN_UPGRADE" -> {
                value.put("plan_id", plan); value.put("current_installation_id", installation);
                value.put("target_installation_id", "77777777-7777-4777-8777-777777777777");
                value.put("migration_digest", digest); value.put("rollback_digest", digest);
                value.put("canary_percent", 1);
            }
            case "RECORD_CANARY" -> {
                value.put("plan_id", plan); value.put("passed", false); value.put("observed_samples", 1);
                value.put("evidence_ref", "urn:agenttrust:evidence:canary-one");
                value.put("evidence_digest", digest);
            }
            case "UPGRADE" -> {
                value.put("plan_id", plan); value.putNull("production_certificate_digest");
            }
            case "ROLLBACK", "DEACTIVATE" -> {
                value.put("installation_id", installation); value.put("reason_digest", digest);
            }
            case "REVOKE_RELEASE" -> {
                value.put("release_id", release); value.put("reason_code", "SECURITY_REVOKED");
                value.put("reason_digest", digest); value.put("running_task_response", "KILL");
            }
            default -> throw new IllegalArgumentException(kind);
        }
        return value;
    }

    private static void submitRelease(ObjectNode value, String digest, String release) {
        value.put("release_id", release); ObjectNode manifest = value.putObject("manifest");
        manifest.put("schema_version", "agenttrust.domain-pack.v1");
        manifest.put("pack_id", "pack:one"); manifest.put("version", "1.0.0");
        manifest.put("digest", digest); manifest.put("publisher_identity", "publisher:one");
        manifest.put("description", "Safe pack"); ObjectNode permissions = manifest.putObject("permissions");
        for (String field : Set.of("tools", "network_destinations", "data_classes",
            "secret_scopes", "executors", "approval_scopes")) permissions.putArray(field);
        ObjectNode tool = MAPPER.createObjectNode(); tool.put("tool_id", "tool:read");
        tool.put("effect_class", "PURE"); tool.put("approval_required", false);
        tool.putNull("compensation_ref"); tool.putNull("irreversible_reason");
        tool.put("executor_template", "executor:read"); manifest.putArray("tools").add(tool);
        manifest.put("policy_bundle_ref", "policy:one"); manifest.put("evaluator_ref", "evaluator:one");
        manifest.putArray("compensation_refs"); manifest.putArray("threat_scenario_refs").add("threat:one");
        manifest.putArray("artifact_refs").add("registry.example/pack@sha256:" + digest);
        manifest.putArray("compatibility").add("agenttrust-1");
        ObjectNode signature = manifest.putObject("signature"); signature.put("key_id", "key:one");
        signature.put("publisher_identity", "publisher:one"); signature.put("subject_digest", digest);
        signature.put("signature", "A".repeat(86)); signature.put("signed_at", Instant.now().toString());
        ObjectNode certificate = value.putObject("release_certificate");
        certificate.put("schema_version", "agenttrust.incident-release.v1");
        certificate.put("certificate_id", "88888888-8888-4888-8888-888888888888");
        certificate.put("release_digest", digest); certificate.put("gate_id", "gate:one");
        certificate.put("gate_version", "1"); certificate.put("definition_digest", digest);
        certificate.putObject("evidence_digests").put("CONTRACT", digest);
        certificate.put("valid_from", Instant.now().minusSeconds(10).toString());
        certificate.put("valid_until", Instant.now().plusSeconds(3600).toString());
        certificate.put("engine_certificate_only", true); certificate.put("production_closure", false);
        certificate.put("key_id", "key:gate"); certificate.put("signature", "A".repeat(86));
        value.put("visibility", "PRIVATE"); value.put("entitlement", "energy");
        value.putArray("allowed_regions").add("cn-east-1"); value.put("risk_rating", "HIGH");
        value.put("minimum_publisher_trust", "VERIFIED");
        value.put("minimum_control_plane_version", "1.0.0");
    }

    private static String resource(ObjectNode command) {
        return switch (command.path("kind").textValue()) {
            case "ONBOARD_PUBLISHER", "VERIFY_PUBLISHER_KEY", "SET_PUBLISHER_TRUST" ->
                command.path("publisher_id").textValue();
            case "CONFIGURE_TENANT_CATALOG" -> "tenant-catalog";
            case "SUBMIT_RELEASE", "REVIEW_RELEASE", "REVOKE_RELEASE" ->
                command.path("release_id").textValue();
            case "REQUEST_INSTALLATION", "APPROVE_INSTALLATION", "INSTALL", "ACTIVATE",
                "ROLLBACK", "DEACTIVATE" -> command.path("installation_id").textValue();
            default -> command.path("plan_id").textValue();
        };
    }

    private static ObjectNode page() {
        ObjectNode release = MAPPER.createObjectNode();
        release.put("release_id", "44444444-4444-4444-8444-444444444444");
        release.put("pack_id", "energy.safety");
        release.put("version", "1.0.0");
        release.put("pack_digest", "a".repeat(64));
        release.put("publisher_id", "publisher:verified");
        release.put("visibility", "TENANT");
        release.put("entitlement", "energy");
        release.putArray("allowed_regions").add("cn-east-1");
        release.put("risk_rating", "HIGH");
        release.putArray("compatibility").add("agenttrust-1");
        release.put("certificate_digest", "b".repeat(64));
        release.put("review_status", "PUBLISHED");
        release.put("updated_at", "2030-01-01T00:00:00Z");
        ObjectNode installation = MAPPER.createObjectNode();
        installation.put("installation_id", "55555555-5555-4555-8555-555555555555");
        installation.put("release_id", "44444444-4444-4444-8444-444444444444");
        installation.put("pack_id", "energy.safety");
        installation.put("version", "1.0.0");
        installation.put("environment", "staging");
        installation.put("state", "INSTALLED");
        installation.put("permission_expansion", false);
        installation.putNull("previous_installation_id");
        installation.put("updated_at", "2030-01-01T00:00:00Z");
        ObjectNode page = MAPPER.createObjectNode();
        page.put("schema_version", "agenttrust.authoritative-pack-page.v1");
        page.put("authoritative", true);
        page.put("tenant_id", TENANT.toString());
        page.putArray("releases").add(release);
        page.putArray("installations").add(installation);
        page.putNull("next_after_pack_id");
        page.put("data_digest", "");
        ObjectNode material = page.deepCopy();
        material.remove("data_digest");
        page.put("data_digest", CANONICAL.digest(material));
        return page;
    }
}
