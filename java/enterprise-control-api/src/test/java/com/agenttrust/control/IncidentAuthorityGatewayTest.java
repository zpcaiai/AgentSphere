package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.agenttrust.control.AdminModels.PrincipalContext;
import com.agenttrust.control.IncidentModels.IncidentCommandRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IncidentAuthorityGatewayTest {
    private static final ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new JavaTimeModule());
    private static final CanonicalDigest CANONICAL = new CanonicalDigest(MAPPER);
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID INCIDENT = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID COMMAND = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID TASK = UUID.fromString("44444444-4444-4444-8444-444444444444");

    @Test
    void exactPageBindsTenantTimelineOrderingAndTerminalState() {
        ObjectNode validPage = page();
        assertDoesNotThrow(() -> IncidentAuthorityGateway.requirePage(validPage, TENANT, null, 50));

        validPage.put("tenant_id", UUID.randomUUID().toString());
        assertThrows(ControlUnavailableException.class,
            () -> IncidentAuthorityGateway.requirePage(validPage, TENANT, null, 50));

        ObjectNode forged = page();
        ((ObjectNode) forged.path("items").path(0).path("timeline").path(0))
            .put("authorization_evidence_ref", "https://attacker.invalid/evidence");
        assertThrows(ControlUnavailableException.class,
            () -> IncidentAuthorityGateway.requirePage(forged, TENANT, null, 50));
    }

    @Test
    void commandRequiresStrongRoleExactTenantAndPayload() {
        PrincipalContext principal = new PrincipalContext("subject:responder", TENANT,
            Set.of("incident-responder"), Set.of(), Set.of(), Set.of(), true, Instant.now(),
            "urn:agenttrust:acr:mfa");
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("owner", "subject:responder");
        payload.put("severity", "P1");
        payload.put("reason_code", "TRIAGE_CONFIRMED");
        IncidentCommandRequest request = new IncidentCommandRequest(
            "agenttrust.incident-command.v1", TENANT, COMMAND, "incident:" + INCIDENT, TASK,
            "TRIAGE", 1, Instant.now(), payload);
        assertDoesNotThrow(() -> IncidentAuthorityGateway.requireCommand(principal, request,
            COMMAND.toString(), MAPPER, CANONICAL));

        payload.put("force_closed", true);
        assertThrows(ControlDeniedException.class,
            () -> IncidentAuthorityGateway.requireCommand(principal, request, COMMAND.toString(),
                MAPPER, CANONICAL));
    }

    @Test
    void receiptCanNeverClaimExecutionSuccess() {
        ObjectNode receipt = receipt();
        assertDoesNotThrow(() -> IncidentAuthorityGateway.requireReceipt(
            receipt, COMMAND, TASK, TENANT));
        receipt.put("ledger_evidence_ref",
            "orchestrator-event://44444444-4444-4444-8444-444444444444/" + TASK + "/1");
        assertThrows(ControlUnavailableException.class,
            () -> IncidentAuthorityGateway.requireReceipt(receipt, COMMAND, TASK, TENANT));
        ObjectNode completed = receipt();
        completed.put("execution_pending", false);
        assertThrows(ControlUnavailableException.class,
            () -> IncidentAuthorityGateway.requireReceipt(completed, COMMAND, TASK, TENANT));
    }

    @Test
    void allFourteenHumanOperationsHaveAnExactValidCommandShape() {
        PrincipalContext principal = new PrincipalContext("subject:commander", TENANT,
            Set.of("incident-responder", "incident-commander", "release-manager"), Set.of(),
            Set.of("approval:one", "approval:two"), Set.of(), true, Instant.now(),
            "urn:agenttrust:acr:mfa");
        for (String operation : Set.of("TRIAGE", "CONTAIN", "INVESTIGATE",
            "PRESERVE_EVIDENCE", "PLAN_REPLAY", "COMPLETE_REPLAY", "PUBLISH_ROOT_CAUSE",
            "BEGIN_REMEDIATION", "TRIGGER_RECERTIFICATION", "EVALUATE_RELEASE",
            "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE", "CLOSE")) {
            IncidentCommandRequest request = new IncidentCommandRequest(
                "agenttrust.incident-command.v1", TENANT, COMMAND,
                Set.of("EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE")
                    .contains(operation) ? "release:release-one" : "incident:" + INCIDENT,
                TASK, operation, 1, Instant.now(), payload(operation));
            assertDoesNotThrow(() -> IncidentAuthorityGateway.requireCommand(principal, request,
                COMMAND.toString(), MAPPER, CANONICAL), operation);
        }
    }

    private static ObjectNode payload(String operation) {
        String digest = "a".repeat(64);
        ObjectNode value = MAPPER.createObjectNode();
        switch (operation) {
            case "TRIAGE" -> {
                value.put("owner", "subject:responder"); value.put("severity", "P1");
                value.put("reason_code", "INCIDENT_TRIAGED");
            }
            case "CONTAIN" -> {
                value.put("reason_code", "INCIDENT_CONTAINED");
                ObjectNode targets = value.putObject("targets");
                targets.put("kill_task", true); targets.put("revoke_credentials", true);
                targets.putArray("isolate_integrations").add("integration:one");
                targets.put("freeze_artifacts", true); value.putNull("break_glass");
            }
            case "INVESTIGATE", "BEGIN_REMEDIATION" ->
                value.put("reason_code", "INCIDENT_WORKFLOW_STARTED");
            case "PRESERVE_EVIDENCE" -> {
                for (String field : Set.of("chain_head_digest", "snapshot_digest",
                    "process_digest", "network_digest", "configuration_digest",
                    "version_digest")) value.put(field, digest);
                value.put("legal_hold_id", "legal-hold:one");
            }
            case "PLAN_REPLAY" -> {
                value.put("replay_id", "55555555-5555-4555-8555-555555555555");
                value.put("mode", "LOGICAL"); value.put("input_digest", digest);
                value.put("source_snapshot_digest", digest);
                value.put("expected_result_digest", digest); value.putArray("resource_refs");
                value.putNull("credential_profile"); value.putNull("fresh_lease_id");
                value.putNull("fresh_lease_digest");
                value.putNull("authorization_lease_expires_at");
            }
            case "COMPLETE_REPLAY" -> {
                value.put("replay_id", "55555555-5555-4555-8555-555555555555");
                value.put("mode", "LOGICAL"); value.put("plan_digest", digest);
            }
            case "PUBLISH_ROOT_CAUSE" -> rootCause(value, digest);
            case "TRIGGER_RECERTIFICATION" -> {
                value.put("root_cause_digest", digest); value.put("release_digest", digest);
                value.putArray("campaigns").add("campaign:one");
            }
            case "EVALUATE_RELEASE" -> releaseGate(value, digest);
            case "START_CANARY" -> {
                value.put("certificate_id", "66666666-6666-4666-8666-666666666666");
                value.put("release_digest", digest); value.put("canary_plan_digest", digest);
                value.put("percentage", 1);
            }
            case "RECORD_CANARY" -> {
                value.put("certificate_id", "66666666-6666-4666-8666-666666666666");
                value.put("release_digest", digest); value.put("metrics_digest", digest);
                value.put("passed", false); value.put("rollback_required", true);
            }
            case "ROLLBACK_RELEASE" -> {
                value.put("release_digest", digest); value.put("target_release_digest", digest);
                value.put("reason_digest", digest);
            }
            case "CLOSE" -> {
                value.put("root_cause_digest", digest);
                value.put("recertification_evidence_ref", "urn:agenttrust:evidence:recertification");
                value.put("recertification_evidence_digest", digest);
            }
            default -> throw new IllegalArgumentException(operation);
        }
        return value;
    }

    private static void rootCause(ObjectNode value, String digest) {
        value.put("report_id", "77777777-7777-4777-8777-777777777777");
        ObjectNode finding = MAPPER.createObjectNode();
        finding.put("finding_id", "finding-one"); finding.put("category", "TRIGGER");
        finding.put("trigger", "trigger-one"); finding.put("system_defect", "defect-one");
        finding.put("detection_gap", "gap-one"); finding.put("recovery_gap", "recovery-one");
        finding.putArray("evidence_refs").add("urn:agenttrust:evidence:finding-one");
        value.putArray("findings").add(finding);
        ObjectNode remediation = MAPPER.createObjectNode();
        remediation.put("remediation_id", "remediation-one");
        remediation.put("finding_id", "finding-one"); remediation.put("policy_ref", "policy:one");
        remediation.put("test_ref", "test:one"); remediation.put("owner", "subject:owner");
        remediation.put("due_at", Instant.now().plusSeconds(3600).toString());
        value.putArray("remediations").add(remediation);
        ObjectNode material = MAPPER.createObjectNode();
        material.set("findings", value.path("findings"));
        material.set("remediations", value.path("remediations"));
        value.put("report_digest", CANONICAL.digest(material));
    }

    private static void releaseGate(ObjectNode value, String digest) {
        value.put("release_digest", digest); ObjectNode definition = value.putObject("definition");
        definition.put("gate_id", "gate-one"); definition.put("version", "1");
        var controls = definition.putArray("required_controls");
        for (String control : Set.of("CONTRACT", "IDENTITY", "POLICY", "SANDBOX",
            "IDEMPOTENCY", "ROLLBACK", "TRACE", "THREAT", "COMPLIANCE",
            "DOMAIN_EVALUATOR")) controls.add(control);
        definition.put("maximum_evidence_age_seconds", 3600);
        ObjectNode material = MAPPER.createObjectNode();
        material.put("gate_id", "gate-one"); material.put("version", "1");
        material.set("required_controls", controls);
        material.put("maximum_evidence_age_seconds", 3600);
        definition.put("definition_digest", CANONICAL.digest(material));
        var evidence = value.putArray("evidence");
        for (var control : controls) {
            ObjectNode item = MAPPER.createObjectNode(); item.put("control_id", control.textValue());
            item.put("evidence_ref", "urn:agenttrust:evidence:" + control.textValue().toLowerCase());
            item.put("evidence_digest", digest); item.put("release_digest", digest);
            item.put("passed", true); item.put("collected_at", Instant.now().minusSeconds(10).toString());
            evidence.add(item);
        }
        value.put("rollback_artifact_digest", digest); value.put("canary_plan_digest", digest);
        value.put("valid_until", Instant.now().plusSeconds(3600).toString());
    }

    private static ObjectNode page() {
        ObjectNode event = MAPPER.createObjectNode();
        event.put("event_id", "55555555-5555-4555-8555-555555555555");
        event.put("sequence", 1);
        event.put("event_type", "DETECT");
        event.putNull("from_status");
        event.put("to_status", "CONTAINED");
        event.put("actor_subject", "detector:runtime");
        event.put("reason_code", "AUTO_CONTAINED");
        event.put("payload_digest", "a".repeat(64));
        event.put("action_hash", "b".repeat(64));
        event.put("ledger_execution_id", "66666666-6666-4666-8666-666666666666");
        event.put("fence_digest", "c".repeat(64));
        event.put("policy_decision_digest", "d".repeat(64));
        event.put("authorization_evidence_ref", "urn:agenttrust:evidence:incident:one");
        event.put("authorization_evidence_digest", "e".repeat(64));
        event.put("occurred_at", "2030-01-01T00:00:00Z");
        ObjectNode incident = MAPPER.createObjectNode();
        incident.put("incident_id", INCIDENT.toString());
        incident.put("correlation_key", "detection:one");
        incident.put("severity", "P1");
        incident.put("status", "CONTAINED");
        incident.put("task_id", TASK.toString());
        incident.put("owner", "subject:responder");
        incident.put("safe_summary", "Bounded incident summary");
        incident.putArray("scope").add("task:" + TASK);
        incident.putArray("evidence_refs").add("evidence://tenant/incident/one");
        incident.put("legal_hold_id", "incident-legal-hold:" + INCIDENT);
        incident.put("resource_version", 1);
        incident.put("created_at", "2030-01-01T00:00:00Z");
        incident.put("updated_at", "2030-01-01T00:00:00Z");
        incident.putArray("timeline").add(event);
        ObjectNode page = MAPPER.createObjectNode();
        page.put("schema_version", "agenttrust.authoritative-incident-page.v1");
        page.put("tenant_id", TENANT.toString());
        page.putArray("items").add(incident);
        page.putNull("next_after_incident_id");
        return page;
    }

    private static ObjectNode receipt() {
        ObjectNode value = MAPPER.createObjectNode();
        value.put("schema_version", "agenttrust.incident-action-receipt.v1");
        value.put("action_id", COMMAND.toString());
        value.put("task_id", TASK.toString());
        value.put("accepted", true);
        value.put("execution_pending", true);
        value.put("ingress_digest", "a".repeat(64));
        value.put("ledger_evidence_ref", "orchestrator-event://" + TENANT + "/" + TASK + "/1");
        value.put("ledger_evidence_digest", "b".repeat(64));
        return value;
    }
}
