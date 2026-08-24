package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

class AuthorityJsonTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void approvalReviewContextIsStrictlyDomainBound() throws Exception {
        JsonNode coding = mapper.readTree("""
            {"domain":"CODING","details":{
              "diff_artifact_ref":"artifact://sha256/%s",
              "command_summary":"Apply the reviewed repository patch",
              "network_scope":"egress:none",
              "rollback_summary":"Restore the reviewed parent revision"}}
            """.formatted("a".repeat(64)));
        assertTrue(AuthorityJson.approvalReviewContext(coding, false));
        assertFalse(AuthorityJson.approvalReviewContext(coding, true));

        JsonNode industrial = mapper.readTree("""
            {"domain":"INDUSTRIAL","details":{
              "current_value":"42.0 C","target_value":"43.0 C",
              "allowed_range":"40.0 C to 45.0 C",
              "interlock_summary":"SIS permissive and operator supervision required",
              "physical_impact":"One degree setpoint increase on line 1"}}
            """);
        assertTrue(AuthorityJson.approvalReviewContext(industrial, true));
        assertFalse(AuthorityJson.approvalReviewContext(industrial, false));
    }

    @Test
    void approvalReviewContextRejectsSecretsAndUnknownFields() throws Exception {
        JsonNode secret = mapper.readTree("""
            {"domain":"CODING","details":{
              "diff_artifact_ref":"artifact://sha256/%s",
              "command_summary":"Authorization: Bearer production-secret",
              "network_scope":"egress:none",
              "rollback_summary":"Restore the reviewed parent revision"}}
            """.formatted("a".repeat(64)));
        assertFalse(AuthorityJson.approvalReviewContext(secret, false));

        JsonNode extension = mapper.readTree("""
            {"domain":"INDUSTRIAL","details":{
              "current_value":"42.0 C","target_value":"43.0 C",
              "allowed_range":"40.0 C to 45.0 C",
              "interlock_summary":"SIS permissive",
              "physical_impact":"One degree setpoint increase",
              "raw_device_frame":"must never reach the browser"}}
            """);
        assertFalse(AuthorityJson.approvalReviewContext(extension, true));
    }

    @Test
    void approvalEvidenceReferencesUseOnlySafeSchemes() throws Exception {
        assertTrue(AuthorityJson.approvalEvidenceReference(
            mapper.readTree("\"evidence://tenant/case/one\"")));
        assertTrue(AuthorityJson.approvalEvidenceReference(
            mapper.readTree("\"urn:agenttrust:ledger-evidence:case-one\"")));
        assertFalse(AuthorityJson.approvalEvidenceReference(
            mapper.readTree("\"https://example.invalid/evidence?token=secret\"")));
        assertFalse(AuthorityJson.approvalEvidenceReference(mapper.readTree("\"evidence://\"")));
        assertFalse(AuthorityJson.approvalEvidenceReference(
            mapper.readTree("\"evidence://case/token=production-secret\"")));
    }

    @Test
    void signedReviewEvidenceIsExactlyBoundToTheApprovalRequest() throws Exception {
        ObjectNode request = (ObjectNode) mapper.readTree("""
            {"tenant_id":"11111111-1111-4111-8111-111111111111",
             "task_id":"22222222-2222-4222-8222-222222222222",
             "action_hash":"%s","resource":"repo:a","resource_version":"commit:one",
             "policy_version":"policy:v1","environment":"production","risk":"HIGH",
             "review_context":{"domain":"CODING","details":{
               "diff_artifact_ref":"artifact://sha256/%s",
               "command_summary":"Apply the reviewed repository patch",
               "network_scope":"egress:none","rollback_summary":"Restore parent revision"}}}
            """.formatted("a".repeat(64), "d".repeat(64)));
        CanonicalDigest canonical = new CanonicalDigest(mapper);
        ObjectNode material = mapper.createObjectNode();
        material.put("schema_version", "agenttrust.approval-review-material.v1");
        material.set("tenant_id", request.path("tenant_id"));
        material.set("task_id", request.path("task_id"));
        material.set("canonical_action_hash", request.path("action_hash"));
        for (String field : new String[] {"resource", "resource_version", "policy_version",
                "environment", "risk"}) {
            material.set(field, request.path(field));
        }
        material.set("review_context", request.path("review_context"));
        material.put("risk_package_ref", "evidence://risk-package/one");
        material.put("risk_package_digest", "e".repeat(64));
        material.put("state_snapshot_ref", "evidence://state-snapshot/one");
        material.put("state_snapshot_digest", "f".repeat(64));

        String eventId = "33333333-3333-4333-8333-333333333333";
        ObjectNode draft = mapper.createObjectNode();
        draft.put("schema_version", "agenttrust.evidence.v1");
        draft.set("tenant_id", request.path("tenant_id"));
        draft.set("task_id", request.path("task_id"));
        draft.put("event_type", "APPROVAL_REVIEW_PREPARED");
        draft.put("actor_subject", "review-fact-authority");
        draft.put("source_service", "URI:spiffe://agenttrust/domain-risk-authority");
        draft.put("trace_id", "44444444-4444-4444-8444-444444444444");
        draft.put("span_id", eventId);
        draft.put("payload_hash", canonical.digest(material));
        draft.put("safe_summary", "Approval coding review facts prepared");
        draft.putArray("artifact_refs")
            .add(request.path("review_context").path("details").path("diff_artifact_ref"))
            .add(material.path("risk_package_ref")).add(material.path("state_snapshot_ref"));
        draft.put("occurred_at", "2026-08-24T00:00:00Z");

        ObjectNode authority = mapper.createObjectNode();
        authority.put("schema_version", "agenttrust.authority-evidence-event-request.v1");
        authority.set("tenant_id", request.path("tenant_id"));
        authority.set("task_id", request.path("task_id"));
        authority.put("authority_event_id", eventId);
        authority.put("idempotency_key", "approval-review:one");
        authority.put("source_kind", "AUTHENTICATED_EVENT");
        authority.putNull("control_binding");
        authority.set("event", draft);
        authority.put("requested_at", "2026-08-24T00:00:00Z");

        ObjectNode signedEvent = mapper.createObjectNode();
        signedEvent.put("schema_version", "agenttrust.evidence.v1");
        signedEvent.put("event_id", eventId);
        signedEvent.put("sequence", 1);
        signedEvent.put("previous_hash", "0".repeat(64));
        signedEvent.put("event_hash", "");
        signedEvent.put("key_id", "evidence-key");
        signedEvent.put("signature", "");
        signedEvent.set("draft", draft);
        signedEvent.put("event_hash", canonical.digest(signedEvent));
        signedEvent.put("signature", "A".repeat(86));

        ObjectNode receipt = mapper.createObjectNode();
        receipt.put("schema_version", "agenttrust.signed-authority-evidence-receipt.v1");
        receipt.set("tenant_id", request.path("tenant_id"));
        receipt.set("task_id", request.path("task_id"));
        receipt.put("authority_event_id", eventId);
        receipt.put("idempotency_key", "approval-review:one");
        receipt.put("source_kind", "AUTHENTICATED_EVENT");
        receipt.put("request_digest", canonical.digest(authority));
        receipt.put("payload_digest", canonical.digest(material));
        receipt.put("evidence_ref", "");
        receipt.put("evidence_digest", "");
        receipt.set("event", signedEvent);
        receipt.put("persisted_at", "2026-08-24T00:00:00Z");
        receipt.put("issuer", "evidence-authority");
        receipt.put("key_id", "evidence-key");
        receipt.put("key_usage", "AUTHORITY_EVIDENCE_RECEIPT");
        receipt.put("signature", "");
        receipt.put("evidence_ref", "evidence://authority-event/"
            + request.path("tenant_id").asText() + "/" + request.path("task_id").asText()
            + "/" + eventId + "/" + signedEvent.path("event_hash").asText());
        receipt.put("evidence_digest", canonical.digest(receipt));
        receipt.put("signature", "B".repeat(86));

        ObjectNode evidence = mapper.createObjectNode();
        evidence.put("schema_version", "agenttrust.approval-review-evidence-binding.v1");
        evidence.set("material", material);
        evidence.set("authority_request", authority);
        evidence.set("receipt", receipt);
        assertTrue(AuthorityJson.signedApprovalReviewEvidence(evidence, request,
            mapper.readTree("\"2026-08-24T00:00:01Z\""), canonical));
        material.put("canonical_action_hash", "b".repeat(64));
        assertFalse(AuthorityJson.signedApprovalReviewEvidence(evidence, request,
            mapper.readTree("\"2026-08-24T00:00:01Z\""), canonical));
    }

    @Test
    void safeReviewTextRejectsEveryControlCharacter() throws Exception {
        assertFalse(AuthorityJson.safeReviewText(mapper.readTree("\"operator\\tsecret\""), 128));
        assertFalse(AuthorityJson.safeReviewText(mapper.readTree("\"operator\\u007fsecret\""), 128));
    }
}
