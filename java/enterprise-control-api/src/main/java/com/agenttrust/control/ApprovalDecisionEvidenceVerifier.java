package com.agenttrust.control;

import com.agenttrust.control.AdminModels.ApprovalIntent;
import com.agenttrust.control.AdminModels.ApprovalIntentReceipt;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Component;

/** Strictly binds and verifies an immutable Approval decision evidence response. */
@Component
public final class ApprovalDecisionEvidenceVerifier {
    private static final String SAFE_RECEIPT_SCHEMA =
        "agenttrust.approval-intent-receipt.v1";
    private static final String RESULT_SCHEMA = "agenttrust.approval-decision-result.v1";
    private static final String RECEIPT_SCHEMA = "agenttrust.approval-decision-evidence.v1";
    private static final String REQUEST_BINDING_SCHEMA =
        "agenttrust.approval-decision-request-binding.v1";
    private static final String KEY_USAGE = "APPROVAL_DECISION_EVIDENCE";
    private static final Set<String> RESULT_FIELDS = Set.of(
        "schema_version", "approval_case", "evidence_receipt");
    private static final Set<String> RECEIPT_FIELDS = Set.of(
        "schema_version", "receipt_id", "tenant_id", "case_id", "task_id", "decision",
        "decision_reason_digest", "request_digest", "decision_digest",
        "idempotency_key_digest", "actor_subject", "principal_assertion_jti",
        "principal_assertion_request_digest", "principal_assertion_digest",
        "approval_case_digest", "action_hash", "step_id", "plan_hash", "parameter_hash",
        "resource", "resource_version", "policy_version", "environment", "risk",
        "case_status", "decided_at", "evidence_ref", "evidence_digest",
        "authority_request_digest", "evidence_outbox_ref", "issuer", "key_id", "key_usage",
        "signature");
    private static final Set<String> CASE_STATUSES = Set.of(
        "PENDING", "APPROVED", "REJECTED", "REVOKED", "EXPIRED", "CONSUMED",
        "POST_REVIEW_REQUIRED");
    private static final Set<String> RISKS = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");
    private final ApprovalAuthoritySignatureVerifier signatures;
    private final CanonicalDigest canonical;
    private final Clock clock;

    public ApprovalDecisionEvidenceVerifier(ApprovalAuthoritySignatureVerifier signatures,
                                            CanonicalDigest canonical) {
        this(signatures, canonical, Clock.systemUTC());
    }

    ApprovalDecisionEvidenceVerifier(ApprovalAuthoritySignatureVerifier signatures,
                                     CanonicalDigest canonical, Clock clock) {
        this.signatures = signatures;
        this.canonical = canonical;
        this.clock = clock;
    }

    public ApprovalIntentReceipt require(JsonNode result, UUID tenantId, UUID caseId,
                                         ApprovalIntent intent, String idempotencyKey,
                                         PrincipalContext principal,
                                         ApprovalPrincipalAssertionSigner.SignedHeader assertion,
        JsonNode decisionRecord) {
        return require(result, tenantId, caseId, intent, idempotencyKey, principal, assertion,
            decisionRecord, true, false);
    }

    public ApprovalIntentReceipt requireReplay(
        JsonNode result, UUID tenantId, UUID caseId, ApprovalIntent intent,
        String idempotencyKey, PrincipalContext principal,
        ApprovalPrincipalAssertionSigner.SignedHeader currentAssertion,
        JsonNode decisionRecord
    ) {
        // Authority idempotency replay returns the originally signed receipt. A retry is
        // intentionally authenticated by a fresh assertion JTI, so only the stable request
        // binding may match the current assertion; the original JTI/digest remain signature-bound.
        return require(result, tenantId, caseId, intent, idempotencyKey, principal,
            currentAssertion, decisionRecord, false, false);
    }

    public ApprovalIntentReceipt requirePersistedReplay(
        JsonNode result, UUID tenantId, UUID caseId, ApprovalIntent intent,
        String idempotencyKey, PrincipalContext principal,
        ApprovalPrincipalAssertionSigner.SignedHeader currentAssertion,
        JsonNode decisionRecord
    ) {
        // VERIFY_ONLY keys are accepted only after this exact full response and evidence_ref
        // crossed fresh verification and were durably bound to a COMPLETED local row.
        return require(result, tenantId, caseId, intent, idempotencyKey, principal,
            currentAssertion, decisionRecord, false, true);
    }

    private ApprovalIntentReceipt require(
        JsonNode result, UUID tenantId, UUID caseId, ApprovalIntent intent,
        String idempotencyKey, PrincipalContext principal,
        ApprovalPrincipalAssertionSigner.SignedHeader assertion, JsonNode decisionRecord,
        boolean bindCurrentAssertion, boolean persistedReplay
    ) {
        if (!AuthorityJson.exact(result, RESULT_FIELDS)
            || !RESULT_SCHEMA.equals(result.path("schema_version").asText())) {
            throw invalid();
        }
        JsonNode approvalCase = result.path("approval_case");
        JsonNode request = approvalCase.path("request");
        JsonNode receipt = result.path("evidence_receipt");
        if (!AuthorityJson.exact(receipt, RECEIPT_FIELDS)
            || !RECEIPT_SCHEMA.equals(receipt.path("schema_version").asText())
            || !AuthorityJson.uuid(receipt.path("receipt_id"))
            || !tenantId.toString().equals(receipt.path("tenant_id").asText())
            || !caseId.toString().equals(receipt.path("case_id").asText())
            || !receipt.path("task_id").equals(request.path("task_id"))
            || !intent.decision().equals(receipt.path("decision").asText())
            || !rawDigest(intent.reason()).equals(receipt.path("decision_reason_digest").asText())
            || !requestDigest(caseId, intent).equals(receipt.path("request_digest").asText())
            || !rawDigest(idempotencyKey).equals(
                receipt.path("idempotency_key_digest").asText())
            || !principal.subject().equals(receipt.path("actor_subject").asText())
            || !AuthorityJson.uuid(receipt.path("principal_assertion_jti"))
            || !assertion.requestDigest().equals(
                receipt.path("principal_assertion_request_digest").asText())
            || !AuthorityJson.digest(receipt.path("principal_assertion_digest"))
            || bindCurrentAssertion && (!assertion.jti().equals(
                receipt.path("principal_assertion_jti").asText())
                || !assertion.assertionDigest().equals(
                    receipt.path("principal_assertion_digest").asText()))
            || !canonical.digest(approvalCase).equals(
                receipt.path("approval_case_digest").asText())
            || !receipt.path("action_hash").equals(request.path("action_hash"))
            || !intent.observedActionHash().equals(receipt.path("action_hash").asText())
            || !receipt.path("step_id").equals(request.path("step_id"))
            || !receipt.path("plan_hash").equals(request.path("plan_hash"))
            || !receipt.path("parameter_hash").equals(request.path("parameter_hash"))
            || !receipt.path("resource").equals(request.path("resource"))
            || !receipt.path("resource_version").equals(request.path("resource_version"))
            || !intent.observedResourceVersion().equals(
                receipt.path("resource_version").asText())
            || !receipt.path("policy_version").equals(request.path("policy_version"))
            || !receipt.path("environment").equals(request.path("environment"))
            || !receipt.path("risk").equals(request.path("risk"))
            || !RISKS.contains(receipt.path("risk").asText())
            || !receipt.path("case_status").equals(approvalCase.path("status"))
            || !CASE_STATUSES.contains(receipt.path("case_status").asText())
            || !receipt.path("decided_at").equals(decisionRecord.path("decided_at"))
            || !AuthorityJson.instant(receipt.path("decided_at"))
            || !receipt.path("decision").equals(decisionRecord.path("decision"))
            || !receipt.path("actor_subject").equals(
                decisionRecord.path("approver_subject"))
            || !decisionRecord.path("strong_auth").isBoolean()
            || !decisionRecord.path("strong_auth").booleanValue()
            || !rawDigest(decisionRecord.path("reason").asText()).equals(
                receipt.path("decision_reason_digest").asText())
            || !AuthorityJson.digest(receipt.path("decision_digest"))
            || !AuthorityJson.digest(receipt.path("evidence_digest"))
            || !AuthorityJson.digest(receipt.path("authority_request_digest"))
            || !AuthorityJson.identifier(receipt.path("issuer"), 256)
            || !receipt.path("key_id").isTextual()
            || !receipt.path("key_id").asText().matches("[A-Za-z0-9_.-]{1,128}")
            || !KEY_USAGE.equals(receipt.path("key_usage").asText())
            || !decisionStatusValid(receipt.path("decision").asText(),
                receipt.path("case_status").asText())) {
            throw invalid();
        }
        Instant decidedAt = Instant.parse(receipt.path("decided_at").asText());
        if (decidedAt.isAfter(clock.instant().plusSeconds(30))) {
            throw invalid();
        }
        String expectedDecisionDigest = canonical.digest(decisionMaterial(receipt));
        String receiptId = receipt.path("receipt_id").asText();
        String expectedEvidenceRef = "urn:agenttrust:approval-decision:" + tenantId + ":"
            + caseId + ":" + receiptId;
        String evidenceRef = receipt.path("evidence_ref").asText();
        String expectedOutboxRef = "outbox://approval-decision-evidence/" + tenantId + "/"
            + receiptId + "/sha256:" + receipt.path("authority_request_digest").asText();
        if (!expectedDecisionDigest.equals(receipt.path("decision_digest").asText())
            || !expectedEvidenceRef.equals(evidenceRef)
            || !expectedOutboxRef.equals(receipt.path("evidence_outbox_ref").asText())) {
            throw invalid();
        }
        ObjectNode unsigned = ((ObjectNode) receipt).deepCopy();
        unsigned.put("evidence_digest", "");
        unsigned.put("signature", "");
        String expectedEvidenceDigest = canonical.digest(unsigned);
        String evidenceDigest = receipt.path("evidence_digest").asText();
        if (!expectedEvidenceDigest.equals(evidenceDigest)) {
            throw invalid();
        }
        if (persistedReplay) {
            signatures.verifyPersisted(receipt.path("issuer").asText(),
                receipt.path("key_id").asText(), decidedAt, evidenceDigest,
                receipt.path("signature").asText());
        } else {
            signatures.verifyFresh(receipt.path("issuer").asText(),
                receipt.path("key_id").asText(), decidedAt, evidenceDigest,
                receipt.path("signature").asText());
        }
        return new ApprovalIntentReceipt(SAFE_RECEIPT_SCHEMA, tenantId, caseId,
            receipt.path("decision").asText(), receipt.path("action_hash").asText(),
            receipt.path("resource_version").asText(), receipt.path("case_status").asText(),
            decidedAt, evidenceRef, evidenceDigest,
            receipt.path("issuer").asText(), receipt.path("key_id").asText());
    }

    private String requestDigest(UUID caseId, ApprovalIntent intent) {
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("schema_version", REQUEST_BINDING_SCHEMA);
        binding.put("case_id", caseId.toString());
        binding.put("decision", GovernedAuthorityGateway.approvalDecisionBody(intent));
        return canonical.digest(binding);
    }

    private static Map<String, Object> decisionMaterial(JsonNode receipt) {
        Map<String, Object> material = new LinkedHashMap<>();
        for (String field : new String[] {
            "schema_version", "tenant_id", "case_id", "task_id", "decision",
            "decision_reason_digest", "request_digest", "idempotency_key_digest",
            "actor_subject", "principal_assertion_jti", "principal_assertion_request_digest",
            "principal_assertion_digest", "approval_case_digest", "action_hash", "step_id",
            "plan_hash", "parameter_hash", "resource", "resource_version", "policy_version",
            "environment", "risk", "case_status", "decided_at"
        }) {
            material.put(field, scalar(receipt.path(field)));
        }
        return material;
    }

    private static Object scalar(JsonNode value) {
        if (!value.isTextual()) {
            throw invalid();
        }
        return value.textValue();
    }

    private static String rawDigest(String value) {
        if (value == null) {
            throw invalid();
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA256_UNAVAILABLE", error);
        }
    }

    private static ControlUnavailableException invalid() {
        return new ControlUnavailableException("CONTROL_APPROVAL_EVIDENCE_INVALID");
    }

    private static boolean decisionStatusValid(String decision, String status) {
        return switch (decision) {
            case "REJECT" -> "REJECTED".equals(status);
            case "POST_REVIEWED" -> "APPROVED".equals(status);
            case "APPROVE" -> Set.of("PENDING", "APPROVED", "POST_REVIEW_REQUIRED")
                .contains(status);
            default -> false;
        };
    }
}
