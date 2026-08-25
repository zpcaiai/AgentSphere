package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ApprovalDecisionEvidenceVerifierTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final CanonicalDigest CANONICAL = new CanonicalDigest(MAPPER);
    private static final Instant NOW = Instant.parse("2026-08-24T05:00:00Z");
    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID CASE = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID TASK = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID STEP = UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final UUID RECEIPT = UUID.fromString("55555555-5555-4555-8555-555555555555");
    @TempDir Path temporary;

    @Test
    void verifiesExactAuthorityEnvelopeAndReturnsOnlyTheSafeProjection() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ApprovalDecisionEvidenceVerifier verifier = verifier(pair);
        Fixture fixture = fixture(pair);

        var safe = verifier.require(fixture.result(), TENANT, CASE, fixture.intent(),
            "approval-key-1", fixture.principal(), fixture.assertion(), fixture.decisionRecord());

        assertEquals("agenttrust.approval-intent-receipt.v1", safe.schemaVersion());
        assertEquals(TENANT, safe.tenantId());
        assertEquals(CASE, safe.caseId());
        assertEquals("APPROVE", safe.decision());
        assertEquals("APPROVED", safe.caseStatus());
        assertEquals("a".repeat(64), safe.actionHash());
        assertEquals("resource-v7", safe.resourceVersion());
        assertEquals("agenttrust-approval", safe.authorityIssuer());
        assertEquals("approval-key-1", safe.authorityKeyId());
    }

    @Test
    void rejectsUnknownFieldsBindingChangesAndSignatureTampering() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ApprovalDecisionEvidenceVerifier verifier = verifier(pair);
        Fixture fixture = fixture(pair);

        for (Consumer<ObjectNode> tamper : java.util.List.<Consumer<ObjectNode>>of(
            value -> receipt(value).put("untrusted", true),
            value -> receipt(value).put("case_id",
                "77777777-7777-4777-8777-777777777777"),
            value -> receipt(value).put("action_hash", "0".repeat(64)),
            value -> receipt(value).put("resource", "agent://production/other"),
            value -> receipt(value).put("resource_version", "resource-v8"),
            value -> receipt(value).put("request_digest", "0".repeat(64)),
            value -> receipt(value).put("idempotency_key_digest", "0".repeat(64)),
            value -> receipt(value).put("decision_reason_digest", "0".repeat(64)),
            value -> receipt(value).put("approval_case_digest", "0".repeat(64)),
            value -> receipt(value).put("decision_digest", "0".repeat(64)),
            value -> receipt(value).put("evidence_digest", "0".repeat(64)),
            value -> receipt(value).put("authority_request_digest", "0".repeat(64)),
            value -> receipt(value).put("evidence_outbox_ref", "outbox://wrong"),
            value -> receipt(value).put("issuer", "other-issuer"),
            value -> receipt(value).put("key_id", "other-key"),
            value -> receipt(value).put("key_usage", "OTHER"),
            value -> receipt(value).put("signature", "A".repeat(86)),
            value -> receipt(value).put("case_status", "CONSUMED"),
            value -> receipt(value).put("decided_at", NOW.plusSeconds(31).toString())
        )) {
            ObjectNode changed = fixture.result().deepCopy();
            tamper.accept(changed);
            assertInvalid(verifier, fixture, changed);
        }
    }

    @Test
    void sameKeyReplayAcceptsFreshAssertionJtiButKeepsStableRequestBinding() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ApprovalDecisionEvidenceVerifier verifier = verifier(pair);
        Fixture fixture = fixture(pair);
        var freshAssertion = new ApprovalPrincipalAssertionSigner.SignedHeader("fresh-header",
            fixture.assertion().requestDigest(), "9".repeat(64),
            "88888888-8888-4888-8888-888888888888");

        assertThrows(ControlUnavailableException.class, () -> verifier.require(fixture.result(),
            TENANT, CASE, fixture.intent(), "approval-key-1", fixture.principal(),
            freshAssertion, fixture.decisionRecord()));
        assertEquals(fixture.result().path("evidence_receipt").path("evidence_ref").asText(),
            verifier.requireReplay(fixture.result(), TENANT, CASE, fixture.intent(),
                "approval-key-1", fixture.principal(), freshAssertion,
                fixture.decisionRecord()).evidenceRef());
        assertEquals(fixture.result().path("evidence_receipt").path("evidence_ref").asText(),
            verifier.requirePersistedReplay(fixture.result(), TENANT, CASE, fixture.intent(),
                "approval-key-1", fixture.principal(), freshAssertion,
                fixture.decisionRecord()).evidenceRef());

        var changedBinding = new ApprovalPrincipalAssertionSigner.SignedHeader("fresh-header",
            "0".repeat(64), "9".repeat(64),
            "88888888-8888-4888-8888-888888888888");
        assertThrows(ControlUnavailableException.class, () -> verifier.requireReplay(
            fixture.result(), TENANT, CASE, fixture.intent(), "approval-key-1",
            fixture.principal(), changedBinding, fixture.decisionRecord()));
    }

    private ApprovalDecisionEvidenceVerifier verifier(KeyPair pair) throws Exception {
        Path principalKey = temporary.resolve("principal.seed");
        ApprovalIntegrationProperties properties = ApprovalTestProperties.create(principalKey);
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        Map<String, Object> key = Map.of(
            "key_id", "approval-key-1", "algorithm", "Ed25519",
            "public_key_base64url",
            Base64.getUrlEncoder().withoutPadding().encodeToString(raw),
            "status", "ACTIVE", "not_before", "2026-01-01T00:00:00Z",
            "expires_at", "2027-01-01T00:00:00Z");
        Files.writeString(properties.authorityVerificationKeyringFile(),
            MAPPER.writeValueAsString(Map.of(
                "schema_version", "agenttrust.approval-decision-evidence-keyring.v1",
                "issuer", "agenttrust-approval", "keys", java.util.List.of(key))),
            StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(properties.authorityVerificationKeyringFile(),
            Set.of(PosixFilePermission.OWNER_READ));
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        return new ApprovalDecisionEvidenceVerifier(
            new ApprovalAuthoritySignatureVerifier(properties, clock), CANONICAL, clock);
    }

    private static Fixture fixture(KeyPair pair) throws Exception {
        String reason = "exact reason\nkept";
        var intent = new AdminModels.ApprovalIntent("agenttrust.approval-intent.v1", CASE,
            "APPROVE", reason, "a".repeat(64), "resource-v7");
        var principal = new AdminModels.PrincipalContext("approver:one", TENANT,
            Set.of("approver"), Set.of(), Set.of(), Set.of(), true,
            NOW.minusSeconds(60), "urn:agenttrust:acr:mfa");
        String assertionRequestDigest = "b".repeat(64);
        var assertion = new ApprovalPrincipalAssertionSigner.SignedHeader("header",
            assertionRequestDigest, "c".repeat(64),
            "66666666-6666-4666-8666-666666666666");

        ObjectNode request = MAPPER.createObjectNode();
        request.put("task_id", TASK.toString());
        request.put("step_id", STEP.toString());
        request.put("action_hash", "a".repeat(64));
        request.put("plan_hash", "d".repeat(64));
        request.put("parameter_hash", "e".repeat(64));
        request.put("resource", "agent://production/one");
        request.put("resource_version", "resource-v7");
        request.put("policy_version", "policy-v3");
        request.put("environment", "PRODUCTION");
        request.put("risk", "HIGH");
        ObjectNode decisionRecord = MAPPER.createObjectNode();
        decisionRecord.put("approver_subject", principal.subject());
        decisionRecord.put("decision", "APPROVE");
        decisionRecord.put("reason", reason);
        decisionRecord.put("decided_at", NOW.toString());
        decisionRecord.put("strong_auth", true);
        ObjectNode approvalCase = MAPPER.createObjectNode();
        approvalCase.set("request", request);
        approvalCase.put("status", "APPROVED");
        approvalCase.putArray("decisions").add(decisionRecord);

        ObjectNode receipt = MAPPER.createObjectNode();
        receipt.put("schema_version", "agenttrust.approval-decision-evidence.v1");
        receipt.put("receipt_id", RECEIPT.toString());
        receipt.put("tenant_id", TENANT.toString());
        receipt.put("case_id", CASE.toString());
        receipt.put("task_id", TASK.toString());
        receipt.put("decision", "APPROVE");
        receipt.put("decision_reason_digest", rawDigest(reason));
        Map<String, Object> requestBinding = new LinkedHashMap<>();
        requestBinding.put("schema_version",
            "agenttrust.approval-decision-request-binding.v1");
        requestBinding.put("case_id", CASE.toString());
        requestBinding.put("decision", GovernedAuthorityGateway.approvalDecisionBody(intent));
        receipt.put("request_digest", CANONICAL.digest(requestBinding));
        receipt.put("decision_digest", "");
        receipt.put("idempotency_key_digest", rawDigest("approval-key-1"));
        receipt.put("actor_subject", principal.subject());
        receipt.put("principal_assertion_jti", assertion.jti());
        receipt.put("principal_assertion_request_digest", assertionRequestDigest);
        receipt.put("principal_assertion_digest", assertion.assertionDigest());
        receipt.put("approval_case_digest", CANONICAL.digest(approvalCase));
        receipt.put("action_hash", "a".repeat(64));
        receipt.put("step_id", STEP.toString());
        receipt.put("plan_hash", "d".repeat(64));
        receipt.put("parameter_hash", "e".repeat(64));
        receipt.put("resource", "agent://production/one");
        receipt.put("resource_version", "resource-v7");
        receipt.put("policy_version", "policy-v3");
        receipt.put("environment", "PRODUCTION");
        receipt.put("risk", "HIGH");
        receipt.put("case_status", "APPROVED");
        receipt.put("decided_at", NOW.toString());
        receipt.put("evidence_ref", "urn:agenttrust:approval-decision:" + TENANT + ":" + CASE
            + ":" + RECEIPT);
        receipt.put("evidence_digest", "");
        receipt.put("authority_request_digest", "f".repeat(64));
        receipt.put("evidence_outbox_ref", "outbox://approval-decision-evidence/" + TENANT + "/"
            + RECEIPT + "/sha256:" + "f".repeat(64));
        receipt.put("issuer", "agenttrust-approval");
        receipt.put("key_id", "approval-key-1");
        receipt.put("key_usage", "APPROVAL_DECISION_EVIDENCE");
        receipt.put("signature", "");

        ObjectNode decisionMaterial = MAPPER.createObjectNode();
        for (String field : new String[] {
            "schema_version", "tenant_id", "case_id", "task_id", "decision",
            "decision_reason_digest", "request_digest", "idempotency_key_digest",
            "actor_subject", "principal_assertion_jti", "principal_assertion_request_digest",
            "principal_assertion_digest", "approval_case_digest", "action_hash", "step_id",
            "plan_hash", "parameter_hash", "resource", "resource_version", "policy_version",
            "environment", "risk", "case_status", "decided_at"
        }) {
            decisionMaterial.set(field, receipt.path(field));
        }
        receipt.put("decision_digest", CANONICAL.digest(decisionMaterial));
        receipt.put("evidence_digest", CANONICAL.digest(receipt));
        receipt.put("signature", sign(pair, receipt.path("evidence_digest").asText()));

        ObjectNode result = MAPPER.createObjectNode();
        result.put("schema_version", "agenttrust.approval-decision-result.v1");
        result.set("approval_case", approvalCase);
        result.set("evidence_receipt", receipt);
        return new Fixture(result, intent, principal, assertion, decisionRecord);
    }

    private static void assertInvalid(ApprovalDecisionEvidenceVerifier verifier, Fixture fixture,
                                      JsonNode result) {
        assertThrows(ControlUnavailableException.class, () -> verifier.require(result, TENANT,
            CASE, fixture.intent(), "approval-key-1", fixture.principal(), fixture.assertion(),
            fixture.decisionRecord()));
    }

    private static ObjectNode receipt(ObjectNode result) {
        return (ObjectNode) result.path("evidence_receipt");
    }

    private static String rawDigest(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sign(KeyPair pair, String digest) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(digest.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }

    private record Fixture(ObjectNode result, AdminModels.ApprovalIntent intent,
                           AdminModels.PrincipalContext principal,
                           ApprovalPrincipalAssertionSigner.SignedHeader assertion,
                           ObjectNode decisionRecord) {}
}
