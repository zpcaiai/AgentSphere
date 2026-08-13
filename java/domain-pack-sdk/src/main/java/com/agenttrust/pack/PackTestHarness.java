package com.agenttrust.pack;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;

public final class PackTestHarness {
    public Report run(DomainPackManifest manifest, List<TestCase> cases,
                      Function<TestCase, Decision> evaluator) {
        manifest.validate();
        if (cases.isEmpty() || cases.size() > 10_000) {
            throw new IllegalArgumentException("DOMAIN_PACK_TEST_SET_INVALID");
        }
        List<Outcome> outcomes = new ArrayList<>();
        for (TestCase test : cases) {
            if (test.caseId() == null || test.caseId().isBlank()
                || test.actionDigest() == null || !test.actionDigest().matches("[a-f0-9]{64}")) {
                throw new IllegalArgumentException("DOMAIN_PACK_TEST_CASE_INVALID");
            }
            Decision actual = evaluator.apply(test);
            outcomes.add(new Outcome(test.caseId(), test.expected(), actual,
                test.expected() == actual));
        }
        boolean passed = outcomes.stream().allMatch(Outcome::passed);
        String digest = sha256(manifest.digest() + outcomes.toString());
        return new Report("agenttrust.domain-pack-test-report.v1", manifest.packId(),
            manifest.digest(), List.copyOf(outcomes), passed, 0, digest,
            "SOFTWARE_CONFORMANCE_ONLY");
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA256_UNAVAILABLE", error);
        }
    }

    public record TestCase(String caseId, String actionDigest, Decision expected) {}
    public record Outcome(String caseId, Decision expected, Decision actual, boolean passed) {}
    public record Report(String schemaVersion, String packId, String packDigest,
                         List<Outcome> outcomes, boolean passed, int sideEffectCount,
                         String evidenceDigest, String evidenceScope) {}
    public enum Decision { ALLOW, DENY, REQUIRE_APPROVAL, ESCALATE }
}
