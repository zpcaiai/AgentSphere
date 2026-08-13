package com.agenttrust.pack;

import java.util.List;
import java.util.Set;

public final class PackSdkSmokeTest {
    private PackSdkSmokeTest() {}

    public static void main(String[] args) {
        var tool = new DomainPackManifest.ToolDefinition("coding.patch",
            DomainPackManifest.EffectClass.COMPENSATABLE, true,
            "coding.rollback", "https://executor.internal/v1/patch");
        var manifest = new DomainPackManifest("agenttrust.domain-pack.v1", "coding.pack",
            "1.0.0", "a".repeat(64), "publisher:agenttrust",
            Set.of("coding.patch"), List.of(tool), "policy:coding:v1",
            "evaluator:coding:v1", Set.of("scenario:coding-injection"));
        var report = new PackTestHarness().run(manifest,
            List.of(new PackTestHarness.TestCase("deny-protected-path", "b".repeat(64),
                PackTestHarness.Decision.DENY)), ignored -> PackTestHarness.Decision.DENY);
        if (!report.passed() || report.sideEffectCount() != 0
            || !"SOFTWARE_CONFORMANCE_ONLY".equals(report.evidenceScope())) {
            throw new AssertionError("DOMAIN_PACK_SDK_SMOKE_FAILED");
        }
    }
}
