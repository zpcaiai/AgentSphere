package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import com.agenttrust.control.AdminModels.AdminIntent;
import com.agenttrust.control.AdminModels.PrincipalContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class EnterpriseServiceTest {
    @Test
    void crossTenantAndMissingSeparationAreDenied() {
        UUID tenant = UUID.randomUUID();
        var principal = new PrincipalContext("admin:1", tenant,
            Set.of("tenant-admin"), Set.of("project:1"), Set.of("approval:1"), Set.of(),
            true, Instant.now(), "urn:agenttrust:acr:mfa");
        var crossTenant = new AdminIntent("agenttrust.enterprise-control.v1",
            UUID.randomUUID(), UUID.randomUUID(), "project:1", "create",
            "organization:x", "admin:1", Set.of("approval:1"),
            "a".repeat(64), Instant.now());
        assertThrows(ControlDeniedException.class,
            () -> EnterpriseService.requireContext(principal, crossTenant,
                Set.of("tenant-admin"), true));
        var missingApproval = new AdminIntent("agenttrust.enterprise-control.v1",
            UUID.randomUUID(), tenant, "project:1", "create", "organization:x",
            "admin:1", Set.of(), "a".repeat(64), Instant.now());
        assertThrows(ControlDeniedException.class,
            () -> EnterpriseService.requireContext(principal, missingApproval,
                Set.of("tenant-admin"), true));
        var weakPrincipal = new PrincipalContext("admin:1", tenant,
            Set.of("tenant-admin"), Set.of("project:1"), Set.of("approval:1"));
        var otherwiseValid = new AdminIntent("agenttrust.enterprise-control.v1",
            UUID.randomUUID(), tenant, "project:1", "create", "organization:x",
            "admin:1", Set.of("approval:1"), "a".repeat(64), Instant.now());
        assertThrows(ControlDeniedException.class,
            () -> EnterpriseService.requireContext(weakPrincipal, otherwiseValid,
                Set.of("tenant-admin"), true));
    }

    @Test
    void actionOperationAndResourceCannotBeSwappedByBrowser() {
        UUID tenant = UUID.randomUUID();
        var intent = new AdminIntent("agenttrust.enterprise-control.v1", UUID.randomUUID(), tenant,
            null, "CREATE_PROJECT", "project:one", "admin:1", Set.of("approval:1"),
            "a".repeat(64), Instant.now());
        assertThrows(ControlDeniedException.class,
            () -> EnterpriseService.requireOperation(intent, "CREATE_INTEGRATION", "project:one"));
        assertThrows(ControlDeniedException.class,
            () -> EnterpriseService.requireOperation(intent, "CREATE_PROJECT", "project:two"));
    }

    @Test
    void actionDigestBindsReasonAndPayloadBeforePep() {
        UUID tenant = UUID.randomUUID();
        UUID actionId = UUID.randomUUID();
        Instant requestedAt = Instant.now();
        var unbound = new AdminIntent("agenttrust.enterprise-control.v1", actionId, tenant,
            null, "REQUEST_POLICY_PROMOTION", "policy://selected", "admin:1",
            Set.of("approval:1"), "0".repeat(64), requestedAt);
        var canonical = new CanonicalDigest(new ObjectMapper());
        String digest = canonical.actionDigest(unbound, "promote reviewed policy", null);
        var bound = new AdminIntent(unbound.schemaVersion(), actionId, tenant, null,
            unbound.operation(), unbound.resource(), unbound.requestedBy(), unbound.approvalIds(),
            digest, requestedAt);
        var service = new EnterpriseService(null, null, null, null, canonical);
        assertDoesNotThrow(() -> service.requireActionDigest(
            bound, "promote reviewed policy", null));
        assertThrows(ControlDeniedException.class, () -> service.requireActionDigest(
            bound, "promote unreviewed policy", null));
        assertThrows(ControlDeniedException.class, () -> service.requireActionDigest(
            bound, "promote reviewed policy", java.util.Map.of("policy", "different")));
    }

}
