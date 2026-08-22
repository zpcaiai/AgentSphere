package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class AuthorityReadinessConfigurationTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void validatesBasicAndComponentReadinessContractsExactly() throws Exception {
        assertTrue(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.pep-readiness.v1\",\"ready\":true}"),
            "agenttrust.pep-readiness.v1"));
        assertTrue(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.audit-retention-readiness.v1\","
                + "\"ready\":true,\"database_ready\":true,\"worm_ready\":true,"
                + "\"deletion_gateway_ready\":true,\"human_principal_keys_ready\":true}"),
            "agenttrust.audit-retention-readiness.v1"));
        assertFalse(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.audit-retention-readiness.v1\","
                + "\"ready\":true,\"database_ready\":true,\"worm_ready\":true}"),
            "agenttrust.audit-retention-readiness.v1"));
        assertFalse(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.audit-retention-readiness.v1\","
                + "\"ready\":true,\"database_ready\":true,\"worm_ready\":true,"
                + "\"deletion_gateway_ready\":true,\"human_principal_keys_ready\":true,"
                + "\"secret\":\"leak\"}"),
            "agenttrust.audit-retention-readiness.v1"));
        assertTrue(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.policy-admin-readiness.v1\","
                + "\"ready\":true,\"database_ready\":true,\"signing_key_ready\":true,"
                + "\"pep_activation_ready\":true}"),
            "agenttrust.policy-admin-readiness.v1"));
        assertFalse(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.policy-admin-readiness.v1\","
                + "\"ready\":true}"),
            "agenttrust.policy-admin-readiness.v1"));
        assertTrue(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.runtime-anomaly-readiness.v1\","
                + "\"ready\":true,\"database_ready\":true,\"orchestrator_ready\":true,"
                + "\"response_dependencies_ready\":true,\"evidence_authority_ready\":true,"
                + "\"deterministic_rules_ready\":true,\"semantic_detector_required\":false,"
                + "\"production_certification\":false}"),
            "agenttrust.runtime-anomaly-readiness.v1"));
        assertFalse(AuthorityReadinessConfiguration.validReadiness(
            mapper.readTree("{\"schema_version\":\"agenttrust.runtime-anomaly-readiness.v1\","
                + "\"ready\":true,\"database_ready\":true,\"orchestrator_ready\":true}"),
            "agenttrust.runtime-anomaly-readiness.v1"));
    }
}
