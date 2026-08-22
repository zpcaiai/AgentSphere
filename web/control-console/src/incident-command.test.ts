import { describe, expect, it } from "vitest";
import { incidentPayloadTemplate, incidentResource, INCIDENT_OPERATIONS,
  prepareIncidentPayload } from "./incident-command";

describe("incident command closure", () => {
  it("constructs and validates all fourteen human-governed operations", async () => {
    const incidentId = "20000000-0000-4000-8000-000000000001";
    for (const operation of INCIDENT_OPERATIONS) {
      const payload = incidentPayloadTemplate(operation, "subject:responder", 2);
      await expect(prepareIncidentPayload(operation, payload, 2)).resolves.toEqual(payload);
      expect(incidentResource(operation, incidentId, "release-one"))
        .toBe(["EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE"]
          .includes(operation) ? "release:release-one" : `incident:${incidentId}`);
    }
  });

  it("fails closed when live replay lacks two independent approvals", async () => {
    const payload = incidentPayloadTemplate("PLAN_REPLAY", "subject:responder");
    Object.assign(payload, { mode: "LIVE", resource_refs: ["resource:production"],
      credential_profile: "production", fresh_lease_id: "30000000-0000-4000-8000-000000000001",
      fresh_lease_digest: "a".repeat(64),
      authorization_lease_expires_at: new Date(Date.now() + 600_000).toISOString() });
    await expect(prepareIncidentPayload("PLAN_REPLAY", payload, 1))
      .rejects.toThrow("CONTROL_INCIDENT_COMMAND_INVALID");
  });
});
