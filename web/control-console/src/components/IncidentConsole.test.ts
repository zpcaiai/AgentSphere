import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import IncidentConsole from "./IncidentConsole.vue";

const tenantId = "11111111-1111-4111-8111-111111111111";
const incident = { incident_id: "20000000-0000-4000-8000-000000000001",
  correlation_key: "correlation:one", severity: "P1" as const, status: "DETECTED" as const,
  task_id: "30000000-0000-4000-8000-000000000001", owner: "subject:responder",
  safe_summary: "Bounded incident summary", scope: ["task:one"],
  evidence_refs: ["urn:agenttrust:evidence:incident-one"], legal_hold_id: "hold:one",
  resource_version: 2, created_at: "2030-01-01T00:00:00Z",
  updated_at: "2030-01-01T00:00:00Z", timeline: [] };

describe("IncidentConsole", () => {
  it("renders authority evidence and covers all fourteen human operations", async () => {
    const wrapper = mount(IncidentConsole, { props: { tenantId, requestedBy: "subject:responder",
      approvalIds: ["approval:one", "approval:two"], locale: "en-US", detail: incident,
      page: { schema_version: "agenttrust.authoritative-incident-page.v1", tenant_id: tenantId,
        items: [incident], next_after_incident_id: null } } });
    expect(wrapper.findAll("#incident-operation option")).toHaveLength(14);
    expect(wrapper.text()).toContain("urn:agenttrust:evidence:incident-one");
    await wrapper.get(`button[aria-label="Select incident ${incident.incident_id}"]`).trigger("click");
    await wrapper.get("#incident-operation").setValue("INVESTIGATE");
    await wrapper.get("form").trigger("submit"); await flushPromises();
    const command = wrapper.emitted("submit")?.[0]?.[0] as Record<string, unknown>;
    expect(command).toMatchObject({ schema_version: "agenttrust.incident-command.v1",
      tenant_id: tenantId, resource_id: `incident:${incident.incident_id}`,
      task_id: incident.task_id, operation: "INVESTIGATE", expected_resource_version: 2 });
  });

  it("labels a 202 receipt as pending rather than remediation success", () => {
    const wrapper = mount(IncidentConsole, { props: { tenantId, requestedBy: "subject:responder",
      approvalIds: [], locale: "en-US", receipt: {
        schema_version: "agenttrust.incident-action-receipt.v1",
        action_id: "20000000-0000-4000-8000-000000000001",
        task_id: "30000000-0000-4000-8000-000000000001", accepted: true,
        execution_pending: true, ingress_digest: "a".repeat(64),
        ledger_evidence_ref: "urn:agenttrust:ledger-evidence:incident-one",
        ledger_evidence_digest: "b".repeat(64) } } });
    expect(wrapper.text()).toContain("execution, remediation, release, and rollback state remain pending");
    expect(wrapper.text()).not.toContain("Remediation succeeded");
  });
});
