import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import AdminWorkbench from "./AdminWorkbench.vue";

describe("AdminWorkbench", () => {
  it("emits a payload-bound organization command after native validation", async () => {
    const wrapper = mount(AdminWorkbench, { props: { tenantId: "11111111-1111-4111-8111-111111111111", projectId: null } });
    const inputs = wrapper.findAll("fieldset input");
    await inputs[0]!.setValue("org-one");
    await inputs[1]!.setValue("Organization One");
    await inputs[2]!.setValue("subject:sponsor");
    await wrapper.find("#admin-reason").setValue("approved change");
    await wrapper.find("form").trigger("submit");
    expect(wrapper.emitted("submit")?.[0]?.[0]).toEqual({
      kind: "CREATE_ORGANIZATION", resource: "organization:org-one", reason: "approved change",
      payload: { organization_id: "org-one", display_name: "Organization One", sponsor_subject: "subject:sponsor" },
    });
  });

  it("renders durable acceptance without any browser-visible credential", async () => {
    const wrapper = mount(AdminWorkbench, { props: { tenantId: "11111111-1111-4111-8111-111111111111", projectId: null,
      actionReceipt: { schema_version: "agenttrust.enterprise-action-receipt.v1",
        action_id: "22222222-2222-4222-8222-222222222222",
        task_id: "33333333-3333-4333-8333-333333333333", accepted: true,
        start_requested: true, execution_pending: true, ingress_digest: "a".repeat(64),
        evidence_ref: "orchestrator-event://11111111-1111-4111-8111-111111111111/33333333-3333-4333-8333-333333333333/1",
        evidence_digest: "b".repeat(64) } } });
    expect(wrapper.find(".action-receipt").text()).toContain("33333333-3333-4333-8333-333333333333");
    expect(wrapper.html()).not.toContain("one_time_secret");
    await wrapper.find(".action-receipt button").trigger("click");
    expect(wrapper.emitted("clearReceipt")).toHaveLength(1);
  });
});
