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

  it("keeps one-time key material explicit and clearable", async () => {
    const wrapper = mount(AdminWorkbench, { props: { tenantId: "11111111-1111-4111-8111-111111111111", projectId: null,
      issuedApiKey: { schema_version: "agenttrust.api-key.v1", api_key_id: "key-id", one_time_secret: `atk_${"A".repeat(43)}`,
        created_at: "2026-08-13T00:00:00Z", expires_at: "2026-08-14T00:00:00Z", scopes: ["tasks:read"] } } });
    expect(wrapper.find(".one-time-secret").text()).toContain(`atk_${"A".repeat(43)}`);
    await wrapper.find(".one-time-secret button").trigger("click");
    expect(wrapper.emitted("clearApiKey")).toHaveLength(1);
  });
});
