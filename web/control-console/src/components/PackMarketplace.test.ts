import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import PackMarketplace from "./PackMarketplace.vue";

const tenantId = "11111111-1111-4111-8111-111111111111";

describe("PackMarketplace", () => {
  it("covers sixteen typed commands and exposes distinct install and activation state", async () => {
    const wrapper = mount(PackMarketplace, { props: { tenantId, locale: "en-US", page: {
      schema_version: "agenttrust.authoritative-pack-page.v1", authoritative: true, tenant_id: tenantId,
      releases: [], installations: [{ installation_id: "20000000-0000-4000-8000-000000000001",
        release_id: "30000000-0000-4000-8000-000000000001", pack_id: "pack:one", version: "1.0.0",
        environment: "production", state: "INSTALLED", permission_expansion: true,
        previous_installation_id: null, updated_at: "2030-01-01T00:00:00Z" }],
      next_after_pack_id: null, data_digest: "a".repeat(64) } } });
    expect(wrapper.findAll("#pack-command-kind option")).toHaveLength(16);
    expect(wrapper.text()).toContain("INSTALL does not ACTIVATE");
    await wrapper.get("#pack-command-kind").setValue("INSTALL");
    await wrapper.get("form").trigger("submit");
    const command = wrapper.emitted("submit")?.[0]?.[0] as { command: { kind: string } };
    expect(command.command.kind).toBe("INSTALL");
  });

  it("never renders accepted as task authorization or lifecycle completion", () => {
    const wrapper = mount(PackMarketplace, { props: { tenantId, locale: "en-US", receipt: {
      schema_version: "agenttrust.marketplace-action-receipt.v1",
      action_id: "20000000-0000-4000-8000-000000000001",
      task_id: "30000000-0000-4000-8000-000000000001", accepted: true,
      execution_pending: true, ingress_digest: "a".repeat(64),
      ledger_evidence_ref: "urn:agenttrust:ledger-evidence:pack-one",
      ledger_evidence_digest: "b".repeat(64) } } });
    expect(wrapper.text()).toContain("no pack is authorized for a task by this receipt");
    expect(wrapper.text()).not.toContain("Lifecycle complete");
  });
});
