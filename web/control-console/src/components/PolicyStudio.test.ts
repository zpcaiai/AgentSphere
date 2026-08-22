import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import PolicyStudio from "./PolicyStudio.vue";

const tenantId = "11111111-1111-4111-8111-111111111111";

describe("PolicyStudio", () => {
  it("exposes all twelve governed operations and emits one exact pending command", async () => {
    const wrapper = mount(PolicyStudio, { props: { tenantId, requestedBy: "subject:reviewer",
      approvalIds: ["approval:one", "approval:two"], locale: "en-US", page: {
        schema_version: "agenttrust.authoritative-policy-page.v1", tenant_id: tenantId,
        items: [{ policy_id: "policy-one", revision: 1, lifecycle_state: "VALIDATED",
          source_digest: "a".repeat(64), author_subject: "subject:author", active_bundle_digest: null,
          active_environment: null, resource_version: 4, updated_at: "2030-01-01T00:00:00Z" }],
        next_after_policy_id: null,
      } } });
    expect(wrapper.findAll("#policy-operation option")).toHaveLength(12);
    await wrapper.get('button[aria-label="Select policy-one"]').trigger("click");
    await wrapper.get("#policy-operation").setValue("VALIDATE");
    await wrapper.get("form").trigger("submit");
    const command = wrapper.emitted("submit")?.[0]?.[0] as Record<string, unknown>;
    expect(command).toMatchObject({ schema_version: "agenttrust.policy-command.v1",
      tenant_id: tenantId, policy_id: "policy-one", operation: "VALIDATE",
      expected_resource_version: 4, payload: {} });
  });

  it("labels an HTTP 202 receipt as pending rather than lifecycle success", () => {
    const wrapper = mount(PolicyStudio, { props: { tenantId, requestedBy: "subject:admin",
      approvalIds: ["approval:one", "approval:two"], locale: "en-US", receipt: {
        schema_version: "agenttrust.policy-action-receipt.v1",
        action_id: "22222222-2222-4222-8222-222222222222",
        task_id: "33333333-3333-4333-8333-333333333333", accepted: true,
        execution_pending: true, ingress_digest: "a".repeat(64),
        ledger_evidence_ref: "urn:agenttrust:ledger-evidence:one",
        ledger_evidence_digest: "b".repeat(64),
      } } });
    expect(wrapper.text()).toContain("execution and lifecycle completion remain pending");
    expect(wrapper.text()).not.toContain("Lifecycle succeeded");
  });
});
