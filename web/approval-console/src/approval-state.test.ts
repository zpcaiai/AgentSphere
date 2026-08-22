import { describe, expect, it } from "vitest";
import { createDecisionIntent, parseApprovalCases } from "./approval-state";

const tenantId = "11111111-1111-4111-8111-111111111111";
const item = {
  schema_version: "agenttrust.approval-case-view.v1",
  case_id: "22222222-2222-4222-8222-222222222222",
  domain: "CODING",
  safe_summary: "Review governed coding action",
  action_hash: "a".repeat(64),
  resource: "repository:one",
  resource_version: "commit:one",
  policy_version: "policy:v1",
  risk: "HIGH",
  evidence_refs: [],
  status: "PENDING",
};

function page() {
  return {
    schema_version: "agenttrust.authoritative-approval-page.v1",
    authoritative: true,
    tenant_id: tenantId,
    resource: "summary",
    items: [item],
    next_cursor: null,
    data_digest: "b".repeat(64),
  };
}

describe("authoritative approval inbox", () => {
  it("accepts only the tenant-bound safe authority view and emits an intent", () => {
    const cases = parseApprovalCases(page(), tenantId);
    expect(cases).toHaveLength(1);
    expect(createDecisionIntent(cases[0]!, "APPROVE", "reviewed")).toEqual({
      schema_version: "agenttrust.approval-intent.v1",
      case_id: item.case_id,
      decision: "APPROVE",
      reason: "reviewed",
      observed_action_hash: item.action_hash,
      observed_resource_version: item.resource_version,
    });
  });

  it("rejects cross-tenant pages and additional unsafe case fields", () => {
    expect(() => parseApprovalCases(page(), "33333333-3333-4333-8333-333333333333"))
      .toThrow("APPROVAL_AUTHORITY_PAGE_INVALID");
    const unsafe = page();
    unsafe.items = [{ ...item, raw_payload: "must not reach the browser" }] as typeof unsafe.items;
    expect(() => parseApprovalCases(unsafe, tenantId)).toThrow("APPROVAL_CASE_INVALID");
  });
});
