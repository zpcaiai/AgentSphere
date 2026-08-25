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
  coding_details: {
    diff_artifact_ref: `artifact://sha256/${"c".repeat(64)}`,
    command_summary: "Apply the reviewed repository patch",
    network_scope: "egress:none",
    rollback_summary: "Restore the reviewed parent revision",
  },
  evidence_refs: ["urn:agenttrust:evidence:risk-package-one",
    "urn:agenttrust:evidence:state-snapshot-one",
    "urn:agenttrust:evidence:approval-case-one"],
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
    expect(createDecisionIntent(cases[0]!, "APPROVE", "😀".repeat(1_001)).reason)
      .toBe("😀".repeat(1_001));
    expect(() => createDecisionIntent(cases[0]!, "APPROVE", "界".repeat(1_366)))
      .toThrow("APPROVAL_INTENT_INVALID");
  });

  it("rejects cross-tenant pages and additional unsafe case fields", () => {
    expect(() => parseApprovalCases(page(), "33333333-3333-4333-8333-333333333333"))
      .toThrow("APPROVAL_AUTHORITY_PAGE_INVALID");
    const unsafe = page();
    const unsafeItems: unknown = [{ ...item, raw_payload: "must not reach the browser" }];
    unsafe.items = unsafeItems as typeof unsafe.items;
    expect(() => parseApprovalCases(unsafe, tenantId)).toThrow("APPROVAL_CASE_INVALID");
  });

  it("fails closed when domain review details are missing or contain secret-like values", () => {
    const missing = page();
    const withoutDetails = { ...item } as Record<string, unknown>;
    delete withoutDetails.coding_details;
    missing.items = [withoutDetails] as unknown as typeof missing.items;
    expect(() => parseApprovalCases(missing, tenantId)).toThrow("APPROVAL_CASE_INVALID");

    const secret = page();
    secret.items = [{ ...item, coding_details: { ...item.coding_details,
      command_summary: "Authorization: Bearer production-secret" } }];
    expect(() => parseApprovalCases(secret, tenantId)).toThrow("APPROVAL_CASE_INVALID");

    const unknownDetail = page();
    unknownDetail.items = [{ ...item, coding_details: { ...item.coding_details,
      raw_command: "must never reach the browser" } }] as unknown as typeof unknownDetail.items;
    expect(() => parseApprovalCases(unknownDetail, tenantId)).toThrow("APPROVAL_CASE_INVALID");

    const secretEvidence = page();
    secretEvidence.items = [{ ...item, evidence_refs: [item.evidence_refs[0]!,
      item.evidence_refs[1]!, "evidence://case?token=production-secret"] }];
    expect(() => parseApprovalCases(secretEvidence, tenantId)).toThrow("APPROVAL_CASE_INVALID");
  });

  it("accepts complete industrial review details and rejects coding details on that domain", () => {
    const industrial = { ...item, domain: "INDUSTRIAL" as const,
      industrial_details: { current_value: "42.0 C", target_value: "43.0 C",
        allowed_range: "40.0 C to 45.0 C",
        interlock_summary: "SIS permissive and operator supervision required",
        physical_impact: "One degree setpoint increase on line 1" } };
    const industrialRecord = industrial as unknown as Record<string, unknown>;
    delete industrialRecord.coding_details;
    const valid = page(); valid.items = [industrialRecord] as unknown as typeof valid.items;
    expect(parseApprovalCases(valid, tenantId)[0]?.domain).toBe("INDUSTRIAL");

    const mixed = page();
    mixed.items = [{ ...industrialRecord, coding_details: item.coding_details }] as unknown as typeof mixed.items;
    expect(() => parseApprovalCases(mixed, tenantId)).toThrow("APPROVAL_CASE_INVALID");
  });
});
