import { describe, expect, it, vi } from "vitest";
import {
  approvalIdempotencyKey,
  buildAdminIntent,
  extractTaskAuthorityStatuses,
  safeAuthorityRows,
  taskCompletionLabel,
  validateDashboard,
  type AuthoritySection,
  type EnterpriseDashboard,
} from "./control-state";

const tenantId = "11111111-1111-4111-8111-111111111111";
const digest = "a".repeat(64);
const taskData = {
  items: [{ task_id: "task-1", runtime_status: "COMPLETED", ledger_terminal: true,
    evaluation_passed: true, evidence_verified: false, status_digest: digest, state_version: 4 }],
};
const dashboard: EnterpriseDashboard = {
  schema_version: "agenttrust.enterprise-dashboard.v1", tenant_id: tenantId, complete: true,
  unavailable_sections: [], sections: { TASKS: { schema_version: "agenttrust.authority-view.v1", section: "TASKS",
    authoritative: true, available: true, data: taskData, data_digest: digest, fetched_at: "2026-08-13T00:00:00Z" } },
};

describe("authoritative console state", () => {
  it("loads tasks from the BFF section and refuses a browser-only completion claim", () => {
    expect(validateDashboard(dashboard)).toBe(dashboard);
    const tasks = extractTaskAuthorityStatuses(dashboard);
    expect(tasks).toHaveLength(1);
    expect(taskCompletionLabel(tasks[0]!)).toBe("VERIFYING");
  });

  it("fails closed when a partial failure is hidden", () => {
    const hidden = structuredClone(dashboard);
    hidden.complete = false;
    hidden.unavailable_sections = ["TASKS"];
    hidden.sections.TASKS!.available = false;
    hidden.sections.TASKS!.safe_error_code = "AUTHORITATIVE_SOURCE_UNAVAILABLE";
    expect(() => validateDashboard(hidden)).toThrow("ENTERPRISE_PARTIAL_FAILURE_HIDDEN");
  });

  it("rejects a contradictory complete flag", () => {
    const contradictory = structuredClone(dashboard);
    contradictory.complete = false;
    expect(() => validateDashboard(contradictory)).toThrow("ENTERPRISE_COMPLETENESS_INVALID");
  });

  it("redacts secrets and bounds structured payloads", () => {
    const section: AuthoritySection<unknown> = {
      schema_version: "agenttrust.authority-view.v1", section: "EVIDENCE", authoritative: true,
      available: true, data: [{ id: "e1", secret: "leak", safe_summary: "safe", prompt: "sensitive",
        nested: { unsafe: true } }], data_digest: digest, fetched_at: "2026-08-13T00:00:00Z",
    };
    expect(safeAuthorityRows(section)[0]!.values).toMatchObject({ secret: "[REDACTED]", prompt: "[REDACTED]",
      safe_summary: "safe", nested: "[STRUCTURED_DATA_REDACTED]" });
  });

  it("canonicalizes and binds the governed request payload", async () => {
    vi.spyOn(crypto, "randomUUID").mockReturnValue("22222222-2222-4222-8222-222222222222");
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-13T01:02:03.000Z"));
    const first = await buildAdminIntent({ tenant_id: tenantId, project_id: null, operation: "CREATE_ORGANIZATION",
      resource: "organization:one", requested_by: "subject:1", approval_ids: ["b", "a"], reason: "reason",
      csrf_token: "csrf", payload: { organization_id: "one", display_name: "One",
        sponsor_subject: "subject:sponsor" } });
    const changed = await buildAdminIntent({ tenant_id: tenantId, project_id: null, operation: "CREATE_ORGANIZATION",
      resource: "organization:one", requested_by: "subject:1", approval_ids: ["a", "b"], reason: "reason",
      csrf_token: "csrf", payload: { organization_id: "one", display_name: "Two",
        sponsor_subject: "subject:sponsor" } });
    expect(first.intent.approval_ids).toEqual(["a", "b"]);
    expect(first.intent.action_digest).toBe(
      "741c60e6c35aace23c59fad505a6daed5ba4c4252b8a2776a830acbe3fa77c4e",
    );
    expect(first.intent.action_digest).not.toBe(changed.intent.action_digest);
    vi.useRealTimers();
  });

  it("keeps approval retries idempotent across page refreshes", async () => {
    const intent = {
      schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "33333333-3333-4333-8333-333333333333",
      decision: "APPROVE" as const,
      reason: "verified by operator",
      observed_action_hash: "b".repeat(64),
      observed_resource_version: "resource-v4",
    };
    const first = await approvalIdempotencyKey(tenantId, "subject:1", intent);
    const retry = await approvalIdempotencyKey(tenantId, "subject:1", structuredClone(intent));
    const changed = await approvalIdempotencyKey(tenantId, "subject:1", { ...intent, decision: "REJECT" });
    expect(first).toMatch(/^approval:[a-f0-9]{64}$/);
    expect(retry).toBe(first);
    expect(changed).not.toBe(first);
  });
});
