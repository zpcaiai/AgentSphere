import { describe, expect, it, vi } from "vitest";
import { AgUiEventReducer, AgUiResumeClient, buildApprovalIntent, type AgUiEventEnvelope } from "../../shared/agui-client";

function event(sequence: number, overrides: Partial<AgUiEventEnvelope> = {}): AgUiEventEnvelope {
  return { schema_version: "agenttrust.a2a-agui.v1", event_id: `event-${sequence}`, tenant_id: "tenant-1", task_id: "task-1",
    sequence, trace_id: "trace-1", kind: "EXECUTION_STATUS", safe_payload: { status: "RUNNING" },
    occurred_at: "2026-08-13T00:00:00Z", backend_signature: "signed", ...overrides };
}

describe("AG-UI client", () => {
  it("requires verified, gap-free backend events", async () => {
    const reducer = new AgUiEventReducer(async (value) => value.backend_signature === "signed", 2);
    expect(await reducer.apply(event(1))).toBe("APPLIED");
    expect(await reducer.apply(event(1))).toBe("DUPLICATE");
    await expect(reducer.apply(event(3))).rejects.toThrow("AGUI_SEQUENCE_GAP");
    await expect(reducer.apply(event(2, { backend_signature: "forged" }))).rejects.toThrow("AGUI_BACKEND_SIGNATURE_INVALID");
  });

  it("uses bounded resume responses and in-memory tokens", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ events: [event(1)], next_resume_token: "token-1",
        safe_snapshot_required: false }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ events: [event(2)], next_resume_token: "token-2",
        safe_snapshot_required: false }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const client = new AgUiResumeClient("https://control.example", "tenant-1", async () => true,
      { maximumEvents: 2, maximumResponseBytes: 10_000 });
    expect(await client.resume("task-1")).toHaveLength(1);
    expect(await client.resume("task-1")).toHaveLength(1);
    expect(String(fetchSpy.mock.calls[1]![0])).toContain("resume_token=token-1");
    expect(Object.keys(window.localStorage ?? {})).toHaveLength(0);
    expect(Object.keys(window.sessionStorage ?? {})).toHaveLength(0);
  });

  it("verifies a safe snapshot, resets its cursor and resumes after an event-ring gap", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ events: [], next_resume_token: "",
        safe_snapshot_required: true }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ schema_version: "agenttrust.agui-safe-snapshot.v1",
        tenant_id: "tenant-1", task_id: "task-1", sequence: 1024,
        safe_state: { status: "RUNNING", evidence_digest: "a".repeat(64) },
        next_resume_token: "snapshot-token", generated_at: "2026-08-13T00:00:00Z",
        backend_signature: "signed" }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ events: [event(1025)], next_resume_token: "token-1025",
        safe_snapshot_required: false }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const client = new AgUiResumeClient("https://control.example", "tenant-1", async () => true);
    expect(await client.resume("task-1")).toHaveLength(1);
    expect(client.currentSequence("task-1")).toBe(1025);
    expect(client.currentSafeSnapshot("task-1")?.safe_state.status).toBe("RUNNING");
    expect(String(fetchSpy.mock.calls[2]![0])).toContain("resume_token=snapshot-token");
  });

  it("builds intent only and validates action binding", () => {
    expect(buildApprovalIntent("20000000-0000-4000-8000-000000000001", "APPROVE", " reviewed ", "a".repeat(64), "v1")).toEqual({
      schema_version: "agenttrust.approval-intent.v1", case_id: "20000000-0000-4000-8000-000000000001", decision: "APPROVE",
      reason: "reviewed", observed_action_hash: "a".repeat(64), observed_resource_version: "v1",
    });
    expect(() => buildApprovalIntent("20000000-0000-4000-8000-000000000001", "APPROVE", "", "a".repeat(64), "v1")).toThrow();
  });
});
