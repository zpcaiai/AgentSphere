import { describe, expect, it, vi } from "vitest";
import { ControlApiClient } from "./api-client";
import { sha256Canonical, type GovernedAdminIntent } from "./control-state";

const tenantId = "11111111-1111-4111-8111-111111111111";
const governed: GovernedAdminIntent = { csrf_token: "csrf", reason: "because", intent: {
  schema_version: "agenttrust.enterprise-control.v1", action_id: "22222222-2222-4222-8222-222222222222",
  tenant_id: tenantId, project_id: null, operation: "CREATE_ORGANIZATION", resource: "organization:one",
  requested_by: "subject:1", approval_ids: ["approval:1"], action_digest: "a".repeat(64),
  requested_at: "2026-08-13T00:00:00Z",
} };

function response(body: unknown, status = 200): Response {
  return new Response(body === null ? null : JSON.stringify(body), {
    status, headers: body === null ? {} : { "Content-Type": "application/json" },
  });
}

describe("ControlApiClient", () => {
  it("rejects unsafe API configuration", () => {
    expect(() => new ControlApiClient("http://control.example")).toThrow("CONTROL_API_CONFIG_INVALID");
    expect(() => new ControlApiClient("https://user:password@control.example")).toThrow("CONTROL_API_CONFIG_INVALID");
  });

  it("provides the configured enterprise OIDC entry point without carrying a token", () => {
    expect(new ControlApiClient("https://control.example").signInUrl())
      .toBe("https://control.example/oauth2/authorization/agenttrust");
  });

  it("uses authenticated session bootstrap and never sends a bearer token", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.enterprise-session.v1", tenant_id: tenantId, subject: "subject:1",
      project_ids: [], approval_ids: [], roles: ["viewer"], owned_resources: [],
      strong_auth: false, authentication_time: null, authentication_context: null,
      csrf_header_name: "X-XSRF-TOKEN", csrf_token: "csrf",
    }));
    await new ControlApiClient("https://control.example").session();
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(String(url)).toBe("https://control.example/v1/session");
    expect(init?.credentials).toBe("include");
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
  });

  it("invalidates the server session with the bound CSRF token", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(null, 204));
    await new ControlApiClient("https://control.example").logout("csrf");
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(String(url)).toBe("https://control.example/v1/session/logout");
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(new Headers(init?.headers).get("X-XSRF-TOKEN")).toBe("csrf");
  });

  it("sends CSRF, stable idempotency and payload-bound governed writes", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.enterprise-action-receipt.v1",
      action_id: governed.intent.action_id,
      task_id: "33333333-3333-4333-8333-333333333333",
      accepted: true, start_requested: true, execution_pending: true,
      ingress_digest: "b".repeat(64), evidence_digest: "c".repeat(64),
      evidence_ref: `orchestrator-event://${tenantId}/33333333-3333-4333-8333-333333333333/1`,
    }, 202));
    const request = { organization_id: "one", display_name: "One", sponsor_subject: "subject:sponsor" };
    await new ControlApiClient("https://control.example").createOrganization(request, governed);
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(new Headers(init?.headers).get("X-XSRF-TOKEN")).toBe("csrf");
    expect(new Headers(init?.headers).get("Idempotency-Key")).toBe(governed.intent.action_id);
    expect(JSON.parse(String(init?.body))).toEqual({ organization: request, intent: governed.intent, reason: "because" });
  });

  it("rejects a mutation response that tries to return raw API key material", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.enterprise-action-receipt.v1",
      action_id: governed.intent.action_id,
      task_id: "33333333-3333-4333-8333-333333333333",
      accepted: true, start_requested: true, execution_pending: true,
      ingress_digest: "b".repeat(64), evidence_digest: "c".repeat(64),
      evidence_ref: `orchestrator-event://${tenantId}/33333333-3333-4333-8333-333333333333/1`,
      one_time_secret: `atk_${"A".repeat(43)}`,
    }, 202));
    await expect(new ControlApiClient("https://control.example").issueApiKey({
      project_id: null, scopes: ["tasks:read"], expires_at: "2026-08-14T00:00:00Z",
    }, { ...governed, intent: { ...governed.intent, operation: "ISSUE_API_KEY", resource: "api-key:new" } }))
      .rejects.toThrow("CONTROL_ENTERPRISE_RECEIPT_INVALID");
  });

  it("submits approval as an intent and not a grant", async () => {
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const, case_id: "20000000-0000-4000-8000-000000000001",
      decision: "APPROVE" as const, reason: "reviewed", observed_action_hash: "b".repeat(64),
      observed_resource_version: "v1" };
    const receipt = { schema_version: "agenttrust.approval-intent-receipt.v1" as const,
      tenant_id: tenantId, case_id: intent.case_id, decision: intent.decision,
      action_hash: intent.observed_action_hash, resource_version: intent.observed_resource_version,
      case_status: "APPROVED" as const, decided_at: "2030-01-02T03:04:05Z",
      evidence_ref: `urn:agenttrust:approval-decision:${tenantId}:${intent.case_id}:30000000-0000-4000-8000-000000000001`,
      evidence_digest: "c".repeat(64), authority_issuer: "agenttrust-approval",
      authority_key_id: "approval-key-1" };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(receipt, 202));
    await expect(new ControlApiClient("https://control.example").submitApprovalIntent(
      tenantId, intent, "csrf", "retry-key-0000001")).resolves.toEqual(receipt);
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(JSON.parse(String(init?.body))).toEqual({ approval_intent: intent });
    expect(String(init?.body)).not.toContain("grant");
    expect(new Headers(init?.headers).get("Accept")).toBe("application/json");
  });

  it("rejects an approval reason beyond the authority UTF-8 byte limit", async () => {
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-000000000001", decision: "APPROVE" as const,
      reason: "界".repeat(1_366), observed_action_hash: "b".repeat(64),
      observed_resource_version: "v1" };
    await expect(new ControlApiClient("https://control.example").submitApprovalIntent(
      tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_INTENT_INVALID");
  });

  it("rejects noncanonical uppercase approval UUIDs before dispatch", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-00000000000A", decision: "APPROVE" as const,
      reason: "reviewed", observed_action_hash: "b".repeat(64),
      observed_resource_version: "v1" };
    await expect(new ControlApiClient("https://control.example").submitApprovalIntent(
      tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_INTENT_INVALID");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("allows multiline astral approval reasons but rejects NUL", async () => {
    const base = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-000000000001", decision: "APPROVE" as const,
      observed_action_hash: "b".repeat(64), observed_resource_version: "v1" };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.approval-intent-receipt.v1", tenant_id: tenantId,
      case_id: base.case_id, decision: base.decision, action_hash: base.observed_action_hash,
      resource_version: base.observed_resource_version, case_status: "APPROVED",
      decided_at: "2030-01-02T03:04:05Z",
      evidence_ref: `urn:agenttrust:approval-decision:${tenantId}:${base.case_id}:30000000-0000-4000-8000-000000000001`,
      evidence_digest: "c".repeat(64), authority_issuer: "agenttrust-approval",
      authority_key_id: "approval-key-1" }, 202));
    await expect(new ControlApiClient("https://control.example").submitApprovalIntent(
      tenantId, { ...base, reason: "😀".repeat(1_001) + "\n" }, "csrf",
      "retry-key-0000001"))
      .resolves.toMatchObject({ decision: "APPROVE" });
    await expect(new ControlApiClient("https://control.example").submitApprovalIntent(
      tenantId, { ...base, reason: "bad\0reason" }, "csrf", "retry-key-0000002"))
      .rejects.toThrow("CONTROL_APPROVAL_INTENT_INVALID");
  });

  it("rejects approval receipts with extensions or broken request bindings", async () => {
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-000000000001", decision: "REJECT" as const,
      reason: "unsafe change", observed_action_hash: "b".repeat(64), observed_resource_version: "v1" };
    const receipt = { schema_version: "agenttrust.approval-intent-receipt.v1",
      tenant_id: tenantId, case_id: intent.case_id, decision: intent.decision,
      action_hash: intent.observed_action_hash, resource_version: intent.observed_resource_version,
      case_status: "REJECTED", decided_at: "2030-01-02T03:04:05Z",
      evidence_ref: `urn:agenttrust:approval-decision:${tenantId}:${intent.case_id}:30000000-0000-4000-8000-000000000001`,
      evidence_digest: "c".repeat(64), authority_issuer: "agenttrust-approval",
      authority_key_id: "approval-key-1" };
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(response({ ...receipt,
      untrusted_complete: true }, 202)).mockResolvedValueOnce(response({ ...receipt,
      action_hash: "d".repeat(64) }, 202));
    const client = new ControlApiClient("https://control.example");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_RECEIPT_INVALID");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_RECEIPT_INVALID");
  });

  it("preserves a fail-closed unknown outcome instead of reporting approval success", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.safe-error.v1", code: "CONTROL_APPROVAL_OUTCOME_UNKNOWN",
      trace_id: "40000000-0000-4000-8000-000000000001",
      occurred_at: "2030-01-02T03:04:05Z",
    }, 503));
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-000000000001", decision: "REJECT" as const,
      reason: "unsafe change", observed_action_hash: "b".repeat(64), observed_resource_version: "v1" };
    await expect(new ControlApiClient("https://control.example").submitApprovalIntent(
      tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_OUTCOME_UNKNOWN");
  });

  it("preserves exact approval conflict and capacity error contracts", async () => {
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-000000000001", decision: "REJECT" as const,
      reason: "unsafe change", observed_action_hash: "b".repeat(64), observed_resource_version: "v1" };
    const safeError = (code: string) => ({ schema_version: "agenttrust.safe-error.v1",
      code, trace_id: "40000000-0000-4000-8000-000000000001",
      occurred_at: "2030-01-02T03:04:05.123456Z" });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(response(safeError("CONTROL_IDEMPOTENCY_CONFLICT"), 409))
      .mockResolvedValueOnce(response(safeError("CONTROL_AUTHORITY_CAPACITY"), 429));
    const client = new ControlApiClient("https://control.example");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toMatchObject({ code: "CONTROL_IDEMPOTENCY_CONFLICT", status: 409 });
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toMatchObject({ code: "CONTROL_AUTHORITY_CAPACITY", status: 429 });
  });

  it("cancels oversized error bodies before parsing them", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.safe-error.v1", code: "CONTROL_AUTHORITY_CAPACITY",
      trace_id: "40000000-0000-4000-8000-000000000001",
      occurred_at: "2030-01-02T03:04:05Z", padding: "x".repeat(20_000),
    }, 503));
    await expect(new ControlApiClient("https://control.example").session())
      .rejects.toMatchObject({ code: "CONTROL_API_RESPONSE_TOO_LARGE", status: 503 });
  });

  it("keeps the request deadline active while the response body is streaming", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      let bodyController: ReadableStreamDefaultController<Uint8Array> | undefined;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          bodyController = controller;
          controller.enqueue(new TextEncoder().encode('{"schema_version":'));
        },
      });
      init?.signal?.addEventListener("abort", () => bodyController?.error(
        new DOMException("deadline", "AbortError")), { once: true });
      return new Response(body, { status: 200,
        headers: { "Content-Type": "application/json" } });
    });
    await expect(new ControlApiClient("https://control.example", 100).session())
      .rejects.toMatchObject({ code: "CONTROL_API_TIMEOUT", status: 200 });
  });

  it("rejects noncanonical approval evidence, timestamps and unsafe error extensions", async () => {
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const,
      case_id: "20000000-0000-4000-8000-000000000001", decision: "APPROVE" as const,
      reason: "reviewed", observed_action_hash: "b".repeat(64), observed_resource_version: "v1" };
    const receipt = { schema_version: "agenttrust.approval-intent-receipt.v1",
      tenant_id: tenantId, case_id: intent.case_id, decision: intent.decision,
      action_hash: intent.observed_action_hash, resource_version: intent.observed_resource_version,
      case_status: "POST_REVIEW_REQUIRED", decided_at: "2030-01-02T03:04:05Z",
      evidence_ref: `urn:agenttrust:approval-decision:${tenantId}:${intent.case_id}:30000000-0000-4000-8000-000000000001`,
      evidence_digest: "c".repeat(64), authority_issuer: ".approval/authority",
      authority_key_id: ".approval-key-1" };
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(response({ ...receipt,
        evidence_ref: receipt.evidence_ref.toUpperCase() }, 202))
      .mockResolvedValueOnce(response({ ...receipt, decided_at: "2030-02-30T03:04:05Z" }, 202))
      .mockResolvedValueOnce(response({ schema_version: "agenttrust.safe-error.v1",
        code: "CONTROL_APPROVAL_OUTCOME_UNKNOWN",
        trace_id: "40000000-0000-4000-8000-000000000001",
        occurred_at: "2030-01-02T03:04:05Z", leaked_reason: "secret" }, 503))
      .mockResolvedValueOnce(response(receipt, 202));
    const client = new ControlApiClient("https://control.example");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_RECEIPT_INVALID");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_APPROVAL_RECEIPT_INVALID");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .rejects.toThrow("CONTROL_API_REJECTED_503");
    await expect(client.submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001"))
      .resolves.toEqual(receipt);
  });

  it("accepts only the exact authoritative Agent Registry inventory wire", async () => {
    const page = {
      schema_version: "agenttrust.authoritative-agent-page.v1", authoritative: true,
      tenant_id: tenantId, resource: "summary", next_cursor: null, data_digest: "a".repeat(64),
      items: [{
        schema_version: "agenttrust.agent-inventory-item.v1", agent_id: "agent:one",
        display_name: "Agent One", owner_subject: "subject:owner",
        sponsor_subject: "subject:sponsor", ownership_status: "CONFIRMED",
        environment: "PRODUCTION", lifecycle: "ACTIVE", agent_type: "coding-agent",
        bom_digest: "b".repeat(64), endpoint_count: 1, identity_count: 1, tool_count: 2,
        pack_count: 1, open_findings: 0, highest_risk: null,
        last_activity_at: "2030-01-02T03:04:05Z", registered_at: "2030-01-01T03:04:05Z",
        updated_at: "2030-01-02T03:04:05Z",
      }],
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(page));
    await expect(new ControlApiClient("https://control.example").listAgents(tenantId, null, 50))
      .resolves.toEqual(page);
  });

  it("rejects Agent inventory extensions and forged tenant bindings", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.authoritative-agent-page.v1", authoritative: true,
      tenant_id: "22222222-2222-4222-8222-222222222222", resource: "summary", items: [],
      next_cursor: null, data_digest: "a".repeat(64), untrusted_summary: "all healthy",
    }));
    await expect(new ControlApiClient("https://control.example").listAgents(tenantId, null, 50))
      .rejects.toThrow("CONTROL_AUTHORITY_PAGE_INVALID");
  });

  it("accepts only the exact tenant-bound keyset Policy page", async () => {
    const page = { schema_version: "agenttrust.authoritative-policy-page.v1", tenant_id: tenantId,
      items: [{ policy_id: "policy-one", revision: 1, lifecycle_state: "DRAFT",
        source_digest: "a".repeat(64), author_subject: "subject:author", active_bundle_digest: null,
        active_environment: null, resource_version: 1, updated_at: "2030-01-01T00:00:00Z" }],
      next_after_policy_id: null };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(page));
    await expect(new ControlApiClient("https://control.example").listPolicies(tenantId, null, 50))
      .resolves.toEqual(page);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ ...page,
      tenant_id: "22222222-2222-4222-8222-222222222222", lifecycle_complete: true }));
    await expect(new ControlApiClient("https://control.example").listPolicies(tenantId, null, 50))
      .rejects.toThrow("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID");
  });

  it("verifies canonical source digests and rejects authority extensions", async () => {
    const source = { schema_version: "agenttrust.policy-admin.v1", source_id: "policy-one",
      tenant_id: tenantId, version: "1", rules: [{ rule_id: "deny-write", subject_pattern: "*",
        tool_pattern: "tool:write", resource_pattern: "*", decision: "DENY", maximum_risk: "CRITICAL",
        reason_code: "POLICY_DENY_WRITE" }], default_decision: "DENY", author: "subject:author",
      source_digest: "", created_at: "2030-01-01T00:00:00Z" };
    source.source_digest = await sha256Canonical(source);
    const page = { schema_version: "agenttrust.authoritative-policy-artifact-page.v1",
      tenant_id: tenantId, policy_id: "policy-one", artifact_type: "SOURCES", items: [source] };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(page));
    await expect(new ControlApiClient("https://control.example").listPolicyArtifacts(
      tenantId, "policy-one", "SOURCES", 50)).resolves.toEqual(page);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ ...page, untrusted_success: true }));
    await expect(new ControlApiClient("https://control.example").listPolicyArtifacts(
      tenantId, "policy-one", "SOURCES", 50)).rejects.toThrow("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID");
  });

  it("submits one canonical Policy action and keeps 202 execution pending", async () => {
    const command = { schema_version: "agenttrust.policy-command.v1" as const, tenant_id: tenantId,
      command_id: "22222222-2222-4222-8222-222222222222", policy_id: "policy-one",
      operation: "VALIDATE" as const, expected_resource_version: 1, payload: {},
      requested_at: "2030-01-01T00:00:00Z" };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.policy-action-receipt.v1", action_id: command.command_id,
      task_id: "33333333-3333-4333-8333-333333333333", accepted: true, execution_pending: true,
      ingress_digest: "a".repeat(64), ledger_evidence_ref: "urn:agenttrust:ledger-evidence:one",
      ledger_evidence_digest: "b".repeat(64),
    }, 202));
    await new ControlApiClient("https://control.example").submitPolicyAction(command, "csrf");
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(String(fetchSpy.mock.calls[0]![0])).toContain("/policies/actions");
    expect(new Headers(init?.headers).get("Idempotency-Key")).toBe(command.command_id);
    expect(new Headers(init?.headers).get("X-XSRF-TOKEN")).toBe("csrf");

    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.policy-action-receipt.v1", action_id: command.command_id,
      task_id: "33333333-3333-4333-8333-333333333333", accepted: true, execution_pending: false,
      ingress_digest: "a".repeat(64), ledger_evidence_ref: "urn:agenttrust:ledger-evidence:one",
      ledger_evidence_digest: "b".repeat(64),
    }, 202));
    await expect(new ControlApiClient("https://control.example").submitPolicyAction(command, "csrf"))
      .rejects.toThrow("CONTROL_POLICY_ACTION_RECEIPT_INVALID");
  });

  it("accepts only exact tenant-bound incident pages and timeline details", async () => {
    const incident = { incident_id: "20000000-0000-4000-8000-000000000001",
      correlation_key: "correlation:one", severity: "P1" as const, status: "DETECTED" as const,
      task_id: "30000000-0000-4000-8000-000000000001", owner: "subject:responder",
      safe_summary: "Bounded incident summary", scope: ["task:one"],
      evidence_refs: ["urn:agenttrust:evidence:incident-one"], legal_hold_id: "hold:one",
      resource_version: 1, created_at: "2030-01-01T00:00:00Z",
      updated_at: "2030-01-01T00:00:00Z", timeline: [] };
    const page = { schema_version: "agenttrust.authoritative-incident-page.v1" as const,
      tenant_id: tenantId, items: [incident], next_after_incident_id: null };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(page));
    await expect(new ControlApiClient("https://control.example").listIncidents(tenantId, null, 50))
      .resolves.toEqual(page);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(incident));
    await expect(new ControlApiClient("https://control.example").getIncident(
      tenantId, incident.incident_id)).resolves.toEqual(incident);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ ...page, authoritative: true }));
    await expect(new ControlApiClient("https://control.example").listIncidents(tenantId, null, 50))
      .rejects.toThrow("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID");
  });

  it("submits incident Canonical Action with exact pending receipt semantics", async () => {
    const command = { schema_version: "agenttrust.incident-command.v1" as const, tenant_id: tenantId,
      command_id: "20000000-0000-4000-8000-000000000001",
      resource_id: "incident:30000000-0000-4000-8000-000000000001",
      task_id: "40000000-0000-4000-8000-000000000001", operation: "INVESTIGATE" as const,
      expected_resource_version: 1, requested_at: "2030-01-01T00:00:00Z",
      payload: { reason_code: "INCIDENT_INVESTIGATION_STARTED" } };
    const receipt = { schema_version: "agenttrust.incident-action-receipt.v1" as const,
      action_id: command.command_id, task_id: command.task_id, accepted: true as const,
      execution_pending: true as const, ingress_digest: "a".repeat(64),
      ledger_evidence_ref: "urn:agenttrust:ledger-evidence:incident-one",
      ledger_evidence_digest: "b".repeat(64) };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(receipt, 202));
    await new ControlApiClient("https://control.example").submitIncidentAction(command, "csrf");
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(String(fetchSpy.mock.calls[0]![0])).toContain("/incidents/actions");
    expect(new Headers(init?.headers).get("Idempotency-Key")).toBe(command.command_id);
    expect(new Headers(init?.headers).get("X-XSRF-TOKEN")).toBe("csrf");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ ...receipt, execution_pending: false }, 202));
    await expect(new ControlApiClient("https://control.example").submitIncidentAction(command, "csrf"))
      .rejects.toThrow("CONTROL_INCIDENT_ACTION_RECEIPT_INVALID");
  });

  it("verifies exact Pack catalog shape and canonical page digest", async () => {
    const material = { schema_version: "agenttrust.authoritative-pack-page.v1" as const,
      authoritative: true as const, tenant_id: tenantId, releases: [{
        release_id: "20000000-0000-4000-8000-000000000001", pack_id: "pack:one",
        version: "1.0.0", pack_digest: "a".repeat(64), publisher_id: "publisher:one",
        visibility: "TENANT" as const, entitlement: "entitlement:one", allowed_regions: ["cn-east"],
        risk_rating: "HIGH" as const, compatibility: ["agenttrust>=1.0.0"],
        certificate_digest: "b".repeat(64), review_status: "PUBLISHED" as const,
        updated_at: "2030-01-01T00:00:00Z" }], installations: [], next_after_pack_id: null };
    const page = { ...material, data_digest: await sha256Canonical(material) };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(page));
    await expect(new ControlApiClient("https://control.example").listPacks(tenantId, "", null, 50))
      .resolves.toEqual(page);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ ...page, data_digest: "0".repeat(64) }));
    await expect(new ControlApiClient("https://control.example").listPacks(tenantId, "", null, 50))
      .rejects.toThrow("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID");
  });

  it("submits one of 16 typed Pack commands and rejects a false 202 success", async () => {
    const command = { schema_version: "agenttrust.marketplace-command.v1" as const, tenant_id: tenantId,
      command_id: "20000000-0000-4000-8000-000000000001", resource_id: "publisher:one",
      expected_resource_version: 0, command: { kind: "ONBOARD_PUBLISHER" as const,
        publisher_id: "publisher:one", publisher_subject: "subject:publisher",
        identity_digest: "a".repeat(64), responsibility_contact: "owner@example.com",
        home_region: "cn-east" }, requested_at: "2030-01-01T00:00:00Z" };
    const receipt = { schema_version: "agenttrust.marketplace-action-receipt.v1" as const,
      action_id: command.command_id, task_id: "30000000-0000-4000-8000-000000000001",
      accepted: true as const, execution_pending: true as const, ingress_digest: "a".repeat(64),
      ledger_evidence_ref: "urn:agenttrust:ledger-evidence:pack-one",
      ledger_evidence_digest: "b".repeat(64) };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(receipt, 202));
    await new ControlApiClient("https://control.example").submitPackAction(command, "csrf");
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(String(fetchSpy.mock.calls[0]![0])).toContain("/packs/actions");
    expect(new Headers(init?.headers).get("Idempotency-Key")).toBe(command.command_id);
    expect(new Headers(init?.headers).get("X-XSRF-TOKEN")).toBe("csrf");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ ...receipt, execution_pending: false }, 202));
    await expect(new ControlApiClient("https://control.example").submitPackAction(command, "csrf"))
      .rejects.toThrow("CONTROL_PACK_ACTION_RECEIPT_INVALID");
  });

  it("rejects an unexpected HTML response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("<html>error</html>", { status: 200,
      headers: { "Content-Type": "text/html" } }));
    await expect(new ControlApiClient("https://control.example").session()).rejects.toThrow("CONTROL_API_CONTENT_TYPE_INVALID");
  });
});
