import { describe, expect, it, vi } from "vitest";
import { ControlApiClient } from "./api-client";
import type { GovernedAdminIntent } from "./control-state";

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
      project_ids: [], approval_ids: [], roles: ["viewer"], csrf_header_name: "X-XSRF-TOKEN", csrf_token: "csrf",
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
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(null, 201));
    const request = { organization_id: "one", display_name: "One", sponsor_subject: "subject:sponsor" };
    await new ControlApiClient("https://control.example").createOrganization(request, governed);
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(new Headers(init?.headers).get("X-XSRF-TOKEN")).toBe("csrf");
    expect(new Headers(init?.headers).get("Idempotency-Key")).toBe(governed.intent.action_id);
    expect(JSON.parse(String(init?.body))).toEqual({ organization: request, intent: governed.intent, reason: "because" });
  });

  it("submits approval as an intent and not a grant", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(null, 202));
    const intent = { schema_version: "agenttrust.approval-intent.v1" as const, case_id: "20000000-0000-4000-8000-000000000001",
      decision: "APPROVE" as const, reason: "reviewed", observed_action_hash: "b".repeat(64),
      observed_resource_version: "v1" };
    await new ControlApiClient("https://control.example").submitApprovalIntent(tenantId, intent, "csrf", "retry-key-0000001");
    const [, init] = fetchSpy.mock.calls[0]!;
    expect(JSON.parse(String(init?.body))).toEqual({ approval_intent: intent });
    expect(String(init?.body)).not.toContain("grant");
  });

  it("adds CSRF protection to side-effect-free policy simulation POST", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response({
      schema_version: "agenttrust.policy-simulation.v1", authoritative: true,
      impact_report_digest: "b".repeat(64), safe_summary: "bounded result",
    }));
    await new ControlApiClient("https://control.example").simulatePolicy(tenantId, "bundle-one", {
      schema_version: "agenttrust.policy-simulation-request.v1", candidate_digest: "c".repeat(64),
      corpus_digest: "d".repeat(64), maximum_cases: 100,
    }, "csrf");
    expect(new Headers(fetchSpy.mock.calls[0]![1]?.headers).get("X-XSRF-TOKEN")).toBe("csrf");
  });

  it("rejects an unexpected HTML response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("<html>error</html>", { status: 200,
      headers: { "Content-Type": "text/html" } }));
    await expect(new ControlApiClient("https://control.example").session()).rejects.toThrow("CONTROL_API_CONTENT_TYPE_INVALID");
  });
});
