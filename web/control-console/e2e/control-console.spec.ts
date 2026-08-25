import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { SERVICE_SECTIONS, type EnterpriseDashboard } from "../src/control-state";

const tenantId = "11111111-1111-4111-8111-111111111111";
const digest = "a".repeat(64);

async function installAuthority(page: Page): Promise<void> {
  await page.route("https://control.e2e.invalid/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/session") {
      await route.fulfill({ json: { schema_version: "agenttrust.enterprise-session.v1", tenant_id: tenantId,
        subject: "subject:e2e", project_ids: ["project-e2e"], approval_ids: ["approval:e2e"], roles: ["control-operator"],
        owned_resources: ["repo:example"], strong_auth: true,
        authentication_time: "2026-08-13T00:00:00Z", authentication_context: "urn:agenttrust:acr:mfa",
        csrf_header_name: "X-XSRF-TOKEN", csrf_token: "e2e-csrf" } });
      return;
    }
    if (url.pathname.endsWith("/dashboard")) {
      const sections = Object.fromEntries(SERVICE_SECTIONS.map((section) => [section, {
        schema_version: "agenttrust.authority-view.v1" as const,
        section,
        authoritative: true as const,
        available: true,
        data: { items: [] },
        data_digest: digest,
        fetched_at: "2026-08-13T00:00:00Z",
      }])) as EnterpriseDashboard["sections"];
      sections.TASKS = { schema_version: "agenttrust.authority-view.v1", section: "TASKS",
        authoritative: true, available: true,
        data: { items: [{ task_id: "task-e2e", runtime_status: "COMPLETED",
          ledger_terminal: true, evaluation_passed: true, evidence_verified: false,
          status_digest: digest, state_version: 7, safe_summary: "Evidence verification pending" }] },
        data_digest: digest, fetched_at: "2026-08-13T00:00:00Z" };
      sections.APPROVALS = { schema_version: "agenttrust.authority-view.v1", section: "APPROVALS",
        authoritative: true, available: true,
        data: { schema_version: "agenttrust.authoritative-approval-page.v1", authoritative: true,
          tenant_id: tenantId, resource: "summary", items: [{ schema_version: "agenttrust.approval-case-view.v1",
            case_id: "20000000-0000-4000-8000-000000000001", domain: "CODING",
            safe_summary: "Review bounded source change", action_hash: digest, resource: "repo:example",
            resource_version: "commit:one", policy_version: "policy:v1", risk: "HIGH",
            coding_details: { diff_artifact_ref: `artifact://sha256/${digest}`,
              command_summary: "Apply the reviewed repository patch", network_scope: "egress:none",
              rollback_summary: "Restore the reviewed parent revision" },
            evidence_refs: ["evidence://risk-package/1", "evidence://state-snapshot/1",
              "evidence://approval-review/1"], status: "PENDING" }], next_cursor: null,
          data_digest: digest },
        data_digest: digest, fetched_at: "2026-08-13T00:00:00Z" };
      await route.fulfill({ json: { schema_version: "agenttrust.enterprise-dashboard.v1", tenant_id: tenantId,
        complete: true, unavailable_sections: [], generated_at: "2026-08-13T00:00:00Z",
        sections } });
      return;
    }
    if (url.pathname.endsWith("/intents")) {
      await route.fulfill({ status: 503, json: { schema_version: "agenttrust.safe-error.v1",
        code: "CONTROL_APPROVAL_OUTCOME_UNKNOWN",
        trace_id: "40000000-0000-4000-8000-000000000001",
        occurred_at: "2026-08-13T00:00:00Z" } });
      return;
    }
    if (/\/v1\/tenants\/[^/]+\/policies$/.test(url.pathname)) {
      await route.fulfill({ json: { schema_version: "agenttrust.authoritative-policy-page.v1",
        tenant_id: tenantId, items: [{ policy_id: "policy-e2e", revision: 1,
          lifecycle_state: "VALIDATED", source_digest: digest, author_subject: "subject:author",
          active_bundle_digest: null, active_environment: null, resource_version: 3,
          updated_at: "2026-08-13T00:00:00Z" }], next_after_policy_id: null } });
      return;
    }
    if (/\/v1\/tenants\/[^/]+\/incidents$/.test(url.pathname)) {
      await route.fulfill({ json: { schema_version: "agenttrust.authoritative-incident-page.v1",
        tenant_id: tenantId, items: [], next_after_incident_id: null } });
      return;
    }
    if (url.pathname.endsWith("/incidents/actions")) {
      const command = route.request().postDataJSON() as { command_id: string; task_id: string };
      await route.fulfill({ status: 202, json: { schema_version: "agenttrust.incident-action-receipt.v1",
        action_id: command.command_id, task_id: command.task_id, accepted: true,
        execution_pending: true, ingress_digest: digest,
        ledger_evidence_ref: "urn:agenttrust:ledger-evidence:incident-e2e",
        ledger_evidence_digest: digest } });
      return;
    }
    if (/\/v1\/tenants\/[^/]+\/packs$/.test(url.pathname)) {
      await route.fulfill({ json: { schema_version: "agenttrust.authoritative-pack-page.v1",
        authoritative: true, tenant_id: tenantId, releases: [], installations: [],
        next_after_pack_id: null,
        data_digest: "b547f29289a5ed269586744e024fb85f6bc465c61f8d45f583403a8f4401109a" } });
      return;
    }
    if (url.pathname.endsWith("/packs/actions")) {
      const command = route.request().postDataJSON() as { command_id: string };
      await route.fulfill({ status: 202, json: { schema_version: "agenttrust.marketplace-action-receipt.v1",
        action_id: command.command_id, task_id: "30000000-0000-4000-8000-000000000002",
        accepted: true, execution_pending: true, ingress_digest: digest,
        ledger_evidence_ref: "urn:agenttrust:ledger-evidence:pack-e2e",
        ledger_evidence_digest: digest } });
      return;
    }
    if (url.pathname.endsWith("/policies/actions")) {
      const command = route.request().postDataJSON() as { command_id: string };
      await route.fulfill({ status: 202, json: { schema_version: "agenttrust.policy-action-receipt.v1",
        action_id: command.command_id, task_id: "30000000-0000-4000-8000-000000000001",
        accepted: true, execution_pending: true, ingress_digest: digest,
        ledger_evidence_ref: "urn:agenttrust:ledger-evidence:policy-e2e",
        ledger_evidence_digest: digest } });
      return;
    }
    await route.fulfill({ status: 404, json: { code: "NOT_FOUND" } });
  });
}

test.beforeEach(async ({ page }) => { await installAuthority(page); });

test("loads BFF tasks and refuses a UI-only completion claim", async ({ page }) => {
  await page.goto("/#/modules/tasks");
  await expect(page.getByRole("heading", { name: "Task runtime" })).toBeVisible();
  await expect(page.getByText("task-e2e")).toBeVisible();
  await expect(page.getByText("VERIFYING")).toBeVisible();
  await expect(page.getByRole("button", { name: /task-e2e/ })).not.toContainText("COMPLETED");
});

test("renders every production runtime authority through a dedicated module route", async ({ page }) => {
  for (const module of ["models", "data", "context", "anomalies", "security_evaluations",
    "supply_chain", "domain_packs"] as const) {
    await page.goto(`/#/modules/${module}`);
    await expect(page.getByRole("heading", { name: module.toUpperCase(), exact: true })).toBeVisible();
    await expect(page.getByText(/No records|暂无记录/)).toBeVisible();
  }
});

test("submits an approval intent but keeps status unknown without immutable evidence", async ({ page }) => {
  let captured: { headers: Record<string, string>; body: unknown } | null = null;
  await page.route("https://control.e2e.invalid/v1/tenants/*/approvals/*/intents", async (route) => {
    captured = { headers: route.request().headers(), body: route.request().postDataJSON() };
    await route.fulfill({ status: 503, json: { schema_version: "agenttrust.safe-error.v1",
      code: "CONTROL_APPROVAL_OUTCOME_UNKNOWN",
      trace_id: "40000000-0000-4000-8000-000000000001",
      occurred_at: "2026-08-13T00:00:00Z" } });
  });
  await page.goto("/#/modules/approvals");
  await page.getByLabel("Decision reason").fill("independent review complete");
  await page.getByRole("button", { name: "Submit approval intent" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "CONTROL_APPROVAL_OUTCOME_UNKNOWN" })).toBeVisible();
  expect(captured).not.toBeNull();
  expect(captured!.headers["x-xsrf-token"]).toBe("e2e-csrf");
  expect(JSON.stringify(captured!.body)).toContain("approval_intent");
  expect(JSON.stringify(captured!.body)).not.toContain("approval_grant");
});

test("has no automatically detectable critical accessibility violations", async ({ page }) => {
  await page.goto("/#/modules/overview");
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((item) => item.impact === "critical")).toEqual([]);
});

test("Incident and Pack workstations have no critical accessibility violations", async ({ page }) => {
  for (const module of ["incidents", "packs"]) {
    await page.goto(`/#/modules/${module}`);
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations.filter((item) => item.impact === "critical"), module).toEqual([]);
  }
});

test("admits Policy lifecycle through one pending Canonical Action route", async ({ page }) => {
  let captured: { headers: Record<string, string>; body: Record<string, unknown> } | null = null;
  await page.route("https://control.e2e.invalid/v1/tenants/*/policies/actions", async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    captured = { headers: route.request().headers(), body };
    await route.fulfill({ status: 202, json: { schema_version: "agenttrust.policy-action-receipt.v1",
      action_id: body.command_id, task_id: "30000000-0000-4000-8000-000000000001",
      accepted: true, execution_pending: true, ingress_digest: digest,
      ledger_evidence_ref: "urn:agenttrust:ledger-evidence:policy-e2e",
      ledger_evidence_digest: digest } });
  });
  await page.goto("/#/modules/policies");
  await page.getByRole("button", { name: "Select policy-e2e" }).click();
  await page.getByLabel("Operation").selectOption("VALIDATE");
  await page.getByRole("button", { name: /Admit canonical action|提交 Canonical Action/ }).click();
  await expect(page.getByText(/execution and lifecycle completion remain pending|执行与生命周期完成仍在等待中/)).toBeVisible();
  expect(captured).not.toBeNull();
  expect(captured!.headers["x-xsrf-token"]).toBe("e2e-csrf");
  expect(captured!.headers["idempotency-key"]).toBe(captured!.body.command_id);
  expect(captured!.body.operation).toBe("VALIDATE");
});

test("admits an Incident command but keeps containment and release state pending", async ({ page }) => {
  let captured: { headers: Record<string, string>; body: Record<string, unknown> } | null = null;
  await page.route("https://control.e2e.invalid/v1/tenants/*/incidents/actions", async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    captured = { headers: route.request().headers(), body };
    await route.fulfill({ status: 202, json: { schema_version: "agenttrust.incident-action-receipt.v1",
      action_id: body.command_id, task_id: body.task_id, accepted: true, execution_pending: true,
      ingress_digest: digest, ledger_evidence_ref: "urn:agenttrust:ledger-evidence:incident-e2e",
      ledger_evidence_digest: digest } });
  });
  await page.goto("/#/modules/incidents");
  await page.getByLabel("Incident UUID").fill("20000000-0000-4000-8000-000000000001");
  await page.getByLabel("Task UUID").fill("30000000-0000-4000-8000-000000000001");
  await page.getByLabel("Operation").selectOption("INVESTIGATE");
  await page.getByRole("button", { name: /Admit canonical incident action|提交 Canonical Incident Action/ }).click();
  await expect(page.getByText(/execution, remediation, release, and rollback state remain pending|执行、修复、发布与回滚状态仍在等待中/)).toBeVisible();
  expect(captured).not.toBeNull();
  expect(captured!.headers["x-xsrf-token"]).toBe("e2e-csrf");
  expect(captured!.headers["idempotency-key"]).toBe(captured!.body.command_id);
  expect(captured!.body.operation).toBe("INVESTIGATE");
});

test("covers Pack typed lifecycle without treating install or active as task authorization", async ({ page }) => {
  let captured: { headers: Record<string, string>; body: Record<string, unknown> } | null = null;
  await page.route("https://control.e2e.invalid/v1/tenants/*/packs/actions", async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    captured = { headers: route.request().headers(), body };
    await route.fulfill({ status: 202, json: { schema_version: "agenttrust.marketplace-action-receipt.v1",
      action_id: body.command_id, task_id: "30000000-0000-4000-8000-000000000002",
      accepted: true, execution_pending: true, ingress_digest: digest,
      ledger_evidence_ref: "urn:agenttrust:ledger-evidence:pack-e2e",
      ledger_evidence_digest: digest } });
  });
  await page.goto("/#/modules/packs");
  await expect(page.getByText("INSTALL does not ACTIVATE")).toBeVisible();
  await page.getByRole("button", { name: /Admit canonical pack action|提交 Canonical Pack Action/ }).click();
  await expect(page.getByText(/no pack is authorized for a task by this receipt|不会授权任何任务使用 Pack/)).toBeVisible();
  expect(captured).not.toBeNull();
  expect(captured!.headers["x-xsrf-token"]).toBe("e2e-csrf");
  expect(captured!.headers["idempotency-key"]).toBe(captured!.body.command_id);
  expect((captured!.body.command as { kind: string }).kind).toBe("ONBOARD_PUBLISHER");
});

test("signs out through the server and returns to the OIDC entry screen", async ({ page }) => {
  let logoutHeaders: Record<string, string> | null = null;
  await page.route("https://control.e2e.invalid/v1/session/logout", async (route) => {
    logoutHeaders = route.request().headers();
    await route.fulfill({ status: 204, body: "" });
  });
  await page.goto("/#/modules/overview");
  await page.getByRole("button", { name: /Sign out|退出登录/ }).click();
  await expect(page.getByRole("link", { name: /Sign in|登录/ })).toHaveAttribute(
    "href", "https://control.e2e.invalid/oauth2/authorization/agenttrust",
  );
  expect(logoutHeaders).not.toBeNull();
  expect(logoutHeaders!["x-xsrf-token"]).toBe("e2e-csrf");
});
