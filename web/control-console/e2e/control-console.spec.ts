import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const tenantId = "11111111-1111-4111-8111-111111111111";
const digest = "a".repeat(64);

async function installAuthority(page: Page): Promise<void> {
  await page.route("https://control.e2e.invalid/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/session") {
      await route.fulfill({ json: { schema_version: "agenttrust.enterprise-session.v1", tenant_id: tenantId,
        subject: "subject:e2e", project_ids: ["project-e2e"], approval_ids: ["approval:e2e"], roles: ["control-operator"],
        csrf_header_name: "X-XSRF-TOKEN", csrf_token: "e2e-csrf" } });
      return;
    }
    if (url.pathname.endsWith("/dashboard")) {
      await route.fulfill({ json: { schema_version: "agenttrust.enterprise-dashboard.v1", tenant_id: tenantId,
        complete: true, unavailable_sections: [], generated_at: "2026-08-13T00:00:00Z", sections: {
          TASKS: { schema_version: "agenttrust.authority-view.v1", section: "TASKS", authoritative: true,
            available: true, data: { items: [{ task_id: "task-e2e", runtime_status: "COMPLETED",
              ledger_terminal: true, evaluation_passed: true, evidence_verified: false,
              status_digest: digest, state_version: 7, safe_summary: "Evidence verification pending" }] },
            data_digest: digest, fetched_at: "2026-08-13T00:00:00Z" },
          APPROVALS: { schema_version: "agenttrust.authority-view.v1", section: "APPROVALS", authoritative: true,
            available: true, data: { items: [{ schema_version: "agenttrust.approval-case-view.v1", case_id: "20000000-0000-4000-8000-000000000001",
              domain: "CODING", safe_summary: "Review bounded source change", action_hash: digest,
              resource: "repo:example", resource_version: "commit:one", policy_version: "policy:v1", risk: "HIGH",
              diff_artifact_ref: "evidence://diff", rollback_summary: "Revert commit", evidence_refs: ["evidence://1"], status: "PENDING" }] },
            data_digest: digest, fetched_at: "2026-08-13T00:00:00Z" },
        } } });
      return;
    }
    if (url.pathname.endsWith("/intents")) {
      await route.fulfill({ status: 202, body: "" });
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

test("submits an approval intent with CSRF and never fabricates approval", async ({ page }) => {
  let captured: { headers: Record<string, string>; body: unknown } | null = null;
  await page.route("https://control.e2e.invalid/v1/tenants/*/approvals/*/intents", async (route) => {
    captured = { headers: route.request().headers(), body: route.request().postDataJSON() };
    await route.fulfill({ status: 202, body: "" });
  });
  await page.goto("/#/modules/approvals");
  await page.getByLabel("Decision reason").fill("independent review complete");
  await page.getByRole("button", { name: "Submit approval intent" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Approval intent accepted" })).toBeVisible();
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
