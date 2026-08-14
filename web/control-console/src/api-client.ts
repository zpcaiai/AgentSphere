import type { ApprovalIntent } from "../../shared/agui-client";
import { validateDashboard, type EnterpriseDashboard, type GovernedAdminIntent } from "./control-state";
import type {
  AgentInventoryItem,
  ApiKeyIssueRequest,
  ApiKeyIssueResponse,
  AuthorityPage,
  CostUsageRequest,
  IntegrationRequest,
  OrganizationRequest,
  PolicyPromotionRequest,
  PolicySimulationRequest,
  PolicySimulationResult,
  ProjectRequest,
  QuotaConsumeRequest,
  QuotaUsage,
  TaskCommand,
  TenantRequest,
} from "./enterprise-api-types";

const MAX_JSON_BYTES = 5_000_000;
const MAX_SECRET_RESPONSE_BYTES = 64_000;
const DIGEST = /^[a-f0-9]{64}$/;

export class ControlApiError extends Error {
  constructor(readonly code: string, readonly status: number | null = null) {
    super(code);
    this.name = "ControlApiError";
  }
}

export interface SessionContext {
  schema_version: "agenttrust.enterprise-session.v1";
  tenant_id: string;
  subject: string;
  project_ids: string[];
  approval_ids: string[];
  roles: string[];
  csrf_header_name: "X-XSRF-TOKEN";
  csrf_token: string;
}

export class ControlApiClient {
  private readonly origin: string;

  constructor(private readonly baseUrl: string, private readonly timeoutMs = 10_000) {
    let parsed: URL;
    try {
      parsed = new URL(baseUrl);
    } catch {
      throw new ControlApiError("CONTROL_API_CONFIG_INVALID");
    }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash
      || timeoutMs < 100 || timeoutMs > 30_000) {
      throw new ControlApiError("CONTROL_API_CONFIG_INVALID");
    }
    this.origin = parsed.origin;
  }

  signInUrl(): string {
    return new URL("/oauth2/authorization/agenttrust", this.baseUrl).toString();
  }

  async dashboard(tenantId: string, resource = "summary", limit = 50): Promise<EnterpriseDashboard> {
    if (!resource || resource.length > 100 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const query = new URLSearchParams({ resource, limit: String(limit) });
    const result = await this.requestJson<EnterpriseDashboard>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/dashboard?${query.toString()}`,
    );
    return validateDashboard(result);
  }

  async session(): Promise<SessionContext> {
    const value = await this.requestJson<SessionContext>("/v1/session");
    if (!value || value.schema_version !== "agenttrust.enterprise-session.v1"
      || typeof value.tenant_id !== "string" || typeof value.subject !== "string" || !value.subject
      || !Array.isArray(value.project_ids) || value.project_ids.length > 1_000
      || !Array.isArray(value.approval_ids) || value.approval_ids.length > 16
      || !Array.isArray(value.roles) || value.roles.length > 100
      || value.csrf_header_name !== "X-XSRF-TOKEN" || typeof value.csrf_token !== "string"
      || !value.csrf_token || value.csrf_token.length > 4_096
      || ![...value.project_ids, ...value.approval_ids, ...value.roles].every((item) => typeof item === "string")) {
      throw new ControlApiError("CONTROL_SESSION_INVALID");
    }
    return value;
  }

  async logout(csrfToken: string): Promise<void> {
    if (!csrfToken || csrfToken.length > 4_096) {
      throw new ControlApiError("CONTROL_SESSION_INVALID");
    }
    const response = await this.fetchWithTimeout("/v1/session/logout", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      redirect: "error",
      headers: { Accept: "application/json", "X-XSRF-TOKEN": csrfToken },
    });
    await this.requireStatus(response, [204]);
  }

  async listAgents(tenantId: string, cursor: string | null, limit = 50): Promise<AuthorityPage<AgentInventoryItem>> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || (cursor?.length ?? 0) > 2_000) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (cursor) query.set("cursor", cursor);
    const value = await this.requestJson<AuthorityPage<AgentInventoryItem>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/agents?${query.toString()}`,
    );
    if (!value || value.authoritative !== true || !Array.isArray(value.items) || value.items.length > limit
      || (value.next_cursor !== null && typeof value.next_cursor !== "string")) {
      throw new ControlApiError("CONTROL_AUTHORITY_PAGE_INVALID");
    }
    return value;
  }

  async simulatePolicy(tenantId: string, bundleId: string,
    request: PolicySimulationRequest, csrfToken: string): Promise<PolicySimulationResult> {
    const response = await this.fetchWithTimeout(
      `/v1/tenants/${encodeURIComponent(tenantId)}/policies/${encodeURIComponent(bundleId)}/simulate`,
      {
        ...this.jsonRequest("POST", request),
        headers: { "Content-Type": "application/json", Accept: "application/json", "X-XSRF-TOKEN": csrfToken },
      },
    );
    const result = await this.parseJson<PolicySimulationResult>(response, [200], MAX_JSON_BYTES);
    if (result.authoritative !== true || !DIGEST.test(result.impact_report_digest)
      || typeof result.safe_summary !== "string") {
      throw new ControlApiError("CONTROL_POLICY_SIMULATION_INVALID");
    }
    return result;
  }

  async submitAdminIntent(value: GovernedAdminIntent): Promise<void> {
    await this.governedPost(
      `/v1/tenants/${encodeURIComponent(value.intent.tenant_id)}/admin/actions`,
      null,
      null,
      value,
      [202],
    );
  }

  async createTenant(request: TenantRequest, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}`,
      "tenant", request, governed, [201]);
  }

  async createOrganization(request: OrganizationRequest, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/organizations`,
      "organization", request, governed, [201]);
  }

  async createProject(request: ProjectRequest, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/projects`,
      "project", request, governed, [201]);
  }

  async createIntegration(request: IntegrationRequest, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/integrations`,
      "integration", request, governed, [201]);
  }

  async consumeQuota(request: QuotaConsumeRequest, governed: GovernedAdminIntent): Promise<QuotaUsage> {
    const result = await this.governedPost<QuotaUsage>(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/quota/consume`,
      "quota", request, governed, [200]);
    if (result.schema_version !== "agenttrust.quota-usage.v1" || result.tenant_id !== governed.intent.tenant_id
      || !Number.isSafeInteger(result.used) || !Number.isSafeInteger(result.limit)) {
      throw new ControlApiError("CONTROL_QUOTA_RESPONSE_INVALID");
    }
    return result;
  }

  async recordCost(request: CostUsageRequest, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/costs`,
      "cost", request, governed, [202]);
  }

  async issueApiKey(request: ApiKeyIssueRequest, governed: GovernedAdminIntent): Promise<ApiKeyIssueResponse> {
    const result = await this.governedPost<ApiKeyIssueResponse>(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/api-keys`,
      "api_key", request, governed, [201], MAX_SECRET_RESPONSE_BYTES);
    if (result.schema_version !== "agenttrust.api-key.v1"
      || !/^atk_[A-Za-z0-9_-]{43}$/.test(result.one_time_secret)
      || typeof result.api_key_id !== "string") {
      throw new ControlApiError("CONTROL_API_KEY_RESPONSE_INVALID");
    }
    return result;
  }

  async revokeApiKey(apiKeyId: string, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/api-keys/${encodeURIComponent(apiKeyId)}/revoke`,
      null, null, governed, [204]);
  }

  async promotePolicy(bundleId: string, request: PolicyPromotionRequest,
    governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/policies/${encodeURIComponent(bundleId)}/promotions`,
      "promotion", request, governed, [202]);
  }

  async submitTaskCommand(taskId: string, command: TaskCommand,
    governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/tasks/${encodeURIComponent(taskId)}/commands`,
      "command", command, governed, [202]);
  }

  async submitApprovalIntent(tenantId: string, value: ApprovalIntent, csrfToken: string,
    idempotencyKey: string): Promise<void> {
    if (!csrfToken || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.case_id)) {
      throw new ControlApiError("CONTROL_APPROVAL_INTENT_INVALID");
    }
    const response = await this.fetchWithTimeout(
      `/v1/tenants/${encodeURIComponent(tenantId)}/approvals/${encodeURIComponent(value.case_id)}/intents`,
      {
        ...this.jsonRequest("POST", { approval_intent: value }),
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
          "X-XSRF-TOKEN": csrfToken,
        },
      },
    );
    await this.requireStatus(response, [202]);
  }

  private async governedPost<T = void>(path: string, field: string | null, value: unknown,
    governed: GovernedAdminIntent, expected: number[], maximumBytes = MAX_JSON_BYTES): Promise<T> {
    const body: Record<string, unknown> = { intent: governed.intent, reason: governed.reason };
    if (field) body[field] = value;
    const response = await this.fetchWithTimeout(path, {
      ...this.jsonRequest("POST", body),
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": governed.intent.action_id,
        "X-XSRF-TOKEN": governed.csrf_token,
      },
    });
    if (expected.includes(204)) {
      await this.requireStatus(response, expected);
      return undefined as T;
    }
    if (expected.every((status) => status === 201 || status === 200) && response.status !== 204
      && response.headers.get("Content-Type")?.includes("application/json")) {
      return this.parseJson<T>(response, expected, maximumBytes);
    }
    await this.requireStatus(response, expected);
    return undefined as T;
  }

  private jsonRequest(method: "POST", body: unknown): RequestInit {
    return {
      method,
      credentials: "include",
      cache: "no-store",
      redirect: "error",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    };
  }

  private async requestJson<T>(path: string): Promise<T> {
    const response = await this.fetchWithTimeout(path, {
      credentials: "include",
      cache: "no-store",
      redirect: "error",
      headers: { Accept: "application/json" },
    });
    return this.parseJson<T>(response, [200], MAX_JSON_BYTES);
  }

  private async parseJson<T>(response: Response, expected: number[], maximumBytes: number): Promise<T> {
    await this.requireStatus(response, expected);
    if (!response.headers.get("Content-Type")?.toLocaleLowerCase().includes("application/json")) {
      throw new ControlApiError("CONTROL_API_CONTENT_TYPE_INVALID", response.status);
    }
    const contentLength = Number(response.headers.get("Content-Length") ?? 0);
    if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
      throw new ControlApiError("CONTROL_API_RESPONSE_TOO_LARGE", response.status);
    }
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maximumBytes) {
      throw new ControlApiError("CONTROL_API_RESPONSE_TOO_LARGE", response.status);
    }
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new ControlApiError("CONTROL_API_JSON_INVALID", response.status);
    }
  }

  private async requireStatus(response: Response, expected: number[]): Promise<void> {
    if (!expected.includes(response.status)) {
      throw new ControlApiError(`CONTROL_API_REJECTED_${response.status}`, response.status);
    }
  }

  private async fetchWithTimeout(path: string, init: RequestInit): Promise<Response> {
    const target = new URL(path, this.baseUrl);
    if (target.origin !== this.origin) throw new ControlApiError("CONTROL_API_ORIGIN_INVALID");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(target, { ...init, signal: controller.signal });
    } catch (error) {
      if (error instanceof ControlApiError) throw error;
      throw new ControlApiError(error instanceof DOMException && error.name === "AbortError"
        ? "CONTROL_API_TIMEOUT" : "CONTROL_API_UNAVAILABLE");
    } finally {
      window.clearTimeout(timeout);
    }
  }
}
