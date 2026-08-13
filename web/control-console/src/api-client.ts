import type { EnterpriseDashboard, GovernedAdminIntent, TaskAuthorityStatus } from "./control-state";
import type {
  ApiKeyIssueRequest,
  ApiKeyIssueResponse,
  CostUsageRequest,
  IntegrationRequest,
  OrganizationRequest,
  ProjectRequest,
  QuotaConsumeRequest,
  QuotaUsage,
  TenantRequest,
} from "./enterprise-api-types";

export interface DashboardPayload {
  dashboard: EnterpriseDashboard;
  tasks: TaskAuthorityStatus[];
}

export class ControlApiClient {
  constructor(private readonly baseUrl: string, private readonly timeoutMs = 10_000) {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "https:" || timeoutMs < 100 || timeoutMs > 30_000) {
      throw new Error("CONTROL_API_CONFIG_INVALID");
    }
  }

  async dashboard(tenantId: string): Promise<EnterpriseDashboard> {
    return this.request<EnterpriseDashboard>(`/v1/tenants/${encodeURIComponent(tenantId)}/dashboard?resource=summary&limit=50`);
  }

  async submitAdminIntent(value: GovernedAdminIntent): Promise<void> {
    const response = await this.fetchWithTimeout(
      `/v1/tenants/${encodeURIComponent(value.intent.tenant_id)}/admin/actions`,
      {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": value.intent.action_id,
          "X-XSRF-TOKEN": value.csrf_token,
        },
        body: JSON.stringify({ intent: value.intent, reason: value.reason }),
      },
    );
    if (response.status !== 202) throw new Error(`CONTROL_ADMIN_INTENT_REJECTED_${response.status}`);
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
    return this.governedPost<QuotaUsage>(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/quota/consume`,
      "quota", request, governed, [200]);
  }

  async recordCost(request: CostUsageRequest, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/costs`,
      "cost", request, governed, [202]);
  }

  async issueApiKey(request: ApiKeyIssueRequest, governed: GovernedAdminIntent): Promise<ApiKeyIssueResponse> {
    return this.governedPost<ApiKeyIssueResponse>(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/api-keys`,
      "api_key", request, governed, [201]);
  }

  async revokeApiKey(apiKeyId: string, governed: GovernedAdminIntent): Promise<void> {
    await this.governedPost(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/api-keys/${encodeURIComponent(apiKeyId)}/revoke`,
      null, null, governed, [204]);
  }

  private async governedPost<T = void>(path: string, field: string | null, value: unknown,
                                       governed: GovernedAdminIntent, expected: number[]): Promise<T> {
    const body: Record<string, unknown> = { intent: governed.intent, reason: governed.reason };
    if (field) body[field] = value;
    const response = await this.fetchWithTimeout(path, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": governed.intent.action_id,
        "X-XSRF-TOKEN": governed.csrf_token,
      },
      body: JSON.stringify(body),
    });
    if (!expected.includes(response.status)) throw new Error(`CONTROL_GOVERNED_WRITE_REJECTED_${response.status}`);
    if (response.status === 204 || response.headers.get("Content-Length") === "0") return undefined as T;
    const text = await response.text();
    if (text.length > 1_000_000) throw new Error("CONTROL_API_RESPONSE_TOO_LARGE");
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private async request<T>(path: string): Promise<T> {
    const response = await this.fetchWithTimeout(path, { credentials: "include", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`CONTROL_API_UNAVAILABLE_${response.status}`);
    const text = await response.text();
    if (text.length > 5_000_000) throw new Error("CONTROL_API_RESPONSE_TOO_LARGE");
    return JSON.parse(text) as T;
  }

  private async fetchWithTimeout(path: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(new URL(path, this.baseUrl), { ...init, signal: controller.signal });
    } finally {
      window.clearTimeout(timeout);
    }
  }
}
