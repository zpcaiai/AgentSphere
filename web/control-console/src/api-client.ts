import type { ApprovalIntent } from "../../shared/agui-client";
import { validateDashboard, type EnterpriseDashboard, type GovernedAdminIntent } from "./control-state";
import { validatePolicyActionReceipt, validatePolicyArtifactPage, validatePolicyPage } from "./policy-contract";
import { validateIncident, validateIncidentActionReceipt, validateIncidentPage } from "./incident-contract";
import { validateMarketplaceActionReceipt, validatePackPage } from "./marketplace-contract";
import { INCIDENT_OPERATIONS } from "./incident-command";
import { marketplaceResource, validateMarketplaceTypedCommand } from "./marketplace-command";
import type {
  AgentInventoryItem,
  ApiKeyIssueRequest,
  AuthorityPage,
  CostUsageRequest,
  IntegrationRequest,
  EnterpriseActionReceipt,
  Incident,
  IncidentActionReceipt,
  IncidentCommand,
  IncidentPage,
  MarketplaceActionReceipt,
  MarketplaceCommand,
  OrganizationRequest,
  PolicyActionReceipt,
  PolicyArtifactPage,
  PolicyArtifactType,
  PolicyCommand,
  PolicyPage,
  PackPage,
  ProjectRequest,
  QuotaConsumeRequest,
  TaskCommand,
  TenantRequest,
} from "./enterprise-api-types";

const MAX_JSON_BYTES = 5_000_000;
const DIGEST = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ENTERPRISE_RECEIPT_FIELDS = [
  "schema_version", "action_id", "task_id", "accepted", "start_requested",
  "execution_pending", "ingress_digest", "evidence_ref", "evidence_digest",
].sort();
const AGENT_PAGE_FIELDS = [
  "schema_version", "authoritative", "tenant_id", "resource", "items", "next_cursor",
  "data_digest",
].sort();
const AGENT_ITEM_FIELDS = [
  "schema_version", "agent_id", "display_name", "owner_subject", "sponsor_subject",
  "ownership_status", "environment", "lifecycle", "agent_type", "bom_digest",
  "endpoint_count", "identity_count", "tool_count", "pack_count", "open_findings",
  "highest_risk", "last_activity_at", "registered_at", "updated_at",
].sort();
const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,5462}$/;

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
  owned_resources: string[];
  strong_auth: boolean;
  authentication_time: string | null;
  authentication_context: string | null;
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
      || !Array.isArray(value.owned_resources) || value.owned_resources.length > 1_024
      || typeof value.strong_auth !== "boolean"
      || (value.authentication_time !== null
        && (typeof value.authentication_time !== "string"
          || Number.isNaN(Date.parse(value.authentication_time))))
      || (value.authentication_context !== null
        && (typeof value.authentication_context !== "string"
          || !value.authentication_context || value.authentication_context.length > 256))
      || value.csrf_header_name !== "X-XSRF-TOKEN" || typeof value.csrf_token !== "string"
      || !value.csrf_token || value.csrf_token.length > 4_096
      || ![...value.project_ids, ...value.approval_ids, ...value.roles, ...value.owned_resources]
        .every((item) => typeof item === "string")
      || value.owned_resources.some((item) => !item || item.length > 2_048 || /[\0\r\n]/.test(item))
      || new Set(value.owned_resources).size !== value.owned_resources.length
      || (value.strong_auth
        && (value.authentication_time === null || value.authentication_context === null))) {
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
    if (!UUID.test(tenantId) || !Number.isSafeInteger(limit) || limit < 1 || limit > 100
      || (cursor !== null && !CURSOR.test(cursor))) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (cursor) query.set("cursor", cursor);
    const value = await this.requestJson<AuthorityPage<AgentInventoryItem>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/agents?${query.toString()}`,
    );
    if (!value || typeof value !== "object"
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(AGENT_PAGE_FIELDS)
      || value.schema_version !== "agenttrust.authoritative-agent-page.v1"
      || value.authoritative !== true || value.tenant_id !== tenantId || value.resource !== "summary"
      || !DIGEST.test(value.data_digest) || !Array.isArray(value.items) || value.items.length > limit
      || (value.next_cursor !== null && !CURSOR.test(value.next_cursor))
      || value.items.some((item) => !this.validAgentInventoryItem(item))) {
      throw new ControlApiError("CONTROL_AUTHORITY_PAGE_INVALID");
    }
    return value;
  }

  private validAgentInventoryItem(item: AgentInventoryItem): boolean {
    const integer = (value: unknown, minimum: number, maximum: number) =>
      Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
    const instant = (value: unknown) => typeof value === "string"
      && value.length <= 64 && !Number.isNaN(Date.parse(value));
    return Boolean(item && typeof item === "object"
      && JSON.stringify(Object.keys(item).sort()) === JSON.stringify(AGENT_ITEM_FIELDS)
      && item.schema_version === "agenttrust.agent-inventory-item.v1"
      && AGENT_ID.test(item.agent_id)
      && typeof item.display_name === "string" && item.display_name.length >= 1
      && item.display_name.length <= 256
      && typeof item.owner_subject === "string" && item.owner_subject.length >= 1
      && item.owner_subject.length <= 512
      && typeof item.sponsor_subject === "string" && item.sponsor_subject.length >= 1
      && item.sponsor_subject.length <= 512
      && ["PENDING", "CONFIRMED"].includes(item.ownership_status)
      && ["DEVELOPMENT", "STAGING", "PRODUCTION"].includes(item.environment)
      && ["DRAFT", "ACTIVE", "SUSPENDED", "RETIRED", "REVOKED"].includes(item.lifecycle)
      && typeof item.agent_type === "string" && item.agent_type.length >= 1
      && item.agent_type.length <= 128 && DIGEST.test(item.bom_digest)
      && integer(item.endpoint_count, 1, 100) && integer(item.identity_count, 1, 1_000)
      && integer(item.tool_count, 0, 1_000) && integer(item.pack_count, 0, 1_000)
      && integer(item.open_findings, 0, Number.MAX_SAFE_INTEGER)
      && (item.highest_risk === null
        || ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(item.highest_risk))
      && instant(item.last_activity_at) && instant(item.registered_at) && instant(item.updated_at));
  }

  async listPolicies(tenantId: string, afterPolicyId: string | null, limit = 50): Promise<PolicyPage> {
    if (!UUID.test(tenantId) || !Number.isSafeInteger(limit) || limit < 1 || limit > 100
      || (afterPolicyId !== null && !/^[A-Za-z0-9._:/-]{1,256}$/.test(afterPolicyId))) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (afterPolicyId) query.set("after_policy_id", afterPolicyId);
    const value = await this.requestJson<PolicyPage>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/policies?${query.toString()}`);
    try { return validatePolicyPage(value, tenantId, afterPolicyId, limit); }
    catch { throw new ControlApiError("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID"); }
  }

  async listPolicyArtifacts(tenantId: string, policyId: string, artifactType: PolicyArtifactType,
    limit = 50): Promise<PolicyArtifactPage> {
    const paths: Record<PolicyArtifactType, string> = {
      SOURCES: "sources", ANALYSES: "analyses", REVIEWS: "reviews", SIMULATIONS: "simulations",
      IMPACT_REPORTS: "impact-reports", PROMOTIONS: "promotions", EXCEPTIONS: "exceptions",
    };
    if (!UUID.test(tenantId) || !/^[A-Za-z0-9._:/-]{1,256}$/.test(policyId)
      || !Object.hasOwn(paths, artifactType) || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const value = await this.requestJson<PolicyArtifactPage>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/policies/${encodeURIComponent(policyId)}/${paths[artifactType]}?limit=${limit}`);
    try { return await validatePolicyArtifactPage(value, tenantId, policyId, artifactType, limit); }
    catch { throw new ControlApiError("CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID"); }
  }

  async submitPolicyAction(command: PolicyCommand, csrfToken: string): Promise<PolicyActionReceipt> {
    if (!UUID.test(command.tenant_id) || !UUID.test(command.command_id) || !csrfToken
      || csrfToken.length > 4_096) {
      throw new ControlApiError("CONTROL_POLICY_COMMAND_INVALID");
    }
    const response = await this.fetchWithTimeout(
      `/v1/tenants/${encodeURIComponent(command.tenant_id)}/policies/actions`, {
        ...this.jsonRequest("POST", command),
        headers: { "Content-Type": "application/json", Accept: "application/json",
          "Idempotency-Key": command.command_id, "X-XSRF-TOKEN": csrfToken },
      });
    const value = await this.parseJson<PolicyActionReceipt>(response, [202], MAX_JSON_BYTES);
    try { return validatePolicyActionReceipt(value, command.command_id); }
    catch { throw new ControlApiError("CONTROL_POLICY_ACTION_RECEIPT_INVALID"); }
  }

  async listIncidents(tenantId: string, afterIncidentId: string | null,
    limit = 50): Promise<IncidentPage> {
    if (!UUID.test(tenantId) || !Number.isSafeInteger(limit) || limit < 1 || limit > 100
      || (afterIncidentId !== null && !UUID.test(afterIncidentId))) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (afterIncidentId) query.set("after_incident_id", afterIncidentId);
    const value = await this.requestJson<IncidentPage>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/incidents?${query.toString()}`);
    try { return validateIncidentPage(value, tenantId, afterIncidentId, limit); }
    catch { throw new ControlApiError("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID"); }
  }

  async getIncident(tenantId: string, incidentId: string): Promise<Incident> {
    if (!UUID.test(tenantId) || !UUID.test(incidentId)) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const value = await this.requestJson<Incident>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/incidents/${encodeURIComponent(incidentId)}`);
    try { return validateIncident(value, incidentId); }
    catch { throw new ControlApiError("CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID"); }
  }

  async submitIncidentAction(command: IncidentCommand,
    csrfToken: string): Promise<IncidentActionReceipt> {
    if (!UUID.test(command.tenant_id) || !UUID.test(command.command_id)
      || !UUID.test(command.task_id) || !INCIDENT_OPERATIONS.includes(command.operation)
      || !Number.isSafeInteger(command.expected_resource_version)
      || command.expected_resource_version < 0 || typeof command.requested_at !== "string"
      || Number.isNaN(Date.parse(command.requested_at))
      || !command.payload || typeof command.payload !== "object" || Array.isArray(command.payload)
      || !incidentResourceBinding(command.operation, command.resource_id)
      || !csrfToken || csrfToken.length > 4_096) {
      throw new ControlApiError("CONTROL_INCIDENT_COMMAND_INVALID");
    }
    const response = await this.fetchWithTimeout(
      `/v1/tenants/${encodeURIComponent(command.tenant_id)}/incidents/actions`, {
        ...this.jsonRequest("POST", command),
        headers: { "Content-Type": "application/json", Accept: "application/json",
          "Idempotency-Key": command.command_id, "X-XSRF-TOKEN": csrfToken },
      });
    const value = await this.parseJson<IncidentActionReceipt>(response, [202], MAX_JSON_BYTES);
    try { return validateIncidentActionReceipt(value, command.command_id, command.task_id); }
    catch { throw new ControlApiError("CONTROL_INCIDENT_ACTION_RECEIPT_INVALID"); }
  }

  async listPacks(tenantId: string, search: string, afterPackId: string | null,
    limit = 50): Promise<PackPage> {
    if (!UUID.test(tenantId) || search.length > 128 || /[\0\r\n]/.test(search)
      || !Number.isSafeInteger(limit) || limit < 1 || limit > 100
      || (afterPackId !== null && !/^[A-Za-z0-9._:/@-]{1,128}$/.test(afterPackId))) {
      throw new ControlApiError("CONTROL_QUERY_INVALID");
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (search) query.set("query", search);
    if (afterPackId) query.set("after_pack_id", afterPackId);
    const value = await this.requestJson<PackPage>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/packs?${query.toString()}`);
    try { return await validatePackPage(value, tenantId, afterPackId, limit); }
    catch { throw new ControlApiError("CONTROL_PACK_AUTHORITY_RESPONSE_INVALID"); }
  }

  async submitPackAction(command: MarketplaceCommand,
    csrfToken: string): Promise<MarketplaceActionReceipt> {
    let typedCommand: MarketplaceCommand["command"];
    try { typedCommand = validateMarketplaceTypedCommand(command.command); }
    catch { throw new ControlApiError("CONTROL_PACK_COMMAND_INVALID"); }
    if (!UUID.test(command.tenant_id) || !UUID.test(command.command_id) || !csrfToken
      || csrfToken.length > 4_096 || marketplaceResource(typedCommand) !== command.resource_id
      || !Number.isSafeInteger(command.expected_resource_version)
      || command.expected_resource_version < 0 || typeof command.requested_at !== "string"
      || Number.isNaN(Date.parse(command.requested_at))) {
      throw new ControlApiError("CONTROL_PACK_COMMAND_INVALID");
    }
    const response = await this.fetchWithTimeout(
      `/v1/tenants/${encodeURIComponent(command.tenant_id)}/packs/actions`, {
        ...this.jsonRequest("POST", command),
        headers: { "Content-Type": "application/json", Accept: "application/json",
          "Idempotency-Key": command.command_id, "X-XSRF-TOKEN": csrfToken },
      });
    const value = await this.parseJson<MarketplaceActionReceipt>(response, [202], MAX_JSON_BYTES);
    try { return validateMarketplaceActionReceipt(value, command.command_id); }
    catch { throw new ControlApiError("CONTROL_PACK_ACTION_RECEIPT_INVALID"); }
  }

  async submitAdminIntent(value: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(
      `/v1/tenants/${encodeURIComponent(value.intent.tenant_id)}/admin/actions`,
      null,
      null,
      value,
    );
  }

  async createTenant(request: TenantRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}`,
      "tenant", request, governed);
  }

  async createOrganization(request: OrganizationRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/organizations`,
      "organization", request, governed);
  }

  async createProject(request: ProjectRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/projects`,
      "project", request, governed);
  }

  async createIntegration(request: IntegrationRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/integrations`,
      "integration", request, governed);
  }

  async consumeQuota(request: QuotaConsumeRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/quota/consume`,
      "quota", request, governed);
  }

  async recordCost(request: CostUsageRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(`/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/costs`,
      "cost", request, governed);
  }

  async issueApiKey(request: ApiKeyIssueRequest, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/api-keys`,
      "api_key", request, governed);
  }

  async revokeApiKey(apiKeyId: string, governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    return this.governedMutation(
      `/v1/tenants/${encodeURIComponent(governed.intent.tenant_id)}/api-keys/${encodeURIComponent(apiKeyId)}/revoke`,
      null, null, governed);
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

  private async governedMutation(path: string, field: string | null, value: unknown,
    governed: GovernedAdminIntent): Promise<EnterpriseActionReceipt> {
    const result = await this.governedPost<EnterpriseActionReceipt>(
      path, field, value, governed, [202]);
    if (!result || typeof result !== "object"
      || JSON.stringify(Object.keys(result).sort()) !== JSON.stringify(ENTERPRISE_RECEIPT_FIELDS)
      || result.schema_version !== "agenttrust.enterprise-action-receipt.v1"
      || !UUID.test(result.action_id) || result.action_id !== governed.intent.action_id
      || !UUID.test(result.task_id) || result.accepted !== true
      || result.start_requested !== true || result.execution_pending !== true
      || !DIGEST.test(result.ingress_digest) || !DIGEST.test(result.evidence_digest)
      || !new RegExp(`^orchestrator-event://${governed.intent.tenant_id}/${result.task_id}/[1-9][0-9]*$`)
        .test(result.evidence_ref)) {
      throw new ControlApiError("CONTROL_ENTERPRISE_RECEIPT_INVALID");
    }
    return result;
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
    if (response.status !== 204
      && response.headers.get("Content-Type")?.toLocaleLowerCase().includes("application/json")) {
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
      const contentType = response.headers.get("Content-Type")?.toLocaleLowerCase() ?? "";
      if (contentType.includes("application/json")) {
        try {
          const body = await response.clone().json() as unknown;
          if (typeof body === "object" && body !== null
            && (body as Record<string, unknown>).schema_version === "agenttrust.safe-error.v1"
            && typeof (body as Record<string, unknown>).code === "string"
            && /^CONTROL_[A-Z0-9_]{3,120}$/.test((body as Record<string, unknown>).code as string)) {
            throw new ControlApiError((body as Record<string, unknown>).code as string,
              response.status);
          }
        } catch (error) {
          if (error instanceof ControlApiError) throw error;
        }
      }
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

function incidentResourceBinding(operation: IncidentCommand["operation"], resourceId: string): boolean {
  const release = ["EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE"]
    .includes(operation);
  return release
    ? /^release:[A-Za-z0-9][A-Za-z0-9._:/-]{0,1015}$/.test(resourceId)
    : /^incident:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(resourceId);
}
