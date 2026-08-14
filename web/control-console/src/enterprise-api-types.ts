import type { components } from "./generated/control-plane-v1";

type Schemas = components["schemas"];
export type QuotaSpec = Schemas["QuotaSpec"];
export type TenantRequest = Schemas["TenantRequest"];
export type OrganizationRequest = Schemas["OrganizationRequest"];
export type ProjectRequest = Schemas["ProjectRequest"];
export type IntegrationRequest = Schemas["IntegrationRequest"];
export type QuotaConsumeRequest = Schemas["QuotaConsumeRequest"];
export type QuotaUsage = Schemas["QuotaUsage"];
export type CostUsageRequest = Schemas["CostUsageRequest"];
export type ApiKeyIssueRequest = Schemas["ApiKeyIssueRequest"];
export type ApiKeyIssueResponse = Schemas["ApiKeyIssueResponse"];

export interface AuthorityPage<T> {
  schema_version: string;
  authoritative: true;
  items: T[];
  next_cursor: string | null;
}

export interface AgentInventoryItem {
  agent_id: string;
  version?: string;
  posture?: string;
  safe_summary?: string;
  [key: string]: unknown;
}

export type TaskCommand = Schemas["TaskCommand"];
export type PolicySimulationRequest = Schemas["PolicySimulationRequest"];

export interface PolicySimulationResult {
  schema_version: string;
  authoritative: true;
  impact_report_digest: string;
  safe_summary: string;
}

export type PolicyPromotionRequest = Schemas["PolicyPromotionRequest"];

export type GovernedWriteCommand =
  | { kind: "CREATE_TENANT"; resource: string; payload: TenantRequest; reason: string }
  | { kind: "CREATE_ORGANIZATION"; resource: string; payload: OrganizationRequest; reason: string }
  | { kind: "CREATE_PROJECT"; resource: string; payload: ProjectRequest; reason: string }
  | { kind: "CREATE_INTEGRATION"; resource: string; payload: IntegrationRequest; reason: string }
  | { kind: "CONSUME_QUOTA"; resource: string; payload: QuotaConsumeRequest; reason: string }
  | { kind: "RECORD_COST"; resource: string; payload: CostUsageRequest; reason: string }
  | { kind: "ISSUE_API_KEY"; resource: "api-key:new"; payload: ApiKeyIssueRequest; reason: string }
  | { kind: "REVOKE_API_KEY"; resource: string; payload: string; reason: string }
  | { kind: "PROMOTE_POLICY"; resource: string; payload: PolicyPromotionRequest; reason: string }
  | { kind: `TASK_${TaskCommand["command_type"]}`; resource: string; payload: TaskCommand; reason: string };
