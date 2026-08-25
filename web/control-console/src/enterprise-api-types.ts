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
export type EnterpriseActionReceipt = Schemas["EnterpriseActionReceipt"];
export type ApprovalIntentReceipt = Schemas["ApprovalIntentReceipt"];

export type AuthorityPage<T> = Omit<Schemas["AgentInventoryPage"], "items"> & { items: T[] };
export type AgentInventoryItem = Schemas["AgentInventoryItem"];

export type TaskCommand = Schemas["TaskCommand"];
export type PolicyOperation = Schemas["PolicyCommand"]["operation"];
export type PolicyRule = Schemas["PolicyRule"];
export type PolicySource = Schemas["PolicySource"];
export type PolicyAction = Schemas["PolicyAction"];
export type PolicyCommand = Schemas["PolicyCommand"];
export type PolicyActionReceipt = Schemas["PolicyActionReceipt"];
export type PolicySummary = Schemas["PolicySummary"];
export type PolicyPage = Schemas["PolicyPage"];
export type PolicyArtifact = Schemas["PolicyArtifact"];
export type PolicyReview = Schemas["PolicyReview"];
export type PolicyArtifactPage = Schemas["PolicyArtifactPage"];
export type PolicyArtifactType = PolicyArtifactPage["artifact_type"];
export type Incident = Schemas["Incident"];
export type IncidentPage = Schemas["IncidentPage"];
export type IncidentOperation = Schemas["IncidentCommand"]["operation"];
export type IncidentCommand = Schemas["IncidentCommand"];
export type IncidentActionReceipt = Schemas["IncidentActionReceipt"];
export type PackRelease = Schemas["PackRelease"];
export type PackInstallation = Schemas["PackInstallation"];
export type PackPage = Schemas["PackPage"];
export type MarketplaceTypedCommand = Schemas["MarketplaceTypedCommand"];
export type MarketplaceCommand = Schemas["MarketplaceCommand"];
export type MarketplaceActionReceipt = Schemas["MarketplaceActionReceipt"];

export type GovernedWriteCommand =
  | { kind: "CREATE_TENANT"; resource: string; payload: TenantRequest; reason: string }
  | { kind: "CREATE_ORGANIZATION"; resource: string; payload: OrganizationRequest; reason: string }
  | { kind: "CREATE_PROJECT"; resource: string; payload: ProjectRequest; reason: string }
  | { kind: "CREATE_INTEGRATION"; resource: string; payload: IntegrationRequest; reason: string }
  | { kind: "CONSUME_QUOTA"; resource: string; payload: QuotaConsumeRequest; reason: string }
  | { kind: "RECORD_COST"; resource: string; payload: CostUsageRequest; reason: string }
  | { kind: "ISSUE_API_KEY"; resource: "api-key:new"; payload: ApiKeyIssueRequest; reason: string }
  | { kind: "REVOKE_API_KEY"; resource: string; payload: string; reason: string }
  | { kind: `TASK_${TaskCommand["command_type"]}`; resource: string; payload: TaskCommand; reason: string };
