export interface QuotaSpec {
  maximum_active_tasks: number;
  maximum_export_records: number;
  maximum_webhooks: number;
  maximum_api_requests_per_minute: number;
}

export interface TenantRequest {
  display_name: string;
  owner_subject: string;
  data_region: string;
  quota: QuotaSpec;
}

export interface OrganizationRequest {
  organization_id: string;
  display_name: string;
  sponsor_subject: string;
}

export interface ProjectRequest {
  project_id: string;
  organization_id: string;
  owner_subject: string;
  environments: string[];
}

export interface IntegrationRequest {
  integration_id: string;
  kind: "IAM" | "NOTIFICATION" | "TICKETING" | "SIEM" | "WEBHOOK";
  endpoint: string;
  secret_ref: string;
  configuration_digest: string;
  active: boolean;
}

export interface QuotaConsumeRequest {
  quota_key: string;
  window_started_at: string;
  amount: number;
  limit: number;
}

export interface QuotaUsage {
  schema_version: "agenttrust.quota-usage.v1";
  tenant_id: string;
  quota_key: string;
  window_started_at: string;
  used: number;
  limit: number;
}

export interface CostUsageRequest {
  usage_id: string;
  project_id: string;
  meter: string;
  quantity: number;
  unit_cost_micros: number;
  source_digest: string;
  recorded_at: string;
}

export interface ApiKeyIssueRequest {
  project_id: string | null;
  scopes: string[];
  expires_at: string;
}

export interface ApiKeyIssueResponse {
  schema_version: "agenttrust.api-key.v1";
  api_key_id: string;
  one_time_secret: string;
  created_at: string;
  expires_at: string;
  scopes: string[];
}
