export type ServiceSection =
  | "TASKS"
  | "INCIDENTS"
  | "AGENTS"
  | "TOOLS"
  | "CREDENTIALS"
  | "APPROVALS"
  | "POLICIES"
  | "PACKS"
  | "TRACE"
  | "EVIDENCE"
  | "COMPLIANCE"
  | "AUDIT"
  | "SRE"
  | "DEPLOYMENTS";

export interface AuthoritySection<T> {
  schema_version: "agenttrust.authority-view.v1";
  section: ServiceSection;
  authoritative: true;
  available: boolean;
  data: T | null;
  data_digest: string;
  safe_error_code?: "AUTHORITATIVE_SOURCE_UNAVAILABLE";
  fetched_at: string;
}

export interface EnterpriseDashboard {
  schema_version: "agenttrust.enterprise-dashboard.v1";
  tenant_id: string;
  sections: Partial<Record<ServiceSection, AuthoritySection<unknown>>>;
  complete: boolean;
  unavailable_sections: ServiceSection[];
}

export interface TaskAuthorityStatus {
  task_id: string;
  runtime_status: string;
  ledger_terminal: boolean;
  evaluation_passed: boolean;
  evidence_verified: boolean;
  status_digest: string;
}

export interface AdminIntent {
  schema_version: "agenttrust.enterprise-control.v1";
  action_id: string;
  tenant_id: string;
  project_id: string | null;
  operation: string;
  resource: string;
  requested_by: string;
  approval_ids: string[];
  action_digest: string;
  requested_at: string;
}

export interface GovernedAdminIntent {
  intent: AdminIntent;
  reason: string;
  csrf_token: string;
}

const DIGEST = /^[a-f0-9]{64}$/;

export function validateDashboard(value: EnterpriseDashboard): EnterpriseDashboard {
  if (!value.tenant_id || value.schema_version !== "agenttrust.enterprise-dashboard.v1") {
    throw new Error("ENTERPRISE_DASHBOARD_INVALID");
  }
  const unavailable = new Set(value.unavailable_sections);
  for (const [name, section] of Object.entries(value.sections)) {
    if (!section || section.section !== name || !DIGEST.test(section.data_digest)) {
      throw new Error("ENTERPRISE_AUTHORITY_SECTION_INVALID");
    }
    if (!section.available && (!unavailable.has(section.section) || section.data !== null)) {
      throw new Error("ENTERPRISE_PARTIAL_FAILURE_HIDDEN");
    }
  }
  if (value.complete === (unavailable.size > 0)) {
    throw new Error("ENTERPRISE_COMPLETENESS_INVALID");
  }
  return value;
}

export function taskCompletionLabel(value: TaskAuthorityStatus): "COMPLETED" | "VERIFYING" | "RUNNING" {
  if (
    value.runtime_status === "COMPLETED" &&
    value.ledger_terminal &&
    value.evaluation_passed &&
    value.evidence_verified &&
    DIGEST.test(value.status_digest)
  ) {
    return "COMPLETED";
  }
  return value.runtime_status === "COMPLETED" ? "VERIFYING" : "RUNNING";
}

export async function buildAdminIntent(input: {
  tenant_id: string;
  project_id: string | null;
  operation: string;
  resource: string;
  requested_by: string;
  approval_ids: string[];
  reason: string;
  csrf_token: string;
  payload?: unknown;
}): Promise<GovernedAdminIntent> {
  if (
    !input.tenant_id ||
    !input.operation ||
    !input.resource ||
    !input.requested_by ||
    input.approval_ids.length === 0 ||
    input.approval_ids.length > 16 ||
    !input.reason.trim() ||
    !input.csrf_token
  ) {
    throw new Error("ENTERPRISE_ADMIN_INTENT_INVALID");
  }
  const actionId = crypto.randomUUID();
  const requestedAt = new Date().toISOString();
  const approvalIds = [...new Set(input.approval_ids)];
  const actionBinding = {
    schema_version: "agenttrust.enterprise-control.v1",
    action_id: actionId,
    tenant_id: input.tenant_id,
    project_id: input.project_id,
    operation: input.operation,
    resource: input.resource,
    requested_by: input.requested_by,
    approval_ids: approvalIds,
    requested_at_epoch_ms: new Date(requestedAt).getTime(),
  };
  const actionDigest = await sha256Canonical({
    action: actionBinding,
    reason: input.reason.trim(),
    request: input.payload ?? null,
  });
  return {
    intent: {
      schema_version: "agenttrust.enterprise-control.v1",
      action_id: actionId,
      tenant_id: input.tenant_id,
      project_id: input.project_id,
      operation: input.operation,
      resource: input.resource,
      requested_by: input.requested_by,
      approval_ids: approvalIds,
      action_digest: actionDigest,
      requested_at: requestedAt,
    },
    reason: input.reason.trim(),
    csrf_token: input.csrf_token,
  };
}

async function sha256Canonical(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(canonicalize(value)));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new Error("ENTERPRISE_ACTION_BINDING_INVALID_NUMBER");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize).sort((left, right) => {
      const leftJson = JSON.stringify(left);
      const rightJson = JSON.stringify(right);
      return leftJson < rightJson ? -1 : leftJson > rightJson ? 1 : 0;
    });
  }
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) throw new Error("ENTERPRISE_ACTION_BINDING_UNDEFINED");
      result[key] = canonicalize(item);
    }
    return result;
  }
  throw new Error("ENTERPRISE_ACTION_BINDING_UNSUPPORTED");
}

export function canRenderSensitiveData(section: AuthoritySection<unknown>, verifiedBackendSignature: boolean): boolean {
  return section.authoritative && section.available && verifiedBackendSignature && DIGEST.test(section.data_digest);
}
