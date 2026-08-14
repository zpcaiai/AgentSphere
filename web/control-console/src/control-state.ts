import type { ApprovalIntent } from "../../shared/agui-client";

export const SERVICE_SECTIONS = [
  "TASKS",
  "INCIDENTS",
  "AGENTS",
  "TOOLS",
  "CREDENTIALS",
  "APPROVALS",
  "POLICIES",
  "PACKS",
  "TRACE",
  "EVIDENCE",
  "COMPLIANCE",
  "AUDIT",
  "SRE",
  "DEPLOYMENTS",
] as const;

export type ServiceSection = (typeof SERVICE_SECTIONS)[number];

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
  generated_at?: string;
}

export interface TaskAuthorityStatus {
  task_id: string;
  runtime_status: string;
  ledger_terminal: boolean;
  evaluation_passed: boolean;
  evidence_verified: boolean;
  status_digest: string;
  state_version?: number;
  safe_summary?: string;
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

export type SafeScalar = string | number | boolean | null;
export interface SafeAuthorityRow {
  row_id: string;
  values: Record<string, SafeScalar>;
}

const DIGEST = /^[a-f0-9]{64}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T/;
const REDACTED_FIELD = /(secret|password|token|credential|private|prompt|payload|content|authorization|cookie|key_material)/i;
const MAX_AUTHORITY_ROWS = 1_000;
const MAX_COLUMNS = 24;
const MAX_SAFE_TEXT = 500;

export function validateDashboard(value: EnterpriseDashboard): EnterpriseDashboard {
  if (!value || !isUuid(value.tenant_id) || value.schema_version !== "agenttrust.enterprise-dashboard.v1") {
    throw new Error("ENTERPRISE_DASHBOARD_INVALID");
  }
  if (!Array.isArray(value.unavailable_sections) || value.unavailable_sections.length > SERVICE_SECTIONS.length) {
    throw new Error("ENTERPRISE_DASHBOARD_INVALID");
  }
  const unavailable = new Set(value.unavailable_sections);
  for (const [name, section] of Object.entries(value.sections)) {
    if (!isServiceSection(name) || !section || section.schema_version !== "agenttrust.authority-view.v1"
      || section.section !== name || section.authoritative !== true || !DIGEST.test(section.data_digest)
      || !ISO_DATE.test(section.fetched_at)) {
      throw new Error("ENTERPRISE_AUTHORITY_SECTION_INVALID");
    }
    if (!section.available && (
      !unavailable.has(section.section)
      || section.data !== null
      || section.safe_error_code !== "AUTHORITATIVE_SOURCE_UNAVAILABLE"
    )) {
      throw new Error("ENTERPRISE_PARTIAL_FAILURE_HIDDEN");
    }
    if (section.available && section.data === null) {
      throw new Error("ENTERPRISE_AUTHORITY_SECTION_INVALID");
    }
  }
  if (value.complete !== (unavailable.size === 0)) {
    throw new Error("ENTERPRISE_COMPLETENESS_INVALID");
  }
  return value;
}

export function taskCompletionLabel(value: TaskAuthorityStatus): "COMPLETED" | "VERIFYING" | "RUNNING" {
  if (
    value.runtime_status === "COMPLETED"
    && value.ledger_terminal
    && value.evaluation_passed
    && value.evidence_verified
    && DIGEST.test(value.status_digest)
  ) {
    return "COMPLETED";
  }
  return value.runtime_status === "COMPLETED" ? "VERIFYING" : "RUNNING";
}

export function extractTaskAuthorityStatuses(dashboard: EnterpriseDashboard): TaskAuthorityStatus[] {
  const section = dashboard.sections.TASKS;
  if (!section?.available || section.data === null) return [];
  const rows = extractItems(section.data);
  if (rows.length > MAX_AUTHORITY_ROWS) throw new Error("ENTERPRISE_AUTHORITY_CAPACITY_EXCEEDED");
  return rows.map((row) => parseTask(row));
}

export function safeAuthorityRows(section: AuthoritySection<unknown>, query = ""): SafeAuthorityRow[] {
  if (!section.available || section.data === null) return [];
  const items = extractItems(section.data);
  if (items.length > MAX_AUTHORITY_ROWS) throw new Error("ENTERPRISE_AUTHORITY_CAPACITY_EXCEEDED");
  const normalized = items.map((item, index) => toSafeRow(item, index));
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return normalized;
  return normalized.filter((row) => Object.values(row.values)
    .some((value) => String(value ?? "").toLocaleLowerCase().includes(needle)));
}

export function extractItems(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (!isRecord(value)) return [value];
  for (const key of ["items", "tasks", "agents", "approvals", "policies", "incidents", "events", "records", "data"]) {
    const candidate = value[key];
    if (Array.isArray(candidate)) return candidate;
  }
  return [value];
}

function toSafeRow(value: unknown, index: number): SafeAuthorityRow {
  if (!isRecord(value)) {
    return { row_id: String(index + 1), values: { value: safeScalar("value", value) } };
  }
  const values: Record<string, SafeScalar> = {};
  for (const key of Object.keys(value).sort().slice(0, MAX_COLUMNS)) {
    values[key] = safeScalar(key, value[key]);
  }
  const stableId = ["id", "task_id", "agent_id", "case_id", "incident_id", "policy_id", "event_id"]
    .map((key) => value[key]).find((candidate) => typeof candidate === "string");
  return { row_id: typeof stableId === "string" ? stableId : String(index + 1), values };
}

function safeScalar(key: string, value: unknown): SafeScalar {
  if (REDACTED_FIELD.test(key)) return "[REDACTED]";
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : "[INVALID_NUMBER]";
  if (typeof value === "string") return value.length <= MAX_SAFE_TEXT ? value : `${value.slice(0, MAX_SAFE_TEXT)}…`;
  if (Array.isArray(value) && value.length <= 20 && value.every((item) => typeof item === "string")) {
    return value.map((item) => item.slice(0, 100)).join(", ");
  }
  return "[STRUCTURED_DATA_REDACTED]";
}

function parseTask(value: unknown): TaskAuthorityStatus {
  if (!isRecord(value)
    || typeof value.task_id !== "string"
    || !value.task_id
    || typeof value.runtime_status !== "string"
    || typeof value.ledger_terminal !== "boolean"
    || typeof value.evaluation_passed !== "boolean"
    || typeof value.evidence_verified !== "boolean"
    || typeof value.status_digest !== "string"
    || !DIGEST.test(value.status_digest)) {
    throw new Error("ENTERPRISE_TASK_AUTHORITY_INVALID");
  }
  const stateVersion = value.state_version;
  if (stateVersion !== undefined && (!Number.isSafeInteger(stateVersion) || Number(stateVersion) < 0)) {
    throw new Error("ENTERPRISE_TASK_AUTHORITY_INVALID");
  }
  return {
    task_id: value.task_id,
    runtime_status: value.runtime_status,
    ledger_terminal: value.ledger_terminal,
    evaluation_passed: value.evaluation_passed,
    evidence_verified: value.evidence_verified,
    status_digest: value.status_digest,
    ...(stateVersion === undefined ? {} : { state_version: Number(stateVersion) }),
    ...(typeof value.safe_summary === "string" ? { safe_summary: value.safe_summary.slice(0, MAX_SAFE_TEXT) } : {}),
  };
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
    !isUuid(input.tenant_id)
    || !input.operation
    || !input.resource
    || !input.requested_by
    || input.approval_ids.length === 0
    || input.approval_ids.length > 16
    || !input.reason.trim()
    || input.reason.length > 2_000
    || !input.csrf_token
  ) {
    throw new Error("ENTERPRISE_ADMIN_INTENT_INVALID");
  }
  const actionId = crypto.randomUUID();
  const requestedAt = new Date().toISOString();
  const approvalIds = [...new Set(input.approval_ids)].sort();
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

/** A refresh-stable retry key; it is an idempotency binding, never an approval grant. */
export async function approvalIdempotencyKey(
  tenantId: string,
  subject: string,
  intent: ApprovalIntent,
): Promise<string> {
  if (!isUuid(tenantId) || !subject || subject.length > 300) {
    throw new Error("APPROVAL_IDEMPOTENCY_BINDING_INVALID");
  }
  const digest = await sha256Canonical({
    actor_subject: subject,
    approval_intent: intent,
    tenant_id: tenantId,
  });
  return `approval:${digest}`;
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
  if (isRecord(value)) {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const item = value[key];
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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isServiceSection(value: string): value is ServiceSection {
  return (SERVICE_SECTIONS as readonly string[]).includes(value);
}
