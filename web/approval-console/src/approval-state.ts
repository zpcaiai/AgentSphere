import { buildApprovalIntent, type ApprovalIntent } from "../../shared/agui-client";

interface ApprovalCaseBase {
  schema_version: "agenttrust.approval-case-view.v1";
  case_id: string;
  safe_summary: string;
  action_hash: string;
  resource: string;
  resource_version: string;
  policy_version: string;
  risk: string;
  evidence_refs: string[];
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "REVOKED";
}

export interface CodingApprovalReviewDetails {
  diff_artifact_ref: string;
  command_summary: string;
  network_scope: string;
  rollback_summary: string;
}

export interface IndustrialApprovalReviewDetails {
  current_value: string;
  target_value: string;
  allowed_range: string;
  interlock_summary: string;
  physical_impact: string;
}

export type ApprovalCaseView = ApprovalCaseBase & (
  | { domain: "CODING"; coding_details: CodingApprovalReviewDetails }
  | { domain: "INDUSTRIAL"; industrial_details: IndustrialApprovalReviewDetails }
);

const DIGEST = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CASE_BASE_FIELDS = ["schema_version", "case_id", "domain", "safe_summary", "action_hash",
  "resource", "resource_version", "policy_version", "risk", "evidence_refs", "status"];
const PAGE_FIELDS = ["schema_version", "authoritative", "tenant_id", "resource", "items",
  "next_cursor", "data_digest"];

export function parseApprovalCases(value: unknown, expectedTenant?: string): ApprovalCaseView[] {
  let items: unknown[];
  if (expectedTenant !== undefined) {
    if (!isRecord(value) || !exactFields(value, PAGE_FIELDS)
      || value.schema_version !== "agenttrust.authoritative-approval-page.v1"
      || value.authoritative !== true || value.tenant_id !== expectedTenant
      || typeof value.resource !== "string" || !/^[a-z][a-z0-9_-]{0,99}$/.test(value.resource)
      || !Array.isArray(value.items)
      || !(value.next_cursor === null
        || typeof value.next_cursor === "string" && /^[A-Za-z0-9_-]{1,5462}$/.test(value.next_cursor))
      || typeof value.data_digest !== "string" || !DIGEST.test(value.data_digest)) {
      throw new Error("APPROVAL_AUTHORITY_PAGE_INVALID");
    }
    items = value.items;
  } else {
    items = Array.isArray(value) ? value
      : isRecord(value) && Array.isArray(value.approvals) ? value.approvals
        : isRecord(value) && Array.isArray(value.items) ? value.items : [];
  }
  if (items.length > (expectedTenant === undefined ? 500 : 100)) {
    throw new Error("APPROVAL_CASE_CAPACITY_EXCEEDED");
  }
  return items.map(parseApprovalCase);
}

export function parseApprovalCase(value: unknown): ApprovalCaseView {
  if (!isRecord(value) || (value.domain !== "CODING" && value.domain !== "INDUSTRIAL")
    || !exactFields(value, [...CASE_BASE_FIELDS,
      value.domain === "CODING" ? "coding_details" : "industrial_details"])
    || value.schema_version !== "agenttrust.approval-case-view.v1"
    || typeof value.case_id !== "string"
    || !UUID.test(value.case_id)
    || !safeReviewText(value.safe_summary, 2_000)
    || typeof value.action_hash !== "string" || !DIGEST.test(value.action_hash)
    || !boundedText(value.resource, 2_048) || !boundedText(value.resource_version, 2_048)
    || !boundedText(value.policy_version, 2_048)
    || !["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(String(value.risk))
    || !Array.isArray(value.evidence_refs) || value.evidence_refs.length !== 3
    || !value.evidence_refs.every(evidenceReference)
    || new Set(value.evidence_refs).size !== value.evidence_refs.length
    || !["PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED"].includes(String(value.status))) {
    throw new Error("APPROVAL_CASE_INVALID");
  }
  if (value.domain === "CODING" && !codingDetails(value.coding_details)) {
    throw new Error("APPROVAL_CASE_INVALID");
  }
  if (value.domain === "INDUSTRIAL" && !industrialDetails(value.industrial_details)) {
    throw new Error("APPROVAL_CASE_INVALID");
  }
  return value as unknown as ApprovalCaseView;
}

export function createDecisionIntent(
  value: ApprovalCaseView,
  decision: "APPROVE" | "REJECT",
  reason: string,
): ApprovalIntent {
  if (value.status !== "PENDING") {
    throw new Error("APPROVAL_CASE_NOT_PENDING");
  }
  return buildApprovalIntent(
    value.case_id,
    decision,
    reason,
    value.action_hash,
    value.resource_version,
  );
}

export function serverEventConfirmsApproval(event: {
  kind: string;
  verified: boolean;
  case_id: string;
}, caseId: string): boolean {
  return event.verified && event.kind === "APPROVAL_RECORDED" && event.case_id === caseId;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum
    && !/[\u0000-\u001F\u007F-\u009F]/.test(value);
}

function safeReviewText(value: unknown, maximum: number): value is string {
  if (!boundedText(value, maximum)) return false;
  const normalized = value.toLocaleLowerCase();
  if (["authorization:", "bearer ", "password", "passwd", "client_secret", "api_key",
    "api-key", "apikey", "x-api-key", "private key", "-----begin", "cookie:",
    "set-cookie", "credential://", "vault-kv://", "secret://", "token=", "token:"]
    .some((marker) => normalized.includes(marker))) return false;
  return !value.split(/[^A-Za-z0-9_-]+/).some((fragment) => fragment.length >= 32
    && /[A-Za-z]/.test(fragment) && /[0-9]/.test(fragment));
}

function codingDetails(value: unknown): value is CodingApprovalReviewDetails {
  return isRecord(value)
    && exactFields(value, ["diff_artifact_ref", "command_summary", "network_scope", "rollback_summary"])
    && typeof value.diff_artifact_ref === "string"
    && /^artifact:\/\/sha256\/[a-f0-9]{64}$/.test(value.diff_artifact_ref)
    && safeReviewText(value.command_summary, 2_048)
    && safeReviewText(value.network_scope, 1_024)
    && safeReviewText(value.rollback_summary, 2_048);
}

function industrialDetails(value: unknown): value is IndustrialApprovalReviewDetails {
  return isRecord(value)
    && exactFields(value, ["current_value", "target_value", "allowed_range", "interlock_summary",
      "physical_impact"])
    && safeReviewText(value.current_value, 512)
    && safeReviewText(value.target_value, 512)
    && safeReviewText(value.allowed_range, 512)
    && safeReviewText(value.interlock_summary, 2_048)
    && safeReviewText(value.physical_impact, 2_048);
}

function evidenceReference(value: unknown): value is string {
  return boundedText(value, 2_048)
    && /^(evidence:\/\/|urn:agenttrust:(evidence|ledger-evidence):)[^\s?#]+$/.test(value)
    && !["authorization:", "bearer ", "password", "passwd", "client_secret", "api_key",
      "api-key", "apikey", "x-api-key", "private key", "-----begin", "cookie:",
      "set-cookie", "credential://", "vault-kv://", "secret://", "token=", "token:"]
      .some((marker) => value.toLocaleLowerCase().includes(marker));
}

function exactFields(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && [...expected].sort().every((field, index) => field === actual[index]);
}
