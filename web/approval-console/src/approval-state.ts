import { buildApprovalIntent, type ApprovalIntent } from "../../shared/agui-client";

export interface ApprovalCaseView {
  schema_version: "agenttrust.approval-case-view.v1";
  case_id: string;
  domain: "CODING" | "INDUSTRIAL";
  safe_summary: string;
  action_hash: string;
  resource: string;
  resource_version: string;
  policy_version: string;
  risk: string;
  diff_artifact_ref?: string;
  rollback_summary?: string;
  current_value?: string;
  target_value?: string;
  interlock_summary?: string;
  evidence_refs: string[];
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "REVOKED";
}

const DIGEST = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CASE_FIELDS = ["schema_version", "case_id", "domain", "safe_summary", "action_hash",
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
  if (!isRecord(value) || !exactFields(value, CASE_FIELDS)
    || value.schema_version !== "agenttrust.approval-case-view.v1"
    || typeof value.case_id !== "string"
    || !UUID.test(value.case_id)
    || (value.domain !== "CODING" && value.domain !== "INDUSTRIAL")
    || !boundedText(value.safe_summary, 2_000)
    || typeof value.action_hash !== "string" || !DIGEST.test(value.action_hash)
    || !boundedText(value.resource, 2_048) || !boundedText(value.resource_version, 2_048)
    || !boundedText(value.policy_version, 2_048)
    || !["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(String(value.risk))
    || !Array.isArray(value.evidence_refs) || value.evidence_refs.length > 100
    || !value.evidence_refs.every((item) => boundedText(item, 2_048))
    || new Set(value.evidence_refs).size !== value.evidence_refs.length
    || !["PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED"].includes(String(value.status))) {
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
    && !/[\0\r\n]/.test(value);
}

function exactFields(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && [...expected].sort().every((field, index) => field === actual[index]);
}
