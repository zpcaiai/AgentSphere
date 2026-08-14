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

export function parseApprovalCases(value: unknown): ApprovalCaseView[] {
  const items = Array.isArray(value) ? value
    : isRecord(value) && Array.isArray(value.approvals) ? value.approvals
      : isRecord(value) && Array.isArray(value.items) ? value.items : [];
  if (items.length > 500) throw new Error("APPROVAL_CASE_CAPACITY_EXCEEDED");
  return items.map(parseApprovalCase);
}

export function parseApprovalCase(value: unknown): ApprovalCaseView {
  if (!isRecord(value) || value.schema_version !== "agenttrust.approval-case-view.v1"
    || typeof value.case_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.case_id)
    || (value.domain !== "CODING" && value.domain !== "INDUSTRIAL")
    || typeof value.safe_summary !== "string" || value.safe_summary.length > 2_000
    || typeof value.action_hash !== "string" || !DIGEST.test(value.action_hash)
    || typeof value.resource !== "string" || typeof value.resource_version !== "string"
    || typeof value.policy_version !== "string" || typeof value.risk !== "string"
    || !Array.isArray(value.evidence_refs) || value.evidence_refs.length > 100
    || !value.evidence_refs.every((item) => typeof item === "string")
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
