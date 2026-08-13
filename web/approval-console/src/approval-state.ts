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
