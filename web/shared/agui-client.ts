export type AgUiEventKind =
  | "PLAN_UPDATED"
  | "TOOL_REQUESTED"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_RECORDED"
  | "EXECUTION_STATUS"
  | "ARTIFACT_AVAILABLE"
  | "EVALUATION_UPDATED"
  | "INCIDENT";

export interface AgUiEventEnvelope {
  schema_version: "agenttrust.a2a-agui.v1";
  event_id: string;
  task_id: string;
  sequence: number;
  trace_id: string;
  kind: AgUiEventKind;
  safe_payload: Record<string, unknown>;
  backend_signature: string;
}

export interface ResumeResponse {
  events: AgUiEventEnvelope[];
  next_resume_token: string;
  safe_snapshot_required: boolean;
}

export type BackendEventVerifier = (event: AgUiEventEnvelope) => Promise<boolean>;

export class AgUiEventReducer {
  private sequence = 0;
  private readonly seen = new Set<string>();

  constructor(private readonly verifyBackendEvent: BackendEventVerifier) {}

  currentSequence(): number {
    return this.sequence;
  }

  resetFromSafeSnapshot(sequence: number): void {
    if (!Number.isSafeInteger(sequence) || sequence < 0) {
      throw new Error("AGUI_SNAPSHOT_SEQUENCE_INVALID");
    }
    this.sequence = sequence;
    this.seen.clear();
  }

  async apply(event: AgUiEventEnvelope): Promise<"APPLIED" | "DUPLICATE"> {
    if (event.schema_version !== "agenttrust.a2a-agui.v1") {
      throw new Error("AGUI_SCHEMA_UNSUPPORTED");
    }
    if (this.seen.has(event.event_id) || event.sequence <= this.sequence) {
      return "DUPLICATE";
    }
    if (event.sequence !== this.sequence + 1) {
      throw new Error("AGUI_SEQUENCE_GAP");
    }
    if (!(await this.verifyBackendEvent(event))) {
      throw new Error("AGUI_BACKEND_SIGNATURE_INVALID");
    }
    this.seen.add(event.event_id);
    this.sequence = event.sequence;
    return "APPLIED";
  }
}

export interface ApprovalIntent {
  schema_version: "agenttrust.approval-intent.v1";
  case_id: string;
  decision: "APPROVE" | "REJECT";
  reason: string;
  observed_action_hash: string;
  observed_resource_version: string;
}

// This object is deliberately an intent, never an authorization or approval grant.
export function buildApprovalIntent(
  caseId: string,
  decision: "APPROVE" | "REJECT",
  reason: string,
  actionHash: string,
  resourceVersion: string,
): ApprovalIntent {
  if (!caseId || !reason || !/^[a-f0-9]{64}$/.test(actionHash) || !resourceVersion) {
    throw new Error("APPROVAL_INTENT_INVALID");
  }
  return {
    schema_version: "agenttrust.approval-intent.v1",
    case_id: caseId,
    decision,
    reason,
    observed_action_hash: actionHash,
    observed_resource_version: resourceVersion,
  };
}
