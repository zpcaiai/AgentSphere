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
  tenant_id: string;
  task_id: string;
  sequence: number;
  trace_id: string;
  kind: AgUiEventKind;
  safe_payload: Record<string, unknown>;
  occurred_at: string;
  backend_signature: string;
}

export interface ResumeResponse {
  events: AgUiEventEnvelope[];
  next_resume_token: string;
  safe_snapshot_required: boolean;
}

export interface AgUiSafeSnapshot {
  schema_version: "agenttrust.agui-safe-snapshot.v1";
  tenant_id: string;
  task_id: string;
  sequence: number;
  safe_state: { status: string; evidence_digest?: string; occurred_at?: string };
  next_resume_token: string;
  generated_at: string;
  backend_signature: string;
}

export type SignedAgUiEnvelope = AgUiEventEnvelope | AgUiSafeSnapshot;
export type BackendEventVerifier = (event: SignedAgUiEnvelope) => Promise<boolean>;

const EVENT_KINDS: ReadonlySet<string> = new Set<AgUiEventKind>([
  "PLAN_UPDATED", "TOOL_REQUESTED", "APPROVAL_REQUIRED", "APPROVAL_RECORDED",
  "EXECUTION_STATUS", "ARTIFACT_AVAILABLE", "EVALUATION_UPDATED", "INCIDENT",
]);

export class AgUiEventReducer {
  private sequence = 0;
  private readonly seen = new Set<string>();
  private readonly order: string[] = [];

  constructor(private readonly verifyBackendEvent: BackendEventVerifier,
    private readonly maximumSeenEvents = 1_000) {
    if (!Number.isSafeInteger(maximumSeenEvents) || maximumSeenEvents < 1 || maximumSeenEvents > 10_000) {
      throw new Error("AGUI_REDUCER_CAPACITY_INVALID");
    }
  }

  currentSequence(): number {
    return this.sequence;
  }

  resetFromSafeSnapshot(sequence: number): void {
    if (!Number.isSafeInteger(sequence) || sequence < 0) {
      throw new Error("AGUI_SNAPSHOT_SEQUENCE_INVALID");
    }
    this.sequence = sequence;
    this.seen.clear();
    this.order.splice(0);
  }

  async apply(event: AgUiEventEnvelope): Promise<"APPLIED" | "DUPLICATE"> {
    validateEvent(event);
    if (this.seen.has(event.event_id) || event.sequence <= this.sequence) return "DUPLICATE";
    if (event.sequence !== this.sequence + 1) throw new Error("AGUI_SEQUENCE_GAP");
    if (!(await this.verifyBackendEvent(event))) throw new Error("AGUI_BACKEND_SIGNATURE_INVALID");
    this.seen.add(event.event_id);
    this.order.push(event.event_id);
    this.sequence = event.sequence;
    while (this.order.length > this.maximumSeenEvents) {
      const removed = this.order.shift();
      if (removed) this.seen.delete(removed);
    }
    return "APPLIED";
  }
}

export interface AgUiResumeOptions {
  maximumEvents?: number;
  maximumResponseBytes?: number;
  timeoutMs?: number;
}

/**
 * Resumable AG-UI transport. Tokens and verified events exist in memory only. A snapshot request
 * invalidates the token and fails closed; the caller must fetch an independently verified safe snapshot.
 */
export class AgUiResumeClient {
  private readonly maximumEvents: number;
  private readonly maximumResponseBytes: number;
  private readonly timeoutMs: number;
  private readonly tokens = new Map<string, string>();
  private readonly reducers = new Map<string, AgUiEventReducer>();
  private readonly snapshots = new Map<string, AgUiSafeSnapshot>();
  private readonly base: URL;

  constructor(baseUrl: string, private readonly tenantId: string, verifier: BackendEventVerifier,
    options: AgUiResumeOptions = {}) {
    this.base = new URL(baseUrl);
    this.maximumEvents = options.maximumEvents ?? 100;
    this.maximumResponseBytes = options.maximumResponseBytes ?? 1_000_000;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    if (this.base.protocol !== "https:" || this.base.username || this.base.password || !tenantId
      || !Number.isSafeInteger(this.maximumEvents) || this.maximumEvents < 1 || this.maximumEvents > 1_000
      || !Number.isSafeInteger(this.maximumResponseBytes) || this.maximumResponseBytes < 1_024
      || this.maximumResponseBytes > 5_000_000 || this.timeoutMs < 100 || this.timeoutMs > 30_000) {
      throw new Error("AGUI_CLIENT_CONFIG_INVALID");
    }
    this.verifier = verifier;
  }

  private readonly verifier: BackendEventVerifier;

  currentSequence(taskId: string): number {
    return this.reducers.get(taskId)?.currentSequence() ?? 0;
  }

  currentSafeSnapshot(taskId: string): AgUiSafeSnapshot | undefined {
    return this.snapshots.get(taskId);
  }

  clear(taskId?: string): void {
    if (taskId) {
      this.tokens.delete(taskId);
      this.reducers.delete(taskId);
      this.snapshots.delete(taskId);
    } else {
      this.tokens.clear();
      this.reducers.clear();
      this.snapshots.clear();
    }
  }

  async resume(taskId: string): Promise<AgUiEventEnvelope[]> {
    return this.resumePage(taskId, true);
  }

  private async resumePage(taskId: string, allowSnapshotRecovery: boolean): Promise<AgUiEventEnvelope[]> {
    if (!taskId || taskId.length > 200) throw new Error("AGUI_TASK_INVALID");
    const query = new URLSearchParams({ limit: String(this.maximumEvents) });
    const token = this.tokens.get(taskId);
    if (token) query.set("resume_token", token);
    const path = `/v1/tenants/${encodeURIComponent(this.tenantId)}/tasks/${encodeURIComponent(taskId)}/agui/events?${query}`;
    const target = new URL(path, this.base);
    if (target.origin !== this.base.origin) throw new Error("AGUI_ORIGIN_INVALID");
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(target, {
        credentials: "include",
        cache: "no-store",
        redirect: "error",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
    } catch {
      throw new Error("AGUI_RESUME_UNAVAILABLE");
    } finally {
      window.clearTimeout(timer);
    }
    if (response.status !== 200 || !response.headers.get("Content-Type")?.includes("application/json")) {
      throw new Error(`AGUI_RESUME_REJECTED_${response.status}`);
    }
    const declaredLength = Number(response.headers.get("Content-Length") ?? 0);
    if (declaredLength > this.maximumResponseBytes) throw new Error("AGUI_RESPONSE_TOO_LARGE");
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > this.maximumResponseBytes) {
      throw new Error("AGUI_RESPONSE_TOO_LARGE");
    }
    let payload: ResumeResponse;
    try { payload = JSON.parse(text) as ResumeResponse; }
    catch { throw new Error("AGUI_RESPONSE_INVALID"); }
    if (!payload || !Array.isArray(payload.events) || payload.events.length > this.maximumEvents
      || typeof payload.next_resume_token !== "string" || payload.next_resume_token.length > 2_048
      || typeof payload.safe_snapshot_required !== "boolean") {
      throw new Error("AGUI_RESPONSE_INVALID");
    }
    if (payload.safe_snapshot_required) {
      this.tokens.delete(taskId);
      if (!allowSnapshotRecovery) throw new Error("AGUI_SAFE_SNAPSHOT_RECOVERY_LOOP");
      await this.recoverFromSafeSnapshot(taskId);
      return this.resumePage(taskId, false);
    }
    const applied: AgUiEventEnvelope[] = [];
    for (const event of payload.events) {
      if (event.tenant_id !== this.tenantId) throw new Error("AGUI_CROSS_TENANT_EVENT_DENIED");
      if (event.task_id !== taskId) throw new Error("AGUI_CROSS_TASK_EVENT_DENIED");
      if (await this.reducerFor(taskId).apply(event) === "APPLIED") applied.push(event);
    }
    if (payload.next_resume_token) this.tokens.set(taskId, payload.next_resume_token);
    return applied;
  }

  private async recoverFromSafeSnapshot(taskId: string): Promise<void> {
    const path = `/v1/tenants/${encodeURIComponent(this.tenantId)}/tasks/${encodeURIComponent(taskId)}/agui/snapshot`;
    const target = new URL(path, this.base);
    if (target.origin !== this.base.origin) throw new Error("AGUI_ORIGIN_INVALID");
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(target, { credentials: "include", cache: "no-store", redirect: "error",
        headers: { Accept: "application/json" }, signal: controller.signal });
    } catch {
      throw new Error("AGUI_SNAPSHOT_UNAVAILABLE");
    } finally {
      window.clearTimeout(timer);
    }
    if (response.status !== 200 || !response.headers.get("Content-Type")?.includes("application/json")) {
      throw new Error(`AGUI_SNAPSHOT_REJECTED_${response.status}`);
    }
    const declaredLength = Number(response.headers.get("Content-Length") ?? 0);
    if (declaredLength > this.maximumResponseBytes) throw new Error("AGUI_RESPONSE_TOO_LARGE");
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > this.maximumResponseBytes) {
      throw new Error("AGUI_RESPONSE_TOO_LARGE");
    }
    let snapshot: AgUiSafeSnapshot;
    try { snapshot = JSON.parse(text) as AgUiSafeSnapshot; }
    catch { throw new Error("AGUI_SNAPSHOT_INVALID"); }
    validateSnapshot(snapshot);
    if (snapshot.tenant_id !== this.tenantId) throw new Error("AGUI_CROSS_TENANT_SNAPSHOT_DENIED");
    if (snapshot.task_id !== taskId) throw new Error("AGUI_CROSS_TASK_SNAPSHOT_DENIED");
    if (!(await this.verifier(snapshot))) throw new Error("AGUI_BACKEND_SIGNATURE_INVALID");
    this.reducerFor(taskId).resetFromSafeSnapshot(snapshot.sequence);
    this.tokens.set(taskId, snapshot.next_resume_token);
    this.snapshots.set(taskId, snapshot);
  }

  private reducerFor(taskId: string): AgUiEventReducer {
    const current = this.reducers.get(taskId);
    if (current) return current;
    // The map is bounded to one reducer per currently resumed task token.
    if (this.reducers.size >= 100 && !this.tokens.has(taskId)) throw new Error("AGUI_TASK_CAPACITY_EXCEEDED");
    const reducer = new AgUiEventReducer(this.verifier, Math.min(this.maximumEvents * 2, 10_000));
    this.reducers.set(taskId, reducer);
    return reducer;
  }
}

export async function createEd25519Verifier(publicKeyBase64Url: string): Promise<BackendEventVerifier> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(publicKeyBase64Url)) throw new Error("AGUI_VERIFY_KEY_INVALID");
  const key = await crypto.subtle.importKey(
    "raw", decodeBase64Url(publicKeyBase64Url), { name: "Ed25519" }, false, ["verify"],
  );
  return async (event: SignedAgUiEnvelope): Promise<boolean> => {
    try {
      if (event.schema_version === "agenttrust.a2a-agui.v1") validateEvent(event);
      else validateSnapshot(event);
      const signature = decodeBase64Url(event.backend_signature);
      const unsigned: Record<string, unknown> = { ...event, backend_signature: "" };
      const message = new TextEncoder().encode(JSON.stringify(canonicalize(unsigned)));
      return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
    } catch {
      return false;
    }
  };
}

function validateSnapshot(snapshot: AgUiSafeSnapshot): void {
  if (!snapshot || snapshot.schema_version !== "agenttrust.agui-safe-snapshot.v1"
    || !snapshot.tenant_id || snapshot.tenant_id.length > 200
    || !snapshot.task_id || snapshot.task_id.length > 200
    || !Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < 0
    || !isRecord(snapshot.safe_state)
    || typeof snapshot.safe_state.status !== "string"
    || !/^[A-Z][A-Z0-9_]{0,63}$/.test(snapshot.safe_state.status)
    || (snapshot.safe_state.evidence_digest !== undefined
      && !/^[a-f0-9]{64}$/.test(snapshot.safe_state.evidence_digest))
    || typeof snapshot.next_resume_token !== "string" || !snapshot.next_resume_token
    || snapshot.next_resume_token.length > 2_048
    || typeof snapshot.generated_at !== "string" || !Number.isFinite(Date.parse(snapshot.generated_at))
    || typeof snapshot.backend_signature !== "string" || !snapshot.backend_signature
    || snapshot.backend_signature.length > 200) {
    throw new Error("AGUI_SNAPSHOT_INVALID");
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
export function validApprovalReason(reason: string): boolean {
  const trimmed = reason.trim();
  return trimmed.length > 0
    && Array.from(trimmed).length <= 2_000
    && !trimmed.includes("\0")
    && new TextEncoder().encode(trimmed).byteLength <= 4_096;
}

export function buildApprovalIntent(caseId: string, decision: "APPROVE" | "REJECT", reason: string,
  actionHash: string, resourceVersion: string): ApprovalIntent {
  const trimmed = reason.trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(caseId)
    || !validApprovalReason(trimmed) || !/^[a-f0-9]{64}$/.test(actionHash)
    || !resourceVersion || Array.from(resourceVersion).length > 512
    || /[\u0000\r\n]/.test(resourceVersion)) {
    throw new Error("APPROVAL_INTENT_INVALID");
  }
  return {
    schema_version: "agenttrust.approval-intent.v1",
    case_id: caseId,
    decision,
    reason: trimmed,
    observed_action_hash: actionHash,
    observed_resource_version: resourceVersion,
  };
}

function validateEvent(event: AgUiEventEnvelope): void {
  if (!event || event.schema_version !== "agenttrust.a2a-agui.v1" || !event.event_id || event.event_id.length > 200
    || !event.tenant_id || event.tenant_id.length > 200
    || !event.task_id || event.task_id.length > 200 || !Number.isSafeInteger(event.sequence) || event.sequence < 1
    || !event.trace_id || event.trace_id.length > 256
    || !EVENT_KINDS.has(event.kind) || !isRecord(event.safe_payload)
    || JSON.stringify(event.safe_payload).length > 64 * 1_024
    || typeof event.occurred_at !== "string" || !Number.isFinite(Date.parse(event.occurred_at))
    || !event.backend_signature || event.backend_signature.length > 200) {
    throw new Error("AGUI_EVENT_INVALID");
  }
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("AGUI_CANONICAL_NUMBER_INVALID");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isRecord(value)) {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key]);
    return result;
  }
  throw new Error("AGUI_CANONICAL_VALUE_INVALID");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
