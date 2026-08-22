import { isRecord, isUuid } from "./control-state";
import type { Incident, IncidentActionReceipt, IncidentPage } from "./enterprise-api-types";

const DIGEST = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9._:/@-]{1,256}$/;
const PAGE_FIELDS = ["schema_version", "tenant_id", "items", "next_after_incident_id"];
const INCIDENT_FIELDS = ["incident_id", "correlation_key", "severity", "status", "task_id", "owner",
  "safe_summary", "scope", "evidence_refs", "legal_hold_id", "resource_version", "created_at",
  "updated_at", "timeline"];
const EVENT_FIELDS = ["event_id", "sequence", "event_type", "from_status", "to_status", "actor_subject",
  "reason_code", "payload_digest", "action_hash", "ledger_execution_id", "fence_digest",
  "policy_decision_digest", "authorization_evidence_ref", "authorization_evidence_digest", "occurred_at"];
const RECEIPT_FIELDS = ["schema_version", "action_id", "task_id", "accepted", "execution_pending",
  "ingress_digest", "ledger_evidence_ref", "ledger_evidence_digest"];
const STATES = new Set(["DETECTED", "TRIAGED", "CONTAINED", "INVESTIGATING", "REMEDIATING",
  "RECERTIFYING", "CLOSED"]);
const TIMELINE_STATES = new Set([...STATES, "GATE_PASSED", "CANARY_RUNNING", "CANARY_PASSED",
  "ROLLBACK_REQUIRED", "ROLLED_BACK"]);
const EVENTS = new Set(["DETECT", "TRIAGE", "CONTAIN", "INVESTIGATE", "PRESERVE_EVIDENCE",
  "PLAN_REPLAY", "COMPLETE_REPLAY", "PUBLISH_ROOT_CAUSE", "BEGIN_REMEDIATION",
  "TRIGGER_RECERTIFICATION", "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY",
  "ROLLBACK_RELEASE", "CLOSE"]);

export function validateIncidentPage(value: unknown, tenantId: string, after: string | null,
  limit: number): IncidentPage {
  assert(exact(value, PAGE_FIELDS) && value.schema_version === "agenttrust.authoritative-incident-page.v1"
    && value.tenant_id === tenantId && Array.isArray(value.items) && value.items.length <= limit
    && (value.next_after_incident_id === null || isUuid(String(value.next_after_incident_id))));
  let previous = after;
  for (const item of value.items) {
    validateIncident(item);
    assert(previous === null || item.incident_id > previous);
    previous = item.incident_id;
  }
  assert(value.next_after_incident_id === null || (value.items.length === limit
    && value.next_after_incident_id === previous));
  return value as unknown as IncidentPage;
}

export function validateIncident(value: unknown, incidentId?: string): Incident {
  assert(exact(value, INCIDENT_FIELDS) && isUuid(String(value.incident_id))
    && (incidentId === undefined || value.incident_id === incidentId)
    && bounded(value.correlation_key, 256) && ["P0", "P1", "P2", "P3"].includes(String(value.severity))
    && STATES.has(String(value.status)) && isUuid(String(value.task_id)) && IDENTIFIER.test(String(value.owner))
    && bounded(value.safe_summary, 512) && strings(value.scope, 1, 256, 1_024)
    && value.scope.every((item) => resource(item, 1_024))
    && strings(value.evidence_refs, 1, 256, 2_048) && value.evidence_refs.every(evidenceRef)
    && IDENTIFIER.test(String(value.legal_hold_id)) && integer(value.resource_version, 1)
    && dateTime(value.created_at) && dateTime(value.updated_at)
    && Date.parse(value.updated_at) >= Date.parse(value.created_at)
    && Array.isArray(value.timeline) && value.timeline.length <= 100_000);
  let sequence = 0;
  let occurred: number | null = null;
  let state: string | null = null;
  for (const event of value.timeline) {
    assert(exact(event, EVENT_FIELDS) && isUuid(String(event.event_id))
      && integer(event.sequence, 1) && event.sequence === sequence + 1
      && EVENTS.has(String(event.event_type)) && nullableState(event.from_status)
      && nullableState(event.to_status) && IDENTIFIER.test(String(event.actor_subject))
      && IDENTIFIER.test(String(event.reason_code)) && digest(event.payload_digest)
      && digest(event.action_hash) && isUuid(String(event.ledger_execution_id))
      && digest(event.fence_digest) && digest(event.policy_decision_digest)
      && evidenceRef(event.authorization_evidence_ref)
      && digest(event.authorization_evidence_digest) && dateTime(event.occurred_at)
      && (occurred === null || Date.parse(event.occurred_at) >= occurred)
      && (sequence === 0 || event.from_status === null || state === null || event.from_status === state));
    sequence = Number(event.sequence);
    occurred = Date.parse(event.occurred_at as string);
    state = event.to_status === null ? state : String(event.to_status);
  }
  assert(value.timeline.length === 0 || state === value.status);
  return value as unknown as Incident;
}

export function validateIncidentActionReceipt(value: unknown, commandId: string,
  taskId: string): IncidentActionReceipt {
  assert(exact(value, RECEIPT_FIELDS)
    && value.schema_version === "agenttrust.incident-action-receipt.v1"
    && value.action_id === commandId && value.task_id === taskId && value.accepted === true
    && value.execution_pending === true && digest(value.ingress_digest)
    && evidenceRef(value.ledger_evidence_ref) && digest(value.ledger_evidence_digest),
  "CONTROL_INCIDENT_ACTION_RECEIPT_INVALID");
  return value as unknown as IncidentActionReceipt;
}

function exact(value: unknown, fields: string[]): value is Record<string, unknown> {
  return isRecord(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}
function digest(value: unknown): value is string { return typeof value === "string" && DIGEST.test(value); }
function bounded(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum && !/[\0\r\n]/.test(value);
}
function strings(value: unknown, minimum: number, maximum: number, maximumLength: number): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum
    && value.every((item) => bounded(item, maximumLength)) && new Set(value).size === value.length;
}
function evidenceRef(value: unknown): value is string {
  return bounded(value, 2_048) && /^(evidence:\/\/|urn:agenttrust:(evidence|ledger-evidence):)/.test(value)
    && !/[\s?#]/.test(value);
}
function resource(value: unknown, maximum: number): boolean {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum
    && /^[A-Za-z0-9._:/@-]+$/.test(value) && !value.includes("..");
}
function integer(value: unknown, minimum: number): boolean { return Number.isSafeInteger(value) && Number(value) >= minimum; }
function dateTime(value: unknown): value is string { return typeof value === "string" && !Number.isNaN(Date.parse(value)); }
function nullableState(value: unknown): boolean { return value === null || TIMELINE_STATES.has(String(value)); }
function assert(condition: unknown, code = "CONTROL_INCIDENT_AUTHORITY_RESPONSE_INVALID"): asserts condition {
  if (!condition) throw new Error(code);
}
