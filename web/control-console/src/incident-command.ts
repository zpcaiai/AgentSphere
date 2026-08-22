import { isRecord, isUuid, sha256Canonical } from "./control-state";
import type { IncidentOperation } from "./enterprise-api-types";

export const INCIDENT_OPERATIONS: IncidentOperation[] = [
  "TRIAGE", "CONTAIN", "INVESTIGATE", "PRESERVE_EVIDENCE", "PLAN_REPLAY",
  "COMPLETE_REPLAY", "PUBLISH_ROOT_CAUSE", "BEGIN_REMEDIATION",
  "TRIGGER_RECERTIFICATION", "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY",
  "ROLLBACK_RELEASE", "CLOSE",
];

const DIGEST = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9._:/@-]+$/;
const RELEASE_OPERATIONS = new Set<IncidentOperation>([
  "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE",
]);
const BASELINE_CONTROLS = ["CONTRACT", "IDENTITY", "POLICY", "SANDBOX", "IDEMPOTENCY",
  "ROLLBACK", "TRACE", "THREAT", "COMPLIANCE", "DOMAIN_EVALUATOR"];

export function incidentResource(operation: IncidentOperation, incidentId: string,
  releaseId: string): string {
  if (RELEASE_OPERATIONS.has(operation)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,1015}$/.test(releaseId)) invalid();
    return `release:${releaseId}`;
  }
  if (!isUuid(incidentId)) invalid();
  return `incident:${incidentId}`;
}

export function incidentPayloadTemplate(operation: IncidentOperation,
  requestedBy: string, approvalCount = 0): Record<string, unknown> {
  const digest = "0".repeat(64);
  const uuid = "00000000-0000-4000-8000-000000000000";
  const evidence = (controlId: string) => ({ control_id: controlId,
    evidence_ref: `urn:agenttrust:evidence:${controlId.toLowerCase()}`, evidence_digest: digest,
    release_digest: digest, passed: true, collected_at: new Date().toISOString() });
  switch (operation) {
    case "TRIAGE": return { owner: requestedBy, severity: "P2", reason_code: "INCIDENT_TRIAGED" };
    case "CONTAIN": return { reason_code: "INCIDENT_CONTAINMENT_REQUIRED", targets: {
      kill_task: true, revoke_credentials: true, isolate_integrations: ["integration:replace-me"],
      freeze_artifacts: true }, break_glass: approvalCount > 0 ? null : {
        break_glass_id: uuid, expires_at: new Date(Date.now() + 600_000).toISOString(),
        review_due_at: new Date(Date.now() + 3_600_000).toISOString(),
        compensating_controls: ["control:replace-me"], reason_digest: digest } };
    case "INVESTIGATE": return { reason_code: "INCIDENT_INVESTIGATION_STARTED" };
    case "PRESERVE_EVIDENCE": return { chain_head_digest: digest, snapshot_digest: digest,
      process_digest: digest, network_digest: digest, configuration_digest: digest,
      version_digest: digest, legal_hold_id: "legal-hold:replace-me" };
    case "PLAN_REPLAY": return { replay_id: uuid, mode: "LOGICAL", input_digest: digest,
      source_snapshot_digest: digest, expected_result_digest: digest, resource_refs: [],
      credential_profile: null, fresh_lease_id: null, fresh_lease_digest: null,
      authorization_lease_expires_at: null };
    case "COMPLETE_REPLAY": return { replay_id: uuid, mode: "LOGICAL", plan_digest: digest };
    case "PUBLISH_ROOT_CAUSE": return { report_id: uuid, report_digest: digest,
      findings: [{ finding_id: "finding-1", category: "TRIGGER", trigger: "replace-me",
        system_defect: "replace-me", detection_gap: "replace-me", recovery_gap: "replace-me",
        evidence_refs: ["urn:agenttrust:evidence:replace-me"] }],
      remediations: [{ remediation_id: "remediation-1", finding_id: "finding-1",
        policy_ref: "policy:replace-me", test_ref: "test:replace-me", owner: requestedBy,
        due_at: new Date(Date.now() + 86_400_000).toISOString() }] };
    case "BEGIN_REMEDIATION": return { reason_code: "INCIDENT_REMEDIATION_STARTED" };
    case "TRIGGER_RECERTIFICATION": return { root_cause_digest: digest, release_digest: digest,
      campaigns: ["campaign:replace-me"] };
    case "EVALUATE_RELEASE": return { release_digest: digest, definition: {
      gate_id: "release-gate:replace-me", version: "1", definition_digest: digest,
      required_controls: BASELINE_CONTROLS, maximum_evidence_age_seconds: 3600 },
      evidence: BASELINE_CONTROLS.map(evidence), rollback_artifact_digest: digest,
      canary_plan_digest: digest, valid_until: new Date(Date.now() + 86_400_000).toISOString() };
    case "START_CANARY": return { certificate_id: uuid, release_digest: digest,
      canary_plan_digest: digest, percentage: 1 };
    case "RECORD_CANARY": return { certificate_id: uuid, release_digest: digest,
      metrics_digest: digest, passed: false, rollback_required: true };
    case "ROLLBACK_RELEASE": return { release_digest: digest, target_release_digest: digest,
      reason_digest: digest };
    case "CLOSE": return { root_cause_digest: digest,
      recertification_evidence_ref: "urn:agenttrust:evidence:replace-me",
      recertification_evidence_digest: digest };
  }
}

export async function prepareIncidentPayload(operation: IncidentOperation, raw: unknown,
  approvalCount: number): Promise<Record<string, unknown>> {
  if (!isRecord(raw) || JSON.stringify(raw).length > 900_000) invalid();
  switch (operation) {
    case "TRIAGE":
      requireExact(raw, ["owner", "severity", "reason_code"]);
      requireIdentifier(raw.owner); requireEnum(raw.severity, ["P0", "P1", "P2", "P3"]);
      requireIdentifier(raw.reason_code, 128); break;
    case "CONTAIN": validateContain(raw, approvalCount); break;
    case "INVESTIGATE": case "BEGIN_REMEDIATION":
      requireExact(raw, ["reason_code"]); requireIdentifier(raw.reason_code, 128); break;
    case "PRESERVE_EVIDENCE":
      requireExact(raw, ["chain_head_digest", "snapshot_digest", "process_digest",
        "network_digest", "configuration_digest", "version_digest", "legal_hold_id"]);
      for (const key of ["chain_head_digest", "snapshot_digest", "process_digest",
        "network_digest", "configuration_digest", "version_digest"]) requireDigest(raw[key]);
      requireIdentifier(raw.legal_hold_id); break;
    case "PLAN_REPLAY": validateReplayPlan(raw, approvalCount); break;
    case "COMPLETE_REPLAY":
      requireExact(raw, ["replay_id", "mode", "plan_digest"]); requireUuid(raw.replay_id);
      requireEnum(raw.mode, ["LOGICAL", "SANDBOX", "LIVE"]); requireDigest(raw.plan_digest);
      if (raw.mode === "LIVE" && approvalCount < 2) invalid(); break;
    case "PUBLISH_ROOT_CAUSE": await validateRootCause(raw); break;
    case "TRIGGER_RECERTIFICATION":
      requireExact(raw, ["root_cause_digest", "release_digest", "campaigns"]);
      requireDigest(raw.root_cause_digest); requireDigest(raw.release_digest);
      requireStringSet(raw.campaigns, 1, 64, 128); if (approvalCount < 1) invalid(); break;
    case "EVALUATE_RELEASE": await validateReleaseGate(raw, approvalCount); break;
    case "START_CANARY":
      requireExact(raw, ["certificate_id", "release_digest", "canary_plan_digest", "percentage"]);
      requireUuid(raw.certificate_id); requireDigest(raw.release_digest);
      requireDigest(raw.canary_plan_digest); requireInteger(raw.percentage, 1, 10);
      if (approvalCount < 2) invalid(); break;
    case "RECORD_CANARY":
      requireExact(raw, ["certificate_id", "release_digest", "metrics_digest", "passed", "rollback_required"]);
      requireUuid(raw.certificate_id); requireDigest(raw.release_digest); requireDigest(raw.metrics_digest);
      if (typeof raw.passed !== "boolean" || typeof raw.rollback_required !== "boolean"
        || !raw.passed && !raw.rollback_required || approvalCount < 2) invalid(); break;
    case "ROLLBACK_RELEASE":
      requireExact(raw, ["release_digest", "target_release_digest", "reason_digest"]);
      requireDigest(raw.release_digest); requireDigest(raw.target_release_digest);
      requireDigest(raw.reason_digest); if (approvalCount < 2) invalid(); break;
    case "CLOSE":
      requireExact(raw, ["root_cause_digest", "recertification_evidence_ref",
        "recertification_evidence_digest"]); requireDigest(raw.root_cause_digest);
      requireEvidence(raw.recertification_evidence_ref); requireDigest(raw.recertification_evidence_digest);
      if (approvalCount < 1) invalid(); break;
  }
  return raw;
}

function validateContain(value: Record<string, unknown>, approvalCount: number): void {
  requireExact(value, ["reason_code", "targets", "break_glass"]); requireIdentifier(value.reason_code, 128);
  if (!isRecord(value.targets)) invalid();
  requireExact(value.targets, ["kill_task", "revoke_credentials", "isolate_integrations", "freeze_artifacts"]);
  if (value.targets.kill_task !== true || value.targets.revoke_credentials !== true
    || value.targets.freeze_artifacts !== true) invalid();
  requireStringSet(value.targets.isolate_integrations, 1, 256, 1_024);
  (value.targets.isolate_integrations as unknown[]).forEach((item) => requireResource(item, 1_024));
  if (approvalCount > 0) { if (value.break_glass !== null) invalid(); return; }
  if (!isRecord(value.break_glass)) invalid();
  requireExact(value.break_glass, ["break_glass_id", "expires_at", "review_due_at",
    "compensating_controls", "reason_digest"]); requireUuid(value.break_glass.break_glass_id);
  requireDigest(value.break_glass.reason_digest);
  requireStringSet(value.break_glass.compensating_controls, 1, 32, 128);
  const now = Date.now(), expires = requireDate(value.break_glass.expires_at), review = requireDate(value.break_glass.review_due_at);
  if (expires <= now || expires > now + 900_000 || review < expires || review > now + 86_400_000) invalid();
}

function validateReplayPlan(value: Record<string, unknown>, approvalCount: number): void {
  requireExact(value, ["replay_id", "mode", "input_digest", "source_snapshot_digest",
    "expected_result_digest", "resource_refs", "credential_profile", "fresh_lease_id",
    "fresh_lease_digest", "authorization_lease_expires_at"]); requireUuid(value.replay_id);
  requireDigest(value.input_digest); requireDigest(value.source_snapshot_digest);
  requireDigest(value.expected_result_digest); requireEnum(value.mode, ["LOGICAL", "SANDBOX", "LIVE"]);
  if (value.mode === "LOGICAL") {
    if (!Array.isArray(value.resource_refs) || value.resource_refs.length !== 0
      || value.credential_profile !== null || value.fresh_lease_id !== null
      || value.fresh_lease_digest !== null || value.authorization_lease_expires_at !== null) invalid();
  } else if (value.mode === "SANDBOX") {
    requireStringSet(value.resource_refs, 1, 256, 1_024);
    if (!(value.resource_refs as string[]).every((item) => item.startsWith("sandbox://"))) invalid();
    (value.resource_refs as unknown[]).forEach((item) => requireResource(item, 1_024));
    if (value.credential_profile !== "test-only" || value.fresh_lease_id !== null
      || value.fresh_lease_digest !== null || value.authorization_lease_expires_at !== null) invalid();
  } else {
    requireStringSet(value.resource_refs, 1, 256, 1_024); requireIdentifier(value.credential_profile, 128);
    (value.resource_refs as unknown[]).forEach((item) => requireResource(item, 1_024));
    if (value.credential_profile === "test-only" || approvalCount < 2) invalid();
    requireUuid(value.fresh_lease_id); requireDigest(value.fresh_lease_digest);
    const expiry = requireDate(value.authorization_lease_expires_at);
    if (expiry <= Date.now() || expiry > Date.now() + 3_600_000) invalid();
  }
}

async function validateRootCause(value: Record<string, unknown>): Promise<void> {
  requireExact(value, ["report_id", "report_digest", "findings", "remediations"]); requireUuid(value.report_id);
  if (!Array.isArray(value.findings) || value.findings.length < 1 || value.findings.length > 256
    || !Array.isArray(value.remediations) || value.remediations.length < 1 || value.remediations.length > 512) invalid();
  const findings = new Set<string>();
  for (const item of value.findings) {
    if (!isRecord(item)) invalid();
    requireExact(item, ["finding_id", "category", "trigger", "system_defect", "detection_gap", "recovery_gap", "evidence_refs"]);
    requireIdentifier(item.finding_id, 128); requireEnum(item.category,
      ["TRIGGER", "SYSTEM_DEFECT", "DETECTION_GAP", "RECOVERY_PROBLEM"]);
    for (const key of ["trigger", "system_defect", "detection_gap", "recovery_gap"]) requireIdentifier(item[key], 512);
    if (findings.has(String(item.finding_id))) invalid(); findings.add(String(item.finding_id));
    requireStringSet(item.evidence_refs, 1, 256, 2_048); (item.evidence_refs as unknown[]).forEach(requireEvidence);
  }
  const covered = new Set<string>();
  for (const item of value.remediations) {
    if (!isRecord(item)) invalid();
    requireExact(item, ["remediation_id", "finding_id", "policy_ref", "test_ref", "owner", "due_at"]);
    requireIdentifier(item.remediation_id, 128); requireIdentifier(item.finding_id, 128);
    requireResource(item.policy_ref, 1_024); requireResource(item.test_ref, 1_024);
    requireIdentifier(item.owner); requireDate(item.due_at); covered.add(String(item.finding_id));
  }
  if (![...findings].every((item) => covered.has(item))) invalid();
  value.report_digest = await sha256Canonical({ findings: value.findings, remediations: value.remediations });
}

async function validateReleaseGate(value: Record<string, unknown>, approvalCount: number): Promise<void> {
  requireExact(value, ["release_digest", "definition", "evidence", "rollback_artifact_digest",
    "canary_plan_digest", "valid_until"]); requireDigest(value.release_digest);
  requireDigest(value.rollback_artifact_digest); requireDigest(value.canary_plan_digest);
  const expiry = requireDate(value.valid_until);
  if (approvalCount < 2 || expiry <= Date.now() || expiry > Date.now() + 7 * 86_400_000 || !isRecord(value.definition)) invalid();
  requireExact(value.definition, ["gate_id", "version", "definition_digest", "required_controls",
    "maximum_evidence_age_seconds"]); requireIdentifier(value.definition.gate_id, 128);
  requireIdentifier(value.definition.version, 64); requireStringSet(value.definition.required_controls, 10, 128, 128);
  requireInteger(value.definition.maximum_evidence_age_seconds, 60, 2_592_000);
  const controls = new Set(value.definition.required_controls as string[]);
  if (!BASELINE_CONTROLS.every((item) => controls.has(item)) || !Array.isArray(value.evidence)
    || value.evidence.length !== controls.size) invalid();
  const observed = new Set<string>(), maximumAge = Number(value.definition.maximum_evidence_age_seconds) * 1_000;
  for (const item of value.evidence) {
    if (!isRecord(item)) invalid();
    requireExact(item, ["control_id", "evidence_ref", "evidence_digest", "release_digest", "passed", "collected_at"]);
    requireIdentifier(item.control_id, 128); requireEvidence(item.evidence_ref); requireDigest(item.evidence_digest);
    if (item.release_digest !== value.release_digest || item.passed !== true || observed.has(String(item.control_id))) invalid();
    const collected = requireDate(item.collected_at);
    if (collected > Date.now() || collected < Date.now() - maximumAge) invalid(); observed.add(String(item.control_id));
  }
  if (observed.size !== controls.size || ![...controls].every((item) => observed.has(item))) invalid();
  value.definition.definition_digest = await sha256Canonical({ gate_id: value.definition.gate_id,
    version: value.definition.version, required_controls: value.definition.required_controls,
    maximum_evidence_age_seconds: value.definition.maximum_evidence_age_seconds });
}

function requireExact(value: Record<string, unknown>, keys: string[]): void {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) invalid();
}
function requireUuid(value: unknown): void { if (typeof value !== "string" || !isUuid(value)) invalid(); }
function requireDigest(value: unknown): void { if (typeof value !== "string" || !DIGEST.test(value)) invalid(); }
function requireIdentifier(value: unknown, maximum = 256): void {
  if (typeof value !== "string" || value.length > maximum || !IDENTIFIER.test(value)) invalid();
}
function requireBounded(value: unknown, maximum: number): void {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\0\r\n]/.test(value)) invalid();
}
function requireResource(value: unknown, maximum: number): void {
  requireBounded(value, maximum);
  if (!/^[A-Za-z0-9._:/@-]+$/.test(String(value)) || String(value).includes("..")) invalid();
}
function requireEnum(value: unknown, allowed: string[]): void { if (typeof value !== "string" || !allowed.includes(value)) invalid(); }
function requireInteger(value: unknown, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) invalid();
}
function requireStringSet(value: unknown, minimum: number, maximum: number, maximumLength: number): void {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum
    || !value.every((item) => typeof item === "string" && item.length >= 1 && item.length <= maximumLength
      && !/[\0\r\n]/.test(item)) || new Set(value).size !== value.length) invalid();
}
function requireEvidence(value: unknown): void {
  requireBounded(value, 2_048);
  if (!/^(evidence:\/\/|urn:agenttrust:(evidence|ledger-evidence):)/.test(String(value)) || /[\s?#]/.test(String(value))) invalid();
}
function requireDate(value: unknown): number {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) invalid();
  return Date.parse(value);
}
function invalid(): never { throw new Error("CONTROL_INCIDENT_COMMAND_INVALID"); }
