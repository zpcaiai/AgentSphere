import { isRecord, isUuid, sha256Canonical } from "./control-state";
import type {
  PolicyActionReceipt, PolicyArtifactPage, PolicyArtifactType, PolicyPage,
} from "./enterprise-api-types";

const DIGEST = /^[a-f0-9]{64}$/;
const POLICY_ID = /^[A-Za-z0-9._:/-]{1,256}$/;
const SUBJECT = /^[A-Za-z0-9._:/@-]{1,256}$/;
const RISKS = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const DECISIONS = new Set(["ALLOW", "DENY", "KILL", "PAUSE", "REQUIRE_APPROVAL"]);
const ENVIRONMENTS = new Set(["DEV", "STAGING", "CANARY", "PRODUCTION"]);
const PAGE_FIELDS = ["schema_version", "tenant_id", "items", "next_after_policy_id"];
const SUMMARY_FIELDS = ["policy_id", "revision", "lifecycle_state", "source_digest", "author_subject",
  "active_bundle_digest", "active_environment", "resource_version", "updated_at"];
const ARTIFACT_PAGE_FIELDS = ["schema_version", "tenant_id", "policy_id", "artifact_type", "items"];
const SOURCE_FIELDS = ["schema_version", "source_id", "tenant_id", "version", "rules", "default_decision",
  "author", "source_digest", "created_at"];
const RULE_FIELDS = ["rule_id", "subject_pattern", "tool_pattern", "resource_pattern", "decision",
  "maximum_risk", "reason_code"];
const ANALYSIS_FIELDS = ["schema_version", "policy_id", "revision", "source_digest", "valid", "findings", "analyzed_at"];
const REVIEW_FIELDS = ["review_id", "revision", "reviewer_subject", "decision", "review_digest", "reviewed_at"];
const SIMULATION_FIELDS = ["simulation_id", "revision", "run_kind", "baseline_bundle_digest",
  "candidate_source_digest", "corpus_digest", "evaluated_actions", "difference_count", "side_effect_count",
  "impact_report_digest", "impact_report", "run_by", "created_at"];
const SIMULATION_REPORT_FIELDS = ["schema_version", "old_bundle_digest", "new_bundle_digest",
  "evaluated_actions", "differences", "side_effect_count", "generated_at"];
const DIFFERENCE_FIELDS = ["action_id", "agent_id", "tool", "resource", "risk", "old_decision", "new_decision"];
const IMPACT_FIELDS = ["schema_version", "impact_report_id", "tenant_id", "policy_id", "revision",
  "simulation_id", "simulation_digest", "evaluated_actions", "difference_count", "affected_agents",
  "affected_tools", "affected_resources", "maximum_risk", "generated_at", "impact_report_digest"];
const PROMOTION_FIELDS = ["environment", "sequence", "bundle_digest", "previous_bundle_digest", "rollback_of",
  "promoted_by", "state", "promotion_digest", "promoted_at", "completed_at"];
const EXCEPTION_FIELDS = ["exception_id", "policy_id", "scope_digest", "owner_subject", "approval_ids",
  "reason_digest", "compensating_controls", "issued_by", "expires_at", "revoked_at", "expired_at", "state", "created_at"];
const RECEIPT_FIELDS = ["schema_version", "action_id", "task_id", "accepted", "execution_pending",
  "ingress_digest", "ledger_evidence_ref", "ledger_evidence_digest"];

export function validatePolicyPage(value: unknown, tenantId: string, after: string | null,
  limit: number): PolicyPage {
  assert(exact(value, PAGE_FIELDS) && value.schema_version === "agenttrust.authoritative-policy-page.v1"
    && value.tenant_id === tenantId && Array.isArray(value.items) && value.items.length <= limit
    && (value.next_after_policy_id === null || policyId(value.next_after_policy_id)));
  let previous = after;
  for (const item of value.items) {
    assert(exact(item, SUMMARY_FIELDS) && policyId(item.policy_id)
      && (previous === null || item.policy_id > previous) && integer(item.revision, 1)
      && ["DRAFT", "VALIDATED", "REVIEW", "SIGNED", "DEPRECATED"].includes(String(item.lifecycle_state))
      && digest(item.source_digest) && bounded(item.author_subject, 256)
      && (item.active_bundle_digest === null || digest(item.active_bundle_digest))
      && (item.active_environment === null || ENVIRONMENTS.has(String(item.active_environment)))
      && integer(item.resource_version, 1) && dateTime(item.updated_at));
    previous = item.policy_id as string;
  }
  assert(value.next_after_policy_id === null || (value.items.length === limit
    && value.next_after_policy_id === previous));
  return value as unknown as PolicyPage;
}

export async function validatePolicyArtifactPage(value: unknown, tenantId: string, policy: string,
  expectedType: PolicyArtifactType, limit: number): Promise<PolicyArtifactPage> {
  assert(exact(value, ARTIFACT_PAGE_FIELDS)
    && value.schema_version === "agenttrust.authoritative-policy-artifact-page.v1"
    && value.tenant_id === tenantId && value.policy_id === policy && value.artifact_type === expectedType
    && Array.isArray(value.items) && value.items.length <= limit);
  for (const item of value.items) {
    switch (expectedType) {
      case "SOURCES": await source(item, tenantId, policy); break;
      case "ANALYSES": analysis(item, policy); break;
      case "REVIEWS": review(item); break;
      case "SIMULATIONS": await simulation(item); break;
      case "IMPACT_REPORTS": await impact(item, tenantId, policy); break;
      case "PROMOTIONS": await promotion(item, tenantId, policy); break;
      case "EXCEPTIONS": exceptionArtifact(item, policy); break;
    }
  }
  return value as unknown as PolicyArtifactPage;
}

export function validatePolicyActionReceipt(value: unknown, commandId: string): PolicyActionReceipt {
  assert(exact(value, RECEIPT_FIELDS) && value.schema_version === "agenttrust.policy-action-receipt.v1"
    && value.action_id === commandId && isUuid(String(value.task_id)) && value.accepted === true
    && value.execution_pending === true && digest(value.ingress_digest)
    && bounded(value.ledger_evidence_ref, 2_048) && !/\s/.test(value.ledger_evidence_ref as string)
    && digest(value.ledger_evidence_digest), "CONTROL_POLICY_ACTION_RECEIPT_INVALID");
  return value as unknown as PolicyActionReceipt;
}

async function source(value: unknown, tenantId: string, policy: string): Promise<void> {
  assert(exact(value, SOURCE_FIELDS) && value.schema_version === "agenttrust.policy-admin.v1"
    && value.source_id === policy && value.tenant_id === tenantId && bounded(value.version, 128)
    && Array.isArray(value.rules) && value.rules.length >= 1 && value.rules.length <= 10_000
    && ["DENY", "KILL", "PAUSE", "REQUIRE_APPROVAL"].includes(String(value.default_decision))
    && SUBJECT.test(String(value.author)) && digest(value.source_digest) && dateTime(value.created_at));
  for (const rule of value.rules) {
    assert(exact(rule, RULE_FIELDS) && bounded(rule.rule_id, 256) && bounded(rule.subject_pattern, 1_024)
      && bounded(rule.tool_pattern, 1_024) && bounded(rule.resource_pattern, 2_048)
      && DECISIONS.has(String(rule.decision)) && RISKS.has(String(rule.maximum_risk))
      && /^[A-Z][A-Z0-9_]{2,127}$/.test(String(rule.reason_code)));
  }
  const input = { ...value, source_digest: "" };
  assert(await sha256Canonical(input) === value.source_digest);
}

function analysis(value: unknown, policy: string): void {
  assert(exact(value, ANALYSIS_FIELDS) && value.schema_version === "agenttrust.policy-static-analysis.v1"
    && value.policy_id === policy && integer(value.revision, 1) && digest(value.source_digest)
    && typeof value.valid === "boolean" && Array.isArray(value.findings) && value.findings.length <= 20_000
    && dateTime(value.analyzed_at));
  let blocking = false;
  for (const finding of value.findings) {
    assert(exact(finding, ["code", "rule_ids", "blocking"]) && bounded(finding.code, 128)
      && strings(finding.rule_ids, 0, 10_000, 256) && typeof finding.blocking === "boolean");
    blocking ||= finding.blocking as boolean;
  }
  assert(value.valid !== blocking);
}

function review(value: unknown): void {
  assert(exact(value, REVIEW_FIELDS) && isUuid(String(value.review_id)) && integer(value.revision, 1)
    && SUBJECT.test(String(value.reviewer_subject)) && ["APPROVE", "REJECT"].includes(String(value.decision))
    && digest(value.review_digest) && dateTime(value.reviewed_at));
}

async function simulation(value: unknown): Promise<void> {
  assert(exact(value, SIMULATION_FIELDS) && isUuid(String(value.simulation_id)) && integer(value.revision, 1)
    && ["SIMULATION", "SHADOW"].includes(String(value.run_kind)) && digest(value.baseline_bundle_digest)
    && digest(value.candidate_source_digest) && digest(value.corpus_digest)
    && integer(value.evaluated_actions, 1, 10_000) && integer(value.difference_count, 0, 10_000)
    && Number(value.difference_count) <= Number(value.evaluated_actions) && value.side_effect_count === 0
    && digest(value.impact_report_digest) && SUBJECT.test(String(value.run_by)) && dateTime(value.created_at));
  const report = value.impact_report;
  assert(exact(report, SIMULATION_REPORT_FIELDS) && report.schema_version === "agenttrust.policy-admin.v1"
    && report.old_bundle_digest === value.baseline_bundle_digest
    && report.new_bundle_digest === value.candidate_source_digest
    && report.evaluated_actions === value.evaluated_actions && report.side_effect_count === 0
    && Array.isArray(report.differences) && report.differences.length === value.difference_count
    && dateTime(report.generated_at));
  for (const difference of report.differences) {
    assert(exact(difference, DIFFERENCE_FIELDS) && bounded(difference.action_id, 256)
      && bounded(difference.agent_id, 256) && bounded(difference.tool, 1_024)
      && bounded(difference.resource, 2_048) && RISKS.has(String(difference.risk))
      && DECISIONS.has(String(difference.old_decision)) && DECISIONS.has(String(difference.new_decision)));
  }
  assert(await sha256Canonical(report) === value.impact_report_digest);
}

async function impact(value: unknown, tenantId: string, policy: string): Promise<void> {
  assert(exact(value, IMPACT_FIELDS) && value.schema_version === "agenttrust.policy-impact-report.v1"
    && isUuid(String(value.impact_report_id)) && value.tenant_id === tenantId && value.policy_id === policy
    && integer(value.revision, 1) && isUuid(String(value.simulation_id)) && digest(value.simulation_digest)
    && integer(value.evaluated_actions, 1, 10_000) && integer(value.difference_count, 0, 10_000)
    && Number(value.difference_count) <= Number(value.evaluated_actions)
    && strings(value.affected_agents, 0, 10_000, 256) && strings(value.affected_tools, 0, 10_000, 1_024)
    && strings(value.affected_resources, 0, 10_000, 2_048) && RISKS.has(String(value.maximum_risk))
    && dateTime(value.generated_at) && digest(value.impact_report_digest));
  const { impact_report_digest: supplied, ...input } = value;
  assert(await sha256Canonical(input) === supplied);
}

async function promotion(value: unknown, tenantId: string, policy: string): Promise<void> {
  assert(exact(value, PROMOTION_FIELDS) && ENVIRONMENTS.has(String(value.environment))
    && integer(value.sequence, 1) && digest(value.bundle_digest)
    && (value.previous_bundle_digest === null || digest(value.previous_bundle_digest))
    && (value.rollback_of === null || integer(value.rollback_of, 1)) && SUBJECT.test(String(value.promoted_by))
    && ["ACTIVE", "SUPERSEDED", "ROLLED_BACK"].includes(String(value.state))
    && digest(value.promotion_digest) && dateTime(value.promoted_at)
    && (value.completed_at === null || dateTime(value.completed_at))
    && ((value.state === "ACTIVE") === (value.completed_at === null)));
  assert(await sha256Canonical({ tenant_id: tenantId, policy_id: policy, environment: value.environment,
    sequence: value.sequence, bundle_digest: value.bundle_digest, rollback_of: value.rollback_of })
    === value.promotion_digest);
}

function exceptionArtifact(value: unknown, policy: string): void {
  assert(exact(value, EXCEPTION_FIELDS) && isUuid(String(value.exception_id)) && value.policy_id === policy
    && digest(value.scope_digest) && SUBJECT.test(String(value.owner_subject))
    && strings(value.approval_ids, 2, 64, 256) && digest(value.reason_digest)
    && strings(value.compensating_controls, 1, 64, 256) && SUBJECT.test(String(value.issued_by))
    && dateTime(value.expires_at) && (value.revoked_at === null || dateTime(value.revoked_at))
    && (value.expired_at === null || dateTime(value.expired_at))
    && ["ACTIVE", "REVOKED", "EXPIRED"].includes(String(value.state)) && dateTime(value.created_at));
  const created = Date.parse(value.created_at as string);
  const expires = Date.parse(value.expires_at as string);
  assert(expires > created && expires <= created + 30 * 86_400_000
    && (value.state !== "ACTIVE" || value.revoked_at === null && value.expired_at === null)
    && (value.state !== "REVOKED" || value.revoked_at !== null && value.expired_at === null)
    && (value.state !== "EXPIRED" || value.revoked_at === null));
}

function exact(value: unknown, fields: string[]): value is Record<string, unknown> {
  return isRecord(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}
function digest(value: unknown): value is string { return typeof value === "string" && DIGEST.test(value); }
function policyId(value: unknown): value is string { return typeof value === "string" && POLICY_ID.test(value); }
function bounded(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum && !/[\0\r\n]/.test(value);
}
function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): boolean {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}
function dateTime(value: unknown): value is string {
  return typeof value === "string" && value.length <= 64 && !Number.isNaN(Date.parse(value));
}
function strings(value: unknown, minimum: number, maximum: number, maximumLength: number): boolean {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum
    && value.every((item) => bounded(item, maximumLength)) && new Set(value).size === value.length;
}
function assert(condition: unknown, code = "CONTROL_POLICY_AUTHORITY_RESPONSE_INVALID"): asserts condition {
  if (!condition) throw new Error(code);
}
