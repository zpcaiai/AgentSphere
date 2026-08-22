import { isRecord, isUuid } from "./control-state";
import type { MarketplaceTypedCommand } from "./enterprise-api-types";

export type MarketplaceKind = MarketplaceTypedCommand["kind"];
export const MARKETPLACE_KINDS: MarketplaceKind[] = [
  "ONBOARD_PUBLISHER", "VERIFY_PUBLISHER_KEY", "SET_PUBLISHER_TRUST",
  "CONFIGURE_TENANT_CATALOG", "SUBMIT_RELEASE", "REVIEW_RELEASE",
  "REQUEST_INSTALLATION", "APPROVE_INSTALLATION", "INSTALL", "ACTIVATE",
  "PLAN_UPGRADE", "RECORD_CANARY", "UPGRADE", "ROLLBACK", "DEACTIVATE",
  "REVOKE_RELEASE",
];

const DIGEST = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9._:/@-]+$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const UUID = "00000000-0000-4000-8000-000000000000";
const HASH = "0".repeat(64);

export function marketplaceTemplate(kind: MarketplaceKind): Record<string, unknown> {
  switch (kind) {
    case "ONBOARD_PUBLISHER": return { kind, publisher_id: "publisher:replace-me",
      publisher_subject: "subject:replace-me", identity_digest: HASH,
      responsibility_contact: "owner@example.invalid", home_region: "region:replace-me" };
    case "VERIFY_PUBLISHER_KEY": return { kind, publisher_id: "publisher:replace-me",
      key_id: "key:replace-me", algorithm: "Ed25519", public_key: "A".repeat(43),
      key_fingerprint: HASH, not_before: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 86_400_000).toISOString(), review_digest: HASH };
    case "SET_PUBLISHER_TRUST": return { kind, publisher_id: "publisher:replace-me",
      trust: "SUSPENDED", reason_digest: HASH };
    case "CONFIGURE_TENANT_CATALOG": return { kind, control_plane_version: "1.0.0",
      region: "region:replace-me", entitlements: ["entitlement:replace-me"],
      allowed_compatibility: ["agenttrust-control-plane>=1.0.0"],
      minimum_publisher_trust: "VERIFIED", maximum_risk: "HIGH" };
    case "SUBMIT_RELEASE": return { kind, release_id: UUID, manifest: manifestTemplate(),
      release_certificate: certificateTemplate(), visibility: "PRIVATE",
      entitlement: "entitlement:replace-me", allowed_regions: ["region:replace-me"],
      risk_rating: "HIGH", minimum_publisher_trust: "VERIFIED",
      minimum_control_plane_version: "1.0.0" };
    case "REVIEW_RELEASE": return { kind, release_id: UUID, decision: "REJECT", review_digest: HASH };
    case "REQUEST_INSTALLATION": return { kind, installation_id: UUID, release_id: UUID,
      environment: "development", request_reason_digest: HASH };
    case "APPROVE_INSTALLATION": return { kind, installation_id: UUID, decision: "REJECT",
      approval_digest: HASH };
    case "INSTALL": return { kind, installation_id: UUID, artifact_receipt_digest: HASH };
    case "ACTIVATE": return { kind, installation_id: UUID, production_certificate_digest: null };
    case "PLAN_UPGRADE": return { kind, plan_id: UUID, current_installation_id: UUID,
      target_installation_id: "00000000-0000-4000-8000-000000000001",
      migration_digest: HASH, rollback_digest: HASH, canary_percent: 1 };
    case "RECORD_CANARY": return { kind, plan_id: UUID, passed: false, observed_samples: 1,
      evidence_ref: "urn:agenttrust:evidence:replace-me", evidence_digest: HASH };
    case "UPGRADE": return { kind, plan_id: UUID, production_certificate_digest: null };
    case "ROLLBACK": return { kind, installation_id: UUID, reason_digest: HASH };
    case "DEACTIVATE": return { kind, installation_id: UUID, reason_digest: HASH };
    case "REVOKE_RELEASE": return { kind, release_id: UUID, reason_code: "SECURITY_REVOKED",
      reason_digest: HASH, running_task_response: "KILL" };
  }
}

export function marketplaceResource(command: MarketplaceTypedCommand): string {
  switch (command.kind) {
    case "ONBOARD_PUBLISHER": case "VERIFY_PUBLISHER_KEY": case "SET_PUBLISHER_TRUST":
      return command.publisher_id;
    case "CONFIGURE_TENANT_CATALOG": return "tenant-catalog";
    case "SUBMIT_RELEASE": case "REVIEW_RELEASE": case "REVOKE_RELEASE": return command.release_id;
    case "REQUEST_INSTALLATION": case "APPROVE_INSTALLATION": case "INSTALL": case "ACTIVATE":
    case "ROLLBACK": case "DEACTIVATE": return command.installation_id;
    case "PLAN_UPGRADE": case "RECORD_CANARY": case "UPGRADE": return command.plan_id;
  }
}

export function validateMarketplaceTypedCommand(value: unknown): MarketplaceTypedCommand {
  if (!isRecord(value) || typeof value.kind !== "string"
    || !(MARKETPLACE_KINDS as string[]).includes(value.kind) || JSON.stringify(value).length > 900_000) invalid();
  switch (value.kind as MarketplaceKind) {
    case "ONBOARD_PUBLISHER":
      exact(value, ["kind", "publisher_id", "publisher_subject", "identity_digest",
        "responsibility_contact", "home_region"]); identifier(value.publisher_id, 128);
      identifier(value.publisher_subject); digest(value.identity_digest); email(value.responsibility_contact);
      identifier(value.home_region, 128); break;
    case "VERIFY_PUBLISHER_KEY":
      exact(value, ["kind", "publisher_id", "key_id", "algorithm", "public_key",
        "key_fingerprint", "not_before", "expires_at", "review_digest"]);
      identifier(value.publisher_id, 128); identifier(value.key_id, 128);
      if (value.algorithm !== "Ed25519" || typeof value.public_key !== "string"
        || !/^[A-Za-z0-9_-]{43}$/.test(value.public_key)) invalid();
      digest(value.key_fingerprint); digest(value.review_digest);
      if (date(value.not_before) >= date(value.expires_at)
        || date(value.expires_at) > Date.now() + 730 * 86_400_000) invalid(); break;
    case "SET_PUBLISHER_TRUST":
      exact(value, ["kind", "publisher_id", "trust", "reason_digest"]);
      identifier(value.publisher_id, 128); oneOf(value.trust, ["SUSPENDED", "REVOKED"]);
      digest(value.reason_digest); break;
    case "CONFIGURE_TENANT_CATALOG":
      exact(value, ["kind", "control_plane_version", "region", "entitlements",
        "allowed_compatibility", "minimum_publisher_trust", "maximum_risk"]);
      semver(value.control_plane_version); identifier(value.region, 128);
      stringSet(value.entitlements, 1, 256, 256); stringSet(value.allowed_compatibility, 1, 256, 256);
      if (value.minimum_publisher_trust !== "VERIFIED") invalid(); risk(value.maximum_risk); break;
    case "SUBMIT_RELEASE": validateSubmitRelease(value); break;
    case "REVIEW_RELEASE":
      exact(value, ["kind", "release_id", "decision", "review_digest"]); uuid(value.release_id);
      oneOf(value.decision, ["APPROVE", "REJECT"]); digest(value.review_digest); break;
    case "REQUEST_INSTALLATION":
      exact(value, ["kind", "installation_id", "release_id", "environment", "request_reason_digest"]);
      uuid(value.installation_id); uuid(value.release_id);
      oneOf(value.environment, ["development", "staging", "canary", "production"]);
      digest(value.request_reason_digest); break;
    case "APPROVE_INSTALLATION":
      exact(value, ["kind", "installation_id", "decision", "approval_digest"]);
      uuid(value.installation_id); oneOf(value.decision, ["APPROVE", "REJECT"]);
      digest(value.approval_digest); break;
    case "INSTALL":
      exact(value, ["kind", "installation_id", "artifact_receipt_digest"]);
      uuid(value.installation_id); digest(value.artifact_receipt_digest); break;
    case "ACTIVATE":
      exact(value, ["kind", "installation_id", "production_certificate_digest"]);
      uuid(value.installation_id); digestOrNull(value.production_certificate_digest); break;
    case "PLAN_UPGRADE":
      exact(value, ["kind", "plan_id", "current_installation_id", "target_installation_id",
        "migration_digest", "rollback_digest", "canary_percent"]); uuid(value.plan_id);
      uuid(value.current_installation_id); uuid(value.target_installation_id);
      if (value.current_installation_id === value.target_installation_id) invalid();
      digest(value.migration_digest); digest(value.rollback_digest); integer(value.canary_percent, 1, 50); break;
    case "RECORD_CANARY":
      exact(value, ["kind", "plan_id", "passed", "observed_samples", "evidence_ref", "evidence_digest"]);
      uuid(value.plan_id); if (typeof value.passed !== "boolean") invalid();
      integer(value.observed_samples, 1, 10_000_000); evidence(value.evidence_ref); digest(value.evidence_digest); break;
    case "UPGRADE":
      exact(value, ["kind", "plan_id", "production_certificate_digest"]);
      uuid(value.plan_id); digestOrNull(value.production_certificate_digest); break;
    case "ROLLBACK": case "DEACTIVATE":
      exact(value, ["kind", "installation_id", "reason_digest"]);
      uuid(value.installation_id); digest(value.reason_digest); break;
    case "REVOKE_RELEASE":
      exact(value, ["kind", "release_id", "reason_code", "reason_digest", "running_task_response"]);
      uuid(value.release_id); identifier(value.reason_code, 128); digest(value.reason_digest);
      oneOf(value.running_task_response, ["PAUSE", "KILL", "ALLOW_TO_FINISH"]); break;
  }
  return value as unknown as MarketplaceTypedCommand;
}

function manifestTemplate(): Record<string, unknown> {
  return { schema_version: "agenttrust.domain-pack.v1", pack_id: "pack:replace-me", version: "1.0.0",
    digest: HASH, publisher_identity: "publisher:replace-me", description: "replace-me",
    permissions: { tools: [], network_destinations: [], data_classes: [], secret_scopes: [],
      executors: [], approval_scopes: [] }, tools: [{ tool_id: "tool:replace-me", effect_class: "PURE",
      approval_required: false, compensation_ref: null, irreversible_reason: null,
      executor_template: "executor:replace-me" }], policy_bundle_ref: "policy:replace-me",
    evaluator_ref: "evaluator:replace-me", compensation_refs: [],
    threat_scenario_refs: ["threat:replace-me"],
    artifact_refs: [`registry.example.invalid/pack@sha256:${HASH}`],
    compatibility: ["agenttrust-control-plane>=1.0.0"], signature: { key_id: "key:replace-me",
      publisher_identity: "publisher:replace-me", subject_digest: HASH,
      signature: "A".repeat(86), signed_at: new Date().toISOString() } };
}
function certificateTemplate(): Record<string, unknown> {
  return { schema_version: "agenttrust.incident-release.v1", certificate_id: UUID,
    release_digest: HASH, gate_id: "gate:replace-me", gate_version: "1", definition_digest: HASH,
    evidence_digests: { CONTRACT: HASH }, valid_from: new Date().toISOString(),
    valid_until: new Date(Date.now() + 86_400_000).toISOString(), engine_certificate_only: true,
    production_closure: false, key_id: "key:replace-me", signature: "A".repeat(86) };
}

function validateSubmitRelease(value: Record<string, unknown>): void {
  exact(value, ["kind", "release_id", "manifest", "release_certificate", "visibility",
    "entitlement", "allowed_regions", "risk_rating", "minimum_publisher_trust",
    "minimum_control_plane_version"]); uuid(value.release_id); validateManifest(value.manifest);
  validateCertificate(value.release_certificate, (value.manifest as Record<string, unknown>).digest);
  oneOf(value.visibility, ["PRIVATE", "TENANT"]); identifier(value.entitlement, 128);
  stringSet(value.allowed_regions, 1, 64, 128, true); risk(value.risk_rating);
  if (value.minimum_publisher_trust !== "VERIFIED") invalid(); semver(value.minimum_control_plane_version);
}

function validateManifest(raw: unknown): void {
  if (!isRecord(raw)) invalid();
  exact(raw, ["schema_version", "pack_id", "version", "digest", "publisher_identity", "description",
    "permissions", "tools", "policy_bundle_ref", "evaluator_ref", "compensation_refs",
    "threat_scenario_refs", "artifact_refs", "compatibility", "signature"]);
  if (raw.schema_version !== "agenttrust.domain-pack.v1") invalid(); identifier(raw.pack_id, 128);
  semver(raw.version); digest(raw.digest); identifier(raw.publisher_identity, 128); bounded(raw.description, 4_096);
  bounded(raw.policy_bundle_ref, 2_048); bounded(raw.evaluator_ref, 2_048);
  stringSet(raw.compensation_refs, 0, 256, 2_048); stringSet(raw.threat_scenario_refs, 1, 256, 2_048);
  stringSet(raw.artifact_refs, 1, 256, 2_048);
  if (!(raw.artifact_refs as string[]).every((item) => !item.endsWith(":latest")
    && /^.{1,1980}sha256:[a-f0-9]{64}$/.test(item))) invalid();
  stringSet(raw.compatibility, 1, 256, 2_048); validatePermissions(raw.permissions);
  if (!Array.isArray(raw.tools) || raw.tools.length < 1 || raw.tools.length > 256) invalid();
  const ids = new Set<string>();
  for (const item of raw.tools) {
    if (!isRecord(item)) invalid(); exact(item, ["tool_id", "effect_class", "approval_required",
      "compensation_ref", "irreversible_reason", "executor_template"]); bounded(item.tool_id, 256);
    oneOf(item.effect_class, ["PURE", "IDEMPOTENT", "COMPENSATABLE", "IRREVERSIBLE"]);
    if (typeof item.approval_required !== "boolean" || ids.has(String(item.tool_id))) invalid();
    ids.add(String(item.tool_id)); nullableBounded(item.compensation_ref, 2_048);
    nullableBounded(item.irreversible_reason, 2_048); bounded(item.executor_template, 2_048);
    if (/\/bin\/sh|bash -c/.test(String(item.executor_template))) invalid();
    if (["PURE", "IDEMPOTENT"].includes(String(item.effect_class))
      && (item.compensation_ref !== null || item.irreversible_reason !== null)) invalid();
    if (item.effect_class === "COMPENSATABLE"
      && (typeof item.compensation_ref !== "string" || item.irreversible_reason !== null)) invalid();
    if (item.effect_class === "IRREVERSIBLE"
      && (item.compensation_ref !== null || typeof item.irreversible_reason !== "string"
        || item.approval_required !== true)) invalid();
  }
  validatePublisherSignature(raw.signature, String(raw.publisher_identity), String(raw.digest));
}

function validatePermissions(raw: unknown): void {
  if (!isRecord(raw)) invalid();
  exact(raw, ["tools", "network_destinations", "data_classes", "secret_scopes", "executors", "approval_scopes"]);
  for (const key of Object.keys(raw)) stringSet(raw[key], 0, 256, 2_048);
}
function validatePublisherSignature(raw: unknown, publisher: string, subjectDigest: string): void {
  if (!isRecord(raw)) invalid(); exact(raw, ["key_id", "publisher_identity", "subject_digest", "signature", "signed_at"]);
  identifier(raw.key_id, 128);
  if (raw.publisher_identity !== publisher || raw.subject_digest !== subjectDigest
    || typeof raw.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(raw.signature)) invalid();
  date(raw.signed_at);
}
function validateCertificate(raw: unknown, releaseDigest: unknown): void {
  if (!isRecord(raw)) invalid(); exact(raw, ["schema_version", "certificate_id", "release_digest",
    "gate_id", "gate_version", "definition_digest", "evidence_digests", "valid_from", "valid_until",
    "engine_certificate_only", "production_closure", "key_id", "signature"]);
  if (raw.schema_version !== "agenttrust.incident-release.v1") invalid(); uuid(raw.certificate_id);
  if (raw.release_digest !== releaseDigest) invalid(); digest(raw.release_digest); identifier(raw.gate_id);
  bounded(raw.gate_version, 128); digest(raw.definition_digest);
  if (!isRecord(raw.evidence_digests) || Object.keys(raw.evidence_digests).length < 1
    || Object.keys(raw.evidence_digests).length > 256) invalid();
  for (const [key, item] of Object.entries(raw.evidence_digests)) { identifier(key, 128); digest(item); }
  if (date(raw.valid_from) >= date(raw.valid_until) || raw.engine_certificate_only !== true
    || raw.production_closure !== false) invalid(); identifier(raw.key_id);
  if (typeof raw.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(raw.signature)) invalid();
}

function exact(value: Record<string, unknown>, keys: string[]): void {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) invalid();
}
function identifier(value: unknown, maximum = 256): void {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || !IDENTIFIER.test(value)) invalid();
}
function bounded(value: unknown, maximum: number): void {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\0\r\n]/.test(value)) invalid();
}
function nullableBounded(value: unknown, maximum: number): void { if (value !== null) bounded(value, maximum); }
function uuid(value: unknown): void { if (typeof value !== "string" || !isUuid(value)) invalid(); }
function digest(value: unknown): void { if (typeof value !== "string" || !DIGEST.test(value)) invalid(); }
function digestOrNull(value: unknown): void { if (value !== null) digest(value); }
function semver(value: unknown): void { if (typeof value !== "string" || !SEMVER.test(value)) invalid(); }
function oneOf(value: unknown, allowed: string[]): void { if (typeof value !== "string" || !allowed.includes(value)) invalid(); }
function integer(value: unknown, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) invalid();
}
function stringSet(value: unknown, minimum: number, maximum: number, maximumLength: number,
  identifiers = false): void {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum || new Set(value).size !== value.length
    || !value.every((item) => typeof item === "string" && item.length >= 1 && item.length <= maximumLength
      && !/[\0\r\n]/.test(item) && (!identifiers || IDENTIFIER.test(item)))) invalid();
}
function email(value: unknown): void {
  if (typeof value !== "string" || value.length > 320 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) invalid();
}
function evidence(value: unknown): void {
  bounded(value, 2_048); if (!String(value).startsWith("urn:agenttrust:") || /[\s?#]/.test(String(value))) invalid();
}
function date(value: unknown): number {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) invalid(); return Date.parse(value);
}
function risk(value: unknown): void { oneOf(value, ["LOW", "MEDIUM", "HIGH", "CRITICAL"]); }
function invalid(): never { throw new Error("CONTROL_PACK_COMMAND_INVALID"); }
