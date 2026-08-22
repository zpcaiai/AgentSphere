import { isRecord, isUuid, sha256Canonical } from "./control-state";
import type { MarketplaceActionReceipt, PackPage } from "./enterprise-api-types";

const DIGEST = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9._:/@-]{1,256}$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const PAGE_FIELDS = ["schema_version", "authoritative", "tenant_id", "releases", "installations",
  "next_after_pack_id", "data_digest"];
const RELEASE_FIELDS = ["release_id", "pack_id", "version", "pack_digest", "publisher_id", "visibility",
  "entitlement", "allowed_regions", "risk_rating", "compatibility", "certificate_digest", "review_status", "updated_at"];
const INSTALL_FIELDS = ["installation_id", "release_id", "pack_id", "version", "environment", "state",
  "permission_expansion", "previous_installation_id", "updated_at"];
const RECEIPT_FIELDS = ["schema_version", "action_id", "task_id", "accepted", "execution_pending",
  "ingress_digest", "ledger_evidence_ref", "ledger_evidence_digest"];

export async function validatePackPage(value: unknown, tenantId: string, after: string | null,
  limit: number): Promise<PackPage> {
  assert(exact(value, PAGE_FIELDS) && value.schema_version === "agenttrust.authoritative-pack-page.v1"
    && value.authoritative === true && value.tenant_id === tenantId && Array.isArray(value.releases)
    && value.releases.length <= limit && Array.isArray(value.installations)
    && value.installations.length <= limit && (value.next_after_pack_id === null
      || identifier(value.next_after_pack_id, 128)) && digest(value.data_digest));
  let previousPack = after;
  let previousVersion: string | null = null;
  for (const release of value.releases) {
    assert(exact(release, RELEASE_FIELDS) && isUuid(String(release.release_id))
      && identifier(release.pack_id, 128) && SEMVER.test(String(release.version))
      && digest(release.pack_digest) && identifier(release.publisher_id, 128)
      && ["PRIVATE", "TENANT"].includes(String(release.visibility)) && identifier(release.entitlement, 128)
      && strings(release.allowed_regions, 1, 64, 128)
      && release.allowed_regions.every((item) => identifier(item, 128))
      && ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(String(release.risk_rating))
      && strings(release.compatibility, 1, 256, 2_048) && digest(release.certificate_digest)
      && ["SUBMITTED", "PUBLISHED", "REJECTED", "REVOKED"].includes(String(release.review_status))
      && dateTime(release.updated_at) && (previousPack === null
        || String(release.pack_id) > previousPack
        || release.pack_id === previousPack && previousVersion !== null
          && String(release.version) > previousVersion));
    if (release.pack_id !== previousPack) previousVersion = null;
    previousPack = String(release.pack_id);
    previousVersion = String(release.version);
  }
  let previousUpdate = Number.POSITIVE_INFINITY;
  for (const installation of value.installations) {
    assert(exact(installation, INSTALL_FIELDS) && isUuid(String(installation.installation_id))
      && isUuid(String(installation.release_id)) && identifier(installation.pack_id, 128)
      && SEMVER.test(String(installation.version))
      && ["development", "staging", "canary", "production"].includes(String(installation.environment))
      && ["PENDING_APPROVAL", "APPROVED", "REJECTED", "INSTALLED", "ACTIVE", "INACTIVE",
        "ROLLED_BACK", "REVOKED"].includes(String(installation.state))
      && typeof installation.permission_expansion === "boolean"
      && (installation.previous_installation_id === null
        || isUuid(String(installation.previous_installation_id)))
      && dateTime(installation.updated_at) && Date.parse(installation.updated_at) <= previousUpdate);
    previousUpdate = Date.parse(installation.updated_at as string);
  }
  assert(value.next_after_pack_id === null || (value.releases.length === limit
    && value.next_after_pack_id === previousPack));
  const { data_digest: supplied, ...material } = value;
  assert(await sha256Canonical(material) === supplied);
  return value as unknown as PackPage;
}

export function validateMarketplaceActionReceipt(value: unknown,
  commandId: string): MarketplaceActionReceipt {
  assert(exact(value, RECEIPT_FIELDS)
    && value.schema_version === "agenttrust.marketplace-action-receipt.v1"
    && value.action_id === commandId && isUuid(String(value.task_id)) && value.accepted === true
    && value.execution_pending === true && digest(value.ingress_digest)
    && bounded(value.ledger_evidence_ref, 2_048)
    && String(value.ledger_evidence_ref).startsWith("urn:agenttrust:")
    && !/[\s?#]/.test(String(value.ledger_evidence_ref)) && digest(value.ledger_evidence_digest),
  "CONTROL_PACK_ACTION_RECEIPT_INVALID");
  return value as unknown as MarketplaceActionReceipt;
}

function exact(value: unknown, fields: string[]): value is Record<string, unknown> {
  return isRecord(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());
}
function digest(value: unknown): value is string { return typeof value === "string" && DIGEST.test(value); }
function bounded(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum && !/[\0\r\n]/.test(value);
}
function identifier(value: unknown, maximum: number): value is string {
  return bounded(value, maximum) && IDENTIFIER.test(value);
}
function strings(value: unknown, minimum: number, maximum: number,
  maximumLength: number): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum
    && value.every((item) => bounded(item, maximumLength)) && new Set(value).size === value.length;
}
function dateTime(value: unknown): value is string { return typeof value === "string" && !Number.isNaN(Date.parse(value)); }
function assert(condition: unknown, code = "CONTROL_PACK_AUTHORITY_RESPONSE_INVALID"): asserts condition {
  if (!condition) throw new Error(code);
}
