BEGIN;
CREATE TABLE IF NOT EXISTS supply_chain_artifacts (
  tenant_id uuid NOT NULL, artifact_digest char(64) NOT NULL, artifact_type text NOT NULL,
  sbom_digest char(64) NOT NULL, provenance_digest char(64) NOT NULL, publisher_id text NOT NULL,
  signature bytea NOT NULL, vulnerability_summary jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, artifact_digest)
);
CREATE TABLE IF NOT EXISTS domain_pack_versions (
  tenant_id uuid NOT NULL, pack_id text NOT NULL, version text NOT NULL, manifest jsonb NOT NULL,
  manifest_digest char(64) NOT NULL, status text NOT NULL CHECK (status IN ('PUBLISHED','APPROVED','ACTIVE','REVOKED')),
  permission_digest char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, pack_id, version)
);
CREATE TABLE IF NOT EXISTS publisher_revocations (
  publisher_id text NOT NULL, key_id text NOT NULL, reason text NOT NULL, revoked_at timestamptz NOT NULL,
  PRIMARY KEY (publisher_id, key_id)
);
COMMIT;
