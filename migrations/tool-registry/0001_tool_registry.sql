BEGIN;
CREATE TABLE IF NOT EXISTS tools (tenant_id uuid NOT NULL, tool_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id, tool_id));
CREATE TABLE IF NOT EXISTS executor_profiles (tenant_id uuid NOT NULL, profile_id text NOT NULL, definition jsonb NOT NULL, definition_hash char(64) NOT NULL, PRIMARY KEY(tenant_id, profile_id));
CREATE TABLE IF NOT EXISTS credential_profiles (tenant_id uuid NOT NULL, profile_id text NOT NULL, definition jsonb NOT NULL, PRIMARY KEY(tenant_id, profile_id));
CREATE TABLE IF NOT EXISTS approval_profiles (tenant_id uuid NOT NULL, profile_id text NOT NULL, definition jsonb NOT NULL, PRIMARY KEY(tenant_id, profile_id));
CREATE TABLE IF NOT EXISTS tool_versions (
  tenant_id uuid NOT NULL,
  tool_id text NOT NULL,
  tool_version text NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT','VALIDATED','SIGNED','ACTIVE','DEPRECATED','REVOKED')),
  manifest jsonb NOT NULL,
  manifest_hash char(64) NOT NULL,
  schema_hash char(64),
  implementation_digest text,
  effect_class text CHECK (effect_class IN ('PURE','IDEMPOTENT','COMPENSATABLE','IRREVERSIBLE')),
  risk_level text CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  revoked_at timestamptz,
  PRIMARY KEY(tenant_id, tool_id, tool_version),
  FOREIGN KEY(tenant_id, tool_id) REFERENCES tools(tenant_id, tool_id)
);
CREATE TABLE IF NOT EXISTS compensation_bindings (
  tenant_id uuid NOT NULL, tool_id text NOT NULL, tool_version text NOT NULL,
  compensation_tool_id text NOT NULL, compensation_tool_version text NOT NULL, precondition_kind text NOT NULL,
  PRIMARY KEY(tenant_id, tool_id, tool_version),
  FOREIGN KEY(tenant_id, tool_id, tool_version) REFERENCES tool_versions(tenant_id, tool_id, tool_version),
  FOREIGN KEY(tenant_id, compensation_tool_id, compensation_tool_version) REFERENCES tool_versions(tenant_id, tool_id, tool_version)
);
CREATE TABLE IF NOT EXISTS tool_signatures (tenant_id uuid NOT NULL, tool_id text NOT NULL, tool_version text NOT NULL, publisher_id text NOT NULL, key_id text NOT NULL, algorithm text NOT NULL, signature bytea NOT NULL, PRIMARY KEY(tenant_id, tool_id, tool_version, key_id));
CREATE TABLE IF NOT EXISTS capabilities (tenant_id uuid NOT NULL, capability_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id, capability_id));
CREATE TABLE IF NOT EXISTS capability_versions (tenant_id uuid NOT NULL, capability_id text NOT NULL, capability_version text NOT NULL, status text NOT NULL, manifest jsonb NOT NULL, manifest_hash char(64) NOT NULL, PRIMARY KEY(tenant_id, capability_id, capability_version));
CREATE TABLE IF NOT EXISTS capability_tools (tenant_id uuid NOT NULL, capability_id text NOT NULL, capability_version text NOT NULL, tool_id text NOT NULL, tool_version text NOT NULL, required boolean NOT NULL, PRIMARY KEY(tenant_id, capability_id, capability_version, tool_id, tool_version));
CREATE TABLE IF NOT EXISTS registry_events (event_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, tool_id text, tool_version text, event_type text NOT NULL, actor_subject text NOT NULL, event_payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS registry_snapshots (tenant_id uuid NOT NULL, revision bigint NOT NULL, snapshot jsonb NOT NULL, snapshot_hash char(64) NOT NULL, signature bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id, revision));

CREATE OR REPLACE FUNCTION prevent_active_tool_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status IN ('ACTIVE','DEPRECATED','REVOKED') AND (
    NEW.manifest IS DISTINCT FROM OLD.manifest OR NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash OR
    NEW.schema_hash IS DISTINCT FROM OLD.schema_hash OR NEW.implementation_digest IS DISTINCT FROM OLD.implementation_digest OR
    NEW.effect_class IS DISTINCT FROM OLD.effect_class OR NEW.risk_level IS DISTINCT FROM OLD.risk_level
  ) THEN RAISE EXCEPTION 'REGISTRY_ACTIVE_VERSION_IMMUTABLE'; END IF;
  IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN RAISE EXCEPTION 'REGISTRY_REVOKED_TERMINAL'; END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS tool_versions_immutable ON tool_versions;
CREATE TRIGGER tool_versions_immutable BEFORE UPDATE ON tool_versions FOR EACH ROW EXECUTE FUNCTION prevent_active_tool_mutation();
COMMIT;

