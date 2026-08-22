-- Production registry persistence must precede the final global FORCE RLS closure.
BEGIN;

ALTER TABLE tool_versions
  ADD COLUMN IF NOT EXISTS registry_revision bigint;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'tool_versions_active_revision_check'
      AND conrelid = 'tool_versions'::regclass
  ) THEN
    ALTER TABLE tool_versions
      ADD CONSTRAINT tool_versions_active_revision_check
      CHECK (
        (status IN ('ACTIVE','DEPRECATED','REVOKED') AND registry_revision > 0)
        OR
        (status NOT IN ('ACTIVE','DEPRECATED','REVOKED') AND registry_revision IS NULL)
      ) NOT VALID;
  END IF;
END
$$;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tool_versions
    WHERE (status IN ('ACTIVE','DEPRECATED','REVOKED')
           AND (registry_revision IS NULL OR registry_revision <= 0))
       OR (status NOT IN ('ACTIVE','DEPRECATED','REVOKED')
           AND registry_revision IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'REGISTRY_PUBLISHED_REVISION_BACKFILL_REQUIRED';
  END IF;
END
$$;
ALTER TABLE tool_versions VALIDATE CONSTRAINT tool_versions_active_revision_check;

ALTER TABLE registry_events
  ADD COLUMN IF NOT EXISTS idempotency_key text;
CREATE UNIQUE INDEX IF NOT EXISTS registry_events_tenant_idempotency
  ON registry_events(tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

ALTER TABLE registry_snapshots
  ADD COLUMN IF NOT EXISTS publisher_id text,
  ADD COLUMN IF NOT EXISTS key_id text,
  ADD COLUMN IF NOT EXISTS algorithm text,
  ADD COLUMN IF NOT EXISTS signed_at timestamptz;

CREATE TABLE IF NOT EXISTS registry_publisher_keys (
  tenant_id uuid NOT NULL,
  publisher_id text NOT NULL,
  key_id text NOT NULL,
  algorithm text NOT NULL CHECK (algorithm = 'Ed25519'),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_by text,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, publisher_id, key_id),
  UNIQUE (tenant_id, key_id),
  CHECK ((status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL)
      OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS registry_tenant_revisions (
  tenant_id uuid PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS registry_idempotency_records (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (
    length(idempotency_key) BETWEEN 1 AND 128
    AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  operation text NOT NULL CHECK (
    operation IN ('VALIDATE','SIGN','ACTIVATE','DEPRECATE','REVOKE')
  ),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  response_receipt jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key)
);

CREATE OR REPLACE FUNCTION enforce_tool_version_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status IN ('ACTIVE','DEPRECATED','REVOKED') AND (
    NEW.manifest IS DISTINCT FROM OLD.manifest OR NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash OR
    NEW.schema_hash IS DISTINCT FROM OLD.schema_hash OR NEW.implementation_digest IS DISTINCT FROM OLD.implementation_digest OR
    NEW.effect_class IS DISTINCT FROM OLD.effect_class OR NEW.risk_level IS DISTINCT FROM OLD.risk_level OR
    NEW.registry_revision IS DISTINCT FROM OLD.registry_revision OR NEW.activated_at IS DISTINCT FROM OLD.activated_at
  ) THEN RAISE EXCEPTION 'REGISTRY_ACTIVE_VERSION_IMMUTABLE'; END IF;
  IF OLD.status = 'ACTIVE' AND NEW.status NOT IN ('ACTIVE','DEPRECATED','REVOKED') THEN
    RAISE EXCEPTION 'REGISTRY_ACTIVE_LIFECYCLE_INVALID';
  END IF;
  IF OLD.status = 'DEPRECATED' AND NEW.status NOT IN ('DEPRECATED','REVOKED') THEN
    RAISE EXCEPTION 'REGISTRY_DEPRECATED_LIFECYCLE_INVALID';
  END IF;
  IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
    RAISE EXCEPTION 'REGISTRY_REVOKED_TERMINAL';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS tool_versions_immutable ON tool_versions;
CREATE TRIGGER tool_versions_immutable BEFORE UPDATE ON tool_versions
  FOR EACH ROW EXECUTE FUNCTION enforce_tool_version_lifecycle();

CREATE OR REPLACE FUNCTION reject_registry_immutable_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'REGISTRY_IMMUTABLE_RECORD';
END $$;
DROP TRIGGER IF EXISTS registry_snapshots_immutable ON registry_snapshots;
CREATE TRIGGER registry_snapshots_immutable BEFORE UPDATE OR DELETE ON registry_snapshots
  FOR EACH ROW EXECUTE FUNCTION reject_registry_immutable_change();
DROP TRIGGER IF EXISTS registry_events_immutable ON registry_events;
CREATE TRIGGER registry_events_immutable BEFORE UPDATE OR DELETE ON registry_events
  FOR EACH ROW EXECUTE FUNCTION reject_registry_immutable_change();
DROP TRIGGER IF EXISTS registry_idempotency_records_immutable ON registry_idempotency_records;
CREATE TRIGGER registry_idempotency_records_immutable
  BEFORE UPDATE OR DELETE ON registry_idempotency_records
  FOR EACH ROW EXECUTE FUNCTION reject_registry_immutable_change();

CREATE OR REPLACE FUNCTION enforce_registry_publisher_key_immutability() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
     NEW.publisher_id IS DISTINCT FROM OLD.publisher_id OR
     NEW.key_id IS DISTINCT FROM OLD.key_id OR
     NEW.algorithm IS DISTINCT FROM OLD.algorithm OR
     NEW.public_key IS DISTINCT FROM OLD.public_key OR
     NEW.created_by IS DISTINCT FROM OLD.created_by OR
     NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'REGISTRY_PUBLISHER_KEY_IMMUTABLE';
  END IF;
  IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
    RAISE EXCEPTION 'REGISTRY_PUBLISHER_KEY_REVOCATION_TERMINAL';
  END IF;
  IF OLD.status = 'ACTIVE' AND NEW.status = 'REVOKED' AND (
    EXISTS (
      SELECT 1 FROM tool_versions
       WHERE tenant_id = OLD.tenant_id AND status = 'ACTIVE'
         AND manifest #>> '{signature,publisher_id}' = OLD.publisher_id
         AND manifest #>> '{signature,key_id}' = OLD.key_id
    ) OR EXISTS (
      SELECT 1 FROM registry_snapshots AS snapshot
      JOIN registry_tenant_revisions AS revision
        ON revision.tenant_id = snapshot.tenant_id AND revision.revision = snapshot.revision
       WHERE snapshot.tenant_id = OLD.tenant_id
         AND snapshot.publisher_id = OLD.publisher_id
         AND snapshot.key_id = OLD.key_id
    )
  ) THEN
    RAISE EXCEPTION 'REGISTRY_PUBLISHER_KEY_IN_USE';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS registry_publisher_keys_immutable ON registry_publisher_keys;
CREATE TRIGGER registry_publisher_keys_immutable BEFORE UPDATE ON registry_publisher_keys
  FOR EACH ROW EXECUTE FUNCTION enforce_registry_publisher_key_immutability();

COMMIT;
