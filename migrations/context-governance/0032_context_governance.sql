BEGIN;
CREATE TABLE IF NOT EXISTS governed_memory_entries (
  tenant_id uuid NOT NULL, memory_id uuid NOT NULL, subject_id text NOT NULL, owner_subject text NOT NULL,
  action_digest char(64) NOT NULL, policy_digest char(64) NOT NULL, content_digest char(64) NOT NULL,
  object_ref text NOT NULL, status text NOT NULL CHECK (status IN ('ACTIVE','QUARANTINED','TOMBSTONED','HELD')),
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, memory_id)
);
CREATE TABLE IF NOT EXISTS prompt_versions (
  tenant_id uuid NOT NULL, prompt_id text NOT NULL, version text NOT NULL, content_digest char(64) NOT NULL,
  provenance_digest char(64) NOT NULL, signature bytea NOT NULL, status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, prompt_id, version)
);
CREATE TABLE IF NOT EXISTS knowledge_snapshots (
  tenant_id uuid NOT NULL, source_id text NOT NULL, snapshot_id text NOT NULL, snapshot_digest char(64) NOT NULL,
  trust_level text NOT NULL, object_ref text NOT NULL, expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, source_id, snapshot_id)
);
COMMIT;
