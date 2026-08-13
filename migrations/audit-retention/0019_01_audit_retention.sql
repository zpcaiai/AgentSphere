BEGIN;
CREATE TABLE IF NOT EXISTS audit_chain_heads (
  tenant_id uuid NOT NULL, stream_id text NOT NULL, last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
  chain_hash char(64) NOT NULL, key_id text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, stream_id)
);
CREATE TABLE IF NOT EXISTS audit_retention_policies (
  tenant_id uuid NOT NULL, policy_id text NOT NULL, policy_version text NOT NULL,
  retention_seconds bigint NOT NULL CHECK (retention_seconds > 0), policy_digest char(64) NOT NULL,
  effective_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, policy_id, policy_version)
);
CREATE TABLE IF NOT EXISTS legal_holds (
  tenant_id uuid NOT NULL, hold_id uuid NOT NULL, object_ref text NOT NULL, reason text NOT NULL,
  placed_by text NOT NULL, released_by text, placed_at timestamptz NOT NULL DEFAULT now(), released_at timestamptz,
  CHECK (released_at IS NULL OR released_by IS NOT NULL), PRIMARY KEY (tenant_id, hold_id)
);
CREATE TABLE IF NOT EXISTS audit_export_manifests (
  tenant_id uuid NOT NULL, export_id uuid NOT NULL, manifest_digest char(64) NOT NULL,
  chain_head char(64) NOT NULL, object_ref text NOT NULL, key_id text NOT NULL, signature bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, export_id)
);
CREATE INDEX IF NOT EXISTS legal_holds_object_idx ON legal_holds (tenant_id, object_ref) WHERE released_at IS NULL;
COMMIT;
