BEGIN;
CREATE TABLE IF NOT EXISTS industrial_asset_channels (
  tenant_id uuid NOT NULL, resource_key text NOT NULL, protocol text NOT NULL, configuration jsonb NOT NULL,
  configuration_hash char(64) NOT NULL, writable boolean NOT NULL, active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, resource_key)
);
CREATE TABLE IF NOT EXISTS industrial_commit_journal (
  tenant_id uuid NOT NULL, commit_id uuid NOT NULL, task_id uuid NOT NULL, action_hash char(64) NOT NULL,
  authorization_id uuid NOT NULL, resource_key text NOT NULL, before_state jsonb NOT NULL, requested_state jsonb NOT NULL,
  after_state jsonb, outcome text NOT NULL CHECK (outcome IN ('PREPARED','COMMITTED','VERIFIED','FAILED','SAFE_STOP')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, commit_id)
);
CREATE TABLE IF NOT EXISTS industrial_telemetry_buffer (
  tenant_id uuid NOT NULL, sample_id uuid NOT NULL, resource_key text NOT NULL, resource_version text NOT NULL,
  sampled_at timestamptz NOT NULL, quality text NOT NULL, value jsonb NOT NULL, PRIMARY KEY (tenant_id, sample_id)
);
CREATE INDEX IF NOT EXISTS industrial_telemetry_resource_idx ON industrial_telemetry_buffer (tenant_id, resource_key, sampled_at DESC);
COMMIT;
