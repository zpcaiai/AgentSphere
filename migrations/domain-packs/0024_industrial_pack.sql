BEGIN;
CREATE TABLE IF NOT EXISTS industrial_pack_actions (
  tenant_id uuid NOT NULL, action_id uuid NOT NULL, asset_id text NOT NULL, point_id text NOT NULL,
  stage text NOT NULL CHECK (stage IN ('SIMULATOR','DIGITAL_TWIN','READ_ONLY','SHADOW','SUPERVISED_WRITE')),
  expected_version text NOT NULL, prepared_digest char(64) NOT NULL, committed_at timestamptz,
  physical_outcome text CHECK (physical_outcome IN ('PENDING','CONVERGED','FAILED','SAFE_STOPPED')),
  PRIMARY KEY (tenant_id, action_id)
);
COMMIT;
