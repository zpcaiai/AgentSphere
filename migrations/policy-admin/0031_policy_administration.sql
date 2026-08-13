BEGIN;
CREATE TABLE IF NOT EXISTS policy_bundles (
  tenant_id uuid NOT NULL, bundle_id text NOT NULL, version text NOT NULL, source_digest char(64) NOT NULL,
  compiled_digest char(64) NOT NULL, static_analysis jsonb NOT NULL, key_id text NOT NULL, signature bytea NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT','REVIEW','CANARY','ACTIVE','ROLLED_BACK','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, bundle_id, version)
);
CREATE TABLE IF NOT EXISTS policy_exceptions (
  tenant_id uuid NOT NULL, exception_id uuid NOT NULL, scope_digest char(64) NOT NULL, owner_subject text NOT NULL,
  approver_subjects jsonb NOT NULL, reason text NOT NULL, compensating_controls jsonb NOT NULL,
  expires_at timestamptz NOT NULL, revoked_at timestamptz, PRIMARY KEY (tenant_id, exception_id)
);
COMMIT;
