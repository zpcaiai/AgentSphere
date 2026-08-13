BEGIN;
CREATE TABLE IF NOT EXISTS backup_manifests (
  backup_id uuid PRIMARY KEY, scope_digest char(64) NOT NULL, database_lsn text NOT NULL,
  object_manifest_digest char(64) NOT NULL, ledger_head_digest char(64) NOT NULL,
  key_id text NOT NULL, signature bytea NOT NULL, created_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_drills (
  drill_id uuid PRIMARY KEY, backup_id uuid NOT NULL, isolated_environment_ref text NOT NULL,
  expected_records bigint NOT NULL, restored_records bigint NOT NULL, object_integrity_passed boolean NOT NULL,
  ledger_reconciled boolean NOT NULL, measured_rto_seconds bigint NOT NULL, measured_rpo_seconds bigint NOT NULL,
  report_digest char(64) NOT NULL, completed_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS deployment_rollouts (
  rollout_id uuid PRIMARY KEY, release_digest char(64) NOT NULL, schema_compatible boolean NOT NULL,
  canary_percent integer NOT NULL CHECK (canary_percent BETWEEN 0 AND 100), rollback_digest char(64) NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','CANARY','PROMOTED','ROLLED_BACK','FAILED')),
  updated_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
