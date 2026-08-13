BEGIN;
CREATE TABLE IF NOT EXISTS coding_pack_runs (
  tenant_id uuid NOT NULL, run_id uuid NOT NULL, repository_ref text NOT NULL, base_commit char(40) NOT NULL,
  branch_name text NOT NULL, allowed_paths jsonb NOT NULL, command_allowlist jsonb NOT NULL,
  diff_digest char(64), test_evidence_ref text, rollback_ref text, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, run_id)
);
COMMIT;
