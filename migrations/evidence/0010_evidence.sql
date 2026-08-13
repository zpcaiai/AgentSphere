BEGIN;
CREATE TABLE IF NOT EXISTS audit_events (
  tenant_id uuid NOT NULL, task_id uuid NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),
  event_id uuid NOT NULL UNIQUE, previous_hash char(64) NOT NULL, event_hash char(64) NOT NULL,
  key_id text NOT NULL, signature bytea NOT NULL, event_type text NOT NULL, safe_payload jsonb NOT NULL,
  occurred_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, task_id, sequence), UNIQUE (tenant_id, task_id, event_hash)
);
CREATE TABLE IF NOT EXISTS evidence_artifacts (
  tenant_id uuid NOT NULL, artifact_hash char(64) NOT NULL, media_type text NOT NULL,
  classification text NOT NULL, retention_until timestamptz NOT NULL, access_policy text NOT NULL,
  object_ref text NOT NULL, byte_length bigint NOT NULL CHECK (byte_length > 0), created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, artifact_hash)
);
CREATE TABLE IF NOT EXISTS evidence_packages (
  tenant_id uuid NOT NULL, package_id uuid NOT NULL, task_id uuid NOT NULL, package_hash char(64) NOT NULL,
  manifest jsonb NOT NULL, built_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, package_id), UNIQUE (tenant_id, task_id, package_hash)
);
CREATE TABLE IF NOT EXISTS evaluation_results (
  tenant_id uuid NOT NULL, evaluation_id uuid NOT NULL, task_id uuid NOT NULL, evaluator_id text NOT NULL,
  evaluator_version text NOT NULL, input_hash char(64) NOT NULL, status text NOT NULL CHECK (status IN ('PASS','FAIL','NEEDS_HUMAN')),
  result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, evaluation_id)
);
CREATE INDEX IF NOT EXISTS audit_events_task_idx ON audit_events (tenant_id, task_id, sequence);
COMMIT;
