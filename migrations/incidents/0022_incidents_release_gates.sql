BEGIN;
CREATE TABLE IF NOT EXISTS incidents (
  tenant_id uuid NOT NULL, incident_id uuid NOT NULL, correlation_key text NOT NULL, severity text NOT NULL,
  status text NOT NULL CHECK (status IN ('OPEN','CONTAINED','INVESTIGATING','REMEDIATED','CLOSED')),
  task_id uuid, owner text, safe_summary text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, incident_id),
  UNIQUE (tenant_id, correlation_key)
);
CREATE TABLE IF NOT EXISTS replay_runs (
  tenant_id uuid NOT NULL, replay_id uuid NOT NULL, incident_id uuid NOT NULL, mode text NOT NULL
    CHECK (mode IN ('LOGICAL','SANDBOX','LIVE')),
  input_digest char(64) NOT NULL, fresh_lease_id uuid, approval_id uuid, effect_count bigint NOT NULL DEFAULT 0,
  evidence_ref text, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, replay_id)
);
CREATE TABLE IF NOT EXISTS release_gate_results (
  tenant_id uuid NOT NULL, release_id text NOT NULL, gate_id text NOT NULL, passed boolean NOT NULL,
  evidence_digest char(64) NOT NULL, environment_ref text, evaluated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, release_id, gate_id)
);
COMMIT;
