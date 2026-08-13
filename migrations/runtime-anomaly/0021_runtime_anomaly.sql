BEGIN;
CREATE TABLE IF NOT EXISTS risk_signals (
  tenant_id uuid NOT NULL, signal_id uuid NOT NULL, task_id uuid NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),
  detector_id text NOT NULL, detector_version text NOT NULL, score numeric(6,5) NOT NULL CHECK (score >= 0 AND score <= 1),
  reason_codes jsonb NOT NULL, feature_digest char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, signal_id), UNIQUE (tenant_id, task_id, sequence, detector_id)
);
CREATE TABLE IF NOT EXISTS continuous_authorization_commands (
  tenant_id uuid NOT NULL, command_id uuid NOT NULL, task_id uuid NOT NULL, action text NOT NULL
    CHECK (action IN ('NARROW_LEASE','PAUSE_NEW_TOOLS','REVOKE_CREDENTIAL','KILL')),
  reason_digest char(64) NOT NULL, key_id text NOT NULL, signature bytea NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(), applied_at timestamptz, PRIMARY KEY (tenant_id, command_id)
);
CREATE INDEX IF NOT EXISTS risk_signals_task_idx ON risk_signals (tenant_id, task_id, sequence);
COMMIT;
