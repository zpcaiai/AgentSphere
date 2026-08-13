BEGIN;
CREATE TABLE IF NOT EXISTS delegation_tokens (
  tenant_id uuid NOT NULL, token_id uuid NOT NULL, root_task_id uuid NOT NULL, parent_task_id uuid NOT NULL,
  parent_token_id uuid, token_hash char(64) NOT NULL, depth integer NOT NULL CHECK (depth > 0),
  remaining_calls integer NOT NULL CHECK (remaining_calls >= 0), expires_at timestamptz NOT NULL,
  revocation_epoch bigint NOT NULL, revoked_at timestamptz, PRIMARY KEY (tenant_id, token_id)
);
CREATE TABLE IF NOT EXISTS agui_events (
  tenant_id uuid NOT NULL, task_id uuid NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0), event_id uuid NOT NULL,
  event_kind text NOT NULL, safe_payload jsonb NOT NULL, signature bytea NOT NULL, trace_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, task_id, sequence), UNIQUE (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS delegation_root_task_idx ON delegation_tokens (tenant_id, root_task_id) WHERE revoked_at IS NULL;
COMMIT;
