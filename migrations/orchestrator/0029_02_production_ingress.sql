BEGIN;
CREATE TABLE IF NOT EXISTS orchestrator_ingress_actions (
  tenant_id uuid NOT NULL, action_id uuid NOT NULL, task_id uuid NOT NULL,
  owner_subject text NOT NULL CHECK (owner_subject <> ''), status text NOT NULL,
  payload_hash char(64) NOT NULL, idempotency_key text NOT NULL, envelope jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, action_id), UNIQUE (tenant_id, task_id), UNIQUE (tenant_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS orchestrator_stream_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY, tenant_id uuid NOT NULL, task_id uuid NOT NULL,
  event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (sequence)
);
CREATE INDEX IF NOT EXISTS orchestrator_stream_task_idx
  ON orchestrator_stream_events (tenant_id, task_id, sequence);
ALTER TABLE orchestrator_ingress_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestrator_ingress_actions FORCE ROW LEVEL SECURITY;
ALTER TABLE orchestrator_stream_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE orchestrator_stream_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS orchestrator_ingress_tenant ON orchestrator_ingress_actions;
CREATE POLICY orchestrator_ingress_tenant ON orchestrator_ingress_actions
  USING (tenant_id::text = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS orchestrator_stream_tenant ON orchestrator_stream_events;
CREATE POLICY orchestrator_stream_tenant ON orchestrator_stream_events
  USING (tenant_id::text = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
COMMIT;
