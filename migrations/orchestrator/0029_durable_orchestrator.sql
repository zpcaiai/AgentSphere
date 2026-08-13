BEGIN;
CREATE TABLE IF NOT EXISTS orchestrator_tasks (
  tenant_id uuid NOT NULL, task_id uuid NOT NULL, goal_digest char(64) NOT NULL, plan_digest char(64) NOT NULL,
  status text NOT NULL, state_version bigint NOT NULL CHECK (state_version >= 0), active_lease_id uuid,
  command_cursor bigint NOT NULL DEFAULT 0 CHECK (command_cursor >= 0), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS orchestrator_steps (
  tenant_id uuid NOT NULL, task_id uuid NOT NULL, step_id text NOT NULL, ordinal integer NOT NULL CHECK (ordinal >= 0),
  status text NOT NULL, effect_status text NOT NULL, evaluator_status text NOT NULL, evidence_ref text,
  state_version bigint NOT NULL CHECK (state_version >= 0), PRIMARY KEY (tenant_id, task_id, step_id),
  UNIQUE (tenant_id, task_id, ordinal)
);
CREATE TABLE IF NOT EXISTS orchestrator_commands (
  tenant_id uuid NOT NULL, task_id uuid NOT NULL, command_id uuid NOT NULL, command_type text NOT NULL,
  expected_state_version bigint NOT NULL, result jsonb, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id, command_id)
);
CREATE INDEX IF NOT EXISTS orchestrator_tasks_status_idx ON orchestrator_tasks (tenant_id, status, updated_at);
COMMIT;
