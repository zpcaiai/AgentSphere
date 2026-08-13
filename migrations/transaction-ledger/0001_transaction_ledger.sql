BEGIN;
CREATE SEQUENCE IF NOT EXISTS execution_fence_seq AS bigint;
CREATE TABLE IF NOT EXISTS executions (
  execution_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  step_id uuid NOT NULL,
  action_hash char(64) NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  fence_token bigint NOT NULL,
  status text NOT NULL CHECK (status IN ('PREPARED','RUNNING','SUCCEEDED','FAILED','TIMED_OUT','CANCELLED','KILLED','COMPENSATING','COMPENSATED','COMPENSATION_FAILED','UNKNOWN')),
  intent jsonb NOT NULL,
  attempt integer NOT NULL DEFAULT 0,
  external_operation_id text,
  result_ref text,
  evidence_ref text,
  last_error_code text,
  manual_recovery jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS executions_recovery_idx ON executions(status, updated_at) WHERE status IN ('RUNNING','UNKNOWN');
CREATE TABLE IF NOT EXISTS execution_attempts (execution_id uuid NOT NULL REFERENCES executions(execution_id), attempt integer NOT NULL, fence_token bigint NOT NULL, started_at timestamptz NOT NULL, finished_at timestamptz, outcome text, PRIMARY KEY(execution_id, attempt));
CREATE TABLE IF NOT EXISTS idempotency_records (tenant_id uuid NOT NULL, idempotency_key text NOT NULL, action_hash char(64) NOT NULL, execution_id uuid NOT NULL REFERENCES executions(execution_id), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id, idempotency_key));
CREATE TABLE IF NOT EXISTS compensation_plans (plan_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, forward_execution_id uuid NOT NULL REFERENCES executions(execution_id), plan jsonb NOT NULL, status text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS resource_versions (tenant_id uuid NOT NULL, resource_key text NOT NULL, resource_version text NOT NULL, observed_at timestamptz NOT NULL, PRIMARY KEY(tenant_id, resource_key));
CREATE TABLE IF NOT EXISTS execution_outbox (event_id uuid PRIMARY KEY, execution_id uuid NOT NULL REFERENCES executions(execution_id), event_type text NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz);
CREATE TABLE IF NOT EXISTS execution_inbox (consumer_id text NOT NULL, message_id text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(consumer_id, message_id));
COMMIT;
