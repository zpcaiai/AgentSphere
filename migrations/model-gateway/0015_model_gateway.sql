BEGIN;
CREATE TABLE IF NOT EXISTS model_provider_versions (
  provider_id text NOT NULL, model_id text NOT NULL, model_version text NOT NULL, manifest jsonb NOT NULL,
  manifest_hash char(64) NOT NULL, approved boolean NOT NULL DEFAULT false, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (provider_id, model_id, model_version)
);
CREATE TABLE IF NOT EXISTS model_budget_reservations (
  reservation_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, task_id uuid NOT NULL, idempotency_key text NOT NULL,
  reserved_microunits bigint NOT NULL CHECK (reserved_microunits > 0), actual_microunits bigint,
  status text NOT NULL CHECK (status IN ('RESERVED','FINALIZED','OVERRUN','RELEASED')),
  created_at timestamptz NOT NULL DEFAULT now(), finalized_at timestamptz, UNIQUE (tenant_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS model_request_evidence (
  request_hash char(64) PRIMARY KEY, tenant_id uuid NOT NULL, task_id uuid NOT NULL, provider_id text NOT NULL,
  model_id text NOT NULL, model_version text NOT NULL, route_reasons jsonb NOT NULL, output_hash char(64),
  input_tokens bigint, output_tokens bigint, cost_microunits bigint, created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
