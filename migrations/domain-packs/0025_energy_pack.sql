BEGIN;
CREATE TABLE IF NOT EXISTS energy_candidate_plans (
  tenant_id uuid NOT NULL, plan_id uuid NOT NULL, asset_id text NOT NULL, algorithm_version text NOT NULL,
  constraint_digest char(64) NOT NULL, forecast_digest char(64) NOT NULL, candidate jsonb NOT NULL,
  confidence numeric(6,5) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  out_of_distribution boolean NOT NULL, shadow_only boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, plan_id)
);
COMMIT;
