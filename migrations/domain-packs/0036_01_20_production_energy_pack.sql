BEGIN;
DO $migration$ BEGIN
  IF to_regclass('public.energy_candidate_plans') IS NOT NULL AND to_regclass('public.energy_candidate_plans_legacy_0025') IS NULL THEN
    ALTER TABLE public.energy_candidate_plans RENAME TO energy_candidate_plans_legacy_0025;
  END IF;
END $migration$;
REVOKE ALL ON TABLE public.energy_candidate_plans_legacy_0025 FROM PUBLIC;

CREATE TABLE IF NOT EXISTS public.energy_assets (
  tenant_id uuid NOT NULL, asset_id uuid NOT NULL, asset_key varchar(512) NOT NULL,
  asset_type varchar(24) NOT NULL CHECK (asset_type IN ('BATTERY','INVERTER','LOAD','PV','GRID_POINT','DATA_CENTER')),
  control_endpoint_manifest_digest char(64) NOT NULL CHECK (control_endpoint_manifest_digest ~ '^[0-9a-f]{64}$'),
  voltage_min double precision NOT NULL, voltage_max double precision NOT NULL CHECK (voltage_max>voltage_min),
  frequency_min double precision NOT NULL, frequency_max double precision NOT NULL CHECK (frequency_max>frequency_min),
  soc_min double precision NOT NULL CHECK (soc_min>=0), soc_max double precision NOT NULL CHECK (soc_max<=1 AND soc_max>soc_min),
  power_min_kw double precision NOT NULL, power_max_kw double precision NOT NULL CHECK (power_max_kw>power_min_kw),
  thermal_max_c double precision NOT NULL, ramp_max_kw_per_second double precision NOT NULL CHECK (ramp_max_kw_per_second>0),
  deterministic_fallback_ref varchar(1024) NOT NULL, fallback_digest char(64) NOT NULL CHECK (fallback_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version>0), status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','PAUSED','ISOLATED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,asset_id), UNIQUE (tenant_id,asset_key)
);
CREATE TABLE IF NOT EXISTS public.energy_forecast_snapshots (
  tenant_id uuid NOT NULL, forecast_id uuid NOT NULL, asset_id uuid NOT NULL,
  model_manifest_digest char(64) NOT NULL CHECK (model_manifest_digest ~ '^[0-9a-f]{64}$'),
  training_data_summary_digest char(64) NOT NULL CHECK (training_data_summary_digest ~ '^[0-9a-f]{64}$'),
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'), output_artifact_ref varchar(1024) NOT NULL,
  output_digest char(64) NOT NULL CHECK (output_digest ~ '^[0-9a-f]{64}$'), confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  out_of_distribution boolean NOT NULL, observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL CHECK (valid_until>observed_at),
  PRIMARY KEY (tenant_id,forecast_id), FOREIGN KEY (tenant_id,asset_id) REFERENCES public.energy_assets(tenant_id,asset_id)
);
CREATE TABLE IF NOT EXISTS public.energy_dispatch_cases (
  tenant_id uuid NOT NULL, execution_id uuid NOT NULL, asset_id uuid NOT NULL, forecast_id uuid NOT NULL,
  stage varchar(24) NOT NULL CHECK (stage IN ('SIMULATOR','DIGITAL_TWIN','READ_ONLY','SHADOW','LIMITED_WRITE')),
  algorithm_type varchar(16) NOT NULL CHECK (algorithm_type IN ('MPC','RL','CBF','RULE')),
  algorithm_manifest_digest char(64) NOT NULL CHECK (algorithm_manifest_digest ~ '^[0-9a-f]{64}$'),
  solver_status varchar(24) NOT NULL CHECK (solver_status IN ('OPTIMAL','FEASIBLE','INFEASIBLE','TIMEOUT','ERROR')),
  before_digest char(64) NOT NULL CHECK (before_digest ~ '^[0-9a-f]{64}$'), plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
  constraint_digest char(64) NOT NULL CHECK (constraint_digest ~ '^[0-9a-f]{64}$'), observed_resource_version bigint NOT NULL CHECK (observed_resource_version>0),
  hard_constraint_valid boolean NOT NULL, communication_age_ms bigint NOT NULL CHECK (communication_age_ms>=0),
  approval_set_id uuid, supervision_id uuid, dispatch_state varchar(24) NOT NULL CHECK (dispatch_state IN ('PREPARED','DISPATCHED','FALLBACK_ACTIVE','MANUAL_RECOVERY','REJECTED','UNKNOWN')),
  dispatch_receipt_digest char(64), fallback_receipt_digest char(64), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,execution_id), FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  FOREIGN KEY (tenant_id,asset_id) REFERENCES public.energy_assets(tenant_id,asset_id), FOREIGN KEY (tenant_id,forecast_id) REFERENCES public.energy_forecast_snapshots(tenant_id,forecast_id),
  FOREIGN KEY (tenant_id,supervision_id) REFERENCES public.domain_physical_supervision(tenant_id,supervision_id),
  CHECK (hard_constraint_valid OR dispatch_state IN ('FALLBACK_ACTIVE','REJECTED')),
  CHECK ((stage='LIMITED_WRITE' AND approval_set_id IS NOT NULL AND supervision_id IS NOT NULL) OR (stage<>'LIMITED_WRITE' AND supervision_id IS NULL)),
  CHECK (dispatch_state<>'DISPATCHED' OR dispatch_receipt_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS public.energy_outcomes (
  tenant_id uuid NOT NULL, outcome_id uuid NOT NULL, execution_id uuid NOT NULL,
  telemetry_digest char(64) NOT NULL CHECK (telemetry_digest ~ '^[0-9a-f]{64}$'), hard_violation_count integer NOT NULL CHECK (hard_violation_count>=0),
  stability_score double precision NOT NULL, economic_delta_microunits bigint NOT NULL, peak_delta_kw double precision NOT NULL,
  soc_lifetime_delta double precision NOT NULL, business_constraint_score double precision NOT NULL,
  confidence_interval_low double precision NOT NULL, confidence_interval_high double precision NOT NULL CHECK (confidence_interval_high>=confidence_interval_low),
  fallback_activated boolean NOT NULL, conclusion varchar(24) NOT NULL CHECK (conclusion IN ('PASS','FAIL','NEEDS_HUMAN','MANUAL_RECOVERY')),
  evaluator_digest char(64) NOT NULL CHECK (evaluator_digest ~ '^[0-9a-f]{64}$'), observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,outcome_id), UNIQUE (tenant_id,execution_id), FOREIGN KEY (tenant_id,execution_id) REFERENCES public.energy_dispatch_cases(tenant_id,execution_id),
  CHECK (conclusion<>'PASS' OR hard_violation_count=0)
);
CREATE TABLE IF NOT EXISTS public.energy_fallback_drills (
  tenant_id uuid NOT NULL, drill_id uuid NOT NULL, asset_id uuid NOT NULL,
  fallback_digest char(64) NOT NULL CHECK (fallback_digest ~ '^[0-9a-f]{64}$'), scenario_digest char(64) NOT NULL CHECK (scenario_digest ~ '^[0-9a-f]{64}$'),
  execution_receipt_digest char(64) NOT NULL CHECK (execution_receipt_digest ~ '^[0-9a-f]{64}$'), conclusion varchar(16) NOT NULL CHECK (conclusion IN ('PASS','FAIL','INCONCLUSIVE')),
  completed_at timestamptz NOT NULL, PRIMARY KEY (tenant_id,drill_id), FOREIGN KEY (tenant_id,asset_id) REFERENCES public.energy_assets(tenant_id,asset_id)
);

CREATE OR REPLACE FUNCTION public.agenttrust_energy_supervision_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$ DECLARE approval_count integer; supervision record; execution record;
BEGIN
  IF NEW.stage<>'LIMITED_WRITE' THEN RETURN NEW; END IF;
  SELECT * INTO supervision FROM public.domain_physical_supervision WHERE tenant_id=NEW.tenant_id AND supervision_id=NEW.supervision_id FOR UPDATE;
  IF NOT FOUND OR supervision.domain<>'ENERGY' OR supervision.stage<>'LIMITED_WRITE' OR supervision.expires_at<=now()
     OR (supervision.consumed_at IS NOT NULL AND supervision.consumed_by_execution_id<>NEW.execution_id) OR supervision.before_digest<>NEW.before_digest
     OR supervision.target_digest<>NEW.plan_digest OR supervision.resource_version<>NEW.observed_resource_version
     OR supervision.approval_set_id<>NEW.approval_set_id THEN RAISE EXCEPTION 'ENERGY_SUPERVISION_INVALID'; END IF;
  SELECT domain,resource_key,resource_version,canonical_action,state INTO execution
    FROM public.domain_pack_executions
   WHERE tenant_id=NEW.tenant_id AND execution_id=NEW.execution_id FOR KEY SHARE;
  IF NOT FOUND OR execution.domain<>'ENERGY' OR execution.resource_key<>supervision.resource_key
     OR execution.resource_version<>NEW.observed_resource_version OR execution.state NOT IN ('PREPARED','EXECUTING') THEN
    RAISE EXCEPTION 'ENERGY_EXECUTION_BINDING_INVALID';
  END IF;
  SELECT count(DISTINCT reviewer_subject) INTO approval_count FROM public.domain_expert_approvals
   WHERE tenant_id=NEW.tenant_id AND approval_set_id=NEW.approval_set_id AND domain='ENERGY'
     AND decision='APPROVED' AND expires_at>now() AND before_digest=NEW.before_digest
     AND target_digest=NEW.plan_digest AND resource_version=NEW.observed_resource_version
     AND resource_key=supervision.resource_key
     AND operation=execution.canonical_action #>> '{intent,operation}'
     AND reviewer_subject<>supervision.supervisor_subject;
  IF approval_count<2 THEN RAISE EXCEPTION 'ENERGY_DUAL_APPROVAL_REQUIRED'; END IF;
  IF supervision.consumed_at IS NULL THEN
    UPDATE public.domain_physical_supervision SET consumed_by_execution_id=NEW.execution_id,consumed_at=now()
     WHERE tenant_id=NEW.tenant_id AND supervision_id=NEW.supervision_id;
  END IF;
  RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS energy_supervision_guard ON public.energy_dispatch_cases;
CREATE TRIGGER energy_supervision_guard BEFORE INSERT ON public.energy_dispatch_cases FOR EACH ROW EXECUTE FUNCTION public.agenttrust_energy_supervision_guard();
DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['energy_assets','energy_forecast_snapshots','energy_dispatch_cases','energy_outcomes','energy_fallback_drills'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('DROP POLICY IF EXISTS energy_tenant_isolation ON public.%I',table_name);
    EXECUTE format('CREATE POLICY energy_tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',table_name); EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',table_name);
  END LOOP;
END $rls$;
DROP TRIGGER IF EXISTS energy_forecast_immutable ON public.energy_forecast_snapshots;
CREATE TRIGGER energy_forecast_immutable BEFORE UPDATE OR DELETE ON public.energy_forecast_snapshots FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
DROP TRIGGER IF EXISTS energy_outcome_immutable ON public.energy_outcomes;
CREATE TRIGGER energy_outcome_immutable BEFORE UPDATE OR DELETE ON public.energy_outcomes FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
DROP TRIGGER IF EXISTS energy_fallback_drill_immutable ON public.energy_fallback_drills;
CREATE TRIGGER energy_fallback_drill_immutable BEFORE UPDATE OR DELETE ON public.energy_fallback_drills FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE INDEX IF NOT EXISTS energy_dispatch_state_idx ON public.energy_dispatch_cases(tenant_id,stage,dispatch_state,updated_at);
REVOKE ALL ON FUNCTION public.agenttrust_energy_supervision_guard() FROM PUBLIC;
COMMIT;
