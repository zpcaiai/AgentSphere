BEGIN;
DO $migration$ BEGIN
  IF to_regclass('public.industrial_pack_actions') IS NOT NULL AND to_regclass('public.industrial_pack_actions_legacy_0024') IS NULL THEN
    ALTER TABLE public.industrial_pack_actions RENAME TO industrial_pack_actions_legacy_0024;
  END IF;
END $migration$;
REVOKE ALL ON TABLE public.industrial_pack_actions_legacy_0024 FROM PUBLIC;

CREATE TABLE public.industrial_asset_models (
  tenant_id uuid NOT NULL, asset_id uuid NOT NULL, site_id varchar(256) NOT NULL,
  line_id varchar(256) NOT NULL, asset_key varchar(512) NOT NULL, protocol varchar(16) NOT NULL CHECK (protocol IN ('OPC_UA','MQTT','MODBUS')),
  endpoint_manifest_digest char(64) NOT NULL CHECK (endpoint_manifest_digest ~ '^[0-9a-f]{64}$'),
  criticality varchar(16) NOT NULL CHECK (criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  agent_control_prohibited boolean NOT NULL, resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version>0),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','MAINTENANCE','ISOLATED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,asset_id), UNIQUE (tenant_id,asset_key)
);
CREATE TABLE public.industrial_point_policies (
  tenant_id uuid NOT NULL, asset_id uuid NOT NULL, point_id varchar(512) NOT NULL,
  engineering_unit varchar(64) NOT NULL, minimum_value double precision NOT NULL,
  maximum_value double precision NOT NULL CHECK (maximum_value>minimum_value),
  maximum_rate_per_second double precision NOT NULL CHECK (maximum_rate_per_second>0),
  maximum_state_age_ms bigint NOT NULL CHECK (maximum_state_age_ms BETWEEN 1 AND 300000),
  allowed_modes text[] NOT NULL CHECK (cardinality(allowed_modes) BETWEEN 1 AND 32),
  interlock_refs text[] NOT NULL, alarm_blocking_severities text[] NOT NULL,
  limited_write_allowed boolean NOT NULL DEFAULT false, policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id,asset_id,point_id), FOREIGN KEY (tenant_id,asset_id) REFERENCES public.industrial_asset_models(tenant_id,asset_id)
);
CREATE TABLE public.industrial_setpoint_cases (
  tenant_id uuid NOT NULL, execution_id uuid NOT NULL, asset_id uuid NOT NULL, point_id varchar(512) NOT NULL,
  stage varchar(24) NOT NULL CHECK (stage IN ('SIMULATOR','DIGITAL_TWIN','READ_ONLY','SHADOW','LIMITED_WRITE')),
  before_value double precision NOT NULL, target_value double precision NOT NULL,
  before_digest char(64) NOT NULL CHECK (before_digest ~ '^[0-9a-f]{64}$'), target_digest char(64) NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
  observed_resource_version bigint NOT NULL CHECK (observed_resource_version>0),
  state_observed_at timestamptz NOT NULL, quality varchar(16) NOT NULL CHECK (quality IN ('GOOD','UNCERTAIN','BAD')),
  interlock_digest char(64) NOT NULL CHECK (interlock_digest ~ '^[0-9a-f]{64}$'),
  alarm_digest char(64) NOT NULL CHECK (alarm_digest ~ '^[0-9a-f]{64}$'),
  simulation_receipt_digest char(64) NOT NULL CHECK (simulation_receipt_digest ~ '^[0-9a-f]{64}$'),
  approval_set_id uuid, supervision_id uuid, commit_state varchar(24) NOT NULL CHECK (commit_state IN ('PREPARED','COMMITTED','SAFE_STOPPED','MANUAL_RECOVERY','REJECTED','UNKNOWN')),
  protocol_receipt_digest char(64), safe_stop_receipt_digest char(64), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,execution_id), FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  FOREIGN KEY (tenant_id,asset_id,point_id) REFERENCES public.industrial_point_policies(tenant_id,asset_id,point_id),
  FOREIGN KEY (tenant_id,supervision_id) REFERENCES public.domain_physical_supervision(tenant_id,supervision_id),
  CHECK ((stage='LIMITED_WRITE' AND approval_set_id IS NOT NULL AND supervision_id IS NOT NULL) OR (stage<>'LIMITED_WRITE' AND supervision_id IS NULL)),
  CHECK (commit_state<>'COMMITTED' OR protocol_receipt_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE public.industrial_telemetry_outcomes (
  tenant_id uuid NOT NULL, outcome_id uuid NOT NULL, execution_id uuid NOT NULL,
  telemetry_window_digest char(64) NOT NULL CHECK (telemetry_window_digest ~ '^[0-9a-f]{64}$'),
  converged boolean NOT NULL, stable_duration_ms bigint NOT NULL CHECK (stable_duration_ms>=0),
  overshoot double precision NOT NULL, oscillation_score double precision NOT NULL CHECK (oscillation_score>=0),
  new_alarm_count integer NOT NULL CHECK (new_alarm_count>=0), interlock_tripped boolean NOT NULL,
  quality varchar(16) NOT NULL CHECK (quality IN ('GOOD','UNCERTAIN','BAD')),
  conclusion varchar(24) NOT NULL CHECK (conclusion IN ('PASS','FAIL','NEEDS_HUMAN','MANUAL_RECOVERY')),
  evaluator_digest char(64) NOT NULL CHECK (evaluator_digest ~ '^[0-9a-f]{64}$'), observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,outcome_id), UNIQUE (tenant_id,execution_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.industrial_setpoint_cases(tenant_id,execution_id),
  CHECK (conclusion<>'PASS' OR (converged AND quality='GOOD' AND NOT interlock_tripped AND new_alarm_count=0))
);
CREATE TABLE public.industrial_stage_certifications (
  tenant_id uuid NOT NULL, certification_id uuid NOT NULL,
  stage varchar(24) NOT NULL CHECK (stage IN ('SIMULATOR','DIGITAL_TWIN','READ_ONLY','SHADOW','LIMITED_WRITE')),
  asset_scope_digest char(64) NOT NULL CHECK (asset_scope_digest ~ '^[0-9a-f]{64}$'),
  release_certificate_digest char(64) NOT NULL CHECK (release_certificate_digest ~ '^[0-9a-f]{64}$'),
  expert_approval_set_id uuid NOT NULL, status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  valid_from timestamptz NOT NULL, valid_until timestamptz NOT NULL CHECK (valid_until>valid_from),
  PRIMARY KEY (tenant_id,certification_id), UNIQUE (tenant_id,stage,asset_scope_digest)
);

CREATE OR REPLACE FUNCTION public.agenttrust_industrial_supervision_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
DECLARE approval_count integer; supervision record; execution record;
BEGIN
  IF NEW.stage<>'LIMITED_WRITE' THEN RETURN NEW; END IF;
  SELECT * INTO supervision FROM public.domain_physical_supervision WHERE tenant_id=NEW.tenant_id AND supervision_id=NEW.supervision_id FOR UPDATE;
  IF NOT FOUND OR supervision.domain<>'INDUSTRIAL' OR supervision.stage<>'LIMITED_WRITE' OR supervision.expires_at<=now()
     OR (supervision.consumed_at IS NOT NULL AND supervision.consumed_by_execution_id<>NEW.execution_id) OR supervision.before_digest<>NEW.before_digest
     OR supervision.target_digest<>NEW.target_digest OR supervision.resource_version<>NEW.observed_resource_version
     OR supervision.approval_set_id<>NEW.approval_set_id THEN
    RAISE EXCEPTION 'INDUSTRIAL_SUPERVISION_INVALID';
  END IF;
  SELECT domain,resource_key,resource_version,canonical_action,state INTO execution
    FROM public.domain_pack_executions
   WHERE tenant_id=NEW.tenant_id AND execution_id=NEW.execution_id FOR KEY SHARE;
  IF NOT FOUND OR execution.domain<>'INDUSTRIAL' OR execution.resource_key<>supervision.resource_key
     OR execution.resource_version<>NEW.observed_resource_version OR execution.state NOT IN ('PREPARED','EXECUTING') THEN
    RAISE EXCEPTION 'INDUSTRIAL_EXECUTION_BINDING_INVALID';
  END IF;
  SELECT count(DISTINCT reviewer_subject) INTO approval_count FROM public.domain_expert_approvals
   WHERE tenant_id=NEW.tenant_id AND approval_set_id=NEW.approval_set_id AND domain='INDUSTRIAL'
     AND decision='APPROVED' AND expires_at>now() AND before_digest=NEW.before_digest
     AND target_digest=NEW.target_digest AND resource_version=NEW.observed_resource_version
     AND resource_key=supervision.resource_key
     AND operation=execution.canonical_action #>> '{intent,operation}'
     AND reviewer_subject<>supervision.supervisor_subject;
  IF approval_count<2 THEN RAISE EXCEPTION 'INDUSTRIAL_DUAL_APPROVAL_REQUIRED'; END IF;
  IF supervision.consumed_at IS NULL THEN
    UPDATE public.domain_physical_supervision SET consumed_by_execution_id=NEW.execution_id,consumed_at=now()
     WHERE tenant_id=NEW.tenant_id AND supervision_id=NEW.supervision_id;
  END IF;
  RETURN NEW;
END $function$;
CREATE TRIGGER industrial_supervision_guard BEFORE INSERT ON public.industrial_setpoint_cases
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_industrial_supervision_guard();

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['industrial_asset_models','industrial_point_policies','industrial_setpoint_cases','industrial_telemetry_outcomes','industrial_stage_certifications'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('CREATE POLICY industrial_tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',table_name);
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',table_name);
  END LOOP;
END $rls$;
CREATE TRIGGER industrial_outcome_immutable BEFORE UPDATE OR DELETE ON public.industrial_telemetry_outcomes FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE TRIGGER industrial_certificate_immutable BEFORE UPDATE OR DELETE ON public.industrial_stage_certifications FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE INDEX industrial_case_state_idx ON public.industrial_setpoint_cases(tenant_id,stage,commit_state,updated_at);
REVOKE ALL ON FUNCTION public.agenttrust_industrial_supervision_guard() FROM PUBLIC;
COMMIT;
