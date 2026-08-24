BEGIN;

DO $migration$
BEGIN
  IF to_regclass('public.coding_pack_runs') IS NOT NULL
     AND to_regclass('public.coding_pack_runs_legacy_0023') IS NULL THEN
    ALTER TABLE public.coding_pack_runs RENAME TO coding_pack_runs_legacy_0023;
  END IF;
END
$migration$;
REVOKE ALL ON TABLE public.coding_pack_runs_legacy_0023 FROM PUBLIC;

-- Shared production contract consumed by all five Domain Packs. Domain plugins do not own a
-- second PEP, ledger, fence, idempotency, executor or Evidence implementation.
CREATE TABLE IF NOT EXISTS public.domain_pack_executions (
  tenant_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  command_id uuid NOT NULL,
  task_id uuid NOT NULL,
  domain varchar(24) NOT NULL CHECK (domain IN ('CODING','INDUSTRIAL','ENERGY','MEDICAL','SENSITIVE')),
  pack_id varchar(256) NOT NULL,
  pack_version varchar(128) NOT NULL,
  pack_manifest_digest char(64) NOT NULL CHECK (pack_manifest_digest ~ '^[0-9a-f]{64}$'),
  tool_id varchar(256) NOT NULL,
  effect_class varchar(20) NOT NULL CHECK (effect_class IN ('PURE','IDEMPOTENT','COMPENSATABLE','IRREVERSIBLE')),
  action_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  idempotency_key varchar(256) NOT NULL,
  actor_subject varchar(512) NOT NULL,
  authorization_id uuid NOT NULL,
  authorization_digest char(64) NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
  policy_decision_id varchar(256) NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[0-9a-f]{64}$'),
  authorization_evidence_ref varchar(1024) NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  resource_key varchar(1024) NOT NULL,
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  canonical_action jsonb NOT NULL CHECK (jsonb_typeof(canonical_action)='object'),
  safe_input jsonb NOT NULL CHECK (jsonb_typeof(safe_input)='object'),
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
  state varchar(24) NOT NULL CHECK (state IN ('PREPARED','EXECUTING','VERIFYING','SUCCEEDED','FAILED','NEEDS_HUMAN','MANUAL_RECOVERY','UNKNOWN')),
  owner_instance_id uuid,
  lease_expires_at timestamptz,
  effect_receipt jsonb,
  effect_receipt_digest char(64),
  evaluator_result jsonb,
  evaluator_result_digest char(64),
  compensation_ref varchar(1024),
  stable_error varchar(128),
  evidence_ref varchar(1024),
  evidence_digest char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,execution_id),
  UNIQUE (tenant_id,idempotency_key), UNIQUE (tenant_id,action_id),
  UNIQUE (tenant_id,ledger_execution_id,ledger_event_id),
  FOREIGN KEY (tenant_id,pack_id,pack_version) REFERENCES public.supply_chain_pack_releases(tenant_id,pack_id,version),
  CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{15,255}$'),
  CHECK ((state='PREPARED' AND owner_instance_id IS NULL AND lease_expires_at IS NULL)
      OR (state<>'PREPARED' AND owner_instance_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK ((state='SUCCEEDED' AND effect_receipt IS NOT NULL AND effect_receipt_digest IS NOT NULL
          AND evaluator_result IS NOT NULL AND evaluator_result_digest IS NOT NULL
          AND evidence_ref IS NOT NULL AND evidence_digest IS NOT NULL AND stable_error IS NULL)
      OR (state IN ('FAILED','NEEDS_HUMAN','MANUAL_RECOVERY','UNKNOWN') AND stable_error IS NOT NULL)
      OR state IN ('PREPARED','EXECUTING','VERIFYING'))
);

CREATE TABLE IF NOT EXISTS public.domain_expert_approvals (
  tenant_id uuid NOT NULL, approval_id uuid NOT NULL, approval_set_id uuid NOT NULL,
  domain varchar(24) NOT NULL CHECK (domain IN ('CODING','INDUSTRIAL','ENERGY','MEDICAL','SENSITIVE')),
  operation varchar(128) NOT NULL, resource_key varchar(1024) NOT NULL,
  before_digest char(64) NOT NULL CHECK (before_digest ~ '^[0-9a-f]{64}$'),
  target_digest char(64) NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  decision varchar(16) NOT NULL CHECK (decision IN ('APPROVED','REJECTED','REVOKED','EXPIRED')),
  reviewer_subject varchar(512) NOT NULL, reviewer_role varchar(256) NOT NULL,
  reviewer_qualification_digest char(64) NOT NULL CHECK (reviewer_qualification_digest ~ '^[0-9a-f]{64}$'),
  principal_assertion_digest char(64) NOT NULL CHECK (principal_assertion_digest ~ '^[0-9a-f]{64}$'),
  evidence_ref varchar(1024) NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  approved_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK (expires_at>approved_at),
  PRIMARY KEY (tenant_id,approval_id), UNIQUE (tenant_id,approval_set_id,reviewer_subject)
);

CREATE TABLE IF NOT EXISTS public.domain_physical_supervision (
  tenant_id uuid NOT NULL, supervision_id uuid NOT NULL, approval_set_id uuid NOT NULL,
  domain varchar(24) NOT NULL CHECK (domain IN ('INDUSTRIAL','ENERGY')),
  stage varchar(24) NOT NULL CHECK (stage IN ('SIMULATOR','DIGITAL_TWIN','READ_ONLY','SHADOW','LIMITED_WRITE')),
  resource_key varchar(1024) NOT NULL,
  before_digest char(64) NOT NULL CHECK (before_digest ~ '^[0-9a-f]{64}$'),
  target_digest char(64) NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  supervisor_subject varchar(512) NOT NULL,
  supervisor_assertion_digest char(64) NOT NULL CHECK (supervisor_assertion_digest ~ '^[0-9a-f]{64}$'),
  evidence_ref varchar(1024) NOT NULL, evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK (expires_at>issued_at),
  consumed_by_execution_id uuid, consumed_at timestamptz,
  PRIMARY KEY (tenant_id,supervision_id), UNIQUE (tenant_id,approval_set_id,resource_key,target_digest),
  CHECK ((consumed_by_execution_id IS NULL AND consumed_at IS NULL) OR (consumed_by_execution_id IS NOT NULL AND consumed_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.domain_pack_evidence_outbox (
  tenant_id uuid NOT NULL, outbox_id uuid NOT NULL, execution_id uuid NOT NULL,
  domain varchar(24) NOT NULL CHECK (domain IN ('CODING','INDUSTRIAL','ENERGY','MEDICAL','SENSITIVE')),
  idempotency_key varchar(256) NOT NULL, payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL, delivered_at timestamptz, delivery_evidence_ref varchar(2048), delivery_receipt_digest char(64),
  PRIMARY KEY (tenant_id,outbox_id), UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  CHECK ((delivered_at IS NULL AND delivery_evidence_ref IS NULL AND delivery_receipt_digest IS NULL)
      OR (delivered_at IS NOT NULL AND delivery_evidence_ref LIKE 'evidence://%' AND delivery_receipt_digest ~ '^[0-9a-f]{64}$'))
);

CREATE TABLE IF NOT EXISTS public.coding_repository_resources (
  tenant_id uuid NOT NULL, repository_id uuid NOT NULL,
  repository_uri varchar(1024) NOT NULL CHECK (repository_uri ~ '^https://'), baseline_commit varchar(128) NOT NULL,
  protected_branches text[] NOT NULL CHECK (cardinality(protected_branches) BETWEEN 1 AND 128),
  allowed_branch_patterns text[] NOT NULL CHECK (cardinality(allowed_branch_patterns) BETWEEN 1 AND 128),
  allowed_path_prefixes text[] NOT NULL CHECK (cardinality(allowed_path_prefixes) BETWEEN 1 AND 1024),
  denied_path_prefixes text[] NOT NULL CHECK (cardinality(denied_path_prefixes) BETWEEN 1 AND 1024),
  command_template_ids text[] NOT NULL CHECK (cardinality(command_template_ids) BETWEEN 1 AND 256),
  dependency_mirror_refs text[] NOT NULL, network_default_deny boolean NOT NULL CHECK (network_default_deny),
  sandbox_profile_digest char(64) NOT NULL CHECK (sandbox_profile_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version>0),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','PAUSED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,repository_id), UNIQUE (tenant_id,repository_uri),
  CHECK ('.env'=ANY(denied_path_prefixes)), CHECK ('.git/hooks'=ANY(denied_path_prefixes))
);

CREATE TABLE IF NOT EXISTS public.coding_execution_cases (
  tenant_id uuid NOT NULL, execution_id uuid NOT NULL, repository_id uuid NOT NULL,
  baseline_commit varchar(128) NOT NULL, task_branch varchar(512) NOT NULL,
  patch_digest char(64) NOT NULL CHECK (patch_digest ~ '^[0-9a-f]{64}$'),
  dependency_lock_digest char(64) NOT NULL CHECK (dependency_lock_digest ~ '^[0-9a-f]{64}$'),
  changed_file_count integer NOT NULL CHECK (changed_file_count BETWEEN 0 AND 10000),
  deleted_line_count integer NOT NULL CHECK (deleted_line_count BETWEEN 0 AND 1000000),
  build_evidence_digest char(64), test_evidence_digest char(64), api_compatibility_digest char(64),
  security_scan_digest char(64), supply_chain_finding_digest char(64), pull_request_ref varchar(1024),
  rollback_ref varchar(1024) NOT NULL,
  evaluator_conclusion varchar(24) CHECK (evaluator_conclusion IN ('PASS','FAIL','NEEDS_HUMAN')),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,execution_id),
  UNIQUE (tenant_id,repository_id,task_branch),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  FOREIGN KEY (tenant_id,repository_id) REFERENCES public.coding_repository_resources(tenant_id,repository_id),
  CHECK (task_branch !~ '^(main|master)$'), CHECK (task_branch ~ '^agent/[A-Za-z0-9._/-]{1,480}$'),
  CHECK (pull_request_ref IS NULL OR pull_request_ref ~ '^https://')
);

CREATE OR REPLACE FUNCTION public.agenttrust_domain_execution_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.execution_id<>OLD.execution_id OR NEW.command_id<>OLD.command_id
     OR NEW.task_id<>OLD.task_id OR NEW.domain<>OLD.domain OR NEW.pack_id<>OLD.pack_id
     OR NEW.pack_version<>OLD.pack_version OR NEW.pack_manifest_digest<>OLD.pack_manifest_digest
     OR NEW.tool_id<>OLD.tool_id OR NEW.effect_class<>OLD.effect_class OR NEW.action_id<>OLD.action_id
     OR NEW.action_hash<>OLD.action_hash OR NEW.request_digest<>OLD.request_digest
     OR NEW.idempotency_key<>OLD.idempotency_key OR NEW.actor_subject<>OLD.actor_subject
     OR NEW.authorization_id<>OLD.authorization_id OR NEW.authorization_digest<>OLD.authorization_digest
     OR NEW.policy_decision_id<>OLD.policy_decision_id OR NEW.policy_decision_digest<>OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref<>OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest<>OLD.authorization_evidence_digest
     OR NEW.ledger_execution_id<>OLD.ledger_execution_id OR NEW.ledger_event_id<>OLD.ledger_event_id
     OR NEW.ledger_event_digest<>OLD.ledger_event_digest OR NEW.fence_digest<>OLD.fence_digest
     OR NEW.resource_key<>OLD.resource_key OR NEW.resource_version<>OLD.resource_version
     OR NEW.canonical_action<>OLD.canonical_action OR NEW.safe_input<>OLD.safe_input
     OR NEW.input_digest<>OLD.input_digest OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'DOMAIN_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  IF OLD.state IN ('SUCCEEDED','FAILED','NEEDS_HUMAN','MANUAL_RECOVERY','UNKNOWN')
     OR (OLD.state='PREPARED' AND NEW.state NOT IN ('EXECUTING','FAILED'))
     OR (OLD.state='EXECUTING' AND NEW.state NOT IN ('EXECUTING','VERIFYING','FAILED','NEEDS_HUMAN','MANUAL_RECOVERY','UNKNOWN'))
     OR (OLD.state='VERIFYING' AND NEW.state NOT IN ('VERIFYING','SUCCEEDED','FAILED','NEEDS_HUMAN','MANUAL_RECOVERY','UNKNOWN')) THEN
    RAISE EXCEPTION 'DOMAIN_EXECUTION_TRANSITION_INVALID';
  END IF;
  IF OLD.state='EXECUTING' AND NEW.state='EXECUTING'
     AND (NEW.owner_instance_id IS DISTINCT FROM OLD.owner_instance_id OR NEW.lease_expires_at<OLD.lease_expires_at) THEN
    RAISE EXCEPTION 'DOMAIN_EXECUTION_LEASE_INVALID';
  END IF;
  RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION public.agenttrust_domain_immutable_row() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$ BEGIN RAISE EXCEPTION 'DOMAIN_IMMUTABLE_RECORD'; END $function$;
CREATE OR REPLACE FUNCTION public.agenttrust_domain_outbox_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' OR OLD.delivered_at IS NOT NULL OR NEW.delivered_at IS NULL
     OR NEW.tenant_id<>OLD.tenant_id OR NEW.outbox_id<>OLD.outbox_id OR NEW.execution_id<>OLD.execution_id
     OR NEW.domain<>OLD.domain OR NEW.idempotency_key<>OLD.idempotency_key OR NEW.payload<>OLD.payload
     OR NEW.payload_digest<>OLD.payload_digest OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'DOMAIN_OUTBOX_IMMUTABLE';
  END IF; RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION public.agenttrust_domain_supervision_consume() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
DECLARE execution record;
BEGIN
  IF TG_OP='DELETE'
     OR NEW.tenant_id<>OLD.tenant_id OR NEW.supervision_id<>OLD.supervision_id
     OR NEW.approval_set_id<>OLD.approval_set_id OR NEW.domain<>OLD.domain OR NEW.stage<>OLD.stage
     OR NEW.resource_key<>OLD.resource_key OR NEW.before_digest<>OLD.before_digest
     OR NEW.target_digest<>OLD.target_digest OR NEW.resource_version<>OLD.resource_version
     OR NEW.supervisor_subject<>OLD.supervisor_subject
     OR NEW.supervisor_assertion_digest<>OLD.supervisor_assertion_digest
     OR NEW.evidence_ref<>OLD.evidence_ref OR NEW.evidence_digest<>OLD.evidence_digest
     OR NEW.issued_at<>OLD.issued_at OR NEW.expires_at<>OLD.expires_at
     OR OLD.consumed_by_execution_id IS NOT NULL OR OLD.consumed_at IS NOT NULL
     OR NEW.consumed_by_execution_id IS NULL OR NEW.consumed_at IS NULL
     OR NEW.consumed_at<OLD.issued_at OR NEW.consumed_at>OLD.expires_at THEN
    RAISE EXCEPTION 'DOMAIN_SUPERVISION_IMMUTABLE';
  END IF;
  SELECT domain,resource_key,resource_version,state INTO execution
    FROM public.domain_pack_executions
   WHERE tenant_id=NEW.tenant_id AND execution_id=NEW.consumed_by_execution_id
   FOR KEY SHARE;
  IF NOT FOUND OR execution.domain<>NEW.domain OR execution.resource_key<>NEW.resource_key
     OR execution.resource_version<>NEW.resource_version OR execution.state NOT IN ('PREPARED','EXECUTING') THEN
    RAISE EXCEPTION 'DOMAIN_SUPERVISION_EXECUTION_BINDING_INVALID';
  END IF;
  RETURN NEW;
END $function$;

DROP TRIGGER IF EXISTS domain_execution_transition_guard ON public.domain_pack_executions;
CREATE TRIGGER domain_execution_transition_guard BEFORE UPDATE ON public.domain_pack_executions
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_execution_transition();
DROP TRIGGER IF EXISTS domain_outbox_transition_guard ON public.domain_pack_evidence_outbox;
CREATE TRIGGER domain_outbox_transition_guard BEFORE UPDATE OR DELETE ON public.domain_pack_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_outbox_transition();
DROP TRIGGER IF EXISTS domain_approval_immutable ON public.domain_expert_approvals;
CREATE TRIGGER domain_approval_immutable BEFORE UPDATE OR DELETE ON public.domain_expert_approvals
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
DROP TRIGGER IF EXISTS domain_supervision_consume_guard ON public.domain_physical_supervision;
CREATE TRIGGER domain_supervision_consume_guard BEFORE UPDATE OR DELETE ON public.domain_physical_supervision
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_supervision_consume();
DROP TRIGGER IF EXISTS coding_case_immutable ON public.coding_execution_cases;
CREATE TRIGGER coding_case_immutable BEFORE UPDATE OR DELETE ON public.coding_execution_cases
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['domain_pack_executions','domain_expert_approvals','domain_physical_supervision','domain_pack_evidence_outbox','coding_repository_resources','coding_execution_cases'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('DROP POLICY IF EXISTS domain_tenant_isolation ON public.%I',table_name);
    EXECUTE format('CREATE POLICY domain_tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',table_name);
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',table_name);
  END LOOP;
END $rls$;

CREATE UNIQUE INDEX IF NOT EXISTS domain_single_resource_flight_idx ON public.domain_pack_executions(tenant_id,resource_key) WHERE state IN ('PREPARED','EXECUTING','VERIFYING');
CREATE INDEX IF NOT EXISTS domain_execution_recovery_idx ON public.domain_pack_executions(tenant_id,state,lease_expires_at,updated_at);
CREATE INDEX IF NOT EXISTS domain_evidence_delivery_idx ON public.domain_pack_evidence_outbox(tenant_id,created_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS coding_repository_status_idx ON public.coding_repository_resources(tenant_id,status,updated_at);
REVOKE ALL ON FUNCTION public.agenttrust_domain_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_domain_immutable_row() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_domain_outbox_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_domain_supervision_consume() FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
COMMIT;
