BEGIN;

ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_status_check;
UPDATE incidents SET status=CASE status
  WHEN 'OPEN' THEN 'DETECTED'
  WHEN 'REMEDIATED' THEN 'REMEDIATING'
  ELSE status END
WHERE status IN ('OPEN','REMEDIATED');
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS scope jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence_refs jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS legal_hold_id text;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resource_version bigint;
UPDATE incidents SET
  scope=COALESCE(scope,'[]'::jsonb),
  evidence_refs=COALESCE(evidence_refs,'[]'::jsonb),
  legal_hold_id=COALESCE(legal_hold_id,'legacy-hold:'||incident_id::text),
  resource_version=COALESCE(resource_version,0),
  task_id=COALESCE(task_id,incident_id), owner=COALESCE(owner,'legacy-owner')
WHERE scope IS NULL OR evidence_refs IS NULL OR legal_hold_id IS NULL OR resource_version IS NULL
   OR task_id IS NULL OR owner IS NULL;
ALTER TABLE incidents ALTER COLUMN task_id SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN owner SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN scope SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN evidence_refs SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN legal_hold_id SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN resource_version SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN resource_version SET DEFAULT 0;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='incidents_production_shape') THEN
    ALTER TABLE incidents ADD CONSTRAINT incidents_production_shape CHECK (
      severity IN ('P0','P1','P2','P3') AND
      status IN ('DETECTED','TRIAGED','CONTAINED','INVESTIGATING','REMEDIATING','RECERTIFYING','CLOSED') AND
      length(correlation_key) BETWEEN 1 AND 256 AND length(owner) BETWEEN 1 AND 256 AND
      length(safe_summary) BETWEEN 1 AND 512 AND safe_summary !~ E'[\\x00\\r\\n]' AND
      jsonb_typeof(scope)='array' AND jsonb_array_length(scope) BETWEEN 1 AND 256 AND
      jsonb_typeof(evidence_refs)='array' AND jsonb_array_length(evidence_refs) BETWEEN 1 AND 256 AND
      length(legal_hold_id) BETWEEN 1 AND 256 AND resource_version >= 0
    ) NOT VALID;
  END IF;
END $$;
ALTER TABLE incidents VALIDATE CONSTRAINT incidents_production_shape;

CREATE TABLE IF NOT EXISTS incident_principal_assertion_replay (
  tenant_id uuid NOT NULL, jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL CHECK (assertion_digest ~ '^[a-f0-9]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL, consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,jti), CHECK (expires_at > consumed_at - interval '30 seconds')
);

CREATE TABLE IF NOT EXISTS incident_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL, task_id uuid NOT NULL,
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 1024 AND resource_id !~ E'[\\x00\\r\\n]'),
  operation text NOT NULL CHECK (operation IN ('DETECT','TRIAGE','CONTAIN','INVESTIGATE','PRESERVE_EVIDENCE','PLAN_REPLAY','COMPLETE_REPLAY','PUBLISH_ROOT_CAUSE','BEGIN_REMEDIATION','TRIGGER_RECERTIFICATION','EVALUATE_RELEASE','START_CANARY','RECORD_CANARY','ROLLBACK_RELEASE','CLOSE')),
  principal_subject text NOT NULL CHECK (length(principal_subject) BETWEEN 1 AND 256),
  principal_kind text NOT NULL CHECK (principal_kind IN ('HUMAN','WORKLOAD')),
  principal_assertion_digest char(64), envelope jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED')), receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key), UNIQUE (tenant_id,action_id), UNIQUE (tenant_id,task_id,action_id),
  CHECK ((principal_kind='HUMAN')=(principal_assertion_digest IS NOT NULL)),
  CHECK (principal_assertion_digest IS NULL OR principal_assertion_digest ~ '^[a-f0-9]{64}$'),
  CHECK (envelope->>'schema_version'='agenttrust.gateway.v1' AND envelope->>'idempotency_key'=idempotency_key),
  CHECK ((state='ACCEPTED')=(receipt IS NOT NULL)),
  CHECK (receipt IS NULL OR (receipt->>'schema_version'='agenttrust.incident-action-receipt.v1' AND receipt->>'action_id'=action_id::text AND receipt->>'task_id'=task_id::text AND receipt->>'accepted'='true' AND receipt->>'execution_pending'='true'))
);

CREATE TABLE IF NOT EXISTS incident_resource_versions (
  tenant_id uuid NOT NULL, resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 1024),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,resource_id)
);

CREATE TABLE IF NOT EXISTS incident_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL, task_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL, ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[a-f0-9]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 1024), resource_version bigint NOT NULL CHECK (resource_version >= 0),
  trace_id text NOT NULL CHECK (length(trace_id) BETWEEN 1 AND 256),
  policy_decision_id text NOT NULL CHECK (length(policy_decision_id) BETWEEN 1 AND 256),
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (length(authorization_evidence_ref) BETWEEN 12 AND 2048),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  request jsonb NOT NULL CHECK (request->>'schema_version'='agenttrust.incident-executor-request.v1'),
  state text NOT NULL CHECK (state IN ('EXECUTING','SUCCEEDED','FAILED','UNKNOWN')),
  execution_owner uuid NOT NULL, execution_lease_until timestamptz,
  safe_result jsonb, safe_result_digest char(64), stable_error text,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key), UNIQUE (tenant_id,ledger_execution_id), UNIQUE (tenant_id,action_hash,fence_digest),
  CHECK ((state='SUCCEEDED')=(safe_result IS NOT NULL)),
  CHECK ((state='SUCCEEDED')=(safe_result_digest IS NOT NULL)),
  CHECK (safe_result_digest IS NULL OR safe_result_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state='FAILED')=(stable_error IS NOT NULL)),
  CHECK ((state='EXECUTING')=(execution_lease_until IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS incident_timeline (
  tenant_id uuid NOT NULL, incident_id uuid NOT NULL, event_id uuid NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128), from_status text, to_status text,
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256), reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 256),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (length(authorization_evidence_ref) BETWEEN 12 AND 2048),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,event_id), UNIQUE (tenant_id,incident_id,sequence),
  FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,incident_id)
);

CREATE TABLE IF NOT EXISTS containment_actions (
  tenant_id uuid NOT NULL, containment_id uuid NOT NULL, incident_id uuid NOT NULL, action_id uuid NOT NULL,
  idempotency_key text NOT NULL, targets jsonb NOT NULL, approval_ids jsonb NOT NULL, break_glass jsonb NOT NULL,
  effect_receipt jsonb NOT NULL, effect_receipt_digest char(64) NOT NULL CHECK (effect_receipt_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (length(authorization_evidence_ref) BETWEEN 12 AND 2048),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'), completed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,containment_id), UNIQUE (tenant_id,action_id),
  FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,incident_id),
  CHECK (jsonb_typeof(targets)='object' AND jsonb_typeof(approval_ids)='array' AND (jsonb_typeof(break_glass)='object' OR break_glass='null'::jsonb))
);

CREATE TABLE IF NOT EXISTS incident_evidence_preservations (
  tenant_id uuid NOT NULL, preservation_id uuid NOT NULL, incident_id uuid NOT NULL,
  chain_head_digest char(64) NOT NULL CHECK (chain_head_digest ~ '^[a-f0-9]{64}$'), snapshot_digest char(64) NOT NULL CHECK (snapshot_digest ~ '^[a-f0-9]{64}$'),
  process_digest char(64) NOT NULL CHECK (process_digest ~ '^[a-f0-9]{64}$'), network_digest char(64) NOT NULL CHECK (network_digest ~ '^[a-f0-9]{64}$'),
  configuration_digest char(64) NOT NULL CHECK (configuration_digest ~ '^[a-f0-9]{64}$'), version_digest char(64) NOT NULL CHECK (version_digest ~ '^[a-f0-9]{64}$'),
  legal_hold_id text NOT NULL CHECK (length(legal_hold_id) BETWEEN 1 AND 256), preserved_by text NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'), created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,preservation_id), FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,incident_id)
);

CREATE TABLE IF NOT EXISTS replay_plans (
  tenant_id uuid NOT NULL, replay_id uuid NOT NULL, incident_id uuid NOT NULL,
  mode text NOT NULL CHECK (mode IN ('LOGICAL','SANDBOX','LIVE')),
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'), source_snapshot_digest char(64) NOT NULL CHECK (source_snapshot_digest ~ '^[a-f0-9]{64}$'),
  expected_result_digest char(64) NOT NULL CHECK (expected_result_digest ~ '^[a-f0-9]{64}$'), plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
  resource_refs jsonb NOT NULL CHECK (jsonb_typeof(resource_refs)='array'), credential_profile text,
  fresh_lease_id uuid, fresh_lease_digest char(64), approval_ids jsonb NOT NULL CHECK (jsonb_typeof(approval_ids)='array'),
  created_by text NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,replay_id), FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,incident_id),
  CHECK ((mode='LOGICAL')=(credential_profile IS NULL AND fresh_lease_id IS NULL AND fresh_lease_digest IS NULL)),
  CHECK (mode<>'LIVE' OR (fresh_lease_id IS NOT NULL AND fresh_lease_digest ~ '^[a-f0-9]{64}$' AND jsonb_array_length(approval_ids)>=2))
);

ALTER TABLE replay_runs ADD COLUMN IF NOT EXISTS result_digest char(64);
ALTER TABLE replay_runs ADD COLUMN IF NOT EXISTS difference_digest char(64);
ALTER TABLE replay_runs ADD COLUMN IF NOT EXISTS production_access_detected boolean;
ALTER TABLE replay_runs ADD COLUMN IF NOT EXISTS effect_receipt jsonb;
UPDATE replay_runs SET result_digest=COALESCE(result_digest,input_digest), difference_digest=COALESCE(difference_digest,input_digest),
  production_access_detected=COALESCE(production_access_detected,false), effect_receipt=COALESCE(effect_receipt,'{}'::jsonb)
WHERE result_digest IS NULL OR difference_digest IS NULL OR production_access_detected IS NULL OR effect_receipt IS NULL;
ALTER TABLE replay_runs ALTER COLUMN result_digest SET NOT NULL;
ALTER TABLE replay_runs ALTER COLUMN difference_digest SET NOT NULL;
ALTER TABLE replay_runs ALTER COLUMN production_access_detected SET NOT NULL;
ALTER TABLE replay_runs ALTER COLUMN effect_receipt SET NOT NULL;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='replay_runs_production_shape') THEN
    ALTER TABLE replay_runs ADD CONSTRAINT replay_runs_production_shape CHECK (
      result_digest ~ '^[a-f0-9]{64}$' AND difference_digest ~ '^[a-f0-9]{64}$' AND
      jsonb_typeof(effect_receipt)='object' AND (mode<>'LOGICAL' OR (effect_count=0 AND NOT production_access_detected)) AND
      (mode<>'SANDBOX' OR NOT production_access_detected)
    ) NOT VALID;
  END IF;
END $$;
ALTER TABLE replay_runs VALIDATE CONSTRAINT replay_runs_production_shape;

CREATE TABLE IF NOT EXISTS root_cause_reports (
  tenant_id uuid NOT NULL, report_id uuid NOT NULL, incident_id uuid NOT NULL,
  report_digest char(64) NOT NULL CHECK (report_digest ~ '^[a-f0-9]{64}$'), findings jsonb NOT NULL, remediations jsonb NOT NULL,
  published_by text NOT NULL, action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'), published_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,report_id), UNIQUE (tenant_id,incident_id,report_digest),
  FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,incident_id),
  CHECK (jsonb_typeof(findings)='array' AND jsonb_array_length(findings)>0 AND jsonb_typeof(remediations)='array' AND jsonb_array_length(remediations)>0)
);

CREATE TABLE IF NOT EXISTS incident_recertifications (
  tenant_id uuid NOT NULL, recertification_id uuid NOT NULL, incident_id uuid NOT NULL,
  root_cause_digest char(64) NOT NULL CHECK (root_cause_digest ~ '^[a-f0-9]{64}$'), release_digest char(64) NOT NULL CHECK (release_digest ~ '^[a-f0-9]{64}$'),
  campaigns jsonb NOT NULL CHECK (jsonb_typeof(campaigns)='array' AND jsonb_array_length(campaigns)>0), approval_ids jsonb NOT NULL CHECK (jsonb_typeof(approval_ids)='array' AND jsonb_array_length(approval_ids)>0),
  requested_by text NOT NULL, action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'), state text NOT NULL CHECK (state IN ('REQUESTED','PASSED','FAILED')), requested_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,recertification_id), FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,incident_id)
);

CREATE TABLE IF NOT EXISTS release_gate_runs (
  tenant_id uuid NOT NULL, gate_run_id uuid NOT NULL, release_id text NOT NULL, release_digest char(64) NOT NULL CHECK (release_digest ~ '^[a-f0-9]{64}$'),
  gate_id text NOT NULL, gate_version text NOT NULL, definition_digest char(64) NOT NULL CHECK (definition_digest ~ '^[a-f0-9]{64}$'), evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  rollback_artifact_digest char(64) NOT NULL CHECK (rollback_artifact_digest ~ '^[a-f0-9]{64}$'), canary_plan_digest char(64) NOT NULL CHECK (canary_plan_digest ~ '^[a-f0-9]{64}$'),
  approval_ids jsonb NOT NULL CHECK (jsonb_typeof(approval_ids)='array' AND jsonb_array_length(approval_ids)>=2),
  state text NOT NULL CHECK (state IN ('GATE_PASSED','CANARY_RUNNING','CANARY_PASSED','ROLLBACK_REQUIRED','ROLLED_BACK')),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'), policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL, authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  evaluated_at timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,gate_run_id), UNIQUE (tenant_id,release_id)
);

CREATE TABLE IF NOT EXISTS release_gate_certificates (
  tenant_id uuid NOT NULL, certificate_id uuid NOT NULL, release_id text NOT NULL, receipt jsonb NOT NULL,
  receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[a-f0-9]{64}$'), key_id text NOT NULL,
  valid_from timestamptz NOT NULL, valid_until timestamptz NOT NULL,
  engine_certificate_only boolean NOT NULL CHECK (engine_certificate_only), production_closure boolean NOT NULL CHECK (NOT production_closure), issued_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,certificate_id), UNIQUE (tenant_id,release_id), CHECK (valid_until>valid_from AND valid_until<=valid_from+interval '7 days')
);

CREATE TABLE IF NOT EXISTS release_canary_events (
  tenant_id uuid NOT NULL, event_id uuid NOT NULL, release_id text NOT NULL, event_type text NOT NULL,
  payload jsonb NOT NULL, payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'), actor_subject text NOT NULL,
  approval_ids jsonb NOT NULL CHECK (jsonb_typeof(approval_ids)='array' AND jsonb_array_length(approval_ids)>=2),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'), occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,event_id), FOREIGN KEY (tenant_id,release_id) REFERENCES release_gate_runs(tenant_id,release_id)
);

CREATE TABLE IF NOT EXISTS incident_evidence_events (
  tenant_id uuid NOT NULL, event_id uuid NOT NULL, task_id uuid NOT NULL, resource_id text NOT NULL, event_type text NOT NULL,
  actor_subject text NOT NULL, payload jsonb NOT NULL, payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'), evidence_outbox_ref text NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'), ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'), policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,event_id), UNIQUE (tenant_id,evidence_outbox_ref)
);

CREATE TABLE IF NOT EXISTS incident_evidence_outbox (
  tenant_id uuid NOT NULL, event_id uuid NOT NULL, task_id uuid NOT NULL, event_type text NOT NULL, idempotency_key text NOT NULL,
  payload jsonb NOT NULL, payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  authority_receipt jsonb, authority_receipt_digest char(64), published_at timestamptz, delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts>=0),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,event_id), UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,event_id) REFERENCES incident_evidence_events(tenant_id,event_id),
  CHECK ((published_at IS NOT NULL)=(authority_receipt IS NOT NULL)),
  CHECK ((authority_receipt IS NOT NULL)=(authority_receipt_digest IS NOT NULL)),
  CHECK (authority_receipt_digest IS NULL OR authority_receipt_digest ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS incident_timeline_order_idx ON incident_timeline(tenant_id,incident_id,sequence);
CREATE INDEX IF NOT EXISTS incident_execution_lease_idx ON incident_authority_executions(state,execution_lease_until) WHERE state='EXECUTING';
CREATE INDEX IF NOT EXISTS incident_outbox_pending_idx ON incident_evidence_outbox(tenant_id,created_at,event_id) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS incident_open_severity_idx ON incidents(tenant_id,severity,status) WHERE status<>'CLOSED';

CREATE OR REPLACE FUNCTION reject_incident_immutable_record()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'INCIDENT_IMMUTABLE_RECORD'; END $$;

CREATE OR REPLACE FUNCTION enforce_incident_resource_version_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.resource_id<>NEW.resource_id OR NEW.resource_version<>OLD.resource_version+1 OR
     NEW.action_hash=OLD.action_hash OR NEW.ledger_execution_id=OLD.ledger_execution_id OR NEW.fence_digest=OLD.fence_digest OR
     NEW.created_at<>OLD.created_at OR NEW.updated_at<OLD.updated_at THEN
    RAISE EXCEPTION 'INCIDENT_RESOURCE_VERSION_TRANSITION_INVALID';
  END IF; RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_incident_ingress_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.idempotency_key<>NEW.idempotency_key OR OLD.request_digest<>NEW.request_digest OR
     OLD.action_id<>NEW.action_id OR OLD.task_id<>NEW.task_id OR OLD.resource_id<>NEW.resource_id OR OLD.operation<>NEW.operation OR
     OLD.principal_subject<>NEW.principal_subject OR OLD.principal_kind<>NEW.principal_kind OR
     OLD.principal_assertion_digest IS DISTINCT FROM NEW.principal_assertion_digest OR OLD.envelope<>NEW.envelope OR
     NOT (OLD.state='PREPARED' AND NEW.state='ACCEPTED' OR OLD.state=NEW.state AND OLD.receipt IS NOT DISTINCT FROM NEW.receipt) THEN
    RAISE EXCEPTION 'INCIDENT_INGRESS_TRANSITION_INVALID';
  END IF; RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_incident_record_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.incident_id<>NEW.incident_id OR OLD.correlation_key<>NEW.correlation_key OR
     OLD.task_id<>NEW.task_id OR OLD.safe_summary<>NEW.safe_summary OR OLD.scope<>NEW.scope OR OLD.evidence_refs<>NEW.evidence_refs OR
     OLD.legal_hold_id<>NEW.legal_hold_id OR OLD.created_at<>NEW.created_at OR NEW.resource_version<>OLD.resource_version+1 OR
     NOT ((OLD.status='DETECTED' AND NEW.status IN ('TRIAGED','CONTAINED')) OR (OLD.status='TRIAGED' AND NEW.status='CONTAINED') OR
          (OLD.status='CONTAINED' AND NEW.status IN ('CONTAINED','INVESTIGATING')) OR
          (OLD.status='INVESTIGATING' AND NEW.status IN ('INVESTIGATING','REMEDIATING')) OR
          (OLD.status='REMEDIATING' AND NEW.status IN ('REMEDIATING','RECERTIFYING')) OR
          (OLD.status='RECERTIFYING' AND NEW.status IN ('RECERTIFYING','CLOSED')) OR
          (OLD.status=NEW.status)) THEN
    RAISE EXCEPTION 'INCIDENT_RECORD_TRANSITION_INVALID';
  END IF; RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_incident_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.idempotency_key<>NEW.idempotency_key OR OLD.request_digest<>NEW.request_digest OR
     OLD.action_id<>NEW.action_id OR OLD.task_id<>NEW.task_id OR OLD.action_hash<>NEW.action_hash OR
     OLD.ledger_execution_id<>NEW.ledger_execution_id OR OLD.ledger_event_id<>NEW.ledger_event_id OR
     OLD.ledger_event_digest<>NEW.ledger_event_digest OR OLD.fence_digest<>NEW.fence_digest OR
     OLD.resource_id<>NEW.resource_id OR OLD.resource_version<>NEW.resource_version OR OLD.trace_id<>NEW.trace_id OR
     OLD.policy_decision_id<>NEW.policy_decision_id OR OLD.policy_decision_digest<>NEW.policy_decision_digest OR
     OLD.authorization_evidence_ref<>NEW.authorization_evidence_ref OR
     OLD.authorization_evidence_digest<>NEW.authorization_evidence_digest OR OLD.request<>NEW.request OR
     NOT ((OLD.state='EXECUTING' AND NEW.state IN ('EXECUTING','SUCCEEDED','FAILED','UNKNOWN')) OR
          (OLD.state=NEW.state AND OLD.safe_result IS NOT DISTINCT FROM NEW.safe_result AND
           OLD.safe_result_digest IS NOT DISTINCT FROM NEW.safe_result_digest AND OLD.stable_error IS NOT DISTINCT FROM NEW.stable_error)) THEN
    RAISE EXCEPTION 'INCIDENT_EXECUTION_TRANSITION_INVALID';
  END IF;
  IF OLD.state='EXECUTING' AND NEW.state='EXECUTING' AND
     (NEW.execution_owner=OLD.execution_owner OR OLD.execution_lease_until>now()) THEN
    RAISE EXCEPTION 'INCIDENT_EXECUTION_LEASE_INVALID';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_release_gate_state_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.gate_run_id<>NEW.gate_run_id OR OLD.release_id<>NEW.release_id OR
     OLD.release_digest<>NEW.release_digest OR OLD.gate_id<>NEW.gate_id OR OLD.gate_version<>NEW.gate_version OR
     OLD.definition_digest<>NEW.definition_digest OR OLD.evidence_digest<>NEW.evidence_digest OR
     OLD.rollback_artifact_digest<>NEW.rollback_artifact_digest OR OLD.canary_plan_digest<>NEW.canary_plan_digest OR
     OLD.approval_ids<>NEW.approval_ids OR OLD.action_hash<>NEW.action_hash OR
     OLD.ledger_execution_id<>NEW.ledger_execution_id OR OLD.fence_digest<>NEW.fence_digest OR
     OLD.policy_decision_digest<>NEW.policy_decision_digest OR OLD.authorization_evidence_ref<>NEW.authorization_evidence_ref OR
     NOT ((OLD.state='GATE_PASSED' AND NEW.state IN ('CANARY_RUNNING','ROLLED_BACK')) OR
          (OLD.state='CANARY_RUNNING' AND NEW.state IN ('CANARY_PASSED','ROLLBACK_REQUIRED','ROLLED_BACK')) OR
          (OLD.state='CANARY_PASSED' AND NEW.state='ROLLED_BACK') OR
          (OLD.state='ROLLBACK_REQUIRED' AND NEW.state='ROLLED_BACK')) THEN
    RAISE EXCEPTION 'RELEASE_GATE_STATE_TRANSITION_INVALID';
  END IF; RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_incident_outbox_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.event_id<>NEW.event_id OR OLD.task_id<>NEW.task_id OR
     OLD.event_type<>NEW.event_type OR OLD.idempotency_key<>NEW.idempotency_key OR OLD.payload<>NEW.payload OR
     OLD.payload_digest<>NEW.payload_digest OR OLD.created_at<>NEW.created_at OR
     NEW.delivery_attempts<OLD.delivery_attempts OR OLD.published_at IS NOT NULL OR
     (NEW.published_at IS NOT NULL AND (NEW.authority_receipt IS NULL OR NEW.authority_receipt_digest IS NULL)) THEN
    RAISE EXCEPTION 'INCIDENT_OUTBOX_TRANSITION_INVALID';
  END IF; RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS incident_resource_version_guard ON incident_resource_versions;
CREATE TRIGGER incident_resource_version_guard BEFORE UPDATE OR DELETE ON incident_resource_versions FOR EACH ROW EXECUTE FUNCTION enforce_incident_resource_version_transition();
DROP TRIGGER IF EXISTS incident_ingress_guard ON incident_action_ingress;
CREATE TRIGGER incident_ingress_guard BEFORE UPDATE OR DELETE ON incident_action_ingress FOR EACH ROW EXECUTE FUNCTION enforce_incident_ingress_transition();
DROP TRIGGER IF EXISTS incident_record_guard ON incidents;
CREATE TRIGGER incident_record_guard BEFORE UPDATE OR DELETE ON incidents FOR EACH ROW EXECUTE FUNCTION enforce_incident_record_transition();
DROP TRIGGER IF EXISTS incident_execution_guard ON incident_authority_executions;
CREATE TRIGGER incident_execution_guard BEFORE UPDATE OR DELETE ON incident_authority_executions FOR EACH ROW EXECUTE FUNCTION enforce_incident_execution_transition();
DROP TRIGGER IF EXISTS release_gate_state_guard ON release_gate_runs;
CREATE TRIGGER release_gate_state_guard BEFORE UPDATE OR DELETE ON release_gate_runs FOR EACH ROW EXECUTE FUNCTION enforce_release_gate_state_transition();
DROP TRIGGER IF EXISTS incident_outbox_guard ON incident_evidence_outbox;
CREATE TRIGGER incident_outbox_guard BEFORE UPDATE OR DELETE ON incident_evidence_outbox FOR EACH ROW EXECUTE FUNCTION enforce_incident_outbox_transition();

DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['incident_principal_assertion_replay','incident_timeline','containment_actions','incident_evidence_preservations','replay_plans','replay_runs','root_cause_reports','incident_recertifications','release_gate_certificates','release_canary_events','incident_evidence_events'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',table_name||'_immutable',table_name);
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_incident_immutable_record()',table_name||'_immutable',table_name);
  END LOOP;
END $$;

DO $$ DECLARE table_name text; DECLARE policy_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['incidents','replay_runs','release_gate_results','incident_principal_assertion_replay','incident_action_ingress','incident_resource_versions','incident_authority_executions','incident_timeline','containment_actions','incident_evidence_preservations','replay_plans','root_cause_reports','incident_recertifications','release_gate_runs','release_gate_certificates','release_canary_events','incident_evidence_events','incident_evidence_outbox'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
    FOR policy_name IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename=table_name LOOP
      EXECUTE format('DROP POLICY %I ON %I',policy_name,table_name);
    END LOOP;
    EXECUTE format('CREATE POLICY tenant_isolation ON %I FOR ALL TO PUBLIC USING (tenant_id::text=current_setting(''app.tenant_id'',true)) WITH CHECK (tenant_id::text=current_setting(''app.tenant_id'',true))',table_name);
  END LOOP;
END $$;

REVOKE ALL ON TABLE incidents,replay_runs,release_gate_results,incident_principal_assertion_replay,
  incident_action_ingress,incident_resource_versions,incident_authority_executions,incident_timeline,
  containment_actions,incident_evidence_preservations,replay_plans,root_cause_reports,
  incident_recertifications,release_gate_runs,release_gate_certificates,release_canary_events,
  incident_evidence_events,incident_evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_incident_immutable_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_incident_resource_version_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_incident_ingress_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_incident_record_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_incident_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_release_gate_state_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_incident_outbox_transition() FROM PUBLIC;

-- The externally provisioned incident_authority_application_role is granted by the production
-- migration runner. This migration creates no LOGIN role and grants nothing to PUBLIC.
COMMIT;
