BEGIN;

-- Batch 21 production authority. The two Batch 21 prototype tables lack tenant-bound
-- source attestations, Canonical Action/ledger facts, durable response delivery and Evidence
-- closure. Preserve them owner-only; they are not promoted into authoritative state.
CREATE SCHEMA IF NOT EXISTS agenttrust_legacy_runtime_anomaly;
REVOKE ALL ON SCHEMA agenttrust_legacy_runtime_anomaly FROM PUBLIC;
ALTER TABLE public.risk_signals SET SCHEMA agenttrust_legacy_runtime_anomaly;
ALTER TABLE public.continuous_authorization_commands SET SCHEMA agenttrust_legacy_runtime_anomaly;
REVOKE ALL ON ALL TABLES IN SCHEMA agenttrust_legacy_runtime_anomaly FROM PUBLIC;

CREATE TABLE runtime_anomaly_signal_sources (
  tenant_id uuid NOT NULL,
  source_id text NOT NULL CHECK (source_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
  key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  ed25519_public_key bytea NOT NULL CHECK (octet_length(ed25519_public_key)=32),
  allowed_signal_kinds text[] NOT NULL,
  workload_identity text NOT NULL CHECK (workload_identity ~ '^(DNS:|URI:)[!-~]+$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED','QUARANTINED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,source_id),
  UNIQUE (tenant_id,key_id),
  CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  CHECK (cardinality(allowed_signal_kinds) BETWEEN 1 AND 16),
  CHECK (allowed_signal_kinds <@ ARRAY[
    'TOOL','RESOURCE','NETWORK','FILE','CREDENTIAL','POLICY_DENY','APPROVAL','PROCESS',
    'TELEMETRY','AUDIT_CONTROL'
  ]::text[])
);

CREATE TABLE runtime_anomaly_trajectories (
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  agent_instance_id uuid NOT NULL,
  agent_type text NOT NULL CHECK (length(agent_type) BETWEEN 1 AND 128),
  domain text NOT NULL CHECK (length(domain) BETWEEN 1 AND 128),
  goal_hash char(64) NOT NULL CHECK (goal_hash ~ '^[0-9a-f]{64}$'),
  plan_hash char(64) NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
  allowed_resource_prefixes text[] NOT NULL,
  allowed_network_destinations text[] NOT NULL,
  authorization_lease_id uuid NOT NULL,
  revocation_epoch bigint NOT NULL CHECK (revocation_epoch >= 0),
  status text NOT NULL CHECK (status IN ('ACTIVE','APPROVAL_REQUIRED','PAUSED','KILLED','COMPLETED')),
  event_count bigint NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  started_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,task_id),
  UNIQUE (tenant_id,authorization_lease_id,revocation_epoch),
  CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  CHECK (cardinality(allowed_resource_prefixes) BETWEEN 1 AND 1024),
  CHECK (cardinality(allowed_network_destinations) BETWEEN 0 AND 1024),
  CHECK ((status='COMPLETED' AND completed_at IS NOT NULL) OR (status<>'COMPLETED' AND completed_at IS NULL)),
  CHECK (last_seen_at >= started_at)
);

CREATE TABLE runtime_anomaly_signals (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  task_id uuid NOT NULL,
  agent_instance_id uuid NOT NULL,
  source_id text NOT NULL,
  signal_kind text NOT NULL CHECK (signal_kind IN (
    'TOOL','RESOURCE','NETWORK','FILE','CREDENTIAL','POLICY_DENY','APPROVAL','PROCESS',
    'TELEMETRY','AUDIT_CONTROL'
  )),
  action text NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  resource_class text NOT NULL CHECK (length(resource_class) BETWEEN 1 AND 128),
  safe_features jsonb NOT NULL CHECK (jsonb_typeof(safe_features) IN ('object','number','string','null')),
  confidence_millionths integer NOT NULL CHECK (confidence_millionths BETWEEN 0 AND 1000000),
  source_version text NOT NULL CHECK (length(source_version) BETWEEN 1 AND 128),
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  signature_key_id text NOT NULL,
  signature bytea NOT NULL CHECK (octet_length(signature)=64),
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,source_id,payload_digest),
  FOREIGN KEY (tenant_id,task_id) REFERENCES runtime_anomaly_trajectories(tenant_id,task_id),
  FOREIGN KEY (tenant_id,source_id) REFERENCES runtime_anomaly_signal_sources(tenant_id,source_id),
  CHECK (received_at >= occurred_at - interval '5 minutes')
);

CREATE INDEX runtime_anomaly_signals_task_time_idx
  ON runtime_anomaly_signals(tenant_id,task_id,occurred_at,event_id);

CREATE TABLE runtime_anomaly_findings (
  tenant_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  task_id uuid NOT NULL,
  rule_id text NOT NULL CHECK (rule_id ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  rule_version text NOT NULL CHECK (length(rule_version) BETWEEN 1 AND 128),
  severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  deterministic boolean NOT NULL,
  confidence_millionths integer NOT NULL CHECK (confidence_millionths BETWEEN 0 AND 1000000),
  evidence_event_ids uuid[] NOT NULL,
  safe_reason text NOT NULL CHECK (length(safe_reason) BETWEEN 1 AND 512),
  status text NOT NULL CHECK (status IN ('OPEN','ACKNOWLEDGED','MITIGATING','RESOLVED','FALSE_POSITIVE')),
  finding_digest char(64) NOT NULL CHECK (finding_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,finding_id),
  UNIQUE (tenant_id,task_id,rule_id,finding_digest),
  FOREIGN KEY (tenant_id,task_id) REFERENCES runtime_anomaly_trajectories(tenant_id,task_id),
  CHECK (cardinality(evidence_event_ids) BETWEEN 1 AND 4096),
  CHECK (NOT deterministic OR confidence_millionths >= 900000)
);

CREATE TABLE runtime_anomaly_aggregates (
  tenant_id uuid NOT NULL,
  aggregate_id uuid NOT NULL,
  task_id uuid NOT NULL,
  severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  score_millionths integer NOT NULL CHECK (score_millionths BETWEEN 0 AND 1000000),
  finding_ids uuid[] NOT NULL,
  semantic_model_id text,
  semantic_model_version text,
  semantic_score_millionths integer CHECK (semantic_score_millionths BETWEEN 0 AND 1000000),
  semantic_reason_codes text[] NOT NULL DEFAULT '{}',
  detector_degraded boolean NOT NULL,
  rule_bundle_digest char(64) NOT NULL CHECK (rule_bundle_digest ~ '^[0-9a-f]{64}$'),
  aggregate_digest char(64) NOT NULL CHECK (aggregate_digest ~ '^[0-9a-f]{64}$'),
  computed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,aggregate_id),
  UNIQUE (tenant_id,task_id,aggregate_digest),
  FOREIGN KEY (tenant_id,task_id) REFERENCES runtime_anomaly_trajectories(tenant_id,task_id),
  CHECK (cardinality(finding_ids) BETWEEN 0 AND 4096),
  CHECK ((semantic_model_id IS NULL AND semantic_model_version IS NULL AND semantic_score_millionths IS NULL)
      OR (semantic_model_id IS NOT NULL AND semantic_model_version IS NOT NULL AND semantic_score_millionths IS NOT NULL))
);

CREATE TABLE runtime_anomaly_baselines (
  tenant_id uuid NOT NULL,
  baseline_id uuid NOT NULL,
  agent_type text NOT NULL CHECK (length(agent_type) BETWEEN 1 AND 128),
  domain text NOT NULL CHECK (length(domain) BETWEEN 1 AND 128),
  maximum_calls_per_minute integer NOT NULL CHECK (maximum_calls_per_minute > 0),
  maximum_distinct_resources integer NOT NULL CHECK (maximum_distinct_resources > 0),
  maximum_destination_fanout integer NOT NULL CHECK (maximum_destination_fanout > 0),
  sample_count bigint NOT NULL CHECK (sample_count >= 10),
  threshold_version text NOT NULL CHECK (length(threshold_version) BETWEEN 1 AND 128),
  approval_id uuid NOT NULL,
  approval_evidence_ref text NOT NULL CHECK (approval_evidence_ref ~ '^evidence://'),
  baseline_digest char(64) NOT NULL CHECK (baseline_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  status text NOT NULL CHECK (status IN ('ACTIVE','RETIRED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,baseline_id),
  UNIQUE (tenant_id,agent_type,domain,threshold_version)
);

CREATE TABLE runtime_anomaly_feedback (
  tenant_id uuid NOT NULL,
  feedback_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  label text NOT NULL CHECK (label IN ('TRUE_POSITIVE','FALSE_POSITIVE','FALSE_NEGATIVE','INCONCLUSIVE')),
  annotation_digest char(64) NOT NULL CHECK (annotation_digest ~ '^[0-9a-f]{64}$'),
  reviewer_subject text NOT NULL CHECK (length(reviewer_subject) BETWEEN 1 AND 256),
  approval_id uuid NOT NULL,
  evidence_ref text NOT NULL CHECK (evidence_ref ~ '^evidence://'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,feedback_id),
  UNIQUE (tenant_id,finding_id,approval_id),
  FOREIGN KEY (tenant_id,finding_id) REFERENCES runtime_anomaly_findings(tenant_id,finding_id)
);

CREATE TABLE runtime_anomaly_cases (
  tenant_id uuid NOT NULL,
  case_id uuid NOT NULL,
  task_id uuid NOT NULL,
  aggregate_id uuid NOT NULL,
  incident_id uuid,
  severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status text NOT NULL CHECK (status IN ('OPEN','CONTAINING','PAUSED','KILLED','RECOVERING','CLOSED')),
  recovery_conditions text[] NOT NULL,
  response_epoch bigint NOT NULL CHECK (response_epoch >= 0),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  opened_at timestamptz NOT NULL DEFAULT now(),
  closed_at timestamptz,
  PRIMARY KEY (tenant_id,case_id),
  UNIQUE (tenant_id,task_id,aggregate_id),
  FOREIGN KEY (tenant_id,task_id) REFERENCES runtime_anomaly_trajectories(tenant_id,task_id),
  FOREIGN KEY (tenant_id,aggregate_id) REFERENCES runtime_anomaly_aggregates(tenant_id,aggregate_id),
  CHECK (cardinality(recovery_conditions) BETWEEN 0 AND 32),
  CHECK ((status='CLOSED' AND closed_at IS NOT NULL) OR (status<>'CLOSED' AND closed_at IS NULL))
);

CREATE TABLE runtime_anomaly_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 256),
  command_id uuid NOT NULL,
  task_id uuid NOT NULL,
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
  operation text NOT NULL CHECK (operation IN (
    'REGISTER_SOURCE','REVOKE_SOURCE','START_TRAJECTORY','UPDATE_BASELINE','RECORD_FEEDBACK',
    'ACKNOWLEDGE_CASE','RECOVER_PAUSED_TASK','COMPLETE_TRAJECTORY'
  )),
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  canonical_action_hash char(64) NOT NULL CHECK (canonical_action_hash ~ '^[0-9a-f]{64}$'),
  canonical_envelope jsonb NOT NULL CHECK (jsonb_typeof(canonical_envelope)='object'),
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED','REJECTED','UNKNOWN')),
  orchestrator_receipt jsonb,
  orchestrator_evidence_ref text,
  orchestrator_evidence_digest char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,command_id),
  CHECK ((state='ACCEPTED' AND orchestrator_receipt IS NOT NULL
      AND orchestrator_evidence_ref IS NOT NULL AND orchestrator_evidence_digest IS NOT NULL)
      OR state<>'ACCEPTED')
);

CREATE TABLE runtime_anomaly_authority_executions (
  tenant_id uuid NOT NULL,
  ledger_execution_id uuid NOT NULL,
  command_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  policy_decision_id text NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[0-9a-f]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (authorization_evidence_ref ~ '^evidence://'),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 256),
  trace_id text NOT NULL CHECK (length(trace_id) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN (
    'PREPARED','RESPONSE_PENDING','MUTATED_PENDING_EVIDENCE','SUCCEEDED','FAILED','UNKNOWN'
  )),
  execution_owner uuid,
  execution_lease_until timestamptz,
  result jsonb,
  result_digest char(64),
  evidence_ref text,
  evidence_digest char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,ledger_execution_id),
  UNIQUE (tenant_id,command_id),
  UNIQUE (tenant_id,idempotency_key),
  CHECK ((state='SUCCEEDED' AND result IS NOT NULL AND result_digest IS NOT NULL
      AND evidence_ref IS NOT NULL AND evidence_digest IS NOT NULL)
      OR state<>'SUCCEEDED'),
  CHECK ((execution_owner IS NULL AND execution_lease_until IS NULL)
      OR (execution_owner IS NOT NULL AND execution_lease_until IS NOT NULL))
);

CREATE TABLE runtime_anomaly_response_commands (
  tenant_id uuid NOT NULL,
  response_id uuid NOT NULL,
  task_id uuid NOT NULL,
  aggregate_id uuid NOT NULL,
  adjustment text NOT NULL CHECK (adjustment IN (
    'NO_CHANGE','REQUIRE_APPROVAL','REDUCE_SCOPE','PAUSE','REVOKE_LEASE','REVOKE_CREDENTIAL','KILL'
  )),
  new_revocation_epoch bigint NOT NULL CHECK (new_revocation_epoch >= 0),
  reason_codes text[] NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  recovery_conditions text[] NOT NULL,
  command_digest char(64) NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
  issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 256),
  key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
  signature bytea NOT NULL CHECK (octet_length(signature)=64),
  state text NOT NULL CHECK (state IN ('PENDING','DELIVERING','APPLIED','FAILED','UNKNOWN')),
  delivery_owner uuid,
  delivery_lease_until timestamptz,
  supervisor_receipt_digest char(64),
  credential_receipt_digest char(64),
  incident_receipt_digest char(64),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  applied_at timestamptz,
  PRIMARY KEY (tenant_id,response_id),
  UNIQUE (tenant_id,task_id,aggregate_id,command_digest),
  FOREIGN KEY (tenant_id,task_id) REFERENCES runtime_anomaly_trajectories(tenant_id,task_id),
  FOREIGN KEY (tenant_id,aggregate_id) REFERENCES runtime_anomaly_aggregates(tenant_id,aggregate_id),
  CHECK (cardinality(reason_codes) BETWEEN 0 AND 64),
  CHECK (cardinality(recovery_conditions) BETWEEN 0 AND 32),
  CHECK (expires_at > issued_at),
  CHECK ((state='APPLIED' AND applied_at IS NOT NULL) OR (state<>'APPLIED' AND applied_at IS NULL)),
  CHECK ((delivery_owner IS NULL AND delivery_lease_until IS NULL)
      OR (delivery_owner IS NOT NULL AND delivery_lease_until IS NOT NULL))
);

CREATE TABLE runtime_anomaly_evidence_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_kind text NOT NULL CHECK (event_kind IN (
    'SIGNAL_INGESTED','FINDING_OPENED','AGGREGATE_COMPUTED','RESPONSE_ISSUED',
    'RESPONSE_APPLIED','ADMIN_MUTATION','FEEDBACK_RECORDED','RECOVERY_AUTHORIZED'
  )),
  subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 256),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  previous_event_digest char(64),
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,event_digest)
);

CREATE TABLE runtime_anomaly_evidence_outbox (
  tenant_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  event_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 256),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('PENDING','DELIVERING','DELIVERED','UNKNOWN')),
  delivery_owner uuid,
  delivery_lease_until timestamptz,
  evidence_ref text,
  evidence_digest char(64),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000000),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id,outbox_id),
  UNIQUE (tenant_id,event_id),
  UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,event_id) REFERENCES runtime_anomaly_evidence_events(tenant_id,event_id),
  CHECK ((state='DELIVERED' AND delivered_at IS NOT NULL AND evidence_ref IS NOT NULL
      AND evidence_digest IS NOT NULL) OR (state<>'DELIVERED' AND delivered_at IS NULL)),
  CHECK ((delivery_owner IS NULL AND delivery_lease_until IS NULL)
      OR (delivery_owner IS NOT NULL AND delivery_lease_until IS NOT NULL))
);

CREATE INDEX runtime_anomaly_open_findings_idx
  ON runtime_anomaly_findings(tenant_id,task_id,severity,created_at)
  WHERE status IN ('OPEN','ACKNOWLEDGED','MITIGATING');
CREATE INDEX runtime_anomaly_response_recovery_idx
  ON runtime_anomaly_response_commands(tenant_id,state,delivery_lease_until,issued_at)
  WHERE state IN ('PENDING','DELIVERING','UNKNOWN');
CREATE INDEX runtime_anomaly_evidence_recovery_idx
  ON runtime_anomaly_evidence_outbox(tenant_id,state,delivery_lease_until,created_at)
  WHERE state IN ('PENDING','DELIVERING','UNKNOWN');

CREATE OR REPLACE FUNCTION runtime_anomaly_guard_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME='runtime_anomaly_trajectories' THEN
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.task_id<>OLD.task_id
      OR NEW.agent_instance_id<>OLD.agent_instance_id OR NEW.goal_hash<>OLD.goal_hash
      OR NEW.plan_hash<>OLD.plan_hash OR NEW.authorization_lease_id<>OLD.authorization_lease_id
      OR NEW.revocation_epoch<OLD.revocation_epoch OR NEW.event_count<OLD.event_count
      OR OLD.status IN ('KILLED','COMPLETED') AND NEW.status<>OLD.status THEN
      RAISE EXCEPTION 'RUNTIME_ANOMALY_IMMUTABLE_OR_STATE_TRANSITION';
    END IF;
  ELSIF TG_TABLE_NAME='runtime_anomaly_response_commands' THEN
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.response_id<>OLD.response_id
      OR NEW.task_id<>OLD.task_id OR NEW.aggregate_id<>OLD.aggregate_id
      OR NEW.adjustment<>OLD.adjustment OR NEW.command_digest<>OLD.command_digest
      OR NEW.signature<>OLD.signature
      OR (OLD.state='APPLIED' AND NEW.state<>'APPLIED')
      OR (OLD.state='UNKNOWN' AND NEW.state NOT IN ('UNKNOWN','APPLIED')) THEN
      RAISE EXCEPTION 'RUNTIME_ANOMALY_IMMUTABLE_OR_STATE_TRANSITION';
    END IF;
  ELSIF TG_TABLE_NAME='runtime_anomaly_authority_executions' THEN
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.ledger_execution_id<>OLD.ledger_execution_id
      OR NEW.action_hash<>OLD.action_hash OR NEW.ledger_event_digest<>OLD.ledger_event_digest
      OR NEW.fence_digest<>OLD.fence_digest
      OR (OLD.state='SUCCEEDED' AND NEW.state<>'SUCCEEDED')
      OR (OLD.state='UNKNOWN' AND NEW.state NOT IN ('UNKNOWN','MUTATED_PENDING_EVIDENCE','SUCCEEDED')) THEN
      RAISE EXCEPTION 'RUNTIME_ANOMALY_IMMUTABLE_OR_STATE_TRANSITION';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER runtime_anomaly_trajectory_guard BEFORE UPDATE ON runtime_anomaly_trajectories
  FOR EACH ROW EXECUTE FUNCTION runtime_anomaly_guard_transition();
CREATE TRIGGER runtime_anomaly_response_guard BEFORE UPDATE ON runtime_anomaly_response_commands
  FOR EACH ROW EXECUTE FUNCTION runtime_anomaly_guard_transition();
CREATE TRIGGER runtime_anomaly_execution_guard BEFORE UPDATE ON runtime_anomaly_authority_executions
  FOR EACH ROW EXECUTE FUNCTION runtime_anomaly_guard_transition();

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

DO $rls$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'runtime_anomaly_signal_sources','runtime_anomaly_trajectories','runtime_anomaly_signals',
    'runtime_anomaly_findings','runtime_anomaly_aggregates','runtime_anomaly_baselines',
    'runtime_anomaly_feedback','runtime_anomaly_cases','runtime_anomaly_action_ingress',
    'runtime_anomaly_authority_executions','runtime_anomaly_response_commands',
    'runtime_anomaly_evidence_events','runtime_anomaly_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format(
      'CREATE POLICY %I ON %I USING (tenant_id=current_setting(''app.tenant_id'',true)::uuid) WITH CHECK (tenant_id=current_setting(''app.tenant_id'',true)::uuid)',
      table_name || '_tenant_policy', table_name
    );
  END LOOP;
END $rls$;

COMMIT;
