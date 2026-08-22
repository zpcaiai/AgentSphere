BEGIN;

-- Batch 33 production authority replaces the pre-production three-table sketch.  Legacy rows are
-- retained as owner-only quarantine records; they are never silently promoted into a tenant.
CREATE SCHEMA IF NOT EXISTS security_eval_legacy;
REVOKE ALL ON SCHEMA security_eval_legacy FROM PUBLIC;
CREATE TABLE IF NOT EXISTS security_eval_legacy.security_eval_legacy_quarantine (
  quarantine_id bigserial PRIMARY KEY,
  source_table text NOT NULL,
  legacy_record jsonb NOT NULL,
  quarantine_reason text NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO security_eval_legacy.security_eval_legacy_quarantine(source_table,legacy_record,quarantine_reason)
SELECT 'attack_scenarios',to_jsonb(legacy_row),'LEGACY_UNSIGNED_OR_TENANT_UNBOUND'
FROM attack_scenarios legacy_row
ON CONFLICT DO NOTHING;
INSERT INTO security_eval_legacy.security_eval_legacy_quarantine(source_table,legacy_record,quarantine_reason)
SELECT 'security_campaigns',to_jsonb(legacy_row),'LEGACY_CONTROL_BINDING_INCOMPLETE'
FROM security_campaigns legacy_row
ON CONFLICT DO NOTHING;
INSERT INTO security_eval_legacy.security_eval_legacy_quarantine(source_table,legacy_record,quarantine_reason)
SELECT 'security_findings',to_jsonb(legacy_row),'LEGACY_REMEDIATION_CHAIN_INCOMPLETE'
FROM security_findings legacy_row
ON CONFLICT DO NOTHING;

ALTER TABLE security_findings SET SCHEMA security_eval_legacy;
ALTER TABLE security_campaigns SET SCHEMA security_eval_legacy;
ALTER TABLE attack_scenarios SET SCHEMA security_eval_legacy;
REVOKE ALL ON ALL TABLES IN SCHEMA security_eval_legacy FROM PUBLIC;

CREATE TABLE security_eval_datasets (
  tenant_id uuid NOT NULL,
  dataset_id uuid NOT NULL,
  dataset_key text NOT NULL,
  safe_name text NOT NULL,
  sensitivity text NOT NULL CHECK (sensitivity IN ('PUBLIC','INTERNAL','RESTRICTED')),
  status text NOT NULL CHECK (status IN ('ACTIVE','QUARANTINED','REVOKED')),
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,dataset_id),
  UNIQUE (tenant_id,dataset_key),
  CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  CHECK (dataset_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$')
);

CREATE TABLE security_eval_dataset_versions (
  tenant_id uuid NOT NULL,
  dataset_id uuid NOT NULL,
  version text NOT NULL,
  dataset_digest char(64) NOT NULL CHECK (dataset_digest ~ '^[0-9a-f]{64}$'),
  manifest jsonb NOT NULL,
  sample_count bigint NOT NULL CHECK (sample_count > 0 AND sample_count <= 10000000),
  signer_key_id text NOT NULL,
  signing_payload_digest char(64) NOT NULL CHECK (signing_payload_digest ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL,
  generator_name text NOT NULL,
  generator_version text NOT NULL,
  deterministic_seed bigint NOT NULL CHECK (deterministic_seed >= 0),
  immutable boolean NOT NULL CHECK (immutable),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,dataset_id,version),
  UNIQUE (tenant_id,dataset_digest),
  FOREIGN KEY (tenant_id,dataset_id) REFERENCES security_eval_datasets(tenant_id,dataset_id),
  CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$'),
  CHECK (length(signature) BETWEEN 64 AND 1024),
  CHECK (manifest ?& ARRAY['schema_version','dataset_id','version','samples_digest','categories','provenance','license'])
);

CREATE TABLE attack_scenarios (
  tenant_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  scenario_key text NOT NULL,
  version text NOT NULL,
  category text NOT NULL CHECK (category IN (
    'PROMPT_INJECTION','GOAL_HIJACK','TOOL_ABUSE','CREDENTIAL_MOVEMENT','MEMORY_POISONING',
    'MCP_DECLARATION_MISMATCH','A2A_CASCADE','IDENTITY_SPOOFING','APPROVAL_BYPASS',
    'SANDBOX_ESCAPE','SLOW_EXFILTRATION','CONTEXT_POISONING','CODING','INDUSTRIAL',
    'ENERGY','MEDICAL','SENSITIVE_INTERACTION','MARKETPLACE'
  )),
  domain_pack text NOT NULL CHECK (domain_pack IN ('COMMON','CODING','INDUSTRIAL','ENERGY','MEDICAL','SENSITIVE_INTERACTION','MARKETPLACE')),
  severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  definition jsonb NOT NULL,
  definition_digest char(64) NOT NULL CHECK (definition_digest ~ '^[0-9a-f]{64}$'),
  dataset_id uuid NOT NULL,
  dataset_version text NOT NULL,
  expected_control_ids text[] NOT NULL,
  physical_effect_mode text NOT NULL CHECK (physical_effect_mode IN ('NONE','DIGITAL_TWIN_ONLY')),
  production_target_prohibited boolean NOT NULL CHECK (production_target_prohibited),
  signer_key_id text NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,scenario_id,version),
  UNIQUE (tenant_id,scenario_key,version),
  UNIQUE (tenant_id,definition_digest),
  FOREIGN KEY (tenant_id,dataset_id,dataset_version)
    REFERENCES security_eval_dataset_versions(tenant_id,dataset_id,version),
  CHECK (cardinality(expected_control_ids) BETWEEN 1 AND 128),
  CHECK (definition ?& ARRAY['schema_version','target','preconditions','steps','expected_controls','success_criteria','failure_criteria','cleanup']),
  CHECK (length(signature) BETWEEN 64 AND 1024)
);

CREATE TABLE security_campaigns (
  tenant_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  campaign_key text NOT NULL,
  safe_name text NOT NULL,
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  baseline_id uuid,
  environment_profile text NOT NULL CHECK (environment_profile ~ '^isolated-[A-Za-z0-9._-]{1,96}$'),
  environment_attestation_digest char(64) NOT NULL CHECK (environment_attestation_digest ~ '^[0-9a-f]{64}$'),
  configuration_digest char(64) NOT NULL CHECK (configuration_digest ~ '^[0-9a-f]{64}$'),
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
  pack_digest char(64) NOT NULL CHECK (pack_digest ~ '^[0-9a-f]{64}$'),
  model_digest char(64) NOT NULL CHECK (model_digest ~ '^[0-9a-f]{64}$'),
  prompt_digest char(64) NOT NULL CHECK (prompt_digest ~ '^[0-9a-f]{64}$'),
  seed bigint NOT NULL CHECK (seed >= 0),
  maximum_steps integer NOT NULL CHECK (maximum_steps BETWEEN 1 AND 100000),
  maximum_requests integer NOT NULL CHECK (maximum_requests BETWEEN 1 AND 100000),
  maximum_tokens bigint NOT NULL CHECK (maximum_tokens BETWEEN 1 AND 1000000000),
  maximum_cost_microunits bigint NOT NULL CHECK (maximum_cost_microunits BETWEEN 1 AND 1000000000000),
  deadline_at timestamptz NOT NULL,
  target_environment text NOT NULL CHECK (target_environment IN ('EPHEMERAL_SANDBOX','ISOLATED_TENANT','DIGITAL_TWIN')),
  production_access_allowed boolean NOT NULL CHECK (NOT production_access_allowed),
  physical_effects_allowed boolean NOT NULL CHECK (NOT physical_effects_allowed),
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RUNNING','ABORTING','COMPLETED','FAILED','CLEANUP_FAILED','KILLED')),
  high_risk_regression boolean NOT NULL DEFAULT false,
  release_blocked boolean NOT NULL DEFAULT false,
  cleanup_complete boolean NOT NULL DEFAULT false,
  evidence_complete boolean NOT NULL DEFAULT false,
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,campaign_id),
  UNIQUE (tenant_id,campaign_key),
  CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  CHECK (deadline_at > created_at)
);

CREATE TABLE security_eval_campaign_scenarios (
  tenant_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  scenario_version text NOT NULL,
  scenario_digest char(64) NOT NULL CHECK (scenario_digest ~ '^[0-9a-f]{64}$'),
  deterministic_seed bigint NOT NULL CHECK (deterministic_seed >= 0),
  ordinal integer NOT NULL CHECK (ordinal > 0),
  PRIMARY KEY (tenant_id,campaign_id,scenario_id,scenario_version),
  UNIQUE (tenant_id,campaign_id,ordinal),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES security_campaigns(tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,scenario_id,scenario_version) REFERENCES attack_scenarios(tenant_id,scenario_id,version)
);

CREATE TABLE security_eval_scenario_results (
  tenant_id uuid NOT NULL,
  result_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  scenario_version text NOT NULL,
  run_id uuid NOT NULL,
  attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 32),
  status text NOT NULL CHECK (status IN ('PREVENTED','DETECTED','CONTAINED','RECOVERED','CONTROL_FAILED','RUNNER_FAILED','CLEANUP_FAILED','KILLED')),
  risk_level text NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  coverage jsonb NOT NULL,
  metric_values jsonb NOT NULL,
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
  output_digest char(64) NOT NULL CHECK (output_digest ~ '^[0-9a-f]{64}$'),
  evidence_refs text[] NOT NULL,
  cleanup_receipt_digest char(64) NOT NULL CHECK (cleanup_receipt_digest ~ '^[0-9a-f]{64}$'),
  production_access_detected boolean NOT NULL CHECK (NOT production_access_detected),
  physical_side_effect_detected boolean NOT NULL CHECK (NOT physical_side_effect_detected),
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,result_id),
  UNIQUE (tenant_id,campaign_id,scenario_id,scenario_version,run_id,attempt),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES security_campaigns(tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,scenario_id,scenario_version) REFERENCES attack_scenarios(tenant_id,scenario_id,version),
  CHECK (cardinality(evidence_refs) BETWEEN 1 AND 128),
  CHECK (completed_at >= started_at),
  CHECK (coverage ?& ARRAY['threat_surfaces','control_ids','domain_packs','sample_count'])
);

CREATE TABLE security_findings (
  tenant_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  result_id uuid NOT NULL,
  severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  risk_type text NOT NULL,
  control_ids text[] NOT NULL,
  policy_refs text[] NOT NULL,
  evidence_refs text[] NOT NULL,
  safe_summary text NOT NULL,
  status text NOT NULL CHECK (status IN ('OPEN','ACCEPTED','REMEDIATING','FIXED','RETESTING','VERIFIED','REJECTED')),
  remediation_required boolean NOT NULL,
  retest_required boolean NOT NULL,
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,finding_id),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES security_campaigns(tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,result_id) REFERENCES security_eval_scenario_results(tenant_id,result_id),
  CHECK (cardinality(control_ids) BETWEEN 1 AND 128),
  CHECK (cardinality(policy_refs) BETWEEN 1 AND 128),
  CHECK (cardinality(evidence_refs) BETWEEN 1 AND 128),
  CHECK (length(safe_summary) BETWEEN 1 AND 2048),
  CHECK (severity NOT IN ('HIGH','CRITICAL') OR (remediation_required AND retest_required))
);

CREATE TABLE security_eval_remediations (
  tenant_id uuid NOT NULL,
  remediation_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  owner_subject text NOT NULL,
  change_ref text NOT NULL,
  change_digest char(64) NOT NULL CHECK (change_digest ~ '^[0-9a-f]{64}$'),
  due_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('PLANNED','IN_PROGRESS','READY_FOR_RETEST','CLOSED','REJECTED')),
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,remediation_id),
  UNIQUE (tenant_id,finding_id,change_digest),
  FOREIGN KEY (tenant_id,finding_id) REFERENCES security_findings(tenant_id,finding_id)
);

CREATE TABLE security_eval_retests (
  tenant_id uuid NOT NULL,
  retest_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  remediation_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  candidate_result_id uuid NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('PASSED','FAILED','INCONCLUSIVE')),
  evidence_refs text[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,retest_id),
  UNIQUE (tenant_id,finding_id,remediation_id,candidate_result_id),
  FOREIGN KEY (tenant_id,finding_id) REFERENCES security_findings(tenant_id,finding_id),
  FOREIGN KEY (tenant_id,remediation_id) REFERENCES security_eval_remediations(tenant_id,remediation_id),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES security_campaigns(tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,candidate_result_id) REFERENCES security_eval_scenario_results(tenant_id,result_id),
  CHECK (cardinality(evidence_refs) BETWEEN 1 AND 128)
);

CREATE TABLE security_eval_baselines (
  tenant_id uuid NOT NULL,
  baseline_id uuid NOT NULL,
  baseline_key text NOT NULL,
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  configuration_digest char(64) NOT NULL CHECK (configuration_digest ~ '^[0-9a-f]{64}$'),
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
  pack_digest char(64) NOT NULL CHECK (pack_digest ~ '^[0-9a-f]{64}$'),
  model_digest char(64) NOT NULL CHECK (model_digest ~ '^[0-9a-f]{64}$'),
  metrics jsonb NOT NULL,
  coverage jsonb NOT NULL,
  sample_count bigint NOT NULL CHECK (sample_count > 0),
  source_report_id uuid NOT NULL,
  report_digest char(64) NOT NULL CHECK (report_digest ~ '^[0-9a-f]{64}$'),
  key_id text NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,baseline_id),
  UNIQUE (tenant_id,baseline_key,release_digest),
  UNIQUE (tenant_id,source_report_id),
  CHECK (length(signature) BETWEEN 64 AND 1024)
);

CREATE TABLE security_eval_reports (
  tenant_id uuid NOT NULL,
  report_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  baseline_id uuid,
  report_digest char(64) NOT NULL CHECK (report_digest ~ '^[0-9a-f]{64}$'),
  report jsonb NOT NULL,
  risk_summary jsonb NOT NULL,
  coverage jsonb NOT NULL,
  sample_count bigint NOT NULL CHECK (sample_count > 0),
  high_risk_regression boolean NOT NULL,
  release_blocked boolean NOT NULL,
  cleanup_complete boolean NOT NULL,
  evidence_complete boolean NOT NULL,
  key_id text NOT NULL,
  signature text NOT NULL,
  attestation_class text NOT NULL CHECK (attestation_class='ENGINE_EVALUATION_ONLY'),
  production_certified boolean NOT NULL CHECK (NOT production_certified),
  generated_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,report_id),
  UNIQUE (tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES security_campaigns(tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,baseline_id) REFERENCES security_eval_baselines(tenant_id,baseline_id),
  CHECK (length(signature) BETWEEN 64 AND 1024),
  CHECK (report ?& ARRAY['schema_version','campaign_id','release_digest','metrics','risk_summary','coverage'])
);

CREATE TABLE security_eval_kill_switches (
  tenant_id uuid NOT NULL,
  switch_id uuid NOT NULL,
  environment_profile text NOT NULL,
  state text NOT NULL CHECK (state IN ('ARMED','TRIPPED')),
  reason_code text NOT NULL,
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  activated_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,switch_id),
  UNIQUE (tenant_id,environment_profile),
  CHECK (environment_profile ~ '^isolated-[A-Za-z0-9._-]{1,96}$'),
  CHECK ((state='TRIPPED')=(activated_at IS NOT NULL))
);

CREATE TABLE security_eval_resource_versions (
  tenant_id uuid NOT NULL,
  resource_id text NOT NULL,
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  last_action_hash char(64) CHECK (last_action_hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,resource_id)
);

CREATE TABLE security_eval_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  resource_id text NOT NULL,
  operation text NOT NULL,
  actor_subject text NOT NULL,
  envelope jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED','UNKNOWN')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id)
);

CREATE TABLE security_eval_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  resource_id text NOT NULL,
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  policy_decision_id text NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[0-9a-f]{64}$'),
  authorization_evidence_ref text NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('PREPARED','RUNNER_PENDING','MUTATED_PENDING_EVIDENCE','SUCCEEDED','FAILED','UNKNOWN')),
  lease_expires_at timestamptz NOT NULL,
  result jsonb,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,ledger_execution_id),
  UNIQUE (tenant_id,ledger_event_id)
);

CREATE TABLE security_eval_evidence_events (
  tenant_id uuid NOT NULL,
  evidence_event_id uuid NOT NULL,
  event_type text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[0-9a-f]{64}$'),
  authorization_evidence_ref text NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
  payload jsonb NOT NULL,
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,evidence_event_id)
);

CREATE TABLE security_eval_evidence_outbox (
  tenant_id uuid NOT NULL,
  evidence_event_id uuid NOT NULL,
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  payload jsonb NOT NULL,
  publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts BETWEEN 0 AND 32),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  authority_receipt_ref text,
  authority_receipt_digest char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,evidence_event_id),
  FOREIGN KEY (tenant_id,evidence_event_id) REFERENCES security_eval_evidence_events(tenant_id,evidence_event_id),
  CHECK ((published_at IS NULL AND authority_receipt_ref IS NULL AND authority_receipt_digest IS NULL)
      OR (published_at IS NOT NULL AND authority_receipt_ref IS NOT NULL
          AND authority_receipt_digest ~ '^[0-9a-f]{64}$'))
);

CREATE OR REPLACE FUNCTION reject_security_eval_immutable_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  RAISE EXCEPTION 'SECURITY_EVAL_IMMUTABLE_RECORD';
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_resource_fence()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.resource_id<>OLD.resource_id
     OR NEW.resource_version<>OLD.resource_version+1
     OR NEW.last_action_hash IS NULL OR NEW.last_action_hash=OLD.last_action_hash THEN
    RAISE EXCEPTION 'SECURITY_EVAL_RESOURCE_FENCE_INVALID';
  END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_campaign_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.campaign_id<>OLD.campaign_id
     OR NEW.campaign_key<>OLD.campaign_key OR NEW.release_digest<>OLD.release_digest
     OR NEW.environment_profile<>OLD.environment_profile
     OR NEW.environment_attestation_digest<>OLD.environment_attestation_digest
     OR NEW.configuration_digest<>OLD.configuration_digest OR NEW.policy_digest<>OLD.policy_digest
     OR NEW.pack_digest<>OLD.pack_digest OR NEW.model_digest<>OLD.model_digest
     OR NEW.prompt_digest<>OLD.prompt_digest OR NEW.seed<>OLD.seed
     OR NEW.target_environment<>OLD.target_environment
     OR NEW.production_access_allowed OR NEW.physical_effects_allowed
     OR NEW.resource_version<>OLD.resource_version+1 OR NOT (
       (OLD.status='DRAFT' AND NEW.status IN ('DRAFT','APPROVED','FAILED')) OR
       (OLD.status='APPROVED' AND NEW.status IN ('APPROVED','RUNNING','FAILED','KILLED')) OR
       (OLD.status='RUNNING' AND NEW.status IN ('RUNNING','ABORTING','COMPLETED','FAILED','CLEANUP_FAILED','KILLED')) OR
       (OLD.status='ABORTING' AND NEW.status IN ('FAILED','CLEANUP_FAILED','KILLED')) OR
       (OLD.status IN ('COMPLETED','FAILED','CLEANUP_FAILED','KILLED') AND NEW.status=OLD.status)
     ) THEN RAISE EXCEPTION 'SECURITY_EVAL_CAMPAIGN_TRANSITION_INVALID'; END IF;
  IF NEW.status='COMPLETED' AND (NOT NEW.cleanup_complete OR NOT NEW.evidence_complete) THEN
    RAISE EXCEPTION 'SECURITY_EVAL_CAMPAIGN_EVIDENCE_INCOMPLETE';
  END IF;
  IF NEW.high_risk_regression AND NOT NEW.release_blocked THEN
    RAISE EXCEPTION 'SECURITY_EVAL_HIGH_RISK_REGRESSION_NOT_BLOCKED';
  END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.idempotency_key<>OLD.idempotency_key
     OR NEW.request_digest<>OLD.request_digest OR NEW.action_hash<>OLD.action_hash
     OR NEW.ledger_execution_id<>OLD.ledger_execution_id OR NEW.ledger_event_id<>OLD.ledger_event_id
     OR NEW.ledger_event_digest<>OLD.ledger_event_digest OR NEW.fence_digest<>OLD.fence_digest
     OR NEW.resource_id<>OLD.resource_id OR NEW.resource_version<>OLD.resource_version
     OR NEW.policy_decision_id<>OLD.policy_decision_id
     OR NEW.policy_decision_digest<>OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref<>OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest<>OLD.authorization_evidence_digest OR NOT (
       (OLD.state='PREPARED' AND NEW.state IN ('RUNNER_PENDING','MUTATED_PENDING_EVIDENCE','FAILED','UNKNOWN')) OR
       (OLD.state='RUNNER_PENDING' AND NEW.state IN ('MUTATED_PENDING_EVIDENCE','FAILED','UNKNOWN')) OR
       (OLD.state='MUTATED_PENDING_EVIDENCE' AND NEW.state IN ('SUCCEEDED','UNKNOWN')) OR
       (OLD.state IN ('SUCCEEDED','FAILED','UNKNOWN') AND NEW.state=OLD.state)
     ) THEN RAISE EXCEPTION 'SECURITY_EVAL_EXECUTION_TRANSITION_INVALID'; END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_ingress_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.idempotency_key<>OLD.idempotency_key
     OR NEW.request_digest<>OLD.request_digest OR NEW.action_id<>OLD.action_id
     OR NEW.task_id<>OLD.task_id OR NEW.resource_id<>OLD.resource_id
     OR NEW.operation<>OLD.operation OR NEW.actor_subject<>OLD.actor_subject
     OR NEW.envelope<>OLD.envelope OR NOT (
       (OLD.state='PREPARED' AND NEW.state IN ('ACCEPTED','UNKNOWN')) OR NEW.state=OLD.state
     ) THEN RAISE EXCEPTION 'SECURITY_EVAL_INGRESS_TRANSITION_INVALID'; END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_dataset_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.dataset_id<>OLD.dataset_id
     OR NEW.dataset_key<>OLD.dataset_key OR NEW.safe_name<>OLD.safe_name
     OR NEW.sensitivity<>OLD.sensitivity OR NEW.resource_version<>OLD.resource_version+1
     OR NOT ((OLD.status='ACTIVE' AND NEW.status IN ('ACTIVE','QUARANTINED','REVOKED'))
             OR (OLD.status IN ('QUARANTINED','REVOKED') AND NEW.status=OLD.status)) THEN
    RAISE EXCEPTION 'SECURITY_EVAL_DATASET_TRANSITION_INVALID';
  END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_finding_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.finding_id<>OLD.finding_id
     OR NEW.campaign_id<>OLD.campaign_id OR NEW.result_id<>OLD.result_id
     OR NEW.severity<>OLD.severity OR NEW.risk_type<>OLD.risk_type
     OR NEW.control_ids<>OLD.control_ids OR NEW.policy_refs<>OLD.policy_refs
     OR NEW.evidence_refs<>OLD.evidence_refs OR NEW.safe_summary<>OLD.safe_summary
     OR NEW.remediation_required<>OLD.remediation_required OR NEW.retest_required<>OLD.retest_required
     OR NEW.resource_version<>OLD.resource_version+1 OR NOT (
       (OLD.status='OPEN' AND NEW.status IN ('OPEN','ACCEPTED','REMEDIATING','REJECTED')) OR
       (OLD.status='ACCEPTED' AND NEW.status IN ('ACCEPTED','REMEDIATING','REJECTED')) OR
       (OLD.status='REMEDIATING' AND NEW.status IN ('REMEDIATING','FIXED','RETESTING','OPEN')) OR
       (OLD.status='FIXED' AND NEW.status IN ('FIXED','RETESTING','OPEN')) OR
       (OLD.status='RETESTING' AND NEW.status IN ('VERIFIED','OPEN')) OR
       (OLD.status IN ('VERIFIED','REJECTED') AND NEW.status=OLD.status)
     ) THEN RAISE EXCEPTION 'SECURITY_EVAL_FINDING_TRANSITION_INVALID'; END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_remediation_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.remediation_id<>OLD.remediation_id
     OR NEW.finding_id<>OLD.finding_id OR NEW.owner_subject<>OLD.owner_subject
     OR NEW.change_ref<>OLD.change_ref OR NEW.change_digest<>OLD.change_digest
     OR NEW.due_at<>OLD.due_at OR NEW.resource_version<>OLD.resource_version+1 OR NOT (
       (OLD.status='PLANNED' AND NEW.status IN ('PLANNED','IN_PROGRESS','READY_FOR_RETEST','REJECTED')) OR
       (OLD.status='IN_PROGRESS' AND NEW.status IN ('IN_PROGRESS','READY_FOR_RETEST','REJECTED')) OR
       (OLD.status='READY_FOR_RETEST' AND NEW.status IN ('IN_PROGRESS','CLOSED','REJECTED')) OR
       (OLD.status IN ('CLOSED','REJECTED') AND NEW.status=OLD.status)
     ) THEN RAISE EXCEPTION 'SECURITY_EVAL_REMEDIATION_TRANSITION_INVALID'; END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_kill_switch_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.switch_id<>OLD.switch_id
     OR NEW.environment_profile<>OLD.environment_profile OR NEW.resource_version<>OLD.resource_version+1
     OR NOT (OLD.state='ARMED' AND NEW.state='TRIPPED')
     OR NEW.activated_at IS NULL THEN RAISE EXCEPTION 'SECURITY_EVAL_KILL_SWITCH_TRANSITION_INVALID'; END IF;
  NEW.updated_at:=now(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_security_eval_outbox_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.evidence_event_id<>OLD.evidence_event_id
     OR NEW.event_digest<>OLD.event_digest OR NEW.payload<>OLD.payload OR NEW.created_at<>OLD.created_at
     OR NEW.publish_attempts<OLD.publish_attempts OR NEW.publish_attempts>OLD.publish_attempts+1
     OR (OLD.published_at IS NOT NULL AND (NEW.published_at<>OLD.published_at
         OR NEW.authority_receipt_ref<>OLD.authority_receipt_ref
         OR NEW.authority_receipt_digest<>OLD.authority_receipt_digest))
     OR (NEW.published_at IS NULL AND (NEW.authority_receipt_ref IS NOT NULL OR NEW.authority_receipt_digest IS NOT NULL))
     OR (NEW.published_at IS NOT NULL AND (NEW.authority_receipt_ref IS NULL
         OR NEW.authority_receipt_digest !~ '^[0-9a-f]{64}$')) THEN
    RAISE EXCEPTION 'SECURITY_EVAL_OUTBOX_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER security_eval_dataset_versions_immutable BEFORE UPDATE OR DELETE ON security_eval_dataset_versions
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_scenarios_immutable BEFORE UPDATE OR DELETE ON attack_scenarios
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_results_immutable BEFORE UPDATE OR DELETE ON security_eval_scenario_results
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_retests_immutable BEFORE UPDATE OR DELETE ON security_eval_retests
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_baselines_immutable BEFORE UPDATE OR DELETE ON security_eval_baselines
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_reports_immutable BEFORE UPDATE OR DELETE ON security_eval_reports
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_evidence_immutable BEFORE UPDATE OR DELETE ON security_eval_evidence_events
FOR EACH ROW EXECUTE FUNCTION reject_security_eval_immutable_change();
CREATE TRIGGER security_eval_resource_fence_guard BEFORE UPDATE ON security_eval_resource_versions
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_resource_fence();
CREATE TRIGGER security_eval_campaign_transition_guard BEFORE UPDATE ON security_campaigns
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_campaign_transition();
CREATE TRIGGER security_eval_execution_transition_guard BEFORE UPDATE ON security_eval_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_execution_transition();
CREATE TRIGGER security_eval_ingress_transition_guard BEFORE UPDATE ON security_eval_action_ingress
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_ingress_transition();
CREATE TRIGGER security_eval_dataset_transition_guard BEFORE UPDATE ON security_eval_datasets
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_dataset_transition();
CREATE TRIGGER security_eval_finding_transition_guard BEFORE UPDATE ON security_findings
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_finding_transition();
CREATE TRIGGER security_eval_remediation_transition_guard BEFORE UPDATE ON security_eval_remediations
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_remediation_transition();
CREATE TRIGGER security_eval_kill_switch_transition_guard BEFORE UPDATE ON security_eval_kill_switches
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_kill_switch_transition();
CREATE TRIGGER security_eval_outbox_transition_guard BEFORE UPDATE ON security_eval_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_security_eval_outbox_transition();

DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'security_eval_datasets','security_eval_dataset_versions','attack_scenarios','security_campaigns',
    'security_eval_campaign_scenarios','security_eval_scenario_results','security_findings',
    'security_eval_remediations','security_eval_retests','security_eval_baselines','security_eval_reports',
    'security_eval_kill_switches','security_eval_resource_versions','security_eval_action_ingress',
    'security_eval_authority_executions','security_eval_evidence_events','security_eval_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('CREATE POLICY security_eval_tenant_isolation ON %I USING '
      '(tenant_id::text=current_setting(''app.tenant_id'',true)) WITH CHECK '
      '(tenant_id::text=current_setting(''app.tenant_id'',true))',table_name);
  END LOOP;
END $$;

CREATE INDEX security_eval_campaign_status_idx ON security_campaigns(tenant_id,status,updated_at);
CREATE INDEX security_eval_results_campaign_idx ON security_eval_scenario_results(tenant_id,campaign_id,created_at);
CREATE INDEX security_eval_findings_status_idx ON security_findings(tenant_id,status,severity,updated_at);
CREATE INDEX security_eval_executions_state_idx ON security_eval_authority_executions(tenant_id,state,updated_at);
CREATE INDEX security_eval_outbox_pending_idx ON security_eval_evidence_outbox(tenant_id,next_attempt_at)
  WHERE published_at IS NULL;

REVOKE ALL ON TABLE security_eval_datasets,
  security_eval_dataset_versions,attack_scenarios,security_campaigns,
  security_eval_campaign_scenarios,security_eval_scenario_results,security_findings,
  security_eval_remediations,security_eval_retests,security_eval_baselines,security_eval_reports,
  security_eval_kill_switches,security_eval_resource_versions,security_eval_action_ingress,
  security_eval_authority_executions,security_eval_evidence_events,security_eval_evidence_outbox
  FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_security_eval_immutable_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_resource_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_campaign_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_ingress_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_dataset_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_finding_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_remediation_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_kill_switch_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_security_eval_outbox_transition() FROM PUBLIC;

-- The production migration runner creates the NOINHERIT LOGIN role and exact table/column grants.
-- No runtime credential is created or broadened by this migration.
COMMIT;
