BEGIN;

CREATE TABLE IF NOT EXISTS policy_sources (
  tenant_id uuid NOT NULL,
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  revision bigint NOT NULL CHECK (revision > 0),
  version text NOT NULL CHECK (length(version) BETWEEN 1 AND 128),
  author_subject text NOT NULL CHECK (length(author_subject) BETWEEN 1 AND 256),
  source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
  source_json jsonb NOT NULL CHECK (
    source_json->>'schema_version' = 'agenttrust.policy-admin.v1'
    AND source_json->>'source_id' = policy_id
    AND source_json->>'source_digest' = source_digest
    AND source_json->>'author' = author_subject
    AND source_json #>> '{tenant_id}' = tenant_id::text
  ),
  lifecycle_state text NOT NULL CHECK (
    lifecycle_state IN ('DRAFT','VALIDATED','REVIEW','SIGNED','DEPRECATED')
  ),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, policy_id, revision),
  UNIQUE (tenant_id, policy_id, source_digest)
);

CREATE TABLE IF NOT EXISTS policy_analysis_results (
  tenant_id uuid NOT NULL,
  policy_id text NOT NULL,
  revision bigint NOT NULL,
  analysis_digest char(64) NOT NULL CHECK (analysis_digest ~ '^[a-f0-9]{64}$'),
  valid boolean NOT NULL,
  findings jsonb NOT NULL CHECK (
    findings->>'schema_version' = 'agenttrust.policy-static-analysis.v1'
    AND findings->>'policy_id' = policy_id
    AND (findings->>'revision')::bigint = revision
    AND (findings->>'valid')::boolean = valid
  ),
  analyzed_by text NOT NULL CHECK (length(analyzed_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, policy_id, revision),
  UNIQUE (tenant_id, analysis_digest),
  FOREIGN KEY (tenant_id, policy_id, revision)
    REFERENCES policy_sources (tenant_id, policy_id, revision)
);

CREATE TABLE IF NOT EXISTS policy_simulation_runs (
  tenant_id uuid NOT NULL,
  simulation_id uuid NOT NULL,
  policy_id text NOT NULL,
  revision bigint NOT NULL,
  run_kind text NOT NULL CHECK (run_kind IN ('SIMULATION','SHADOW')),
  baseline_bundle_digest char(64) NOT NULL CHECK (baseline_bundle_digest ~ '^[a-f0-9]{64}$'),
  candidate_source_digest char(64) NOT NULL CHECK (candidate_source_digest ~ '^[a-f0-9]{64}$'),
  corpus_digest char(64) NOT NULL CHECK (corpus_digest ~ '^[a-f0-9]{64}$'),
  evaluated_actions bigint NOT NULL CHECK (evaluated_actions BETWEEN 1 AND 10000),
  difference_count bigint NOT NULL CHECK (difference_count BETWEEN 0 AND evaluated_actions),
  side_effect_count bigint NOT NULL CHECK (side_effect_count = 0),
  impact_report_digest char(64) NOT NULL CHECK (impact_report_digest ~ '^[a-f0-9]{64}$'),
  impact_report jsonb NOT NULL CHECK (
    impact_report->>'schema_version' = 'agenttrust.policy-admin.v1'
    AND (impact_report->>'side_effect_count')::bigint = 0
  ),
  run_by text NOT NULL CHECK (length(run_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, simulation_id),
  UNIQUE (tenant_id, impact_report_digest),
  FOREIGN KEY (tenant_id, policy_id, revision)
    REFERENCES policy_sources (tenant_id, policy_id, revision)
);

CREATE TABLE IF NOT EXISTS policy_impact_reports (
  tenant_id uuid NOT NULL,
  impact_report_id uuid NOT NULL,
  policy_id text NOT NULL,
  revision bigint NOT NULL,
  simulation_id uuid NOT NULL,
  impact_report_digest char(64) NOT NULL CHECK (impact_report_digest ~ '^[a-f0-9]{64}$'),
  impact_report jsonb NOT NULL CHECK (
    impact_report->>'schema_version' = 'agenttrust.policy-impact-report.v1'
    AND impact_report->>'impact_report_id' = impact_report_id::text
    AND impact_report->>'tenant_id' = tenant_id::text
    AND impact_report->>'policy_id' = policy_id
    AND impact_report->>'impact_report_digest' = impact_report_digest
  ),
  generated_by text NOT NULL CHECK (length(generated_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, impact_report_id),
  UNIQUE (tenant_id, impact_report_digest),
  FOREIGN KEY (tenant_id, simulation_id)
    REFERENCES policy_simulation_runs (tenant_id, simulation_id),
  FOREIGN KEY (tenant_id, policy_id, revision)
    REFERENCES policy_sources (tenant_id, policy_id, revision)
);

CREATE TABLE IF NOT EXISTS policy_reviews (
  tenant_id uuid NOT NULL,
  policy_id text NOT NULL,
  revision bigint NOT NULL,
  review_id uuid NOT NULL,
  reviewer_subject text NOT NULL CHECK (length(reviewer_subject) BETWEEN 1 AND 256),
  decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  review_digest char(64) NOT NULL CHECK (review_digest ~ '^[a-f0-9]{64}$'),
  reviewed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, review_id),
  UNIQUE (tenant_id, policy_id, revision, reviewer_subject),
  FOREIGN KEY (tenant_id, policy_id, revision)
    REFERENCES policy_sources (tenant_id, policy_id, revision)
);

ALTER TABLE policy_bundles
  ADD COLUMN IF NOT EXISTS policy_id text,
  ADD COLUMN IF NOT EXISTS revision bigint,
  ADD COLUMN IF NOT EXISTS analysis_digest char(64),
  ADD COLUMN IF NOT EXISTS bundle_json jsonb,
  ADD COLUMN IF NOT EXISTS signed_at timestamptz,
  ADD COLUMN IF NOT EXISTS deprecated_at timestamptz;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM policy_bundles
    WHERE policy_id IS NULL OR revision IS NULL OR analysis_digest IS NULL
       OR bundle_json IS NULL OR signed_at IS NULL
  ) THEN
    RAISE EXCEPTION 'POLICY_BUNDLE_PRODUCTION_BACKFILL_REQUIRED';
  END IF;
END $$;

ALTER TABLE policy_bundles
  ALTER COLUMN policy_id SET NOT NULL,
  ALTER COLUMN revision SET NOT NULL,
  ALTER COLUMN analysis_digest SET NOT NULL,
  ALTER COLUMN bundle_json SET NOT NULL,
  ALTER COLUMN signed_at SET NOT NULL;

ALTER TABLE policy_bundles DROP CONSTRAINT IF EXISTS policy_bundles_status_check;
ALTER TABLE policy_bundles ADD CONSTRAINT policy_bundles_status_check CHECK (
  status IN ('DRAFT','REVIEW','SIGNED','CANARY','ACTIVE','ROLLED_BACK','REVOKED','DEPRECATED')
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.policy_bundles'::regclass
      AND conname='policy_bundles_compiled_digest_unique'
  ) THEN
    ALTER TABLE policy_bundles
      ADD CONSTRAINT policy_bundles_compiled_digest_unique
      UNIQUE (tenant_id, compiled_digest);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.policy_bundles'::regclass
      AND conname='policy_bundles_source_fk'
  ) THEN
    ALTER TABLE policy_bundles
      ADD CONSTRAINT policy_bundles_source_fk
      FOREIGN KEY (tenant_id, policy_id, revision)
      REFERENCES policy_sources (tenant_id, policy_id, revision) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.policy_bundles'::regclass
      AND conname='policy_bundles_json_binding_check'
  ) THEN
    ALTER TABLE policy_bundles ADD CONSTRAINT policy_bundles_json_binding_check CHECK (
      bundle_json->>'schema_version' = 'agenttrust.signed-policy-bundle.v1'
      AND bundle_json->>'bundle_id' = bundle_id
      AND bundle_json->>'policy_id' = policy_id
      AND (bundle_json->>'source_revision')::bigint = revision
      AND bundle_json->>'version' = version
      AND bundle_json->>'source_digest' = source_digest
      AND bundle_json->>'bundle_digest' = compiled_digest
      AND bundle_json->>'key_id' = key_id
      AND bundle_json #>> '{tenant_id}' = tenant_id::text
      AND analysis_digest ~ '^[a-f0-9]{64}$'
      AND revision > 0
      AND octet_length(signature) = 64
      AND (deprecated_at IS NULL OR deprecated_at >= signed_at)
    ) NOT VALID;
  END IF;
END $$;

ALTER TABLE policy_bundles VALIDATE CONSTRAINT policy_bundles_source_fk;
ALTER TABLE policy_bundles VALIDATE CONSTRAINT policy_bundles_json_binding_check;

ALTER TABLE policy_exceptions
  ADD COLUMN IF NOT EXISTS policy_id text,
  ADD COLUMN IF NOT EXISTS reason_digest char(64),
  ADD COLUMN IF NOT EXISTS issued_by text,
  ADD COLUMN IF NOT EXISTS revocation_reason_digest char(64),
  ADD COLUMN IF NOT EXISTS expired_at timestamptz,
  ADD COLUMN IF NOT EXISTS created_at timestamptz;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM policy_exceptions
    WHERE policy_id IS NULL OR reason_digest IS NULL OR issued_by IS NULL OR created_at IS NULL
  ) THEN
    RAISE EXCEPTION 'POLICY_EXCEPTION_PRODUCTION_BACKFILL_REQUIRED';
  END IF;
END $$;

ALTER TABLE policy_exceptions
  ALTER COLUMN policy_id SET NOT NULL,
  ALTER COLUMN reason_digest SET NOT NULL,
  ALTER COLUMN issued_by SET NOT NULL,
  ALTER COLUMN created_at SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.policy_exceptions'::regclass
      AND conname='policy_exception_production_check'
  ) THEN
    ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exception_production_check CHECK (
      length(policy_id) BETWEEN 1 AND 256
      AND reason_digest ~ '^[a-f0-9]{64}$'
      AND length(issued_by) BETWEEN 1 AND 256
      AND jsonb_typeof(approver_subjects)='array'
      AND jsonb_array_length(approver_subjects) BETWEEN 2 AND 64
      AND jsonb_typeof(compensating_controls)='array'
      AND jsonb_array_length(compensating_controls) BETWEEN 1 AND 64
      AND expires_at > created_at
      AND expires_at <= created_at + interval '30 days'
      AND NOT (revoked_at IS NOT NULL AND expired_at IS NOT NULL)
      AND (revoked_at IS NULL OR revocation_reason_digest ~ '^[a-f0-9]{64}$')
    ) NOT VALID;
  END IF;
END $$;
ALTER TABLE policy_exceptions VALIDATE CONSTRAINT policy_exception_production_check;

CREATE TABLE IF NOT EXISTS policy_promotions (
  tenant_id uuid NOT NULL,
  policy_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('DEV','STAGING','CANARY','PRODUCTION')),
  sequence bigint NOT NULL CHECK (sequence > 0),
  bundle_digest char(64) NOT NULL CHECK (bundle_digest ~ '^[a-f0-9]{64}$'),
  previous_bundle_digest char(64),
  rollback_of bigint,
  promoted_by text NOT NULL CHECK (length(promoted_by) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('PENDING_ACTIVATION','UNKNOWN','ACTIVE','SUPERSEDED','ROLLED_BACK')),
  promotion_digest char(64) NOT NULL CHECK (promotion_digest ~ '^[a-f0-9]{64}$'),
  promoted_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, policy_id, environment, sequence),
  UNIQUE (tenant_id, promotion_digest),
  UNIQUE (tenant_id, environment, sequence),
  FOREIGN KEY (tenant_id, bundle_digest)
    REFERENCES policy_bundles (tenant_id, compiled_digest),
  CHECK (previous_bundle_digest IS NULL OR previous_bundle_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state IN ('PENDING_ACTIVATION','UNKNOWN','ACTIVE')) = (completed_at IS NULL)),
  CHECK (rollback_of IS NULL OR rollback_of < sequence)
);

DROP INDEX IF EXISTS policy_promotions_single_active_idx;
CREATE UNIQUE INDEX policy_promotions_single_active_idx
  ON policy_promotions (tenant_id, environment) WHERE state='ACTIVE';
CREATE UNIQUE INDEX IF NOT EXISTS policy_promotions_single_unresolved_idx
  ON policy_promotions (tenant_id, environment)
  WHERE state IN ('PENDING_ACTIVATION','UNKNOWN');

CREATE TABLE IF NOT EXISTS policy_activation_intents (
  tenant_id uuid NOT NULL,
  activation_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (
    length(idempotency_key) BETWEEN 16 AND 128
    AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  environment text NOT NULL CHECK (environment IN ('DEV','STAGING','CANARY','PRODUCTION')),
  sequence bigint NOT NULL CHECK (sequence > 0),
  bundle_digest char(64) NOT NULL CHECK (bundle_digest ~ '^[a-f0-9]{64}$'),
  previous_bundle_digest char(64),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  request_body jsonb NOT NULL CHECK (
    request_body->>'schema_version' = 'agenttrust.policy-activation-request.v1'
    AND request_body->>'activation_id' = activation_id::text
    AND request_body->>'idempotency_key' = idempotency_key
    AND request_body->>'policy_id' = policy_id
    AND request_body->>'environment' = environment
    AND (request_body->>'sequence')::bigint = sequence
    AND COALESCE(request_body->>'previous_bundle_digest','') = COALESCE(previous_bundle_digest,'')
    AND request_body #>> '{tenant_id}' = tenant_id::text
    AND request_body #>> '{bundle,bundle_digest}' = bundle_digest
  ),
  state text NOT NULL CHECK (state IN ('PENDING','UNKNOWN','ACTIVE')),
  claim_owner uuid NOT NULL,
  claim_expires_at timestamptz NOT NULL,
  acknowledgement_digest char(64),
  acknowledgement jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  PRIMARY KEY (tenant_id, activation_id),
  UNIQUE (tenant_id, environment, idempotency_key),
  UNIQUE (tenant_id, environment, sequence),
  FOREIGN KEY (tenant_id, policy_id, environment, sequence)
    REFERENCES policy_promotions (tenant_id, policy_id, environment, sequence),
  CHECK (previous_bundle_digest IS NULL OR previous_bundle_digest ~ '^[a-f0-9]{64}$'),
  CHECK (
    (state IN ('PENDING','UNKNOWN') AND acknowledgement_digest IS NULL
      AND acknowledgement IS NULL AND activated_at IS NULL)
    OR (state='ACTIVE' AND acknowledgement_digest ~ '^[a-f0-9]{64}$'
      AND jsonb_typeof(acknowledgement)='object' AND activated_at IS NOT NULL
      AND acknowledgement->>'schema_version'='agenttrust.pep-policy-activation-ack.v1'
      AND acknowledgement->>'activation_id'=activation_id::text
      AND acknowledgement->>'idempotency_key'=idempotency_key
      AND acknowledgement->>'policy_id'=policy_id
      AND acknowledgement->>'environment'=environment
      AND (acknowledgement->>'sequence')::bigint=sequence
      AND acknowledgement->>'bundle_digest'=bundle_digest
      AND acknowledgement #>> '{tenant_id}'=tenant_id::text
      AND acknowledgement->>'active'='true'
      AND (acknowledgement->>'acknowledged_at')::timestamptz=activated_at)
  )
);

CREATE TABLE IF NOT EXISTS policy_resource_versions (
  tenant_id uuid NOT NULL,
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, policy_id),
  UNIQUE (tenant_id, ledger_execution_id)
);

CREATE TABLE IF NOT EXISTS policy_principal_assertion_replay (
  tenant_id uuid NOT NULL,
  jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL CHECK (assertion_digest ~ '^[a-f0-9]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, jti),
  CHECK (expires_at > consumed_at - interval '30 seconds')
);

CREATE TABLE IF NOT EXISTS policy_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (
    length(idempotency_key) BETWEEN 16 AND 128
    AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  principal_subject text NOT NULL CHECK (length(principal_subject) BETWEEN 1 AND 256),
  principal_assertion_digest char(64) NOT NULL CHECK (principal_assertion_digest ~ '^[a-f0-9]{64}$'),
  envelope jsonb NOT NULL CHECK (
    envelope->>'schema_version' = 'agenttrust.gateway.v1'
    AND envelope->>'idempotency_key' = idempotency_key
    AND envelope #>> '{tenant_context,tenant_id}' = tenant_id::text
    AND envelope #>> '{identity_context,tenant_id}' = tenant_id::text
  ),
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, action_id),
  UNIQUE (tenant_id, task_id),
  CHECK ((state='ACCEPTED') = (receipt IS NOT NULL)),
  CHECK (receipt IS NULL OR (
    receipt->>'schema_version' = 'agenttrust.policy-action-receipt.v1'
    AND receipt->>'action_id' = action_id::text
    AND receipt->>'task_id' = task_id::text
    AND receipt->>'accepted' = 'true'
    AND receipt->>'execution_pending' = 'true'
  ))
);

CREATE TABLE IF NOT EXISTS policy_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (
    length(idempotency_key) BETWEEN 16 AND 128
    AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  trace_id text NOT NULL CHECK (length(trace_id) BETWEEN 1 AND 256),
  request jsonb NOT NULL CHECK (
    request->>'schema_version' = 'agenttrust.policy-executor-request.v1'
    AND request #>> '{command,command_id}' = action_id::text
    AND request #>> '{command,policy_id}' = policy_id
    AND request #>> '{command,tenant_id}' = tenant_id::text
  ),
  state text NOT NULL CHECK (state IN ('PREPARED','EXECUTING','SUCCEEDED','FAILED','UNKNOWN')),
  safe_result jsonb,
  safe_result_digest char(64),
  stable_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, ledger_execution_id),
  UNIQUE (tenant_id, action_hash, fence_digest),
  CHECK ((state='SUCCEEDED') = (safe_result IS NOT NULL)),
  CHECK ((state='SUCCEEDED') = (safe_result_digest IS NOT NULL)),
  CHECK (safe_result_digest IS NULL OR safe_result_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state='FAILED') = (stable_error IS NOT NULL)),
  CHECK (safe_result IS NULL OR safe_result->>'schema_version' = 'agenttrust.policy-mutation-result.v1')
);

CREATE TABLE IF NOT EXISTS policy_evidence_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  event_type text NOT NULL CHECK (event_type ~ '^POLICY_[A-Z_]{3,120}$'),
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
  payload jsonb NOT NULL CHECK (
    payload->>'schema_version' = 'agenttrust.policy-lifecycle-evidence.v1'
    AND payload->>'event_id' = event_id::text
    AND payload->>'tenant_id' = tenant_id::text
    AND payload->>'policy_id' = policy_id
    AND payload->>'principal_subject' = actor_subject
  ),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  evidence_ref text NOT NULL CHECK (evidence_ref LIKE 'urn:agenttrust:policy-evidence:%'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, evidence_ref)
);

CREATE TABLE IF NOT EXISTS policy_evidence_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type = 'POLICY_LIFECYCLE_EVIDENCE'),
  aggregate_id text NOT NULL CHECK (length(aggregate_id) BETWEEN 1 AND 256),
  payload jsonb NOT NULL,
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id) REFERENCES policy_evidence_events (tenant_id, event_id),
  CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE OR REPLACE FUNCTION enforce_policy_source_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.policy_id <> NEW.policy_id
     OR OLD.revision <> NEW.revision OR OLD.version <> NEW.version
     OR OLD.author_subject <> NEW.author_subject OR OLD.source_digest <> NEW.source_digest
     OR OLD.source_json <> NEW.source_json OR OLD.created_at <> NEW.created_at THEN
    RAISE EXCEPTION 'POLICY_SOURCE_ARTIFACT_IMMUTABLE';
  END IF;
  IF NOT ((OLD.lifecycle_state='DRAFT' AND NEW.lifecycle_state='VALIDATED')
       OR (OLD.lifecycle_state IN ('VALIDATED','REVIEW') AND NEW.lifecycle_state='REVIEW')
       OR (OLD.lifecycle_state='REVIEW' AND NEW.lifecycle_state='SIGNED')
       OR (OLD.lifecycle_state=NEW.lifecycle_state)) THEN
    RAISE EXCEPTION 'POLICY_SOURCE_TRANSITION_INVALID';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_bundle_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.bundle_id <> NEW.bundle_id
     OR OLD.version <> NEW.version OR OLD.policy_id <> NEW.policy_id
     OR OLD.revision <> NEW.revision OR OLD.source_digest <> NEW.source_digest
     OR OLD.compiled_digest <> NEW.compiled_digest OR OLD.analysis_digest <> NEW.analysis_digest
     OR OLD.static_analysis <> NEW.static_analysis OR OLD.key_id <> NEW.key_id
     OR OLD.signature <> NEW.signature OR OLD.bundle_json <> NEW.bundle_json
     OR OLD.signed_at <> NEW.signed_at OR OLD.created_at <> NEW.created_at THEN
    RAISE EXCEPTION 'POLICY_BUNDLE_ARTIFACT_IMMUTABLE';
  END IF;
  IF NOT ((OLD.status='SIGNED' AND NEW.status IN ('CANARY','ACTIVE','DEPRECATED'))
       OR (OLD.status='CANARY' AND NEW.status IN ('ACTIVE','ROLLED_BACK','DEPRECATED'))
       OR (OLD.status='ACTIVE' AND NEW.status IN ('ROLLED_BACK','DEPRECATED'))
       OR (OLD.status='ROLLED_BACK' AND NEW.status='DEPRECATED')
       OR (OLD.status=NEW.status AND OLD.deprecated_at IS NOT DISTINCT FROM NEW.deprecated_at)) THEN
    RAISE EXCEPTION 'POLICY_BUNDLE_TRANSITION_INVALID';
  END IF;
  IF (NEW.status='DEPRECATED') <> (NEW.deprecated_at IS NOT NULL) THEN
    RAISE EXCEPTION 'POLICY_BUNDLE_DEPRECATION_INVALID';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_promotion_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.policy_id <> NEW.policy_id
     OR OLD.environment <> NEW.environment OR OLD.sequence <> NEW.sequence
     OR OLD.bundle_digest <> NEW.bundle_digest
     OR OLD.previous_bundle_digest IS DISTINCT FROM NEW.previous_bundle_digest
     OR OLD.rollback_of IS DISTINCT FROM NEW.rollback_of
     OR OLD.promoted_by <> NEW.promoted_by OR OLD.promotion_digest <> NEW.promotion_digest
     OR OLD.promoted_at <> NEW.promoted_at THEN
    RAISE EXCEPTION 'POLICY_PROMOTION_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state='PENDING_ACTIVATION' AND NEW.state IN ('UNKNOWN','ACTIVE'))
       OR (OLD.state='UNKNOWN' AND NEW.state='PENDING_ACTIVATION')
       OR (OLD.state='ACTIVE' AND NEW.state IN ('SUPERSEDED','ROLLED_BACK'))) THEN
    RAISE EXCEPTION 'POLICY_PROMOTION_TRANSITION_INVALID';
  END IF;
  IF NEW.state IN ('SUPERSEDED','ROLLED_BACK') THEN
    NEW.completed_at := now();
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_activation_intent_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.activation_id<>NEW.activation_id
     OR OLD.idempotency_key<>NEW.idempotency_key OR OLD.policy_id<>NEW.policy_id
     OR OLD.environment<>NEW.environment OR OLD.sequence<>NEW.sequence
     OR OLD.bundle_digest<>NEW.bundle_digest
     OR OLD.previous_bundle_digest IS DISTINCT FROM NEW.previous_bundle_digest
     OR OLD.request_digest<>NEW.request_digest OR OLD.request_body<>NEW.request_body
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'POLICY_ACTIVATION_INTENT_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state='PENDING' AND NEW.state IN ('UNKNOWN','ACTIVE')
            AND NEW.claim_owner=OLD.claim_owner AND NEW.claim_expires_at=OLD.claim_expires_at)
       OR (OLD.state='UNKNOWN' AND NEW.state='PENDING'
            AND NEW.claim_owner<>OLD.claim_owner AND NEW.claim_expires_at>clock_timestamp())
       OR (OLD.state='PENDING' AND NEW.state='PENDING'
            AND OLD.claim_expires_at<=clock_timestamp() AND NEW.claim_owner<>OLD.claim_owner
            AND NEW.claim_expires_at>clock_timestamp())) THEN
    RAISE EXCEPTION 'POLICY_ACTIVATION_INTENT_TRANSITION_INVALID';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_exception_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.exception_id <> NEW.exception_id
     OR OLD.policy_id <> NEW.policy_id OR OLD.scope_digest <> NEW.scope_digest
     OR OLD.owner_subject <> NEW.owner_subject OR OLD.approver_subjects <> NEW.approver_subjects
     OR OLD.reason <> NEW.reason OR OLD.reason_digest <> NEW.reason_digest
     OR OLD.compensating_controls <> NEW.compensating_controls OR OLD.issued_by <> NEW.issued_by
     OR OLD.expires_at <> NEW.expires_at OR OLD.created_at <> NEW.created_at THEN
    RAISE EXCEPTION 'POLICY_EXCEPTION_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.revoked_at IS NULL AND OLD.expired_at IS NULL
           AND ((NEW.revoked_at IS NOT NULL AND NEW.expired_at IS NULL
                 AND NEW.revocation_reason_digest ~ '^[a-f0-9]{64}$')
             OR (NEW.expired_at IS NOT NULL AND NEW.revoked_at IS NULL
                 AND NEW.revocation_reason_digest IS NULL)))) THEN
    RAISE EXCEPTION 'POLICY_EXCEPTION_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_resource_fence()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.policy_id <> NEW.policy_id
     OR NEW.resource_version <> OLD.resource_version + 1
     OR OLD.created_at <> NEW.created_at THEN
    RAISE EXCEPTION 'POLICY_RESOURCE_FENCE_INVALID';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_ingress_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.idempotency_key <> NEW.idempotency_key
     OR OLD.request_digest <> NEW.request_digest OR OLD.action_id <> NEW.action_id
     OR OLD.task_id <> NEW.task_id OR OLD.principal_subject <> NEW.principal_subject
     OR OLD.principal_assertion_digest <> NEW.principal_assertion_digest
     OR OLD.envelope <> NEW.envelope OR OLD.created_at <> NEW.created_at
     OR NOT (OLD.state='PREPARED' AND NEW.state='ACCEPTED'
             OR OLD.state=NEW.state AND OLD.receipt IS NOT DISTINCT FROM NEW.receipt) THEN
    RAISE EXCEPTION 'POLICY_INGRESS_BINDING_IMMUTABLE';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_policy_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.idempotency_key <> NEW.idempotency_key
     OR OLD.request_digest <> NEW.request_digest OR OLD.action_id <> NEW.action_id
     OR OLD.action_hash <> NEW.action_hash OR OLD.ledger_execution_id <> NEW.ledger_execution_id
     OR OLD.fence_digest <> NEW.fence_digest OR OLD.policy_id <> NEW.policy_id
     OR OLD.resource_version <> NEW.resource_version OR OLD.trace_id <> NEW.trace_id
     OR OLD.request <> NEW.request OR OLD.created_at <> NEW.created_at THEN
    RAISE EXCEPTION 'POLICY_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state='PREPARED' AND NEW.state IN ('EXECUTING','FAILED'))
       OR (OLD.state='EXECUTING' AND NEW.state IN ('SUCCEEDED','FAILED','UNKNOWN'))
       OR (OLD.state='UNKNOWN' AND NEW.state='EXECUTING')
       OR (OLD.state=NEW.state AND OLD.safe_result IS NOT DISTINCT FROM NEW.safe_result
           AND OLD.safe_result_digest IS NOT DISTINCT FROM NEW.safe_result_digest
           AND OLD.stable_error IS NOT DISTINCT FROM NEW.stable_error)) THEN
    RAISE EXCEPTION 'POLICY_EXECUTION_TRANSITION_INVALID';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS policy_source_transition_guard ON policy_sources;
CREATE TRIGGER policy_source_transition_guard BEFORE UPDATE ON policy_sources
FOR EACH ROW EXECUTE FUNCTION enforce_policy_source_transition();
DROP TRIGGER IF EXISTS policy_bundle_immutable_guard ON policy_bundles;
CREATE TRIGGER policy_bundle_immutable_guard BEFORE UPDATE ON policy_bundles
FOR EACH ROW EXECUTE FUNCTION enforce_policy_bundle_immutable();
DROP TRIGGER IF EXISTS policy_promotion_transition_guard ON policy_promotions;
CREATE TRIGGER policy_promotion_transition_guard BEFORE UPDATE ON policy_promotions
FOR EACH ROW EXECUTE FUNCTION enforce_policy_promotion_transition();
DROP TRIGGER IF EXISTS policy_activation_intent_transition_guard ON policy_activation_intents;
CREATE TRIGGER policy_activation_intent_transition_guard BEFORE UPDATE ON policy_activation_intents
FOR EACH ROW EXECUTE FUNCTION enforce_policy_activation_intent_transition();
DROP TRIGGER IF EXISTS policy_exception_transition_guard ON policy_exceptions;
CREATE TRIGGER policy_exception_transition_guard BEFORE UPDATE ON policy_exceptions
FOR EACH ROW EXECUTE FUNCTION enforce_policy_exception_transition();
DROP TRIGGER IF EXISTS policy_resource_fence_guard ON policy_resource_versions;
CREATE TRIGGER policy_resource_fence_guard BEFORE UPDATE ON policy_resource_versions
FOR EACH ROW EXECUTE FUNCTION enforce_policy_resource_fence();
DROP TRIGGER IF EXISTS policy_ingress_immutable_guard ON policy_action_ingress;
CREATE TRIGGER policy_ingress_immutable_guard BEFORE UPDATE ON policy_action_ingress
FOR EACH ROW EXECUTE FUNCTION enforce_policy_ingress_immutable();
DROP TRIGGER IF EXISTS policy_execution_transition_guard ON policy_authority_executions;
CREATE TRIGGER policy_execution_transition_guard BEFORE UPDATE ON policy_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_policy_execution_transition();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'policy_sources','policy_analysis_results','policy_simulation_runs','policy_impact_reports','policy_reviews',
    'policy_bundles','policy_exceptions','policy_promotions','policy_activation_intents','policy_resource_versions',
    'policy_principal_assertion_replay','policy_action_ingress','policy_authority_executions',
    'policy_evidence_events','policy_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING '
      '(tenant_id::text=current_setting(''app.tenant_id'',true)) WITH CHECK '
      '(tenant_id::text=current_setting(''app.tenant_id'',true))', table_name
    );
  END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS policy_sources_latest_idx
  ON policy_sources (tenant_id, policy_id, revision DESC);
CREATE INDEX IF NOT EXISTS policy_simulations_policy_idx
  ON policy_simulation_runs (tenant_id, policy_id, revision, created_at DESC);
CREATE INDEX IF NOT EXISTS policy_impact_policy_idx
  ON policy_impact_reports (tenant_id, policy_id, revision, created_at DESC);
CREATE INDEX IF NOT EXISTS policy_reviews_policy_idx
  ON policy_reviews (tenant_id, policy_id, revision, decision);
CREATE INDEX IF NOT EXISTS policy_assertion_expiry_idx
  ON policy_principal_assertion_replay (expires_at);
CREATE INDEX IF NOT EXISTS policy_execution_state_idx
  ON policy_authority_executions (tenant_id, state, updated_at);
CREATE INDEX IF NOT EXISTS policy_activation_intent_state_idx
  ON policy_activation_intents (tenant_id, state, updated_at);
CREATE INDEX IF NOT EXISTS policy_evidence_outbox_pending_idx
  ON policy_evidence_outbox (tenant_id, created_at) WHERE published_at IS NULL;

REVOKE ALL ON TABLE policy_sources,policy_analysis_results,policy_simulation_runs,policy_impact_reports,
  policy_reviews,policy_bundles,policy_exceptions,policy_promotions,policy_activation_intents,policy_resource_versions,
  policy_principal_assertion_replay,policy_action_ingress,policy_authority_executions,
  policy_evidence_events,policy_evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_source_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_bundle_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_promotion_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_activation_intent_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_exception_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_resource_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_ingress_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_policy_execution_transition() FROM PUBLIC;

-- The production migration runner provisions the NOINHERIT LOGIN role and grants the exact
-- table/column matrix. This migration never creates credentials or treats a local role as proof.

COMMIT;
