-- Production PEP request fingerprints, signed decisions, and execution authorizations.
BEGIN;

CREATE TABLE IF NOT EXISTS pep_authorization_requests (
  tenant_id uuid NOT NULL,
  stage text NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL,
  result_status text NOT NULL,
  response_digest char(64),
  response_body jsonb,
  claim_owner uuid NOT NULL,
  claim_expires_at timestamptz NOT NULL,
  claim_context_digest char(64) NOT NULL,
  claim_context jsonb NOT NULL,
  completed_at timestamptz,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, stage, idempotency_key),
  CHECK (stage IN ('PRE_APPROVAL','PRE_EXECUTION')),
  CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
  CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CHECK (result_status IN ('IN_PROGRESS','SUCCEEDED','DENIED')),
  CHECK (claim_context_digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(claim_context) = 'object'),
  CHECK (
    (result_status = 'IN_PROGRESS' AND response_digest IS NULL AND response_body IS NULL AND completed_at IS NULL)
    OR
    (result_status IN ('SUCCEEDED','DENIED') AND response_digest ~ '^[0-9a-f]{64}$'
      AND jsonb_typeof(response_body) = 'object' AND completed_at IS NOT NULL)
  )
);

-- A rerun upgrades the short-lived pre-release table shape without weakening the terminal
-- records. Existing terminal rows receive deterministic bookkeeping values only.
DROP TRIGGER IF EXISTS pep_authorization_requests_immutable ON pep_authorization_requests;
ALTER TABLE pep_authorization_requests ADD COLUMN IF NOT EXISTS claim_owner uuid;
ALTER TABLE pep_authorization_requests ADD COLUMN IF NOT EXISTS claim_expires_at timestamptz;
ALTER TABLE pep_authorization_requests ADD COLUMN IF NOT EXISTS claim_context_digest char(64);
ALTER TABLE pep_authorization_requests ADD COLUMN IF NOT EXISTS claim_context jsonb;
ALTER TABLE pep_authorization_requests ADD COLUMN IF NOT EXISTS completed_at timestamptz;
ALTER TABLE pep_authorization_requests ALTER COLUMN response_digest DROP NOT NULL;
ALTER TABLE pep_authorization_requests ALTER COLUMN response_body DROP NOT NULL;
UPDATE pep_authorization_requests
   SET claim_owner = (
         substr(md5(tenant_id::text || ':' || stage || ':' || idempotency_key),1,8) || '-' ||
         substr(md5(tenant_id::text || ':' || stage || ':' || idempotency_key),9,4) || '-' ||
         substr(md5(tenant_id::text || ':' || stage || ':' || idempotency_key),13,4) || '-' ||
         substr(md5(tenant_id::text || ':' || stage || ':' || idempotency_key),17,4) || '-' ||
         substr(md5(tenant_id::text || ':' || stage || ':' || idempotency_key),21,12)
       )::uuid,
       claim_expires_at = created_at,
       completed_at = created_at
 WHERE result_status IN ('SUCCEEDED','DENIED')
   AND (claim_owner IS NULL OR claim_expires_at IS NULL OR completed_at IS NULL);
ALTER TABLE pep_authorization_requests ALTER COLUMN claim_owner SET NOT NULL;
ALTER TABLE pep_authorization_requests ALTER COLUMN claim_expires_at SET NOT NULL;
ALTER TABLE pep_authorization_requests DROP CONSTRAINT IF EXISTS pep_authorization_requests_result_status_check;
ALTER TABLE pep_authorization_requests DROP CONSTRAINT IF EXISTS pep_authorization_requests_terminal_shape_check;
ALTER TABLE pep_authorization_requests DROP CONSTRAINT IF EXISTS pep_authorization_requests_claim_context_check;
ALTER TABLE pep_authorization_requests DROP CONSTRAINT IF EXISTS pep_authorization_requests_stage_check;
ALTER TABLE pep_authorization_requests
  ADD CONSTRAINT pep_authorization_requests_stage_check
  CHECK (stage IN ('PRE_APPROVAL','PRE_EXECUTION','GOVERNANCE_APPROVAL','GOVERNANCE_QUERY'));
ALTER TABLE pep_authorization_requests
  ADD CONSTRAINT pep_authorization_requests_result_status_check
  CHECK (result_status IN ('IN_PROGRESS','SUCCEEDED','DENIED'));
ALTER TABLE pep_authorization_requests
  ADD CONSTRAINT pep_authorization_requests_terminal_shape_check
  CHECK (
    (result_status = 'IN_PROGRESS' AND response_digest IS NULL AND response_body IS NULL AND completed_at IS NULL)
    OR
    (result_status IN ('SUCCEEDED','DENIED') AND response_digest ~ '^[0-9a-f]{64}$'
      AND jsonb_typeof(response_body) = 'object' AND completed_at IS NOT NULL)
  );
ALTER TABLE pep_authorization_requests
  ADD CONSTRAINT pep_authorization_requests_claim_context_check
  CHECK (
    result_status <> 'IN_PROGRESS'
    OR (claim_context_digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(claim_context) = 'object')
  );

CREATE TABLE IF NOT EXISTS pep_policy_decisions (
  tenant_id uuid NOT NULL,
  decision_id text NOT NULL,
  stage text NOT NULL,
  action_hash char(64) NOT NULL,
  input_hash char(64) NOT NULL,
  policy_version text NOT NULL,
  policy_bundle_hash char(64) NOT NULL,
  decision_body jsonb NOT NULL,
  evaluated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, decision_id),
  CHECK (length(decision_id) BETWEEN 1 AND 256),
  CHECK (stage IN ('PRE_APPROVAL','PRE_EXECUTION')),
  CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  CHECK (input_hash ~ '^[0-9a-f]{64}$'),
  CHECK (length(policy_version) BETWEEN 1 AND 256),
  CHECK (policy_bundle_hash ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(decision_body) = 'object'),
  CHECK (evaluated_at < expires_at)
);

ALTER TABLE pep_policy_decisions DROP CONSTRAINT IF EXISTS pep_policy_decisions_stage_check;
ALTER TABLE pep_policy_decisions
  ADD CONSTRAINT pep_policy_decisions_stage_check
  CHECK (stage IN ('PRE_APPROVAL','PRE_EXECUTION','GOVERNANCE_APPROVAL','GOVERNANCE_QUERY'));

CREATE TABLE IF NOT EXISTS pep_execution_authorizations (
  tenant_id uuid NOT NULL,
  authorization_id uuid NOT NULL,
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL,
  action_hash char(64) NOT NULL,
  fence_digest char(64) NOT NULL,
  preapproval_digest char(64) NOT NULL,
  approval_consumption_ref text,
  approval_receipt_digest char(64),
  credential_id uuid NOT NULL,
  credential_claims_digest char(64) NOT NULL,
  authorization_digest char(64) NOT NULL,
  signed_authorization jsonb NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, authorization_id),
  UNIQUE (tenant_id, ledger_execution_id),
  CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  CHECK (preapproval_digest ~ '^[0-9a-f]{64}$'),
  CHECK ((approval_consumption_ref IS NULL) = (approval_receipt_digest IS NULL)),
  CHECK (approval_consumption_ref IS NULL OR length(approval_consumption_ref) BETWEEN 1 AND 2048),
  CHECK (approval_receipt_digest IS NULL OR approval_receipt_digest ~ '^[0-9a-f]{64}$'),
  CHECK (credential_claims_digest ~ '^[0-9a-f]{64}$'),
  CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(signed_authorization) = 'object'),
  CHECK ((signed_authorization ->> 'tenant_id') = tenant_id::text),
  CHECK ((signed_authorization ->> 'authorization_id') = authorization_id::text),
  CHECK ((signed_authorization ->> 'ledger_execution_id') = ledger_execution_id::text),
  CHECK ((signed_authorization ->> 'ledger_event_id') = ledger_event_id::text),
  CHECK ((signed_authorization ->> 'ledger_event_digest') = ledger_event_digest),
  CHECK ((signed_authorization ->> 'action_hash') = action_hash),
  CHECK ((signed_authorization ->> 'fence_digest') = fence_digest),
  CHECK (issued_at < expires_at)
);

CREATE TABLE IF NOT EXISTS pep_human_assertion_uses (
  tenant_id uuid NOT NULL,
  assertion_jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL,
  stage text NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, assertion_jti),
  UNIQUE (tenant_id, assertion_digest),
  FOREIGN KEY (tenant_id, stage, idempotency_key)
    REFERENCES pep_authorization_requests (tenant_id, stage, idempotency_key),
  CHECK (assertion_digest ~ '^[0-9a-f]{64}$'),
  CHECK (stage IN ('GOVERNANCE_APPROVAL','GOVERNANCE_QUERY')),
  CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
  CHECK (request_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS pep_governance_evidence (
  tenant_id uuid NOT NULL,
  evidence_id uuid NOT NULL,
  decision_id text NOT NULL,
  stage text NOT NULL,
  request_digest char(64) NOT NULL,
  assertion_jti uuid NOT NULL,
  evidence_digest char(64) NOT NULL,
  evidence_ref text NOT NULL,
  evidence_body jsonb NOT NULL,
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, evidence_id),
  UNIQUE (tenant_id, decision_id),
  UNIQUE (tenant_id, evidence_ref),
  FOREIGN KEY (tenant_id, decision_id)
    REFERENCES pep_policy_decisions (tenant_id, decision_id),
  FOREIGN KEY (tenant_id, assertion_jti)
    REFERENCES pep_human_assertion_uses (tenant_id, assertion_jti),
  CHECK (stage IN ('GOVERNANCE_APPROVAL','GOVERNANCE_QUERY')),
  CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  CHECK (length(evidence_ref) BETWEEN 1 AND 2048),
  CHECK (jsonb_typeof(evidence_body) = 'object'),
  CHECK (evidence_body ->> 'schema_version' = 'agenttrust.pep-governance-evidence.v1'),
  CHECK (evidence_body ->> 'tenant_id' = tenant_id::text),
  CHECK (evidence_body ->> 'evidence_id' = evidence_id::text),
  CHECK (evidence_body ->> 'decision_id' = decision_id),
  CHECK (evidence_body ->> 'request_digest' = request_digest),
  CHECK (evidence_body ->> 'assertion_jti' = assertion_jti::text),
  CHECK (evidence_body ->> 'evidence_digest' = evidence_digest),
  CHECK (evidence_body ->> 'evidence_ref' = evidence_ref)
);

CREATE TABLE IF NOT EXISTS pep_evidence_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  evidence_id uuid NOT NULL,
  event_type text NOT NULL,
  event_digest char(64) NOT NULL,
  event_body jsonb NOT NULL,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, evidence_id)
    REFERENCES pep_governance_evidence (tenant_id, evidence_id),
  CHECK (event_type = 'PEP_GOVERNANCE_DECISION_RECORDED'),
  CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(event_body) = 'object'),
  CHECK (event_body ->> 'schema_version' = 'agenttrust.pep-evidence-outbox.v1'),
  CHECK (event_body ->> 'tenant_id' = tenant_id::text),
  CHECK (event_body ->> 'event_id' = event_id::text),
  CHECK (event_body ->> 'evidence_id' = evidence_id::text),
  CHECK (event_body ->> 'event_type' = event_type),
  CHECK (event_body ->> 'event_digest' = event_digest)
);

CREATE TABLE IF NOT EXISTS pep_policy_bundle_artifacts (
  tenant_id uuid NOT NULL,
  bundle_digest char(64) NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
  bundle_id uuid NOT NULL,
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  source_revision bigint NOT NULL CHECK (source_revision > 0),
  policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
  key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
  bundle_body jsonb NOT NULL CHECK (
    bundle_body->>'schema_version' = 'agenttrust.signed-policy-bundle.v1'
    AND bundle_body->>'bundle_digest' = bundle_digest
    AND bundle_body->>'bundle_id' = bundle_id::text
    AND bundle_body->>'policy_id' = policy_id
    AND (bundle_body->>'source_revision')::bigint = source_revision
    AND bundle_body->>'version' = policy_version
    AND bundle_body->>'key_id' = key_id
    AND bundle_body #>> '{tenant_id}' = tenant_id::text
  ),
  verified_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, bundle_digest),
  UNIQUE (tenant_id, bundle_id)
);

CREATE TABLE IF NOT EXISTS pep_policy_activation_requests (
  tenant_id uuid NOT NULL,
  environment text NOT NULL CHECK (environment IN ('DEV','STAGING','CANARY','PRODUCTION')),
  idempotency_key varchar(128) NOT NULL CHECK (
    length(idempotency_key) BETWEEN 16 AND 128
    AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  activation_id uuid NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_bundle_digest char(64),
  bundle_digest char(64) NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
  request_body jsonb NOT NULL CHECK (
    request_body->>'schema_version' = 'agenttrust.policy-activation-request.v1'
    AND request_body->>'activation_id' = activation_id::text
    AND request_body->>'idempotency_key' = idempotency_key
    AND request_body->>'environment' = environment
    AND request_body->>'policy_id' = policy_id
    AND (request_body->>'sequence')::bigint = sequence
    AND COALESCE(request_body->>'previous_bundle_digest','') = COALESCE(previous_bundle_digest,'')
    AND request_body #>> '{tenant_id}' = tenant_id::text
    AND request_body #>> '{bundle,bundle_digest}' = bundle_digest
  ),
  state text NOT NULL CHECK (state IN ('PENDING','UNKNOWN','ACTIVE','REJECTED')),
  claim_owner uuid NOT NULL,
  claim_expires_at timestamptz NOT NULL,
  pdp_ack_digest char(64),
  pdp_ack_body jsonb,
  response_digest char(64),
  response_body jsonb,
  completed_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, environment, idempotency_key),
  UNIQUE (tenant_id, activation_id),
  FOREIGN KEY (tenant_id, bundle_digest)
    REFERENCES pep_policy_bundle_artifacts (tenant_id, bundle_digest),
  CHECK (previous_bundle_digest IS NULL OR previous_bundle_digest ~ '^[0-9a-f]{64}$'),
  CHECK (
    (state IN ('PENDING','UNKNOWN') AND pdp_ack_digest IS NULL AND pdp_ack_body IS NULL
      AND response_digest IS NULL AND response_body IS NULL AND completed_at IS NULL)
    OR (state='ACTIVE' AND pdp_ack_digest ~ '^[0-9a-f]{64}$'
      AND jsonb_typeof(pdp_ack_body)='object' AND response_digest ~ '^[0-9a-f]{64}$'
      AND jsonb_typeof(response_body)='object' AND completed_at IS NOT NULL
      AND pdp_ack_body->>'schema_version'='agenttrust.pdp-policy-activation-ack.v1'
      AND pdp_ack_body->>'activation_id'=activation_id::text
      AND pdp_ack_body->>'idempotency_key'=idempotency_key
      AND pdp_ack_body->>'policy_id'=policy_id
      AND (pdp_ack_body->>'sequence')::bigint=sequence
      AND pdp_ack_body->>'bundle_digest'=bundle_digest
      AND pdp_ack_body->>'environment'=environment
      AND pdp_ack_body #>> '{tenant_id}'=tenant_id::text
      AND pdp_ack_body->>'active'='true'
      AND response_body->>'schema_version'='agenttrust.pep-policy-activation-ack.v1'
      AND response_body->>'activation_id'=activation_id::text
      AND response_body->>'idempotency_key'=idempotency_key
      AND response_body->>'policy_id'=policy_id
      AND (response_body->>'sequence')::bigint=sequence
      AND response_body->>'bundle_digest'=bundle_digest
      AND response_body->>'environment'=environment
      AND response_body #>> '{tenant_id}'=tenant_id::text
      AND response_body->>'active'='true'
      AND response_body->>'pdp_ack_digest'=pdp_ack_digest)
    OR (state='REJECTED' AND completed_at IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS pep_active_policy_bundles (
  tenant_id uuid NOT NULL,
  environment text NOT NULL CHECK (environment IN ('DEV','STAGING','CANARY','PRODUCTION')),
  activation_id uuid NOT NULL,
  policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 256),
  sequence bigint NOT NULL CHECK (sequence > 0),
  bundle_digest char(64) NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
  policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
  pdp_ack_digest char(64) NOT NULL CHECK (pdp_ack_digest ~ '^[0-9a-f]{64}$'),
  activated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, environment),
  UNIQUE (tenant_id, activation_id),
  FOREIGN KEY (tenant_id, activation_id)
    REFERENCES pep_policy_activation_requests (tenant_id, activation_id),
  FOREIGN KEY (tenant_id, bundle_digest)
    REFERENCES pep_policy_bundle_artifacts (tenant_id, bundle_digest)
);

CREATE TABLE IF NOT EXISTS pep_policy_activation_evidence (
  tenant_id uuid NOT NULL,
  activation_id uuid NOT NULL,
  evidence_ref text NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 2048),
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  pdp_ack_digest char(64) NOT NULL CHECK (pdp_ack_digest ~ '^[0-9a-f]{64}$'),
  pdp_ack_body jsonb NOT NULL,
  evidence_body jsonb NOT NULL CHECK (
    evidence_body->>'schema_version' = 'agenttrust.pep-policy-activation-evidence.v1'
    AND evidence_body->>'activation_id' = activation_id::text
    AND evidence_body->>'evidence_ref' = evidence_ref
    AND evidence_body->>'evidence_digest' = evidence_digest
    AND evidence_body->>'pdp_ack_digest' = pdp_ack_digest
    AND evidence_body #>> '{tenant_id}' = tenant_id::text
  ),
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, activation_id),
  UNIQUE (tenant_id, evidence_ref),
  FOREIGN KEY (tenant_id, activation_id)
    REFERENCES pep_policy_activation_requests (tenant_id, activation_id)
);

CREATE TABLE IF NOT EXISTS pep_policy_activation_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  activation_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type='PEP_POLICY_BUNDLE_ACTIVATED'),
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  event_body jsonb NOT NULL CHECK (
    event_body->>'schema_version' = 'agenttrust.pep-policy-activation-outbox.v1'
    AND event_body->>'event_id' = event_id::text
    AND event_body->>'event_type' = event_type
    AND event_body->>'event_digest' = event_digest
    AND event_body->>'activation_id' = activation_id::text
    AND event_body #>> '{tenant_id}' = tenant_id::text
  ),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, activation_id)
    REFERENCES pep_policy_activation_evidence (tenant_id, activation_id)
);

CREATE INDEX IF NOT EXISTS pep_policy_decisions_action_idx
  ON pep_policy_decisions (tenant_id, action_hash, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS pep_authorizations_action_idx
  ON pep_execution_authorizations (tenant_id, action_hash, issued_at DESC);
CREATE INDEX IF NOT EXISTS pep_governance_evidence_decision_idx
  ON pep_governance_evidence (tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS pep_evidence_outbox_order_idx
  ON pep_evidence_outbox (tenant_id, occurred_at, event_id);
CREATE INDEX IF NOT EXISTS pep_policy_activation_request_order_idx
  ON pep_policy_activation_requests (tenant_id, environment, sequence DESC);
CREATE UNIQUE INDEX IF NOT EXISTS pep_policy_activation_single_unresolved_idx
  ON pep_policy_activation_requests (tenant_id, environment)
  WHERE state IN ('PENDING','UNKNOWN');
CREATE INDEX IF NOT EXISTS pep_policy_activation_outbox_order_idx
  ON pep_policy_activation_outbox (tenant_id, occurred_at, event_id);

CREATE OR REPLACE FUNCTION validate_pep_active_policy_bundle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pep_policy_activation_requests AS request
      JOIN pep_policy_bundle_artifacts AS bundle
        ON bundle.tenant_id=request.tenant_id AND bundle.bundle_digest=request.bundle_digest
     WHERE request.tenant_id=NEW.tenant_id
       AND request.environment=NEW.environment
       AND request.activation_id=NEW.activation_id
       AND request.policy_id=NEW.policy_id
       AND request.sequence=NEW.sequence
       AND request.bundle_digest=NEW.bundle_digest
       AND request.pdp_ack_digest=NEW.pdp_ack_digest
       AND request.state='ACTIVE'
       AND bundle.policy_version=NEW.policy_version
       AND (request.pdp_ack_body->>'activated_at')::timestamptz=NEW.activated_at
  ) THEN
    RAISE EXCEPTION 'PEP_ACTIVE_POLICY_BINDING_INVALID';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS pep_active_policy_binding ON pep_active_policy_bundles;
CREATE TRIGGER pep_active_policy_binding
BEFORE INSERT OR UPDATE ON pep_active_policy_bundles
FOR EACH ROW EXECUTE FUNCTION validate_pep_active_policy_bundle();

CREATE OR REPLACE FUNCTION reject_immutable_pep_record()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND TG_TABLE_NAME = 'pep_policy_activation_requests'
     AND NEW.tenant_id = OLD.tenant_id
     AND NEW.environment = OLD.environment
     AND NEW.idempotency_key = OLD.idempotency_key
     AND NEW.activation_id = OLD.activation_id
     AND NEW.request_digest = OLD.request_digest
     AND NEW.policy_id = OLD.policy_id
     AND NEW.sequence = OLD.sequence
     AND NEW.previous_bundle_digest IS NOT DISTINCT FROM OLD.previous_bundle_digest
     AND NEW.bundle_digest = OLD.bundle_digest
     AND NEW.request_body = OLD.request_body
     AND NEW.created_at = OLD.created_at
     AND (
       (OLD.state='PENDING' AND NEW.state='UNKNOWN'
         AND NEW.claim_owner=OLD.claim_owner AND NEW.claim_expires_at=OLD.claim_expires_at
         AND NEW.pdp_ack_digest IS NULL AND NEW.pdp_ack_body IS NULL
         AND NEW.response_digest IS NULL AND NEW.response_body IS NULL AND NEW.completed_at IS NULL)
       OR (OLD.state='UNKNOWN' AND NEW.state='PENDING'
         AND NEW.claim_owner<>OLD.claim_owner AND NEW.claim_expires_at>clock_timestamp()
         AND NEW.pdp_ack_digest IS NULL AND NEW.pdp_ack_body IS NULL
         AND NEW.response_digest IS NULL AND NEW.response_body IS NULL AND NEW.completed_at IS NULL)
       OR (OLD.state='PENDING' AND NEW.state='PENDING'
         AND OLD.claim_expires_at<=clock_timestamp() AND NEW.claim_owner<>OLD.claim_owner
         AND NEW.claim_expires_at>clock_timestamp()
         AND NEW.pdp_ack_digest IS NULL AND NEW.pdp_ack_body IS NULL
         AND NEW.response_digest IS NULL AND NEW.response_body IS NULL AND NEW.completed_at IS NULL)
       OR (OLD.state='PENDING' AND NEW.state='ACTIVE'
         AND NEW.claim_owner=OLD.claim_owner AND NEW.claim_expires_at=OLD.claim_expires_at
         AND NEW.pdp_ack_digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(NEW.pdp_ack_body)='object'
         AND NEW.response_digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(NEW.response_body)='object'
         AND NEW.completed_at IS NOT NULL)
     )
  THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE'
     AND TG_TABLE_NAME = 'pep_active_policy_bundles'
     AND NEW.tenant_id = OLD.tenant_id
     AND NEW.environment = OLD.environment
     AND NEW.sequence > OLD.sequence
     AND NEW.activation_id <> OLD.activation_id
     AND NEW.bundle_digest <> OLD.bundle_digest
     AND NEW.activated_at >= OLD.activated_at
  THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE'
     AND TG_TABLE_NAME = 'pep_authorization_requests'
     AND OLD.result_status = 'IN_PROGRESS'
     AND NEW.result_status = 'IN_PROGRESS'
     AND NEW.tenant_id = OLD.tenant_id
     AND NEW.stage = OLD.stage
     AND NEW.idempotency_key = OLD.idempotency_key
     AND NEW.request_digest = OLD.request_digest
     AND NEW.created_at = OLD.created_at
     AND NEW.claim_context_digest IS NOT DISTINCT FROM OLD.claim_context_digest
     AND OLD.response_digest IS NULL
     AND NEW.response_digest IS NULL
     AND OLD.response_body IS NULL
     AND NEW.response_body IS NULL
     AND OLD.completed_at IS NULL
     AND NEW.completed_at IS NULL
     AND OLD.claim_expires_at <= clock_timestamp()
     AND NEW.claim_owner <> OLD.claim_owner
     AND NEW.claim_expires_at > clock_timestamp()
  THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE'
     AND TG_TABLE_NAME = 'pep_authorization_requests'
     AND OLD.result_status = 'IN_PROGRESS'
     AND NEW.result_status IN ('SUCCEEDED','DENIED')
     AND NEW.tenant_id = OLD.tenant_id
     AND NEW.stage = OLD.stage
     AND NEW.idempotency_key = OLD.idempotency_key
     AND NEW.request_digest = OLD.request_digest
     AND NEW.claim_owner = OLD.claim_owner
     AND NEW.claim_expires_at = OLD.claim_expires_at
     AND NEW.created_at = OLD.created_at
     AND NEW.claim_context_digest IS NOT DISTINCT FROM OLD.claim_context_digest
     AND NEW.claim_context IS NOT DISTINCT FROM OLD.claim_context
     AND OLD.response_digest IS NULL
     AND OLD.response_body IS NULL
     AND OLD.completed_at IS NULL
     AND NEW.response_digest ~ '^[0-9a-f]{64}$'
     AND jsonb_typeof(NEW.response_body) = 'object'
     AND NEW.completed_at IS NOT NULL
     AND NEW.completed_at >= NEW.created_at
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'PEP_IMMUTABLE_RECORD_MUTATION_DENIED';
END
$$;

DO $$
DECLARE
  table_name text;
  policy_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'pep_authorization_requests',
    'pep_policy_decisions',
    'pep_execution_authorizations',
    'pep_human_assertion_uses',
    'pep_governance_evidence',
    'pep_evidence_outbox',
    'pep_policy_bundle_artifacts',
    'pep_policy_activation_requests',
    'pep_active_policy_bundles',
    'pep_policy_activation_evidence',
    'pep_policy_activation_outbox'
  ]
  LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', table_name || '_immutable', table_name);
    EXECUTE format(
      'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_immutable_pep_record()',
      table_name || '_immutable', table_name
    );
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    FOR policy_name IN
      SELECT policyname FROM pg_policies
       WHERE schemaname = 'public' AND tablename = table_name
    LOOP
      EXECUTE format('DROP POLICY %I ON %I', policy_name, table_name);
    END LOOP;
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id::text = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id::text = current_setting(''app.tenant_id'', true))',
      table_name
    );
  END LOOP;
END
$$;

REVOKE ALL ON TABLE
  pep_authorization_requests,
  pep_policy_decisions,
  pep_execution_authorizations,
  pep_human_assertion_uses,
  pep_governance_evidence,
  pep_evidence_outbox,
  pep_policy_bundle_artifacts,
  pep_policy_activation_requests,
  pep_active_policy_bundles,
  pep_policy_activation_evidence,
  pep_policy_activation_outbox
FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_immutable_pep_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_pep_active_policy_bundle() FROM PUBLIC;

COMMIT;
