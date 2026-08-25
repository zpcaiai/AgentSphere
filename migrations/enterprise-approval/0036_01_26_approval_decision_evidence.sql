-- Transactional, immutable evidence for human approval decisions. The Approval
-- authority signs the local decision receipt; the outbox carries an exact
-- AUTHENTICATED_EVENT request to the independent Evidence authority without
-- pretending that the human decision has a PEP/ledger execution binding.
BEGIN;

-- Existing decisions have no trustworthy Approval-authority signature. Mutable
-- cases and live grants must be drained; terminal audit history remains intact
-- and is never furnished with invented receipts.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM approval_decisions d
      JOIN approval_cases c
        ON c.tenant_id=d.tenant_id AND c.case_id=d.case_id
     WHERE c.status IN ('PENDING','APPROVED','POST_REVIEW_REQUIRED')
        OR EXISTS (
          SELECT 1 FROM approval_grants g
           WHERE g.tenant_id=d.tenant_id AND g.case_id=d.case_id
             AND g.remaining_uses > 0 AND g.revoked_at IS NULL
        )
  ) THEN
    RAISE EXCEPTION 'APPROVAL_UNSIGNED_MUTABLE_DECISIONS_MUST_BE_DRAINED';
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS approval_decision_evidence_receipts (
  tenant_id uuid NOT NULL,
  receipt_id uuid NOT NULL,
  case_id uuid NOT NULL,
  approver_subject text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT','POST_REVIEWED')),
  decision_digest char(64) NOT NULL CHECK (decision_digest ~ '^[a-f0-9]{64}$'),
  evidence_ref text NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  signed_receipt jsonb NOT NULL,
  authority_request_digest char(64) NOT NULL
    CHECK (authority_request_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,receipt_id),
  UNIQUE (tenant_id,case_id,approver_subject),
  UNIQUE (tenant_id,evidence_ref),
  FOREIGN KEY (tenant_id,case_id,approver_subject)
    REFERENCES approval_decisions(tenant_id,case_id,approver_subject),
  CHECK (length(approver_subject) BETWEEN 1 AND 256),
  CHECK (length(evidence_ref) BETWEEN 1 AND 2048),
  CHECK (evidence_ref = 'urn:agenttrust:approval-decision:' || tenant_id::text || ':'
    || case_id::text || ':' || receipt_id::text),
  CHECK (jsonb_typeof(signed_receipt)='object' AND octet_length(signed_receipt::text)<=1048576),
  CHECK (signed_receipt ?& ARRAY[
    'schema_version','receipt_id','tenant_id','case_id','task_id','decision',
    'decision_reason_digest','request_digest','decision_digest','idempotency_key_digest',
    'actor_subject','principal_assertion_jti','principal_assertion_request_digest',
    'principal_assertion_digest','approval_case_digest','action_hash','step_id','plan_hash',
    'parameter_hash','resource','resource_version','policy_version','environment','risk',
    'case_status','decided_at','evidence_ref','evidence_digest','authority_request_digest',
    'evidence_outbox_ref','issuer','key_id','key_usage','signature'
  ] AND signed_receipt - ARRAY[
    'schema_version','receipt_id','tenant_id','case_id','task_id','decision',
    'decision_reason_digest','request_digest','decision_digest','idempotency_key_digest',
    'actor_subject','principal_assertion_jti','principal_assertion_request_digest',
    'principal_assertion_digest','approval_case_digest','action_hash','step_id','plan_hash',
    'parameter_hash','resource','resource_version','policy_version','environment','risk',
    'case_status','decided_at','evidence_ref','evidence_digest','authority_request_digest',
    'evidence_outbox_ref','issuer','key_id','key_usage','signature'
  ] = '{}'::jsonb),
  CHECK (COALESCE(
    signed_receipt ->> 'schema_version' = 'agenttrust.approval-decision-evidence.v1'
    AND signed_receipt ->> 'receipt_id' = receipt_id::text
    AND signed_receipt ->> 'tenant_id' = tenant_id::text
    AND signed_receipt ->> 'case_id' = case_id::text
    AND signed_receipt ->> 'actor_subject' = approver_subject
    AND signed_receipt ->> 'decision' = decision
    AND signed_receipt ->> 'decision_digest' = decision_digest::text
    AND signed_receipt ->> 'evidence_ref' = evidence_ref
    AND signed_receipt ->> 'evidence_digest' = evidence_digest::text
    AND signed_receipt ->> 'authority_request_digest' = authority_request_digest::text
    AND signed_receipt ->> 'evidence_outbox_ref'
      = 'outbox://approval-decision-evidence/' || tenant_id::text || '/'
        || receipt_id::text || '/sha256:' || authority_request_digest::text
    AND signed_receipt ->> 'key_usage' = 'APPROVAL_DECISION_EVIDENCE'
    AND signed_receipt ->> 'decision_reason_digest' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'request_digest' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'idempotency_key_digest' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'principal_assertion_jti' ~
      '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND signed_receipt ->> 'principal_assertion_request_digest' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'principal_assertion_digest' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'approval_case_digest' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'action_hash' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'plan_hash' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'parameter_hash' ~ '^[a-f0-9]{64}$'
    AND signed_receipt ->> 'signature' ~ '^[A-Za-z0-9_-]{86}$',
    false
  ))
);

CREATE TABLE IF NOT EXISTS approval_decision_evidence_outbox (
  tenant_id uuid NOT NULL,
  authority_event_id uuid NOT NULL,
  receipt_id uuid NOT NULL,
  case_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL
    CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  evidence_ref text NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 2048),
  authority_request jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  next_attempt_at timestamptz NOT NULL,
  lease_owner uuid,
  lease_expires_at timestamptz,
  last_attempt_at timestamptz,
  last_error_code text CHECK (last_error_code IN (
    'CONFIGURATION_INVALID','OUTCOME_UNKNOWN','RECEIPT_INVALID'
  )),
  signed_authority_receipt jsonb,
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id,authority_event_id),
  UNIQUE (tenant_id,receipt_id),
  UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,receipt_id)
    REFERENCES approval_decision_evidence_receipts(tenant_id,receipt_id),
  CHECK (authority_event_id=receipt_id),
  CHECK (jsonb_typeof(authority_request)='object'
    AND octet_length(authority_request::text)<=1048576),
  CHECK (authority_request ?& ARRAY[
    'schema_version','tenant_id','task_id','authority_event_id','idempotency_key',
    'source_kind','control_binding','event','requested_at'
  ] AND authority_request - ARRAY[
    'schema_version','tenant_id','task_id','authority_event_id','idempotency_key',
    'source_kind','control_binding','event','requested_at'
  ] = '{}'::jsonb),
  CHECK (jsonb_typeof(authority_request -> 'event')='object'
    AND authority_request -> 'event' ?& ARRAY[
      'schema_version','tenant_id','task_id','event_type','actor_subject','source_service',
      'trace_id','span_id','payload_hash','safe_summary','artifact_refs','occurred_at'
    ] AND (authority_request -> 'event') - ARRAY[
      'schema_version','tenant_id','task_id','event_type','actor_subject','source_service',
      'trace_id','span_id','payload_hash','safe_summary','artifact_refs','occurred_at'
    ] = '{}'::jsonb),
  CHECK (COALESCE(
    authority_request ->> 'schema_version'
      = 'agenttrust.authority-evidence-event-request.v1'
    AND authority_request ->> 'tenant_id' = tenant_id::text
    AND authority_request ->> 'authority_event_id' = authority_event_id::text
    AND authority_request ->> 'idempotency_key' = idempotency_key
    AND authority_request ->> 'source_kind' = 'AUTHENTICATED_EVENT'
    AND authority_request -> 'control_binding' = 'null'::jsonb
    AND authority_request -> 'event' ->> 'schema_version' = 'agenttrust.evidence.v1'
    AND authority_request -> 'event' ->> 'tenant_id' = tenant_id::text
    AND authority_request -> 'event' ->> 'event_type' = 'APPROVAL_DECISION'
    AND authority_request -> 'event' ->> 'payload_hash' = payload_digest::text
    AND authority_request -> 'event' -> 'artifact_refs'
      = jsonb_build_array(evidence_ref),
    false
  )),
  CHECK ((lease_owner IS NULL AND lease_expires_at IS NULL)
    OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
      AND last_attempt_at IS NOT NULL AND lease_expires_at > last_attempt_at)),
  CHECK (last_attempt_at IS NULL OR last_attempt_at >= created_at),
  CHECK (delivered_at IS NULL OR (
    lease_owner IS NULL AND lease_expires_at IS NULL AND last_error_code IS NULL
  )),
  CHECK ((signed_authority_receipt IS NULL AND delivered_at IS NULL)
    OR COALESCE((jsonb_typeof(signed_authority_receipt)='object'
      AND octet_length(signed_authority_receipt::text)<=1048576
      AND signed_authority_receipt ?& ARRAY[
        'schema_version','tenant_id','task_id','authority_event_id','idempotency_key',
        'source_kind','request_digest','payload_digest','evidence_ref','evidence_digest',
        'event','persisted_at','issuer','key_id','key_usage','signature'
      ]
      AND signed_authority_receipt - ARRAY[
        'schema_version','tenant_id','task_id','authority_event_id','idempotency_key',
        'source_kind','request_digest','payload_digest','evidence_ref','evidence_digest',
        'event','persisted_at','issuer','key_id','key_usage','signature'
      ] = '{}'::jsonb
      AND delivered_at IS NOT NULL
      AND signed_authority_receipt ->> 'schema_version'
        = 'agenttrust.signed-authority-evidence-receipt.v1'
      AND signed_authority_receipt ->> 'tenant_id' = tenant_id::text
      AND signed_authority_receipt ->> 'task_id'
        = authority_request ->> 'task_id'
      AND signed_authority_receipt ->> 'authority_event_id' = authority_event_id::text
      AND signed_authority_receipt ->> 'idempotency_key' = idempotency_key
      AND signed_authority_receipt ->> 'source_kind' = 'AUTHENTICATED_EVENT'
      AND signed_authority_receipt ->> 'request_digest' = request_digest::text
      AND signed_authority_receipt ->> 'payload_digest' = payload_digest::text
      AND jsonb_typeof(signed_authority_receipt -> 'event')='object'
      AND signed_authority_receipt -> 'event' ?& ARRAY[
        'schema_version','event_id','sequence','previous_hash','event_hash',
        'key_id','signature','draft'
      ]
      AND (signed_authority_receipt -> 'event') - ARRAY[
        'schema_version','event_id','sequence','previous_hash','event_hash',
        'key_id','signature','draft'
      ] = '{}'::jsonb
      AND signed_authority_receipt -> 'event' ->> 'event_id' = authority_event_id::text
      AND signed_authority_receipt -> 'event' -> 'draft'
        = authority_request -> 'event'
      AND signed_authority_receipt ->> 'key_usage' = 'AUTHORITY_EVIDENCE_RECEIPT'
      AND signed_authority_receipt ->> 'issuer' ~ '^[A-Za-z0-9_.:/@-]{1,256}$'
      AND signed_authority_receipt ->> 'key_id' ~ '^[A-Za-z0-9_.-]{1,128}$'
      AND signed_authority_receipt ->> 'evidence_digest' ~ '^[a-f0-9]{64}$'
      AND signed_authority_receipt ->> 'signature' ~ '^[A-Za-z0-9_-]{86}$'),false)),
  CHECK (delivered_at IS NULL OR delivered_at >= created_at)
);

CREATE INDEX IF NOT EXISTS approval_decision_evidence_outbox_pending_idx
  ON approval_decision_evidence_outbox(
    tenant_id,next_attempt_at,lease_expires_at,created_at,authority_event_id
  )
  WHERE delivered_at IS NULL;

CREATE OR REPLACE FUNCTION enforce_approval_decision_evidence_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  decision_assertion_jti uuid;
  decision_assertion_request_digest char(64);
  decision_assertion_digest char(64);
  decision_decided_at timestamptz;
  case_task_id uuid;
  case_step_id uuid;
  case_action_hash char(64);
  case_plan_hash char(64);
  case_parameter_hash char(64);
  case_resource text;
  case_resource_version text;
  case_policy_version text;
  case_status text;
  case_request jsonb;
BEGIN
  SELECT assertion_jti,assertion_request_digest,assertion_digest,decided_at
    INTO decision_assertion_jti,decision_assertion_request_digest,
         decision_assertion_digest,decision_decided_at
    FROM approval_decisions
   WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id
     AND approver_subject=NEW.approver_subject;
  SELECT task_id,step_id,action_hash,plan_hash,parameter_hash,resource,resource_version,
         policy_version,status,request
    INTO case_task_id,case_step_id,case_action_hash,case_plan_hash,case_parameter_hash,
         case_resource,case_resource_version,case_policy_version,case_status,case_request
    FROM approval_cases
   WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id;
  IF decision_assertion_jti IS NULL OR case_task_id IS NULL
     OR NEW.signed_receipt ->> 'principal_assertion_jti'
          IS DISTINCT FROM decision_assertion_jti::text
     OR NEW.signed_receipt ->> 'principal_assertion_request_digest'
          IS DISTINCT FROM decision_assertion_request_digest::text
     OR NEW.signed_receipt ->> 'principal_assertion_digest'
          IS DISTINCT FROM decision_assertion_digest::text
     OR (NEW.signed_receipt ->> 'decided_at')::timestamptz
          IS DISTINCT FROM decision_decided_at
     OR NEW.signed_receipt ->> 'task_id' IS DISTINCT FROM case_task_id::text
     OR NEW.signed_receipt ->> 'step_id' IS DISTINCT FROM case_step_id::text
     OR NEW.signed_receipt ->> 'action_hash' IS DISTINCT FROM case_action_hash::text
     OR NEW.signed_receipt ->> 'plan_hash' IS DISTINCT FROM case_plan_hash::text
     OR NEW.signed_receipt ->> 'parameter_hash' IS DISTINCT FROM case_parameter_hash::text
     OR NEW.signed_receipt ->> 'resource' IS DISTINCT FROM case_resource
     OR NEW.signed_receipt ->> 'resource_version' IS DISTINCT FROM case_resource_version
     OR NEW.signed_receipt ->> 'policy_version' IS DISTINCT FROM case_policy_version
     OR NEW.signed_receipt ->> 'environment'
          IS DISTINCT FROM (case_request ->> 'environment')
     OR NEW.signed_receipt ->> 'risk' IS DISTINCT FROM (case_request ->> 'risk')
     OR NEW.signed_receipt ->> 'case_status' IS DISTINCT FROM case_status THEN
    RAISE EXCEPTION 'APPROVAL_DECISION_EVIDENCE_BINDING_INVALID';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION enforce_approval_decision_evidence_outbox_immutable_payload()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP='DELETE'
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.authority_event_id IS DISTINCT FROM OLD.authority_event_id
     OR NEW.receipt_id IS DISTINCT FROM OLD.receipt_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.payload_digest IS DISTINCT FROM OLD.payload_digest
     OR NEW.evidence_ref IS DISTINCT FROM OLD.evidence_ref
     OR NEW.authority_request IS DISTINCT FROM OLD.authority_request
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'APPROVAL_DECISION_EVIDENCE_OUTBOX_PAYLOAD_MUTATION_DENIED';
  END IF;
  IF OLD.delivered_at IS NOT NULL AND (
       NEW.delivery_attempts IS DISTINCT FROM OLD.delivery_attempts
       OR NEW.next_attempt_at IS DISTINCT FROM OLD.next_attempt_at
       OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
       OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
       OR NEW.last_attempt_at IS DISTINCT FROM OLD.last_attempt_at
       OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code
       OR NEW.signed_authority_receipt IS DISTINCT FROM OLD.signed_authority_receipt
       OR NEW.delivered_at IS DISTINCT FROM OLD.delivered_at
     ) THEN
    RAISE EXCEPTION 'APPROVAL_DECISION_EVIDENCE_DELIVERY_MUTATION_DENIED';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION enforce_approval_decision_has_evidence()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM approval_decision_evidence_receipts r
      JOIN approval_decision_evidence_outbox o
        ON o.tenant_id=r.tenant_id AND o.receipt_id=r.receipt_id
     WHERE r.tenant_id=NEW.tenant_id AND r.case_id=NEW.case_id
       AND r.approver_subject=NEW.approver_subject
       AND r.decision=NEW.decision
       AND o.case_id=NEW.case_id
       AND o.evidence_ref=r.evidence_ref
       AND o.request_digest=r.authority_request_digest
       AND o.payload_digest=r.decision_digest
  ) THEN
    RAISE EXCEPTION 'APPROVAL_DECISION_EVIDENCE_REQUIRED';
  END IF;
  RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS approval_decision_evidence_receipts_immutable
  ON approval_decision_evidence_receipts;
DROP TRIGGER IF EXISTS approval_decision_evidence_receipts_binding
  ON approval_decision_evidence_receipts;
CREATE TRIGGER approval_decision_evidence_receipts_binding
  BEFORE INSERT ON approval_decision_evidence_receipts
  FOR EACH ROW EXECUTE FUNCTION enforce_approval_decision_evidence_binding();
CREATE TRIGGER approval_decision_evidence_receipts_immutable
  BEFORE UPDATE OR DELETE ON approval_decision_evidence_receipts
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_approval_mutation();

DROP TRIGGER IF EXISTS approval_decision_evidence_outbox_immutable_payload
  ON approval_decision_evidence_outbox;
CREATE TRIGGER approval_decision_evidence_outbox_immutable_payload
  BEFORE UPDATE OR DELETE ON approval_decision_evidence_outbox
  FOR EACH ROW EXECUTE FUNCTION enforce_approval_decision_evidence_outbox_immutable_payload();

DROP TRIGGER IF EXISTS approval_decision_requires_evidence ON approval_decisions;
CREATE CONSTRAINT TRIGGER approval_decision_requires_evidence
  AFTER INSERT ON approval_decisions
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION enforce_approval_decision_has_evidence();

ALTER TABLE approval_decision_evidence_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_decision_evidence_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON approval_decision_evidence_receipts;
CREATE POLICY tenant_isolation ON approval_decision_evidence_receipts
  AS PERMISSIVE FOR ALL TO PUBLIC
  USING (tenant_id::text=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id::text=current_setting('app.tenant_id',true));

ALTER TABLE approval_decision_evidence_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_decision_evidence_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON approval_decision_evidence_outbox;
CREATE POLICY tenant_isolation ON approval_decision_evidence_outbox
  AS PERMISSIVE FOR ALL TO PUBLIC
  USING (tenant_id::text=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id::text=current_setting('app.tenant_id',true));

REVOKE ALL ON TABLE approval_decision_evidence_receipts FROM PUBLIC;
REVOKE ALL ON TABLE approval_decision_evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_decision_evidence_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_decision_evidence_outbox_immutable_payload() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_decision_has_evidence() FROM PUBLIC;

COMMIT;
