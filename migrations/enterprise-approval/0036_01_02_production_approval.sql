BEGIN;

ALTER TABLE approval_cases
  ADD COLUMN IF NOT EXISTS request_digest char(64),
  ADD COLUMN IF NOT EXISTS created_by text,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

ALTER TABLE approval_decisions
  ADD COLUMN IF NOT EXISTS assertion_issuer text,
  ADD COLUMN IF NOT EXISTS assertion_jti uuid,
  ADD COLUMN IF NOT EXISTS assertion_request_digest char(64),
  ADD COLUMN IF NOT EXISTS assertion_digest char(64),
  ADD COLUMN IF NOT EXISTS assertion_expires_at timestamptz;

ALTER TABLE approval_grants
  ADD COLUMN IF NOT EXISTS binding_hash char(64),
  ADD COLUMN IF NOT EXISTS task_id uuid,
  ADD COLUMN IF NOT EXISTS step_id uuid,
  ADD COLUMN IF NOT EXISTS action_hash char(64),
  ADD COLUMN IF NOT EXISTS plan_hash char(64),
  ADD COLUMN IF NOT EXISTS parameter_hash char(64),
  ADD COLUMN IF NOT EXISTS resource text,
  ADD COLUMN IF NOT EXISTS resource_version text,
  ADD COLUMN IF NOT EXISTS policy_version text,
  ADD COLUMN IF NOT EXISTS environment text,
  ADD COLUMN IF NOT EXISTS maximum_risk text,
  ADD COLUMN IF NOT EXISTS issued_at timestamptz,
  ADD COLUMN IF NOT EXISTS issued_by text,
  ADD COLUMN IF NOT EXISTS key_id text,
  ADD COLUMN IF NOT EXISTS revoked_by text,
  ADD COLUMN IF NOT EXISTS revocation_reason_digest char(64),
  ADD COLUMN IF NOT EXISTS revocation_receipt jsonb,
  ADD COLUMN IF NOT EXISTS last_consumed_at timestamptz;

-- Existing rows cannot be assigned invented request, actor, or signature evidence.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM approval_cases
     WHERE request_digest IS NULL OR created_by IS NULL OR updated_at IS NULL
  ) THEN
    RAISE EXCEPTION 'APPROVAL_CASE_PRODUCTION_BACKFILL_REQUIRED';
  END IF;
  IF EXISTS (
    SELECT 1 FROM approval_decisions
     WHERE assertion_issuer IS NULL OR assertion_jti IS NULL
        OR assertion_request_digest IS NULL OR assertion_digest IS NULL
        OR assertion_expires_at IS NULL
  ) THEN
    RAISE EXCEPTION 'APPROVAL_DECISION_PRINCIPAL_ASSERTION_BACKFILL_REQUIRED';
  END IF;
  IF EXISTS (
    SELECT 1 FROM approval_grants
     WHERE binding_hash IS NULL OR task_id IS NULL OR step_id IS NULL
        OR action_hash IS NULL OR plan_hash IS NULL OR parameter_hash IS NULL
        OR resource IS NULL OR resource_version IS NULL OR policy_version IS NULL
        OR environment IS NULL OR maximum_risk IS NULL OR issued_at IS NULL
        OR issued_by IS NULL OR key_id IS NULL
        OR (revocation_receipt IS NOT NULL AND (
          NOT (revocation_receipt ? 'principal_assertion_jti')
          OR NOT (revocation_receipt ? 'principal_assertion_digest')
        ))
  ) THEN
    RAISE EXCEPTION 'APPROVAL_GRANT_PRODUCTION_BACKFILL_REQUIRED';
  END IF;
END
$$;

ALTER TABLE approval_cases
  ALTER COLUMN request_digest SET NOT NULL,
  ALTER COLUMN created_by SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE approval_decisions
  ALTER COLUMN assertion_issuer SET NOT NULL,
  ALTER COLUMN assertion_jti SET NOT NULL,
  ALTER COLUMN assertion_request_digest SET NOT NULL,
  ALTER COLUMN assertion_digest SET NOT NULL,
  ALTER COLUMN assertion_expires_at SET NOT NULL;
ALTER TABLE approval_grants
  ALTER COLUMN binding_hash SET NOT NULL,
  ALTER COLUMN task_id SET NOT NULL,
  ALTER COLUMN step_id SET NOT NULL,
  ALTER COLUMN action_hash SET NOT NULL,
  ALTER COLUMN plan_hash SET NOT NULL,
  ALTER COLUMN parameter_hash SET NOT NULL,
  ALTER COLUMN resource SET NOT NULL,
  ALTER COLUMN resource_version SET NOT NULL,
  ALTER COLUMN policy_version SET NOT NULL,
  ALTER COLUMN environment SET NOT NULL,
  ALTER COLUMN maximum_risk SET NOT NULL,
  ALTER COLUMN issued_at SET NOT NULL,
  ALTER COLUMN issued_by SET NOT NULL,
  ALTER COLUMN key_id SET NOT NULL;

CREATE TABLE IF NOT EXISTS approval_mutation_receipts (
  tenant_id uuid NOT NULL,
  operation text NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL,
  response_body jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, operation, idempotency_key),
  CHECK (length(operation) BETWEEN 1 AND 512),
  CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(response_body) = 'object')
);

CREATE TABLE IF NOT EXISTS approval_principal_assertion_uses (
  tenant_id uuid NOT NULL,
  assertion_jti uuid NOT NULL,
  issuer text NOT NULL,
  subject text NOT NULL,
  scope text NOT NULL,
  request_digest char(64) NOT NULL,
  assertion_digest char(64) NOT NULL,
  signed_assertion jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  first_used_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, assertion_jti),
  CHECK (length(issuer) BETWEEN 1 AND 256),
  CHECK (length(subject) BETWEEN 1 AND 256),
  CHECK (scope IN ('approvals:request','approvals:decide','approvals:issue','approvals:revoke')),
  CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CHECK (assertion_digest ~ '^[0-9a-f]{64}$'),
  CHECK (jsonb_typeof(signed_assertion) = 'object'),
  CHECK (COALESCE(
    signed_assertion ->> 'schema_version' = 'agenttrust.signed-approval-principal-assertion.v1'
    AND signed_assertion ->> 'tenant_id' = tenant_id::text
    AND signed_assertion ->> 'jti' = assertion_jti::text
    AND signed_assertion ->> 'issuer' = issuer
    AND signed_assertion ->> 'subject' = subject
    AND signed_assertion ->> 'scope' = scope
    AND signed_assertion ->> 'request_digest' = request_digest::text
    AND signed_assertion -> 'strong_auth' = 'true'::jsonb
    AND length(signed_assertion ->> 'signature') = 86,
    false
  )),
  CHECK (expires_at > first_used_at)
);

CREATE TABLE IF NOT EXISTS approval_consumptions (
  tenant_id uuid NOT NULL,
  receipt_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  case_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL,
  consumption_ref text NOT NULL,
  signed_receipt jsonb NOT NULL,
  wire_receipt jsonb NOT NULL,
  consumed_by text NOT NULL,
  client_identity text NOT NULL,
  consumed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, receipt_id),
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, grant_id),
  UNIQUE (tenant_id, consumption_ref),
  CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CHECK (length(consumption_ref) BETWEEN 1 AND 2048),
  CHECK (consumption_ref LIKE 'urn:agenttrust:approval-consumption:%'),
  CHECK (length(consumed_by) BETWEEN 1 AND 256),
  CHECK (length(client_identity) BETWEEN 5 AND 512),
  CHECK (client_identity ~ '^(DNS|URI):[^[:space:]]+$'),
  CHECK (jsonb_typeof(signed_receipt) = 'object'),
  CHECK (jsonb_typeof(wire_receipt) = 'object'),
  CHECK (COALESCE(
    signed_receipt ->> 'schema_version' = 'agenttrust.approval-consumption.v1'
    AND signed_receipt ->> 'tenant_id' = tenant_id::text
    AND signed_receipt ->> 'receipt_id' = receipt_id::text
    AND signed_receipt ->> 'grant_id' = grant_id::text
    AND signed_receipt ->> 'case_id' = case_id::text
    AND signed_receipt ->> 'request_digest' = request_digest::text
    AND signed_receipt ->> 'consumed_by' = consumed_by
    AND signed_receipt ->> 'client_identity' = client_identity
    AND wire_receipt ->> 'consumption_ref' = consumption_ref,
    false
  ))
);

CREATE TABLE IF NOT EXISTS approval_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL,
  aggregate_id text NOT NULL,
  actor_subject text NOT NULL,
  payload_digest char(64) NOT NULL,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  CHECK (length(event_type) BETWEEN 1 AND 64),
  CHECK (length(aggregate_id) BETWEEN 1 AND 256),
  CHECK (length(actor_subject) BETWEEN 1 AND 256),
  CHECK (payload_digest ~ '^[0-9a-f]{64}$')
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_cases_status_check'
       AND conrelid = 'approval_cases'::regclass
  ) THEN
    ALTER TABLE approval_cases
      ADD CONSTRAINT approval_cases_status_check
      CHECK (status IN ('PENDING','APPROVED','REJECTED','REVOKED','EXPIRED','CONSUMED','POST_REVIEW_REQUIRED'))
      NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_cases_request_digest_check'
       AND conrelid = 'approval_cases'::regclass
  ) THEN
    ALTER TABLE approval_cases
      ADD CONSTRAINT approval_cases_request_digest_check
      CHECK (request_digest ~ '^[0-9a-f]{64}$') NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_decisions_decision_check'
       AND conrelid = 'approval_decisions'::regclass
  ) THEN
    ALTER TABLE approval_decisions
      ADD CONSTRAINT approval_decisions_decision_check
      CHECK (decision IN ('APPROVE','REJECT','POST_REVIEWED')) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_decisions_assertion_digest_check'
       AND conrelid = 'approval_decisions'::regclass
  ) THEN
    ALTER TABLE approval_decisions
      ADD CONSTRAINT approval_decisions_assertion_digest_check
      CHECK (
        assertion_request_digest ~ '^[0-9a-f]{64}$'
        AND assertion_digest ~ '^[0-9a-f]{64}$'
        AND length(assertion_issuer) BETWEEN 1 AND 256
        AND assertion_expires_at > decided_at
      ) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_decisions_assertion_use_fk'
       AND conrelid = 'approval_decisions'::regclass
  ) THEN
    ALTER TABLE approval_decisions
      ADD CONSTRAINT approval_decisions_assertion_use_fk
      FOREIGN KEY (tenant_id, assertion_jti)
      REFERENCES approval_principal_assertion_uses (tenant_id, assertion_jti) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_grants_binding_hash_check'
       AND conrelid = 'approval_grants'::regclass
  ) THEN
    ALTER TABLE approval_grants
      ADD CONSTRAINT approval_grants_binding_hash_check
      CHECK (binding_hash ~ '^[0-9a-f]{64}$') NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_grants_maximum_risk_check'
       AND conrelid = 'approval_grants'::regclass
  ) THEN
    ALTER TABLE approval_grants
      ADD CONSTRAINT approval_grants_maximum_risk_check
      CHECK (maximum_risk IN ('LOW','MEDIUM','HIGH','CRITICAL')) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_grants_single_use_check'
       AND conrelid = 'approval_grants'::regclass
  ) THEN
    ALTER TABLE approval_grants
      ADD CONSTRAINT approval_grants_single_use_check
      CHECK (remaining_uses IN (0,1)) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_consumptions_grant_fk'
       AND conrelid = 'approval_consumptions'::regclass
  ) THEN
    ALTER TABLE approval_consumptions
      ADD CONSTRAINT approval_consumptions_grant_fk
      FOREIGN KEY (tenant_id, grant_id)
      REFERENCES approval_grants (tenant_id, grant_id) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_consumptions_case_fk'
       AND conrelid = 'approval_consumptions'::regclass
  ) THEN
    ALTER TABLE approval_consumptions
      ADD CONSTRAINT approval_consumptions_case_fk
      FOREIGN KEY (tenant_id, case_id)
      REFERENCES approval_cases (tenant_id, case_id) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_grants_case_unique'
       AND conrelid = 'approval_grants'::regclass
  ) THEN
    ALTER TABLE approval_grants
      ADD CONSTRAINT approval_grants_case_unique UNIQUE (tenant_id, case_id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'approval_grants_binding_unique'
       AND conrelid = 'approval_grants'::regclass
  ) THEN
    ALTER TABLE approval_grants
      ADD CONSTRAINT approval_grants_binding_unique UNIQUE (tenant_id, binding_hash);
  END IF;
END
$$;

ALTER TABLE approval_cases VALIDATE CONSTRAINT approval_cases_status_check;
ALTER TABLE approval_cases VALIDATE CONSTRAINT approval_cases_request_digest_check;
ALTER TABLE approval_decisions VALIDATE CONSTRAINT approval_decisions_decision_check;
ALTER TABLE approval_decisions VALIDATE CONSTRAINT approval_decisions_assertion_digest_check;
ALTER TABLE approval_decisions VALIDATE CONSTRAINT approval_decisions_assertion_use_fk;
ALTER TABLE approval_grants VALIDATE CONSTRAINT approval_grants_binding_hash_check;
ALTER TABLE approval_grants VALIDATE CONSTRAINT approval_grants_maximum_risk_check;
ALTER TABLE approval_grants VALIDATE CONSTRAINT approval_grants_single_use_check;
ALTER TABLE approval_consumptions VALIDATE CONSTRAINT approval_consumptions_grant_fk;
ALTER TABLE approval_consumptions VALIDATE CONSTRAINT approval_consumptions_case_fk;

CREATE INDEX IF NOT EXISTS approval_cases_task_status_idx
  ON approval_cases (tenant_id, task_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS approval_cases_expiry_idx
  ON approval_cases (tenant_id, expires_at)
  WHERE status IN ('PENDING','APPROVED','POST_REVIEW_REQUIRED');
CREATE INDEX IF NOT EXISTS approval_cases_authoritative_page_idx
  ON approval_cases (tenant_id, created_at DESC, case_id DESC);
CREATE INDEX IF NOT EXISTS approval_grants_expiry_idx
  ON approval_grants (tenant_id, expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS approval_events_aggregate_idx
  ON approval_events (tenant_id, aggregate_id, occurred_at, event_id);
CREATE INDEX IF NOT EXISTS approval_principal_assertion_expiry_idx
  ON approval_principal_assertion_uses (tenant_id, expires_at);

CREATE OR REPLACE FUNCTION reject_immutable_approval_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'APPROVAL_IMMUTABLE_RECORD_MUTATION_DENIED';
END
$$;

CREATE OR REPLACE FUNCTION enforce_approval_case_immutable_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'APPROVAL_CASE_BINDING_MUTATION_DENIED';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.task_id IS DISTINCT FROM OLD.task_id
     OR NEW.step_id IS DISTINCT FROM OLD.step_id
     OR NEW.action_hash IS DISTINCT FROM OLD.action_hash
     OR NEW.plan_hash IS DISTINCT FROM OLD.plan_hash
     OR NEW.parameter_hash IS DISTINCT FROM OLD.parameter_hash
     OR NEW.resource IS DISTINCT FROM OLD.resource
     OR NEW.resource_version IS DISTINCT FROM OLD.resource_version
     OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
     OR NEW.request IS DISTINCT FROM OLD.request
     OR NEW.policy IS DISTINCT FROM OLD.policy
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.post_review_due_at IS DISTINCT FROM OLD.post_review_due_at
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
    RAISE EXCEPTION 'APPROVAL_CASE_BINDING_MUTATION_DENIED';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION enforce_approval_grant_immutable_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'APPROVAL_GRANT_BINDING_MUTATION_DENIED';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.grant_id IS DISTINCT FROM OLD.grant_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.grant_hash IS DISTINCT FROM OLD.grant_hash
     OR NEW.signed_grant IS DISTINCT FROM OLD.signed_grant
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.binding_hash IS DISTINCT FROM OLD.binding_hash
     OR NEW.task_id IS DISTINCT FROM OLD.task_id
     OR NEW.step_id IS DISTINCT FROM OLD.step_id
     OR NEW.action_hash IS DISTINCT FROM OLD.action_hash
     OR NEW.plan_hash IS DISTINCT FROM OLD.plan_hash
     OR NEW.parameter_hash IS DISTINCT FROM OLD.parameter_hash
     OR NEW.resource IS DISTINCT FROM OLD.resource
     OR NEW.resource_version IS DISTINCT FROM OLD.resource_version
     OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
     OR NEW.environment IS DISTINCT FROM OLD.environment
     OR NEW.maximum_risk IS DISTINCT FROM OLD.maximum_risk
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.issued_by IS DISTINCT FROM OLD.issued_by
     OR NEW.key_id IS DISTINCT FROM OLD.key_id THEN
    RAISE EXCEPTION 'APPROVAL_GRANT_BINDING_MUTATION_DENIED';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION enforce_approval_notification_immutable_payload()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'APPROVAL_NOTIFICATION_PAYLOAD_MUTATION_DENIED';
  END IF;
  IF NEW.notification_id IS DISTINCT FROM OLD.notification_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.payload IS DISTINCT FROM OLD.payload
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'APPROVAL_NOTIFICATION_PAYLOAD_MUTATION_DENIED';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS approval_cases_immutable_binding ON approval_cases;
CREATE TRIGGER approval_cases_immutable_binding
  BEFORE UPDATE OR DELETE ON approval_cases
  FOR EACH ROW EXECUTE FUNCTION enforce_approval_case_immutable_binding();
DROP TRIGGER IF EXISTS approval_grants_immutable_binding ON approval_grants;
CREATE TRIGGER approval_grants_immutable_binding
  BEFORE UPDATE OR DELETE ON approval_grants
  FOR EACH ROW EXECUTE FUNCTION enforce_approval_grant_immutable_binding();
DROP TRIGGER IF EXISTS approval_notifications_immutable_payload ON approval_notification_outbox;
CREATE TRIGGER approval_notifications_immutable_payload
  BEFORE UPDATE OR DELETE ON approval_notification_outbox
  FOR EACH ROW EXECUTE FUNCTION enforce_approval_notification_immutable_payload();

DROP TRIGGER IF EXISTS approval_consumptions_immutable ON approval_consumptions;
CREATE TRIGGER approval_consumptions_immutable
  BEFORE UPDATE OR DELETE ON approval_consumptions
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_approval_mutation();
DROP TRIGGER IF EXISTS approval_decisions_immutable ON approval_decisions;
CREATE TRIGGER approval_decisions_immutable
  BEFORE UPDATE OR DELETE ON approval_decisions
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_approval_mutation();
DROP TRIGGER IF EXISTS approval_mutation_receipts_immutable ON approval_mutation_receipts;
CREATE TRIGGER approval_mutation_receipts_immutable
  BEFORE UPDATE OR DELETE ON approval_mutation_receipts
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_approval_mutation();
DROP TRIGGER IF EXISTS approval_principal_assertion_uses_immutable ON approval_principal_assertion_uses;
CREATE TRIGGER approval_principal_assertion_uses_immutable
  BEFORE UPDATE OR DELETE ON approval_principal_assertion_uses
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_approval_mutation();
DROP TRIGGER IF EXISTS approval_events_immutable ON approval_events;
CREATE TRIGGER approval_events_immutable
  BEFORE UPDATE OR DELETE ON approval_events
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_approval_mutation();

DO $$
DECLARE
  table_name text;
  policy_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'approval_cases',
    'approval_decisions',
    'approval_grants',
    'approval_notification_outbox',
    'approval_mutation_receipts',
    'approval_principal_assertion_uses',
    'approval_consumptions',
    'approval_events'
  ]
  LOOP
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
  approval_cases,
  approval_decisions,
  approval_grants,
  approval_notification_outbox,
  approval_mutation_receipts,
  approval_principal_assertion_uses,
  approval_consumptions,
  approval_events
FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_immutable_approval_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_case_immutable_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_grant_immutable_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_approval_notification_immutable_payload() FROM PUBLIC;

COMMIT;
