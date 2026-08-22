-- Production Evidence Authority: execution fencing, immutable signed chains, exact replay,
-- offline packages, evaluator records, WORM attestations, outbox and FORCE RLS.
-- Runtime roles and least-privilege grants are provisioned by the deployment migration runner;
-- this migration deliberately does not create or mutate externally managed login roles.
BEGIN;

ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS signed_event jsonb,
  ADD COLUMN IF NOT EXISTS request_digest char(64),
  ADD COLUMN IF NOT EXISTS execution_id uuid,
  ADD COLUMN IF NOT EXISTS authorization_id uuid,
  ADD COLUMN IF NOT EXISTS result_hash char(64);

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_production_binding_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_production_binding_check CHECK (
  (request_digest IS NULL AND execution_id IS NULL AND authorization_id IS NULL
   AND result_hash IS NULL)
  OR
  (request_digest ~ '^[a-f0-9]{64}$' AND execution_id IS NULL
   AND authorization_id IS NULL AND result_hash IS NULL
   AND jsonb_typeof(signed_event)='object')
  OR
  (request_digest ~ '^[a-f0-9]{64}$' AND execution_id IS NOT NULL
   AND authorization_id IS NOT NULL AND result_hash ~ '^[a-f0-9]{64}$'
   AND jsonb_typeof(signed_event)='object')
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='audit_events_hash_format_check') THEN
    ALTER TABLE audit_events ADD CONSTRAINT audit_events_hash_format_check CHECK (
      previous_hash ~ '^[a-f0-9]{64}$' AND event_hash ~ '^[a-f0-9]{64}$'
      AND length(key_id) BETWEEN 1 AND 128
      AND jsonb_typeof(safe_payload)='object'
      AND octet_length(safe_payload::text) <= 1048576
    );
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS evidence_chain_heads (
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  last_sequence bigint NOT NULL CHECK (last_sequence > 0),
  chain_hash char(64) NOT NULL CHECK (chain_hash ~ '^[a-f0-9]{64}$'),
  key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,task_id)
);

CREATE TABLE IF NOT EXISTS execution_evidence_receipts (
  tenant_id uuid NOT NULL,
  receipt_id uuid NOT NULL,
  task_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  authorization_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[a-f0-9]{64}$'),
  evidence_ref text NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 2048),
  receipt_payload jsonb NOT NULL CHECK (
    jsonb_typeof(receipt_payload)='object' AND octet_length(receipt_payload::text) <= 1048576
  ),
  persisted_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,receipt_id),
  UNIQUE (tenant_id,idempotency_key),
  UNIQUE (tenant_id,execution_id),
  UNIQUE (tenant_id,evidence_ref)
);

CREATE TABLE IF NOT EXISTS evidence_artifact_requests (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  artifact_hash char(64) NOT NULL CHECK (artifact_hash ~ '^[a-f0-9]{64}$'),
  worm_receipt jsonb NOT NULL CHECK (
    jsonb_typeof(worm_receipt)='object' AND octet_length(worm_receipt::text) <= 65536
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,artifact_hash)
    REFERENCES evidence_artifacts(tenant_id,artifact_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_events_tenant_event
  ON audit_events(tenant_id,event_id);

CREATE TABLE IF NOT EXISTS evidence_event_requests (
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  event_id uuid NOT NULL,
  signed_event jsonb NOT NULL CHECK (
    jsonb_typeof(signed_event)='object' AND octet_length(signed_event::text) <= 1048576
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,event_id),
  FOREIGN KEY (tenant_id,event_id) REFERENCES audit_events(tenant_id,event_id)
);

CREATE TABLE IF NOT EXISTS evidence_package_requests (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  package_id uuid NOT NULL,
  signed_package jsonb NOT NULL CHECK (
    jsonb_typeof(signed_package)='object' AND octet_length(signed_package::text) <= 16777216
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,package_id),
  FOREIGN KEY (tenant_id,package_id) REFERENCES evidence_packages(tenant_id,package_id)
);

ALTER TABLE evaluation_results
  ADD COLUMN IF NOT EXISTS idempotency_key varchar(128),
  ADD COLUMN IF NOT EXISTS chain_head char(64);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM evaluation_results
     WHERE idempotency_key IS NULL OR chain_head IS NULL
  ) THEN
    RAISE EXCEPTION 'EVIDENCE_PRODUCTION_EVALUATION_BACKFILL_REQUIRED';
  END IF;
END
$$;

ALTER TABLE evaluation_results
  ALTER COLUMN idempotency_key SET NOT NULL,
  ALTER COLUMN chain_head SET NOT NULL;
ALTER TABLE evaluation_results DROP CONSTRAINT IF EXISTS evaluation_results_idempotency_format;
ALTER TABLE evaluation_results ADD CONSTRAINT evaluation_results_idempotency_format CHECK (
  idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$' AND chain_head ~ '^[a-f0-9]{64}$'
  AND input_hash ~ '^[a-f0-9]{64}$' AND jsonb_typeof(result)='object'
  AND octet_length(result::text) <= 1048576
);
CREATE UNIQUE INDEX IF NOT EXISTS evaluation_results_tenant_idempotency
  ON evaluation_results(tenant_id,idempotency_key);

CREATE TABLE IF NOT EXISTS evidence_outbox (
  tenant_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  task_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 65536
    AND payload::text !~* '(bearer[[:space:]]+[a-z0-9._~-]{8,}|"(token|secret|private_key|credential_handle)"[[:space:]]*:)'
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,outbox_id),
  UNIQUE (tenant_id,event_type,event_id)
);

ALTER TABLE evidence_outbox DROP CONSTRAINT IF EXISTS evidence_outbox_event_type_check;
ALTER TABLE evidence_outbox ADD CONSTRAINT evidence_outbox_event_type_check CHECK (event_type IN (
  'EXECUTION_EVIDENCE_APPENDED','LIFECYCLE_EVIDENCE_APPENDED','EVIDENCE_ARTIFACT_STORED',
  'EVIDENCE_PACKAGE_BUILT','EVALUATION_RECORDED'
));

CREATE INDEX IF NOT EXISTS audit_events_execution_lookup
  ON audit_events(tenant_id,execution_id) WHERE execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS evidence_receipts_task_sequence
  ON execution_evidence_receipts(tenant_id,task_id,persisted_at);
CREATE INDEX IF NOT EXISTS evidence_outbox_created
  ON evidence_outbox(tenant_id,created_at,outbox_id);
CREATE INDEX IF NOT EXISTS evidence_artifacts_retention
  ON evidence_artifacts(tenant_id,retention_until,artifact_hash);

CREATE OR REPLACE FUNCTION reject_evidence_immutable_record()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
BEGIN
  RAISE EXCEPTION 'EVIDENCE_IMMUTABLE_RECORD';
END
$$;

CREATE OR REPLACE FUNCTION enforce_evidence_chain_head_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
BEGIN
  IF TG_OP='DELETE'
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.task_id IS DISTINCT FROM OLD.task_id
     OR NEW.last_sequence <> OLD.last_sequence + 1
     OR NEW.chain_hash = OLD.chain_hash
     OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'EVIDENCE_CHAIN_HEAD_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS evidence_chain_heads_transition ON evidence_chain_heads;
CREATE TRIGGER evidence_chain_heads_transition BEFORE UPDATE OR DELETE ON evidence_chain_heads
  FOR EACH ROW EXECUTE FUNCTION enforce_evidence_chain_head_transition();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'audit_events','evidence_artifacts','evidence_packages','evaluation_results',
    'execution_evidence_receipts','evidence_artifact_requests','evidence_event_requests','evidence_package_requests',
    'evidence_outbox'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',table_name || '_immutable',table_name);
    EXECUTE format(
      'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_evidence_immutable_record()',
      table_name || '_immutable',table_name
    );
  END LOOP;
END
$$;

DO $$
DECLARE table_name text; policy_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'audit_events','evidence_artifacts','evidence_packages','evaluation_results',
    'evidence_chain_heads','execution_evidence_receipts','evidence_artifact_requests','evidence_event_requests',
    'evidence_package_requests','evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
    FOR policy_name IN
      SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename=table_name
    LOOP
      EXECUTE format('DROP POLICY %I ON %I',policy_name,table_name);
    END LOOP;
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id::text=current_setting(''app.tenant_id'',true)) WITH CHECK (tenant_id::text=current_setting(''app.tenant_id'',true))',
      table_name
    );
  END LOOP;
END
$$;

REVOKE ALL ON TABLE audit_events,evidence_artifacts,evidence_packages,evaluation_results,
  evidence_chain_heads,execution_evidence_receipts,evidence_artifact_requests,
  evidence_event_requests,evidence_package_requests,evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_evidence_immutable_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_evidence_chain_head_transition() FROM PUBLIC;

COMMIT;
