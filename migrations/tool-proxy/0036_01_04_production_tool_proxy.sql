-- Durable Tool Proxy invocation state, audit, outbox, FORCE RLS and least-privilege role.
BEGIN;

CREATE TABLE IF NOT EXISTS tool_proxy_invocations (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL,
  authorization_id text NOT NULL,
  authorization_digest char(64) NOT NULL,
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL,
  fence_digest char(64) NOT NULL,
  action_hash char(64) NOT NULL,
  trace_id varchar(128) NOT NULL,
  tool_id text NOT NULL,
  tool_version text NOT NULL,
  tool_snapshot_hash char(64) NOT NULL,
  registry_revision bigint NOT NULL,
  credential_claims_digest char(64) NOT NULL,
  target_profile_hash char(64) NOT NULL,
  execution_owner uuid,
  execution_lease_until timestamptz,
  state text NOT NULL,
  safe_result jsonb,
  safe_result_digest char(64),
  stable_error varchar(128),
  credential_consumption_id uuid,
  credential_consumption_receipt_digest char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,authorization_id),
  UNIQUE (tenant_id,ledger_execution_id),
  CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  CHECK (authorization_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  CHECK (authorization_digest ~ '^[a-f0-9]{64}$'),
  CHECK (ledger_event_digest ~ '^[a-f0-9]{64}$'),
  CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  CHECK (trace_id ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  CHECK (tool_snapshot_hash ~ '^[a-f0-9]{64}$'),
  CHECK (registry_revision > 0),
  CHECK (credential_claims_digest ~ '^[a-f0-9]{64}$'),
  CHECK (target_profile_hash ~ '^[a-f0-9]{64}$'),
  CHECK (length(tool_id) BETWEEN 1 AND 256 AND length(tool_version) BETWEEN 1 AND 256),
  CHECK (stable_error IS NULL OR stable_error ~ '^PROXY_[A-Z0-9_]{1,121}$'),
  CHECK (state IN ('PREPARED','EXECUTING','SUCCEEDED','FAILED','UNKNOWN')),
  CHECK (
    (state='PREPARED' AND execution_owner IS NULL AND execution_lease_until IS NULL
      AND safe_result IS NULL AND safe_result_digest IS NULL
      AND stable_error IS NULL AND completed_at IS NULL)
    OR
    (state='EXECUTING' AND execution_owner IS NOT NULL AND execution_lease_until IS NOT NULL
      AND execution_lease_until > updated_at AND safe_result IS NULL AND safe_result_digest IS NULL
      AND stable_error IS NULL AND completed_at IS NULL)
    OR
    (state='SUCCEEDED' AND jsonb_typeof(safe_result)='object'
      AND safe_result_digest ~ '^[a-f0-9]{64}$' AND stable_error IS NULL
      AND execution_owner IS NOT NULL AND execution_lease_until IS NULL
      AND credential_consumption_id IS NOT NULL
      AND credential_consumption_receipt_digest ~ '^[a-f0-9]{64}$'
      AND completed_at IS NOT NULL)
    OR
    (state='FAILED' AND execution_owner IS NULL AND execution_lease_until IS NULL
      AND safe_result IS NULL AND safe_result_digest IS NULL
      AND stable_error IS NOT NULL AND completed_at IS NOT NULL)
    OR
    (state='UNKNOWN' AND execution_owner IS NOT NULL AND execution_lease_until IS NULL
      AND safe_result IS NULL AND safe_result_digest IS NULL
      AND stable_error IS NOT NULL AND completed_at IS NOT NULL)
  ),
  CHECK (safe_result IS NULL OR octet_length(safe_result::text) <= 1048576),
  CHECK (safe_result IS NULL OR safe_result::text !~* '(bearer[[:space:]]+[a-z0-9._~-]{8,}|"(credential_handle|workload_credential|private_key)"[[:space:]]*:)')
);

CREATE INDEX IF NOT EXISTS tool_proxy_invocations_state_age
  ON tool_proxy_invocations(tenant_id,state,execution_lease_until,updated_at)
  WHERE state IN ('PREPARED','EXECUTING','UNKNOWN');
CREATE INDEX IF NOT EXISTS tool_proxy_invocations_action
  ON tool_proxy_invocations(tenant_id,action_hash,created_at DESC);

CREATE TABLE IF NOT EXISTS tool_proxy_audit_events (
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  event_type text NOT NULL CHECK (event_type IN (
    'TOOL_EXECUTION_STARTED','TOOL_EXECUTION_REJECTED',
    'TOOL_EXECUTION_SUCCEEDED','TOOL_EXECUTION_UNKNOWN'
  )),
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,idempotency_key,event_type),
  FOREIGN KEY (tenant_id,idempotency_key)
    REFERENCES tool_proxy_invocations(tenant_id,idempotency_key),
  CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 65536),
  CHECK (payload::text !~* '(bearer[[:space:]]+[a-z0-9._~-]{8,}|"(credential_handle|workload_credential|private_key|target_secret)"[[:space:]]*:)')
);

CREATE TABLE IF NOT EXISTS tool_proxy_outbox (
  outbox_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type IN (
    'TOOL_EXECUTION_STARTED','TOOL_EXECUTION_REJECTED',
    'TOOL_EXECUTION_SUCCEEDED','TOOL_EXECUTION_UNKNOWN'
  )),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,outbox_id),
  UNIQUE (tenant_id,event_id),
  FOREIGN KEY (tenant_id,event_id)
    REFERENCES tool_proxy_audit_events(tenant_id,event_id),
  CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 65536),
  CHECK (payload::text !~* '(bearer[[:space:]]+[a-z0-9._~-]{8,}|"(credential_handle|workload_credential|private_key|target_secret)"[[:space:]]*:)')
);

CREATE OR REPLACE FUNCTION enforce_tool_proxy_invocation_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'TOOL_PROXY_INVOCATION_IMMUTABLE';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
     OR NEW.authorization_digest IS DISTINCT FROM OLD.authorization_digest
     OR NEW.ledger_execution_id IS DISTINCT FROM OLD.ledger_execution_id
     OR NEW.ledger_event_id IS DISTINCT FROM OLD.ledger_event_id
     OR NEW.ledger_event_digest IS DISTINCT FROM OLD.ledger_event_digest
     OR NEW.fence_digest IS DISTINCT FROM OLD.fence_digest
     OR NEW.action_hash IS DISTINCT FROM OLD.action_hash
     OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
     OR NEW.tool_id IS DISTINCT FROM OLD.tool_id
     OR NEW.tool_version IS DISTINCT FROM OLD.tool_version
     OR NEW.tool_snapshot_hash IS DISTINCT FROM OLD.tool_snapshot_hash
     OR NEW.registry_revision IS DISTINCT FROM OLD.registry_revision
     OR NEW.credential_claims_digest IS DISTINCT FROM OLD.credential_claims_digest
     OR NEW.target_profile_hash IS DISTINCT FROM OLD.target_profile_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'TOOL_PROXY_INVOCATION_BINDING_IMMUTABLE';
  END IF;
  IF NEW.updated_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'TOOL_PROXY_INVOCATION_TIMESTAMP_INVALID';
  END IF;
  IF NOT (
    (OLD.state='PREPARED' AND NEW.state='EXECUTING'
      AND OLD.execution_owner IS NULL AND OLD.execution_lease_until IS NULL
      AND NEW.execution_owner IS NOT NULL
      AND NEW.execution_lease_until BETWEEN now()+interval '5 seconds' AND now()+interval '1 hour'
      AND NEW.completed_at IS NULL)
    OR
    (OLD.state='PREPARED' AND NEW.state='FAILED'
      AND NEW.execution_owner IS NULL AND NEW.execution_lease_until IS NULL
      AND NEW.completed_at IS NOT DISTINCT FROM now())
    OR
    (OLD.state='EXECUTING' AND NEW.state IN ('SUCCEEDED','UNKNOWN')
      AND NEW.execution_owner=OLD.execution_owner AND NEW.execution_lease_until IS NULL
      AND NEW.completed_at IS NOT DISTINCT FROM now())
  ) THEN
    RAISE EXCEPTION 'TOOL_PROXY_INVOCATION_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION reject_tool_proxy_immutable_record()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'TOOL_PROXY_IMMUTABLE_RECORD';
END
$$;

DROP TRIGGER IF EXISTS tool_proxy_invocations_transition ON tool_proxy_invocations;
CREATE TRIGGER tool_proxy_invocations_transition
  BEFORE UPDATE OR DELETE ON tool_proxy_invocations
  FOR EACH ROW EXECUTE FUNCTION enforce_tool_proxy_invocation_transition();
DROP TRIGGER IF EXISTS tool_proxy_audit_events_immutable ON tool_proxy_audit_events;
CREATE TRIGGER tool_proxy_audit_events_immutable
  BEFORE UPDATE OR DELETE ON tool_proxy_audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_tool_proxy_immutable_record();
DROP TRIGGER IF EXISTS tool_proxy_outbox_immutable ON tool_proxy_outbox;
CREATE TRIGGER tool_proxy_outbox_immutable
  BEFORE UPDATE OR DELETE ON tool_proxy_outbox
  FOR EACH ROW EXECUTE FUNCTION reject_tool_proxy_immutable_record();

DO $$
DECLARE
  table_name text;
  policy_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'tool_proxy_invocations','tool_proxy_audit_events','tool_proxy_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
    FOR policy_name IN
      SELECT policyname FROM pg_policies
       WHERE schemaname='public' AND tablename=table_name
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

REVOKE ALL ON TABLE tool_proxy_invocations,tool_proxy_audit_events,tool_proxy_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_tool_proxy_invocation_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_tool_proxy_immutable_record() FROM PUBLIC;

-- Application LOGIN roles are externally pre-provisioned and granted by the
-- production migration runner. This migration deliberately creates no role and
-- grants no application privilege, preventing a fixed NOLOGIN role from being
-- mistaken for the runtime identity.

COMMIT;
