BEGIN;

ALTER TABLE enterprise_api_keys
  ADD COLUMN IF NOT EXISTS credential_ref text;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.enterprise_api_keys'::regclass
      AND conname='enterprise_api_key_credential_ref_safe'
  ) THEN
    ALTER TABLE enterprise_api_keys
      ADD CONSTRAINT enterprise_api_key_credential_ref_safe
      CHECK (credential_ref IS NULL OR (
        credential_ref ~ '^vault-kv://[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+/[0-9a-f-]{36}/[0-9a-f-]{36}#v[1-9][0-9]*$'
        AND length(credential_ref) <= 2048
      )) NOT VALID;
  END IF;
END $$;
ALTER TABLE enterprise_api_keys
  VALIDATE CONSTRAINT enterprise_api_key_credential_ref_safe;

CREATE TABLE IF NOT EXISTS enterprise_principal_assertion_replay (
  tenant_id uuid NOT NULL,
  jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL CHECK (assertion_digest ~ '^[a-f0-9]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, jti),
  CHECK (expires_at > consumed_at - interval '30 seconds')
);

CREATE TABLE IF NOT EXISTS enterprise_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (
    length(idempotency_key) BETWEEN 16 AND 128
    AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  principal_subject text NOT NULL CHECK (length(principal_subject) BETWEEN 1 AND 256),
  principal_assertion_digest char(64) NOT NULL
    CHECK (principal_assertion_digest ~ '^[a-f0-9]{64}$'),
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
  CHECK ((state = 'ACCEPTED') = (receipt IS NOT NULL)),
  CHECK (receipt IS NULL OR (
    receipt->>'schema_version' = 'agenttrust.enterprise-action-receipt.v1'
    AND receipt->>'action_id' = action_id::text
    AND receipt->>'task_id' = task_id::text
    AND receipt->>'accepted' = 'true'
    AND receipt->>'execution_pending' = 'true'
  ))
);

CREATE TABLE IF NOT EXISTS enterprise_resource_versions (
  tenant_id uuid NOT NULL,
  resource text NOT NULL CHECK (
    length(resource) BETWEEN 1 AND 1000
    AND resource !~ E'[\\x00\\r\\n]'
  ),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, resource)
);

CREATE TABLE IF NOT EXISTS enterprise_authority_executions (
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
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1000),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  trace_id text NOT NULL CHECK (length(trace_id) BETWEEN 1 AND 256),
  request jsonb NOT NULL CHECK (
    request->>'schema_version' = 'agenttrust.enterprise-executor-request.v1'
    AND request->>'action_id' = action_id::text
    AND request->>'resource' = resource
    AND NOT (request ? 'api_key')
    AND NOT (request ? 'token')
    AND NOT (request ? 'password')
    AND NOT (request ? 'secret')
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
  CHECK ((state = 'SUCCEEDED') = (safe_result IS NOT NULL)),
  CHECK ((state = 'SUCCEEDED') = (safe_result_digest IS NOT NULL)),
  CHECK (safe_result_digest IS NULL OR safe_result_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state = 'FAILED') = (stable_error IS NOT NULL)),
  CHECK (safe_result IS NULL OR (
    safe_result->>'schema_version' = 'agenttrust.enterprise-mutation-result.v1'
    AND NOT (safe_result::text ~* '"(api_key|secret|token|password)"[[:space:]]*:')
  ))
);

CREATE TABLE IF NOT EXISTS enterprise_authority_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  aggregate_id text NOT NULL CHECK (length(aggregate_id) BETWEEN 1 AND 256),
  payload jsonb NOT NULL,
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  PRIMARY KEY (tenant_id, event_id),
  CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE OR REPLACE FUNCTION enforce_enterprise_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id
     OR OLD.idempotency_key <> NEW.idempotency_key
     OR OLD.request_digest <> NEW.request_digest
     OR OLD.action_id <> NEW.action_id
     OR OLD.action_hash <> NEW.action_hash
     OR OLD.ledger_execution_id <> NEW.ledger_execution_id
     OR OLD.fence_digest <> NEW.fence_digest
     OR OLD.resource <> NEW.resource
     OR OLD.resource_version <> NEW.resource_version
     OR OLD.trace_id <> NEW.trace_id
     OR OLD.request <> NEW.request THEN
    RAISE EXCEPTION 'ENTERPRISE_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state = 'PREPARED' AND NEW.state IN ('EXECUTING','FAILED'))
       OR (OLD.state = 'EXECUTING' AND NEW.state IN ('SUCCEEDED','FAILED','UNKNOWN'))
       OR (OLD.state = NEW.state AND OLD.safe_result IS NOT DISTINCT FROM NEW.safe_result
           AND OLD.safe_result_digest IS NOT DISTINCT FROM NEW.safe_result_digest
           AND OLD.stable_error IS NOT DISTINCT FROM NEW.stable_error)) THEN
    RAISE EXCEPTION 'ENTERPRISE_EXECUTION_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS enterprise_execution_transition_guard
  ON enterprise_authority_executions;
CREATE TRIGGER enterprise_execution_transition_guard
BEFORE UPDATE ON enterprise_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_enterprise_execution_transition();

CREATE OR REPLACE FUNCTION enforce_enterprise_ingress_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id
     OR OLD.idempotency_key <> NEW.idempotency_key
     OR OLD.request_digest <> NEW.request_digest
     OR OLD.action_id <> NEW.action_id
     OR OLD.task_id <> NEW.task_id
     OR OLD.principal_subject <> NEW.principal_subject
     OR OLD.principal_assertion_digest <> NEW.principal_assertion_digest
     OR OLD.envelope <> NEW.envelope
     OR NOT (OLD.state = 'PREPARED' AND NEW.state = 'ACCEPTED'
             OR OLD.state = NEW.state AND OLD.receipt IS NOT DISTINCT FROM NEW.receipt) THEN
    RAISE EXCEPTION 'ENTERPRISE_INGRESS_BINDING_IMMUTABLE';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS enterprise_ingress_immutable_guard ON enterprise_action_ingress;
CREATE TRIGGER enterprise_ingress_immutable_guard
BEFORE UPDATE ON enterprise_action_ingress
FOR EACH ROW EXECUTE FUNCTION enforce_enterprise_ingress_immutable();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'enterprise_principal_assertion_replay',
    'enterprise_action_ingress',
    'enterprise_resource_versions',
    'enterprise_authority_executions',
    'enterprise_authority_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    IF NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename=table_name
        AND policyname='tenant_isolation'
    ) THEN
      EXECUTE format(
        'CREATE POLICY tenant_isolation ON %I USING '
        '(tenant_id::text=current_setting(''app.tenant_id'',true)) WITH CHECK '
        '(tenant_id::text=current_setting(''app.tenant_id'',true))',
        table_name
      );
    END IF;
  END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS enterprise_assertion_expiry_idx
  ON enterprise_principal_assertion_replay (expires_at);
CREATE INDEX IF NOT EXISTS enterprise_ingress_task_idx
  ON enterprise_action_ingress (tenant_id, task_id);
CREATE INDEX IF NOT EXISTS enterprise_execution_state_idx
  ON enterprise_authority_executions (tenant_id, state, updated_at);
CREATE INDEX IF NOT EXISTS enterprise_outbox_pending_idx
  ON enterprise_authority_outbox (tenant_id, created_at) WHERE published_at IS NULL;

REVOKE ALL ON TABLE enterprise_principal_assertion_replay,enterprise_action_ingress,
  enterprise_resource_versions,enterprise_authority_executions,enterprise_authority_outbox
  FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_enterprise_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_enterprise_ingress_immutable() FROM PUBLIC;

-- The externally provisioned enterprise_authority_application_role is granted by the production
-- migration runner after it revokes all existing privileges. This migration deliberately creates
-- no LOGIN role and cannot turn a fixed NOLOGIN role into production identity evidence.

COMMIT;
