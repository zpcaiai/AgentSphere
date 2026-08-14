BEGIN;

CREATE TABLE IF NOT EXISTS enterprise_remote_actions (
  tenant_id uuid NOT NULL,
  action_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
  request_digest char(64) NOT NULL,
  operation text NOT NULL CHECK (operation <> ''),
  resource text NOT NULL CHECK (resource <> ''),
  request_payload jsonb NOT NULL,
  status text NOT NULL CHECK (
    status IN ('PENDING', 'DISPATCHED', 'COMPLETED', 'UNKNOWN', 'FAILED')
  ),
  response_payload jsonb,
  evidence_ref text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error_code text,
  next_attempt_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  dispatched_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, action_id),
  UNIQUE (tenant_id, idempotency_key),
  CHECK (jsonb_typeof(request_payload) = 'object'),
  CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
  CHECK (status <> 'COMPLETED' OR response_payload IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS enterprise_remote_actions_dispatch_idx
  ON enterprise_remote_actions (tenant_id, status, next_attempt_at, created_at)
  WHERE status IN ('PENDING', 'DISPATCHED', 'UNKNOWN');

CREATE TABLE IF NOT EXISTS enterprise_approval_intents (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
  intent_digest char(64) NOT NULL,
  case_id uuid NOT NULL,
  actor_subject text NOT NULL CHECK (actor_subject <> ''),
  decision text NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
  observed_action_hash char(64) NOT NULL,
  observed_resource_version text NOT NULL CHECK (observed_resource_version <> ''),
  reason_digest char(64) NOT NULL,
  status text NOT NULL CHECK (
    status IN ('PENDING', 'DISPATCHED', 'COMPLETED', 'UNKNOWN', 'FAILED')
  ),
  evidence_ref text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error_code text,
  next_attempt_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  dispatched_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, idempotency_key),
  CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
  CHECK (status <> 'COMPLETED' OR evidence_ref IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS enterprise_approval_intents_dispatch_idx
  ON enterprise_approval_intents (tenant_id, status, next_attempt_at, created_at)
  WHERE status IN ('PENDING', 'DISPATCHED', 'UNKNOWN');

CREATE OR REPLACE FUNCTION enterprise_remote_action_timestamps()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  IF NEW.status = 'DISPATCHED' AND NEW.dispatched_at IS NULL THEN
    NEW.dispatched_at = now();
  END IF;
  IF NEW.status = 'COMPLETED' AND NEW.completed_at IS NULL THEN
    NEW.completed_at = now();
  ELSIF NEW.status <> 'COMPLETED' THEN
    NEW.completed_at = NULL;
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS enterprise_remote_action_timestamps_trigger
  ON enterprise_remote_actions;
CREATE TRIGGER enterprise_remote_action_timestamps_trigger
  BEFORE INSERT OR UPDATE ON enterprise_remote_actions
  FOR EACH ROW EXECUTE FUNCTION enterprise_remote_action_timestamps();

DROP TRIGGER IF EXISTS enterprise_approval_intent_timestamps_trigger
  ON enterprise_approval_intents;
CREATE TRIGGER enterprise_approval_intent_timestamps_trigger
  BEFORE INSERT OR UPDATE ON enterprise_approval_intents
  FOR EACH ROW EXECUTE FUNCTION enterprise_remote_action_timestamps();

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'enterprise_remote_actions',
    'enterprise_approval_intents'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id::text = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id::text = current_setting(''app.tenant_id'', true))',
      table_name
    );
  END LOOP;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'enterprise_remote_action_tenant_fk'
  ) THEN
    ALTER TABLE enterprise_remote_actions
      ADD CONSTRAINT enterprise_remote_action_tenant_fk
      FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants (tenant_id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'enterprise_approval_intent_tenant_fk'
  ) THEN
    ALTER TABLE enterprise_approval_intents
      ADD CONSTRAINT enterprise_approval_intent_tenant_fk
      FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants (tenant_id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'enterprise_approval_intent_case_fk'
  ) THEN
    ALTER TABLE enterprise_approval_intents
      ADD CONSTRAINT enterprise_approval_intent_case_fk
      FOREIGN KEY (tenant_id, case_id) REFERENCES approval_cases (tenant_id, case_id);
  END IF;
END
$$;

COMMIT;
