BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'executions_tenant_execution_unique'
  ) THEN
    ALTER TABLE executions
      ADD CONSTRAINT executions_tenant_execution_unique UNIQUE (tenant_id, execution_id);
  END IF;
END
$$;

ALTER TABLE execution_attempts ADD COLUMN IF NOT EXISTS tenant_id uuid;
UPDATE execution_attempts AS attempt
   SET tenant_id = execution.tenant_id
  FROM executions AS execution
 WHERE attempt.execution_id = execution.execution_id
   AND attempt.tenant_id IS NULL;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM execution_attempts WHERE tenant_id IS NULL) THEN
    RAISE EXCEPTION 'LEDGER_ATTEMPT_TENANT_BACKFILL_INCOMPLETE';
  END IF;
END
$$;
ALTER TABLE execution_attempts ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE execution_attempts DROP CONSTRAINT IF EXISTS execution_attempts_execution_id_fkey;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'execution_attempts_execution_tenant_fk'
  ) THEN
    ALTER TABLE execution_attempts
      ADD CONSTRAINT execution_attempts_execution_tenant_fk
      FOREIGN KEY (tenant_id, execution_id)
      REFERENCES executions (tenant_id, execution_id);
  END IF;
END
$$;

ALTER TABLE idempotency_records DROP CONSTRAINT IF EXISTS idempotency_records_execution_id_fkey;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'idempotency_records_execution_tenant_fk'
  ) THEN
    ALTER TABLE idempotency_records
      ADD CONSTRAINT idempotency_records_execution_tenant_fk
      FOREIGN KEY (tenant_id, execution_id)
      REFERENCES executions (tenant_id, execution_id);
  END IF;
END
$$;

ALTER TABLE compensation_plans DROP CONSTRAINT IF EXISTS compensation_plans_forward_execution_id_fkey;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'compensation_plans_execution_tenant_fk'
  ) THEN
    ALTER TABLE compensation_plans
      ADD CONSTRAINT compensation_plans_execution_tenant_fk
      FOREIGN KEY (tenant_id, forward_execution_id)
      REFERENCES executions (tenant_id, execution_id);
  END IF;
END
$$;

ALTER TABLE execution_outbox ADD COLUMN IF NOT EXISTS tenant_id uuid;
UPDATE execution_outbox AS outbox
   SET tenant_id = execution.tenant_id
  FROM executions AS execution
 WHERE outbox.execution_id = execution.execution_id
   AND outbox.tenant_id IS NULL;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM execution_outbox WHERE tenant_id IS NULL) THEN
    RAISE EXCEPTION 'LEDGER_OUTBOX_TENANT_BACKFILL_INCOMPLETE';
  END IF;
END
$$;

-- Existing inbox rows cannot be assigned to a tenant from their legacy columns.
-- Keep this additive step committed; 0003 requires the operator to explicitly
-- backfill any legacy rows before it makes the column required and enables FORCE RLS.
-- The release runner does not start application workloads between these migrations.
ALTER TABLE execution_inbox ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE execution_outbox ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE execution_outbox DROP CONSTRAINT IF EXISTS execution_outbox_execution_id_fkey;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'execution_outbox_execution_tenant_fk'
  ) THEN
    ALTER TABLE execution_outbox
      ADD CONSTRAINT execution_outbox_execution_tenant_fk
      FOREIGN KEY (tenant_id, execution_id)
      REFERENCES executions (tenant_id, execution_id);
  END IF;
END
$$;

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'executions',
    'execution_attempts',
    'idempotency_records',
    'compensation_plans',
    'resource_versions',
    'execution_outbox'
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

COMMIT;
