BEGIN;

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'orchestrator_tasks',
    'orchestrator_steps',
    'orchestrator_commands'
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
    SELECT 1 FROM pg_constraint WHERE conname = 'orchestrator_steps_task_fk'
  ) THEN
    ALTER TABLE orchestrator_steps
      ADD CONSTRAINT orchestrator_steps_task_fk
      FOREIGN KEY (tenant_id, task_id)
      REFERENCES orchestrator_tasks (tenant_id, task_id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'orchestrator_commands_task_fk'
  ) THEN
    ALTER TABLE orchestrator_commands
      ADD CONSTRAINT orchestrator_commands_task_fk
      FOREIGN KEY (tenant_id, task_id)
      REFERENCES orchestrator_tasks (tenant_id, task_id);
  END IF;
END
$$;

COMMIT;
