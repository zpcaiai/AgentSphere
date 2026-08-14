-- Fail closed for every batch-owned public table with a tenant_id column.
-- Keep this migration last; the integration gate rejects later unprotected tenant tables.
DO $$
DECLARE
  tenant_table record;
  tenant_policy record;
BEGIN
  FOR tenant_table IN
    SELECT DISTINCT columns.table_schema, columns.table_name
      FROM information_schema.columns AS columns
      JOIN information_schema.tables AS tables
        ON tables.table_schema = columns.table_schema
       AND tables.table_name = columns.table_name
     WHERE columns.table_schema = 'public'
       AND columns.column_name = 'tenant_id'
       AND tables.table_type = 'BASE TABLE'
     ORDER BY columns.table_schema, columns.table_name
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',
      tenant_table.table_schema,
      tenant_table.table_name
    );
    EXECUTE format(
      'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',
      tenant_table.table_schema,
      tenant_table.table_name
    );

    -- Normalize policy state instead of merely adding one permissive policy.
    -- PostgreSQL ORs permissive policies; retaining any older broad policy would
    -- silently bypass the canonical tenant predicate.
    FOR tenant_policy IN
      SELECT policyname
        FROM pg_policies
       WHERE schemaname = tenant_table.table_schema
         AND tablename = tenant_table.table_name
    LOOP
      EXECUTE format(
        'DROP POLICY %I ON %I.%I',
        tenant_policy.policyname,
        tenant_table.table_schema,
        tenant_table.table_name
      );
    END LOOP;
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I.%I AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id::text = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id::text = current_setting(''app.tenant_id'', true))',
      tenant_table.table_schema,
      tenant_table.table_name
    );
  END LOOP;
END
$$;
