BEGIN;
CREATE TABLE IF NOT EXISTS audit_records (
  tenant_id uuid NOT NULL,
  record_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  previous_hash char(64) NOT NULL,
  record_hash char(64) NOT NULL,
  key_id text NOT NULL,
  signature text NOT NULL,
  record_payload jsonb NOT NULL,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, record_id),
  UNIQUE (tenant_id, sequence),
  UNIQUE (tenant_id, record_hash)
);
CREATE INDEX IF NOT EXISTS audit_records_time_idx ON audit_records(tenant_id, occurred_at, sequence);
CREATE TABLE IF NOT EXISTS audit_deletion_proofs (
  tenant_id uuid NOT NULL, deletion_id uuid NOT NULL, policy_id text NOT NULL,
  proof_payload jsonb NOT NULL, proof_digest char(64) NOT NULL,
  executed_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, deletion_id)
);
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['audit_chain_heads','audit_retention_policies','legal_holds','audit_export_manifests','audit_records','audit_deletion_proofs']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=table_name AND policyname='tenant_isolation') THEN
      EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id::text = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id::text = current_setting(''app.tenant_id'', true))', table_name);
    END IF;
  END LOOP;
END $$;
COMMIT;
