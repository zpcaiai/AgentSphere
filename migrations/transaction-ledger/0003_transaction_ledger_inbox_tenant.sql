BEGIN;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM execution_inbox WHERE tenant_id IS NULL) THEN
    RAISE EXCEPTION 'LEDGER_INBOX_TENANT_BACKFILL_REQUIRED';
  END IF;
END
$$;

ALTER TABLE execution_inbox ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE execution_inbox DROP CONSTRAINT IF EXISTS execution_inbox_pkey;
ALTER TABLE execution_inbox
  ADD CONSTRAINT execution_inbox_pkey
  PRIMARY KEY (tenant_id, consumer_id, message_id);
ALTER TABLE execution_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_inbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON execution_inbox;
CREATE POLICY tenant_isolation ON execution_inbox
  USING (tenant_id::text = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

COMMIT;
