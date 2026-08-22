-- Signed evidence bridge for state-owning production authorities. Governed
-- actions are bound to the final PEP authorization; authenticated observations
-- are explicitly distinguished and cannot claim a fabricated action binding.
BEGIN;

CREATE TABLE IF NOT EXISTS authority_evidence_event_requests (
  tenant_id uuid NOT NULL,
  authority_event_id uuid NOT NULL,
  task_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL
    CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
  request_digest char(64) NOT NULL
    CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  payload_digest char(64) NOT NULL
    CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  source_kind text NOT NULL
    CHECK (source_kind IN ('GOVERNED_ACTION','AUTHENTICATED_EVENT')),
  control_binding jsonb,
  signed_receipt jsonb NOT NULL CHECK (
    jsonb_typeof(signed_receipt)='object'
    AND octet_length(signed_receipt::text) <= 1048576
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,authority_event_id),
  UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,authority_event_id)
    REFERENCES audit_events(tenant_id,event_id),
  CHECK (
    (source_kind='GOVERNED_ACTION' AND jsonb_typeof(control_binding)='object')
    OR (source_kind='AUTHENTICATED_EVENT' AND control_binding IS NULL)
  )
);

DROP TRIGGER IF EXISTS authority_evidence_event_requests_immutable
  ON authority_evidence_event_requests;
CREATE TRIGGER authority_evidence_event_requests_immutable
  BEFORE UPDATE OR DELETE ON authority_evidence_event_requests
  FOR EACH ROW EXECUTE FUNCTION reject_evidence_immutable_record();

ALTER TABLE authority_evidence_event_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_evidence_event_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON authority_evidence_event_requests;
CREATE POLICY tenant_isolation ON authority_evidence_event_requests
  AS PERMISSIVE FOR ALL TO PUBLIC
  USING (tenant_id::text=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id::text=current_setting('app.tenant_id',true));

ALTER TABLE evidence_outbox DROP CONSTRAINT IF EXISTS evidence_outbox_event_type_check;
ALTER TABLE evidence_outbox ADD CONSTRAINT evidence_outbox_event_type_check
  CHECK (event_type IN (
    'EXECUTION_EVIDENCE_APPENDED','LIFECYCLE_EVIDENCE_APPENDED',
    'AUTHORITY_EVIDENCE_APPENDED','EVIDENCE_ARTIFACT_STORED',
    'EVIDENCE_PACKAGE_BUILT','EVALUATION_RECORDED'
  ));

CREATE INDEX IF NOT EXISTS authority_evidence_task_created
  ON authority_evidence_event_requests(tenant_id,task_id,created_at,authority_event_id);

REVOKE ALL ON TABLE authority_evidence_event_requests FROM PUBLIC;

COMMIT;
