-- Production Audit Retention Authority: exact replay, immutable signed chains and exports,
-- independently releasable Legal Hold, provider deletion proofs, outbox and FORCE RLS.
-- Deployment tooling owns runtime LOGIN roles and least-privilege grants.
BEGIN;

ALTER TABLE audit_records
  ADD COLUMN IF NOT EXISTS request_id varchar(256),
  ADD COLUMN IF NOT EXISTS request_digest char(64);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='audit_records_production_check') THEN
    ALTER TABLE audit_records ADD CONSTRAINT audit_records_production_check CHECK (
      sequence > 0
      AND previous_hash ~ '^[a-f0-9]{64}$'
      AND record_hash ~ '^[a-f0-9]{64}$'
      AND length(key_id) BETWEEN 1 AND 128
      AND length(signature) BETWEEN 1 AND 1024
      AND jsonb_typeof(record_payload)='object'
      AND octet_length(record_payload::text) <= 1048576
      AND (
        (request_id IS NULL AND request_digest IS NULL)
        OR
        (request_id ~ '^[A-Za-z0-9._:/-]{1,256}$' AND request_digest ~ '^[a-f0-9]{64}$')
      )
    );
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS audit_records_tenant_request
  ON audit_records(tenant_id,request_id) WHERE request_id IS NOT NULL;

ALTER TABLE audit_retention_policies
  ADD COLUMN IF NOT EXISTS event_type varchar(128),
  ADD COLUMN IF NOT EXISTS classification varchar(32),
  ADD COLUMN IF NOT EXISTS compliance_profile varchar(128),
  ADD COLUMN IF NOT EXISTS anonymize_after_seconds bigint;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='audit_retention_policy_production_check') THEN
    ALTER TABLE audit_retention_policies ADD CONSTRAINT audit_retention_policy_production_check CHECK (
      policy_digest ~ '^[a-f0-9]{64}$'
      AND retention_seconds > 0
      AND (
        (event_type IS NULL AND classification IS NULL AND compliance_profile IS NULL)
        OR
        (length(event_type) BETWEEN 1 AND 128
         AND classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')
         AND length(compliance_profile) BETWEEN 1 AND 128)
      )
      AND (anonymize_after_seconds IS NULL OR anonymize_after_seconds > 0)
    );
  END IF;
END
$$;
CREATE INDEX IF NOT EXISTS audit_retention_policy_resolution
  ON audit_retention_policies(tenant_id,policy_id,effective_at DESC,policy_version DESC);

ALTER TABLE legal_holds
  ADD COLUMN IF NOT EXISTS task_id uuid,
  ADD COLUMN IF NOT EXISTS actor_subject varchar(512),
  ADD COLUMN IF NOT EXISTS resource_prefix varchar(2048),
  ADD COLUMN IF NOT EXISTS starts_at timestamptz,
  ADD COLUMN IF NOT EXISTS ends_at timestamptz,
  ADD COLUMN IF NOT EXISTS hold_payload jsonb,
  ADD COLUMN IF NOT EXISTS release_reason varchar(256);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='legal_holds_production_check') THEN
    ALTER TABLE legal_holds ADD CONSTRAINT legal_holds_production_check CHECK (
      length(object_ref) BETWEEN 1 AND 2048
      AND length(reason) BETWEEN 1 AND 256
      AND length(placed_by) BETWEEN 1 AND 512
      AND (released_at IS NULL OR (released_by IS NOT NULL AND release_reason IS NOT NULL))
      AND (starts_at IS NULL OR ends_at IS NULL OR ends_at >= starts_at)
      AND (hold_payload IS NULL OR (jsonb_typeof(hold_payload)='object' AND octet_length(hold_payload::text) <= 65536))
    );
  END IF;
END
$$;
CREATE INDEX IF NOT EXISTS legal_holds_active_scope
  ON legal_holds(tenant_id,starts_at,ends_at) WHERE released_at IS NULL;

ALTER TABLE audit_export_manifests
  ADD COLUMN IF NOT EXISTS request_digest char(64),
  ADD COLUMN IF NOT EXISTS idempotency_key varchar(128),
  ADD COLUMN IF NOT EXISTS package_payload jsonb,
  ADD COLUMN IF NOT EXISTS worm_receipt jsonb;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='audit_export_production_check') THEN
    ALTER TABLE audit_export_manifests ADD CONSTRAINT audit_export_production_check CHECK (
      manifest_digest ~ '^[a-f0-9]{64}$'
      AND chain_head ~ '^[a-f0-9]{64}$'
      AND length(object_ref) BETWEEN 1 AND 2048
      AND (
        (request_digest IS NULL AND idempotency_key IS NULL AND package_payload IS NULL AND worm_receipt IS NULL)
        OR
        (request_digest ~ '^[a-f0-9]{64}$'
         AND idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'
         AND jsonb_typeof(package_payload)='object'
         AND octet_length(package_payload::text) <= 67108864
         AND jsonb_typeof(worm_receipt)='object'
         AND octet_length(worm_receipt::text) <= 65536)
      )
    );
  END IF;
END
$$;
CREATE UNIQUE INDEX IF NOT EXISTS audit_export_tenant_idempotency
  ON audit_export_manifests(tenant_id,idempotency_key) WHERE idempotency_key IS NOT NULL;

ALTER TABLE audit_deletion_proofs
  ADD COLUMN IF NOT EXISTS request_digest char(64),
  ADD COLUMN IF NOT EXISTS idempotency_key varchar(128),
  ADD COLUMN IF NOT EXISTS object_receipts jsonb;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='audit_deletion_production_check') THEN
    ALTER TABLE audit_deletion_proofs ADD CONSTRAINT audit_deletion_production_check CHECK (
      proof_digest ~ '^[a-f0-9]{64}$'
      AND jsonb_typeof(proof_payload)='object'
      AND octet_length(proof_payload::text) <= 16777216
      AND (
        (request_digest IS NULL AND idempotency_key IS NULL AND object_receipts IS NULL)
        OR
        (request_digest ~ '^[a-f0-9]{64}$'
         AND idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'
         AND jsonb_typeof(object_receipts)='array'
         AND octet_length(object_receipts::text) <= 16777216)
      )
    );
  END IF;
END
$$;
CREATE UNIQUE INDEX IF NOT EXISTS audit_deletion_tenant_idempotency
  ON audit_deletion_proofs(tenant_id,idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_operation_replays (
  tenant_id uuid NOT NULL,
  operation varchar(64) NOT NULL CHECK (operation IN (
    'APPEND','QUERY','AUTHORITATIVE_QUERY','EXPORT','DELETE','RETENTION_POLICY','LEGAL_HOLD_PLACE',
    'LEGAL_HOLD_RELEASE','CONTROL_REGISTER','EVIDENCE_NODE','EVIDENCE_EDGE'
  )),
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  response_digest char(64) NOT NULL CHECK (response_digest ~ '^[a-f0-9]{64}$'),
  response_body jsonb NOT NULL CHECK (
    jsonb_typeof(response_body)='object' AND octet_length(response_body::text) <= 100663296
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,operation,idempotency_key)
);

CREATE TABLE IF NOT EXISTS audit_human_assertion_uses (
  tenant_id uuid NOT NULL,
  assertion_jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL CHECK (assertion_digest ~ '^[a-f0-9]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  idempotency_key varchar(128) NOT NULL
    CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]{1,128}$'),
  operation varchar(64) NOT NULL CHECK (operation='AUTHORITATIVE_QUERY'),
  actor_subject varchar(512) NOT NULL CHECK (
    length(actor_subject) BETWEEN 1 AND 512
    AND position(chr(13) in actor_subject)=0
    AND position(chr(10) in actor_subject)=0
  ),
  client_identity varchar(512) NOT NULL CHECK (
    client_identity ~ '^(DNS|URI):[^[:space:]]{1,508}$'
  ),
  service_subject varchar(256) NOT NULL CHECK (
    service_subject ~ '^[A-Za-z0-9_.:/@-]{1,256}$'
  ),
  scope varchar(128) NOT NULL CHECK (scope='audit:query'),
  receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  used_at timestamptz NOT NULL CHECK (used_at < expires_at),
  PRIMARY KEY (tenant_id,assertion_jti),
  UNIQUE (tenant_id,assertion_digest),
  UNIQUE (tenant_id,operation,idempotency_key)
);
CREATE INDEX IF NOT EXISTS audit_human_assertion_expiry
  ON audit_human_assertion_uses(tenant_id,expires_at);

CREATE TABLE IF NOT EXISTS audit_retention_outbox (
  tenant_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  task_id uuid NOT NULL,
  event_type varchar(64) NOT NULL CHECK (event_type IN (
    'AUDIT_RECORDS_APPENDED','AUDIT_QUERY_RECORDED','AUDIT_EXPORT_STORED',
    'AUTHORITATIVE_AUDIT_QUERY_RECORDED',
    'RETENTION_DELETION_PROVED','RETENTION_POLICY_REGISTERED','LEGAL_HOLD_PLACED',
    'LEGAL_HOLD_RELEASED','CONTROL_REGISTERED','EVIDENCE_NODE_ADDED','EVIDENCE_EDGE_ADDED'
  )),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 65536
    AND payload::text !~* '(bearer[[:space:]]+[a-z0-9._~-]{8,}|"(token|secret|private_key|credential_handle)"[[:space:]]*:)'
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,outbox_id),
  UNIQUE (tenant_id,event_type,payload_digest)
);
CREATE INDEX IF NOT EXISTS audit_retention_outbox_created
  ON audit_retention_outbox(tenant_id,created_at,outbox_id);

CREATE TABLE IF NOT EXISTS audit_control_definitions (
  tenant_id uuid NOT NULL,
  control_id varchar(256) NOT NULL,
  control_digest char(64) NOT NULL CHECK (control_digest ~ '^[a-f0-9]{64}$'),
  definition jsonb NOT NULL CHECK (
    jsonb_typeof(definition)='object' AND octet_length(definition::text) <= 1048576
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,control_id)
);

CREATE TABLE IF NOT EXISTS audit_evidence_nodes (
  tenant_id uuid NOT NULL,
  node_id varchar(512) NOT NULL,
  node_type varchar(128) NOT NULL,
  node_digest char(64) NOT NULL CHECK (node_digest ~ '^[a-f0-9]{64}$'),
  classification varchar(32) NOT NULL CHECK (
    classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')
  ),
  node_payload jsonb NOT NULL CHECK (
    jsonb_typeof(node_payload)='object' AND octet_length(node_payload::text) <= 1048576
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,node_id)
);

CREATE TABLE IF NOT EXISTS audit_evidence_edges (
  tenant_id uuid NOT NULL,
  from_node varchar(512) NOT NULL,
  relation varchar(128) NOT NULL,
  to_node varchar(512) NOT NULL,
  edge_digest char(64) NOT NULL CHECK (edge_digest ~ '^[a-f0-9]{64}$'),
  edge_payload jsonb NOT NULL CHECK (
    jsonb_typeof(edge_payload)='object' AND octet_length(edge_payload::text) <= 1048576
  ),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,from_node,relation,to_node),
  FOREIGN KEY (tenant_id,from_node) REFERENCES audit_evidence_nodes(tenant_id,node_id),
  FOREIGN KEY (tenant_id,to_node) REFERENCES audit_evidence_nodes(tenant_id,node_id)
);

CREATE OR REPLACE FUNCTION reject_audit_immutable_record()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
BEGIN
  RAISE EXCEPTION 'AUDIT_IMMUTABLE_RECORD';
END
$$;

CREATE OR REPLACE FUNCTION enforce_audit_chain_head_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
BEGIN
  IF TG_OP='DELETE'
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.stream_id IS DISTINCT FROM OLD.stream_id
     OR NEW.last_sequence <= OLD.last_sequence
     OR NEW.chain_hash = OLD.chain_hash
     OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'AUDIT_CHAIN_HEAD_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION enforce_legal_hold_release_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
BEGIN
  IF TG_OP='DELETE'
     OR OLD.released_at IS NOT NULL
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.hold_id IS DISTINCT FROM OLD.hold_id
     OR NEW.object_ref IS DISTINCT FROM OLD.object_ref
     OR NEW.reason IS DISTINCT FROM OLD.reason
     OR NEW.placed_by IS DISTINCT FROM OLD.placed_by
     OR NEW.placed_at IS DISTINCT FROM OLD.placed_at
     OR NEW.task_id IS DISTINCT FROM OLD.task_id
     OR NEW.actor_subject IS DISTINCT FROM OLD.actor_subject
     OR NEW.resource_prefix IS DISTINCT FROM OLD.resource_prefix
     OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
     OR NEW.ends_at IS DISTINCT FROM OLD.ends_at
     OR NEW.hold_payload IS DISTINCT FROM OLD.hold_payload
     OR NEW.released_at IS NULL
     OR NEW.released_by IS NULL
     OR NEW.release_reason IS NULL
     OR NEW.released_by = ''
     OR NEW.release_reason = ''
     OR NEW.released_by = OLD.placed_by
     OR NEW.released_at < OLD.placed_at
  THEN
    RAISE EXCEPTION 'LEGAL_HOLD_RELEASE_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS audit_chain_heads_transition ON audit_chain_heads;
CREATE TRIGGER audit_chain_heads_transition BEFORE UPDATE OR DELETE ON audit_chain_heads
  FOR EACH ROW EXECUTE FUNCTION enforce_audit_chain_head_transition();

DROP TRIGGER IF EXISTS legal_holds_release_transition ON legal_holds;
CREATE TRIGGER legal_holds_release_transition BEFORE UPDATE OR DELETE ON legal_holds
  FOR EACH ROW EXECUTE FUNCTION enforce_legal_hold_release_transition();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'audit_records','audit_retention_policies','audit_export_manifests',
    'audit_deletion_proofs','audit_operation_replays','audit_retention_outbox',
    'audit_human_assertion_uses','audit_control_definitions','audit_evidence_nodes',
    'audit_evidence_edges'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',table_name || '_immutable',table_name);
    EXECUTE format(
      'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_audit_immutable_record()',
      table_name || '_immutable',table_name
    );
  END LOOP;
END
$$;

DO $$
DECLARE table_name text; policy_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'audit_chain_heads','audit_retention_policies','legal_holds','audit_export_manifests',
    'audit_records','audit_deletion_proofs','audit_operation_replays','audit_retention_outbox',
    'audit_human_assertion_uses','audit_control_definitions','audit_evidence_nodes',
    'audit_evidence_edges'
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

REVOKE ALL ON TABLE audit_chain_heads,audit_retention_policies,legal_holds,
  audit_export_manifests,audit_records,audit_deletion_proofs,audit_operation_replays,
  audit_retention_outbox,audit_human_assertion_uses,audit_control_definitions,
  audit_evidence_nodes,audit_evidence_edges
  FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_audit_immutable_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_audit_chain_head_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_legal_hold_release_transition() FROM PUBLIC;

COMMIT;
