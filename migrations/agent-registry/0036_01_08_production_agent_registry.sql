BEGIN;

-- Existing minimal Batch 30 tables are upgraded in place.  New columns are nullable for legacy
-- rows so the migration never invents ownership/BOM evidence; production readiness fails closed
-- until legitimate rows are backfilled through the governed APIs.
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS ownership_version bigint;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS ownership_confirmed_at timestamptz;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS ownership_review_due_at timestamptz;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS agent_type text;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS endpoints jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS identity_refs jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS tool_refs jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS pack_refs jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS requested_permissions jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS approved_permissions jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS bom jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS last_activity_at timestamptz;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS registered_by text;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS registration_source text;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS registration_provenance jsonb;
ALTER TABLE agent_assets ADD COLUMN IF NOT EXISTS record_version bigint;

ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS source text;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS endpoint text;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS protocol text;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS component_digests jsonb;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS provenance_ref text;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS observation_key char(64);
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS ingested_by text;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS ingested_at timestamptz;
ALTER TABLE agent_discovery_facts ADD COLUMN IF NOT EXISTS trust_state text;

ALTER TABLE agent_posture_findings ALTER COLUMN agent_id DROP NOT NULL;
ALTER TABLE agent_posture_findings ADD COLUMN IF NOT EXISTS observation_id uuid;
ALTER TABLE agent_posture_findings ADD COLUMN IF NOT EXISTS reason_code text;
ALTER TABLE agent_posture_findings ADD COLUMN IF NOT EXISTS condition_key char(64);
ALTER TABLE agent_posture_findings ADD COLUMN IF NOT EXISTS finding_key char(64);
ALTER TABLE agent_posture_findings ADD COLUMN IF NOT EXISTS detected_at timestamptz;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agent_assets_complete_write') THEN
    ALTER TABLE agent_assets ADD CONSTRAINT agent_assets_complete_write CHECK (
      display_name IS NOT NULL AND length(display_name) BETWEEN 1 AND 256 AND
      ownership_version IS NOT NULL AND ownership_version > 0 AND
      ownership_review_due_at IS NOT NULL AND ownership_review_due_at > registered_at AND
      agent_type IS NOT NULL AND length(agent_type) BETWEEN 1 AND 128 AND
      endpoints IS NOT NULL AND jsonb_typeof(endpoints)='array' AND jsonb_array_length(endpoints) BETWEEN 1 AND 100 AND
      identity_refs IS NOT NULL AND jsonb_typeof(identity_refs)='array' AND jsonb_array_length(identity_refs) BETWEEN 1 AND 1000 AND
      tool_refs IS NOT NULL AND jsonb_typeof(tool_refs)='array' AND jsonb_array_length(tool_refs) <= 1000 AND
      pack_refs IS NOT NULL AND jsonb_typeof(pack_refs)='array' AND jsonb_array_length(pack_refs) <= 1000 AND
      requested_permissions IS NOT NULL AND jsonb_typeof(requested_permissions)='array' AND jsonb_array_length(requested_permissions) <= 2000 AND
      approved_permissions IS NOT NULL AND jsonb_typeof(approved_permissions)='array' AND jsonb_array_length(approved_permissions) <= 2000 AND
      bom IS NOT NULL AND jsonb_typeof(bom)='object' AND
      last_activity_at IS NOT NULL AND registered_by IS NOT NULL AND
      registration_source IN ('EXPLICIT_REGISTRATION','GOVERNED_IMPORT') AND
      registration_provenance IS NOT NULL AND jsonb_typeof(registration_provenance)='object' AND
      record_version IS NOT NULL AND record_version > 0
    ) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agent_assets_ownership_confirmation') THEN
    ALTER TABLE agent_assets ADD CONSTRAINT agent_assets_ownership_confirmation CHECK (
      ownership_confirmed_at IS NULL OR ownership_confirmed_at <= ownership_review_due_at
    ) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agent_discovery_untrusted_only') THEN
    ALTER TABLE agent_discovery_facts ADD CONSTRAINT agent_discovery_untrusted_only CHECK (
      source IN ('PROTOCOL_DISCOVERY','NETWORK_OBSERVATION','LOG_OBSERVATION','IMPORT') AND
      endpoint IS NOT NULL AND protocol IS NOT NULL AND component_digests IS NOT NULL AND
      jsonb_typeof(component_digests)='object' AND provenance_ref IS NOT NULL AND
      observation_key ~ '^[a-f0-9]{64}$' AND ingested_by IS NOT NULL AND ingested_at IS NOT NULL AND
      trust_state='UNTRUSTED_OBSERVATION' AND reconciled_agent_id IS NULL
    ) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agent_posture_finding_complete') THEN
    ALTER TABLE agent_posture_findings ADD CONSTRAINT agent_posture_finding_complete CHECK (
      posture IN ('SHADOW','ORPHAN','DORMANT','OVERPRIVILEGED','DRIFTED','REVOKED_BUT_ACTIVE') AND
      severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND
      reason_code IS NOT NULL AND length(reason_code) BETWEEN 1 AND 128 AND
      condition_key ~ '^[a-f0-9]{64}$' AND finding_key ~ '^[a-f0-9]{64}$' AND detected_at IS NOT NULL AND
      (agent_id IS NOT NULL OR observation_id IS NOT NULL)
    ) NOT VALID;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS agent_boms (
  tenant_id uuid NOT NULL,
  agent_id text NOT NULL,
  bom_digest char(64) NOT NULL CHECK (bom_digest ~ '^[a-f0-9]{64}$'),
  bom jsonb NOT NULL CHECK (jsonb_typeof(bom)='object'),
  generated_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL,
  recorded_by text NOT NULL CHECK (length(recorded_by) BETWEEN 1 AND 512),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,agent_id,bom_digest),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agent_assets(tenant_id,agent_id)
);

CREATE TABLE IF NOT EXISTS agent_ownership_confirmations (
  tenant_id uuid NOT NULL,
  agent_id text NOT NULL,
  ownership_version bigint NOT NULL CHECK (ownership_version > 0),
  role text NOT NULL CHECK (role IN ('OWNER','SPONSOR')),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
  confirmation_digest char(64) NOT NULL CHECK (confirmation_digest ~ '^[a-f0-9]{64}$'),
  confirmed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,agent_id,ownership_version,role),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agent_assets(tenant_id,agent_id)
);

CREATE TABLE IF NOT EXISTS agent_relationship_edges (
  tenant_id uuid NOT NULL,
  edge_id uuid NOT NULL,
  from_ref text NOT NULL CHECK (length(from_ref) BETWEEN 1 AND 1024),
  to_ref text NOT NULL CHECK (length(to_ref) BETWEEN 1 AND 1024),
  relationship_kind text NOT NULL CHECK (relationship_kind IN (
    'USES_TOOL','USES_PACK','OWNS','SPONSORED_BY','OBSERVED_AT','DELEGATES_TO'
  )),
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 512),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,edge_id),
  CHECK (from_ref<>to_ref)
);

CREATE TABLE IF NOT EXISTS agent_posture_resolutions (
  tenant_id uuid NOT NULL,
  resolution_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
  resolved_at timestamptz NOT NULL,
  resolved_by text NOT NULL CHECK (length(resolved_by) BETWEEN 1 AND 512),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,resolution_id),
  UNIQUE (tenant_id,finding_id),
  FOREIGN KEY (tenant_id,finding_id) REFERENCES agent_posture_findings(tenant_id,finding_id)
);

CREATE TABLE IF NOT EXISTS agent_relationship_supersessions (
  tenant_id uuid NOT NULL,
  supersession_id uuid NOT NULL,
  edge_id uuid NOT NULL,
  superseded_at timestamptz NOT NULL,
  superseded_by text NOT NULL CHECK (length(superseded_by) BETWEEN 1 AND 512),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,supersession_id),
  UNIQUE (tenant_id,edge_id),
  FOREIGN KEY (tenant_id,edge_id) REFERENCES agent_relationship_edges(tenant_id,edge_id)
);

CREATE TABLE IF NOT EXISTS agent_lifecycle_records (
  tenant_id uuid NOT NULL,
  record_id uuid NOT NULL,
  agent_id text NOT NULL,
  from_state text NOT NULL CHECK (from_state IN ('DRAFT','ACTIVE','SUSPENDED','RETIRED','REVOKED')),
  to_state text NOT NULL CHECK (to_state IN ('DRAFT','ACTIVE','SUSPENDED','RETIRED','REVOKED')),
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
  external_evidence_refs jsonb NOT NULL CHECK (jsonb_typeof(external_evidence_refs)='array'),
  event_ref text NOT NULL CHECK (length(event_ref) BETWEEN 1 AND 2048),
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[a-f0-9]{64}$'),
  changed boolean NOT NULL,
  transitioned_at timestamptz NOT NULL,
  transitioned_by text NOT NULL CHECK (length(transitioned_by) BETWEEN 1 AND 512),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,record_id),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agent_assets(tenant_id,agent_id)
);

CREATE TABLE IF NOT EXISTS agent_registry_idempotency (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  response jsonb NOT NULL CHECK (jsonb_typeof(response)='object'),
  response_digest char(64) NOT NULL CHECK (response_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,idempotency_key)
);

CREATE TABLE IF NOT EXISTS agent_registry_audit_heads (
  tenant_id uuid PRIMARY KEY,
  sequence bigint NOT NULL CHECK (sequence > 0),
  chain_hash char(64) NOT NULL CHECK (chain_hash ~ '^[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_registry_audit_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
  governance_digest char(64) NOT NULL CHECK (governance_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  policy_decision_id text NOT NULL CHECK (length(policy_decision_id) BETWEEN 1 AND 256),
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  execution_id uuid NOT NULL,
  ledger_entry_id uuid NOT NULL,
  ledger_entry_digest char(64) NOT NULL CHECK (ledger_entry_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (
    length(authorization_evidence_ref) BETWEEN 12 AND 2048
    AND authorization_evidence_ref LIKE 'evidence://%'
    AND position('?' IN authorization_evidence_ref)=0
    AND position('#' IN authorization_evidence_ref)=0
    AND authorization_evidence_ref !~ '[[:space:]]'
  ),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  event_hash char(64) NOT NULL CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  event_ref text NOT NULL CHECK (length(event_ref) BETWEEN 1 AND 2048),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,sequence),
  UNIQUE (tenant_id,event_hash),
  UNIQUE (tenant_id,event_ref)
);

CREATE TABLE IF NOT EXISTS agent_registry_outbox (
  tenant_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,outbox_id),
  UNIQUE (tenant_id,event_id),
  FOREIGN KEY (tenant_id,event_id) REFERENCES agent_registry_audit_events(tenant_id,event_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_posture_finding_key_unique
  ON agent_posture_findings(tenant_id,finding_key) WHERE finding_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS agent_posture_condition_open
  ON agent_posture_findings(tenant_id,condition_key,finding_id) WHERE open;
CREATE INDEX IF NOT EXISTS agent_assets_inventory_page
  ON agent_assets(tenant_id,agent_id);
CREATE INDEX IF NOT EXISTS agent_discovery_claimed_agent
  ON agent_discovery_facts(tenant_id,observed_agent_ref,observed_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS agent_discovery_exact_observation
  ON agent_discovery_facts(tenant_id,collector_id,observation_key,observation_digest)
  WHERE observation_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS agent_posture_open_risk
  ON agent_posture_findings(tenant_id,agent_id,open,severity,detected_at DESC);
CREATE INDEX IF NOT EXISTS agent_relationship_from
  ON agent_relationship_edges(tenant_id,from_ref,edge_id);
CREATE INDEX IF NOT EXISTS agent_relationship_to
  ON agent_relationship_edges(tenant_id,to_ref,edge_id);
CREATE INDEX IF NOT EXISTS agent_registry_outbox_order
  ON agent_registry_outbox(tenant_id,created_at,outbox_id);

CREATE OR REPLACE FUNCTION reject_agent_registry_immutable_record()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  RAISE EXCEPTION 'AGENT_REGISTRY_IMMUTABLE_RECORD';
END
$$;

CREATE OR REPLACE FUNCTION enforce_agent_registry_audit_head_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.sequence<>OLD.sequence+1 OR
     NEW.chain_hash=OLD.chain_hash OR NEW.updated_at<OLD.updated_at THEN
    RAISE EXCEPTION 'AGENT_REGISTRY_AUDIT_HEAD_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS agent_registry_audit_head_transition ON agent_registry_audit_heads;
CREATE TRIGGER agent_registry_audit_head_transition
  BEFORE UPDATE OR DELETE ON agent_registry_audit_heads
  FOR EACH ROW EXECUTE FUNCTION enforce_agent_registry_audit_head_transition();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'agent_discovery_facts','agent_posture_findings','agent_boms','agent_ownership_confirmations',
    'agent_relationship_edges','agent_relationship_supersessions','agent_posture_resolutions','agent_lifecycle_records','agent_registry_idempotency',
    'agent_registry_audit_events','agent_registry_outbox'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',table_name||'_immutable',table_name);
    EXECUTE format(
      'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_agent_registry_immutable_record()',
      table_name||'_immutable',table_name
    );
  END LOOP;
END
$$;

DO $$
DECLARE table_name text;
DECLARE policy_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'agent_assets','agent_discovery_facts','agent_posture_findings','agent_boms',
    'agent_ownership_confirmations','agent_relationship_edges','agent_relationship_supersessions','agent_posture_resolutions','agent_lifecycle_records',
    'agent_registry_idempotency','agent_registry_audit_heads','agent_registry_audit_events',
    'agent_registry_outbox'
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

REVOKE ALL ON TABLE agent_assets,agent_discovery_facts,agent_posture_findings,agent_boms,
  agent_ownership_confirmations,agent_relationship_edges,agent_relationship_supersessions,agent_posture_resolutions,agent_lifecycle_records,
  agent_registry_idempotency,agent_registry_audit_heads,agent_registry_audit_events,
  agent_registry_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_agent_registry_immutable_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_agent_registry_audit_head_transition() FROM PUBLIC;

-- Runtime LOGIN role `agenttrust_agent_registry` is externally provisioned.  The production
-- migration runner must grant it only SELECT/INSERT plus narrowly required UPDATE on agent_assets
-- and agent_registry_audit_heads; this migration deliberately creates no role.

COMMIT;
