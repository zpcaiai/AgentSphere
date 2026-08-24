BEGIN;

-- Batch 32 production closure extends the original domain tables in-place. Legacy rows are
-- quarantined until an operator re-imports them through the governed execution path.
ALTER TABLE governed_memory_entries
  ADD COLUMN IF NOT EXISTS requested_by text,
  ADD COLUMN IF NOT EXISTS purpose text,
  ADD COLUMN IF NOT EXISTS classification text,
  ADD COLUMN IF NOT EXISTS jurisdiction text,
  ADD COLUMN IF NOT EXISTS visibility jsonb,
  ADD COLUMN IF NOT EXISTS trust_level text,
  ADD COLUMN IF NOT EXISTS provenance jsonb,
  ADD COLUMN IF NOT EXISTS policy_version text,
  ADD COLUMN IF NOT EXISTS ledger_execution_id uuid,
  ADD COLUMN IF NOT EXISTS fence_digest char(64),
  ADD COLUMN IF NOT EXISTS resource_version bigint,
  ADD COLUMN IF NOT EXISTS quarantine_reason_digest char(64),
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

UPDATE governed_memory_entries
   SET requested_by = COALESCE(requested_by, 'migration:legacy'),
       purpose = COALESCE(purpose, 'legacy-import'),
       classification = COALESCE(classification, 'RESTRICTED'),
       jurisdiction = COALESCE(jurisdiction, 'UNKNOWN'),
       visibility = COALESCE(visibility, '[]'::jsonb),
       trust_level = COALESCE(trust_level, 'UNTRUSTED'),
       provenance = COALESCE(provenance, '{"schema_version":"agenttrust.provenance.v1","source_type":"legacy","source_id":"legacy","source_version":"0.0.0","source_digest":"0000000000000000000000000000000000000000000000000000000000000000","imported_by":"migration:legacy"}'::jsonb),
       policy_version = COALESCE(policy_version, policy_digest),
       ledger_execution_id = COALESCE(ledger_execution_id, '00000000-0000-0000-0000-000000000000'::uuid),
       fence_digest = COALESCE(fence_digest, repeat('0', 64)),
       resource_version = COALESCE(resource_version, 0),
       quarantine_reason_digest = COALESCE(quarantine_reason_digest, repeat('0', 64)),
       updated_at = COALESCE(updated_at, created_at),
       status = 'QUARANTINED'
 WHERE requested_by IS NULL OR jurisdiction IS NULL OR ledger_execution_id IS NULL OR resource_version IS NULL;

ALTER TABLE governed_memory_entries
  ALTER COLUMN requested_by SET NOT NULL,
  ALTER COLUMN purpose SET NOT NULL,
  ALTER COLUMN classification SET NOT NULL,
  ALTER COLUMN jurisdiction SET NOT NULL,
  ALTER COLUMN visibility SET NOT NULL,
  ALTER COLUMN trust_level SET NOT NULL,
  ALTER COLUMN provenance SET NOT NULL,
  ALTER COLUMN policy_version SET NOT NULL,
  ALTER COLUMN ledger_execution_id SET NOT NULL,
  ALTER COLUMN fence_digest SET NOT NULL,
  ALTER COLUMN resource_version SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE governed_memory_entries
  DROP CONSTRAINT IF EXISTS governed_memory_classification_check,
  DROP CONSTRAINT IF EXISTS governed_memory_jurisdiction_check,
  DROP CONSTRAINT IF EXISTS governed_memory_visibility_array_check,
  DROP CONSTRAINT IF EXISTS governed_memory_trust_check,
  DROP CONSTRAINT IF EXISTS governed_memory_provenance_check,
  DROP CONSTRAINT IF EXISTS governed_memory_fence_digest_check,
  DROP CONSTRAINT IF EXISTS governed_memory_resource_version_check;

ALTER TABLE governed_memory_entries
  ADD CONSTRAINT governed_memory_classification_check
    CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')),
  ADD CONSTRAINT governed_memory_jurisdiction_check
    CHECK (length(jurisdiction) BETWEEN 1 AND 64),
  ADD CONSTRAINT governed_memory_visibility_array_check
    CHECK (jsonb_typeof(visibility)='array'),
  ADD CONSTRAINT governed_memory_trust_check
    CHECK (trust_level IN ('UNTRUSTED','IMPORTED','VERIFIED','AUTHORITATIVE')),
  ADD CONSTRAINT governed_memory_provenance_check
    CHECK (provenance->>'schema_version'='agenttrust.provenance.v1'),
  ADD CONSTRAINT governed_memory_fence_digest_check
    CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  ADD CONSTRAINT governed_memory_resource_version_check
    CHECK (resource_version >= 0);

ALTER TABLE prompt_versions
  ADD COLUMN IF NOT EXISTS artifact_digest char(64),
  ADD COLUMN IF NOT EXISTS supply_chain_receipt jsonb,
  ADD COLUMN IF NOT EXISTS approved_by jsonb,
  ADD COLUMN IF NOT EXISTS trust_level text,
  ADD COLUMN IF NOT EXISTS rollout_percent integer,
  ADD COLUMN IF NOT EXISTS resource_version bigint,
  ADD COLUMN IF NOT EXISTS object_ref text,
  ADD COLUMN IF NOT EXISTS activated_at timestamptz,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

UPDATE prompt_versions
   SET artifact_digest = COALESCE(artifact_digest, content_digest),
       supply_chain_receipt = COALESCE(supply_chain_receipt, '{}'::jsonb),
       approved_by = COALESCE(approved_by, '[]'::jsonb),
       trust_level = COALESCE(trust_level, 'UNTRUSTED'),
       rollout_percent = COALESCE(rollout_percent, 0),
       resource_version = COALESCE(resource_version, 0),
       object_ref = COALESCE(object_ref, 'object://legacy/quarantined/' || content_digest),
       updated_at = COALESCE(updated_at, created_at),
       status = CASE WHEN supply_chain_receipt IS NULL THEN 'REVOKED' ELSE status END
 WHERE artifact_digest IS NULL OR supply_chain_receipt IS NULL OR approved_by IS NULL
    OR trust_level IS NULL OR rollout_percent IS NULL OR resource_version IS NULL
    OR object_ref IS NULL OR updated_at IS NULL;

ALTER TABLE prompt_versions
  ALTER COLUMN artifact_digest SET NOT NULL,
  ALTER COLUMN supply_chain_receipt SET NOT NULL,
  ALTER COLUMN approved_by SET NOT NULL,
  ALTER COLUMN trust_level SET NOT NULL,
  ALTER COLUMN rollout_percent SET NOT NULL,
  ALTER COLUMN resource_version SET NOT NULL,
  ALTER COLUMN object_ref SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE prompt_versions
  DROP CONSTRAINT IF EXISTS prompt_status_check,
  DROP CONSTRAINT IF EXISTS prompt_trust_check,
  DROP CONSTRAINT IF EXISTS prompt_approved_by_array_check,
  DROP CONSTRAINT IF EXISTS prompt_rollout_percent_check,
  DROP CONSTRAINT IF EXISTS prompt_resource_version_check;

ALTER TABLE prompt_versions
  ADD CONSTRAINT prompt_status_check
    CHECK (status IN ('STAGED','ACTIVE','RETIRED','QUARANTINED','REVOKED')),
  ADD CONSTRAINT prompt_trust_check
    CHECK (trust_level IN ('UNTRUSTED','IMPORTED','VERIFIED','AUTHORITATIVE')),
  ADD CONSTRAINT prompt_approved_by_array_check
    CHECK (jsonb_typeof(approved_by)='array'),
  ADD CONSTRAINT prompt_rollout_percent_check
    CHECK (rollout_percent BETWEEN 0 AND 100),
  ADD CONSTRAINT prompt_resource_version_check
    CHECK (resource_version >= 0);

ALTER TABLE knowledge_snapshots
  ADD COLUMN IF NOT EXISTS source_version text,
  ADD COLUMN IF NOT EXISTS content_digest char(64),
  ADD COLUMN IF NOT EXISTS artifact_digest char(64),
  ADD COLUMN IF NOT EXISTS supply_chain_receipt jsonb,
  ADD COLUMN IF NOT EXISTS classification text,
  ADD COLUMN IF NOT EXISTS jurisdiction text,
  ADD COLUMN IF NOT EXISTS quarantined boolean,
  ADD COLUMN IF NOT EXISTS resource_version bigint,
  ADD COLUMN IF NOT EXISTS index_ref text,
  ADD COLUMN IF NOT EXISTS tombstoned boolean,
  ADD COLUMN IF NOT EXISTS created_at timestamptz,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

UPDATE knowledge_snapshots
   SET source_version = COALESCE(source_version, '0.0.0'),
       content_digest = COALESCE(content_digest, snapshot_digest),
       artifact_digest = COALESCE(artifact_digest, snapshot_digest),
       supply_chain_receipt = COALESCE(supply_chain_receipt, '{}'::jsonb),
       classification = COALESCE(classification, 'RESTRICTED'),
       jurisdiction = COALESCE(jurisdiction, 'UNKNOWN'),
       quarantined = true,
       resource_version = COALESCE(resource_version, 0),
       index_ref = NULL,
       tombstoned = COALESCE(tombstoned, false),
       created_at = COALESCE(created_at, now()),
       updated_at = COALESCE(updated_at, now())
 WHERE source_version IS NULL OR content_digest IS NULL OR artifact_digest IS NULL
    OR supply_chain_receipt IS NULL OR classification IS NULL OR jurisdiction IS NULL
    OR quarantined IS NULL OR resource_version IS NULL OR tombstoned IS NULL
    OR created_at IS NULL OR updated_at IS NULL;

ALTER TABLE knowledge_snapshots
  ALTER COLUMN source_version SET NOT NULL,
  ALTER COLUMN content_digest SET NOT NULL,
  ALTER COLUMN artifact_digest SET NOT NULL,
  ALTER COLUMN supply_chain_receipt SET NOT NULL,
  ALTER COLUMN classification SET NOT NULL,
  ALTER COLUMN jurisdiction SET NOT NULL,
  ALTER COLUMN quarantined SET NOT NULL,
  ALTER COLUMN resource_version SET NOT NULL,
  ALTER COLUMN tombstoned SET NOT NULL,
  ALTER COLUMN created_at SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE knowledge_snapshots
  DROP CONSTRAINT IF EXISTS knowledge_snapshot_classification_check,
  DROP CONSTRAINT IF EXISTS knowledge_snapshot_trust_check,
  DROP CONSTRAINT IF EXISTS knowledge_snapshot_resource_version_check,
  DROP CONSTRAINT IF EXISTS knowledge_snapshot_index_ref_check;

ALTER TABLE knowledge_snapshots
  ADD CONSTRAINT knowledge_snapshot_classification_check
    CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')),
  ADD CONSTRAINT knowledge_snapshot_trust_check
    CHECK (trust_level IN ('UNTRUSTED','IMPORTED','VERIFIED','AUTHORITATIVE')),
  ADD CONSTRAINT knowledge_snapshot_resource_version_check
    CHECK (resource_version >= 0),
  ADD CONSTRAINT knowledge_snapshot_index_ref_check
    CHECK (index_ref IS NULL OR index_ref LIKE 'vector://%');

CREATE TABLE IF NOT EXISTS context_knowledge_sources (
  tenant_id uuid NOT NULL,
  source_id text NOT NULL CHECK (length(source_id) BETWEEN 1 AND 512),
  owner_subject text NOT NULL CHECK (length(owner_subject) BETWEEN 1 AND 512),
  trust_level text NOT NULL CHECK (trust_level IN ('UNTRUSTED','IMPORTED','VERIFIED','AUTHORITATIVE')),
  allowed_subjects jsonb NOT NULL CHECK (jsonb_typeof(allowed_subjects)='array'),
  classification text NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')),
  jurisdiction text NOT NULL CHECK (length(jurisdiction) BETWEEN 1 AND 64),
  provenance jsonb NOT NULL CHECK (provenance->>'schema_version'='agenttrust.provenance.v1'),
  resource_version bigint NOT NULL CHECK (resource_version >= 1),
  quarantined boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source_id)
);

CREATE TABLE IF NOT EXISTS context_deletion_tombstones (
  tenant_id uuid NOT NULL,
  tombstone_id uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type IN ('MEMORY','KNOWLEDGE_SNAPSHOT')),
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
  content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
  deleted_by text NOT NULL CHECK (length(deleted_by) BETWEEN 1 AND 512),
  object_purged boolean NOT NULL,
  index_purged boolean NOT NULL,
  cache_purged boolean NOT NULL,
  legal_hold_blocked boolean NOT NULL,
  deletion_receipt jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, tombstone_id)
);

CREATE TABLE IF NOT EXISTS context_quarantine_records (
  tenant_id uuid NOT NULL,
  quarantine_id uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type IN ('MEMORY','PROMPT','KNOWLEDGE_SOURCE','KNOWLEDGE_SNAPSHOT')),
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
  reason_codes jsonb NOT NULL CHECK (jsonb_typeof(reason_codes)='array'),
  detector_digest char(64) NOT NULL CHECK (detector_digest ~ '^[a-f0-9]{64}$'),
  released_by text,
  remediation_evidence_ref text,
  remediation_evidence_digest char(64),
  quarantined_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  PRIMARY KEY (tenant_id, quarantine_id),
  CHECK ((released_at IS NULL AND released_by IS NULL AND remediation_evidence_ref IS NULL AND remediation_evidence_digest IS NULL)
      OR (released_at IS NOT NULL AND released_by IS NOT NULL AND remediation_evidence_ref IS NOT NULL
          AND remediation_evidence_digest ~ '^[a-f0-9]{64}$'))
);

CREATE TABLE IF NOT EXISTS context_resource_versions (
  tenant_id uuid NOT NULL,
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, resource)
);

CREATE TABLE IF NOT EXISTS context_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  operation text NOT NULL CHECK (operation IN (
    'WRITE_MEMORY','DELETE_MEMORY','PUBLISH_PROMPT','ACTIVATE_PROMPT','ROLLBACK_PROMPT',
    'REGISTER_KNOWLEDGE_SOURCE','PUBLISH_KNOWLEDGE_SNAPSHOT','DELETE_KNOWLEDGE_SNAPSHOT',
    'QUARANTINE_RESOURCE','RELEASE_QUARANTINE'
  )),
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
  envelope jsonb NOT NULL CHECK (envelope->>'schema_version'='agenttrust.gateway.v1'),
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, action_id),
  CHECK ((state='ACCEPTED' AND receipt IS NOT NULL) OR (state='PREPARED' AND receipt IS NULL))
);

CREATE TABLE IF NOT EXISTS context_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[a-f0-9]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  trace_id varchar(128) NOT NULL,
  policy_decision_id varchar(256) NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  request jsonb NOT NULL CHECK (request->>'schema_version'='agenttrust.context-execution-request.v1'),
  state text NOT NULL CHECK (state IN ('PREPARED','SIDE_EFFECTS_PENDING','MUTATED_PENDING_EVIDENCE','SUCCEEDED','FAILED','UNKNOWN')),
  external_receipts jsonb,
  safe_result jsonb,
  evidence_request jsonb,
  evidence_ref text,
  evidence_digest char(64),
  evidence_receipt jsonb,
  stable_error varchar(128),
  execution_owner uuid NOT NULL,
  execution_lease_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, action_id),
  CHECK ((state='SUCCEEDED' AND safe_result IS NOT NULL AND evidence_ref IS NOT NULL
          AND evidence_digest IS NOT NULL AND evidence_receipt IS NOT NULL)
      OR state<>'SUCCEEDED')
);

CREATE TABLE IF NOT EXISTS context_retrieval_decisions (
  tenant_id uuid NOT NULL,
  decision_id uuid NOT NULL,
  retrieval_id uuid NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
  query_digest char(64) NOT NULL CHECK (query_digest ~ '^[a-f0-9]{64}$'),
  authorized_resources jsonb NOT NULL CHECK (jsonb_typeof(authorized_resources)='array'),
  policy_decision_id varchar(256) NOT NULL,
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
  policy_evidence_ref text NOT NULL,
  policy_evidence_digest char(64) NOT NULL CHECK (policy_evidence_digest ~ '^[a-f0-9]{64}$'),
  trace_id varchar(128) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, decision_id),
  UNIQUE (tenant_id, retrieval_id)
);

CREATE TABLE IF NOT EXISTS context_evidence_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  action_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  payload jsonb NOT NULL CHECK (payload->>'schema_version'='agenttrust.context-lifecycle-evidence.v1'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, idempotency_key)
);

CREATE OR REPLACE FUNCTION enforce_context_resource_fence()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $function$
BEGIN
  IF NEW.resource_version <> OLD.resource_version + 1
     OR NEW.action_hash = OLD.action_hash
     OR NEW.ledger_execution_id = OLD.ledger_execution_id
     OR NEW.fence_digest = OLD.fence_digest THEN
    RAISE EXCEPTION 'CONTEXT_RESOURCE_FENCE_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_context_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $function$
BEGIN
  IF OLD.state IN ('SUCCEEDED','FAILED','UNKNOWN')
     OR (OLD.state='PREPARED' AND NEW.state NOT IN ('SIDE_EFFECTS_PENDING','FAILED','UNKNOWN'))
     OR (OLD.state='SIDE_EFFECTS_PENDING' AND NEW.state NOT IN ('SIDE_EFFECTS_PENDING','MUTATED_PENDING_EVIDENCE','FAILED','UNKNOWN'))
     OR (OLD.state='MUTATED_PENDING_EVIDENCE' AND NEW.state NOT IN ('MUTATED_PENDING_EVIDENCE','SUCCEEDED','UNKNOWN')) THEN
    RAISE EXCEPTION 'CONTEXT_EXECUTION_TRANSITION_INVALID';
  END IF;
  IF NEW.request_digest <> OLD.request_digest OR NEW.action_id <> OLD.action_id
     OR NEW.task_id <> OLD.task_id
     OR NEW.action_hash <> OLD.action_hash OR NEW.ledger_execution_id <> OLD.ledger_execution_id
     OR NEW.ledger_event_id <> OLD.ledger_event_id OR NEW.ledger_event_digest <> OLD.ledger_event_digest
     OR NEW.fence_digest <> OLD.fence_digest OR NEW.resource <> OLD.resource
     OR NEW.resource_version <> OLD.resource_version OR NEW.trace_id <> OLD.trace_id
     OR NEW.policy_decision_id <> OLD.policy_decision_id
     OR NEW.policy_decision_digest <> OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref <> OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest <> OLD.authorization_evidence_digest
     OR NEW.request <> OLD.request THEN
    RAISE EXCEPTION 'CONTEXT_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_context_ingress_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'CONTEXT_INGRESS_IMMUTABLE';
  END IF;
  IF OLD.state <> 'PREPARED' OR NEW.state <> 'ACCEPTED'
     OR OLD.receipt IS NOT NULL OR NEW.receipt IS NULL THEN
    RAISE EXCEPTION 'CONTEXT_INGRESS_TRANSITION_INVALID';
  END IF;
  IF NEW.request_digest <> OLD.request_digest OR NEW.action_id <> OLD.action_id
     OR NEW.task_id <> OLD.task_id OR NEW.action_hash <> OLD.action_hash
     OR NEW.resource <> OLD.resource OR NEW.operation <> OLD.operation
     OR NEW.actor_subject <> OLD.actor_subject OR NEW.envelope <> OLD.envelope
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'CONTEXT_INGRESS_BINDING_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_context_quarantine_release()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'CONTEXT_QUARANTINE_IMMUTABLE';
  END IF;
  IF OLD.released_at IS NOT NULL OR NEW.released_at IS NULL
     OR NEW.released_by IS NULL OR NEW.remediation_evidence_ref IS NULL
     OR NEW.remediation_evidence_digest IS NULL THEN
    RAISE EXCEPTION 'CONTEXT_QUARANTINE_RELEASE_INVALID';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.quarantine_id <> OLD.quarantine_id
     OR NEW.resource_type <> OLD.resource_type OR NEW.resource_id <> OLD.resource_id
     OR NEW.reason_codes <> OLD.reason_codes OR NEW.detector_digest <> OLD.detector_digest
     OR NEW.quarantined_at <> OLD.quarantined_at THEN
    RAISE EXCEPTION 'CONTEXT_QUARANTINE_BINDING_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_context_outbox_delivery()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'CONTEXT_EVIDENCE_OUTBOX_IMMUTABLE';
  END IF;
  IF OLD.delivered_at IS NOT NULL OR NEW.delivered_at IS NULL
     OR NEW.tenant_id <> OLD.tenant_id OR NEW.event_id <> OLD.event_id
     OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.action_id <> OLD.action_id
     OR NEW.execution_id <> OLD.execution_id OR NEW.payload <> OLD.payload
     OR NEW.payload_digest <> OLD.payload_digest OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'CONTEXT_EVIDENCE_OUTBOX_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION reject_context_immutable_change()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $function$
BEGIN
  RAISE EXCEPTION 'CONTEXT_IMMUTABLE_RECORD';
END
$function$;

DROP TRIGGER IF EXISTS context_resource_fence_guard ON context_resource_versions;
CREATE TRIGGER context_resource_fence_guard BEFORE UPDATE ON context_resource_versions
FOR EACH ROW EXECUTE FUNCTION enforce_context_resource_fence();
DROP TRIGGER IF EXISTS context_execution_transition_guard ON context_authority_executions;
CREATE TRIGGER context_execution_transition_guard BEFORE UPDATE ON context_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_context_execution_transition();
DROP TRIGGER IF EXISTS context_ingress_transition_guard ON context_action_ingress;
CREATE TRIGGER context_ingress_transition_guard BEFORE UPDATE OR DELETE ON context_action_ingress
FOR EACH ROW EXECUTE FUNCTION enforce_context_ingress_transition();
DROP TRIGGER IF EXISTS context_quarantine_release_guard ON context_quarantine_records;
CREATE TRIGGER context_quarantine_release_guard BEFORE UPDATE OR DELETE ON context_quarantine_records
FOR EACH ROW EXECUTE FUNCTION enforce_context_quarantine_release();
DROP TRIGGER IF EXISTS context_tombstone_immutable_guard ON context_deletion_tombstones;
CREATE TRIGGER context_tombstone_immutable_guard BEFORE UPDATE OR DELETE ON context_deletion_tombstones
FOR EACH ROW EXECUTE FUNCTION reject_context_immutable_change();
DROP TRIGGER IF EXISTS context_retrieval_immutable_guard ON context_retrieval_decisions;
CREATE TRIGGER context_retrieval_immutable_guard BEFORE UPDATE OR DELETE ON context_retrieval_decisions
FOR EACH ROW EXECUTE FUNCTION reject_context_immutable_change();
DROP TRIGGER IF EXISTS context_evidence_outbox_guard ON context_evidence_outbox;
CREATE TRIGGER context_evidence_outbox_guard BEFORE UPDATE OR DELETE ON context_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_context_outbox_delivery();

DO $rls$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'governed_memory_entries','prompt_versions','knowledge_snapshots',
    'context_knowledge_sources','context_deletion_tombstones','context_quarantine_records',
    'context_resource_versions','context_action_ingress','context_authority_executions','context_retrieval_decisions',
    'context_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I', relation_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON public.%I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      relation_name
    );
  END LOOP;
END
$rls$;

CREATE INDEX IF NOT EXISTS governed_memory_retrieval_idx
  ON governed_memory_entries (tenant_id, owner_subject, status, expires_at);
CREATE INDEX IF NOT EXISTS prompt_versions_active_idx
  ON prompt_versions (tenant_id, prompt_id, status, resource_version DESC);
CREATE UNIQUE INDEX IF NOT EXISTS prompt_single_active_idx
  ON prompt_versions (tenant_id, prompt_id) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS knowledge_snapshots_retrieval_idx
  ON knowledge_snapshots (tenant_id, source_id, quarantined, expires_at);
CREATE INDEX IF NOT EXISTS context_execution_state_idx
  ON context_authority_executions (tenant_id, state, updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS context_single_resource_flight_idx
  ON context_authority_executions (tenant_id, resource, resource_version)
  WHERE state IN ('PREPARED','SIDE_EFFECTS_PENDING','MUTATED_PENDING_EVIDENCE');
CREATE INDEX IF NOT EXISTS context_evidence_outbox_pending_idx
  ON context_evidence_outbox (tenant_id, created_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS context_action_ingress_state_idx
  ON context_action_ingress (tenant_id, state, updated_at);
CREATE INDEX IF NOT EXISTS context_retrieval_decision_subject_idx
  ON context_retrieval_decisions (tenant_id, subject, created_at DESC);

REVOKE ALL ON TABLE governed_memory_entries,prompt_versions,knowledge_snapshots,
  context_knowledge_sources,context_deletion_tombstones,context_quarantine_records,
  context_resource_versions,context_action_ingress,context_authority_executions,context_retrieval_decisions,
  context_evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_context_resource_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_context_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_context_ingress_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_context_quarantine_release() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_context_outbox_delivery() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_context_immutable_change() FROM PUBLIC;

COMMIT;
