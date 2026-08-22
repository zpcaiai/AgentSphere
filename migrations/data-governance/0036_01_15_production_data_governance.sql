BEGIN;

-- Batch 18 production authority. The original 0018 tables remain read-only migration history;
-- production roles are granted only the authority tables below.
ALTER TABLE IF EXISTS data_labels ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS data_labels FORCE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS cross_domain_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS cross_domain_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS retention_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS retention_actions FORCE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS data_policy_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS data_policy_decisions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE data_labels,cross_domain_grants,retention_actions,data_policy_decisions FROM PUBLIC;

CREATE TABLE IF NOT EXISTS data_resource_versions (
  tenant_id uuid NOT NULL,
  resource varchar(1024) NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,resource)
);

CREATE TABLE IF NOT EXISTS data_authority_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(256) NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 256),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  resource varchar(1024) NOT NULL,
  operation varchar(64) NOT NULL CHECK (operation IN (
    'REGISTER_LABEL','RECORD_POLICY_DECISION','RECORD_DLP_SCAN','RECORD_TRANSFORM_RECEIPT',
    'ISSUE_CROSS_DOMAIN_GRANT','CONSUME_CROSS_DOMAIN_GRANT','RESOLVE_RETENTION',
    'PLACE_LEGAL_HOLD','RELEASE_LEGAL_HOLD','AUTHORIZE_EXPORT','COMPLETE_EXPORT'
  )),
  actor_subject varchar(256) NOT NULL,
  envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope)='object'),
  state varchar(16) NOT NULL CHECK (state IN ('PREPARED','ACCEPTED')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id),
  UNIQUE (tenant_id,action_hash),
  CHECK ((state='PREPARED' AND receipt IS NULL) OR (state='ACCEPTED' AND receipt IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS data_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(256) NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[a-f0-9]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  resource varchar(1024) NOT NULL,
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  trace_id varchar(256) NOT NULL,
  policy_decision_id varchar(256) NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (length(authorization_evidence_ref) BETWEEN 12 AND 2048),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  request jsonb NOT NULL CHECK (jsonb_typeof(request)='object'),
  state varchar(32) NOT NULL CHECK (state IN ('EXECUTING','MUTATED_PENDING_EVIDENCE','COMPLETED')),
  execution_owner uuid NOT NULL,
  execution_lease_until timestamptz,
  evidence_event_id uuid,
  result jsonb,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,action_id),
  UNIQUE (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_hash),
  UNIQUE (tenant_id,ledger_execution_id),
  UNIQUE (tenant_id,ledger_event_id),
  CHECK (
    (state='EXECUTING' AND execution_lease_until IS NOT NULL AND evidence_event_id IS NULL AND result IS NULL)
    OR (state='MUTATED_PENDING_EVIDENCE' AND execution_lease_until IS NULL AND evidence_event_id IS NOT NULL AND result IS NOT NULL)
    OR (state='COMPLETED' AND execution_lease_until IS NULL AND evidence_event_id IS NOT NULL AND result IS NOT NULL AND completed_at IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS governed_data_labels (
  tenant_id uuid NOT NULL,
  object_ref varchar(2048) NOT NULL,
  object_version varchar(256) NOT NULL,
  object_digest char(64) NOT NULL CHECK (object_digest ~ '^[a-f0-9]{64}$'),
  label jsonb NOT NULL CHECK (label->>'schema_version'='agenttrust.data-governance.v1'),
  label_digest char(64) NOT NULL CHECK (label_digest ~ '^[a-f0-9]{64}$'),
  classification varchar(16) NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')),
  confidence varchar(24) NOT NULL CHECK (confidence IN ('UNKNOWN','INFERRED','DETERMINISTIC','HUMAN_VERIFIED')),
  source_evidence_ref text NOT NULL,
  source_evidence_digest char(64) NOT NULL CHECK (source_evidence_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,object_ref,object_version),
  UNIQUE (tenant_id,label_digest),
  UNIQUE (tenant_id,action_hash)
);

CREATE TABLE IF NOT EXISTS data_policy_decision_records (
  tenant_id uuid NOT NULL,
  decision_id uuid NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  request jsonb NOT NULL CHECK (jsonb_typeof(request)='object'),
  decision jsonb NOT NULL CHECK (jsonb_typeof(decision)='object'),
  decision_digest char(64) NOT NULL CHECK (decision_digest ~ '^[a-f0-9]{64}$'),
  policy_version varchar(256) NOT NULL,
  allowed boolean NOT NULL,
  shadow boolean NOT NULL,
  evaluated_at timestamptz NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,decision_id),
  UNIQUE (tenant_id,request_digest,policy_version,shadow),
  UNIQUE (tenant_id,decision_digest),
  UNIQUE (tenant_id,action_hash)
);

CREATE TABLE IF NOT EXISTS data_dlp_scan_summaries (
  tenant_id uuid NOT NULL,
  scan_id uuid NOT NULL,
  content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 8388608),
  finding_counts jsonb NOT NULL CHECK (jsonb_typeof(finding_counts)='object'),
  findings_digest char(64) NOT NULL CHECK (findings_digest ~ '^[a-f0-9]{64}$'),
  engine_revision varchar(256) NOT NULL,
  engine_receipt_ref text NOT NULL,
  engine_receipt_digest char(64) NOT NULL CHECK (engine_receipt_digest ~ '^[a-f0-9]{64}$'),
  high_risk boolean NOT NULL,
  blocking boolean NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,scan_id),
  UNIQUE (tenant_id,engine_receipt_digest),
  UNIQUE (tenant_id,action_hash)
);

CREATE TABLE IF NOT EXISTS data_transform_receipts (
  tenant_id uuid NOT NULL,
  transform_id uuid NOT NULL,
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
  output_digest char(64) NOT NULL CHECK (output_digest ~ '^[a-f0-9]{64}$'),
  transformations jsonb NOT NULL CHECK (jsonb_typeof(transformations)='array' AND jsonb_array_length(transformations) BETWEEN 1 AND 16),
  reversible boolean NOT NULL,
  key_reference_digest char(64) CHECK (key_reference_digest ~ '^[a-f0-9]{64}$'),
  dlp_scan_id uuid NOT NULL,
  dlp_receipt_digest char(64) NOT NULL CHECK (dlp_receipt_digest ~ '^[a-f0-9]{64}$'),
  transform_receipt_digest char(64) NOT NULL CHECK (transform_receipt_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,transform_id),
  UNIQUE (tenant_id,action_hash),
  UNIQUE (tenant_id,transform_receipt_digest),
  CHECK ((reversible AND key_reference_digest IS NOT NULL) OR (NOT reversible AND key_reference_digest IS NULL)),
  FOREIGN KEY (tenant_id,dlp_scan_id) REFERENCES data_dlp_scan_summaries(tenant_id,scan_id)
);

CREATE TABLE IF NOT EXISTS data_cross_domain_grants (
  tenant_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  source_zone varchar(128) NOT NULL,
  target_zone varchar(128) NOT NULL,
  source_jurisdiction varchar(64) NOT NULL,
  target_jurisdiction varchar(64) NOT NULL,
  object_digest char(64) NOT NULL CHECK (object_digest ~ '^[a-f0-9]{64}$'),
  classification varchar(16) NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','REGULATED')),
  approval_id uuid NOT NULL,
  approval_evidence_ref text NOT NULL,
  approval_evidence_digest char(64) NOT NULL CHECK (approval_evidence_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  single_use boolean NOT NULL CHECK (single_use),
  consumed_at timestamptz,
  consumption_id uuid,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,grant_id),
  UNIQUE (tenant_id,approval_id,object_digest,source_zone,target_zone),
  UNIQUE (tenant_id,action_hash),
  CHECK (source_zone<>target_zone),
  CHECK ((consumed_at IS NULL AND consumption_id IS NULL) OR (consumed_at IS NOT NULL AND consumption_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS data_cross_domain_consumptions (
  tenant_id uuid NOT NULL,
  consumption_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  export_intent_id uuid NOT NULL,
  object_digest char(64) NOT NULL CHECK (object_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,consumption_id),
  UNIQUE (tenant_id,grant_id),
  UNIQUE (tenant_id,export_intent_id),
  UNIQUE (tenant_id,action_hash),
  FOREIGN KEY (tenant_id,grant_id) REFERENCES data_cross_domain_grants(tenant_id,grant_id)
);

CREATE TABLE IF NOT EXISTS data_retention_records (
  tenant_id uuid NOT NULL,
  retention_id uuid NOT NULL,
  object_ref varchar(2048) NOT NULL,
  retention_label varchar(128) NOT NULL,
  retention_action varchar(16) NOT NULL CHECK (retention_action IN ('DELETE','ARCHIVE','RETAIN')),
  retain_until timestamptz NOT NULL,
  policy_version varchar(256) NOT NULL,
  legal_hold_checked_at timestamptz NOT NULL,
  resolver_receipt_ref text NOT NULL,
  resolver_receipt_digest char(64) NOT NULL CHECK (resolver_receipt_digest ~ '^[a-f0-9]{64}$'),
  adapter_receipt jsonb NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,retention_id),
  UNIQUE (tenant_id,object_ref,policy_version),
  UNIQUE (tenant_id,action_hash)
);

CREATE TABLE IF NOT EXISTS data_legal_holds (
  tenant_id uuid NOT NULL,
  hold_id uuid NOT NULL,
  object_ref varchar(2048) NOT NULL,
  reason_digest char(64) NOT NULL CHECK (reason_digest ~ '^[a-f0-9]{64}$'),
  approval_id uuid NOT NULL,
  approval_evidence_ref text NOT NULL,
  approval_evidence_digest char(64) NOT NULL CHECK (approval_evidence_digest ~ '^[a-f0-9]{64}$'),
  effective_at timestamptz NOT NULL,
  state varchar(16) NOT NULL CHECK (state IN ('ACTIVE','RELEASED')),
  adapter_receipt jsonb NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  released_at timestamptz,
  release_approval_id uuid,
  release_evidence_ref text,
  release_evidence_digest char(64) CHECK (release_evidence_digest ~ '^[a-f0-9]{64}$'),
  release_adapter_receipt jsonb,
  release_action_hash char(64) CHECK (release_action_hash ~ '^[a-f0-9]{64}$'),
  release_ledger_execution_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,hold_id),
  UNIQUE (tenant_id,approval_id),
  UNIQUE (tenant_id,action_hash),
  CHECK (
    (state='ACTIVE' AND released_at IS NULL AND release_approval_id IS NULL
      AND release_evidence_ref IS NULL AND release_evidence_digest IS NULL
      AND release_adapter_receipt IS NULL AND release_action_hash IS NULL
      AND release_ledger_execution_id IS NULL)
    OR
    (state='RELEASED' AND released_at IS NOT NULL AND release_approval_id IS NOT NULL
      AND release_evidence_ref IS NOT NULL AND release_evidence_digest IS NOT NULL
      AND release_adapter_receipt IS NOT NULL AND release_action_hash IS NOT NULL
      AND release_ledger_execution_id IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS data_one_active_legal_hold
  ON data_legal_holds(tenant_id,object_ref) WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS data_export_intents (
  tenant_id uuid NOT NULL,
  export_id uuid NOT NULL,
  object_ref varchar(2048) NOT NULL,
  object_digest char(64) NOT NULL CHECK (object_digest ~ '^[a-f0-9]{64}$'),
  label_digest char(64) NOT NULL CHECK (label_digest ~ '^[a-f0-9]{64}$'),
  decision_id uuid NOT NULL,
  dlp_scan_id uuid NOT NULL,
  dlp_receipt_digest char(64) NOT NULL CHECK (dlp_receipt_digest ~ '^[a-f0-9]{64}$'),
  transform_id uuid,
  transform_receipt_digest char(64) CHECK (transform_receipt_digest ~ '^[a-f0-9]{64}$'),
  grant_id uuid,
  object_authorization_ref text NOT NULL CHECK (object_authorization_ref ~ '^object://'),
  object_authorization_digest char(64) NOT NULL CHECK (object_authorization_digest ~ '^[a-f0-9]{64}$'),
  destination_kind varchar(2048) NOT NULL,
  destination_digest char(64) NOT NULL CHECK (destination_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  redirects_allowed boolean NOT NULL CHECK (NOT redirects_allowed),
  state varchar(16) NOT NULL CHECK (state IN ('AUTHORIZED','COMPLETED')),
  adapter_receipt jsonb NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  artifact_ref text,
  artifact_digest char(64) CHECK (artifact_digest ~ '^[a-f0-9]{64}$'),
  watermark_digest char(64) CHECK (watermark_digest ~ '^[a-f0-9]{64}$'),
  signature_digest char(64) CHECK (signature_digest ~ '^[a-f0-9]{64}$'),
  worm_receipt_ref text,
  worm_receipt_digest char(64) CHECK (worm_receipt_digest ~ '^[a-f0-9]{64}$'),
  completion_adapter_receipt jsonb,
  completed_at timestamptz,
  completion_action_hash char(64) CHECK (completion_action_hash ~ '^[a-f0-9]{64}$'),
  completion_ledger_execution_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,export_id),
  UNIQUE (tenant_id,action_hash),
  UNIQUE (tenant_id,object_digest,destination_digest,decision_id),
  FOREIGN KEY (tenant_id,decision_id) REFERENCES data_policy_decision_records(tenant_id,decision_id),
  FOREIGN KEY (tenant_id,dlp_scan_id) REFERENCES data_dlp_scan_summaries(tenant_id,scan_id),
  FOREIGN KEY (tenant_id,transform_id) REFERENCES data_transform_receipts(tenant_id,transform_id),
  FOREIGN KEY (tenant_id,grant_id) REFERENCES data_cross_domain_grants(tenant_id,grant_id),
  CHECK ((transform_id IS NULL) = (transform_receipt_digest IS NULL)),
  CHECK (
    (state='AUTHORIZED' AND artifact_ref IS NULL AND artifact_digest IS NULL
      AND watermark_digest IS NULL AND signature_digest IS NULL AND worm_receipt_ref IS NULL
      AND worm_receipt_digest IS NULL AND completion_adapter_receipt IS NULL
      AND completed_at IS NULL AND completion_action_hash IS NULL
      AND completion_ledger_execution_id IS NULL)
    OR
    (state='COMPLETED' AND artifact_ref IS NOT NULL AND artifact_digest IS NOT NULL
      AND watermark_digest IS NOT NULL AND signature_digest IS NOT NULL
      AND worm_receipt_ref IS NOT NULL AND worm_receipt_digest IS NOT NULL
      AND completion_adapter_receipt IS NOT NULL AND completed_at IS NOT NULL
      AND completion_action_hash IS NOT NULL AND completion_ledger_execution_id IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS data_evidence_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  action_id uuid NOT NULL,
  idempotency_key varchar(256) NOT NULL,
  payload jsonb NOT NULL CHECK (payload->>'schema_version'='agenttrust.data-governance-evidence.v1'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  state varchar(16) NOT NULL CHECK (state IN ('PENDING','DELIVERED')),
  delivery_receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id),
  CHECK ((state='PENDING' AND delivery_receipt IS NULL AND delivered_at IS NULL)
      OR (state='DELIVERED' AND delivery_receipt IS NOT NULL AND delivered_at IS NOT NULL))
);

CREATE OR REPLACE FUNCTION enforce_data_resource_fence()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA_RESOURCE_FENCE_IMMUTABLE'; END IF;
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.resource<>OLD.resource
     OR NEW.resource_version<>OLD.resource_version+1
     OR NEW.action_hash=OLD.action_hash OR NEW.ledger_execution_id=OLD.ledger_execution_id
     OR NEW.fence_digest=OLD.fence_digest THEN
    RAISE EXCEPTION 'DATA_RESOURCE_FENCE_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_data_ingress_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA_INGRESS_IMMUTABLE'; END IF;
  IF OLD.state<>'PREPARED' OR NEW.state<>'ACCEPTED'
     OR OLD.receipt IS NOT NULL OR NEW.receipt IS NULL
     OR NEW.tenant_id<>OLD.tenant_id OR NEW.idempotency_key<>OLD.idempotency_key
     OR NEW.request_digest<>OLD.request_digest OR NEW.action_id<>OLD.action_id
     OR NEW.task_id<>OLD.task_id OR NEW.action_hash<>OLD.action_hash
     OR NEW.resource<>OLD.resource OR NEW.operation<>OLD.operation
     OR NEW.actor_subject<>OLD.actor_subject OR NEW.envelope<>OLD.envelope
     OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'DATA_INGRESS_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_data_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA_EXECUTION_IMMUTABLE'; END IF;
  IF OLD.state='COMPLETED'
     OR (OLD.state='EXECUTING' AND NEW.state NOT IN ('EXECUTING','MUTATED_PENDING_EVIDENCE'))
     OR (OLD.state='MUTATED_PENDING_EVIDENCE' AND NEW.state<>'COMPLETED') THEN
    RAISE EXCEPTION 'DATA_EXECUTION_TRANSITION_INVALID';
  END IF;
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.idempotency_key<>OLD.idempotency_key
     OR NEW.request_digest<>OLD.request_digest OR NEW.action_id<>OLD.action_id
     OR NEW.task_id<>OLD.task_id OR NEW.action_hash<>OLD.action_hash
     OR NEW.ledger_execution_id<>OLD.ledger_execution_id
     OR NEW.ledger_event_id<>OLD.ledger_event_id
     OR NEW.ledger_event_digest<>OLD.ledger_event_digest OR NEW.fence_digest<>OLD.fence_digest
     OR NEW.resource<>OLD.resource OR NEW.resource_version<>OLD.resource_version
     OR NEW.trace_id<>OLD.trace_id OR NEW.policy_decision_id<>OLD.policy_decision_id
     OR NEW.policy_decision_digest<>OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref<>OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest<>OLD.authorization_evidence_digest
     OR NEW.request<>OLD.request OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'DATA_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  IF OLD.state='EXECUTING' AND NEW.state='EXECUTING'
     AND (OLD.execution_lease_until>=now() OR NEW.execution_owner=OLD.execution_owner
          OR NEW.execution_lease_until<=OLD.execution_lease_until
          OR NEW.result IS NOT NULL OR NEW.evidence_event_id IS NOT NULL) THEN
    RAISE EXCEPTION 'DATA_EXECUTION_LEASE_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_data_grant_consumption()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
     OR NEW.consumption_id IS NULL OR OLD.tenant_id<>NEW.tenant_id OR OLD.grant_id<>NEW.grant_id
     OR OLD.source_zone<>NEW.source_zone OR OLD.target_zone<>NEW.target_zone
     OR OLD.source_jurisdiction<>NEW.source_jurisdiction
     OR OLD.target_jurisdiction<>NEW.target_jurisdiction OR OLD.object_digest<>NEW.object_digest
     OR OLD.classification<>NEW.classification OR OLD.approval_id<>NEW.approval_id
     OR OLD.approval_evidence_ref<>NEW.approval_evidence_ref
     OR OLD.approval_evidence_digest<>NEW.approval_evidence_digest
     OR OLD.expires_at<>NEW.expires_at OR OLD.single_use<>NEW.single_use
     OR OLD.action_hash<>NEW.action_hash OR OLD.ledger_execution_id<>NEW.ledger_execution_id
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'DATA_CROSS_DOMAIN_GRANT_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_data_legal_hold_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'ACTIVE' OR NEW.state<>'RELEASED'
     OR NEW.released_at IS NULL OR NEW.release_approval_id IS NULL
     OR NEW.release_evidence_ref IS NULL OR NEW.release_evidence_digest IS NULL
     OR NEW.release_adapter_receipt IS NULL OR NEW.release_action_hash IS NULL
     OR NEW.release_ledger_execution_id IS NULL
     OR OLD.tenant_id<>NEW.tenant_id OR OLD.hold_id<>NEW.hold_id
     OR OLD.object_ref<>NEW.object_ref OR OLD.reason_digest<>NEW.reason_digest
     OR OLD.approval_id<>NEW.approval_id OR OLD.approval_evidence_ref<>NEW.approval_evidence_ref
     OR OLD.approval_evidence_digest<>NEW.approval_evidence_digest
     OR OLD.effective_at<>NEW.effective_at OR OLD.adapter_receipt<>NEW.adapter_receipt
     OR OLD.action_hash<>NEW.action_hash OR OLD.ledger_execution_id<>NEW.ledger_execution_id
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'DATA_LEGAL_HOLD_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_data_export_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'AUTHORIZED' OR NEW.state<>'COMPLETED'
     OR NEW.completed_at IS NULL OR NEW.artifact_ref IS NULL OR NEW.artifact_digest IS NULL
     OR NEW.watermark_digest IS NULL OR NEW.signature_digest IS NULL
     OR NEW.worm_receipt_ref IS NULL OR NEW.worm_receipt_digest IS NULL
     OR NEW.completion_adapter_receipt IS NULL OR NEW.completion_action_hash IS NULL
     OR NEW.completion_ledger_execution_id IS NULL
     OR OLD.tenant_id<>NEW.tenant_id OR OLD.export_id<>NEW.export_id
     OR OLD.object_ref<>NEW.object_ref OR OLD.object_digest<>NEW.object_digest
     OR OLD.label_digest<>NEW.label_digest OR OLD.decision_id<>NEW.decision_id
     OR OLD.dlp_scan_id<>NEW.dlp_scan_id OR OLD.dlp_receipt_digest<>NEW.dlp_receipt_digest
     OR OLD.transform_id IS DISTINCT FROM NEW.transform_id
     OR OLD.transform_receipt_digest IS DISTINCT FROM NEW.transform_receipt_digest
     OR OLD.grant_id IS DISTINCT FROM NEW.grant_id
     OR OLD.object_authorization_ref<>NEW.object_authorization_ref
     OR OLD.object_authorization_digest<>NEW.object_authorization_digest
     OR OLD.destination_kind<>NEW.destination_kind
     OR OLD.destination_digest<>NEW.destination_digest OR OLD.expires_at<>NEW.expires_at
     OR OLD.redirects_allowed<>NEW.redirects_allowed OR OLD.adapter_receipt<>NEW.adapter_receipt
     OR OLD.action_hash<>NEW.action_hash OR OLD.ledger_execution_id<>NEW.ledger_execution_id
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'DATA_EXPORT_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_data_outbox_delivery()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'PENDING' OR NEW.state<>'DELIVERED'
     OR NEW.delivery_receipt IS NULL OR NEW.delivered_at IS NULL
     OR OLD.tenant_id<>NEW.tenant_id OR OLD.event_id<>NEW.event_id
     OR OLD.action_id<>NEW.action_id OR OLD.idempotency_key<>NEW.idempotency_key
     OR OLD.payload<>NEW.payload OR OLD.payload_digest<>NEW.payload_digest
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'DATA_EVIDENCE_OUTBOX_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION reject_data_immutable_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  RAISE EXCEPTION 'DATA_GOVERNANCE_RECORD_IMMUTABLE';
END
$function$;

DROP TRIGGER IF EXISTS data_resource_fence_guard ON data_resource_versions;
CREATE TRIGGER data_resource_fence_guard BEFORE UPDATE OR DELETE ON data_resource_versions
FOR EACH ROW EXECUTE FUNCTION enforce_data_resource_fence();
DROP TRIGGER IF EXISTS data_ingress_guard ON data_authority_ingress;
CREATE TRIGGER data_ingress_guard BEFORE UPDATE OR DELETE ON data_authority_ingress
FOR EACH ROW EXECUTE FUNCTION enforce_data_ingress_transition();
DROP TRIGGER IF EXISTS data_execution_guard ON data_authority_executions;
CREATE TRIGGER data_execution_guard BEFORE UPDATE OR DELETE ON data_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_data_execution_transition();
DROP TRIGGER IF EXISTS data_grant_guard ON data_cross_domain_grants;
CREATE TRIGGER data_grant_guard BEFORE UPDATE OR DELETE ON data_cross_domain_grants
FOR EACH ROW EXECUTE FUNCTION enforce_data_grant_consumption();
DROP TRIGGER IF EXISTS data_hold_guard ON data_legal_holds;
CREATE TRIGGER data_hold_guard BEFORE UPDATE OR DELETE ON data_legal_holds
FOR EACH ROW EXECUTE FUNCTION enforce_data_legal_hold_transition();
DROP TRIGGER IF EXISTS data_export_guard ON data_export_intents;
CREATE TRIGGER data_export_guard BEFORE UPDATE OR DELETE ON data_export_intents
FOR EACH ROW EXECUTE FUNCTION enforce_data_export_transition();
DROP TRIGGER IF EXISTS data_outbox_guard ON data_evidence_outbox;
CREATE TRIGGER data_outbox_guard BEFORE UPDATE OR DELETE ON data_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_data_outbox_delivery();

DO $immutable$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'governed_data_labels','data_policy_decision_records','data_dlp_scan_summaries',
    'data_transform_receipts','data_cross_domain_consumptions','data_retention_records'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS data_immutable_guard ON public.%I',relation_name);
    EXECUTE format('CREATE TRIGGER data_immutable_guard BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION reject_data_immutable_change()',relation_name);
  END LOOP;
END
$immutable$;

DO $rls$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'data_resource_versions','data_authority_ingress','data_authority_executions',
    'governed_data_labels','data_policy_decision_records','data_dlp_scan_summaries',
    'data_transform_receipts','data_cross_domain_grants','data_cross_domain_consumptions',
    'data_retention_records','data_legal_holds','data_export_intents','data_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I',relation_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',
      relation_name
    );
  END LOOP;
END
$rls$;

CREATE INDEX IF NOT EXISTS data_ingress_state_idx
  ON data_authority_ingress(tenant_id,state,updated_at);
CREATE INDEX IF NOT EXISTS data_execution_state_idx
  ON data_authority_executions(tenant_id,state,updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS data_single_resource_flight_idx
  ON data_authority_executions(tenant_id,resource,resource_version)
  WHERE state IN ('EXECUTING','MUTATED_PENDING_EVIDENCE');
CREATE INDEX IF NOT EXISTS data_outbox_pending_idx
  ON data_evidence_outbox(tenant_id,created_at,event_id) WHERE state='PENDING';
CREATE INDEX IF NOT EXISTS data_labels_current_idx
  ON governed_data_labels(tenant_id,object_ref,created_at DESC);
CREATE INDEX IF NOT EXISTS data_decision_lookup_idx
  ON data_policy_decision_records(tenant_id,allowed,evaluated_at DESC);
CREATE INDEX IF NOT EXISTS data_scan_content_idx
  ON data_dlp_scan_summaries(tenant_id,content_digest,created_at DESC);
CREATE INDEX IF NOT EXISTS data_grant_expiry_idx
  ON data_cross_domain_grants(tenant_id,expires_at) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS data_retention_due_idx
  ON data_retention_records(tenant_id,retain_until,retention_action);
CREATE INDEX IF NOT EXISTS data_export_state_idx
  ON data_export_intents(tenant_id,state,expires_at);

REVOKE ALL ON TABLE data_resource_versions,data_authority_ingress,data_authority_executions,
  governed_data_labels,data_policy_decision_records,data_dlp_scan_summaries,
  data_transform_receipts,data_cross_domain_grants,data_cross_domain_consumptions,
  data_retention_records,data_legal_holds,data_export_intents,data_evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_resource_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_ingress_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_grant_consumption() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_legal_hold_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_export_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_data_outbox_delivery() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_data_immutable_change() FROM PUBLIC;

COMMIT;
