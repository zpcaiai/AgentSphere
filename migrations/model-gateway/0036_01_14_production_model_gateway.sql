BEGIN;

-- The Batch 15 prototype tables did not carry the complete tenant/action/fence contract.
-- Keep them query-inaccessible to application roles rather than silently treating them as
-- production evidence.
DO $migration$
BEGIN
  IF to_regclass('public.model_provider_versions') IS NOT NULL
     AND to_regclass('public.model_provider_versions_legacy_0015') IS NULL THEN
    ALTER TABLE public.model_provider_versions RENAME TO model_provider_versions_legacy_0015;
  END IF;
  IF to_regclass('public.model_budget_reservations') IS NOT NULL
     AND to_regclass('public.model_budget_reservations_legacy_0015') IS NULL THEN
    ALTER TABLE public.model_budget_reservations RENAME TO model_budget_reservations_legacy_0015;
  END IF;
  IF to_regclass('public.model_request_evidence') IS NOT NULL
     AND to_regclass('public.model_request_evidence_legacy_0015') IS NULL THEN
    ALTER TABLE public.model_request_evidence RENAME TO model_request_evidence_legacy_0015;
  END IF;
END
$migration$;

DO $legacy_revoke$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'model_provider_versions_legacy_0015',
    'model_budget_reservations_legacy_0015',
    'model_request_evidence_legacy_0015'
  ] LOOP
    IF to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC', table_name);
    END IF;
  END LOOP;
END
$legacy_revoke$;

CREATE TABLE IF NOT EXISTS public.model_provider_revisions (
  provider_id varchar(128) NOT NULL,
  model_id varchar(256) NOT NULL,
  model_version varchar(256) NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
  endpoint_profile varchar(128) NOT NULL,
  endpoint_digest char(64) NOT NULL CHECK (endpoint_digest ~ '^[a-f0-9]{64}$'),
  deployment_kind varchar(16) NOT NULL CHECK (deployment_kind IN ('PUBLIC_API','VPC','ON_PREM','LOCAL')),
  region varchar(128) NOT NULL,
  jurisdiction varchar(128) NOT NULL,
  data_terms_version varchar(256) NOT NULL,
  maximum_context_bytes integer NOT NULL CHECK (maximum_context_bytes BETWEEN 1 AND 16777216),
  maximum_output_bytes integer NOT NULL CHECK (maximum_output_bytes BETWEEN 1 AND 33554432),
  cost_microunits_per_token bigint NOT NULL CHECK (cost_microunits_per_token >= 0),
  issuer varchar(256) NOT NULL,
  signing_key_id varchar(128) NOT NULL,
  signature text NOT NULL CHECK (length(signature) BETWEEN 86 AND 128),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revocation_reason varchar(256),
  PRIMARY KEY (provider_id, model_id, model_version, revision),
  UNIQUE (manifest_digest),
  CHECK ((status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason IS NULL)
      OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.model_provider_revocations (
  provider_id varchar(128) NOT NULL,
  model_id varchar(256) NOT NULL,
  model_version varchar(256) NOT NULL,
  provider_revision bigint NOT NULL CHECK (provider_revision > 0),
  provider_manifest_digest char(64) NOT NULL CHECK (provider_manifest_digest ~ '^[a-f0-9]{64}$'),
  reason_code varchar(128) NOT NULL CHECK (reason_code ~ '^[A-Z0-9_]+$'),
  revoked_at timestamptz NOT NULL,
  issuer varchar(256) NOT NULL,
  signing_key_id varchar(128) NOT NULL,
  revocation_digest char(64) NOT NULL CHECK (revocation_digest ~ '^[a-f0-9]{64}$'),
  signature text NOT NULL CHECK (length(signature) BETWEEN 86 AND 128),
  PRIMARY KEY (provider_id, model_id, model_version, provider_revision),
  UNIQUE (revocation_digest),
  FOREIGN KEY (provider_id, model_id, model_version, provider_revision)
    REFERENCES public.model_provider_revisions(provider_id, model_id, model_version, revision)
);

CREATE TABLE IF NOT EXISTS public.model_tenant_provider_approvals (
  tenant_id uuid NOT NULL,
  approval_id uuid NOT NULL,
  provider_id varchar(128) NOT NULL,
  model_id varchar(256) NOT NULL,
  model_version varchar(256) NOT NULL,
  provider_revision bigint NOT NULL CHECK (provider_revision > 0),
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
  allowed_deployment_profiles text[] NOT NULL CHECK (cardinality(allowed_deployment_profiles) BETWEEN 1 AND 32),
  allowed_source_jurisdictions text[] NOT NULL CHECK (cardinality(allowed_source_jurisdictions) BETWEEN 1 AND 64),
  maximum_request_microunits bigint NOT NULL CHECK (maximum_request_microunits > 0),
  approval_evidence_ref varchar(512) NOT NULL,
  approval_evidence_digest char(64) NOT NULL CHECK (approval_evidence_digest ~ '^[a-f0-9]{64}$'),
  approved_by varchar(512) NOT NULL,
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  approved_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > approved_at),
  revoked_at timestamptz,
  revocation_reason varchar(256),
  PRIMARY KEY (tenant_id, approval_id),
  UNIQUE (tenant_id, provider_id, model_id, model_version, provider_revision),
  FOREIGN KEY (provider_id, model_id, model_version, provider_revision)
    REFERENCES public.model_provider_revisions(provider_id, model_id, model_version, revision),
  CHECK ((status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
      OR (status <> 'REVOKED' AND revoked_at IS NULL AND revocation_reason IS NULL))
);

CREATE TABLE IF NOT EXISTS public.model_budget_accounts (
  tenant_id uuid PRIMARY KEY,
  limit_microunits bigint NOT NULL CHECK (limit_microunits > 0),
  reserved_microunits bigint NOT NULL DEFAULT 0 CHECK (reserved_microunits >= 0),
  spent_microunits bigint NOT NULL DEFAULT 0 CHECK (spent_microunits >= 0),
  account_version bigint NOT NULL DEFAULT 1 CHECK (account_version > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (reserved_microunits + spent_microunits <= limit_microunits)
);

CREATE TABLE IF NOT EXISTS public.model_gateway_requests (
  tenant_id uuid NOT NULL,
  request_id uuid NOT NULL,
  task_id uuid NOT NULL,
  action_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  operation varchar(16) NOT NULL CHECK (operation IN ('GENERATE','STREAM','EMBEDDINGS')),
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  authorization_id uuid NOT NULL,
  authorization_digest char(64) NOT NULL CHECK (authorization_digest ~ '^[a-f0-9]{64}$'),
  policy_decision_id varchar(256) NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref varchar(512) NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[a-f0-9]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  resource_version varchar(256) NOT NULL,
  classification varchar(32) NOT NULL,
  source_jurisdiction varchar(128) NOT NULL,
  deployment_profile varchar(128) NOT NULL,
  prompt_digest char(64) NOT NULL CHECK (prompt_digest ~ '^[a-f0-9]{64}$'),
  maximum_cost_microunits bigint NOT NULL CHECK (maximum_cost_microunits > 0),
  state varchar(16) NOT NULL CHECK (state IN ('PREPARED','EXECUTING','SUCCEEDED','FAILED','UNKNOWN')),
  owner_instance_id uuid,
  lease_expires_at timestamptz,
  selected_provider_key varchar(768),
  provider_request_id varchar(512),
  output_digest char(64) CHECK (output_digest IS NULL OR output_digest ~ '^[a-f0-9]{64}$'),
  output_artifact_ref varchar(512),
  output_artifact_digest char(64) CHECK (output_artifact_digest IS NULL OR output_artifact_digest ~ '^[a-f0-9]{64}$'),
  safe_response jsonb CHECK (safe_response IS NULL OR jsonb_typeof(safe_response) = 'object'),
  stable_error varchar(128),
  evidence_ref varchar(512),
  evidence_digest char(64) CHECK (evidence_digest IS NULL OR evidence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, request_id),
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, ledger_execution_id),
  CHECK ((state = 'EXECUTING' AND owner_instance_id IS NOT NULL AND lease_expires_at IS NOT NULL)
      OR (state <> 'EXECUTING' AND owner_instance_id IS NULL AND lease_expires_at IS NULL)),
  CHECK ((state = 'SUCCEEDED' AND safe_response IS NOT NULL AND output_digest IS NOT NULL
           AND output_artifact_ref IS NOT NULL AND output_artifact_digest IS NOT NULL
           AND evidence_ref IS NOT NULL AND evidence_digest IS NOT NULL AND completed_at IS NOT NULL)
      OR state <> 'SUCCEEDED'),
  CHECK ((state IN ('FAILED','UNKNOWN') AND stable_error IS NOT NULL AND completed_at IS NOT NULL)
      OR state NOT IN ('FAILED','UNKNOWN'))
);

CREATE TABLE IF NOT EXISTS public.model_budget_reservations (
  tenant_id uuid NOT NULL,
  reservation_id uuid NOT NULL,
  request_id uuid NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  reserved_microunits bigint NOT NULL CHECK (reserved_microunits > 0),
  actual_microunits bigint CHECK (actual_microunits IS NULL OR actual_microunits >= 0),
  state varchar(16) NOT NULL CHECK (state IN ('RESERVED','FINALIZED','UNKNOWN','RELEASED')),
  provider_key varchar(768),
  provider_request_id varchar(512),
  created_at timestamptz NOT NULL DEFAULT now(),
  finalized_at timestamptz,
  PRIMARY KEY (tenant_id, reservation_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, request_id)
    REFERENCES public.model_gateway_requests(tenant_id, request_id),
  CHECK ((state = 'RESERVED' AND actual_microunits IS NULL AND finalized_at IS NULL)
      OR (state <> 'RESERVED' AND actual_microunits IS NOT NULL AND finalized_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.model_stream_chunk_digests (
  tenant_id uuid NOT NULL,
  request_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  chunk_digest char(64) NOT NULL CHECK (chunk_digest ~ '^[a-f0-9]{64}$'),
  byte_count integer NOT NULL CHECK (byte_count > 0),
  terminal boolean NOT NULL DEFAULT false,
  finish_reason varchar(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id, sequence),
  FOREIGN KEY (tenant_id, request_id)
    REFERENCES public.model_gateway_requests(tenant_id, request_id),
  CHECK ((terminal AND finish_reason IS NOT NULL) OR (NOT terminal AND finish_reason IS NULL))
);

CREATE TABLE IF NOT EXISTS public.model_execution_evidence (
  tenant_id uuid NOT NULL,
  evidence_id uuid NOT NULL,
  request_id uuid NOT NULL,
  evidence_ref varchar(512) NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  provider_key varchar(768) NOT NULL,
  provider_request_id varchar(512) NOT NULL,
  provider_manifest_digest char(64) NOT NULL CHECK (provider_manifest_digest ~ '^[a-f0-9]{64}$'),
  route_decision_digest char(64) NOT NULL CHECK (route_decision_digest ~ '^[a-f0-9]{64}$'),
  data_policy_version varchar(256) NOT NULL,
  pre_transform_policy_decision_digest char(64) NOT NULL CHECK (pre_transform_policy_decision_digest ~ '^[a-f0-9]{64}$'),
  data_policy_decision_digest char(64) NOT NULL CHECK (data_policy_decision_digest ~ '^[a-f0-9]{64}$'),
  transformation_digest char(64) NOT NULL CHECK (transformation_digest ~ '^[a-f0-9]{64}$'),
  input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
  output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
  cost_microunits bigint NOT NULL CHECK (cost_microunits >= 0),
  prompt_digest char(64) NOT NULL CHECK (prompt_digest ~ '^[a-f0-9]{64}$'),
  output_digest char(64) NOT NULL CHECK (output_digest ~ '^[a-f0-9]{64}$'),
  residency_policy_evidence_ref varchar(2048) NOT NULL,
  residency_policy_evidence_digest char(64) NOT NULL CHECK (residency_policy_evidence_digest ~ '^[a-f0-9]{64}$'),
  input_dlp_report_digest char(64) NOT NULL CHECK (input_dlp_report_digest ~ '^[a-f0-9]{64}$'),
  input_dlp_evidence_ref varchar(2048) NOT NULL,
  input_dlp_evidence_digest char(64) NOT NULL CHECK (input_dlp_evidence_digest ~ '^[a-f0-9]{64}$'),
  transform_evidence_ref varchar(2048),
  transform_evidence_digest char(64) CHECK (transform_evidence_digest IS NULL OR transform_evidence_digest ~ '^[a-f0-9]{64}$'),
  output_dlp_report_digest char(64) NOT NULL CHECK (output_dlp_report_digest ~ '^[a-f0-9]{64}$'),
  output_dlp_evidence_ref varchar(2048) NOT NULL,
  output_dlp_evidence_digest char(64) NOT NULL CHECK (output_dlp_evidence_digest ~ '^[a-f0-9]{64}$'),
  output_label_evidence_ref varchar(2048) NOT NULL,
  output_label_evidence_digest char(64) NOT NULL CHECK (output_label_evidence_digest ~ '^[a-f0-9]{64}$'),
  artifact_policy_evidence_ref varchar(2048) NOT NULL,
  artifact_policy_evidence_digest char(64) NOT NULL CHECK (artifact_policy_evidence_digest ~ '^[a-f0-9]{64}$'),
  grant_consumption_evidence_ref varchar(2048),
  grant_consumption_evidence_digest char(64) CHECK (grant_consumption_evidence_digest IS NULL OR grant_consumption_evidence_digest ~ '^[a-f0-9]{64}$'),
  export_authorization_evidence_ref varchar(2048) NOT NULL,
  export_authorization_evidence_digest char(64) NOT NULL CHECK (export_authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  export_completion_evidence_ref varchar(2048) NOT NULL,
  export_completion_evidence_digest char(64) NOT NULL CHECK (export_completion_evidence_digest ~ '^[a-f0-9]{64}$'),
  artifact_store_receipt_ref varchar(2048) NOT NULL,
  artifact_store_receipt_digest char(64) NOT NULL CHECK (artifact_store_receipt_digest ~ '^[a-f0-9]{64}$'),
  trace_id varchar(128) NOT NULL,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, evidence_id),
  UNIQUE (tenant_id, request_id),
  UNIQUE (tenant_id, evidence_ref),
  FOREIGN KEY (tenant_id, request_id)
    REFERENCES public.model_gateway_requests(tenant_id, request_id),
  CHECK ((transform_evidence_ref IS NULL) = (transform_evidence_digest IS NULL)),
  CHECK ((grant_consumption_evidence_ref IS NULL) = (grant_consumption_evidence_digest IS NULL))
);

CREATE TABLE IF NOT EXISTS public.model_billing_usage_lines (
  tenant_id uuid NOT NULL,
  usage_id uuid NOT NULL,
  request_id uuid NOT NULL,
  provider_key varchar(768) NOT NULL,
  provider_request_id varchar(512) NOT NULL,
  input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
  output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
  metered_microunits bigint NOT NULL CHECK (metered_microunits >= 0),
  residency_policy_evidence_digest char(64) NOT NULL CHECK (residency_policy_evidence_digest ~ '^[a-f0-9]{64}$'),
  provider_statement_digest char(64) CHECK (provider_statement_digest IS NULL OR provider_statement_digest ~ '^[a-f0-9]{64}$'),
  reconciliation_state varchar(16) NOT NULL CHECK (reconciliation_state IN ('PENDING','MATCHED','MISMATCH')),
  created_at timestamptz NOT NULL DEFAULT now(),
  reconciled_at timestamptz,
  PRIMARY KEY (tenant_id, usage_id),
  UNIQUE (tenant_id, request_id),
  UNIQUE (tenant_id, provider_key, provider_request_id),
  FOREIGN KEY (tenant_id, request_id)
    REFERENCES public.model_gateway_requests(tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS public.model_billing_reconciliations (
  tenant_id uuid NOT NULL,
  reconciliation_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  authorization_id uuid NOT NULL,
  authorization_digest char(64) NOT NULL CHECK (authorization_digest ~ '^[a-f0-9]{64}$'),
  policy_decision_id varchar(256) NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  authorization_evidence_ref varchar(512) NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[a-f0-9]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  resource_version varchar(256) NOT NULL,
  provider_id varchar(128) NOT NULL,
  statement_period varchar(64) NOT NULL,
  statement_digest char(64) NOT NULL CHECK (statement_digest ~ '^[a-f0-9]{64}$'),
  residency_policy_evidence_digest char(64) NOT NULL CHECK (residency_policy_evidence_digest ~ '^[a-f0-9]{64}$'),
  matched_requests bigint NOT NULL CHECK (matched_requests >= 0),
  total_metered_microunits bigint NOT NULL CHECK (total_metered_microunits >= 0),
  total_billed_microunits bigint NOT NULL CHECK (total_billed_microunits >= 0),
  matched boolean NOT NULL,
  trace_id varchar(128) NOT NULL,
  evidence_ref varchar(512) NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  safe_response jsonb NOT NULL CHECK (jsonb_typeof(safe_response) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, reconciliation_id),
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, provider_id, statement_period),
  UNIQUE (tenant_id, statement_digest),
  UNIQUE (tenant_id, ledger_execution_id)
);

CREATE TABLE IF NOT EXISTS public.model_evidence_outbox (
  tenant_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  request_id uuid NOT NULL,
  event_type varchar(128) NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, outbox_id),
  UNIQUE (tenant_id, request_id, event_type),
  FOREIGN KEY (tenant_id, request_id)
    REFERENCES public.model_gateway_requests(tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS public.model_authority_evidence_outbox (
  tenant_id uuid NOT NULL,
  authority_event_id uuid NOT NULL,
  action_id uuid NOT NULL,
  event_kind varchar(128) NOT NULL CHECK (event_kind ~ '^[A-Z0-9_]+$'),
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  state varchar(16) NOT NULL CHECK (state IN ('PREPARED','DELIVERED')),
  signed_receipt jsonb CHECK (signed_receipt IS NULL OR jsonb_typeof(signed_receipt) = 'object'),
  evidence_ref varchar(2048),
  evidence_digest char(64) CHECK (evidence_digest IS NULL OR evidence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id, authority_event_id),
  UNIQUE (tenant_id, idempotency_key),
  CHECK ((state = 'PREPARED' AND signed_receipt IS NULL AND evidence_ref IS NULL
          AND evidence_digest IS NULL AND delivered_at IS NULL)
      OR (state = 'DELIVERED' AND signed_receipt IS NOT NULL AND evidence_ref IS NOT NULL
          AND evidence_digest IS NOT NULL AND delivered_at IS NOT NULL))
);

-- Preserve the exact Batch 18 command, including requested_at, before network dispatch. A retry
-- replays this JSON byte-for-byte at the semantic level instead of constructing a conflicting
-- command with a new timestamp under the same command/idempotency identity.
CREATE TABLE IF NOT EXISTS public.model_data_governance_outbox (
  tenant_id uuid NOT NULL,
  command_id uuid NOT NULL,
  action_id uuid NOT NULL,
  phase varchar(256) NOT NULL CHECK (phase ~ '^[A-Za-z0-9._:/-]+$'),
  idempotency_key varchar(128) NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  command jsonb NOT NULL CHECK (jsonb_typeof(command) = 'object'),
  command_digest char(64) NOT NULL CHECK (command_digest ~ '^[a-f0-9]{64}$'),
  state varchar(16) NOT NULL CHECK (state IN ('PREPARED','COMPLETED')),
  mutation_result jsonb CHECK (mutation_result IS NULL OR jsonb_typeof(mutation_result) = 'object'),
  evidence_ref varchar(2048),
  evidence_digest char(64) CHECK (evidence_digest IS NULL OR evidence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, command_id),
  UNIQUE (tenant_id, action_id, phase),
  UNIQUE (tenant_id, idempotency_key),
  CHECK ((state = 'PREPARED' AND mutation_result IS NULL AND evidence_ref IS NULL
          AND evidence_digest IS NULL AND completed_at IS NULL)
      OR (state = 'COMPLETED' AND mutation_result IS NOT NULL AND evidence_ref IS NOT NULL
          AND evidence_digest IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE OR REPLACE FUNCTION public.agenttrust_model_immutable_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  RAISE EXCEPTION 'MODEL_IMMUTABLE_ROW';
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_model_immutable_row() FROM PUBLIC;

DO $triggers$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'model_provider_revisions',
    'model_provider_revocations',
    'model_stream_chunk_digests',
    'model_execution_evidence',
    'model_billing_reconciliations',
    'model_evidence_outbox'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS model_immutable_row ON public.%I', table_name);
    EXECUTE format(
      'CREATE TRIGGER model_immutable_row BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.agenttrust_model_immutable_row()',
      table_name
    );
  END LOOP;
END
$triggers$;

CREATE OR REPLACE FUNCTION public.agenttrust_model_request_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id
     OR NEW.request_id <> OLD.request_id
     OR NEW.task_id <> OLD.task_id
     OR NEW.action_id <> OLD.action_id
     OR NEW.action_hash <> OLD.action_hash
     OR NEW.request_digest <> OLD.request_digest
     OR NEW.operation <> OLD.operation
     OR NEW.idempotency_key <> OLD.idempotency_key
     OR NEW.authorization_id <> OLD.authorization_id
     OR NEW.authorization_digest <> OLD.authorization_digest
     OR NEW.policy_decision_id <> OLD.policy_decision_id
     OR NEW.policy_decision_digest <> OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref <> OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest <> OLD.authorization_evidence_digest
     OR NEW.ledger_execution_id <> OLD.ledger_execution_id
     OR NEW.ledger_event_id <> OLD.ledger_event_id
     OR NEW.ledger_event_digest <> OLD.ledger_event_digest
     OR NEW.fence_digest <> OLD.fence_digest
     OR NEW.resource_version <> OLD.resource_version
     OR NEW.classification <> OLD.classification
     OR NEW.source_jurisdiction <> OLD.source_jurisdiction
     OR NEW.deployment_profile <> OLD.deployment_profile
     OR NEW.prompt_digest <> OLD.prompt_digest
     OR NEW.maximum_cost_microunits <> OLD.maximum_cost_microunits
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'MODEL_REQUEST_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state = 'PREPARED' AND NEW.state IN ('EXECUTING','FAILED'))
       OR (OLD.state = 'EXECUTING' AND NEW.state IN ('SUCCEEDED','FAILED','UNKNOWN'))
       OR (OLD.state = NEW.state AND OLD.safe_response IS NOT DISTINCT FROM NEW.safe_response
           AND OLD.stable_error IS NOT DISTINCT FROM NEW.stable_error
           AND OLD.evidence_ref IS NOT DISTINCT FROM NEW.evidence_ref
           AND OLD.evidence_digest IS NOT DISTINCT FROM NEW.evidence_digest
           AND OLD.output_artifact_ref IS NOT DISTINCT FROM NEW.output_artifact_ref
           AND OLD.output_artifact_digest IS NOT DISTINCT FROM NEW.output_artifact_digest
           AND OLD.selected_provider_key IS NOT DISTINCT FROM NEW.selected_provider_key
           AND OLD.provider_request_id IS NOT DISTINCT FROM NEW.provider_request_id)) THEN
    RAISE EXCEPTION 'MODEL_REQUEST_TRANSITION_INVALID';
  END IF;
  IF OLD.state = 'EXECUTING' AND NEW.state = 'EXECUTING' AND
     (NEW.selected_provider_key IS DISTINCT FROM OLD.selected_provider_key
      OR NEW.provider_request_id IS DISTINCT FROM OLD.provider_request_id) THEN
    RAISE EXCEPTION 'MODEL_PROVIDER_BINDING_IMMUTABLE';
  END IF;
  IF OLD.state = 'EXECUTING' AND NEW.state <> 'EXECUTING' AND
     NEW.selected_provider_key IS DISTINCT FROM OLD.selected_provider_key THEN
    RAISE EXCEPTION 'MODEL_PROVIDER_BINDING_IMMUTABLE';
  END IF;
  IF OLD.state = 'EXECUTING' AND NEW.state = 'EXECUTING' AND
     (NEW.owner_instance_id IS DISTINCT FROM OLD.owner_instance_id
      OR NEW.lease_expires_at < OLD.lease_expires_at) THEN
    RAISE EXCEPTION 'MODEL_EXECUTION_LEASE_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_model_request_transition_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS model_request_transition_guard ON public.model_gateway_requests;
CREATE TRIGGER model_request_transition_guard
BEFORE UPDATE ON public.model_gateway_requests
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_model_request_transition_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_model_usage_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id
     OR NEW.usage_id <> OLD.usage_id
     OR NEW.request_id <> OLD.request_id
     OR NEW.provider_key <> OLD.provider_key
     OR NEW.provider_request_id <> OLD.provider_request_id
     OR NEW.input_tokens <> OLD.input_tokens
     OR NEW.output_tokens <> OLD.output_tokens
     OR NEW.metered_microunits <> OLD.metered_microunits
     OR NEW.residency_policy_evidence_digest <> OLD.residency_policy_evidence_digest
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'MODEL_USAGE_BINDING_IMMUTABLE';
  END IF;
  IF OLD.reconciliation_state <> 'PENDING'
     OR NEW.reconciliation_state NOT IN ('MATCHED','MISMATCH')
     OR OLD.provider_statement_digest IS NOT NULL
     OR NEW.provider_statement_digest IS NULL
     OR OLD.reconciled_at IS NOT NULL
     OR NEW.reconciled_at IS NULL THEN
    RAISE EXCEPTION 'MODEL_USAGE_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_model_usage_transition_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS model_usage_transition_guard ON public.model_billing_usage_lines;
CREATE TRIGGER model_usage_transition_guard
BEFORE UPDATE ON public.model_billing_usage_lines
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_model_usage_transition_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_model_approval_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'MODEL_APPROVAL_IMMUTABLE';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id
     OR NEW.approval_id <> OLD.approval_id
     OR NEW.provider_id <> OLD.provider_id
     OR NEW.model_id <> OLD.model_id
     OR NEW.model_version <> OLD.model_version
     OR NEW.provider_revision <> OLD.provider_revision
     OR NEW.manifest_digest <> OLD.manifest_digest
     OR NEW.allowed_deployment_profiles <> OLD.allowed_deployment_profiles
     OR NEW.allowed_source_jurisdictions <> OLD.allowed_source_jurisdictions
     OR NEW.maximum_request_microunits <> OLD.maximum_request_microunits
     OR NEW.approval_evidence_ref <> OLD.approval_evidence_ref
     OR NEW.approval_evidence_digest <> OLD.approval_evidence_digest
     OR NEW.approved_by <> OLD.approved_by
     OR NEW.approved_at <> OLD.approved_at
     OR NEW.expires_at <> OLD.expires_at
     OR OLD.status <> 'ACTIVE'
     OR NEW.status NOT IN ('REVOKED','EXPIRED') THEN
    RAISE EXCEPTION 'MODEL_APPROVAL_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_model_approval_transition_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS model_approval_transition_guard ON public.model_tenant_provider_approvals;
CREATE TRIGGER model_approval_transition_guard
BEFORE UPDATE OR DELETE ON public.model_tenant_provider_approvals
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_model_approval_transition_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_model_authority_outbox_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR OLD.state <> 'PREPARED'
     OR NEW.state <> 'DELIVERED'
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.authority_event_id <> OLD.authority_event_id
     OR NEW.action_id <> OLD.action_id
     OR NEW.event_kind <> OLD.event_kind
     OR NEW.idempotency_key <> OLD.idempotency_key
     OR NEW.request <> OLD.request
     OR NEW.request_digest <> OLD.request_digest
     OR NEW.created_at <> OLD.created_at
     OR NEW.signed_receipt IS NULL
     OR NEW.evidence_ref IS NULL
     OR NEW.evidence_digest IS NULL
     OR NEW.delivered_at IS NULL THEN
    RAISE EXCEPTION 'MODEL_AUTHORITY_EVIDENCE_OUTBOX_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_model_authority_outbox_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS model_authority_outbox_guard ON public.model_authority_evidence_outbox;
CREATE TRIGGER model_authority_outbox_guard
BEFORE UPDATE OR DELETE ON public.model_authority_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_model_authority_outbox_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_model_data_outbox_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR OLD.state <> 'PREPARED'
     OR NEW.state <> 'COMPLETED'
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.command_id <> OLD.command_id
     OR NEW.action_id <> OLD.action_id
     OR NEW.phase <> OLD.phase
     OR NEW.idempotency_key <> OLD.idempotency_key
     OR NEW.command <> OLD.command
     OR NEW.command_digest <> OLD.command_digest
     OR NEW.created_at <> OLD.created_at
     OR NEW.mutation_result IS NULL
     OR NEW.evidence_ref IS NULL
     OR NEW.evidence_digest IS NULL
     OR NEW.completed_at IS NULL THEN
    RAISE EXCEPTION 'MODEL_DATA_GOVERNANCE_OUTBOX_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_model_data_outbox_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS model_data_outbox_guard ON public.model_data_governance_outbox;
CREATE TRIGGER model_data_outbox_guard
BEFORE UPDATE OR DELETE ON public.model_data_governance_outbox
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_model_data_outbox_guard();

CREATE INDEX IF NOT EXISTS model_requests_tenant_state_idx
  ON public.model_gateway_requests(tenant_id, state, updated_at);
CREATE INDEX IF NOT EXISTS model_approvals_active_idx
  ON public.model_tenant_provider_approvals(tenant_id, status, expires_at);
CREATE INDEX IF NOT EXISTS model_provider_revocations_digest_idx
  ON public.model_provider_revocations(provider_manifest_digest, revoked_at);
CREATE INDEX IF NOT EXISTS model_usage_reconciliation_idx
  ON public.model_billing_usage_lines(tenant_id, reconciliation_state, created_at);
CREATE INDEX IF NOT EXISTS model_reconciliations_period_idx
  ON public.model_billing_reconciliations(tenant_id, provider_id, statement_period);
CREATE INDEX IF NOT EXISTS model_authority_evidence_pending_idx
  ON public.model_authority_evidence_outbox(tenant_id, state, created_at);
CREATE INDEX IF NOT EXISTS model_data_governance_pending_idx
  ON public.model_data_governance_outbox(tenant_id, state, created_at);

DO $rls$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'model_tenant_provider_approvals',
    'model_budget_accounts',
    'model_gateway_requests',
    'model_budget_reservations',
    'model_stream_chunk_digests',
    'model_execution_evidence',
    'model_billing_usage_lines',
    'model_billing_reconciliations',
    'model_evidence_outbox',
    'model_authority_evidence_outbox',
    'model_data_governance_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS model_tenant_isolation ON public.%I', table_name);
    EXECUTE format(
      'CREATE POLICY model_tenant_isolation ON public.%I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      table_name
    );
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC', table_name);
  END LOOP;
END
$rls$;

REVOKE ALL ON TABLE public.model_provider_revisions FROM PUBLIC;
REVOKE ALL ON TABLE public.model_provider_revocations FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

COMMIT;
