BEGIN;

-- MCP lifecycle and replay state used by McpStateStore. These rows are durable authority, not
-- cached observations; all consumer implementations must use transactions and unique conflicts.
CREATE TABLE IF NOT EXISTS public.mcp_authorization_consumptions (
  tenant_id uuid NOT NULL,
  authorization_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  arguments_digest char(64) NOT NULL CHECK (arguments_digest ~ '^[a-f0-9]{64}$'),
  snapshot_hash char(64) NOT NULL CHECK (snapshot_hash ~ '^[a-f0-9]{64}$'),
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, authorization_id)
);
CREATE TABLE IF NOT EXISTS public.mcp_server_transitions (
  tenant_id uuid NOT NULL,
  transition_id uuid NOT NULL,
  server_id text NOT NULL,
  from_status text,
  to_status text NOT NULL CHECK (to_status IN ('PENDING','APPROVED','FROZEN','REVOKED','QUARANTINED')),
  manifest_hash char(64) NOT NULL CHECK (manifest_hash ~ '^[a-f0-9]{64}$'),
  reason_code varchar(128) NOT NULL CHECK (reason_code ~ '^[A-Z0-9_]+$'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, transition_id)
);
CREATE TABLE IF NOT EXISTS public.mcp_runtime_call_evidence (
  tenant_id uuid NOT NULL,
  call_id uuid NOT NULL,
  server_id text NOT NULL,
  tool_name text NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  snapshot_hash char(64),
  result_hash char(64),
  outcome varchar(128) NOT NULL,
  trace_id varchar(256) NOT NULL,
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, call_id),
  CHECK (snapshot_hash IS NULL OR snapshot_hash ~ '^[a-f0-9]{64}$'),
  CHECK (result_hash IS NULL OR result_hash ~ '^[a-f0-9]{64}$')
);

-- A2A revocation epochs, child-budget reservations, task status and AG-UI sequence allocation.
CREATE TABLE IF NOT EXISTS public.delegation_tenant_epochs (
  tenant_id uuid PRIMARY KEY,
  revocation_epoch bigint NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.delegation_call_consumptions (
  tenant_id uuid NOT NULL,
  token_id uuid NOT NULL,
  consumption_sequence bigint NOT NULL CHECK (consumption_sequence > 0),
  remaining_calls integer NOT NULL CHECK (remaining_calls >= 0),
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, token_id, consumption_sequence),
  FOREIGN KEY (tenant_id, token_id) REFERENCES public.delegation_tokens(tenant_id, token_id)
);
CREATE TABLE IF NOT EXISTS public.a2a_task_links (
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  remote_task_id varchar(512) NOT NULL,
  agent_id varchar(256) NOT NULL,
  agent_card_hash char(64) NOT NULL CHECK (agent_card_hash ~ '^[a-f0-9]{64}$'),
  agent_endpoint varchar(2048) NOT NULL CHECK (agent_endpoint ~ '^https://'),
  protocol_version varchar(16) NOT NULL CHECK (protocol_version IN ('0.3.0','1.0')),
  state varchar(24) NOT NULL CHECK (state IN ('SUBMITTED','WORKING','INPUT_REQUIRED','AUTH_REQUIRED','VERIFYING','COMPLETED','CANCELLING','CANCELLED','REJECTED','FAILED')),
  remote_status varchar(24) NOT NULL CHECK (remote_status IN ('submitted','working','input-required','auth-required','completed','canceled','rejected','failed')),
  evaluation_status varchar(32),
  revision bigint NOT NULL CHECK (revision > 0),
  signed_record jsonb NOT NULL CHECK (jsonb_typeof(signed_record) = 'object'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, task_id),
  UNIQUE (tenant_id, remote_task_id)
);
CREATE TABLE IF NOT EXISTS public.agui_stream_sequences (
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  last_reserved_sequence bigint NOT NULL DEFAULT 0 CHECK (last_reserved_sequence >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id)
);

-- Industrial replay and append-only journal. A DISPATCHING entry followed by no terminal record is
-- deliberately UNKNOWN and must be reconciled from device telemetry before any retry.
CREATE TABLE IF NOT EXISTS public.industrial_authorization_consumptions (
  tenant_id uuid NOT NULL,
  authorization_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  resource_key text NOT NULL,
  purpose varchar(16) NOT NULL CHECK (purpose IN ('WRITE','SAFE_STOP')),
  central_policy_version varchar(256) NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, authorization_id)
);
CREATE TABLE IF NOT EXISTS public.industrial_operation_journal (
  tenant_id uuid NOT NULL,
  journal_sequence bigint GENERATED ALWAYS AS IDENTITY,
  journal_id uuid NOT NULL,
  preparation_id uuid,
  authorization_id uuid,
  action_hash char(64),
  resource_key text NOT NULL,
  phase varchar(32) NOT NULL CHECK (phase IN ('PREPARED','DISPATCHING','COMMITTED','VERIFIED','NOOP','UNKNOWN','SAFE_STOP_REQUESTED','SAFE_STOP_COMPLETED')),
  central_policy_version varchar(256),
  local_policy_version varchar(256),
  clock_health_digest char(64),
  convergence_evidence jsonb,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  prior_journal_digest char(64) NOT NULL CHECK (prior_journal_digest ~ '^[a-f0-9]{64}$'),
  journal_digest char(64) NOT NULL CHECK (journal_digest ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, journal_sequence),
  UNIQUE (tenant_id, journal_id),
  UNIQUE (tenant_id, journal_digest),
  CHECK (action_hash IS NULL OR action_hash ~ '^[a-f0-9]{64}$'),
  CHECK (clock_health_digest IS NULL OR clock_health_digest ~ '^[a-f0-9]{64}$'),
  CHECK (convergence_evidence IS NULL OR jsonb_typeof(convergence_evidence) = 'object')
);

-- Verified provider residency and billing signatures remain separately queryable from the final
-- signed model Evidence. Nullable upgrade columns preserve historical pre-attestation rows; every
-- new authority write supplies both members of each pair.
ALTER TABLE public.model_execution_evidence
  ADD COLUMN IF NOT EXISTS residency_attestation_ref varchar(2048),
  ADD COLUMN IF NOT EXISTS residency_attestation_digest char(64);
ALTER TABLE public.model_execution_evidence
  DROP CONSTRAINT IF EXISTS model_execution_residency_attestation_pair;
ALTER TABLE public.model_execution_evidence
  ADD CONSTRAINT model_execution_residency_attestation_pair CHECK (
    (residency_attestation_ref IS NULL) = (residency_attestation_digest IS NULL)
    AND (residency_attestation_digest IS NULL OR residency_attestation_digest ~ '^[a-f0-9]{64}$')
  );
ALTER TABLE public.model_billing_reconciliations
  ADD COLUMN IF NOT EXISTS provider_attestation_digest char(64);
ALTER TABLE public.model_billing_reconciliations
  DROP CONSTRAINT IF EXISTS model_billing_provider_attestation_digest_valid;
ALTER TABLE public.model_billing_reconciliations
  ADD CONSTRAINT model_billing_provider_attestation_digest_valid CHECK (
    provider_attestation_digest IS NULL OR provider_attestation_digest ~ '^[a-f0-9]{64}$'
  );

CREATE OR REPLACE FUNCTION public.agenttrust_protocol_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  RAISE EXCEPTION 'PROTOCOL_RUNTIME_EVIDENCE_IMMUTABLE';
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_protocol_append_only() FROM PUBLIC;

DO $triggers$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'mcp_authorization_consumptions',
    'mcp_server_transitions',
    'mcp_runtime_call_evidence',
    'delegation_call_consumptions',
    'industrial_authorization_consumptions',
    'industrial_operation_journal',
    'agui_events'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS protocol_append_only ON public.%I', table_name);
    EXECUTE format(
      'CREATE TRIGGER protocol_append_only BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.agenttrust_protocol_append_only()',
      table_name
    );
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC', table_name);
  END LOOP;
END
$triggers$;

CREATE OR REPLACE FUNCTION public.agenttrust_delegation_token_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.token_id <> OLD.token_id
     OR NEW.root_task_id <> OLD.root_task_id
     OR NEW.parent_task_id <> OLD.parent_task_id
     OR NEW.parent_token_id IS DISTINCT FROM OLD.parent_token_id
     OR NEW.token_hash <> OLD.token_hash
     OR NEW.depth <> OLD.depth
     OR NEW.expires_at <> OLD.expires_at
     OR NEW.revocation_epoch <> OLD.revocation_epoch
     OR NEW.remaining_calls > OLD.remaining_calls
     OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
     OR (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.revoked_at < now() - interval '5 minutes') THEN
    RAISE EXCEPTION 'A2A_DELEGATION_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_delegation_token_transition_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS delegation_token_transition_guard ON public.delegation_tokens;
CREATE TRIGGER delegation_token_transition_guard
BEFORE UPDATE OR DELETE ON public.delegation_tokens
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_delegation_token_transition_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_a2a_task_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.task_id <> OLD.task_id
     OR NEW.remote_task_id <> OLD.remote_task_id
     OR NEW.agent_id <> OLD.agent_id
     OR NEW.agent_card_hash <> OLD.agent_card_hash
     OR NEW.agent_endpoint <> OLD.agent_endpoint
     OR NEW.protocol_version <> OLD.protocol_version
     OR NEW.revision <> OLD.revision + 1
     OR NEW.updated_at <= OLD.updated_at
     OR OLD.state IN ('COMPLETED','CANCELLED','REJECTED','FAILED')
     OR NOT (
       (OLD.state = 'SUBMITTED' AND NEW.state IN ('SUBMITTED','WORKING','INPUT_REQUIRED','AUTH_REQUIRED','VERIFYING','COMPLETED','CANCELLING','CANCELLED','REJECTED','FAILED')) OR
       (OLD.state = 'WORKING' AND NEW.state IN ('WORKING','INPUT_REQUIRED','AUTH_REQUIRED','VERIFYING','COMPLETED','CANCELLING','CANCELLED','REJECTED','FAILED')) OR
       (OLD.state IN ('INPUT_REQUIRED','AUTH_REQUIRED') AND NEW.state IN ('WORKING','INPUT_REQUIRED','AUTH_REQUIRED','VERIFYING','COMPLETED','CANCELLING','CANCELLED','REJECTED','FAILED')) OR
       (OLD.state = 'VERIFYING' AND NEW.state IN ('VERIFYING','COMPLETED','CANCELLING','CANCELLED','REJECTED','FAILED')) OR
       (OLD.state = 'CANCELLING' AND NEW.state IN ('CANCELLING','VERIFYING','COMPLETED','CANCELLED','REJECTED','FAILED'))
     ) THEN
    RAISE EXCEPTION 'A2A_TASK_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_a2a_task_transition_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS a2a_task_transition_guard ON public.a2a_task_links;
CREATE TRIGGER a2a_task_transition_guard
BEFORE UPDATE OR DELETE ON public.a2a_task_links
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_a2a_task_transition_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_agui_sequence_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.task_id <> OLD.task_id
     OR NEW.last_reserved_sequence <> OLD.last_reserved_sequence + 1
     OR NEW.updated_at <= OLD.updated_at THEN
    RAISE EXCEPTION 'AGUI_SEQUENCE_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_agui_sequence_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS agui_sequence_guard ON public.agui_stream_sequences;
CREATE TRIGGER agui_sequence_guard
BEFORE UPDATE OR DELETE ON public.agui_stream_sequences
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_agui_sequence_guard();

CREATE OR REPLACE FUNCTION public.agenttrust_industrial_journal_chain_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE latest_digest char(64);
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  SELECT journal_digest INTO latest_digest
    FROM public.industrial_operation_journal
   WHERE tenant_id = NEW.tenant_id
   ORDER BY journal_sequence DESC LIMIT 1;
  IF NEW.prior_journal_digest <> COALESCE(latest_digest, repeat('0', 64)) THEN
    RAISE EXCEPTION 'INDUSTRIAL_JOURNAL_CHAIN_INVALID';
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.agenttrust_industrial_journal_chain_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS industrial_journal_chain_guard ON public.industrial_operation_journal;
CREATE TRIGGER industrial_journal_chain_guard
BEFORE INSERT ON public.industrial_operation_journal
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_industrial_journal_chain_guard();

CREATE INDEX IF NOT EXISTS mcp_runtime_calls_scope_idx
  ON public.mcp_runtime_call_evidence(tenant_id, server_id, tool_name, occurred_at DESC);
CREATE INDEX IF NOT EXISTS a2a_task_state_idx
  ON public.a2a_task_links(tenant_id, state, updated_at DESC);
CREATE INDEX IF NOT EXISTS industrial_journal_preparation_idx
  ON public.industrial_operation_journal(tenant_id, preparation_id, journal_sequence);

COMMIT;
