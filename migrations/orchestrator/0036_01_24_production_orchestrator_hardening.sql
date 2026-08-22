BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'orchestrator_ingress_contract_check'
       AND conrelid = 'public.orchestrator_ingress_actions'::regclass
  ) THEN
    ALTER TABLE public.orchestrator_ingress_actions
      ADD CONSTRAINT orchestrator_ingress_contract_check CHECK (
        owner_subject ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
        AND status IN ('PENDING_WORKFLOW', 'CREATED', 'START_REQUESTED')
        AND payload_hash ~ '^[0-9a-f]{64}$'
        AND idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'
        AND jsonb_typeof(envelope) = 'object'
        AND envelope->>'schema_version' = 'agenttrust.gateway.v1'
        AND envelope->>'protocol' = 'HTTP'
        AND envelope->>'idempotency_key' = idempotency_key
        AND envelope->>'payload_hash' = payload_hash
        AND envelope#>>'{tenant_context,tenant_id}' = tenant_id::text
        AND envelope#>>'{identity_context,tenant_id}' = tenant_id::text
        AND envelope#>>'{identity_context,owner_subject}' = owner_subject
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'orchestrator_stream_event_contract_check'
       AND conrelid = 'public.orchestrator_stream_events'::regclass
  ) THEN
    ALTER TABLE public.orchestrator_stream_events
      ADD CONSTRAINT orchestrator_stream_event_contract_check CHECK (
        jsonb_typeof(event) = 'object'
        AND event->>'schema_version' = 'agenttrust.orchestrator-command.v1'
        AND event->>'tenant_id' = tenant_id::text
        AND event->>'task_id' = task_id::text
        AND event->>'command_id' ~ '^[A-Za-z0-9._:-]{1,256}$'
        AND event->>'request_idempotency_key' ~ '^[A-Za-z0-9._:-]{1,256}$'
        AND event->>'command_type' IN (
          'START', 'PAUSE', 'RESUME', 'CANCEL', 'KILL',
          'CHECKPOINT', 'VERIFY', 'COMPLETE'
        )
        AND event->>'expected_state_version' ~ '^(0|[1-9][0-9]*)$'
        AND event->>'payload_digest' ~ '^[0-9a-f]{64}$'
        AND event->>'requested_by' ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
        AND length(event->>'requested_at') BETWEEN 20 AND 40
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'orchestrator_stream_ingress_fk'
       AND conrelid = 'public.orchestrator_stream_events'::regclass
  ) THEN
    ALTER TABLE public.orchestrator_stream_events
      ADD CONSTRAINT orchestrator_stream_ingress_fk
      FOREIGN KEY (tenant_id, task_id)
      REFERENCES public.orchestrator_ingress_actions (tenant_id, task_id)
      NOT VALID;
  END IF;
END
$$;

ALTER TABLE public.orchestrator_ingress_actions
  VALIDATE CONSTRAINT orchestrator_ingress_contract_check;
ALTER TABLE public.orchestrator_stream_events
  VALIDATE CONSTRAINT orchestrator_stream_event_contract_check;
ALTER TABLE public.orchestrator_stream_events
  VALIDATE CONSTRAINT orchestrator_stream_ingress_fk;

CREATE UNIQUE INDEX IF NOT EXISTS orchestrator_stream_command_once_idx
  ON public.orchestrator_stream_events (
    tenant_id, task_id, ((event->>'command_id'))
  );

CREATE OR REPLACE FUNCTION public.agenttrust_guard_orchestrator_ingress()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'ORCHESTRATOR_INGRESS_DELETE_FORBIDDEN';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id
     OR NEW.action_id <> OLD.action_id
     OR NEW.task_id <> OLD.task_id
     OR NEW.owner_subject <> OLD.owner_subject
     OR NEW.payload_hash <> OLD.payload_hash
     OR NEW.idempotency_key <> OLD.idempotency_key
     OR NEW.envelope <> OLD.envelope
     OR NEW.created_at <> OLD.created_at
     OR NEW.updated_at < OLD.updated_at
     OR NOT (
       NEW.status = OLD.status
       OR OLD.status = 'PENDING_WORKFLOW' AND NEW.status = 'CREATED'
       OR OLD.status = 'CREATED' AND NEW.status = 'START_REQUESTED'
     )
  THEN
    RAISE EXCEPTION 'ORCHESTRATOR_INGRESS_IMMUTABLE_OR_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS orchestrator_ingress_guard
  ON public.orchestrator_ingress_actions;
CREATE TRIGGER orchestrator_ingress_guard
BEFORE UPDATE OR DELETE ON public.orchestrator_ingress_actions
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_guard_orchestrator_ingress();

CREATE OR REPLACE FUNCTION public.agenttrust_guard_orchestrator_stream()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'ORCHESTRATOR_STREAM_APPEND_ONLY';
END
$$;

DROP TRIGGER IF EXISTS orchestrator_stream_append_only
  ON public.orchestrator_stream_events;
CREATE TRIGGER orchestrator_stream_append_only
BEFORE UPDATE OR DELETE ON public.orchestrator_stream_events
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_guard_orchestrator_stream();

COMMIT;
