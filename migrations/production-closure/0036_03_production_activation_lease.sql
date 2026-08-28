-- Global, database-enforced production write activation.
--
-- This migration intentionally remains last in migrations/manifest.txt. Every
-- application table is protected by a statement trigger. A short lease renewed
-- only after the independently verified activation watcher is healthy makes a
-- watcher, database, projection, or revocation failure fail closed for writes.
-- The schema migration history and the two activation-control tables are the
-- only exclusions; application roles receive no direct privileges on them.

CREATE TABLE IF NOT EXISTS public.production_activation_lease (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  revision bigint NOT NULL CHECK (revision >= 0),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'FENCED', 'REVOKED')),
  release_id text NOT NULL CHECK (
    release_id = 'UNINITIALIZED'
    OR release_id ~ '^git:(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$'
  ),
  certificate_id text,
  revocation_registry_id text,
  revocation_sequence bigint CHECK (revocation_sequence IS NULL OR revocation_sequence > 0),
  revocation_registry_digest char(64),
  projection_id text,
  projection_head_digest char(64),
  watcher_verified_at timestamptz,
  renewed_at timestamptz,
  valid_until timestamptz NOT NULL,
  transition_receipt_digest char(64),
  state_digest char(64) NOT NULL,
  CHECK (
    state <> 'ACTIVE'
    OR (
      certificate_id ~ '^pc-[0-9a-f]{24}$'
      AND length(revocation_registry_id) BETWEEN 1 AND 256
      AND revocation_sequence IS NOT NULL
      AND revocation_registry_digest ~ '^[0-9a-f]{64}$'
      AND length(projection_id) BETWEEN 1 AND 256
      AND projection_head_digest ~ '^[0-9a-f]{64}$'
      AND watcher_verified_at IS NOT NULL
      AND renewed_at IS NOT NULL
      AND transition_receipt_digest ~ '^[0-9a-f]{64}$'
      AND state_digest ~ '^[0-9a-f]{64}$'
    )
  )
);

CREATE TABLE IF NOT EXISTS public.production_activation_history (
  revision bigint PRIMARY KEY CHECK (revision > 0),
  previous_state_digest char(64) NOT NULL CHECK (
    previous_state_digest ~ '^[0-9a-f]{64}$'
  ),
  state_digest char(64) NOT NULL UNIQUE CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'FENCED', 'REVOKED')),
  release_id text NOT NULL CHECK (
    release_id ~ '^git:(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$'
  ),
  certificate_id text CHECK (certificate_id IS NULL OR certificate_id ~ '^pc-[0-9a-f]{24}$'),
  revocation_registry_id text,
  revocation_sequence bigint CHECK (revocation_sequence IS NULL OR revocation_sequence > 0),
  revocation_registry_digest char(64),
  projection_id text,
  projection_head_digest char(64),
  transition_receipt_digest char(64) NOT NULL CHECK (
    transition_receipt_digest ~ '^[0-9a-f]{64}$'
  ),
  transitioned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  transitioned_by text NOT NULL DEFAULT session_user
);

INSERT INTO public.production_activation_lease (
  singleton,
  revision,
  state,
  release_id,
  valid_until,
  state_digest
)
VALUES (
  true,
  0,
  'FENCED',
  'UNINITIALIZED',
  '-infinity'::timestamptz,
  repeat('0', 64)
)
ON CONFLICT (singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION public.agenttrust_enforce_production_activation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $activation_guard$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM public.production_activation_lease AS lease
     WHERE lease.singleton
       AND lease.state = 'ACTIVE'
       AND lease.valid_until > clock_timestamp()
       AND lease.renewed_at >= clock_timestamp() - interval '60 seconds'
       AND lease.watcher_verified_at >= clock_timestamp() - interval '60 seconds'
       AND lease.release_id ~ '^git:(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$'
       AND lease.state_digest ~ '^[0-9a-f]{64}$'
  ) THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_LEASE_NOT_ACTIVE'
      USING ERRCODE = '55000';
  END IF;
  RETURN NULL;
END
$activation_guard$;

CREATE OR REPLACE FUNCTION public.agenttrust_renew_production_activation(
  expected_state_digest char(64),
  expected_release_id text,
  expected_certificate_id text,
  registry_id text,
  registry_sequence bigint,
  registry_digest char(64),
  verified_projection_id text,
  verified_projection_head_digest char(64),
  verified_at timestamptz,
  requested_valid_until timestamptz
)
RETURNS TABLE (
  renewed_revision bigint,
  renewed_state_digest char(64),
  renewed_valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $renew_activation$
DECLARE
  current_lease public.production_activation_lease%ROWTYPE;
BEGIN
  IF expected_state_digest IS NULL
     OR expected_state_digest !~ '^[0-9a-f]{64}$'
     OR expected_release_id IS NULL
     OR expected_release_id !~ '^git:(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$'
     OR expected_certificate_id IS NULL
     OR expected_certificate_id !~ '^pc-[0-9a-f]{24}$'
     OR registry_id IS NULL
     OR length(registry_id) NOT BETWEEN 1 AND 256
     OR registry_sequence IS NULL
     OR registry_sequence <= 0
     OR registry_digest IS NULL
     OR registry_digest !~ '^[0-9a-f]{64}$'
     OR verified_projection_id IS NULL
     OR length(verified_projection_id) NOT BETWEEN 1 AND 256
     OR verified_projection_head_digest IS NULL
     OR verified_projection_head_digest !~ '^[0-9a-f]{64}$'
     OR verified_at IS NULL
     OR verified_at > clock_timestamp()
     OR verified_at < clock_timestamp() - interval '30 seconds'
     OR requested_valid_until IS NULL
     OR requested_valid_until <= clock_timestamp()
     OR requested_valid_until > clock_timestamp() + interval '45 seconds' THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_RENEWAL_INVALID'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT current_lease
    FROM public.production_activation_lease
   WHERE singleton
   FOR UPDATE;

  IF current_lease.state <> 'ACTIVE'
     OR current_lease.state_digest <> expected_state_digest
     OR current_lease.release_id <> expected_release_id
     OR current_lease.certificate_id <> expected_certificate_id
     OR current_lease.revocation_registry_id <> registry_id
     OR current_lease.revocation_sequence > registry_sequence
     OR current_lease.projection_id <> verified_projection_id THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_RENEWAL_CAS_REJECTED'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.production_activation_lease
     SET revocation_sequence = registry_sequence,
         revocation_registry_digest = registry_digest,
         projection_head_digest = verified_projection_head_digest,
         watcher_verified_at = verified_at,
         renewed_at = clock_timestamp(),
         valid_until = requested_valid_until
   WHERE singleton;

  RETURN QUERY
  SELECT lease.revision, lease.state_digest, lease.valid_until
    FROM public.production_activation_lease AS lease
   WHERE lease.singleton;
END
$renew_activation$;

CREATE OR REPLACE FUNCTION public.agenttrust_transition_production_activation(
  expected_state_digest char(64),
  next_state_digest char(64),
  next_state text,
  next_release_id text,
  next_certificate_id text,
  registry_id text,
  registry_sequence bigint,
  registry_digest char(64),
  verified_projection_id text,
  verified_projection_head_digest char(64),
  verified_at timestamptz,
  requested_valid_until timestamptz,
  signed_transition_receipt_digest char(64)
)
RETURNS TABLE (
  transitioned_revision bigint,
  transitioned_state text,
  transitioned_state_digest char(64),
  transitioned_valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $transition_activation$
DECLARE
  current_lease public.production_activation_lease%ROWTYPE;
  next_revision bigint;
BEGIN
  IF expected_state_digest IS NULL
     OR expected_state_digest !~ '^[0-9a-f]{64}$'
     OR next_state_digest IS NULL
     OR next_state_digest !~ '^[0-9a-f]{64}$'
     OR next_state_digest = expected_state_digest
     OR next_state IS NULL
     OR next_state NOT IN ('ACTIVE', 'FENCED', 'REVOKED')
     OR next_release_id IS NULL
     OR next_release_id !~ '^git:(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$'
     OR signed_transition_receipt_digest IS NULL
     OR signed_transition_receipt_digest !~ '^[0-9a-f]{64}$'
     OR verified_at IS NULL
     OR verified_at > clock_timestamp()
     OR verified_at < clock_timestamp() - interval '30 seconds' THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_TRANSITION_INVALID'
      USING ERRCODE = '22023';
  END IF;
  IF next_state = 'ACTIVE' AND (
       next_certificate_id IS NULL
       OR next_certificate_id !~ '^pc-[0-9a-f]{24}$'
       OR registry_id IS NULL
       OR length(registry_id) NOT BETWEEN 1 AND 256
       OR registry_sequence IS NULL
       OR registry_sequence <= 0
       OR registry_digest IS NULL
       OR registry_digest !~ '^[0-9a-f]{64}$'
       OR verified_projection_id IS NULL
       OR length(verified_projection_id) NOT BETWEEN 1 AND 256
       OR verified_projection_head_digest IS NULL
       OR verified_projection_head_digest !~ '^[0-9a-f]{64}$'
       OR requested_valid_until IS NULL
       OR requested_valid_until <= clock_timestamp()
       OR requested_valid_until > clock_timestamp() + interval '45 seconds'
     ) THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_TRANSITION_INVALID'
      USING ERRCODE = '22023';
  END IF;
  IF requested_valid_until IS NULL
     OR (next_state <> 'ACTIVE' AND requested_valid_until > clock_timestamp()) THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_FENCE_VALIDITY_INVALID'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT current_lease
    FROM public.production_activation_lease
   WHERE singleton
   FOR UPDATE;
  IF current_lease.state_digest <> expected_state_digest
     OR current_lease.state = 'REVOKED'
     OR (next_state = 'ACTIVE' AND current_lease.state <> 'FENCED')
     OR (next_state = 'FENCED' AND current_lease.state <> 'ACTIVE') THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_TRANSITION_CAS_REJECTED'
      USING ERRCODE = '40001';
  END IF;

  next_revision := current_lease.revision + 1;
  UPDATE public.production_activation_lease
     SET revision = next_revision,
         state = next_state,
         release_id = next_release_id,
         certificate_id = next_certificate_id,
         revocation_registry_id = registry_id,
         revocation_sequence = registry_sequence,
         revocation_registry_digest = registry_digest,
         projection_id = verified_projection_id,
         projection_head_digest = verified_projection_head_digest,
         watcher_verified_at = verified_at,
         renewed_at = clock_timestamp(),
         valid_until = requested_valid_until,
         transition_receipt_digest = signed_transition_receipt_digest,
         state_digest = next_state_digest
   WHERE singleton;

  INSERT INTO public.production_activation_history (
    revision,
    previous_state_digest,
    state_digest,
    state,
    release_id,
    certificate_id,
    revocation_registry_id,
    revocation_sequence,
    revocation_registry_digest,
    projection_id,
    projection_head_digest,
    transition_receipt_digest
  ) VALUES (
    next_revision,
    expected_state_digest,
    next_state_digest,
    next_state,
    next_release_id,
    next_certificate_id,
    registry_id,
    registry_sequence,
    registry_digest,
    verified_projection_id,
    verified_projection_head_digest,
    signed_transition_receipt_digest
  )
  ON CONFLICT (revision) DO NOTHING;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PRODUCTION_ACTIVATION_HISTORY_CONFLICT'
      USING ERRCODE = '40001';
  END IF;

  RETURN QUERY
  SELECT lease.revision, lease.state, lease.state_digest, lease.valid_until
    FROM public.production_activation_lease AS lease
   WHERE lease.singleton;
END
$transition_activation$;

REVOKE ALL ON public.production_activation_lease FROM PUBLIC;
REVOKE ALL ON public.production_activation_history FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_enforce_production_activation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_renew_production_activation(
  char(64), text, text, text, bigint, char(64), text, char(64), timestamptz, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_transition_production_activation(
  char(64), char(64), text, text, text, text, bigint, char(64), text, char(64),
  timestamptz, timestamptz, char(64)
) FROM PUBLIC;

DO $install_activation_guards$
DECLARE
  guarded_table record;
BEGIN
  FOR guarded_table IN
    SELECT tables.table_schema, tables.table_name
      FROM information_schema.tables AS tables
     WHERE tables.table_schema = 'public'
       AND tables.table_type = 'BASE TABLE'
       AND tables.table_name NOT IN (
         'agenttrust_schema_migrations',
         'production_activation_lease',
         'production_activation_history'
       )
     ORDER BY tables.table_name
  LOOP
    IF NOT EXISTS (
      SELECT 1
        FROM pg_trigger AS trigger
        JOIN pg_class AS relation ON relation.oid = trigger.tgrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = guarded_table.table_schema
         AND relation.relname = guarded_table.table_name
         AND trigger.tgname = 'agenttrust_production_activation_guard'
         AND NOT trigger.tgisinternal
    ) THEN
      EXECUTE format(
        'CREATE TRIGGER agenttrust_production_activation_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %I.%I FOR EACH STATEMENT EXECUTE FUNCTION public.agenttrust_enforce_production_activation()',
        guarded_table.table_schema,
        guarded_table.table_name
      );
    END IF;
  END LOOP;
END
$install_activation_guards$;
