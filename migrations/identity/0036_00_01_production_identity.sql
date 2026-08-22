-- Production Workload Credential Authority. Global FORCE RLS closure runs later.
BEGIN;

ALTER TABLE credential_handles
  ADD COLUMN IF NOT EXISTS handle_sha256 char(64),
  ADD COLUMN IF NOT EXISTS policy_decision_id text,
  ADD COLUMN IF NOT EXISTS tool_id text,
  ADD COLUMN IF NOT EXISTS credential_profile text,
  ADD COLUMN IF NOT EXISTS operation text,
  ADD COLUMN IF NOT EXISTS resource text,
  ADD COLUMN IF NOT EXISTS target_profile text,
  ADD COLUMN IF NOT EXISTS claims jsonb,
  ADD COLUMN IF NOT EXISTS claims_digest char(64),
  ADD COLUMN IF NOT EXISTS binding_receipt_digest char(64),
  ADD COLUMN IF NOT EXISTS issuer text,
  ADD COLUMN IF NOT EXISTS key_id text,
  ADD COLUMN IF NOT EXISTS revoked_reason text;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM credential_handles
     WHERE handle_sha256 IS NULL OR policy_decision_id IS NULL OR tool_id IS NULL
        OR credential_profile IS NULL OR operation IS NULL OR resource IS NULL
        OR target_profile IS NULL OR claims IS NULL OR claims_digest IS NULL
        OR binding_receipt_digest IS NULL OR issuer IS NULL OR key_id IS NULL
  ) THEN
    RAISE EXCEPTION 'IDENTITY_PRODUCTION_CREDENTIAL_BACKFILL_REQUIRED';
  END IF;
END
$$;

ALTER TABLE credential_handles
  ALTER COLUMN handle_sha256 SET NOT NULL,
  ALTER COLUMN policy_decision_id SET NOT NULL,
  ALTER COLUMN tool_id SET NOT NULL,
  ALTER COLUMN credential_profile SET NOT NULL,
  ALTER COLUMN operation SET NOT NULL,
  ALTER COLUMN resource SET NOT NULL,
  ALTER COLUMN target_profile SET NOT NULL,
  ALTER COLUMN claims SET NOT NULL,
  ALTER COLUMN claims_digest SET NOT NULL,
  ALTER COLUMN binding_receipt_digest SET NOT NULL,
  ALTER COLUMN issuer SET NOT NULL,
  ALTER COLUMN key_id SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_handle_sha256_check') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_handle_sha256_check
      CHECK (handle_sha256 ~ '^[a-f0-9]{64}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_claims_digest_check') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_claims_digest_check
      CHECK (claims_digest ~ '^[a-f0-9]{64}$' AND binding_receipt_digest ~ '^[a-f0-9]{64}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_action_hash_check') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_action_hash_check
      CHECK (action_hash ~ '^[a-f0-9]{64}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_revocation_reason_check') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_revocation_reason_check
      CHECK ((revoked_at IS NULL AND revoked_reason IS NULL) OR
             (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL));
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS credential_handles_tenant_handle_sha256
  ON credential_handles(tenant_id,handle_sha256);
CREATE INDEX IF NOT EXISTS credential_handles_live_signing_key
  ON credential_handles(tenant_id,issuer,key_id,expires_at)
  WHERE revoked_at IS NULL AND remaining_uses > 0;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agent_principals_tenant_agent_unique') THEN
    ALTER TABLE agent_principals ADD CONSTRAINT agent_principals_tenant_agent_unique
      UNIQUE (tenant_id,agent_instance_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_tenant_agent_fk') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_tenant_agent_fk
      FOREIGN KEY (tenant_id,agent_instance_id)
      REFERENCES agent_principals(tenant_id,agent_instance_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_profile_fk') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_profile_fk
      FOREIGN KEY (tenant_id,credential_profile)
      REFERENCES credential_profiles(tenant_id,profile_id);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS identity_tenant_epochs (
  tenant_id uuid PRIMARY KEY,
  revocation_epoch bigint NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_task_lifecycle (
  tenant_id uuid NOT NULL,
  task_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('ACTIVE','PAUSED','CANCELED','KILLED')),
  reason_code text,
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,task_id),
  CHECK ((state IN ('ACTIVE','PAUSED') AND reason_code IS NULL) OR
         (state IN ('CANCELED','KILLED') AND reason_code IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS identity_credential_signing_keys (
  tenant_id uuid NOT NULL,
  issuer text NOT NULL,
  key_id text NOT NULL,
  algorithm text NOT NULL CHECK (algorithm='Ed25519'),
  public_key bytea NOT NULL CHECK (octet_length(public_key)=32),
  status text NOT NULL CHECK (status IN ('ACTIVE','VERIFY_ONLY','REVOKED')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id,issuer,key_id),
  CHECK ((status <> 'REVOKED' AND revoked_at IS NULL) OR
         (status = 'REVOKED' AND revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_credential_signing_keys_one_active
  ON identity_credential_signing_keys(tenant_id,issuer) WHERE status='ACTIVE';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credential_handles_signing_key_fk') THEN
    ALTER TABLE credential_handles ADD CONSTRAINT credential_handles_signing_key_fk
      FOREIGN KEY (tenant_id,issuer,key_id)
      REFERENCES identity_credential_signing_keys(tenant_id,issuer,key_id);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS identity_credential_idempotency (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (
    length(idempotency_key) BETWEEN 1 AND 128 AND
    idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
  ),
  operation text NOT NULL CHECK (
    operation IN ('ISSUE','CONSUME','REVOKE_CREDENTIAL','REVOKE_TASK','REVOKE_AGENT',
                  'REVOKE_TENANT','PAUSE_TASK','UNFREEZE_TASK','CANCEL_TASK','KILL_TASK')
  ),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  response_ciphertext bytea CHECK (response_ciphertext IS NULL OR octet_length(response_ciphertext) >= 16),
  response_nonce bytea CHECK (response_nonce IS NULL OR octet_length(response_nonce)=12),
  encryption_key_id text,
  response_digest char(64) NOT NULL CHECK (response_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  replay_until timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  PRIMARY KEY (tenant_id,idempotency_key),
  CHECK (replay_until > created_at),
  CHECK ((response_ciphertext IS NOT NULL AND response_nonce IS NOT NULL AND encryption_key_id IS NOT NULL) OR
         (response_ciphertext IS NULL AND response_nonce IS NULL AND encryption_key_id IS NULL))
);
CREATE INDEX IF NOT EXISTS identity_idempotency_live_key
  ON identity_credential_idempotency(tenant_id,encryption_key_id)
  WHERE response_ciphertext IS NOT NULL;
CREATE INDEX IF NOT EXISTS identity_idempotency_replay_retention
  ON identity_credential_idempotency(replay_until)
  WHERE response_ciphertext IS NOT NULL;

CREATE TABLE IF NOT EXISTS identity_credential_events (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type IN (
    'CREDENTIAL_ISSUED','CREDENTIAL_CONSUMED','CREDENTIAL_REVOKED','TASK_PAUSED',
    'TASK_UNFROZEN','TASK_CANCELED','TASK_KILLED','AGENT_REVOKED','TENANT_REVOKED'
  )),
  credential_id uuid,
  task_id uuid,
  agent_instance_id uuid,
  scope_digest char(64) NOT NULL CHECK (scope_digest ~ '^[a-f0-9]{64}$'),
  actor_subject text NOT NULL,
  event_payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,event_id),
  CHECK (jsonb_typeof(event_payload)='object' AND octet_length(event_payload::text) <= 16384),
  CHECK (event_payload::text !~* '"(credential_handle|workload_credential|bearer|token|secret)"[[:space:]]*:')
);

CREATE TABLE IF NOT EXISTS identity_credential_outbox (
  outbox_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL,
  credential_id uuid,
  scope_digest char(64) NOT NULL CHECK (scope_digest ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 4096),
  CHECK (payload::text !~* '"(credential_handle|workload_credential|bearer|token|secret)"[[:space:]]*:'),
  FOREIGN KEY (tenant_id,event_id)
    REFERENCES identity_credential_events(tenant_id,event_id)
);

CREATE INDEX IF NOT EXISTS identity_events_tenant_created
  ON identity_credential_events(tenant_id,created_at,event_id);
CREATE INDEX IF NOT EXISTS identity_outbox_tenant_created
  ON identity_credential_outbox(tenant_id,created_at,outbox_id);

CREATE OR REPLACE FUNCTION reject_identity_immutable_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'IDENTITY_IMMUTABLE_RECORD';
END $$;

DROP TRIGGER IF EXISTS identity_revocations_immutable ON identity_revocations;
CREATE TRIGGER identity_revocations_immutable BEFORE UPDATE OR DELETE ON identity_revocations
  FOR EACH ROW EXECUTE FUNCTION reject_identity_immutable_change();
CREATE OR REPLACE FUNCTION enforce_identity_idempotency_retention() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.response_ciphertext IS NULL OR NEW.response_nonce IS NULL OR NEW.encryption_key_id IS NULL THEN
      RAISE EXCEPTION 'IDENTITY_IDEMPOTENCY_RESPONSE_REQUIRED';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'IDENTITY_IDEMPOTENCY_TOMBSTONE_IMMUTABLE';
  END IF;
  IF now() < OLD.replay_until OR
     NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
     NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
     NEW.operation IS DISTINCT FROM OLD.operation OR
     NEW.request_digest IS DISTINCT FROM OLD.request_digest OR
     NEW.response_digest IS DISTINCT FROM OLD.response_digest OR
     NEW.created_at IS DISTINCT FROM OLD.created_at OR
     NEW.replay_until IS DISTINCT FROM OLD.replay_until OR
     NEW.response_ciphertext IS NOT NULL OR NEW.response_nonce IS NOT NULL OR
     NEW.encryption_key_id IS NOT NULL THEN
    RAISE EXCEPTION 'IDENTITY_IDEMPOTENCY_IMMUTABLE';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_credential_idempotency_immutable ON identity_credential_idempotency;
CREATE TRIGGER identity_credential_idempotency_immutable BEFORE INSERT OR UPDATE OR DELETE ON identity_credential_idempotency
  FOR EACH ROW EXECUTE FUNCTION enforce_identity_idempotency_retention();
DROP TRIGGER IF EXISTS identity_credential_events_immutable ON identity_credential_events;
CREATE TRIGGER identity_credential_events_immutable BEFORE UPDATE OR DELETE ON identity_credential_events
  FOR EACH ROW EXECUTE FUNCTION reject_identity_immutable_change();
DROP TRIGGER IF EXISTS identity_credential_outbox_immutable ON identity_credential_outbox;
CREATE TRIGGER identity_credential_outbox_immutable BEFORE UPDATE OR DELETE ON identity_credential_outbox
  FOR EACH ROW EXECUTE FUNCTION reject_identity_immutable_change();

CREATE OR REPLACE FUNCTION enforce_identity_credential_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.credential_id IS DISTINCT FROM OLD.credential_id OR
     NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
     NEW.agent_instance_id IS DISTINCT FROM OLD.agent_instance_id OR
     NEW.task_id IS DISTINCT FROM OLD.task_id OR NEW.step_id IS DISTINCT FROM OLD.step_id OR
     NEW.action_hash IS DISTINCT FROM OLD.action_hash OR NEW.audience IS DISTINCT FROM OLD.audience OR
     NEW.scope_hash IS DISTINCT FROM OLD.scope_hash OR NEW.max_uses IS DISTINCT FROM OLD.max_uses OR
     NEW.revocation_epoch IS DISTINCT FROM OLD.revocation_epoch OR
     NEW.issued_at IS DISTINCT FROM OLD.issued_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
     NEW.handle_sha256 IS DISTINCT FROM OLD.handle_sha256 OR NEW.claims IS DISTINCT FROM OLD.claims OR
     NEW.claims_digest IS DISTINCT FROM OLD.claims_digest OR
     NEW.binding_receipt_digest IS DISTINCT FROM OLD.binding_receipt_digest OR
     NEW.issuer IS DISTINCT FROM OLD.issuer OR NEW.key_id IS DISTINCT FROM OLD.key_id OR
     NEW.policy_decision_id IS DISTINCT FROM OLD.policy_decision_id OR
     NEW.tool_id IS DISTINCT FROM OLD.tool_id OR NEW.credential_profile IS DISTINCT FROM OLD.credential_profile OR
     NEW.operation IS DISTINCT FROM OLD.operation OR NEW.resource IS DISTINCT FROM OLD.resource OR
     NEW.target_profile IS DISTINCT FROM OLD.target_profile THEN
    RAISE EXCEPTION 'IDENTITY_CREDENTIAL_IMMUTABLE';
  END IF;
  IF NEW.remaining_uses > OLD.remaining_uses OR
     OLD.remaining_uses - NEW.remaining_uses > 1 THEN
    RAISE EXCEPTION 'IDENTITY_CREDENTIAL_USAGE_INVALID';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND
     (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason) THEN
    RAISE EXCEPTION 'IDENTITY_CREDENTIAL_REVOCATION_TERMINAL';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS credential_handles_production_mutation ON credential_handles;
CREATE TRIGGER credential_handles_production_mutation BEFORE UPDATE ON credential_handles
  FOR EACH ROW EXECUTE FUNCTION enforce_identity_credential_mutation();

CREATE OR REPLACE FUNCTION enforce_identity_task_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.task_id IS DISTINCT FROM OLD.task_id THEN
    RAISE EXCEPTION 'IDENTITY_TASK_IDENTITY_IMMUTABLE';
  END IF;
  IF OLD.state IN ('CANCELED','KILLED') AND NEW.state IS DISTINCT FROM OLD.state THEN
    RAISE EXCEPTION 'IDENTITY_TASK_TERMINAL';
  END IF;
  IF OLD.state='ACTIVE' AND NEW.state NOT IN ('ACTIVE','PAUSED','CANCELED','KILLED') THEN
    RAISE EXCEPTION 'IDENTITY_TASK_TRANSITION_INVALID';
  END IF;
  IF OLD.state='PAUSED' AND NEW.state NOT IN ('PAUSED','ACTIVE','CANCELED','KILLED') THEN
    RAISE EXCEPTION 'IDENTITY_TASK_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_task_lifecycle_guard ON identity_task_lifecycle;
CREATE TRIGGER identity_task_lifecycle_guard BEFORE UPDATE ON identity_task_lifecycle
  FOR EACH ROW EXECUTE FUNCTION enforce_identity_task_lifecycle();

CREATE OR REPLACE FUNCTION enforce_identity_signing_key_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'IDENTITY_SIGNING_KEY_IMMUTABLE';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.issuer IS DISTINCT FROM OLD.issuer OR
     NEW.key_id IS DISTINCT FROM OLD.key_id OR NEW.algorithm IS DISTINCT FROM OLD.algorithm OR
     NEW.public_key IS DISTINCT FROM OLD.public_key OR NEW.created_by IS DISTINCT FROM OLD.created_by OR
     NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'IDENTITY_SIGNING_KEY_IMMUTABLE';
  END IF;
  IF OLD.status='REVOKED' AND NEW.status <> 'REVOKED' THEN
    RAISE EXCEPTION 'IDENTITY_SIGNING_KEY_REVOCATION_TERMINAL';
  END IF;
  IF NEW.status='REVOKED' AND OLD.status <> 'REVOKED' AND EXISTS (
    SELECT 1 FROM credential_handles
     WHERE tenant_id=OLD.tenant_id AND issuer=OLD.issuer AND key_id=OLD.key_id
       AND revoked_at IS NULL AND remaining_uses > 0 AND expires_at > now()
  ) THEN
    RAISE EXCEPTION 'IDENTITY_SIGNING_KEY_HAS_LIVE_CREDENTIALS';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_signing_keys_guard ON identity_credential_signing_keys;
CREATE TRIGGER identity_signing_keys_guard BEFORE UPDATE OR DELETE ON identity_credential_signing_keys
  FOR EACH ROW EXECUTE FUNCTION enforce_identity_signing_key_lifecycle();

COMMIT;
