BEGIN;
CREATE TABLE IF NOT EXISTS trust_bundles (
  bundle_version text PRIMARY KEY,
  issuer text NOT NULL,
  jwks jsonb NOT NULL,
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL CHECK (valid_until > valid_from),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_principals (
  agent_instance_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  owner_subject text NOT NULL,
  organization_id text NOT NULL,
  trust_level text NOT NULL CHECK (trust_level IN ('development','verified','attested')),
  revocation_epoch bigint NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_principals_tenant_idx ON agent_principals(tenant_id, owner_subject);
CREATE TABLE IF NOT EXISTS credential_handles (
  credential_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  agent_instance_id uuid NOT NULL REFERENCES agent_principals(agent_instance_id),
  task_id uuid NOT NULL,
  step_id uuid NOT NULL,
  action_hash char(64) NOT NULL,
  audience text NOT NULL,
  scope_hash char(64) NOT NULL,
  max_uses integer NOT NULL CHECK (max_uses > 0),
  remaining_uses integer NOT NULL CHECK (remaining_uses >= 0),
  revocation_epoch bigint NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > issued_at),
  CHECK (remaining_uses <= max_uses)
);
CREATE INDEX IF NOT EXISTS credential_task_idx ON credential_handles(tenant_id, task_id, revoked_at);
CREATE TABLE IF NOT EXISTS identity_revocations (
  revocation_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('credential','task','agent','tenant')),
  subject_id text NOT NULL,
  reason_code text NOT NULL,
  revoked_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, subject_kind, subject_id)
);
COMMIT;

