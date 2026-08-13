BEGIN;
CREATE TABLE IF NOT EXISTS data_labels (
  tenant_id uuid NOT NULL, object_ref text NOT NULL, object_version text NOT NULL, label jsonb NOT NULL,
  label_hash char(64) NOT NULL, classification text NOT NULL, confidence text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, object_ref, object_version)
);
CREATE TABLE IF NOT EXISTS cross_domain_grants (
  tenant_id uuid NOT NULL, grant_id uuid NOT NULL, source_zone text NOT NULL, target_zone text NOT NULL,
  jurisdiction text NOT NULL, object_hash char(64) NOT NULL, approval_id uuid NOT NULL, expires_at timestamptz NOT NULL,
  consumed_at timestamptz, PRIMARY KEY (tenant_id, grant_id)
);
CREATE TABLE IF NOT EXISTS retention_actions (
  action_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, object_ref text NOT NULL, policy_version text NOT NULL,
  due_at timestamptz NOT NULL, action text NOT NULL CHECK (action IN ('DELETE','ARCHIVE','LEGAL_HOLD')),
  completed_at timestamptz, evidence_ref text
);
CREATE TABLE IF NOT EXISTS data_policy_decisions (
  decision_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, request_hash char(64) NOT NULL,
  policy_version text NOT NULL, allowed boolean NOT NULL, reason_codes jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
