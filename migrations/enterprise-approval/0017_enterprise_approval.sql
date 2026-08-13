BEGIN;
CREATE TABLE IF NOT EXISTS approval_cases (
  tenant_id uuid NOT NULL, case_id uuid NOT NULL, task_id uuid NOT NULL, step_id uuid NOT NULL,
  action_hash char(64) NOT NULL, plan_hash char(64) NOT NULL, parameter_hash char(64) NOT NULL,
  resource text NOT NULL, resource_version text NOT NULL, policy_version text NOT NULL, status text NOT NULL,
  request jsonb NOT NULL, policy jsonb NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  post_review_due_at timestamptz, PRIMARY KEY (tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS approval_decisions (
  tenant_id uuid NOT NULL, case_id uuid NOT NULL, approver_subject text NOT NULL, decision text NOT NULL,
  roles jsonb NOT NULL, reason text NOT NULL, strong_auth boolean NOT NULL, decided_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, case_id, approver_subject), FOREIGN KEY (tenant_id, case_id) REFERENCES approval_cases(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS approval_grants (
  tenant_id uuid NOT NULL, grant_id uuid NOT NULL, case_id uuid NOT NULL, grant_hash char(64) NOT NULL,
  signed_grant jsonb NOT NULL, remaining_uses integer NOT NULL CHECK (remaining_uses >= 0), revoked_at timestamptz,
  expires_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, grant_id), FOREIGN KEY (tenant_id, case_id) REFERENCES approval_cases(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS approval_notification_outbox (
  notification_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, case_id uuid NOT NULL, payload jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0, delivered_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
