BEGIN;
CREATE TABLE IF NOT EXISTS enterprise_tenants (
  tenant_id uuid PRIMARY KEY, display_name text NOT NULL, owner_subject text NOT NULL, data_region text NOT NULL,
  active boolean NOT NULL DEFAULT true, quota jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS enterprise_organizations (
  tenant_id uuid NOT NULL, organization_id text NOT NULL, display_name text NOT NULL, sponsor_subject text NOT NULL,
  PRIMARY KEY (tenant_id, organization_id)
);
CREATE TABLE IF NOT EXISTS enterprise_projects (
  tenant_id uuid NOT NULL, project_id text NOT NULL, organization_id text NOT NULL, owner_subject text NOT NULL,
  environments jsonb NOT NULL, PRIMARY KEY (tenant_id, project_id)
);
CREATE TABLE IF NOT EXISTS enterprise_admin_actions (
  tenant_id uuid NOT NULL, action_id uuid NOT NULL, requester_subject text NOT NULL, operation text NOT NULL,
  resource text NOT NULL, action_digest char(64) NOT NULL, approvals jsonb NOT NULL,
  result_digest char(64), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, action_id)
);
COMMIT;
