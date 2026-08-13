BEGIN;
ALTER TABLE enterprise_admin_actions ADD COLUMN IF NOT EXISTS reason text;
UPDATE enterprise_admin_actions SET reason = 'legacy-migration' WHERE reason IS NULL;
ALTER TABLE enterprise_admin_actions ALTER COLUMN reason SET NOT NULL;

CREATE TABLE IF NOT EXISTS enterprise_api_keys (
  tenant_id uuid NOT NULL, api_key_id uuid NOT NULL, project_id text,
  key_hash char(64) NOT NULL, scopes jsonb NOT NULL, created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  revoked_at timestamptz, revocation_reason text,
  PRIMARY KEY (tenant_id, api_key_id),
  CHECK (expires_at > created_at),
  CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);
CREATE TABLE IF NOT EXISTS enterprise_licenses (
  tenant_id uuid NOT NULL, license_id uuid NOT NULL, plan_code text NOT NULL,
  entitlements jsonb NOT NULL, starts_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  license_digest char(64) NOT NULL, key_id text NOT NULL, signature text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','EXPIRED','REVOKED')),
  PRIMARY KEY (tenant_id, license_id), CHECK (expires_at > starts_at)
);
CREATE TABLE IF NOT EXISTS enterprise_integrations (
  tenant_id uuid NOT NULL, integration_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('IAM','NOTIFICATION','TICKETING','SIEM','WEBHOOK')),
  endpoint text NOT NULL CHECK (endpoint LIKE 'https://%'), secret_ref text NOT NULL,
  configuration_digest char(64) NOT NULL, active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, integration_id)
);
CREATE TABLE IF NOT EXISTS enterprise_quota_usage (
  tenant_id uuid NOT NULL, quota_key text NOT NULL, window_started_at timestamptz NOT NULL,
  used bigint NOT NULL CHECK (used >= 0), limit_value bigint NOT NULL CHECK (limit_value > 0),
  PRIMARY KEY (tenant_id, quota_key, window_started_at)
);
CREATE TABLE IF NOT EXISTS enterprise_cost_usage (
  tenant_id uuid NOT NULL, usage_id uuid NOT NULL, project_id text NOT NULL,
  meter text NOT NULL, quantity bigint NOT NULL CHECK (quantity > 0),
  unit_cost_micros bigint NOT NULL CHECK (unit_cost_micros >= 0),
  total_cost_micros bigint NOT NULL CHECK (total_cost_micros >= 0),
  source_digest char(64) NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, usage_id),
  CHECK (total_cost_micros = quantity * unit_cost_micros)
);
CREATE TABLE IF NOT EXISTS enterprise_request_idempotency (
  tenant_id uuid NOT NULL, idempotency_key text NOT NULL,
  request_digest char(64) NOT NULL,
  state text NOT NULL CHECK (state IN ('IN_PROGRESS','COMPLETED')),
  response_status integer,
  response_payload jsonb,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key),
  CHECK (length(idempotency_key) BETWEEN 16 AND 128),
  CHECK ((state = 'COMPLETED') = (response_status IS NOT NULL))
);

ALTER TABLE enterprise_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_admin_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_quota_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_cost_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_request_idempotency ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['enterprise_tenants','enterprise_organizations','enterprise_projects','enterprise_admin_actions','enterprise_api_keys','enterprise_licenses','enterprise_integrations','enterprise_quota_usage','enterprise_cost_usage','enterprise_request_idempotency']
  LOOP
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = table_name AND policyname = 'tenant_isolation') THEN
      EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id::text = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id::text = current_setting(''app.tenant_id'', true))', table_name);
    END IF;
  END LOOP;
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_org_tenant_fk') THEN
    ALTER TABLE enterprise_organizations ADD CONSTRAINT enterprise_org_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_project_org_fk') THEN
    ALTER TABLE enterprise_projects ADD CONSTRAINT enterprise_project_org_fk FOREIGN KEY (tenant_id, organization_id) REFERENCES enterprise_organizations(tenant_id, organization_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_admin_tenant_fk') THEN
    ALTER TABLE enterprise_admin_actions ADD CONSTRAINT enterprise_admin_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_api_key_tenant_fk') THEN
    ALTER TABLE enterprise_api_keys ADD CONSTRAINT enterprise_api_key_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_api_key_project_fk') THEN
    ALTER TABLE enterprise_api_keys ADD CONSTRAINT enterprise_api_key_project_fk FOREIGN KEY (tenant_id, project_id) REFERENCES enterprise_projects(tenant_id, project_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_license_tenant_fk') THEN
    ALTER TABLE enterprise_licenses ADD CONSTRAINT enterprise_license_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_integration_tenant_fk') THEN
    ALTER TABLE enterprise_integrations ADD CONSTRAINT enterprise_integration_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_quota_tenant_fk') THEN
    ALTER TABLE enterprise_quota_usage ADD CONSTRAINT enterprise_quota_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_cost_tenant_fk') THEN
    ALTER TABLE enterprise_cost_usage ADD CONSTRAINT enterprise_cost_tenant_fk FOREIGN KEY (tenant_id) REFERENCES enterprise_tenants(tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='enterprise_cost_project_fk') THEN
    ALTER TABLE enterprise_cost_usage ADD CONSTRAINT enterprise_cost_project_fk FOREIGN KEY (tenant_id, project_id) REFERENCES enterprise_projects(tenant_id, project_id);
  END IF;
END $$;
COMMIT;
