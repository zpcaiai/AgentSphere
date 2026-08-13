BEGIN;
CREATE TABLE IF NOT EXISTS attack_scenarios (
  scenario_id text NOT NULL, version text NOT NULL, category text NOT NULL, scenario_digest char(64) NOT NULL,
  definition jsonb NOT NULL, dataset_version text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scenario_id, version)
);
CREATE TABLE IF NOT EXISTS security_campaigns (
  tenant_id uuid NOT NULL, campaign_id uuid NOT NULL, environment text NOT NULL,
  policy_digest char(64) NOT NULL, pack_digest char(64) NOT NULL, seed bigint NOT NULL,
  status text NOT NULL CHECK (status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CLEANUP_FAILED')),
  report_digest char(64), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, campaign_id)
);
CREATE TABLE IF NOT EXISTS security_findings (
  tenant_id uuid NOT NULL, finding_id uuid NOT NULL, campaign_id uuid NOT NULL, severity text NOT NULL,
  control_id text NOT NULL, evidence_digest char(64) NOT NULL, remediation_ref text,
  status text NOT NULL CHECK (status IN ('OPEN','ACCEPTED','FIXED','VERIFIED')),
  PRIMARY KEY (tenant_id, finding_id)
);
COMMIT;
