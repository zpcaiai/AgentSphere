BEGIN;
CREATE TABLE IF NOT EXISTS agent_assets (
  tenant_id uuid NOT NULL, agent_id text NOT NULL, owner_subject text NOT NULL, sponsor_subject text NOT NULL,
  lifecycle text NOT NULL CHECK (lifecycle IN ('DRAFT','ACTIVE','SUSPENDED','RETIRED','REVOKED')),
  environment text NOT NULL, bom_digest char(64) NOT NULL, registered_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, agent_id)
);
CREATE TABLE IF NOT EXISTS agent_discovery_facts (
  tenant_id uuid NOT NULL, fact_id uuid NOT NULL, observed_agent_ref text NOT NULL, collector_id text NOT NULL,
  observation_digest char(64) NOT NULL, observed_at timestamptz NOT NULL, reconciled_agent_id text,
  PRIMARY KEY (tenant_id, fact_id)
);
CREATE TABLE IF NOT EXISTS agent_posture_findings (
  tenant_id uuid NOT NULL, finding_id uuid NOT NULL, agent_id text NOT NULL, posture text NOT NULL,
  severity text NOT NULL, evidence_digest char(64) NOT NULL, open boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, finding_id)
);
COMMIT;
