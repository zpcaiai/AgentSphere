BEGIN;
CREATE TABLE IF NOT EXISTS mcp_servers (
  tenant_id uuid NOT NULL, server_id text NOT NULL, status text NOT NULL CHECK (status IN ('PENDING','APPROVED','FROZEN','REVOKED','QUARANTINED')),
  manifest jsonb NOT NULL, manifest_hash char(64) NOT NULL, implementation_digest text NOT NULL,
  approved_at timestamptz, revoked_at timestamptz, PRIMARY KEY (tenant_id, server_id)
);
CREATE TABLE IF NOT EXISTS mcp_tool_snapshots (
  tenant_id uuid NOT NULL, server_id text NOT NULL, tool_name text NOT NULL, snapshot_hash char(64) NOT NULL,
  input_schema jsonb NOT NULL, output_schema jsonb NOT NULL, declared_effect text NOT NULL, risk_level text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, server_id, tool_name, snapshot_hash),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers(tenant_id, server_id)
);
CREATE TABLE IF NOT EXISTS mcp_call_evidence (
  call_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, server_id text NOT NULL, tool_name text NOT NULL,
  action_hash char(64) NOT NULL, snapshot_hash char(64) NOT NULL, result_hash char(64), outcome text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
