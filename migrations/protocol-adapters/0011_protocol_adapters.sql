BEGIN;
CREATE TABLE IF NOT EXISTS protocol_adapter_versions (
  adapter_id text NOT NULL, adapter_version text NOT NULL, protocol text NOT NULL, manifest jsonb NOT NULL,
  manifest_hash char(64) NOT NULL, publisher_key_id text NOT NULL, status text NOT NULL CHECK (status IN ('PENDING','APPROVED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (adapter_id, adapter_version)
);
CREATE TABLE IF NOT EXISTS protocol_mapping_reports (
  report_id uuid PRIMARY KEY, adapter_id text NOT NULL, adapter_version text NOT NULL,
  external_version text NOT NULL, internal_version text NOT NULL, report jsonb NOT NULL,
  blocking_loss_count integer NOT NULL CHECK (blocking_loss_count >= 0), created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (adapter_id, adapter_version) REFERENCES protocol_adapter_versions(adapter_id, adapter_version)
);
COMMIT;
