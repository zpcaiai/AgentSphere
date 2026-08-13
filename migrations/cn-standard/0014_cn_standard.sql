BEGIN;
CREATE TABLE IF NOT EXISTS cn_standard_bundles (
  standard_id text NOT NULL, standard_version text NOT NULL, source_uri text NOT NULL, published_at timestamptz NOT NULL,
  license text NOT NULL, schema_hash char(64) NOT NULL, bundle_digest char(64) NOT NULL, bundle jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('IMPORTED','ACTIVE','RETIRED')),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (standard_id, standard_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS cn_standard_one_active_idx ON cn_standard_bundles (standard_id) WHERE status = 'ACTIVE';
COMMIT;
