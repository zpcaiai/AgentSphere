BEGIN;
CREATE TABLE IF NOT EXISTS marketplace_listings (
  tenant_id uuid NOT NULL, listing_id uuid NOT NULL, pack_id text NOT NULL, version text NOT NULL,
  visibility text NOT NULL CHECK (visibility IN ('PRIVATE','TENANT','PUBLIC')),
  publisher_id text NOT NULL, certificate_digest char(64) NOT NULL, status text NOT NULL
    CHECK (status IN ('PUBLISHED','WITHDRAWN','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, listing_id),
  UNIQUE (tenant_id, pack_id, version)
);
CREATE TABLE IF NOT EXISTS pack_installations (
  tenant_id uuid NOT NULL, installation_id uuid NOT NULL, listing_id uuid NOT NULL, environment text NOT NULL,
  approval_id uuid, installed_version text NOT NULL, previous_version text,
  status text NOT NULL CHECK (status IN ('PENDING_APPROVAL','INSTALLED','ACTIVE','ROLLED_BACK','REVOKED')),
  updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, installation_id)
);
COMMIT;
