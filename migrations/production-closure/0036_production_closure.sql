BEGIN;
CREATE TABLE IF NOT EXISTS production_closure_reports (
  release_id text NOT NULL, scope_digest char(64) NOT NULL, report_digest char(64) NOT NULL,
  eligible boolean NOT NULL, blockers jsonb NOT NULL, gate_digests jsonb NOT NULL,
  evaluated_at timestamptz NOT NULL, PRIMARY KEY (release_id, scope_digest)
);
CREATE TABLE IF NOT EXISTS production_closure_certificates (
  certificate_id text PRIMARY KEY, release_id text NOT NULL, scope_digest char(64) NOT NULL,
  report_digest char(64) NOT NULL, key_id text NOT NULL, signature bytea NOT NULL,
  issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz, revocation_reason text,
  CHECK (revoked_at IS NULL OR revocation_reason IS NOT NULL)
);
COMMIT;
