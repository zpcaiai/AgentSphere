BEGIN;
CREATE TABLE IF NOT EXISTS sensitive_interaction_handoffs (
  tenant_id uuid NOT NULL, handoff_id uuid NOT NULL, conversation_hash char(64) NOT NULL,
  region_code text NOT NULL, risk_level text NOT NULL, consent_digest char(64),
  destination_type text NOT NULL CHECK (destination_type IN ('HUMAN_SUPPORT','EMERGENCY_SERVICE','TRUSTED_CONTACT')),
  source_directory_version text NOT NULL, status text NOT NULL CHECK (status IN ('REQUESTED','ACCEPTED','FAILED','CLOSED')),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, handoff_id)
);
COMMIT;
