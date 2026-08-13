BEGIN;
CREATE TABLE IF NOT EXISTS medical_review_cases (
  tenant_id uuid NOT NULL, review_id uuid NOT NULL, patient_ref_hash char(64) NOT NULL,
  requester_subject text NOT NULL, care_relationship_digest char(64) NOT NULL, recommendation_digest char(64) NOT NULL,
  risk_level text NOT NULL, reviewer_subject text, decision text CHECK (decision IN ('APPROVED','REJECTED','ESCALATED')),
  created_at timestamptz NOT NULL DEFAULT now(), decided_at timestamptz, PRIMARY KEY (tenant_id, review_id)
);
COMMIT;
