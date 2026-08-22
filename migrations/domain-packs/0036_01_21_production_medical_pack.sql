BEGIN;
DO $migration$ BEGIN
  IF to_regclass('public.medical_review_cases') IS NOT NULL AND to_regclass('public.medical_review_cases_legacy_0026') IS NULL THEN
    ALTER TABLE public.medical_review_cases RENAME TO medical_review_cases_legacy_0026;
  END IF;
END $migration$;
REVOKE ALL ON TABLE public.medical_review_cases_legacy_0026 FROM PUBLIC;

CREATE TABLE public.medical_care_relationships (
  tenant_id uuid NOT NULL, relationship_id uuid NOT NULL, patient_ref_digest char(64) NOT NULL CHECK (patient_ref_digest ~ '^[0-9a-f]{64}$'),
  practitioner_subject varchar(512) NOT NULL, relationship_type varchar(32) NOT NULL CHECK (relationship_type IN ('TREATING','DELEGATED','CODING','EMERGENCY')),
  purpose_of_use varchar(64) NOT NULL, permitted_data_classes text[] NOT NULL CHECK (cardinality(permitted_data_classes) BETWEEN 1 AND 64),
  jurisdiction varchar(128) NOT NULL, resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version>0),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED','EXPIRED')),
  valid_from timestamptz NOT NULL, valid_until timestamptz NOT NULL CHECK (valid_until>valid_from),
  source_evidence_ref varchar(1024) NOT NULL, source_evidence_digest char(64) NOT NULL CHECK (source_evidence_digest ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id,relationship_id), UNIQUE (tenant_id,patient_ref_digest,practitioner_subject,purpose_of_use)
);
CREATE TABLE public.medical_access_decisions (
  tenant_id uuid NOT NULL, decision_id uuid NOT NULL, execution_id uuid NOT NULL, relationship_id uuid NOT NULL,
  patient_ref_digest char(64) NOT NULL CHECK (patient_ref_digest ~ '^[0-9a-f]{64}$'), requester_subject varchar(512) NOT NULL,
  purpose_of_use varchar(64) NOT NULL, requested_fields text[] NOT NULL CHECK (cardinality(requested_fields) BETWEEN 1 AND 256),
  released_fields text[] NOT NULL, redacted_field_count integer NOT NULL CHECK (redacted_field_count>=0),
  data_policy_decision_digest char(64) NOT NULL CHECK (data_policy_decision_digest ~ '^[0-9a-f]{64}$'),
  residency_decision_digest char(64) NOT NULL CHECK (residency_decision_digest ~ '^[0-9a-f]{64}$'),
  minimum_necessary boolean NOT NULL, break_glass boolean NOT NULL, break_glass_approval_id uuid,
  conclusion varchar(16) NOT NULL CHECK (conclusion IN ('ALLOW','DENY','NEEDS_HUMAN')), decided_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,decision_id), UNIQUE (tenant_id,execution_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  FOREIGN KEY (tenant_id,relationship_id) REFERENCES public.medical_care_relationships(tenant_id,relationship_id),
  CHECK (conclusion<>'ALLOW' OR minimum_necessary), CHECK ((break_glass AND break_glass_approval_id IS NOT NULL) OR NOT break_glass)
);
CREATE TABLE public.medical_clinical_evidence (
  tenant_id uuid NOT NULL, evidence_id uuid NOT NULL, execution_id uuid NOT NULL,
  source_snapshot_digest char(64) NOT NULL CHECK (source_snapshot_digest ~ '^[0-9a-f]{64}$'),
  source_time timestamptz NOT NULL, knowledge_version varchar(256) NOT NULL, knowledge_digest char(64) NOT NULL CHECK (knowledge_digest ~ '^[0-9a-f]{64}$'),
  model_manifest_digest char(64) NOT NULL CHECK (model_manifest_digest ~ '^[0-9a-f]{64}$'), prompt_digest char(64) NOT NULL CHECK (prompt_digest ~ '^[0-9a-f]{64}$'),
  output_artifact_ref varchar(1024) NOT NULL, output_digest char(64) NOT NULL CHECK (output_digest ~ '^[0-9a-f]{64}$'),
  uncertainty_basis_digest char(64) NOT NULL CHECK (uncertainty_basis_digest ~ '^[0-9a-f]{64}$'), private_deployment boolean NOT NULL CHECK (private_deployment),
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,evidence_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id)
);
CREATE TABLE public.medical_human_reviews (
  tenant_id uuid NOT NULL, review_id uuid NOT NULL, execution_id uuid NOT NULL, evidence_id uuid NOT NULL,
  output_digest char(64) NOT NULL CHECK (output_digest ~ '^[0-9a-f]{64}$'), risk_level varchar(16) NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  reviewer_subject varchar(512) NOT NULL, reviewer_role varchar(128) NOT NULL,
  reviewer_qualification_digest char(64) NOT NULL CHECK (reviewer_qualification_digest ~ '^[0-9a-f]{64}$'),
  decision varchar(16) NOT NULL CHECK (decision IN ('APPROVED','REJECTED','ESCALATED')),
  modification_digest char(64), principal_assertion_digest char(64) NOT NULL CHECK (principal_assertion_digest ~ '^[0-9a-f]{64}$'),
  evidence_ref varchar(1024) NOT NULL, evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'), reviewed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,review_id), UNIQUE (tenant_id,execution_id,reviewer_subject),
  FOREIGN KEY (tenant_id,evidence_id) REFERENCES public.medical_clinical_evidence(tenant_id,evidence_id),
  CHECK (risk_level NOT IN ('HIGH','CRITICAL') OR reviewer_role IN ('CLINICIAN','PHYSICIAN','PHARMACIST','LICENSED_REVIEWER'))
);
CREATE TABLE public.medical_evaluation_findings (
  tenant_id uuid NOT NULL, finding_id uuid NOT NULL, execution_id uuid NOT NULL,
  patient_match boolean NOT NULL, evidence_complete boolean NOT NULL, factual_consistency boolean NOT NULL,
  sensitive_leakage_count integer NOT NULL CHECK (sensitive_leakage_count>=0), omission_risk_count integer NOT NULL CHECK (omission_risk_count>=0),
  human_review_required boolean NOT NULL, human_review_complete boolean NOT NULL,
  conclusion varchar(16) NOT NULL CHECK (conclusion IN ('PASS','FAIL','NEEDS_HUMAN')),
  evaluator_digest char(64) NOT NULL CHECK (evaluator_digest ~ '^[0-9a-f]{64}$'), evaluated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,finding_id), UNIQUE (tenant_id,execution_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  CHECK (conclusion<>'PASS' OR (patient_match AND evidence_complete AND factual_consistency AND sensitive_leakage_count=0 AND (NOT human_review_required OR human_review_complete)))
);

DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['medical_care_relationships','medical_access_decisions','medical_clinical_evidence','medical_human_reviews','medical_evaluation_findings'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('CREATE POLICY medical_tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',table_name); EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',table_name);
  END LOOP;
END $rls$;
CREATE TRIGGER medical_access_immutable BEFORE UPDATE OR DELETE ON public.medical_access_decisions FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE TRIGGER medical_evidence_immutable BEFORE UPDATE OR DELETE ON public.medical_clinical_evidence FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE TRIGGER medical_review_immutable BEFORE UPDATE OR DELETE ON public.medical_human_reviews FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE TRIGGER medical_finding_immutable BEFORE UPDATE OR DELETE ON public.medical_evaluation_findings FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE INDEX medical_relationship_lookup_idx ON public.medical_care_relationships(tenant_id,patient_ref_digest,practitioner_subject,status,valid_until);
CREATE INDEX medical_review_execution_idx ON public.medical_human_reviews(tenant_id,execution_id,decision);
COMMIT;
