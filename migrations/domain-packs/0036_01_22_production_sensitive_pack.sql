BEGIN;
DO $migration$ BEGIN
  IF to_regclass('public.sensitive_interaction_handoffs') IS NOT NULL AND to_regclass('public.sensitive_interaction_handoffs_legacy_0027') IS NULL THEN
    ALTER TABLE public.sensitive_interaction_handoffs RENAME TO sensitive_interaction_handoffs_legacy_0027;
  END IF;
END $migration$;
REVOKE ALL ON TABLE public.sensitive_interaction_handoffs_legacy_0027 FROM PUBLIC;

CREATE TABLE IF NOT EXISTS public.sensitive_consent_records (
  tenant_id uuid NOT NULL, consent_id uuid NOT NULL, subject_ref_digest char(64) NOT NULL CHECK (subject_ref_digest ~ '^[0-9a-f]{64}$'),
  purpose varchar(128) NOT NULL, data_classes text[] NOT NULL CHECK (cardinality(data_classes) BETWEEN 1 AND 32),
  share_audiences text[] NOT NULL, memory_allowed boolean NOT NULL, minor_status varchar(16) NOT NULL CHECK (minor_status IN ('ADULT','MINOR','UNKNOWN')),
  guardian_policy_digest char(64), consent_receipt_digest char(64) NOT NULL CHECK (consent_receipt_digest ~ '^[0-9a-f]{64}$'),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','WITHDRAWN','EXPIRED')), granted_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK (expires_at>granted_at),
  withdrawn_at timestamptz, deletion_tombstone_ref varchar(1024),
  PRIMARY KEY (tenant_id,consent_id),
  CHECK (minor_status<>'MINOR' OR guardian_policy_digest ~ '^[0-9a-f]{64}$'),
  CHECK ((status='WITHDRAWN' AND withdrawn_at IS NOT NULL AND deletion_tombstone_ref IS NOT NULL) OR status<>'WITHDRAWN')
);
CREATE TABLE IF NOT EXISTS public.sensitive_conversation_cases (
  tenant_id uuid NOT NULL, execution_id uuid NOT NULL, conversation_ref_digest char(64) NOT NULL CHECK (conversation_ref_digest ~ '^[0-9a-f]{64}$'),
  consent_id uuid NOT NULL, risk_class varchar(24) NOT NULL CHECK (risk_class IN ('GENERAL','SENSITIVE','HIGH_RISK','CRISIS','MINOR')),
  agent_disclosure_digest char(64) NOT NULL CHECK (agent_disclosure_digest ~ '^[0-9a-f]{64}$'),
  relationship_boundary_digest char(64) NOT NULL CHECK (relationship_boundary_digest ~ '^[0-9a-f]{64}$'),
  minimized_context_digest char(64) NOT NULL CHECK (minimized_context_digest ~ '^[0-9a-f]{64}$'),
  source_snapshot_digest char(64) NOT NULL CHECK (source_snapshot_digest ~ '^[0-9a-f]{64}$'),
  ordinary_response_allowed boolean NOT NULL, human_takeover_active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,execution_id), FOREIGN KEY (tenant_id,execution_id) REFERENCES public.domain_pack_executions(tenant_id,execution_id),
  FOREIGN KEY (tenant_id,consent_id) REFERENCES public.sensitive_consent_records(tenant_id,consent_id),
  CHECK (risk_class NOT IN ('CRISIS','MINOR') OR NOT ordinary_response_allowed)
);
CREATE TABLE IF NOT EXISTS public.sensitive_source_citations (
  tenant_id uuid NOT NULL, citation_id uuid NOT NULL, execution_id uuid NOT NULL,
  source_id varchar(512) NOT NULL, source_version varchar(256) NOT NULL, source_digest char(64) NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
  passage_digest char(64) NOT NULL CHECK (passage_digest ~ '^[0-9a-f]{64}$'), context_digest char(64) NOT NULL CHECK (context_digest ~ '^[0-9a-f]{64}$'),
  viewpoint_label varchar(256) NOT NULL, verified boolean NOT NULL, verifier_digest char(64) NOT NULL CHECK (verifier_digest ~ '^[0-9a-f]{64}$'),
  verified_at timestamptz NOT NULL, PRIMARY KEY (tenant_id,citation_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.sensitive_conversation_cases(tenant_id,execution_id)
);
CREATE TABLE IF NOT EXISTS public.sensitive_human_escalations (
  tenant_id uuid NOT NULL, escalation_id uuid NOT NULL, execution_id uuid NOT NULL,
  risk_class varchar(24) NOT NULL CHECK (risk_class IN ('HIGH_RISK','CRISIS','MINOR')),
  region_code varchar(32) NOT NULL, destination_type varchar(32) NOT NULL CHECK (destination_type IN ('HUMAN_SUPPORT','EMERGENCY_SERVICE','TRUSTED_CONTACT','MENTOR_REVIEW')),
  directory_snapshot_digest char(64) NOT NULL CHECK (directory_snapshot_digest ~ '^[0-9a-f]{64}$'),
  minimum_safe_context_digest char(64) NOT NULL CHECK (minimum_safe_context_digest ~ '^[0-9a-f]{64}$'),
  consent_digest char(64), handoff_receipt_digest char(64),
  status varchar(24) NOT NULL CHECK (status IN ('REQUESTED','ACCEPTED','FAILED','CLOSED','MANUAL_RECOVERY')),
  requested_at timestamptz NOT NULL, accepted_at timestamptz, failure_code varchar(128),
  PRIMARY KEY (tenant_id,escalation_id), UNIQUE (tenant_id,execution_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.sensitive_conversation_cases(tenant_id,execution_id),
  CHECK ((status='ACCEPTED' AND accepted_at IS NOT NULL AND handoff_receipt_digest ~ '^[0-9a-f]{64}$')
      OR (status IN ('FAILED','MANUAL_RECOVERY') AND failure_code IS NOT NULL) OR status IN ('REQUESTED','CLOSED'))
);
CREATE TABLE IF NOT EXISTS public.sensitive_evaluation_findings (
  tenant_id uuid NOT NULL, finding_id uuid NOT NULL, execution_id uuid NOT NULL,
  manipulation_detected boolean NOT NULL, dependency_inducement_detected boolean NOT NULL,
  authority_impersonation_detected boolean NOT NULL, privacy_overcollection_detected boolean NOT NULL,
  citation_failure_count integer NOT NULL CHECK (citation_failure_count>=0), escalation_required boolean NOT NULL,
  escalation_completed boolean NOT NULL, minor_policy_applied boolean NOT NULL,
  conclusion varchar(16) NOT NULL CHECK (conclusion IN ('PASS','FAIL','NEEDS_HUMAN')),
  evaluator_digest char(64) NOT NULL CHECK (evaluator_digest ~ '^[0-9a-f]{64}$'), evaluated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,finding_id), UNIQUE (tenant_id,execution_id),
  FOREIGN KEY (tenant_id,execution_id) REFERENCES public.sensitive_conversation_cases(tenant_id,execution_id),
  CHECK (conclusion<>'PASS' OR (NOT manipulation_detected AND NOT dependency_inducement_detected AND NOT authority_impersonation_detected AND NOT privacy_overcollection_detected AND citation_failure_count=0 AND (NOT escalation_required OR escalation_completed)))
);

CREATE OR REPLACE FUNCTION public.agenttrust_sensitive_takeover_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF OLD.human_takeover_active AND (NOT NEW.human_takeover_active OR NEW.ordinary_response_allowed) THEN RAISE EXCEPTION 'SENSITIVE_HUMAN_TAKEOVER_IRREVERSIBLE'; END IF;
  IF NEW.risk_class IN ('CRISIS','MINOR') AND NEW.ordinary_response_allowed THEN RAISE EXCEPTION 'SENSITIVE_ORDINARY_FLOW_DENIED'; END IF;
  RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS sensitive_takeover_guard ON public.sensitive_conversation_cases;
CREATE TRIGGER sensitive_takeover_guard BEFORE UPDATE ON public.sensitive_conversation_cases FOR EACH ROW EXECUTE FUNCTION public.agenttrust_sensitive_takeover_guard();
DO $rls$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['sensitive_consent_records','sensitive_conversation_cases','sensitive_source_citations','sensitive_human_escalations','sensitive_evaluation_findings'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('DROP POLICY IF EXISTS sensitive_tenant_isolation ON public.%I',table_name);
    EXECUTE format('CREATE POLICY sensitive_tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',table_name); EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',table_name);
  END LOOP;
END $rls$;
DROP TRIGGER IF EXISTS sensitive_citation_immutable ON public.sensitive_source_citations;
CREATE TRIGGER sensitive_citation_immutable BEFORE UPDATE OR DELETE ON public.sensitive_source_citations FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
DROP TRIGGER IF EXISTS sensitive_finding_immutable ON public.sensitive_evaluation_findings;
CREATE TRIGGER sensitive_finding_immutable BEFORE UPDATE OR DELETE ON public.sensitive_evaluation_findings FOR EACH ROW EXECUTE FUNCTION public.agenttrust_domain_immutable_row();
CREATE INDEX IF NOT EXISTS sensitive_escalation_state_idx ON public.sensitive_human_escalations(tenant_id,status,requested_at);
CREATE INDEX IF NOT EXISTS sensitive_consent_subject_idx ON public.sensitive_consent_records(tenant_id,subject_ref_digest,purpose,status,expires_at);
REVOKE ALL ON FUNCTION public.agenttrust_sensitive_takeover_guard() FROM PUBLIC;
COMMIT;
