BEGIN;

-- Batch 20 production authority. The v1 tables are retained as an owner-only quarantine;
-- tenant/action/evidence bindings were not sufficient to treat those rows as production state.
DO $migration$
BEGIN
  IF to_regclass('public.supply_chain_artifacts') IS NOT NULL
     AND to_regclass('public.supply_chain_artifacts_legacy_0020') IS NULL THEN
    ALTER TABLE public.supply_chain_artifacts RENAME TO supply_chain_artifacts_legacy_0020;
  END IF;
  IF to_regclass('public.domain_pack_versions') IS NOT NULL
     AND to_regclass('public.domain_pack_versions_legacy_0020') IS NULL THEN
    ALTER TABLE public.domain_pack_versions RENAME TO domain_pack_versions_legacy_0020;
  END IF;
  IF to_regclass('public.publisher_revocations') IS NOT NULL
     AND to_regclass('public.publisher_revocations_legacy_0020') IS NULL THEN
    ALTER TABLE public.publisher_revocations RENAME TO publisher_revocations_legacy_0020;
  END IF;
END
$migration$;

REVOKE ALL ON TABLE public.supply_chain_artifacts_legacy_0020 FROM PUBLIC;
REVOKE ALL ON TABLE public.domain_pack_versions_legacy_0020 FROM PUBLIC;
REVOKE ALL ON TABLE public.publisher_revocations_legacy_0020 FROM PUBLIC;

CREATE TABLE public.supply_chain_publishers (
  publisher_id varchar(256) PRIMARY KEY,
  organization_id varchar(256) NOT NULL,
  source_repository_prefix varchar(1024) NOT NULL,
  assurance_level varchar(24) NOT NULL CHECK (assurance_level IN ('INTERNAL','PARTNER','INDEPENDENT')),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (publisher_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$'),
  CHECK (source_repository_prefix ~ '^https://')
);

CREATE TABLE public.supply_chain_publisher_keys (
  publisher_id varchar(256) NOT NULL REFERENCES public.supply_chain_publishers(publisher_id),
  key_id varchar(256) NOT NULL,
  algorithm varchar(24) NOT NULL CHECK (algorithm IN ('ED25519','SIGSTORE_KEYLESS','ENTERPRISE_PKI')),
  public_key_spki bytea NOT NULL CHECK (octet_length(public_key_spki) BETWEEN 32 AND 8192),
  identity_claim varchar(1024) NOT NULL,
  issuer varchar(1024) NOT NULL,
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL CHECK (valid_until > valid_from),
  status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  revoked_at timestamptz,
  revocation_reason varchar(512),
  PRIMARY KEY (publisher_id,key_id),
  CHECK ((status='REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
      OR (status<>'REVOKED' AND revoked_at IS NULL AND revocation_reason IS NULL))
);

CREATE TABLE public.supply_chain_artifact_revisions (
  tenant_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  artifact_type varchar(32) NOT NULL CHECK (artifact_type IN (
    'RUST_CRATE','PYTHON_PACKAGE','MAVEN_PACKAGE','NPM_PACKAGE','OCI_IMAGE','PROTOCOL_ADAPTER',
    'POLICY_BUNDLE','PROMPT','EVALUATOR','MODEL_MANIFEST','DOMAIN_PACK'
  )),
  name varchar(256) NOT NULL,
  version varchar(128) NOT NULL,
  artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
  immutable_reference varchar(2048) NOT NULL,
  publisher_id varchar(256) NOT NULL,
  publisher_key_id varchar(256) NOT NULL,
  sbom_format varchar(32) NOT NULL CHECK (sbom_format IN ('SPDX_JSON','CYCLONEDX_JSON')),
  sbom_digest char(64) NOT NULL CHECK (sbom_digest ~ '^[0-9a-f]{64}$'),
  component_count integer NOT NULL CHECK (component_count BETWEEN 1 AND 1000000),
  provenance_digest char(64) NOT NULL CHECK (provenance_digest ~ '^[0-9a-f]{64}$'),
  source_repository varchar(1024) NOT NULL CHECK (source_repository ~ '^https://'),
  source_commit varchar(128) NOT NULL,
  builder_identity varchar(1024) NOT NULL,
  build_definition_digest char(64) NOT NULL CHECK (build_definition_digest ~ '^[0-9a-f]{64}$'),
  signature_envelope jsonb NOT NULL CHECK (jsonb_typeof(signature_envelope)='object'),
  signature_digest char(64) NOT NULL CHECK (signature_digest ~ '^[0-9a-f]{64}$'),
  license_report_digest char(64) NOT NULL CHECK (license_report_digest ~ '^[0-9a-f]{64}$'),
  vulnerability_report_digest char(64) NOT NULL CHECK (vulnerability_report_digest ~ '^[0-9a-f]{64}$'),
  maximum_vulnerability varchar(16) NOT NULL CHECK (maximum_vulnerability IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  compatibility jsonb NOT NULL CHECK (jsonb_typeof(compatibility)='array'),
  status varchar(16) NOT NULL CHECK (status IN ('VERIFIED','QUARANTINED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,artifact_id),
  UNIQUE (tenant_id,artifact_digest),
  UNIQUE (tenant_id,artifact_type,name,version),
  FOREIGN KEY (publisher_id,publisher_key_id)
    REFERENCES public.supply_chain_publisher_keys(publisher_id,key_id),
  CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$'),
  CHECK (immutable_reference !~* '(^|:)latest($|@)' AND immutable_reference LIKE '%sha256:%')
);

CREATE TABLE public.supply_chain_pack_releases (
  tenant_id uuid NOT NULL,
  pack_id varchar(256) NOT NULL,
  version varchar(128) NOT NULL,
  artifact_id uuid NOT NULL,
  manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest)='object'),
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  permission_digest char(64) NOT NULL CHECK (permission_digest ~ '^[0-9a-f]{64}$'),
  dependency_lock jsonb NOT NULL CHECK (jsonb_typeof(dependency_lock)='array'),
  dependency_lock_digest char(64) NOT NULL CHECK (dependency_lock_digest ~ '^[0-9a-f]{64}$'),
  lifecycle_state varchar(20) NOT NULL CHECK (lifecycle_state IN (
    'PUBLISHED','VALIDATED','APPROVED','ACTIVE','QUARANTINED','REVOKED','ROLLED_BACK'
  )),
  resource_version bigint NOT NULL DEFAULT 1 CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,pack_id,version),
  UNIQUE (tenant_id,manifest_digest),
  FOREIGN KEY (tenant_id,artifact_id)
    REFERENCES public.supply_chain_artifact_revisions(tenant_id,artifact_id),
  CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$'),
  CHECK (manifest ?& ARRAY['schema_version','pack_id','version','digest','permissions','tools','signature'])
);

CREATE TABLE public.supply_chain_conformance_runs (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  pack_id varchar(256) NOT NULL,
  version varchar(128) NOT NULL,
  sandbox_profile_digest char(64) NOT NULL CHECK (sandbox_profile_digest ~ '^[0-9a-f]{64}$'),
  schema_report_digest char(64) NOT NULL CHECK (schema_report_digest ~ '^[0-9a-f]{64}$'),
  dependency_report_digest char(64) NOT NULL CHECK (dependency_report_digest ~ '^[0-9a-f]{64}$'),
  vulnerability_report_digest char(64) NOT NULL CHECK (vulnerability_report_digest ~ '^[0-9a-f]{64}$'),
  license_report_digest char(64) NOT NULL CHECK (license_report_digest ~ '^[0-9a-f]{64}$'),
  behavior_report_digest char(64) NOT NULL CHECK (behavior_report_digest ~ '^[0-9a-f]{64}$'),
  threat_report_digest char(64) NOT NULL CHECK (threat_report_digest ~ '^[0-9a-f]{64}$'),
  network_violation_count integer NOT NULL CHECK (network_violation_count >= 0),
  conclusion varchar(16) NOT NULL CHECK (conclusion IN ('PASS','FAIL','INCONCLUSIVE')),
  runner_identity varchar(512) NOT NULL,
  completed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,run_id),
  FOREIGN KEY (tenant_id,pack_id,version)
    REFERENCES public.supply_chain_pack_releases(tenant_id,pack_id,version)
);

CREATE TABLE public.supply_chain_pack_approvals (
  tenant_id uuid NOT NULL,
  approval_id uuid NOT NULL,
  pack_id varchar(256) NOT NULL,
  version varchar(128) NOT NULL,
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  previous_manifest_digest char(64),
  permission_diff jsonb NOT NULL CHECK (jsonb_typeof(permission_diff)='object'),
  permission_diff_digest char(64) NOT NULL CHECK (permission_diff_digest ~ '^[0-9a-f]{64}$'),
  environment varchar(64) NOT NULL,
  decision varchar(16) NOT NULL CHECK (decision IN ('APPROVED','REJECTED','EXPIRED','REVOKED')),
  approver_subject varchar(512) NOT NULL,
  approver_role varchar(256) NOT NULL,
  principal_assertion_digest char(64) NOT NULL CHECK (principal_assertion_digest ~ '^[0-9a-f]{64}$'),
  evidence_ref varchar(1024) NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  approved_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > approved_at),
  PRIMARY KEY (tenant_id,approval_id),
  UNIQUE (tenant_id,pack_id,version,environment,manifest_digest),
  FOREIGN KEY (tenant_id,pack_id,version)
    REFERENCES public.supply_chain_pack_releases(tenant_id,pack_id,version)
);

CREATE TABLE public.supply_chain_installations (
  tenant_id uuid NOT NULL,
  environment varchar(64) NOT NULL,
  pack_id varchar(256) NOT NULL,
  version varchar(128) NOT NULL,
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  approval_id uuid NOT NULL,
  previous_version varchar(128),
  previous_manifest_digest char(64),
  state varchar(16) NOT NULL CHECK (state IN ('ACTIVE','PAUSED','REVOKED','ROLLED_BACK')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  activated_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,environment,pack_id),
  FOREIGN KEY (tenant_id,pack_id,version)
    REFERENCES public.supply_chain_pack_releases(tenant_id,pack_id,version),
  FOREIGN KEY (tenant_id,approval_id)
    REFERENCES public.supply_chain_pack_approvals(tenant_id,approval_id)
);

CREATE TABLE public.supply_chain_revocations (
  tenant_id uuid NOT NULL,
  revocation_id uuid NOT NULL,
  scope varchar(24) NOT NULL CHECK (scope IN ('PUBLISHER','KEY','ARTIFACT','PACK_RELEASE')),
  subject_id varchar(1024) NOT NULL,
  subject_digest char(64),
  reason_code varchar(128) NOT NULL,
  running_task_disposition varchar(20) NOT NULL CHECK (running_task_disposition IN ('PAUSE','KILL','ALLOW_TO_FINISH')),
  impact_digest char(64) NOT NULL CHECK (impact_digest ~ '^[0-9a-f]{64}$'),
  actor_subject varchar(512) NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,revocation_id),
  UNIQUE (tenant_id,scope,subject_id)
);

CREATE TABLE public.supply_chain_authority_commands (
  tenant_id uuid NOT NULL,
  command_id uuid NOT NULL,
  task_id uuid NOT NULL,
  action_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  operation varchar(24) NOT NULL CHECK (operation IN (
    'PUBLISH','VALIDATE','APPROVE','ACTIVATE','ROLLBACK','REVOKE','QUARANTINE','RECOVER'
  )),
  resource_key varchar(768) NOT NULL,
  expected_resource_version bigint NOT NULL CHECK (expected_resource_version >= 0),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  idempotency_key varchar(256) NOT NULL,
  actor_subject varchar(512) NOT NULL,
  authorization_id uuid NOT NULL,
  authorization_digest char(64) NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
  policy_decision_id varchar(256) NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[0-9a-f]{64}$'),
  authorization_evidence_ref varchar(1024) NOT NULL,
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  canonical_action jsonb NOT NULL CHECK (jsonb_typeof(canonical_action)='object'),
  safe_request jsonb NOT NULL CHECK (jsonb_typeof(safe_request)='object'),
  state varchar(16) NOT NULL CHECK (state IN ('PREPARED','EXECUTING','SUCCEEDED','FAILED','UNKNOWN')),
  owner_instance_id uuid,
  lease_expires_at timestamptz,
  effect_receipt jsonb,
  result_digest char(64),
  stable_error varchar(128),
  evidence_ref varchar(1024),
  evidence_digest char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,command_id),
  UNIQUE (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id),
  UNIQUE (tenant_id,ledger_execution_id,ledger_event_id),
  CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{15,255}$'),
  CHECK ((state='PREPARED' AND owner_instance_id IS NULL AND lease_expires_at IS NULL)
      OR (state='EXECUTING' AND owner_instance_id IS NOT NULL AND lease_expires_at IS NOT NULL)
      OR (state IN ('SUCCEEDED','FAILED','UNKNOWN') AND owner_instance_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK ((state='SUCCEEDED' AND effect_receipt IS NOT NULL AND result_digest IS NOT NULL
          AND evidence_ref IS NOT NULL AND evidence_digest IS NOT NULL AND stable_error IS NULL)
      OR (state IN ('FAILED','UNKNOWN') AND stable_error IS NOT NULL)
      OR state IN ('PREPARED','EXECUTING'))
);

CREATE TABLE public.supply_chain_evidence_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  command_id uuid NOT NULL,
  action_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  event_type varchar(128) NOT NULL,
  subject_digest char(64) NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  previous_event_digest char(64),
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,event_digest),
  FOREIGN KEY (tenant_id,command_id)
    REFERENCES public.supply_chain_authority_commands(tenant_id,command_id)
);

CREATE TABLE public.supply_chain_evidence_outbox (
  tenant_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  command_id uuid NOT NULL,
  idempotency_key varchar(256) NOT NULL,
  destination varchar(64) NOT NULL CHECK (destination='EVIDENCE_AUTHORITY'),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  delivered_at timestamptz,
  delivery_evidence_ref varchar(2048),
  delivery_receipt_digest char(64),
  PRIMARY KEY (tenant_id,outbox_id),
  UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,command_id)
    REFERENCES public.supply_chain_authority_commands(tenant_id,command_id),
  CHECK ((delivered_at IS NULL AND delivery_evidence_ref IS NULL AND delivery_receipt_digest IS NULL)
      OR (delivered_at IS NOT NULL AND delivery_evidence_ref LIKE 'evidence://%' AND delivery_receipt_digest ~ '^[0-9a-f]{64}$'))
);

CREATE OR REPLACE FUNCTION public.agenttrust_supply_immutable_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  RAISE EXCEPTION 'SUPPLY_CHAIN_IMMUTABLE_RECORD';
END
$function$;

CREATE OR REPLACE FUNCTION public.agenttrust_supply_command_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.command_id<>OLD.command_id
     OR NEW.task_id<>OLD.task_id OR NEW.action_id<>OLD.action_id
     OR NEW.action_hash<>OLD.action_hash OR NEW.operation<>OLD.operation
     OR NEW.resource_key<>OLD.resource_key OR NEW.expected_resource_version<>OLD.expected_resource_version
     OR NEW.request_digest<>OLD.request_digest OR NEW.idempotency_key<>OLD.idempotency_key
     OR NEW.actor_subject<>OLD.actor_subject OR NEW.authorization_id<>OLD.authorization_id
     OR NEW.authorization_digest<>OLD.authorization_digest
     OR NEW.policy_decision_id<>OLD.policy_decision_id
     OR NEW.policy_decision_digest<>OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref<>OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest<>OLD.authorization_evidence_digest
     OR NEW.ledger_execution_id<>OLD.ledger_execution_id OR NEW.ledger_event_id<>OLD.ledger_event_id
     OR NEW.ledger_event_digest<>OLD.ledger_event_digest OR NEW.fence_digest<>OLD.fence_digest
     OR NEW.resource_version<>OLD.resource_version OR NEW.canonical_action<>OLD.canonical_action
     OR NEW.safe_request<>OLD.safe_request OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_COMMAND_BINDING_IMMUTABLE';
  END IF;
  IF OLD.state IN ('SUCCEEDED','FAILED','UNKNOWN')
     OR (OLD.state='PREPARED' AND NEW.state NOT IN ('EXECUTING','FAILED'))
     OR (OLD.state='EXECUTING' AND NEW.state NOT IN ('EXECUTING','SUCCEEDED','FAILED','UNKNOWN')) THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_COMMAND_TRANSITION_INVALID';
  END IF;
  IF OLD.state='EXECUTING' AND NEW.state='EXECUTING'
     AND (NEW.owner_instance_id IS DISTINCT FROM OLD.owner_instance_id
          OR NEW.lease_expires_at < OLD.lease_expires_at) THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_COMMAND_LEASE_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.agenttrust_supply_installation_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.environment<>OLD.environment OR NEW.pack_id<>OLD.pack_id
     OR NEW.resource_version<>OLD.resource_version+1 OR NEW.updated_at<=OLD.updated_at
  THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_INSTALLATION_FENCE_INVALID';
  END IF;
  IF (OLD.state='ACTIVE' AND NEW.state NOT IN ('ACTIVE','PAUSED','REVOKED','ROLLED_BACK'))
     OR (OLD.state='PAUSED' AND NEW.state NOT IN ('ACTIVE','REVOKED','ROLLED_BACK'))
     OR OLD.state='REVOKED'
     OR (OLD.state='ROLLED_BACK' AND NEW.state NOT IN ('ACTIVE','REVOKED'))
     OR (NEW.state IN ('PAUSED','REVOKED') AND
         (NEW.version<>OLD.version OR NEW.manifest_digest<>OLD.manifest_digest
          OR NEW.approval_id<>OLD.approval_id OR NEW.previous_version IS DISTINCT FROM OLD.previous_version
          OR NEW.previous_manifest_digest IS DISTINCT FROM OLD.previous_manifest_digest
          OR NEW.activated_at<>OLD.activated_at))
     OR (NEW.state='ACTIVE' AND
         (NEW.activated_at<=OLD.activated_at
          OR (NEW.version=OLD.version AND NEW.manifest_digest=OLD.manifest_digest
              AND NEW.approval_id=OLD.approval_id))) THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_INSTALLATION_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.agenttrust_supply_release_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.pack_id<>OLD.pack_id OR NEW.version<>OLD.version
     OR NEW.artifact_id<>OLD.artifact_id OR NEW.manifest<>OLD.manifest
     OR NEW.manifest_digest<>OLD.manifest_digest OR NEW.permission_digest<>OLD.permission_digest
     OR NEW.dependency_lock<>OLD.dependency_lock OR NEW.dependency_lock_digest<>OLD.dependency_lock_digest
     OR NEW.created_at<>OLD.created_at OR NEW.resource_version<>OLD.resource_version+1
     OR NEW.updated_at<=OLD.updated_at THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_RELEASE_BINDING_IMMUTABLE';
  END IF;
  IF OLD.lifecycle_state='REVOKED'
     OR (OLD.lifecycle_state='ROLLED_BACK' AND NEW.lifecycle_state NOT IN ('ACTIVE','REVOKED'))
     OR (OLD.lifecycle_state='PUBLISHED' AND NEW.lifecycle_state NOT IN ('VALIDATED','QUARANTINED','REVOKED'))
     OR (OLD.lifecycle_state='VALIDATED' AND NEW.lifecycle_state NOT IN ('APPROVED','QUARANTINED','REVOKED'))
     OR (OLD.lifecycle_state='APPROVED' AND NEW.lifecycle_state NOT IN ('ACTIVE','QUARANTINED','REVOKED'))
     OR (OLD.lifecycle_state='ACTIVE' AND NEW.lifecycle_state NOT IN ('QUARANTINED','REVOKED','ROLLED_BACK'))
     OR (OLD.lifecycle_state='QUARANTINED' AND NEW.lifecycle_state<>'REVOKED') THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_RELEASE_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.agenttrust_supply_artifact_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'SUPPLY_CHAIN_ARTIFACT_IMMUTABLE'; END IF;
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.artifact_id<>OLD.artifact_id
     OR NEW.artifact_type<>OLD.artifact_type OR NEW.name<>OLD.name OR NEW.version<>OLD.version
     OR NEW.artifact_digest<>OLD.artifact_digest OR NEW.immutable_reference<>OLD.immutable_reference
     OR NEW.publisher_id<>OLD.publisher_id OR NEW.publisher_key_id<>OLD.publisher_key_id
     OR NEW.sbom_format<>OLD.sbom_format OR NEW.sbom_digest<>OLD.sbom_digest
     OR NEW.component_count<>OLD.component_count OR NEW.provenance_digest<>OLD.provenance_digest
     OR NEW.source_repository<>OLD.source_repository OR NEW.source_commit<>OLD.source_commit
     OR NEW.builder_identity<>OLD.builder_identity OR NEW.build_definition_digest<>OLD.build_definition_digest
     OR NEW.signature_envelope<>OLD.signature_envelope OR NEW.signature_digest<>OLD.signature_digest
     OR NEW.license_report_digest<>OLD.license_report_digest
     OR NEW.vulnerability_report_digest<>OLD.vulnerability_report_digest
     OR NEW.maximum_vulnerability<>OLD.maximum_vulnerability OR NEW.compatibility<>OLD.compatibility
     OR NEW.created_at<>OLD.created_at
     OR OLD.status='REVOKED'
     OR (OLD.status='VERIFIED' AND NEW.status NOT IN ('QUARANTINED','REVOKED'))
     OR (OLD.status='QUARANTINED' AND NEW.status<>'REVOKED') THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_ARTIFACT_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.agenttrust_supply_outbox_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF TG_OP='DELETE' OR OLD.delivered_at IS NOT NULL OR NEW.delivered_at IS NULL
     OR NEW.tenant_id<>OLD.tenant_id OR NEW.outbox_id<>OLD.outbox_id
     OR NEW.command_id<>OLD.command_id OR NEW.idempotency_key<>OLD.idempotency_key
     OR NEW.destination<>OLD.destination OR NEW.payload<>OLD.payload
     OR NEW.payload_digest<>OLD.payload_digest OR NEW.created_at<>OLD.created_at THEN
    RAISE EXCEPTION 'SUPPLY_CHAIN_OUTBOX_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS supply_command_transition_guard ON public.supply_chain_authority_commands;
CREATE TRIGGER supply_command_transition_guard BEFORE UPDATE ON public.supply_chain_authority_commands
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_supply_command_transition();
DROP TRIGGER IF EXISTS supply_installation_transition_guard ON public.supply_chain_installations;
CREATE TRIGGER supply_installation_transition_guard BEFORE UPDATE ON public.supply_chain_installations
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_supply_installation_transition();
DROP TRIGGER IF EXISTS supply_release_transition_guard ON public.supply_chain_pack_releases;
CREATE TRIGGER supply_release_transition_guard BEFORE UPDATE ON public.supply_chain_pack_releases
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_supply_release_transition();
DROP TRIGGER IF EXISTS supply_artifact_transition_guard ON public.supply_chain_artifact_revisions;
CREATE TRIGGER supply_artifact_transition_guard BEFORE UPDATE OR DELETE ON public.supply_chain_artifact_revisions
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_supply_artifact_transition();
DROP TRIGGER IF EXISTS supply_outbox_transition_guard ON public.supply_chain_evidence_outbox;
CREATE TRIGGER supply_outbox_transition_guard BEFORE UPDATE OR DELETE ON public.supply_chain_evidence_outbox
FOR EACH ROW EXECUTE FUNCTION public.agenttrust_supply_outbox_transition();

DO $immutable$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'supply_chain_conformance_runs','supply_chain_pack_approvals',
    'supply_chain_revocations','supply_chain_evidence_events'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS supply_immutable_row ON public.%I',table_name);
    EXECUTE format('CREATE TRIGGER supply_immutable_row BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.agenttrust_supply_immutable_row()',table_name);
  END LOOP;
END
$immutable$;

DO $rls$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'supply_chain_artifact_revisions','supply_chain_pack_releases','supply_chain_conformance_runs',
    'supply_chain_pack_approvals','supply_chain_installations','supply_chain_revocations',
    'supply_chain_authority_commands','supply_chain_evidence_events','supply_chain_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('DROP POLICY IF EXISTS supply_tenant_isolation ON public.%I',table_name);
    EXECUTE format('CREATE POLICY supply_tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',table_name);
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',table_name);
  END LOOP;
END
$rls$;

CREATE UNIQUE INDEX supply_single_pack_flight_idx
  ON public.supply_chain_authority_commands(tenant_id,resource_key)
  WHERE state IN ('PREPARED','EXECUTING');
CREATE INDEX supply_command_recovery_idx
  ON public.supply_chain_authority_commands(tenant_id,state,lease_expires_at,updated_at);
CREATE INDEX supply_outbox_delivery_idx
  ON public.supply_chain_evidence_outbox(tenant_id,created_at) WHERE delivered_at IS NULL;
CREATE UNIQUE INDEX supply_one_active_manifest_idx
  ON public.supply_chain_installations(tenant_id,environment,pack_id) WHERE state='ACTIVE';

REVOKE ALL ON TABLE public.supply_chain_publishers,public.supply_chain_publisher_keys FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_supply_immutable_row() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_supply_command_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_supply_installation_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_supply_release_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_supply_artifact_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agenttrust_supply_outbox_transition() FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

COMMIT;
