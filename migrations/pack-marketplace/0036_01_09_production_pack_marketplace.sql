BEGIN;

CREATE TABLE IF NOT EXISTS marketplace_publishers (
  tenant_id uuid NOT NULL,
  publisher_id text NOT NULL CHECK (length(publisher_id) BETWEEN 1 AND 128),
  owner_subject text NOT NULL CHECK (length(owner_subject) BETWEEN 1 AND 256),
  identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
  responsibility_contact text NOT NULL CHECK (length(responsibility_contact) BETWEEN 3 AND 320),
  home_region text NOT NULL CHECK (length(home_region) BETWEEN 1 AND 128),
  trust_status text NOT NULL CHECK (trust_status IN ('UNTRUSTED','VERIFIED','SUSPENDED','REVOKED')),
  verified_by text,
  verified_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,publisher_id),
  UNIQUE (tenant_id,owner_subject),
  CHECK ((trust_status='VERIFIED') <= (verified_by IS NOT NULL AND verified_at IS NOT NULL)),
  CHECK ((trust_status='REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS marketplace_publisher_keys (
  tenant_id uuid NOT NULL,
  publisher_id text NOT NULL,
  key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
  algorithm text NOT NULL CHECK (algorithm='Ed25519'),
  public_key bytea NOT NULL CHECK (octet_length(public_key)=32),
  key_fingerprint char(64) NOT NULL CHECK (key_fingerprint ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE','VERIFY_ONLY','REVOKED')),
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  reviewed_by text NOT NULL CHECK (length(reviewed_by) BETWEEN 1 AND 256),
  review_digest char(64) NOT NULL CHECK (review_digest ~ '^[a-f0-9]{64}$'),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,publisher_id,key_id),
  UNIQUE (tenant_id,key_fingerprint),
  FOREIGN KEY (tenant_id,publisher_id)
    REFERENCES marketplace_publishers (tenant_id,publisher_id),
  CHECK (not_before < expires_at),
  CHECK ((status='REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS marketplace_pack_names (
  tenant_id uuid NOT NULL,
  pack_id text NOT NULL CHECK (length(pack_id) BETWEEN 1 AND 128),
  publisher_id text NOT NULL,
  reserved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,pack_id),
  FOREIGN KEY (tenant_id,publisher_id)
    REFERENCES marketplace_publishers (tenant_id,publisher_id)
);

CREATE TABLE IF NOT EXISTS marketplace_tenant_catalog (
  tenant_id uuid PRIMARY KEY,
  control_plane_version text NOT NULL CHECK (control_plane_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
  region text NOT NULL CHECK (length(region) BETWEEN 1 AND 128),
  entitlements text[] NOT NULL CHECK (cardinality(entitlements) BETWEEN 1 AND 256),
  allowed_compatibility text[] NOT NULL CHECK (cardinality(allowed_compatibility) BETWEEN 1 AND 256),
  minimum_publisher_trust text NOT NULL CHECK (minimum_publisher_trust='VERIFIED'),
  maximum_risk text NOT NULL CHECK (maximum_risk IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  configured_by text NOT NULL CHECK (length(configured_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (array_position(entitlements,NULL) IS NULL),
  CHECK (array_position(allowed_compatibility,NULL) IS NULL)
);

CREATE TABLE IF NOT EXISTS marketplace_releases (
  tenant_id uuid NOT NULL,
  release_id uuid NOT NULL,
  pack_id text NOT NULL,
  version text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
  publisher_id text NOT NULL,
  manifest jsonb NOT NULL,
  pack_digest char(64) NOT NULL CHECK (pack_digest ~ '^[a-f0-9]{64}$'),
  permission_digest char(64) NOT NULL CHECK (permission_digest ~ '^[a-f0-9]{64}$'),
  release_certificate jsonb NOT NULL,
  certificate_digest char(64) NOT NULL CHECK (certificate_digest ~ '^[a-f0-9]{64}$'),
  visibility text NOT NULL CHECK (visibility IN ('PRIVATE','TENANT')),
  entitlement text NOT NULL CHECK (length(entitlement) BETWEEN 1 AND 128),
  allowed_regions text[] NOT NULL CHECK (cardinality(allowed_regions) BETWEEN 1 AND 64),
  risk_rating text NOT NULL CHECK (risk_rating IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  minimum_publisher_trust text NOT NULL CHECK (minimum_publisher_trust='VERIFIED'),
  minimum_control_plane_version text NOT NULL CHECK (minimum_control_plane_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
  review_status text NOT NULL CHECK (review_status IN ('SUBMITTED','PUBLISHED','REJECTED','REVOKED')),
  submitted_by text NOT NULL CHECK (length(submitted_by) BETWEEN 1 AND 256),
  reviewed_by text,
  review_digest char(64),
  published_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,release_id),
  UNIQUE (tenant_id,pack_id,version),
  UNIQUE (tenant_id,pack_digest),
  FOREIGN KEY (tenant_id,pack_id) REFERENCES marketplace_pack_names (tenant_id,pack_id),
  FOREIGN KEY (tenant_id,publisher_id) REFERENCES marketplace_publishers (tenant_id,publisher_id),
  CHECK (manifest->>'schema_version'='agenttrust.domain-pack.v1'),
  CHECK (manifest->>'pack_id'=pack_id),
  CHECK (manifest->>'version'=version),
  CHECK (manifest->>'digest'=pack_digest),
  CHECK (manifest->>'publisher_identity'=publisher_id),
  CHECK (release_certificate->>'schema_version'='agenttrust.incident-release.v1'),
  CHECK (release_certificate->>'release_digest'=pack_digest),
  CHECK (release_certificate->>'engine_certificate_only'='true'),
  CHECK (release_certificate->>'production_closure'='false'),
  CHECK (array_position(allowed_regions,NULL) IS NULL),
  CHECK (review_digest IS NULL OR review_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((review_status IN ('PUBLISHED','REJECTED')) <= (reviewed_by IS NOT NULL AND review_digest IS NOT NULL)),
  CHECK ((review_status='PUBLISHED') <= (published_at IS NOT NULL)),
  CHECK ((review_status='REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS marketplace_installations (
  tenant_id uuid NOT NULL,
  installation_id uuid NOT NULL,
  release_id uuid NOT NULL,
  pack_id text NOT NULL,
  version text NOT NULL,
  pack_digest char(64) NOT NULL CHECK (pack_digest ~ '^[a-f0-9]{64}$'),
  environment text NOT NULL CHECK (environment IN ('development','staging','canary','production')),
  requester_subject text NOT NULL CHECK (length(requester_subject) BETWEEN 1 AND 256),
  request_reason_digest char(64) NOT NULL CHECK (request_reason_digest ~ '^[a-f0-9]{64}$'),
  permission_digest char(64) NOT NULL CHECK (permission_digest ~ '^[a-f0-9]{64}$'),
  permission_diff jsonb NOT NULL,
  permission_expansion boolean NOT NULL,
  state text NOT NULL CHECK (state IN ('PENDING_APPROVAL','APPROVED','REJECTED','INSTALLED','ACTIVE','INACTIVE','ROLLED_BACK','REVOKED')),
  approved_by text,
  approval_digest char(64),
  artifact_receipt_digest char(64),
  previous_installation_id uuid,
  production_certificate_digest char(64),
  deactivation_reason_digest char(64),
  approved_at timestamptz,
  installed_at timestamptz,
  activated_at timestamptz,
  deactivated_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,installation_id),
  FOREIGN KEY (tenant_id,release_id) REFERENCES marketplace_releases (tenant_id,release_id),
  FOREIGN KEY (tenant_id,previous_installation_id) REFERENCES marketplace_installations (tenant_id,installation_id),
  CHECK (permission_diff ? 'added_tools' AND permission_diff ? 'added_network_destinations'
    AND permission_diff ? 'added_data_classes' AND permission_diff ? 'added_secret_scopes'
    AND permission_diff ? 'added_executors' AND permission_diff ? 'added_approval_scopes'),
  CHECK (approval_digest IS NULL OR approval_digest ~ '^[a-f0-9]{64}$'),
  CHECK (artifact_receipt_digest IS NULL OR artifact_receipt_digest ~ '^[a-f0-9]{64}$'),
  CHECK (production_certificate_digest IS NULL OR production_certificate_digest ~ '^[a-f0-9]{64}$'),
  CHECK (deactivation_reason_digest IS NULL OR deactivation_reason_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state IN ('APPROVED','REJECTED','INSTALLED','ACTIVE','INACTIVE','ROLLED_BACK')) <=
    (approved_by IS NOT NULL AND approval_digest IS NOT NULL)),
  CHECK ((state IN ('INSTALLED','ACTIVE','INACTIVE','ROLLED_BACK')) <=
    (artifact_receipt_digest IS NOT NULL AND installed_at IS NOT NULL)),
  CHECK ((state='ACTIVE') <= (activated_at IS NOT NULL)),
  CHECK ((state='REVOKED') = (revoked_at IS NOT NULL)),
  CHECK (environment <> 'production' OR state NOT IN ('ACTIVE','INACTIVE','ROLLED_BACK')
    OR production_certificate_digest IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS marketplace_single_active_installation_idx
  ON marketplace_installations (tenant_id,pack_id,environment) WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS marketplace_upgrade_plans (
  tenant_id uuid NOT NULL,
  plan_id uuid NOT NULL,
  pack_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('development','staging','canary','production')),
  current_installation_id uuid NOT NULL,
  target_installation_id uuid NOT NULL,
  current_version text NOT NULL,
  target_version text NOT NULL,
  permission_expansion boolean NOT NULL,
  migration_digest char(64) NOT NULL CHECK (migration_digest ~ '^[a-f0-9]{64}$'),
  rollback_digest char(64) NOT NULL CHECK (rollback_digest ~ '^[a-f0-9]{64}$'),
  canary_percent smallint NOT NULL CHECK (canary_percent BETWEEN 1 AND 50),
  state text NOT NULL CHECK (state IN ('PLANNED','CANARY_PASSED','CANARY_FAILED','COMPLETED','ROLLED_BACK')),
  planned_by text NOT NULL CHECK (length(planned_by) BETWEEN 1 AND 256),
  rollback_reason_digest char(64),
  completed_at timestamptz,
  rolled_back_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,plan_id),
  UNIQUE (tenant_id,target_installation_id),
  FOREIGN KEY (tenant_id,current_installation_id) REFERENCES marketplace_installations (tenant_id,installation_id),
  FOREIGN KEY (tenant_id,target_installation_id) REFERENCES marketplace_installations (tenant_id,installation_id),
  CHECK (current_installation_id <> target_installation_id),
  CHECK (rollback_reason_digest IS NULL OR rollback_reason_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state='COMPLETED') <= (completed_at IS NOT NULL)),
  CHECK ((state='ROLLED_BACK') = (rolled_back_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS marketplace_canary_results (
  tenant_id uuid NOT NULL,
  canary_id uuid NOT NULL,
  plan_id uuid NOT NULL,
  passed boolean NOT NULL,
  observed_samples bigint NOT NULL CHECK (observed_samples BETWEEN 1 AND 10000000),
  evidence_ref text NOT NULL CHECK (evidence_ref LIKE 'urn:agenttrust:%' AND length(evidence_ref)<=2048),
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  recorded_by text NOT NULL CHECK (length(recorded_by) BETWEEN 1 AND 256),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,canary_id),
  UNIQUE (tenant_id,plan_id),
  FOREIGN KEY (tenant_id,plan_id) REFERENCES marketplace_upgrade_plans (tenant_id,plan_id)
);

CREATE TABLE IF NOT EXISTS marketplace_revocations (
  tenant_id uuid NOT NULL,
  notice_id uuid NOT NULL,
  release_id uuid NOT NULL,
  pack_id text NOT NULL,
  version text NOT NULL,
  pack_digest char(64) NOT NULL CHECK (pack_digest ~ '^[a-f0-9]{64}$'),
  reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
  reason_digest char(64) NOT NULL CHECK (reason_digest ~ '^[a-f0-9]{64}$'),
  running_task_response text NOT NULL CHECK (running_task_response IN ('PAUSE','KILL','ALLOW_TO_FINISH')),
  revoked_by text NOT NULL CHECK (length(revoked_by) BETWEEN 1 AND 256),
  revoked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,notice_id),
  UNIQUE (tenant_id,release_id),
  FOREIGN KEY (tenant_id,release_id) REFERENCES marketplace_releases (tenant_id,release_id)
);

CREATE TABLE IF NOT EXISTS marketplace_resource_versions (
  tenant_id uuid NOT NULL,
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 256),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  policy_decision_id text NOT NULL CHECK (length(policy_decision_id) BETWEEN 1 AND 256),
  ledger_entry_id text NOT NULL CHECK (length(ledger_entry_id) BETWEEN 1 AND 256),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,resource_id),
  UNIQUE (tenant_id,ledger_execution_id)
);

CREATE TABLE IF NOT EXISTS marketplace_principal_assertion_replay (
  tenant_id uuid NOT NULL,
  jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL CHECK (assertion_digest ~ '^[a-f0-9]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,jti),
  CHECK (expires_at > consumed_at - interval '30 seconds')
);

CREATE TABLE IF NOT EXISTS marketplace_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 256),
  principal_subject text NOT NULL CHECK (length(principal_subject) BETWEEN 1 AND 256),
  principal_assertion_digest char(64) NOT NULL CHECK (principal_assertion_digest ~ '^[a-f0-9]{64}$'),
  envelope jsonb NOT NULL CHECK (
    envelope->>'schema_version'='agenttrust.gateway.v1'
    AND envelope->>'idempotency_key'=idempotency_key
    AND envelope #>> '{tenant_context,tenant_id}'=tenant_id::text
    AND envelope #>> '{identity_context,tenant_id}'=tenant_id::text
  ),
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id),
  UNIQUE (tenant_id,task_id),
  CHECK ((state='ACCEPTED')=(receipt IS NOT NULL)),
  CHECK (receipt IS NULL OR (
    receipt->>'schema_version'='agenttrust.marketplace-action-receipt.v1'
    AND receipt->>'action_id'=action_id::text
    AND receipt->>'task_id'=task_id::text
    AND receipt->>'accepted'='true'
    AND receipt->>'execution_pending'='true'
  ))
);

CREATE TABLE IF NOT EXISTS marketplace_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._:/-]+$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  action_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  policy_decision_id text NOT NULL CHECK (length(policy_decision_id) BETWEEN 1 AND 256),
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[a-f0-9]{64}$'),
  ledger_entry_id text NOT NULL CHECK (length(ledger_entry_id) BETWEEN 1 AND 256),
  ledger_entry_digest char(64) NOT NULL CHECK (ledger_entry_digest ~ '^[a-f0-9]{64}$'),
  ledger_execution_id uuid NOT NULL,
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 256),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  authorization_evidence_ref text NOT NULL CHECK (authorization_evidence_ref LIKE 'urn:agenttrust:%' AND length(authorization_evidence_ref)<=2048),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[a-f0-9]{64}$'),
  trace_id text NOT NULL CHECK (length(trace_id) BETWEEN 1 AND 256),
  request jsonb NOT NULL CHECK (
    request->>'schema_version'='agenttrust.marketplace-executor-request.v1'
    AND request #>> '{command,command_id}'=action_id::text
    AND request #>> '{command,resource_id}'=resource_id
    AND request #>> '{command,tenant_id}'=tenant_id::text
  ),
  state text NOT NULL CHECK (state IN ('PREPARED','EXECUTING','SUCCEEDED','FAILED','UNKNOWN')),
  safe_result jsonb,
  safe_result_digest char(64),
  stable_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,ledger_execution_id),
  UNIQUE (tenant_id,action_hash,fence_digest),
  CHECK ((state='SUCCEEDED')=(safe_result IS NOT NULL)),
  CHECK ((state='SUCCEEDED')=(safe_result_digest IS NOT NULL)),
  CHECK (safe_result_digest IS NULL OR safe_result_digest ~ '^[a-f0-9]{64}$'),
  CHECK ((state='FAILED')=(stable_error IS NOT NULL)),
  CHECK (safe_result IS NULL OR safe_result->>'schema_version'='agenttrust.marketplace-mutation-result.v1')
);

CREATE TABLE IF NOT EXISTS marketplace_evidence_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 256),
  event_type text NOT NULL CHECK (event_type ~ '^MARKETPLACE_[A-Z_]{3,120}$'),
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
  payload jsonb NOT NULL CHECK (
    payload->>'schema_version'='agenttrust.marketplace-lifecycle-evidence.v1'
    AND payload->>'event_id'=event_id::text
    AND payload->>'tenant_id'=tenant_id::text
    AND payload->>'resource_id'=resource_id
    AND payload->>'principal_subject'=actor_subject
  ),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  evidence_ref text NOT NULL CHECK (evidence_ref LIKE 'urn:agenttrust:marketplace-evidence:%'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,evidence_ref)
);

CREATE TABLE IF NOT EXISTS marketplace_evidence_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type='MARKETPLACE_LIFECYCLE_EVIDENCE'),
  aggregate_id text NOT NULL CHECK (length(aggregate_id) BETWEEN 1 AND 256),
  payload jsonb NOT NULL,
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  PRIMARY KEY (tenant_id,event_id),
  FOREIGN KEY (tenant_id,event_id) REFERENCES marketplace_evidence_events (tenant_id,event_id),
  CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE OR REPLACE FUNCTION enforce_marketplace_publisher_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.publisher_id<>NEW.publisher_id
     OR OLD.owner_subject<>NEW.owner_subject OR OLD.identity_digest<>NEW.identity_digest
     OR OLD.responsibility_contact<>NEW.responsibility_contact OR OLD.home_region<>NEW.home_region
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_PUBLISHER_IDENTITY_IMMUTABLE';
  END IF;
  IF NOT ((OLD.trust_status='UNTRUSTED' AND NEW.trust_status IN ('VERIFIED','SUSPENDED','REVOKED'))
       OR (OLD.trust_status='VERIFIED' AND NEW.trust_status IN ('SUSPENDED','REVOKED'))
       OR (OLD.trust_status='SUSPENDED' AND NEW.trust_status IN ('VERIFIED','REVOKED'))) THEN
    RAISE EXCEPTION 'MARKETPLACE_PUBLISHER_TRANSITION_INVALID';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_publisher_key_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.publisher_id<>NEW.publisher_id OR OLD.key_id<>NEW.key_id
     OR OLD.algorithm<>NEW.algorithm OR OLD.public_key<>NEW.public_key
     OR OLD.key_fingerprint<>NEW.key_fingerprint OR OLD.not_before<>NEW.not_before
     OR OLD.expires_at<>NEW.expires_at OR OLD.reviewed_by<>NEW.reviewed_by
     OR OLD.review_digest<>NEW.review_digest OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_PUBLISHER_KEY_IMMUTABLE';
  END IF;
  IF NOT (OLD.status IN ('ACTIVE','VERIFY_ONLY') AND NEW.status='REVOKED') THEN
    RAISE EXCEPTION 'MARKETPLACE_PUBLISHER_KEY_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_release_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.release_id<>NEW.release_id OR OLD.pack_id<>NEW.pack_id
     OR OLD.version<>NEW.version OR OLD.publisher_id<>NEW.publisher_id OR OLD.manifest<>NEW.manifest
     OR OLD.pack_digest<>NEW.pack_digest OR OLD.permission_digest<>NEW.permission_digest
     OR OLD.release_certificate<>NEW.release_certificate OR OLD.certificate_digest<>NEW.certificate_digest
     OR OLD.visibility<>NEW.visibility OR OLD.entitlement<>NEW.entitlement
     OR OLD.allowed_regions<>NEW.allowed_regions OR OLD.risk_rating<>NEW.risk_rating
     OR OLD.minimum_publisher_trust<>NEW.minimum_publisher_trust
     OR OLD.minimum_control_plane_version<>NEW.minimum_control_plane_version
     OR OLD.submitted_by<>NEW.submitted_by OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_RELEASE_ARTIFACT_IMMUTABLE';
  END IF;
  IF NOT ((OLD.review_status='SUBMITTED' AND NEW.review_status IN ('PUBLISHED','REJECTED','REVOKED'))
       OR (OLD.review_status='PUBLISHED' AND NEW.review_status='REVOKED')) THEN
    RAISE EXCEPTION 'MARKETPLACE_RELEASE_TRANSITION_INVALID';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_installation_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.installation_id<>NEW.installation_id
     OR OLD.release_id<>NEW.release_id OR OLD.pack_id<>NEW.pack_id OR OLD.version<>NEW.version
     OR OLD.pack_digest<>NEW.pack_digest OR OLD.environment<>NEW.environment
     OR OLD.requester_subject<>NEW.requester_subject OR OLD.request_reason_digest<>NEW.request_reason_digest
     OR OLD.permission_digest<>NEW.permission_digest OR OLD.permission_diff<>NEW.permission_diff
     OR OLD.permission_expansion<>NEW.permission_expansion OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_INSTALLATION_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state='PENDING_APPROVAL' AND NEW.state IN ('APPROVED','REJECTED','REVOKED'))
       OR (OLD.state='APPROVED' AND NEW.state IN ('INSTALLED','REVOKED'))
       OR (OLD.state='INSTALLED' AND NEW.state IN ('ACTIVE','REVOKED'))
       OR (OLD.state='ACTIVE' AND NEW.state IN ('INACTIVE','ROLLED_BACK','REVOKED'))
       OR (OLD.state='INACTIVE' AND NEW.state IN ('ACTIVE','REVOKED'))) THEN
    RAISE EXCEPTION 'MARKETPLACE_INSTALLATION_TRANSITION_INVALID';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_upgrade_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.plan_id<>NEW.plan_id OR OLD.pack_id<>NEW.pack_id
     OR OLD.environment<>NEW.environment OR OLD.current_installation_id<>NEW.current_installation_id
     OR OLD.target_installation_id<>NEW.target_installation_id OR OLD.current_version<>NEW.current_version
     OR OLD.target_version<>NEW.target_version OR OLD.permission_expansion<>NEW.permission_expansion
     OR OLD.migration_digest<>NEW.migration_digest OR OLD.rollback_digest<>NEW.rollback_digest
     OR OLD.canary_percent<>NEW.canary_percent OR OLD.planned_by<>NEW.planned_by
     OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_UPGRADE_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state='PLANNED' AND NEW.state IN ('CANARY_PASSED','CANARY_FAILED'))
       OR (OLD.state='CANARY_PASSED' AND NEW.state='COMPLETED')
       OR (OLD.state='COMPLETED' AND NEW.state='ROLLED_BACK')) THEN
    RAISE EXCEPTION 'MARKETPLACE_UPGRADE_TRANSITION_INVALID';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_resource_fence()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.resource_id<>NEW.resource_id
     OR NEW.resource_version<>OLD.resource_version+1 OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_RESOURCE_FENCE_INVALID';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_ingress_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.idempotency_key<>NEW.idempotency_key
     OR OLD.request_digest<>NEW.request_digest OR OLD.action_id<>NEW.action_id
     OR OLD.task_id<>NEW.task_id OR OLD.resource_id<>NEW.resource_id
     OR OLD.principal_subject<>NEW.principal_subject
     OR OLD.principal_assertion_digest<>NEW.principal_assertion_digest
     OR OLD.envelope<>NEW.envelope OR OLD.created_at<>NEW.created_at
     OR NOT (OLD.state='PREPARED' AND NEW.state='ACCEPTED') THEN
    RAISE EXCEPTION 'MARKETPLACE_INGRESS_BINDING_IMMUTABLE';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enforce_marketplace_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.tenant_id<>NEW.tenant_id OR OLD.idempotency_key<>NEW.idempotency_key
     OR OLD.request_digest<>NEW.request_digest OR OLD.action_id<>NEW.action_id
     OR OLD.action_hash<>NEW.action_hash OR OLD.policy_decision_id<>NEW.policy_decision_id
     OR OLD.policy_decision_digest<>NEW.policy_decision_digest OR OLD.ledger_entry_id<>NEW.ledger_entry_id
     OR OLD.ledger_entry_digest<>NEW.ledger_entry_digest OR OLD.ledger_execution_id<>NEW.ledger_execution_id
     OR OLD.fence_digest<>NEW.fence_digest OR OLD.resource_id<>NEW.resource_id
     OR OLD.resource_version<>NEW.resource_version OR OLD.authorization_evidence_ref<>NEW.authorization_evidence_ref
     OR OLD.authorization_evidence_digest<>NEW.authorization_evidence_digest
     OR OLD.trace_id<>NEW.trace_id OR OLD.request<>NEW.request OR OLD.created_at<>NEW.created_at THEN
    RAISE EXCEPTION 'MARKETPLACE_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  IF NOT ((OLD.state='PREPARED' AND NEW.state IN ('EXECUTING','FAILED'))
       OR (OLD.state='EXECUTING' AND NEW.state IN ('SUCCEEDED','FAILED','UNKNOWN'))) THEN
    RAISE EXCEPTION 'MARKETPLACE_EXECUTION_TRANSITION_INVALID';
  END IF;
  NEW.updated_at:=now();
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION reject_marketplace_immutable_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  RAISE EXCEPTION 'MARKETPLACE_IMMUTABLE_RECORD';
END $$;

DROP TRIGGER IF EXISTS marketplace_publisher_transition_guard ON marketplace_publishers;
CREATE TRIGGER marketplace_publisher_transition_guard BEFORE UPDATE ON marketplace_publishers
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_publisher_transition();
DROP TRIGGER IF EXISTS marketplace_publisher_key_transition_guard ON marketplace_publisher_keys;
CREATE TRIGGER marketplace_publisher_key_transition_guard BEFORE UPDATE ON marketplace_publisher_keys
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_publisher_key_transition();
DROP TRIGGER IF EXISTS marketplace_release_transition_guard ON marketplace_releases;
CREATE TRIGGER marketplace_release_transition_guard BEFORE UPDATE ON marketplace_releases
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_release_transition();
DROP TRIGGER IF EXISTS marketplace_installation_transition_guard ON marketplace_installations;
CREATE TRIGGER marketplace_installation_transition_guard BEFORE UPDATE ON marketplace_installations
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_installation_transition();
DROP TRIGGER IF EXISTS marketplace_upgrade_transition_guard ON marketplace_upgrade_plans;
CREATE TRIGGER marketplace_upgrade_transition_guard BEFORE UPDATE ON marketplace_upgrade_plans
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_upgrade_transition();
DROP TRIGGER IF EXISTS marketplace_resource_fence_guard ON marketplace_resource_versions;
CREATE TRIGGER marketplace_resource_fence_guard BEFORE UPDATE ON marketplace_resource_versions
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_resource_fence();
DROP TRIGGER IF EXISTS marketplace_ingress_transition_guard ON marketplace_action_ingress;
CREATE TRIGGER marketplace_ingress_transition_guard BEFORE UPDATE ON marketplace_action_ingress
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_ingress_transition();
DROP TRIGGER IF EXISTS marketplace_execution_transition_guard ON marketplace_authority_executions;
CREATE TRIGGER marketplace_execution_transition_guard BEFORE UPDATE ON marketplace_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_marketplace_execution_transition();
DROP TRIGGER IF EXISTS marketplace_evidence_immutable_guard ON marketplace_evidence_events;
CREATE TRIGGER marketplace_evidence_immutable_guard BEFORE UPDATE OR DELETE ON marketplace_evidence_events
FOR EACH ROW EXECUTE FUNCTION reject_marketplace_immutable_change();

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'marketplace_publishers','marketplace_publisher_keys','marketplace_pack_names',
    'marketplace_tenant_catalog','marketplace_releases','marketplace_installations',
    'marketplace_upgrade_plans','marketplace_canary_results','marketplace_revocations',
    'marketplace_resource_versions','marketplace_principal_assertion_replay',
    'marketplace_action_ingress','marketplace_authority_executions',
    'marketplace_evidence_events','marketplace_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I',table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING '
      '(tenant_id::text=current_setting(''app.tenant_id'',true)) WITH CHECK '
      '(tenant_id::text=current_setting(''app.tenant_id'',true))',table_name
    );
  END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS marketplace_releases_catalog_idx
  ON marketplace_releases (tenant_id,pack_id,version,review_status);
CREATE INDEX IF NOT EXISTS marketplace_installations_state_idx
  ON marketplace_installations (tenant_id,pack_id,environment,state,updated_at DESC);
CREATE INDEX IF NOT EXISTS marketplace_upgrade_state_idx
  ON marketplace_upgrade_plans (tenant_id,state,updated_at);
CREATE INDEX IF NOT EXISTS marketplace_revocations_digest_idx
  ON marketplace_revocations (tenant_id,pack_digest);
CREATE INDEX IF NOT EXISTS marketplace_assertion_expiry_idx
  ON marketplace_principal_assertion_replay (expires_at);
CREATE INDEX IF NOT EXISTS marketplace_execution_state_idx
  ON marketplace_authority_executions (tenant_id,state,updated_at);
CREATE INDEX IF NOT EXISTS marketplace_evidence_outbox_pending_idx
  ON marketplace_evidence_outbox (tenant_id,created_at) WHERE published_at IS NULL;

REVOKE ALL ON TABLE marketplace_publishers,marketplace_publisher_keys,marketplace_pack_names,
  marketplace_tenant_catalog,marketplace_releases,marketplace_installations,
  marketplace_upgrade_plans,marketplace_canary_results,marketplace_revocations,
  marketplace_resource_versions,marketplace_principal_assertion_replay,
  marketplace_action_ingress,marketplace_authority_executions,
  marketplace_evidence_events,marketplace_evidence_outbox FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_publisher_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_publisher_key_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_release_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_installation_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_upgrade_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_resource_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_ingress_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_marketplace_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_marketplace_immutable_change() FROM PUBLIC;

-- The production migration runner provisions the NOINHERIT LOGIN role and the exact
-- table/column grant matrix. No credential is created by this migration.
COMMIT;
