BEGIN;

-- Batch 34 production closure.  The original three tables did not carry a tenant binding or
-- immutable execution facts.  Move them without data loss to an owner-only schema for explicit
-- re-import, and create the tenant-scoped authority model in public.  Legacy rows are never
-- silently trusted or exposed to the runtime role.
CREATE SCHEMA IF NOT EXISTS agenttrust_legacy_sre;
REVOKE ALL ON SCHEMA agenttrust_legacy_sre FROM PUBLIC;
DO $legacy_tables$
BEGIN
  IF to_regclass('agenttrust_legacy_sre.backup_manifests') IS NULL THEN
    IF to_regclass('public.backup_manifests') IS NULL THEN
      RAISE EXCEPTION 'SRE_LEGACY_BACKUP_MANIFESTS_MISSING';
    END IF;
    ALTER TABLE public.backup_manifests SET SCHEMA agenttrust_legacy_sre;
  END IF;
  IF to_regclass('agenttrust_legacy_sre.recovery_drills') IS NULL THEN
    IF to_regclass('public.recovery_drills') IS NULL THEN
      RAISE EXCEPTION 'SRE_LEGACY_RECOVERY_DRILLS_MISSING';
    END IF;
    ALTER TABLE public.recovery_drills SET SCHEMA agenttrust_legacy_sre;
  END IF;
  IF to_regclass('agenttrust_legacy_sre.deployment_rollouts') IS NULL THEN
    IF to_regclass('public.deployment_rollouts') IS NULL THEN
      RAISE EXCEPTION 'SRE_LEGACY_DEPLOYMENT_ROLLOUTS_MISSING';
    END IF;
    ALTER TABLE public.deployment_rollouts SET SCHEMA agenttrust_legacy_sre;
  END IF;
END
$legacy_tables$;
REVOKE ALL ON TABLE agenttrust_legacy_sre.backup_manifests,
  agenttrust_legacy_sre.recovery_drills,
  agenttrust_legacy_sre.deployment_rollouts FROM PUBLIC;

CREATE TABLE IF NOT EXISTS sre_legacy_quarantine (
  quarantine_id bigserial PRIMARY KEY,
  source_table text NOT NULL,
  legacy_record jsonb NOT NULL,
  quarantine_reason text NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO sre_legacy_quarantine(source_table,legacy_record,quarantine_reason)
SELECT 'backup_manifests',to_jsonb(value),'LEGACY_TENANT_OR_CONTROL_BINDING_MISSING'
FROM agenttrust_legacy_sre.backup_manifests value
WHERE NOT EXISTS (
  SELECT 1 FROM sre_legacy_quarantine quarantine
  WHERE quarantine.source_table='backup_manifests'
    AND quarantine.legacy_record=to_jsonb(value)
);
INSERT INTO sre_legacy_quarantine(source_table,legacy_record,quarantine_reason)
SELECT 'recovery_drills',to_jsonb(value),'LEGACY_TENANT_OR_CONTROL_BINDING_MISSING'
FROM agenttrust_legacy_sre.recovery_drills value
WHERE NOT EXISTS (
  SELECT 1 FROM sre_legacy_quarantine quarantine
  WHERE quarantine.source_table='recovery_drills'
    AND quarantine.legacy_record=to_jsonb(value)
);
INSERT INTO sre_legacy_quarantine(source_table,legacy_record,quarantine_reason)
SELECT 'deployment_rollouts',to_jsonb(value),'LEGACY_TENANT_OR_CONTROL_BINDING_MISSING'
FROM agenttrust_legacy_sre.deployment_rollouts value
WHERE NOT EXISTS (
  SELECT 1 FROM sre_legacy_quarantine quarantine
  WHERE quarantine.source_table='deployment_rollouts'
    AND quarantine.legacy_record=to_jsonb(value)
);

CREATE TABLE IF NOT EXISTS sre_service_slos (
  tenant_id uuid NOT NULL,
  slo_id uuid NOT NULL,
  service text NOT NULL CHECK (service ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
  sli_kind text NOT NULL CHECK (sli_kind IN (
    'AVAILABILITY','AUTHORIZATION_LATENCY','UNSAFE_ALLOW','EVIDENCE_COMPLETENESS',
    'RECOVERY_TIME','RECOVERY_POINT','BACKPRESSURE_REJECTION'
  )),
  window_seconds bigint NOT NULL CHECK (window_seconds BETWEEN 60 AND 2592000),
  target_millionths integer NOT NULL CHECK (target_millionths BETWEEN 1 AND 1000000),
  minimum_samples bigint NOT NULL CHECK (minimum_samples BETWEEN 1 AND 1000000000),
  fast_burn_threshold_millionths integer NOT NULL CHECK (fast_burn_threshold_millionths BETWEEN 1 AND 1000000000),
  slow_burn_threshold_millionths integer NOT NULL CHECK (slow_burn_threshold_millionths BETWEEN 1 AND 1000000000),
  release_blocking boolean NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','PAUSED','RETIRED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,slo_id),
  UNIQUE (tenant_id,service,sli_kind),
  CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE TABLE IF NOT EXISTS sre_sli_observations (
  tenant_id uuid NOT NULL,
  observation_id uuid NOT NULL,
  slo_id uuid NOT NULL,
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  good_events bigint NOT NULL CHECK (good_events >= 0),
  total_events bigint NOT NULL CHECK (total_events >= good_events),
  window_started_at timestamptz NOT NULL,
  window_ended_at timestamptz NOT NULL,
  trace_evidence_ref text NOT NULL,
  metrics_evidence_ref text NOT NULL,
  logs_evidence_ref text NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,observation_id),
  UNIQUE (tenant_id,slo_id,window_started_at,window_ended_at,release_digest),
  FOREIGN KEY (tenant_id,slo_id) REFERENCES sre_service_slos(tenant_id,slo_id),
  CHECK (window_ended_at > window_started_at),
  CHECK (trace_evidence_ref ~ '^evidence://'),
  CHECK (metrics_evidence_ref ~ '^evidence://'),
  CHECK (logs_evidence_ref ~ '^evidence://')
);

CREATE TABLE IF NOT EXISTS sre_burn_alerts (
  tenant_id uuid NOT NULL,
  alert_id uuid NOT NULL,
  slo_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('OPEN','ACKNOWLEDGED','MITIGATING','RESOLVED')),
  burn_rate_millionths bigint NOT NULL CHECK (burn_rate_millionths >= 0),
  severity text NOT NULL CHECK (severity IN ('WARNING','CRITICAL')),
  opened_from_observation_id uuid NOT NULL,
  owner_subject text,
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  opened_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  PRIMARY KEY (tenant_id,alert_id),
  FOREIGN KEY (tenant_id,slo_id) REFERENCES sre_service_slos(tenant_id,slo_id),
  FOREIGN KEY (tenant_id,opened_from_observation_id) REFERENCES sre_sli_observations(tenant_id,observation_id),
  CHECK ((state='OPEN' AND owner_subject IS NULL AND resolved_at IS NULL)
      OR (state IN ('ACKNOWLEDGED','MITIGATING') AND owner_subject IS NOT NULL AND resolved_at IS NULL)
      OR (state='RESOLVED' AND owner_subject IS NOT NULL AND resolved_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS sre_incident_links (
  tenant_id uuid NOT NULL,
  link_id uuid NOT NULL,
  alert_id uuid NOT NULL,
  incident_id uuid NOT NULL,
  incident_evidence_ref text NOT NULL CHECK (incident_evidence_ref ~ '^evidence://'),
  linked_by text NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,link_id),
  UNIQUE (tenant_id,alert_id,incident_id),
  FOREIGN KEY (tenant_id,alert_id) REFERENCES sre_burn_alerts(tenant_id,alert_id)
);

CREATE TABLE IF NOT EXISTS sre_deployment_topologies (
  tenant_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  deployment_mode text NOT NULL CHECK (deployment_mode IN ('SAAS','PRIVATE','OFFLINE','EDGE_HYBRID')),
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  topology_digest char(64) NOT NULL CHECK (topology_digest ~ '^[0-9a-f]{64}$'),
  zones text[] NOT NULL,
  components jsonb NOT NULL,
  quorum_rules jsonb NOT NULL,
  disruption_budgets jsonb NOT NULL,
  immutable_image_digests jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('REGISTERED','HEALTHY','DEGRADED','FAILED','RETIRED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,topology_id),
  UNIQUE (tenant_id,topology_digest),
  CHECK (cardinality(zones) BETWEEN 1 AND 32),
  CHECK (jsonb_typeof(components)='object' AND jsonb_typeof(quorum_rules)='object'
      AND jsonb_typeof(disruption_budgets)='object' AND jsonb_typeof(immutable_image_digests)='object')
);

CREATE TABLE IF NOT EXISTS sre_zone_health_observations (
  tenant_id uuid NOT NULL,
  observation_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  zone text NOT NULL,
  component_health jsonb NOT NULL,
  dependency_health jsonb NOT NULL,
  ready_replicas integer NOT NULL CHECK (ready_replicas >= 0),
  required_replicas integer NOT NULL CHECK (required_replicas > 0),
  topology_probe_digest char(64) NOT NULL CHECK (topology_probe_digest ~ '^[0-9a-f]{64}$'),
  external_evidence_status text NOT NULL CHECK (external_evidence_status IN ('NOT_RUN','OBSERVED','VERIFIED')),
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,observation_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (jsonb_typeof(component_health)='object' AND jsonb_typeof(dependency_health)='object')
);

CREATE TABLE IF NOT EXISTS backup_manifests (
  tenant_id uuid NOT NULL,
  backup_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  scope_digest char(64) NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
  database_lsn text NOT NULL,
  database_artifact_digest char(64) NOT NULL CHECK (database_artifact_digest ~ '^[0-9a-f]{64}$'),
  object_manifest_digest char(64) NOT NULL CHECK (object_manifest_digest ~ '^[0-9a-f]{64}$'),
  ledger_head_digest char(64) NOT NULL CHECK (ledger_head_digest ~ '^[0-9a-f]{64}$'),
  worm_retention_until timestamptz NOT NULL,
  key_version text NOT NULL,
  key_recovery_evidence_ref text NOT NULL CHECK (key_recovery_evidence_ref ~ '^evidence://'),
  record_counts jsonb NOT NULL,
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  signature_key_id text NOT NULL,
  signature text NOT NULL,
  external_evidence_status text NOT NULL CHECK (external_evidence_status IN ('NOT_RUN','OBSERVED','VERIFIED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,backup_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (worm_retention_until > created_at),
  CHECK (jsonb_typeof(record_counts)='object'),
  CHECK (length(signature) BETWEEN 64 AND 1024)
);

CREATE TABLE IF NOT EXISTS sre_backup_artifacts (
  tenant_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  backup_id uuid NOT NULL,
  artifact_kind text NOT NULL CHECK (artifact_kind IN ('DATABASE','OBJECT_MANIFEST','LEDGER_HEAD','KEY_RECOVERY')),
  immutable_ref text NOT NULL,
  artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  encryption_key_version text NOT NULL,
  worm_locked boolean NOT NULL CHECK (worm_locked),
  evidence_ref text NOT NULL CHECK (evidence_ref ~ '^evidence://'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,artifact_id),
  UNIQUE (tenant_id,backup_id,artifact_kind),
  FOREIGN KEY (tenant_id,backup_id) REFERENCES backup_manifests(tenant_id,backup_id)
);

CREATE TABLE IF NOT EXISTS recovery_drills (
  tenant_id uuid NOT NULL,
  drill_id uuid NOT NULL,
  backup_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  isolated_environment_ref text NOT NULL CHECK (isolated_environment_ref !~* '(^|[/:-])prod(uction)?($|[/:-])'),
  restore_target_digest char(64) NOT NULL CHECK (restore_target_digest ~ '^[0-9a-f]{64}$'),
  expected_record_counts jsonb NOT NULL,
  restored_record_counts jsonb NOT NULL,
  object_integrity_passed boolean NOT NULL,
  ledger_reconciled boolean NOT NULL,
  key_recovery_passed boolean NOT NULL,
  measured_rto_seconds bigint NOT NULL CHECK (measured_rto_seconds >= 0),
  measured_rpo_seconds bigint NOT NULL CHECK (measured_rpo_seconds >= 0),
  report_digest char(64) NOT NULL CHECK (report_digest ~ '^[0-9a-f]{64}$'),
  command_digest char(64) NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
  external_evidence_status text NOT NULL CHECK (external_evidence_status IN ('NOT_RUN','OBSERVED','VERIFIED')),
  passed boolean NOT NULL,
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,drill_id),
  FOREIGN KEY (tenant_id,backup_id) REFERENCES backup_manifests(tenant_id,backup_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (completed_at >= started_at),
  CHECK (NOT passed OR (object_integrity_passed AND ledger_reconciled AND key_recovery_passed
      AND expected_record_counts=restored_record_counts)),
  CHECK (jsonb_typeof(expected_record_counts)='object' AND jsonb_typeof(restored_record_counts)='object')
);

CREATE TABLE IF NOT EXISTS sre_dr_plans (
  tenant_id uuid NOT NULL,
  plan_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  recovery_drill_id uuid NOT NULL,
  source_zones text[] NOT NULL,
  target_zones text[] NOT NULL,
  maximum_rto_seconds bigint NOT NULL CHECK (maximum_rto_seconds > 0),
  maximum_rpo_seconds bigint NOT NULL CHECK (maximum_rpo_seconds >= 0),
  failover_steps jsonb NOT NULL,
  failback_steps jsonb NOT NULL,
  health_checks jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT','READY','FAILING_OVER','FAILED_OVER','FAILING_BACK','COMPLETED','FAILED','UNKNOWN')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,plan_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  FOREIGN KEY (tenant_id,recovery_drill_id) REFERENCES recovery_drills(tenant_id,drill_id),
  CHECK (cardinality(source_zones) BETWEEN 1 AND 32 AND cardinality(target_zones) BETWEEN 1 AND 32),
  CHECK (NOT source_zones && target_zones),
  CHECK (jsonb_typeof(failover_steps)='array' AND jsonb_array_length(failover_steps)>0),
  CHECK (jsonb_typeof(failback_steps)='array' AND jsonb_array_length(failback_steps)>0),
  CHECK (jsonb_typeof(health_checks)='array' AND jsonb_array_length(health_checks)>0)
);

CREATE TABLE IF NOT EXISTS sre_dr_events (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  plan_id uuid NOT NULL,
  phase text NOT NULL CHECK (phase IN ('FAILOVER','FAILBACK')),
  from_state text NOT NULL,
  to_state text NOT NULL,
  adapter_receipt_digest char(64) NOT NULL CHECK (adapter_receipt_digest ~ '^[0-9a-f]{64}$'),
  health_evidence_ref text NOT NULL CHECK (health_evidence_ref ~ '^evidence://'),
  measured_rto_seconds bigint NOT NULL CHECK (measured_rto_seconds >= 0),
  measured_rpo_seconds bigint NOT NULL CHECK (measured_rpo_seconds >= 0),
  external_evidence_status text NOT NULL CHECK (external_evidence_status IN ('NOT_RUN','OBSERVED','VERIFIED')),
  succeeded boolean NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,plan_id,phase,adapter_receipt_digest),
  FOREIGN KEY (tenant_id,plan_id) REFERENCES sre_dr_plans(tenant_id,plan_id)
);

CREATE TABLE IF NOT EXISTS sre_chaos_campaigns (
  tenant_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  environment_ref text NOT NULL,
  fault_types text[] NOT NULL,
  fault_budget_seconds integer NOT NULL CHECK (fault_budget_seconds BETWEEN 1 AND 3600),
  blast_radius jsonb NOT NULL,
  abort_conditions jsonb NOT NULL,
  cleanup_plan_digest char(64) NOT NULL CHECK (cleanup_plan_digest ~ '^[0-9a-f]{64}$'),
  production_target_allowed boolean NOT NULL DEFAULT false,
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RUNNING','ABORTING','COMPLETED','FAILED','CLEANUP_FAILED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (cardinality(fault_types) BETWEEN 1 AND 16),
  CHECK (fault_types <@ ARRAY['PROCESS_KILL','LATENCY','PACKET_LOSS','NETWORK_PARTITION','DISK_FULL','CLOCK_DRIFT','CPU_EXHAUSTION','MEMORY_EXHAUSTION','CERTIFICATE_FAILURE','KEY_ROTATION_FAILURE','STORAGE_FAILURE','MESSAGE_BACKLOG']::text[]),
  CHECK (jsonb_typeof(blast_radius)='object' AND jsonb_typeof(abort_conditions)='array')
);

CREATE TABLE IF NOT EXISTS sre_chaos_results (
  tenant_id uuid NOT NULL,
  result_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  fault_type text NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  safety_abort_triggered boolean NOT NULL,
  cleanup_verified boolean NOT NULL,
  dependency_failure_semantics_verified boolean NOT NULL,
  emergency_stop_verified boolean NOT NULL,
  production_evidence boolean NOT NULL DEFAULT false,
  command_digest char(64) NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
  report_digest char(64) NOT NULL CHECK (report_digest ~ '^[0-9a-f]{64}$'),
  evidence_refs text[] NOT NULL,
  PRIMARY KEY (tenant_id,result_id),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES sre_chaos_campaigns(tenant_id,campaign_id),
  CHECK (completed_at >= started_at),
  CHECK (cardinality(evidence_refs) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS sre_load_campaigns (
  tenant_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  workload_digest char(64) NOT NULL CHECK (workload_digest ~ '^[0-9a-f]{64}$'),
  duration_seconds integer NOT NULL CHECK (duration_seconds BETWEEN 60 AND 604800),
  concurrency integer NOT NULL CHECK (concurrency BETWEEN 1 AND 1000000),
  maximum_requests bigint NOT NULL CHECK (maximum_requests BETWEEN 1 AND 10000000000),
  tenant_quota jsonb NOT NULL,
  stop_conditions jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','RUNNING','COMPLETED','FAILED','ABORTED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,campaign_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (jsonb_typeof(tenant_quota)='object' AND jsonb_typeof(stop_conditions)='array')
);

CREATE TABLE IF NOT EXISTS sre_load_results (
  tenant_id uuid NOT NULL,
  result_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  requests bigint NOT NULL CHECK (requests > 0),
  success_millionths integer NOT NULL CHECK (success_millionths BETWEEN 0 AND 1000000),
  p50_milliseconds bigint NOT NULL CHECK (p50_milliseconds >= 0),
  p95_milliseconds bigint NOT NULL CHECK (p95_milliseconds >= p50_milliseconds),
  p99_milliseconds bigint NOT NULL CHECK (p99_milliseconds >= p95_milliseconds),
  throughput_millionths bigint NOT NULL CHECK (throughput_millionths >= 0),
  backpressure_rejections bigint NOT NULL CHECK (backpressure_rejections >= 0),
  noisy_neighbor_isolation_passed boolean NOT NULL,
  production_evidence boolean NOT NULL DEFAULT false,
  report_digest char(64) NOT NULL CHECK (report_digest ~ '^[0-9a-f]{64}$'),
  evidence_refs text[] NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,result_id),
  UNIQUE (tenant_id,campaign_id,report_digest),
  FOREIGN KEY (tenant_id,campaign_id) REFERENCES sre_load_campaigns(tenant_id,campaign_id),
  CHECK (completed_at > started_at),
  CHECK (cardinality(evidence_refs) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS deployment_rollouts (
  tenant_id uuid NOT NULL,
  rollout_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  from_release_digest char(64) NOT NULL CHECK (from_release_digest ~ '^[0-9a-f]{64}$'),
  to_release_digest char(64) NOT NULL CHECK (to_release_digest ~ '^[0-9a-f]{64}$'),
  schema_compatible boolean NOT NULL,
  api_compatible boolean NOT NULL,
  policy_compatible boolean NOT NULL,
  pack_compatible boolean NOT NULL,
  migration_digest char(64) NOT NULL CHECK (migration_digest ~ '^[0-9a-f]{64}$'),
  rollback_digest char(64) NOT NULL CHECK (rollback_digest ~ '^[0-9a-f]{64}$'),
  canary_steps integer[] NOT NULL,
  current_canary_percent integer NOT NULL CHECK (current_canary_percent BETWEEN 0 AND 100),
  maximum_error_rate_millionths integer NOT NULL CHECK (maximum_error_rate_millionths BETWEEN 0 AND 1000000),
  status text NOT NULL CHECK (status IN ('PLANNED','CANARY','PROMOTED','ROLLING_BACK','ROLLED_BACK','FAILED')),
  resource_version bigint NOT NULL CHECK (resource_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,rollout_id),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (from_release_digest <> to_release_digest),
  CHECK (cardinality(canary_steps) BETWEEN 1 AND 20),
  CHECK (0 < ALL(canary_steps) AND 100 >= ALL(canary_steps)),
  CHECK (schema_compatible AND api_compatible AND policy_compatible AND pack_compatible)
);

CREATE TABLE IF NOT EXISTS sre_canary_observations (
  tenant_id uuid NOT NULL,
  observation_id uuid NOT NULL,
  rollout_id uuid NOT NULL,
  canary_percent integer NOT NULL CHECK (canary_percent BETWEEN 1 AND 100),
  error_rate_millionths integer NOT NULL CHECK (error_rate_millionths BETWEEN 0 AND 1000000),
  unsafe_allow_count bigint NOT NULL CHECK (unsafe_allow_count >= 0),
  evidence_gap_count bigint NOT NULL CHECK (evidence_gap_count >= 0),
  rollback_triggered boolean NOT NULL,
  metrics_digest char(64) NOT NULL CHECK (metrics_digest ~ '^[0-9a-f]{64}$'),
  evidence_refs text[] NOT NULL,
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,observation_id),
  UNIQUE (tenant_id,rollout_id,canary_percent,metrics_digest),
  FOREIGN KEY (tenant_id,rollout_id) REFERENCES deployment_rollouts(tenant_id,rollout_id),
  CHECK (cardinality(evidence_refs) BETWEEN 1 AND 128),
  CHECK (NOT (unsafe_allow_count > 0 OR evidence_gap_count > 0) OR rollback_triggered)
);

CREATE TABLE IF NOT EXISTS sre_cost_capacity_observations (
  tenant_id uuid NOT NULL,
  observation_id uuid NOT NULL,
  topology_id uuid NOT NULL,
  release_digest char(64) NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
  period_started_at timestamptz NOT NULL,
  period_ended_at timestamptz NOT NULL,
  task_count bigint NOT NULL CHECK (task_count >= 0),
  request_count bigint NOT NULL CHECK (request_count >= 0),
  compute_microunits bigint NOT NULL CHECK (compute_microunits >= 0),
  storage_microunits bigint NOT NULL CHECK (storage_microunits >= 0),
  network_microunits bigint NOT NULL CHECK (network_microunits >= 0),
  model_microunits bigint NOT NULL CHECK (model_microunits >= 0),
  maximum_global_tasks bigint NOT NULL CHECK (maximum_global_tasks > 0),
  maximum_tasks_per_tenant bigint NOT NULL CHECK (maximum_tasks_per_tenant > 0),
  queue_capacity bigint NOT NULL CHECK (queue_capacity > 0),
  connection_pool_capacity bigint NOT NULL CHECK (connection_pool_capacity > 0),
  evidence_buffer_capacity bigint NOT NULL CHECK (evidence_buffer_capacity > 0),
  source_digest char(64) NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id,observation_id),
  UNIQUE (tenant_id,topology_id,period_started_at,period_ended_at,release_digest),
  FOREIGN KEY (tenant_id,topology_id) REFERENCES sre_deployment_topologies(tenant_id,topology_id),
  CHECK (period_ended_at > period_started_at),
  CHECK (maximum_tasks_per_tenant <= maximum_global_tasks)
);

CREATE TABLE IF NOT EXISTS sre_observability_evidence (
  tenant_id uuid NOT NULL,
  evidence_id uuid NOT NULL,
  resource text NOT NULL,
  trace_id text NOT NULL,
  trace_digest char(64) NOT NULL CHECK (trace_digest ~ '^[0-9a-f]{64}$'),
  log_digest char(64) NOT NULL CHECK (log_digest ~ '^[0-9a-f]{64}$'),
  metrics_digest char(64) NOT NULL CHECK (metrics_digest ~ '^[0-9a-f]{64}$'),
  redaction_policy_digest char(64) NOT NULL CHECK (redaction_policy_digest ~ '^[0-9a-f]{64}$'),
  immutable_refs text[] NOT NULL,
  collected_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,evidence_id),
  CHECK (cardinality(immutable_refs) BETWEEN 3 AND 128)
);

CREATE TABLE IF NOT EXISTS sre_resource_versions (
  tenant_id uuid NOT NULL,
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 1024),
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,resource)
);

CREATE TABLE IF NOT EXISTS sre_action_ingress (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  action_id uuid NOT NULL,
  task_id uuid NOT NULL,
  resource text NOT NULL,
  operation text NOT NULL,
  principal_subject text NOT NULL,
  principal_assertion_digest char(64) NOT NULL CHECK (principal_assertion_digest ~ '^[0-9a-f]{64}$'),
  envelope jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('PREPARED','ACCEPTED','REJECTED','UNKNOWN')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id),
  CHECK ((state='ACCEPTED' AND receipt IS NOT NULL) OR state<>'ACCEPTED')
);

CREATE TABLE IF NOT EXISTS sre_principal_assertion_replay (
  tenant_id uuid NOT NULL,
  jti uuid NOT NULL,
  assertion_digest char(64) NOT NULL CHECK (assertion_digest ~ '^[0-9a-f]{64}$'),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,jti)
);

CREATE TABLE IF NOT EXISTS sre_authority_executions (
  tenant_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  action_id uuid NOT NULL,
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  ledger_execution_id uuid NOT NULL,
  ledger_event_id uuid NOT NULL,
  ledger_event_digest char(64) NOT NULL CHECK (ledger_event_digest ~ '^[0-9a-f]{64}$'),
  fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[0-9a-f]{64}$'),
  resource text NOT NULL,
  resource_version bigint NOT NULL CHECK (resource_version >= 0),
  trace_id varchar(128) NOT NULL,
  policy_decision_id text NOT NULL,
  policy_decision_digest char(64) NOT NULL CHECK (policy_decision_digest ~ '^[0-9a-f]{64}$'),
  authorization_evidence_ref text NOT NULL CHECK (authorization_evidence_ref ~ '^evidence://'),
  authorization_evidence_digest char(64) NOT NULL CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
  request jsonb NOT NULL CHECK (request->>'schema_version'='agenttrust.sre-executor-request.v1'),
  state text NOT NULL CHECK (state IN ('PREPARED','SIDE_EFFECTS_PENDING','MUTATED_PENDING_EVIDENCE','SUCCEEDED','FAILED','UNKNOWN')),
  external_receipt jsonb,
  safe_result jsonb,
  evidence_request jsonb,
  evidence_ref text,
  evidence_digest char(64),
  stable_error varchar(128),
  execution_owner uuid NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,idempotency_key),
  UNIQUE (tenant_id,action_id),
  CHECK ((state='SUCCEEDED' AND safe_result IS NOT NULL AND evidence_ref IS NOT NULL AND evidence_digest IS NOT NULL)
      OR state<>'SUCCEEDED')
);

CREATE TABLE IF NOT EXISTS sre_evidence_outbox (
  tenant_id uuid NOT NULL,
  event_id uuid NOT NULL,
  idempotency_key varchar(128) NOT NULL,
  action_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  payload jsonb NOT NULL CHECK (payload->>'schema_version'='agenttrust.sre-lifecycle-evidence.v1'),
  payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts BETWEEN 0 AND 1000),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,event_id),
  UNIQUE (tenant_id,idempotency_key)
);

CREATE OR REPLACE FUNCTION enforce_sre_resource_fence()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF NEW.resource_version <> OLD.resource_version + 1
     OR NEW.action_hash=OLD.action_hash
     OR NEW.ledger_execution_id=OLD.ledger_execution_id
     OR NEW.ledger_event_id=OLD.ledger_event_id
     OR NEW.ledger_event_digest=OLD.ledger_event_digest
     OR NEW.fence_digest=OLD.fence_digest THEN
    RAISE EXCEPTION 'SRE_RESOURCE_FENCE_INVALID';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION enforce_sre_execution_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  IF OLD.state IN ('SUCCEEDED','FAILED','UNKNOWN')
     OR (OLD.state='PREPARED' AND NEW.state NOT IN ('SIDE_EFFECTS_PENDING','MUTATED_PENDING_EVIDENCE','FAILED','UNKNOWN'))
     OR (OLD.state='SIDE_EFFECTS_PENDING' AND NEW.state NOT IN ('MUTATED_PENDING_EVIDENCE','FAILED','UNKNOWN'))
     OR (OLD.state='MUTATED_PENDING_EVIDENCE' AND NEW.state NOT IN ('SUCCEEDED','UNKNOWN')) THEN
    RAISE EXCEPTION 'SRE_EXECUTION_TRANSITION_INVALID';
  END IF;
  IF NEW.request_digest<>OLD.request_digest OR NEW.action_id<>OLD.action_id
     OR NEW.action_hash<>OLD.action_hash OR NEW.ledger_execution_id<>OLD.ledger_execution_id
     OR NEW.ledger_event_id<>OLD.ledger_event_id OR NEW.ledger_event_digest<>OLD.ledger_event_digest
     OR NEW.fence_digest<>OLD.fence_digest OR NEW.resource<>OLD.resource
     OR NEW.resource_version<>OLD.resource_version OR NEW.trace_id<>OLD.trace_id
     OR NEW.policy_decision_id<>OLD.policy_decision_id
     OR NEW.policy_decision_digest<>OLD.policy_decision_digest
     OR NEW.authorization_evidence_ref<>OLD.authorization_evidence_ref
     OR NEW.authorization_evidence_digest<>OLD.authorization_evidence_digest
     OR NEW.request<>OLD.request THEN
    RAISE EXCEPTION 'SRE_EXECUTION_BINDING_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION reject_sre_immutable_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $function$
BEGIN
  RAISE EXCEPTION 'SRE_IMMUTABLE_RECORD';
END
$function$;

DROP TRIGGER IF EXISTS sre_resource_fence_guard ON sre_resource_versions;
CREATE TRIGGER sre_resource_fence_guard BEFORE UPDATE ON sre_resource_versions
FOR EACH ROW EXECUTE FUNCTION enforce_sre_resource_fence();
DROP TRIGGER IF EXISTS sre_execution_transition_guard ON sre_authority_executions;
CREATE TRIGGER sre_execution_transition_guard BEFORE UPDATE ON sre_authority_executions
FOR EACH ROW EXECUTE FUNCTION enforce_sre_execution_transition();

DO $immutability$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'sre_sli_observations','sre_incident_links','sre_zone_health_observations','sre_backup_artifacts',
    'sre_dr_events','sre_chaos_results','sre_load_results','sre_canary_observations',
    'sre_cost_capacity_observations','sre_observability_evidence'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS sre_immutable_guard ON public.%I',relation_name);
    EXECUTE format('CREATE TRIGGER sre_immutable_guard BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION reject_sre_immutable_change()',relation_name);
  END LOOP;
END
$immutability$;

DO $rls$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'sre_service_slos','sre_sli_observations','sre_burn_alerts','sre_incident_links',
    'sre_deployment_topologies','sre_zone_health_observations','backup_manifests','sre_backup_artifacts',
    'recovery_drills','sre_dr_plans','sre_dr_events','sre_chaos_campaigns','sre_chaos_results',
    'sre_load_campaigns','sre_load_results','deployment_rollouts','sre_canary_observations',
    'sre_cost_capacity_observations','sre_observability_evidence','sre_resource_versions',
    'sre_action_ingress','sre_principal_assertion_replay','sre_authority_executions','sre_evidence_outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I',relation_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON public.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',
      relation_name
    );
  END LOOP;
END
$rls$;

CREATE INDEX IF NOT EXISTS sre_slo_active_idx ON sre_service_slos(tenant_id,status,service,sli_kind);
CREATE INDEX IF NOT EXISTS sre_sli_window_idx ON sre_sli_observations(tenant_id,slo_id,window_ended_at DESC);
CREATE INDEX IF NOT EXISTS sre_burn_alert_open_idx ON sre_burn_alerts(tenant_id,severity,opened_at) WHERE state<>'RESOLVED';
CREATE INDEX IF NOT EXISTS sre_zone_health_idx ON sre_zone_health_observations(tenant_id,topology_id,observed_at DESC);
CREATE INDEX IF NOT EXISTS sre_backup_time_idx ON backup_manifests(tenant_id,created_at DESC);
CREATE INDEX IF NOT EXISTS sre_dr_plan_state_idx ON sre_dr_plans(tenant_id,status,updated_at);
CREATE INDEX IF NOT EXISTS sre_chaos_state_idx ON sre_chaos_campaigns(tenant_id,status,updated_at);
CREATE INDEX IF NOT EXISTS sre_load_state_idx ON sre_load_campaigns(tenant_id,status,updated_at);
CREATE INDEX IF NOT EXISTS sre_rollout_state_idx ON deployment_rollouts(tenant_id,status,updated_at);
CREATE INDEX IF NOT EXISTS sre_execution_state_idx ON sre_authority_executions(tenant_id,state,lease_expires_at);
CREATE INDEX IF NOT EXISTS sre_evidence_pending_idx ON sre_evidence_outbox(tenant_id,next_attempt_at,created_at) WHERE delivered_at IS NULL;

REVOKE ALL ON TABLE sre_legacy_quarantine FROM PUBLIC;
REVOKE ALL ON TABLE sre_service_slos,sre_sli_observations,sre_burn_alerts,sre_incident_links,
  sre_deployment_topologies,sre_zone_health_observations,backup_manifests,sre_backup_artifacts,
  recovery_drills,sre_dr_plans,sre_dr_events,sre_chaos_campaigns,sre_chaos_results,
  sre_load_campaigns,sre_load_results,deployment_rollouts,sre_canary_observations,
  sre_cost_capacity_observations,sre_observability_evidence,sre_resource_versions,
  sre_action_ingress,sre_principal_assertion_replay,sre_authority_executions,sre_evidence_outbox FROM PUBLIC;
REVOKE ALL ON SEQUENCE sre_legacy_quarantine_quarantine_id_seq FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_sre_resource_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_sre_execution_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_sre_immutable_change() FROM PUBLIC;

COMMIT;
