//! Fail-closed dependency semantics, bounded capacity, recovery, and upgrade gates.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

pub const SRE_SCHEMA_VERSION: &str = "agenttrust.platform-sre.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Dependency {
    Policy,
    Identity,
    Ledger,
    Orchestrator,
    Evidence,
    Approval,
    ObjectStorage,
    Kms,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionClass {
    ReadOnly,
    OrdinaryWrite,
    HighRiskWrite,
    EmergencyStop,
    NewCredential,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureMode {
    AllowHealthy,
    FailClosed,
    DegradedRead,
    LocalWalThenReconcile,
    EmergencyAllowThenEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureResolution {
    pub schema_version: String,
    pub action_class: ActionClass,
    pub unavailable_dependencies: BTreeSet<Dependency>,
    pub mode: FailureMode,
    pub requires_signed_snapshot: bool,
    pub requires_local_safety_journal: bool,
    pub reason_code: String,
}

pub struct DependencyFailureResolver;

impl DependencyFailureResolver {
    pub fn resolve(
        action: ActionClass,
        unavailable: BTreeSet<Dependency>,
        signed_policy_snapshot_valid: bool,
    ) -> FailureResolution {
        let (mode, snapshot, journal, reason) = if unavailable.is_empty() {
            (
                FailureMode::AllowHealthy,
                false,
                false,
                "DEPENDENCIES_HEALTHY",
            )
        } else if action == ActionClass::EmergencyStop {
            (
                FailureMode::EmergencyAllowThenEvidence,
                false,
                true,
                "EMERGENCY_SAFETY_PRIORITY",
            )
        } else if action == ActionClass::ReadOnly
            && signed_policy_snapshot_valid
            && unavailable.is_subset(&BTreeSet::from([
                Dependency::Policy,
                Dependency::Evidence,
                Dependency::ObjectStorage,
            ]))
        {
            (
                FailureMode::DegradedRead,
                true,
                true,
                "SIGNED_SNAPSHOT_DEGRADED_READ",
            )
        } else {
            (
                FailureMode::FailClosed,
                false,
                false,
                "SECURITY_DEPENDENCY_UNAVAILABLE",
            )
        };
        FailureResolution {
            schema_version: SRE_SCHEMA_VERSION.into(),
            action_class: action,
            unavailable_dependencies: unavailable,
            mode,
            requires_signed_snapshot: snapshot,
            requires_local_safety_journal: journal,
            reason_code: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthContract {
    pub service: String,
    pub build_digest: String,
    pub schema_versions: BTreeSet<String>,
    pub policy_digest: Option<String>,
    pub dependency_health: BTreeMap<Dependency, bool>,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub checked_at: DateTime<Utc>,
}

pub struct ReadinessGate;

impl ReadinessGate {
    pub fn evaluate(
        health: &HealthContract,
        security_dependencies: &BTreeSet<Dependency>,
    ) -> Result<(), SreError> {
        if health.service.is_empty()
            || health.build_digest.len() != 64
            || health.schema_versions.is_empty()
            || health.queue_capacity == 0
            || health.queue_depth >= health.queue_capacity
            || security_dependencies.iter().any(|dependency| {
                !health
                    .dependency_health
                    .get(dependency)
                    .copied()
                    .unwrap_or(false)
            })
        {
            return Err(SreError::NotReady);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapacityProfile {
    pub profile_id: String,
    pub maximum_global_tasks: usize,
    pub maximum_tasks_per_tenant: usize,
    pub queue_capacity: usize,
    pub connection_pool_capacity: usize,
    pub evidence_buffer_capacity: usize,
    pub measured_at_release_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SliKind {
    Availability,
    AuthorizationLatency,
    UnsafeAllow,
    EvidenceCompleteness,
    RecoveryTime,
    RecoveryPoint,
    BackpressureRejection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceSlo {
    pub schema_version: String,
    pub slo_id: String,
    pub service: String,
    pub sli_kind: SliKind,
    pub window_seconds: u64,
    pub target_millionths: u32,
    pub minimum_samples: u64,
    pub release_blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SliObservation {
    pub slo_id: String,
    pub good_events: u64,
    pub total_events: u64,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SloEvaluation {
    pub schema_version: String,
    pub slo_id: String,
    pub achieved_millionths: u32,
    pub passed: bool,
    pub release_blocking: bool,
    pub evidence_digest: String,
}

pub struct SloEvaluator;

impl SloEvaluator {
    pub fn evaluate(
        slo: &ServiceSlo,
        observation: &SliObservation,
    ) -> Result<SloEvaluation, SreError> {
        if slo.schema_version != SRE_SCHEMA_VERSION
            || slo.slo_id.is_empty()
            || slo.service.is_empty()
            || slo.window_seconds == 0
            || slo.target_millionths > 1_000_000
            || observation.slo_id != slo.slo_id
            || observation.total_events < slo.minimum_samples
            || observation.good_events > observation.total_events
            || observation.window_ended_at <= observation.window_started_at
            || observation
                .window_ended_at
                .signed_duration_since(observation.window_started_at)
                .num_seconds()
                != slo.window_seconds as i64
            || !is_sha256(&observation.evidence_digest)
        {
            return Err(SreError::SloEvidenceInvalid);
        }
        let achieved = if observation.total_events == 0 {
            0
        } else {
            ((observation.good_events as u128 * 1_000_000) / observation.total_events as u128)
                as u32
        };
        let passed = achieved >= slo.target_millionths;
        let evidence_digest = hex(Sha256::digest(
            serde_json::to_vec(&(slo, observation, achieved, passed))
                .map_err(|_| SreError::SerializationFailed)?,
        ));
        Ok(SloEvaluation {
            schema_version: SRE_SCHEMA_VERSION.into(),
            slo_id: slo.slo_id.clone(),
            achieved_millionths: achieved,
            passed,
            release_blocking: slo.release_blocking,
            evidence_digest,
        })
    }
}

pub struct BoundedQueue<T> {
    capacity: usize,
    values: Mutex<VecDeque<T>>,
    rejected: Mutex<u64>,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Result<Self, SreError> {
        if capacity == 0 {
            return Err(SreError::CapacityInvalid);
        }
        Ok(Self {
            capacity,
            values: Mutex::new(VecDeque::new()),
            rejected: Mutex::new(0),
        })
    }

    pub fn push(&self, value: T) -> Result<(), SreError> {
        let mut values = self.values.lock();
        if values.len() >= self.capacity {
            let mut rejected = self.rejected.lock();
            *rejected = rejected.saturating_add(1);
            return Err(SreError::Backpressure);
        }
        values.push_back(value);
        Ok(())
    }

    pub fn pop(&self) -> Option<T> {
        self.values.lock().pop_front()
    }

    pub fn saturation_millionths(&self) -> u32 {
        ((self.values.lock().len() as u64 * 1_000_000) / self.capacity as u64) as u32
    }

    pub fn rejected(&self) -> u64 {
        *self.rejected.lock()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub schema_version: String,
    pub backup_id: String,
    pub release_digest: String,
    pub database_lsn: String,
    pub object_manifest_digest: String,
    pub encrypted: bool,
    pub key_version: String,
    pub record_counts: BTreeMap<String, u64>,
    pub created_at: DateTime<Utc>,
    pub backup_digest: String,
}

impl BackupManifest {
    pub fn compute_digest(&self) -> Result<String, SreError> {
        let mut copy = self.clone();
        copy.backup_digest.clear();
        Ok(hex(Sha256::digest(
            serde_json::to_vec(&copy).map_err(|_| SreError::SerializationFailed)?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupRequest {
    pub schema_version: String,
    pub backup_id: String,
    pub release_digest: String,
    pub scope: BTreeSet<String>,
    pub key_version: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseBackupArtifact {
    pub database_lsn: String,
    pub artifact_digest: String,
    pub encrypted: bool,
    pub key_version: String,
    pub record_counts: BTreeMap<String, u64>,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectBackupArtifact {
    pub manifest_digest: String,
    pub encrypted: bool,
    pub key_version: String,
    pub object_count: u64,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupReceipt {
    pub schema_version: String,
    pub manifest: BackupManifest,
    pub database_artifact_digest: String,
    pub object_count: u64,
    pub ledger_head_digest: String,
    pub key_recovery_verified: bool,
    pub evidence_refs: BTreeSet<String>,
    pub evidence_digest: String,
}

pub trait BackupPort: Send + Sync {
    fn backup_database(
        &self,
        request: &BackupRequest,
        idempotency_key: &str,
    ) -> Result<DatabaseBackupArtifact, SreError>;
    fn backup_objects(
        &self,
        request: &BackupRequest,
        idempotency_key: &str,
    ) -> Result<ObjectBackupArtifact, SreError>;
    fn ledger_head_digest(&self, request: &BackupRequest) -> Result<String, SreError>;
    fn verify_key_recovery(
        &self,
        key_version: &str,
        idempotency_key: &str,
    ) -> Result<String, SreError>;
}

pub struct BackupController<P: BackupPort> {
    port: P,
}

impl<P: BackupPort> BackupController<P> {
    pub fn new(port: P) -> Self {
        Self { port }
    }

    pub fn run(&self, request: &BackupRequest) -> Result<BackupReceipt, SreError> {
        if request.schema_version != SRE_SCHEMA_VERSION
            || request.backup_id.is_empty()
            || !is_sha256(&request.release_digest)
            || request.scope.is_empty()
            || request.scope.len() > 64
            || request.key_version.is_empty()
            || request.requested_at > Utc::now()
        {
            return Err(SreError::BackupRequestInvalid);
        }
        let database = self
            .port
            .backup_database(request, &format!("backup:{}:database", request.backup_id))?;
        let objects = self
            .port
            .backup_objects(request, &format!("backup:{}:objects", request.backup_id))?;
        let ledger_head_digest = self.port.ledger_head_digest(request)?;
        let key_evidence = self.port.verify_key_recovery(
            &request.key_version,
            &format!("backup:{}:key-recovery", request.backup_id),
        )?;
        if database.database_lsn.is_empty()
            || !is_sha256(&database.artifact_digest)
            || !database.encrypted
            || database.key_version != request.key_version
            || database.record_counts.is_empty()
            || database.evidence_ref.is_empty()
            || !is_sha256(&objects.manifest_digest)
            || !objects.encrypted
            || objects.key_version != request.key_version
            || objects.evidence_ref.is_empty()
            || !is_sha256(&ledger_head_digest)
            || key_evidence.is_empty()
        {
            return Err(SreError::BackupEvidenceInvalid);
        }
        let mut manifest = BackupManifest {
            schema_version: SRE_SCHEMA_VERSION.into(),
            backup_id: request.backup_id.clone(),
            release_digest: request.release_digest.clone(),
            database_lsn: database.database_lsn.clone(),
            object_manifest_digest: objects.manifest_digest.clone(),
            encrypted: true,
            key_version: request.key_version.clone(),
            record_counts: database.record_counts.clone(),
            created_at: Utc::now(),
            backup_digest: String::new(),
        };
        manifest.backup_digest = manifest.compute_digest()?;
        let evidence_refs = BTreeSet::from([
            database.evidence_ref.clone(),
            objects.evidence_ref.clone(),
            key_evidence,
        ]);
        let evidence_digest = hex(Sha256::digest(
            serde_json::to_vec(&(
                &manifest,
                &database.artifact_digest,
                objects.object_count,
                &ledger_head_digest,
                &evidence_refs,
            ))
            .map_err(|_| SreError::SerializationFailed)?,
        ));
        Ok(BackupReceipt {
            schema_version: SRE_SCHEMA_VERSION.into(),
            manifest,
            database_artifact_digest: database.artifact_digest,
            object_count: objects.object_count,
            ledger_head_digest,
            key_recovery_verified: true,
            evidence_refs,
            evidence_digest,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryDrill {
    pub schema_version: String,
    pub drill_id: String,
    pub backup_id: String,
    pub isolated_environment: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub source_last_committed_at: DateTime<Utc>,
    pub restored_last_committed_at: DateTime<Utc>,
    pub restored_record_counts: BTreeMap<String, u64>,
    pub object_integrity_verified: bool,
    pub ledger_evidence_reconciled: bool,
    pub executed_command_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryVerification {
    pub schema_version: String,
    pub drill_id: String,
    pub rto_seconds: i64,
    pub rpo_seconds: i64,
    pub passed: bool,
    pub evidence_digest: String,
}

pub struct RecoveryVerifier;

impl RecoveryVerifier {
    pub fn verify(
        backup: &BackupManifest,
        drill: &RecoveryDrill,
        maximum_rto_seconds: i64,
        maximum_rpo_seconds: i64,
    ) -> Result<RecoveryVerification, SreError> {
        if backup.schema_version != SRE_SCHEMA_VERSION
            || drill.schema_version != SRE_SCHEMA_VERSION
            || backup.backup_id != drill.backup_id
            || backup.backup_digest != backup.compute_digest()?
            || !backup.encrypted
            || backup.object_manifest_digest.len() != 64
            || backup.key_version.is_empty()
            || drill.isolated_environment.is_empty()
            || drill.isolated_environment == "production"
            || drill.executed_command_digest.len() != 64
        {
            return Err(SreError::RecoveryEvidenceInvalid);
        }
        let rto = drill
            .completed_at
            .signed_duration_since(drill.started_at)
            .num_seconds();
        let rpo = drill
            .source_last_committed_at
            .signed_duration_since(drill.restored_last_committed_at)
            .num_seconds()
            .max(0);
        let passed = rto >= 0
            && rto <= maximum_rto_seconds
            && rpo <= maximum_rpo_seconds
            && backup.record_counts == drill.restored_record_counts
            && drill.object_integrity_verified
            && drill.ledger_evidence_reconciled;
        let evidence_digest = hex(Sha256::digest(
            serde_json::to_vec(&(backup, drill, rto, rpo, passed))
                .map_err(|_| SreError::SerializationFailed)?,
        ));
        Ok(RecoveryVerification {
            schema_version: SRE_SCHEMA_VERSION.into(),
            drill_id: drill.drill_id.clone(),
            rto_seconds: rto,
            rpo_seconds: rpo,
            passed,
            evidence_digest,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradePlan {
    pub schema_version: String,
    pub upgrade_id: String,
    pub from_release_digest: String,
    pub to_release_digest: String,
    pub schema_forward_compatible: bool,
    pub api_compatible: bool,
    pub policy_compatible: bool,
    pub pack_compatible: bool,
    pub rollback_artifact_digest: String,
    pub canary_steps: Vec<u32>,
    pub maximum_error_rate_millionths: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeDecision {
    pub schema_version: String,
    pub upgrade_id: String,
    pub allowed: bool,
    pub rollback_required: bool,
    pub reason_codes: BTreeSet<String>,
}

pub struct UpgradeOrchestrator;

impl UpgradeOrchestrator {
    pub fn evaluate(plan: &UpgradePlan, observed_error_rate_millionths: u32) -> UpgradeDecision {
        let compatible = plan.schema_version == SRE_SCHEMA_VERSION
            && plan.from_release_digest.len() == 64
            && plan.to_release_digest.len() == 64
            && plan.rollback_artifact_digest.len() == 64
            && plan.schema_forward_compatible
            && plan.api_compatible
            && plan.policy_compatible
            && plan.pack_compatible
            && !plan.canary_steps.is_empty();
        let regression = observed_error_rate_millionths > plan.maximum_error_rate_millionths;
        let mut reasons = BTreeSet::new();
        if !compatible {
            reasons.insert("UPGRADE_INCOMPATIBLE".into());
        }
        if regression {
            reasons.insert("CANARY_REGRESSION".into());
        }
        UpgradeDecision {
            schema_version: SRE_SCHEMA_VERSION.into(),
            upgrade_id: plan.upgrade_id.clone(),
            allowed: compatible && !regression,
            rollback_required: regression,
            reason_codes: reasons,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SreError {
    #[error("SRE_NOT_READY")]
    NotReady,
    #[error("SRE_CAPACITY_INVALID")]
    CapacityInvalid,
    #[error("SRE_BACKPRESSURE")]
    Backpressure,
    #[error("SRE_RECOVERY_EVIDENCE_INVALID")]
    RecoveryEvidenceInvalid,
    #[error("SRE_SERIALIZATION_FAILED")]
    SerializationFailed,
    #[error("SRE_SLO_EVIDENCE_INVALID")]
    SloEvidenceInvalid,
    #[error("SRE_BACKUP_REQUEST_INVALID")]
    BackupRequestInvalid,
    #[error("SRE_BACKUP_EVIDENCE_INVALID")]
    BackupEvidenceInvalid,
    #[error("SRE_BACKUP_OPERATION_FAILED")]
    BackupOperationFailed,
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    struct TestBackupPort {
        encrypted: bool,
    }

    impl BackupPort for TestBackupPort {
        fn backup_database(
            &self,
            request: &BackupRequest,
            _: &str,
        ) -> Result<DatabaseBackupArtifact, SreError> {
            Ok(DatabaseBackupArtifact {
                database_lsn: "0/1234".into(),
                artifact_digest: "d".repeat(64),
                encrypted: self.encrypted,
                key_version: request.key_version.clone(),
                record_counts: BTreeMap::from([("tasks".into(), 20)]),
                evidence_ref: "evidence:database-backup".into(),
            })
        }

        fn backup_objects(
            &self,
            request: &BackupRequest,
            _: &str,
        ) -> Result<ObjectBackupArtifact, SreError> {
            Ok(ObjectBackupArtifact {
                manifest_digest: "b".repeat(64),
                encrypted: self.encrypted,
                key_version: request.key_version.clone(),
                object_count: 7,
                evidence_ref: "evidence:object-backup".into(),
            })
        }

        fn ledger_head_digest(&self, _: &BackupRequest) -> Result<String, SreError> {
            Ok("c".repeat(64))
        }

        fn verify_key_recovery(&self, _: &str, _: &str) -> Result<String, SreError> {
            Ok("evidence:key-recovery".into())
        }
    }

    #[test]
    fn security_dependency_outage_never_silently_allows_write() {
        for action in [
            ActionClass::OrdinaryWrite,
            ActionClass::HighRiskWrite,
            ActionClass::NewCredential,
        ] {
            let resolution = DependencyFailureResolver::resolve(
                action,
                BTreeSet::from([Dependency::Policy]),
                true,
            );
            assert_eq!(resolution.mode, FailureMode::FailClosed);
        }
        let emergency = DependencyFailureResolver::resolve(
            ActionClass::EmergencyStop,
            BTreeSet::from([Dependency::Evidence]),
            false,
        );
        assert_eq!(emergency.mode, FailureMode::EmergencyAllowThenEvidence);
        assert!(emergency.requires_local_safety_journal);
    }

    #[test]
    fn queue_saturates_with_visible_rejection() {
        let queue = BoundedQueue::new(1).unwrap_or_else(|error| panic!("queue: {error}"));
        queue
            .push(1_u8)
            .unwrap_or_else(|error| panic!("push: {error}"));
        assert_eq!(queue.push(2), Err(SreError::Backpressure));
        assert_eq!(queue.saturation_millionths(), 1_000_000);
        assert_eq!(queue.rejected(), 1);
    }

    #[test]
    fn recovery_verifier_requires_actual_integrity_and_counts() {
        let now = Utc::now();
        let mut backup = BackupManifest {
            schema_version: SRE_SCHEMA_VERSION.into(),
            backup_id: "backup:1".into(),
            release_digest: "a".repeat(64),
            database_lsn: "0/123".into(),
            object_manifest_digest: "o".repeat(64),
            encrypted: true,
            key_version: "kms:v1".into(),
            record_counts: BTreeMap::from([("tasks".into(), 10)]),
            created_at: now,
            backup_digest: String::new(),
        };
        backup.backup_digest = backup
            .compute_digest()
            .unwrap_or_else(|error| panic!("digest: {error}"));
        let drill = RecoveryDrill {
            schema_version: SRE_SCHEMA_VERSION.into(),
            drill_id: "drill:1".into(),
            backup_id: backup.backup_id.clone(),
            isolated_environment: "restore-test".into(),
            started_at: now,
            completed_at: now + Duration::seconds(10),
            source_last_committed_at: now,
            restored_last_committed_at: now - Duration::seconds(2),
            restored_record_counts: BTreeMap::from([("tasks".into(), 9)]),
            object_integrity_verified: true,
            ledger_evidence_reconciled: true,
            executed_command_digest: "c".repeat(64),
        };
        let result = RecoveryVerifier::verify(&backup, &drill, 60, 5)
            .unwrap_or_else(|error| panic!("verify: {error}"));
        assert!(!result.passed);
    }

    #[test]
    fn backup_controller_rejects_unencrypted_components() {
        let request = BackupRequest {
            schema_version: SRE_SCHEMA_VERSION.into(),
            backup_id: "backup:1".into(),
            release_digest: "a".repeat(64),
            scope: BTreeSet::from(["postgres".into(), "objects".into()]),
            key_version: "kms:v2".into(),
            requested_at: Utc::now(),
        };
        let receipt = BackupController::new(TestBackupPort { encrypted: true })
            .run(&request)
            .unwrap_or_else(|error| panic!("backup: {error}"));
        assert!(receipt.key_recovery_verified);
        assert_eq!(receipt.evidence_refs.len(), 3);
        assert_eq!(
            BackupController::new(TestBackupPort { encrypted: false }).run(&request),
            Err(SreError::BackupEvidenceInvalid)
        );
    }

    #[test]
    fn slo_evaluator_requires_complete_window_and_minimum_samples() {
        let started = Utc::now() - Duration::minutes(5);
        let slo = ServiceSlo {
            schema_version: SRE_SCHEMA_VERSION.into(),
            slo_id: "pep-availability".into(),
            service: "policy-pep".into(),
            sli_kind: SliKind::Availability,
            window_seconds: 300,
            target_millionths: 999_000,
            minimum_samples: 100,
            release_blocking: true,
        };
        let observation = SliObservation {
            slo_id: slo.slo_id.clone(),
            good_events: 999,
            total_events: 1000,
            window_started_at: started,
            window_ended_at: started + Duration::minutes(5),
            evidence_digest: "e".repeat(64),
        };
        let evaluation = SloEvaluator::evaluate(&slo, &observation)
            .unwrap_or_else(|error| panic!("slo: {error}"));
        assert!(evaluation.passed);
        let mut incomplete = observation;
        incomplete.total_events = 10;
        incomplete.good_events = 10;
        assert_eq!(
            SloEvaluator::evaluate(&slo, &incomplete),
            Err(SreError::SloEvidenceInvalid)
        );
    }
}
