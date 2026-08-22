//! Versioned, deterministic security campaign and regression metrics.

pub mod authority;
pub mod production_harness;
pub mod server;

use agent_trust_contracts::{RiskLevel, TenantId};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const SECURITY_EVAL_SCHEMA_VERSION: &str = "agenttrust.security-eval.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackCategory {
    PromptInjection,
    GoalHijack,
    ToolAbuse,
    CredentialMovement,
    MemoryPoisoning,
    MultiAgentCascade,
    SandboxEscape,
    SlowExfiltration,
    Coding,
    Industrial,
    Energy,
    Medical,
    SensitiveInteraction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackStep {
    pub sequence: u32,
    pub action: String,
    pub input_digest: String,
    pub expected_control_ids: BTreeSet<String>,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackScenario {
    pub schema_version: String,
    pub scenario_id: String,
    pub version: String,
    pub category: AttackCategory,
    pub severity: RiskLevel,
    pub target_control_ids: BTreeSet<String>,
    pub preconditions: BTreeSet<String>,
    pub steps: Vec<AttackStep>,
    pub success_criteria: BTreeSet<String>,
    pub failure_criteria: BTreeSet<String>,
    pub cleanup_steps: BTreeSet<String>,
    pub dataset_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackDataset {
    pub schema_version: String,
    pub dataset_id: String,
    pub version: String,
    pub digest: String,
    pub provenance: String,
    pub license: String,
    pub sample_count: u64,
    pub categories: BTreeSet<AttackCategory>,
    pub sensitivity: String,
    pub immutable: bool,
    pub registered_at: DateTime<Utc>,
}

pub struct AttackDatasetRegistry {
    maximum_datasets: usize,
    datasets: RwLock<BTreeMap<(String, String), AttackDataset>>,
}

impl AttackDatasetRegistry {
    pub fn new(maximum_datasets: usize) -> Result<Self, EvalLabError> {
        if maximum_datasets == 0 {
            return Err(EvalLabError::DatasetInvalid);
        }
        Ok(Self {
            maximum_datasets,
            datasets: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn register(&self, dataset: AttackDataset) -> Result<AttackDataset, EvalLabError> {
        if dataset.schema_version != SECURITY_EVAL_SCHEMA_VERSION
            || dataset.dataset_id.is_empty()
            || dataset.version.is_empty()
            || !is_sha256(&dataset.digest)
            || dataset.provenance.is_empty()
            || dataset.license.is_empty()
            || dataset.sample_count == 0
            || dataset.categories.is_empty()
            || !matches!(
                dataset.sensitivity.as_str(),
                "PUBLIC" | "INTERNAL" | "RESTRICTED"
            )
            || !dataset.immutable
            || dataset.registered_at > Utc::now()
        {
            return Err(EvalLabError::DatasetInvalid);
        }
        let key = (dataset.dataset_id.clone(), dataset.version.clone());
        let mut datasets = self.datasets.write();
        if let Some(existing) = datasets.get(&key) {
            return if existing.digest == dataset.digest {
                Ok(existing.clone())
            } else {
                Err(EvalLabError::DatasetConflict)
            };
        }
        if datasets.len() >= self.maximum_datasets {
            return Err(EvalLabError::DatasetCapacityExceeded);
        }
        datasets.insert(key, dataset.clone());
        Ok(dataset)
    }

    pub fn resolve(&self, dataset_id: &str, version: &str) -> Result<AttackDataset, EvalLabError> {
        self.datasets
            .read()
            .get(&(dataset_id.into(), version.into()))
            .cloned()
            .ok_or(EvalLabError::DatasetNotFound)
    }
}

pub struct ScenarioCompiler;

impl ScenarioCompiler {
    pub fn compile(scenario: &AttackScenario) -> Result<String, EvalLabError> {
        if scenario.schema_version != SECURITY_EVAL_SCHEMA_VERSION
            || scenario.scenario_id.is_empty()
            || scenario.version.is_empty()
            || scenario.target_control_ids.is_empty()
            || scenario.preconditions.is_empty()
            || scenario.steps.is_empty()
            || scenario.success_criteria.is_empty()
            || scenario.failure_criteria.is_empty()
            || scenario.cleanup_steps.is_empty()
            || !is_sha256(&scenario.dataset_digest)
        {
            return Err(EvalLabError::ScenarioInvalid);
        }
        let mut prior = 0;
        for step in &scenario.steps {
            if step.sequence <= prior
                || step.action.is_empty()
                || !is_sha256(&step.input_digest)
                || step.expected_control_ids.is_empty()
                || step.expected_outcome.is_empty()
            {
                return Err(EvalLabError::ScenarioInvalid);
            }
            prior = step.sequence;
        }
        Ok(hex(Sha256::digest(
            serde_json::to_vec(scenario).map_err(|_| EvalLabError::SerializationFailed)?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepObservation {
    pub sequence: u32,
    pub prevented: bool,
    pub detected: bool,
    pub contained: bool,
    pub recovered: bool,
    pub observed_control_ids: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioRun {
    pub schema_version: String,
    pub run_id: String,
    pub tenant_id: TenantId,
    pub scenario_id: String,
    pub scenario_digest: String,
    pub seed: u64,
    pub environment_profile: String,
    pub configuration_digest: String,
    pub policy_digest: String,
    pub pack_digest: String,
    pub observations: Vec<StepObservation>,
    pub cleanup_complete: bool,
    pub evidence_complete: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

pub trait AttackExecutor: Send + Sync {
    fn execute_step(
        &self,
        scenario: &AttackScenario,
        step: &AttackStep,
        seed: u64,
    ) -> Result<StepObservation, EvalLabError>;
    fn cleanup(&self, scenario: &AttackScenario, run_id: &str) -> Result<bool, EvalLabError>;
}

pub struct RedTeamRunner<E: AttackExecutor> {
    executor: E,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioRunRequest {
    pub tenant_id: TenantId,
    pub seed: u64,
    pub environment_profile: String,
    pub configuration_digest: String,
    pub policy_digest: String,
    pub pack_digest: String,
}

impl<E: AttackExecutor> RedTeamRunner<E> {
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn run(
        &self,
        scenario: &AttackScenario,
        request: &ScenarioRunRequest,
    ) -> Result<ScenarioRun, EvalLabError> {
        let scenario_digest = ScenarioCompiler::compile(scenario)?;
        if !request.environment_profile.starts_with("isolated-")
            || [
                &request.configuration_digest,
                &request.policy_digest,
                &request.pack_digest,
            ]
            .iter()
            .any(|digest| !is_sha256(digest))
        {
            return Err(EvalLabError::EnvironmentDenied);
        }
        let run_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();
        let mut observations = Vec::new();
        for step in &scenario.steps {
            observations.push(self.executor.execute_step(scenario, step, request.seed)?);
        }
        let cleanup_complete = self.executor.cleanup(scenario, &run_id)?;
        let evidence_complete = observations.iter().all(|observation| {
            !observation.evidence_refs.is_empty()
                && observation
                    .observed_control_ids
                    .is_superset(&scenario.target_control_ids)
        });
        Ok(ScenarioRun {
            schema_version: SECURITY_EVAL_SCHEMA_VERSION.into(),
            run_id,
            tenant_id: request.tenant_id.clone(),
            scenario_id: scenario.scenario_id.clone(),
            scenario_digest,
            seed: request.seed,
            environment_profile: request.environment_profile.clone(),
            configuration_digest: request.configuration_digest.clone(),
            policy_digest: request.policy_digest.clone(),
            pack_digest: request.pack_digest.clone(),
            observations,
            cleanup_complete,
            evidence_complete,
            started_at,
            completed_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityMetric {
    pub phase: String,
    pub successes: u64,
    pub samples: u64,
    pub rate: f64,
    pub confidence_low: f64,
    pub confidence_high: f64,
    pub latency_p95_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CampaignReport {
    pub schema_version: String,
    pub campaign_id: String,
    pub release_digest: String,
    pub metrics: BTreeMap<String, SecurityMetric>,
    pub scenario_count: usize,
    pub sample_count: usize,
    pub all_cleanup_complete: bool,
    pub all_evidence_complete: bool,
    pub generated_at: DateTime<Utc>,
}

pub struct MetricCalculator;

impl MetricCalculator {
    pub fn calculate(
        release_digest: String,
        runs: &[ScenarioRun],
    ) -> Result<CampaignReport, EvalLabError> {
        if !is_sha256(&release_digest) || runs.is_empty() {
            return Err(EvalLabError::CampaignInvalid);
        }
        let observations = runs
            .iter()
            .flat_map(|run| run.observations.iter())
            .collect::<Vec<_>>();
        let metrics = BTreeMap::from([
            (
                "prevent".into(),
                metric("prevent", &observations, |item| item.prevented),
            ),
            (
                "detect".into(),
                metric("detect", &observations, |item| item.detected),
            ),
            (
                "contain".into(),
                metric("contain", &observations, |item| item.contained),
            ),
            (
                "recover".into(),
                metric("recover", &observations, |item| item.recovered),
            ),
        ]);
        Ok(CampaignReport {
            schema_version: SECURITY_EVAL_SCHEMA_VERSION.into(),
            campaign_id: Uuid::new_v4().to_string(),
            release_digest,
            metrics,
            scenario_count: runs.len(),
            sample_count: observations.len(),
            all_cleanup_complete: runs.iter().all(|run| run.cleanup_complete),
            all_evidence_complete: runs.iter().all(|run| run.evidence_complete),
            generated_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegressionFinding {
    pub metric: String,
    pub baseline_rate_millionths: u32,
    pub candidate_rate_millionths: u32,
    pub maximum_drop_millionths: u32,
    pub blocking: bool,
}

pub struct BaselineComparator;

impl BaselineComparator {
    pub fn compare(
        baseline: &CampaignReport,
        candidate: &CampaignReport,
        maximum_drop_millionths: u32,
    ) -> Vec<RegressionFinding> {
        baseline
            .metrics
            .iter()
            .filter_map(|(name, baseline_metric)| {
                let candidate_metric = candidate.metrics.get(name)?;
                let baseline_rate = (baseline_metric.rate * 1_000_000.0).round() as u32;
                let candidate_rate = (candidate_metric.rate * 1_000_000.0).round() as u32;
                let drop = baseline_rate.saturating_sub(candidate_rate);
                (drop > maximum_drop_millionths).then_some(RegressionFinding {
                    metric: name.clone(),
                    baseline_rate_millionths: baseline_rate,
                    candidate_rate_millionths: candidate_rate,
                    maximum_drop_millionths,
                    blocking: true,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFinding {
    pub finding_id: String,
    pub scenario_id: String,
    pub severity: RiskLevel,
    pub control_ids: BTreeSet<String>,
    pub policy_refs: BTreeSet<String>,
    pub remediation_id: String,
    pub retest_required: bool,
}

#[derive(Default)]
pub struct FindingService {
    findings: RwLock<BTreeMap<String, SecurityFinding>>,
}

impl FindingService {
    pub fn open(&self, finding: SecurityFinding) -> Result<(), EvalLabError> {
        if finding.finding_id.is_empty()
            || finding.scenario_id.is_empty()
            || finding.control_ids.is_empty()
            || finding.policy_refs.is_empty()
            || finding.remediation_id.is_empty()
            || !finding.retest_required
        {
            return Err(EvalLabError::FindingInvalid);
        }
        self.findings
            .write()
            .insert(finding.finding_id.clone(), finding);
        Ok(())
    }
}

fn metric(
    name: &str,
    observations: &[&StepObservation],
    predicate: impl Fn(&StepObservation) -> bool,
) -> SecurityMetric {
    let samples = observations.len() as u64;
    let successes = observations
        .iter()
        .filter(|observation| predicate(observation))
        .count() as u64;
    let rate = if samples == 0 {
        0.0
    } else {
        successes as f64 / samples as f64
    };
    let (low, high) = wilson_interval(successes, samples);
    let mut latencies = observations
        .iter()
        .map(|observation| observation.latency_ms)
        .collect::<Vec<_>>();
    latencies.sort_unstable();
    let p95_index = latencies.len().saturating_sub(1) * 95 / 100;
    SecurityMetric {
        phase: name.into(),
        successes,
        samples,
        rate,
        confidence_low: low,
        confidence_high: high,
        latency_p95_ms: latencies.get(p95_index).copied().unwrap_or(0),
    }
}

fn wilson_interval(successes: u64, samples: u64) -> (f64, f64) {
    if samples == 0 {
        return (0.0, 0.0);
    }
    let n = samples as f64;
    let p = successes as f64 / n;
    let z = 1.96;
    let denominator = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denominator;
    let margin = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denominator;
    ((center - margin).max(0.0), (center + margin).min(1.0))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvalLabError {
    #[error("SECURITY_EVAL_SCENARIO_INVALID")]
    ScenarioInvalid,
    #[error("SECURITY_EVAL_ENVIRONMENT_DENIED")]
    EnvironmentDenied,
    #[error("SECURITY_EVAL_CAMPAIGN_INVALID")]
    CampaignInvalid,
    #[error("SECURITY_EVAL_FINDING_INVALID")]
    FindingInvalid,
    #[error("SECURITY_EVAL_EXECUTION_FAILED")]
    ExecutionFailed,
    #[error("SECURITY_EVAL_CLEANUP_FAILED")]
    CleanupFailed,
    #[error("SECURITY_EVAL_SERIALIZATION_FAILED")]
    SerializationFailed,
    #[error("SECURITY_EVAL_DATASET_INVALID")]
    DatasetInvalid,
    #[error("SECURITY_EVAL_DATASET_CONFLICT")]
    DatasetConflict,
    #[error("SECURITY_EVAL_DATASET_CAPACITY_EXCEEDED")]
    DatasetCapacityExceeded,
    #[error("SECURITY_EVAL_DATASET_NOT_FOUND")]
    DatasetNotFound,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeterministicExecutor {
        cleanup: bool,
        evidence: bool,
    }

    impl AttackExecutor for DeterministicExecutor {
        fn execute_step(
            &self,
            scenario: &AttackScenario,
            step: &AttackStep,
            seed: u64,
        ) -> Result<StepObservation, EvalLabError> {
            Ok(StepObservation {
                sequence: step.sequence,
                prevented: seed.is_multiple_of(2),
                detected: true,
                contained: true,
                recovered: self.cleanup,
                observed_control_ids: scenario.target_control_ids.clone(),
                evidence_refs: if self.evidence {
                    BTreeSet::from([format!("evidence:{}:{seed}", step.sequence)])
                } else {
                    BTreeSet::new()
                },
                latency_ms: 10 + seed,
            })
        }
        fn cleanup(&self, _: &AttackScenario, _: &str) -> Result<bool, EvalLabError> {
            Ok(self.cleanup)
        }
    }

    fn scenario(category: AttackCategory) -> AttackScenario {
        AttackScenario {
            schema_version: SECURITY_EVAL_SCHEMA_VERSION.into(),
            scenario_id: format!("scenario:{category:?}"),
            version: "1.0.0".into(),
            category,
            severity: RiskLevel::High,
            target_control_ids: BTreeSet::from(["C-AUTHZ".into()]),
            preconditions: BTreeSet::from(["isolated-tenant".into()]),
            steps: vec![AttackStep {
                sequence: 1,
                action: "attempt".into(),
                input_digest: "a".repeat(64),
                expected_control_ids: BTreeSet::from(["C-AUTHZ".into()]),
                expected_outcome: "DENY".into(),
            }],
            success_criteria: BTreeSet::from(["prevented".into()]),
            failure_criteria: BTreeSet::from(["side-effect".into()]),
            cleanup_steps: BTreeSet::from(["destroy-sandbox".into()]),
            dataset_digest: "d".repeat(64),
        }
    }

    fn run_request(environment_profile: &str) -> ScenarioRunRequest {
        ScenarioRunRequest {
            tenant_id: TenantId::new(),
            seed: 2,
            environment_profile: environment_profile.into(),
            configuration_digest: "c".repeat(64),
            policy_digest: "d".repeat(64),
            pack_digest: "e".repeat(64),
        }
    }

    #[test]
    fn attack_dataset_registry_is_immutable_and_digest_pinned() {
        let registry =
            AttackDatasetRegistry::new(10).unwrap_or_else(|error| panic!("registry: {error}"));
        let dataset = AttackDataset {
            schema_version: SECURITY_EVAL_SCHEMA_VERSION.into(),
            dataset_id: "prompt-injection-core".into(),
            version: "1.0.0".into(),
            digest: "a".repeat(64),
            provenance: "internal-red-team".into(),
            license: "PROPRIETARY-TEST-ONLY".into(),
            sample_count: 100,
            categories: BTreeSet::from([AttackCategory::PromptInjection]),
            sensitivity: "RESTRICTED".into(),
            immutable: true,
            registered_at: Utc::now(),
        };
        registry
            .register(dataset.clone())
            .unwrap_or_else(|error| panic!("register: {error}"));
        assert_eq!(
            registry
                .resolve(&dataset.dataset_id, &dataset.version)
                .unwrap_or_else(|error| panic!("resolve: {error}"))
                .digest,
            dataset.digest
        );
        let mut mutated = dataset;
        mutated.digest = "b".repeat(64);
        assert_eq!(
            registry.register(mutated),
            Err(EvalLabError::DatasetConflict)
        );
    }

    #[test]
    fn production_target_and_incomplete_evidence_fail_closed() {
        let runner = RedTeamRunner::new(DeterministicExecutor {
            cleanup: true,
            evidence: false,
        });
        let value = scenario(AttackCategory::PromptInjection);
        assert_eq!(
            runner.run(&value, &run_request("production")),
            Err(EvalLabError::EnvironmentDenied)
        );
        let run = runner
            .run(&value, &run_request("isolated-sandbox"))
            .unwrap_or_else(|error| panic!("run: {error}"));
        assert!(!run.evidence_complete);
    }

    #[test]
    fn same_seed_is_repeatable_and_metrics_include_confidence() {
        let runner = RedTeamRunner::new(DeterministicExecutor {
            cleanup: true,
            evidence: true,
        });
        let value = scenario(AttackCategory::SlowExfiltration);
        let first = runner
            .run(&value, &run_request("isolated-sandbox"))
            .unwrap_or_else(|error| panic!("run: {error}"));
        let second = runner
            .run(&value, &run_request("isolated-sandbox"))
            .unwrap_or_else(|error| panic!("run: {error}"));
        assert_eq!(first.observations, second.observations);
        let report = MetricCalculator::calculate("f".repeat(64), &[first, second])
            .unwrap_or_else(|error| panic!("metrics: {error}"));
        let prevent = report
            .metrics
            .get("prevent")
            .unwrap_or_else(|| panic!("prevent metric"));
        assert_eq!(prevent.samples, 2);
        assert!(prevent.confidence_high >= prevent.confidence_low);
    }

    #[test]
    fn scenario_catalog_covers_common_and_five_domains() {
        let categories = BTreeSet::from([
            AttackCategory::PromptInjection,
            AttackCategory::CredentialMovement,
            AttackCategory::MemoryPoisoning,
            AttackCategory::Coding,
            AttackCategory::Industrial,
            AttackCategory::Energy,
            AttackCategory::Medical,
            AttackCategory::SensitiveInteraction,
        ]);
        assert!(categories.contains(&AttackCategory::Coding));
        assert!(categories.contains(&AttackCategory::SensitiveInteraction));
        for category in categories {
            assert!(ScenarioCompiler::compile(&scenario(category)).is_ok());
        }
    }
}
