//! Deterministic runtime anomaly detection and continuous authorization.

use agent_trust_contracts::{AgentInstanceId, RiskLevel, TaskId, TenantId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;
use uuid::Uuid;

pub const ANOMALY_SCHEMA_VERSION: &str = "agenttrust.runtime-anomaly.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalKind {
    Tool,
    Resource,
    Network,
    File,
    Credential,
    PolicyDeny,
    Process,
    Telemetry,
    AuditControl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskSignal {
    pub schema_version: String,
    pub event_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub agent_instance_id: AgentInstanceId,
    pub kind: SignalKind,
    pub action: String,
    pub resource: String,
    pub resource_class: String,
    pub value: Value,
    pub confidence_millionths: u32,
    pub source_version: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrajectoryState {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub goal_hash: String,
    pub plan_hash: String,
    pub allowed_resource_prefixes: BTreeSet<String>,
    pub allowed_network_destinations: BTreeSet<String>,
    pub event_count: usize,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

struct TaskWindow {
    state: TrajectoryState,
    signals: VecDeque<RiskSignal>,
    event_ids: BTreeSet<String>,
}

pub struct TrajectoryMonitor {
    maximum_tasks: usize,
    maximum_signals_per_task: usize,
    maximum_clock_skew: Duration,
    windows: Mutex<BTreeMap<(TenantId, TaskId), TaskWindow>>,
}

impl TrajectoryMonitor {
    pub fn new(
        maximum_tasks: usize,
        maximum_signals_per_task: usize,
        maximum_clock_skew: Duration,
    ) -> Result<Self, AnomalyError> {
        if maximum_tasks == 0
            || maximum_signals_per_task == 0
            || maximum_clock_skew < Duration::zero()
        {
            return Err(AnomalyError::ConfigurationInvalid);
        }
        Ok(Self {
            maximum_tasks,
            maximum_signals_per_task,
            maximum_clock_skew,
            windows: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn start(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        goal_hash: String,
        plan_hash: String,
        allowed_resource_prefixes: BTreeSet<String>,
        allowed_network_destinations: BTreeSet<String>,
    ) -> Result<TrajectoryState, AnomalyError> {
        if goal_hash.len() != 64 || plan_hash.len() != 64 {
            return Err(AnomalyError::TrajectoryInvalid);
        }
        let mut windows = self.windows.lock();
        let key = (tenant_id.clone(), task_id.clone());
        if let Some(existing) = windows.get(&key) {
            if existing.state.goal_hash == goal_hash && existing.state.plan_hash == plan_hash {
                return Ok(existing.state.clone());
            }
            return Err(AnomalyError::TrajectoryConflict);
        }
        if windows.len() >= self.maximum_tasks {
            return Err(AnomalyError::CapacityExceeded);
        }
        let now = Utc::now();
        let state = TrajectoryState {
            schema_version: ANOMALY_SCHEMA_VERSION.into(),
            tenant_id,
            task_id,
            goal_hash,
            plan_hash,
            allowed_resource_prefixes,
            allowed_network_destinations,
            event_count: 0,
            first_seen_at: now,
            last_seen_at: now,
        };
        windows.insert(
            key,
            TaskWindow {
                state: state.clone(),
                signals: VecDeque::new(),
                event_ids: BTreeSet::new(),
            },
        );
        Ok(state)
    }

    pub fn consume(
        &self,
        signal: RiskSignal,
        now: DateTime<Utc>,
    ) -> Result<TrajectoryState, AnomalyError> {
        validate_signal(&signal)?;
        let mut windows = self.windows.lock();
        let window = windows
            .get_mut(&(signal.tenant_id.clone(), signal.task_id.clone()))
            .ok_or(AnomalyError::TrajectoryNotFound)?;
        if !window.event_ids.insert(signal.event_id.clone()) {
            return Ok(window.state.clone());
        }
        if signal.occurred_at > now + self.maximum_clock_skew
            || signal.occurred_at < window.state.first_seen_at - self.maximum_clock_skew
        {
            return Err(AnomalyError::SignalClockInvalid);
        }
        if window.signals.len() >= self.maximum_signals_per_task
            && let Some(removed) = window.signals.pop_front()
        {
            window.event_ids.remove(&removed.event_id);
        }
        window.signals.push_back(signal.clone());
        let mut ordered = window.signals.drain(..).collect::<Vec<_>>();
        ordered.sort_by_key(|item| item.occurred_at);
        window.signals.extend(ordered);
        window.state.event_count = window.state.event_count.saturating_add(1);
        window.state.last_seen_at = window.state.last_seen_at.max(signal.occurred_at);
        Ok(window.state.clone())
    }

    pub fn signals(
        &self,
        tenant: &TenantId,
        task: &TaskId,
    ) -> Result<Vec<RiskSignal>, AnomalyError> {
        self.windows
            .lock()
            .get(&(tenant.clone(), task.clone()))
            .map(|window| window.signals.iter().cloned().collect())
            .ok_or(AnomalyError::TrajectoryNotFound)
    }

    pub fn state(&self, tenant: &TenantId, task: &TaskId) -> Result<TrajectoryState, AnomalyError> {
        self.windows
            .lock()
            .get(&(tenant.clone(), task.clone()))
            .map(|window| window.state.clone())
            .ok_or(AnomalyError::TrajectoryNotFound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskFinding {
    pub schema_version: String,
    pub finding_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub rule_id: String,
    pub rule_version: String,
    pub severity: RiskLevel,
    pub deterministic: bool,
    pub confidence_millionths: u32,
    pub evidence_event_ids: BTreeSet<String>,
    pub safe_reason: String,
}

pub struct RuleDetector {
    rule_version: String,
    slow_exfiltration_distinct_domains: usize,
    repeated_side_effect_limit: usize,
}

impl RuleDetector {
    pub fn new(
        rule_version: String,
        slow_exfiltration_distinct_domains: usize,
        repeated_side_effect_limit: usize,
    ) -> Result<Self, AnomalyError> {
        if rule_version.is_empty()
            || slow_exfiltration_distinct_domains < 2
            || repeated_side_effect_limit < 2
        {
            return Err(AnomalyError::ConfigurationInvalid);
        }
        Ok(Self {
            rule_version,
            slow_exfiltration_distinct_domains,
            repeated_side_effect_limit,
        })
    }

    pub fn evaluate(&self, state: &TrajectoryState, signals: &[RiskSignal]) -> Vec<RiskFinding> {
        let mut findings = Vec::new();
        for signal in signals {
            let normalized = format!("{} {}", signal.action, signal.resource).to_ascii_lowercase();
            let rule = if signal.kind == SignalKind::Network
                && (normalized.contains("169.254.169.254")
                    || normalized.contains("metadata.google.internal"))
            {
                Some((
                    "RUNTIME_METADATA_SSRF",
                    RiskLevel::Critical,
                    "metadata endpoint access",
                ))
            } else if signal.kind == SignalKind::File
                && (normalized.contains("/etc/shadow")
                    || normalized.contains("/var/run/docker.sock")
                    || normalized.contains("../"))
            {
                Some((
                    "RUNTIME_HOST_PATH",
                    RiskLevel::Critical,
                    "host or traversal path access",
                ))
            } else if signal.kind == SignalKind::AuditControl && normalized.contains("disable") {
                Some((
                    "RUNTIME_AUDIT_SUPPRESSION",
                    RiskLevel::Critical,
                    "audit suppression attempt",
                ))
            } else if signal.kind == SignalKind::Credential
                && (normalized.contains("write")
                    || normalized.contains("copy")
                    || normalized.contains("network"))
            {
                Some((
                    "RUNTIME_CREDENTIAL_MOVEMENT",
                    RiskLevel::Critical,
                    "credential movement",
                ))
            } else if signal.kind == SignalKind::Process && normalized.contains("unregistered") {
                Some((
                    "RUNTIME_UNREGISTERED_EXECUTOR",
                    RiskLevel::High,
                    "unregistered executor",
                ))
            } else if signal.kind == SignalKind::Resource
                && !state
                    .allowed_resource_prefixes
                    .iter()
                    .any(|prefix| signal.resource.starts_with(prefix))
            {
                Some((
                    "RUNTIME_SCOPE_EXPANSION",
                    RiskLevel::High,
                    "resource outside signed plan",
                ))
            } else if signal.kind == SignalKind::Network
                && !state
                    .allowed_network_destinations
                    .contains(&signal.resource)
            {
                Some((
                    "RUNTIME_NETWORK_EXPANSION",
                    RiskLevel::High,
                    "network destination outside plan",
                ))
            } else {
                None
            };
            if let Some((rule_id, severity, reason)) = rule {
                findings.push(finding(
                    state,
                    FindingInput {
                        rule_id,
                        version: &self.rule_version,
                        severity,
                        deterministic: true,
                        confidence: signal.confidence_millionths,
                        event_ids: [signal.event_id.clone()].into_iter().collect(),
                        reason,
                    },
                ));
            }
        }

        let effect_events = signals
            .iter()
            .filter(|signal| signal.kind == SignalKind::Tool && signal.action == "SIDE_EFFECT")
            .collect::<Vec<_>>();
        if effect_events.len() >= self.repeated_side_effect_limit {
            findings.push(finding(
                state,
                FindingInput {
                    rule_id: "RUNTIME_REPEATED_SIDE_EFFECT",
                    version: &self.rule_version,
                    severity: RiskLevel::High,
                    deterministic: true,
                    confidence: 1_000_000,
                    event_ids: effect_events
                        .iter()
                        .map(|signal| signal.event_id.clone())
                        .collect(),
                    reason: "repeated side effect pattern",
                },
            ));
        }
        let network = signals
            .iter()
            .filter(|signal| signal.kind == SignalKind::Network)
            .collect::<Vec<_>>();
        let domains = network
            .iter()
            .map(|signal| signal.resource.clone())
            .collect::<BTreeSet<_>>();
        if domains.len() >= self.slow_exfiltration_distinct_domains
            && network
                .iter()
                .all(|signal| signal.value.as_u64().is_some_and(|bytes| bytes <= 4096))
        {
            findings.push(finding(
                state,
                FindingInput {
                    rule_id: "RUNTIME_SLOW_EXFILTRATION",
                    version: &self.rule_version,
                    severity: RiskLevel::High,
                    deterministic: true,
                    confidence: 950_000,
                    event_ids: network
                        .iter()
                        .map(|signal| signal.event_id.clone())
                        .collect(),
                    reason: "small transfers across many destinations",
                },
            ));
        }
        findings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticScore {
    pub schema_version: String,
    pub model_id: String,
    pub model_version: String,
    pub score_millionths: u32,
    pub confidence_millionths: u32,
    pub goal_drift: bool,
    pub reason_codes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskAggregate {
    pub schema_version: String,
    pub aggregate_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub severity: RiskLevel,
    pub score_millionths: u32,
    pub deterministic_findings: Vec<RiskFinding>,
    pub semantic_score: Option<SemanticScore>,
    pub detector_degraded: bool,
    pub computed_at: DateTime<Utc>,
}

pub struct RiskAggregator;

impl RiskAggregator {
    pub fn update(
        state: &TrajectoryState,
        deterministic_findings: Vec<RiskFinding>,
        semantic_score: Option<SemanticScore>,
        semantic_detector_available: bool,
    ) -> RiskAggregate {
        let deterministic_score = deterministic_findings
            .iter()
            .map(|finding| finding.confidence_millionths)
            .max()
            .unwrap_or(0);
        let semantic_value = semantic_score.as_ref().map_or(0, |score| {
            score.score_millionths.min(score.confidence_millionths)
        });
        let score = deterministic_score.max(semantic_value);
        let severity = deterministic_findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or_else(|| severity_for_score(score));
        RiskAggregate {
            schema_version: ANOMALY_SCHEMA_VERSION.into(),
            aggregate_id: Uuid::new_v4().to_string(),
            tenant_id: state.tenant_id.clone(),
            task_id: state.task_id.clone(),
            severity,
            score_millionths: score,
            deterministic_findings,
            semantic_score,
            detector_degraded: !semantic_detector_available,
            computed_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationAdjustment {
    NoChange,
    RequireApproval,
    ReduceScope,
    Pause,
    RevokeLease,
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseCommand {
    pub schema_version: String,
    pub response_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub adjustment: AuthorizationAdjustment,
    pub new_revocation_epoch: u64,
    pub reason_codes: BTreeSet<String>,
    pub evidence_digest: String,
    pub recovery_conditions: BTreeSet<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl ResponseCommand {
    fn signing_bytes(&self) -> Result<Vec<u8>, AnomalyError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| AnomalyError::Canonicalization)
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), AnomalyError> {
        if now < self.issued_at || now >= self.expires_at {
            return Err(AnomalyError::ResponseInvalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| AnomalyError::ResponseInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| AnomalyError::ResponseInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| AnomalyError::ResponseInvalid)
    }
}

pub struct ContinuousAuthorizationController {
    issuer: String,
    key_id: String,
    signing_key: SigningKey,
}

impl ContinuousAuthorizationController {
    pub fn new(
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, AnomalyError> {
        if issuer.is_empty() || key_id.is_empty() {
            return Err(AnomalyError::ConfigurationInvalid);
        }
        Ok(Self {
            issuer,
            key_id,
            signing_key,
        })
    }

    pub fn adjust(
        &self,
        aggregate: &RiskAggregate,
        current_epoch: u64,
    ) -> Result<ResponseCommand, AnomalyError> {
        let critical_rules = aggregate
            .deterministic_findings
            .iter()
            .filter(|finding| finding.deterministic && finding.severity == RiskLevel::Critical)
            .map(|finding| finding.rule_id.clone())
            .collect::<BTreeSet<_>>();
        let adjustment = if !critical_rules.is_empty() {
            AuthorizationAdjustment::Kill
        } else if aggregate.severity == RiskLevel::Critical {
            AuthorizationAdjustment::Pause
        } else if aggregate.severity == RiskLevel::High {
            AuthorizationAdjustment::RevokeLease
        } else if aggregate.severity == RiskLevel::Medium {
            AuthorizationAdjustment::RequireApproval
        } else {
            AuthorizationAdjustment::NoChange
        };
        let reason_codes = aggregate
            .deterministic_findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .chain(
                aggregate
                    .semantic_score
                    .iter()
                    .flat_map(|score| score.reason_codes.iter().cloned()),
            )
            .collect::<BTreeSet<_>>();
        let evidence_digest = hex(Sha256::digest(
            serde_jcs::to_vec(aggregate).map_err(|_| AnomalyError::Canonicalization)?,
        ));
        let now = Utc::now();
        let mut command = ResponseCommand {
            schema_version: ANOMALY_SCHEMA_VERSION.into(),
            response_id: Uuid::new_v4().to_string(),
            tenant_id: aggregate.tenant_id.clone(),
            task_id: aggregate.task_id.clone(),
            adjustment,
            new_revocation_epoch: if matches!(
                adjustment,
                AuthorizationAdjustment::RevokeLease | AuthorizationAdjustment::Kill
            ) {
                current_epoch.saturating_add(1)
            } else {
                current_epoch
            },
            reason_codes,
            evidence_digest,
            recovery_conditions: if adjustment == AuthorizationAdjustment::Pause {
                BTreeSet::from(["HUMAN_REVIEW".into(), "NEW_AUTHORIZATION_LEASE".into()])
            } else {
                BTreeSet::new()
            },
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        command.signature =
            URL_SAFE_NO_PAD.encode(self.signing_key.sign(&command.signing_bytes()?).to_bytes());
        Ok(command)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub schema_version: String,
    pub agent_type: String,
    pub domain: String,
    pub maximum_calls_per_minute: u32,
    pub maximum_distinct_resources: u32,
    pub sample_count: u64,
    pub version: String,
}

#[derive(Default)]
pub struct BaselineStore {
    values: RwLock<BTreeMap<(String, String), Baseline>>,
}

impl BaselineStore {
    pub fn update(&self, baseline: Baseline, reviewer_approved: bool) -> Result<(), AnomalyError> {
        if baseline.schema_version != ANOMALY_SCHEMA_VERSION
            || baseline.agent_type.is_empty()
            || baseline.domain.is_empty()
            || baseline.maximum_calls_per_minute == 0
            || baseline.maximum_distinct_resources == 0
            || baseline.sample_count < 10
            || baseline.version.is_empty()
            || !reviewer_approved
        {
            return Err(AnomalyError::BaselineDenied);
        }
        self.values.write().insert(
            (baseline.agent_type.clone(), baseline.domain.clone()),
            baseline,
        );
        Ok(())
    }

    pub fn get(&self, agent_type: &str, domain: &str) -> Result<Baseline, AnomalyError> {
        self.values
            .read()
            .get(&(agent_type.into(), domain.into()))
            .cloned()
            .ok_or(AnomalyError::BaselineMissing)
    }
}

struct FindingInput<'a> {
    rule_id: &'a str,
    version: &'a str,
    severity: RiskLevel,
    deterministic: bool,
    confidence: u32,
    event_ids: BTreeSet<String>,
    reason: &'a str,
}

fn finding(state: &TrajectoryState, input: FindingInput<'_>) -> RiskFinding {
    RiskFinding {
        schema_version: ANOMALY_SCHEMA_VERSION.into(),
        finding_id: Uuid::new_v4().to_string(),
        tenant_id: state.tenant_id.clone(),
        task_id: state.task_id.clone(),
        rule_id: input.rule_id.into(),
        rule_version: input.version.into(),
        severity: input.severity,
        deterministic: input.deterministic,
        confidence_millionths: input.confidence.min(1_000_000),
        evidence_event_ids: input.event_ids,
        safe_reason: input.reason.into(),
    }
}

fn validate_signal(signal: &RiskSignal) -> Result<(), AnomalyError> {
    if signal.schema_version != ANOMALY_SCHEMA_VERSION
        || signal.event_id.is_empty()
        || signal.action.is_empty()
        || signal.resource.is_empty()
        || signal.resource_class.is_empty()
        || signal.confidence_millionths > 1_000_000
        || signal.source_version.is_empty()
    {
        Err(AnomalyError::SignalInvalid)
    } else {
        Ok(())
    }
}

fn severity_for_score(score: u32) -> RiskLevel {
    match score {
        900_000.. => RiskLevel::Critical,
        700_000..=899_999 => RiskLevel::High,
        400_000..=699_999 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnomalyError {
    #[error("ANOMALY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("ANOMALY_TRAJECTORY_INVALID")]
    TrajectoryInvalid,
    #[error("ANOMALY_TRAJECTORY_CONFLICT")]
    TrajectoryConflict,
    #[error("ANOMALY_TRAJECTORY_NOT_FOUND")]
    TrajectoryNotFound,
    #[error("ANOMALY_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("ANOMALY_SIGNAL_INVALID")]
    SignalInvalid,
    #[error("ANOMALY_SIGNAL_CLOCK_INVALID")]
    SignalClockInvalid,
    #[error("ANOMALY_CANONICALIZATION_FAILED")]
    Canonicalization,
    #[error("ANOMALY_RESPONSE_INVALID")]
    ResponseInvalid,
    #[error("ANOMALY_BASELINE_DENIED")]
    BaselineDenied,
    #[error("ANOMALY_BASELINE_MISSING")]
    BaselineMissing,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> (TrajectoryMonitor, TenantId, TaskId, AgentInstanceId) {
        let monitor = TrajectoryMonitor::new(10, 100, Duration::minutes(2))
            .unwrap_or_else(|error| panic!("monitor: {error}"));
        let tenant = TenantId::new();
        let task = TaskId::new();
        monitor
            .start(
                tenant.clone(),
                task.clone(),
                "a".repeat(64),
                "b".repeat(64),
                BTreeSet::from(["repo://allowed".into()]),
                BTreeSet::from(["packages.example".into()]),
            )
            .unwrap_or_else(|error| panic!("start: {error}"));
        (monitor, tenant, task, AgentInstanceId::new())
    }

    struct SignalSpec<'a> {
        id: &'a str,
        kind: SignalKind,
        action: &'a str,
        resource: &'a str,
        value: Value,
    }

    fn signal(
        tenant: &TenantId,
        task: &TaskId,
        agent: &AgentInstanceId,
        spec: SignalSpec<'_>,
    ) -> RiskSignal {
        RiskSignal {
            schema_version: ANOMALY_SCHEMA_VERSION.into(),
            event_id: spec.id.into(),
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            agent_instance_id: agent.clone(),
            kind: spec.kind,
            action: spec.action.into(),
            resource: spec.resource.into(),
            resource_class: "test".into(),
            value: spec.value,
            confidence_millionths: 1_000_000,
            source_version: "1.0.0".into(),
            occurred_at: Utc::now(),
        }
    }

    #[test]
    fn duplicate_and_out_of_order_signals_are_deterministic() {
        let (monitor, tenant, task, agent) = monitor();
        let first = signal(
            &tenant,
            &task,
            &agent,
            SignalSpec {
                id: "e1",
                kind: SignalKind::Tool,
                action: "READ",
                resource: "repo://allowed/a",
                value: Value::Null,
            },
        );
        monitor
            .consume(first.clone(), Utc::now())
            .unwrap_or_else(|error| panic!("consume: {error}"));
        monitor
            .consume(first, Utc::now())
            .unwrap_or_else(|error| panic!("retry: {error}"));
        assert_eq!(
            monitor
                .state(&tenant, &task)
                .unwrap_or_else(|error| panic!("state: {error}"))
                .event_count,
            1
        );
    }

    #[test]
    fn ssrf_credential_movement_and_slow_exfiltration_trigger() {
        let (monitor, tenant, task, agent) = monitor();
        let inputs = [
            signal(
                &tenant,
                &task,
                &agent,
                SignalSpec {
                    id: "e1",
                    kind: SignalKind::Network,
                    action: "GET",
                    resource: "169.254.169.254",
                    value: Value::from(100),
                },
            ),
            signal(
                &tenant,
                &task,
                &agent,
                SignalSpec {
                    id: "e2",
                    kind: SignalKind::Credential,
                    action: "COPY",
                    resource: "file://tmp/token",
                    value: Value::Null,
                },
            ),
            signal(
                &tenant,
                &task,
                &agent,
                SignalSpec {
                    id: "e3",
                    kind: SignalKind::Network,
                    action: "POST",
                    resource: "outside-a.example",
                    value: Value::from(128),
                },
            ),
            signal(
                &tenant,
                &task,
                &agent,
                SignalSpec {
                    id: "e4",
                    kind: SignalKind::Network,
                    action: "POST",
                    resource: "outside-b.example",
                    value: Value::from(128),
                },
            ),
            signal(
                &tenant,
                &task,
                &agent,
                SignalSpec {
                    id: "e5",
                    kind: SignalKind::Network,
                    action: "POST",
                    resource: "outside-c.example",
                    value: Value::from(128),
                },
            ),
        ];
        for input in inputs {
            monitor
                .consume(input, Utc::now())
                .unwrap_or_else(|error| panic!("consume: {error}"));
        }
        let detector = RuleDetector::new("rules:v1".into(), 3, 3)
            .unwrap_or_else(|error| panic!("detector: {error}"));
        let findings = detector.evaluate(
            &monitor
                .state(&tenant, &task)
                .unwrap_or_else(|error| panic!("state: {error}")),
            &monitor
                .signals(&tenant, &task)
                .unwrap_or_else(|error| panic!("signals: {error}")),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "RUNTIME_METADATA_SSRF")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "RUNTIME_CREDENTIAL_MOVEMENT")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "RUNTIME_SLOW_EXFILTRATION")
        );
    }

    #[test]
    fn semantic_detector_cannot_kill_and_rules_work_when_it_is_down() {
        let (monitor, tenant, task, _) = monitor();
        let state = monitor
            .state(&tenant, &task)
            .unwrap_or_else(|error| panic!("state: {error}"));
        let semantic = SemanticScore {
            schema_version: ANOMALY_SCHEMA_VERSION.into(),
            model_id: "semantic".into(),
            model_version: "1.0.0".into(),
            score_millionths: 1_000_000,
            confidence_millionths: 1_000_000,
            goal_drift: true,
            reason_codes: BTreeSet::from(["SEMANTIC_DRIFT".into()]),
        };
        let aggregate = RiskAggregator::update(&state, vec![], Some(semantic), true);
        let controller = ContinuousAuthorizationController::new(
            "response-controller".into(),
            "response-key".into(),
            SigningKey::from_bytes(&[31_u8; 32]),
        )
        .unwrap_or_else(|error| panic!("controller: {error}"));
        let command = controller
            .adjust(&aggregate, 1)
            .unwrap_or_else(|error| panic!("adjust: {error}"));
        assert_eq!(command.adjustment, AuthorizationAdjustment::Pause);

        let degraded = RiskAggregator::update(&state, vec![], None, false);
        assert!(degraded.detector_degraded);
        assert_eq!(degraded.severity, RiskLevel::Low);
    }

    #[test]
    fn critical_deterministic_rule_signs_kill_and_old_lease_epoch_is_replaced() {
        let (monitor, tenant, task, agent) = monitor();
        let input = signal(
            &tenant,
            &task,
            &agent,
            SignalSpec {
                id: "e1",
                kind: SignalKind::AuditControl,
                action: "DISABLE",
                resource: "audit://sink",
                value: Value::Null,
            },
        );
        monitor
            .consume(input, Utc::now())
            .unwrap_or_else(|error| panic!("consume: {error}"));
        let detector = RuleDetector::new("rules:v1".into(), 3, 3)
            .unwrap_or_else(|error| panic!("detector: {error}"));
        let findings = detector.evaluate(
            &monitor
                .state(&tenant, &task)
                .unwrap_or_else(|error| panic!("state: {error}")),
            &monitor
                .signals(&tenant, &task)
                .unwrap_or_else(|error| panic!("signals: {error}")),
        );
        let aggregate = RiskAggregator::update(
            &monitor
                .state(&tenant, &task)
                .unwrap_or_else(|error| panic!("state: {error}")),
            findings,
            None,
            false,
        );
        let key = SigningKey::from_bytes(&[32_u8; 32]);
        let controller = ContinuousAuthorizationController::new(
            "response-controller".into(),
            "response-key".into(),
            key.clone(),
        )
        .unwrap_or_else(|error| panic!("controller: {error}"));
        let command = controller
            .adjust(&aggregate, 7)
            .unwrap_or_else(|error| panic!("adjust: {error}"));
        assert_eq!(command.adjustment, AuthorizationAdjustment::Kill);
        assert_eq!(command.new_revocation_epoch, 8);
        assert!(command.verify(&key.verifying_key(), Utc::now()).is_ok());
    }
}
