use crate::{DOMAIN_PACKS_SCHEMA_VERSION, tool, unsigned_pack_manifest};
use agent_trust_contracts::{EffectClass, EvaluationStatus, RiskLevel, TenantId};
use agent_trust_industrial_edge_gateway::QualityCode;
use agent_trust_pack_supply_chain::DomainPackManifest;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndustrialStage {
    Simulator,
    Twin,
    ReadOnly,
    Shadow,
    LimitedWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndustrialAssetModel {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub resource_key: String,
    pub engineering_unit: String,
    pub minimum: f64,
    pub maximum: f64,
    pub maximum_delta: f64,
    pub maximum_rate_per_second: f64,
    pub maximum_freshness_ms: i64,
    pub criticality: RiskLevel,
    pub agent_control_prohibited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndustrialState {
    pub resource_key: String,
    pub value: f64,
    pub resource_version: String,
    pub quality: QualityCode,
    pub sampled_at: DateTime<Utc>,
    pub active_alarm_severity: Option<RiskLevel>,
    pub interlock_healthy: bool,
    pub maintenance_window_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetpointRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub resource_key: String,
    pub target: f64,
    pub engineering_unit: String,
    pub stage: IndustrialStage,
    pub action_hash: String,
    pub approval_id: Option<String>,
    pub stage_certificate_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetpointPreparation {
    pub schema_version: String,
    pub preparation_id: String,
    pub tenant_id: TenantId,
    pub resource_key: String,
    pub before_value: f64,
    pub target: f64,
    pub expected_resource_version: String,
    pub action_hash: String,
    pub approval_id: String,
    pub stage: IndustrialStage,
    pub prepared_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct IndustrialPolicyPack;

impl IndustrialPolicyPack {
    pub fn prepare(
        asset: &IndustrialAssetModel,
        state: &IndustrialState,
        request: &SetpointRequest,
        now: DateTime<Utc>,
    ) -> Result<SetpointPreparation, IndustrialError> {
        if asset.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || request.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || asset.tenant_id != request.tenant_id
            || asset.resource_key != request.resource_key
            || asset.resource_key != state.resource_key
            || asset.agent_control_prohibited
            || request.engineering_unit != asset.engineering_unit
            || request.action_hash.len() != 64
            || !matches!(
                request.stage,
                IndustrialStage::Simulator
                    | IndustrialStage::Shadow
                    | IndustrialStage::LimitedWrite
            )
            || request.stage == IndustrialStage::LimitedWrite
                && request
                    .stage_certificate_digest
                    .as_deref()
                    .is_none_or(|digest| digest.len() != 64)
            || request.approval_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(IndustrialError::WriteDenied);
        }
        if state.quality != QualityCode::Good
            || now
                .signed_duration_since(state.sampled_at)
                .num_milliseconds()
                < 0
            || now
                .signed_duration_since(state.sampled_at)
                .num_milliseconds()
                > asset.maximum_freshness_ms
            || !state.interlock_healthy
            || !state.maintenance_window_open
            || state
                .active_alarm_severity
                .is_some_and(|severity| severity >= RiskLevel::High)
        {
            return Err(IndustrialError::StateUnsafe);
        }
        if request.target < asset.minimum
            || request.target > asset.maximum
            || (request.target - state.value).abs() > asset.maximum_delta
        {
            return Err(IndustrialError::SetpointInvalid);
        }
        Ok(SetpointPreparation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            preparation_id: Uuid::new_v4().to_string(),
            tenant_id: request.tenant_id.clone(),
            resource_key: request.resource_key.clone(),
            before_value: state.value,
            target: request.target,
            expected_resource_version: state.resource_version.clone(),
            action_hash: request.action_hash.clone(),
            approval_id: request.approval_id.clone().unwrap_or_default(),
            stage: request.stage,
            prepared_at: now,
            expires_at: now + Duration::minutes(2),
        })
    }

    pub fn authorize_commit(
        preparation: &SetpointPreparation,
        current: &IndustrialState,
        approval_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), IndustrialError> {
        if now >= preparation.expires_at
            || current.resource_key != preparation.resource_key
            || current.resource_version != preparation.expected_resource_version
            || current.value != preparation.before_value
            || current.quality != QualityCode::Good
            || approval_id != preparation.approval_id
            || !current.interlock_healthy
            || current.active_alarm_severity.is_some()
        {
            return Err(IndustrialError::CommitStale);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryOutcome {
    pub target: f64,
    pub samples: Vec<(DateTime<Utc>, f64)>,
    pub new_alarm: bool,
    pub interlock_tripped: bool,
    pub communication_lost: bool,
    pub quality: QualityCode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndustrialEvaluation {
    pub schema_version: String,
    pub status: EvaluationStatus,
    pub hard_gates: BTreeMap<String, bool>,
    pub findings: BTreeSet<String>,
}

pub struct PhysicalEvaluator;

impl PhysicalEvaluator {
    pub fn evaluate(
        outcome: &TelemetryOutcome,
        tolerance: f64,
        required_stable_samples: usize,
    ) -> IndustrialEvaluation {
        let stable = outcome.samples.len() >= required_stable_samples
            && outcome
                .samples
                .iter()
                .rev()
                .take(required_stable_samples)
                .all(|(_, value)| (*value - outcome.target).abs() <= tolerance);
        let hard_gates = BTreeMap::from([
            (
                "telemetry_quality".into(),
                outcome.quality == QualityCode::Good,
            ),
            ("convergence".into(), stable),
            ("no_new_alarm".into(), !outcome.new_alarm),
            ("interlock".into(), !outcome.interlock_tripped),
            ("communication".into(), !outcome.communication_lost),
        ]);
        let status = if outcome.quality != QualityCode::Good {
            EvaluationStatus::NeedsHuman
        } else if hard_gates.values().all(|passed| *passed) {
            EvaluationStatus::Pass
        } else {
            EvaluationStatus::Fail
        };
        IndustrialEvaluation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            status,
            hard_gates,
            findings: if status == EvaluationStatus::Pass {
                BTreeSet::new()
            } else {
                BTreeSet::from(["PHYSICAL_OUTCOME_NOT_VERIFIED".into()])
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryAction {
    RestoreIfVersionUnchanged,
    SafeStop,
    ManualRecovery,
}

pub struct SafeRecoveryPlanner;

impl SafeRecoveryPlanner {
    pub fn plan(
        reversible: bool,
        current_version_matches: bool,
        interlock_tripped: bool,
        communication_lost: bool,
    ) -> RecoveryAction {
        if interlock_tripped || communication_lost {
            RecoveryAction::SafeStop
        } else if reversible && current_version_matches {
            RecoveryAction::RestoreIfVersionUnchanged
        } else {
            RecoveryAction::ManualRecovery
        }
    }
}

pub fn manifest() -> DomainPackManifest {
    unsigned_pack_manifest(
        "industrial",
        "Industrial asset, interlock, staged setpoint, recovery, and physical outcome controls",
        vec![
            tool(
                "industrial.telemetry_read",
                EffectClass::Pure,
                false,
                None,
                None,
                "industrial-read-v1",
            ),
            tool(
                "industrial.simulation_run",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "industrial-sim-v1",
            ),
            tool(
                "industrial.setpoint_prepare",
                EffectClass::Pure,
                true,
                None,
                None,
                "industrial-prepare-v1",
            ),
            tool(
                "industrial.setpoint_commit",
                EffectClass::Compensatable,
                true,
                Some("industrial.state_restore"),
                None,
                "industrial-commit-v1",
            ),
            tool(
                "industrial.operation_stop",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "industrial-stop-v1",
            ),
        ],
        BTreeSet::from(["INDUSTRIAL_TELEMETRY".into()]),
        BTreeSet::from([
            "INDUSTRIAL_STALE_STATE".into(),
            "INDUSTRIAL_INTERLOCK".into(),
            "INDUSTRIAL_THIRD_PARTY_CHANGE".into(),
            "INDUSTRIAL_OSCILLATION".into(),
        ]),
    )
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum IndustrialError {
    #[error("INDUSTRIAL_WRITE_DENIED")]
    WriteDenied,
    #[error("INDUSTRIAL_STATE_UNSAFE")]
    StateUnsafe,
    #[error("INDUSTRIAL_SETPOINT_INVALID")]
    SetpointInvalid,
    #[error("INDUSTRIAL_COMMIT_STALE")]
    CommitStale,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset() -> IndustrialAssetModel {
        IndustrialAssetModel {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            tenant_id: TenantId::new(),
            resource_key: "site/line/pump/setpoint".into(),
            engineering_unit: "bar".into(),
            minimum: 1.0,
            maximum: 10.0,
            maximum_delta: 1.0,
            maximum_rate_per_second: 0.2,
            maximum_freshness_ms: 1_000,
            criticality: RiskLevel::Medium,
            agent_control_prohibited: false,
        }
    }

    fn state(asset: &IndustrialAssetModel) -> IndustrialState {
        IndustrialState {
            resource_key: asset.resource_key.clone(),
            value: 5.0,
            resource_version: "version-1".into(),
            quality: QualityCode::Good,
            sampled_at: Utc::now(),
            active_alarm_severity: None,
            interlock_healthy: true,
            maintenance_window_open: true,
        }
    }

    fn request(asset: &IndustrialAssetModel) -> SetpointRequest {
        SetpointRequest {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            tenant_id: asset.tenant_id.clone(),
            resource_key: asset.resource_key.clone(),
            target: 5.5,
            engineering_unit: "bar".into(),
            stage: IndustrialStage::Simulator,
            action_hash: "a".repeat(64),
            approval_id: Some("approval:1".into()),
            stage_certificate_digest: None,
        }
    }

    #[test]
    fn alarm_interlock_range_and_post_approval_change_fail_closed() {
        let asset = asset();
        let mut current = state(&asset);
        current.active_alarm_severity = Some(RiskLevel::High);
        assert_eq!(
            IndustrialPolicyPack::prepare(&asset, &current, &request(&asset), Utc::now()),
            Err(IndustrialError::StateUnsafe)
        );
        current.active_alarm_severity = None;
        let preparation =
            IndustrialPolicyPack::prepare(&asset, &current, &request(&asset), Utc::now())
                .unwrap_or_else(|error| panic!("prepare: {error}"));
        current.resource_version = "changed".into();
        assert_eq!(
            IndustrialPolicyPack::authorize_commit(
                &preparation,
                &current,
                "approval:1",
                Utc::now()
            ),
            Err(IndustrialError::CommitStale)
        );
    }

    #[test]
    fn ack_without_convergence_fails_and_disconnect_safe_stops() {
        let outcome = TelemetryOutcome {
            target: 5.5,
            samples: vec![(Utc::now(), 5.1), (Utc::now(), 5.2)],
            new_alarm: false,
            interlock_tripped: false,
            communication_lost: false,
            quality: QualityCode::Good,
        };
        assert_eq!(
            PhysicalEvaluator::evaluate(&outcome, 0.05, 2).status,
            EvaluationStatus::Fail
        );
        assert_eq!(
            SafeRecoveryPlanner::plan(true, true, false, true),
            RecoveryAction::SafeStop
        );
    }
}
