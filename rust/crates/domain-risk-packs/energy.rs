use crate::{DOMAIN_PACKS_SCHEMA_VERSION, tool, unsigned_pack_manifest};
use agent_trust_contracts::{EffectClass, EvaluationStatus, TenantId};
use agent_trust_pack_supply_chain::DomainPackManifest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnergyAsset {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub asset_id: String,
    pub minimum_power_kw: f64,
    pub maximum_power_kw: f64,
    pub minimum_soc: f64,
    pub maximum_soc: f64,
    pub minimum_voltage: f64,
    pub maximum_voltage: f64,
    pub minimum_frequency_hz: f64,
    pub maximum_frequency_hz: f64,
    pub maximum_temperature_c: f64,
    pub maximum_ramp_kw_per_minute: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnergyTelemetry {
    pub asset_id: String,
    pub power_kw: f64,
    pub soc: f64,
    pub voltage: f64,
    pub frequency_hz: f64,
    pub temperature_c: f64,
    pub quality_good: bool,
    pub sampled_at: DateTime<Utc>,
    pub resource_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForecastSnapshot {
    pub forecast_id: String,
    pub model_digest: String,
    pub training_data_digest: String,
    pub confidence_millionths: u32,
    pub ood_score_millionths: u32,
    pub generated_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DispatchStep {
    pub sequence: u32,
    pub power_kw: f64,
    pub duration_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DispatchPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub tenant_id: TenantId,
    pub asset_id: String,
    pub expected_resource_version: String,
    pub algorithm_id: String,
    pub algorithm_digest: String,
    pub solver_status: String,
    pub forecast_id: String,
    pub steps: Vec<DispatchStep>,
    pub idempotency_key: String,
}

pub struct ConstraintPolicyPack;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintThresholds {
    pub maximum_telemetry_age_seconds: i64,
    pub minimum_forecast_confidence: u32,
    pub maximum_ood_score: u32,
}

impl ConstraintPolicyPack {
    pub fn validate(
        asset: &EnergyAsset,
        telemetry: &EnergyTelemetry,
        forecast: &ForecastSnapshot,
        plan: &DispatchPlan,
        thresholds: ConstraintThresholds,
        now: DateTime<Utc>,
    ) -> Result<(), EnergyError> {
        if asset.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || plan.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || asset.tenant_id != plan.tenant_id
            || asset.asset_id != telemetry.asset_id
            || asset.asset_id != plan.asset_id
            || telemetry.resource_version != plan.expected_resource_version
            || !telemetry.quality_good
            || now
                .signed_duration_since(telemetry.sampled_at)
                .num_seconds()
                < 0
            || now
                .signed_duration_since(telemetry.sampled_at)
                .num_seconds()
                > thresholds.maximum_telemetry_age_seconds
            || now >= forecast.valid_until
            || forecast.confidence_millionths < thresholds.minimum_forecast_confidence
            || forecast.ood_score_millionths > thresholds.maximum_ood_score
            || forecast.forecast_id != plan.forecast_id
            || plan.algorithm_digest.len() != 64
            || plan.solver_status != "OPTIMAL"
            || plan.steps.is_empty()
            || plan.idempotency_key.is_empty()
        {
            return Err(EnergyError::PlanDenied);
        }
        if telemetry.soc < asset.minimum_soc
            || telemetry.soc > asset.maximum_soc
            || telemetry.voltage < asset.minimum_voltage
            || telemetry.voltage > asset.maximum_voltage
            || telemetry.frequency_hz < asset.minimum_frequency_hz
            || telemetry.frequency_hz > asset.maximum_frequency_hz
            || telemetry.temperature_c > asset.maximum_temperature_c
        {
            return Err(EnergyError::UnsafeTelemetry);
        }
        let mut prior = telemetry.power_kw;
        for step in &plan.steps {
            let minutes = f64::from(step.duration_seconds).max(1.0) / 60.0;
            if step.power_kw < asset.minimum_power_kw
                || step.power_kw > asset.maximum_power_kw
                || (step.power_kw - prior).abs() / minutes > asset.maximum_ramp_kw_per_minute
            {
                return Err(EnergyError::HardConstraintViolation);
            }
            prior = step.power_kw;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FallbackMode {
    DeterministicSafeControl,
    LastKnownSafe,
    ManualTakeover,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FallbackCommand {
    pub schema_version: String,
    pub asset_id: String,
    pub mode: FallbackMode,
    pub target_power_kw: f64,
    pub reason_code: String,
    pub independent_of_model: bool,
    pub activated_at: DateTime<Utc>,
}

pub struct FallbackController;

impl FallbackController {
    pub fn activate(
        asset: &EnergyAsset,
        telemetry: Option<&EnergyTelemetry>,
        reason: &str,
    ) -> FallbackCommand {
        let (mode, target) = match telemetry {
            Some(value)
                if value.quality_good
                    && value.soc >= asset.minimum_soc
                    && value.soc <= asset.maximum_soc =>
            {
                (
                    FallbackMode::DeterministicSafeControl,
                    value
                        .power_kw
                        .clamp(asset.minimum_power_kw, asset.maximum_power_kw),
                )
            }
            Some(value) => (
                FallbackMode::LastKnownSafe,
                value
                    .power_kw
                    .clamp(asset.minimum_power_kw, asset.maximum_power_kw),
            ),
            None => (
                FallbackMode::ManualTakeover,
                0.0_f64.clamp(asset.minimum_power_kw, asset.maximum_power_kw),
            ),
        };
        FallbackCommand {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            asset_id: asset.asset_id.clone(),
            mode,
            target_power_kw: target,
            reason_code: reason.into(),
            independent_of_model: true,
            activated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnergyOutcome {
    pub hard_constraint_violations: u32,
    pub stable: bool,
    pub fallback_available: bool,
    pub baseline_cost: f64,
    pub realized_cost: f64,
    pub peak_reduction_kw: f64,
    pub confidence_low: f64,
    pub confidence_high: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnergyEvaluation {
    pub schema_version: String,
    pub status: EvaluationStatus,
    pub hard_gates: BTreeMap<String, bool>,
    pub economic_improvement: f64,
    pub findings: BTreeSet<String>,
}

pub struct EnergyEvaluator;

impl EnergyEvaluator {
    pub fn evaluate(outcome: &EnergyOutcome) -> EnergyEvaluation {
        let hard_gates = BTreeMap::from([
            (
                "hard_constraints".into(),
                outcome.hard_constraint_violations == 0,
            ),
            ("stability".into(), outcome.stable),
            ("fallback".into(), outcome.fallback_available),
            (
                "uncertainty".into(),
                outcome.confidence_low.is_finite()
                    && outcome.confidence_high >= outcome.confidence_low,
            ),
        ]);
        let economic_improvement = outcome.baseline_cost - outcome.realized_cost;
        let passed = hard_gates.values().all(|passed| *passed);
        EnergyEvaluation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            status: if passed {
                EvaluationStatus::Pass
            } else {
                EvaluationStatus::Fail
            },
            hard_gates,
            economic_improvement,
            findings: if passed {
                BTreeSet::new()
            } else {
                BTreeSet::from(["ENERGY_HARD_GATE_FAILED".into()])
            },
        }
    }
}

pub fn manifest() -> DomainPackManifest {
    unsigned_pack_manifest(
        "energy",
        "Energy forecast, hard constraint, dispatch, fallback, and outcome controls",
        vec![
            tool(
                "energy.telemetry_read",
                EffectClass::Pure,
                false,
                None,
                None,
                "energy-read-v1",
            ),
            tool(
                "energy.forecast_run",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "energy-forecast-v1",
            ),
            tool(
                "energy.optimize_plan",
                EffectClass::Pure,
                false,
                None,
                None,
                "energy-optimize-v1",
            ),
            tool(
                "energy.dispatch_prepare",
                EffectClass::Pure,
                true,
                None,
                None,
                "energy-prepare-v1",
            ),
            tool(
                "energy.dispatch_commit",
                EffectClass::Compensatable,
                true,
                Some("energy.fallback_activate"),
                None,
                "energy-dispatch-v1",
            ),
            tool(
                "energy.fallback_activate",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "energy-fallback-v1",
            ),
        ],
        BTreeSet::from(["ENERGY_TELEMETRY".into()]),
        BTreeSet::from([
            "ENERGY_SOC_OUT_OF_RANGE".into(),
            "ENERGY_FORECAST_DRIFT".into(),
            "ENERGY_RL_OOD".into(),
            "ENERGY_COMMUNICATION_DELAY".into(),
        ]),
    )
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum EnergyError {
    #[error("ENERGY_PLAN_DENIED")]
    PlanDenied,
    #[error("ENERGY_UNSAFE_TELEMETRY")]
    UnsafeTelemetry,
    #[error("ENERGY_HARD_CONSTRAINT_VIOLATION")]
    HardConstraintViolation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn asset() -> EnergyAsset {
        EnergyAsset {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            tenant_id: TenantId::new(),
            asset_id: "battery:1".into(),
            minimum_power_kw: -100.0,
            maximum_power_kw: 100.0,
            minimum_soc: 0.1,
            maximum_soc: 0.9,
            minimum_voltage: 380.0,
            maximum_voltage: 420.0,
            minimum_frequency_hz: 49.5,
            maximum_frequency_hz: 50.5,
            maximum_temperature_c: 50.0,
            maximum_ramp_kw_per_minute: 60.0,
        }
    }

    #[test]
    fn model_output_cannot_bypass_hard_constraints_and_stale_data_falls_back() {
        let asset = asset();
        let telemetry = EnergyTelemetry {
            asset_id: asset.asset_id.clone(),
            power_kw: 0.0,
            soc: 0.5,
            voltage: 400.0,
            frequency_hz: 50.0,
            temperature_c: 25.0,
            quality_good: true,
            sampled_at: Utc::now() - Duration::minutes(10),
            resource_version: "v1".into(),
        };
        let forecast = ForecastSnapshot {
            forecast_id: "f1".into(),
            model_digest: "m".repeat(64),
            training_data_digest: "t".repeat(64),
            confidence_millionths: 900_000,
            ood_score_millionths: 10_000,
            generated_at: Utc::now(),
            valid_until: Utc::now() + Duration::hours(1),
        };
        let plan = DispatchPlan {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            plan_id: "p1".into(),
            tenant_id: asset.tenant_id.clone(),
            asset_id: asset.asset_id.clone(),
            expected_resource_version: "v1".into(),
            algorithm_id: "rl".into(),
            algorithm_digest: "a".repeat(64),
            solver_status: "OPTIMAL".into(),
            forecast_id: "f1".into(),
            steps: vec![DispatchStep {
                sequence: 1,
                power_kw: 1000.0,
                duration_seconds: 60,
            }],
            idempotency_key: "dispatch:1".into(),
        };
        assert_eq!(
            ConstraintPolicyPack::validate(
                &asset,
                &telemetry,
                &forecast,
                &plan,
                ConstraintThresholds {
                    maximum_telemetry_age_seconds: 60,
                    minimum_forecast_confidence: 800_000,
                    maximum_ood_score: 100_000,
                },
                Utc::now()
            ),
            Err(EnergyError::PlanDenied)
        );
        assert!(
            FallbackController::activate(&asset, Some(&telemetry), "STALE_DATA")
                .independent_of_model
        );
    }

    #[test]
    fn economic_gain_never_hides_safety_failure() {
        let evaluation = EnergyEvaluator::evaluate(&EnergyOutcome {
            hard_constraint_violations: 1,
            stable: true,
            fallback_available: true,
            baseline_cost: 1000.0,
            realized_cost: 1.0,
            peak_reduction_kw: 100.0,
            confidence_low: 900.0,
            confidence_high: 1100.0,
        });
        assert_eq!(evaluation.status, EvaluationStatus::Fail);
        assert!(evaluation.economic_improvement > 0.0);
    }
}
