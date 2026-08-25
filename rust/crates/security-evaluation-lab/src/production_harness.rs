//! Deterministic, bounded attack-harness safety primitives.
//!
//! These primitives make failure behavior testable; they are not evidence of real Linux isolation,
//! provider compatibility, or production red-team execution.

use crate::EvalLabError;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatSurface {
    ModelPrompt,
    ToolInvocation,
    McpDeclarationBehavior,
    A2aRecursiveDelegation,
    ContextPoisoning,
    IdentitySpoofing,
    ApprovalBypass,
    SandboxEscape,
    CredentialExfiltration,
    SlowFragmentedExfiltration,
    PhysicalControlSimulation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureInjection {
    RunnerCrash,
    CleanupFailure,
    DatasetCorruption,
    ModelProviderUnavailable,
    EvidenceDrop,
    DetectionServiceUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IsolationBoundary {
    pub environment_profile: String,
    pub environment_attestation_digest: String,
    pub target_environment: String,
    pub production_credentials_present: bool,
    pub production_network_route_present: bool,
    pub physical_write_capability_present: bool,
    pub digital_twin_only: bool,
    pub kill_switch_armed: bool,
}

impl IsolationBoundary {
    pub fn validate(&self) -> Result<(), EvalLabError> {
        if !self.environment_profile.starts_with("isolated-")
            || !is_digest(&self.environment_attestation_digest)
            || !matches!(
                self.target_environment.as_str(),
                "EPHEMERAL_SANDBOX" | "ISOLATED_TENANT" | "DIGITAL_TWIN"
            )
            || self.production_credentials_present
            || self.production_network_route_present
            || self.physical_write_capability_present
            || !self.kill_switch_armed
            || (self.target_environment == "DIGITAL_TWIN" && !self.digital_twin_only)
        {
            return Err(EvalLabError::EnvironmentDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignBudget {
    pub maximum_steps: u64,
    pub maximum_requests: u64,
    pub maximum_tokens: u64,
    pub maximum_cost_microunits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BudgetState {
    steps: u64,
    requests: u64,
    tokens: u64,
    cost_microunits: u64,
    killed: bool,
}

pub struct CampaignBudgetGuard {
    maximum: CampaignBudget,
    state: Mutex<BudgetState>,
}

impl CampaignBudgetGuard {
    pub fn new(maximum: CampaignBudget) -> Result<Self, EvalLabError> {
        if maximum.maximum_steps == 0
            || maximum.maximum_requests == 0
            || maximum.maximum_tokens == 0
            || maximum.maximum_cost_microunits == 0
        {
            return Err(EvalLabError::CampaignInvalid);
        }
        Ok(Self {
            maximum,
            state: Mutex::new(BudgetState {
                steps: 0,
                requests: 0,
                tokens: 0,
                cost_microunits: 0,
                killed: false,
            }),
        })
    }

    pub fn reserve(
        &self,
        steps: u64,
        requests: u64,
        tokens: u64,
        cost_microunits: u64,
    ) -> Result<(), EvalLabError> {
        if steps == 0 || requests == 0 {
            return Err(EvalLabError::CampaignInvalid);
        }
        let mut state = self.state.lock();
        let next = BudgetState {
            steps: state
                .steps
                .checked_add(steps)
                .ok_or(EvalLabError::CampaignInvalid)?,
            requests: state
                .requests
                .checked_add(requests)
                .ok_or(EvalLabError::CampaignInvalid)?,
            tokens: state
                .tokens
                .checked_add(tokens)
                .ok_or(EvalLabError::CampaignInvalid)?,
            cost_microunits: state
                .cost_microunits
                .checked_add(cost_microunits)
                .ok_or(EvalLabError::CampaignInvalid)?,
            killed: state.killed,
        };
        if state.killed
            || next.steps > self.maximum.maximum_steps
            || next.requests > self.maximum.maximum_requests
            || next.tokens > self.maximum.maximum_tokens
            || next.cost_microunits > self.maximum.maximum_cost_microunits
        {
            state.killed = true;
            return Err(EvalLabError::EnvironmentDenied);
        }
        *state = next;
        Ok(())
    }

    pub fn trip(&self) {
        self.state.lock().killed = true;
    }

    pub fn killed(&self) -> bool {
        self.state.lock().killed
    }
}

#[derive(Default)]
pub struct FailureController {
    active: Mutex<BTreeSet<FailureInjection>>,
}

impl FailureController {
    pub fn activate(&self, failure: FailureInjection) {
        self.active.lock().insert(failure);
    }

    pub fn clear(&self, failure: FailureInjection) {
        self.active.lock().remove(&failure);
    }

    pub fn check_dataset(&self) -> Result<(), EvalLabError> {
        if self
            .active
            .lock()
            .contains(&FailureInjection::DatasetCorruption)
        {
            Err(EvalLabError::DatasetInvalid)
        } else {
            Ok(())
        }
    }

    pub fn check_before_step(&self) -> Result<(), EvalLabError> {
        let active = self.active.lock();
        if active.contains(&FailureInjection::RunnerCrash)
            || active.contains(&FailureInjection::ModelProviderUnavailable)
        {
            Err(EvalLabError::ExecutionFailed)
        } else {
            Ok(())
        }
    }

    pub fn check_evidence(&self) -> Result<(), EvalLabError> {
        if self.active.lock().contains(&FailureInjection::EvidenceDrop) {
            Err(EvalLabError::ExecutionFailed)
        } else {
            Ok(())
        }
    }

    pub fn cleanup(&self) -> Result<(), EvalLabError> {
        if self
            .active
            .lock()
            .contains(&FailureInjection::CleanupFailure)
        {
            Err(EvalLabError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    pub fn baseline_guard_available(&self) -> bool {
        // Detector unavailability never disables deterministic baseline guards.
        true
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn isolation_rejects_production_network_and_physical_write() {
        let mut boundary = IsolationBoundary {
            environment_profile: "isolated-tenant-42".into(),
            environment_attestation_digest: "a".repeat(64),
            target_environment: "DIGITAL_TWIN".into(),
            production_credentials_present: false,
            production_network_route_present: false,
            physical_write_capability_present: false,
            digital_twin_only: true,
            kill_switch_armed: true,
        };
        assert!(boundary.validate().is_ok());
        boundary.production_network_route_present = true;
        assert_eq!(boundary.validate(), Err(EvalLabError::EnvironmentDenied));
        boundary.production_network_route_present = false;
        boundary.physical_write_capability_present = true;
        assert_eq!(boundary.validate(), Err(EvalLabError::EnvironmentDenied));
    }

    #[test]
    fn concurrent_budget_reservation_is_atomic_and_trips_closed() {
        let guard = Arc::new(
            CampaignBudgetGuard::new(CampaignBudget {
                maximum_steps: 32,
                maximum_requests: 32,
                maximum_tokens: 320,
                maximum_cost_microunits: 320,
            })
            .unwrap_or_else(|error| panic!("guard: {error}")),
        );
        let threads = (0..64)
            .map(|_| {
                let guard = guard.clone();
                std::thread::spawn(move || guard.reserve(1, 1, 10, 10))
            })
            .collect::<Vec<_>>();
        let successes = threads
            .into_iter()
            .filter(|thread| {
                thread
                    .join()
                    .unwrap_or_else(|_| panic!("thread panicked"))
                    .is_ok()
            })
            .count();
        assert_eq!(successes, 32);
        assert!(guard.killed());
        assert_eq!(
            guard.reserve(1, 1, 1, 1),
            Err(EvalLabError::EnvironmentDenied)
        );
    }

    #[test]
    fn injected_failures_are_explicit_and_baseline_guard_survives_detector_loss() {
        let controller = FailureController::default();
        controller.activate(FailureInjection::DatasetCorruption);
        controller.activate(FailureInjection::CleanupFailure);
        controller.activate(FailureInjection::EvidenceDrop);
        controller.activate(FailureInjection::DetectionServiceUnavailable);
        assert_eq!(
            controller.check_dataset(),
            Err(EvalLabError::DatasetInvalid)
        );
        assert_eq!(controller.cleanup(), Err(EvalLabError::CleanupFailed));
        assert_eq!(
            controller.check_evidence(),
            Err(EvalLabError::ExecutionFailed)
        );
        assert!(controller.baseline_guard_available());
    }
}
