use crate::{DOMAIN_PACKS_SCHEMA_VERSION, tool, unsigned_pack_manifest};
use agent_trust_contracts::{EffectClass, EvaluationStatus, RiskLevel, TenantId};
use agent_trust_pack_supply_chain::DomainPackManifest;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryResource {
    pub tenant_id: TenantId,
    pub repository_id: String,
    pub immutable_url: String,
    pub baseline_sha: String,
    pub task_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchPolicy {
    pub allowed_branch_prefix: String,
    pub protected_branches: BTreeSet<String>,
    pub allowed_path_prefixes: BTreeSet<String>,
    pub denied_paths: BTreeSet<String>,
    pub command_templates: BTreeSet<String>,
    pub network_destinations: BTreeSet<String>,
    pub maximum_changed_files: usize,
    pub maximum_deleted_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchPlan {
    pub schema_version: String,
    pub repository: RepositoryResource,
    pub changed_paths: BTreeSet<String>,
    pub deleted_lines: usize,
    pub dependency_changes: BTreeSet<String>,
    pub action_hash: String,
}

pub struct CodingToolProvider {
    policy: BranchPolicy,
}

impl CodingToolProvider {
    pub fn new(policy: BranchPolicy) -> Result<Self, CodingError> {
        if policy.allowed_branch_prefix.is_empty()
            || policy.allowed_path_prefixes.is_empty()
            || policy.command_templates.is_empty()
            || policy.maximum_changed_files == 0
        {
            return Err(CodingError::PolicyInvalid);
        }
        Ok(Self { policy })
    }

    pub fn validate_patch(&self, plan: &PatchPlan) -> Result<(), CodingError> {
        if plan.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || plan.repository.baseline_sha.len() < 7
            || !plan
                .repository
                .task_branch
                .starts_with(&self.policy.allowed_branch_prefix)
            || self
                .policy
                .protected_branches
                .contains(&plan.repository.task_branch)
            || plan.changed_paths.is_empty()
            || plan.changed_paths.len() > self.policy.maximum_changed_files
            || plan.deleted_lines > self.policy.maximum_deleted_lines
            || plan.action_hash.len() != 64
        {
            return Err(CodingError::PatchDenied);
        }
        for path in &plan.changed_paths {
            let lower = path.to_ascii_lowercase();
            if path.starts_with('/')
                || path.split('/').any(|part| part == ".." || part.is_empty())
                || lower.ends_with(".pem")
                || lower.ends_with(".key")
                || lower == ".env"
                || lower.starts_with(".git/")
                || lower.contains("docker.sock")
                || self
                    .policy
                    .denied_paths
                    .iter()
                    .any(|denied| path == denied || path.starts_with(&format!("{denied}/")))
                || !self
                    .policy
                    .allowed_path_prefixes
                    .iter()
                    .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
            {
                return Err(CodingError::PathDenied);
            }
        }
        Ok(())
    }

    pub fn validate_command(
        &self,
        template_id: &str,
        requested_network: &BTreeSet<String>,
    ) -> Result<(), CodingError> {
        if !self.policy.command_templates.contains(template_id)
            || !requested_network.is_subset(&self.policy.network_destinations)
            || template_id.to_ascii_lowercase().contains("shell")
        {
            return Err(CodingError::CommandDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildEvidence {
    pub baseline_sha: String,
    pub diff_hash: String,
    pub command_template: String,
    pub image_digest: String,
    pub exit_code: i32,
    pub artifact_digest: Option<String>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestEvidence {
    pub test_suite: String,
    pub test_count: u32,
    pub failed_count: u32,
    pub skipped_security_tests: u32,
    pub report_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiCompatibilityFinding {
    pub breaking: bool,
    pub symbol: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupplyChainFinding {
    pub severity: RiskLevel,
    pub component: String,
    pub reason_code: String,
    pub approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodingEvaluation {
    pub schema_version: String,
    pub status: EvaluationStatus,
    pub hard_gates: BTreeMap<String, bool>,
    pub evidence_refs: BTreeSet<String>,
    pub findings: BTreeSet<String>,
}

pub struct CodingEvaluator;

impl CodingEvaluator {
    pub fn evaluate(
        build: &BuildEvidence,
        tests: Option<&TestEvidence>,
        compatibility: &[ApiCompatibilityFinding],
        supply_chain: &[SupplyChainFinding],
        patch_scope_valid: bool,
    ) -> CodingEvaluation {
        let tests_pass = tests.is_some_and(|tests| {
            tests.test_count > 0
                && tests.failed_count == 0
                && tests.skipped_security_tests == 0
                && tests.report_digest.len() == 64
        });
        let hard_gates = BTreeMap::from([
            (
                "build".into(),
                build.exit_code == 0
                    && build
                        .artifact_digest
                        .as_deref()
                        .is_some_and(|digest| digest.len() == 64),
            ),
            ("tests".into(), tests_pass),
            (
                "api_compatibility".into(),
                compatibility.iter().all(|finding| !finding.breaking),
            ),
            (
                "supply_chain".into(),
                supply_chain
                    .iter()
                    .all(|finding| finding.severity < RiskLevel::High || finding.approved),
            ),
            ("patch_scope".into(), patch_scope_valid),
        ]);
        let passed = hard_gates.values().all(|value| *value);
        let evidence_refs = tests
            .map(|tests| {
                BTreeSet::from([
                    format!("build:{}", build.diff_hash),
                    format!("tests:{}", tests.report_digest),
                ])
            })
            .unwrap_or_default();
        CodingEvaluation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            status: if passed {
                EvaluationStatus::Pass
            } else {
                EvaluationStatus::Fail
            },
            hard_gates,
            evidence_refs,
            findings: if passed {
                BTreeSet::new()
            } else {
                BTreeSet::from(["CODING_HARD_GATE_FAILED".into()])
            },
        }
    }
}

#[derive(Default)]
pub struct GitProxyAdapter {
    branches: Mutex<BTreeMap<String, String>>,
    pull_requests: Mutex<BTreeMap<String, String>>,
}

impl GitProxyAdapter {
    pub fn create_task_branch(
        &self,
        task_id: &str,
        baseline_sha: &str,
    ) -> Result<String, CodingError> {
        if task_id.is_empty() || baseline_sha.len() < 7 {
            return Err(CodingError::GitOperationDenied);
        }
        let mut branches = self.branches.lock();
        Ok(branches
            .entry(task_id.into())
            .or_insert_with(|| format!("agent-task/{task_id}"))
            .clone())
    }

    pub fn create_pull_request(
        &self,
        task_id: &str,
        branch: &str,
        build_passed: bool,
    ) -> Result<String, CodingError> {
        if !build_passed || !branch.starts_with("agent-task/") {
            return Err(CodingError::GitOperationDenied);
        }
        let mut pull_requests = self.pull_requests.lock();
        Ok(pull_requests
            .entry(task_id.into())
            .or_insert_with(|| format!("pr:{task_id}"))
            .clone())
    }

    pub fn rollback(&self, task_id: &str, baseline_sha: &str) -> Result<String, CodingError> {
        if baseline_sha.len() < 7 {
            return Err(CodingError::GitOperationDenied);
        }
        self.branches.lock().remove(task_id);
        self.pull_requests.lock().remove(task_id);
        Ok(baseline_sha.into())
    }
}

pub fn manifest() -> DomainPackManifest {
    unsigned_pack_manifest(
        "coding",
        "Repository, build, test, dependency, and pull-request safety controls",
        vec![
            tool(
                "coding.repo_read",
                EffectClass::Pure,
                false,
                None,
                None,
                "coding-read-v1",
            ),
            tool(
                "coding.workspace_patch",
                EffectClass::Compensatable,
                true,
                Some("coding.workspace_reset"),
                None,
                "coding-patch-v1",
            ),
            tool(
                "coding.build_run",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "coding-build-v1",
            ),
            tool(
                "coding.tests_run",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "coding-test-v1",
            ),
            tool(
                "coding.pull_request_create",
                EffectClass::Compensatable,
                true,
                Some("coding.pull_request_close"),
                None,
                "coding-pr-v1",
            ),
        ],
        BTreeSet::from(["SOURCE_CODE".into()]),
        BTreeSet::from([
            "CODING_PATH_TRAVERSAL".into(),
            "CODING_SECRET_READ".into(),
            "CODING_MALICIOUS_BUILD".into(),
            "CODING_DEPENDENCY_POISONING".into(),
        ]),
    )
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodingError {
    #[error("CODING_POLICY_INVALID")]
    PolicyInvalid,
    #[error("CODING_PATCH_DENIED")]
    PatchDenied,
    #[error("CODING_PATH_DENIED")]
    PathDenied,
    #[error("CODING_COMMAND_DENIED")]
    CommandDenied,
    #[error("CODING_GIT_OPERATION_DENIED")]
    GitOperationDenied,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> CodingToolProvider {
        CodingToolProvider::new(BranchPolicy {
            allowed_branch_prefix: "agent-task/".into(),
            protected_branches: BTreeSet::from(["main".into(), "master".into()]),
            allowed_path_prefixes: BTreeSet::from(["src".into(), "tests".into()]),
            denied_paths: BTreeSet::from([".github/workflows".into()]),
            command_templates: BTreeSet::from(["cargo-test-v1".into()]),
            network_destinations: BTreeSet::new(),
            maximum_changed_files: 20,
            maximum_deleted_lines: 500,
        })
        .unwrap_or_else(|error| panic!("provider: {error}"))
    }

    fn plan(path: &str) -> PatchPlan {
        PatchPlan {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            repository: RepositoryResource {
                tenant_id: TenantId::new(),
                repository_id: "repo:1".into(),
                immutable_url: "https://git.example/repo.git".into(),
                baseline_sha: "abcdef123456".into(),
                task_branch: "agent-task/123".into(),
            },
            changed_paths: BTreeSet::from([path.into()]),
            deleted_lines: 1,
            dependency_changes: BTreeSet::new(),
            action_hash: "a".repeat(64),
        }
    }

    #[test]
    fn secrets_traversal_shell_and_protected_branch_are_denied() {
        let provider = provider();
        assert_eq!(
            provider.validate_patch(&plan("../.env")),
            Err(CodingError::PathDenied)
        );
        assert_eq!(
            provider.validate_patch(&plan("src/private.pem")),
            Err(CodingError::PathDenied)
        );
        assert_eq!(
            provider.validate_command("arbitrary-shell", &BTreeSet::new()),
            Err(CodingError::CommandDenied)
        );
        let mut protected = plan("src/lib.rs");
        protected.repository.task_branch = "main".into();
        assert_eq!(
            provider.validate_patch(&protected),
            Err(CodingError::PatchDenied)
        );
    }

    #[test]
    fn missing_tests_cannot_pass_and_branch_pr_are_idempotent() {
        let evaluation = CodingEvaluator::evaluate(
            &BuildEvidence {
                baseline_sha: "abcdef1".into(),
                diff_hash: "d".repeat(64),
                command_template: "cargo-test-v1".into(),
                image_digest: "i".repeat(64),
                exit_code: 0,
                artifact_digest: Some("a".repeat(64)),
                completed_at: Utc::now(),
            },
            None,
            &[],
            &[],
            true,
        );
        assert_eq!(evaluation.status, EvaluationStatus::Fail);
        let git = GitProxyAdapter::default();
        let first = git
            .create_task_branch("task-1", "abcdef1")
            .unwrap_or_else(|error| panic!("branch: {error}"));
        assert_eq!(
            git.create_task_branch("task-1", "abcdef1")
                .unwrap_or_else(|error| panic!("branch retry: {error}")),
            first
        );
        let pr = git
            .create_pull_request("task-1", &first, true)
            .unwrap_or_else(|error| panic!("pr: {error}"));
        assert_eq!(
            git.create_pull_request("task-1", &first, true)
                .unwrap_or_else(|error| panic!("pr retry: {error}")),
            pr
        );
        assert_eq!(
            git.rollback("task-1", "abcdef1")
                .unwrap_or_else(|error| panic!("rollback: {error}")),
            "abcdef1"
        );
    }
}
