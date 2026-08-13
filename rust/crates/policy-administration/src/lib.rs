//! Immutable policy lifecycle, simulation, promotion, rollback, and exception governance.

use agent_trust_contracts::{Decision, RiskLevel, TenantId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const POLICY_ADMIN_SCHEMA_VERSION: &str = "agenttrust.policy-admin.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub rule_id: String,
    pub subject_pattern: String,
    pub tool_pattern: String,
    pub resource_pattern: String,
    pub decision: Decision,
    pub maximum_risk: RiskLevel,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySource {
    pub schema_version: String,
    pub source_id: String,
    pub tenant_id: TenantId,
    pub version: String,
    pub rules: Vec<PolicyRule>,
    pub default_decision: Decision,
    pub author: String,
    pub source_digest: String,
    pub created_at: DateTime<Utc>,
}

impl PolicySource {
    pub fn compute_digest(&self) -> Result<String, PolicyAdminError> {
        let mut copy = self.clone();
        copy.source_digest.clear();
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(&copy).map_err(|_| PolicyAdminError::Canonicalization)?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaticFinding {
    pub code: String,
    pub rule_ids: BTreeSet<String>,
    pub blocking: bool,
}

pub struct StaticAnalyzer;

impl StaticAnalyzer {
    pub fn analyze(source: &PolicySource) -> Vec<StaticFinding> {
        let mut findings = Vec::new();
        if source.default_decision == Decision::Allow {
            findings.push(StaticFinding {
                code: "DEFAULT_ALLOW_DENIED".into(),
                rule_ids: BTreeSet::new(),
                blocking: true,
            });
        }
        let mut ids = BTreeSet::new();
        for rule in &source.rules {
            if !ids.insert(rule.rule_id.clone()) {
                findings.push(StaticFinding {
                    code: "DUPLICATE_RULE_ID".into(),
                    rule_ids: BTreeSet::from([rule.rule_id.clone()]),
                    blocking: true,
                });
            }
            if rule.decision == Decision::Allow
                && rule.subject_pattern == "*"
                && rule.tool_pattern == "*"
                && rule.resource_pattern == "*"
            {
                findings.push(StaticFinding {
                    code: "OVERBROAD_ALLOW".into(),
                    rule_ids: BTreeSet::from([rule.rule_id.clone()]),
                    blocking: true,
                });
            }
            if rule.rule_id.is_empty()
                || rule.subject_pattern.is_empty()
                || rule.tool_pattern.is_empty()
                || rule.resource_pattern.is_empty()
                || rule.reason_code.is_empty()
            {
                findings.push(StaticFinding {
                    code: "RULE_FIELD_INVALID".into(),
                    rule_ids: BTreeSet::from([rule.rule_id.clone()]),
                    blocking: true,
                });
            }
        }
        for (index, left) in source.rules.iter().enumerate() {
            for right in source.rules.iter().skip(index + 1) {
                if left.subject_pattern == right.subject_pattern
                    && left.tool_pattern == right.tool_pattern
                    && left.resource_pattern == right.resource_pattern
                    && left.maximum_risk == right.maximum_risk
                    && left.decision != right.decision
                {
                    findings.push(StaticFinding {
                        code: "CONFLICTING_RULES".into(),
                        rule_ids: BTreeSet::from([left.rule_id.clone(), right.rule_id.clone()]),
                        blocking: true,
                    });
                }
            }
        }
        findings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub tenant_id: TenantId,
    pub version: String,
    pub source_digest: String,
    pub bundle_digest: String,
    pub rules: Vec<PolicyRule>,
    pub default_decision: Decision,
    pub review_ids: BTreeSet<String>,
    pub key_id: String,
    pub signature: String,
    pub compiled_at: DateTime<Utc>,
}

impl PolicyBundle {
    fn signing_bytes(&self) -> Result<Vec<u8>, PolicyAdminError> {
        let mut copy = self.clone();
        copy.bundle_digest.clear();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| PolicyAdminError::Canonicalization)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), PolicyAdminError> {
        let expected = hex(Sha256::digest(self.signing_bytes()?));
        if self.bundle_digest != expected || self.review_ids.is_empty() {
            return Err(PolicyAdminError::BundleInvalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| PolicyAdminError::BundleInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| PolicyAdminError::BundleInvalid)?;
        key.verify(self.bundle_digest.as_bytes(), &signature)
            .map_err(|_| PolicyAdminError::BundleInvalid)
    }
}

pub struct PolicyCompiler {
    key_id: String,
    signing_key: SigningKey,
}

impl PolicyCompiler {
    pub fn new(key_id: String, signing_key: SigningKey) -> Result<Self, PolicyAdminError> {
        if key_id.is_empty() {
            return Err(PolicyAdminError::ConfigurationInvalid);
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    pub fn compile(
        &self,
        source: &PolicySource,
        review_ids: BTreeSet<String>,
    ) -> Result<PolicyBundle, PolicyAdminError> {
        if source.schema_version != POLICY_ADMIN_SCHEMA_VERSION
            || source.source_id.is_empty()
            || source.author.is_empty()
            || source.rules.is_empty()
            || source.source_digest != source.compute_digest()?
            || review_ids.is_empty()
            || StaticAnalyzer::analyze(source)
                .iter()
                .any(|finding| finding.blocking)
        {
            return Err(PolicyAdminError::SourceDenied);
        }
        let mut bundle = PolicyBundle {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            bundle_id: Uuid::new_v4().to_string(),
            tenant_id: source.tenant_id.clone(),
            version: source.version.clone(),
            source_digest: source.source_digest.clone(),
            bundle_digest: String::new(),
            rules: source.rules.clone(),
            default_decision: source.default_decision,
            review_ids,
            key_id: self.key_id.clone(),
            signature: String::new(),
            compiled_at: Utc::now(),
        };
        bundle.bundle_digest = hex(Sha256::digest(bundle.signing_bytes()?));
        bundle.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(bundle.bundle_digest.as_bytes())
                .to_bytes(),
        );
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAction {
    pub action_id: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub subject: String,
    pub tool: String,
    pub resource: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionResult {
    pub action_id: String,
    pub decision: Decision,
    pub reason_codes: BTreeSet<String>,
}

pub struct SimulationEngine;

impl SimulationEngine {
    pub fn evaluate(bundle: &PolicyBundle, action: &PolicyAction) -> DecisionResult {
        let mut matched = bundle
            .rules
            .iter()
            .filter(|rule| {
                pattern_matches(&rule.subject_pattern, &action.subject)
                    && pattern_matches(&rule.tool_pattern, &action.tool)
                    && pattern_matches(&rule.resource_pattern, &action.resource)
                    && action.risk <= rule.maximum_risk
            })
            .collect::<Vec<_>>();
        matched.sort_by_key(|rule| decision_priority(rule.decision));
        let decision = matched
            .first()
            .map_or(bundle.default_decision, |rule| rule.decision);
        let reason_codes = matched
            .iter()
            .map(|rule| rule.reason_code.clone())
            .collect();
        DecisionResult {
            action_id: action.action_id.clone(),
            decision,
            reason_codes,
        }
    }

    pub fn shadow_compare(
        old: &PolicyBundle,
        new: &PolicyBundle,
        actions: &[PolicyAction],
    ) -> ImpactReport {
        let differences = actions
            .iter()
            .filter_map(|action| {
                let old_result = Self::evaluate(old, action);
                let new_result = Self::evaluate(new, action);
                (old_result.decision != new_result.decision).then_some(DecisionDifference {
                    action_id: action.action_id.clone(),
                    agent_id: action.agent_id.clone(),
                    tool: action.tool.clone(),
                    resource: action.resource.clone(),
                    risk: action.risk,
                    old_decision: old_result.decision,
                    new_decision: new_result.decision,
                })
            })
            .collect::<Vec<_>>();
        ImpactReport {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            old_bundle_digest: old.bundle_digest.clone(),
            new_bundle_digest: new.bundle_digest.clone(),
            evaluated_actions: actions.len(),
            differences,
            side_effect_count: 0,
            generated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionDifference {
    pub action_id: String,
    pub agent_id: String,
    pub tool: String,
    pub resource: String,
    pub risk: RiskLevel,
    pub old_decision: Decision,
    pub new_decision: Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactReport {
    pub schema_version: String,
    pub old_bundle_digest: String,
    pub new_bundle_digest: String,
    pub evaluated_actions: usize,
    pub differences: Vec<DecisionDifference>,
    pub side_effect_count: u32,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PromotionEnvironment {
    Dev,
    Staging,
    Canary,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionRecord {
    pub tenant_id: TenantId,
    pub environment: PromotionEnvironment,
    pub bundle_digest: String,
    pub previous_digest: Option<String>,
    pub promoted_by: String,
    pub promoted_at: DateTime<Utc>,
    pub rolled_back: bool,
}

#[derive(Default)]
pub struct PromotionController {
    active: RwLock<BTreeMap<(TenantId, PromotionEnvironment), PromotionRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistributionAcknowledgement {
    pub service: String,
    pub environment: PromotionEnvironment,
    pub bundle_digest: String,
    pub active: bool,
    pub evidence_ref: String,
    pub acknowledged_at: DateTime<Utc>,
}

pub trait PolicyDistributionPort: Send + Sync {
    fn publish(
        &self,
        bundle: &PolicyBundle,
        environment: PromotionEnvironment,
        idempotency_key: &str,
    ) -> Result<DistributionAcknowledgement, PolicyAdminError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyPublication {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub environment: PromotionEnvironment,
    pub bundle_digest: String,
    pub acknowledgements: BTreeMap<String, DistributionAcknowledgement>,
    pub converged: bool,
    pub evidence_digest: String,
}

pub struct PolicyPublisher<P: PolicyDistributionPort> {
    targets: BTreeMap<String, P>,
}

impl<P: PolicyDistributionPort> PolicyPublisher<P> {
    pub fn new(targets: BTreeMap<String, P>) -> Result<Self, PolicyAdminError> {
        if targets.is_empty() || targets.len() > 100 || targets.keys().any(String::is_empty) {
            return Err(PolicyAdminError::ConfigurationInvalid);
        }
        Ok(Self { targets })
    }

    pub fn publish(
        &self,
        promotion: &PromotionRecord,
        bundle: &PolicyBundle,
        command_id: &str,
    ) -> Result<PolicyPublication, PolicyAdminError> {
        if command_id.is_empty()
            || promotion.tenant_id != bundle.tenant_id
            || promotion.bundle_digest != bundle.bundle_digest
            || promotion.rolled_back
        {
            return Err(PolicyAdminError::PublicationDenied);
        }
        let mut acknowledgements = BTreeMap::new();
        for (name, target) in &self.targets {
            let acknowledgement = target.publish(
                bundle,
                promotion.environment,
                &format!("{command_id}:{name}"),
            )?;
            if acknowledgement.service != *name
                || acknowledgement.environment != promotion.environment
                || acknowledgement.bundle_digest != bundle.bundle_digest
                || !acknowledgement.active
                || acknowledgement.evidence_ref.is_empty()
                || acknowledgement.acknowledged_at < promotion.promoted_at
            {
                return Err(PolicyAdminError::PublicationFailed);
            }
            acknowledgements.insert(name.clone(), acknowledgement);
        }
        let evidence_digest = hex(Sha256::digest(
            serde_jcs::to_vec(&(promotion, bundle.bundle_digest.as_str(), &acknowledgements))
                .map_err(|_| PolicyAdminError::Canonicalization)?,
        ));
        Ok(PolicyPublication {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            tenant_id: bundle.tenant_id.clone(),
            environment: promotion.environment,
            bundle_digest: bundle.bundle_digest.clone(),
            acknowledgements,
            converged: true,
            evidence_digest,
        })
    }
}

pub struct PolicyRepository {
    maximum_sources: usize,
    maximum_bundles: usize,
    sources: RwLock<BTreeMap<(TenantId, String, String), PolicySource>>,
    bundles: RwLock<BTreeMap<(TenantId, String), PolicyBundle>>,
}

impl PolicyRepository {
    pub fn new(maximum_sources: usize, maximum_bundles: usize) -> Result<Self, PolicyAdminError> {
        if maximum_sources == 0 || maximum_bundles == 0 {
            return Err(PolicyAdminError::ConfigurationInvalid);
        }
        Ok(Self {
            maximum_sources,
            maximum_bundles,
            sources: RwLock::new(BTreeMap::new()),
            bundles: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn save_source(&self, source: PolicySource) -> Result<(), PolicyAdminError> {
        if source.schema_version != POLICY_ADMIN_SCHEMA_VERSION
            || source.source_digest != source.compute_digest()?
        {
            return Err(PolicyAdminError::SourceDenied);
        }
        let key = (
            source.tenant_id.clone(),
            source.source_id.clone(),
            source.version.clone(),
        );
        let mut sources = self.sources.write();
        if let Some(existing) = sources.get(&key) {
            return if existing.source_digest == source.source_digest {
                Ok(())
            } else {
                Err(PolicyAdminError::RepositoryConflict)
            };
        }
        if sources.len() >= self.maximum_sources {
            return Err(PolicyAdminError::RepositoryCapacityExceeded);
        }
        sources.insert(key, source);
        Ok(())
    }

    pub fn save_bundle(&self, bundle: PolicyBundle) -> Result<(), PolicyAdminError> {
        let key = (bundle.tenant_id.clone(), bundle.bundle_digest.clone());
        let mut bundles = self.bundles.write();
        if let Some(existing) = bundles.get(&key) {
            return if existing == &bundle {
                Ok(())
            } else {
                Err(PolicyAdminError::RepositoryConflict)
            };
        }
        if bundles.len() >= self.maximum_bundles {
            return Err(PolicyAdminError::RepositoryCapacityExceeded);
        }
        bundles.insert(key, bundle);
        Ok(())
    }

    pub fn bundle(
        &self,
        tenant: &TenantId,
        digest: &str,
    ) -> Result<PolicyBundle, PolicyAdminError> {
        self.bundles
            .read()
            .get(&(tenant.clone(), digest.into()))
            .cloned()
            .ok_or(PolicyAdminError::NotFound)
    }
}

impl PromotionController {
    pub fn promote(
        &self,
        tenant: TenantId,
        environment: PromotionEnvironment,
        bundle: &PolicyBundle,
        actor: String,
        impact: &ImpactReport,
        high_risk_reviewed: bool,
    ) -> Result<PromotionRecord, PolicyAdminError> {
        if actor.is_empty()
            || bundle.tenant_id != tenant
            || impact.new_bundle_digest != bundle.bundle_digest
            || impact.evaluated_actions == 0
            || environment == PromotionEnvironment::Production && !high_risk_reviewed
        {
            return Err(PolicyAdminError::PromotionDenied);
        }
        let mut active = self.active.write();
        let key = (tenant.clone(), environment);
        let previous_digest = active.get(&key).map(|record| record.bundle_digest.clone());
        let record = PromotionRecord {
            tenant_id: tenant,
            environment,
            bundle_digest: bundle.bundle_digest.clone(),
            previous_digest,
            promoted_by: actor,
            promoted_at: Utc::now(),
            rolled_back: false,
        };
        active.insert(key, record.clone());
        Ok(record)
    }

    pub fn observe_canary(
        &self,
        tenant: &TenantId,
        denial_rate_millionths: u32,
        error_rate_millionths: u32,
        maximum_denial_rate_millionths: u32,
        maximum_error_rate_millionths: u32,
    ) -> Result<PromotionRecord, PolicyAdminError> {
        let key = (tenant.clone(), PromotionEnvironment::Canary);
        let mut active = self.active.write();
        let record = active.get_mut(&key).ok_or(PolicyAdminError::NotFound)?;
        if denial_rate_millionths <= maximum_denial_rate_millionths
            && error_rate_millionths <= maximum_error_rate_millionths
        {
            return Ok(record.clone());
        }
        let previous = record
            .previous_digest
            .clone()
            .ok_or(PolicyAdminError::RollbackUnavailable)?;
        record.bundle_digest = previous;
        record.rolled_back = true;
        Ok(record.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionGrant {
    pub schema_version: String,
    pub exception_id: String,
    pub tenant_id: TenantId,
    pub owner: String,
    pub scope: BTreeSet<String>,
    pub reason_code: String,
    pub compensating_controls: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
pub struct ExceptionService {
    grants: RwLock<BTreeMap<(TenantId, String), ExceptionGrant>>,
}

impl ExceptionService {
    pub fn issue(&self, grant: ExceptionGrant, reviewer: &str) -> Result<(), PolicyAdminError> {
        if grant.schema_version != POLICY_ADMIN_SCHEMA_VERSION
            || grant.exception_id.is_empty()
            || grant.owner.is_empty()
            || reviewer.is_empty()
            || reviewer == grant.owner
            || grant.scope.is_empty()
            || grant.reason_code.is_empty()
            || grant.compensating_controls.is_empty()
            || grant.expires_at <= Utc::now()
            || grant.expires_at > Utc::now() + Duration::days(30)
            || grant.revoked_at.is_some()
        {
            return Err(PolicyAdminError::ExceptionDenied);
        }
        self.grants
            .write()
            .insert((grant.tenant_id.clone(), grant.exception_id.clone()), grant);
        Ok(())
    }

    pub fn validate(
        &self,
        tenant: &TenantId,
        exception_id: &str,
        resource: &str,
        now: DateTime<Utc>,
    ) -> Result<(), PolicyAdminError> {
        let grant = self
            .grants
            .read()
            .get(&(tenant.clone(), exception_id.into()))
            .cloned()
            .ok_or(PolicyAdminError::NotFound)?;
        if now >= grant.expires_at
            || grant.revoked_at.is_some()
            || !grant
                .scope
                .iter()
                .any(|prefix| resource.starts_with(prefix))
        {
            return Err(PolicyAdminError::ExceptionDenied);
        }
        Ok(())
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    pattern == "*"
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| value.starts_with(prefix))
        || pattern == value
}

fn decision_priority(decision: Decision) -> u8 {
    match decision {
        Decision::Kill => 0,
        Decision::Deny => 1,
        Decision::Pause => 2,
        Decision::RequireApproval => 3,
        Decision::Allow => 4,
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
pub enum PolicyAdminError {
    #[error("POLICY_ADMIN_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("POLICY_ADMIN_CANONICALIZATION_FAILED")]
    Canonicalization,
    #[error("POLICY_ADMIN_SOURCE_DENIED")]
    SourceDenied,
    #[error("POLICY_ADMIN_BUNDLE_INVALID")]
    BundleInvalid,
    #[error("POLICY_ADMIN_PROMOTION_DENIED")]
    PromotionDenied,
    #[error("POLICY_ADMIN_ROLLBACK_UNAVAILABLE")]
    RollbackUnavailable,
    #[error("POLICY_ADMIN_EXCEPTION_DENIED")]
    ExceptionDenied,
    #[error("POLICY_ADMIN_NOT_FOUND")]
    NotFound,
    #[error("POLICY_ADMIN_PUBLICATION_DENIED")]
    PublicationDenied,
    #[error("POLICY_ADMIN_PUBLICATION_FAILED")]
    PublicationFailed,
    #[error("POLICY_ADMIN_REPOSITORY_CONFLICT")]
    RepositoryConflict,
    #[error("POLICY_ADMIN_REPOSITORY_CAPACITY_EXCEEDED")]
    RepositoryCapacityExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDistributionPort {
        service: String,
        active: bool,
    }

    impl PolicyDistributionPort for TestDistributionPort {
        fn publish(
            &self,
            bundle: &PolicyBundle,
            environment: PromotionEnvironment,
            _: &str,
        ) -> Result<DistributionAcknowledgement, PolicyAdminError> {
            Ok(DistributionAcknowledgement {
                service: self.service.clone(),
                environment,
                bundle_digest: bundle.bundle_digest.clone(),
                active: self.active,
                evidence_ref: format!("evidence:{}", self.service),
                acknowledged_at: Utc::now(),
            })
        }
    }

    fn source(tenant: &TenantId, version: &str, decision: Decision) -> PolicySource {
        let mut source = PolicySource {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            source_id: format!("source:{version}"),
            tenant_id: tenant.clone(),
            version: version.into(),
            rules: vec![PolicyRule {
                rule_id: "repo-rule".into(),
                subject_pattern: "agent:coding".into(),
                tool_pattern: "coding.*".into(),
                resource_pattern: "repo://allowed/*".into(),
                decision,
                maximum_risk: RiskLevel::High,
                reason_code: "REPO_SCOPE".into(),
            }],
            default_decision: Decision::Deny,
            author: "policy-author".into(),
            source_digest: String::new(),
            created_at: Utc::now(),
        };
        source.source_digest = source
            .compute_digest()
            .unwrap_or_else(|error| panic!("digest: {error}"));
        source
    }

    fn action(tenant: &TenantId) -> PolicyAction {
        PolicyAction {
            action_id: "action:1".into(),
            tenant_id: tenant.clone(),
            agent_id: "coding".into(),
            subject: "agent:coding".into(),
            tool: "coding.patch".into(),
            resource: "repo://allowed/src/lib.rs".into(),
            risk: RiskLevel::Medium,
        }
    }

    #[test]
    fn publication_requires_all_execution_targets_to_acknowledge_exact_digest() {
        let tenant = TenantId::new();
        let key = SigningKey::from_bytes(&[52_u8; 32]);
        let compiler = PolicyCompiler::new("policy-key".into(), key)
            .unwrap_or_else(|error| panic!("compiler: {error}"));
        let bundle = compiler
            .compile(
                &source(&tenant, "1.0.0", Decision::Allow),
                BTreeSet::from(["review:1".into()]),
            )
            .unwrap_or_else(|error| panic!("compile: {error}"));
        let promotion = PromotionRecord {
            tenant_id: tenant,
            environment: PromotionEnvironment::Canary,
            bundle_digest: bundle.bundle_digest.clone(),
            previous_digest: None,
            promoted_by: "policy-admin:1".into(),
            promoted_at: Utc::now(),
            rolled_back: false,
        };
        let publisher = PolicyPublisher::new(BTreeMap::from([
            (
                "gateway".into(),
                TestDistributionPort {
                    service: "gateway".into(),
                    active: true,
                },
            ),
            (
                "orchestrator".into(),
                TestDistributionPort {
                    service: "orchestrator".into(),
                    active: true,
                },
            ),
        ]))
        .unwrap_or_else(|error| panic!("publisher: {error}"));
        let publication = publisher
            .publish(&promotion, &bundle, "publish:1")
            .unwrap_or_else(|error| panic!("publish: {error}"));
        assert!(publication.converged);
        assert_eq!(publication.acknowledgements.len(), 2);
    }

    #[test]
    fn default_allow_and_conflicts_are_blocking() {
        let tenant = TenantId::new();
        let mut unsafe_source = source(&tenant, "1.0.0", Decision::Allow);
        unsafe_source.default_decision = Decision::Allow;
        assert!(
            StaticAnalyzer::analyze(&unsafe_source)
                .iter()
                .any(|finding| finding.code == "DEFAULT_ALLOW_DENIED")
        );
        unsafe_source.rules.push(PolicyRule {
            decision: Decision::Deny,
            rule_id: "conflict".into(),
            ..unsafe_source.rules[0].clone()
        });
        assert!(
            StaticAnalyzer::analyze(&unsafe_source)
                .iter()
                .any(|finding| finding.code == "CONFLICTING_RULES")
        );
    }

    #[test]
    fn simulation_has_no_side_effect_and_reports_impact() {
        let tenant = TenantId::new();
        let compiler =
            PolicyCompiler::new("policy-key".into(), SigningKey::from_bytes(&[51_u8; 32]))
                .unwrap_or_else(|error| panic!("compiler: {error}"));
        let old = compiler
            .compile(
                &source(&tenant, "1.0.0", Decision::Deny),
                BTreeSet::from(["review:1".into()]),
            )
            .unwrap_or_else(|error| panic!("old: {error}"));
        let new = compiler
            .compile(
                &source(&tenant, "1.1.0", Decision::Allow),
                BTreeSet::from(["review:2".into()]),
            )
            .unwrap_or_else(|error| panic!("new: {error}"));
        let impact = SimulationEngine::shadow_compare(&old, &new, &[action(&tenant)]);
        assert_eq!(impact.side_effect_count, 0);
        assert_eq!(impact.differences.len(), 1);
    }

    #[test]
    fn canary_regression_rolls_back_and_production_requires_review() {
        let tenant = TenantId::new();
        let key = SigningKey::from_bytes(&[52_u8; 32]);
        let compiler = PolicyCompiler::new("policy-key".into(), key.clone())
            .unwrap_or_else(|error| panic!("compiler: {error}"));
        let old = compiler
            .compile(
                &source(&tenant, "1.0.0", Decision::Deny),
                BTreeSet::from(["review:1".into()]),
            )
            .unwrap_or_else(|error| panic!("old: {error}"));
        let new = compiler
            .compile(
                &source(&tenant, "1.1.0", Decision::Allow),
                BTreeSet::from(["review:2".into()]),
            )
            .unwrap_or_else(|error| panic!("new: {error}"));
        assert!(new.verify(&key.verifying_key()).is_ok());
        let controller = PromotionController::default();
        let old_impact = ImpactReport {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            old_bundle_digest: old.bundle_digest.clone(),
            new_bundle_digest: old.bundle_digest.clone(),
            evaluated_actions: 1,
            differences: vec![],
            side_effect_count: 0,
            generated_at: Utc::now(),
        };
        controller
            .promote(
                tenant.clone(),
                PromotionEnvironment::Canary,
                &old,
                "reviewer".into(),
                &old_impact,
                true,
            )
            .unwrap_or_else(|error| panic!("old promote: {error}"));
        let impact = SimulationEngine::shadow_compare(&old, &new, &[action(&tenant)]);
        controller
            .promote(
                tenant.clone(),
                PromotionEnvironment::Canary,
                &new,
                "reviewer".into(),
                &impact,
                true,
            )
            .unwrap_or_else(|error| panic!("new promote: {error}"));
        let rolled = controller
            .observe_canary(&tenant, 900_000, 100_000, 100_000, 10_000)
            .unwrap_or_else(|error| panic!("observe: {error}"));
        assert!(rolled.rolled_back);
        assert_eq!(rolled.bundle_digest, old.bundle_digest);
        assert_eq!(
            controller.promote(
                tenant,
                PromotionEnvironment::Production,
                &new,
                "reviewer".into(),
                &impact,
                false
            ),
            Err(PolicyAdminError::PromotionDenied)
        );
    }

    #[test]
    fn exception_requires_separation_expiry_and_scope() {
        let tenant = TenantId::new();
        let service = ExceptionService::default();
        let grant = ExceptionGrant {
            schema_version: POLICY_ADMIN_SCHEMA_VERSION.into(),
            exception_id: "exception:1".into(),
            tenant_id: tenant.clone(),
            owner: "owner:1".into(),
            scope: BTreeSet::from(["repo://allowed".into()]),
            reason_code: "INCIDENT_RECOVERY".into(),
            compensating_controls: BTreeSet::from(["READ_ONLY".into()]),
            expires_at: Utc::now() + Duration::hours(1),
            revoked_at: None,
        };
        assert_eq!(
            service.issue(grant.clone(), "owner:1"),
            Err(PolicyAdminError::ExceptionDenied)
        );
        service
            .issue(grant, "reviewer:2")
            .unwrap_or_else(|error| panic!("issue: {error}"));
        assert!(
            service
                .validate(&tenant, "exception:1", "repo://allowed/file", Utc::now())
                .is_ok()
        );
        assert_eq!(
            service.validate(&tenant, "exception:1", "repo://other/file", Utc::now()),
            Err(PolicyAdminError::ExceptionDenied)
        );
    }
}
