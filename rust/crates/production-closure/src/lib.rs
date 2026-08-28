//! The only component allowed to issue an Agent Trust production-closure certificate.
//!
//! Earlier release-gate certificates are inputs to this gate, never substitutes for it.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const CLOSURE_SCHEMA_VERSION: &str = "agenttrust.production-closure.v1";
pub const REQUIRED_BATCH_FIRST: u8 = 1;
pub const REQUIRED_BATCH_LAST: u8 = 35;
pub const DOMAIN_ASSURANCE_SCHEMA_VERSION: &str = "agenttrust.domain-assurance-attestation.v1";
pub const EXTERNAL_GATE_ASSURANCE_SCHEMA_VERSION: &str =
    "agenttrust.external-gate-assurance-attestation.v1";
pub const EXTERNAL_SIGNING_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-signing-request.v1";
pub const EXTERNAL_SIGNATURE_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-external-signature.v1";
pub const CLOSURE_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-revocation-registry.v1";

const REQUIRED_GATES: [(&str, bool); 15] = [
    ("CONTRACT_COMPATIBILITY", false),
    ("SUPPLY_CHAIN_PROVENANCE", true),
    ("MULTITENANT_ISOLATION", true),
    ("IDEMPOTENCY_AND_RECOVERY", true),
    ("CONTINUOUS_AUTHORIZATION", true),
    ("DOMAIN_CODING", true),
    ("DOMAIN_INDUSTRIAL", true),
    ("DOMAIN_ENERGY", true),
    ("DOMAIN_MEDICAL", true),
    ("DOMAIN_SENSITIVE_INTERACTION", true),
    ("SECURITY_CAMPAIGN", true),
    ("HA_DR_RESTORE", true),
    ("UPGRADE_ROLLBACK", true),
    ("CONTROL_EVIDENCE_GRAPH", true),
    ("ENTERPRISE_ACCEPTANCE", true),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClosureScope {
    pub release_id: String,
    pub commit_digest: String,
    pub build_digest: String,
    pub policy_digest: String,
    pub pack_set_digest: String,
    pub prompt_set_digest: String,
    pub model_set_digest: String,
    pub topology_digest: String,
    pub environment: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl ClosureScope {
    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), ClosureError> {
        let digests = [
            &self.commit_digest,
            &self.build_digest,
            &self.policy_digest,
            &self.pack_set_digest,
            &self.prompt_set_digest,
            &self.model_set_digest,
            &self.topology_digest,
        ];
        if self.release_id.is_empty()
            || self.environment != "production"
            || digests.iter().any(|digest| !is_sha256(digest))
            || self.valid_from > now
            || self.valid_until <= now
            || self.valid_until <= self.valid_from
        {
            return Err(ClosureError::ScopeInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BatchStatus {
    NotStarted,
    InProgress,
    Implemented,
    EvidenceVerified,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchEvidenceStatus {
    pub batch: u8,
    pub status: BatchStatus,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceKind {
    UnitTest,
    IntegrationTest,
    RealEnvironment,
    IndependentAssurance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateEvidence {
    pub gate_id: String,
    pub scope_digest: String,
    pub passed: bool,
    pub evidence_kind: EvidenceKind,
    pub evidence_digests: BTreeMap<String, String>,
    pub environment_reference: Option<String>,
    pub measured_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub source_certificate_type: Option<String>,
}

/// A human-originated, scope-bound assurance record for domains where software
/// tests cannot substitute for qualified acceptance. Every listed reviewer
/// signs the same canonical payload, including the complete reviewer roster.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceDomain {
    Industrial,
    Medical,
    SensitiveInteraction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceDecision {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceReviewer {
    pub reviewer_id: String,
    pub organization: String,
    pub role: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAssuranceAttestation {
    pub schema_version: String,
    pub attestation_id: String,
    pub domain: AssuranceDomain,
    pub release_id: String,
    pub scope_digest: String,
    pub environment_reference: String,
    pub decision: AssuranceDecision,
    pub automated: bool,
    pub evidence_digests: BTreeMap<String, String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reviewers: Vec<AssuranceReviewer>,
}

impl DomainAssuranceAttestation {
    pub fn signing_payload(&self) -> Result<Vec<u8>, ClosureError> {
        let mut unsigned = self.clone();
        for reviewer in &mut unsigned.reviewers {
            reviewer.signature.clear();
        }
        serde_jcs::to_vec(&unsigned).map_err(|_| ClosureError::SerializationFailed)
    }

    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify_offline(
        &self,
        expected_scope_digest: &str,
        keys: &BTreeMap<String, VerifyingKey>,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        let required_roles: BTreeSet<&str> = match self.domain {
            AssuranceDomain::Industrial => BTreeSet::from(["SAFETY_ENGINEER", "OPERATIONS_OWNER"]),
            AssuranceDomain::Medical => {
                BTreeSet::from(["LICENSED_CLINICIAN", "PRIVACY_LEGAL_REVIEWER"])
            }
            AssuranceDomain::SensitiveInteraction => {
                BTreeSet::from(["SAFEGUARDING_LEAD", "HUMAN_SUPPORT_OWNER"])
            }
        };
        let reviewer_ids: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.reviewer_id.as_str())
            .collect();
        let key_ids: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.key_id.as_str())
            .collect();
        let roles: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.role.as_str())
            .collect();
        let duration = self.expires_at.signed_duration_since(self.issued_at);
        let valid = self.schema_version == DOMAIN_ASSURANCE_SCHEMA_VERSION
            && !self.attestation_id.is_empty()
            && !self.release_id.is_empty()
            && self.scope_digest == expected_scope_digest
            && is_sha256(&self.scope_digest)
            && self
                .environment_reference
                .starts_with("environment://production/")
            && self.decision == AssuranceDecision::Approved
            && !self.automated
            && !self.evidence_digests.is_empty()
            && self.evidence_digests.len() <= 256
            && self.evidence_digests.values().all(|value| is_sha256(value))
            && self.issued_at <= now
            && self.expires_at > now
            && duration > chrono::Duration::zero()
            && duration <= chrono::Duration::days(90)
            && (2..=10).contains(&self.reviewers.len())
            && reviewer_ids.len() == self.reviewers.len()
            && key_ids.len() == self.reviewers.len()
            && required_roles.is_subset(&roles)
            && self.reviewers.iter().all(|reviewer| {
                !reviewer.reviewer_id.is_empty()
                    && !reviewer.organization.is_empty()
                    && !reviewer.role.is_empty()
                    && !reviewer.key_id.is_empty()
                    && reviewer.signature.len() <= 128
            });
        if !valid {
            return Err(ClosureError::DomainAssuranceInvalid);
        }
        let payload = self.signing_payload()?;
        for reviewer in &self.reviewers {
            let key = keys
                .get(&reviewer.key_id)
                .ok_or(ClosureError::DomainAssuranceInvalid)?;
            let decoded = URL_SAFE_NO_PAD
                .decode(&reviewer.signature)
                .map_err(|_| ClosureError::DomainAssuranceInvalid)?;
            let signature = Signature::from_slice(&decoded)
                .map_err(|_| ClosureError::DomainAssuranceInvalid)?;
            key.verify(&payload, &signature)
                .map_err(|_| ClosureError::DomainAssuranceInvalid)?;
        }
        Ok(())
    }

    pub fn verified_gate_evidence(
        &self,
        expected_scope_digest: &str,
        keys: &BTreeMap<String, VerifyingKey>,
        now: DateTime<Utc>,
    ) -> Result<GateEvidence, ClosureError> {
        self.verify_offline(expected_scope_digest, keys, now)?;
        let gate_id = match self.domain {
            AssuranceDomain::Industrial => "DOMAIN_INDUSTRIAL",
            AssuranceDomain::Medical => "DOMAIN_MEDICAL",
            AssuranceDomain::SensitiveInteraction => "DOMAIN_SENSITIVE_INTERACTION",
        };
        Ok(GateEvidence {
            gate_id: gate_id.into(),
            scope_digest: self.scope_digest.clone(),
            passed: true,
            evidence_kind: EvidenceKind::IndependentAssurance,
            evidence_digests: BTreeMap::from([("attestation".into(), self.digest()?)]),
            environment_reference: Some(self.environment_reference.clone()),
            measured_at: self.issued_at,
            expires_at: self.expires_at,
            source_certificate_type: Some("DOMAIN_ASSURANCE_ATTESTATION".into()),
        })
    }
}

/// Multi-party real-environment attestation for gates whose production facts
/// cannot be established inside the repository. It is deliberately separate
/// from `GateEvidence`: callers must verify signatures before converting it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalGateAssuranceAttestation {
    pub schema_version: String,
    pub attestation_id: String,
    pub gate_id: String,
    pub release_id: String,
    pub scope_digest: String,
    pub environment_reference: String,
    pub decision: AssuranceDecision,
    pub automated: bool,
    pub change_ticket: String,
    pub evidence_digests: BTreeMap<String, String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reviewers: Vec<AssuranceReviewer>,
}

impl ExternalGateAssuranceAttestation {
    pub fn signing_payload(&self) -> Result<Vec<u8>, ClosureError> {
        let mut unsigned = self.clone();
        for reviewer in &mut unsigned.reviewers {
            reviewer.signature.clear();
        }
        serde_jcs::to_vec(&unsigned).map_err(|_| ClosureError::SerializationFailed)
    }

    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify_offline(
        &self,
        expected_scope_digest: &str,
        keys: &BTreeMap<String, VerifyingKey>,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        let required_roles =
            external_gate_roles(&self.gate_id).ok_or(ClosureError::ExternalAssuranceInvalid)?;
        let reviewer_ids: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.reviewer_id.as_str())
            .collect();
        let key_ids: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.key_id.as_str())
            .collect();
        let organizations: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.organization.as_str())
            .collect();
        let roles: BTreeSet<&str> = self
            .reviewers
            .iter()
            .map(|reviewer| reviewer.role.as_str())
            .collect();
        let duration = self.expires_at.signed_duration_since(self.issued_at);
        let valid = self.schema_version == EXTERNAL_GATE_ASSURANCE_SCHEMA_VERSION
            && !self.attestation_id.is_empty()
            && !self.release_id.is_empty()
            && self.scope_digest == expected_scope_digest
            && is_sha256(&self.scope_digest)
            && self
                .environment_reference
                .starts_with("environment://production/")
            && self.decision == AssuranceDecision::Approved
            && !self.automated
            && !self.change_ticket.is_empty()
            && self.change_ticket.len() <= 256
            && !self.evidence_digests.is_empty()
            && self.evidence_digests.len() <= 512
            && self.evidence_digests.values().all(|value| is_sha256(value))
            && self.issued_at <= now
            && self.expires_at > now
            && duration > chrono::Duration::zero()
            && duration <= chrono::Duration::days(30)
            && (2..=12).contains(&self.reviewers.len())
            && reviewer_ids.len() == self.reviewers.len()
            && key_ids.len() == self.reviewers.len()
            && organizations.len() >= 2
            && required_roles.is_subset(&roles)
            && self.reviewers.iter().all(|reviewer| {
                !reviewer.reviewer_id.is_empty()
                    && !reviewer.organization.is_empty()
                    && !reviewer.role.is_empty()
                    && !reviewer.key_id.is_empty()
                    && reviewer.signature.len() <= 128
            });
        if !valid {
            return Err(ClosureError::ExternalAssuranceInvalid);
        }
        let payload = self.signing_payload()?;
        for reviewer in &self.reviewers {
            let key = keys
                .get(&reviewer.key_id)
                .ok_or(ClosureError::ExternalAssuranceInvalid)?;
            let decoded = URL_SAFE_NO_PAD
                .decode(&reviewer.signature)
                .map_err(|_| ClosureError::ExternalAssuranceInvalid)?;
            let signature = Signature::from_slice(&decoded)
                .map_err(|_| ClosureError::ExternalAssuranceInvalid)?;
            key.verify(&payload, &signature)
                .map_err(|_| ClosureError::ExternalAssuranceInvalid)?;
        }
        Ok(())
    }

    pub fn verified_gate_evidence(
        &self,
        expected_scope_digest: &str,
        keys: &BTreeMap<String, VerifyingKey>,
        now: DateTime<Utc>,
    ) -> Result<GateEvidence, ClosureError> {
        self.verify_offline(expected_scope_digest, keys, now)?;
        Ok(GateEvidence {
            gate_id: self.gate_id.clone(),
            scope_digest: self.scope_digest.clone(),
            passed: true,
            evidence_kind: EvidenceKind::RealEnvironment,
            evidence_digests: BTreeMap::from([("attestation".into(), self.digest()?)]),
            environment_reference: Some(self.environment_reference.clone()),
            measured_at: self.issued_at,
            expires_at: self.expires_at,
            source_certificate_type: Some("EXTERNAL_GATE_ASSURANCE_ATTESTATION".into()),
        })
    }
}

fn external_gate_roles(gate_id: &str) -> Option<BTreeSet<&'static str>> {
    let roles = match gate_id {
        "SUPPLY_CHAIN_PROVENANCE" => ["RELEASE_ENGINEER", "INDEPENDENT_AUDITOR"],
        "MULTITENANT_ISOLATION" => ["SECURITY_ENGINEER", "INDEPENDENT_AUDITOR"],
        "IDEMPOTENCY_AND_RECOVERY" | "CONTINUOUS_AUTHORIZATION" => ["SRE", "SECURITY_ENGINEER"],
        "DOMAIN_CODING" => ["CODING_DOMAIN_OWNER", "INDEPENDENT_AUDITOR"],
        "DOMAIN_ENERGY" => ["ENERGY_DOMAIN_ENGINEER", "SAFETY_ENGINEER"],
        "SECURITY_CAMPAIGN" => ["RED_TEAM_LEAD", "SECURITY_OWNER"],
        "HA_DR_RESTORE" | "UPGRADE_ROLLBACK" => ["SRE", "DISASTER_RECOVERY_OWNER"],
        "CONTROL_EVIDENCE_GRAPH" => ["COMPLIANCE_OWNER", "INDEPENDENT_AUDITOR"],
        "ENTERPRISE_ACCEPTANCE" => ["CUSTOMER_RELEASE_AUTHORITY", "INDEPENDENT_AUDITOR"],
        _ => return None,
    };
    Some(BTreeSet::from(roles))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    P3,
    P2,
    P1,
    P0,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidualRisk {
    pub risk_id: String,
    pub severity: Severity,
    pub description: String,
    pub owner: String,
    pub accepted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateException {
    pub exception_id: String,
    pub gate_id: String,
    pub severity: Severity,
    pub owner: String,
    pub approved_by: BTreeSet<String>,
    pub compensating_control_digests: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClosureInput {
    pub schema_version: String,
    pub scope: ClosureScope,
    pub batch_statuses: Vec<BatchEvidenceStatus>,
    pub gate_evidence: Vec<GateEvidence>,
    pub residual_risks: Vec<ResidualRisk>,
    pub exceptions: Vec<GateException>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClosureReport {
    pub schema_version: String,
    pub release_id: String,
    pub scope_digest: String,
    pub eligible: bool,
    pub blockers: BTreeSet<String>,
    pub verified_gate_digests: BTreeMap<String, String>,
    pub evaluated_at: DateTime<Utc>,
    pub report_digest: String,
}

impl ClosureReport {
    fn unsigned_digest(&self) -> Result<String, ClosureError> {
        let mut unsigned = self.clone();
        unsigned.report_digest.clear();
        let bytes = serde_jcs::to_vec(&unsigned).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify_digest(&self) -> Result<(), ClosureError> {
        if self.report_digest == self.unsigned_digest()? {
            Ok(())
        } else {
            Err(ClosureError::ReportInvalid)
        }
    }
}

pub struct ClosureRunner;

impl ClosureRunner {
    pub fn evaluate(
        input: &ClosureInput,
        now: DateTime<Utc>,
    ) -> Result<ClosureReport, ClosureError> {
        input.scope.validate(now)?;
        if input.schema_version != CLOSURE_SCHEMA_VERSION {
            return Err(ClosureError::SchemaUnsupported);
        }
        let scope_digest = input.scope.digest()?;
        let mut blockers = BTreeSet::new();
        let mut verified_gate_digests = BTreeMap::new();

        Self::check_batches(&input.batch_statuses, &mut blockers);
        Self::check_risks(&input.residual_risks, &mut blockers);
        let exception_gates = Self::valid_exception_gates(&input.exceptions, now, &mut blockers);

        let mut evidence_by_gate: BTreeMap<&str, Vec<&GateEvidence>> = BTreeMap::new();
        for evidence in &input.gate_evidence {
            evidence_by_gate
                .entry(&evidence.gate_id)
                .or_default()
                .push(evidence);
        }
        for (gate_id, external_required) in REQUIRED_GATES {
            let entries = evidence_by_gate.get(gate_id).cloned().unwrap_or_default();
            if entries.len() != 1 {
                blockers.insert(format!("GATE_{gate_id}_CARDINALITY"));
                continue;
            }
            let evidence = entries[0];
            let can_be_excepted = exception_gates.contains(gate_id);
            let external_kind = matches!(
                evidence.evidence_kind,
                EvidenceKind::RealEnvironment | EvidenceKind::IndependentAssurance
            );
            let valid_digests = !evidence.evidence_digests.is_empty()
                && evidence
                    .evidence_digests
                    .values()
                    .all(|digest| is_sha256(digest));
            let source_is_intermediate =
                evidence.source_certificate_type.as_deref() == Some("BATCH_22_ENGINE_CERTIFICATE");
            let valid = evidence.scope_digest == scope_digest
                && evidence.passed
                && evidence.measured_at <= now
                && evidence.expires_at > now
                && valid_digests
                && (!external_required
                    || external_kind
                        && evidence
                            .environment_reference
                            .as_ref()
                            .is_some_and(|value| !value.is_empty()))
                && !source_is_intermediate;
            if !valid && !can_be_excepted {
                blockers.insert(format!("GATE_{gate_id}_FAILED"));
                continue;
            }
            if valid {
                verified_gate_digests.insert(gate_id.into(), digest_gate(evidence)?);
            }
        }

        let mut report = ClosureReport {
            schema_version: CLOSURE_SCHEMA_VERSION.into(),
            release_id: input.scope.release_id.clone(),
            scope_digest,
            eligible: blockers.is_empty(),
            blockers,
            verified_gate_digests,
            evaluated_at: now,
            report_digest: String::new(),
        };
        report.report_digest = report.unsigned_digest()?;
        Ok(report)
    }

    fn check_batches(statuses: &[BatchEvidenceStatus], blockers: &mut BTreeSet<String>) {
        let mut by_batch = BTreeMap::new();
        for status in statuses {
            if !(REQUIRED_BATCH_FIRST..=REQUIRED_BATCH_LAST).contains(&status.batch) {
                blockers.insert(format!("BATCH_{:02}_UNEXPECTED", status.batch));
                continue;
            }
            if by_batch.insert(status.batch, status).is_some() {
                blockers.insert(format!("BATCH_{:02}_DUPLICATE", status.batch));
            }
        }
        for batch in REQUIRED_BATCH_FIRST..=REQUIRED_BATCH_LAST {
            match by_batch.get(&batch) {
                Some(status)
                    if status.status == BatchStatus::EvidenceVerified
                        && is_sha256(&status.evidence_digest) => {}
                Some(_) => {
                    blockers.insert(format!("BATCH_{batch:02}_NOT_EVIDENCE_VERIFIED"));
                }
                None => {
                    blockers.insert(format!("BATCH_{batch:02}_MISSING"));
                }
            }
        }
    }

    fn check_risks(risks: &[ResidualRisk], blockers: &mut BTreeSet<String>) {
        for risk in risks {
            if risk.risk_id.is_empty() || risk.owner.is_empty() || risk.description.is_empty() {
                blockers.insert("RESIDUAL_RISK_INVALID".into());
            }
            if risk.severity >= Severity::P1
                || risk.accepted_by.as_deref().unwrap_or_default().is_empty()
            {
                blockers.insert(format!("RESIDUAL_RISK_{}_BLOCKING", risk.risk_id));
            }
        }
    }

    fn valid_exception_gates(
        exceptions: &[GateException],
        now: DateTime<Utc>,
        blockers: &mut BTreeSet<String>,
    ) -> BTreeSet<String> {
        let known_gates: BTreeSet<&str> = REQUIRED_GATES.iter().map(|(gate, _)| *gate).collect();
        exceptions
            .iter()
            .filter_map(|exception| {
                let valid = !exception.exception_id.is_empty()
                    && known_gates.contains(exception.gate_id.as_str())
                    && exception.severity <= Severity::P2
                    && exception.approved_by.len() >= 2
                    && !exception.approved_by.contains(&exception.owner)
                    && !exception.compensating_control_digests.is_empty()
                    && exception
                        .compensating_control_digests
                        .iter()
                        .all(|digest| is_sha256(digest))
                    && exception.expires_at > now;
                if valid {
                    Some(exception.gate_id.clone())
                } else {
                    blockers.insert(format!("EXCEPTION_{}_INVALID", exception.exception_id));
                    None
                }
            })
            .collect()
    }
}

pub trait EvidenceSourcePort: Send + Sync {
    fn batch_statuses(
        &self,
        scope: &ClosureScope,
    ) -> Result<Vec<BatchEvidenceStatus>, ClosureError>;
    fn gate_evidence(&self, scope: &ClosureScope) -> Result<Vec<GateEvidence>, ClosureError>;
    fn residual_risks(&self, scope: &ClosureScope) -> Result<Vec<ResidualRisk>, ClosureError>;
    fn exceptions(&self, scope: &ClosureScope) -> Result<Vec<GateException>, ClosureError>;
}

pub struct EvidenceCollector<P: EvidenceSourcePort> {
    source: P,
}

impl<P: EvidenceSourcePort> EvidenceCollector<P> {
    pub fn new(source: P) -> Self {
        Self { source }
    }

    pub fn collect(&self, scope: ClosureScope) -> Result<ClosureInput, ClosureError> {
        let batch_statuses = self.source.batch_statuses(&scope)?;
        let gate_evidence = self.source.gate_evidence(&scope)?;
        let residual_risks = self.source.residual_risks(&scope)?;
        let exceptions = self.source.exceptions(&scope)?;
        if batch_statuses.len() > 128
            || gate_evidence.len() > 128
            || residual_risks.len() > 10_000
            || exceptions.len() > 1_000
        {
            return Err(ClosureError::EvidenceCapacityExceeded);
        }
        Ok(ClosureInput {
            schema_version: CLOSURE_SCHEMA_VERSION.into(),
            scope,
            batch_statuses,
            gate_evidence,
            residual_risks,
            exceptions,
        })
    }
}

pub struct GateAggregator;

impl GateAggregator {
    pub fn aggregate(
        input: &ClosureInput,
        now: DateTime<Utc>,
    ) -> Result<ClosureReport, ClosureError> {
        ClosureRunner::evaluate(input, now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionRequest {
    pub exception_id: String,
    pub gate_id: String,
    pub severity: Severity,
    pub owner: String,
    pub compensating_control_digests: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
}

pub struct ExceptionAuthority {
    authorized_approvers: BTreeSet<String>,
}

impl ExceptionAuthority {
    pub fn new(authorized_approvers: BTreeSet<String>) -> Result<Self, ClosureError> {
        if authorized_approvers.len() < 2 || authorized_approvers.iter().any(String::is_empty) {
            return Err(ClosureError::ConfigurationInvalid);
        }
        Ok(Self {
            authorized_approvers,
        })
    }

    pub fn approve(
        &self,
        request: &ExceptionRequest,
        approvers: BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<GateException, ClosureError> {
        let known_gates: BTreeSet<&str> = REQUIRED_GATES.iter().map(|(gate, _)| *gate).collect();
        if request.exception_id.is_empty()
            || !known_gates.contains(request.gate_id.as_str())
            || request.severity > Severity::P2
            || request.owner.is_empty()
            || request.compensating_control_digests.is_empty()
            || request
                .compensating_control_digests
                .iter()
                .any(|digest| !is_sha256(digest))
            || request.expires_at <= now
            || approvers.len() < 2
            || !approvers.is_subset(&self.authorized_approvers)
            || approvers.contains(&request.owner)
        {
            return Err(ClosureError::ExceptionInvalid);
        }
        Ok(GateException {
            exception_id: request.exception_id.clone(),
            gate_id: request.gate_id.clone(),
            severity: request.severity,
            owner: request.owner.clone(),
            approved_by: approvers,
            compensating_control_digests: request.compensating_control_digests.clone(),
            expires_at: request.expires_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductionClosureCertificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub release_id: String,
    pub scope_digest: String,
    pub report_digest: String,
    pub production_closure: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub key_id: String,
    pub signature: String,
}

impl ProductionClosureCertificate {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ClosureError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ClosureError::SerializationFailed)
    }

    pub fn verify_offline(
        &self,
        report: &ClosureReport,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        report.verify_digest()?;
        if self.schema_version != CLOSURE_SCHEMA_VERSION
            || !self.production_closure
            || !report.eligible
            || self.certificate_id != format!("pc-{}", &report.report_digest[..24])
            || self.release_id != report.release_id
            || self.scope_digest != report.scope_digest
            || self.report_digest != report.report_digest
            || !is_key_id(&self.key_id)
            || self.issued_at > now
            || self.expires_at <= now
        {
            return Err(ClosureError::CertificateInvalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ClosureError::CertificateInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| ClosureError::CertificateInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ClosureError::CertificateInvalid)
    }
}

/// A private-key-free request that can be sent to an approved external KMS or
/// signing service. The service signs `signing_payload` exactly as supplied;
/// the finalizer independently reconstructs and verifies the payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalCertificateSigningRequest {
    pub schema_version: String,
    pub algorithm: String,
    pub key_id: String,
    pub certificate: ProductionClosureCertificate,
    pub signing_payload: String,
    pub payload_sha256: String,
}

impl ExternalCertificateSigningRequest {
    pub fn prepare(
        report: &ClosureReport,
        scope: &ClosureScope,
        key_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, ClosureError> {
        let certificate = unsigned_certificate(report, scope, key_id.into(), now)?;
        let payload = certificate.signing_bytes()?;
        Ok(Self {
            schema_version: EXTERNAL_SIGNING_REQUEST_SCHEMA_VERSION.into(),
            algorithm: CLOSURE_SIGNATURE_ALGORITHM.into(),
            key_id: certificate.key_id.clone(),
            certificate,
            signing_payload: URL_SAFE_NO_PAD.encode(&payload),
            payload_sha256: hex(Sha256::digest(payload)),
        })
    }

    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify(
        &self,
        report: &ClosureReport,
        scope: &ClosureScope,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        report.verify_digest()?;
        scope.validate(now)?;
        if self.schema_version != EXTERNAL_SIGNING_REQUEST_SCHEMA_VERSION
            || self.algorithm != CLOSURE_SIGNATURE_ALGORITHM
            || !is_key_id(&self.key_id)
            || self.key_id != self.certificate.key_id
            || self.certificate.schema_version != CLOSURE_SCHEMA_VERSION
            || self.certificate.certificate_id != format!("pc-{}", &report.report_digest[..24])
            || !self.certificate.signature.is_empty()
            || !self.certificate.production_closure
            || !report.eligible
            || self.certificate.release_id != report.release_id
            || self.certificate.release_id != scope.release_id
            || self.certificate.scope_digest != report.scope_digest
            || self.certificate.scope_digest != scope.digest()?
            || self.certificate.report_digest != report.report_digest
            || report.evaluated_at > self.certificate.issued_at
            || self.certificate.issued_at > now
            || self.certificate.expires_at != scope.valid_until
            || self.certificate.expires_at <= now
            || report.verified_gate_digests.len() != REQUIRED_GATES.len()
        {
            return Err(ClosureError::ExternalSigningInvalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&self.signing_payload)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        if !is_sha256(&self.payload_sha256)
            || self.payload_sha256 != hex(Sha256::digest(&payload))
            || payload != self.certificate.signing_bytes()?
        {
            return Err(ClosureError::ExternalSigningInvalid);
        }
        Ok(())
    }
}

/// Detached result returned by an external KMS integration. The request digest
/// prevents a signature response from being replayed for another certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalCertificateSignature {
    pub schema_version: String,
    pub request_digest: String,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl ExternalCertificateSignature {
    pub fn finalize(
        &self,
        request: &ExternalCertificateSigningRequest,
        report: &ClosureReport,
        scope: &ClosureScope,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError> {
        request.verify(report, scope, now)?;
        if self.schema_version != EXTERNAL_SIGNATURE_SCHEMA_VERSION
            || self.algorithm != CLOSURE_SIGNATURE_ALGORITHM
            || self.key_id != request.key_id
            || self.request_digest != request.digest()?
            || !is_sha256(&self.request_digest)
        {
            return Err(ClosureError::ExternalSigningInvalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&request.signing_payload)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| ClosureError::ExternalSigningInvalid)?;
        key.verify(&payload, &signature)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;

        let mut certificate = request.certificate.clone();
        certificate.signature = self.signature.clone();
        certificate
            .verify_offline(report, key, now)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        Ok(certificate)
    }
}

fn unsigned_certificate(
    report: &ClosureReport,
    scope: &ClosureScope,
    key_id: String,
    now: DateTime<Utc>,
) -> Result<ProductionClosureCertificate, ClosureError> {
    report.verify_digest()?;
    scope.validate(now)?;
    if !is_key_id(&key_id)
        || !report.eligible
        || report.scope_digest != scope.digest()?
        || report.release_id != scope.release_id
        || report.verified_gate_digests.len() != REQUIRED_GATES.len()
    {
        return Err(ClosureError::NotEligible);
    }
    Ok(ProductionClosureCertificate {
        schema_version: CLOSURE_SCHEMA_VERSION.into(),
        certificate_id: format!("pc-{}", &report.report_digest[..24]),
        release_id: report.release_id.clone(),
        scope_digest: report.scope_digest.clone(),
        report_digest: report.report_digest.clone(),
        production_closure: true,
        issued_at: now,
        expires_at: scope.valid_until,
        key_id,
        signature: String::new(),
    })
}

pub struct ClosureAuthority {
    key_id: String,
    signing_key: SigningKey,
}

impl ClosureAuthority {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Result<Self, ClosureError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(ClosureError::ConfigurationInvalid);
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    pub fn issue(
        &self,
        report: &ClosureReport,
        scope: &ClosureScope,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError> {
        let mut certificate = unsigned_certificate(report, scope, self.key_id.clone(), now)?;
        certificate.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(&certificate.signing_bytes()?)
                .to_bytes(),
        );
        Ok(certificate)
    }
}

pub trait CertificateSigner {
    fn sign_certificate(
        &self,
        report: &ClosureReport,
        scope: &ClosureScope,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError>;
}

impl CertificateSigner for ClosureAuthority {
    fn sign_certificate(
        &self,
        report: &ClosureReport,
        scope: &ClosureScope,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError> {
        self.issue(report, scope, now)
    }
}

#[derive(Default)]
pub struct CertificateRegistry {
    revoked: RwLock<BTreeMap<String, String>>,
}

impl CertificateRegistry {
    pub fn revoke(
        &self,
        certificate_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), ClosureError> {
        let certificate_id = certificate_id.into();
        let reason = reason.into();
        if certificate_id.is_empty() || reason.is_empty() {
            return Err(ClosureError::RevocationInvalid);
        }
        self.revoked.write().insert(certificate_id, reason);
        Ok(())
    }

    pub fn verify_active(
        &self,
        certificate: &ProductionClosureCertificate,
        report: &ClosureReport,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        if self
            .revoked
            .read()
            .contains_key(&certificate.certificate_id)
        {
            return Err(ClosureError::CertificateRevoked);
        }
        certificate.verify_offline(report, key, now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateRevocationEntry {
    pub certificate_id: String,
    pub release_id: String,
    pub reason_code: String,
    pub evidence_digest: String,
    pub revoked_at: DateTime<Utc>,
}

/// A short-lived, signed snapshot distributed to offline certificate consumers.
/// Sequence and previous digest make rollback or snapshot deletion detectable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCertificateRevocationRegistry {
    pub schema_version: String,
    pub registry_id: String,
    pub sequence: u64,
    pub previous_registry_digest: Option<String>,
    pub published_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub key_id: String,
    pub entries: Vec<CertificateRevocationEntry>,
    pub signature: String,
}

impl SignedCertificateRevocationRegistry {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ClosureError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_jcs::to_vec(&unsigned).map_err(|_| ClosureError::SerializationFailed)
    }

    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ClosureError> {
        let valid_chain = if self.sequence == 1 {
            self.previous_registry_digest.is_none()
        } else {
            self.previous_registry_digest
                .as_deref()
                .is_some_and(is_sha256)
        };
        let entries_ordered = self
            .entries
            .windows(2)
            .all(|pair| pair[0].certificate_id.as_str() < pair[1].certificate_id.as_str());
        let entries_valid = self.entries.iter().all(|entry| {
            is_certificate_id(&entry.certificate_id)
                && !entry.release_id.is_empty()
                && entry.release_id.len() <= 256
                && is_reason_code(&entry.reason_code)
                && is_sha256(&entry.evidence_digest)
                && entry.revoked_at <= self.published_at
        });
        if self.schema_version != CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION
            || !is_key_id(&self.registry_id)
            || !is_key_id(&self.key_id)
            || self.sequence == 0
            || !valid_chain
            || self.entries.len() > 100_000
            || !entries_ordered
            || !entries_valid
            || self.published_at > now
            || self.expires_at <= now
            || self.expires_at <= self.published_at
            || self.expires_at - self.published_at > Duration::days(7)
        {
            return Err(ClosureError::RevocationInvalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ClosureError::RevocationInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| ClosureError::RevocationInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ClosureError::RevocationInvalid)
    }

    pub fn verify_active(
        &self,
        certificate: &ProductionClosureCertificate,
        report: &ClosureReport,
        certificate_key: &VerifyingKey,
        registry_key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        self.verify(registry_key, now)?;
        if self.published_at < certificate.issued_at {
            return Err(ClosureError::RevocationInvalid);
        }
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.certificate_id == certificate.certificate_id)
        {
            if entry.release_id != certificate.release_id {
                return Err(ClosureError::RevocationInvalid);
            }
            return Err(ClosureError::CertificateRevoked);
        }
        certificate.verify_offline(report, certificate_key, now)
    }

    pub fn verify_successor(
        &self,
        previous: &SignedCertificateRevocationRegistry,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        previous.verify(key, now)?;
        self.verify(key, now)?;
        let previous_digest = previous.digest()?;
        if self.registry_id != previous.registry_id
            || self.key_id != previous.key_id
            || self.sequence != previous.sequence.saturating_add(1)
            || self.previous_registry_digest.as_deref() != Some(previous_digest.as_str())
            || self.published_at <= previous.published_at
        {
            return Err(ClosureError::RevocationInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClosureError {
    #[error("CLOSURE_SCHEMA_UNSUPPORTED")]
    SchemaUnsupported,
    #[error("CLOSURE_SCOPE_INVALID")]
    ScopeInvalid,
    #[error("CLOSURE_SERIALIZATION_FAILED")]
    SerializationFailed,
    #[error("CLOSURE_REPORT_INVALID")]
    ReportInvalid,
    #[error("CLOSURE_NOT_ELIGIBLE")]
    NotEligible,
    #[error("CLOSURE_CERTIFICATE_INVALID")]
    CertificateInvalid,
    #[error("CLOSURE_CERTIFICATE_REVOKED")]
    CertificateRevoked,
    #[error("CLOSURE_REVOCATION_INVALID")]
    RevocationInvalid,
    #[error("CLOSURE_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("CLOSURE_EVIDENCE_CAPACITY_EXCEEDED")]
    EvidenceCapacityExceeded,
    #[error("CLOSURE_EXCEPTION_INVALID")]
    ExceptionInvalid,
    #[error("CLOSURE_DOMAIN_ASSURANCE_INVALID")]
    DomainAssuranceInvalid,
    #[error("CLOSURE_EXTERNAL_ASSURANCE_INVALID")]
    ExternalAssuranceInvalid,
    #[error("CLOSURE_EXTERNAL_SIGNING_INVALID")]
    ExternalSigningInvalid,
}

fn digest_gate(evidence: &GateEvidence) -> Result<String, ClosureError> {
    let bytes = serde_jcs::to_vec(evidence).map_err(|_| ClosureError::SerializationFailed)?;
    Ok(hex(Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn is_certificate_id(value: &str) -> bool {
    value.strip_prefix("pc-").is_some_and(|digest| {
        digest.len() == 24 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn is_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn scope(now: DateTime<Utc>) -> ClosureScope {
        ClosureScope {
            release_id: "release:1".into(),
            commit_digest: "1".repeat(64),
            build_digest: "2".repeat(64),
            policy_digest: "3".repeat(64),
            pack_set_digest: "4".repeat(64),
            prompt_set_digest: "5".repeat(64),
            model_set_digest: "6".repeat(64),
            topology_digest: "7".repeat(64),
            environment: "production".into(),
            valid_from: now - Duration::minutes(1),
            valid_until: now + Duration::hours(1),
        }
    }

    fn complete_input(now: DateTime<Utc>) -> ClosureInput {
        let scope = scope(now);
        let scope_digest = scope
            .digest()
            .unwrap_or_else(|error| panic!("scope: {error}"));
        ClosureInput {
            schema_version: CLOSURE_SCHEMA_VERSION.into(),
            scope,
            batch_statuses: (REQUIRED_BATCH_FIRST..=REQUIRED_BATCH_LAST)
                .map(|batch| BatchEvidenceStatus {
                    batch,
                    status: BatchStatus::EvidenceVerified,
                    evidence_digest: format!("{batch:064x}"),
                })
                .collect(),
            gate_evidence: REQUIRED_GATES
                .iter()
                .map(|(gate, external)| GateEvidence {
                    gate_id: (*gate).into(),
                    scope_digest: scope_digest.clone(),
                    passed: true,
                    evidence_kind: if *external {
                        EvidenceKind::RealEnvironment
                    } else {
                        EvidenceKind::IntegrationTest
                    },
                    evidence_digests: BTreeMap::from([("report".into(), "a".repeat(64))]),
                    environment_reference: external
                        .then(|| "environment://production/cluster-1".into()),
                    measured_at: now - Duration::minutes(1),
                    expires_at: now + Duration::hours(1),
                    source_certificate_type: None,
                })
                .collect(),
            residual_risks: Vec::new(),
            exceptions: Vec::new(),
        }
    }

    fn signed_domain_attestation(
        now: DateTime<Utc>,
        domain: AssuranceDomain,
        roles: [&str; 2],
    ) -> (DomainAssuranceAttestation, BTreeMap<String, VerifyingKey>) {
        let signing_keys = [
            SigningKey::from_bytes(&[81_u8; 32]),
            SigningKey::from_bytes(&[82_u8; 32]),
        ];
        let mut attestation = DomainAssuranceAttestation {
            schema_version: DOMAIN_ASSURANCE_SCHEMA_VERSION.into(),
            attestation_id: "attestation:domain:1".into(),
            domain,
            release_id: "release:1".into(),
            scope_digest: "a".repeat(64),
            environment_reference: "environment://production/site-1".into(),
            decision: AssuranceDecision::Approved,
            automated: false,
            evidence_digests: BTreeMap::from([("acceptance-report".into(), "b".repeat(64))]),
            issued_at: now - Duration::minutes(1),
            expires_at: now + Duration::days(30),
            reviewers: roles
                .into_iter()
                .enumerate()
                .map(|(index, role)| AssuranceReviewer {
                    reviewer_id: format!("reviewer:{index}"),
                    organization: "independent-assurance.example".into(),
                    role: role.into(),
                    key_id: format!("reviewer-key:{index}"),
                    signature: String::new(),
                })
                .collect(),
        };
        let payload = attestation
            .signing_payload()
            .unwrap_or_else(|error| panic!("payload: {error}"));
        for (reviewer, key) in attestation.reviewers.iter_mut().zip(&signing_keys) {
            reviewer.signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
        }
        let keys = attestation
            .reviewers
            .iter()
            .zip(&signing_keys)
            .map(|(reviewer, key)| (reviewer.key_id.clone(), key.verifying_key()))
            .collect();
        (attestation, keys)
    }

    fn signed_external_attestation(
        now: DateTime<Utc>,
        gate_id: &str,
        roles: [&str; 2],
    ) -> (
        ExternalGateAssuranceAttestation,
        BTreeMap<String, VerifyingKey>,
    ) {
        let signing_keys = [
            SigningKey::from_bytes(&[91_u8; 32]),
            SigningKey::from_bytes(&[92_u8; 32]),
        ];
        let mut attestation = ExternalGateAssuranceAttestation {
            schema_version: EXTERNAL_GATE_ASSURANCE_SCHEMA_VERSION.into(),
            attestation_id: "attestation:external:1".into(),
            gate_id: gate_id.into(),
            release_id: "release:1".into(),
            scope_digest: "a".repeat(64),
            environment_reference: "environment://production/customer-1".into(),
            decision: AssuranceDecision::Approved,
            automated: false,
            change_ticket: "CHG-12345".into(),
            evidence_digests: BTreeMap::from([("acceptance-report".into(), "b".repeat(64))]),
            issued_at: now - Duration::minutes(1),
            expires_at: now + Duration::days(14),
            reviewers: roles
                .into_iter()
                .enumerate()
                .map(|(index, role)| AssuranceReviewer {
                    reviewer_id: format!("external-reviewer:{index}"),
                    organization: format!("organization-{index}.example"),
                    role: role.into(),
                    key_id: format!("external-key:{index}"),
                    signature: String::new(),
                })
                .collect(),
        };
        let payload = attestation
            .signing_payload()
            .unwrap_or_else(|error| panic!("payload: {error}"));
        for (reviewer, key) in attestation.reviewers.iter_mut().zip(&signing_keys) {
            reviewer.signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
        }
        let keys = attestation
            .reviewers
            .iter()
            .zip(&signing_keys)
            .map(|(reviewer, key)| (reviewer.key_id.clone(), key.verifying_key()))
            .collect();
        (attestation, keys)
    }

    #[test]
    fn missing_batch_and_intermediate_certificate_fail_closed() {
        let now = Utc::now();
        let mut input = complete_input(now);
        input.batch_statuses.pop();
        input.batch_statuses.push(BatchEvidenceStatus {
            batch: 36,
            status: BatchStatus::EvidenceVerified,
            evidence_digest: "d".repeat(64),
        });
        input.gate_evidence[0].source_certificate_type = Some("BATCH_22_ENGINE_CERTIFICATE".into());
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        assert!(!report.eligible);
        assert!(report.blockers.contains("BATCH_35_MISSING"));
        assert!(report.blockers.contains("BATCH_36_UNEXPECTED"));
        let authority = ClosureAuthority::new("closure-key", SigningKey::from_bytes(&[71_u8; 32]))
            .unwrap_or_else(|error| panic!("authority: {error}"));
        assert_eq!(
            authority.issue(&report, &input.scope, now),
            Err(ClosureError::NotEligible)
        );
    }

    #[test]
    fn unit_test_cannot_satisfy_external_gate_and_p1_cannot_be_waived() {
        let now = Utc::now();
        let mut input = complete_input(now);
        input.gate_evidence[1].evidence_kind = EvidenceKind::UnitTest;
        input.exceptions.push(GateException {
            exception_id: "exception:p1".into(),
            gate_id: input.gate_evidence[1].gate_id.clone(),
            severity: Severity::P1,
            owner: "owner".into(),
            approved_by: BTreeSet::from(["reviewer:1".into(), "reviewer:2".into()]),
            compensating_control_digests: BTreeSet::from(["c".repeat(64)]),
            expires_at: now + Duration::hours(1),
        });
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        assert!(!report.eligible);
        assert!(report.blockers.contains("EXCEPTION_exception:p1_INVALID"));
    }

    #[test]
    fn eligible_report_is_signed_offline_verified_tamper_evident_and_revocable() {
        let now = Utc::now();
        let input = complete_input(now);
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        assert!(report.eligible);
        let key = SigningKey::from_bytes(&[72_u8; 32]);
        let authority = ClosureAuthority::new("closure-key", key.clone())
            .unwrap_or_else(|error| panic!("authority: {error}"));
        let certificate = authority
            .issue(&report, &input.scope, now)
            .unwrap_or_else(|error| panic!("certificate: {error}"));
        let registry = CertificateRegistry::default();
        assert_eq!(
            registry.verify_active(&certificate, &report, &key.verifying_key(), now),
            Ok(())
        );
        let mut tampered = certificate.clone();
        tampered.release_id = "release:other".into();
        assert_eq!(
            tampered.verify_offline(&report, &key.verifying_key(), now),
            Err(ClosureError::CertificateInvalid)
        );
        registry
            .revoke(certificate.certificate_id.clone(), "rollout regression")
            .unwrap_or_else(|error| panic!("revoke: {error}"));
        assert_eq!(
            registry.verify_active(&certificate, &report, &key.verifying_key(), now),
            Err(ClosureError::CertificateRevoked)
        );
    }

    #[test]
    fn external_signing_request_closes_kms_flow_without_loading_a_private_key() {
        let now = Utc::now();
        let input = complete_input(now);
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        let request = ExternalCertificateSigningRequest::prepare(
            &report,
            &input.scope,
            "kms:key:production-closure",
            now,
        )
        .unwrap_or_else(|error| panic!("request: {error}"));
        request
            .verify(&report, &input.scope, now)
            .unwrap_or_else(|error| panic!("request verify: {error}"));

        let external_kms_key = SigningKey::from_bytes(&[73_u8; 32]);
        let payload = URL_SAFE_NO_PAD
            .decode(&request.signing_payload)
            .unwrap_or_else(|error| panic!("payload: {error}"));
        let response = ExternalCertificateSignature {
            schema_version: EXTERNAL_SIGNATURE_SCHEMA_VERSION.into(),
            request_digest: request
                .digest()
                .unwrap_or_else(|error| panic!("digest: {error}")),
            algorithm: CLOSURE_SIGNATURE_ALGORITHM.into(),
            key_id: request.key_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(external_kms_key.sign(&payload).to_bytes()),
        };
        let certificate = response
            .finalize(
                &request,
                &report,
                &input.scope,
                &external_kms_key.verifying_key(),
                now,
            )
            .unwrap_or_else(|error| panic!("finalize: {error}"));
        assert_eq!(certificate.key_id, "kms:key:production-closure");
        assert!(!certificate.signature.is_empty());
        assert_eq!(
            certificate.verify_offline(&report, &external_kms_key.verifying_key(), now),
            Ok(())
        );
    }

    #[test]
    fn external_signing_rejects_request_response_and_signature_replay_tampering() {
        let now = Utc::now();
        let input = complete_input(now);
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        let request = ExternalCertificateSigningRequest::prepare(
            &report,
            &input.scope,
            "kms:key:production-closure",
            now,
        )
        .unwrap_or_else(|error| panic!("request: {error}"));
        let external_kms_key = SigningKey::from_bytes(&[74_u8; 32]);
        let payload = URL_SAFE_NO_PAD
            .decode(&request.signing_payload)
            .unwrap_or_else(|error| panic!("payload: {error}"));
        let response = ExternalCertificateSignature {
            schema_version: EXTERNAL_SIGNATURE_SCHEMA_VERSION.into(),
            request_digest: request
                .digest()
                .unwrap_or_else(|error| panic!("digest: {error}")),
            algorithm: CLOSURE_SIGNATURE_ALGORITHM.into(),
            key_id: request.key_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(external_kms_key.sign(&payload).to_bytes()),
        };

        let mut tampered_request = request.clone();
        tampered_request.certificate.release_id = "release:other".into();
        assert_eq!(
            response.finalize(
                &tampered_request,
                &report,
                &input.scope,
                &external_kms_key.verifying_key(),
                now,
            ),
            Err(ClosureError::ExternalSigningInvalid)
        );

        let mut replayed_response = response.clone();
        replayed_response.request_digest = "f".repeat(64);
        assert_eq!(
            replayed_response.finalize(
                &request,
                &report,
                &input.scope,
                &external_kms_key.verifying_key(),
                now,
            ),
            Err(ClosureError::ExternalSigningInvalid)
        );

        let wrong_key = SigningKey::from_bytes(&[75_u8; 32]);
        assert_eq!(
            response.finalize(
                &request,
                &report,
                &input.scope,
                &wrong_key.verifying_key(),
                now,
            ),
            Err(ClosureError::ExternalSigningInvalid)
        );
    }

    #[test]
    fn signed_revocation_registry_is_required_and_detects_revoked_certificate() {
        let now = Utc::now();
        let issued_at = now - Duration::minutes(1);
        let input = complete_input(issued_at);
        let report = ClosureRunner::evaluate(&input, issued_at)
            .unwrap_or_else(|error| panic!("report: {error}"));
        let certificate_key = SigningKey::from_bytes(&[76_u8; 32]);
        let authority = ClosureAuthority::new("closure-key", certificate_key.clone())
            .unwrap_or_else(|error| panic!("authority: {error}"));
        let certificate = authority
            .issue(&report, &input.scope, issued_at)
            .unwrap_or_else(|error| panic!("certificate: {error}"));
        let registry_key = SigningKey::from_bytes(&[77_u8; 32]);

        let mut active_registry = SignedCertificateRevocationRegistry {
            schema_version: CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION.into(),
            registry_id: "registry:production-closure".into(),
            sequence: 1,
            previous_registry_digest: None,
            published_at: now - Duration::seconds(1),
            expires_at: now + Duration::days(1),
            key_id: "registry-key:1".into(),
            entries: Vec::new(),
            signature: String::new(),
        };
        active_registry.signature = URL_SAFE_NO_PAD.encode(
            registry_key
                .sign(
                    &active_registry
                        .signing_bytes()
                        .unwrap_or_else(|error| panic!("registry payload: {error}")),
                )
                .to_bytes(),
        );
        assert_eq!(
            active_registry.verify_active(
                &certificate,
                &report,
                &certificate_key.verifying_key(),
                &registry_key.verifying_key(),
                now,
            ),
            Ok(())
        );

        let previous_digest = active_registry
            .digest()
            .unwrap_or_else(|error| panic!("registry digest: {error}"));
        let mut revoked_registry = SignedCertificateRevocationRegistry {
            sequence: 2,
            previous_registry_digest: Some(previous_digest),
            published_at: now,
            entries: vec![CertificateRevocationEntry {
                certificate_id: certificate.certificate_id.clone(),
                release_id: certificate.release_id.clone(),
                reason_code: "SECURITY_REGRESSION".into(),
                evidence_digest: "e".repeat(64),
                revoked_at: now,
            }],
            signature: String::new(),
            ..active_registry.clone()
        };
        revoked_registry.signature = URL_SAFE_NO_PAD.encode(
            registry_key
                .sign(
                    &revoked_registry
                        .signing_bytes()
                        .unwrap_or_else(|error| panic!("registry payload: {error}")),
                )
                .to_bytes(),
        );
        assert_eq!(
            revoked_registry
                .verify_successor(&active_registry, &registry_key.verifying_key(), now,),
            Ok(())
        );
        assert_eq!(
            revoked_registry.verify_active(
                &certificate,
                &report,
                &certificate_key.verifying_key(),
                &registry_key.verifying_key(),
                now,
            ),
            Err(ClosureError::CertificateRevoked)
        );
    }

    #[test]
    fn revocation_registry_rejects_rollback_staleness_and_tampering() {
        let now = Utc::now();
        let registry_key = SigningKey::from_bytes(&[78_u8; 32]);
        let mut registry = SignedCertificateRevocationRegistry {
            schema_version: CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION.into(),
            registry_id: "registry:production-closure".into(),
            sequence: 2,
            previous_registry_digest: Some("a".repeat(64)),
            published_at: now - Duration::minutes(1),
            expires_at: now + Duration::days(1),
            key_id: "registry-key:1".into(),
            entries: Vec::new(),
            signature: String::new(),
        };
        registry.signature = URL_SAFE_NO_PAD.encode(
            registry_key
                .sign(
                    &registry
                        .signing_bytes()
                        .unwrap_or_else(|error| panic!("registry payload: {error}")),
                )
                .to_bytes(),
        );
        assert_eq!(registry.verify(&registry_key.verifying_key(), now), Ok(()));

        let mut rollback = registry.clone();
        rollback.sequence = 1;
        assert_eq!(
            rollback.verify(&registry_key.verifying_key(), now),
            Err(ClosureError::RevocationInvalid)
        );
        let mut stale = registry.clone();
        stale.expires_at = now;
        assert_eq!(
            stale.verify(&registry_key.verifying_key(), now),
            Err(ClosureError::RevocationInvalid)
        );
        let mut tampered = registry;
        tampered.registry_id = "registry:other".into();
        assert_eq!(
            tampered.verify(&registry_key.verifying_key(), now),
            Err(ClosureError::RevocationInvalid)
        );
    }

    #[test]
    fn qualified_domain_reviewers_sign_scope_bound_acceptance() {
        let now = Utc::now();
        let cases = [
            (
                AssuranceDomain::Industrial,
                ["SAFETY_ENGINEER", "OPERATIONS_OWNER"],
                "DOMAIN_INDUSTRIAL",
            ),
            (
                AssuranceDomain::Medical,
                ["LICENSED_CLINICIAN", "PRIVACY_LEGAL_REVIEWER"],
                "DOMAIN_MEDICAL",
            ),
            (
                AssuranceDomain::SensitiveInteraction,
                ["SAFEGUARDING_LEAD", "HUMAN_SUPPORT_OWNER"],
                "DOMAIN_SENSITIVE_INTERACTION",
            ),
        ];
        for (domain, roles, gate_id) in cases {
            let (attestation, keys) = signed_domain_attestation(now, domain, roles);
            assert_eq!(
                attestation.verify_offline(&"a".repeat(64), &keys, now),
                Ok(())
            );
            let evidence = attestation
                .verified_gate_evidence(&"a".repeat(64), &keys, now)
                .unwrap_or_else(|error| panic!("gate evidence: {error}"));
            assert_eq!(evidence.gate_id, gate_id);
            assert_eq!(evidence.evidence_kind, EvidenceKind::IndependentAssurance);
        }
    }

    #[test]
    fn domain_assurance_rejects_automation_wrong_roles_and_tampering() {
        let now = Utc::now();
        let (attestation, keys) = signed_domain_attestation(
            now,
            AssuranceDomain::Industrial,
            ["SAFETY_ENGINEER", "OPERATIONS_OWNER"],
        );

        let mut automated = attestation.clone();
        automated.automated = true;
        assert_eq!(
            automated.verify_offline(&"a".repeat(64), &keys, now),
            Err(ClosureError::DomainAssuranceInvalid)
        );

        let mut wrong_role = attestation.clone();
        wrong_role.reviewers[1].role = "LICENSED_CLINICIAN".into();
        assert_eq!(
            wrong_role.verify_offline(&"a".repeat(64), &keys, now),
            Err(ClosureError::DomainAssuranceInvalid)
        );

        let mut tampered = attestation;
        tampered
            .evidence_digests
            .insert("extra".into(), "c".repeat(64));
        assert_eq!(
            tampered.verify_offline(&"a".repeat(64), &keys, now),
            Err(ClosureError::DomainAssuranceInvalid)
        );
    }

    #[test]
    fn customer_and_independent_reviewer_sign_enterprise_acceptance() {
        let now = Utc::now();
        let (attestation, keys) = signed_external_attestation(
            now,
            "ENTERPRISE_ACCEPTANCE",
            ["CUSTOMER_RELEASE_AUTHORITY", "INDEPENDENT_AUDITOR"],
        );
        assert_eq!(
            attestation.verify_offline(&"a".repeat(64), &keys, now),
            Ok(())
        );
        let evidence = attestation
            .verified_gate_evidence(&"a".repeat(64), &keys, now)
            .unwrap_or_else(|error| panic!("evidence: {error}"));
        assert_eq!(evidence.gate_id, "ENTERPRISE_ACCEPTANCE");
        assert_eq!(evidence.evidence_kind, EvidenceKind::RealEnvironment);
        assert_eq!(
            evidence.source_certificate_type.as_deref(),
            Some("EXTERNAL_GATE_ASSURANCE_ATTESTATION")
        );
    }

    #[test]
    fn external_assurance_rejects_same_organization_wrong_role_and_tampering() {
        let now = Utc::now();
        let (attestation, keys) =
            signed_external_attestation(now, "HA_DR_RESTORE", ["SRE", "DISASTER_RECOVERY_OWNER"]);
        let mut same_organization = attestation.clone();
        same_organization.reviewers[1].organization =
            same_organization.reviewers[0].organization.clone();
        assert_eq!(
            same_organization.verify_offline(&"a".repeat(64), &keys, now),
            Err(ClosureError::ExternalAssuranceInvalid)
        );
        let mut wrong_role = attestation.clone();
        wrong_role.reviewers[1].role = "INDEPENDENT_AUDITOR".into();
        assert_eq!(
            wrong_role.verify_offline(&"a".repeat(64), &keys, now),
            Err(ClosureError::ExternalAssuranceInvalid)
        );
        let mut tampered = attestation;
        tampered.change_ticket = "CHG-TAMPERED".into();
        assert_eq!(
            tampered.verify_offline(&"a".repeat(64), &keys, now),
            Err(ClosureError::ExternalAssuranceInvalid)
        );
    }
}
