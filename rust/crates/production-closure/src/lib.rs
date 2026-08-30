//! The only component allowed to issue an Agent Trust production-closure certificate.
//!
//! Earlier release-gate certificates are inputs to this gate, never substitutes for it.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(any(test, feature = "development-local-signing"))]
use ed25519_dalek::{Signer, SigningKey};
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
    "agenttrust.production-closure-external-signature.v2";
pub const CLOSURE_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-revocation-registry.v1";
pub const REVIEWER_KEYRING_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-reviewer-keyring.v1";
pub const REVIEWER_KEY_USAGE: &str = "PRODUCTION_ASSURANCE_REVIEW";
pub const REVOCATION_UPDATE_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-revocation-update.v1";
pub const REVOCATION_SIGNING_REQUEST_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-revocation-signing-request.v1";
pub const REVOCATION_EXTERNAL_SIGNATURE_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-revocation-external-signature.v2";
pub const ACTIVATION_EXPECTATION_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-activation-expectation.v1";
pub const ACTIVATION_RECEIPT_SCHEMA_VERSION: &str =
    "agenttrust.production-closure-activation-receipt.v1";

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
#[serde(deny_unknown_fields)]
pub struct ClosureScope {
    pub release_id: String,
    pub commit_digest: String,
    pub signed_git_provenance_digest: String,
    pub signed_release_binding_digest: String,
    pub release_digest: String,
    pub reviewer_keyring_digest: String,
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
            &self.signed_git_provenance_digest,
            &self.signed_release_binding_digest,
            &self.release_digest,
            &self.reviewer_keyring_digest,
            &self.build_digest,
            &self.policy_digest,
            &self.pack_set_digest,
            &self.prompt_set_digest,
            &self.model_set_digest,
            &self.topology_digest,
        ];
        if !is_git_release_id(&self.release_id)
            || self.environment != "production"
            || digests.iter().any(|digest| !is_sha256(digest))
            || self.valid_from > now
            || self.valid_until <= now
            || self.valid_until <= self.valid_from
            || self.valid_until - self.valid_from > Duration::days(30)
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
#[serde(deny_unknown_fields)]
pub struct BatchEvidenceStatus {
    pub batch: u8,
    pub status: BatchStatus,
    pub scope_digest: String,
    pub evidence_digest: String,
    pub measured_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct AssuranceReviewer {
    pub reviewer_id: String,
    pub organization: String,
    pub role: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewerKeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedReviewerKey {
    pub key_id: String,
    pub reviewer_id: String,
    pub organization: String,
    pub roles: BTreeSet<String>,
    pub key_usage: String,
    pub algorithm: String,
    pub public_key: String,
    pub status: ReviewerKeyStatus,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Deployment-owned trust root for human assurance.  A caller-provided public
/// key set is intentionally insufficient: identity, organization, qualified
/// role, key usage, validity and revocation are all part of the trusted data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedReviewerKeyring {
    pub schema_version: String,
    pub keyring_id: String,
    pub version: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub keys: Vec<TrustedReviewerKey>,
}

impl TrustedReviewerKeyring {
    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<(), ClosureError> {
        let duration = self.expires_at.signed_duration_since(self.issued_at);
        let mut key_ids = BTreeSet::new();
        let valid = self.schema_version == REVIEWER_KEYRING_SCHEMA_VERSION
            && is_key_id(&self.keyring_id)
            && self.version > 0
            && self.issued_at <= now
            && self.expires_at > now
            && duration > Duration::zero()
            && duration <= Duration::days(366)
            && (2..=1_000).contains(&self.keys.len())
            && self.keys.iter().all(|key| {
                let status_valid = match key.status {
                    ReviewerKeyStatus::Active => key.revoked_at.is_none(),
                    ReviewerKeyStatus::Revoked => key.revoked_at.is_some_and(|revoked_at| {
                        revoked_at <= now && revoked_at >= key.not_before
                    }),
                };
                key_ids.insert(key.key_id.as_str())
                    && is_key_id(&key.key_id)
                    && key.key_id.len() <= 128
                    && is_bounded_text(&key.reviewer_id, 128)
                    && is_bounded_text(&key.organization, 256)
                    && !key.roles.is_empty()
                    && key.roles.len() <= 16
                    && key.roles.iter().all(|role| is_assurance_role(role))
                    && key.key_usage == REVIEWER_KEY_USAGE
                    && key.algorithm == CLOSURE_SIGNATURE_ALGORITHM
                    && key.not_before < key.not_after
                    && key.not_after > self.issued_at
                    && status_valid
                    && decode_verifying_key(&key.public_key).is_ok()
            });
        if valid {
            Ok(())
        } else {
            Err(ClosureError::ReviewerKeyringInvalid)
        }
    }

    fn reviewer_key(
        &self,
        reviewer: &AssuranceReviewer,
        attestation_issued_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(&TrustedReviewerKey, VerifyingKey), ClosureError> {
        self.verify(now)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id == reviewer.key_id)
            .ok_or(ClosureError::ReviewerKeyringInvalid)?;
        if key.status != ReviewerKeyStatus::Active
            || key.reviewer_id != reviewer.reviewer_id
            || key.organization != reviewer.organization
            || !key.roles.contains(&reviewer.role)
            || key.key_usage != REVIEWER_KEY_USAGE
            || key.not_before > attestation_issued_at
            || key.not_after <= now
        {
            return Err(ClosureError::ReviewerKeyringInvalid);
        }
        Ok((key, decode_verifying_key(&key.public_key)?))
    }

    fn assurance_valid_until(
        &self,
        reviewers: &[AssuranceReviewer],
        attestation_issued_at: DateTime<Utc>,
        attestation_expires_at: DateTime<Utc>,
        scope_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, ClosureError> {
        let mut valid_until = attestation_expires_at
            .min(scope_expires_at)
            .min(self.expires_at);
        for reviewer in reviewers {
            let (key, _) = self.reviewer_key(reviewer, attestation_issued_at, now)?;
            valid_until = valid_until.min(key.not_after);
        }
        if valid_until <= now {
            return Err(ClosureError::ReviewerKeyringInvalid);
        }
        Ok(valid_until)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
        expected_scope: &ClosureScope,
        keyring: &TrustedReviewerKeyring,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        expected_scope.validate(now)?;
        keyring.verify(now)?;
        let expected_scope_digest = expected_scope.digest()?;
        if keyring.digest()? != expected_scope.reviewer_keyring_digest {
            return Err(ClosureError::ReviewerKeyringInvalid);
        }
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
            && is_key_id(&self.attestation_id)
            && self.release_id == expected_scope.release_id
            && self.scope_digest == expected_scope_digest
            && is_sha256(&self.scope_digest)
            && is_environment_reference(&self.environment_reference)
            && self.decision == AssuranceDecision::Approved
            && !self.automated
            && !self.evidence_digests.is_empty()
            && self.evidence_digests.len() <= 256
            && self.evidence_digests.keys().all(|key| is_key_id(key))
            && self.evidence_digests.values().all(|value| is_sha256(value))
            && self.issued_at <= now
            && self.expires_at > now
            && duration > chrono::Duration::zero()
            && duration <= chrono::Duration::days(90)
            && (2..=10).contains(&self.reviewers.len())
            && reviewer_ids.len() == self.reviewers.len()
            && key_ids.len() == self.reviewers.len()
            && required_roles.is_subset(&roles)
            && !self.evidence_digests.contains_key("attestation")
            && !self.evidence_digests.contains_key("reviewer_keyring")
            && self.reviewers.iter().all(|reviewer| {
                is_bounded_text(&reviewer.reviewer_id, 128)
                    && is_bounded_text(&reviewer.organization, 256)
                    && is_assurance_role(&reviewer.role)
                    && is_key_id(&reviewer.key_id)
                    && reviewer.key_id.len() <= 128
                    && is_signature(&reviewer.signature)
            });
        if !valid {
            return Err(ClosureError::DomainAssuranceInvalid);
        }
        let payload = self.signing_payload()?;
        for reviewer in &self.reviewers {
            let (_, key) = keyring.reviewer_key(reviewer, self.issued_at, now)?;
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
        expected_scope: &ClosureScope,
        keyring: &TrustedReviewerKeyring,
        now: DateTime<Utc>,
    ) -> Result<GateEvidence, ClosureError> {
        self.verify_offline(expected_scope, keyring, now)?;
        let gate_id = match self.domain {
            AssuranceDomain::Industrial => "DOMAIN_INDUSTRIAL",
            AssuranceDomain::Medical => "DOMAIN_MEDICAL",
            AssuranceDomain::SensitiveInteraction => "DOMAIN_SENSITIVE_INTERACTION",
        };
        let mut evidence_digests = self.evidence_digests.clone();
        evidence_digests.insert("attestation".into(), self.digest()?);
        evidence_digests.insert("reviewer_keyring".into(), keyring.digest()?);
        Ok(GateEvidence {
            gate_id: gate_id.into(),
            scope_digest: self.scope_digest.clone(),
            passed: true,
            evidence_kind: EvidenceKind::IndependentAssurance,
            evidence_digests,
            environment_reference: Some(self.environment_reference.clone()),
            measured_at: self.issued_at,
            expires_at: keyring.assurance_valid_until(
                &self.reviewers,
                self.issued_at,
                self.expires_at,
                expected_scope.valid_until,
                now,
            )?,
            source_certificate_type: Some("DOMAIN_ASSURANCE_ATTESTATION".into()),
        })
    }
}

/// Multi-party real-environment attestation for gates whose production facts
/// cannot be established inside the repository. It is deliberately separate
/// from `GateEvidence`: callers must verify signatures before converting it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
        expected_scope: &ClosureScope,
        keyring: &TrustedReviewerKeyring,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        expected_scope.validate(now)?;
        keyring.verify(now)?;
        let expected_scope_digest = expected_scope.digest()?;
        if keyring.digest()? != expected_scope.reviewer_keyring_digest {
            return Err(ClosureError::ReviewerKeyringInvalid);
        }
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
            && is_key_id(&self.attestation_id)
            && self.release_id == expected_scope.release_id
            && self.scope_digest == expected_scope_digest
            && is_sha256(&self.scope_digest)
            && is_environment_reference(&self.environment_reference)
            && self.decision == AssuranceDecision::Approved
            && !self.automated
            && is_bounded_text(&self.change_ticket, 256)
            && !self.evidence_digests.is_empty()
            && self.evidence_digests.len() <= 512
            && self.evidence_digests.keys().all(|key| is_key_id(key))
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
            && !self.evidence_digests.contains_key("attestation")
            && !self.evidence_digests.contains_key("reviewer_keyring")
            && self.reviewers.iter().all(|reviewer| {
                is_bounded_text(&reviewer.reviewer_id, 128)
                    && is_bounded_text(&reviewer.organization, 256)
                    && is_assurance_role(&reviewer.role)
                    && is_key_id(&reviewer.key_id)
                    && reviewer.key_id.len() <= 128
                    && is_signature(&reviewer.signature)
            });
        if !valid {
            return Err(ClosureError::ExternalAssuranceInvalid);
        }
        let payload = self.signing_payload()?;
        for reviewer in &self.reviewers {
            let (_, key) = keyring.reviewer_key(reviewer, self.issued_at, now)?;
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
        expected_scope: &ClosureScope,
        keyring: &TrustedReviewerKeyring,
        now: DateTime<Utc>,
    ) -> Result<GateEvidence, ClosureError> {
        self.verify_offline(expected_scope, keyring, now)?;
        let mut evidence_digests = self.evidence_digests.clone();
        evidence_digests.insert("attestation".into(), self.digest()?);
        evidence_digests.insert("reviewer_keyring".into(), keyring.digest()?);
        Ok(GateEvidence {
            gate_id: self.gate_id.clone(),
            scope_digest: self.scope_digest.clone(),
            passed: true,
            evidence_kind: EvidenceKind::RealEnvironment,
            evidence_digests,
            environment_reference: Some(self.environment_reference.clone()),
            measured_at: self.issued_at,
            expires_at: keyring.assurance_valid_until(
                &self.reviewers,
                self.issued_at,
                self.expires_at,
                expected_scope.valid_until,
                now,
            )?,
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
#[serde(deny_unknown_fields)]
pub struct ResidualRisk {
    pub risk_id: String,
    pub severity: Severity,
    pub description: String,
    pub owner: String,
    pub accepted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ClosureInput {
    pub schema_version: String,
    pub scope: ClosureScope,
    pub batch_statuses: Vec<BatchEvidenceStatus>,
    pub gate_evidence: Vec<GateEvidence>,
    pub residual_risks: Vec<ResidualRisk>,
    pub exceptions: Vec<GateException>,
}

impl ClosureInput {
    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClosureReport {
    pub schema_version: String,
    pub release_id: String,
    pub scope_digest: String,
    pub input_digest: String,
    pub eligible: bool,
    pub blockers: BTreeSet<String>,
    pub verified_gate_digests: BTreeMap<String, String>,
    pub evaluated_at: DateTime<Utc>,
    pub evidence_valid_until: DateTime<Utc>,
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

    pub fn verify_input(&self, input: &ClosureInput) -> Result<(), ClosureError> {
        self.verify_digest()?;
        if self.input_digest != input.digest()?
            || self.release_id != input.scope.release_id
            || self.scope_digest != input.scope.digest()?
            || ClosureRunner::evaluate(input, self.evaluated_at)? != *self
        {
            return Err(ClosureError::ReportInvalid);
        }
        Ok(())
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
        if input.batch_statuses.len() > 128
            || input.gate_evidence.len() > 128
            || input.residual_risks.len() > 10_000
            || input.exceptions.len() > 1_000
        {
            return Err(ClosureError::EvidenceCapacityExceeded);
        }
        let scope_digest = input.scope.digest()?;
        let input_digest = input.digest()?;
        let mut blockers = BTreeSet::new();
        let mut verified_gate_digests = BTreeMap::new();
        let mut evidence_valid_until = input.scope.valid_until;

        Self::check_batches(
            &input.batch_statuses,
            &scope_digest,
            now,
            &mut evidence_valid_until,
            &mut blockers,
        );
        Self::check_risks(&input.residual_risks, &mut blockers);
        let exception_gates = Self::valid_exception_gates(
            &input.exceptions,
            now,
            &mut evidence_valid_until,
            &mut blockers,
        );

        let mut evidence_by_gate: BTreeMap<&str, Vec<&GateEvidence>> = BTreeMap::new();
        let known_gates: BTreeSet<&str> = REQUIRED_GATES.iter().map(|(gate, _)| *gate).collect();
        for evidence in &input.gate_evidence {
            if !known_gates.contains(evidence.gate_id.as_str()) {
                blockers.insert(format!("GATE_{}_UNEXPECTED", evidence.gate_id));
                continue;
            }
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
            let evidence_kind_valid = if external_required {
                external_kind
            } else {
                evidence.evidence_kind == EvidenceKind::IntegrationTest
                    && evidence.environment_reference.is_none()
            };
            let valid_digests = !evidence.evidence_digests.is_empty()
                && evidence.evidence_digests.keys().all(|key| is_key_id(key))
                && evidence
                    .evidence_digests
                    .values()
                    .all(|digest| is_sha256(digest));
            let source_is_intermediate =
                evidence.source_certificate_type.as_deref() == Some("BATCH_22_ENGINE_CERTIFICATE");
            let expected_assurance_type = match gate_id {
                "CONTRACT_COMPATIBILITY" => Some("QUALIFIED_BATCH_EVIDENCE_SET"),
                "DOMAIN_INDUSTRIAL" | "DOMAIN_MEDICAL" | "DOMAIN_SENSITIVE_INTERACTION" => {
                    Some("DOMAIN_ASSURANCE_ATTESTATION")
                }
                _ if external_required => Some("EXTERNAL_GATE_ASSURANCE_ATTESTATION"),
                _ => None,
            };
            let trusted_source = expected_assurance_type.is_none_or(|expected| {
                evidence.source_certificate_type.as_deref() == Some(expected)
            });
            let trusted_assurance = !external_required
                || evidence.evidence_digests.get("reviewer_keyring")
                    == Some(&input.scope.reviewer_keyring_digest);
            let assurance_digest_present = !external_required
                || evidence.evidence_digests.contains_key("assurance")
                || evidence.evidence_digests.contains_key("attestation");
            let source_binding_valid = gate_id != "SUPPLY_CHAIN_PROVENANCE"
                || evidence.evidence_digests.get("signed_git_provenance")
                    == Some(&input.scope.signed_git_provenance_digest)
                    && evidence.evidence_digests.get("signed_release_binding")
                        == Some(&input.scope.signed_release_binding_digest)
                    && evidence.evidence_digests.get("release")
                        == Some(&input.scope.release_digest);
            let valid = evidence.scope_digest == scope_digest
                && evidence.passed
                && evidence.measured_at <= now
                && evidence.expires_at > now
                && valid_digests
                && evidence_kind_valid
                && (!external_required
                    || evidence
                        .environment_reference
                        .as_ref()
                        .is_some_and(|value| is_environment_reference(value)))
                && !source_is_intermediate;
            let valid = valid
                && trusted_source
                && trusted_assurance
                && assurance_digest_present
                && source_binding_valid;
            if !valid && !can_be_excepted {
                blockers.insert(format!("GATE_{gate_id}_FAILED"));
                continue;
            }
            if valid {
                evidence_valid_until = evidence_valid_until.min(evidence.expires_at);
                verified_gate_digests.insert(gate_id.into(), digest_gate(evidence)?);
            }
        }
        if verified_gate_digests.len() != REQUIRED_GATES.len() {
            blockers.insert("GATE_RESOLUTION_INCOMPLETE".into());
        }

        let mut report = ClosureReport {
            schema_version: CLOSURE_SCHEMA_VERSION.into(),
            release_id: input.scope.release_id.clone(),
            scope_digest,
            input_digest,
            eligible: blockers.is_empty(),
            blockers,
            verified_gate_digests,
            evaluated_at: now,
            evidence_valid_until,
            report_digest: String::new(),
        };
        report.report_digest = report.unsigned_digest()?;
        Ok(report)
    }

    fn check_batches(
        statuses: &[BatchEvidenceStatus],
        scope_digest: &str,
        now: DateTime<Utc>,
        evidence_valid_until: &mut DateTime<Utc>,
        blockers: &mut BTreeSet<String>,
    ) {
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
                        && status.scope_digest == scope_digest
                        && is_sha256(&status.scope_digest)
                        && is_sha256(&status.evidence_digest)
                        && status.measured_at <= now
                        && status.expires_at > now =>
                {
                    *evidence_valid_until = (*evidence_valid_until).min(status.expires_at);
                }
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
        let mut risk_ids = BTreeSet::new();
        for risk in risks {
            if !is_key_id(&risk.risk_id)
                || !risk_ids.insert(risk.risk_id.as_str())
                || !is_bounded_text(&risk.owner, 256)
                || !is_bounded_text(&risk.description, 4_096)
            {
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
        evidence_valid_until: &mut DateTime<Utc>,
        blockers: &mut BTreeSet<String>,
    ) -> BTreeSet<String> {
        let known_gates: BTreeSet<&str> = REQUIRED_GATES.iter().map(|(gate, _)| *gate).collect();
        let mut exception_ids = BTreeSet::new();
        let mut exception_gate_ids = BTreeSet::new();
        exceptions
            .iter()
            .filter_map(|exception| {
                let valid = is_key_id(&exception.exception_id)
                    && exception_ids.insert(exception.exception_id.as_str())
                    && exception_gate_ids.insert(exception.gate_id.as_str())
                    && known_gates.contains(exception.gate_id.as_str())
                    && exception.severity <= Severity::P2
                    && is_bounded_text(&exception.owner, 256)
                    && exception.approved_by.len() >= 2
                    && !exception.approved_by.contains(&exception.owner)
                    && !exception.compensating_control_digests.is_empty()
                    && exception
                        .compensating_control_digests
                        .iter()
                        .all(|digest| is_sha256(digest))
                    && exception.expires_at > now;
                if valid {
                    *evidence_valid_until = (*evidence_valid_until).min(exception.expires_at);
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ProductionClosureCertificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub release_id: String,
    pub scope_digest: String,
    pub input_digest: String,
    pub report_digest: String,
    pub signed_git_provenance_digest: String,
    pub signed_release_binding_digest: String,
    pub release_digest: String,
    pub reviewer_keyring_digest: String,
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
        input: &ClosureInput,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        report.verify_input(input)?;
        if self.schema_version != CLOSURE_SCHEMA_VERSION
            || !self.production_closure
            || !report.eligible
            || self.certificate_id != format!("pc-{}", &report.report_digest[..24])
            || self.release_id != report.release_id
            || self.scope_digest != report.scope_digest
            || self.input_digest != report.input_digest
            || self.report_digest != report.report_digest
            || self.signed_git_provenance_digest != input.scope.signed_git_provenance_digest
            || self.signed_release_binding_digest != input.scope.signed_release_binding_digest
            || self.release_digest != input.scope.release_digest
            || self.reviewer_keyring_digest != input.scope.reviewer_keyring_digest
            || !is_key_id(&self.key_id)
            || self.issued_at > now
            || self.issued_at < report.evaluated_at
            || self.expires_at != report.evidence_valid_until
            || self.expires_at <= now
            || !is_signature(&self.signature)
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
#[serde(deny_unknown_fields)]
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
        input: &ClosureInput,
        key_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, ClosureError> {
        let certificate = unsigned_certificate(report, input, key_id.into(), now)?;
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
        input: &ClosureInput,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        report.verify_input(input)?;
        input.scope.validate(now)?;
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
            || self.certificate.release_id != input.scope.release_id
            || self.certificate.scope_digest != report.scope_digest
            || self.certificate.scope_digest != input.scope.digest()?
            || self.certificate.input_digest != report.input_digest
            || self.certificate.report_digest != report.report_digest
            || self.certificate.signed_git_provenance_digest
                != input.scope.signed_git_provenance_digest
            || self.certificate.signed_release_binding_digest
                != input.scope.signed_release_binding_digest
            || self.certificate.release_digest != input.scope.release_digest
            || self.certificate.reviewer_keyring_digest != input.scope.reviewer_keyring_digest
            || report.evaluated_at > self.certificate.issued_at
            || self.certificate.issued_at > now
            || self.certificate.expires_at != report.evidence_valid_until
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
#[serde(deny_unknown_fields)]
pub struct ExternalCertificateSignature {
    pub schema_version: String,
    pub request_digest: String,
    pub algorithm: String,
    pub key_id: String,
    pub signed_at: DateTime<Utc>,
    pub audit_receipt_digest: String,
    pub signature: String,
}

impl ExternalCertificateSignature {
    pub fn finalize(
        &self,
        request: &ExternalCertificateSigningRequest,
        report: &ClosureReport,
        input: &ClosureInput,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError> {
        request.verify(report, input, now)?;
        if self.schema_version != EXTERNAL_SIGNATURE_SCHEMA_VERSION
            || self.algorithm != CLOSURE_SIGNATURE_ALGORITHM
            || self.key_id != request.key_id
            || self.request_digest != request.digest()?
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.audit_receipt_digest)
            || self.signed_at > now + Duration::minutes(1)
            || self.signed_at < now - Duration::minutes(15)
            || !is_signature(&self.signature)
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
            .verify_offline(report, input, key, now)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        Ok(certificate)
    }
}

fn unsigned_certificate(
    report: &ClosureReport,
    input: &ClosureInput,
    key_id: String,
    now: DateTime<Utc>,
) -> Result<ProductionClosureCertificate, ClosureError> {
    report.verify_input(input)?;
    input.scope.validate(now)?;
    if !is_key_id(&key_id)
        || !report.eligible
        || report.scope_digest != input.scope.digest()?
        || report.release_id != input.scope.release_id
        || report.input_digest != input.digest()?
        || report.evidence_valid_until > input.scope.valid_until
        || report.evidence_valid_until <= now
        || report.verified_gate_digests.len() != REQUIRED_GATES.len()
    {
        return Err(ClosureError::NotEligible);
    }
    Ok(ProductionClosureCertificate {
        schema_version: CLOSURE_SCHEMA_VERSION.into(),
        certificate_id: format!("pc-{}", &report.report_digest[..24]),
        release_id: report.release_id.clone(),
        scope_digest: report.scope_digest.clone(),
        input_digest: report.input_digest.clone(),
        report_digest: report.report_digest.clone(),
        signed_git_provenance_digest: input.scope.signed_git_provenance_digest.clone(),
        signed_release_binding_digest: input.scope.signed_release_binding_digest.clone(),
        release_digest: input.scope.release_digest.clone(),
        reviewer_keyring_digest: input.scope.reviewer_keyring_digest.clone(),
        production_closure: true,
        issued_at: now,
        expires_at: report.evidence_valid_until,
        key_id,
        signature: String::new(),
    })
}

#[cfg(any(test, feature = "development-local-signing"))]
pub struct ClosureAuthority {
    key_id: String,
    signing_key: SigningKey,
}

#[cfg(any(test, feature = "development-local-signing"))]
impl ClosureAuthority {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Result<Self, ClosureError> {
        let key_id = key_id.into();
        if !is_key_id(&key_id) {
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
        input: &ClosureInput,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError> {
        let mut certificate = unsigned_certificate(report, input, self.key_id.clone(), now)?;
        certificate.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(&certificate.signing_bytes()?)
                .to_bytes(),
        );
        Ok(certificate)
    }
}

#[cfg(any(test, feature = "development-local-signing"))]
pub trait CertificateSigner {
    fn sign_certificate(
        &self,
        report: &ClosureReport,
        input: &ClosureInput,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError>;
}

#[cfg(any(test, feature = "development-local-signing"))]
impl CertificateSigner for ClosureAuthority {
    fn sign_certificate(
        &self,
        report: &ClosureReport,
        input: &ClosureInput,
        now: DateTime<Utc>,
    ) -> Result<ProductionClosureCertificate, ClosureError> {
        self.issue(report, input, now)
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
        if !is_certificate_id(&certificate_id) || !is_bounded_text(&reason, 1_024) {
            return Err(ClosureError::RevocationInvalid);
        }
        self.revoked.write().insert(certificate_id, reason);
        Ok(())
    }

    pub fn verify_active(
        &self,
        certificate: &ProductionClosureCertificate,
        report: &ClosureReport,
        input: &ClosureInput,
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
        certificate.verify_offline(report, input, key, now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

    fn validate_unsigned(&self, now: DateTime<Utc>) -> Result<(), ClosureError> {
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
                && is_git_release_id(&entry.release_id)
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
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ClosureError> {
        self.validate_unsigned(now)?;
        if !is_signature(&self.signature) {
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
        input: &ClosureInput,
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
        certificate.verify_offline(report, input, certificate_key, now)
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
            || previous.sequence.checked_add(1) != Some(self.sequence)
            || self.previous_registry_digest.as_deref() != Some(previous_digest.as_str())
            || self.published_at <= previous.published_at
            || previous.entries.iter().any(|previous_entry| {
                self.entries
                    .binary_search_by(|entry| {
                        entry
                            .certificate_id
                            .as_str()
                            .cmp(previous_entry.certificate_id.as_str())
                    })
                    .ok()
                    .and_then(|index| self.entries.get(index))
                    != Some(previous_entry)
            })
        {
            return Err(ClosureError::RevocationInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationRegistryUpdate {
    pub schema_version: String,
    pub registry_id: String,
    pub key_id: String,
    pub base_checkpoint_digest: String,
    pub valid_for_seconds: u64,
    pub new_entries: Vec<CertificateRevocationEntry>,
}

impl RevocationRegistryUpdate {
    fn validate(&self, now: DateTime<Utc>) -> Result<(), ClosureError> {
        let mut certificate_ids = BTreeSet::new();
        let valid = self.schema_version == REVOCATION_UPDATE_SCHEMA_VERSION
            && is_key_id(&self.registry_id)
            && is_key_id(&self.key_id)
            && is_sha256(&self.base_checkpoint_digest)
            && (300..=604_800).contains(&self.valid_for_seconds)
            && self.new_entries.len() <= 10_000
            && self.new_entries.iter().all(|entry| {
                certificate_ids.insert(entry.certificate_id.as_str())
                    && is_certificate_id(&entry.certificate_id)
                    && is_git_release_id(&entry.release_id)
                    && is_reason_code(&entry.reason_code)
                    && is_sha256(&entry.evidence_digest)
                    && entry.revoked_at <= now
            });
        if valid {
            Ok(())
        } else {
            Err(ClosureError::RevocationInvalid)
        }
    }
}

/// Private-key-free request for issuing or refreshing the signed revocation
/// registry.  A successor is constructed by merging additions into the
/// previously verified snapshot; callers cannot omit historical revocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalRevocationRegistrySigningRequest {
    pub schema_version: String,
    pub algorithm: String,
    pub key_id: String,
    pub base_checkpoint_digest: String,
    pub registry: SignedCertificateRevocationRegistry,
    pub signing_payload: String,
    pub payload_sha256: String,
}

impl ExternalRevocationRegistrySigningRequest {
    pub fn prepare(
        update: &RevocationRegistryUpdate,
        previous: Option<&SignedCertificateRevocationRegistry>,
        registry_key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<Self, ClosureError> {
        update.validate(now)?;
        if let Some(previous) = previous {
            previous.verify(registry_key, now)?;
            if previous.registry_id != update.registry_id || previous.key_id != update.key_id {
                return Err(ClosureError::RevocationInvalid);
            }
        }

        let mut entries: BTreeMap<String, CertificateRevocationEntry> = previous
            .map(|registry| {
                registry
                    .entries
                    .iter()
                    .cloned()
                    .map(|entry| (entry.certificate_id.clone(), entry))
                    .collect()
            })
            .unwrap_or_default();
        for entry in &update.new_entries {
            if entries
                .insert(entry.certificate_id.clone(), entry.clone())
                .is_some()
            {
                return Err(ClosureError::RevocationInvalid);
            }
        }
        let sequence = match previous {
            Some(registry) => registry
                .sequence
                .checked_add(1)
                .ok_or(ClosureError::RevocationInvalid)?,
            None => 1,
        };
        let registry = SignedCertificateRevocationRegistry {
            schema_version: CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION.into(),
            registry_id: update.registry_id.clone(),
            sequence,
            previous_registry_digest: previous
                .map(SignedCertificateRevocationRegistry::digest)
                .transpose()?,
            published_at: now,
            expires_at: now
                + Duration::seconds(
                    i64::try_from(update.valid_for_seconds)
                        .map_err(|_| ClosureError::RevocationInvalid)?,
                ),
            key_id: update.key_id.clone(),
            entries: entries.into_values().collect(),
            signature: String::new(),
        };
        registry.validate_unsigned(now)?;
        validate_unsigned_successor(&registry, previous)?;
        let payload = registry.signing_bytes()?;
        Ok(Self {
            schema_version: REVOCATION_SIGNING_REQUEST_SCHEMA_VERSION.into(),
            algorithm: CLOSURE_SIGNATURE_ALGORITHM.into(),
            key_id: update.key_id.clone(),
            base_checkpoint_digest: update.base_checkpoint_digest.clone(),
            registry,
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
        previous: Option<&SignedCertificateRevocationRegistry>,
        now: DateTime<Utc>,
    ) -> Result<(), ClosureError> {
        if self.schema_version != REVOCATION_SIGNING_REQUEST_SCHEMA_VERSION
            || self.algorithm != CLOSURE_SIGNATURE_ALGORITHM
            || !is_key_id(&self.key_id)
            || !is_sha256(&self.base_checkpoint_digest)
            || self.key_id != self.registry.key_id
            || !self.registry.signature.is_empty()
        {
            return Err(ClosureError::ExternalSigningInvalid);
        }
        self.registry.validate_unsigned(now)?;
        validate_unsigned_successor(&self.registry, previous)?;
        let payload = URL_SAFE_NO_PAD
            .decode(&self.signing_payload)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        if !is_sha256(&self.payload_sha256)
            || self.payload_sha256 != hex(Sha256::digest(&payload))
            || payload != self.registry.signing_bytes()?
        {
            return Err(ClosureError::ExternalSigningInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalRevocationRegistrySignature {
    pub schema_version: String,
    pub request_digest: String,
    pub algorithm: String,
    pub key_id: String,
    pub signed_at: DateTime<Utc>,
    pub audit_receipt_digest: String,
    pub signature: String,
}

impl ExternalRevocationRegistrySignature {
    pub fn finalize(
        &self,
        request: &ExternalRevocationRegistrySigningRequest,
        previous: Option<&SignedCertificateRevocationRegistry>,
        key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<SignedCertificateRevocationRegistry, ClosureError> {
        request.verify(previous, now)?;
        if let Some(previous) = previous {
            previous.verify(key, now)?;
        }
        if self.schema_version != REVOCATION_EXTERNAL_SIGNATURE_SCHEMA_VERSION
            || self.algorithm != CLOSURE_SIGNATURE_ALGORITHM
            || self.key_id != request.key_id
            || self.request_digest != request.digest()?
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.audit_receipt_digest)
            || self.signed_at > now + Duration::minutes(1)
            || self.signed_at < now - Duration::minutes(15)
            || !is_signature(&self.signature)
        {
            return Err(ClosureError::ExternalSigningInvalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&request.signing_payload)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;
        key.verify(&payload, &signature)
            .map_err(|_| ClosureError::ExternalSigningInvalid)?;

        let mut registry = request.registry.clone();
        registry.signature = self.signature.clone();
        registry.verify(key, now)?;
        if let Some(previous) = previous {
            registry.verify_successor(previous, key, now)?;
        }
        Ok(registry)
    }
}

fn validate_unsigned_successor(
    current: &SignedCertificateRevocationRegistry,
    previous: Option<&SignedCertificateRevocationRegistry>,
) -> Result<(), ClosureError> {
    let valid = match previous {
        None => current.sequence == 1 && current.previous_registry_digest.is_none(),
        Some(previous) => {
            let previous_digest = previous.digest()?;
            current.registry_id == previous.registry_id
                && current.key_id == previous.key_id
                && previous.sequence.checked_add(1) == Some(current.sequence)
                && current.previous_registry_digest.as_deref() == Some(previous_digest.as_str())
                && current.published_at > previous.published_at
                && previous.entries.iter().all(|previous_entry| {
                    current
                        .entries
                        .binary_search_by(|entry| {
                            entry
                                .certificate_id
                                .as_str()
                                .cmp(previous_entry.certificate_id.as_str())
                        })
                        .ok()
                        .and_then(|index| current.entries.get(index))
                        == Some(previous_entry)
                })
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ClosureError::RevocationInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionActivationExpectation {
    pub schema_version: String,
    pub release_id: String,
    pub scope_digest: String,
    pub build_digest: String,
    pub release_digest: String,
    pub topology_digest: String,
}

impl ProductionActivationExpectation {
    pub fn digest(&self) -> Result<String, ClosureError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    fn verify(&self) -> Result<(), ClosureError> {
        if self.schema_version != ACTIVATION_EXPECTATION_SCHEMA_VERSION
            || !is_git_release_id(&self.release_id)
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.build_digest)
            || !is_sha256(&self.release_digest)
            || !is_sha256(&self.topology_digest)
        {
            return Err(ClosureError::ActivationInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionActivationReceipt {
    pub schema_version: String,
    pub certificate_id: String,
    pub release_id: String,
    pub scope_digest: String,
    pub input_digest: String,
    pub report_digest: String,
    pub activation_expectation_digest: String,
    pub revocation_registry_id: String,
    pub revocation_sequence: u64,
    pub revocation_registry_digest: String,
    pub verified_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub production_write_enabled: bool,
    pub receipt_digest: String,
}

impl ProductionActivationReceipt {
    fn unsigned_digest(&self) -> Result<String, ClosureError> {
        let mut unsigned = self.clone();
        unsigned.receipt_digest.clear();
        let bytes = serde_jcs::to_vec(&unsigned).map_err(|_| ClosureError::SerializationFailed)?;
        Ok(hex(Sha256::digest(bytes)))
    }

    pub fn verify_digest(&self) -> Result<(), ClosureError> {
        if self.production_write_enabled
            && self.valid_until > self.verified_at
            && self.receipt_digest == self.unsigned_digest()?
        {
            Ok(())
        } else {
            Err(ClosureError::ActivationInvalid)
        }
    }
}

pub struct ProductionActivationVerifier;

impl ProductionActivationVerifier {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        certificate: &ProductionClosureCertificate,
        report: &ClosureReport,
        input: &ClosureInput,
        certificate_key: &VerifyingKey,
        registry: &SignedCertificateRevocationRegistry,
        registry_key: &VerifyingKey,
        expectation: &ProductionActivationExpectation,
        now: DateTime<Utc>,
    ) -> Result<ProductionActivationReceipt, ClosureError> {
        expectation.verify()?;
        registry.verify_active(
            certificate,
            report,
            input,
            certificate_key,
            registry_key,
            now,
        )?;
        if expectation.release_id != input.scope.release_id
            || expectation.scope_digest != input.scope.digest()?
            || expectation.scope_digest != certificate.scope_digest
            || expectation.build_digest != input.scope.build_digest
            || expectation.release_digest != input.scope.release_digest
            || expectation.topology_digest != input.scope.topology_digest
        {
            return Err(ClosureError::ActivationInvalid);
        }
        let mut receipt = ProductionActivationReceipt {
            schema_version: ACTIVATION_RECEIPT_SCHEMA_VERSION.into(),
            certificate_id: certificate.certificate_id.clone(),
            release_id: certificate.release_id.clone(),
            scope_digest: certificate.scope_digest.clone(),
            input_digest: certificate.input_digest.clone(),
            report_digest: certificate.report_digest.clone(),
            activation_expectation_digest: expectation.digest()?,
            revocation_registry_id: registry.registry_id.clone(),
            revocation_sequence: registry.sequence,
            revocation_registry_digest: registry.digest()?,
            verified_at: now,
            valid_until: certificate.expires_at.min(registry.expires_at),
            production_write_enabled: true,
            receipt_digest: String::new(),
        };
        if receipt.valid_until <= now {
            return Err(ClosureError::ActivationInvalid);
        }
        receipt.receipt_digest = receipt.unsigned_digest()?;
        Ok(receipt)
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
    #[error("CLOSURE_REVIEWER_KEYRING_INVALID")]
    ReviewerKeyringInvalid,
    #[error("CLOSURE_ACTIVATION_INVALID")]
    ActivationInvalid,
}

fn digest_gate(evidence: &GateEvidence) -> Result<String, ClosureError> {
    let bytes = serde_jcs::to_vec(evidence).map_err(|_| ClosureError::SerializationFailed)?;
    Ok(hex(Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_git_release_id(value: &str) -> bool {
    value
        .strip_prefix("git:sha1:")
        .is_some_and(|object_id| is_lower_hex(object_id, 40))
        || value
            .strip_prefix("git:sha256:")
            .is_some_and(|object_id| is_lower_hex(object_id, 64))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_bounded_text(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_environment_reference(value: &str) -> bool {
    value
        .strip_prefix("environment://production/")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && value.len() <= 512
                && suffix.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
        })
}

fn is_assurance_role(value: &str) -> bool {
    matches!(
        value,
        "SAFETY_ENGINEER"
            | "OPERATIONS_OWNER"
            | "LICENSED_CLINICIAN"
            | "PRIVACY_LEGAL_REVIEWER"
            | "SAFEGUARDING_LEAD"
            | "HUMAN_SUPPORT_OWNER"
            | "RELEASE_ENGINEER"
            | "INDEPENDENT_AUDITOR"
            | "SECURITY_ENGINEER"
            | "SRE"
            | "CODING_DOMAIN_OWNER"
            | "ENERGY_DOMAIN_ENGINEER"
            | "RED_TEAM_LEAD"
            | "SECURITY_OWNER"
            | "DISASTER_RECOVERY_OWNER"
            | "COMPLIANCE_OWNER"
            | "CUSTOMER_RELEASE_AUTHORITY"
    )
}

fn is_signature(value: &str) -> bool {
    if value.len() != 86 {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 64 && URL_SAFE_NO_PAD.encode(decoded) == value)
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey, ClosureError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ClosureError::ReviewerKeyringInvalid)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ClosureError::ReviewerKeyringInvalid);
    }
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ClosureError::ReviewerKeyringInvalid)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ClosureError::ReviewerKeyringInvalid)
}

fn is_key_id(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn is_certificate_id(value: &str) -> bool {
    value
        .strip_prefix("pc-")
        .is_some_and(|digest| is_lower_hex(digest, 24))
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
            release_id: format!("git:sha1:{}", "f".repeat(40)),
            commit_digest: "1".repeat(64),
            signed_git_provenance_digest: "8".repeat(64),
            signed_release_binding_digest: "9".repeat(64),
            release_digest: "a".repeat(64),
            reviewer_keyring_digest: "b".repeat(64),
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
            scope: scope.clone(),
            batch_statuses: (REQUIRED_BATCH_FIRST..=REQUIRED_BATCH_LAST)
                .map(|batch| BatchEvidenceStatus {
                    batch,
                    status: BatchStatus::EvidenceVerified,
                    scope_digest: scope_digest.clone(),
                    evidence_digest: format!("{batch:064x}"),
                    measured_at: now - Duration::minutes(1),
                    expires_at: now + Duration::minutes(45),
                })
                .collect(),
            gate_evidence: REQUIRED_GATES
                .iter()
                .map(|(gate, external)| {
                    let mut evidence_digests = BTreeMap::from([("report".into(), "c".repeat(64))]);
                    if *external {
                        evidence_digests.insert(
                            "reviewer_keyring".into(),
                            scope.reviewer_keyring_digest.clone(),
                        );
                        evidence_digests.insert("assurance".into(), "d".repeat(64));
                    }
                    if *gate == "SUPPLY_CHAIN_PROVENANCE" {
                        evidence_digests.insert(
                            "signed_git_provenance".into(),
                            scope.signed_git_provenance_digest.clone(),
                        );
                        evidence_digests.insert(
                            "signed_release_binding".into(),
                            scope.signed_release_binding_digest.clone(),
                        );
                        evidence_digests.insert("release".into(), scope.release_digest.clone());
                    }
                    let source_certificate_type = match *gate {
                        "DOMAIN_INDUSTRIAL" | "DOMAIN_MEDICAL" | "DOMAIN_SENSITIVE_INTERACTION" => {
                            Some("DOMAIN_ASSURANCE_ATTESTATION".into())
                        }
                        _ if *external => Some("EXTERNAL_GATE_ASSURANCE_ATTESTATION".into()),
                        _ => Some("QUALIFIED_BATCH_EVIDENCE_SET".into()),
                    };
                    GateEvidence {
                        gate_id: (*gate).into(),
                        scope_digest: scope_digest.clone(),
                        passed: true,
                        evidence_kind: if *external {
                            EvidenceKind::RealEnvironment
                        } else {
                            EvidenceKind::IntegrationTest
                        },
                        evidence_digests,
                        environment_reference: external
                            .then(|| "environment://production/cluster-1".into()),
                        measured_at: now - Duration::minutes(1),
                        expires_at: now + Duration::minutes(50),
                        source_certificate_type,
                    }
                })
                .collect(),
            residual_risks: Vec::new(),
            exceptions: Vec::new(),
        }
    }

    fn reviewer_keyring(
        now: DateTime<Utc>,
        reviewers: &[AssuranceReviewer],
        roles: [&str; 2],
        signing_keys: &[SigningKey; 2],
    ) -> TrustedReviewerKeyring {
        TrustedReviewerKeyring {
            schema_version: REVIEWER_KEYRING_SCHEMA_VERSION.into(),
            keyring_id: "reviewers:production".into(),
            version: 1,
            issued_at: now - Duration::hours(2),
            expires_at: now + Duration::days(60),
            keys: reviewers
                .iter()
                .zip(roles)
                .zip(signing_keys)
                .map(|((reviewer, role), key)| TrustedReviewerKey {
                    key_id: reviewer.key_id.clone(),
                    reviewer_id: reviewer.reviewer_id.clone(),
                    organization: reviewer.organization.clone(),
                    roles: BTreeSet::from([role.into()]),
                    key_usage: REVIEWER_KEY_USAGE.into(),
                    algorithm: CLOSURE_SIGNATURE_ALGORITHM.into(),
                    public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                    status: ReviewerKeyStatus::Active,
                    not_before: now - Duration::hours(1),
                    not_after: now + Duration::minutes(30),
                    revoked_at: None,
                })
                .collect(),
        }
    }

    fn signed_domain_attestation(
        now: DateTime<Utc>,
        domain: AssuranceDomain,
        roles: [&str; 2],
    ) -> (
        ClosureScope,
        DomainAssuranceAttestation,
        TrustedReviewerKeyring,
    ) {
        let signing_keys = [
            SigningKey::from_bytes(&[81_u8; 32]),
            SigningKey::from_bytes(&[82_u8; 32]),
        ];
        let mut attestation = DomainAssuranceAttestation {
            schema_version: DOMAIN_ASSURANCE_SCHEMA_VERSION.into(),
            attestation_id: "attestation:domain:1".into(),
            domain,
            release_id: String::new(),
            scope_digest: String::new(),
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
        let keyring = reviewer_keyring(now, &attestation.reviewers, roles, &signing_keys);
        let mut scope = scope(now);
        scope.reviewer_keyring_digest = keyring
            .digest()
            .unwrap_or_else(|error| panic!("keyring: {error}"));
        attestation.release_id = scope.release_id.clone();
        attestation.scope_digest = scope
            .digest()
            .unwrap_or_else(|error| panic!("scope: {error}"));
        let payload = attestation
            .signing_payload()
            .unwrap_or_else(|error| panic!("payload: {error}"));
        for (reviewer, key) in attestation.reviewers.iter_mut().zip(&signing_keys) {
            reviewer.signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
        }
        (scope, attestation, keyring)
    }

    fn signed_external_attestation(
        now: DateTime<Utc>,
        gate_id: &str,
        roles: [&str; 2],
    ) -> (
        ClosureScope,
        ExternalGateAssuranceAttestation,
        TrustedReviewerKeyring,
    ) {
        let signing_keys = [
            SigningKey::from_bytes(&[91_u8; 32]),
            SigningKey::from_bytes(&[92_u8; 32]),
        ];
        let mut attestation = ExternalGateAssuranceAttestation {
            schema_version: EXTERNAL_GATE_ASSURANCE_SCHEMA_VERSION.into(),
            attestation_id: "attestation:external:1".into(),
            gate_id: gate_id.into(),
            release_id: String::new(),
            scope_digest: String::new(),
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
        let keyring = reviewer_keyring(now, &attestation.reviewers, roles, &signing_keys);
        let mut scope = scope(now);
        scope.reviewer_keyring_digest = keyring
            .digest()
            .unwrap_or_else(|error| panic!("keyring: {error}"));
        attestation.release_id = scope.release_id.clone();
        attestation.scope_digest = scope
            .digest()
            .unwrap_or_else(|error| panic!("scope: {error}"));
        let payload = attestation
            .signing_payload()
            .unwrap_or_else(|error| panic!("payload: {error}"));
        for (reviewer, key) in attestation.reviewers.iter_mut().zip(&signing_keys) {
            reviewer.signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
        }
        (scope, attestation, keyring)
    }

    #[test]
    fn missing_batch_and_intermediate_certificate_fail_closed() {
        let now = Utc::now();
        let mut input = complete_input(now);
        input.batch_statuses.pop();
        input.batch_statuses.push(BatchEvidenceStatus {
            batch: 36,
            status: BatchStatus::EvidenceVerified,
            scope_digest: input
                .scope
                .digest()
                .unwrap_or_else(|error| panic!("scope: {error}")),
            evidence_digest: "d".repeat(64),
            measured_at: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(30),
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
            authority.issue(&report, &input, now),
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
            .issue(&report, &input, now)
            .unwrap_or_else(|error| panic!("certificate: {error}"));
        let registry = CertificateRegistry::default();
        assert_eq!(
            registry.verify_active(&certificate, &report, &input, &key.verifying_key(), now),
            Ok(())
        );
        let mut tampered = certificate.clone();
        tampered.release_id = "release:other".into();
        assert_eq!(
            tampered.verify_offline(&report, &input, &key.verifying_key(), now),
            Err(ClosureError::CertificateInvalid)
        );
        registry
            .revoke(certificate.certificate_id.clone(), "rollout regression")
            .unwrap_or_else(|error| panic!("revoke: {error}"));
        assert_eq!(
            registry.verify_active(&certificate, &report, &input, &key.verifying_key(), now),
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
            &input,
            "kms:key:production-closure",
            now,
        )
        .unwrap_or_else(|error| panic!("request: {error}"));
        request
            .verify(&report, &input, now)
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
            signed_at: now,
            audit_receipt_digest: "a".repeat(64),
            signature: URL_SAFE_NO_PAD.encode(external_kms_key.sign(&payload).to_bytes()),
        };
        let certificate = response
            .finalize(
                &request,
                &report,
                &input,
                &external_kms_key.verifying_key(),
                now,
            )
            .unwrap_or_else(|error| panic!("finalize: {error}"));
        assert_eq!(certificate.key_id, "kms:key:production-closure");
        assert!(!certificate.signature.is_empty());
        assert_eq!(
            certificate.verify_offline(&report, &input, &external_kms_key.verifying_key(), now),
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
            &input,
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
            signed_at: now,
            audit_receipt_digest: "a".repeat(64),
            signature: URL_SAFE_NO_PAD.encode(external_kms_key.sign(&payload).to_bytes()),
        };

        let mut tampered_request = request.clone();
        tampered_request.certificate.release_id = "release:other".into();
        assert_eq!(
            response.finalize(
                &tampered_request,
                &report,
                &input,
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
                &input,
                &external_kms_key.verifying_key(),
                now,
            ),
            Err(ClosureError::ExternalSigningInvalid)
        );

        let wrong_key = SigningKey::from_bytes(&[75_u8; 32]);
        assert_eq!(
            response.finalize(&request, &report, &input, &wrong_key.verifying_key(), now,),
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
            .issue(&report, &input, issued_at)
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
                &input,
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
                &input,
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
    fn external_revocation_signing_preserves_every_historical_entry() {
        let now = Utc::now();
        let signing_key = SigningKey::from_bytes(&[79_u8; 32]);
        let first_update = RevocationRegistryUpdate {
            schema_version: REVOCATION_UPDATE_SCHEMA_VERSION.into(),
            registry_id: "registry:production-closure".into(),
            key_id: "registry-key:1".into(),
            base_checkpoint_digest: "e".repeat(64),
            valid_for_seconds: 86_400,
            new_entries: vec![CertificateRevocationEntry {
                certificate_id: format!("pc-{}", "a".repeat(24)),
                release_id: format!("git:sha1:{}", "1".repeat(40)),
                reason_code: "SECURITY_REGRESSION".into(),
                evidence_digest: "b".repeat(64),
                revoked_at: now - Duration::seconds(1),
            }],
        };
        let first_request = ExternalRevocationRegistrySigningRequest::prepare(
            &first_update,
            None,
            &signing_key.verifying_key(),
            now,
        )
        .unwrap_or_else(|error| panic!("first request: {error}"));
        assert_eq!(
            first_request.base_checkpoint_digest,
            first_update.base_checkpoint_digest
        );
        let first_payload = URL_SAFE_NO_PAD
            .decode(&first_request.signing_payload)
            .unwrap_or_else(|error| panic!("payload: {error}"));
        let first_response = ExternalRevocationRegistrySignature {
            schema_version: REVOCATION_EXTERNAL_SIGNATURE_SCHEMA_VERSION.into(),
            request_digest: first_request
                .digest()
                .unwrap_or_else(|error| panic!("request digest: {error}")),
            algorithm: CLOSURE_SIGNATURE_ALGORITHM.into(),
            key_id: first_request.key_id.clone(),
            signed_at: now,
            audit_receipt_digest: "a".repeat(64),
            signature: URL_SAFE_NO_PAD.encode(signing_key.sign(&first_payload).to_bytes()),
        };
        let first_registry = first_response
            .finalize(&first_request, None, &signing_key.verifying_key(), now)
            .unwrap_or_else(|error| panic!("first registry: {error}"));

        let second_update = RevocationRegistryUpdate {
            base_checkpoint_digest: "f".repeat(64),
            new_entries: vec![CertificateRevocationEntry {
                certificate_id: format!("pc-{}", "c".repeat(24)),
                release_id: format!("git:sha256:{}", "2".repeat(64)),
                reason_code: "KEY_COMPROMISE".into(),
                evidence_digest: "d".repeat(64),
                revoked_at: now,
            }],
            ..first_update
        };
        let second_request = ExternalRevocationRegistrySigningRequest::prepare(
            &second_update,
            Some(&first_registry),
            &signing_key.verifying_key(),
            now + Duration::seconds(1),
        )
        .unwrap_or_else(|error| panic!("second request: {error}"));
        assert_eq!(second_request.registry.entries.len(), 2);
        assert_eq!(
            second_request.base_checkpoint_digest,
            second_update.base_checkpoint_digest
        );

        let mut unbound = second_request.clone();
        unbound.base_checkpoint_digest = "not-a-digest".into();
        assert_eq!(
            unbound.verify(Some(&first_registry), now + Duration::seconds(1)),
            Err(ClosureError::ExternalSigningInvalid)
        );

        let mut omission = second_request.registry.clone();
        omission.entries.remove(0);
        assert_eq!(
            validate_unsigned_successor(&omission, Some(&first_registry)),
            Err(ClosureError::RevocationInvalid)
        );
    }

    #[test]
    fn report_binds_complete_input_and_uses_earliest_evidence_expiry() {
        let now = Utc::now();
        let input = complete_input(now);
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        assert_eq!(
            report.input_digest,
            input
                .digest()
                .unwrap_or_else(|error| panic!("input digest: {error}"))
        );
        assert_eq!(report.evidence_valid_until, now + Duration::minutes(45));
        assert_eq!(report.verify_input(&input), Ok(()));

        let mut tampered = input;
        tampered.batch_statuses[0].evidence_digest = "e".repeat(64);
        assert_eq!(
            report.verify_input(&tampered),
            Err(ClosureError::ReportInvalid)
        );
    }

    #[test]
    fn activation_verifier_pins_deployment_material_and_revocation_state() {
        let now = Utc::now();
        let input = complete_input(now);
        let report =
            ClosureRunner::evaluate(&input, now).unwrap_or_else(|error| panic!("report: {error}"));
        let certificate_key = SigningKey::from_bytes(&[83_u8; 32]);
        let certificate = ClosureAuthority::new("closure-key:1", certificate_key.clone())
            .and_then(|authority| authority.issue(&report, &input, now))
            .unwrap_or_else(|error| panic!("certificate: {error}"));
        let registry_key = SigningKey::from_bytes(&[84_u8; 32]);
        let mut registry = SignedCertificateRevocationRegistry {
            schema_version: CERTIFICATE_REVOCATION_REGISTRY_SCHEMA_VERSION.into(),
            registry_id: "registry:production-closure".into(),
            sequence: 1,
            previous_registry_digest: None,
            published_at: now,
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
        let expectation = ProductionActivationExpectation {
            schema_version: ACTIVATION_EXPECTATION_SCHEMA_VERSION.into(),
            release_id: input.scope.release_id.clone(),
            scope_digest: input
                .scope
                .digest()
                .unwrap_or_else(|error| panic!("scope: {error}")),
            build_digest: input.scope.build_digest.clone(),
            release_digest: input.scope.release_digest.clone(),
            topology_digest: input.scope.topology_digest.clone(),
        };
        let receipt = ProductionActivationVerifier::verify(
            &certificate,
            &report,
            &input,
            &certificate_key.verifying_key(),
            &registry,
            &registry_key.verifying_key(),
            &expectation,
            now,
        )
        .unwrap_or_else(|error| panic!("activation: {error}"));
        assert!(receipt.production_write_enabled);
        assert_eq!(receipt.verify_digest(), Ok(()));

        let mut mismatched = expectation;
        mismatched.build_digest = "f".repeat(64);
        assert_eq!(
            ProductionActivationVerifier::verify(
                &certificate,
                &report,
                &input,
                &certificate_key.verifying_key(),
                &registry,
                &registry_key.verifying_key(),
                &mismatched,
                now,
            ),
            Err(ClosureError::ActivationInvalid)
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
            let (scope, attestation, keyring) = signed_domain_attestation(now, domain, roles);
            assert_eq!(attestation.verify_offline(&scope, &keyring, now), Ok(()));
            let evidence = attestation
                .verified_gate_evidence(&scope, &keyring, now)
                .unwrap_or_else(|error| panic!("gate evidence: {error}"));
            assert_eq!(evidence.gate_id, gate_id);
            assert_eq!(evidence.evidence_kind, EvidenceKind::IndependentAssurance);
            assert_eq!(evidence.expires_at, now + Duration::minutes(30));
        }
    }

    #[test]
    fn domain_assurance_rejects_automation_wrong_roles_and_tampering() {
        let now = Utc::now();
        let (scope, attestation, keyring) = signed_domain_attestation(
            now,
            AssuranceDomain::Industrial,
            ["SAFETY_ENGINEER", "OPERATIONS_OWNER"],
        );

        let mut automated = attestation.clone();
        automated.automated = true;
        assert_eq!(
            automated.verify_offline(&scope, &keyring, now),
            Err(ClosureError::DomainAssuranceInvalid)
        );

        let mut wrong_role = attestation.clone();
        wrong_role.reviewers[1].role = "LICENSED_CLINICIAN".into();
        assert_eq!(
            wrong_role.verify_offline(&scope, &keyring, now),
            Err(ClosureError::DomainAssuranceInvalid)
        );

        let mut tampered = attestation;
        tampered
            .evidence_digests
            .insert("extra".into(), "c".repeat(64));
        assert_eq!(
            tampered.verify_offline(&scope, &keyring, now),
            Err(ClosureError::DomainAssuranceInvalid)
        );
    }

    #[test]
    fn reviewer_keyring_rejects_revoked_and_identity_mismatched_keys() {
        let now = Utc::now();
        let (mut scope, mut attestation, keyring) = signed_domain_attestation(
            now,
            AssuranceDomain::Industrial,
            ["SAFETY_ENGINEER", "OPERATIONS_OWNER"],
        );
        let mut identity_mismatch = attestation.clone();
        identity_mismatch.reviewers[0].reviewer_id = "reviewer:substitute".into();
        assert_eq!(
            identity_mismatch.verify_offline(&scope, &keyring, now),
            Err(ClosureError::ReviewerKeyringInvalid)
        );

        let mut revoked_keyring = keyring;
        revoked_keyring.keys[0].status = ReviewerKeyStatus::Revoked;
        revoked_keyring.keys[0].revoked_at = Some(now - Duration::seconds(30));
        scope.reviewer_keyring_digest = revoked_keyring
            .digest()
            .unwrap_or_else(|error| panic!("keyring digest: {error}"));
        attestation.scope_digest = scope
            .digest()
            .unwrap_or_else(|error| panic!("scope digest: {error}"));
        assert_eq!(
            attestation.verify_offline(&scope, &revoked_keyring, now),
            Err(ClosureError::ReviewerKeyringInvalid)
        );
    }

    #[test]
    fn customer_and_independent_reviewer_sign_enterprise_acceptance() {
        let now = Utc::now();
        let (scope, attestation, keyring) = signed_external_attestation(
            now,
            "ENTERPRISE_ACCEPTANCE",
            ["CUSTOMER_RELEASE_AUTHORITY", "INDEPENDENT_AUDITOR"],
        );
        assert_eq!(attestation.verify_offline(&scope, &keyring, now), Ok(()));
        let evidence = attestation
            .verified_gate_evidence(&scope, &keyring, now)
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
        let (scope, attestation, keyring) =
            signed_external_attestation(now, "HA_DR_RESTORE", ["SRE", "DISASTER_RECOVERY_OWNER"]);
        let mut same_organization = attestation.clone();
        same_organization.reviewers[1].organization =
            same_organization.reviewers[0].organization.clone();
        assert_eq!(
            same_organization.verify_offline(&scope, &keyring, now),
            Err(ClosureError::ExternalAssuranceInvalid)
        );
        let mut wrong_role = attestation.clone();
        wrong_role.reviewers[1].role = "INDEPENDENT_AUDITOR".into();
        assert_eq!(
            wrong_role.verify_offline(&scope, &keyring, now),
            Err(ClosureError::ExternalAssuranceInvalid)
        );
        let mut tampered = attestation;
        tampered.change_ticket = "CHG-TAMPERED".into();
        assert_eq!(
            tampered.verify_offline(&scope, &keyring, now),
            Err(ClosureError::ExternalAssuranceInvalid)
        );
    }
}
