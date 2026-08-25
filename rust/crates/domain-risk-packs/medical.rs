use crate::{DOMAIN_PACKS_SCHEMA_VERSION, tool, unsigned_pack_manifest};
use agent_trust_contracts::{DataClassification, EffectClass, EvaluationStatus, TenantId};
use agent_trust_pack_supply_chain::DomainPackManifest;
use chrono::{DateTime, Utc};
#[cfg(test)]
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatientContextRef {
    pub tenant_id: TenantId,
    pub patient_id: String,
    pub patient_identity_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CareRelationship {
    pub relationship_id: String,
    pub tenant_id: TenantId,
    pub patient_id: String,
    pub practitioner_subject: String,
    pub role: String,
    pub purposes: BTreeSet<String>,
    pub delegated_by: Option<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClinicalDataScope {
    pub purpose: String,
    pub requested_fields: BTreeSet<String>,
    pub maximum_classification: DataClassification,
    pub allow_export: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClinicalAccessDecision {
    pub schema_version: String,
    pub allowed: bool,
    pub minimum_fields: BTreeSet<String>,
    pub denied_fields: BTreeSet<String>,
    pub reason_codes: BTreeSet<String>,
    pub relationship_id: String,
    pub decided_at: DateTime<Utc>,
}

pub struct ClinicalAccessPolicy {
    minimum_fields_by_purpose: BTreeMap<String, BTreeSet<String>>,
    prohibited_fields: BTreeSet<String>,
}

impl ClinicalAccessPolicy {
    pub fn new(
        minimum_fields_by_purpose: BTreeMap<String, BTreeSet<String>>,
        prohibited_fields: BTreeSet<String>,
    ) -> Result<Self, MedicalError> {
        if minimum_fields_by_purpose.is_empty() {
            return Err(MedicalError::PolicyInvalid);
        }
        Ok(Self {
            minimum_fields_by_purpose,
            prohibited_fields,
        })
    }

    pub fn evaluate(
        &self,
        subject: &str,
        patient: &PatientContextRef,
        relationship: &CareRelationship,
        scope: &ClinicalDataScope,
        now: DateTime<Utc>,
    ) -> ClinicalAccessDecision {
        let minimum = self
            .minimum_fields_by_purpose
            .get(&scope.purpose)
            .cloned()
            .unwrap_or_default();
        let denied_fields = scope
            .requested_fields
            .difference(&minimum)
            .chain(scope.requested_fields.intersection(&self.prohibited_fields))
            .cloned()
            .collect::<BTreeSet<_>>();
        let relationship_valid = relationship.tenant_id == patient.tenant_id
            && relationship.patient_id == patient.patient_id
            && relationship.practitioner_subject == subject
            && relationship.purposes.contains(&scope.purpose)
            && now >= relationship.valid_from
            && now < relationship.valid_until
            && !relationship.revoked;
        let classification_allowed = scope.maximum_classification <= DataClassification::Regulated;
        let allowed = relationship_valid
            && !minimum.is_empty()
            && denied_fields.is_empty()
            && classification_allowed
            && !scope.allow_export;
        let mut reasons = BTreeSet::new();
        if !relationship_valid {
            reasons.insert("CARE_RELATIONSHIP_INVALID".into());
        }
        if !denied_fields.is_empty() {
            reasons.insert("MINIMUM_NECESSARY_EXCEEDED".into());
        }
        if scope.allow_export {
            reasons.insert("EXPORT_REQUIRES_SEPARATE_APPROVAL".into());
        }
        if allowed {
            reasons.insert("CLINICAL_ACCESS_ALLOWED".into());
        }
        ClinicalAccessDecision {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            allowed,
            minimum_fields: minimum,
            denied_fields,
            reason_codes: reasons,
            relationship_id: relationship.relationship_id.clone(),
            decided_at: now,
        }
    }
}

pub struct MedicalToolProvider;

impl MedicalToolProvider {
    pub fn authorize(
        tool_id: &str,
        access: &ClinicalAccessDecision,
        private_model: bool,
    ) -> Result<(), MedicalError> {
        let allowed_tools = [
            "medical.patient_context_read",
            "medical.document_search",
            "medical.summary_generate",
            "medical.coding_suggest",
            "medical.risk_flag",
            "medical.review_request",
        ];
        if !allowed_tools.contains(&tool_id)
            || !access.allowed
            || !private_model
            || tool_id.contains("diagnos")
            || tool_id.contains("prescri")
            || tool_id.contains("treatment")
        {
            return Err(MedicalError::ToolDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClinicalEvidenceRef {
    pub source_id: String,
    pub source_version: String,
    pub source_digest: String,
    pub excerpt_hash: String,
    pub retrieved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HumanReview {
    pub schema_version: String,
    pub review_id: String,
    pub tenant_id: TenantId,
    pub patient_id: String,
    pub output_hash: String,
    pub reviewer_subject: String,
    pub reviewer_role: String,
    pub decision: String,
    pub modifications_hash: Option<String>,
    pub reviewed_at: DateTime<Utc>,
}

pub trait HumanReviewService: Send + Sync {
    fn approved(&self, tenant: &TenantId, output_hash: &str) -> bool;
}

#[cfg(test)]
#[derive(Default)]
pub struct InMemoryHumanReviewService {
    reviews: RwLock<BTreeMap<(TenantId, String), HumanReview>>,
}

#[cfg(test)]
impl InMemoryHumanReviewService {
    pub fn record(&self, review: HumanReview) -> Result<(), MedicalError> {
        if review.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || review.review_id.is_empty()
            || review.patient_id.is_empty()
            || review.output_hash.len() != 64
            || review.reviewer_subject.is_empty()
            || !matches!(
                review.reviewer_role.as_str(),
                "PHYSICIAN" | "NURSE" | "CODER"
            )
            || !matches!(review.decision.as_str(), "APPROVE" | "REJECT" | "MODIFY")
            || review.decision == "MODIFY"
                && review
                    .modifications_hash
                    .as_deref()
                    .is_none_or(|hash| hash.len() != 64)
        {
            return Err(MedicalError::ReviewInvalid);
        }
        self.reviews.write().insert(
            (review.tenant_id.clone(), review.output_hash.clone()),
            review,
        );
        Ok(())
    }

    fn lookup_approved(&self, tenant: &TenantId, output_hash: &str) -> bool {
        self.reviews
            .read()
            .get(&(tenant.clone(), output_hash.into()))
            .is_some_and(|review| matches!(review.decision.as_str(), "APPROVE" | "MODIFY"))
    }
}

#[cfg(test)]
impl HumanReviewService for InMemoryHumanReviewService {
    fn approved(&self, tenant: &TenantId, output_hash: &str) -> bool {
        self.lookup_approved(tenant, output_hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MedicalEvaluationInput {
    pub tenant_id: TenantId,
    pub requested_patient_id: String,
    pub evidence_patient_ids: BTreeSet<String>,
    pub output_hash: String,
    pub evidence: Vec<ClinicalEvidenceRef>,
    pub high_risk: bool,
    pub sensitive_data_leaked: bool,
    pub knowledge_version_current: bool,
    pub model_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MedicalEvaluation {
    pub schema_version: String,
    pub status: EvaluationStatus,
    pub hard_gates: BTreeMap<String, bool>,
    pub findings: BTreeSet<String>,
}

pub struct MedicalEvaluator;

impl MedicalEvaluator {
    pub fn evaluate(
        input: &MedicalEvaluationInput,
        reviews: &dyn HumanReviewService,
        now: DateTime<Utc>,
    ) -> MedicalEvaluation {
        let evidence_complete = !input.evidence.is_empty()
            && input.evidence.iter().all(|evidence| {
                evidence.source_digest.len() == 64
                    && evidence.excerpt_hash.len() == 64
                    && now < evidence.expires_at
            });
        let hard_gates = BTreeMap::from([
            (
                "patient_match".into(),
                input.evidence_patient_ids == BTreeSet::from([input.requested_patient_id.clone()]),
            ),
            ("evidence".into(), evidence_complete),
            ("sensitive_leak".into(), !input.sensitive_data_leaked),
            ("knowledge_current".into(), input.knowledge_version_current),
            ("model_version".into(), input.model_digest.len() == 64),
            (
                "human_review".into(),
                !input.high_risk || reviews.approved(&input.tenant_id, &input.output_hash),
            ),
        ]);
        let passed = hard_gates.values().all(|passed| *passed);
        MedicalEvaluation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            status: if passed {
                EvaluationStatus::Pass
            } else if input.high_risk {
                EvaluationStatus::NeedsHuman
            } else {
                EvaluationStatus::Fail
            },
            hard_gates,
            findings: if passed {
                BTreeSet::new()
            } else {
                BTreeSet::from(["MEDICAL_HARD_GATE_FAILED".into()])
            },
        }
    }
}

pub fn manifest() -> DomainPackManifest {
    unsigned_pack_manifest(
        "medical",
        "Minimum-necessary clinical information assistance with evidence and professional review",
        vec![
            tool(
                "medical.patient_context_read",
                EffectClass::Pure,
                false,
                None,
                None,
                "medical-read-v1",
            ),
            tool(
                "medical.document_search",
                EffectClass::Pure,
                false,
                None,
                None,
                "medical-search-v1",
            ),
            tool(
                "medical.summary_generate",
                EffectClass::Pure,
                false,
                None,
                None,
                "medical-summary-v1",
            ),
            tool(
                "medical.coding_suggest",
                EffectClass::Pure,
                false,
                None,
                None,
                "medical-coding-v1",
            ),
            tool(
                "medical.risk_flag",
                EffectClass::Idempotent,
                false,
                None,
                None,
                "medical-risk-v1",
            ),
            tool(
                "medical.review_request",
                EffectClass::Idempotent,
                true,
                None,
                None,
                "medical-review-v1",
            ),
        ],
        BTreeSet::from(["REGULATED_CLINICAL".into()]),
        BTreeSet::from([
            "MEDICAL_PATIENT_MISMATCH".into(),
            "MEDICAL_FIELD_OVERREACH".into(),
            "MEDICAL_NO_EVIDENCE".into(),
            "MEDICAL_PROMPT_INJECTION".into(),
        ]),
    )
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MedicalError {
    #[error("MEDICAL_POLICY_INVALID")]
    PolicyInvalid,
    #[error("MEDICAL_TOOL_DENIED")]
    ToolDenied,
    #[error("MEDICAL_REVIEW_INVALID")]
    ReviewInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn policy() -> ClinicalAccessPolicy {
        ClinicalAccessPolicy::new(
            BTreeMap::from([(
                "SUMMARY".into(),
                BTreeSet::from(["notes".into(), "medications".into()]),
            )]),
            BTreeSet::from(["genetics".into()]),
        )
        .unwrap_or_else(|error| panic!("policy: {error}"))
    }

    #[test]
    fn wrong_patient_missing_relationship_and_extra_fields_are_denied() {
        let tenant = TenantId::new();
        let patient = PatientContextRef {
            tenant_id: tenant.clone(),
            patient_id: "patient:1".into(),
            patient_identity_version: "v1".into(),
        };
        let relationship = CareRelationship {
            relationship_id: "care:1".into(),
            tenant_id: tenant,
            patient_id: "patient:2".into(),
            practitioner_subject: "doctor:1".into(),
            role: "PHYSICIAN".into(),
            purposes: BTreeSet::from(["SUMMARY".into()]),
            delegated_by: None,
            valid_from: Utc::now() - Duration::minutes(1),
            valid_until: Utc::now() + Duration::hours(1),
            revoked: false,
        };
        let scope = ClinicalDataScope {
            purpose: "SUMMARY".into(),
            requested_fields: BTreeSet::from(["notes".into(), "genetics".into()]),
            maximum_classification: DataClassification::Regulated,
            allow_export: false,
        };
        let decision = policy().evaluate("doctor:1", &patient, &relationship, &scope, Utc::now());
        assert!(!decision.allowed);
        assert!(decision.reason_codes.contains("CARE_RELATIONSHIP_INVALID"));
        assert!(decision.reason_codes.contains("MINIMUM_NECESSARY_EXCEEDED"));
    }

    #[test]
    fn high_risk_output_without_review_never_completes() {
        let input = MedicalEvaluationInput {
            tenant_id: TenantId::new(),
            requested_patient_id: "patient:1".into(),
            evidence_patient_ids: BTreeSet::from(["patient:1".into()]),
            output_hash: "o".repeat(64),
            evidence: vec![ClinicalEvidenceRef {
                source_id: "doc:1".into(),
                source_version: "1".into(),
                source_digest: "d".repeat(64),
                excerpt_hash: "e".repeat(64),
                retrieved_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
            }],
            high_risk: true,
            sensitive_data_leaked: false,
            knowledge_version_current: true,
            model_digest: "m".repeat(64),
        };
        assert_eq!(
            MedicalEvaluator::evaluate(&input, &InMemoryHumanReviewService::default(), Utc::now())
                .status,
            EvaluationStatus::NeedsHuman
        );
    }
}
