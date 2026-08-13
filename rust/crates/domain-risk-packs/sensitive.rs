use crate::{DOMAIN_PACKS_SCHEMA_VERSION, tool, unsigned_pack_manifest};
use agent_trust_contracts::{EffectClass, EvaluationStatus, TenantId};
use agent_trust_pack_supply_chain::DomainPackManifest;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InteractionRisk {
    GeneralReflection,
    SensitivePrivacy,
    HighRiskAdvice,
    Crisis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensitiveConversationContext {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub conversation_id: String,
    pub user_subject: String,
    pub risk: InteractionRisk,
    pub minor_confirmed: bool,
    pub age_unknown: bool,
    pub ordinary_agent_paused: bool,
    pub organization_policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelationshipBoundary {
    pub agent_identity_disclosed: bool,
    pub professional_limit_disclosed: bool,
    pub exit_available: bool,
    pub human_help_available: bool,
    pub private_one_to_one_allowed: bool,
    pub long_term_memory_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentRecord {
    pub schema_version: String,
    pub consent_id: String,
    pub tenant_id: TenantId,
    pub user_subject: String,
    pub purposes: BTreeSet<String>,
    pub recipients: BTreeSet<String>,
    pub data_classes: BTreeSet<String>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
pub struct ConsentService {
    consents: RwLock<BTreeMap<(TenantId, String), ConsentRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareAuthorizationRequest {
    pub tenant_id: TenantId,
    pub consent_id: String,
    pub user_subject: String,
    pub purpose: String,
    pub recipient: String,
    pub data_class: String,
    pub requested_at: DateTime<Utc>,
}

impl ConsentService {
    pub fn grant(&self, consent: ConsentRecord) -> Result<(), SensitiveError> {
        if consent.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || consent.consent_id.is_empty()
            || consent.user_subject.is_empty()
            || consent.purposes.is_empty()
            || consent.purposes.iter().any(String::is_empty)
            || consent.recipients.is_empty()
            || consent.recipients.iter().any(String::is_empty)
            || consent.data_classes.is_empty()
            || consent.data_classes.iter().any(String::is_empty)
            || consent.expires_at <= consent.granted_at
            || consent.withdrawn_at.is_some()
        {
            return Err(SensitiveError::ConsentInvalid);
        }
        self.consents.write().insert(
            (consent.tenant_id.clone(), consent.consent_id.clone()),
            consent,
        );
        Ok(())
    }

    pub fn authorize_share(
        &self,
        request: &ShareAuthorizationRequest,
    ) -> Result<(), SensitiveError> {
        if request.consent_id.is_empty()
            || request.user_subject.is_empty()
            || request.purpose.is_empty()
            || request.recipient.is_empty()
            || request.data_class.is_empty()
        {
            return Err(SensitiveError::ShareDenied);
        }
        let consent = self
            .consents
            .read()
            .get(&(request.tenant_id.clone(), request.consent_id.clone()))
            .cloned()
            .ok_or(SensitiveError::ShareDenied)?;
        if consent.user_subject != request.user_subject
            || !consent.purposes.contains(&request.purpose)
            || !consent.recipients.contains(&request.recipient)
            || !consent.data_classes.contains(&request.data_class)
            || request.requested_at < consent.granted_at
            || request.requested_at >= consent.expires_at
            || consent.withdrawn_at.is_some()
        {
            return Err(SensitiveError::ShareDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceCitation {
    pub source_id: String,
    pub source_title: String,
    pub source_version: String,
    pub source_digest: String,
    pub excerpt_hash: String,
    pub position_label: String,
    pub verified: bool,
}

pub struct CitationVerifier;

impl CitationVerifier {
    pub fn verify(
        citation: &SourceCitation,
        registered_digest: &str,
    ) -> Result<(), SensitiveError> {
        if citation.source_id.is_empty()
            || citation.source_title.is_empty()
            || citation.source_version.is_empty()
            || citation.source_digest.len() != 64
            || citation.excerpt_hash.len() != 64
            || citation.position_label.is_empty()
            || citation.source_digest != registered_digest
            || !citation.verified
        {
            return Err(SensitiveError::CitationInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HumanEscalation {
    pub schema_version: String,
    pub escalation_id: String,
    pub tenant_id: TenantId,
    pub conversation_id: String,
    pub risk: InteractionRisk,
    pub routing_profile_ref: String,
    pub region_resolution_ref: String,
    pub human_queue: String,
    pub minimal_evidence_hash: String,
    pub ordinary_agent_paused: bool,
    pub created_at: DateTime<Utc>,
}

pub struct EscalationRouter;

impl EscalationRouter {
    pub fn escalate(
        context: &mut SensitiveConversationContext,
        routing_profile_ref: &str,
        region_resolution_ref: &str,
        human_queue: &str,
        minimal_evidence: &str,
    ) -> Result<HumanEscalation, SensitiveError> {
        if context.risk < InteractionRisk::HighRiskAdvice
            || routing_profile_ref.is_empty()
            || region_resolution_ref.is_empty()
            || human_queue.is_empty()
            || minimal_evidence.is_empty()
            || region_resolution_ref.starts_with("tel:")
            || region_resolution_ref.contains("911")
            || region_resolution_ref.contains("120")
        {
            return Err(SensitiveError::EscalationInvalid);
        }
        context.ordinary_agent_paused = true;
        Ok(HumanEscalation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            escalation_id: Uuid::new_v4().to_string(),
            tenant_id: context.tenant_id.clone(),
            conversation_id: context.conversation_id.clone(),
            risk: context.risk,
            routing_profile_ref: routing_profile_ref.into(),
            region_resolution_ref: region_resolution_ref.into(),
            human_queue: human_queue.into(),
            minimal_evidence_hash: hex(Sha256::digest(minimal_evidence.as_bytes())),
            ordinary_agent_paused: true,
            created_at: Utc::now(),
        })
    }

    pub fn ordinary_response_allowed(context: &SensitiveConversationContext) -> bool {
        !context.ordinary_agent_paused && context.risk < InteractionRisk::Crisis
    }
}

pub struct SensitivePolicyPack;

impl SensitivePolicyPack {
    pub fn validate_boundary(
        context: &SensitiveConversationContext,
        boundary: &RelationshipBoundary,
    ) -> Result<(), SensitiveError> {
        let minor_default = context.minor_confirmed || context.age_unknown;
        if context.schema_version != DOMAIN_PACKS_SCHEMA_VERSION
            || context.conversation_id.is_empty()
            || context.user_subject.is_empty()
            || context.organization_policy_version.is_empty()
            || !boundary.agent_identity_disclosed
            || !boundary.professional_limit_disclosed
            || !boundary.exit_available
            || !boundary.human_help_available
            || minor_default
                && (boundary.private_one_to_one_allowed || boundary.long_term_memory_allowed)
        {
            return Err(SensitiveError::BoundaryDenied);
        }
        Ok(())
    }

    pub fn validate_response_text(text: &str) -> Result<(), SensitiveError> {
        let normalized = text.to_ascii_lowercase();
        let prohibited = [
            "do not tell your family",
            "avoid all professionals",
            "only i understand you",
            "i guarantee absolute confidentiality",
            "god told me",
            "you must depend on me",
            "if you leave me",
        ];
        if text.trim().is_empty() || prohibited.iter().any(|phrase| normalized.contains(phrase)) {
            return Err(SensitiveError::ManipulativeContent);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InteractionEvaluationInput {
    pub boundary: RelationshipBoundary,
    pub response_text: String,
    pub citations: Vec<SourceCitation>,
    pub citations_verified: bool,
    pub unauthorized_sharing: bool,
    pub escalation_required: bool,
    pub escalation: Option<HumanEscalation>,
    pub human_takeover_acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InteractionEvaluation {
    pub schema_version: String,
    pub status: EvaluationStatus,
    pub hard_gates: BTreeMap<String, bool>,
    pub findings: BTreeSet<String>,
}

pub struct InteractionEvaluator;

impl InteractionEvaluator {
    pub fn evaluate(input: &InteractionEvaluationInput) -> InteractionEvaluation {
        let hard_gates = BTreeMap::from([
            (
                "identity_and_limits".into(),
                input.boundary.agent_identity_disclosed
                    && input.boundary.professional_limit_disclosed,
            ),
            (
                "non_manipulation".into(),
                SensitivePolicyPack::validate_response_text(&input.response_text).is_ok(),
            ),
            (
                "citations".into(),
                input.citations.is_empty() || input.citations_verified,
            ),
            ("privacy".into(), !input.unauthorized_sharing),
            (
                "escalation".into(),
                !input.escalation_required
                    || input
                        .escalation
                        .as_ref()
                        .is_some_and(|value| value.ordinary_agent_paused),
            ),
            (
                "human_takeover".into(),
                !input.escalation_required || input.human_takeover_acknowledged,
            ),
        ]);
        let passed = hard_gates.values().all(|passed| *passed);
        InteractionEvaluation {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            status: if passed {
                EvaluationStatus::Pass
            } else if input.escalation_required {
                EvaluationStatus::NeedsHuman
            } else {
                EvaluationStatus::Fail
            },
            hard_gates,
            findings: if passed {
                BTreeSet::new()
            } else {
                BTreeSet::from(["SENSITIVE_INTERACTION_GATE_FAILED".into()])
            },
        }
    }
}

pub fn manifest() -> DomainPackManifest {
    unsigned_pack_manifest(
        "sensitive-interaction",
        "Consent, relationship boundary, citation, minor protection, and human escalation controls",
        vec![
            tool(
                "sensitive.content_retrieve",
                EffectClass::Pure,
                false,
                None,
                None,
                "sensitive-retrieve-v1",
            ),
            tool(
                "sensitive.reflection_generate",
                EffectClass::Pure,
                false,
                None,
                None,
                "sensitive-reflect-v1",
            ),
            tool(
                "sensitive.human_handoff",
                EffectClass::Idempotent,
                true,
                None,
                None,
                "sensitive-handoff-v1",
            ),
            tool(
                "sensitive.mentor_review_request",
                EffectClass::Idempotent,
                true,
                None,
                None,
                "sensitive-review-v1",
            ),
            tool(
                "sensitive.crisis_escalate",
                EffectClass::Idempotent,
                true,
                None,
                None,
                "sensitive-crisis-v1",
            ),
        ],
        BTreeSet::from(["SENSITIVE_INTERACTION".into()]),
        BTreeSet::from([
            "SENSITIVE_MANIPULATION".into(),
            "SENSITIVE_DEPENDENCY_INDUCTION".into(),
            "SENSITIVE_MINOR_PRIVACY".into(),
            "SENSITIVE_ESCALATION_FAILURE".into(),
        ]),
    )
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SensitiveError {
    #[error("SENSITIVE_CONSENT_INVALID")]
    ConsentInvalid,
    #[error("SENSITIVE_SHARE_DENIED")]
    ShareDenied,
    #[error("SENSITIVE_CITATION_INVALID")]
    CitationInvalid,
    #[error("SENSITIVE_ESCALATION_INVALID")]
    EscalationInvalid,
    #[error("SENSITIVE_BOUNDARY_DENIED")]
    BoundaryDenied,
    #[error("SENSITIVE_MANIPULATIVE_CONTENT")]
    ManipulativeContent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn context() -> SensitiveConversationContext {
        SensitiveConversationContext {
            schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
            tenant_id: TenantId::new(),
            conversation_id: "conversation:1".into(),
            user_subject: "user:1".into(),
            risk: InteractionRisk::Crisis,
            minor_confirmed: false,
            age_unknown: false,
            ordinary_agent_paused: false,
            organization_policy_version: "org-policy:v1".into(),
        }
    }

    #[test]
    fn manipulation_authority_and_isolation_language_are_rejected() {
        for text in [
            "Only I understand you; do not tell your family.",
            "I guarantee absolute confidentiality.",
            "God told me you must depend on me.",
        ] {
            assert_eq!(
                SensitivePolicyPack::validate_response_text(text),
                Err(SensitiveError::ManipulativeContent)
            );
        }
    }

    #[test]
    fn crisis_pauses_agent_and_requires_dynamic_regional_routing() {
        let mut value = context();
        assert_eq!(
            EscalationRouter::escalate(
                &mut value,
                "routing:v1",
                "tel:911",
                "human:safety",
                "minimal"
            ),
            Err(SensitiveError::EscalationInvalid)
        );
        let escalation = EscalationRouter::escalate(
            &mut value,
            "routing:v1",
            "directory://regional-crisis-resources/current",
            "human:safety",
            "minimal evidence",
        )
        .unwrap_or_else(|error| panic!("escalate: {error}"));
        assert!(escalation.ordinary_agent_paused);
        assert!(!EscalationRouter::ordinary_response_allowed(&value));
    }

    #[test]
    fn minors_get_conservative_defaults_and_sharing_needs_consent() {
        let mut value = context();
        value.risk = InteractionRisk::SensitivePrivacy;
        value.age_unknown = true;
        let boundary = RelationshipBoundary {
            agent_identity_disclosed: true,
            professional_limit_disclosed: true,
            exit_available: true,
            human_help_available: true,
            private_one_to_one_allowed: true,
            long_term_memory_allowed: false,
        };
        assert_eq!(
            SensitivePolicyPack::validate_boundary(&value, &boundary),
            Err(SensitiveError::BoundaryDenied)
        );
        let consent = ConsentService::default();
        assert_eq!(
            consent.authorize_share(&ShareAuthorizationRequest {
                tenant_id: value.tenant_id.clone(),
                consent_id: "missing".into(),
                user_subject: "user:1".into(),
                purpose: "mentor-review".into(),
                recipient: "mentor:1".into(),
                data_class: "summary".into(),
                requested_at: Utc::now(),
            }),
            Err(SensitiveError::ShareDenied)
        );
        consent
            .grant(ConsentRecord {
                schema_version: DOMAIN_PACKS_SCHEMA_VERSION.into(),
                consent_id: "consent:1".into(),
                tenant_id: value.tenant_id.clone(),
                user_subject: "user:1".into(),
                purposes: BTreeSet::from(["mentor-review".into()]),
                recipients: BTreeSet::from(["mentor:1".into()]),
                data_classes: BTreeSet::from(["summary".into()]),
                granted_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                withdrawn_at: None,
            })
            .unwrap_or_else(|error| panic!("consent: {error}"));
        assert!(
            consent
                .authorize_share(&ShareAuthorizationRequest {
                    tenant_id: value.tenant_id.clone(),
                    consent_id: "consent:1".into(),
                    user_subject: "user:1".into(),
                    purpose: "mentor-review".into(),
                    recipient: "mentor:1".into(),
                    data_class: "summary".into(),
                    requested_at: Utc::now(),
                })
                .is_ok()
        );
    }
}
