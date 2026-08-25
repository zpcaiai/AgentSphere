//! Human-governance authorization on the production PEP boundary.
//!
//! The service credential authenticates the calling BFF.  This module separately verifies a
//! short-lived Ed25519 assertion for the human principal and binds it to the exact request body,
//! route, tenant, mTLS SAN, service subject, scope, and idempotency key before consulting the PDP.

use crate::authority::{PepAuthority, PepAuthorityError};
use crate::postgres::{GovernanceEvidenceRecord, PepClaimResult, canonical_digest};
use crate::{POLICY_SCHEMA_VERSION, validate_policy_decision};
use agent_trust_contracts::{
    Decision, HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE, PolicyDecision, SignedHumanPrincipalAssertion,
    TenantId, human_principal_request_digest,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize, de::DeserializeSeed};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const GOVERNANCE_AUTHORIZATION_REQUEST_SCHEMA: &str = "agenttrust.authorization-request.v1";
pub const GOVERNANCE_POLICY_INPUT_SCHEMA: &str = "agenttrust.governance-policy-input.v1";
pub const GOVERNANCE_EVIDENCE_SCHEMA: &str = "agenttrust.pep-governance-evidence.v1";
pub const HUMAN_PRINCIPAL_KEYRING_SCHEMA: &str = "agenttrust.human-principal-keyring.v1";
pub const APPROVAL_ROUTE: &str = "/v1/authorize/approval";
pub const QUERY_ROUTE: &str = "/v1/authorize/query";
pub const APPROVAL_SCOPE: &str = "pep:approval";
pub const QUERY_SCOPE: &str = "pep:query";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceStage {
    GovernanceApproval,
    GovernanceQuery,
}

impl GovernanceStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GovernanceApproval => "GOVERNANCE_APPROVAL",
            Self::GovernanceQuery => "GOVERNANCE_QUERY",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HumanPrincipalProjection {
    pub subject: String,
    pub tenant_id: TenantId,
    pub roles: BTreeSet<String>,
    pub project_ids: BTreeSet<String>,
    pub approval_ids: BTreeSet<String>,
    pub owned_resources: BTreeSet<String>,
    pub strong_auth: bool,
    pub authentication_time: DateTime<Utc>,
    pub authentication_context: String,
}

impl HumanPrincipalProjection {
    fn matches(&self, assertion: &SignedHumanPrincipalAssertion) -> bool {
        self.tenant_id == assertion.tenant_id
            && self.subject == assertion.subject
            && self.roles == assertion.roles
            && self.project_ids == assertion.project_ids
            && self.approval_ids == assertion.approval_ids
            && self.owned_resources == assertion.owned_resources
            && self.strong_auth == assertion.strong_auth
            && self.authentication_time == assertion.authentication_time
            && self.authentication_context == assertion.authentication_context
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAuthorizationAction {
    pub schema_version: String,
    pub case_id: String,
    pub decision: String,
    pub reason: String,
    pub observed_action_hash: String,
    pub observed_resource_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueryAuthorizationAction {
    pub schema_version: String,
    pub operation: String,
    pub resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceAuthorizationRequest<T> {
    pub schema_version: String,
    pub principal: HumanPrincipalProjection,
    pub action: T,
}

pub type ApprovalAuthorizationRequest = GovernanceAuthorizationRequest<ApprovalAuthorizationAction>;
pub type QueryAuthorizationRequest = GovernanceAuthorizationRequest<QueryAuthorizationAction>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernancePolicyInput {
    pub schema_version: String,
    pub stage: GovernanceStage,
    pub tenant_id: TenantId,
    pub principal: HumanPrincipalProjection,
    pub operation: String,
    pub resource: String,
    pub project_id: Option<String>,
    pub approval_ids: BTreeSet<String>,
    pub action: Value,
    pub idempotency_key: String,
    pub request_digest: String,
    pub assertion_digest: String,
    pub assertion_jti: String,
    pub client_identity: String,
    pub service_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceAuthorizationResponse {
    pub decision: Decision,
    pub policy_digest: String,
    pub evidence_ref: String,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub tenant_id: TenantId,
    pub stage: GovernanceStage,
    pub decision_id: String,
    pub decision: Decision,
    pub reason_codes: Vec<String>,
    pub request_digest: String,
    pub assertion_digest: String,
    pub assertion_jti: String,
    pub principal_subject: String,
    pub operation: String,
    pub resource: String,
    pub project_id: Option<String>,
    pub approval_ids: BTreeSet<String>,
    pub policy_version: String,
    pub policy_bundle_hash: String,
    pub policy_decision_digest: String,
    pub evaluated_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub evidence_ref: String,
}

impl GovernanceEvidence {
    fn seal(&mut self) -> Result<(), PepAuthorityError> {
        self.evidence_digest.clear();
        self.evidence_ref.clear();
        let digest = canonical_digest(self)?;
        self.evidence_ref = format!(
            "urn:agenttrust:pep-governance-evidence:{}:{}:sha256:{}",
            self.tenant_id.0, self.evidence_id, digest
        );
        self.evidence_digest = digest;
        Ok(())
    }

    pub fn verify_seal(&self) -> Result<(), PepAuthorityError> {
        let mut unsigned = self.clone();
        let expected_digest = unsigned.evidence_digest.clone();
        let expected_ref = unsigned.evidence_ref.clone();
        unsigned.evidence_digest.clear();
        unsigned.evidence_ref.clear();
        let actual = canonical_digest(&unsigned)?;
        let reference = format!(
            "urn:agenttrust:pep-governance-evidence:{}:{}:sha256:{}",
            self.tenant_id.0, self.evidence_id, actual
        );
        if actual != expected_digest || reference != expected_ref {
            return Err(PepAuthorityError::PersistenceUnavailable);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernanceClaimContext {
    input: GovernancePolicyInput,
    assertion: SignedHumanPrincipalAssertion,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalKeyringDocument {
    schema_version: String,
    audience: String,
    keys: Vec<HumanPrincipalKeyDocument>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalKeyDocument {
    issuer: String,
    key_id: String,
    algorithm: String,
    usage: String,
    status: HumanPrincipalKeyStatus,
    public_key: String,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HumanPrincipalKeyStatus {
    Active,
    VerifyOnly,
}

#[derive(Clone)]
struct HumanPrincipalKey {
    verifying_key: VerifyingKey,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    status: HumanPrincipalKeyStatus,
}

#[derive(Clone)]
pub struct HumanPrincipalVerifier {
    keyring_file: PathBuf,
    audience: String,
    maximum_authentication_age_seconds: i64,
    query_requires_strong_auth: bool,
}

/// A human-principal assertion that passed signature, keyring, request-binding, freshness, and
/// authentication-strength verification for the current route.  Its private field prevents an
/// unverified wire assertion from being passed to the governance authority by another module.
pub(crate) struct VerifiedHumanPrincipalAssertion(SignedHumanPrincipalAssertion);

impl HumanPrincipalVerifier {
    pub fn from_file(
        keyring_file: PathBuf,
        audience: String,
        maximum_authentication_age_seconds: i64,
        query_requires_strong_auth: bool,
    ) -> Result<Self, PepAuthorityError> {
        if !keyring_file.is_absolute()
            || !identifier(&audience, 256)
            || maximum_authentication_age_seconds <= 0
            || maximum_authentication_age_seconds > 86_400
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let verifier = Self {
            keyring_file,
            audience,
            maximum_authentication_age_seconds,
            query_requires_strong_auth,
        };
        verifier.load_keyring(Utc::now())?;
        Ok(verifier)
    }

    pub fn ready(&self) -> bool {
        self.load_keyring(Utc::now()).is_ok()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify<T: Serialize + ?Sized>(
        &self,
        encoded_assertion: &str,
        body: &T,
        tenant: &TenantId,
        client_identity: &str,
        service_subject: &str,
        path: &str,
        scope: &str,
        idempotency_key: &str,
        require_strong_auth: bool,
        now: DateTime<Utc>,
    ) -> Result<VerifiedHumanPrincipalAssertion, PepAuthorityError> {
        let assertion = decode_assertion(encoded_assertion)?;
        let keyring = self.load_keyring(now)?;
        let key = keyring
            .get(&(assertion.issuer.clone(), assertion.key_id.clone()))
            .ok_or(PepAuthorityError::AuthorizationDenied)?;
        if !fresh_human_principal_key_status(key.status)
            || !key.tenant_ids.contains(&tenant.0)
            || now < key.not_before
            || now >= key.expires_at
            || assertion.issued_at < key.not_before
            || assertion.expires_at > key.expires_at
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let request_digest = human_principal_request_digest(
            "POST",
            path,
            tenant,
            client_identity,
            service_subject,
            scope,
            idempotency_key,
            body,
        )
        .map_err(|_| PepAuthorityError::RequestInvalid)?;
        assertion
            .verify(
                &key.verifying_key,
                tenant,
                client_identity,
                service_subject,
                scope,
                &request_digest,
                &assertion.issuer,
                &self.audience,
                require_strong_auth,
                self.maximum_authentication_age_seconds,
                now,
            )
            .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
        Ok(VerifiedHumanPrincipalAssertion(assertion))
    }

    fn load_keyring(
        &self,
        now: DateTime<Utc>,
    ) -> Result<BTreeMap<(String, String), HumanPrincipalKey>, PepAuthorityError> {
        let raw = secure_public_file(&self.keyring_file, 1_048_576)?;
        let value = parse_strict_json(&raw, 16, 4_096, 2_048, 4_096)?;
        let key_values = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(PepAuthorityError::ConfigurationInvalid)?;
        for key in key_values {
            reject_duplicate_string_array(key, "tenant_ids", Some(1_024))?;
        }
        let document: HumanPrincipalKeyringDocument =
            serde_json::from_value(value).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != HUMAN_PRINCIPAL_KEYRING_SCHEMA
            || document.audience != self.audience
            || document.keys.is_empty()
            || document.keys.len() > 128
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        let mut active_usable = false;
        for document in document.keys {
            if !identifier(&document.issuer, 256)
                || !identifier(&document.key_id, 128)
                || document.algorithm != "Ed25519"
                || document.usage != HUMAN_PRINCIPAL_ASSERTION_KEY_USAGE
                || document.tenant_ids.is_empty()
                || document.tenant_ids.len() > 1_024
                || document
                    .tenant_ids
                    .iter()
                    .any(|tenant| !canonical_uuid(tenant))
                || document.not_before >= document.expires_at
            {
                return Err(PepAuthorityError::ConfigurationInvalid);
            }
            if document.public_key.len() != 43
                || !document
                    .public_key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(PepAuthorityError::ConfigurationInvalid);
            }
            let raw_key = URL_SAFE_NO_PAD
                .decode(&document.public_key)
                .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
            let bytes: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
            let verifying_key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
            active_usable |= matches!(document.status, HumanPrincipalKeyStatus::Active)
                && now >= document.not_before
                && now < document.expires_at;
            if keys
                .insert(
                    (document.issuer, document.key_id),
                    HumanPrincipalKey {
                        verifying_key,
                        tenant_ids: document.tenant_ids,
                        not_before: document.not_before,
                        expires_at: document.expires_at,
                        status: document.status,
                    },
                )
                .is_some()
            {
                return Err(PepAuthorityError::ConfigurationInvalid);
            }
        }
        if !active_usable {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        Ok(keys)
    }

    pub fn query_requires_strong_auth(&self) -> bool {
        self.query_requires_strong_auth
    }
}

impl PepAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn authorize_approval_governance(
        &self,
        request: ApprovalAuthorizationRequest,
        assertion: VerifiedHumanPrincipalAssertion,
        idempotency_key: String,
        client_identity: String,
        service_subject: String,
    ) -> Result<GovernanceAuthorizationResponse, PepAuthorityError> {
        let assertion = assertion.0;
        validate_common_request(&request, &assertion, &idempotency_key)?;
        let action = &request.action;
        if action.schema_version != "agenttrust.approval-intent.v1"
            || !canonical_uuid(&action.case_id)
            || !matches!(action.decision.as_str(), "APPROVE" | "REJECT")
            || !valid_approval_reason(&action.reason)
            || !digest(&action.observed_action_hash)
            || !valid_approval_resource_version(&action.observed_resource_version)
            || !assertion.approval_ids.contains(&action.case_id)
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let resource = format!("approval:{}", action.case_id);
        let input = governance_input(
            GovernanceStage::GovernanceApproval,
            &request,
            &assertion,
            "APPROVAL_DECIDE".into(),
            resource,
            None,
            BTreeSet::from([action.case_id.clone()]),
            idempotency_key,
            client_identity,
            service_subject,
        )?;
        self.authorize_governance(input, assertion).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn authorize_query_governance(
        &self,
        request: QueryAuthorizationRequest,
        assertion: VerifiedHumanPrincipalAssertion,
        idempotency_key: String,
        client_identity: String,
        service_subject: String,
    ) -> Result<GovernanceAuthorizationResponse, PepAuthorityError> {
        let assertion = assertion.0;
        validate_common_request(&request, &assertion, &idempotency_key)?;
        let action = &request.action;
        if action.schema_version != "agenttrust.query-authorization.v1"
            || !operation(&action.operation)
            || action.resource.is_empty()
            || action.resource.len() > 2_048
            || unsafe_text(&action.resource)
        {
            return Err(PepAuthorityError::RequestInvalid);
        }
        let project_id = action.resource.strip_prefix("project:").map(str::to_owned);
        let approval_id = action.resource.strip_prefix("approval:").map(str::to_owned);
        let project_authorized = project_id
            .as_ref()
            .is_some_and(|project| assertion.project_ids.contains(project));
        let approval_authorized = approval_id
            .as_ref()
            .is_some_and(|approval| assertion.approval_ids.contains(approval));
        if !assertion.owned_resources.contains(&action.resource)
            && !project_authorized
            && !approval_authorized
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let approval_ids = approval_id.into_iter().collect();
        let input = governance_input(
            GovernanceStage::GovernanceQuery,
            &request,
            &assertion,
            action.operation.clone(),
            action.resource.clone(),
            project_id,
            approval_ids,
            idempotency_key,
            client_identity,
            service_subject,
        )?;
        self.authorize_governance(input, assertion).await
    }

    async fn authorize_governance(
        &self,
        input: GovernancePolicyInput,
        assertion: SignedHumanPrincipalAssertion,
    ) -> Result<GovernanceAuthorizationResponse, PepAuthorityError> {
        let tenant = input.tenant_id.clone();
        let stage = input.stage.as_str();
        let request_digest = input.request_digest.clone();
        let idempotency_key = input.idempotency_key.clone();
        let claim_context = GovernanceClaimContext { input, assertion };
        let (owner, context) = match self
            .store
            .begin_claim::<GovernanceAuthorizationResponse, GovernanceClaimContext>(
                &tenant,
                stage,
                &idempotency_key,
                &request_digest,
                &claim_context,
            )
            .await?
        {
            PepClaimResult::Replay(response) => return Ok(response),
            PepClaimResult::Acquired { owner, context } => (owner, context),
        };
        self.store
            .bind_human_assertion(
                &tenant,
                stage,
                &idempotency_key,
                &request_digest,
                &owner,
                &context.assertion.jti,
                &context.input.assertion_digest,
            )
            .await?;
        let input_hash = canonical_digest(&context.input)?;
        let (decision, active_bundle_digest) = self
            .evaluate_governance_policy(&context.input, stage, &tenant)
            .await?;
        validate_policy_decision(&decision, &input_hash, Utc::now(), &active_bundle_digest)
            .map_err(|_| PepAuthorityError::DependencyResponseInvalid)?;
        validate_governance_decision(&decision)?;
        let response_decision = if decision.decision == Decision::Allow {
            Decision::Allow
        } else {
            Decision::Deny
        };
        let recorded_at = Utc::now();
        let mut evidence = GovernanceEvidence {
            schema_version: GOVERNANCE_EVIDENCE_SCHEMA.into(),
            evidence_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.clone(),
            stage: context.input.stage,
            decision_id: decision.decision_id.clone(),
            decision: response_decision,
            reason_codes: decision.reason_codes.clone(),
            request_digest: request_digest.clone(),
            assertion_digest: context.input.assertion_digest.clone(),
            assertion_jti: context.input.assertion_jti.clone(),
            principal_subject: context.input.principal.subject.clone(),
            operation: context.input.operation.clone(),
            resource: context.input.resource.clone(),
            project_id: context.input.project_id.clone(),
            approval_ids: context.input.approval_ids.clone(),
            policy_version: decision.policy_version.0.clone(),
            policy_bundle_hash: decision.policy_bundle_hash.clone(),
            policy_decision_digest: canonical_digest(&decision)?,
            evaluated_at: decision.evaluated_at,
            recorded_at,
            evidence_digest: String::new(),
            evidence_ref: String::new(),
        };
        evidence.seal()?;
        evidence.verify_seal()?;
        let response = GovernanceAuthorizationResponse {
            decision: response_decision,
            policy_digest: decision.policy_bundle_hash.clone(),
            evidence_ref: evidence.evidence_ref.clone(),
            reason_codes: decision.reason_codes.clone(),
        };
        self.store
            .persist_governance(
                &tenant,
                stage,
                &idempotency_key,
                &request_digest,
                &owner,
                &input_hash,
                &response,
                &decision,
                GovernanceEvidenceRecord {
                    evidence_id: &evidence.evidence_id,
                    assertion_jti: &evidence.assertion_jti,
                    evidence_digest: &evidence.evidence_digest,
                    evidence_ref: &evidence.evidence_ref,
                    evidence_body: serde_json::to_value(&evidence)
                        .map_err(|_| PepAuthorityError::ResponseInvalid)?,
                    recorded_at: evidence.recorded_at,
                },
            )
            .await
    }

    pub(crate) async fn governance_evidence(
        &self,
        tenant: &TenantId,
        evidence_id: &str,
    ) -> Result<Option<GovernanceEvidence>, PepAuthorityError> {
        if !canonical_uuid(evidence_id) {
            return Err(PepAuthorityError::RequestInvalid);
        }
        let evidence = self
            .store
            .load_governance_evidence(tenant, evidence_id)
            .await?;
        let evidence = evidence
            .map(|value| {
                serde_json::from_value::<GovernanceEvidence>(value)
                    .map_err(|_| PepAuthorityError::PersistenceUnavailable)
            })
            .transpose()?;
        if let Some(evidence) = &evidence {
            evidence.verify_seal()?;
            if &evidence.tenant_id != tenant || evidence.evidence_id != evidence_id {
                return Err(PepAuthorityError::PersistenceUnavailable);
            }
        }
        Ok(evidence)
    }
}

fn governance_input<T: Serialize>(
    stage: GovernanceStage,
    request: &GovernanceAuthorizationRequest<T>,
    assertion: &SignedHumanPrincipalAssertion,
    operation: String,
    resource: String,
    project_id: Option<String>,
    approval_ids: BTreeSet<String>,
    idempotency_key: String,
    client_identity: String,
    service_subject: String,
) -> Result<GovernancePolicyInput, PepAuthorityError> {
    let assertion_digest = assertion
        .assertion_digest()
        .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
    Ok(GovernancePolicyInput {
        schema_version: GOVERNANCE_POLICY_INPUT_SCHEMA.into(),
        stage,
        tenant_id: request.principal.tenant_id.clone(),
        principal: request.principal.clone(),
        operation,
        resource,
        project_id,
        approval_ids,
        action: serde_json::to_value(&request.action)
            .map_err(|_| PepAuthorityError::RequestInvalid)?,
        idempotency_key,
        request_digest: assertion.request_digest.clone(),
        assertion_digest,
        assertion_jti: assertion.jti.clone(),
        client_identity,
        service_subject,
    })
}

fn validate_common_request<T>(
    request: &GovernanceAuthorizationRequest<T>,
    assertion: &SignedHumanPrincipalAssertion,
    idempotency_key: &str,
) -> Result<(), PepAuthorityError> {
    if request.schema_version != GOVERNANCE_AUTHORIZATION_REQUEST_SCHEMA
        || !request.principal.matches(assertion)
        || !idempotency(idempotency_key)
        || !canonical_uuid(&request.principal.tenant_id.0)
    {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    Ok(())
}

fn validate_governance_decision(decision: &PolicyDecision) -> Result<(), PepAuthorityError> {
    if decision.schema_version.0 != POLICY_SCHEMA_VERSION
        || !identifier(&decision.decision_id, 256)
        || !matches!(decision.decision, Decision::Allow | Decision::Deny)
        || decision.reason_codes.is_empty()
        || decision.reason_codes.len() > 64
        || decision
            .reason_codes
            .iter()
            .any(|reason| !identifier(reason, 256))
        || decision.policy_version.0.is_empty()
        || decision.policy_version.0.len() > 256
        || !digest(&decision.policy_bundle_hash)
        || !digest(&decision.input_hash)
        || !decision.obligations.is_empty()
    {
        return Err(PepAuthorityError::DependencyResponseInvalid);
    }
    Ok(())
}

pub fn decode_assertion(encoded: &str) -> Result<SignedHumanPrincipalAssertion, PepAuthorityError> {
    if encoded.is_empty() || encoded.len() > 87_382 || encoded.contains('=') {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
    if raw.is_empty() || raw.len() > 65_536 {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    let value = parse_strict_json(&raw, 8, 4_096, 64, 2_048)
        .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
    for field in ["roles", "project_ids", "approval_ids", "owned_resources"] {
        reject_duplicate_string_array(&value, field, Some(1_024))
            .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
    }
    serde_json::from_value(value).map_err(|_| PepAuthorityError::AuthorizationDenied)
}

fn parse_strict_json(
    raw: &[u8],
    maximum_depth: usize,
    maximum_array_items: usize,
    maximum_object_keys: usize,
    maximum_string_bytes: usize,
) -> Result<Value, PepAuthorityError> {
    let limits = StrictJsonLimits {
        maximum_depth,
        maximum_array_items,
        maximum_object_keys,
        maximum_string_bytes,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValueSeed { limits, depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    deserializer
        .end()
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    Ok(value)
}

#[derive(Clone, Copy)]
struct StrictJsonLimits {
    maximum_depth: usize,
    maximum_array_items: usize,
    maximum_object_keys: usize,
    maximum_string_bytes: usize,
}

struct StrictValueSeed {
    limits: StrictJsonLimits,
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        if self.depth > self.limits.maximum_depth {
            return Err(serde::de::Error::custom("PEP_JSON_DEPTH_EXCEEDED"));
        }
        deserializer.deserialize_any(StrictValueVisitor {
            limits: self.limits,
            depth: self.depth,
        })
    }
}

struct StrictValueVisitor {
    limits: StrictJsonLimits,
    depth: usize,
}

impl<'de> serde::de::Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("strict bounded JSON")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("PEP_JSON_NUMBER_INVALID"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > self.limits.maximum_string_bytes {
            return Err(E::custom("PEP_JSON_STRING_TOO_LARGE"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        StrictValueSeed {
            limits: self.limits,
            depth: self.depth + 1,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            limits: self.limits,
            depth: self.depth + 1,
        })? {
            if values.len() >= self.limits.maximum_array_items {
                return Err(serde::de::Error::custom("PEP_JSON_ARRAY_TOO_LARGE"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.limits.maximum_string_bytes
                || values.len() >= self.limits.maximum_object_keys
                || values.contains_key(&key)
            {
                return Err(serde::de::Error::custom("PEP_JSON_OBJECT_INVALID"));
            }
            let value = map.next_value_seed(StrictValueSeed {
                limits: self.limits,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn reject_duplicate_string_array(
    value: &Value,
    field: &str,
    maximum: Option<usize>,
) -> Result<(), PepAuthorityError> {
    let Some(array) = value.get(field).and_then(Value::as_array) else {
        if field == "keys" {
            return Ok(());
        }
        return Err(PepAuthorityError::ConfigurationInvalid);
    };
    if maximum.is_some_and(|maximum| array.len() > maximum) {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    let mut values = BTreeSet::new();
    for value in array {
        let value = value
            .as_str()
            .ok_or(PepAuthorityError::ConfigurationInvalid)?;
        if !values.insert(value) {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
    }
    Ok(())
}

fn secure_public_file(path: &Path, maximum: u64) -> Result<Vec<u8>, PepAuthorityError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
    }
    std::fs::read(path).map_err(|_| PepAuthorityError::ConfigurationInvalid)
}

fn operation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn idempotency(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn unsafe_text(value: &str) -> bool {
    value.contains(['\0', '\r', '\n'])
}

fn valid_approval_reason(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= 2_000
        && value.len() <= 4_096
        && !value.contains('\0')
}

fn valid_approval_resource_version(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 512 && !unsafe_text(value)
}

fn fresh_human_principal_key_status(status: HumanPrincipalKeyStatus) -> bool {
    matches!(status, HumanPrincipalKeyStatus::Active)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_json_rejects_duplicate_security_fields() {
        let raw = br#"{"schema_version":"agenttrust.signed-human-principal-assertion.v1","tenant_id":"00000000-0000-4000-8000-000000000001","subject":"human","subject":"attacker"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(
            decode_assertion(&encoded),
            Err(PepAuthorityError::AuthorizationDenied)
        );
    }

    #[test]
    fn resource_requires_exact_signed_scope() {
        assert!(operation("VIEW_ENTERPRISE_DASHBOARD"));
        assert!(!operation("view-dashboard"));
        assert!(canonical_uuid("00000000-0000-4000-8000-000000000001"));
    }

    #[test]
    fn approval_human_text_matches_the_public_unicode_contract() {
        assert!(valid_approval_reason(&("😀".repeat(1_001) + "\n")));
        assert!(!valid_approval_reason(&"界".repeat(1_366)));
        assert!(!valid_approval_reason("bad\0reason"));
        assert!(valid_approval_resource_version(&"😀".repeat(512)));
        assert!(!valid_approval_resource_version(&"😀".repeat(513)));
        assert!(!valid_approval_resource_version("version\none"));
        assert!(fresh_human_principal_key_status(HumanPrincipalKeyStatus::Active));
        assert!(!fresh_human_principal_key_status(
            HumanPrincipalKeyStatus::VerifyOnly
        ));
    }

    #[test]
    fn governance_evidence_detects_post_commit_tampering() {
        let now = Utc::now();
        let mut evidence = GovernanceEvidence {
            schema_version: GOVERNANCE_EVIDENCE_SCHEMA.into(),
            evidence_id: "00000000-0000-4000-8000-000000000010".into(),
            tenant_id: TenantId("00000000-0000-4000-8000-000000000001".into()),
            stage: GovernanceStage::GovernanceQuery,
            decision_id: "decision-1".into(),
            decision: Decision::Deny,
            reason_codes: vec!["RESOURCE_SCOPE_DENIED".into()],
            request_digest: "a".repeat(64),
            assertion_digest: "b".repeat(64),
            assertion_jti: "00000000-0000-4000-8000-000000000011".into(),
            principal_subject: "human-1".into(),
            operation: "VIEW_RESOURCE".into(),
            resource: "project:project-1".into(),
            project_id: Some("project-1".into()),
            approval_ids: BTreeSet::new(),
            policy_version: "policy-1".into(),
            policy_bundle_hash: "c".repeat(64),
            policy_decision_digest: "d".repeat(64),
            evaluated_at: now.to_owned(),
            recorded_at: now,
            evidence_digest: String::new(),
            evidence_ref: String::new(),
        };
        evidence
            .seal()
            .unwrap_or_else(|error| panic!("test evidence must seal: {error:?}"));
        assert!(evidence.verify_seal().is_ok());
        evidence.resource = "project:attacker-project".into();
        assert_eq!(
            evidence.verify_seal(),
            Err(PepAuthorityError::PersistenceUnavailable)
        );
    }
}
