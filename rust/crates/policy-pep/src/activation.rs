//! Signed policy publication and durable PDP activation convergence.
//!
//! This module deliberately keeps the network call outside both PEP database transactions.  A
//! durable PENDING claim exists before the call; only a verified, exact PDP acknowledgement can
//! atomically advance the active mapping and persist evidence.  UNKNOWN claims are retryable with
//! the same idempotency key and can therefore recover a response lost after PDP activation.

use crate::authority::{PepAuthority, PepAuthorityError, read_verifying_key, secure_read};
use crate::postgres::{PolicyActivationClaimResult, canonical_digest};
use agent_trust_contracts::{
    PDP_POLICY_ACTIVATION_ACK_KEY_USAGE, PEP_POLICY_ACTIVATION_ACK_KEY_USAGE,
    PEP_POLICY_ACTIVATION_ACK_SCHEMA_VERSION, PdpPolicyActivationAcknowledgement,
    PepPolicyActivationAcknowledgement, PolicyActivationRequest, SignedPolicyBundle,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const POLICY_BUNDLE_KEYRING_SCHEMA: &str = "agenttrust.policy-bundle-keyring.v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBundleKeyringDocument {
    schema_version: String,
    keys: Vec<PolicyBundleKeyDocument>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBundleKeyDocument {
    key_id: String,
    status: PolicyBundleKeyStatus,
    verifying_key_file: PathBuf,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PolicyBundleKeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone)]
struct PolicyBundleVerificationKey {
    status: PolicyBundleKeyStatus,
    verifying_key: VerifyingKey,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PolicyBundleKeyring {
    keys: Arc<BTreeMap<String, PolicyBundleVerificationKey>>,
}

impl PolicyBundleKeyring {
    pub fn from_file(path: &Path) -> Result<Self, PepAuthorityError> {
        let raw = secure_read(path, false, 1_048_576)?;
        let document: PolicyBundleKeyringDocument =
            serde_json::from_slice(&raw).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != POLICY_BUNDLE_KEYRING_SCHEMA
            || document.keys.is_empty()
            || document.keys.len() > 64
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for definition in document.keys {
            if definition.key_id.is_empty()
                || definition.key_id.len() > 128
                || !definition.key_id.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
                || definition.valid_from >= definition.valid_until
                || definition.valid_until - definition.valid_from > Duration::days(3650)
                || keys
                    .insert(
                        definition.key_id,
                        PolicyBundleVerificationKey {
                            status: definition.status,
                            verifying_key: read_verifying_key(&definition.verifying_key_file)?,
                            valid_from: definition.valid_from,
                            valid_until: definition.valid_until,
                        },
                    )
                    .is_some()
            {
                return Err(PepAuthorityError::ConfigurationInvalid);
            }
        }
        if !keys
            .values()
            .any(|key| key.status == PolicyBundleKeyStatus::Active)
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    pub fn ready(&self) -> bool {
        !self.keys.is_empty()
            && self
                .keys
                .values()
                .any(|key| key.status == PolicyBundleKeyStatus::Active)
    }

    pub fn verify_for_activation(
        &self,
        bundle: &SignedPolicyBundle,
        now: DateTime<Utc>,
    ) -> Result<(), PepAuthorityError> {
        let key = self
            .keys
            .get(&bundle.key_id)
            .ok_or(PepAuthorityError::AuthorizationDenied)?;
        if key.status != PolicyBundleKeyStatus::Active
            || bundle.compiled_at < key.valid_from
            || bundle.compiled_at >= key.valid_until
            || bundle.compiled_at > now + Duration::seconds(30)
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        bundle
            .verify(&key.verifying_key)
            .map_err(|_| PepAuthorityError::AuthorizationDenied)
    }
}

impl PepAuthority {
    pub async fn activate_policy(
        &self,
        request: PolicyActivationRequest,
    ) -> Result<PepPolicyActivationAcknowledgement, PepAuthorityError> {
        request
            .validate()
            .map_err(|_| PepAuthorityError::RequestInvalid)?;
        self.policy_bundle_keys
            .verify_for_activation(&request.bundle, Utc::now())?;
        let claim = self.store.begin_policy_activation(&request).await?;
        let owner = match claim {
            PolicyActivationClaimResult::Replay(acknowledgement) => {
                acknowledgement
                    .verify(&self.signing_key.verifying_key())
                    .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
                validate_pep_ack(&request, &acknowledgement)?;
                return Ok(acknowledgement);
            }
            PolicyActivationClaimResult::Acquired(owner) => owner,
        };

        let result = self.activate_at_pdp(&request).await;
        let pdp_acknowledgement = match result {
            Ok(value) => value,
            Err(error) => {
                self.store
                    .mark_policy_activation_unknown(&request, &owner)
                    .await?;
                return Err(error);
            }
        };
        let pdp_ack_digest = canonical_digest(&pdp_acknowledgement)?;
        let acknowledged_at = Utc::now();
        let mut acknowledgement = PepPolicyActivationAcknowledgement {
            schema_version: PEP_POLICY_ACTIVATION_ACK_SCHEMA_VERSION.into(),
            activation_id: request.activation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            tenant_id: request.tenant_id.clone(),
            policy_id: request.policy_id.clone(),
            environment: request.environment,
            sequence: request.sequence,
            bundle_digest: request.bundle.bundle_digest.clone(),
            active: true,
            pdp_ack_digest,
            evidence_ref: String::new(),
            evidence_digest: String::new(),
            acknowledged_at,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            key_usage: PEP_POLICY_ACTIVATION_ACK_KEY_USAGE.into(),
            signature: String::new(),
        };
        acknowledgement
            .bind_evidence()
            .map_err(|_| PepAuthorityError::ResponseInvalid)?;
        acknowledgement
            .sign(&self.signing_key)
            .map_err(|_| PepAuthorityError::ResponseInvalid)?;
        validate_pep_ack(&request, &acknowledgement)?;
        self.store
            .complete_policy_activation(&request, &owner, &pdp_acknowledgement, &acknowledgement)
            .await
    }

    async fn activate_at_pdp(
        &self,
        request: &PolicyActivationRequest,
    ) -> Result<PdpPolicyActivationAcknowledgement, PepAuthorityError> {
        let acknowledgement: PdpPolicyActivationAcknowledgement = self
            .pdp_activation
            .post_idempotent(&request.tenant_id, request, Some(&request.idempotency_key))
            .await?;
        let signer = self.pdp_activation.signer()?;
        if signer.key_usage.as_ref() != PDP_POLICY_ACTIVATION_ACK_KEY_USAGE
            || acknowledgement.issuer != signer.issuer.as_ref()
            || acknowledgement.key_id != signer.key_id.as_ref()
            || acknowledgement.activation_id != request.activation_id
            || acknowledgement.idempotency_key != request.idempotency_key
            || acknowledgement.tenant_id != request.tenant_id
            || acknowledgement.policy_id != request.policy_id
            || acknowledgement.environment != request.environment
            || acknowledgement.sequence != request.sequence
            || acknowledgement.bundle_digest != request.bundle.bundle_digest
            || acknowledgement.activated_at < request.requested_at
            || acknowledgement.activated_at > Utc::now() + Duration::seconds(30)
        {
            return Err(PepAuthorityError::DependencyResponseInvalid);
        }
        acknowledgement
            .verify(&signer.verifying_key)
            .map_err(|_| PepAuthorityError::DependencyResponseInvalid)?;
        Ok(acknowledgement)
    }
}

fn validate_pep_ack(
    request: &PolicyActivationRequest,
    acknowledgement: &PepPolicyActivationAcknowledgement,
) -> Result<(), PepAuthorityError> {
    if acknowledgement.activation_id != request.activation_id
        || acknowledgement.idempotency_key != request.idempotency_key
        || acknowledgement.tenant_id != request.tenant_id
        || acknowledgement.policy_id != request.policy_id
        || acknowledgement.environment != request.environment
        || acknowledgement.sequence != request.sequence
        || acknowledgement.bundle_digest != request.bundle.bundle_digest
        || !acknowledgement.active
    {
        return Err(PepAuthorityError::ResponseInvalid);
    }
    Ok(())
}
