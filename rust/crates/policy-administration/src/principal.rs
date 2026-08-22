//! Verification of request-bound human assertions at the Policy Administration boundary.

use agent_trust_contracts::{SignedHumanPrincipalAssertion, TenantId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

pub const HUMAN_PRINCIPAL_KEYRING_SCHEMA_VERSION: &str = "agenttrust.human-principal-keyring.v1";
const MAX_ASSERTION_BYTES: usize = 65_536;
const MAX_ENCODED_ASSERTION_BYTES: usize = 87_384;

#[derive(Debug, Error)]
pub enum PrincipalAssertionError {
    #[error("POLICY_PRINCIPAL_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("POLICY_PRINCIPAL_ASSERTION_INVALID")]
    AssertionInvalid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalKeyringDocument {
    schema_version: String,
    audience: String,
    keys: Vec<HumanPrincipalVerificationKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanPrincipalVerificationKeyDocument {
    issuer: String,
    key_id: String,
    algorithm: String,
    usage: String,
    status: String,
    public_key: String,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct HumanPrincipalVerificationKey {
    key: VerifyingKey,
    tenants: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct HumanPrincipalKeyring {
    audience: String,
    keys: BTreeMap<(String, String), HumanPrincipalVerificationKey>,
}

impl HumanPrincipalKeyring {
    pub fn from_file(
        path: &Path,
        expected_audience: &str,
    ) -> Result<Self, PrincipalAssertionError> {
        if !path.is_absolute() || !identifier(expected_audience, 256) {
            return Err(PrincipalAssertionError::ConfigurationInvalid);
        }
        let raw = std::fs::read(path).map_err(|_| PrincipalAssertionError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(PrincipalAssertionError::ConfigurationInvalid);
        }
        let document: HumanPrincipalKeyringDocument = serde_json::from_slice(&raw)
            .map_err(|_| PrincipalAssertionError::ConfigurationInvalid)?;
        if document.schema_version != HUMAN_PRINCIPAL_KEYRING_SCHEMA_VERSION
            || document.audience != expected_audience
            || document.keys.is_empty()
            || document.keys.len() > 128
        {
            return Err(PrincipalAssertionError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        let mut has_active_key = false;
        let now = Utc::now();
        for entry in document.keys {
            if !identifier(&entry.issuer, 256)
                || !identifier(&entry.key_id, 128)
                || entry.algorithm != "Ed25519"
                || entry.usage != "HUMAN_PRINCIPAL_ASSERTION"
                || !matches!(entry.status.as_str(), "ACTIVE" | "VERIFY_ONLY")
                || entry.not_before >= entry.expires_at
                || invalid_tenants(&entry.tenant_ids)
            {
                return Err(PrincipalAssertionError::ConfigurationInvalid);
            }
            let public = URL_SAFE_NO_PAD
                .decode(entry.public_key)
                .map_err(|_| PrincipalAssertionError::ConfigurationInvalid)?;
            let bytes: [u8; 32] = public
                .try_into()
                .map_err(|_| PrincipalAssertionError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| PrincipalAssertionError::ConfigurationInvalid)?;
            has_active_key |=
                entry.status == "ACTIVE" && now >= entry.not_before && now < entry.expires_at;
            if keys
                .insert(
                    (entry.issuer, entry.key_id),
                    HumanPrincipalVerificationKey {
                        key,
                        tenants: entry.tenant_ids,
                        not_before: entry.not_before,
                        expires_at: entry.expires_at,
                    },
                )
                .is_some()
            {
                return Err(PrincipalAssertionError::ConfigurationInvalid);
            }
        }
        if !has_active_key {
            return Err(PrincipalAssertionError::ConfigurationInvalid);
        }
        Ok(Self {
            audience: document.audience,
            keys,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_encoded(
        &self,
        encoded: &str,
        expected_tenant: &TenantId,
        expected_client_identity: &str,
        expected_service_subject: &str,
        expected_scope: &str,
        expected_request_digest: &str,
        maximum_authentication_age_seconds: i64,
        now: DateTime<Utc>,
    ) -> Result<VerifiedHumanPrincipal, PrincipalAssertionError> {
        if !(60..=86_400).contains(&maximum_authentication_age_seconds)
            || encoded.is_empty()
            || encoded.len() > MAX_ENCODED_ASSERTION_BYTES
            || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(PrincipalAssertionError::AssertionInvalid);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| PrincipalAssertionError::AssertionInvalid)?;
        if raw.is_empty() || raw.len() > MAX_ASSERTION_BYTES {
            return Err(PrincipalAssertionError::AssertionInvalid);
        }
        let assertion: SignedHumanPrincipalAssertion =
            serde_json::from_slice(&raw).map_err(|_| PrincipalAssertionError::AssertionInvalid)?;
        let key = self
            .keys
            .get(&(assertion.issuer.clone(), assertion.key_id.clone()))
            .ok_or(PrincipalAssertionError::AssertionInvalid)?;
        if !key.tenants.contains(&expected_tenant.0)
            || key.not_before > assertion.issued_at
            || key.expires_at < assertion.expires_at
            || key.not_before > now + Duration::seconds(30)
            || key.expires_at <= now
        {
            return Err(PrincipalAssertionError::AssertionInvalid);
        }
        assertion
            .verify(
                &key.key,
                expected_tenant,
                expected_client_identity,
                expected_service_subject,
                expected_scope,
                expected_request_digest,
                &assertion.issuer,
                &self.audience,
                true,
                maximum_authentication_age_seconds,
                now,
            )
            .map_err(|_| PrincipalAssertionError::AssertionInvalid)?;
        let assertion_digest = assertion
            .assertion_digest()
            .map_err(|_| PrincipalAssertionError::AssertionInvalid)?;
        Ok(VerifiedHumanPrincipal {
            tenant_id: assertion.tenant_id,
            subject: assertion.subject,
            roles: assertion.roles,
            project_ids: assertion.project_ids,
            approval_ids: assertion.approval_ids,
            owned_resources: assertion.owned_resources,
            jti: assertion.jti,
            assertion_digest,
            expires_at: assertion.expires_at,
            authentication_context: assertion.authentication_context,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHumanPrincipal {
    pub tenant_id: TenantId,
    pub subject: String,
    pub roles: BTreeSet<String>,
    pub project_ids: BTreeSet<String>,
    pub approval_ids: BTreeSet<String>,
    pub owned_resources: BTreeSet<String>,
    pub jti: String,
    pub assertion_digest: String,
    pub expires_at: DateTime<Utc>,
    pub authentication_context: String,
}

fn invalid_tenants(values: &BTreeSet<String>) -> bool {
    values.is_empty()
        || values.len() > 1_024
        || values.iter().any(|value| {
            !uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == *value)
        })
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}
