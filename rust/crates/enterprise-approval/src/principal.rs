//! Short-lived, request-bound human principal assertions for approval mutations.

use super::postgres::ApprovalPrincipal;
use super::{ApprovalError, TenantId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const APPROVAL_PRINCIPAL_ASSERTION_SCHEMA_VERSION: &str =
    "agenttrust.signed-approval-principal-assertion.v1";
pub const APPROVAL_PRINCIPAL_KEYRING_SCHEMA_VERSION: &str =
    "agenttrust.approval-principal-keyring.v1";
pub const APPROVAL_PRINCIPAL_REQUEST_BINDING_SCHEMA_VERSION: &str =
    "agenttrust.approval-principal-request-binding.v1";

const MAX_ASSERTION_BYTES: usize = 32_768;
const MAX_ENCODED_ASSERTION_BYTES: usize = 43_691;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 300;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Serialize)]
struct ApprovalPrincipalRequestBinding<'a, T: Serialize> {
    schema_version: &'static str,
    method: &'a str,
    path: &'a str,
    tenant_id: &'a str,
    client_identity: &'a str,
    service_subject: &'a str,
    scope: &'a str,
    idempotency_key: &'a str,
    body: &'a T,
}

#[allow(clippy::too_many_arguments)]
pub fn approval_principal_request_digest<T: Serialize>(
    method: &str,
    path: &str,
    tenant_id: &str,
    client_identity_value: &str,
    service_subject: &str,
    scope: &str,
    idempotency_key: &str,
    body: &T,
) -> Result<String, ApprovalError> {
    if method != "POST"
        || !path.starts_with('/')
        || path.len() > 2_048
        || path.contains(['\0', '\r', '\n', '?', '#'])
        || !uuid::Uuid::parse_str(tenant_id).is_ok_and(|parsed| parsed.to_string() == tenant_id)
        || !client_identity(client_identity_value)
        || !identifier(service_subject)
        || !human_scope(scope)
        || idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || !idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        return Err(ApprovalError::RequestInvalid);
    }
    let binding = ApprovalPrincipalRequestBinding {
        schema_version: APPROVAL_PRINCIPAL_REQUEST_BINDING_SCHEMA_VERSION,
        method,
        path,
        tenant_id,
        client_identity: client_identity_value,
        service_subject,
        scope,
        idempotency_key,
        body,
    };
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&binding).map_err(|_| ApprovalError::RequestInvalid)?,
    )))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalPrincipalAssertion {
    pub schema_version: String,
    pub tenant_id: String,
    pub subject: String,
    pub roles: BTreeSet<String>,
    pub owned_resources: BTreeSet<String>,
    pub strong_auth: bool,
    pub issuer: String,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jti: String,
    pub request_digest: String,
    pub client_identity: String,
    pub scope: String,
    pub key_id: String,
    pub signature: String,
}

impl SignedApprovalPrincipalAssertion {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut material = self.clone();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| ApprovalError::AuthenticationRequired)
    }

    fn assertion_digest(&self) -> Result<String, ApprovalError> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| ApprovalError::AuthenticationRequired)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn to_header_value(&self) -> Result<String, ApprovalError> {
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;
        Signature::from_slice(&signature).map_err(|_| ApprovalError::AuthenticationRequired)?;
        let raw = serde_json::to_vec(self).map_err(|_| ApprovalError::AuthenticationRequired)?;
        if raw.is_empty() || raw.len() > MAX_ASSERTION_BYTES {
            return Err(ApprovalError::AuthenticationRequired);
        }
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalKeyringDocument {
    schema_version: String,
    audience: String,
    keys: Vec<PrincipalVerificationKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalVerificationKeyDocument {
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
struct PrincipalVerificationKey {
    key: VerifyingKey,
    tenant_ids: BTreeSet<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct ApprovalPrincipalAssertionKeyring {
    audience: String,
    keys: BTreeMap<(String, String), PrincipalVerificationKey>,
}

impl ApprovalPrincipalAssertionKeyring {
    pub fn from_file(path: &Path, expected_audience: &str) -> Result<Self, ApprovalError> {
        if !bounded(expected_audience, 256) {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let raw = std::fs::read(path).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let document: PrincipalKeyringDocument =
            serde_json::from_slice(&raw).map_err(|_| ApprovalError::ConfigurationInvalid)?;
        if document.schema_version != APPROVAL_PRINCIPAL_KEYRING_SCHEMA_VERSION
            || document.audience != expected_audience
            || document.keys.is_empty()
            || document.keys.len() > 128
        {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            if !identifier(&entry.issuer)
                || !key_identifier(&entry.key_id)
                || entry.algorithm != "Ed25519"
                || entry.usage != "APPROVAL_PRINCIPAL_ASSERTION"
                || entry.status != "ACTIVE"
                || entry.not_before >= entry.expires_at
                || entry.tenant_ids.is_empty()
                || entry.tenant_ids.len() > 1_024
                || entry.tenant_ids.iter().any(|tenant| {
                    !uuid::Uuid::parse_str(tenant)
                        .is_ok_and(|parsed| parsed.to_string() == tenant.as_str())
                })
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(&entry.public_key)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| ApprovalError::ConfigurationInvalid)?;
            let identity = (entry.issuer, entry.key_id);
            if keys
                .insert(
                    identity,
                    PrincipalVerificationKey {
                        key,
                        tenant_ids: entry.tenant_ids,
                        not_before: entry.not_before,
                        expires_at: entry.expires_at,
                    },
                )
                .is_some()
            {
                return Err(ApprovalError::ConfigurationInvalid);
            }
        }
        Ok(Self {
            audience: document.audience,
            keys,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn covers_tenant_at(&self, tenant: &TenantId, now: DateTime<Utc>) -> bool {
        self.keys.values().any(|verification| {
            verification.tenant_ids.contains(&tenant.0)
                && verification.not_before <= now
                && verification.expires_at
                    >= now + Duration::seconds(MAX_ASSERTION_LIFETIME_SECONDS)
        })
    }

    pub fn verify_encoded(
        &self,
        encoded: &str,
        expected_tenant: &TenantId,
        expected_client_identity: &str,
        expected_scope: &str,
        expected_request_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalPrincipal, ApprovalError> {
        if encoded.is_empty()
            || encoded.len() > MAX_ENCODED_ASSERTION_BYTES
            || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
            || !digest(expected_request_digest)
        {
            return Err(ApprovalError::AuthenticationRequired);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;
        if raw.is_empty() || raw.len() > MAX_ASSERTION_BYTES {
            return Err(ApprovalError::AuthenticationRequired);
        }
        let assertion: SignedApprovalPrincipalAssertion =
            serde_json::from_slice(&raw).map_err(|_| ApprovalError::AuthenticationRequired)?;
        let verification = self
            .keys
            .get(&(assertion.issuer.clone(), assertion.key_id.clone()))
            .ok_or(ApprovalError::AuthenticationRequired)?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&assertion.signature)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;
        verification
            .key
            .verify(&assertion.signing_bytes()?, &signature)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;

        let tenant = uuid::Uuid::parse_str(&assertion.tenant_id)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;
        let jti = uuid::Uuid::parse_str(&assertion.jti)
            .map_err(|_| ApprovalError::AuthenticationRequired)?;
        let maximum_expiry =
            assertion.issued_at + Duration::seconds(MAX_ASSERTION_LIFETIME_SECONDS);
        if assertion.schema_version != APPROVAL_PRINCIPAL_ASSERTION_SCHEMA_VERSION
            || tenant.to_string() != assertion.tenant_id
            || jti.to_string() != assertion.jti
            || assertion.tenant_id != expected_tenant.0
            || assertion.client_identity != expected_client_identity
            || assertion.scope != expected_scope
            || assertion.request_digest != expected_request_digest
            || assertion.audience != self.audience
            || !verification.tenant_ids.contains(&assertion.tenant_id)
            || !assertion.strong_auth
            || !identifier(&assertion.subject)
            || assertion.roles.is_empty()
            || assertion.roles.len() > 64
            || assertion.roles.iter().any(|role| !identifier(role))
            || assertion.owned_resources.len() > 1_024
            || assertion
                .owned_resources
                .iter()
                .any(|resource| !bounded(resource, 2_048))
            || !client_identity(&assertion.client_identity)
            || !human_scope(&assertion.scope)
            || !identifier(&assertion.issuer)
            || !key_identifier(&assertion.key_id)
            || assertion.issued_at < now - Duration::seconds(MAX_ASSERTION_LIFETIME_SECONDS)
            || assertion.issued_at > now + Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
            || assertion.expires_at <= now
            || assertion.expires_at <= assertion.issued_at
            || assertion.expires_at > maximum_expiry
            || verification.not_before > assertion.issued_at
            || verification.expires_at <= assertion.issued_at
            || verification.expires_at <= now
            || verification.expires_at < assertion.expires_at
        {
            return Err(ApprovalError::AuthenticationRequired);
        }
        let assertion_digest = assertion.assertion_digest()?;
        let assertion_document =
            serde_json::to_value(&assertion).map_err(|_| ApprovalError::AuthenticationRequired)?;
        Ok(ApprovalPrincipal {
            tenant_id: expected_tenant.clone(),
            subject: assertion.subject,
            roles: assertion.roles,
            owned_resources: assertion.owned_resources,
            strong_auth: true,
            assertion_issuer: assertion.issuer,
            assertion_jti: assertion.jti,
            assertion_request_digest: assertion.request_digest,
            assertion_digest,
            assertion_document,
            assertion_expires_at: assertion.expires_at,
        })
    }
}

fn identifier(value: &str) -> bool {
    bounded(value, 256)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn key_identifier(value: &str) -> bool {
    bounded(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn client_identity(value: &str) -> bool {
    value.len() <= 512
        && (value.starts_with("DNS:") || value.starts_with("URI:"))
        && value.split_once(':').is_some_and(|(_, identity)| {
            !identity.is_empty() && identity.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

fn human_scope(value: &str) -> bool {
    matches!(
        value,
        "approvals:request" | "approvals:decide" | "approvals:issue" | "approvals:revoke"
    )
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains('\0')
        && !value.contains(['\r', '\n'])
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
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_assertion(
        signing: &SigningKey,
        now: DateTime<Utc>,
    ) -> Result<SignedApprovalPrincipalAssertion, ApprovalError> {
        let mut assertion = SignedApprovalPrincipalAssertion {
            schema_version: APPROVAL_PRINCIPAL_ASSERTION_SCHEMA_VERSION.into(),
            tenant_id: "01900000-0000-7000-8000-000000000001".into(),
            subject: "human-approver@example.test".into(),
            roles: BTreeSet::from(["production-approver".into()]),
            owned_resources: BTreeSet::from(["urn:resource:one".into()]),
            strong_auth: true,
            issuer: "enterprise-idp".into(),
            audience: "agenttrust-approval".into(),
            issued_at: now,
            expires_at: now + Duration::minutes(4),
            jti: "01900000-0000-7000-8000-000000000002".into(),
            request_digest: "a".repeat(64),
            client_identity: "URI:spiffe://agenttrust/bff".into(),
            scope: "approvals:decide".into(),
            key_id: "idp-key-1".into(),
            signature: String::new(),
        };
        assertion.signature =
            URL_SAFE_NO_PAD.encode(signing.sign(&assertion.signing_bytes()?).to_bytes());
        Ok(assertion)
    }

    #[test]
    fn assertion_is_bound_to_tenant_san_scope_and_request_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let signing = SigningKey::from_bytes(&[91_u8; 32]);
        let now = Utc::now();
        let assertion = signed_assertion(&signing, now)?;
        let keyring = ApprovalPrincipalAssertionKeyring {
            audience: "agenttrust-approval".into(),
            keys: BTreeMap::from([(
                ("enterprise-idp".into(), "idp-key-1".into()),
                PrincipalVerificationKey {
                    key: signing.verifying_key(),
                    tenant_ids: BTreeSet::from([assertion.tenant_id.clone()]),
                    not_before: now - Duration::minutes(1),
                    expires_at: now + Duration::days(1),
                },
            )]),
        };
        let encoded = assertion.to_header_value()?;
        let tenant = TenantId(assertion.tenant_id.clone());
        let principal = keyring.verify_encoded(
            &encoded,
            &tenant,
            &assertion.client_identity,
            &assertion.scope,
            &assertion.request_digest,
            now,
        )?;
        assert_eq!(principal.subject, assertion.subject);
        assert!(
            keyring
                .verify_encoded(
                    &encoded,
                    &tenant,
                    &assertion.client_identity,
                    &assertion.scope,
                    &"b".repeat(64),
                    now,
                )
                .is_err()
        );
        Ok(())
    }
}
